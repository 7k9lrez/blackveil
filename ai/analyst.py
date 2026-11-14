"""Module 02: Gemini AI Security Assistant & Offline MITRE ATT&CK Correlation Engine."""

from __future__ import annotations

import getpass
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import ConfigManager, SecretsManager
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class AISecurityAnalyst:
    """Google Gemini AI Assistant + Multi-turn Terminal Chat + Offline MITRE ATT&CK Heuristic Engine."""

    SYSTEM_PROMPT = (
        "You are BLACKVEIL AI Security Analyst, a senior cybersecurity engineer and DFIR specialist. "
        "Provide accurate, concise, defensive and analytical guidance. Never fabricate command outputs, "
        "CVEs, or telemetry that were not provided. Map findings to MITRE ATT&CK IDs when relevant."
    )

    MITRE_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
        (
            re.compile(r"failed password|authentication failure|brute|4625|failed_auth", re.I),
            "T1110 (Brute Force)",
            "HIGH",
            "Enforce account lockout thresholds, MFA, and rate-limit authentication endpoints.",
        ),
        (
            re.compile(r"invoke-expression|encodedcommand|downloadstring|powershell|certutil", re.I),
            "T1059.001 (PowerShell / Script Execution)",
            "CRITICAL",
            "Enable PowerShell ScriptBlock Logging (Event 4104), Constrained Language Mode, and AMSI auditing.",
        ),
        (
            re.compile(r"union\s+select|or\s+1=1|sql\s*injection", re.I),
            "T1190 (Exploit Public-Facing Application)",
            "HIGH",
            "Replace dynamic SQL concatenation with parameterized queries and deploy WAF rules.",
        ),
        (
            re.compile(r"\.\./|\.\.\\|/etc/passwd|boot\.ini", re.I),
            "T1083 (File and Directory Discovery / Path Traversal)",
            "HIGH",
            "Canonicalize file paths server-side and restrict file reads to an allowlisted root directory.",
        ),
        (
            re.compile(r"sudo:|SeDebugPrivilege|nt authority\\system|privilege", re.I),
            "T1548 (Abuse Elevation Control Mechanism)",
            "CRITICAL",
            "Audit sudoers / Windows Administrator group memberships and alert on unexpected token elevation.",
        ),
        (
            re.compile(r"entropy|ransomware|locked_sim|virtualalloc|createremotethread", re.I),
            "T1486 / T1055 (Data Encrypted for Impact / Process Injection)",
            "CRITICAL",
            "Isolate affected host immediately, capture volatile memory/evidence, and verify immutable backups.",
        ),
    ]

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        db: DatabaseManager,
        reports: ReportManager,
        secrets: SecretsManager | None = None,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.db = db
        self.reports = reports
        self.secrets = secrets or SecretsManager()

    def get_api_key(self) -> str:
        return self.secrets.get_secret("gemini_api_key", ("GEMINI_API_KEY", "GOOGLE_API_KEY"))

    def configure(
        self,
        api_key: str | None = None,
        prompt_key: bool = False,
        model: str | None = None,
        timeout: int | None = None,
        retries: int | None = None,
        show: bool = False,
        clear_key: bool = False,
    ) -> dict[str, Any]:
        """Configure Gemini API key securely (never printed raw) and model/retry settings."""
        if clear_key:
            self.secrets.set_secret("gemini_api_key", "")
            self.console.print("[bright_green][+][/] Stored Gemini API key removed from local secrets store.")

        if prompt_key:
            entered = getpass.getpass("Enter Google Gemini API key (hidden input): ").strip()
            if entered:
                self.secrets.set_secret("gemini_api_key", entered)
                self.console.print("[bright_green][+][/] Gemini API key saved securely in restricted store.")
            else:
                self.console.print("[yellow][!][/] Empty input; existing API key unchanged.")
        elif api_key is not None:
            self.secrets.set_secret("gemini_api_key", api_key)
            self.console.print("[bright_green][+][/] Gemini API key updated in restricted store (never written to config.json or logs).")

        if model:
            self.config.set("ai_model", model.strip())
        if timeout is not None:
            self.config.set("gemini_timeout", str(max(5, int(timeout))))
        if retries is not None:
            self.config.set("gemini_retries", str(max(1, int(retries))))

        current_key = self.get_api_key()
        masked = self.secrets.mask_value(current_key)
        env_active = bool(os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("GOOGLE_API_KEY", "").strip())
        cur_model = str(self.config.get("ai_model", "gemini-4-hydrogen"))
        cur_timeout = int(self.config.get("gemini_timeout", 25))
        cur_retries = int(self.config.get("gemini_retries", 2))

        if show or (not any([prompt_key, api_key is not None, model, timeout is not None, retries is not None, clear_key])):
            self.console.print(
                Panel(
                    f"[white]Gemini API Key :[/] [bright_green]{masked}[/] "
                    f"[grey70](source: {'ENV' if env_active else 'RESTRICTED_STORE' if current_key else 'NONE'})[/]\n"
                    f"[white]Active Model   :[/] [bright_green]{cur_model}[/]\n"
                    f"[white]Timeout / Retry:[/] {cur_timeout}s / {cur_retries} attempt(s)\n"
                    f"[grey70]Tip: Run `ai config --api-key` for hidden prompt or set GEMINI_API_KEY env var.[/]",
                    title="[bold bright_green]GEMINI AI CONFIGURATION[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )
        return {
            "configured": bool(current_key),
            "masked_key": masked,
            "model": cur_model,
            "timeout": cur_timeout,
            "retries": cur_retries,
        }

    def _call_gemini(
        self,
        prompt_text: str,
        history_messages: list[dict[str, str]] | None = None,
        system_instruction: str | None = None,
    ) -> tuple[bool, str]:
        """Call Google Gemini API with timeout, exponential backoff retry, and clear error reporting."""
        api_key = self.get_api_key()
        if not api_key:
            return False, "Gemini API key not configured. Run `ai config --api-key` or set GEMINI_API_KEY."

        model = str(self.config.get("ai_model", "gemini-4-hydrogen"))
        timeout = int(self.config.get("gemini_timeout", 25))
        max_attempts = max(1, int(self.config.get("gemini_retries", 2)) + 1)
        sys_text = system_instruction or self.SYSTEM_PROMPT

        contents: list[dict[str, Any]] = []
        if history_messages:
            for msg in history_messages[-12:]:
                role = "model" if msg.get("role") == "model" else "user"
                contents.append({"role": role, "parts": [{"text": str(msg.get("content", ""))[:12000]}]})
        contents.append({"role": "user", "parts": [{"text": prompt_text[:24000]}]})

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{urllib.parse.quote(model)}:generateContent?key={urllib.parse.quote(api_key)}"
        )
        payload = {
            "systemInstruction": {"parts": [{"text": sys_text}]},
            "contents": contents,
        }
        body_bytes = json.dumps(payload).encode("utf-8")

        last_err = "Unknown error"
        for attempt in range(1, max_attempts + 1):
            req = urllib.request.Request(
                url,
                data=body_bytes,
                headers={"Content-Type": "application/json", "User-Agent": "BLACKVEIL-X/1.0"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                candidates = data.get("candidates", [])
                if not candidates:
                    return False, "Empty candidate list returned by Gemini API."
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "\n".join(p.get("text", "") for p in parts if p.get("text")).strip()
                return (True, text) if text else (False, "Gemini returned no text output.")
            except urllib.error.HTTPError as exc:
                err_body = ""
                try:
                    err_body = exc.read(500).decode("utf-8", errors="replace")
                except Exception:
                    pass
                if exc.code in {400, 401, 403}:
                    return False, f"Gemini authentication/request error (HTTP {exc.code}): verify API key and model '{model}'."
                if exc.code == 404:
                    return False, f"Gemini model '{model}' not found (HTTP 404). Update with `ai config --model <name>`."
                if exc.code == 429:
                    last_err = "Gemini API quota/rate limit reached (HTTP 429)."
                elif exc.code >= 500:
                    last_err = f"Gemini server error HTTP {exc.code}: {exc.reason}"
                else:
                    return False, f"Gemini API HTTP {exc.code}: {exc.reason} {err_body[:120]}"
            except Exception as exc:
                last_err = f"Gemini network/timeout error: {exc}"

            if attempt < max_attempts:
                time.sleep(min(4.0, 0.8 * (2 ** (attempt - 1))))

        return False, last_err

    def _save_chat_turn(self, session_id: str, role: str, content: str, model: str) -> None:
        try:
            with self.db.connection() as conn:
                conn.execute(
                    "INSERT INTO ai_chat_history (session_id, role, content, model, created_at) VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, model, utc_now()),
                )
        except Exception:
            pass

    def ask(self, question: str, session_id: str | None = None) -> dict[str, Any]:
        """Ask Gemini a single cybersecurity/technical question (with optional persisted conversation session)."""
        q = question.strip()
        if not q:
            self.console.print("[bold red][-][/] Provide a question. Usage: ai ask <question>")
            return {}

        sid = session_id or f"AI-{uuid.uuid4().hex[:8]}"
        history: list[dict[str, str]] = []
        if session_id:
            with self.db.connection() as conn:
                rows = conn.execute(
                    "SELECT role, content FROM ai_chat_history WHERE session_id = ? ORDER BY id ASC LIMIT 20",
                    (sid,),
                ).fetchall()
                history = [{"role": r["role"], "content": r["content"]} for r in rows]

        model = str(self.config.get("ai_model", "gemini-4-hydrogen"))
        with self.console.status(f"[bold bright_green][*] Querying Gemini ({model})...[/]", spinner="dots"):
            ok, reply = self._call_gemini(q, history_messages=history)

        if not ok:
            self.console.print(f"[bold red][-][/] Gemini Assistant unavailable: {reply}")
            return {"ok": False, "error": reply, "question": q}

        self._save_chat_turn(sid, "user", q, model)
        self._save_chat_turn(sid, "model", reply, model)
        self.console.print(
            Panel(
                reply,
                title=f"[bold bright_green]GEMINI AI ASSISTANT ({model}) // {sid}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return {"ok": True, "session_id": sid, "model": model, "question": q, "answer": reply}

    def interactive_chat(self) -> int:
        """Interactive multi-turn Gemini terminal chat mode inside BLACKVEIL."""
        api_key = self.get_api_key()
        model = str(self.config.get("ai_model", "gemini-4-hydrogen"))
        sid = f"CHAT-{uuid.uuid4().hex[:8]}"
        history: list[dict[str, str]] = []

        self.console.print(
            Panel(
                f"[bold bright_green]BLACKVEIL GEMINI INTERACTIVE TERMINAL[/]\n"
                f"[white]Session ID :[/] {sid}  |  [white]Model:[/] {model}\n"
                f"[white]API Key    :[/] {'[bright_green]CONFIGURED[/]' if api_key else '[yellow]NOT SET (run `ai config --api-key`)[/]'}\n"
                f"[grey70]Commands: /clear (reset context), /history, /model <name>, /exit[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        if not api_key:
            self.console.print("[yellow][!][/] Set your Gemini key first via `ai config --api-key` or `GEMINI_API_KEY`.")
            return 1

        while True:
            try:
                self.console.print("[bold bright_green]BLACKVEIL AI[/][white]>[/] ", end="")
                line = input().strip()
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[grey70][*] Exiting Gemini chat mode.[/]")
                break

            if not line:
                continue
            low = line.lower()
            if low in {"/exit", "exit", "quit", "/quit"}:
                self.console.print("[bright_green][*][/] Closed Gemini chat session.")
                break
            if low == "/clear":
                history.clear()
                self.console.print("[bright_green][+][/] Conversation context cleared.")
                continue
            if low == "/history":
                for idx, turn in enumerate(history, start=1):
                    who = "YOU" if turn["role"] == "user" else "GEMINI"
                    self.console.print(f"[grey70]{idx}. [{who}][/] {turn['content'][:160]}")
                continue
            if low.startswith("/model "):
                new_model = line.split(None, 1)[1].strip()
                self.config.set("ai_model", new_model)
                model = new_model
                self.console.print(f"[bright_green][+][/] Switched Gemini model to {model}.")
                continue

            with self.console.status(f"[bold bright_green][*] Thinking ({model})...[/]", spinner="dots"):
                ok, reply = self._call_gemini(line, history_messages=history)
            if not ok:
                self.console.print(f"[bold red][-][/] {reply}")
                continue
            history.append({"role": "user", "content": line})
            history.append({"role": "model", "content": reply})
            self._save_chat_turn(sid, "user", line, model)
            self._save_chat_turn(sid, "model", reply, model)
            self.console.print(Panel(reply, title=f"[bold bright_green]GEMINI ({model})[/]", border_style="bright_green", box=box.SQUARE))
        return 0

    def _local_security_reasoning(self, content: str, context_label: str) -> dict[str, Any]:
        """Deterministic offline SOC/DFIR rule correlation & MITRE ATT&CK mapping."""
        matched: list[dict[str, str]] = []
        lines = content.splitlines()
        for pat, technique, sev, remediation in self.MITRE_RULES:
            hit_lines = [ln.strip() for ln in lines if pat.search(ln)]
            if hit_lines or pat.search(content):
                matched.append(
                    {
                        "technique": technique,
                        "severity": sev,
                        "evidence_count": str(max(1, len(hit_lines))),
                        "sample": (hit_lines[0][:110] if hit_lines else "Matched in payload"),
                        "remediation": remediation,
                    }
                )

        ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        overall = "INFO"
        if matched:
            overall = max((m["severity"] for m in matched), key=lambda s: risk_order.get(s, 0))

        return {
            "context": context_label,
            "overall_severity": overall,
            "lines_inspected": len(lines),
            "observables_ips": ips[:15],
            "mitre_mappings": matched,
        }

    def _load_target_text(self, target: str | None) -> tuple[str, str]:
        """Resolve a file path, incident/report/scan ID, or fallback to recent session findings."""
        if target:
            p = Path(target).expanduser()
            if p.exists() and p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")[:30000], f"File: {p.name}"

            with self.db.connection() as conn:
                inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (target,)).fetchone()
                if inc:
                    return json.dumps(dict(inc), indent=2), f"Incident: {target}"
                rep = conn.execute("SELECT * FROM reports_index WHERE id = ?", (target,)).fetchone()
                if rep:
                    return json.dumps(dict(rep), indent=2), f"Report: {target}"
                wscan = conn.execute("SELECT * FROM website_scans WHERE id = ? OR host = ?", (target, target)).fetchone()
                if wscan:
                    return json.dumps(dict(wscan), indent=2), f"Website Scan: {wscan['host']}"
            return target, "Direct Input"

        if self.reports.session_records:
            latest = self.reports.session_records[-1]
            return json.dumps(latest, indent=2, default=str), f"Latest Finding ({latest['id']})"

        with self.db.connection() as conn:
            events = conn.execute("SELECT * FROM security_events ORDER BY created_at DESC LIMIT 10").fetchall()
            if events:
                return json.dumps([dict(e) for e in events], indent=2), "Recent Security Events"

        return "", "Empty"

    def analyze(self, target: str | None = None, mode: str = "analyze") -> dict[str, Any]:
        """Run AI security analysis/explanation (live Gemini if configured, else deterministic MITRE reasoner)."""
        payload_text, label = self._load_target_text(target)
        if not payload_text.strip():
            self.console.print("[bold yellow][!][/] No input file, event ID, or recent session finding available to analyze.")
            return {}

        local_eval = self._local_security_reasoning(payload_text, label)
        prompt = (
            f"Task: {mode.upper()}\nTarget Context: {label}\n"
            f"Pre-extracted observables: IPs={local_eval['observables_ips']}, Techniques={local_eval['mitre_mappings']}\n\n"
            f"Data to {mode}:\n{payload_text[:15000]}"
        )
        with self.console.status("[bold bright_green][*] Running AI Security Analyst correlation...[/]", spinner="dots"):
            llm_ok, llm_output = self._call_gemini(prompt)

        mode_banner = (
            f"[bold bright_green]LIVE GEMINI ({self.config.get('ai_model', 'gemini-4-hydrogen')})[/]"
            if llm_ok
            else f"[yellow]OFFLINE MITRE REASONER[/] [grey70]({llm_output})[/]"
        )

        self.console.print(
            Panel(
                f"[white]Target      :[/] [bright_green]{label}[/]\n"
                f"[white]Engine Mode :[/] {mode_banner}\n"
                f"[white]Risk Level  :[/] [bold {'red' if local_eval['overall_severity'] in {'CRITICAL', 'HIGH'} else 'bright_green'}]{local_eval['overall_severity']}[/]\n"
                f"[white]IPs Found   :[/] {', '.join(local_eval['observables_ips']) or 'None'}",
                title=f"[bold bright_green]AI SECURITY ANALYST // {mode.upper()}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        if local_eval["mitre_mappings"]:
            table = Table(title="[bold bright_green]MITRE ATT&CK & TELEMETRY CORRELATION[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
            table.add_column("Severity", width=10)
            table.add_column("MITRE Technique", style="white")
            table.add_column("Hits", justify="right", width=5)
            table.add_column("Recommended Remediation", style="grey70")
            for m in local_eval["mitre_mappings"]:
                col = "bold red" if m["severity"] == "CRITICAL" else "bold yellow"
                table.add_row(f"[{col}]{m['severity']}[/]", m["technique"], m["evidence_count"], m["remediation"])
            self.console.print(table)

        if llm_ok:
            self.console.print(Panel(llm_output, title="[bold bright_green]GEMINI AI ANALYST BRIEFING[/]", border_style="bright_green", box=box.SQUARE))

        result = {
            "mode": mode,
            "target": label,
            "engine": "gemini" if llm_ok else "local_mitre_reasoner",
            "local_correlation": local_eval,
            "ai_briefing": llm_output if llm_ok else None,
            "analyzed_at": utc_now(),
        }
        self.reports.record("AI_ANALYSIS", f"AI {mode.title()}: {label}", result, severity=local_eval["overall_severity"])
        return result

    def report(self, target: str | None = None, fmt: str = "json") -> None:
        self.analyze(target=target, mode="report")
        self.reports.export_report(export_format=fmt, export_all=False)

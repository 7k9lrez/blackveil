"""Module 05: Log Intelligence - Windows Event Logs, syslog, search, correlation & timeline."""

from __future__ import annotations

import platform
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.config import LOGS_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager
from modules.reports import ReportManager


class LogIntelligenceModule:
    """Analyzes Windows Event Logs, Linux system logs, and application log files."""

    DETECTION_RULES: list[tuple[str, str, re.Pattern[str]]] = [
        ("Auth Failure / Brute Force", "HIGH", re.compile(r"failed password|4625|authentication failure|logon failure|failed_auth", re.I)),
        ("Privilege / Account Escalation", "CRITICAL", re.compile(r"4672|4720|sudo:.*COMMAND=|SeDebugPrivilege|Privilege", re.I)),
        ("Suspicious Script / LOLBin", "CRITICAL", re.compile(r"4104|encodedcommand|invoke-expression|downloadstring|certutil", re.I)),
        ("Web Injection / Traversal", "HIGH", re.compile(r"union\s+select|\.\./|/etc/passwd|xp_cmdshell", re.I)),
        ("Service / Crash / Error", "MEDIUM", re.compile(r"\b(?:error|critical|exception|fatal|crash)\b", re.I)),
    ]

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.reports = reports

    def _read_source_lines(self, file_path: str | None = None, channel: str = "Security", limit: int = 80) -> tuple[list[str], str]:
        if file_path:
            p = Path(file_path).expanduser()
            if not p.exists() or not p.is_file():
                self.console.print(f"[bold red][-][/] Log file not found: {p}")
                return [], str(p)
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            return lines[-limit:] if limit > 0 else lines, str(p.resolve())

        sys_name = platform.system()
        if sys_name == "Windows":
            try:
                proc = subprocess.run(
                    ["wevtutil", "qe", channel, f"/c:{limit}", "/rd:true", "/f:text"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding="utf-8",
                    errors="replace",
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return proc.stdout.splitlines(), f"Windows EventLog ({channel})"
            except Exception:
                pass
            # Fallback to System or BLACKVEIL log if Security channel requires admin
            if channel == "Security":
                try:
                    proc = subprocess.run(
                        ["wevtutil", "qe", "Application", f"/c:{limit}", "/rd:true", "/f:text"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        encoding="utf-8",
                        errors="replace",
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        return proc.stdout.splitlines(), "Windows EventLog (Application fallback - Security requires Admin)"
                except Exception:
                    pass
        else:
            for candidate in (Path("/var/log/auth.log"), Path("/var/log/syslog"), Path("/var/log/messages")):
                if candidate.exists():
                    try:
                        return candidate.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:], str(candidate)
                    except PermissionError:
                        continue

        bv_log = LOGS_DIR / "blackveil.log"
        if bv_log.exists():
            return bv_log.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:], str(bv_log)
        return [], "No readable logs"

    def analyze(self, file_path: str | None = None, channel: str = "Security", limit: int = 120) -> dict[str, Any]:
        lines, source = self._read_source_lines(file_path=file_path, channel=channel, limit=limit)
        if not lines:
            self.console.print(f"[yellow][!][/] No log entries retrieved from '{source}'.")
            return {}

        hits: list[dict[str, Any]] = []
        rule_counts: Counter[str] = Counter()
        for idx, line in enumerate(lines, start=1):
            for rule_name, sev, pat in self.DETECTION_RULES:
                if pat.search(line):
                    rule_counts[rule_name] += 1
                    hits.append({"line": idx, "rule": rule_name, "severity": sev, "text": line.strip()[:120]})

        table = Table(
            title=f"[bold bright_green]LOG INTELLIGENCE // {source} ({len(lines)} LINES)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Line", width=6, justify="right", style="grey70")
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=28, style="white")
        table.add_column("Log Excerpt", style="grey70")

        for h in hits[:35]:
            col = "bold red" if h["severity"] == "CRITICAL" else "bold yellow" if h["severity"] == "HIGH" else "yellow"
            table.add_row(str(h["line"]), f"[{col}]{h['severity']}[/]", h["rule"], h["text"])

        if hits:
            self.console.print(table)
        else:
            self.console.print(f"[bright_green][+][/] Analyzed {len(lines)} lines from {source}; zero threat signatures matched.")

        res = {"source": source, "lines_analyzed": len(lines), "rule_counts": dict(rule_counts), "hits": hits[:50]}
        self.reports.record("LOG_INTELLIGENCE", f"Log Analysis: {source}", res, severity="HIGH" if hits else "INFO")
        return res

    def search(self, query: str, file_path: str | None = None, channel: str = "Application") -> list[str]:
        lines, source = self._read_source_lines(file_path=file_path, channel=channel, limit=400)
        pat = re.compile(query, re.I)
        matched = [ln for ln in lines if pat.search(ln)]
        self.console.print(f"[bright_green][*][/] Matched [white]{len(matched)}[/] line(s) for /{query}/ in [grey70]{source}[/]:")
        for ln in matched[:30]:
            self.console.print(f"  [grey70]{ln[:160]}[/]")
        return matched

    def timeline(self, file_path: str | None = None) -> list[dict[str, str]]:
        lines, source = self._read_source_lines(file_path=file_path, limit=150)
        ts_pat = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
        events: list[dict[str, str]] = []
        for ln in lines:
            m = ts_pat.search(ln)
            if m:
                events.append({"timestamp": m.group(1), "event": ln.strip()[:120]})

        table = Table(title=f"[bold bright_green]CHRONOLOGICAL LOG TIMELINE // {source}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Timestamp", style="bright_green", width=20)
        table.add_column("Event", style="white")
        for ev in events[:30]:
            table.add_row(ev["timestamp"], ev["event"])
        if events:
            self.console.print(table)
        else:
            self.console.print("[grey70][*] No ISO-formatted timestamps detected in log source.[/]")
        return events

    def export(self, file_path: str | None = None, fmt: str = "json") -> None:
        self.analyze(file_path=file_path)
        self.reports.export_report(export_format=fmt, export_all=False)

"""Terminal Session Recorder with sensitive secret masking and replay."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import SESSIONS_DIR, ensure_directories
from database.db import DatabaseManager, utc_now


class SessionRecorder:
    """Records terminal commands, execution durations, and masked outputs."""

    MASK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"(AIza[0-9A-Za-z\-_]{20,})"), "AIza****MASKED"),
        (re.compile(r"(AKIA[0-9A-Z]{12,})"), "AKIA****MASKED"),
        (re.compile(r"(gh[pousr]_[0-9A-Za-z]{16,})"), "gh_****MASKED"),
        (re.compile(r"(sk-[0-9A-Za-z]{16,})"), "sk-****MASKED"),
        (re.compile(r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.I), "Bearer ****MASKED"),
        (re.compile(r"(--check\s+)(\"[^\"]+\"|'[^']+'|\S+)", re.I), r"\1****MASKED"),
        (re.compile(r"(--(?:api-key|gsb-key|vt-key|cse-key|key)(?:=|\s+))(\"[^\"]+\"|'[^']+'|\S+)", re.I), r"\1****MASKED"),
        (re.compile(r"((?:password|passwd|secret|token|api_key|key)\s*[=:]\s*)(\"[^\"]+\"|'[^']+'|\S+)", re.I), r"\1****MASKED"),
    ]

    def __init__(self, console: Console, db: DatabaseManager) -> None:
        self.console = console
        self.db = db
        ensure_directories()
        self.active_session_id: str | None = None
        self.active_file: Path | None = None
        self.command_count = 0

    @classmethod
    def mask_sensitive(cls, text: str) -> str:
        """Mask tokens, API keys, and passwords before writing session transcripts."""
        masked = text
        for pattern, repl in cls.MASK_PATTERNS:
            masked = pattern.sub(repl, masked)
        return masked

    def start(self, session_name: str | None = None) -> str:
        if self.active_session_id:
            self.console.print(f"[yellow][!][/] Session '{self.active_session_id}' is already recording.")
            return self.active_session_id

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sid = session_name.strip() if session_name else f"SES-{stamp}"
        safe_sid = "".join(c for c in sid if c.isalnum() or c in {"-", "_"}) or f"SES-{stamp}"
        file_path = SESSIONS_DIR / f"{safe_sid}.jsonl"

        self.active_session_id = safe_sid
        self.active_file = file_path
        self.command_count = 0

        header = {
            "type": "session_start",
            "session_id": safe_sid,
            "started_at": utc_now(),
        }
        file_path.write_text(json.dumps(header) + "\n", encoding="utf-8")

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO terminal_sessions (id, started_at, ended_at, command_count, file_path, status)
                VALUES (?, ?, NULL, 0, ?, 'RECORDING')
                """,
                (safe_sid, utc_now(), str(file_path)),
            )

        self.console.print(
            Panel(
                f"[bright_green][+] Terminal Session Recording STARTED[/]\n"
                f"[white]Session ID:[/] [bright_green]{safe_sid}[/]\n"
                f"[white]Transcript:[/] {file_path}\n"
                f"[grey70]Sensitive tokens/passwords are automatically masked.[/]",
                title="[bold bright_green]SESSION RECORDER[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return safe_sid

    def record_command(self, raw_command: str, status_code: int, duration_ms: float, output_excerpt: str = "") -> None:
        if not self.active_session_id or not self.active_file:
            return
        self.command_count += 1
        entry = {
            "type": "command",
            "seq": self.command_count,
            "timestamp": utc_now(),
            "command": self.mask_sensitive(raw_command),
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "output": self.mask_sensitive(output_excerpt[:2000]),
        }
        with self.active_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE terminal_sessions SET command_count = ? WHERE id = ?",
                (self.command_count, self.active_session_id),
            )

    def stop(self) -> None:
        if not self.active_session_id or not self.active_file:
            self.console.print("[grey70][*] No active session recording.[/]")
            return

        footer = {
            "type": "session_end",
            "session_id": self.active_session_id,
            "ended_at": utc_now(),
            "commands_recorded": self.command_count,
        }
        with self.active_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(footer) + "\n")

        with self.db.connection() as conn:
            conn.execute(
                "UPDATE terminal_sessions SET ended_at = ?, command_count = ?, status = 'CLOSED' WHERE id = ?",
                (utc_now(), self.command_count, self.active_session_id),
            )

        self.console.print(
            f"[bright_green][+][/] Session [white]{self.active_session_id}[/] stopped ({self.command_count} commands saved)."
        )
        self.active_session_id = None
        self.active_file = None
        self.command_count = 0

    def list_sessions(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, started_at, ended_at, command_count, file_path, status FROM terminal_sessions ORDER BY started_at DESC"
            ).fetchall()
        items = [dict(r) for r in rows]

        table = Table(
            title="[bold bright_green]TERMINAL SESSION ARCHIVE[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Session ID", style="bright_green")
        table.add_column("Status", width=10)
        table.add_column("Cmds", justify="right", width=6)
        table.add_column("Started", style="grey70")
        table.add_column("File", style="white")

        if not items:
            self.console.print("[grey70][*] No recorded terminal sessions found.[/]")
            return []

        for item in items:
            st = "[bold bright_green]RECORDING[/]" if item["status"] == "RECORDING" else "[grey70]CLOSED[/]"
            table.add_row(item["id"], st, str(item["command_count"]), item["started_at"][:19], Path(item["file_path"]).name)
        self.console.print(table)
        return items

    def replay(self, session_id: str) -> list[dict[str, Any]]:
        path = SESSIONS_DIR / f"{session_id}.jsonl"
        if not path.exists():
            self.console.print(f"[bold red][-][/] Session '{session_id}' not found.")
            return []

        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        table = Table(
            title=f"[bold bright_green]SESSION REPLAY // {session_id}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("#", width=4, justify="right", style="grey70")
        table.add_column("Timestamp", width=19, style="grey70")
        table.add_column("Command (Masked)", style="bright_green")
        table.add_column("RC", width=4, justify="right")
        table.add_column("Duration", width=10, justify="right", style="grey70")

        for ev in events:
            if ev.get("type") == "command":
                rc = ev.get("status_code", 0)
                rc_str = f"[bright_green]{rc}[/]" if rc == 0 else f"[bold red]{rc}[/]"
                table.add_row(
                    str(ev.get("seq", "-")),
                    str(ev.get("timestamp", ""))[:19],
                    ev.get("command", ""),
                    rc_str,
                    f"{ev.get('duration_ms', 0)} ms",
                )
        self.console.print(table)
        return events

    def export(self, session_id: str, fmt: str = "txt") -> Path | None:
        path = SESSIONS_DIR / f"{session_id}.jsonl"
        if not path.exists():
            self.console.print(f"[bold red][-][/] Session '{session_id}' not found.")
            return None

        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        fmt_l = fmt.lower()
        out_path = SESSIONS_DIR / f"{session_id}_export.{fmt_l}"
        if fmt_l == "json":
            out_path.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            lines = [f"BLACKVEIL TERMINAL SESSION EXPORT: {session_id}", "=" * 70]
            for ev in events:
                if ev.get("type") == "command":
                    lines.append(f"[{ev['seq']}] {ev['timestamp']} | RC={ev['status_code']} | {ev['duration_ms']}ms")
                    lines.append(f"  $ {ev['command']}")
                    if ev.get("output"):
                        lines.append(f"  > {ev['output'][:300]}")
            out_path.write_text("\n".join(lines), encoding="utf-8")

        self.console.print(f"[bright_green][+][/] Exported session transcript to [white]{out_path}[/]")
        return out_path

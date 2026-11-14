"""Module 17: Automation Engine - Scheduled/on-demand security playbooks backed by SQLite."""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now


class AutomationEngineModule:
    """Stores and executes repeatable multi-step BLACKVEIL security playbooks."""

    def __init__(self, console: Console, logger: BlackveilLogger, db: DatabaseManager) -> None:
        self.console = console
        self.logger = logger
        self.db = db

    def create_playbook(self, name: str, commands: list[str], description: str = "") -> str | None:
        clean_name = name.strip().lower()
        if not clean_name or not commands:
            self.console.print("[bold red][-][/] Provide both playbook name and at least one command.")
            return None

        pb_id = f"AUTO-{uuid.uuid4().hex[:8].upper()}"
        with self.db.connection() as conn:
            existing = conn.execute("SELECT id FROM automation_playbooks WHERE name = ?", (clean_name,)).fetchone()
            if existing:
                self.console.print(f"[bold red][-][/] Playbook '{clean_name}' already exists.")
                return None
            conn.execute(
                """
                INSERT INTO automation_playbooks (id, name, description, commands_json, enabled, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (pb_id, clean_name, description or f"Playbook ({len(commands)} steps)", json.dumps(commands), utc_now()),
            )
        self.console.print(f"[bold bright_green][+][/] Automation playbook [white]'{clean_name}'[/] created ({pb_id}, {len(commands)} step(s)).")
        return pb_id

    def list_playbooks(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM automation_playbooks ORDER BY created_at DESC").fetchall()]
        if not rows:
            self.console.print("[grey70][*] No automation playbooks created yet. Use `automation create --name daily-audit --commands \"audit firewall; deps audit\"`.[/]")
            return []

        table = Table(title="[bold bright_green]AUTOMATION PLAYBOOKS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("ID", style="bright_green", width=14)
        table.add_column("Name", style="white")
        table.add_column("State", width=10)
        table.add_column("Steps", justify="right", width=6)
        table.add_column("Last Run", style="grey70", width=19)

        for r in rows:
            cmds = json.loads(r["commands_json"])
            st = "[bright_green]ENABLED[/]" if r["enabled"] else "[grey50]DISABLED[/]"
            table.add_row(r["id"], r["name"], st, str(len(cmds)), (r["last_run_at"] or "-")[:19])
        self.console.print(table)
        return rows

    def run_playbook(self, target: str, executor: Callable[[str], int]) -> bool:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM automation_playbooks WHERE id = ? OR name = ?",
                (target, target.strip().lower()),
            ).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Playbook '{target}' not found.")
            return False
        if not row["enabled"]:
            self.console.print(f"[bold yellow][!][/] Playbook '{row['name']}' is disabled.")
            return False

        commands: list[str] = json.loads(row["commands_json"])
        started = utc_now()
        ok_count = 0
        self.console.print(f"[bright_green][*][/] Running playbook [white]{row['name']}[/] ({len(commands)} steps)...")

        for idx, cmd_line in enumerate(commands, start=1):
            if cmd_line.strip().lower().startswith("automation run"):
                self.console.print("[bold red][-][/] Recursive `automation run` blocked.")
                continue
            self.console.print(f"[grey70]  [{idx}/{len(commands)}] -> {cmd_line}[/]")
            rc = executor(cmd_line)
            if rc == 0:
                ok_count += 1

        finished = utc_now()
        status = "SUCCESS" if ok_count == len(commands) else "PARTIAL"
        summary = f"{ok_count}/{len(commands)} steps succeeded"
        with self.db.connection() as conn:
            conn.execute("UPDATE automation_playbooks SET last_run_at = ? WHERE id = ?", (finished, row["id"]))
            conn.execute(
                "INSERT INTO automation_runs (playbook_id, status, summary, started_at, finished_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], status, summary, started, finished),
            )
        self.console.print(f"[bold bright_green][+][/] Playbook finished: {summary}")
        return ok_count == len(commands)

    def history(self, limit: int = 20) -> None:
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT r.*, p.name FROM automation_runs r
                JOIN automation_playbooks p ON p.id = r.playbook_id
                ORDER BY r.id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        if not rows:
            self.console.print("[grey70][*] No automation run history recorded.[/]")
            return
        table = Table(title="[bold bright_green]AUTOMATION RUN HISTORY[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Run#", width=5, justify="right", style="grey70")
        table.add_column("Playbook", style="white")
        table.add_column("Status", width=10)
        table.add_column("Summary", style="bright_green")
        table.add_column("Finished", style="grey70", width=19)
        for r in rows:
            table.add_row(str(r["id"]), r["name"], r["status"], r["summary"], r["finished_at"][:19])
        self.console.print(table)

    def disable(self, target: str) -> bool:
        with self.db.connection() as conn:
            cur = conn.execute(
                "UPDATE automation_playbooks SET enabled = 0 WHERE id = ? OR name = ?",
                (target, target.strip().lower()),
            )
            if cur.rowcount == 0:
                self.console.print(f"[bold red][-][/] Playbook '{target}' not found.")
                return False
        self.console.print(f"[bright_green][+][/] Playbook '{target}' disabled.")
        return True

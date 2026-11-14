"""Module 10: Incident Response Engine - SQLite incident tracking, investigation notes, timeline & closure."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class IncidentResponseModule:
    """Manages structured SOC incident response tickets and timelines."""

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

    def create(self, title: str, severity: str = "HIGH", summary: str = "") -> str:
        inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        sev = severity.upper()
        if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            sev = "MEDIUM"
        now = utc_now()
        timeline = [{"timestamp": now, "action": "INCIDENT_OPENED", "note": summary or title}]

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO incidents (id, title, severity, status, summary, assignee, timeline_json, artifacts_json, created_at)
                VALUES (?, ?, ?, 'OPEN', ?, 'SOC_ANALYST', ?, '[]', ?)
                """,
                (inc_id, title, sev, summary or title, json.dumps(timeline), now),
            )
        self.console.print(f"[bold bright_green][+][/] Incident created: [white]{inc_id}[/] ([bold {'red' if sev in {'HIGH', 'CRITICAL'} else 'yellow'}]{sev}[/]) - {title}")
        self.reports.record("INCIDENT_CREATED", f"Incident {inc_id}: {title}", {"id": inc_id, "severity": sev, "summary": summary}, severity=sev)
        return inc_id

    def list_incidents(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()]
        if not rows:
            self.console.print("[grey70][*] No incidents logged. Create one with `incident create --title \"...\"`.[/]")
            return []

        table = Table(title="[bold bright_green]INCIDENT RESPONSE QUEUE[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Incident ID", style="bright_green", width=19)
        table.add_column("Severity", width=10)
        table.add_column("Status", width=14)
        table.add_column("Title", style="white")
        table.add_column("Created", style="grey70", width=19)

        for r in rows:
            scol = "bold red" if r["severity"] in {"CRITICAL", "HIGH"} else "yellow"
            stcol = "bright_green" if r["status"] == "CLOSED" else "bold yellow"
            table.add_row(r["id"], f"[{scol}]{r['severity']}[/]", f"[{stcol}]{r['status']}[/]", r["title"], r["created_at"][:19])
        self.console.print(table)
        return rows

    def investigate(self, inc_id: str, note: str, artifact: str | None = None) -> bool:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
            if not row:
                self.console.print(f"[bold red][-][/] Incident '{inc_id}' not found.")
                return False
            timeline = json.loads(row["timeline_json"])
            artifacts = json.loads(row["artifacts_json"])
            timeline.append({"timestamp": utc_now(), "action": "INVESTIGATION_NOTE", "note": note})
            if artifact:
                artifacts.append(artifact)
            conn.execute(
                "UPDATE incidents SET status = 'INVESTIGATING', timeline_json = ?, artifacts_json = ? WHERE id = ?",
                (json.dumps(timeline), json.dumps(artifacts), inc_id),
            )
        self.console.print(f"[bright_green][+][/] Updated incident [white]{inc_id}[/] -> INVESTIGATING.")
        return True

    def timeline(self, inc_id: str) -> None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Incident '{inc_id}' not found.")
            return
        tl = json.loads(row["timeline_json"])
        table = Table(title=f"[bold bright_green]INCIDENT TIMELINE // {inc_id} ({row['title']})[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Timestamp", style="grey70", width=20)
        table.add_column("Action", style="bright_green", width=20)
        table.add_column("Details", style="white")
        for ev in tl:
            table.add_row(ev["timestamp"][:19], ev["action"], ev["note"])
        self.console.print(table)

    def close(self, inc_id: str, resolution: str = "Contained and remediated") -> bool:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
            if not row:
                self.console.print(f"[bold red][-][/] Incident '{inc_id}' not found.")
                return False
            timeline = json.loads(row["timeline_json"])
            now = utc_now()
            timeline.append({"timestamp": now, "action": "INCIDENT_CLOSED", "note": resolution})
            conn.execute(
                "UPDATE incidents SET status = 'CLOSED', timeline_json = ?, closed_at = ? WHERE id = ?",
                (json.dumps(timeline), now, inc_id),
            )
        self.console.print(Panel(f"[bright_green][+] Incident {inc_id} CLOSED[/]\n[white]Resolution:[/] {resolution}", border_style="bright_green", box=box.SQUARE))
        self.reports.record("INCIDENT_CLOSED", f"Incident Closed: {inc_id}", {"id": inc_id, "resolution": resolution})
        return True

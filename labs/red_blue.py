"""Module 20: Red Team / Blue Team Purple Exercise Engine (Strictly Isolated Lab)."""

from __future__ import annotations

import json
import secrets
import shutil
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import SANDBOX_DATA_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.forensics import ForensicsModule
from modules.reports import ReportManager


class RedBlueTeamModule:
    """Runs Red Team controlled simulations inside an isolated lab and Blue Team real detection analysis."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        reports: ReportManager,
        forensics: ForensicsModule,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.reports = reports
        self.forensics = forensics
        self.lab_dir = SANDBOX_DATA_DIR / "purple_team_lab"
        self.state_file = self.lab_dir / "exercise_state.json"

    def _ensure_lab(self) -> None:
        self.lab_dir.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {"red_executed": False, "blue_executed": False, "ttps_simulated": [], "ttps_detected": [], "score": 0}
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {"red_executed": False, "blue_executed": False, "ttps_simulated": [], "ttps_detected": [], "score": 0}

    def _save_state(self, state: dict[str, Any]) -> None:
        self._ensure_lab()
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def redteam_start(self, scenario: str = "full-chain") -> dict[str, Any]:
        """Execute controlled Red Team offensive telemetry strictly inside data/sandbox/purple_team_lab."""
        self._ensure_lab()
        telemetry_log = self.lab_dir / "purple_telemetry.log"
        payload_file = self.lab_dir / "staged_dropper.bin"
        config_drop = self.lab_dir / "leaked_service.env"

        # 1. Simulate SSH/RDP credential spray log entries (RFC 5737 test IP)
        # 2. Simulate encoded PowerShell execution event
        # 3. Drop high-entropy staged payload disguised with .txt extension
        # 4. Drop dummy credential file
        log_entries = [
            f"{utc_now()} | AUTH | src=198.51.100.77 user=admin status=FAILED_AUTH",
            f"{utc_now()} | AUTH | src=198.51.100.77 user=admin status=FAILED_AUTH",
            f"{utc_now()} | AUTH | src=198.51.100.77 user=admin status=FAILED_AUTH",
            f"{utc_now()} | AUTH | src=198.51.100.77 user=admin status=FAILED_AUTH",
            f"{utc_now()} | AUTH | src=198.51.100.77 user=admin status=FAILED_AUTH",
            f"{utc_now()} | PROC | parent=winword.exe child=powershell.exe cmd='powershell -EncodedCommand SQBFAFgA'",
            f"{utc_now()} | WEB  | src=198.51.100.77 uri='/api/export?file=../../etc/passwd' code=403",
        ]
        telemetry_log.write_text("\n".join(log_entries) + "\n", encoding="utf-8")
        # High-entropy binary drop
        payload_file.write_bytes(b"MZ" + secrets.token_bytes(2048))
        config_drop.write_text("LAB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n", encoding="utf-8")

        ttps = ["T1110 Brute Force", "T1059.001 Encoded PowerShell", "T1083 Path Traversal", "T1027 High-Entropy Dropper"]
        state = {
            "red_executed": True,
            "red_timestamp": utc_now(),
            "scenario": scenario,
            "blue_executed": False,
            "ttps_simulated": ttps,
            "ttps_detected": [],
            "score": 0,
        }
        self._save_state(state)

        self.console.print(
            Panel(
                f"[bold red][RED TEAM][/] Controlled adversary emulation deployed inside [white]{self.lab_dir}[/]\n"
                f"[white]Simulated TTPs:[/] {', '.join(ttps)}\n"
                f"[grey70]Next step: Run `blueteam start` to execute Blue Team detection & correlation.[/]",
                title="[bold red]RED TEAM // ADVERSARY EMULATION[/]",
                border_style="red",
                box=box.SQUARE,
            )
        )
        return state

    def blueteam_start(self) -> dict[str, Any]:
        """Run real Blue Team detectors against the sandboxed Red Team artifacts & logs."""
        state = self._load_state()
        if not state.get("red_executed"):
            self.console.print("[yellow][!][/] No active Red Team exercise found. Run `redteam start` first.")
            return {}

        detected: list[str] = []
        telemetry_log = self.lab_dir / "purple_telemetry.log"
        payload_file = self.lab_dir / "staged_dropper.bin"

        if telemetry_log.exists():
            text = telemetry_log.read_text(encoding="utf-8", errors="replace")
            if text.count("FAILED_AUTH") >= 5:
                detected.append("T1110 Brute Force")
            if "EncodedCommand" in text or "winword.exe" in text:
                detected.append("T1059.001 Encoded PowerShell")
            if "../../" in text:
                detected.append("T1083 Path Traversal")

        if payload_file.exists():
            raw = payload_file.read_bytes()
            entropy = self.forensics.calculate_entropy(raw)
            if entropy >= 7.0 and raw[:2] == b"MZ":
                detected.append("T1027 High-Entropy Dropper")

        simulated = state.get("ttps_simulated", [])
        rate = round((len(detected) / max(1, len(simulated))) * 100.0, 1)
        state["blue_executed"] = True
        state["blue_timestamp"] = utc_now()
        state["ttps_detected"] = detected
        state["score"] = int(rate)
        self._save_state(state)

        self.db.record_lab_result("PURPLE_TEAM", "RED_BLUE_DRILL", "COMPLETED", int(rate), state)

        table = Table(
            title=f"[bold bright_green]BLUE TEAM // DETECTION TELEMETRY ({rate}% COVERAGE)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("MITRE ATT&CK TTP", style="white")
        table.add_column("Blue Team Verdict", width=16)

        for ttp in simulated:
            hit = ttp in detected
            table.add_row(ttp, "[bold bright_green]DETECTED[/]" if hit else "[bold red]MISSED[/]")
        self.console.print(table)

        self.reports.record("RED_BLUE_EXERCISE", f"Purple Team Exercise ({rate}% Detection)", state, severity="INFO")
        return state

    def status(self) -> dict[str, Any]:
        state = self._load_state()
        self.console.print(
            Panel(
                f"[white]Lab Workspace :[/] {self.lab_dir}\n"
                f"[white]Red Team Run  :[/] {'[bold red]ACTIVE[/]' if state.get('red_executed') else '[grey70]IDLE[/]'}\n"
                f"[white]Blue Team Run :[/] {'[bold bright_green]ANALYZED[/]' if state.get('blue_executed') else '[grey70]PENDING[/]'}\n"
                f"[white]Detection Rate:[/] [bright_green]{state.get('score', 0)}%[/]",
                title="[bold bright_green]RED / BLUE TEAM STATUS[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return state

    def report(self, fmt: str = "json") -> None:
        state = self._load_state()
        self.reports.record("PURPLE_TEAM_REPORT", "Red Team vs Blue Team After-Action Report", state)
        self.reports.export_report(export_format=fmt, export_all=False)

    def reset(self) -> None:
        if self.lab_dir.exists():
            shutil.rmtree(self.lab_dir, ignore_errors=True)
        self.console.print("[bright_green][+][/] Red/Blue Team lab workspace reset cleanly.")

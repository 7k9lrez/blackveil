"""Section 4: Mission, XP, Level, Rank & Achievement Progression System."""

from __future__ import annotations

import hashlib
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now


MISSIONS_CATALOG: list[dict[str, Any]] = [
    {
        "id": "MIS-BEG-01",
        "title": "Host Reconnaissance Baseline",
        "difficulty": "BEGINNER",
        "xp": 100,
        "objective": "Run `intel --system` and submit your local hostname (e.g. from Hostname field).",
        "hint": "Use `intel --system` and check the Hostname / FQDN row.",
        "verify_mode": "hostname",
    },
    {
        "id": "MIS-BEG-02",
        "title": "Cryptographic Integrity Check",
        "difficulty": "BEGINNER",
        "xp": 120,
        "objective": "Compute SHA-256 of the literal string `BLACKVEIL_OP` using `hash --text BLACKVEIL_OP` and submit the first 12 hex characters.",
        "hint": "Run `hash --text BLACKVEIL_OP` and copy the first 12 characters of SHA-256.",
        "verify_sha256": hashlib.sha256(hashlib.sha256(b"BLACKVEIL_OP").hexdigest()[:12].encode()).hexdigest(),
    },
    {
        "id": "MIS-INT-01",
        "title": "Entropy & Password Hardening",
        "difficulty": "INTERMEDIATE",
        "xp": 200,
        "objective": "Run `password --dict-test` and identify which default password matched inside `data/common_passwords.txt`.",
        "hint": "Execute `password --dict-test` without arguments.",
        "verify_sha256": hashlib.sha256(b"letmein123").hexdigest(),
    },
    {
        "id": "MIS-INT-02",
        "title": "Cyber War Room Incident Drill",
        "difficulty": "INTERMEDIATE",
        "xp": 250,
        "objective": "Execute `simulate --scenario brute-force` and submit the RFC5737 attacker IP flagged in the detection table.",
        "hint": "Look at the Source column in the Brute-Force Detection Results table.",
        "verify_sha256": hashlib.sha256(b"198.51.100.44").hexdigest(),
    },
    {
        "id": "MIS-ADV-01",
        "title": "Log Forensics & MITRE TTP Hunt",
        "difficulty": "ADVANCED",
        "xp": 350,
        "objective": "Run `simulate --scenario log-analysis` followed by `ai analyze` and submit the MITRE PowerShell sub-technique ID (e.g. TXXXX.XXX).",
        "hint": "Format starts with T1059...",
        "verify_sha256": hashlib.sha256(b"T1059.001").hexdigest(),
    },
]

ACHIEVEMENTS_CATALOG: list[tuple[str, str, str, int]] = [
    ("ACH-FIRST-BLOOD", "First Contact", "Complete your first BLACKVEIL mission.", 50),
    ("ACH-TRIPLE-THREAT", "Operational Specialist", "Complete 3 cybersecurity missions.", 150),
    ("ACH-MASTER-OP", "Shadow Architect", "Reach Operator Level 3 or complete all 5 missions.", 300),
    ("ACH-CTF-SOLVER", "Flag Hunter", "Solve at least 1 CTF challenge.", 100),
]


class MissionManager:
    """Manages Beginner/Intermediate/Advanced missions, XP, levels, achievements, and profile."""

    def __init__(self, console: Console, logger: BlackveilLogger, db: DatabaseManager) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self._seed_catalog()

    def _seed_catalog(self) -> None:
        with self.db.connection() as conn:
            for m in MISSIONS_CATALOG:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO missions_progress (mission_id, title, difficulty, status, xp_awarded, attempts)
                    VALUES (?, ?, ?, 'AVAILABLE', 0, 0)
                    """,
                    (m["id"], m["title"], m["difficulty"]),
                )
            for aid, title, desc, bonus in ACHIEVEMENTS_CATALOG:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO achievements (id, title, description, xp_bonus, unlocked_at)
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (aid, title, desc, bonus),
                )

    @staticmethod
    def _rank_for_level(level: int) -> str:
        if level >= 8:
            return "Blackveil Phantom Director"
        if level >= 5:
            return "Principal Threat Architect"
        if level >= 3:
            return "Senior Cyber Operator"
        if level >= 2:
            return "Field Security Analyst"
        return "Initiate Analyst"

    def award_xp(self, amount: int, reason: str, ctf_increment: int = 0, mission_increment: int = 0) -> dict[str, Any]:
        """Add XP, recompute level/rank, and evaluate achievement unlocks."""
        with self.db.connection() as conn:
            prof = dict(conn.execute("SELECT * FROM operator_profile WHERE id = 1").fetchone())
            new_xp = int(prof["xp"]) + amount
            new_level = max(1, (new_xp // 250) + 1)
            new_rank = self._rank_for_level(new_level)
            new_missions = int(prof["missions_completed"]) + mission_increment
            new_ctf = int(prof["ctf_solved"]) + ctf_increment

            conn.execute(
                """
                UPDATE operator_profile
                SET xp = ?, level = ?, rank_title = ?, missions_completed = ?, ctf_solved = ?, updated_at = ?
                WHERE id = 1
                """,
                (new_xp, new_level, new_rank, new_missions, new_ctf, utc_now()),
            )

        self._evaluate_achievements()
        self.logger.info("missions", f"Awarded {amount} XP ({reason})")
        return {"xp": new_xp, "level": new_level, "rank": new_rank}

    def _evaluate_achievements(self) -> None:
        with self.db.connection() as conn:
            prof = dict(conn.execute("SELECT * FROM operator_profile WHERE id = 1").fetchone())
            unlocks: list[str] = []
            if prof["missions_completed"] >= 1:
                unlocks.append("ACH-FIRST-BLOOD")
            if prof["missions_completed"] >= 3:
                unlocks.append("ACH-TRIPLE-THREAT")
            if prof["level"] >= 3 or prof["missions_completed"] >= len(MISSIONS_CATALOG):
                unlocks.append("ACH-MASTER-OP")
            if prof["ctf_solved"] >= 1:
                unlocks.append("ACH-CTF-SOLVER")

            for aid in unlocks:
                row = conn.execute("SELECT unlocked_at, title, xp_bonus FROM achievements WHERE id = ?", (aid,)).fetchone()
                if row and row["unlocked_at"] is None:
                    conn.execute("UPDATE achievements SET unlocked_at = ? WHERE id = ?", (utc_now(), aid))
                    conn.execute("UPDATE operator_profile SET xp = xp + ? WHERE id = 1", (row["xp_bonus"],))
                    self.console.print(f"[bold bright_green][★ ACHIEVEMENT UNLOCKED][/] {row['title']} (+{row['xp_bonus']} XP)")

    def list_missions(self) -> None:
        with self.db.connection() as conn:
            rows = {r["mission_id"]: dict(r) for r in conn.execute("SELECT * FROM missions_progress").fetchall()}

        table = Table(
            title="[bold bright_green]BLACKVEIL OPERATIONS // MISSIONS BOARD[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green", width=11)
        table.add_column("Difficulty", width=13)
        table.add_column("Title", style="white")
        table.add_column("XP", justify="right", width=6)
        table.add_column("Status", width=12)

        for m in MISSIONS_CATALOG:
            prog = rows.get(m["id"], {})
            status = prog.get("status", "AVAILABLE")
            st_col = "bold bright_green" if status == "COMPLETED" else "yellow" if status == "ACTIVE" else "grey70"
            diff_col = "bright_green" if m["difficulty"] == "BEGINNER" else "yellow" if m["difficulty"] == "INTERMEDIATE" else "bold red"
            table.add_row(m["id"], f"[{diff_col}]{m['difficulty']}[/]", m["title"], str(m["xp"]), f"[{st_col}]{status}[/]")
        self.console.print(table)

    def _find_mission(self, mission_id: str) -> dict[str, Any] | None:
        key = mission_id.strip().upper()
        for m in MISSIONS_CATALOG:
            if m["id"] == key:
                return m
        self.console.print(f"[bold red][-][/] Mission '{mission_id}' not found.")
        return None

    def start_mission(self, mission_id: str) -> bool:
        m = self._find_mission(mission_id)
        if not m:
            return False
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE missions_progress SET status = CASE WHEN status = 'COMPLETED' THEN 'COMPLETED' ELSE 'ACTIVE' END, started_at = COALESCE(started_at, ?) WHERE mission_id = ?",
                (utc_now(), m["id"]),
            )
        self.inspect_mission(m["id"])
        return True

    def inspect_mission(self, mission_id: str) -> None:
        m = self._find_mission(mission_id)
        if not m:
            return
        with self.db.connection() as conn:
            prog = dict(conn.execute("SELECT * FROM missions_progress WHERE mission_id = ?", (m["id"],)).fetchone())
        self.console.print(
            Panel(
                f"[white]Mission ID :[/] [bright_green]{m['id']}[/] ({m['difficulty']})\n"
                f"[white]Title      :[/] {m['title']}\n"
                f"[white]Reward     :[/] [bright_green]+{m['xp']} XP[/]\n"
                f"[white]Status     :[/] {prog['status']} (Attempts: {prog['attempts']})\n"
                f"[white]Objective  :[/] {m['objective']}\n"
                f"[grey70]Hint       : {m['hint']}[/]",
                title="[bold bright_green]MISSION BRIEFING[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

    def submit_mission(self, mission_id: str, answer: str) -> bool:
        import socket

        m = self._find_mission(mission_id)
        if not m:
            return False

        with self.db.connection() as conn:
            prog = dict(conn.execute("SELECT * FROM missions_progress WHERE mission_id = ?", (m["id"],)).fetchone())
            conn.execute("UPDATE missions_progress SET attempts = attempts + 1 WHERE mission_id = ?", (m["id"],))

        cleaned = answer.strip()
        if m.get("verify_mode") == "hostname":
            valid = cleaned.lower() == socket.gethostname().lower()
        else:
            digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
            valid = digest == m.get("verify_sha256")

        if not valid:
            self.console.print(f"[bold red][-][/] Incorrect submission for {m['id']}. Review hint and try again.")
            return False

        if prog["status"] == "COMPLETED":
            self.console.print(f"[bright_green][+][/] Valid answer! Mission {m['id']} was already completed earlier.")
            return True

        with self.db.connection() as conn:
            conn.execute(
                "UPDATE missions_progress SET status = 'COMPLETED', xp_awarded = ?, completed_at = ? WHERE mission_id = ?",
                (m["xp"], utc_now(), m["id"]),
            )
        self.console.print(f"[bold bright_green][+] MISSION COMPLETED: {m['title']} (+{m['xp']} XP)[/]")
        self.award_xp(m["xp"], f"Completed mission {m['id']}", mission_increment=1)
        return True

    def show_history(self) -> None:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM missions_progress WHERE status != 'AVAILABLE' ORDER BY COALESCE(completed_at, started_at) DESC"
            ).fetchall()
        if not rows:
            self.console.print("[grey70][*] No missions started or completed yet. Run `mission start MIS-BEG-01`.[/]")
            return
        table = Table(title="[bold bright_green]MISSION HISTORY[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("ID", style="bright_green")
        table.add_column("Title", style="white")
        table.add_column("Status", width=11)
        table.add_column("XP", justify="right")
        table.add_column("Completed", style="grey70")
        for r in rows:
            table.add_row(r["mission_id"], r["title"], r["status"], str(r["xp_awarded"]), (r["completed_at"] or "-")[:19])
        self.console.print(table)

    def show_profile(self, detailed: bool = False) -> dict[str, Any]:
        with self.db.connection() as conn:
            prof = dict(conn.execute("SELECT * FROM operator_profile WHERE id = 1").fetchone())
            unlocked = conn.execute("SELECT COUNT(*) AS cnt FROM achievements WHERE unlocked_at IS NOT NULL").fetchone()["cnt"]

        next_lvl_xp = prof["level"] * 250
        self.console.print(
            Panel(
                f"[white]Operator Codename :[/] [bold bright_green]{prof['codename']}[/]\n"
                f"[white]Rank Title        :[/] [bright_green]{prof['rank_title']}[/]\n"
                f"[white]Level             :[/] [bold bright_green]{prof['level']}[/]\n"
                f"[white]Total XP          :[/] {prof['xp']} / {next_lvl_xp} (next level)\n"
                f"[white]Missions Completed:[/] {prof['missions_completed']} / {len(MISSIONS_CATALOG)}\n"
                f"[white]CTF Solved        :[/] {prof['ctf_solved']}\n"
                f"[white]Achievements      :[/] {unlocked} / {len(ACHIEVEMENTS_CATALOG)}",
                title="[bold bright_green]OPERATOR PROFILE[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        if detailed:
            self.show_achievements()
        return prof

    def show_achievements(self) -> None:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM achievements ORDER BY unlocked_at IS NULL, id").fetchall()
        table = Table(title="[bold bright_green]ACHIEVEMENTS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("ID", style="grey70", width=18)
        table.add_column("Title", style="white")
        table.add_column("Description", style="grey70")
        table.add_column("Bonus", justify="right", width=7)
        table.add_column("State", width=14)
        for r in rows:
            st = f"[bold bright_green]UNLOCKED[/]" if r["unlocked_at"] else "[grey50]LOCKED[/]"
            table.add_row(r["id"], r["title"], r["description"], f"+{r['xp_bonus']}", st)
        self.console.print(table)

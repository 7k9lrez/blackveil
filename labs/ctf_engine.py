"""Module 16: Local & Isolated CTF Challenge Engine."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import LABS_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from missions.manager import MissionManager


def _build_flag(parts: tuple[str, ...]) -> str:
    return "BV{" + "_".join(parts) + "}"


CTF_CHALLENGES: list[dict[str, Any]] = [
    {
        "id": "CTF-01",
        "title": "Base64 Dropper Artifact",
        "category": "Forensics",
        "difficulty": "BEGINNER",
        "points": 100,
        "description": "Inspect the suspicious payload file in your CTF workspace and decode the hidden operator token.",
        "hint": "The file `dropper_note.txt` contains a Base64-encoded string.",
        "flag_sha256": hashlib.sha256(_build_flag(("DECODED", "PAYLOAD", "101")).encode()).hexdigest(),
        "artifact_name": "dropper_note.txt",
        "artifact_builder": lambda: (
            "Suspicious Script Dropper Excerpt:\n"
            "EncodedBlob=" + base64.b64encode(_build_flag(("DECODED", "PAYLOAD", "101")).encode()).decode() + "\n"
        ),
    },
    {
        "id": "CTF-02",
        "title": "Magic Byte Masquerade",
        "category": "Digital Forensics",
        "difficulty": "INTERMEDIATE",
        "points": 200,
        "description": "A binary artifact claims to be a harmless `.jpg`, but its magic header reveals its true identity. Use `forensic --file` to verify.",
        "hint": "Look at the ASCII string embedded after the PNG signature inside `evidence_photo.jpg`.",
        "flag_sha256": hashlib.sha256(_build_flag(("MAGIC", "HEADER", "MISMATCH")).encode()).hexdigest(),
        "artifact_name": "evidence_photo.jpg",
        "artifact_builder": lambda: (
            b"\x89PNG\r\n\x1a\n"
            + b"IHDR"
            + b"\x00" * 12
            + ("FORENSIC_TAG=" + _build_flag(("MAGIC", "HEADER", "MISMATCH"))).encode("ascii")
        ),
    },
    {
        "id": "CTF-03",
        "title": "SOC Intrusion Timeline",
        "category": "Log Forensics",
        "difficulty": "INTERMEDIATE",
        "points": 250,
        "description": "Analyze `auth_breach.log` using `logs analyze` to extract the exfiltrated token left by the intruder.",
        "hint": "Search for the line containing `EXFIL_MARKER` inside `auth_breach.log`.",
        "flag_sha256": hashlib.sha256(_build_flag(("TIMELINE", "CONTAINED", "2026")).encode()).hexdigest(),
        "artifact_name": "auth_breach.log",
        "artifact_builder": lambda: (
            "2026-11-14 02:10:00 INFO sshd: session opened for ops\n"
            "2026-11-14 02:11:12 WARN sshd: Failed password for admin from 203.0.113.55\n"
            "2026-11-14 02:11:19 WARN sshd: Failed password for admin from 203.0.113.55\n"
            f"2026-11-14 02:12:04 CRIT auditd: EXFIL_MARKER={_build_flag(('TIMELINE', 'CONTAINED', '2026'))}\n"
        ),
    },
]


class CTFEngineModule:
    """Delivers real local CTF challenges with workspace artifacts, hints, flag hashing, and scoreboard."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        missions: MissionManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.missions = missions
        self.ws_root = LABS_DIR / "ctf_workspaces"
        self.ws_root.mkdir(parents=True, exist_ok=True)
        self._seed_challenges()

    def _seed_challenges(self) -> None:
        with self.db.connection() as conn:
            for ch in CTF_CHALLENGES:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ctf_challenges (id, title, category, difficulty, points, solved, attempts)
                    VALUES (?, ?, ?, ?, ?, 0, 0)
                    """,
                    (ch["id"], ch["title"], ch["category"], ch["difficulty"], ch["points"]),
                )

    def _find(self, cid: str) -> dict[str, Any] | None:
        key = cid.strip().upper()
        for ch in CTF_CHALLENGES:
            if ch["id"] == key:
                return ch
        self.console.print(f"[bold red][-][/] CTF challenge '{cid}' not found.")
        return None

    def list_challenges(self) -> None:
        with self.db.connection() as conn:
            rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM ctf_challenges").fetchall()}

        table = Table(
            title="[bold bright_green]BLACKVEIL CTF ARENA // LOCAL CHALLENGES[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green", width=9)
        table.add_column("Category", style="grey70", width=18)
        table.add_column("Difficulty", width=13)
        table.add_column("Title", style="white")
        table.add_column("Pts", justify="right", width=6)
        table.add_column("Status", width=10)

        for ch in CTF_CHALLENGES:
            st = rows.get(ch["id"], {})
            solved = bool(st.get("solved"))
            table.add_row(
                ch["id"],
                ch["category"],
                ch["difficulty"],
                ch["title"],
                str(ch["points"]),
                "[bold bright_green]SOLVED[/]" if solved else "[grey70]OPEN[/]",
            )
        self.console.print(table)

    def start_challenge(self, cid: str) -> Path | None:
        ch = self._find(cid)
        if not ch:
            return None
        ws = self.ws_root / ch["id"]
        ws.mkdir(parents=True, exist_ok=True)
        artifact_path = ws / ch["artifact_name"]
        content = ch["artifact_builder"]()
        if isinstance(content, bytes):
            artifact_path.write_bytes(content)
        else:
            artifact_path.write_text(content, encoding="utf-8")

        self.console.print(
            Panel(
                f"[white]Challenge :[/] [bold bright_green]{ch['id']}[/] - {ch['title']} ({ch['points']} pts)\n"
                f"[white]Category  :[/] {ch['category']} | {ch['difficulty']}\n"
                f"[white]Task      :[/] {ch['description']}\n"
                f"[white]Artifact  :[/] [bright_green]{artifact_path}[/]\n"
                f"[grey70]Submit flag with: ctf submit {ch['id']} <BV{{...}}>[/]",
                title="[bold bright_green]CTF BRIEFING[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return artifact_path

    def hint(self, cid: str) -> None:
        ch = self._find(cid)
        if ch:
            self.console.print(f"[yellow][HINT {ch['id']}][/] {ch['hint']}")

    def submit(self, cid: str, flag: str) -> bool:
        ch = self._find(cid)
        if not ch:
            return False
        with self.db.connection() as conn:
            row = dict(conn.execute("SELECT * FROM ctf_challenges WHERE id = ?", (ch["id"],)).fetchone())
            conn.execute("UPDATE ctf_challenges SET attempts = attempts + 1 WHERE id = ?", (ch["id"],))

        submitted_hash = hashlib.sha256(flag.strip().encode("utf-8")).hexdigest()
        if submitted_hash != ch["flag_sha256"]:
            self.console.print(f"[bold red][-][/] Incorrect flag for {ch['id']}.")
            return False

        if row["solved"]:
            self.console.print(f"[bright_green][+][/] Flag verified! {ch['id']} was already solved.")
            return True

        with self.db.connection() as conn:
            conn.execute("UPDATE ctf_challenges SET solved = 1, solved_at = ? WHERE id = ?", (utc_now(), ch["id"]))
        self.db.record_lab_result("CTF", ch["id"], "SOLVED", ch["points"], {"title": ch["title"]})
        self.console.print(f"[bold bright_green][+] FLAG ACCEPTED! +{ch['points']} pts & XP awarded![/]")
        self.missions.award_xp(ch["points"], f"Solved CTF {ch['id']}", ctf_increment=1)
        return True

    def scoreboard(self) -> None:
        with self.db.connection() as conn:
            prof = dict(conn.execute("SELECT * FROM operator_profile WHERE id = 1").fetchone())
            rows = conn.execute("SELECT * FROM ctf_challenges ORDER BY id").fetchall()

        total_pts = sum(int(r["points"]) for r in rows if r["solved"])
        table = Table(
            title="[bold bright_green]CTF SCOREBOARD & OPERATOR STANDING[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Operator", style="bright_green")
        table.add_column("Rank", style="white")
        table.add_column("CTF Solved", justify="right")
        table.add_column("CTF Score", justify="right", style="bright_green")
        table.add_column("Total XP", justify="right", style="white")

        table.add_row(
            prof["codename"],
            prof["rank_title"],
            f"{prof['ctf_solved']} / {len(rows)}",
            f"{total_pts} pts",
            str(prof["xp"]),
        )
        self.console.print(table)

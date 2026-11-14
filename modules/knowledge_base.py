"""Module 18: Knowledge Base - Searchable cybersecurity notes, TTP references & export."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import REPORTS_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now


SEED_KB_ARTICLES: list[tuple[str, str, str, str, str]] = [
    (
        "KB-001",
        "MITRE T1110 - Brute Force Defense",
        "Detection",
        "mitre,auth,brute-force,soc",
        "Detect credential brute-force by correlating >=5 failed logins within 10s per source IP (Event ID 4625 on Windows / sshd Failed password on Linux). Mitigate with MFA, rate-limiting, and account lockout thresholds.",
    ),
    (
        "KB-002",
        "Shannon Entropy & Binary Packing",
        "Forensics",
        "entropy,forensics,pe,malware",
        "Unpacked native executables typically score 5.0-6.6 bits/byte in Shannon entropy. Scores above 7.2 strongly suggest compression, UPX packing, or encrypted payloads.",
    ),
    (
        "KB-003",
        "Docker Sandbox Isolation Checklist",
        "Infrastructure",
        "docker,sandbox,containers,hardening",
        "Always enforce --cap-drop=ALL, --security-opt=no-new-privileges:true, --network=none (unless internal bridge required), --pids-limit, --memory, and never mount /var/run/docker.sock or host root paths.",
    ),
    (
        "KB-004",
        "Digital Evidence Chain of Custody",
        "DFIR",
        "dfir,evidence,sha256,custody",
        "Immediately acquire read-only copies of volatile artifacts, record dual SHA-256 & SHA-512 hashes with UTC timestamps, and verify hashes before and after forensic examination.",
    ),
]


class KnowledgeBaseModule:
    """SQLite-backed cybersecurity knowledge base for notes, runbooks, and TTP references."""

    def __init__(self, console: Console, logger: BlackveilLogger, db: DatabaseManager) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self._seed()

    def _seed(self) -> None:
        now = utc_now()
        with self.db.connection() as conn:
            for kid, title, cat, tags, content in SEED_KB_ARTICLES:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO knowledge_base (id, title, category, tags, content, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (kid, title, cat, tags, content, now, now),
                )

    def list_entries(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM knowledge_base ORDER BY id").fetchall()]
        table = Table(title=f"[bold bright_green]KNOWLEDGE BASE ({len(rows)} ARTICLES)[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("ID", style="bright_green", width=10)
        table.add_column("Category", style="grey70", width=16)
        table.add_column("Title", style="white")
        table.add_column("Tags", style="grey70")
        for r in rows:
            table.add_row(r["id"], r["category"], r["title"], r["tags"])
        self.console.print(table)
        return rows

    def search(self, query: str) -> list[dict[str, Any]]:
        like = f"%{query.strip()}%"
        with self.db.connection() as conn:
            rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM knowledge_base WHERE title LIKE ? OR tags LIKE ? OR content LIKE ? OR category LIKE ?",
                    (like, like, like, like),
                ).fetchall()
            ]
        if not rows:
            self.console.print(f"[grey70][*] No knowledge base articles matched '{query}'.[/]")
            return []
        for r in rows:
            self.console.print(f"[bright_green]{r['id']}[/] | [white]{r['title']}[/] ({r['category']}) — [grey70]{r['content'][:110]}...[/]")
        return rows

    def add(self, title: str, content: str, category: str = "Notes", tags: str = "operator") -> str:
        kid = f"KB-{uuid.uuid4().hex[:5].upper()}"
        now = utc_now()
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO knowledge_base (id, title, category, tags, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (kid, title, category, tags, content, now, now),
            )
        self.console.print(f"[bright_green][+][/] Added knowledge base note [white]{kid}[/]: {title}")
        return kid

    def explain(self, target: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM knowledge_base WHERE id = ? OR title LIKE ?",
                (target.upper(), f"%{target}%"),
            ).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Knowledge base entry '{target}' not found.")
            return None
        r = dict(row)
        self.console.print(
            Panel(
                f"[white]ID       :[/] [bright_green]{r['id']}[/] | [white]Category:[/] {r['category']}\n"
                f"[white]Tags     :[/] [grey70]{r['tags']}[/]\n\n"
                f"{r['content']}",
                title=f"[bold bright_green]{r['title']}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return r

    def export(self, fmt: str = "json") -> Path:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM knowledge_base ORDER BY id").fetchall()]
        out = REPORTS_DIR / f"blackveil_knowledge_base.{fmt.lower()}"
        if fmt.lower() == "json":
            out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            lines = [f"# {r['id']}: {r['title']} [{r['category']}]\nTags: {r['tags']}\n{r['content']}\n" for r in rows]
            out.write_text("\n---\n".join(lines), encoding="utf-8")
        self.console.print(f"[bright_green][+][/] Knowledge Base exported to [white]{out}[/]")
        return out

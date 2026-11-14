"""Central SQLite persistence manager with migration support for BLACKVEIL X."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from core.config import DB_FILE, ensure_directories
from database.migrations import MIGRATIONS


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DatabaseManager:
    """Thread-safe SQLite wrapper with automatic schema migrations."""

    def __init__(self, db_path: Path = DB_FILE) -> None:
        self.db_path = db_path
        ensure_directories()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.run_migrations()
        self._ensure_operator_profile()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def run_migrations(self) -> list[int]:
        """Apply any pending numbered SQLite schema migrations."""
        applied_now: list[int] = []
        with self.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                """
            )
            rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
            existing = {int(r["version"]) for r in rows}

            for version, name, sql in sorted(MIGRATIONS, key=lambda m: m[0]):
                if version not in existing:
                    conn.executescript(sql)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                        (version, name, utc_now()),
                    )
                    applied_now.append(version)
        return applied_now

    def get_schema_version(self) -> int:
        with self.connection() as conn:
            row = conn.execute("SELECT COALESCE(MAX(version), 0) AS ver FROM schema_migrations").fetchone()
            return int(row["ver"]) if row else 0

    def _ensure_operator_profile(self) -> None:
        with self.connection() as conn:
            row = conn.execute("SELECT id FROM operator_profile WHERE id = 1").fetchone()
            if not row:
                conn.execute(
                    """
                    INSERT INTO operator_profile (id, codename, xp, level, rank_title, missions_completed, ctf_solved, updated_at)
                    VALUES (1, 'BLACKVEIL@ROOT', 0, 1, 'Initiate Analyst', 0, 0, ?)
                    """,
                    (utc_now(),),
                )

    def log_security_event(self, event_id: str, source_module: str, severity: str, title: str, details: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_events (id, source_module, severity, title, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, source_module, severity.upper(), title, json.dumps(details, default=str), utc_now()),
            )

    def record_lab_result(self, lab_type: str, lab_id: str, status: str, score: int, details: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO lab_results (lab_type, lab_id, status, score, details_json, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (lab_type, lab_id, status, score, json.dumps(details, default=str), utc_now()),
            )

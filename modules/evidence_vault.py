"""Module 06: Digital Evidence Vault - Chain of Custody, SHA256/512 sealing & tamper verification."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import VAULT_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager
from modules.system_intel import format_bytes


class EvidenceVaultModule:
    """Preserves digital evidence artifacts with cryptographic hashes and immutable custody logs."""

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
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _hash_artifact(path: Path) -> tuple[str, str]:
        s256 = hashlib.sha256()
        s512 = hashlib.sha512()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 256)
                if not chunk:
                    break
                s256.update(chunk)
                s512.update(chunk)
        return s256.hexdigest(), s512.hexdigest()

    def add_evidence(self, source_path: str, description: str = "Acquired digital artifact") -> dict[str, Any] | None:
        src = Path(source_path).expanduser()
        if not src.exists() or not src.is_file():
            self.console.print(f"[bold red][-][/] Evidence source file not found: {src}")
            return None

        ev_id = f"EVD-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        sha256, sha512 = self._hash_artifact(src)
        size_bytes = src.stat().st_size
        sealed_name = f"{ev_id}_{src.name}"
        vault_file = VAULT_DIR / sealed_name
        shutil.copy2(src, vault_file)

        collector = f"{platform.node()}"
        custody_log = [
            {"timestamp": utc_now(), "action": "ACQUIRED_AND_SEALED", "actor": collector, "sha256": sha256}
        ]

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO evidence_vault
                (id, original_path, vault_path, sha256, sha512, size_bytes, collector, description, custody_log_json, sealed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev_id,
                    str(src.resolve()),
                    str(vault_file.resolve()),
                    sha256,
                    sha512,
                    size_bytes,
                    collector,
                    description,
                    json.dumps(custody_log),
                    utc_now(),
                ),
            )

        self.console.print(
            Panel(
                f"[bold bright_green][+] Evidence Sealed in Digital Vault[/]\n"
                f"[white]Evidence ID :[/] [bright_green]{ev_id}[/]\n"
                f"[white]Source      :[/] {src.resolve()}\n"
                f"[white]Vault File  :[/] {vault_file}\n"
                f"[white]Size        :[/] {format_bytes(size_bytes)}\n"
                f"[white]SHA-256     :[/] [bright_green]{sha256}[/]",
                title="[bold bright_green]DIGITAL EVIDENCE VAULT[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        res = {"id": ev_id, "sha256": sha256, "sha512": sha512, "vault_path": str(vault_file)}
        self.reports.record("EVIDENCE_VAULT", f"Evidence Acquired: {ev_id}", res)
        return res

    def list_evidence(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM evidence_vault ORDER BY sealed_at DESC").fetchall()]

        table = Table(
            title="[bold bright_green]DIGITAL EVIDENCE VAULT INVENTORY[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Evidence ID", style="bright_green", width=19)
        table.add_column("Artifact", style="white")
        table.add_column("Size", justify="right", width=11)
        table.add_column("SHA-256 (Prefix)", style="grey70", width=18)
        table.add_column("Sealed At", style="grey70", width=19)

        if not rows:
            self.console.print("[grey70][*] Evidence Vault is empty. Seal an artifact with `evidence add --file <path>`.[/]")
            return []

        for r in rows:
            table.add_row(r["id"], Path(r["vault_path"]).name, format_bytes(r["size_bytes"]), r["sha256"][:16] + "...", r["sealed_at"][:19])
        self.console.print(table)
        return rows

    def verify_evidence(self, evidence_id: str) -> bool:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM evidence_vault WHERE id = ?", (evidence_id,)).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Evidence ID '{evidence_id}' not found.")
            return False

        vpath = Path(row["vault_path"])
        if not vpath.exists():
            self.console.print(f"[bold red][-] TAMPER ALERT[/]: Vault artifact missing at {vpath}!")
            return False

        curr_256, curr_512 = self._hash_artifact(vpath)
        intact = curr_256 == row["sha256"] and curr_512 == row["sha512"]

        custody = json.loads(row["custody_log_json"])
        custody.append({"timestamp": utc_now(), "action": "INTEGRITY_VERIFIED" if intact else "TAMPER_DETECTED", "sha256": curr_256})
        with self.db.connection() as conn:
            conn.execute("UPDATE evidence_vault SET custody_log_json = ? WHERE id = ?", (json.dumps(custody), evidence_id))

        if intact:
            self.console.print(f"[bold bright_green][+] CHAIN OF CUSTODY INTACT[/]: {evidence_id} matches SHA-256 {curr_256}")
        else:
            self.console.print(f"[bold red][-] INTEGRITY VIOLATION[/]: {evidence_id} hash mismatch!")
        return intact

    def export_manifest(self, fmt: str = "json") -> None:
        rows = self.list_evidence()
        self.reports.record("EVIDENCE_MANIFEST", "Digital Evidence Vault Custody Manifest", {"count": len(rows), "items": rows})
        self.reports.export_report(export_format=fmt, export_all=False)

"""Module 04: File Integrity Guard - Recursive SHA-256 baselining, diffing, and live watching."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class FileIntegrityGuard:
    """Monitors directories and files for unauthorized tampering via SHA-256 baselines in SQLite."""

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

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 128)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _walk_target(self, target: Path) -> dict[str, dict[str, Any]]:
        snapshot: dict[str, dict[str, Any]] = {}
        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = [p for p in target.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        else:
            return snapshot

        for fp in files:
            try:
                st = fp.stat()
                snapshot[str(fp.resolve())] = {
                    "sha256": self._sha256_file(fp),
                    "size_bytes": st.st_size,
                    "mtime": st.st_mtime,
                }
            except (PermissionError, OSError):
                continue
        return snapshot

    def create_baseline(self, target_path: str, baseline_name: str = "default") -> dict[str, Any]:
        target = Path(target_path).expanduser()
        if not target.exists():
            self.console.print(f"[bold red][-][/] Path not found: {target}")
            return {}

        snap = self._walk_target(target)
        now = utc_now()
        with self.db.connection() as conn:
            conn.execute("DELETE FROM integrity_baselines WHERE baseline_name = ?", (baseline_name,))
            for fpath, meta in snap.items():
                conn.execute(
                    """
                    INSERT INTO integrity_baselines (baseline_name, root_path, file_path, sha256, size_bytes, mtime, captured_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (baseline_name, str(target.resolve()), fpath, meta["sha256"], meta["size_bytes"], meta["mtime"], now),
                )

        self.console.print(
            f"[bold bright_green][+][/] Integrity baseline [white]'{baseline_name}'[/] created: [bright_green]{len(snap)}[/] file(s) hashed under {target.resolve()}"
        )
        res = {"baseline": baseline_name, "root": str(target.resolve()), "file_count": len(snap), "captured_at": now}
        self.reports.record("INTEGRITY_BASELINE", f"Integrity Baseline: {baseline_name}", res)
        return res

    def scan_against_baseline(self, baseline_name: str = "default", target_path: str | None = None) -> dict[str, Any]:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM integrity_baselines WHERE baseline_name = ?", (baseline_name,)).fetchall()
        if not rows:
            self.console.print(f"[bold yellow][!][/] No integrity baseline named '{baseline_name}'. Create one first with `integrity baseline --path <dir>`.")
            return {}

        root_str = target_path or rows[0]["root_path"]
        root = Path(root_str).expanduser()
        if not root.exists():
            self.console.print(f"[bold red][-][/] Target path no longer exists: {root}")
            return {}

        old_map = {r["file_path"]: dict(r) for r in rows}
        new_map = self._walk_target(root)

        added = sorted(set(new_map.keys()) - set(old_map.keys()))
        deleted = sorted(set(old_map.keys()) - set(new_map.keys()))
        modified = sorted(k for k in (set(old_map.keys()) & set(new_map.keys())) if old_map[k]["sha256"] != new_map[k]["sha256"])

        table = Table(
            title=f"[bold bright_green]FILE INTEGRITY SCAN // {baseline_name}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green" if not (added or deleted or modified) else "red",
            header_style="bold bright_green",
        )
        table.add_column("Change Type", width=12)
        table.add_column("File Path", style="white")
        table.add_column("Details", style="grey70")

        for fp in modified:
            table.add_row("[bold red]MODIFIED[/]", fp, f"{old_map[fp]['sha256'][:12]} -> {new_map[fp]['sha256'][:12]}")
        for fp in added:
            table.add_row("[bold yellow]ADDED[/]", fp, f"Size={new_map[fp]['size_bytes']} B")
        for fp in deleted:
            table.add_row("[bold red]DELETED[/]", fp, "Missing from disk")

        if not (added or deleted or modified):
            self.console.print(f"[bold bright_green][+] INTACT[/]: All {len(old_map)} tracked file(s) match SHA-256 baseline '{baseline_name}'.")
        else:
            self.console.print(table)

        result = {
            "baseline": baseline_name,
            "tracked_count": len(old_map),
            "modified": modified,
            "added": added,
            "deleted": deleted,
        }
        self.reports.record(
            "INTEGRITY_SCAN",
            f"Integrity Scan: {baseline_name}",
            result,
            severity="HIGH" if (modified or deleted) else "INFO",
        )
        return result

    def watch(self, target_path: str, interval: float = 2.0, duration: float = 0.0) -> None:
        """Continuously watch a directory for SHA-256 changes until Ctrl+C."""
        root = Path(target_path).expanduser()
        if not root.exists():
            self.console.print(f"[bold red][-][/] Path not found: {root}")
            return
        prev = self._walk_target(root)
        self.console.print(f"[bright_green][*][/] Watching [white]{root.resolve()}[/] ({len(prev)} files). Press CTRL+C to stop.")
        start = time.monotonic()
        try:
            while True:
                time.sleep(max(0.5, interval))
                curr = self._walk_target(root)
                for fp in set(curr) - set(prev):
                    self.console.print(f"[bold yellow][ADDED][/] {fp}")
                for fp in set(prev) - set(curr):
                    self.console.print(f"[bold red][DELETED][/] {fp}")
                for fp in set(prev) & set(curr):
                    if prev[fp]["sha256"] != curr[fp]["sha256"]:
                        self.console.print(f"[bold red][MODIFIED][/] {fp} ({curr[fp]['sha256'][:16]}...)")
                prev = curr
                if duration > 0 and (time.monotonic() - start) >= duration:
                    break
        except KeyboardInterrupt:
            self.console.print("\n[bright_green][*][/] File integrity watch stopped.")

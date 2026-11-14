"""Module 19: Local Computer Intelligence Search - Multi-threaded indexed search, hashes, duplicates, services & startup."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from core.config import ConfigManager
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager
from modules.system_intel import SystemIntelModule, format_bytes


class ComputerSearchModule:
    """Fast, safe, cancellable local computer search, indexing, duplicate detection, processes, services & startup."""

    SKIP_DIR_NAMES = {
        "winsxs", "$recycle.bin", "system volume information", "__pycache__", ".git", "node_modules"
    }
    POSIX_SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run")

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        db: DatabaseManager,
        sys_intel: SystemIntelModule,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.db = db
        self.sys_intel = sys_intel
        self.reports = reports

    @staticmethod
    def parse_size(raw: str | None) -> int | None:
        if not raw:
            return None
        s = raw.strip().upper()
        mult = 1
        for suf, factor in (("GB", 1024 ** 3), ("G", 1024 ** 3), ("MB", 1024 ** 2), ("M", 1024 ** 2), ("KB", 1024), ("K", 1024), ("B", 1)):
            if s.endswith(suf):
                mult = factor
                s = s[: -len(suf)].strip()
                break
        return int(float(s) * mult)

    def _should_skip_dir(self, dir_path: Path, explicit_root: Path) -> bool:
        resolved = str(dir_path)
        if platform.system() != "Windows":
            for pref in self.POSIX_SKIP_PREFIXES:
                if resolved == pref or resolved.startswith(pref + "/"):
                    if not str(explicit_root).startswith(pref):
                        return True
        if dir_path.name.lower() in self.SKIP_DIR_NAMES and dir_path.resolve() != explicit_root.resolve():
            return True
        return False

    def _walk_files(
        self,
        root: Path,
        cancel_event: threading.Event,
    ) -> tuple[list[Path], int]:
        """Collect accessible files cleanly without crashing on PermissionError."""
        files: list[Path] = []
        perm_errors = 0
        stack = [root]

        while stack and not cancel_event.is_set():
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        if cancel_event.is_set():
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                sub = Path(entry.path)
                                if not self._should_skip_dir(sub, root):
                                    stack.append(sub)
                            elif entry.is_file(follow_symlinks=False):
                                files.append(Path(entry.path))
                        except (PermissionError, OSError):
                            perm_errors += 1
            except (PermissionError, OSError):
                perm_errors += 1
        return files, perm_errors

    @staticmethod
    def _file_sha256(path: Path, max_bytes: int | None = None) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            remaining = max_bytes
            while True:
                chunk = fh.read(65536 if remaining is None else min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
        return h.hexdigest()

    def build_or_update_index(self, root_dir: str = ".") -> dict[str, Any]:
        """Index accessible files into SQLite file_index table for rapid repeated queries."""
        root = Path(root_dir).expanduser().resolve()
        if not root.exists():
            self.console.print(f"[bold red][-][/] Directory not found: {root}")
            return {}

        cancel = threading.Event()
        with self.console.status(f"[bold bright_green][*] Indexing files under {root}...[/]", spinner="dots"):
            files, perm_denied = self._walk_files(root, cancel)
            now_ts = utc_now()
            rows: list[tuple[str, str, str, int, float, str]] = []
            for p in files:
                try:
                    st = p.stat()
                    rows.append((str(p), p.name, p.suffix.lower(), st.st_size, st.st_mtime, now_ts))
                except OSError:
                    perm_denied += 1

            with self.db.connection() as conn:
                conn.executemany(
                    """
                    INSERT INTO file_index (path, name, ext, size_bytes, mtime, indexed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        name=excluded.name,
                        ext=excluded.ext,
                        size_bytes=excluded.size_bytes,
                        mtime=excluded.mtime,
                        indexed_at=excluded.indexed_at
                    """,
                    rows,
                )

        self.console.print(
            f"[bold bright_green][+][/] Indexed [white]{len(rows):,}[/] files under [bright_green]{root}[/] "
            f"[grey70](permission skipped: {perm_denied})[/]"
        )
        return {"root": str(root), "indexed_count": len(rows), "permission_skipped": perm_denied}

    def search(
        self,
        query: str = "",
        root_dir: str = ".",
        search_content: bool = False,
        extensions: list[str] | None = None,
        min_size: str | None = None,
        max_size: str | None = None,
        modified_days: int | None = None,
        use_index: bool = False,
        update_index: bool = False,
        compute_hash: bool = False,
        find_duplicates: bool = False,
        large_top: int = 0,
        limit: int = 80,
    ) -> dict[str, Any]:
        """Search local filesystem or SQLite index with filename, content, size, date, duplicate & hash filters."""
        if update_index:
            self.build_or_update_index(root_dir)

        root = Path(root_dir).expanduser().resolve()
        if not root.exists():
            self.console.print(f"[bold red][-][/] Search path does not exist: {root}")
            return {}

        min_b = self.parse_size(min_size)
        max_b = self.parse_size(max_size)
        ext_set = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions} if extensions else set()
        cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=modified_days)).timestamp() if modified_days else None
        q_lower = query.strip().lower()
        max_content_bytes = int(self.config.get("computer_search_max_file_mb", 10)) * 1024 * 1024

        cancel = threading.Event()
        perm_denied = 0
        candidates: list[dict[str, Any]] = []

        try:
            if use_index and not search_content and not find_duplicates and not large_top:
                with self.db.connection() as conn:
                    rows = conn.execute(
                        "SELECT path, name, ext, size_bytes, mtime FROM file_index WHERE LOWER(name) LIKE ? LIMIT 2000",
                        (f"%{q_lower}%",),
                    ).fetchall()
                for r in rows:
                    candidates.append(
                        {"path": r["path"], "name": r["name"], "ext": r["ext"], "size": r["size_bytes"], "mtime": r["mtime"], "snippet": ""}
                    )
            else:
                with Progress(
                    SpinnerColumn(style="bright_green"),
                    TextColumn("[bright_green]{task.description}"),
                    TimeElapsedColumn(),
                    console=self.console,
                    transient=True,
                ) as prog:
                    prog.add_task(f"Scanning {root}", total=None)
                    all_files, perm_denied = self._walk_files(root, cancel)

                if large_top > 0:
                    sized: list[dict[str, Any]] = []
                    for p in all_files:
                        try:
                            st = p.stat()
                            sized.append({"path": str(p), "name": p.name, "ext": p.suffix.lower(), "size": st.st_size, "mtime": st.st_mtime, "snippet": ""})
                        except OSError:
                            perm_denied += 1
                    sized.sort(key=lambda x: x["size"], reverse=True)
                    candidates = sized[:large_top]
                elif find_duplicates:
                    by_size: dict[int, list[Path]] = defaultdict(list)
                    for p in all_files:
                        try:
                            sz = p.stat().st_size
                            if sz > 0:
                                by_size[sz].append(p)
                        except OSError:
                            perm_denied += 1
                    dup_groups: list[dict[str, Any]] = []
                    for sz, group in by_size.items():
                        if len(group) < 2:
                            continue
                        by_hash: dict[str, list[str]] = defaultdict(list)
                        for p in group:
                            try:
                                digest = self._file_sha256(p)
                                by_hash[digest].append(str(p))
                            except OSError:
                                perm_denied += 1
                        for digest, paths in by_hash.items():
                            if len(paths) > 1:
                                dup_groups.append({"sha256": digest, "size_bytes": sz, "count": len(paths), "paths": paths})
                    dup_groups.sort(key=lambda g: g["size_bytes"] * (g["count"] - 1), reverse=True)
                    self._render_duplicates(dup_groups, perm_denied)
                    return {"root": str(root), "duplicate_groups": dup_groups, "permission_skipped": perm_denied}
                else:
                    threads = max(1, int(self.config.get("computer_search_threads", 8)))
                    lock = threading.Lock()

                    def inspect_file(fp: Path) -> None:
                        if cancel.is_set():
                            return
                        try:
                            st = fp.stat()
                        except OSError:
                            return
                        ext = fp.suffix.lower()
                        if ext_set and ext not in ext_set:
                            return
                        if min_b is not None and st.st_size < min_b:
                            return
                        if max_b is not None and st.st_size > max_b:
                            return
                        if cutoff_ts is not None and st.st_mtime < cutoff_ts:
                            return

                        snippet = ""
                        matched = False
                        if not q_lower:
                            matched = True
                        elif not search_content:
                            matched = q_lower in fp.name.lower() or q_lower in str(fp).lower()
                        else:
                            if q_lower in fp.name.lower():
                                matched = True
                                snippet = "[filename match]"
                            if st.st_size <= max_content_bytes:
                                try:
                                    raw = fp.read_bytes()
                                    if b"\x00" not in raw[:2048]:
                                        text = raw.decode("utf-8", errors="replace")
                                        for idx, line in enumerate(text.splitlines(), start=1):
                                            if q_lower in line.lower():
                                                matched = True
                                                snippet = f"L{idx}: {line.strip()[:80]}"
                                                break
                                except OSError:
                                    pass

                        if matched:
                            digest = ""
                            if compute_hash and st.st_size <= 50 * 1024 * 1024:
                                try:
                                    digest = self._file_sha256(fp)
                                except OSError:
                                    digest = "ERR"
                            with lock:
                                candidates.append(
                                    {
                                        "path": str(fp),
                                        "name": fp.name,
                                        "ext": ext,
                                        "size": st.st_size,
                                        "mtime": st.st_mtime,
                                        "sha256": digest,
                                        "snippet": snippet,
                                    }
                                )

                    with ThreadPoolExecutor(max_workers=threads) as pool:
                        list(pool.map(inspect_file, all_files))
        except KeyboardInterrupt:
            cancel.set()
            self.console.print("\n[bold yellow][!][/] Search cancelled by user; displaying partial results.")

        # Apply filter again if loaded from index
        if use_index:
            filtered: list[dict[str, Any]] = []
            for item in candidates:
                if ext_set and item["ext"] not in ext_set:
                    continue
                if min_b is not None and item["size"] < min_b:
                    continue
                if max_b is not None and item["size"] > max_b:
                    continue
                if cutoff_ts is not None and item["mtime"] < cutoff_ts:
                    continue
                filtered.append(item)
            candidates = filtered

        shown = candidates[:limit]
        table = Table(
            title=f"[bold bright_green]LOCAL COMPUTER SEARCH // {len(candidates)} MATCH(ES) (SHOWING {len(shown)})[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Size", justify="right", width=11, style="white")
        table.add_column("Modified", width=19, style="grey70")
        table.add_column("Path", style="bright_green")
        if search_content or compute_hash:
            table.add_column("Match / SHA-256", style="grey70")

        for item in shown:
            mtime_str = datetime.fromtimestamp(item["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
            row = [format_bytes(item["size"]), mtime_str, item["path"]]
            if search_content or compute_hash:
                extra = item.get("sha256", "")[:16] if compute_hash else item.get("snippet", "")
                row.append(extra)
            table.add_row(*row)
        if shown:
            self.console.print(table)
        else:
            self.console.print("[grey70][*] No matching files found.[/]")

        if perm_denied > 0:
            self.console.print(f"[grey70][*] Skipped {perm_denied} protected directory/file entries (PermissionError handled cleanly).[/]")

        res = {"root": str(root), "query": query, "total_matches": len(candidates), "results": shown, "permission_skipped": perm_denied}
        self.reports.record("COMPUTER_SEARCH", f"Local Search '{query or '*'}' in {root.name}", res)
        return res

    def _render_duplicates(self, groups: list[dict[str, Any]], perm_denied: int) -> None:
        if not groups:
            self.console.print("[bright_green][+][/] No duplicate files found.")
            return
        table = Table(
            title=f"[bold bright_green]DUPLICATE FILES BY SHA-256 ({len(groups)} GROUP(S))[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Size", justify="right", width=11, style="white")
        table.add_column("Copies", justify="right", width=7, style="yellow")
        table.add_column("SHA-256 (prefix)", width=18, style="grey70")
        table.add_column("Paths", style="bright_green")
        for g in groups[:25]:
            table.add_row(format_bytes(g["size_bytes"]), str(g["count"]), g["sha256"][:16], "\n".join(g["paths"][:4]))
        self.console.print(table)
        if perm_denied:
            self.console.print(f"[grey70][*] Skipped {perm_denied} restricted entries.[/]")

    def show_services(self, filter_str: str = "") -> list[dict[str, str]]:
        """List OS services (read-only) on Windows or Linux/POSIX."""
        services: list[dict[str, str]] = []
        sys_name = platform.system()
        try:
            if sys_name == "Windows":
                proc = subprocess.run(["sc", "query", "state=", "all"], capture_output=True, text=True, timeout=12, encoding="utf-8", errors="replace")
                cur_name = ""
                cur_disp = ""
                for line in proc.stdout.splitlines():
                    s = line.strip()
                    if s.startswith("SERVICE_NAME:"):
                        cur_name = s.split(":", 1)[1].strip()
                    elif s.startswith("DISPLAY_NAME:"):
                        cur_disp = s.split(":", 1)[1].strip()
                    elif s.startswith("STATE") and cur_name:
                        st = s.split(":", 1)[1].strip()
                        services.append({"name": cur_name, "display": cur_disp or cur_name, "state": st})
                        cur_name, cur_disp = "", ""
            else:
                proc = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding="utf-8",
                    errors="replace",
                )
                for line in proc.stdout.splitlines():
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        services.append({"name": parts[0], "state": f"{parts[2]}/{parts[3]}", "display": parts[4] if len(parts) > 4 else parts[0]})
        except Exception as exc:
            self.console.print(f"[yellow][!][/] Could not enumerate OS services: {exc}")

        if filter_str:
            fl = filter_str.lower()
            services = [s for s in services if fl in s["name"].lower() or fl in s["display"].lower()]

        table = Table(
            title=f"[bold bright_green]SYSTEM SERVICES ({len(services)} FOUND)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Service Name", style="bright_green")
        table.add_column("State", style="white", width=22)
        table.add_column("Description / Display", style="grey70")
        for s in services[:50]:
            table.add_row(s["name"], s["state"], s["display"][:60])
        if services:
            self.console.print(table)
        else:
            self.console.print("[grey70][*] No services returned (or service manager unavailable in this container/OS).[/]")
        self.reports.record("COMPUTER_SERVICES", "OS Services Enumeration", {"count": len(services), "services": services[:100]})
        return services

    def show_startup(self) -> list[dict[str, str]]:
        """List OS startup programs read-only (Windows Registry Run keys & Startup folders / POSIX autostart)."""
        entries: list[dict[str, str]] = []
        sys_name = platform.system()
        if sys_name == "Windows":
            try:
                import winreg  # type: ignore

                roots = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
                ]
                for hive, subkey, label in roots:
                    try:
                        with winreg.OpenKey(hive, subkey) as k:
                            idx = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(k, idx)
                                    entries.append({"source": label, "name": str(name), "command": str(val)})
                                    idx += 1
                                except OSError:
                                    break
                    except OSError:
                        pass
            except ImportError:
                pass
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                st_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if st_dir.exists():
                    for item in st_dir.iterdir():
                        entries.append({"source": "User Startup Folder", "name": item.name, "command": str(item)})
        else:
            for d in (Path("/etc/xdg/autostart"), Path.home() / ".config" / "autostart"):
                if d.exists():
                    for item in d.glob("*.desktop"):
                        entries.append({"source": str(d), "name": item.stem, "command": str(item)})
            systemd_dir = Path("/etc/systemd/system/multi-user.target.wants")
            if systemd_dir.exists():
                for item in systemd_dir.iterdir():
                    entries.append({"source": "systemd multi-user.wants", "name": item.name, "command": str(item)})

        table = Table(
            title=f"[bold bright_green]STARTUP PROGRAMS & AUTORUNS ({len(entries)} FOUND)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Source", style="grey70", width=26)
        table.add_column("Name", style="bright_green", width=26)
        table.add_column("Target / Command", style="white")
        for e in entries[:60]:
            table.add_row(e["source"], e["name"], e["command"][:80])
        if entries:
            self.console.print(table)
        else:
            self.console.print("[grey70][*] No user/system startup entries found.[/]")
        self.reports.record("COMPUTER_STARTUP", "Startup Programs Inventory", {"count": len(entries), "entries": entries})
        return entries

    def show_disk(self, root_dir: str = ".", top_large: int = 15) -> dict[str, Any]:
        """Show storage partition usage plus largest accessible files under root_dir."""
        parts: list[dict[str, Any]] = []
        ptab = Table(title="[bold bright_green]DISK PARTITIONS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
        ptab.add_column("Device", style="white")
        ptab.add_column("Mount", style="grey70")
        ptab.add_column("Total", justify="right", style="white")
        ptab.add_column("Free", justify="right", style="bright_green")
        ptab.add_column("Used %", justify="right")
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
                parts.append({"device": part.device, "mount": part.mountpoint, "total": u.total, "free": u.free, "percent": u.percent})
                col = "bold red" if u.percent >= 90 else "yellow" if u.percent >= 75 else "bright_green"
                ptab.add_row(part.device, part.mountpoint, format_bytes(u.total), format_bytes(u.free), f"[{col}]{u.percent:.1f}%[/]")
            except OSError:
                continue
        self.console.print(ptab)

        large_res = self.search(query="", root_dir=root_dir, large_top=top_large, limit=top_large)
        return {"partitions": parts, "largest_files": large_res.get("results", [])}

    def report(self, root_dir: str = ".", fmt: str = "json") -> None:
        self.show_disk(root_dir=root_dir, top_large=10)
        self.show_startup()
        self.reports.export_report(export_format=fmt, export_all=True)

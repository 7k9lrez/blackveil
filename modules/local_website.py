"""Module 16: Local Website Environment - Safe static snapshot capture & loopback inspection."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import posixpath
import re
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import ConfigManager, LOCAL_SITES_DIR, ensure_directories
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class _AssetExtractor(HTMLParser):
    """Collects same-origin static assets (CSS, JS, images, linked pages) from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()
        self.assets: list[str] = []
        self.pages: list[str] = []

    def _add(self, raw: str, is_page: bool = False) -> None:
        val = raw.strip()
        if not val or val.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
            return
        full = urllib.parse.urljoin(self.base_url, val)
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in {"http", "https"}:
            return
        if (parsed.hostname or "").lower() != self.base_host:
            return
        clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
        bucket = self.pages if is_page else self.assets
        if clean not in bucket:
            bucket.append(clean)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if t == "script" and attr_map.get("src"):
            self._add(attr_map["src"], is_page=False)
        elif t == "link" and attr_map.get("href"):
            self._add(attr_map["href"], is_page=False)
        elif t == "img" and attr_map.get("src"):
            self._add(attr_map["src"], is_page=False)
        elif t == "a" and attr_map.get("href"):
            href = attr_map["href"]
            path_l = urllib.parse.urlparse(href).path.lower()
            if path_l.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
                self._add(href, is_page=False)
            elif not path_l or "." not in posixpath.basename(path_l) or path_l.endswith((".html", ".htm")):
                self._add(href, is_page=True)


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Loopback static file handler without noisy stderr dumps."""

    def log_message(self, format: str, *args: Any) -> None:
        return


class _ThreadingTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LocalWebsiteModule:
    """Downloads accessible static resources safely into an isolated workspace and serves on 127.0.0.1."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        db: DatabaseManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.db = db
        self.reports = reports
        ensure_directories()
        self._servers: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _safe_rel_path(url_path: str, content_type: str, is_root: bool = False) -> Path:
        decoded = urllib.parse.unquote(url_path or "/")
        clean_parts = [p for p in decoded.split("/") if p and p not in {".", ".."}]
        if not clean_parts:
            return Path("index.html")
        last = clean_parts[-1]
        if decoded.endswith("/") or ("." not in last and "html" in content_type.lower()):
            clean_parts.append("index.html")
        elif is_root and "." not in last:
            clean_parts.append("index.html")
        sanitized = [re.sub(r"[^A-Za-z0-9._-]", "_", part) for part in clean_parts]
        return Path(*sanitized)

    @staticmethod
    def _fetch_bytes(url: str, max_bytes: int) -> tuple[bool, int, str, bytes, str]:
        req = urllib.request.Request(url, headers={"User-Agent": "BLACKVEIL-X-LocalCapture/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    return False, resp.status, ctype, b"", f"Resource exceeded per-file cap ({max_bytes} bytes)"
                return True, resp.status, ctype, data, ""
        except urllib.error.HTTPError as exc:
            return False, exc.code, "", b"", f"HTTP {exc.code}"
        except Exception as exc:
            return False, 0, "", b"", str(exc)

    def create_local_environment(
        self,
        raw_url: str,
        port: int = 0,
        max_pages: int | None = None,
    ) -> dict[str, Any]:
        """Download accessible static HTML/CSS/JS/images with strict caps and launch 127.0.0.1 server."""
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            self.console.print(f"[bold red][-][/] Invalid URL: '{raw_url}'")
            return {}

        cap_files = max_pages or int(self.config.get("local_site_max_pages", 35))
        cap_total_bytes = int(self.config.get("local_site_max_bytes", 10485760))

        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", host)
        site_dir = LOCAL_SITES_DIR / slug
        site_dir.mkdir(parents=True, exist_ok=True)

        queue: list[tuple[str, bool]] = [(url, True)]
        visited: set[str] = set()
        downloaded_files: list[dict[str, Any]] = []
        skipped_urls: list[dict[str, str]] = []
        total_bytes = 0

        self.logger.info("local_website", f"Starting static capture for {url} (max_files={cap_files}, max_bytes={cap_total_bytes})")
        with self.console.status(f"[bold bright_green][*] Downloading accessible static assets from {host}...[/]", spinner="dots"):
            while queue and len(downloaded_files) < cap_files and total_bytes < cap_total_bytes:
                cur_url, is_page = queue.pop(0)
                if cur_url in visited:
                    continue
                visited.add(cur_url)

                ok, status, ctype, content, err = self._fetch_bytes(cur_url, min(2_000_000, cap_total_bytes - total_bytes))
                if not ok:
                    skipped_urls.append({"url": cur_url, "reason": err or f"status {status}"})
                    continue

                if total_bytes + len(content) > cap_total_bytes:
                    skipped_urls.append({"url": cur_url, "reason": "Total workspace size cap reached"})
                    break

                cur_parsed = urllib.parse.urlparse(cur_url)
                rel = self._safe_rel_path(cur_parsed.path, ctype, is_root=(cur_url == url))
                dest = (site_dir / rel).resolve()
                if not str(dest).startswith(str(site_dir.resolve())):
                    skipped_urls.append({"url": cur_url, "reason": "Path traversal blocked"})
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                total_bytes += len(content)
                sha256 = hashlib.sha256(content).hexdigest()
                downloaded_files.append(
                    {
                        "url": cur_url,
                        "local_rel_path": str(rel).replace("\\", "/"),
                        "content_type": ctype,
                        "size_bytes": len(content),
                        "sha256": sha256,
                    }
                )

                if "html" in ctype.lower() or rel.suffix.lower() in {".html", ".htm"}:
                    try:
                        extractor = _AssetExtractor(cur_url)
                        extractor.feed(content.decode("utf-8", errors="replace"))
                        for asset in extractor.assets:
                            if asset not in visited:
                                queue.append((asset, False))
                        for pg in extractor.pages[:8]:
                            if pg not in visited and is_page:
                                queue.append((pg, True))
                    except Exception:
                        pass

        if not downloaded_files:
            self.console.print(f"[bold red][-][/] Could not capture any accessible static files from '{url}'.")
            return {"source_url": url, "host": host, "files_count": 0, "skipped": skipped_urls}

        # Write manifest for offline inspection
        manifest = {
            "source_url": url,
            "host": host,
            "captured_at": utc_now(),
            "files": downloaded_files,
            "skipped": skipped_urls,
            "total_bytes": total_bytes,
            "limitations_notice": (
                "Static copy only: server-side APIs, databases, authentication, and dynamic backend routes "
                "cannot execute inside this isolated local mirror."
            ),
        }
        (site_dir / "_blackveil_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # Stop prior server for same host if already running
        if host in self._servers:
            self.stop(host, quiet=True)

        # Serve strictly on 127.0.0.1 loopback
        handler_cls = lambda *args, **kwargs: _QuietHandler(*args, directory=str(site_dir), **kwargs)
        httpd = _ThreadingTCPServer(("127.0.0.1", port), handler_cls)
        actual_port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True, name=f"bv-local-{slug}")
        thread.start()

        site_id = f"LOC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self._servers[host] = {
            "id": site_id,
            "host": host,
            "source_url": url,
            "local_dir": str(site_dir),
            "port": actual_port,
            "httpd": httpd,
            "thread": thread,
            "files_count": len(downloaded_files),
            "total_bytes": total_bytes,
            "started_at": utc_now(),
        }

        try:
            with self.db.connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO local_websites
                    (id, source_url, host, local_dir, port, files_count, total_bytes, status, created_at, stopped_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING', ?, NULL)
                    """,
                    (site_id, url, host, str(site_dir), actual_port, len(downloaded_files), total_bytes, utc_now()),
                )
        except Exception:
            pass

        self.console.print(
            Panel(
                f"[bold bright_green][+] Local Static Environment READY[/]\n"
                f"[white]Environment ID :[/] [bright_green]{site_id}[/]\n"
                f"[white]Source URL     :[/] {url}\n"
                f"[white]Local Loopback :[/] [bright_green]http://127.0.0.1:{actual_port}/[/]\n"
                f"[white]Workspace Dir  :[/] {site_dir}\n"
                f"[white]Captured Files :[/] {len(downloaded_files)} ({total_bytes:,} bytes)\n"
                f"[yellow]Notice         :[/] Static snapshot only — server-side/dynamic features do not run locally.",
                title="[bold bright_green]LOCAL WEBSITE ENVIRONMENT[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        self.reports.record("LOCAL_WEBSITE", f"Local Static Environment: {host}", manifest)
        return self._servers[host]

    def status(self) -> list[dict[str, Any]]:
        rows_out: list[dict[str, Any]] = []
        table = Table(
            title="[bold bright_green]LOCAL WEBSITE ENVIRONMENTS // STATUS[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green")
        table.add_column("Host", style="white")
        table.add_column("Loopback Endpoint", style="bright_green")
        table.add_column("Files", justify="right", width=6)
        table.add_column("Size", justify="right", width=11)
        table.add_column("State", width=10)

        for host, entry in self._servers.items():
            alive = entry["thread"].is_alive()
            rows_out.append({k: v for k, v in entry.items() if k not in {"httpd", "thread"}})
            table.add_row(
                entry["id"],
                host,
                f"http://127.0.0.1:{entry['port']}/",
                str(entry["files_count"]),
                f"{entry['total_bytes']:,} B",
                "[bold bright_green]RUNNING[/]" if alive else "[yellow]STOPPED[/]",
            )

        if not rows_out:
            # Show historical entries from SQLite if none active in memory
            with self.db.connection() as conn:
                db_rows = conn.execute(
                    "SELECT id, host, port, files_count, total_bytes, status FROM local_websites ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            if not db_rows:
                self.console.print("[grey70][*] No active or historical local website environments found.[/]")
                return []
            for r in db_rows:
                table.add_row(r["id"], r["host"], f"127.0.0.1:{r['port'] or '-'}", str(r["files_count"]), f"{r['total_bytes']:,} B", "[grey70]INACTIVE[/]")
        self.console.print(table)
        return rows_out

    def stop(self, target: str | None = None, quiet: bool = False) -> int:
        if not self._servers:
            if not quiet:
                self.console.print("[grey70][*] No active local website server is currently running.[/]")
            return 0

        targets = list(self._servers.keys()) if not target else [
            k for k, v in self._servers.items() if k == target or v["id"] == target
        ]
        stopped = 0
        for host in targets:
            entry = self._servers.pop(host, None)
            if not entry:
                continue
            try:
                entry["httpd"].shutdown()
                entry["httpd"].server_close()
            except Exception:
                pass
            try:
                with self.db.connection() as conn:
                    conn.execute(
                        "UPDATE local_websites SET status = 'STOPPED', stopped_at = ? WHERE id = ?",
                        (utc_now(), entry["id"]),
                    )
            except Exception:
                pass
            stopped += 1
            if not quiet:
                self.console.print(f"[bright_green][+][/] Stopped local environment [white]{host}[/] (port {entry['port']}).")

        if stopped == 0 and not quiet:
            self.console.print(f"[bold red][-][/] Local environment '{target}' not found.")
        return stopped

    def inspect(self, target: str | None = None) -> dict[str, Any]:
        """Inspect downloaded local static files and compare root document against live site if reachable."""
        site_dir: Path | None = None
        if target:
            slug = re.sub(r"[^a-zA-Z0-9._-]", "_", target.strip().removeprefix("https://").removeprefix("http://").split("/")[0].lower())
            cand = LOCAL_SITES_DIR / slug
            if cand.exists():
                site_dir = cand
        elif self._servers:
            first_key = next(iter(self._servers))
            site_dir = Path(self._servers[first_key]["local_dir"])
        else:
            dirs = sorted([d for d in LOCAL_SITES_DIR.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
            if dirs:
                site_dir = dirs[0]

        if not site_dir or not (site_dir / "_blackveil_manifest.json").exists():
            self.console.print("[yellow][!][/] No local website snapshot found to inspect. Run `website local <URL>` first.")
            return {}

        manifest = json.loads((site_dir / "_blackveil_manifest.json").read_text(encoding="utf-8"))
        files = manifest.get("files", [])
        live_diff = "Not checked"
        root_entry = files[0] if files else None
        if root_entry:
            ok, status, _, live_bytes, err = self._fetch_bytes(root_entry["url"], 2_000_000)
            if ok:
                live_hash = hashlib.sha256(live_bytes).hexdigest()
                if live_hash == root_entry["sha256"]:
                    live_diff = "MATCHES_LIVE (Root SHA-256 identical)"
                else:
                    live_diff = f"DIFFERS_FROM_LIVE (Local {root_entry['size_bytes']} B vs Live {len(live_bytes)} B)"
            else:
                live_diff = f"Live check unavailable ({err or status})"

        table = Table(
            title=f"[bold bright_green]LOCAL ENVIRONMENT INSPECTOR // {manifest['host']}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Local File", style="bright_green")
        table.add_column("Content-Type", style="grey70")
        table.add_column("Size", justify="right", style="white")
        table.add_column("SHA-256 (prefix)", style="grey70")
        for f in files[:25]:
            table.add_row(f["local_rel_path"], f["content_type"].split(";")[0], f"{f['size_bytes']:,} B", f["sha256"][:16])
        self.console.print(table)

        self.console.print(
            Panel(
                f"[white]Workspace   :[/] {site_dir}\n"
                f"[white]Live Diff   :[/] [bright_green]{live_diff}[/]\n"
                f"[white]Skipped URLs:[/] {len(manifest.get('skipped', []))}\n"
                f"[yellow]Limitations :[/] {manifest.get('limitations_notice')}",
                title="[bold bright_green]DIFF & DYNAMIC LIMITATIONS[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return {"manifest": manifest, "live_diff": live_diff}

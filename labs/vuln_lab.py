"""Module 01: Vulnerability Lab - Intentionally vulnerable isolated training targets & remediation tasks."""

from __future__ import annotations

import http.server
import json
import shutil
import socketserver
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import LABS_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


VULN_MACHINES: list[dict[str, Any]] = [
    {
        "id": "VULN-01",
        "name": "Insecure Secret & Config Vault",
        "category": "Secrets & Misconfiguration",
        "difficulty": "BEGINNER",
        "tasks": [
            "1. Install and start VULN-01 to generate the vulnerable service config directory.",
            "2. Run `secret scan --path <workspace>` to locate leaked credentials & weak JWT secret.",
            "3. Run `audit permissions` or inspect file permissions in the workspace.",
        ],
        "goal": "Identify all 3 leaked secret types and remediate hardcoded tokens.",
    },
    {
        "id": "VULN-02",
        "name": "Local Vulnerable Web Lab (Path Traversal & Weak Auth)",
        "category": "Web / Local Loopback App",
        "difficulty": "INTERMEDIATE",
        "tasks": [
            "1. Start VULN-02 to launch an isolated 127.0.0.1 HTTP training target on an ephemeral port.",
            "2. Inspect the vulnerable Python handler in `labs/workspaces/VULN-02/app.py`.",
            "3. Spot the unsanitized `file=` query parameter and plaintext credential comparison.",
        ],
        "goal": "Analyze path traversal + weak auth flaws and patch `app.py` safely.",
    },
    {
        "id": "VULN-03",
        "name": "Command Injection & Forensic Log Target",
        "category": "OS Command Injection / DFIR",
        "difficulty": "ADVANCED",
        "tasks": [
            "1. Install VULN-03 to deploy the vulnerable diagnostics script and incident log.",
            "2. Audit `diag_runner.py` for unsafe `shell=True` command concatenation.",
            "3. Run `logs analyze --file <workspace>/service.log` and `ai analyze` to reconstruct the probe.",
        ],
        "goal": "Trace the injected diagnostic payload and eliminate `shell=True` injection.",
    },
]


class VulnLabModule:
    """Manages intentionally vulnerable isolated training labs."""

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
        self.workspaces_dir = LABS_DIR / "workspaces"
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self._running_servers: dict[str, tuple[socketserver.TCPServer, int]] = {}
        self._seed_catalog()

    def _seed_catalog(self) -> None:
        with self.db.connection() as conn:
            for m in VULN_MACHINES:
                conn.execute(
                    "INSERT OR IGNORE INTO vuln_labs (id, name, category, status) VALUES (?, ?, ?, 'NOT_INSTALLED')",
                    (m["id"], m["name"], m["category"]),
                )

    def _find_lab(self, lab_id: str) -> dict[str, Any] | None:
        key = lab_id.strip().upper()
        for m in VULN_MACHINES:
            if m["id"] == key:
                return m
        self.console.print(f"[bold red][-][/] Vulnerability lab '{lab_id}' not found.")
        return None

    def list_labs(self) -> None:
        with self.db.connection() as conn:
            rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM vuln_labs").fetchall()}

        table = Table(
            title="[bold bright_green]VULNERABILITY LAB // TRAINING MACHINES[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green", width=10)
        table.add_column("Name", style="white")
        table.add_column("Category", style="grey70")
        table.add_column("Difficulty", width=13)
        table.add_column("Status", width=15)

        for m in VULN_MACHINES:
            st = rows.get(m["id"], {}).get("status", "NOT_INSTALLED")
            if m["id"] in self._running_servers:
                st = f"RUNNING:{self._running_servers[m['id']][1]}"
            col = "bright_green" if "RUNNING" in st or st == "INSTALLED" else "grey70"
            table.add_row(m["id"], m["name"], m["category"], m["difficulty"], f"[{col}]{st}[/]")
        self.console.print(table)

    def install(self, lab_id: str) -> Path | None:
        lab = self._find_lab(lab_id)
        if not lab:
            return None

        ws = self.workspaces_dir / lab["id"]
        ws.mkdir(parents=True, exist_ok=True)

        if lab["id"] == "VULN-01":
            (ws / "config.env").write_text(
                "# Deliberately Vulnerable Lab Fixture (Non-functional training values)\n"
                "APP_ENV=staging\n"
                "TRAIN_AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
                "TRAIN_DB_PASS=Summer2024!\n"
                "TRAIN_JWT_SECRET=weak_dev_secret_123\n",
                encoding="utf-8",
            )
            (ws / "README_TASKS.txt").write_text("\n".join(lab["tasks"]), encoding="utf-8")
        elif lab["id"] == "VULN-02":
            (ws / "public_note.txt").write_text("BLACKVEIL Training Web Lab - Public Document", encoding="utf-8")
            (ws / "secret_flag.txt").write_text("TRAINING_ASSET_ONLY_DO_NOT_EXPOSE", encoding="utf-8")
            (ws / "app.py").write_text(
                "# Deliberately Vulnerable Training Handler (Loopback Only)\n"
                "def read_doc(base_dir, filename):\n"
                "    # FLAW: No path canonicalization or '..' check\n"
                "    return open(base_dir + '/' + filename, 'r').read()\n\n"
                "def check_login(user, password):\n"
                "    # FLAW: Hardcoded credential & timing-unsafe compare\n"
                "    return user == 'admin' and password == 'admin123'\n",
                encoding="utf-8",
            )
        elif lab["id"] == "VULN-03":
            (ws / "diag_runner.py").write_text(
                "import subprocess\n"
                "def ping_host(user_input):\n"
                "    # FLAW: shell=True with untrusted user_input\n"
                "    return subprocess.run(f'ping -c 1 {user_input}', shell=True, capture_output=True)\n",
                encoding="utf-8",
            )
            (ws / "service.log").write_text(
                "2026-11-14 07:01:00 INFO diag_runner: host=127.0.0.1 status=ok\n"
                "2026-11-14 07:02:14 WARN diag_runner: input='127.0.0.1 && cat /etc/passwd' blocked_in_sandbox=true\n"
                "2026-11-14 07:03:05 CRIT httpd: GET /download?file=../../etc/passwd 403\n",
                encoding="utf-8",
            )

        with self.db.connection() as conn:
            conn.execute(
                "UPDATE vuln_labs SET status = 'INSTALLED', container_or_path = ?, installed_at = ? WHERE id = ?",
                (str(ws), utc_now(), lab["id"]),
            )
        self.console.print(f"[bright_green][+][/] Vulnerability lab [white]{lab['id']}[/] installed at [bright_green]{ws}[/]")
        self.inspect(lab["id"])
        return ws

    def start(self, lab_id: str) -> dict[str, Any] | None:
        lab = self._find_lab(lab_id)
        if not lab:
            return None
        ws = self.workspaces_dir / lab["id"]
        if not ws.exists():
            ws = self.install(lab["id"])
            if not ws:
                return None

        port_info = ""
        if lab["id"] == "VULN-02" and lab["id"] not in self._running_servers:
            root_ws = ws

            class TrainingHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # noqa: N802
                    parsed = urllib.parse.urlparse(self.path)
                    qs = urllib.parse.parse_qs(parsed.query)
                    if parsed.path == "/doc":
                        name = qs.get("file", ["public_note.txt"])[0]
                        # Intentionally restricted inside root_ws while demonstrating traversal pattern detection
                        safe_target = (root_ws / Path(name).name)
                        body = f"Training Lab Response | Requested={name} | SafePreview={safe_target.name}"
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(body.encode("utf-8"))
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"BLACKVEIL VULN-02 Loopback Target Ready (/doc?file=public_note.txt)")

                def log_message(self, format: str, *args: Any) -> None:
                    return

            srv = socketserver.TCPServer(("127.0.0.1", 0), TrainingHandler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._running_servers[lab["id"]] = (srv, port)
            port_info = f" | Loopback Target: http://127.0.0.1:{port}/"

        with self.db.connection() as conn:
            conn.execute("UPDATE vuln_labs SET status = 'RUNNING' WHERE id = ?", (lab["id"],))
        self.console.print(f"[bold bright_green][+][/] Lab [white]{lab['id']}[/] started in isolated workspace [bright_green]{ws}[/]{port_info}")
        return {"id": lab["id"], "workspace": str(ws)}

    def inspect(self, lab_id: str) -> None:
        lab = self._find_lab(lab_id)
        if not lab:
            return
        with self.db.connection() as conn:
            row = dict(conn.execute("SELECT * FROM vuln_labs WHERE id = ?", (lab["id"],)).fetchone())
        lines = [
            f"[white]Lab ID     :[/] [bright_green]{lab['id']}[/] ({lab['difficulty']})",
            f"[white]Name       :[/] {lab['name']}",
            f"[white]Status     :[/] {row['status']}",
            f"[white]Workspace  :[/] {row['container_or_path'] or 'Not installed'}",
            f"[white]Goal       :[/] [bright_green]{lab['goal']}[/]",
            "[white]Tasks      :[/]",
            *[f"   [grey70]{t}[/]" for t in lab["tasks"]],
        ]
        self.console.print(Panel("\n".join(lines), title=f"[bold bright_green]VULNERABILITY LAB // {lab['id']}[/]", border_style="bright_green", box=box.SQUARE))

    def reset(self, lab_id: str) -> None:
        lab = self._find_lab(lab_id)
        if not lab:
            return
        if lab["id"] in self._running_servers:
            srv, _ = self._running_servers.pop(lab["id"])
            srv.shutdown()
            srv.server_close()
        ws = self.workspaces_dir / lab["id"]
        if ws.exists():
            shutil.rmtree(ws, ignore_errors=True)
        with self.db.connection() as conn:
            conn.execute("UPDATE vuln_labs SET status = 'NOT_INSTALLED', container_or_path = NULL WHERE id = ?", (lab["id"],))
        self.console.print(f"[bright_green][+][/] Lab [white]{lab['id']}[/] reset cleanly.")

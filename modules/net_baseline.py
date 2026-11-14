"""Module 07: Network Baseline - Captures normal host network posture and detects deviations."""

from __future__ import annotations

import json
import socket
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.network import NetworkModule
from modules.reports import ReportManager


class NetworkBaselineModule:
    """Records normal listening ports, active remote peers, gateway, and ARP neighbors."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        network: NetworkModule,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.network = network
        self.reports = reports

    def _capture_live_posture(self) -> dict[str, Any]:
        listening: list[str] = []
        established: list[str] = []
        try:
            for c in psutil.net_connections(kind="inet"):
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                if c.status == "LISTEN" and c.laddr:
                    listening.append(f"{proto}:{c.laddr.ip}:{c.laddr.port}")
                elif c.status == "ESTABLISHED" and c.raddr:
                    established.append(f"{proto}:{c.raddr.ip}:{c.raddr.port}")
        except psutil.AccessDenied:
            pass

        return {
            "host": socket.gethostname(),
            "local_ip": self.network.get_primary_local_ip(),
            "gateway": self.network.get_default_gateway(),
            "listening": sorted(set(listening)),
            "established_remotes": sorted(set(established)),
            "arp_neighbors": self.network._read_arp_cache(),
            "captured_at": utc_now(),
        }

    def create(self, name: str = "default") -> dict[str, Any]:
        snap = self._capture_live_posture()
        with self.db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO network_baselines (name, host, snapshot_json, created_at) VALUES (?, ?, ?, ?)",
                (name, snap["host"], json.dumps(snap), snap["captured_at"]),
            )
        self.console.print(
            f"[bold bright_green][+][/] Network baseline [white]'{name}'[/] saved: "
            f"[bright_green]{len(snap['listening'])}[/] listening sockets, "
            f"[bright_green]{len(snap['established_remotes'])}[/] active remotes, "
            f"[bright_green]{len(snap['arp_neighbors'])}[/] ARP neighbors."
        )
        return snap

    def inspect(self, name: str = "default") -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM network_baselines WHERE name = ?", (name,)).fetchone()
        if not row:
            self.console.print(f"[yellow][!][/] Baseline '{name}' not found. Run `baseline create`.")
            return None
        snap = json.loads(row["snapshot_json"])
        table = Table(title=f"[bold bright_green]NETWORK BASELINE // {name}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", show_header=False)
        table.add_column("Field", style="grey70", width=22)
        table.add_column("Value", style="white")
        table.add_row("Captured At", snap["captured_at"])
        table.add_row("Local IP / Gateway", f"{snap['local_ip']} / {snap['gateway']}")
        table.add_row("Listening Sockets", ", ".join(snap["listening"][:12]) or "None")
        table.add_row("Remote Peers", ", ".join(snap["established_remotes"][:10]) or "None")
        table.add_row("ARP Neighbors", str(len(snap["arp_neighbors"])))
        self.console.print(table)
        return snap

    def compare(self, name: str = "default") -> dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM network_baselines WHERE name = ?", (name,)).fetchone()
        if not row:
            self.console.print(f"[yellow][!][/] Baseline '{name}' not found. Run `baseline create` first.")
            return {}

        old = json.loads(row["snapshot_json"])
        curr = self._capture_live_posture()

        new_listen = sorted(set(curr["listening"]) - set(old["listening"]))
        closed_listen = sorted(set(old["listening"]) - set(curr["listening"]))
        new_remotes = sorted(set(curr["established_remotes"]) - set(old["established_remotes"]))
        gw_changed = curr["gateway"] != old["gateway"]

        table = Table(
            title=f"[bold bright_green]NETWORK BASELINE DRIFT // {name}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="red" if (new_listen or gw_changed) else "bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Category", style="white", width=22)
        table.add_column("Delta", style="grey70")

        table.add_row("Gateway Status", f"[bold red]CHANGED ({old['gateway']} -> {curr['gateway']})[/]" if gw_changed else f"[bright_green]UNCHANGED ({curr['gateway']})[/]")
        table.add_row("New Listening Ports", f"[bold red]{', '.join(new_listen)}[/]" if new_listen else "[bright_green]None[/]")
        table.add_row("Closed Listening Ports", ", ".join(closed_listen) if closed_listen else "None")
        table.add_row("New Remote Connections", f"[yellow]{', '.join(new_remotes[:12])}[/]" if new_remotes else "[bright_green]None[/]")
        self.console.print(table)

        diff = {
            "baseline": name,
            "gateway_changed": gw_changed,
            "new_listening": new_listen,
            "closed_listening": closed_listen,
            "new_remotes": new_remotes,
        }
        self.reports.record("NETWORK_BASELINE", f"Network Baseline Drift: {name}", diff, severity="HIGH" if (new_listen or gw_changed) else "INFO")
        return diff

    def report(self, name: str = "default", fmt: str = "json") -> None:
        self.compare(name=name)
        self.reports.export_report(export_format=fmt, export_all=False)

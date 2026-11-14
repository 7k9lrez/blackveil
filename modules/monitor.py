"""Live Real-Time System, Network & Process Monitor for BLACKVEIL."""

from __future__ import annotations

import socket
import time
from collections import deque
from datetime import datetime
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.config import ConfigManager
from core.logger import BlackveilLogger
from modules.system_intel import format_bytes


class LiveMonitorModule:
    """Continuously updating Rich terminal telemetry monitor."""

    def __init__(self, console: Console, logger: BlackveilLogger, config: ConfigManager) -> None:
        self.console = console
        self.logger = logger
        self.config = config

    @staticmethod
    def _bar(pct: float, width: int = 18) -> str:
        filled = max(0, min(width, int(round((pct / 100.0) * width))))
        color = "bold red" if pct >= 85 else "yellow" if pct >= 65 else "bright_green"
        return f"[{color}]{'█' * filled}[/][grey35]{'░' * (width - filled)}[/] [{color}]{pct:5.1f}%[/]"

    def _build_dashboard(
        self,
        prev_net: Any,
        elapsed_step: float,
        events: deque[str],
        seen_listen_ports: set[int],
    ) -> tuple[Layout, Any]:
        cpu_pct = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        net_now = psutil.net_io_counters()

        dt = max(elapsed_step, 0.2)
        tx_rate = max(0.0, (net_now.bytes_sent - prev_net.bytes_sent) / dt)
        rx_rate = max(0.0, (net_now.bytes_recv - prev_net.bytes_recv) / dt)

        now_str = datetime.now().strftime("%H:%M:%S")
        if cpu_pct >= 85.0:
            events.appendleft(f"[bold red]{now_str} | ALERT | High CPU utilization: {cpu_pct:.1f}%[/]")
        if mem.percent >= 88.0:
            events.appendleft(f"[bold red]{now_str} | ALERT | High RAM pressure: {mem.percent:.1f}%[/]")

        # Top processes
        proc_rows: list[tuple[int, str, float, float]] = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                proc_rows.append(
                    (
                        info["pid"],
                        (info["name"] or "?")[:22],
                        float(info["cpu_percent"] or 0.0),
                        float(info["memory_percent"] or 0.0),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        proc_rows.sort(key=lambda r: (r[2], r[3]), reverse=True)

        # Active network connections
        conn_rows: list[tuple[str, str, str, str]] = []
        current_listen: set[int] = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    current_listen.add(c.laddr.port)
                if len(conn_rows) < 8 and c.status in {"ESTABLISHED", "LISTEN"}:
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                    conn_rows.append((proto, laddr, raddr, c.status))
        except psutil.AccessDenied:
            conn_rows.append(("N/A", "AccessDenied", "Run as Admin", "RESTRICTED"))

        new_ports = current_listen - seen_listen_ports
        if seen_listen_ports and new_ports:
            for p in sorted(new_ports):
                events.appendleft(f"[bold yellow]{now_str} | NET   | New listening port detected: {p}[/]")
        seen_listen_ports.update(current_listen)

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="top", size=11),
            Layout(name="middle"),
            Layout(name="footer", size=7),
        )
        layout["top"].split_row(Layout(name="resources"), Layout(name="network_io"))
        layout["middle"].split_row(Layout(name="processes"), Layout(name="connections"))

        header_text = Text.assemble(
            (" BLACKVEIL LIVE MONITOR ", "bold black on bright_green"),
            ("  Host: ", "grey70"),
            (socket.gethostname(), "bold white"),
            ("  |  Time: ", "grey70"),
            (now_str, "bright_green"),
            ("  |  Press ", "grey70"),
            ("CTRL+C", "bold red"),
            (" to exit live view", "grey70"),
        )
        layout["header"].update(Panel(header_text, border_style="bright_green", box=box.SQUARE))

        res_lines = [
            f"[white]CPU Total :[/] {self._bar(cpu_pct)}",
            f"[white]RAM Used  :[/] {self._bar(mem.percent)}  [grey70]({format_bytes(mem.used)} / {format_bytes(mem.total)})[/]",
            f"[white]Swap Used :[/] {self._bar(swap.percent)}  [grey70]({format_bytes(swap.used)} / {format_bytes(swap.total)})[/]",
            f"[white]Cores     :[/] " + "  ".join(f"C{i}:{c:.0f}%" for i, c in enumerate(per_core[:8])),
            f"[white]Processes :[/] [bright_green]{len(proc_rows)}[/] active",
        ]
        layout["resources"].update(
            Panel("\n".join(res_lines), title="[bold bright_green]SYSTEM TELEMETRY[/]", border_style="bright_green", box=box.SQUARE)
        )

        net_lines = [
            f"[white]TX Rate    :[/] [bright_green]{format_bytes(tx_rate)}/s[/]",
            f"[white]RX Rate    :[/] [bright_green]{format_bytes(rx_rate)}/s[/]",
            f"[white]Total Sent :[/] {format_bytes(net_now.bytes_sent)}",
            f"[white]Total Recv :[/] {format_bytes(net_now.bytes_recv)}",
            f"[white]ListenPort :[/] [bright_green]{len(current_listen)}[/] open sockets",
        ]
        layout["network_io"].update(
            Panel("\n".join(net_lines), title="[bold bright_green]NETWORK THROUGHPUT[/]", border_style="bright_green", box=box.SQUARE)
        )

        proc_table = Table(box=box.SIMPLE, header_style="bold bright_green", expand=True)
        proc_table.add_column("PID", style="bright_green", width=7, justify="right")
        proc_table.add_column("Process", style="white")
        proc_table.add_column("CPU%", justify="right", width=7)
        proc_table.add_column("MEM%", justify="right", width=7)
        for pid, name, c_pct, m_pct in proc_rows[:8]:
            proc_table.add_row(str(pid), name, f"{c_pct:.1f}", f"{m_pct:.1f}")
        layout["processes"].update(
            Panel(proc_table, title="[bold bright_green]TOP ACTIVE PROCESSES[/]", border_style="bright_green", box=box.SQUARE)
        )

        conn_table = Table(box=box.SIMPLE, header_style="bold bright_green", expand=True)
        conn_table.add_column("Proto", width=5, style="grey70")
        conn_table.add_column("Local", style="white")
        conn_table.add_column("Remote", style="bright_green")
        conn_table.add_column("State", width=11)
        for proto, laddr, raddr, st in conn_rows:
            conn_table.add_row(proto, laddr[:22], raddr[:22], st)
        layout["connections"].update(
            Panel(conn_table, title="[bold bright_green]LIVE SOCKETS[/]", border_style="bright_green", box=box.SQUARE)
        )

        event_text = "\n".join(list(events)[:4]) if events else "[grey70]No anomalies observed.[/]"
        layout["footer"].update(
            Panel(event_text, title="[bold bright_green]SYSTEM EVENT STREAM[/]", border_style="bright_green", box=box.SQUARE)
        )
        return layout, net_now

    def run_live(self, interval: float | None = None, duration: float = 0.0) -> None:
        """Start continuous live monitor until Ctrl+C or optional duration expires."""
        refresh_sec = max(0.4, interval if interval is not None else float(self.config.get("monitor_interval", 1.0)))
        events: deque[str] = deque(maxlen=12)
        events.appendleft(f"[bright_green]{datetime.now().strftime('%H:%M:%S')} | INFO  | Live telemetry stream initialized[/]")
        seen_listen: set[int] = set()

        # Prime CPU counters
        psutil.cpu_percent(interval=None, percpu=True)
        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        prev_net = psutil.net_io_counters()
        start_time = time.monotonic()
        last_tick = start_time
        self.logger.info("monitor", "Started live monitor session")

        try:
            with Live(console=self.console, refresh_per_second=2, screen=True) as live:
                while True:
                    time.sleep(refresh_sec)
                    now_tick = time.monotonic()
                    step = now_tick - last_tick
                    last_tick = now_tick
                    layout, prev_net = self._build_dashboard(prev_net, step, events, seen_listen)
                    live.update(layout)
                    if duration > 0 and (now_tick - start_time) >= duration:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            self.logger.info("monitor", "Stopped live monitor session")
            self.console.print("[bright_green][*][/] Live monitor terminated cleanly.")

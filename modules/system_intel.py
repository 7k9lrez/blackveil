"""System Intelligence & Process Analysis module for BLACKVEIL."""

from __future__ import annotations

import ctypes
import os
import platform
import re
import socket
import time
from datetime import datetime, timedelta
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager


def is_admin() -> bool:
    """Check whether the current process holds Administrator/root privileges."""
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


def format_bytes(num_bytes: float) -> str:
    """Convert byte count into human-readable units."""
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} EB"


class SystemIntelModule:
    """Collects real host telemetry, disk health, uptime, network I/O, and process analytics."""

    SUSPICIOUS_CMD_PATTERNS: list[tuple[str, str]] = [
        (r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}", "Encoded PowerShell command"),
        (r"(?:invoke-expression|\biex\b|downloadstring|webclient)", "Dynamic script download/execution pattern"),
        (r"(?:certutil\s+.*-urlcache|bitsadmin\s+.*/transfer)", "Living-off-the-Land file transfer binary"),
        (r"(?:mshta|regsvr32|rundll32)\s+.*(?:http://|https://|javascript:|vbscript:)", "Scripted LOLBin remote execution"),
        (r"(?:nc\.exe|ncat|netcat)\s+.*-e\s+", "Reverse shell flag detected"),
        (r"-w\s+hidden|-windowstyle\s+hidden", "Hidden window execution flag"),
    ]

    SUSPICIOUS_PATH_KEYWORDS = (
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "/tmp/",
        "/dev/shm/",
        "\\users\\public\\",
        "\\programdata\\temp",
    )

    SUSPICIOUS_PARENT_CHILD = {
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("outlook.exe", "powershell.exe"),
        ("powershell.exe", "mshta.exe"),
    }

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports

    def collect_system_snapshot(self, measure_net_window: float = 0.5) -> dict[str, Any]:
        """Gather real host hardware, OS, storage, uptime, and network throughput snapshot."""
        boot_ts = psutil.boot_time()
        boot_dt = datetime.fromtimestamp(boot_ts)
        uptime_delta = timedelta(seconds=int(time.time() - boot_ts))

        net_before = psutil.net_io_counters()
        cpu_total = psutil.cpu_percent(interval=measure_net_window)
        net_after = psutil.net_io_counters()

        elapsed = max(measure_net_window, 0.1)
        tx_rate = (net_after.bytes_sent - net_before.bytes_sent) / elapsed
        rx_rate = (net_after.bytes_recv - net_before.bytes_recv) / elapsed

        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_freq = psutil.cpu_freq()
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        disks: list[dict[str, Any]] = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append(
                    {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_bytes": usage.total,
                        "used_bytes": usage.used,
                        "free_bytes": usage.free,
                        "percent": usage.percent,
                    }
                )
            except (PermissionError, OSError):
                continue

        snapshot = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "os_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown",
            "python_version": platform.python_version(),
            "privileges": "ADMINISTRATOR / ROOT" if is_admin() else "STANDARD USER",
            "boot_time": boot_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": str(uptime_delta),
            "cpu": {
                "physical_cores": psutil.cpu_count(logical=False) or 0,
                "logical_cores": psutil.cpu_count(logical=True) or 0,
                "total_percent": cpu_total,
                "per_core_percent": cpu_per_core,
                "frequency_mhz": round(cpu_freq.current, 1) if cpu_freq else None,
            },
            "memory": {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "used_bytes": mem.used,
                "percent": mem.percent,
                "swap_total_bytes": swap.total,
                "swap_used_bytes": swap.used,
                "swap_percent": swap.percent,
            },
            "disks": disks,
            "network_io": {
                "bytes_sent_total": net_after.bytes_sent,
                "bytes_recv_total": net_after.bytes_recv,
                "packets_sent": net_after.packets_sent,
                "packets_recv": net_after.packets_recv,
                "tx_bytes_per_sec": round(tx_rate, 2),
                "rx_bytes_per_sec": round(rx_rate, 2),
            },
            "active_process_count": len(psutil.pids()),
        }
        return snapshot

    def show_system_intel(self) -> dict[str, Any]:
        """Render full System Intelligence report."""
        with self.console.status("[bold bright_green][*] Sampling host hardware & kernel telemetry...[/]", spinner="dots"):
            snap = self.collect_system_snapshot(measure_net_window=0.6)

        info_table = Table(
            title="[bold bright_green]SYSTEM INTELLIGENCE // HOST TELEMETRY[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        info_table.add_column("Metric", style="grey70", width=22)
        info_table.add_column("Value", style="white")

        priv_style = "bold bright_green" if "ADMIN" in snap["privileges"] else "bold yellow"
        info_table.add_row("Hostname / FQDN", f"[bright_green]{snap['hostname']}[/] ({snap['fqdn']})")
        info_table.add_row("Operating System", f"{snap['os_system']} {snap['os_release']} ({snap['architecture']})")
        info_table.add_row("OS Build", snap["os_version"])
        info_table.add_row("Processor", snap["processor"])
        info_table.add_row("Execution Context", f"[{priv_style}]{snap['privileges']}[/]")
        info_table.add_row("Boot Time / Uptime", f"{snap['boot_time']}  |  Up [bright_green]{snap['uptime']}[/]")
        info_table.add_row("Active Processes", str(snap["active_process_count"]))
        info_table.add_row(
            "Network Throughput",
            f"TX [bright_green]{format_bytes(snap['network_io']['tx_bytes_per_sec'])}/s[/]  |  "
            f"RX [bright_green]{format_bytes(snap['network_io']['rx_bytes_per_sec'])}/s[/]  "
            f"(Total: {format_bytes(snap['network_io']['bytes_sent_total'])} sent / {format_bytes(snap['network_io']['bytes_recv_total'])} recv)",
        )
        self.console.print(info_table)

        res_table = Table(
            title="[bold bright_green]COMPUTE & MEMORY UTILIZATION[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        res_table.add_column("Resource", style="white")
        res_table.add_column("Allocation / Cores", style="grey70")
        res_table.add_column("Used", style="white", justify="right")
        res_table.add_column("Utilization", justify="right")

        cpu_pct = snap["cpu"]["total_percent"]
        cpu_color = "bold red" if cpu_pct >= 85 else "yellow" if cpu_pct >= 65 else "bright_green"
        freq_txt = f" @ {snap['cpu']['frequency_mhz']} MHz" if snap["cpu"]["frequency_mhz"] else ""
        res_table.add_row(
            "CPU",
            f"{snap['cpu']['physical_cores']}P / {snap['cpu']['logical_cores']}L cores{freq_txt}",
            f"{len(snap['cpu']['per_core_percent'])} threads",
            f"[{cpu_color}]{cpu_pct:.1f}%[/]",
        )

        mem = snap["memory"]
        mem_color = "bold red" if mem["percent"] >= 85 else "yellow" if mem["percent"] >= 70 else "bright_green"
        res_table.add_row(
            "RAM",
            format_bytes(mem["total_bytes"]),
            format_bytes(mem["used_bytes"]),
            f"[{mem_color}]{mem['percent']:.1f}%[/]",
        )
        res_table.add_row(
            "Swap",
            format_bytes(mem["swap_total_bytes"]),
            format_bytes(mem["swap_used_bytes"]),
            f"[grey70]{mem['swap_percent']:.1f}%[/]",
        )
        self.console.print(res_table)

        disk_table = Table(
            title="[bold bright_green]STORAGE PARTITIONS[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        disk_table.add_column("Device", style="white")
        disk_table.add_column("Mount", style="grey70")
        disk_table.add_column("FS", style="grey70")
        disk_table.add_column("Total", justify="right", style="white")
        disk_table.add_column("Free", justify="right", style="bright_green")
        disk_table.add_column("Used %", justify="right")

        for disk in snap["disks"]:
            d_color = "bold red" if disk["percent"] >= 90 else "yellow" if disk["percent"] >= 75 else "bright_green"
            disk_table.add_row(
                disk["device"],
                disk["mountpoint"],
                disk["fstype"] or "-",
                format_bytes(disk["total_bytes"]),
                format_bytes(disk["free_bytes"]),
                f"[{d_color}]{disk['percent']:.1f}%[/]",
            )
        self.console.print(disk_table)

        self.reports.record("SYSTEM_INTEL", "Host System Telemetry Snapshot", snap)
        return snap

    def _collect_processes(self) -> list[dict[str, Any]]:
        """Enumerate live OS processes safely without crashing on AccessDenied."""
        # Prime cpu_percent measurements briefly
        procs: list[psutil.Process] = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc.cpu_percent(interval=None)
                procs.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(0.15)
        results: list[dict[str, Any]] = []
        for proc in procs:
            try:
                with proc.oneshot():
                    pid = proc.pid
                    name = proc.name()
                    ppid = proc.ppid()
                    status = proc.status()
                    cpu = proc.cpu_percent(interval=None)
                    mem_pct = proc.memory_percent()
                    mem_rss = proc.memory_info().rss
                    try:
                        username = proc.username()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        username = "ACCESS_DENIED"
                    try:
                        exe = proc.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        exe = ""
                    try:
                        cmdline = " ".join(proc.cmdline())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        cmdline = ""

                    results.append(
                        {
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                            "status": status,
                            "username": username,
                            "cpu_percent": round(cpu, 2),
                            "mem_percent": round(mem_pct, 2),
                            "rss_bytes": mem_rss,
                            "exe": exe,
                            "cmdline": cmdline,
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return results

    def analyze_process_risk(self, proc: dict[str, Any], name_by_pid: dict[int, str]) -> list[str]:
        """Evaluate real heuristic security indicators for an active process."""
        findings: list[str] = []
        exe_lower = (proc.get("exe") or "").lower()
        cmd_lower = (proc.get("cmdline") or "").lower()
        pname_lower = (proc.get("name") or "").lower()
        parent_name = name_by_pid.get(proc.get("ppid", -1), "").lower()

        for suspicious_dir in self.SUSPICIOUS_PATH_KEYWORDS:
            if suspicious_dir in exe_lower:
                cleaned_dir = suspicious_dir.strip("\\/")
                findings.append(f"Executable running from volatile/temp path ({cleaned_dir})")
                break

        for pattern, desc in self.SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                findings.append(desc)

        if (parent_name, pname_lower) in self.SUSPICIOUS_PARENT_CHILD:
            findings.append(f"Unusual parent-child spawn chain: {parent_name} -> {pname_lower}")

        if proc.get("cpu_percent", 0.0) > 80.0:
            findings.append(f"High CPU consumption ({proc['cpu_percent']:.1f}%)")

        return findings

    def list_processes(self, limit: int = 25, sort_by: str = "cpu", suspicious_only: bool = False) -> list[dict[str, Any]]:
        """List active system processes or filter by suspicious heuristics."""
        with self.console.status("[bold bright_green][*] Enumerating active OS processes...[/]", spinner="dots"):
            procs = self._collect_processes()

        name_by_pid = {p["pid"]: p["name"] for p in procs}
        for p in procs:
            p["risk_flags"] = self.analyze_process_risk(p, name_by_pid)

        if suspicious_only:
            filtered = [p for p in procs if p["risk_flags"]]
        else:
            filtered = procs

        key_map = {
            "cpu": lambda x: x["cpu_percent"],
            "mem": lambda x: x["mem_percent"],
            "pid": lambda x: x["pid"],
            "name": lambda x: x["name"].lower(),
        }
        sort_fn = key_map.get(sort_by.lower(), key_map["cpu"])
        reverse = sort_by.lower() in {"cpu", "mem"}
        filtered.sort(key=sort_fn, reverse=reverse)
        displayed = filtered[:limit] if not suspicious_only else filtered

        title = (
            "[bold red]PROCESS SECURITY AUDIT // FLAGGED INDICATORS[/]"
            if suspicious_only
            else f"[bold bright_green]ACTIVE PROCESSES (TOP {len(displayed)} BY {sort_by.upper()})[/]"
        )
        table = Table(title=title, box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("PID", style="bright_green", width=7, justify="right")
        table.add_column("PPID", style="grey70", width=7, justify="right")
        table.add_column("Name", style="white", width=24)
        table.add_column("User", style="grey70", width=18)
        table.add_column("CPU%", justify="right", width=7)
        table.add_column("RAM", justify="right", width=10)
        table.add_column("Indicators / Path", style="grey70")

        if not displayed:
            if suspicious_only:
                self.console.print("[bold bright_green][+] No suspicious process indicators detected in active process table.[/]")
            else:
                self.console.print("[yellow][!] No processes returned.[/]")
        else:
            for p in displayed:
                flags = p["risk_flags"]
                indicator_txt = (
                    f"[bold red]{'; '.join(flags)}[/]"
                    if flags
                    else (p["exe"][:48] + "..." if len(p["exe"]) > 48 else p["exe"] or "[grey50]protected[/]")
                )
                cpu_str = f"[bold red]{p['cpu_percent']:.1f}[/]" if p["cpu_percent"] > 50 else f"{p['cpu_percent']:.1f}"
                table.add_row(
                    str(p["pid"]),
                    str(p["ppid"]),
                    p["name"][:24],
                    p["username"].split("\\")[-1][:18],
                    cpu_str,
                    format_bytes(p["rss_bytes"]),
                    indicator_txt,
                )
            self.console.print(table)

        if not is_admin():
            self.console.print("[grey70][*] Note: Some system-level process paths/command lines require Administrator/root privileges.[/]")

        self.reports.record(
            "PROCESS_AUDIT",
            "Suspicious Process Scan" if suspicious_only else f"Top {len(displayed)} Processes",
            {"total_processes": len(procs), "flagged_count": sum(1 for p in procs if p["risk_flags"]), "processes": displayed},
            severity="WARNING" if any(p["risk_flags"] for p in displayed) else "INFO",
        )
        return displayed

    def inspect_process(self, pid: int) -> dict[str, Any] | None:
        """Inspect a specific PID in detail including open network sockets and command line."""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                info: dict[str, Any] = {
                    "pid": proc.pid,
                    "ppid": proc.ppid(),
                    "name": proc.name(),
                    "status": proc.status(),
                    "created": datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                    "cpu_percent": proc.cpu_percent(interval=0.2),
                    "memory_rss": format_bytes(proc.memory_info().rss),
                    "memory_percent": round(proc.memory_percent(), 2),
                    "threads": proc.num_threads(),
                }
                try:
                    info["username"] = proc.username()
                except psutil.AccessDenied:
                    info["username"] = "ACCESS_DENIED (Requires Admin)"
                try:
                    info["exe"] = proc.exe()
                except psutil.AccessDenied:
                    info["exe"] = "ACCESS_DENIED (Requires Admin)"
                try:
                    info["cmdline"] = " ".join(proc.cmdline()) or "(empty)"
                except psutil.AccessDenied:
                    info["cmdline"] = "ACCESS_DENIED (Requires Admin)"
                try:
                    info["cwd"] = proc.cwd()
                except (psutil.AccessDenied, FileNotFoundError):
                    info["cwd"] = "ACCESS_DENIED"
                try:
                    conns = proc.net_connections(kind="inet")
                    info["connections"] = [
                        {
                            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                            "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                            "status": c.status,
                        }
                        for c in conns
                    ]
                except psutil.AccessDenied:
                    info["connections"] = []
                    info["connections_note"] = "ACCESS_DENIED (Requires Admin)"
        except psutil.NoSuchProcess:
            self.console.print(f"[bold red][-][/] Process with PID {pid} does not exist.")
            return None
        except psutil.AccessDenied:
            self.console.print(f"[bold red][-][/] Access denied inspecting PID {pid}. Run BLACKVEIL as Administrator/root.")
            return None

        lines = [
            f"[white]PID / PPID  :[/] [bright_green]{info['pid']}[/] / {info['ppid']}",
            f"[white]Name        :[/] [bright_green]{info['name']}[/] ({info['status']})",
            f"[white]User        :[/] {info['username']}",
            f"[white]Started     :[/] {info['created']}",
            f"[white]Executable  :[/] {info['exe']}",
            f"[white]Working Dir :[/] {info['cwd']}",
            f"[white]CommandLine :[/] {info['cmdline']}",
            f"[white]CPU / RAM   :[/] {info['cpu_percent']:.1f}% CPU  |  {info['memory_rss']} ({info['memory_percent']}%)",
            f"[white]Threads     :[/] {info['threads']}",
            f"[white]Net Sockets :[/] {len(info['connections'])}",
        ]
        for conn in info["connections"][:10]:
            lines.append(f"   [grey70]->[/] {conn['local']}  ==>  {conn['remote']}  [{conn['status']}]")

        self.console.print(
            Panel(
                "\n".join(lines),
                title=f"[bold bright_green]PROCESS INSPECTOR // PID {pid}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        self.reports.record("PROCESS_INSPECT", f"Process Inspection PID {pid}", info)
        return info

"""Module 08: Configuration Auditor - Audits Windows & Linux system, firewall, permissions, and services."""

from __future__ import annotations

import os
import platform
import stat
import subprocess
from pathlib import Path
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.table import Table

from core.config import BASE_DIR
from core.logger import BlackveilLogger
from modules.reports import ReportManager
from modules.system_intel import is_admin


class ConfigAuditorModule:
    """Performs real security posture checks across OS settings, firewall, permissions, and running services."""

    RISKY_SERVICES = {"telnet", "tlntsvr", "ftp", "ftpsvc", "tftpd", "rsh", "rexec", "snmp"}

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports

    @staticmethod
    def _run_cmd(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
            return res.returncode, (res.stdout + "\n" + res.stderr).strip()
        except Exception as exc:
            return 1, str(exc)

    def audit_system(self) -> list[dict[str, str]]:
        sys_name = platform.system()
        checks: list[dict[str, str]] = [
            {
                "check": "Execution Privilege Separation",
                "status": "WARN" if is_admin() else "PASS",
                "detail": "Running elevated (use least-privilege when scanning untrusted artifacts)" if is_admin() else "Running as standard user",
            }
        ]

        if sys_name == "Windows":
            rc, out = self._run_cmd(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA"])
            uac_on = rc == 0 and "0x1" in out.lower()
            checks.append({"check": "Windows UAC (EnableLUA)", "status": "PASS" if uac_on else "FAIL", "detail": "Enabled (0x1)" if uac_on else "Disabled or unreadable"})

            rc_def, out_def = self._run_cmd(["sc", "query", "WinDefend"])
            def_on = rc_def == 0 and "RUNNING" in out_def.upper()
            checks.append({"check": "Windows Defender Service", "status": "PASS" if def_on else "WARN", "detail": "RUNNING" if def_on else "Not running / third-party AV"})
        else:
            aslr_path = Path("/proc/sys/kernel/randomize_va_space")
            if aslr_path.exists():
                val = aslr_path.read_text(encoding="utf-8", errors="ignore").strip()
                checks.append({"check": "Kernel ASLR (randomize_va_space)", "status": "PASS" if val == "2" else "WARN", "detail": f"Value={val} (2=Full ASLR)"})
            ipf = Path("/proc/sys/net/ipv4/ip_forward")
            if ipf.exists():
                val = ipf.read_text(encoding="utf-8", errors="ignore").strip()
                checks.append({"check": "IPv4 Forwarding", "status": "PASS" if val == "0" else "INFO", "detail": f"ip_forward={val}"})

        self._render_table("SYSTEM CONFIGURATION AUDIT", checks)
        self.reports.record("AUDIT_SYSTEM", "OS Security Configuration Audit", {"checks": checks})
        return checks

    def audit_firewall(self) -> list[dict[str, str]]:
        sys_name = platform.system()
        checks: list[dict[str, str]] = []
        if sys_name == "Windows":
            rc, out = self._run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
            if rc == 0:
                on_count = out.upper().count("ON")
                off_count = out.upper().count("OFF")
                checks.append({
                    "check": "Windows Defender Firewall Profiles",
                    "status": "PASS" if off_count == 0 and on_count >= 1 else "FAIL",
                    "detail": f"Active profiles ON={on_count}, OFF={off_count}",
                })
            else:
                checks.append({"check": "Windows Firewall Query", "status": "WARN", "detail": out[:120]})
        else:
            rc, out = self._run_cmd(["ufw", "status"])
            if rc == 0:
                active = "Status: active" in out
                checks.append({"check": "UFW Firewall", "status": "PASS" if active else "FAIL", "detail": out.splitlines()[0]})
            else:
                rc2, out2 = self._run_cmd(["iptables", "-L", "-n"])
                checks.append({
                    "check": "Netfilter / iptables",
                    "status": "PASS" if rc2 == 0 else "INFO",
                    "detail": f"{len(out2.splitlines())} rules inspected" if rc2 == 0 else "Requires root to query iptables/nftables",
                })
        self._render_table("FIREWALL AUDIT", checks)
        self.reports.record("AUDIT_FIREWALL", "Firewall Posture Audit", {"checks": checks})
        return checks

    def audit_permissions(self, target_dir: str | None = None) -> list[dict[str, str]]:
        root = Path(target_dir).expanduser() if target_dir else BASE_DIR
        checks: list[dict[str, str]] = []
        if not root.exists():
            self.console.print(f"[bold red][-][/] Directory not found: {root}")
            return []

        world_writable: list[str] = []
        for p in root.rglob("*"):
            if "__pycache__" in p.parts:
                continue
            try:
                mode = p.stat().st_mode
                if platform.system() != "Windows" and (mode & stat.S_IWOTH):
                    world_writable.append(str(p))
            except OSError:
                continue

        checks.append({
            "check": f"World-Writable Files ({root.name})",
            "status": "WARN" if world_writable else "PASS",
            "detail": f"{len(world_writable)} world-writable entries found" if world_writable else "Zero world-writable files detected",
        })
        if (BASE_DIR / "data" / "blackveil.db").exists():
            db_mode = stat.filemode((BASE_DIR / "data" / "blackveil.db").stat().st_mode)
            checks.append({"check": "BLACKVEIL SQLite DB Mode", "status": "INFO", "detail": db_mode})

        self._render_table("FILESYSTEM PERMISSIONS AUDIT", checks)
        self.reports.record("AUDIT_PERMISSIONS", "Filesystem Permissions Audit", {"checks": checks, "world_writable": world_writable[:20]})
        return checks

    def audit_services(self) -> list[dict[str, str]]:
        checks: list[dict[str, str]] = []
        sys_name = platform.system()
        running_names: list[str] = []

        if sys_name == "Windows" and hasattr(psutil, "win_service_iter"):
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    if info.get("status") == "running":
                        running_names.append(info.get("name", "").lower())
                except Exception:
                    continue
        else:
            for proc in psutil.process_iter(["name"]):
                try:
                    running_names.append((proc.info["name"] or "").lower())
                except Exception:
                    continue

        risky_found = sorted({name for name in running_names if name in self.RISKY_SERVICES})
        checks.append({
            "check": "Running Services / Daemons Count",
            "status": "INFO",
            "detail": f"{len(running_names)} active services/processes audited",
        })
        checks.append({
            "check": "Legacy Cleartext Services (Telnet/FTP/SNMP)",
            "status": "FAIL" if risky_found else "PASS",
            "detail": f"Detected: {', '.join(risky_found)}" if risky_found else "None running",
        })
        self._render_table("SERVICES SECURITY AUDIT", checks)
        self.reports.record("AUDIT_SERVICES", "Services Security Audit", {"checks": checks, "risky_services": risky_found})
        return checks

    def _render_table(self, title: str, checks: list[dict[str, str]]) -> None:
        table = Table(title=f"[bold bright_green]{title}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Security Check", style="white", width=36)
        table.add_column("Status", width=8)
        table.add_column("Details", style="grey70")
        for c in checks:
            st = c["status"]
            col = "bold bright_green" if st == "PASS" else "bold red" if st == "FAIL" else "bold yellow" if st == "WARN" else "grey70"
            table.add_row(c["check"], f"[{col}]{st}[/]", c["detail"])
        self.console.print(table)

    def full_report(self, fmt: str = "json") -> None:
        self.audit_system()
        self.audit_firewall()
        self.audit_permissions()
        self.audit_services()
        self.reports.export_report(export_format=fmt, export_all=True)

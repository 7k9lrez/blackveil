"""Unified Global Command Parser & Dispatcher for BLACKVEIL X Ecosystem."""

from __future__ import annotations

import argparse
import platform
import shlex
import socket
import sys
import time
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ai.analyst import AISecurityAnalyst
from automation.engine import AutomationEngineModule
from core.config import ConfigManager, DATA_DIR, DB_FILE, LOGS_DIR, REPORTS_DIR, SecretsManager
from core.logger import BlackveilLogger, HistoryManager
from core.session_recorder import SessionRecorder
from database.db import DatabaseManager, utc_now
from labs.ctf_engine import CTFEngineModule
from labs.red_blue import RedBlueTeamModule
from labs.vuln_lab import VulnLabModule
from missions.manager import MissionManager
from modules.cert_watcher import CertWatcherModule
from modules.computer_search import ComputerSearchModule
from modules.config_auditor import ConfigAuditorModule
from modules.deps_guard import DependencyGuardModule
from modules.dns_intel import DnsIntelModule
from modules.evidence_vault import EvidenceVaultModule
from modules.external_search import ExternalSearchModule
from modules.forensics import ForensicsModule
from modules.incident_engine import IncidentResponseModule
from modules.integrity_guard import FileIntegrityGuard
from modules.ip_intel import IpIntelModule
from modules.knowledge_base import KnowledgeBaseModule
from modules.local_website import LocalWebsiteModule
from modules.log_intel import LogIntelligenceModule
from modules.monitor import LiveMonitorModule
from modules.net_baseline import NetworkBaselineModule
from modules.network import NetworkModule, scapy_available
from modules.password_lab import PasswordLabModule
from modules.pcap_analyzer import PcapAnalyzerModule
from modules.reports import ReportManager
from modules.secret_scanner import SecretScannerModule
from modules.system_intel import SystemIntelModule, is_admin
from modules.threat_intel import ThreatIntelModule
from modules.url_detector import UrlDetectorModule
from modules.warroom import WarRoomModule
from modules.website_intel import WebsiteIntelModule
from plugins.engine import PluginEngineModule
from sandbox.container_inspector import ContainerInspectorModule
from sandbox.manager import SandboxManager


class NonExitingParser(argparse.ArgumentParser):
    """ArgumentParser subclass that raises ValueError instead of terminating the shell."""

    def error(self, message: str) -> None:
        raise ValueError(message)

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if message:
            raise ValueError(message.strip())
        raise SystemExit(status)


def tokenize_command(raw_line: str) -> list[str]:
    """Tokenize input while preserving Windows backslashes in paths."""
    tokens = shlex.split(raw_line, posix=False)
    cleaned: list[str] = []
    for tok in tokens:
        if len(tok) >= 2 and ((tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'")):
            cleaned.append(tok[1:-1])
        else:
            cleaned.append(tok)
    return cleaned


class CommandDispatcher:
    """Routes interactive shell commands & direct CLI invocations across all BLACKVEIL X subsystems."""

    COMMANDS: dict[str, tuple[str, str]] = {
        "help": ("Show command matrix or command details", "help [command]"),
        "clear": ("Clear terminal screen", "clear"),
        "exit": ("Exit BLACKVEIL terminal", "exit"),
        "about": ("Show BLACKVEIL X Ecosystem overview", "about"),
        "status": ("Show privileges, SQLite schema, Docker & module status", "status"),
        "sandbox": ("Docker isolated sandbox lifecycle & snapshots", "sandbox <create|list|start|stop|delete|enter|inspect|snapshot|restore|reset|resources|network|cleanup>"),
        "container": ("Docker container inventory, stats & CIS audit", "container <list|inspect|resources|audit|report>"),
        "vuln": ("Vulnerability Lab training machines", "vuln <list|install|start|inspect|reset> [ID]"),
        "ai": ("Gemini AI Assistant, chat & MITRE analyst", "ai | ai <ask|analyze|explain|investigate|config|report> [target]"),
        "website": ("Website intelligence scan, IP & local mirror", "website <scan|ip|local> <URL|status|stop|inspect>"),
        "ipinfo": ("Public/Private IP ASN, RDAP & GeoIP lookup", "ipinfo <IP>"),
        "ip": ("Own public IP, local IPs, connections & log IPs", "ip <local|connections|report|logs analyze> [target]"),
        "url": ("Malicious URL structure, TLS & reputation check", "url <check|reputation|analyze> <URL>"),
        "computer": ("Local filesystem search, services, startup & disk", "computer <search|find|processes|services|startup|disk|report>"),
        "search": ("Multi-source external intel search & deep summary", "search [web|google|sources|deep|report] <QUERY>"),
        "threat": ("Threat Intelligence IOC lookup & feeds", "threat <lookup|analyze|feed|report> [observable]"),
        "integrity": ("SHA-256 File Integrity Guard & watcher", "integrity <baseline|scan|diff|watch> [--path DIR]"),
        "logs": ("Log Intelligence (Windows EventLog / file / timeline)", "logs <analyze|search|correlate|timeline|export> [--file PATH]"),
        "evidence": ("Digital Evidence Vault & chain of custody", "evidence <add|list|verify|export> [target]"),
        "baseline": ("Host Network Baseline capture & drift detection", "baseline <create|compare|inspect|report> [name]"),
        "audit": ("OS, firewall, permissions & services security audit", "audit <system|firewall|permissions|services|report>"),
        "secret": ("Source & config credential scanner (masked)", "secret <scan|inspect|report> [path]"),
        "incident": ("SOC Incident Response tracking & timelines", "incident <create|list|investigate|timeline|close>"),
        "pcap": ("Pure-Python PCAP analyzer & packet inspector", "pcap <load|summary|filter|inspect|export> [file]"),
        "dns": ("DNS multi-record lookup & resolver comparison", "dns <lookup|inspect|compare|report> <domain>"),
        "cert": ("SSL/TLS X.509 certificate & expiry watcher", "cert <inspect|expiry|check|report> <host>"),
        "deps": ("Python dependency tree & CVE audit", "deps <scan|tree|outdated|audit|report>"),
        "ctf": ("Local isolated CTF challenges & scoreboard", "ctf <list|start|hint|submit|scoreboard>"),
        "automation": ("Multi-step security playbook automation", "automation <create|list|run|history|disable>"),
        "kb": ("Cybersecurity Knowledge Base & operator notes", "kb <search|add|list|explain|export>"),
        "plugin": ("Signed & AST-audited Python plugin engine", "plugin <list|install|inspect|enable|disable|create|run>"),
        "redteam": ("Isolated Red Team adversary emulation", "redteam start [--scenario full-chain]"),
        "blueteam": ("Blue Team detection & TTP coverage scoring", "blueteam start"),
        "team": ("Purple Team status, report & workspace reset", "team <status|report|reset>"),
        "mission": ("Operations missions board & submissions", "mission <list|start|inspect|submit|history>"),
        "profile": ("Operator XP, level, rank & stats", "profile [stats]"),
        "achievements": ("View unlocked & locked achievements", "achievements"),
        "session": ("Terminal session recorder with secret masking", "session <start|stop|list|replay|export>"),
        "intel": ("Host system & network intelligence", "intel --system | --network | --dns DOMAIN | --all"),
        "scan": ("Authorized local subnet discovery & port audit", "scan --local [--subnet CIDR] | scan --ports TARGET"),
        "ports": ("TCP port audit & local listening sockets", "ports [TARGET] [--ports SPEC] [--listening]"),
        "trace": ("Real OS traceroute", "trace TARGET [--max-hops 20]"),
        "network": ("Interfaces, gateway, DNS & connections", "network [--info] [--interfaces] [--connections] [--dns DOMAIN]"),
        "process": ("Active processes, risk audit & PID inspector", "process [--top 25] [--suspicious] [--inspect PID]"),
        "hash": ("Cryptographic hashing & integrity verification", "hash --file PATH [--verify HASH] | --text TEXT"),
        "forensic": ("Digital forensics: magic bytes, PE, entropy & IOCs", "forensic --file PATH [--save-baseline] [--export json|txt]"),
        "password": ("Password Lab: entropy, generator & test-hash audit", "password --check PW | --generate | --dict-test [PW]"),
        "simulate": ("Cyber War Room defensive scenarios", "simulate --scenario <brute-force|port-scan|suspicious-process|ransomware|log-analysis|incident-detection>"),
        "monitor": ("Live real-time terminal telemetry dashboard", "monitor --live [--interval 1.0]"),
        "history": ("Command history viewer", "history [--limit 25] [--clear]"),
        "config": ("Configuration viewer & editor", "config [--show] [--set KEY VAL] [--reset]"),
        "report": ("Advanced Report Engine (TXT/JSON/CSV/PDF)", "report <create|list|inspect|export> | --export [--format pdf]"),
    }

    def __init__(
        self,
        console: Console,
        config: ConfigManager,
        logger: BlackveilLogger,
        history: HistoryManager,
        db: DatabaseManager | None = None,
    ) -> None:
        self.console = console
        self.config = config
        self.logger = logger
        self.history = history
        self.db = db or DatabaseManager()

        self.reports = ReportManager(console, logger, self.db)
        self.session_recorder = SessionRecorder(console, self.db)
        self.sys_intel = SystemIntelModule(console, logger, self.reports)
        self.network = NetworkModule(console, logger, config, self.reports)
        self.forensics = ForensicsModule(console, logger, self.reports)
        self.password_lab = PasswordLabModule(console, logger, self.reports)
        self.warroom = WarRoomModule(console, logger, self.reports, self.sys_intel, self.forensics, self.password_lab)
        self.monitor = LiveMonitorModule(console, logger, config)

        # BLACKVEIL X Subsystems
        self.sandbox = SandboxManager(console, logger, config, self.db, self.reports)
        self.container_inspector = ContainerInspectorModule(console, logger, self.sandbox, self.reports)
        self.vuln_lab = VulnLabModule(console, logger, self.db, self.reports)
        self.secrets = SecretsManager()
        self.ai_analyst = AISecurityAnalyst(console, logger, config, self.db, self.reports, secrets=self.secrets)
        self.threat_intel = ThreatIntelModule(console, logger, self.db, self.reports)
        self.integrity_guard = FileIntegrityGuard(console, logger, self.db, self.reports)
        self.log_intel = LogIntelligenceModule(console, logger, self.db, self.reports)
        self.evidence_vault = EvidenceVaultModule(console, logger, self.db, self.reports)
        self.net_baseline = NetworkBaselineModule(console, logger, self.db, self.network, self.reports)
        self.config_auditor = ConfigAuditorModule(console, logger, self.reports)
        self.secret_scanner = SecretScannerModule(console, logger, self.reports)
        self.incident_engine = IncidentResponseModule(console, logger, self.db, self.reports)
        self.pcap_analyzer = PcapAnalyzerModule(console, logger, self.reports)
        self.dns_intel = DnsIntelModule(console, logger, self.reports)
        self.cert_watcher = CertWatcherModule(console, logger, self.reports)
        self.deps_guard = DependencyGuardModule(console, logger, self.reports)
        self.website_intel = WebsiteIntelModule(console, logger, self.db, self.reports, self.dns_intel, self.cert_watcher)
        self.local_website = LocalWebsiteModule(console, logger, config, self.db, self.reports)
        self.ip_intel = IpIntelModule(console, logger, self.network, self.reports)
        self.url_detector = UrlDetectorModule(console, logger, config, self.secrets, self.threat_intel, self.reports)
        self.computer_search = ComputerSearchModule(console, logger, config, self.db, self.sys_intel, self.reports)
        self.external_search = ExternalSearchModule(console, logger, config, self.secrets, self.db, self.ai_analyst, self.reports)
        self.missions = MissionManager(console, logger, self.db)
        self.ctf_engine = CTFEngineModule(console, logger, self.db, self.missions)
        self.automation = AutomationEngineModule(console, logger, self.db)
        self.kb = KnowledgeBaseModule(console, logger, self.db)
        self.plugins = PluginEngineModule(console, logger, self.db)
        self.red_blue = RedBlueTeamModule(console, logger, self.db, self.reports, self.forensics)
        self.should_exit = False

    def execute_line(self, raw_line: str) -> int:
        stripped = raw_line.strip()
        if not stripped:
            return 0
        try:
            tokens = tokenize_command(stripped)
        except ValueError as exc:
            self.console.print(f"[bold red][-][/] Syntax error: {exc}")
            return 1
        if not tokens:
            return 0

        masked_cmd = self.session_recorder.mask_sensitive(stripped)
        if tokens[0].lower() not in {"history", "clear"}:
            self.history.add(masked_cmd)

        t0 = time.perf_counter()
        rc = self.execute_tokens(tokens)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        try:
            with self.db.connection() as conn:
                conn.execute(
                    "INSERT INTO command_history (command, status_code, executed_at) VALUES (?, ?, ?)",
                    (masked_cmd, rc, utc_now()),
                )
        except Exception:
            pass

        if tokens[0].lower() != "session":
            self.session_recorder.record_command(masked_cmd, rc, elapsed_ms)

        return rc

    def execute_tokens(self, tokens: list[str]) -> int:
        cmd = tokens[0].lower()
        args = tokens[1:]

        if cmd in {"exit", "quit"}:
            if self.session_recorder.active_session_id:
                self.session_recorder.stop()
            self.should_exit = True
            self.console.print("[bright_green][*][/] Terminating BLACKVEIL X session. Stay sharp.")
            return 0
        if cmd == "clear":
            self.console.clear()
            return 0
        if cmd == "help":
            return self._cmd_help(args)
        if cmd == "about":
            return self._cmd_about()
        if cmd == "status":
            return self._cmd_status()

        self.logger.info("dispatcher", f"Command: {cmd} {' '.join(args)}")

        routes: dict[str, Any] = {
            "intel": self._cmd_intel,
            "scan": self._cmd_scan,
            "ports": self._cmd_ports,
            "trace": self._cmd_trace,
            "network": self._cmd_network,
            "process": self._cmd_process,
            "hash": self._cmd_hash,
            "forensic": self._cmd_forensic,
            "password": self._cmd_password,
            "pwlab": self._cmd_password,
            "simulate": self._cmd_simulate,
            "monitor": self._cmd_monitor,
            "history": self._cmd_history,
            "config": self._cmd_config,
            "report": self._cmd_report,
            "sandbox": self._cmd_sandbox,
            "container": self._cmd_container,
            "vuln": self._cmd_vuln,
            "ai": self._cmd_ai,
            "website": self._cmd_website,
            "ipinfo": self._cmd_ipinfo,
            "ip": self._cmd_ip,
            "url": self._cmd_url,
            "computer": self._cmd_computer,
            "search": self._cmd_search,
            "threat": self._cmd_threat,
            "integrity": self._cmd_integrity,
            "logs": self._cmd_logs,
            "evidence": self._cmd_evidence,
            "baseline": self._cmd_baseline,
            "audit": self._cmd_audit,
            "secret": self._cmd_secret,
            "incident": self._cmd_incident,
            "pcap": self._cmd_pcap,
            "dns": self._cmd_dns,
            "cert": self._cmd_cert,
            "deps": self._cmd_deps,
            "ctf": self._cmd_ctf,
            "automation": self._cmd_automation,
            "kb": self._cmd_kb,
            "plugin": self._cmd_plugin,
            "redteam": self._cmd_redteam,
            "blueteam": self._cmd_blueteam,
            "team": self._cmd_team,
            "mission": self._cmd_mission,
            "profile": self._cmd_profile,
            "achievements": lambda _: (self.missions.show_achievements(), 0)[1],
            "session": self._cmd_session,
        }

        handler = routes.get(cmd)
        if not handler:
            self.console.print(f"[bold red][-][/] Unknown command '{cmd}'. Type [bright_green]help[/] to view commands.")
            return 127

        try:
            return int(handler(args))
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow][!][/] Operation cancelled by user (CTRL+C).")
            return 130
        except ValueError as exc:
            self.console.print(f"[bold red][-][/] Argument error: {exc}")
            if cmd in self.COMMANDS:
                self.console.print(f"[grey70]Usage: {self.COMMANDS[cmd][1]}[/]")
            return 2
        except Exception as exc:
            self.logger.error("dispatcher", f"Unhandled error in '{cmd}': {exc}")
            self.console.print(f"[bold red][-][/] Execution error in '{cmd}': {exc}")
            return 1

    # --- Core Meta Commands ---
    def _cmd_help(self, args: list[str]) -> int:
        if args:
            target = args[0].lower()
            if target in self.COMMANDS:
                desc, usage = self.COMMANDS[target]
                self.console.print(
                    Panel(
                        f"[white]Command :[/] [bold bright_green]{target}[/]\n"
                        f"[white]Purpose :[/] {desc}\n"
                        f"[white]Usage   :[/] [bright_green]{usage}[/]",
                        title="[bold bright_green]COMMAND HELP[/]",
                        border_style="bright_green",
                        box=box.SQUARE,
                    )
                )
                return 0
            self.console.print(f"[bold red][-][/] No help entry for '{target}'.")
            return 1

        table = Table(
            title="[bold bright_green]BLACKVEIL X ECOSYSTEM // GLOBAL COMMAND MATRIX[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Command", style="bold bright_green", width=13)
        table.add_column("Description", style="white", width=44)
        table.add_column("Syntax", style="grey70")
        for name, (desc, usage) in self.COMMANDS.items():
            table.add_row(name, desc, usage)
        self.console.print(table)
        return 0

    def _cmd_about(self) -> int:
        self.console.print(
            Panel(
                "[bold bright_green]BLACKVEIL X // ULTIMATE CYBERSECURITY ECOSYSTEM[/]\n"
                "[white]Subsystems :[/] Hardened Docker Sandbox Infrastructure, 20 Security Modules,\n"
                "             AI Security Analyst, Missions & CTF Arena, Terminal Session Recorder,\n"
                "             SQLite Migration Engine, Multi-Format Reporting (TXT/JSON/CSV/PDF).\n"
                "[grey70]ONE TERMINAL. ONE ECOSYSTEM. INFINITE POSSIBILITIES.[/]",
                title="[bold bright_green]ABOUT BLACKVEIL X[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return 0

    def _cmd_status(self) -> int:
        docker_ok, docker_info = self.sandbox.check_docker_ready(quiet=True)
        table = Table(title="[bold bright_green]BLACKVEIL X RUNTIME STATUS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", show_header=False)
        table.add_column("Component", style="grey70", width=26)
        table.add_column("State", style="white")
        table.add_row("Host / OS", f"{socket.gethostname()} ({platform.system()} {platform.release()})")
        table.add_row("Python Runtime", sys.version.split()[0])
        table.add_row("Privileges", "[bold bright_green]ADMIN/ROOT[/]" if is_admin() else "[bold yellow]STANDARD USER[/]")
        table.add_row("SQLite Database", f"[bright_green]READY[/] (Schema v{self.db.get_schema_version()} @ {DB_FILE.name})")
        table.add_row("Docker Sandbox Engine", f"[bright_green]ONLINE ({docker_info})[/]" if docker_ok else f"[yellow]UNAVAILABLE[/] ({docker_info[:70]})")
        table.add_row("Scapy Engine", "[bright_green]AVAILABLE[/]" if scapy_available() else "[yellow]SOCKET FALLBACK[/]")
        opera_st = self.external_search.detect_opera_browser()
        ai_key_set = bool(self.ai_analyst.get_api_key())
        table.add_row("Gemini AI Assistant", f"[bright_green]CONFIGURED ({self.config.get('ai_model')})[/]" if ai_key_set else "[yellow]OFFLINE MITRE MODE (Run `ai config --api-key`)[/]")
        table.add_row("Opera Browser", f"[bright_green]INSTALLED ({opera_st['path']})[/]" if opera_st["installed"] else "[grey70]NOT INSTALLED[/]")
        table.add_row("Session Recorder", f"[bold bright_green]RECORDING ({self.session_recorder.active_session_id})[/]" if self.session_recorder.active_session_id else "[grey70]IDLE[/]")
        table.add_row("Data / Logs / Reports", f"{DATA_DIR.name}/  |  {LOGS_DIR.name}/  |  {REPORTS_DIR.name}/")
        self.console.print(table)
        return 0

    # --- Existing Base Commands ---
    def _cmd_intel(self, args: list[str]) -> int:
        p = NonExitingParser(prog="intel", add_help=False)
        p.add_argument("--system", action="store_true")
        p.add_argument("--network", action="store_true")
        p.add_argument("--dns", type=str, default=None)
        p.add_argument("--all", action="store_true")
        ns = p.parse_args(args)
        if not (ns.system or ns.network or ns.dns or ns.all):
            ns.system = True
        if ns.all or ns.system:
            self.sys_intel.show_system_intel()
        if ns.all or ns.network:
            self.network.show_network_overview(include_connections=False)
        if ns.dns:
            self.network.resolve_dns(ns.dns)
        return 0

    def _cmd_scan(self, args: list[str]) -> int:
        p = NonExitingParser(prog="scan", add_help=False)
        p.add_argument("--local", action="store_true")
        p.add_argument("--subnet", type=str, default=None)
        p.add_argument("--ports", nargs="?", const="127.0.0.1", default=None)
        p.add_argument("--range", dest="port_range", type=str, default=None)
        p.add_argument("--timeout", type=float, default=None)
        p.add_argument("--authorized", action="store_true")
        ns = p.parse_args(args)
        if not ns.local and ns.ports is None:
            raise ValueError("Specify --local or --ports <target>")
        if ns.local:
            self.network.discover_local_network(subnet_cidr=ns.subnet)
        if ns.ports is not None:
            plist = self.network.parse_port_spec(ns.port_range)
            self.network.scan_ports(target=ns.ports, ports=plist, timeout=ns.timeout, allow_external=ns.authorized)
        return 0

    def _cmd_ports(self, args: list[str]) -> int:
        p = NonExitingParser(prog="ports", add_help=False)
        p.add_argument("target", nargs="?", default="127.0.0.1")
        p.add_argument("--ports", "-p", type=str, default=None)
        p.add_argument("--timeout", type=float, default=None)
        p.add_argument("--listening", action="store_true")
        p.add_argument("--authorized", action="store_true")
        ns = p.parse_args(args)
        if ns.listening:
            self.network.show_connections(limit=60)
            return 0
        self.network.scan_ports(target=ns.target, ports=self.network.parse_port_spec(ns.ports), timeout=ns.timeout, allow_external=ns.authorized)
        return 0

    def _cmd_trace(self, args: list[str]) -> int:
        p = NonExitingParser(prog="trace", add_help=False)
        p.add_argument("target")
        p.add_argument("--max-hops", type=int, default=20)
        ns = p.parse_args(args)
        self.network.traceroute(target=ns.target, max_hops=ns.max_hops)
        return 0

    def _cmd_network(self, args: list[str]) -> int:
        p = NonExitingParser(prog="network", add_help=False)
        p.add_argument("--info", action="store_true")
        p.add_argument("--interfaces", action="store_true")
        p.add_argument("--connections", action="store_true")
        p.add_argument("--gateway", action="store_true")
        p.add_argument("--dns", type=str, default=None)
        ns = p.parse_args(args)
        if not any([ns.info, ns.interfaces, ns.connections, ns.gateway, ns.dns]):
            ns.info = True
        if ns.info or ns.interfaces:
            self.network.show_network_overview(include_connections=ns.connections)
        elif ns.connections:
            self.network.show_connections()
        if ns.gateway and not (ns.info or ns.interfaces):
            self.console.print(f"[white]Primary Local IP:[/] [bright_green]{self.network.get_primary_local_ip()}[/] | [white]Gateway:[/] [bright_green]{self.network.get_default_gateway()}[/]")
        if ns.dns:
            self.network.resolve_dns(ns.dns)
        return 0

    def _cmd_process(self, args: list[str]) -> int:
        p = NonExitingParser(prog="process", add_help=False)
        p.add_argument("--list", action="store_true")
        p.add_argument("--top", type=int, default=25)
        p.add_argument("--sort", choices=["cpu", "mem", "pid", "name"], default="cpu")
        p.add_argument("--suspicious", action="store_true")
        p.add_argument("--inspect", type=int, default=None)
        ns = p.parse_args(args)
        if ns.inspect is not None:
            self.sys_intel.inspect_process(ns.inspect)
            return 0
        self.sys_intel.list_processes(limit=ns.top, sort_by=ns.sort, suspicious_only=ns.suspicious)
        return 0

    def _cmd_hash(self, args: list[str]) -> int:
        p = NonExitingParser(prog="hash", add_help=False)
        p.add_argument("--file", "-f", type=str, default=None)
        p.add_argument("--text", "-t", type=str, default=None)
        p.add_argument("--verify", type=str, default=None)
        ns = p.parse_args(args)
        if ns.file:
            self.forensics.hash_file_command(ns.file, expected_hash=ns.verify)
            return 0
        if ns.text is not None:
            self.forensics.hash_text_command(ns.text)
            return 0
        raise ValueError("Provide --file <path> or --text <string>.")

    def _cmd_forensic(self, args: list[str]) -> int:
        p = NonExitingParser(prog="forensic", add_help=False)
        p.add_argument("--file", "-f", required=True)
        p.add_argument("--save-baseline", action="store_true")
        p.add_argument("--verify-baseline", action="store_true")
        p.add_argument("--export", choices=["json", "txt", "csv", "pdf"], default=None)
        ns = p.parse_args(args)
        self.forensics.analyze_file(ns.file, save_baseline=ns.save_baseline, verify_baseline=ns.verify_baseline, export_fmt=ns.export)
        return 0

    def _cmd_password(self, args: list[str]) -> int:
        p = NonExitingParser(prog="password", add_help=False)
        p.add_argument("--check", type=str, default=None)
        p.add_argument("--generate", action="store_true")
        p.add_argument("--length", type=int, default=20)
        p.add_argument("--count", type=int, default=3)
        p.add_argument("--dict-test", nargs="?", const="letmein123", default=None)
        ns = p.parse_args(args)
        if not (ns.check or ns.generate or ns.dict_test is not None):
            raise ValueError("Specify --check <pw>, --generate, or --dict-test [pw].")
        if ns.check:
            self.password_lab.analyze_strength(ns.check)
        if ns.generate:
            self.password_lab.generate_secure_password(length=ns.length, count=ns.count)
        if ns.dict_test is not None:
            self.password_lab.run_controlled_dictionary_test(test_password=ns.dict_test)
        return 0

    def _cmd_simulate(self, args: list[str]) -> int:
        p = NonExitingParser(prog="simulate", add_help=False)
        p.add_argument("--scenario", "-s", required=True)
        p.add_argument("--log-file", type=str, default=None)
        ns = p.parse_args(args)
        self.warroom.run_scenario(ns.scenario, log_file=ns.log_file)
        return 0

    def _cmd_monitor(self, args: list[str]) -> int:
        p = NonExitingParser(prog="monitor", add_help=False)
        p.add_argument("--live", action="store_true")
        p.add_argument("--interval", type=float, default=None)
        p.add_argument("--duration", type=float, default=0.0)
        ns = p.parse_args(args)
        self.monitor.run_live(interval=ns.interval, duration=ns.duration)
        return 0

    def _cmd_history(self, args: list[str]) -> int:
        p = NonExitingParser(prog="history", add_help=False)
        p.add_argument("--limit", type=int, default=25)
        p.add_argument("--clear", action="store_true")
        ns = p.parse_args(args)
        if ns.clear:
            self.history.clear()
            self.console.print("[bright_green][+][/] Command history cleared.")
            return 0
        entries = self.history.entries[-ns.limit :]
        if not entries:
            self.console.print("[grey70][*] Command history is empty.[/]")
            return 0
        table = Table(title="[bold bright_green]COMMAND HISTORY[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("#", style="grey70", width=5, justify="right")
        table.add_column("Timestamp", style="grey70", width=20)
        table.add_column("Command", style="bright_green")
        start_idx = max(1, len(self.history.entries) - len(entries) + 1)
        for offset, item in enumerate(entries):
            table.add_row(str(start_idx + offset), item.get("timestamp", "-"), item.get("command", ""))
        self.console.print(table)
        return 0

    def _cmd_config(self, args: list[str]) -> int:
        p = NonExitingParser(prog="config", add_help=False)
        p.add_argument("--show", action="store_true")
        p.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), default=None)
        p.add_argument("--reset", action="store_true")
        ns = p.parse_args(args)
        if ns.reset:
            self.config.reset()
            self.console.print("[bright_green][+][/] Configuration reset.")
            return 0
        if ns.set:
            ok, msg = self.config.set(ns.set[0], ns.set[1])
            if ok:
                if ns.set[0] == "log_level":
                    self.logger.set_level(ns.set[1])
                self.console.print(f"[bright_green][+][/] {msg}")
                return 0
            self.console.print(f"[bold red][-][/] {msg}")
            return 1
        table = Table(title="[bold bright_green]BLACKVEIL CONFIGURATION[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Key", style="white")
        table.add_column("Value", style="bright_green")
        for k, v in self.config.data.items():
            table.add_row(k, repr(v))
        self.console.print(table)
        return 0

    def _cmd_report(self, args: list[str]) -> int:
        # Support both `report create/list/inspect/export` and legacy `report --export`
        if args and args[0].lower() in {"create", "list", "inspect", "export"}:
            sub = args[0].lower()
            rest = args[1:]
            p = NonExitingParser(prog=f"report {sub}", add_help=False)
            p.add_argument("target", nargs="?", default=None)
            p.add_argument("--title", type=str, default="blackveil_report")
            p.add_argument("--format", "-f", choices=["txt", "json", "csv", "pdf"], default=str(self.config.get("default_report_format", "json")))
            p.add_argument("--all", action="store_true")
            ns = p.parse_args(rest)
            if sub == "list":
                self.reports.list_reports()
            elif sub == "inspect":
                if not ns.target:
                    raise ValueError("Provide report filename to inspect.")
                self.reports.view_report(ns.target)
            elif sub == "create":
                self.reports.create_custom_report(title=ns.target or ns.title, export_format=ns.format)
            elif sub == "export":
                self.reports.export_report(export_format=ns.format, export_all=ns.all, custom_name=ns.target)
            return 0

        p = NonExitingParser(prog="report", add_help=False)
        p.add_argument("--export", action="store_true")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default=None)
        p.add_argument("--all", action="store_true")
        p.add_argument("--name", type=str, default=None)
        p.add_argument("--list", action="store_true")
        p.add_argument("--view", type=str, default=None)
        ns = p.parse_args(args)
        if ns.view:
            self.reports.view_report(ns.view)
        elif ns.export:
            fmt = ns.format or str(self.config.get("default_report_format", "json"))
            self.reports.export_report(export_format=fmt, export_all=ns.all, custom_name=ns.name)
        else:
            self.reports.list_reports()
        return 0

    # --- BLACKVEIL X New Ecosystem Commands ---
    def _cmd_sandbox(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify sandbox subcommand: create|list|start|stop|delete|enter|inspect|snapshot|restore|reset|resources|network|cleanup")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"sandbox {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--name", "-n", type=str, default=None)
        p.add_argument("--image", type=str, default=None)
        p.add_argument("--cpus", type=str, default=None)
        p.add_argument("--memory", type=str, default=None)
        p.add_argument("--disk", type=str, default=None)
        p.add_argument("--pids", type=int, default=None)
        p.add_argument("--timeout", type=int, default=None)
        p.add_argument("--snap", type=str, default=None)
        p.add_argument("--cmd", type=str, default=None)
        p.add_argument("--allow", action="store_true")
        p.add_argument("--yes", "-y", action="store_true")
        ns = p.parse_args(rest)

        tgt = ns.name or ns.target
        if sub == "create":
            self.sandbox.create(
                name=tgt or "linux-lab",
                image=ns.image,
                cpus=ns.cpus,
                memory=ns.memory,
                disk_limit=ns.disk,
                pids_limit=ns.pids,
                timeout_minutes=ns.timeout,
            )
        elif sub == "list":
            self.sandbox.list_sandboxes()
        elif sub == "start":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.start(tgt)
        elif sub == "stop":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.stop(tgt)
        elif sub == "delete":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.delete(tgt, assume_yes=ns.yes)
        elif sub == "enter":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            return self.sandbox.enter(tgt, command=ns.cmd)
        elif sub == "inspect":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.inspect(tgt)
        elif sub == "snapshot":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.snapshot(tgt, snapshot_name=ns.snap)
        elif sub == "restore":
            if not tgt or not ns.snap:
                raise ValueError("Usage: sandbox restore <name> --snap <snapshot_name>")
            self.sandbox.restore(tgt, snapshot_name=ns.snap)
        elif sub == "reset":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.reset(tgt, assume_yes=ns.yes)
        elif sub == "resources":
            self.sandbox.resources(target=tgt)
        elif sub == "network":
            if not tgt:
                raise ValueError("Provide sandbox name or ID.")
            self.sandbox.configure_network(tgt, allow_isolated_bridge=ns.allow)
        elif sub == "cleanup":
            self.sandbox.cleanup(assume_yes=ns.yes)
        else:
            raise ValueError(f"Unknown sandbox action '{sub}'.")
        return 0

    def _cmd_container(self, args: list[str]) -> int:
        if not args:
            self.container_inspector.list_containers()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"container {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "list":
            self.container_inspector.list_containers()
        elif sub == "inspect":
            if not ns.target:
                raise ValueError("Provide container ID or name.")
            self.container_inspector.inspect_container(ns.target)
        elif sub == "resources":
            self.container_inspector.resources()
        elif sub == "audit":
            self.container_inspector.audit_containers()
        elif sub == "report":
            self.container_inspector.report(fmt=ns.format)
        else:
            raise ValueError(f"Unknown container action '{sub}'.")
        return 0

    def _cmd_vuln(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.vuln_lab.list_labs()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"vuln {sub}", add_help=False)
        p.add_argument("lab_id", nargs="?", default=None)
        p.add_argument("--id", dest="opt_id", type=str, default=None)
        ns = p.parse_args(rest)
        lid = ns.opt_id or ns.lab_id
        if not lid:
            raise ValueError("Specify lab ID (e.g. VULN-01).")
        if sub == "install":
            self.vuln_lab.install(lid)
        elif sub == "start":
            self.vuln_lab.start(lid)
        elif sub == "inspect":
            self.vuln_lab.inspect(lid)
        elif sub == "reset":
            self.vuln_lab.reset(lid)
        else:
            raise ValueError(f"Unknown vuln action '{sub}'.")
        return 0

    def _cmd_ai(self, args: list[str]) -> int:
        if not args:
            return self.ai_analyst.interactive_chat()
        sub = args[0].lower()
        rest = args[1:]
        if sub == "ask":
            p = NonExitingParser(prog="ai ask", add_help=False)
            p.add_argument("question", nargs="*")
            p.add_argument("--session", type=str, default=None)
            ns = p.parse_args(rest)
            q_text = " ".join(ns.question).strip()
            if not q_text:
                raise ValueError("Usage: ai ask <question>")
            self.ai_analyst.ask(q_text, session_id=ns.session)
            return 0
        if sub == "config":
            p = NonExitingParser(prog="ai config", add_help=False)
            p.add_argument("--api-key", nargs="?", const="__PROMPT__", default=None)
            p.add_argument("--model", type=str, default=None)
            p.add_argument("--timeout", type=int, default=None)
            p.add_argument("--retries", type=int, default=None)
            p.add_argument("--show", action="store_true")
            p.add_argument("--clear", action="store_true")
            ns = p.parse_args(rest)
            prompt_key = ns.api_key == "__PROMPT__"
            key_val = None if prompt_key else ns.api_key
            self.ai_analyst.configure(
                api_key=key_val,
                prompt_key=prompt_key,
                model=ns.model,
                timeout=ns.timeout,
                retries=ns.retries,
                show=ns.show,
                clear_key=ns.clear,
            )
            return 0

        p = NonExitingParser(prog=f"ai {sub}", add_help=False)
        p.add_argument("target", nargs="*")
        p.add_argument("--file", type=str, default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        tgt = ns.file or (" ".join(ns.target).strip() if ns.target else None)
        if sub in {"analyze", "explain", "investigate"}:
            self.ai_analyst.analyze(tgt, mode=sub)
        elif sub == "report":
            self.ai_analyst.report(tgt, fmt=ns.format)
        else:
            # Allow `ai <freeform question>` seamlessly if not a known subcommand
            self.ai_analyst.ask(" ".join(args))
        return 0

    def _cmd_threat(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify threat subcommand: lookup|analyze|feed|report")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"threat {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--online", action="store_true")
        p.add_argument("--add", type=str, default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "lookup":
            if not ns.target:
                raise ValueError("Provide IP, domain, URL, or hash.")
            self.threat_intel.lookup(ns.target, online=ns.online)
        elif sub == "analyze":
            if not ns.target:
                raise ValueError("Provide observable or file path.")
            self.threat_intel.analyze_file_or_list(ns.target)
        elif sub == "feed":
            self.threat_intel.manage_feed(sync_online=ns.online, add_ioc=ns.add)
        elif sub == "report":
            self.threat_intel.report(ns.target, fmt=ns.format)
        else:
            raise ValueError(f"Unknown threat action '{sub}'.")
        return 0

    def _cmd_integrity(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify integrity subcommand: baseline|scan|diff|watch")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"integrity {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--path", type=str, default=None)
        p.add_argument("--name", type=str, default="default")
        p.add_argument("--interval", type=float, default=2.0)
        p.add_argument("--duration", type=float, default=0.0)
        ns = p.parse_args(rest)
        path_val = ns.path or ns.target or "."
        if sub == "baseline":
            self.integrity_guard.create_baseline(path_val, baseline_name=ns.name)
        elif sub in {"scan", "diff"}:
            self.integrity_guard.scan_against_baseline(baseline_name=ns.name, target_path=ns.path or ns.target)
        elif sub == "watch":
            self.integrity_guard.watch(path_val, interval=ns.interval, duration=ns.duration)
        else:
            raise ValueError(f"Unknown integrity action '{sub}'.")
        return 0

    def _cmd_logs(self, args: list[str]) -> int:
        if not args:
            self.log_intel.analyze()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"logs {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--file", type=str, default=None)
        p.add_argument("--channel", type=str, default="Security")
        p.add_argument("--query", "-q", type=str, default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        fpath = ns.file or (ns.target if sub != "search" else None)
        if sub in {"analyze", "correlate"}:
            self.log_intel.analyze(file_path=fpath, channel=ns.channel)
        elif sub == "search":
            q = ns.query or ns.target
            if not q:
                raise ValueError("Provide search pattern.")
            self.log_intel.search(q, file_path=ns.file, channel=ns.channel)
        elif sub == "timeline":
            self.log_intel.timeline(file_path=fpath)
        elif sub == "export":
            self.log_intel.export(file_path=fpath, fmt=ns.format)
        else:
            raise ValueError(f"Unknown logs action '{sub}'.")
        return 0

    def _cmd_evidence(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.evidence_vault.list_evidence()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"evidence {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--file", type=str, default=None)
        p.add_argument("--desc", type=str, default="Acquired digital artifact")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "add":
            tgt = ns.file or ns.target
            if not tgt:
                raise ValueError("Provide --file <path>.")
            self.evidence_vault.add_evidence(tgt, description=ns.desc)
        elif sub == "verify":
            if not ns.target:
                raise ValueError("Provide Evidence ID (e.g. EVD-...).")
            self.evidence_vault.verify_evidence(ns.target)
        elif sub == "export":
            self.evidence_vault.export_manifest(fmt=ns.format)
        else:
            raise ValueError(f"Unknown evidence action '{sub}'.")
        return 0

    def _cmd_baseline(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify baseline subcommand: create|compare|inspect|report")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"baseline {sub}", add_help=False)
        p.add_argument("name", nargs="?", default="default")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "create":
            self.net_baseline.create(name=ns.name)
        elif sub == "compare":
            self.net_baseline.compare(name=ns.name)
        elif sub == "inspect":
            self.net_baseline.inspect(name=ns.name)
        elif sub == "report":
            self.net_baseline.report(name=ns.name, fmt=ns.format)
        else:
            raise ValueError(f"Unknown baseline action '{sub}'.")
        return 0

    def _cmd_audit(self, args: list[str]) -> int:
        if not args:
            self.config_auditor.audit_system()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"audit {sub}", add_help=False)
        p.add_argument("--path", type=str, default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "system":
            self.config_auditor.audit_system()
        elif sub == "firewall":
            self.config_auditor.audit_firewall()
        elif sub == "permissions":
            self.config_auditor.audit_permissions(target_dir=ns.path)
        elif sub == "services":
            self.config_auditor.audit_services()
        elif sub == "report":
            self.config_auditor.full_report(fmt=ns.format)
        else:
            raise ValueError(f"Unknown audit action '{sub}'.")
        return 0

    def _cmd_secret(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify secret subcommand: scan|inspect|report")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"secret {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--path", type=str, default=None)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        tgt = ns.path or ns.target or "."
        if sub == "scan":
            self.secret_scanner.scan(tgt)
        elif sub == "inspect":
            self.secret_scanner.inspect_last()
        elif sub == "report":
            self.secret_scanner.report(target_path=tgt, fmt=ns.format)
        else:
            raise ValueError(f"Unknown secret action '{sub}'.")
        return 0

    def _cmd_incident(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.incident_engine.list_incidents()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"incident {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--title", type=str, default=None)
        p.add_argument("--severity", type=str, default="HIGH")
        p.add_argument("--note", type=str, default="Investigated by SOC analyst")
        p.add_argument("--artifact", type=str, default=None)
        ns = p.parse_args(rest)
        if sub == "create":
            title = ns.title or ns.target
            if not title:
                raise ValueError("Provide --title \"...\".")
            self.incident_engine.create(title=title, severity=ns.severity)
        elif sub == "investigate":
            if not ns.target:
                raise ValueError("Provide Incident ID.")
            self.incident_engine.investigate(ns.target, note=ns.note, artifact=ns.artifact)
        elif sub == "timeline":
            if not ns.target:
                raise ValueError("Provide Incident ID.")
            self.incident_engine.timeline(ns.target)
        elif sub == "close":
            if not ns.target:
                raise ValueError("Provide Incident ID.")
            self.incident_engine.close(ns.target, resolution=ns.note)
        else:
            raise ValueError(f"Unknown incident action '{sub}'.")
        return 0

    def _cmd_pcap(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify pcap subcommand: load|summary|filter|inspect|export")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"pcap {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--file", type=str, default=None)
        p.add_argument("--expr", type=str, default=None)
        p.add_argument("--index", type=int, default=1)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        fpath = ns.file or (ns.target if sub in {"load", "summary", "export"} else None)
        if sub == "load":
            if not fpath:
                raise ValueError("Provide PCAP file path.")
            self.pcap_analyzer.load(fpath)
        elif sub == "summary":
            self.pcap_analyzer.summary(file_path=fpath)
        elif sub == "filter":
            expr = ns.expr or ns.target
            if not expr:
                raise ValueError("Provide filter expression (e.g. tcp, port=80, ip=127.0.0.1).")
            self.pcap_analyzer.filter_packets(expr, file_path=ns.file)
        elif sub == "inspect":
            idx = int(ns.target) if (ns.target and ns.target.isdigit()) else ns.index
            self.pcap_analyzer.inspect_packet(index=idx, file_path=ns.file)
        elif sub == "export":
            self.pcap_analyzer.export(file_path=fpath, fmt=ns.format)
        else:
            raise ValueError(f"Unknown pcap action '{sub}'.")
        return 0

    def _cmd_dns(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify dns subcommand: lookup|inspect|compare|report")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"dns {sub}", add_help=False)
        p.add_argument("domain")
        p.add_argument("--server", type=str, default="8.8.8.8")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "lookup":
            self.dns_intel.lookup(ns.domain)
        elif sub == "inspect":
            self.dns_intel.inspect(ns.domain, server=ns.server)
        elif sub == "compare":
            self.dns_intel.compare(ns.domain)
        elif sub == "report":
            self.dns_intel.report(ns.domain, fmt=ns.format)
        else:
            raise ValueError(f"Unknown dns action '{sub}'.")
        return 0

    def _cmd_cert(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Specify cert subcommand: inspect|expiry|check|report")
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"cert {sub}", add_help=False)
        p.add_argument("target")
        p.add_argument("--port", type=int, default=443)
        p.add_argument("--warn-days", type=int, default=30)
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub in {"inspect", "expiry", "check"}:
            self.cert_watcher.inspect_cert(ns.target, port=ns.port, warn_days=ns.warn_days)
        elif sub == "report":
            self.cert_watcher.report(ns.target, fmt=ns.format)
        else:
            raise ValueError(f"Unknown cert action '{sub}'.")
        return 0

    def _cmd_deps(self, args: list[str]) -> int:
        if not args:
            self.deps_guard.scan()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"deps {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--file", type=str, default=None)
        p.add_argument("--online", action="store_true")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        if sub == "scan":
            self.deps_guard.scan(req_file=ns.file or ns.target)
        elif sub == "tree":
            self.deps_guard.tree(root_pkg=ns.target)
        elif sub == "outdated":
            self.deps_guard.outdated()
        elif sub == "audit":
            self.deps_guard.audit(online=ns.online)
        elif sub == "report":
            self.deps_guard.report(fmt=ns.format)
        else:
            raise ValueError(f"Unknown deps action '{sub}'.")
        return 0

    def _cmd_ctf(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.ctf_engine.list_challenges()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        if sub == "scoreboard":
            self.ctf_engine.scoreboard()
            return 0
        p = NonExitingParser(prog=f"ctf {sub}", add_help=False)
        p.add_argument("cid", nargs="?", default="CTF-01")
        p.add_argument("flag", nargs="?", default=None)
        ns = p.parse_args(rest)
        if sub == "start":
            self.ctf_engine.start_challenge(ns.cid)
        elif sub == "hint":
            self.ctf_engine.hint(ns.cid)
        elif sub == "submit":
            if not ns.flag:
                raise ValueError("Usage: ctf submit <CTF-01> <BV{...}>")
            self.ctf_engine.submit(ns.cid, ns.flag)
        else:
            raise ValueError(f"Unknown ctf action '{sub}'.")
        return 0

    def _cmd_automation(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.automation.list_playbooks()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        if sub == "history":
            self.automation.history()
            return 0
        p = NonExitingParser(prog=f"automation {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--name", type=str, default=None)
        p.add_argument("--commands", type=str, default=None)
        p.add_argument("--desc", type=str, default="")
        ns = p.parse_args(rest)
        tgt = ns.name or ns.target
        if sub == "create":
            if not tgt or not ns.commands:
                raise ValueError("Usage: automation create --name <name> --commands \"cmd1; cmd2\"")
            cmds = [c.strip() for c in ns.commands.split(";") if c.strip()]
            self.automation.create_playbook(tgt, cmds, description=ns.desc)
        elif sub == "run":
            if not tgt:
                raise ValueError("Provide playbook name or ID.")
            self.automation.run_playbook(tgt, self.execute_line)
        elif sub == "disable":
            if not tgt:
                raise ValueError("Provide playbook name or ID.")
            self.automation.disable(tgt)
        else:
            raise ValueError(f"Unknown automation action '{sub}'.")
        return 0

    def _cmd_kb(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.kb.list_entries()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"kb {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--title", type=str, default=None)
        p.add_argument("--content", type=str, default=None)
        p.add_argument("--category", type=str, default="Notes")
        p.add_argument("--tags", type=str, default="operator")
        p.add_argument("--format", choices=["json", "txt", "md"], default="json")
        ns = p.parse_args(rest)
        if sub == "search":
            if not ns.target:
                raise ValueError("Provide search query.")
            self.kb.search(ns.target)
        elif sub == "add":
            if not ns.title or not ns.content:
                raise ValueError("Usage: kb add --title \"...\" --content \"...\"")
            self.kb.add(ns.title, ns.content, category=ns.category, tags=ns.tags)
        elif sub == "explain":
            if not ns.target:
                raise ValueError("Provide article ID or title.")
            self.kb.explain(ns.target)
        elif sub == "export":
            self.kb.export(fmt=ns.format)
        else:
            raise ValueError(f"Unknown kb action '{sub}'.")
        return 0

    def _cmd_plugin(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.plugins.list_plugins()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"plugin {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--name", type=str, default=None)
        p.add_argument("--path", type=str, default=None)
        p.add_argument("--yes", "-y", action="store_true")
        ns = p.parse_args(rest)
        tgt = ns.name or ns.target
        if sub == "create":
            if not tgt:
                raise ValueError("Provide --name <plugin_name>.")
            self.plugins.create_plugin(tgt)
        elif sub == "install":
            pth = ns.path or ns.target
            if not pth:
                raise ValueError("Provide --path <plugin_dir>.")
            self.plugins.install_plugin(pth, assume_yes=ns.yes)
        elif sub == "inspect":
            if not tgt:
                raise ValueError("Provide plugin name.")
            self.plugins.inspect_plugin(tgt)
        elif sub == "enable":
            if not tgt:
                raise ValueError("Provide plugin name.")
            self.plugins.set_enabled(tgt, True)
        elif sub == "disable":
            if not tgt:
                raise ValueError("Provide plugin name.")
            self.plugins.set_enabled(tgt, False)
        elif sub == "run":
            if not tgt:
                raise ValueError("Provide plugin name.")
            return self.plugins.run_plugin(tgt)
        else:
            raise ValueError(f"Unknown plugin action '{sub}'.")
        return 0

    def _cmd_redteam(self, args: list[str]) -> int:
        if not args or args[0].lower() != "start":
            raise ValueError("Usage: redteam start [--scenario full-chain]")
        p = NonExitingParser(prog="redteam start", add_help=False)
        p.add_argument("--scenario", type=str, default="full-chain")
        ns = p.parse_args(args[1:])
        self.red_blue.redteam_start(scenario=ns.scenario)
        return 0

    def _cmd_blueteam(self, args: list[str]) -> int:
        if not args or args[0].lower() != "start":
            raise ValueError("Usage: blueteam start")
        self.red_blue.blueteam_start()
        return 0

    def _cmd_team(self, args: list[str]) -> int:
        if not args:
            self.red_blue.status()
            return 0
        sub = args[0].lower()
        if sub == "status":
            self.red_blue.status()
        elif sub == "report":
            fmt = args[1] if len(args) > 1 else "json"
            self.red_blue.report(fmt=fmt)
        elif sub == "reset":
            self.red_blue.reset()
        else:
            raise ValueError("Usage: team <status|report|reset>")
        return 0

    def _cmd_mission(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.missions.list_missions()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        if sub == "history":
            self.missions.show_history()
            return 0
        p = NonExitingParser(prog=f"mission {sub}", add_help=False)
        p.add_argument("mid")
        p.add_argument("answer", nargs="?", default=None)
        ns = p.parse_args(rest)
        if sub == "start":
            self.missions.start_mission(ns.mid)
        elif sub == "inspect":
            self.missions.inspect_mission(ns.mid)
        elif sub == "submit":
            if not ns.answer:
                raise ValueError("Usage: mission submit <MIS-ID> <answer>")
            self.missions.submit_mission(ns.mid, ns.answer)
        else:
            raise ValueError(f"Unknown mission action '{sub}'.")
        return 0

    def _cmd_profile(self, args: list[str]) -> int:
        detailed = bool(args and args[0].lower() == "stats")
        self.missions.show_profile(detailed=detailed)
        return 0

    def _cmd_session(self, args: list[str]) -> int:
        if not args or args[0].lower() == "list":
            self.session_recorder.list_sessions()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        p = NonExitingParser(prog=f"session {sub}", add_help=False)
        p.add_argument("target", nargs="?", default=None)
        p.add_argument("--name", type=str, default=None)
        p.add_argument("--format", choices=["txt", "json"], default="txt")
        ns = p.parse_args(rest)
        if sub == "start":
            self.session_recorder.start(session_name=ns.name or ns.target)
        elif sub == "stop":
            self.session_recorder.stop()
        elif sub == "replay":
            if not ns.target:
                raise ValueError("Provide Session ID.")
            self.session_recorder.replay(ns.target)
        elif sub == "export":
            if not ns.target:
                raise ValueError("Provide Session ID.")
            self.session_recorder.export(ns.target, fmt=ns.format)
        else:
            raise ValueError(f"Unknown session action '{sub}'.")
        return 0

    # --- BLACKVEIL X Advanced Intelligence Expansion (7 New Modules) ---
    def _cmd_website(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Usage: website <scan|ip|local> <URL|status|stop|inspect>")
        sub = args[0].lower()
        rest = args[1:]
        if sub == "scan":
            p = NonExitingParser(prog="website scan", add_help=False)
            p.add_argument("url")
            p.add_argument("--active-authorized", action="store_true")
            p.add_argument("--export", choices=["json", "txt", "csv"], default=None)
            ns = p.parse_args(rest)
            self.website_intel.scan(ns.url, active_authorized=ns.active_authorized, export_fmt=ns.export)
        elif sub == "ip":
            if not rest:
                raise ValueError("Usage: website ip <URL>")
            self.ip_intel.website_ip(rest[0])
        elif sub == "local":
            if not rest:
                raise ValueError("Usage: website local <URL|status|stop|inspect>")
            action = rest[0].lower()
            if action == "status":
                self.local_website.status()
            elif action == "stop":
                self.local_website.stop(target=rest[1] if len(rest) > 1 else None)
            elif action == "inspect":
                self.local_website.inspect(target=rest[1] if len(rest) > 1 else None)
            else:
                p = NonExitingParser(prog="website local", add_help=False)
                p.add_argument("url")
                p.add_argument("--port", type=int, default=0)
                p.add_argument("--max-pages", type=int, default=None)
                ns = p.parse_args(rest)
                self.local_website.create_local_environment(ns.url, port=ns.port, max_pages=ns.max_pages)
        else:
            raise ValueError(f"Unknown website subcommand '{sub}'. Use scan|ip|local.")
        return 0

    def _cmd_ipinfo(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Usage: ipinfo <IP>")
        self.ip_intel.ipinfo(args[0])
        return 0

    def _cmd_ip(self, args: list[str]) -> int:
        if not args:
            self.ip_intel.ip_local()
            return 0
        sub = args[0].lower()
        rest = args[1:]
        if sub == "local":
            self.ip_intel.ip_local()
        elif sub == "connections":
            p = NonExitingParser(prog="ip connections", add_help=False)
            p.add_argument("--limit", type=int, default=50)
            ns = p.parse_args(rest)
            self.ip_intel.ip_connections(limit=ns.limit)
        elif sub == "report":
            p = NonExitingParser(prog="ip report", add_help=False)
            p.add_argument("target")
            p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
            ns = p.parse_args(rest)
            self.ip_intel.ip_report(ns.target, fmt=ns.format)
        elif sub == "logs":
            if len(rest) >= 2 and rest[0].lower() == "analyze":
                self.ip_intel.analyze_access_logs(rest[1])
            elif rest:
                self.ip_intel.analyze_access_logs(rest[0])
            else:
                raise ValueError("Usage: ip logs analyze <FILE>")
        else:
            raise ValueError(f"Unknown ip subcommand '{sub}'. Use local|connections|report|logs analyze.")
        return 0

    def _cmd_url(self, args: list[str]) -> int:
        if len(args) < 2:
            raise ValueError("Usage: url <check|reputation|analyze> <URL>")
        sub = args[0].lower()
        if sub not in {"check", "reputation", "analyze"}:
            raise ValueError(f"Unknown url subcommand '{sub}'. Use check|reputation|analyze.")
        self.url_detector.analyze(args[1], mode=sub)
        return 0

    def _cmd_computer(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Usage: computer <search|find|processes|services|startup|disk|report>")
        sub = args[0].lower()
        rest = args[1:]
        if sub in {"search", "find"}:
            p = NonExitingParser(prog=f"computer {sub}", add_help=False)
            p.add_argument("query", nargs="*")
            p.add_argument("--path", type=str, default=".")
            p.add_argument("--content", action="store_true")
            p.add_argument("--ext", type=str, default=None)
            p.add_argument("--min-size", type=str, default=None)
            p.add_argument("--max-size", type=str, default=None)
            p.add_argument("--days", type=int, default=None)
            p.add_argument("--index", action="store_true")
            p.add_argument("--update-index", action="store_true")
            p.add_argument("--duplicates", action="store_true")
            p.add_argument("--large", action="store_true")
            p.add_argument("--hash", action="store_true")
            p.add_argument("--limit", type=int, default=80)
            ns = p.parse_args(rest)
            q = " ".join(ns.query).strip()
            exts = [e.strip() for e in ns.ext.split(",") if e.strip()] if ns.ext else None
            self.computer_search.search(
                query=q,
                root_dir=ns.path,
                search_content=ns.content,
                extensions=exts,
                min_size=ns.min_size,
                max_size=ns.max_size,
                modified_days=ns.days,
                use_index=ns.index,
                update_index=ns.update_index,
                compute_hash=ns.hash,
                find_duplicates=ns.duplicates,
                large_top=25 if ns.large else 0,
                limit=ns.limit,
            )
        elif sub == "processes":
            self._cmd_process(rest)
        elif sub == "services":
            p = NonExitingParser(prog="computer services", add_help=False)
            p.add_argument("--filter", type=str, default="")
            ns = p.parse_args(rest)
            self.computer_search.show_services(filter_str=ns.filter)
        elif sub == "startup":
            self.computer_search.show_startup()
        elif sub == "disk":
            p = NonExitingParser(prog="computer disk", add_help=False)
            p.add_argument("--path", type=str, default=".")
            p.add_argument("--top-large", type=int, default=15)
            ns = p.parse_args(rest)
            self.computer_search.show_disk(root_dir=ns.path, top_large=ns.top_large)
        elif sub == "report":
            p = NonExitingParser(prog="computer report", add_help=False)
            p.add_argument("--path", type=str, default=".")
            p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
            ns = p.parse_args(rest)
            self.computer_search.report(root_dir=ns.path, fmt=ns.format)
        else:
            raise ValueError(f"Unknown computer subcommand '{sub}'.")
        return 0

    def _cmd_search(self, args: list[str]) -> int:
        if not args:
            raise ValueError("Usage: search [web|google|sources|deep|report] <QUERY>")
        sub_candidates = {"web", "google", "sources", "deep", "report"}
        first = args[0].lower()
        if first in sub_candidates:
            mode = first
            rest = args[1:]
        else:
            mode = "multi"
            rest = args

        p = NonExitingParser(prog="search", add_help=False)
        p.add_argument("query", nargs="*")
        p.add_argument("--urls", type=str, default=None)
        p.add_argument("--open-opera", action="store_true")
        p.add_argument("--format", choices=["json", "txt", "csv", "pdf"], default="json")
        ns = p.parse_args(rest)
        q_text = " ".join(ns.query).strip()
        url_list = [u.strip() for u in ns.urls.split(",") if u.strip()] if ns.urls else None
        export_fmt = ns.format if mode == "report" else None
        self.external_search.search(
            query=q_text,
            mode="multi" if mode == "report" else mode,
            urls=url_list,
            open_opera=ns.open_opera,
            export_fmt=export_fmt,
        )
        return 0


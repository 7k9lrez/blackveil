"""Rich terminal shell, ASCII banner, Windows console setup, and interactive loop for BLACKVEIL X."""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.theme import Theme

from core.command_parser import CommandDispatcher
from core.config import ConfigManager, LOGS_DIR, REPORTS_DIR, ensure_directories
from core.logger import BlackveilLogger, HistoryManager
from database.db import DatabaseManager
from modules.network import scapy_available
from modules.system_intel import is_admin

BLACKVEIL_BANNER = """╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗   ██╗███████╗║
║   ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║   ██║██╔════╝║
║   ██████╔╝██║     ███████║██║     █████╔╝ ██║   ██║█████╗  ║
║   ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║   ██║██╔══╝  ║
║   ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╔╝███████╗║
║   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝║
║                                                            ║
║             ADVANCED CYBER OPERATIONS v1.0                 ║
║                  TERMINAL FRAMEWORK                        ║
╚════════════════════════════════════════════════════════════╝"""

BLACKVEIL_THEME = Theme(
    {
        "info": "bright_green",
        "warning": "bold yellow",
        "danger": "bold red",
        "muted": "grey70",
        "prompt": "bold bright_green",
    }
)


def configure_windows_console() -> None:
    """Enable UTF-8 and ANSI VT100 processing on Windows 10/11 CMD & PowerShell."""
    if platform.system() == "Windows":
        try:
            os.system("")
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def create_console() -> Console:
    configure_windows_console()
    return Console(theme=BLACKVEIL_THEME, style="white on black", highlight=False)


class BlackveilTerminal:
    """Interactive terminal loop and ecosystem boot diagnostics."""

    def __init__(self) -> None:
        ensure_directories()
        self.console = create_console()
        self.config = ConfigManager()
        self.logger = BlackveilLogger(level=str(self.config.get("log_level", "INFO")))
        self.history = HistoryManager(max_entries=int(self.config.get("max_history", 250)))
        self.db = DatabaseManager()
        self.dispatcher = CommandDispatcher(self.console, self.config, self.logger, self.history, db=self.db)
        self._init_readline()

    def _init_readline(self) -> None:
        try:
            import readline  # type: ignore

            for item in self.history.entries[-100:]:
                cmd = item.get("command", "")
                if cmd:
                    readline.add_history(cmd)
        except Exception:
            pass

    def show_boot_sequence(self) -> None:
        self.console.clear()
        self.console.print(Text(BLACKVEIL_BANNER, style="bold bright_green"))
        self.console.print()

        checks = [
            ("Verifying runtime directories", lambda: self._check_dirs()),
            ("Initializing SQLite DB & migrations", lambda: f"Schema v{self.db.get_schema_version()} READY"),
            ("Checking Docker Sandbox Engine", lambda: self._check_docker()),
            ("Auditing execution privileges", lambda: "ADMIN/ROOT" if is_admin() else "STANDARD USER"),
            ("Checking network packet backend", lambda: "SCAPY + SOCKET" if scapy_available() else "SOCKET + OS NATIVE"),
        ]

        results: list[str] = []
        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bright_green]{task.description}"),
            BarColumn(bar_width=24, complete_style="bright_green"),
            TextColumn("[white]{task.completed}/{task.total}"),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("Booting BLACKVEIL X Ecosystem", total=len(checks))
            for label, probe_fn in checks:
                detail = probe_fn()
                results.append(f"[bright_green][OK][/] {label}: [white]{detail}[/]")
                time.sleep(0.05)
                progress.advance(task)

        for line in results:
            self.console.print(line)

        priv_msg = (
            "[bright_green]ELEVATED[/]"
            if is_admin()
            else "[yellow]STANDARD USER[/] [grey70](Raw L2 ARP & protected PIDs require Admin)[/]"
        )
        self.console.print(
            Panel(
                f"[white]Host:[/] [bright_green]{os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or platform.node()}[/]  |  "
                f"[white]OS:[/] {platform.system()} {platform.release()}  |  "
                f"[white]Context:[/] {priv_msg}\n"
                f"[grey70]ONE TERMINAL. ONE ECOSYSTEM. INFINITE POSSIBILITIES. Type [bold bright_green]help[/] or [bold bright_green]mission list[/].[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

    def _check_docker(self) -> str:
        ok, info = self.dispatcher.sandbox.check_docker_ready(quiet=True)
        return f"ONLINE ({info})" if ok else "OFFLINE (Non-Docker modules active)"

    @staticmethod
    def _check_dirs() -> str:
        ensure_directories()
        for p in (LOGS_DIR, REPORTS_DIR):
            test_file = Path(p) / ".write_probe"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
        return "READY"

    def run_interactive(self) -> int:
        self.show_boot_sequence()
        self.logger.info("terminal", "Interactive BLACKVEIL X session started")
        prompt_user = str(self.config.get("prompt_user", "BLACKVEIL@ROOT"))

        while not self.dispatcher.should_exit:
            try:
                rec_tag = "[bold red][REC][/] " if self.dispatcher.session_recorder.active_session_id else ""
                self.console.print(f"{rec_tag}[bold bright_green]{prompt_user}[/][white]:[/][bold green]~[/][white]$ [/]", end="")
                raw_input = input()
                self.dispatcher.execute_line(raw_input)
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow][!][/] Interrupt received. Type [bright_green]exit[/] to quit BLACKVEIL.")
            except EOFError:
                self.console.print("\n[bright_green][*][/] EOF received. Closing BLACKVEIL.")
                break

        if self.dispatcher.session_recorder.active_session_id:
            self.dispatcher.session_recorder.stop()
        self.logger.info("terminal", "Interactive session ended")
        return 0

    def run_cli(self, argv: list[str]) -> int:
        from core.session_recorder import SessionRecorder

        self.logger.info("cli", f"CLI invocation: {SessionRecorder.mask_sensitive(' '.join(argv))}")
        return self.dispatcher.execute_tokens(argv)

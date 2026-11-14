"""Module 09: Secret Scanner - Detects exposed keys, tokens, private keys, and passwords with strict masking."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager


class SecretScannerModule:
    """Scans codebases and config files for accidental credential leaks while masking sensitive values."""

    RULES: list[tuple[str, str, re.Pattern[str]]] = [
        ("AWS Access Key ID", "CRITICAL", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("Google API Key", "CRITICAL", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,45})\b")),
        ("GitHub Token", "CRITICAL", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,})\b")),
        ("Private Key Block", "CRITICAL", re.compile(r"(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----)")),
        ("JWT Token", "HIGH", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
        ("Generic Hardcoded Secret", "HIGH", re.compile(r"(?:password|passwd|api_key|secret_key|jwt_secret|db_pass)\s*[:=]\s*['\"]?([^\s'\"]{6,64})", re.I)),
    ]

    SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
    TEXT_EXTS = {".py", ".env", ".json", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".txt", ".sh", ".bat", ".ps1", ".ts", ".js", ".xml", ".toml"}

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports
        self.last_findings: list[dict[str, Any]] = []

    @staticmethod
    def mask_value(secret: str) -> str:
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}{'*' * min(12, len(secret) - 8)}{secret[-4:]}"

    def scan(self, target_path: str = ".") -> list[dict[str, Any]]:
        root = Path(target_path).expanduser()
        if not root.exists():
            self.console.print(f"[bold red][-][/] Scan path not found: {root}")
            return []

        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file() and not any(part in self.SKIP_DIRS for part in p.parts)
            and (p.suffix.lower() in self.TEXT_EXTS or p.name.startswith(".env"))
        ]

        findings: list[dict[str, Any]] = []
        for fp in files:
            try:
                if fp.stat().st_size > 2 * 1024 * 1024:
                    continue
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, start=1):
                for rule_name, sev, pat in self.RULES:
                    for match in pat.finditer(line):
                        raw_secret = match.group(1) if match.groups() else match.group(0)
                        if "MASKED" in raw_secret or "EXAMPLE" in raw_secret and "AKIA" not in raw_secret:
                            continue
                        findings.append(
                            {
                                "file": str(fp),
                                "line": line_no,
                                "rule": rule_name,
                                "severity": sev,
                                "masked_preview": self.mask_value(raw_secret),
                            }
                        )

        self.last_findings = findings
        table = Table(
            title=f"[bold bright_green]SECRET SCANNER // {len(files)} FILES SCANNED ({len(findings)} FINDINGS)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="red" if findings else "bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Severity", width=10)
        table.add_column("Rule", style="white", width=24)
        table.add_column("Location", style="grey70")
        table.add_column("Masked Value", style="bright_green")

        if not findings:
            self.console.print(f"[bold bright_green][+][/] Clean scan: zero exposed credentials detected across {len(files)} file(s).")
        else:
            for f in findings[:40]:
                col = "bold red" if f["severity"] == "CRITICAL" else "bold yellow"
                table.add_row(f"[{col}]{f['severity']}[/]", f["rule"], f"{f['file']}:{f['line']}", f["masked_preview"])
            self.console.print(table)

        self.reports.record("SECRET_SCAN", f"Secret Scan: {target_path}", {"files_scanned": len(files), "findings": findings}, severity="CRITICAL" if findings else "INFO")
        return findings

    def inspect_last(self) -> None:
        if not self.last_findings:
            self.console.print("[grey70][*] No secret scan findings in current session. Run `secret scan --path <dir>` first.[/]")
            return
        for idx, f in enumerate(self.last_findings, start=1):
            self.console.print(f"[{idx}] [bold red]{f['severity']}[/] | {f['rule']} | {f['file']}:{f['line']} | Masked={f['masked_preview']}")

    def report(self, target_path: str = ".", fmt: str = "json") -> None:
        self.scan(target_path=target_path)
        self.reports.export_report(export_format=fmt, export_all=False)

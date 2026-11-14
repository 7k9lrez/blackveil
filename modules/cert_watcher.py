"""Module 13: Certificate Watcher - Live SSL/TLS X.509 certificate inspection and expiry verification."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager


class CertWatcherModule:
    """Inspects live X.509 TLS certificates, SANs, cipher suites, and days until expiration."""

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports

    def inspect_cert(self, target: str, port: int = 443, warn_days: int = 30) -> dict[str, Any]:
        host = target.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        if ":" in host:
            host, p_str = host.split(":", 1)
            port = int(p_str)

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=8) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    tls_ver = tls_sock.version()
                    cipher = tls_sock.cipher()
        except ssl.SSLCertVerificationError as exc:
            self.console.print(f"[bold red][-] TLS VERIFICATION FAILED for {host}:{port}[/]: {exc}")
            res = {"host": host, "port": port, "verified": False, "error": str(exc)}
            self.reports.record("CERT_WATCHER", f"TLS Cert Failed: {host}:{port}", res, severity="CRITICAL")
            return res
        except Exception as exc:
            self.console.print(f"[bold red][-][/] Could not connect to {host}:{port} over TLS: {exc}")
            return {"host": host, "port": port, "error": str(exc)}

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]

        exp_style = "bold red" if days_left < 0 else "bold yellow" if days_left <= warn_days else "bold bright_green"
        table = Table(title=f"[bold bright_green]TLS CERTIFICATE INSPECTOR // {host}:{port}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", show_header=False)
        table.add_column("Field", style="grey70", width=20)
        table.add_column("Value", style="white")
        table.add_row("Common Name (CN)", subject.get("commonName", "-"))
        table.add_row("Issuer", issuer.get("organizationName", issuer.get("commonName", "-")))
        table.add_row("TLS Protocol / Cipher", f"{tls_ver} | {cipher[0] if cipher else '-'}")
        table.add_row("Valid From", not_before.strftime("%Y-%m-%d %H:%M UTC"))
        table.add_row("Valid Until", not_after.strftime("%Y-%m-%d %H:%M UTC"))
        table.add_row("Days Remaining", f"[{exp_style}]{days_left} days[/]")
        table.add_row("SANs", ", ".join(sans[:8]) + (f" (+{len(sans)-8} more)" if len(sans) > 8 else ""))
        table.add_row("Chain Status", "[bold bright_green]TRUSTED / VERIFIED[/]")
        self.console.print(table)

        res = {
            "host": host,
            "port": port,
            "verified": True,
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName"),
            "tls_version": tls_ver,
            "not_after": not_after.isoformat(),
            "days_remaining": days_left,
            "sans": sans[:20],
        }
        self.reports.record("CERT_WATCHER", f"TLS Certificate: {host}:{port}", res, severity="HIGH" if days_left <= warn_days else "INFO")
        return res

    def report(self, target: str, fmt: str = "json") -> None:
        self.inspect_cert(target)
        self.reports.export_report(export_format=fmt, export_all=False)

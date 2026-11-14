"""Module 17: IP Intelligence - Public/Local IP, Website DNS/ASN/RDAP, Connections & Log IP Analyzer."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import BlackveilLogger
from modules.network import NetworkModule
from modules.reports import ReportManager


class IpIntelModule:
    """Provides ethical IP intelligence, ASN/RDAP lookups, active connections, and owner log analysis."""

    GEO_DISCLAIMER = (
        "Geolocation reflects ISP/ASN registration or PoP routing only (city/region approximation) "
        "and does not identify a physical street address."
    )

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        network: NetworkModule,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.network = network
        self.reports = reports

    @staticmethod
    def _http_json(url: str, timeout: float = 6.0) -> dict[str, Any] | None:
        req = urllib.request.Request(url, headers={"User-Agent": "BLACKVEIL-X-IPIntel/1.0", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _query_rdap_ip(self, ip_str: str) -> dict[str, Any]:
        data = self._http_json(f"https://rdap.arin.net/registry/ip/{ip_str}", timeout=6.0)
        if not data:
            return {}
        org_name = data.get("name") or "-"
        for ent in data.get("entities", []):
            vcard = ent.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        org_name = str(item[3])
                        break
        return {
            "handle": data.get("handle", "-"),
            "network_name": data.get("name", "-"),
            "organization": org_name,
            "country": data.get("country", "-"),
            "cidr": f"{data.get('startAddress', '?')} - {data.get('endAddress', '?')}",
            "source": "RDAP (rdap.arin.net)",
        }

    def _query_geo_ip(self, ip_str: str) -> dict[str, Any]:
        data = self._http_json(
            f"http://ip-api.com/json/{ip_str}?fields=status,message,country,regionName,city,isp,org,as,reverse,proxy,hosting,query",
            timeout=6.0,
        )
        if not data or data.get("status") != "success":
            return {}
        return {
            "country": data.get("country", "-"),
            "region": data.get("regionName", "-"),
            "city": data.get("city", "-"),
            "isp": data.get("isp", "-"),
            "org": data.get("org", "-"),
            "asn": data.get("as", "-"),
            "hosting": bool(data.get("hosting", False)),
            "proxy": bool(data.get("proxy", False)),
            "source": "ip-api.com",
        }

    def ipinfo(self, ip_str: str, quiet: bool = False) -> dict[str, Any]:
        """Inspect IP classification, reverse DNS, RDAP registration, and provider/GeoIP details."""
        cleaned = ip_str.strip()
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            self.console.print(f"[bold red][-][/] Invalid IP address: '{ip_str}'")
            return {}

        scope = (
            "LOOPBACK" if addr.is_loopback
            else "PRIVATE (RFC1918/ULA)" if addr.is_private
            else "LINK-LOCAL" if addr.is_link_local
            else "MULTICAST" if addr.is_multicast
            else "PUBLIC"
        )

        ptr = "No PTR record"
        try:
            ptr = socket.gethostbyaddr(cleaned)[0]
        except OSError:
            pass

        rdap: dict[str, Any] = {}
        geo: dict[str, Any] = {}
        if scope == "PUBLIC":
            with self.console.status(f"[bold bright_green][*] Querying RDAP & ASN telemetry for {cleaned}...[/]", spinner="dots"):
                rdap = self._query_rdap_ip(cleaned)
                geo = self._query_geo_ip(cleaned)

        result = {
            "ip": cleaned,
            "version": f"IPv{addr.version}",
            "scope": scope,
            "reverse_ptr": ptr,
            "rdap": rdap,
            "geo": geo,
            "accuracy_disclaimer": self.GEO_DISCLAIMER,
        }

        if not quiet:
            table = Table(
                title=f"[bold bright_green]IP INTELLIGENCE // {cleaned}[/]",
                box=box.SIMPLE_HEAVY,
                border_style="bright_green",
                show_header=False,
            )
            table.add_column("Field", style="grey70", width=22)
            table.add_column("Value", style="white")
            table.add_row("IP / Version", f"[bright_green]{cleaned}[/] ({result['version']})")
            table.add_row("Address Scope", scope)
            table.add_row("Reverse DNS (PTR)", ptr)
            if scope == "PUBLIC":
                table.add_row("ASN / ISP", f"{geo.get('asn', '-')} | {geo.get('isp', '-')}")
                table.add_row("Organization", geo.get("org") or rdap.get("organization") or "-")
                table.add_row("RDAP Network / Range", f"{rdap.get('network_name', '-')} ({rdap.get('cidr', '-')})")
                loc_parts = [p for p in (geo.get("city"), geo.get("region"), geo.get("country") or rdap.get("country")) if p and p != "-"]
                table.add_row("Approx. Location", ", ".join(loc_parts) or "Unavailable (offline/blocked)")
                table.add_row("Hosting / Proxy Flag", f"Hosting={geo.get('hosting', 'unknown')} | Proxy={geo.get('proxy', 'unknown')}")
            table.add_row("Accuracy Notice", f"[grey70]{self.GEO_DISCLAIMER}[/]")
            self.console.print(table)

        self.reports.record("IP_INTEL", f"IP Intelligence: {cleaned}", result)
        return result

    def website_ip(self, raw_url: str) -> dict[str, Any]:
        """Resolve a website's IPv4/IPv6 addresses and inspect hosting/ASN provider details."""
        cleaned = raw_url.strip()
        if "://" in cleaned:
            host = urllib.parse.urlparse(cleaned).hostname or ""
        else:
            host = cleaned.split("/")[0].split(":")[0]
        if not host:
            self.console.print(f"[bold red][-][/] Could not extract hostname from '{raw_url}'")
            return {}

        ipv4: list[str] = []
        ipv6: list[str] = []
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0].split("%")[0]
                if fam == socket.AF_INET and ip not in ipv4:
                    ipv4.append(ip)
                elif fam == socket.AF_INET6 and ip not in ipv6:
                    ipv6.append(ip)
        except OSError as exc:
            self.console.print(f"[bold red][-][/] DNS resolution failed for '{host}': {exc}")
            return {}

        primary_ip = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else "")
        primary_info = self.ipinfo(primary_ip, quiet=True) if primary_ip else {}

        table = Table(
            title=f"[bold bright_green]WEBSITE IP INTELLIGENCE // {host}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        table.add_column("Field", style="grey70", width=22)
        table.add_column("Value", style="white")
        table.add_row("Target Host", f"[bright_green]{host}[/]")
        table.add_row("IPv4 Addresses", ", ".join(ipv4) or "-")
        table.add_row("IPv6 Addresses", ", ".join(ipv6) or "-")
        if primary_info:
            geo = primary_info.get("geo", {})
            rdap = primary_info.get("rdap", {})
            table.add_row("Primary IP PTR", primary_info.get("reverse_ptr", "-"))
            table.add_row("Hosting / ASN", f"{geo.get('asn', '-')} | {geo.get('org') or rdap.get('organization') or '-'}")
            table.add_row("Approx. Region", f"{geo.get('city', '-')}, {geo.get('country') or rdap.get('country') or '-'}")
        table.add_row("Accuracy Notice", f"[grey70]{self.GEO_DISCLAIMER}[/]")
        self.console.print(table)

        res = {"host": host, "ipv4": ipv4, "ipv6": ipv6, "primary_ip_intel": primary_info}
        self.reports.record("WEBSITE_IP", f"Website IP Resolution: {host}", res)
        return res

    def ip_local(self) -> dict[str, Any]:
        """Display local interface IPs, default gateway, and user's own public IP via HTTPS."""
        local_ip = self.network.get_primary_local_ip()
        gateway = self.network.get_default_gateway()
        interfaces = self.network.collect_interfaces()

        public_ip = "Unavailable (offline or blocked)"
        public_src = "-"
        resp = self._http_json("https://api.ipify.org?format=json", timeout=5.0)
        if resp and resp.get("ip"):
            public_ip = str(resp["ip"])
            public_src = "api.ipify.org"
        else:
            try:
                req = urllib.request.Request("https://ifconfig.me/ip", headers={"User-Agent": "BLACKVEIL-X/1.0"})
                with urllib.request.urlopen(req, timeout=5.0) as r:
                    cand = r.read(64).decode("utf-8", errors="replace").strip()
                    ipaddress.ip_address(cand)
                    public_ip = cand
                    public_src = "ifconfig.me"
            except Exception:
                pass

        self.console.print(
            Panel(
                f"[white]Hostname         :[/] [bright_green]{socket.gethostname()}[/]\n"
                f"[white]Primary Local IP :[/] [bright_green]{local_ip}[/]\n"
                f"[white]Default Gateway  :[/] [bright_green]{gateway}[/]\n"
                f"[white]Own Public IP    :[/] [bold bright_green]{public_ip}[/] [grey70](source: {public_src})[/]",
                title="[bold bright_green]LOCAL & OWN PUBLIC IP INTELLIGENCE[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        self.network.show_network_overview(include_connections=False)
        res = {"local_ip": local_ip, "gateway": gateway, "public_ip": public_ip, "public_source": public_src, "interfaces": interfaces}
        self.reports.record("IP_LOCAL", "Local & Own Public IP Summary", res)
        return res

    def ip_connections(self, limit: int = 50) -> list[dict[str, Any]]:
        """Show active local machine network connections and summarize remote endpoints."""
        conns = self.network.show_connections(limit=limit)
        if conns:
            states = Counter(c["status"] for c in conns)
            remote_ips = Counter(
                c["remote"].rsplit(":", 1)[0]
                for c in conns
                if c["remote"] != "-" and not c["remote"].startswith(("127.", "::1", "0.0.0.0"))
            )
            self.console.print(
                Panel(
                    f"[white]Total Sockets :[/] {len(conns)}\n"
                    f"[white]By State      :[/] {', '.join(f'{k}={v}' for k, v in states.most_common())}\n"
                    f"[white]Top Remote IPs:[/] {', '.join(f'{ip} ({cnt})' for ip, cnt in remote_ips.most_common(6)) or 'None'}",
                    title="[bold bright_green]CONNECTION INTELLIGENCE SUMMARY[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )
        return conns

    def ip_report(self, target: str, fmt: str = "json") -> None:
        """Analyze IP or URL and export report."""
        try:
            ipaddress.ip_address(target.strip())
            self.ipinfo(target.strip())
        except ValueError:
            self.website_ip(target.strip())
        self.reports.export_report(export_format=fmt, export_all=False)

    def analyze_access_logs(self, file_path: str) -> dict[str, Any]:
        """Analyze user-provided web server/access logs for visitor IPs, timestamps, and HTTP statuses."""
        path = Path(file_path).expanduser()
        if not path.exists() or not path.is_file():
            self.console.print(f"[bold red][-][/] Access log file not found: '{file_path}'")
            return {}

        clf_re = re.compile(
            r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
        )
        ip_fallback_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        ts_fallback_re = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\b")

        ip_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        path_counts: Counter[str] = Counter()
        ip_first_last: dict[str, list[str]] = {}
        total_lines = 0
        parsed_lines = 0

        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            total_lines += 1
            m = clf_re.match(line)
            if m:
                parsed_lines += 1
                ip = m.group("ip")
                ts = m.group("ts")
                req_path = m.group("path")
                st = m.group("status")
                ip_counts[ip] += 1
                status_counts[st] += 1
                path_counts[req_path] += 1
                if ip not in ip_first_last:
                    ip_first_last[ip] = [ts, ts]
                else:
                    ip_first_last[ip][1] = ts
            else:
                ip_m = ip_fallback_re.search(line)
                if ip_m:
                    parsed_lines += 1
                    ip = ip_m.group(0)
                    ip_counts[ip] += 1
                    ts_m = ts_fallback_re.search(line)
                    ts_val = ts_m.group(0) if ts_m else "-"
                    if ip not in ip_first_last:
                        ip_first_last[ip] = [ts_val, ts_val]
                    else:
                        ip_first_last[ip][1] = ts_val

        table = Table(
            title=f"[bold bright_green]ACCESS LOG VISITOR IP ANALYSIS // {path.name}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Source IP", style="bright_green")
        table.add_column("Requests", justify="right", style="white")
        table.add_column("First Seen", style="grey70")
        table.add_column("Last Seen", style="grey70")

        for ip, cnt in ip_counts.most_common(25):
            first_ts, last_ts = ip_first_last.get(ip, ["-", "-"])
            table.add_row(ip, str(cnt), first_ts[:26], last_ts[:26])
        self.console.print(table)

        self.console.print(
            Panel(
                f"[white]Log File     :[/] {path}\n"
                f"[white]Total Lines  :[/] {total_lines}  |  [white]Parsed Entries:[/] {parsed_lines}\n"
                f"[white]Unique IPs   :[/] {len(ip_counts)}\n"
                f"[white]HTTP Statuses:[/] {', '.join(f'{k}={v}' for k, v in status_counts.most_common(8)) or 'N/A'}\n"
                f"[white]Top Paths    :[/] {', '.join(f'{p} ({c})' for p, c in path_counts.most_common(5)) or 'N/A'}",
                title="[bold bright_green]LOG TRAFFIC SUMMARY[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        res = {
            "file": str(path),
            "total_lines": total_lines,
            "parsed_entries": parsed_lines,
            "unique_ips": len(ip_counts),
            "top_ips": [{"ip": ip, "requests": cnt, "first_seen": ip_first_last[ip][0], "last_seen": ip_first_last[ip][1]} for ip, cnt in ip_counts.most_common(30)],
            "status_distribution": dict(status_counts),
            "top_paths": dict(path_counts.most_common(15)),
        }
        self.reports.record("ACCESS_LOG_INTEL", f"Access Log IP Analysis: {path.name}", res)
        return res

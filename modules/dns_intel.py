"""Module 12: DNS Intelligence - Multi-record queries (A/AAAA/MX/TXT/NS/PTR) & resolver comparison."""

from __future__ import annotations

import os
import socket
import struct
import subprocess
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager


class DnsIntelModule:
    """Performs DNS lookups, multi-record inspection, and cross-resolver comparison."""

    RECORD_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports

    @staticmethod
    def _encode_qname(domain: str) -> bytes:
        parts = [p.encode("ascii") for p in domain.strip(".").split(".") if p]
        return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"

    @staticmethod
    def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        jumped = False
        orig_offset = offset
        seen: set[int] = set()
        while offset < len(packet):
            if offset in seen:
                break
            seen.add(offset)
            length = packet[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    orig_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                offset = pointer
                jumped = True
            else:
                offset += 1
                labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
                offset += length
        return ".".join(labels), (orig_offset if jumped else offset)

    def _raw_udp_query(self, domain: str, qtype: str, server: str = "8.8.8.8", timeout: float = 2.5) -> list[str]:
        """Pure-Python DNS UDP wire query for A, AAAA, NS, MX, TXT, CNAME records."""
        qcode = self.RECORD_TYPES.get(qtype.upper(), 1)
        txid = int.from_bytes(os.urandom(2), "big")
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = self._encode_qname(domain) + struct.pack("!HH", qcode, 1)
        pkt = header + question

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(pkt, (server, 53))
                resp, _ = sock.recvfrom(4096)
        except OSError:
            return []

        if len(resp) < 12:
            return []
        _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
        offset = 12
        for _ in range(qdcount):
            _, offset = self._decode_name(resp, offset)
            offset += 4

        answers: list[str] = []
        for _ in range(ancount):
            if offset >= len(resp):
                break
            _, offset = self._decode_name(resp, offset)
            if offset + 10 > len(resp):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", resp[offset : offset + 10])
            offset += 10
            rdata = resp[offset : offset + rdlen]
            if rtype == 1 and len(rdata) == 4:
                answers.append(socket.inet_ntoa(rdata))
            elif rtype == 28 and len(rdata) == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in {2, 5}:
                name, _ = self._decode_name(resp, offset)
                answers.append(name)
            elif rtype == 15 and len(rdata) >= 3:
                pref = struct.unpack("!H", rdata[:2])[0]
                exch, _ = self._decode_name(resp, offset + 2)
                answers.append(f"{pref} {exch}")
            elif rtype == 16:
                txt_parts: list[str] = []
                pos = 0
                while pos < len(rdata):
                    ln = rdata[pos]
                    txt_parts.append(rdata[pos + 1 : pos + 1 + ln].decode("utf-8", errors="replace"))
                    pos += 1 + ln
                answers.append("".join(txt_parts))
            offset += rdlen
        return answers

    def lookup(self, domain: str) -> dict[str, Any]:
        """Resolve A/AAAA/PTR via system resolver."""
        ipv4: list[str] = []
        ipv6: list[str] = []
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                ip = sockaddr[0].split("%")[0]
                if fam == socket.AF_INET and ip not in ipv4:
                    ipv4.append(ip)
                elif fam == socket.AF_INET6 and ip not in ipv6:
                    ipv6.append(ip)
        except socket.gaierror as exc:
            self.console.print(f"[bold red][-][/] DNS lookup failed for '{domain}': {exc}")
            return {"domain": domain, "error": str(exc)}

        table = Table(title=f"[bold bright_green]DNS LOOKUP // {domain}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Type", style="grey70", width=10)
        table.add_column("Records", style="bright_green")
        table.add_row("A", ", ".join(ipv4) or "-")
        table.add_row("AAAA", ", ".join(ipv6) or "-")
        self.console.print(table)
        res = {"domain": domain, "A": ipv4, "AAAA": ipv6}
        self.reports.record("DNS_LOOKUP", f"DNS Lookup: {domain}", res)
        return res

    def inspect(self, domain: str, server: str = "8.8.8.8") -> dict[str, Any]:
        """Inspect A, AAAA, NS, MX, TXT, CNAME records via direct DNS wire query (with nslookup fallback)."""
        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
            vals = self._raw_udp_query(domain, rtype, server=server)
            if vals:
                records[rtype] = vals

        if not records:
            # Fallback to OS nslookup if outbound UDP/53 is blocked
            try:
                proc = subprocess.run(["nslookup", domain], capture_output=True, text=True, timeout=6, encoding="utf-8", errors="replace")
                records["NSLOOKUP"] = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()][:10]
            except Exception:
                pass

        table = Table(title=f"[bold bright_green]DNS RECORD INSPECTOR // {domain} (Resolver {server})[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Record", style="bright_green", width=10)
        table.add_column("Values", style="white")
        for rtype, vals in records.items():
            table.add_row(rtype, "\n".join(vals))
        if not records:
            self.console.print(f"[yellow][!][/] No DNS records returned for '{domain}'.")
        else:
            self.console.print(table)

        res = {"domain": domain, "resolver": server, "records": records}
        self.reports.record("DNS_INSPECT", f"DNS Deep Inspection: {domain}", res)
        return res

    def compare(self, domain: str, resolver_a: str = "8.8.8.8", resolver_b: str = "1.1.1.1") -> dict[str, Any]:
        """Compare A-record answers across two independent DNS resolvers to flag anomalies."""
        ans_a = sorted(self._raw_udp_query(domain, "A", server=resolver_a))
        ans_b = sorted(self._raw_udp_query(domain, "A", server=resolver_b))
        consistent = bool(ans_a and ans_b and set(ans_a) == set(ans_b))

        table = Table(title=f"[bold bright_green]DNS RESOLVER COMPARISON // {domain}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Resolver", style="white", width=18)
        table.add_column("A Records", style="bright_green")
        table.add_row(resolver_a, ", ".join(ans_a) or "No response")
        table.add_row(resolver_b, ", ".join(ans_b) or "No response")
        table.add_row("Verdict", "[bold bright_green]CONSISTENT[/]" if consistent else "[bold yellow]DIFFERENT / UNAVAILABLE[/]")
        self.console.print(table)

        res = {"domain": domain, resolver_a: ans_a, resolver_b: ans_b, "consistent": consistent}
        self.reports.record("DNS_COMPARE", f"DNS Compare: {domain}", res)
        return res

    def report(self, domain: str, fmt: str = "json") -> None:
        self.inspect(domain)
        self.reports.export_report(export_format=fmt, export_all=False)

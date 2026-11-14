"""Module 11: PCAP Analyzer - Pure-Python binary PCAP parser + protocol & packet inspection."""

from __future__ import annotations

import socket
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager


class PcapAnalyzerModule:
    """Parses real libpcap (.pcap) packet captures without requiring libpcap/Npcap."""

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports
        self.loaded_file: Path | None = None
        self.packets: list[dict[str, Any]] = []

    def _parse_pcap(self, path: Path) -> list[dict[str, Any]]:
        raw = path.read_bytes()
        if len(raw) < 24:
            raise ValueError("File is smaller than 24-byte PCAP global header.")

        magic = raw[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError(f"Unsupported capture magic header ({magic.hex()}). Standard .pcap format required.")

        _, ver_maj, ver_min, _, _, snaplen, link_type = struct.unpack(endian + "IHHiIII", raw[:24])
        offset = 24
        parsed: list[dict[str, Any]] = []
        idx = 0

        while offset + 16 <= len(raw):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", raw[offset : offset + 16])
            offset += 16
            frame = raw[offset : offset + incl_len]
            offset += incl_len
            idx += 1

            pkt: dict[str, Any] = {
                "index": idx,
                "timestamp": datetime.fromtimestamp(ts_sec + ts_usec / 1e6, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3],
                "length": orig_len,
                "protocol": "OTHER",
                "src_ip": "-",
                "dst_ip": "-",
                "src_port": None,
                "dst_port": None,
                "info": f"LinkType={link_type} Len={incl_len}",
                "payload_ascii": "",
            }

            # Ethernet II (link_type == 1)
            if link_type == 1 and len(frame) >= 14:
                eth_type = struct.unpack("!H", frame[12:14])[0]
                if eth_type == 0x0800 and len(frame) >= 34:  # IPv4
                    ihl = (frame[14] & 0x0F) * 4
                    proto_num = frame[23]
                    src_ip = socket.inet_ntoa(frame[26:30])
                    dst_ip = socket.inet_ntoa(frame[30:34])
                    pkt["src_ip"] = src_ip
                    pkt["dst_ip"] = dst_ip

                    l4 = frame[14 + ihl :]
                    if proto_num == 6 and len(l4) >= 20:  # TCP
                        sport, dport, _, _, doff_flags = struct.unpack("!HHIIH", l4[:14])
                        data_off = ((doff_flags >> 12) & 0x0F) * 4
                        flags = doff_flags & 0x3F
                        flag_names = [name for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")) if flags & bit]
                        pkt["protocol"] = "HTTP" if (sport in {80, 8080} or dport in {80, 8080}) else "TLS" if (sport == 443 or dport == 443) else "TCP"
                        pkt["src_port"] = sport
                        pkt["dst_port"] = dport
                        payload = l4[data_off:]
                        pkt["info"] = f"{sport} -> {dport} [{' '.join(flag_names) or 'TCP'}]"
                        pkt["payload_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:120])
                    elif proto_num == 17 and len(l4) >= 8:  # UDP
                        sport, dport, ulen = struct.unpack("!HHH", l4[:6])
                        pkt["protocol"] = "DNS" if (sport == 53 or dport == 53) else "UDP"
                        pkt["src_port"] = sport
                        pkt["dst_port"] = dport
                        payload = l4[8:]
                        pkt["info"] = f"{sport} -> {dport} Len={ulen}"
                        pkt["payload_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload[:120])
                    elif proto_num == 1 and len(l4) >= 4:  # ICMP
                        icmp_type, icmp_code = l4[0], l4[1]
                        pkt["protocol"] = "ICMP"
                        pkt["info"] = f"ICMP type={icmp_type} code={icmp_code}"
                elif eth_type == 0x0806:
                    pkt["protocol"] = "ARP"
                    pkt["info"] = "ARP Frame"

            parsed.append(pkt)
        return parsed

    def load(self, file_path: str) -> list[dict[str, Any]]:
        path = Path(file_path).expanduser()
        if not path.exists() or not path.is_file():
            self.console.print(f"[bold red][-][/] PCAP file not found: {path}")
            return []
        try:
            self.packets = self._parse_pcap(path)
            self.loaded_file = path.resolve()
        except Exception as exc:
            self.console.print(f"[bold red][-][/] Failed to parse PCAP: {exc}")
            return []
        self.console.print(f"[bright_green][+][/] Loaded [white]{len(self.packets)}[/] packet(s) from [bright_green]{self.loaded_file.name}[/]")
        return self.packets

    def _ensure_loaded(self, file_path: str | None) -> bool:
        if file_path:
            return len(self.load(file_path)) > 0
        if not self.packets:
            self.console.print("[yellow][!][/] No PCAP loaded. Specify a file: `pcap summary <file.pcap>` or `pcap load <file.pcap>`.")
            return False
        return True

    def summary(self, file_path: str | None = None) -> dict[str, Any]:
        if not self._ensure_loaded(file_path):
            return {}
        proto_counts = Counter(p["protocol"] for p in self.packets)
        talkers = Counter(p["src_ip"] for p in self.packets if p["src_ip"] != "-")
        total_bytes = sum(p["length"] for p in self.packets)

        table = Table(
            title=f"[bold bright_green]PCAP SUMMARY // {self.loaded_file.name if self.loaded_file else 'LOADED'}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        table.add_column("Metric", style="grey70", width=22)
        table.add_column("Value", style="white")
        table.add_row("Total Packets", f"[bright_green]{len(self.packets)}[/]")
        table.add_row("Total Capture Bytes", f"{total_bytes:,} B")
        table.add_row("Protocol Breakdown", ", ".join(f"{k}={v}" for k, v in proto_counts.most_common()))
        table.add_row("Top Source Talkers", ", ".join(f"{ip} ({cnt})" for ip, cnt in talkers.most_common(5)) or "N/A")
        self.console.print(table)

        res = {"file": str(self.loaded_file), "packet_count": len(self.packets), "total_bytes": total_bytes, "protocols": dict(proto_counts), "top_talkers": dict(talkers.most_common(5))}
        self.reports.record("PCAP_SUMMARY", f"PCAP Summary: {self.loaded_file.name if self.loaded_file else 'capture'}", res)
        return res

    def filter_packets(self, expr: str, file_path: str | None = None) -> list[dict[str, Any]]:
        if not self._ensure_loaded(file_path):
            return []
        q = expr.strip().lower()
        matched: list[dict[str, Any]] = []
        for p in self.packets:
            if q.startswith("port="):
                port = int(q.split("=", 1)[1])
                if p["src_port"] == port or p["dst_port"] == port:
                    matched.append(p)
            elif q.startswith("ip="):
                ip = q.split("=", 1)[1]
                if p["src_ip"] == ip or p["dst_ip"] == ip:
                    matched.append(p)
            elif q in p["protocol"].lower() or q in p["info"].lower() or q in p["src_ip"] or q in p["dst_ip"]:
                matched.append(p)

        self._render_packet_table(matched[:30], title=f"PCAP FILTER '{expr}' ({len(matched)} MATCHES)")
        return matched

    def inspect_packet(self, index: int = 1, file_path: str | None = None) -> dict[str, Any] | None:
        if not self._ensure_loaded(file_path):
            return None
        if index < 1 or index > len(self.packets):
            self.console.print(f"[bold red][-][/] Packet index out of range (1..{len(self.packets)}).")
            return None
        p = self.packets[index - 1]
        self.console.print(
            Panel(
                f"[white]Packet #   :[/] [bright_green]{p['index']}[/] ({p['timestamp']})\n"
                f"[white]Protocol   :[/] {p['protocol']}  |  [white]Length:[/] {p['length']} B\n"
                f"[white]Endpoints  :[/] {p['src_ip']}:{p['src_port'] or '-'} -> {p['dst_ip']}:{p['dst_port'] or '-'}\n"
                f"[white]Info       :[/] {p['info']}\n"
                f"[white]ASCII View :[/] [grey70]{p['payload_ascii'] or '(no printable payload)'}[/]",
                title=f"[bold bright_green]PACKET INSPECTOR // #{index}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return p

    def _render_packet_table(self, packets: list[dict[str, Any]], title: str) -> None:
        table = Table(title=f"[bold bright_green]{title}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("#", width=5, justify="right", style="grey70")
        table.add_column("Time", width=13, style="grey70")
        table.add_column("Proto", width=7, style="bright_green")
        table.add_column("Source", style="white")
        table.add_column("Destination", style="white")
        table.add_column("Info", style="grey70")
        for p in packets:
            src = f"{p['src_ip']}:{p['src_port']}" if p["src_port"] else p["src_ip"]
            dst = f"{p['dst_ip']}:{p['dst_port']}" if p["dst_port"] else p["dst_ip"]
            table.add_row(str(p["index"]), p["timestamp"], p["protocol"], src, dst, p["info"])
        self.console.print(table)

    def export(self, file_path: str | None = None, fmt: str = "json") -> None:
        if self.summary(file_path=file_path):
            self.reports.export_report(export_format=fmt, export_all=False)

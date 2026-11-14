"""Module 03: Threat Intelligence - IOC lookup, observable analysis, feed sync, and reporting."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
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

from core.config import DATA_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


SEED_IOC_FEED: dict[str, Any] = {
    "updated_at": "2026-11-14T00:00:00Z",
    "source": "BLACKVEIL Built-in Defensive Reference IOCs (EICAR + RFC Documentation Test Vectors)",
    "hashes": {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File (Standard AV Test Signature)",
        "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File MD5",
    },
    "ips": {
        "198.51.100.44": "RFC5737 Lab Brute-Force Simulation Vector",
        "203.0.113.77": "RFC5737 Lab Log Intrusion Vector",
    },
    "domains": {
        "malware.testing.blackveil.local": "Local Lab Sinkhole Test Domain",
    },
}


class ThreatIntelModule:
    """Evaluates IPs, domains, URLs, and file hashes using local feeds, structural heuristics, and optional online APIs."""

    SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".loan"}

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.reports = reports
        self.feed_path = DATA_DIR / "threat_feed.json"
        self._ensure_feed()

    def _ensure_feed(self) -> None:
        if not self.feed_path.exists():
            self.feed_path.write_text(json.dumps(SEED_IOC_FEED, indent=2), encoding="utf-8")

    def _load_feed(self) -> dict[str, Any]:
        self._ensure_feed()
        try:
            return json.loads(self.feed_path.read_text(encoding="utf-8"))
        except Exception:
            return SEED_IOC_FEED

    @staticmethod
    def _classify_observable(obs: str) -> str:
        s = obs.strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", s):
            return "HASH"
        if s.lower().startswith(("http://", "https://")):
            return "URL"
        try:
            ipaddress.ip_address(s)
            return "IP"
        except ValueError:
            return "DOMAIN"

    @staticmethod
    def _string_entropy(text: str) -> float:
        if not text:
            return 0.0
        cnt = Counter(text)
        total = len(text)
        return round(-sum((v / total) * math.log2(v / total) for v in cnt.values()), 3)

    def lookup(self, observable: str, online: bool = False) -> dict[str, Any]:
        """Lookup and score an IP, domain, URL, or file hash."""
        obs = observable.strip()
        kind = self._classify_observable(obs)
        feed = self._load_feed()
        indicators: list[str] = []
        risk_score = 0
        resolved_ips: list[str] = []

        if kind == "HASH":
            hit = feed.get("hashes", {}).get(obs.lower())
            if hit:
                risk_score += 90
                indicators.append(f"Matched local IOC hash database: {hit}")
        elif kind == "IP":
            ip_obj = ipaddress.ip_address(obs)
            if ip_obj.is_private or ip_obj.is_loopback:
                indicators.append("RFC1918 Private / Loopback Address (Non-routable)")
            hit = feed.get("ips", {}).get(obs)
            if hit:
                risk_score += 75
                indicators.append(f"Matched local threat feed IP: {hit}")
        elif kind in {"DOMAIN", "URL"}:
            parsed = urllib.parse.urlparse(obs if kind == "URL" else f"https://{obs}")
            host = (parsed.hostname or obs).lower()
            hit = feed.get("domains", {}).get(host)
            if hit:
                risk_score += 80
                indicators.append(f"Matched local threat feed domain: {hit}")
            if "xn--" in host:
                risk_score += 35
                indicators.append("Punycode (IDN) label detected — verify against homograph spoofing")
            if any(host.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                risk_score += 20
                indicators.append("High-abuse TLD category detected")
            ent = self._string_entropy(host.split(".")[0])
            if ent >= 3.8 and len(host.split(".")[0]) >= 12:
                risk_score += 30
                indicators.append(f"High domain label entropy ({ent}) — potential DGA pattern")
            if kind == "URL" and "@" in obs:
                risk_score += 40
                indicators.append("URL contains '@' credential-obfuscation pattern")
            if kind == "URL" and parsed.scheme == "http":
                risk_score += 10
                indicators.append("Unencrypted HTTP scheme")
            try:
                resolved_ips = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})[:5]
            except OSError:
                resolved_ips = []

        # Optional VirusTotal lookup if user configured VT_API_KEY env var and requested --online
        vt_note = "Not queried (local mode)"
        vt_key = os.environ.get("VT_API_KEY", "").strip()
        if online and vt_key and kind == "HASH":
            try:
                req = urllib.request.Request(
                    f"https://www.virustotal.com/api/v3/files/{obs.lower()}",
                    headers={"x-apikey": vt_key, "User-Agent": "BLACKVEIL-X/1.0"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    vt_data = json.loads(resp.read().decode("utf-8"))
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = int(stats.get("malicious", 0))
                vt_note = f"VirusTotal malicious={mal}, suspicious={stats.get('suspicious', 0)}"
                if mal > 0:
                    risk_score = min(100, risk_score + 70)
                    indicators.append(vt_note)
            except Exception as exc:
                vt_note = f"VirusTotal error: {exc}"
        elif online and not vt_key:
            vt_note = "VT_API_KEY not set; using local IOC + DNS/heuristic checks"

        verdict = "MALICIOUS / HIGH RISK" if risk_score >= 70 else "SUSPICIOUS" if risk_score >= 30 else "CLEAN / LOW RISK"
        v_col = "bold red" if risk_score >= 70 else "bold yellow" if risk_score >= 30 else "bold bright_green"

        self.console.print(
            Panel(
                f"[white]Observable  :[/] [bright_green]{obs}[/] ({kind})\n"
                f"[white]Verdict     :[/] [{v_col}]{verdict}[/] (Score: {risk_score}/100)\n"
                f"[white]DNS Resolve :[/] {', '.join(resolved_ips) if resolved_ips else 'N/A'}\n"
                f"[white]Online Feed :[/] {vt_note}\n"
                f"[white]Indicators  :[/] {'; '.join(indicators) if indicators else 'No adverse indicators triggered'}",
                title="[bold bright_green]THREAT INTELLIGENCE // LOOKUP[/]",
                border_style="bright_green" if risk_score < 30 else "red",
                box=box.SQUARE,
            )
        )

        result = {
            "observable": obs,
            "type": kind,
            "risk_score": risk_score,
            "verdict": verdict,
            "resolved_ips": resolved_ips,
            "indicators": indicators,
            "online_status": vt_note,
        }
        self.reports.record("THREAT_INTEL", f"Threat Lookup: {obs}", result, severity="HIGH" if risk_score >= 70 else "INFO")
        return result

    def analyze_file_or_list(self, target: str) -> dict[str, Any]:
        """Extract observables (IPs/domains/URLs) or hash a file and evaluate threat indicators."""
        p = Path(target).expanduser()
        if p.exists() and p.is_file():
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            return self.lookup(digest)
        return self.lookup(target)

    def manage_feed(self, sync_online: bool = False, add_ioc: str | None = None) -> dict[str, Any]:
        """Inspect local IOC feed, add custom IOC, or sync public Feodo Tracker IP blocklist when --online."""
        feed = self._load_feed()
        if add_ioc:
            kind = self._classify_observable(add_ioc)
            bucket = "hashes" if kind == "HASH" else "ips" if kind == "IP" else "domains"
            feed.setdefault(bucket, {})[add_ioc.strip().lower() if kind != "IP" else add_ioc.strip()] = f"Operator IOC added {utc_now()[:10]}"
            feed["updated_at"] = utc_now()
            self.feed_path.write_text(json.dumps(feed, indent=2), encoding="utf-8")
            self.console.print(f"[bright_green][+][/] Added {kind} IOC '{add_ioc}' to local threat feed.")

        if sync_online:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "BLACKVEIL-X/1.0"})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    entries = json.loads(resp.read().decode("utf-8"))
                added = 0
                for item in entries[:200]:
                    ip_addr = item.get("ip_address")
                    if ip_addr:
                        feed.setdefault("ips", {})[ip_addr] = f"FeodoTracker ({item.get('malware', 'C2')})"
                        added += 1
                feed["updated_at"] = utc_now()
                self.feed_path.write_text(json.dumps(feed, indent=2), encoding="utf-8")
                self.console.print(f"[bright_green][+][/] Synced {added} IOCs from FeodoTracker feed.")
            except Exception as exc:
                self.console.print(f"[bold yellow][!][/] Online feed sync failed ({exc}); local cache remains active.")

        table = Table(title="[bold bright_green]THREAT INTELLIGENCE FEED SUMMARY[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", show_header=False)
        table.add_column("Metric", style="grey70", width=22)
        table.add_column("Value", style="white")
        table.add_row("Feed File", str(self.feed_path))
        table.add_row("Last Updated", str(feed.get("updated_at")))
        table.add_row("Hash IOCs", str(len(feed.get("hashes", {}))))
        table.add_row("IP IOCs", str(len(feed.get("ips", {}))))
        table.add_row("Domain IOCs", str(len(feed.get("domains", {}))))
        self.console.print(table)
        return feed

    def report(self, observable: str | None = None, fmt: str = "json") -> None:
        if observable:
            self.lookup(observable)
        self.reports.export_report(export_format=fmt, export_all=False)

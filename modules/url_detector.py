"""Module 18: Malicious URL Detector - Structural, IDN homograph, TLS, redirect & reputation analysis."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import ConfigManager, SecretsManager
from core.logger import BlackveilLogger
from modules.reports import ReportManager
from modules.threat_intel import ThreatIntelModule


class _HeadNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class UrlDetectorModule:
    """Evaluates URL safety without executing payloads or auto-opening target pages."""

    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc", "lnkd.in",
    }
    SUSPICIOUS_TLDS = {
        "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
        "work", "buzz", "monster", "rest", "fit", "cam", "icu",
    }
    EXECUTABLE_EXTENSIONS = (
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".msi", ".hta", ".iso", ".img", ".lnk", ".apk", ".dll", ".pif",
    )
    PHISHING_KEYWORDS = (
        "login", "signin", "verify", "update-account", "secure-billing",
        "password-reset", "wallet-connect", "confirm-identity", "suspended", "webscr",
    )
    BRAND_TARGETS = ("paypal", "microsoft", "google", "apple", "amazon", "netflix", "binance", "metamask", "github")

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        secrets: SecretsManager,
        threat_intel: ThreatIntelModule,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.secrets = secrets
        self.threat_intel = threat_intel
        self.reports = reports

    @staticmethod
    def _normalize_url(raw_url: str) -> str:
        cleaned = raw_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"
        return cleaned

    @staticmethod
    def _trace_redirects_safe(url: str, max_hops: int = 8) -> tuple[list[dict[str, Any]], bool]:
        """Trace redirects via HEAD without downloading payload bodies or executing content."""
        opener = urllib.request.build_opener(_HeadNoRedirect())
        chain: list[dict[str, Any]] = []
        cur = url
        visited: set[str] = set()
        reachable = False

        for _ in range(max_hops):
            if cur in visited:
                break
            visited.add(cur)
            req = urllib.request.Request(cur, method="HEAD", headers={"User-Agent": "BLACKVEIL-X-URLGuard/1.0"})
            try:
                with opener.open(req, timeout=5.0) as resp:
                    reachable = True
                    chain.append({"url": cur, "status": resp.status, "location": resp.headers.get("Location", "")})
                    break
            except urllib.error.HTTPError as exc:
                loc = exc.headers.get("Location", "") if exc.headers else ""
                chain.append({"url": cur, "status": exc.code, "location": loc})
                if exc.code in {301, 302, 303, 307, 308} and loc:
                    reachable = True
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
                if exc.code in {400, 401, 403, 404, 405, 429}:
                    reachable = True
                break
            except Exception as exc:
                chain.append({"url": cur, "status": None, "error": str(exc)})
                break
        return chain, reachable

    @staticmethod
    def _check_domain_age_rdap(domain: str) -> dict[str, Any]:
        parts = domain.lower().strip(".").split(".")
        reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        req = urllib.request.Request(
            f"https://rdap.org/domain/{urllib.parse.quote(reg_domain)}",
            headers={"User-Agent": "BLACKVEIL-X-URLGuard/1.0", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                    dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - dt).days
                    return {"checked": True, "domain": reg_domain, "registered_at": dt.date().isoformat(), "age_days": age_days}
            return {"checked": True, "domain": reg_domain, "registered_at": None, "age_days": None}
        except Exception as exc:
            return {"checked": False, "domain": reg_domain, "error": str(exc)}

    @staticmethod
    def _check_tls_basic(host: str) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=5.0) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    return {"verified": True, "days_left": (not_after - datetime.now(timezone.utc)).days, "tls_version": tls.version()}
        except ssl.SSLCertVerificationError as exc:
            return {"verified": False, "error": str(exc)}
        except Exception as exc:
            return {"verified": None, "error": str(exc)}

    def _query_google_safe_browsing(self, url: str) -> dict[str, Any]:
        api_key = self.secrets.get_secret("google_safe_browsing_api_key", ("GOOGLE_SAFE_BROWSING_API_KEY",))
        if not api_key:
            return {"executed": False, "reason": "GOOGLE_SAFE_BROWSING_API_KEY not configured"}
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={urllib.parse.quote(api_key)}"
        payload = {
            "client": {"clientId": "blackveil-x", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        req = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            matches = data.get("matches", [])
            return {"executed": True, "malicious": bool(matches), "matches": matches}
        except Exception as exc:
            return {"executed": False, "reason": str(exc)}

    def _query_virustotal_url(self, url: str) -> dict[str, Any]:
        vt_key = self.secrets.get_secret("virustotal_api_key", ("VT_API_KEY", "VIRUSTOTAL_API_KEY"))
        if not vt_key:
            return {"executed": False, "reason": "VT_API_KEY not configured"}
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": vt_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"executed": True, "stats": stats, "malicious_votes": int(stats.get("malicious", 0)), "suspicious_votes": int(stats.get("suspicious", 0))}
        except Exception as exc:
            return {"executed": False, "reason": str(exc)}

    def analyze(self, raw_url: str, mode: str = "analyze") -> dict[str, Any]:
        """Inspect URL structure, homographs, redirects, TLS, domain age, and optional threat APIs."""
        url = self._normalize_url(raw_url)
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        path_lower = (parsed.path or "").lower()

        reasons: list[dict[str, str]] = []
        score = 0
        checks_performed = ["URL structural & lexical inspection", "IDN/homograph check", "Local IOC reputation check"]
        checks_skipped: list[str] = []

        if scheme in {"javascript", "data", "vbscript", "file"}:
            score += 90
            reasons.append({"severity": "DANGEROUS", "reason": f"Unsafe URI scheme '{scheme}:' detected."})
        elif scheme == "http":
            score += 15
            reasons.append({"severity": "SUSPICIOUS", "reason": "Plain HTTP without TLS encryption."})

        if parsed.username or parsed.password or "@" in parsed.netloc:
            score += 45
            reasons.append({"severity": "DANGEROUS", "reason": "Credential/@ authority obfuscation detected in URL netloc."})

        if not host:
            reasons.append({"severity": "UNKNOWN", "reason": "URL has no valid hostname."})
            return {"url": raw_url, "verdict": "UNKNOWN", "score": 0, "reasons": reasons}

        # IP literal or integer/hex IP obfuscation
        is_ip_host = False
        try:
            ipaddress.ip_address(host)
            is_ip_host = True
        except ValueError:
            if re.fullmatch(r"(?:0x[0-9a-f]+|\d{7,10})", host):
                is_ip_host = True
        if is_ip_host:
            score += 35
            reasons.append({"severity": "SUSPICIOUS", "reason": f"Host uses raw/obfuscated IP literal ({host}) instead of domain name."})

        # IDN / Punycode / Homograph detection
        has_non_ascii = any(ord(ch) > 127 for ch in host)
        if "xn--" in host or has_non_ascii:
            score += 30
            try:
                decoded_idn = host.encode("ascii", errors="ignore").decode("idna")
            except Exception:
                decoded_idn = host
            reasons.append({"severity": "SUSPICIOUS", "reason": f"IDN/Punycode domain detected ({host} -> {decoded_idn}); verify against homograph spoofing."})

        # Shortener & TLD & Subdomain depth
        if host in self.URL_SHORTENERS:
            score += 20
            reasons.append({"severity": "SUSPICIOUS", "reason": f"Known URL shortener ({host}) obscures final destination."})

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in self.SUSPICIOUS_TLDS:
            score += 18
            reasons.append({"severity": "SUSPICIOUS", "reason": f"High-abuse TLD '.{tld}' detected."})

        if host.count(".") >= 4 or host.count("-") >= 4:
            score += 15
            reasons.append({"severity": "SUSPICIOUS", "reason": "Excessive subdomain nesting or hyphenation."})

        if len(url) > 160:
            score += 10
            reasons.append({"severity": "SUSPICIOUS", "reason": f"Unusually long URL ({len(url)} chars)."})

        # Suspicious download extension
        if any(path_lower.endswith(ext) for ext in self.EXECUTABLE_EXTENSIONS):
            score += 35
            reasons.append({"severity": "DANGEROUS", "reason": f"URL points directly to executable/script payload extension ({path_lower.rsplit('.', 1)[-1]})."})

        # Phishing / brand lure patterns
        full_lower = url.lower()
        kw_hits = [kw for kw in self.PHISHING_KEYWORDS if kw in full_lower]
        if kw_hits:
            score += 15
            reasons.append({"severity": "SUSPICIOUS", "reason": f"Credential/phishing lure keywords present: {', '.join(kw_hits[:4])}."})

        reg_root = ".".join(host.split(".")[-2:])
        for brand in self.BRAND_TARGETS:
            if brand in host and brand not in reg_root:
                score += 35
                reasons.append({"severity": "DANGEROUS", "reason": f"Possible brand impersonation: '{brand}' appears in subdomain/lure outside registered domain '{reg_root}'."})
                break

        # Local Threat Intel feed check
        local_hit = False
        feed = self.threat_intel._load_feed()
        feed_match = feed.get("domains", {}).get(host) or feed.get("ips", {}).get(host)
        if feed_match:
            local_hit = True
            score += 75
            reasons.append({"severity": "DANGEROUS", "reason": f"Matched local BLACKVEIL threat feed: {feed_match}"})

        # Online checks (DNS, Redirects, TLS, Domain age, Optional GSB/VT)
        dns_resolved = False
        redirects: list[dict[str, Any]] = []
        tls_info: dict[str, Any] = {}
        rdap_age: dict[str, Any] = {}
        gsb_res: dict[str, Any] = {}
        vt_res: dict[str, Any] = {}

        with self.console.status(f"[bold bright_green][*] Inspecting URL reputation & metadata for {host}...[/]", spinner="dots"):
            try:
                socket.getaddrinfo(host, None)
                dns_resolved = True
                checks_performed.append("DNS resolution")
            except OSError:
                checks_skipped.append("DNS resolution failed / host unresolvable")

            if dns_resolved and scheme in {"http", "https"}:
                redirects, reachable = self._trace_redirects_safe(url)
                checks_performed.append("HEAD redirect chain check")
                if len(redirects) > 1:
                    final_host = (urllib.parse.urlparse(redirects[-1]["url"]).hostname or "").lower()
                    if final_host and final_host != host:
                        score += 20
                        reasons.append({"severity": "SUSPICIOUS", "reason": f"Cross-domain redirect chain ends at '{final_host}'."})
                if scheme == "https":
                    tls_info = self._check_tls_basic(host)
                    checks_performed.append("TLS certificate check")
                    if tls_info.get("verified") is False:
                        score += 40
                        reasons.append({"severity": "DANGEROUS", "reason": f"Untrusted/invalid TLS certificate: {tls_info.get('error', '')[:80]}"})
                if not is_ip_host:
                    rdap_age = self._check_domain_age_rdap(host)
                    if rdap_age.get("checked"):
                        checks_performed.append("RDAP domain registration age")
                        if isinstance(rdap_age.get("age_days"), int) and rdap_age["age_days"] < 30:
                            score += 30
                            reasons.append({"severity": "SUSPICIOUS", "reason": f"Newly registered domain ({rdap_age['age_days']} days old)."})
                    else:
                        checks_skipped.append(f"RDAP domain age ({rdap_age.get('error', 'unavailable')})")
            else:
                reachable = False

            gsb_res = self._query_google_safe_browsing(url)
            if gsb_res.get("executed"):
                checks_performed.append("Google Safe Browsing API")
                if gsb_res.get("malicious"):
                    score = max(score + 60, 90)
                    reasons.append({"severity": "DANGEROUS", "reason": "Flagged by Google Safe Browsing API."})
            else:
                checks_skipped.append(f"Google Safe Browsing ({gsb_res.get('reason')})")

            vt_res = self._query_virustotal_url(url)
            if vt_res.get("executed"):
                checks_performed.append("VirusTotal URL API")
                if vt_res.get("malicious_votes", 0) > 0:
                    score = max(score + 50, 85)
                    reasons.append({"severity": "DANGEROUS", "reason": f"VirusTotal flagged malicious by {vt_res['malicious_votes']} engine(s)."})
                elif vt_res.get("suspicious_votes", 0) > 0:
                    score += 25
                    reasons.append({"severity": "SUSPICIOUS", "reason": f"VirusTotal flagged suspicious by {vt_res['suspicious_votes']} engine(s)."})
            else:
                checks_skipped.append(f"VirusTotal API ({vt_res.get('reason')})")

        score = min(100, score)
        if score >= 60:
            verdict = "DANGEROUS"
        elif score >= 20:
            verdict = "SUSPICIOUS"
        elif not dns_resolved and not local_hit:
            verdict = "UNKNOWN"
            reasons.append({"severity": "UNKNOWN", "reason": "Domain could not be resolved and external reputation APIs were unavailable/unconfigured."})
        else:
            verdict = "SAFE"

        result = {
            "url": url,
            "host": host,
            "mode": mode,
            "verdict": verdict,
            "risk_score": score,
            "reasons": reasons,
            "dns_resolved": dns_resolved,
            "redirects": redirects,
            "tls": tls_info,
            "rdap_domain_age": rdap_age,
            "google_safe_browsing": gsb_res,
            "virustotal": vt_res,
            "checks_performed": checks_performed,
            "checks_skipped": checks_skipped,
        }
        self._render_verdict(result)
        sev = "CRITICAL" if verdict == "DANGEROUS" else "WARNING" if verdict == "SUSPICIOUS" else "INFO"
        self.reports.record("URL_DETECTOR", f"URL Check ({verdict}): {host}", result, severity=sev)
        return result

    def _render_verdict(self, res: dict[str, Any]) -> None:
        v = res["verdict"]
        v_col = "bold red" if v == "DANGEROUS" else "bold yellow" if v == "SUSPICIOUS" else "bold bright_green" if v == "SAFE" else "grey70"
        age_txt = f"{res['rdap_domain_age'].get('age_days')} days (reg {res['rdap_domain_age'].get('registered_at')})" if res["rdap_domain_age"].get("age_days") is not None else "Unavailable"
        tls_txt = f"Verified={res['tls'].get('verified')} ({res['tls'].get('tls_version', '-')})" if res["tls"] else "Not checked"

        self.console.print(
            Panel(
                f"[white]URL         :[/] {res['url']}\n"
                f"[white]Verdict     :[/] [{v_col}]{v}[/]  (Risk Score: {res['risk_score']}/100)\n"
                f"[white]DNS / TLS   :[/] DNS={'OK' if res['dns_resolved'] else 'FAIL'} | TLS={tls_txt}\n"
                f"[white]Domain Age  :[/] {age_txt}\n"
                f"[white]Redirects   :[/] {len(res['redirects'])} hop(s)\n"
                f"[white]Checks Run  :[/] {', '.join(res['checks_performed'])}\n"
                f"[white]Skipped     :[/] [grey70]{'; '.join(res['checks_skipped']) or 'None'}[/]",
                title=f"[bold bright_green]MALICIOUS URL DETECTOR // {v}[/]",
                border_style="red" if v == "DANGEROUS" else "yellow" if v == "SUSPICIOUS" else "bright_green",
                box=box.SQUARE,
            )
        )

        if res["reasons"]:
            table = Table(title="[bold bright_green]VERDICT EVIDENCE & INDICATORS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
            table.add_column("Level", width=12)
            table.add_column("Indicator / Reason", style="white")
            for item in res["reasons"]:
                col = "bold red" if item["severity"] == "DANGEROUS" else "yellow" if item["severity"] == "SUSPICIOUS" else "grey70"
                table.add_row(f"[{col}]{item['severity']}[/]", item["reason"])
            self.console.print(table)
        else:
            self.console.print("[bright_green][+][/] No malicious structural, redirect, or TLS anomalies detected.")

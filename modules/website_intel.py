"""Module 15: Advanced Website Intelligence - Passive & authorized web technical analysis."""

from __future__ import annotations

import csv
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import REPORTS_DIR, ensure_directories
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.cert_watcher import CertWatcherModule
from modules.dns_intel import DnsIntelModule
from modules.reports import ReportManager


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Capture redirects one hop at a time without blindly following."""

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class _PageInspectorParser(HTMLParser):
    """Extracts metadata, scripts, stylesheets, images, and links from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()
        self.in_title = False
        self.title_parts: list[str] = []
        self.meta_description = ""
        self.meta_generator = ""
        self.html_lang = ""
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.images: list[str] = []
        self.internal_links: list[str] = []
        self.external_links: list[str] = []
        self.forms_count = 0
        self.text_snippets: list[str] = []
        self._skip_text = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if t == "html" and attr_map.get("lang"):
            self.html_lang = attr_map["lang"].strip()
        elif t == "title":
            self.in_title = True
        elif t in {"script", "style"}:
            self._skip_text = True
            if t == "script" and attr_map.get("src"):
                self.scripts.append(urllib.parse.urljoin(self.base_url, attr_map["src"]))
        elif t == "meta":
            name = attr_map.get("name", "").lower()
            if name == "description" and attr_map.get("content"):
                self.meta_description = attr_map["content"].strip()
            elif name == "generator" and attr_map.get("content"):
                self.meta_generator = attr_map["content"].strip()
        elif t == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "").strip()
            if href and "stylesheet" in rel:
                self.stylesheets.append(urllib.parse.urljoin(self.base_url, href))
        elif t == "img":
            src = attr_map.get("src", "").strip()
            if src:
                self.images.append(urllib.parse.urljoin(self.base_url, src))
        elif t == "a":
            href = attr_map.get("href", "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                resolved = urllib.parse.urljoin(self.base_url, href)
                host = (urllib.parse.urlparse(resolved).hostname or "").lower()
                if host == self.base_host or not host:
                    if resolved not in self.internal_links:
                        self.internal_links.append(resolved)
                else:
                    if resolved not in self.external_links:
                        self.external_links.append(resolved)
        elif t == "form":
            self.forms_count += 1

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t in {"script", "style"}:
            self._skip_text = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        elif not self._skip_text:
            cleaned = " ".join(data.split())
            if cleaned:
                self.text_snippets.append(cleaned)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:180]


class WebsiteIntelModule:
    """Comprehensive passive website intelligence scanner with source attribution and non-HTML reports."""

    SECURITY_HEADERS = (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    )

    TECH_SIGNATURES: list[tuple[str, str, str]] = [
        (r"wp-content|wp-includes|wordpress", "WordPress", "HTML / Asset URLs"),
        (r"/_next/static|__NEXT_DATA__", "Next.js", "HTML / Script Paths"),
        (r"react(?:\.production|\.development|-dom)", "React", "Script Asset"),
        (r"vue(?:\.runtime|\.global|\.\d)", "Vue.js", "Script Asset"),
        (r"jquery(?:-\d|\.min\.js)", "jQuery", "Script Asset"),
        (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap", "CSS/JS Asset"),
        (r"csrfmiddlewaretoken|django", "Django", "HTML Form/Cookie"),
        (r"cloudflare|__cf_bm|cf-ray", "Cloudflare", "HTTP Headers/Cookies"),
        (r"laravel_session|xsrf-token", "Laravel", "Set-Cookie Header"),
        (r"phpsessid", "PHP", "Set-Cookie Header"),
        (r"asp\.net|__viewstate", "ASP.NET", "Headers/HTML"),
    ]

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        db: DatabaseManager,
        reports: ReportManager,
        dns_intel: DnsIntelModule,
        cert_watcher: CertWatcherModule,
    ) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        self.reports = reports
        self.dns_intel = dns_intel
        self.cert_watcher = cert_watcher

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        cleaned = raw_url.strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = f"https://{cleaned}"
        return cleaned

    @staticmethod
    def _single_http_request(url: str, method: str = "GET", timeout: float = 8.0) -> dict[str, Any]:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        req = urllib.request.Request(
            url,
            method=method,
            headers={"User-Agent": "BLACKVEIL-X-PassiveScanner/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(250_000) if method == "GET" else b""
                raw_headers = list(resp.headers.items())
                return {
                    "ok": True,
                    "url": resp.geturl(),
                    "status": resp.status,
                    "headers": {k.lower(): v for k, v in raw_headers},
                    "raw_headers": raw_headers,
                    "body": body.decode("utf-8", errors="replace"),
                }
        except urllib.error.HTTPError as exc:
            raw_headers = list(exc.headers.items()) if exc.headers else []
            body = b""
            try:
                if method == "GET" and exc.fp:
                    body = exc.read(150_000)
            except Exception:
                pass
            return {
                "ok": exc.code in {301, 302, 303, 307, 308},
                "url": url,
                "status": exc.code,
                "headers": {k.lower(): v for k, v in raw_headers},
                "raw_headers": raw_headers,
                "body": body.decode("utf-8", errors="replace"),
                "error": f"HTTP {exc.code}: {exc.reason}",
            }
        except Exception as exc:
            return {"ok": False, "url": url, "status": None, "headers": {}, "raw_headers": [], "body": "", "error": str(exc)}

    def _trace_redirects_and_fetch(self, start_url: str, max_hops: int = 8) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        current = start_url
        visited: set[str] = set()
        final_resp: dict[str, Any] = {}

        for _ in range(max_hops):
            if current in visited:
                break
            visited.add(current)
            resp = self._single_http_request(current, method="GET", timeout=8.0)
            chain.append(
                {
                    "url": current,
                    "status": resp.get("status"),
                    "location": resp.get("headers", {}).get("location", ""),
                    "error": resp.get("error", ""),
                }
            )
            final_resp = resp
            loc = resp.get("headers", {}).get("location")
            if resp.get("status") in {301, 302, 303, 307, 308} and loc:
                current = urllib.parse.urljoin(current, loc)
                continue
            break
        return chain, final_resp

    @staticmethod
    def _parse_cookies(raw_headers: list[tuple[str, str]]) -> list[dict[str, Any]]:
        cookies: list[dict[str, Any]] = []
        for k, v in raw_headers:
            if k.lower() != "set-cookie":
                continue
            parts = [p.strip() for p in v.split(";") if p.strip()]
            name_val = parts[0] if parts else v
            name = name_val.split("=", 1)[0].strip()
            flags = {p.lower() for p in parts[1:]}
            samesite = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), "Missing")
            cookies.append(
                {
                    "name": name,
                    "httponly": "httponly" in flags,
                    "secure": "secure" in flags,
                    "samesite": samesite,
                }
            )
        return cookies

    @staticmethod
    def _parse_csp(csp_value: str) -> dict[str, Any]:
        if not csp_value:
            return {"present": False, "directives": {}, "warnings": ["Content-Security-Policy header is missing."]}
        directives: dict[str, str] = {}
        for chunk in csp_value.split(";"):
            part = chunk.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            directives[tokens[0].lower()] = tokens[1] if len(tokens) > 1 else ""
        warnings: list[str] = []
        lower_val = csp_value.lower()
        if "'unsafe-inline'" in lower_val:
            warnings.append("CSP permits 'unsafe-inline', weakening XSS defense.")
        if "'unsafe-eval'" in lower_val:
            warnings.append("CSP permits 'unsafe-eval'.")
        if "default-src" not in directives:
            warnings.append("CSP lacks fallback 'default-src' directive.")
        return {"present": True, "directives": directives, "warnings": warnings}

    def _fetch_text_resource(self, url: str) -> dict[str, Any]:
        resp = self._single_http_request(url, method="GET", timeout=5.0)
        return {
            "url": url,
            "present": resp.get("status") == 200,
            "status": resp.get("status"),
            "preview": resp.get("body", "")[:1500],
            "length": len(resp.get("body", "")),
        }

    def scan(
        self,
        raw_url: str,
        active_authorized: bool = False,
        export_fmt: str | None = None,
    ) -> dict[str, Any]:
        """Execute comprehensive passive website intelligence scan (and optional non-destructive authorized checks)."""
        target_url = self.normalize_url(raw_url)
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or ""
        if not host:
            self.console.print(f"[bold red][-][/] Invalid URL: '{raw_url}'")
            return {}

        self.logger.info("website_intel", f"Scanning website {target_url} (active_authorized={active_authorized})")
        with self.console.status(f"[bold bright_green][*] Running Website Intelligence scan on {host}...[/]", spinner="dots"):
            # 1. HTTP & HTTPS reachability
            http_probe = self._single_http_request(f"http://{host}", method="HEAD", timeout=5.0)
            https_probe = self._single_http_request(f"https://{host}", method="HEAD", timeout=5.0)

            # 2. Redirect chain + main body fetch
            redirect_chain, main_resp = self._trace_redirects_and_fetch(target_url)
            if main_resp.get("status") is None and target_url.startswith("https://"):
                # Try HTTP fallback if HTTPS unreachable
                redirect_chain, main_resp = self._trace_redirects_and_fetch(f"http://{host}{parsed.path or '/'}")

            final_url = main_resp.get("url") or (redirect_chain[-1]["url"] if redirect_chain else target_url)
            headers = main_resp.get("headers", {})
            raw_headers = main_resp.get("raw_headers", [])
            body_html = main_resp.get("body", "")

            # 3. DNS + IP addresses + Nameservers
            ipv4_list: list[str] = []
            ipv6_list: list[str] = []
            try:
                for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                    ip = sockaddr[0].split("%")[0]
                    if fam == socket.AF_INET and ip not in ipv4_list:
                        ipv4_list.append(ip)
                    elif fam == socket.AF_INET6 and ip not in ipv6_list:
                        ipv6_list.append(ip)
            except OSError:
                pass

            ns_records = self.dns_intel._raw_udp_query(host, "NS")
            mx_records = self.dns_intel._raw_udp_query(host, "MX")
            txt_records = self.dns_intel._raw_udp_query(host, "TXT")

            # 4. SSL/TLS certificate & TLS configuration (non-intrusive handshake)
            tls_info = self._inspect_tls_quiet(host, parsed.port or 443)

            # 5. HTML parsing
            parser = _PageInspectorParser(final_url)
            if body_html:
                try:
                    parser.feed(body_html)
                except Exception:
                    pass

            # 6. robots.txt & sitemap.xml
            parsed_final = urllib.parse.urlparse(final_url)
            root_base = f"{parsed_final.scheme or 'https'}://{parsed_final.netloc or host}"
            robots_info = self._fetch_text_resource(f"{root_base}/robots.txt")
            sitemap_info = self._fetch_text_resource(f"{root_base}/sitemap.xml")
            sitemap_urls = re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", sitemap_info.get("preview", ""), re.I)

            # 7. Cookies & Security Headers
            cookies = self._parse_cookies(raw_headers)
            csp_analysis = self._parse_csp(headers.get("content-security-policy", ""))
            sec_headers_status = {
                hdr: {
                    "present": hdr in headers,
                    "value": headers.get(hdr, ""),
                    "source": f"HTTP Response Header ({hdr})",
                }
                for hdr in self.SECURITY_HEADERS
            }

            # 8. Technology Fingerprinting with explicit source attribution
            tech_detected: list[dict[str, str]] = []
            if headers.get("server"):
                tech_detected.append({"name": headers["server"], "source": "HTTP Header 'Server'"})
            if headers.get("x-powered-by"):
                tech_detected.append({"name": headers["x-powered-by"], "source": "HTTP Header 'X-Powered-By'"})
            if parser.meta_generator:
                tech_detected.append({"name": parser.meta_generator, "source": "HTML <meta name='generator'>"})

            combined_probe = "\n".join(
                [
                    body_html[:60000],
                    " ".join(parser.scripts),
                    " ".join(parser.stylesheets),
                    json.dumps(headers),
                ]
            )
            seen_tech = {t["name"].lower() for t in tech_detected}
            for pat, label, src in self.TECH_SIGNATURES:
                if re.search(pat, combined_probe, re.I) and label.lower() not in seen_tech:
                    tech_detected.append({"name": label, "source": src})
                    seen_tech.add(label.lower())

            # 9. Passive security findings & risk grading
            findings: list[dict[str, str]] = []
            if not https_probe.get("status"):
                findings.append(
                    {
                        "risk": "HIGH",
                        "finding": "HTTPS endpoint unreachable or unconfigured",
                        "source": f"Direct HTTPS HEAD probe ({host}:443)",
                        "remediation": "Enable TLS 1.2/1.3 with a valid trusted certificate.",
                    }
                )
            elif http_probe.get("status") == 200 and not http_probe.get("headers", {}).get("location"):
                findings.append(
                    {
                        "risk": "MEDIUM",
                        "finding": "Plain HTTP (port 80) returned 200 OK without HTTPS redirect",
                        "source": f"HTTP HEAD probe (http://{host})",
                        "remediation": "Redirect all HTTP traffic to HTTPS (301/308).",
                    }
                )

            if tls_info.get("verified") is False:
                findings.append(
                    {
                        "risk": "CRITICAL",
                        "finding": f"TLS certificate verification failed: {tls_info.get('error', 'untrusted')}",
                        "source": "TLS X.509 Peer Handshake",
                        "remediation": "Install a valid CA-signed certificate matching the domain.",
                    }
                )
            elif isinstance(tls_info.get("days_remaining"), int) and tls_info["days_remaining"] <= 21:
                findings.append(
                    {
                        "risk": "HIGH",
                        "finding": f"TLS certificate expiring soon ({tls_info['days_remaining']} days remaining)",
                        "source": "TLS X.509 Certificate notAfter",
                        "remediation": "Renew SSL/TLS certificate promptly.",
                    }
                )

            missing_headers_map = {
                "strict-transport-security": ("MEDIUM", "HSTS header missing; browsers may allow initial HTTP downgrade."),
                "content-security-policy": ("MEDIUM", "Content-Security-Policy header missing; weaker XSS/injection mitigation."),
                "x-frame-options": ("LOW", "X-Frame-Options missing; clickjacking protection relies solely on CSP frame-ancestors."),
                "x-content-type-options": ("LOW", "X-Content-Type-Options: nosniff missing."),
                "referrer-policy": ("INFO", "Referrer-Policy header not explicitly configured."),
            }
            for hname, (rk, msg) in missing_headers_map.items():
                if not sec_headers_status[hname]["present"]:
                    findings.append({"risk": rk, "finding": msg, "source": "HTTP Response Headers", "remediation": f"Configure {hname}."})

            for w in csp_analysis.get("warnings", []):
                if csp_analysis.get("present"):
                    findings.append({"risk": "LOW", "finding": w, "source": "HTTP Header 'Content-Security-Policy'", "remediation": "Harden CSP directives."})

            for ck in cookies:
                if not ck["secure"] or not ck["httponly"]:
                    findings.append(
                        {
                            "risk": "MEDIUM",
                            "finding": f"Cookie '{ck['name']}' missing flags (Secure={ck['secure']}, HttpOnly={ck['httponly']})",
                            "source": "HTTP Header 'Set-Cookie'",
                            "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict attributes on sensitive cookies.",
                        }
                    )

            if headers.get("server") and re.search(r"\d+\.\d+", headers["server"]):
                findings.append(
                    {
                        "risk": "LOW",
                        "finding": f"Server banner exposes version details: {headers['server']}",
                        "source": "HTTP Header 'Server'",
                        "remediation": "Suppress detailed version tokens in server configuration.",
                    }
                )

            # Optional authorized active header/method check (safe OPTIONS only)
            allowed_methods = ""
            if active_authorized:
                opt_resp = self._single_http_request(final_url, method="OPTIONS", timeout=5.0)
                allowed_methods = opt_resp.get("headers", {}).get("allow", "")
                if "TRACE" in allowed_methods.upper():
                    findings.append(
                        {
                            "risk": "MEDIUM",
                            "finding": "HTTP TRACE method advertised in Allow header",
                            "source": "Authorized OPTIONS Request",
                            "remediation": "Disable HTTP TRACE method on the web server.",
                        }
                    )

        risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        overall_risk = max((f["risk"] for f in findings), key=lambda r: risk_rank.get(r, 0), default="INFO")

        # Link classification summary
        classified_links = {
            "internal_count": len(parser.internal_links),
            "external_count": len(parser.external_links),
            "scripts_count": len(set(parser.scripts)),
            "stylesheets_count": len(set(parser.stylesheets)),
            "images_count": len(set(parser.images)),
            "internal_sample": parser.internal_links[:25],
            "external_sample": parser.external_links[:25],
            "scripts_sample": sorted(set(parser.scripts))[:20],
            "stylesheets_sample": sorted(set(parser.stylesheets))[:20],
            "images_sample": sorted(set(parser.images))[:20],
        }

        result: dict[str, Any] = {
            "target_url": target_url,
            "final_url": final_url,
            "host": host,
            "scan_mode": "AUTHORIZED_PASSIVE_PLUS_OPTIONS" if active_authorized else "PASSIVE_LOW_INTENSITY",
            "http_reachability": {"status": http_probe.get("status"), "error": http_probe.get("error", "")},
            "https_reachability": {"status": https_probe.get("status"), "error": https_probe.get("error", "")},
            "http_status": main_resp.get("status"),
            "redirect_chain": redirect_chain,
            "response_headers": dict(raw_headers),
            "dns": {"A": ipv4_list, "AAAA": ipv6_list, "NS": ns_records, "MX": mx_records, "TXT": txt_records[:10]},
            "tls": tls_info,
            "page_metadata": {
                "title": parser.title,
                "meta_description": parser.meta_description,
                "language": parser.html_lang,
                "forms_count": parser.forms_count,
            },
            "robots_txt": robots_info,
            "sitemap_xml": {"present": sitemap_info.get("present"), "status": sitemap_info.get("status"), "extracted_urls": sitemap_urls[:50]},
            "security_headers": sec_headers_status,
            "csp_analysis": csp_analysis,
            "cookies": cookies,
            "technologies": tech_detected,
            "assets_and_links": classified_links,
            "passive_findings": findings,
            "allowed_methods": allowed_methods,
            "overall_risk": overall_risk,
            "scanned_at": utc_now(),
        }

        self._render_scan_output(result)
        self._save_scan_db(result)
        self.reports.record("WEBSITE_INTEL", f"Website Intelligence: {host}", result, severity=overall_risk)

        if export_fmt:
            self.export_non_html_report(result, fmt=export_fmt)

        return result

    @staticmethod
    def _inspect_tls_quiet(host: str, port: int = 443) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=6) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    return {
                        "verified": True,
                        "tls_version": tls_sock.version(),
                        "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else "-",
                        "subject_cn": subject.get("commonName", "-"),
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "-")),
                        "not_after": not_after.isoformat(),
                        "days_remaining": (not_after - datetime.now(timezone.utc)).days,
                        "sans": [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"][:15],
                    }
        except ssl.SSLCertVerificationError as exc:
            return {"verified": False, "error": str(exc)}
        except Exception as exc:
            return {"verified": None, "error": str(exc)}

    def _render_scan_output(self, res: dict[str, Any]) -> None:
        risk_col = "bold red" if res["overall_risk"] in {"CRITICAL", "HIGH"} else "bold yellow" if res["overall_risk"] == "MEDIUM" else "bold bright_green"
        self.console.print(
            Panel(
                f"[white]Target URL  :[/] [bright_green]{res['final_url']}[/]\n"
                f"[white]HTTP/HTTPS  :[/] HTTP={res['http_reachability']['status'] or 'ERR'} | HTTPS={res['https_reachability']['status'] or 'ERR'} | Final={res['http_status'] or 'ERR'}\n"
                f"[white]Page Title  :[/] {res['page_metadata']['title'] or '-'}  (Lang: {res['page_metadata']['language'] or '-'})\n"
                f"[white]Meta Desc   :[/] {(res['page_metadata']['meta_description'] or '-')[:120]}\n"
                f"[white]DNS A / AAAA:[/] {', '.join(res['dns']['A']) or '-'} | {', '.join(res['dns']['AAAA']) or '-'}\n"
                f"[white]Nameservers :[/] {', '.join(res['dns']['NS'][:4]) or '-'}\n"
                f"[white]TLS / Cert  :[/] {res['tls'].get('tls_version', '-')} | Issuer={res['tls'].get('issuer', '-')} | DaysLeft={res['tls'].get('days_remaining', '-')}\n"
                f"[white]robots/smap :[/] robots.txt={res['robots_txt']['status']} | sitemap.xml={res['sitemap_xml']['status']} ({len(res['sitemap_xml']['extracted_urls'])} URLs)\n"
                f"[white]Assets/Links:[/] Internal={res['assets_and_links']['internal_count']} | External={res['assets_and_links']['external_count']} | JS={res['assets_and_links']['scripts_count']} | CSS={res['assets_and_links']['stylesheets_count']} | IMG={res['assets_and_links']['images_count']}\n"
                f"[white]Overall Risk:[/] [{risk_col}]{res['overall_risk']}[/]  ([grey70]Mode: {res['scan_mode']}[/])",
                title=f"[bold bright_green]WEBSITE INTELLIGENCE // {res['host']}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        if len(res["redirect_chain"]) > 1:
            rtab = Table(title="[bold bright_green]REDIRECT CHAIN[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
            rtab.add_column("Hop", width=5, justify="right", style="grey70")
            rtab.add_column("Status", width=8, style="bright_green")
            rtab.add_column("URL", style="white")
            for idx, hop in enumerate(res["redirect_chain"], start=1):
                rtab.add_row(str(idx), str(hop.get("status") or "ERR"), hop["url"])
            self.console.print(rtab)

        htab = Table(title="[bold bright_green]SECURITY HEADERS & TECHNOLOGIES[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
        htab.add_column("Security Header", style="white", width=28)
        htab.add_column("Status", width=10)
        htab.add_column("Value / Source", style="grey70")
        for hdr, info in res["security_headers"].items():
            st = "[bright_green]SET[/]" if info["present"] else "[yellow]MISSING[/]"
            htab.add_row(hdr, st, (info["value"][:72] + "..." if len(info["value"]) > 72 else info["value"]) or info["source"])
        self.console.print(htab)

        if res["technologies"]:
            ttab = Table(title="[bold bright_green]DETECTED TECHNOLOGIES (WITH SOURCE)[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
            ttab.add_column("Technology", style="bright_green")
            ttab.add_column("Detection Source", style="grey70")
            for t in res["technologies"]:
                ttab.add_row(t["name"], t["source"])
            self.console.print(ttab)

        if res["passive_findings"]:
            ftab = Table(title="[bold bright_green]PASSIVE SECURITY FINDINGS[/]", box=box.SIMPLE_HEAVY, border_style="bright_green")
            ftab.add_column("Risk", width=10)
            ftab.add_column("Finding", style="white")
            ftab.add_column("Source", style="grey70")
            for f in res["passive_findings"]:
                col = "bold red" if f["risk"] in {"CRITICAL", "HIGH"} else "yellow" if f["risk"] == "MEDIUM" else "bright_green"
                ftab.add_row(f"[{col}]{f['risk']}[/]", f["finding"], f["source"])
            self.console.print(ftab)

    def _save_scan_db(self, res: dict[str, Any]) -> None:
        scan_id = f"WEB-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        try:
            with self.db.connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO website_scans (id, url, host, http_status, tls_verified, risk_level, summary_json, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        res["final_url"],
                        res["host"],
                        res.get("http_status") or 0,
                        1 if res.get("tls", {}).get("verified") else 0,
                        res["overall_risk"],
                        json.dumps(res, default=str),
                        res["scanned_at"],
                    ),
                )
        except Exception:
            pass

    def export_non_html_report(self, result: dict[str, Any], fmt: str = "json") -> Path | None:
        """Export Website Intelligence report strictly in non-HTML formats (JSON, TXT, CSV)."""
        ensure_directories()
        fmt_l = fmt.lower().strip()
        if fmt_l not in {"json", "txt", "csv"}:
            self.console.print("[bold red][-][/] Website scan reports support only non-HTML formats: json, txt, csv.")
            return None
        safe_host = "".join(c if c.isalnum() or c in {"-", "_"} else "_" for c in result["host"])
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = REPORTS_DIR / f"website_scan_{safe_host}_{stamp}.{fmt_l}"

        if fmt_l == "json":
            out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        elif fmt_l == "txt":
            lines = [
                f"BLACKVEIL X WEBSITE INTELLIGENCE REPORT: {result['final_url']}",
                "=" * 78,
                f"Host          : {result['host']}",
                f"HTTP Status   : {result.get('http_status')}",
                f"Overall Risk  : {result['overall_risk']}",
                f"Title         : {result['page_metadata']['title']}",
                f"DNS A         : {', '.join(result['dns']['A'])}",
                f"DNS NS        : {', '.join(result['dns']['NS'])}",
                f"TLS Issuer    : {result['tls'].get('issuer', '-')}",
                "",
                "PASSIVE FINDINGS:",
            ]
            for f in result["passive_findings"]:
                lines.append(f"  - [{f['risk']}] {f['finding']} (Source: {f['source']})")
            lines.append("")
            lines.append("TECHNOLOGIES:")
            for t in result["technologies"]:
                lines.append(f"  - {t['name']} (Source: {t['source']})")
            out_path.write_text("\n".join(lines), encoding="utf-8")
        else:
            with out_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["section", "item", "risk_or_status", "source", "details"])
                writer.writerow(["meta", result["final_url"], result["overall_risk"], "HTTP/TLS", f"status={result.get('http_status')}"])
                for hdr, info in result["security_headers"].items():
                    writer.writerow(["security_header", hdr, "SET" if info["present"] else "MISSING", info["source"], info["value"]])
                for t in result["technologies"]:
                    writer.writerow(["technology", t["name"], "DETECTED", t["source"], ""])
                for f in result["passive_findings"]:
                    writer.writerow(["finding", f["finding"], f["risk"], f["source"], f["remediation"]])

        self.console.print(f"[bold bright_green][+][/] Website Intelligence {fmt_l.upper()} report saved: [white]{out_path}[/]")
        return out_path

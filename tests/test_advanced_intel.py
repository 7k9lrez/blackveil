"""Automated unit tests for the 7 BLACKVEIL X Advanced Intelligence modules."""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ai.analyst import AISecurityAnalyst
from core.command_parser import CommandDispatcher
from core.config import ConfigManager, SecretsManager
from core.logger import BlackveilLogger, HistoryManager
from core.session_recorder import SessionRecorder
from database.db import DatabaseManager
from modules.cert_watcher import CertWatcherModule
from modules.computer_search import ComputerSearchModule
from modules.dns_intel import DnsIntelModule
from modules.external_search import ExternalSearchModule
from modules.ip_intel import IpIntelModule
from modules.local_website import LocalWebsiteModule
from modules.network import NetworkModule
from modules.reports import ReportManager
from modules.system_intel import SystemIntelModule
from modules.threat_intel import ThreatIntelModule
from modules.url_detector import UrlDetectorModule
from modules.website_intel import WebsiteIntelModule
from rich.console import Console


class _DemoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
            ctype = "text/plain"
        elif self.path == "/sitemap.xml":
            body = b"<urlset><url><loc>http://127.0.0.1/about.html</loc></url></urlset>"
            ctype = "application/xml"
        elif self.path == "/app.js":
            body = b"console.log('ok');"
            ctype = "application/javascript"
        elif self.path == "/style.css":
            body = b"body { color: #0f0; }"
            ctype = "text/css"
        else:
            body = (
                b"<!doctype html><html lang='en'><head>"
                b"<title>Blackveil Test Target</title>"
                b"<meta name='description' content='Unit test target site'>"
                b"<meta name='generator' content='TestEngine 1.0'>"
                b"<link rel='stylesheet' href='/style.css'>"
                b"<script src='/app.js'></script>"
                b"</head><body>"
                b"<a href='/about.html'>About</a>"
                b"<a href='https://example.org/docs'>External</a>"
                b"</body></html>"
            )
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "UnitTestHTTP/1.2")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Server", "UnitTestHTTP/1.2")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class _LocalTestServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class AdvancedIntelExpansionTests(unittest.TestCase):
    """Tests Website Intel, Local Website Mirror, IP Intel, URL Detector, Gemini Config, Computer Search, External Search & Dispatcher."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = _LocalTestServer(("127.0.0.1", 0), _DemoHandler)
        cls.port = cls.httpd.server_address[1]
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bv_adv_"))
        self.console = Console(quiet=True)
        self.logger = BlackveilLogger()
        self.config = ConfigManager(config_path=self.tmp_dir / "config.json")
        self.secrets = SecretsManager(secrets_path=self.tmp_dir / "secrets.json")
        self.db = DatabaseManager(db_path=self.tmp_dir / "adv_test.db")
        self.reports = ReportManager(self.console, self.logger, self.db)
        self.network = NetworkModule(self.console, self.logger, self.config, self.reports)
        self.sys_intel = SystemIntelModule(self.console, self.logger, self.reports)
        self.dns_intel = DnsIntelModule(self.console, self.logger, self.reports)
        self.cert_watcher = CertWatcherModule(self.console, self.logger, self.reports)
        self.threat_intel = ThreatIntelModule(self.console, self.logger, self.db, self.reports)
        self.ai_analyst = AISecurityAnalyst(self.console, self.logger, self.config, self.db, self.reports, secrets=self.secrets)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_schema_v3_tables_present(self) -> None:
        self.assertGreaterEqual(self.db.get_schema_version(), 3)
        with self.db.connection() as conn:
            tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for tbl in ("website_scans", "local_websites", "ai_chat_history", "file_index", "external_search_history"):
            self.assertIn(tbl, tables)

    def test_02_website_intel_scan_and_non_html_reports(self) -> None:
        scanner = WebsiteIntelModule(self.console, self.logger, self.db, self.reports, self.dns_intel, self.cert_watcher)
        res = scanner.scan(f"http://127.0.0.1:{self.port}/")
        self.assertEqual(res["http_status"], 200)
        self.assertEqual(res["page_metadata"]["title"], "Blackveil Test Target")
        self.assertEqual(res["page_metadata"]["language"], "en")
        self.assertTrue(res["robots_txt"]["present"])
        self.assertGreaterEqual(res["assets_and_links"]["scripts_count"], 1)
        self.assertGreaterEqual(res["assets_and_links"]["stylesheets_count"], 1)
        self.assertGreaterEqual(res["assets_and_links"]["external_count"], 1)
        self.assertTrue(any(c["name"] == "sessionid" and not c["httponly"] for c in res["cookies"]))
        self.assertTrue(any("TestEngine" in t["name"] for t in res["technologies"]))

        for fmt in ("json", "txt", "csv"):
            out = scanner.export_non_html_report(res, fmt=fmt)
            self.assertIsNotNone(out)
            assert out is not None
            self.assertTrue(out.exists())
            out.unlink(missing_ok=True)
        self.assertIsNone(scanner.export_non_html_report(res, fmt="html"))

    def test_03_local_website_environment_lifecycle(self) -> None:
        local_env = LocalWebsiteModule(self.console, self.logger, self.config, self.db, self.reports)
        info = local_env.create_local_environment(f"http://127.0.0.1:{self.port}/", max_pages=10)
        self.assertGreaterEqual(info["files_count"], 3)
        self.assertTrue(info["port"] > 0)
        status_list = local_env.status()
        self.assertEqual(len(status_list), 1)
        insp = local_env.inspect("127.0.0.1")
        self.assertIn("MATCHES_LIVE", insp["live_diff"])
        stopped = local_env.stop("127.0.0.1")
        self.assertEqual(stopped, 1)

    def test_04_ip_intel_and_access_log_parser(self) -> None:
        ip_mod = IpIntelModule(self.console, self.logger, self.network, self.reports)
        loop_res = ip_mod.ipinfo("127.0.0.1", quiet=True)
        self.assertEqual(loop_res["scope"], "LOOPBACK")

        log_file = self.tmp_dir / "access.log"
        log_file.write_text(
            '203.0.113.10 - - [14/Nov/2026:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024\n'
            '203.0.113.10 - - [14/Nov/2026:08:01:00 +0000] "POST /login HTTP/1.1" 401 312\n'
            '198.51.100.22 - - [14/Nov/2026:08:02:00 +0000] "GET /robots.txt HTTP/1.1" 200 80\n',
            encoding="utf-8",
        )
        log_res = ip_mod.analyze_access_logs(str(log_file))
        self.assertEqual(log_res["unique_ips"], 2)
        self.assertEqual(log_res["top_ips"][0]["ip"], "203.0.113.10")
        self.assertEqual(log_res["top_ips"][0]["requests"], 2)

    def test_05_url_detector_heuristics_and_missing_keys(self) -> None:
        detector = UrlDetectorModule(self.console, self.logger, self.config, self.secrets, self.threat_intel, self.reports)
        bad_url = "http://paypal.login-verify.xn--p1ai/update/payload.exe"
        res = detector.analyze(bad_url, mode="check")
        self.assertEqual(res["verdict"], "DANGEROUS")
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(any("Google Safe Browsing" in s for s in res["checks_skipped"]))

        unknown_url = "https://nonexistent.invalid.blackveil-test-domain.example"
        res2 = detector.analyze(unknown_url, mode="reputation")
        self.assertEqual(res2["verdict"], "UNKNOWN")

    def test_06_gemini_config_secret_isolation_and_masking(self) -> None:
        old_env = os.environ.pop("GEMINI_API_KEY", None)
        try:
            self.ai_analyst.configure(api_key="AIzaSySecretUnitKey1234567890", model="gemini-4-argon")
            self.assertNotIn("AIzaSySecretUnitKey1234567890", json.dumps(self.config.data))
            self.assertEqual(self.ai_analyst.get_api_key(), "AIzaSySecretUnitKey1234567890")
            masked = SessionRecorder.mask_sensitive("ai config --api-key AIzaSySecretUnitKey1234567890")
            self.assertNotIn("AIzaSySecretUnitKey1234567890", masked)
            self.ai_analyst.configure(clear_key=True)
            self.assertEqual(self.ai_analyst.get_api_key(), "")
        finally:
            if old_env is not None:
                os.environ["GEMINI_API_KEY"] = old_env

    def test_07_computer_search_index_content_and_duplicates(self) -> None:
        ws = self.tmp_dir / "search_root"
        ws.mkdir()
        (ws / "alpha.py").write_text("SECRET_NEEDLE = 'hello_blackveil'\n", encoding="utf-8")
        (ws / "dup1.txt").write_text("identical duplicate payload 12345", encoding="utf-8")
        (ws / "dup2.txt").write_text("identical duplicate payload 12345", encoding="utf-8")

        csearch = ComputerSearchModule(self.console, self.logger, self.config, self.db, self.sys_intel, self.reports)
        idx_res = csearch.build_or_update_index(str(ws))
        self.assertEqual(idx_res["indexed_count"], 3)

        name_hits = csearch.search(query="alpha", root_dir=str(ws), use_index=True)
        self.assertEqual(name_hits["total_matches"], 1)

        content_hits = csearch.search(query="hello_blackveil", root_dir=str(ws), search_content=True, extensions=[".py"])
        self.assertEqual(content_hits["total_matches"], 1)

        dups = csearch.search(query="", root_dir=str(ws), find_duplicates=True)
        self.assertEqual(len(dups["duplicate_groups"]), 1)

    def test_08_external_search_dedup_and_opera_detection(self) -> None:
        ext = ExternalSearchModule(self.console, self.logger, self.config, self.secrets, self.db, self.ai_analyst, self.reports)
        ranked = ext._dedup_and_rank(
            "openssl tls",
            [
                {"title": "OpenSSL Docs", "url": "https://openssl.org/docs/", "snippet": "TLS reference", "source": "Wikipedia", "date": "-"},
                {"title": "Duplicate", "url": "https://openssl.org/docs", "snippet": "dup", "source": "GitHub", "date": "-"},
                {"title": "Unrelated", "url": "https://example.com/other", "snippet": "nothing here", "source": "DuckDuckGo API", "date": "-"},
            ],
        )
        self.assertEqual(len(ranked), 2)
        self.assertEqual(ranked[0]["url"], "https://openssl.org/docs/")
        opera = ext.detect_opera_browser()
        self.assertIn("installed", opera)

    def test_09_dispatcher_routes_new_commands_with_masked_history(self) -> None:
        history = HistoryManager(history_file=self.tmp_dir / "history.json")
        disp = CommandDispatcher(self.console, self.config, self.logger, history, db=self.db)
        disp.secrets = self.secrets
        disp.ai_analyst.secrets = self.secrets

        rc1 = disp.execute_line("ai config --api-key DummySecretKey987654321")
        self.assertEqual(rc1, 0)
        self.assertFalse(any("DummySecretKey987654321" in e["command"] for e in history.entries))
        disp.ai_analyst.configure(clear_key=True)

        rc2 = disp.execute_line(f"website scan http://127.0.0.1:{self.port}/")
        self.assertEqual(rc2, 0)
        rc3 = disp.execute_line("ipinfo 127.0.0.1")
        self.assertEqual(rc3, 0)
        rc4 = disp.execute_line("url check http://evil.example.zip/drop.exe")
        self.assertEqual(rc4, 0)


if __name__ == "__main__":
    unittest.main()

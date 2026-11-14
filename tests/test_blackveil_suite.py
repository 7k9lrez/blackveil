"""Comprehensive automated unit & security policy tests for BLACKVEIL X."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.config import ConfigManager
from core.logger import BlackveilLogger
from core.session_recorder import SessionRecorder
from database.db import DatabaseManager
from labs.ctf_engine import CTFEngineModule
from labs.red_blue import RedBlueTeamModule
from labs.vuln_lab import VulnLabModule
from missions.manager import MissionManager
from modules.deps_guard import DependencyGuardModule
from modules.evidence_vault import EvidenceVaultModule
from modules.forensics import ForensicsModule
from modules.incident_engine import IncidentResponseModule
from modules.integrity_guard import FileIntegrityGuard
from modules.knowledge_base import KnowledgeBaseModule
from modules.log_intel import LogIntelligenceModule
from modules.pcap_analyzer import PcapAnalyzerModule
from modules.secret_scanner import SecretScannerModule
from modules.threat_intel import ThreatIntelModule
from plugins.engine import PluginEngineModule
from reports.engine import AdvancedReportEngine
from rich.console import Console
from sandbox.manager import SandboxManager


class BlackveilEcosystemTestSuite(unittest.TestCase):
    """Validates database migrations, sandbox hardening, all 20 subsystems, and security controls."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bv_test_"))
        self.console = Console(quiet=True)
        self.logger = BlackveilLogger()
        self.config = ConfigManager(config_path=self.tmp_dir / "config.json")
        self.db = DatabaseManager(db_path=self.tmp_dir / "test_blackveil.db")
        self.reports = AdvancedReportEngine(self.console, self.logger, self.db)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_database_migrations_and_profile(self) -> None:
        self.assertGreaterEqual(self.db.get_schema_version(), 2)
        with self.db.connection() as conn:
            tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for expected in (
            "sandboxes",
            "sandbox_snapshots",
            "missions_progress",
            "operator_profile",
            "achievements",
            "incidents",
            "evidence_vault",
            "plugins_registry",
            "automation_playbooks",
            "knowledge_base",
        ):
            self.assertIn(expected, tables)

    def test_02_sandbox_hardened_flags_enforced(self) -> None:
        args = SandboxManager.build_hardened_create_args(
            container_name="bv_testlab",
            image="alpine:latest",
            cpus="0.5",
            memory="256m",
            pids_limit=64,
            network_mode="none",
        )
        self.assertNotIn("--privileged", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges:true", args)
        self.assertIn("--network=none", args)
        self.assertFalse(any("docker.sock" in a or ":/" in a for a in args))

    def test_03_session_recorder_masks_secrets(self) -> None:
        masked = SessionRecorder.mask_sensitive(
            "password --check SuperSecret99! Bearer eyJhbGciOiJIUzI1NiJ9 AIzaSyDummyKey12345678901234567890"
        )
        self.assertNotIn("SuperSecret99!", masked)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", masked)
        self.assertNotIn("AIzaSyDummyKey", masked)
        self.assertIn("MASKED", masked)

    def test_04_advanced_report_engine_all_formats(self) -> None:
        self.reports.record("TEST_CAT", "Test Finding", {"ok": True, "count": 3}, severity="HIGH")
        for fmt in ("json", "txt", "csv", "pdf"):
            out = self.reports.export_report(export_format=fmt, export_all=False, custom_name=f"unit_test_{fmt}")
            self.assertIsNotNone(out)
            assert out is not None
            self.assertTrue(out.exists())
            if fmt == "pdf":
                self.assertTrue(out.read_bytes().startswith(b"%PDF-1.4"))
            out.unlink(missing_ok=True)

    def test_05_secret_scanner_masks_findings(self) -> None:
        sample = self.tmp_dir / "leak.env"
        sample.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASS=MyVerySecretPass123\n", encoding="utf-8")
        scanner = SecretScannerModule(self.console, self.logger, self.reports)
        findings = scanner.scan(str(sample))
        self.assertGreaterEqual(len(findings), 2)
        for f in findings:
            self.assertNotIn("MyVerySecretPass123", f["masked_preview"])
            self.assertIn("****", f["masked_preview"])

    def test_06_integrity_guard_detects_tampering(self) -> None:
        target_dir = self.tmp_dir / "watched"
        target_dir.mkdir()
        f1 = target_dir / "app.conf"
        f1.write_text("mode=secure\n", encoding="utf-8")

        guard = FileIntegrityGuard(self.console, self.logger, self.db, self.reports)
        guard.create_baseline(str(target_dir), baseline_name="unit_base")
        clean_scan = guard.scan_against_baseline("unit_base")
        self.assertEqual(clean_scan["modified"], [])

        f1.write_text("mode=tampered\n", encoding="utf-8")
        diff_scan = guard.scan_against_baseline("unit_base")
        self.assertEqual(len(diff_scan["modified"]), 1)

    def test_07_pcap_analyzer_parses_real_binary_pcap(self) -> None:
        # Build a valid synthetic little-endian libpcap capture with 1 Ethernet+IPv4+TCP packet
        eth = b"\xff" * 6 + b"\x00" * 6 + struct.pack("!H", 0x0800)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01")
        tcp_hdr = struct.pack("!HHIIHHHH", 54321, 80, 1, 0, (5 << 12) | 0x02, 8192, 0, 0)
        frame = eth + ip_hdr + tcp_hdr
        global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pkt_hdr = struct.pack("<IIII", 1700000000, 0, len(frame), len(frame))
        pcap_file = self.tmp_dir / "test.pcap"
        pcap_file.write_bytes(global_hdr + pkt_hdr + frame)

        analyzer = PcapAnalyzerModule(self.console, self.logger, self.reports)
        summary = analyzer.summary(str(pcap_file))
        self.assertEqual(summary["packet_count"], 1)
        self.assertEqual(summary["protocols"].get("HTTP"), 1)

    def test_08_plugin_engine_blocks_unsafe_or_unsigned_plugins(self) -> None:
        engine = PluginEngineModule(self.console, self.logger, self.db)
        bad_dir = self.tmp_dir / "evil_plugin"
        bad_dir.mkdir()
        bad_py = bad_dir / "plugin.py"
        bad_py.write_text("import subprocess\ndef run(c, a):\n    eval('1+1')\n", encoding="utf-8")
        (bad_dir / "manifest.json").write_text(
            json.dumps({"name": "evil", "sha256": hashlib.sha256(bad_py.read_bytes()).hexdigest(), "permissions": []}),
            encoding="utf-8",
        )
        self.assertFalse(engine.install_plugin(str(bad_dir), assume_yes=True))

        # Unsigned plugin must also fail
        unsigned_dir = self.tmp_dir / "unsigned"
        unsigned_dir.mkdir()
        (unsigned_dir / "plugin.py").write_text("def run(c, a):\n    return 0\n", encoding="utf-8")
        (unsigned_dir / "manifest.json").write_text(json.dumps({"name": "unsigned", "sha256": "deadbeef"}), encoding="utf-8")
        self.assertFalse(engine.install_plugin(str(unsigned_dir), assume_yes=True))

    def test_09_missions_ctf_and_red_blue_flow(self) -> None:
        missions = MissionManager(self.console, self.logger, self.db)
        self.assertTrue(missions.submit_mission("MIS-INT-01", "letmein123"))
        prof = missions.show_profile()
        self.assertGreaterEqual(prof["xp"], 200)

        ctf = CTFEngineModule(self.console, self.logger, self.db, missions)
        artifact = ctf.start_challenge("CTF-01")
        self.assertIsNotNone(artifact)
        self.assertTrue(ctf.submit("CTF-01", "BV{DECODED_PAYLOAD_101}"))

        forensics = ForensicsModule(self.console, self.logger, self.reports)
        rb = RedBlueTeamModule(self.console, self.logger, self.db, self.reports, forensics)
        rb.redteam_start()
        blue = rb.blueteam_start()
        self.assertEqual(blue["score"], 100)
        rb.reset()

    def test_10_incidents_kb_threat_vuln_deps(self) -> None:
        inc = IncidentResponseModule(self.console, self.logger, self.db, self.reports)
        inc_id = inc.create("Unit Test Incident", severity="HIGH")
        self.assertTrue(inc.investigate(inc_id, "Verified artifact"))
        self.assertTrue(inc.close(inc_id, "Resolved"))

        kb = KnowledgeBaseModule(self.console, self.logger, self.db)
        self.assertGreaterEqual(len(kb.search("Shannon")), 1)

        ti = ThreatIntelModule(self.console, self.logger, self.db, self.reports)
        res = ti.lookup("198.51.100.44")
        self.assertGreaterEqual(res["risk_score"], 75)

        vuln = VulnLabModule(self.console, self.logger, self.db, self.reports)
        ws = vuln.install("VULN-01")
        self.assertIsNotNone(ws)
        vuln.reset("VULN-01")

        deps = DependencyGuardModule(self.console, self.logger, self.reports)
        self.assertIsInstance(deps.audit(online=False), list)

        ev = EvidenceVaultModule(self.console, self.logger, self.db, self.reports)
        art = self.tmp_dir / "evidence_sample.txt"
        art.write_text("forensic sample", encoding="utf-8")
        rec = ev.add_evidence(str(art))
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertTrue(ev.verify_evidence(rec["id"]))

        li = LogIntelligenceModule(self.console, self.logger, self.db, self.reports)
        log_f = self.tmp_dir / "test.log"
        log_f.write_text("2026-11-14 01:00:00 WARN sshd: Failed password for root from 203.0.113.1\n", encoding="utf-8")
        log_res = li.analyze(str(log_f))
        self.assertGreaterEqual(len(log_res["hits"]), 1)


if __name__ == "__main__":
    unittest.main()

"""Digital Forensics, Hashing, PE/Metadata & File Integrity module for BLACKVEIL."""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
import struct
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.config import BASELINE_FILE, DATA_DIR, ensure_directories
from core.logger import BlackveilLogger
from modules.reports import ReportManager
from modules.system_intel import format_bytes


class ForensicsModule:
    """Real file hashing, magic-byte signature validation, PE metadata, entropy, and integrity verification."""

    SUSPICIOUS_API_INDICATORS = [
        b"VirtualAlloc",
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"NtUnmapViewOfSection",
        b"SetWindowsHookEx",
        b"ShellExecute",
        b"WinExec",
        b"URLDownloadToFile",
        b"IsDebuggerPresent",
        b"RegSetValueEx",
        b"CryptEncrypt",
        b"Invoke-Expression",
        b"FromBase64String",
        b"powershell",
    ]

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> list[dict[str, Any]]:
        sig_file = DATA_DIR / "file_signatures.json"
        if not sig_file.exists():
            return []
        try:
            data = json.loads(sig_file.read_text(encoding="utf-8"))
            return data.get("signatures", [])
        except (OSError, json.JSONDecodeError):
            return []

    def compute_file_hashes(self, file_path: Path, show_progress: bool = True) -> dict[str, str]:
        """Compute MD5, SHA1, SHA256, and SHA512 using chunked streaming."""
        total_size = file_path.stat().st_size
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        chunk_size = 1024 * 256
        if show_progress and total_size > 0:
            with Progress(
                SpinnerColumn(style="bright_green"),
                TextColumn("[bright_green]{task.description}"),
                BarColumn(bar_width=30, complete_style="bright_green", finished_style="green"),
                TextColumn("[white]{task.percentage:>3.0f}%"),
                console=self.console,
            ) as progress:
                task = progress.add_task(f"Hashing {file_path.name}", total=total_size)
                with file_path.open("rb") as fh:
                    while True:
                        chunk = fh.read(chunk_size)
                        if not chunk:
                            break
                        md5.update(chunk)
                        sha1.update(chunk)
                        sha256.update(chunk)
                        sha512.update(chunk)
                        progress.advance(task, len(chunk))
        else:
            with file_path.open("rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
        }

    def hash_file_command(self, target_path: str, expected_hash: str | None = None) -> dict[str, Any]:
        """Calculate and display cryptographic hashes for a target file, optionally verifying against expected hash."""
        path = Path(target_path).expanduser()
        if not path.exists() or not path.is_file():
            self.console.print(f"[bold red][-][/] File not found: {path}")
            return {}

        try:
            hashes = self.compute_file_hashes(path)
        except PermissionError:
            self.console.print(f"[bold red][-][/] Permission denied reading file: {path}")
            return {}
        except OSError as exc:
            self.console.print(f"[bold red][-][/] I/O error hashing file: {exc}")
            return {}

        size_bytes = path.stat().st_size
        table = Table(
            title=f"[bold bright_green]CRYPTOGRAPHIC HASH // {path.name}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        table.add_column("Algorithm", style="grey70", width=12)
        table.add_column("Digest", style="bright_green")

        table.add_row("File", f"[white]{path.resolve()}[/] ({format_bytes(size_bytes)})")
        table.add_row("MD5", hashes["md5"])
        table.add_row("SHA-1", hashes["sha1"])
        table.add_row("SHA-256", hashes["sha256"])
        table.add_row("SHA-512", hashes["sha512"])

        verified: bool | None = None
        if expected_hash:
            norm = expected_hash.strip().lower()
            matched_algo = next((k for k, v in hashes.items() if v.lower() == norm), None)
            verified = matched_algo is not None
            if verified:
                table.add_row("Integrity", f"[bold bright_green]MATCHED ({matched_algo.upper()})[/]")
            else:
                table.add_row("Integrity", "[bold red]MISMATCH - DIGEST DOES NOT MATCH EXPECTED VALUE[/]")

        self.console.print(table)
        result = {"file": str(path.resolve()), "size_bytes": size_bytes, "hashes": hashes, "verified": verified}
        self.reports.record("HASH_ANALYSIS", f"Cryptographic Hash: {path.name}", result)
        return result

    def hash_text_command(self, text: str) -> dict[str, Any]:
        """Compute hashes of a literal string."""
        raw = text.encode("utf-8")
        hashes = {
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "sha512": hashlib.sha512(raw).hexdigest(),
        }
        table = Table(
            title="[bold bright_green]STRING HASH DIGESTS[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        table.add_column("Algorithm", style="grey70", width=12)
        table.add_column("Digest", style="bright_green")
        for algo, digest in hashes.items():
            table.add_row(algo.upper(), digest)
        self.console.print(table)
        return hashes

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Compute Shannon entropy (0.0 to 8.0 bits/byte)."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def detect_magic_type(self, header: bytes) -> dict[str, Any]:
        """Match file magic bytes against known signatures."""
        for sig in self.signatures:
            offset = int(sig.get("offset", 0))
            magic_bytes = bytes.fromhex(sig["hex"])
            if len(header) >= offset + len(magic_bytes):
                if header[offset : offset + len(magic_bytes)] == magic_bytes:
                    return {
                        "matched": True,
                        "type_name": sig["name"],
                        "expected_extensions": sig.get("extensions", []),
                    }

        # Fallback heuristic for UTF-8/ASCII text scripts
        if header:
            printable = sum(1 for b in header[:512] if 32 <= b <= 126 or b in (9, 10, 13))
            if printable / max(1, len(header[:512])) > 0.90:
                return {
                    "matched": True,
                    "type_name": "Plain Text / Script / Source Code",
                    "expected_extensions": [".txt", ".py", ".ps1", ".bat", ".sh", ".json", ".xml", ".csv", ".log", ".md", ".ini", ".cfg"],
                }

        return {"matched": False, "type_name": "Unknown Binary / Raw Data", "expected_extensions": []}

    @staticmethod
    def _parse_pe_metadata(raw: bytes) -> dict[str, Any] | None:
        """Parse basic Windows PE/COFF headers safely without external dependencies."""
        if len(raw) < 64 or raw[:2] != b"MZ":
            return None
        try:
            pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
            if pe_offset + 24 > len(raw) or raw[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return None
            machine, num_sections, ts, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", raw, pe_offset + 4)
            machine_map = {0x014C: "x86 (32-bit)", 0x8664: "x64 (AMD64)", 0xAA64: "ARM64"}
            compile_time = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC") if ts > 0 else "0 / Stripped"
            is_dll = bool(characteristics & 0x2000)

            sections: list[str] = []
            sec_table_offset = pe_offset + 24 + opt_size
            for i in range(min(num_sections, 16)):
                off = sec_table_offset + i * 40
                if off + 40 <= len(raw):
                    sec_name = raw[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                    sections.append(sec_name)

            return {
                "architecture": machine_map.get(machine, f"0x{machine:04X}"),
                "is_dll": is_dll,
                "section_count": num_sections,
                "sections": sections,
                "compile_timestamp": compile_time,
            }
        except struct.error:
            return None

    def _scan_indicators(self, raw_sample: bytes) -> dict[str, Any]:
        """Extract URLs, IPv4 addresses, and suspicious API/script indicators from binary/text sample."""
        api_hits: list[str] = []
        for marker in self.SUSPICIOUS_API_INDICATORS:
            if marker.lower() in raw_sample.lower():
                api_hits.append(marker.decode("ascii", errors="ignore"))

        urls = sorted(set(re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,80}", raw_sample)))
        ips = sorted(set(re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_sample)))
        return {
            "suspicious_markers": api_hits,
            "embedded_urls": [u.decode("ascii", errors="replace") for u in urls[:10]],
            "embedded_ips": [ip.decode("ascii", errors="replace") for ip in ips[:10]],
        }

    def _load_baselines(self) -> dict[str, Any]:
        ensure_directories()
        if not BASELINE_FILE.exists():
            return {}
        try:
            data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_baselines(self, baselines: dict[str, Any]) -> None:
        ensure_directories()
        BASELINE_FILE.write_text(json.dumps(baselines, indent=2, ensure_ascii=False), encoding="utf-8")

    def analyze_file(
        self,
        target_path: str,
        save_baseline: bool = False,
        verify_baseline: bool = False,
        export_fmt: str | None = None,
    ) -> dict[str, Any]:
        """Run comprehensive digital forensic analysis on a local file."""
        path = Path(target_path).expanduser()
        if not path.exists() or not path.is_file():
            self.console.print(f"[bold red][-][/] Target file not found: {path}")
            return {}

        resolved = str(path.resolve())
        st = path.stat()
        ext = path.suffix.lower()

        hashes = self.compute_file_hashes(path, show_progress=True)
        with path.open("rb") as fh:
            # Read up to 4 MB for entropy, header, PE, and string IOC inspection
            sample = fh.read(4 * 1024 * 1024)

        entropy = self.calculate_entropy(sample)
        magic = self.detect_magic_type(sample[:1024])
        pe_meta = self._parse_pe_metadata(sample)
        indicators = self._scan_indicators(sample)

        extension_mismatch = False
        if magic["matched"] and magic["expected_extensions"]:
            if ext not in magic["expected_extensions"]:
                extension_mismatch = True

        risk_notes: list[str] = []
        if extension_mismatch:
            risk_notes.append(f"Extension mismatch: '{ext or '(none)'}' vs detected '{magic['type_name']}'")
        if entropy >= 7.2:
            risk_notes.append(f"High Shannon entropy ({entropy:.2f}/8.0) - possible packing, compression, or encryption")
        if len(indicators["suspicious_markers"]) >= 3:
            risk_notes.append(f"Multiple sensitive API/script indicators ({len(indicators['suspicious_markers'])} matched)")
        if pe_meta and any(s.lower() in {".upx", "upx0", "upx1", ".aspack"} for s in pe_meta["sections"]):
            risk_notes.append("Packer section signature detected in PE header")

        # Integrity baseline handling
        baselines = self._load_baselines()
        integrity_status = "Not checked (use --save-baseline or --verify-baseline)"
        if save_baseline:
            baselines[resolved] = {
                "sha256": hashes["sha256"],
                "sha512": hashes["sha512"],
                "size": st.st_size,
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save_baselines(baselines)
            integrity_status = "BASELINE SAVED"
        elif verify_baseline or resolved in baselines:
            base = baselines.get(resolved)
            if not base:
                integrity_status = "NO BASELINE RECORDED FOR THIS FILE"
            elif base["sha256"] == hashes["sha256"]:
                integrity_status = f"INTACT (Matches baseline from {base['saved_at']})"
            else:
                integrity_status = f"MODIFIED / TAMPERED (Baseline SHA256 mismatch from {base['saved_at']})"
                risk_notes.append("File integrity baseline mismatch detected!")

        meta_table = Table(
            title=f"[bold bright_green]DIGITAL FORENSICS // {path.name}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        meta_table.add_column("Field", style="grey70", width=22)
        meta_table.add_column("Analysis", style="white")

        meta_table.add_row("Full Path", resolved)
        meta_table.add_row("File Size", f"{format_bytes(st.st_size)} ({st.st_size:,} bytes)")
        meta_table.add_row("Declared Extension", ext or "(none)")
        mismatch_tag = " [bold red][MISMATCH][/]" if extension_mismatch else " [bright_green][CONSISTENT][/]"
        meta_table.add_row("True Signature Type", f"[bright_green]{magic['type_name']}[/]{mismatch_tag}")
        ent_color = "bold red" if entropy >= 7.2 else "yellow" if entropy >= 6.4 else "bright_green"
        meta_table.add_row("Shannon Entropy", f"[{ent_color}]{entropy:.4f} / 8.0000 bits/byte[/]")
        meta_table.add_row("Permissions Mode", stat.filemode(st.st_mode))
        meta_table.add_row("Created", datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S"))
        meta_table.add_row("Modified", datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
        meta_table.add_row("Accessed", datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S"))
        meta_table.add_row("SHA-256", f"[bright_green]{hashes['sha256']}[/]")
        meta_table.add_row("SHA-512", f"[grey70]{hashes['sha512'][:64]}...[/]")
        meta_table.add_row("Integrity Baseline", integrity_status)

        if pe_meta:
            meta_table.add_row(
                "PE Header Info",
                f"{pe_meta['architecture']} | DLL={pe_meta['is_dll']} | Compiled: {pe_meta['compile_timestamp']} | Sections: {', '.join(pe_meta['sections'])}",
            )

        self.console.print(meta_table)

        if indicators["suspicious_markers"] or indicators["embedded_urls"] or indicators["embedded_ips"]:
            ioc_lines = []
            if indicators["suspicious_markers"]:
                ioc_lines.append(f"[yellow]API/Script Markers:[/] {', '.join(indicators['suspicious_markers'])}")
            if indicators["embedded_urls"]:
                ioc_lines.append(f"[grey70]Embedded URLs:[/] {', '.join(indicators['embedded_urls'])}")
            if indicators["embedded_ips"]:
                ioc_lines.append(f"[grey70]Embedded IPs:[/] {', '.join(indicators['embedded_ips'])}")
            self.console.print(
                Panel(
                    "\n".join(ioc_lines),
                    title="[bold yellow]EXTRACTED STRING INDICATORS[/]",
                    border_style="yellow",
                    box=box.SQUARE,
                )
            )

        if risk_notes:
            self.console.print(
                Panel(
                    "\n".join(f"[bold red][!][/] {note}" for note in risk_notes),
                    title="[bold red]FORENSIC ANOMALY ALERTS[/]",
                    border_style="red",
                    box=box.SQUARE,
                )
            )
        else:
            self.console.print("[bold bright_green][+][/] No structural tampering or high-risk forensic anomalies flagged.")

        report_data = {
            "file": resolved,
            "size_bytes": st.st_size,
            "extension": ext,
            "detected_type": magic["type_name"],
            "extension_mismatch": extension_mismatch,
            "entropy": entropy,
            "hashes": hashes,
            "timestamps": {
                "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
            },
            "pe_metadata": pe_meta,
            "indicators": indicators,
            "integrity_status": integrity_status,
            "risk_notes": risk_notes,
        }
        self.reports.record(
            "DIGITAL_FORENSICS",
            f"Forensic Analysis: {path.name}",
            report_data,
            severity="HIGH" if risk_notes else "INFO",
        )

        if export_fmt:
            self.reports.export_report(export_format=export_fmt, export_all=False)

        return report_data

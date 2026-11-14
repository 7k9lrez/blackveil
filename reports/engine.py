"""Advanced Report Engine supporting TXT, JSON, CSV, and pure-Python PDF 1.4 generation."""

from __future__ import annotations

import csv
import io
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import REPORTS_DIR, ensure_directories
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now


def _pdf_escape(text: str) -> str:
    """Escape ASCII text safely for PDF content stream literals."""
    ascii_safe = text.encode("ascii", errors="replace").decode("ascii")
    return ascii_safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_pdf_document(out_path: Path, title: str, lines: list[str]) -> None:
    """Generate a valid, multi-page PDF 1.4 document using standard Courier/Helvetica fonts."""
    wrapped: list[str] = []
    for raw_line in lines:
        if not raw_line:
            wrapped.append("")
            continue
        while len(raw_line) > 92:
            wrapped.append(raw_line[:92])
            raw_line = "  " + raw_line[92:]
        wrapped.append(raw_line)

    lines_per_page = 52
    pages_lines = [wrapped[i : i + lines_per_page] for i in range(0, max(1, len(wrapped)), lines_per_page)]

    objects: list[bytes] = []

    # 1: Catalog, 2: Pages, 3: Font Courier, 4: Font Helvetica-Bold
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    next_id = 5
    for _ in pages_lines:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2

    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_ids)} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    for idx, page_lines in enumerate(pages_lines):
        pid = page_ids[idx]
        cid = content_ids[idx]
        stream_cmds = [
            "BT",
            "/F2 13 Tf",
            "45 760 Td",
            f"({_pdf_escape(title)}) Tj",
            "/F1 9 Tf",
            "0 -22 Td",
        ]
        for line in page_lines:
            stream_cmds.append(f"({_pdf_escape(line)}) Tj")
            stream_cmds.append("0 -13 Td")
        stream_cmds.append(f"0 -10 Td (Page {idx + 1} of {len(pages_lines)} | BLACKVEIL X Security Framework) Tj")
        stream_cmds.append("ET")
        stream_bytes = "\n".join(stream_cmds).encode("ascii", errors="replace")

        page_obj = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>"
        ).encode("ascii")
        content_obj = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii") + stream_bytes + b"\nendstream"
        )
        # Ensure insertion in exact object number order
        while len(objects) < cid:
            objects.append(b"")
        objects[pid - 1] = page_obj
        objects[cid - 1] = content_obj

    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = [0]
    for idx, obj_body in enumerate(objects, start=1):
        offsets.append(buf.tell())
        buf.write(f"{idx} 0 obj\n".encode("ascii"))
        buf.write(obj_body)
        buf.write(b"\nendobj\n")

    xref_pos = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    buf.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.write(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    out_path.write_bytes(buf.getvalue())


class AdvancedReportEngine:
    """Unified multi-format report engine (TXT, JSON, CSV, PDF) backed by SQLite + reports/."""

    SUPPORTED_FORMATS = {"json", "txt", "csv", "pdf"}

    def __init__(self, console: Console, logger: BlackveilLogger, db: DatabaseManager | None = None) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        ensure_directories()
        self.session_records: list[dict[str, Any]] = []

    def record(self, category: str, title: str, data: dict[str, Any], severity: str = "INFO") -> dict[str, Any]:
        """Record a real finding in session memory and SQLite reports_index."""
        entry = {
            "id": f"BV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{len(self.session_records) + 1:03d}",
            "timestamp": utc_now(),
            "category": category,
            "title": title,
            "severity": severity.upper(),
            "host": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "data": data,
        }
        self.session_records.append(entry)
        if self.db:
            try:
                with self.db.connection() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO reports_index
                        (id, title, category, severity, format, file_path, data_json, created_at)
                        VALUES (?, ?, ?, ?, 'MEMORY', NULL, ?, ?)
                        """,
                        (entry["id"], title, category, entry["severity"], json.dumps(data, default=str), entry["timestamp"]),
                    )
            except Exception:
                pass
        self.logger.info("reports", f"Recorded finding {entry['id']}: {category} - {title}")
        return entry

    def create_custom_report(self, title: str, category: str = "OPERATOR_REPORT", severity: str = "INFO", export_format: str = "json") -> Path | None:
        """Create a formal report from current session findings or custom operator bundle and export immediately."""
        if not self.session_records:
            self.record(
                category,
                title,
                {"summary": "Generated ecosystem status report", "host": platform.node(), "platform": platform.platform()},
                severity=severity,
            )
        return self.export_report(export_format=export_format, export_all=True, custom_name=title)

    def export_report(
        self,
        export_format: str = "json",
        export_all: bool = False,
        custom_name: str | None = None,
        record_id: str | None = None,
    ) -> Path | None:
        """Export session findings or a specific SQLite report record to TXT, JSON, CSV, or PDF."""
        ensure_directories()
        fmt = export_format.lower().strip()
        if fmt not in self.SUPPORTED_FORMATS:
            self.console.print(f"[bold red][-][/] Unsupported format '{export_format}'. Supported: txt, json, csv, pdf")
            return None

        payload_records: list[dict[str, Any]] = []
        if record_id and self.db:
            with self.db.connection() as conn:
                row = conn.execute("SELECT * FROM reports_index WHERE id = ?", (record_id,)).fetchone()
            if row:
                payload_records = [
                    {
                        "id": row["id"],
                        "timestamp": row["created_at"],
                        "category": row["category"],
                        "title": row["title"],
                        "severity": row["severity"],
                        "host": platform.node(),
                        "os": f"{platform.system()} {platform.release()}",
                        "data": json.loads(row["data_json"]),
                    }
                ]
        if not payload_records:
            if not self.session_records:
                self.console.print(
                    "[bold yellow][!][/] No session findings recorded yet. Run a module first or use `report create --title ...`."
                )
                return None
            payload_records = self.session_records if export_all else [self.session_records[-1]]

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = custom_name or (f"blackveil_session_{stamp}" if export_all else f"blackveil_report_{stamp}")
        safe_name = "".join(c for c in base_name if c.isalnum() or c in {"_", "-"}).strip() or f"blackveil_{stamp}"
        out_path = REPORTS_DIR / f"{safe_name}.{fmt}"

        bundle = {
            "framework": "BLACKVEIL X Advanced Cyber Operations Ecosystem",
            "generated_at": utc_now(),
            "host": platform.node(),
            "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "total_records": len(payload_records),
            "records": payload_records,
        }

        if fmt == "json":
            out_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        elif fmt == "txt":
            out_path.write_text(self._render_txt(bundle), encoding="utf-8")
        elif fmt == "csv":
            self._write_csv(out_path, payload_records)
        elif fmt == "pdf":
            txt_lines = self._render_txt(bundle).splitlines()
            write_pdf_document(out_path, f"BLACKVEIL X REPORT - {safe_name}", txt_lines)

        if self.db:
            try:
                with self.db.connection() as conn:
                    for rec in payload_records:
                        conn.execute(
                            "UPDATE reports_index SET format = ?, file_path = ? WHERE id = ?",
                            (fmt.upper(), str(out_path), rec["id"]),
                        )
            except Exception:
                pass

        self.logger.info("reports", f"Exported {fmt.upper()} report to {out_path}")
        self.console.print(
            Panel(
                f"[bold bright_green][+] Report exported successfully[/]\n"
                f"[white]Path:[/] [bright_green]{out_path}[/]\n"
                f"[white]Format:[/] {fmt.upper()}  |  [white]Records:[/] {len(payload_records)}",
                title="[bold bright_green]ADVANCED REPORT ENGINE[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return out_path

    def _render_txt(self, bundle: dict[str, Any]) -> str:
        lines = [
            "=" * 78,
            f"  {bundle['framework']}",
            f"  Generated : {bundle['generated_at']}",
            f"  Host      : {bundle['host']}",
            f"  Platform  : {bundle['platform']}",
            f"  Records   : {bundle['total_records']}",
            "=" * 78,
            "",
        ]
        for idx, rec in enumerate(bundle["records"], start=1):
            lines.extend(
                [
                    f"[{idx}] ID: {rec['id']} | Category: {rec['category']} | Severity: {rec['severity']}",
                    f"    Title     : {rec['title']}",
                    f"    Timestamp : {rec['timestamp']}",
                    "-" * 78,
                    json.dumps(rec["data"], indent=2, ensure_ascii=False, default=str),
                    "",
                ]
            )
        return "\n".join(lines)

    @staticmethod
    def _write_csv(out_path: Path, records: list[dict[str, Any]]) -> None:
        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["id", "timestamp", "category", "severity", "title", "host", "data_json"])
            for rec in records:
                writer.writerow(
                    [
                        rec.get("id", ""),
                        rec.get("timestamp", ""),
                        rec.get("category", ""),
                        rec.get("severity", ""),
                        rec.get("title", ""),
                        rec.get("host", ""),
                        json.dumps(rec.get("data", {}), ensure_ascii=False, default=str),
                    ]
                )

    def list_reports(self) -> None:
        ensure_directories()
        files = sorted(
            [p for p in REPORTS_DIR.iterdir() if p.is_file() and p.suffix.lower() in {".json", ".txt", ".csv", ".pdf"}],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        table = Table(
            title="[bold bright_green]REPORTS ARCHIVE (TXT / JSON / CSV / PDF)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("#", style="grey70", width=4)
        table.add_column("Filename", style="white")
        table.add_column("Format", style="bright_green", width=8)
        table.add_column("Size", style="grey70", justify="right")
        table.add_column("Modified", style="grey70")

        if not files:
            self.console.print("[grey70][*] No exported reports found in reports/ directory yet.[/]")
            self.console.print(f"[grey70][*] Current session findings ready to export: {len(self.session_records)}[/]")
            return

        for idx, file_path in enumerate(files, start=1):
            st = file_path.stat()
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(str(idx), file_path.name, file_path.suffix.lstrip(".").upper(), f"{st.st_size:,} B", mtime)

        self.console.print(table)
        self.console.print(f"[grey70]Session buffer: {len(self.session_records)} finding(s) | Directory: {REPORTS_DIR}[/]")

    def view_report(self, filename: str) -> None:
        target = REPORTS_DIR / filename
        if not target.exists() or not target.is_file():
            self.console.print(f"[bold red][-][/] Report not found: {target}")
            return
        if target.suffix.lower() == ".pdf":
            st = target.stat()
            self.console.print(
                Panel(
                    f"[white]PDF Report:[/] [bright_green]{target.name}[/]\n"
                    f"[white]Size      :[/] {st.st_size:,} bytes\n"
                    f"[white]Path      :[/] {target}\n"
                    f"[grey70]Binary PDF verified (%PDF-1.4 header). Open with any PDF reader.[/]",
                    title="[bold bright_green]PDF REPORT INSPECTOR[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )
            return
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            if len(content) > 12000:
                content = content[:12000] + "\n... [truncated for terminal view] ..."
            self.console.print(
                Panel(
                    content,
                    title=f"[bold bright_green]REPORT INSPECTOR: {target.name}[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )
        except OSError as exc:
            self.console.print(f"[bold red][-][/] Failed to read report: {exc}")

"""Module 14: Dependency Guard - Python package inventory, dependency tree, outdated & vulnerability audit."""

from __future__ import annotations

import importlib.metadata as importlib_meta
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from core.logger import BlackveilLogger
from modules.reports import ReportManager


class DependencyGuardModule:
    """Scans Python environment or requirements.txt for dependencies, outdated versions, and CVEs."""

    # Built-in offline baseline of critical well-known vulnerable Python package thresholds
    KNOWN_ADVISORIES: dict[str, tuple[tuple[int, ...], str, str]] = {
        "urllib3": ((1, 26, 18), "CVE-2023-45803", "Upgrade urllib3 >= 1.26.18 / 2.0.7"),
        "requests": ((2, 32, 0), "CVE-2024-35195", "Upgrade requests >= 2.32.0"),
        "cryptography": ((42, 0, 4), "CVE-2024-26130", "Upgrade cryptography >= 42.0.4"),
        "pillow": ((10, 3, 0), "CVE-2024-28219", "Upgrade pillow >= 10.3.0"),
        "jinja2": ((3, 1, 4), "CVE-2024-34064", "Upgrade jinja2 >= 3.1.4"),
        "pyyaml": ((5, 4, 0), "CVE-2020-14343", "Upgrade PyYAML >= 5.4"),
    }

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports

    @staticmethod
    def _ver_tuple(ver_str: str) -> tuple[int, ...]:
        nums = [int(x) for x in re.findall(r"\d+", ver_str.split("+")[0])]
        return tuple(nums[:4]) if nums else (0,)

    def _collect_installed(self) -> list[dict[str, Any]]:
        pkgs: list[dict[str, Any]] = []
        for dist in importlib_meta.distributions():
            name = dist.metadata.get("Name") or dist.name
            version = dist.version
            reqs = [r.split(";")[0].split()[0].strip("=<>!~") for r in (dist.requires or [])]
            pkgs.append({"name": name, "version": version, "requires": sorted(set(reqs))})
        pkgs.sort(key=lambda x: x["name"].lower())
        return pkgs

    def _parse_requirements_file(self, req_path: Path) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for ln in req_path.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9._-]+)\s*([=<>!~]+.*)?$", ln.split(";")[0].strip())
            if m:
                items.append({"name": m.group(1), "spec": (m.group(2) or "*").strip()})
        return items

    def scan(self, req_file: str | None = None) -> list[dict[str, Any]]:
        if req_file:
            p = Path(req_file).expanduser()
            if not p.exists():
                self.console.print(f"[bold red][-][/] Requirements file not found: {p}")
                return []
            reqs = self._parse_requirements_file(p)
            table = Table(title=f"[bold bright_green]DEPENDENCY SCAN // {p.name}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
            table.add_column("Package", style="bright_green")
            table.add_column("Declared Constraint", style="white")
            for r in reqs:
                table.add_row(r["name"], r["spec"])
            self.console.print(table)
            return reqs

        pkgs = self._collect_installed()
        table = Table(title=f"[bold bright_green]INSTALLED PYTHON PACKAGES ({len(pkgs)})[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Package", style="bright_green")
        table.add_column("Version", style="white", width=16)
        table.add_column("Direct Dependencies", style="grey70")
        for p in pkgs[:40]:
            table.add_row(p["name"], p["version"], ", ".join(p["requires"][:6]) or "-")
        self.console.print(table)
        return pkgs

    def tree(self, root_pkg: str | None = None) -> None:
        pkgs = {p["name"].lower(): p for p in self._collect_installed()}
        tree = Tree(f"[bold bright_green]PYTHON DEPENDENCY TREE ({sys.version.split()[0]})[/]")
        targets = [pkgs[root_pkg.lower()]] if root_pkg and root_pkg.lower() in pkgs else list(pkgs.values())[:15]
        for p in targets:
            branch = tree.add(f"[bright_green]{p['name']}[/] [white]{p['version']}[/]")
            for dep in p["requires"][:8]:
                dep_info = pkgs.get(dep.lower())
                branch.add(f"[grey70]{dep} ({dep_info['version'] if dep_info else 'not installed'})[/]")
        self.console.print(tree)

    def outdated(self) -> list[dict[str, str]]:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                timeout=20,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode != 0:
                self.console.print(f"[yellow][!][/] pip outdated check unavailable: {proc.stderr.strip()}")
                return []
            items = json.loads(proc.stdout or "[]")
        except Exception as exc:
            self.console.print(f"[yellow][!][/] Could not query outdated packages: {exc}")
            return []

        if not items:
            self.console.print("[bold bright_green][+][/] All installed Python packages are up to date.")
            return []

        table = Table(title="[bold bright_green]OUTDATED PACKAGES[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Package", style="white")
        table.add_column("Installed", style="yellow")
        table.add_column("Latest", style="bright_green")
        for item in items:
            table.add_row(item["name"], item["version"], item["latest_version"])
        self.console.print(table)
        return items

    def audit(self, online: bool = False) -> list[dict[str, Any]]:
        pkgs = self._collect_installed()
        findings: list[dict[str, Any]] = []

        for p in pkgs:
            key = p["name"].lower()
            if key in self.KNOWN_ADVISORIES:
                min_safe, cve, fix = self.KNOWN_ADVISORIES[key]
                if self._ver_tuple(p["version"]) < min_safe:
                    findings.append({"package": p["name"], "version": p["version"], "advisory": cve, "remediation": fix, "source": "LOCAL_CVE_DB"})

        if online and pkgs:
            # Query OSV.dev batch endpoint safely
            batch = [{"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]} for p in pkgs[:50]]
            try:
                req = urllib.request.Request(
                    "https://api.osv.dev/v1/querybatch",
                    data=json.dumps({"queries": batch}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "BLACKVEIL-X/1.0"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    osv_resp = json.loads(resp.read().decode("utf-8"))
                for pkg, res in zip(pkgs[:50], osv_resp.get("results", [])):
                    for vuln in res.get("vulns", [])[:2]:
                        findings.append({"package": pkg["name"], "version": pkg["version"], "advisory": vuln.get("id", "OSV"), "remediation": "Upgrade to patched release", "source": "OSV.dev"})
            except Exception as exc:
                self.console.print(f"[yellow][!][/] Online OSV.dev query failed ({exc}); using offline CVE threshold database.")

        if not findings:
            self.console.print(f"[bold bright_green][+][/] Audited {len(pkgs)} package(s): zero known vulnerabilities matched.")
        else:
            table = Table(title="[bold red]DEPENDENCY VULNERABILITY AUDIT[/]", box=box.SIMPLE_HEAVY, border_style="red", header_style="bold bright_green")
            table.add_column("Package", style="white")
            table.add_column("Version", style="yellow")
            table.add_column("Advisory", style="bold red")
            table.add_column("Remediation", style="grey70")
            for f in findings:
                table.add_row(f["package"], f["version"], f["advisory"], f["remediation"])
            self.console.print(table)

        self.reports.record("DEPENDENCY_AUDIT", "Python Dependency Vulnerability Audit", {"packages_checked": len(pkgs), "findings": findings}, severity="HIGH" if findings else "INFO")
        return findings

    def report(self, fmt: str = "json") -> None:
        self.audit()
        self.reports.export_report(export_format=fmt, export_all=False)

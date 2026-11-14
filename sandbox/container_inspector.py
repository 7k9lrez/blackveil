"""Module 15: Docker Container Inspector & Security Auditor."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from core.logger import BlackveilLogger
from modules.reports import ReportManager
from sandbox.manager import SandboxManager


class ContainerInspectorModule:
    """Inspects Docker containers for configuration risks, capabilities, mounts, and resource usage."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        sandbox_mgr: SandboxManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.sandbox_mgr = sandbox_mgr
        self.reports = reports

    def list_containers(self, show_all: bool = True) -> list[dict[str, Any]]:
        ready, _ = self.sandbox_mgr.check_docker_ready()
        if not ready:
            return []

        args = ["ps"]
        if show_all:
            args.append("-a")
        args.extend(["--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Networks}}"])
        res = self.sandbox_mgr._run_docker(args)
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Docker error: {res.stderr.strip()}")
            return []

        items: list[dict[str, Any]] = []
        for ln in res.stdout.splitlines():
            parts = ln.split("\t")
            if len(parts) >= 5:
                items.append({"id": parts[0], "name": parts[1], "image": parts[2], "status": parts[3], "networks": parts[4]})

        table = Table(
            title=f"[bold bright_green]CONTAINER INVENTORY ({len(items)})[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green", width=14)
        table.add_column("Name", style="white")
        table.add_column("Image", style="grey70")
        table.add_column("Status", style="white")
        table.add_column("Networks", style="grey70")

        for item in items:
            table.add_row(item["id"], item["name"], item["image"], item["status"], item["networks"])
        if not items:
            self.console.print("[grey70][*] No Docker containers found.[/]")
        else:
            self.console.print(table)
        return items

    def inspect_container(self, target: str) -> dict[str, Any] | None:
        ready, _ = self.sandbox_mgr.check_docker_ready()
        if not ready:
            return None
        res = self.sandbox_mgr._run_docker(["inspect", target])
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Container '{target}' not found: {res.stderr.strip()}")
            return None
        data = json.loads(res.stdout)[0]
        hc = data.get("HostConfig", {})
        cfg = data.get("Config", {})
        summary = {
            "id": data.get("Id", "")[:12],
            "name": data.get("Name", "").lstrip("/"),
            "image": cfg.get("Image"),
            "user": cfg.get("User") or "root (default)",
            "privileged": hc.get("Privileged"),
            "network_mode": hc.get("NetworkMode"),
            "cap_drop": hc.get("CapDrop"),
            "cap_add": hc.get("CapAdd"),
            "mounts": [f"{m.get('Source')} -> {m.get('Destination')}" for m in data.get("Mounts", [])],
            "memory_limit": hc.get("Memory"),
            "pids_limit": hc.get("PidsLimit"),
        }
        table = Table(title=f"[bold bright_green]CONTAINER INSPECT // {summary['name']}[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", show_header=False)
        table.add_column("Field", style="grey70", width=18)
        table.add_column("Value", style="white")
        for k, v in summary.items():
            table.add_row(k, str(v))
        self.console.print(table)
        return summary

    def resources(self) -> None:
        self.sandbox_mgr.resources(target=None)

    def audit_containers(self) -> list[dict[str, Any]]:
        ready, _ = self.sandbox_mgr.check_docker_ready()
        if not ready:
            return []
        containers = self.list_containers(show_all=True)
        findings: list[dict[str, Any]] = []

        for c in containers:
            res = self.sandbox_mgr._run_docker(["inspect", c["id"]])
            if res.returncode != 0:
                continue
            data = json.loads(res.stdout)[0]
            hc = data.get("HostConfig", {})
            cfg = data.get("Config", {})
            mounts = data.get("Mounts", [])
            risks: list[str] = []
            if hc.get("Privileged"):
                risks.append("CRITICAL: Container runs in --privileged mode")
            if hc.get("NetworkMode") == "host":
                risks.append("HIGH: Container shares host network namespace")
            if any("docker.sock" in str(m.get("Source", "")) for m in mounts):
                risks.append("CRITICAL: Docker socket mounted inside container")
            if not (cfg.get("User") or "").strip() or cfg.get("User") in {"0", "root"}:
                risks.append("MEDIUM: Container runs as root user")
            if int(hc.get("Memory") or 0) == 0:
                risks.append("LOW: No memory limit configured")
            if "ALL" not in (hc.get("CapDrop") or []):
                risks.append("MEDIUM: Linux capabilities not dropped (--cap-drop=ALL missing)")

            findings.append({"name": c["name"], "id": c["id"], "risk_count": len(risks), "risks": risks})

        table = Table(
            title="[bold bright_green]CONTAINER SECURITY AUDIT (CIS-STYLE)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Container", style="white")
        table.add_column("Status", width=12)
        table.add_column("Security Findings", style="grey70")

        for f in findings:
            st = "[bright_green]HARDENED[/]" if f["risk_count"] == 0 else f"[bold red]{f['risk_count']} RISKS[/]"
            table.add_row(f["name"], st, "; ".join(f["risks"]) if f["risks"] else "All isolation checks passed")
        self.console.print(table)
        self.reports.record("CONTAINER_AUDIT", "Docker Container Security Audit", {"containers": findings}, severity="WARNING" if any(f["risk_count"] for f in findings) else "INFO")
        return findings

    def report(self, fmt: str = "json") -> None:
        self.audit_containers()
        self.reports.export_report(export_format=fmt, export_all=False)

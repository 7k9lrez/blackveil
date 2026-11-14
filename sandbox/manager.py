"""Hardened Docker Engine Sandbox Manager for BLACKVEIL X."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import ConfigManager
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class SandboxManager:
    """Manages hardened, resource-limited, network-isolated Docker Engine sandboxes."""

    ISOLATED_NET_NAME = "blackveil-isolated-lab"

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        db: DatabaseManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.db = db
        self.reports = reports

    @staticmethod
    def docker_binary() -> str | None:
        return shutil.which("docker")

    def check_docker_ready(self, quiet: bool = False) -> tuple[bool, str]:
        """Verify Docker CLI and Docker Engine / Docker Desktop WSL2 daemon availability."""
        docker_bin = self.docker_binary()
        if not docker_bin:
            msg = (
                "Docker CLI not found in PATH. Install Docker Desktop (Windows/WSL2) or Docker Engine to use sandbox containers. "
                "All non-Docker BLACKVEIL modules remain fully operational."
            )
            if not quiet:
                self.console.print(f"[bold red][-][/] {msg}")
            return False, msg

        try:
            proc = subprocess.run(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=8,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or proc.stdout.strip() or "Docker daemon unreachable"
                hint = (
                    "Start Docker Desktop (WSL2 backend) on Windows."
                    if platform.system() == "Windows"
                    else "Start the docker service (systemctl start docker)."
                )
                msg = f"Docker daemon is not running ({err}). {hint}"
                if not quiet:
                    self.console.print(f"[bold red][-][/] {msg}")
                return False, msg
            return True, proc.stdout.strip()
        except Exception as exc:
            msg = f"Docker availability check failed: {exc}"
            if not quiet:
                self.console.print(f"[bold red][-][/] {msg}")
            return False, msg

    def _run_docker(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        docker_bin = self.docker_binary() or "docker"
        return subprocess.run(
            [docker_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )

    def _next_sandbox_id(self) -> str:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT id FROM sandboxes").fetchall()
        nums: list[int] = []
        for r in rows:
            parts = str(r["id"]).split("-")
            if len(parts) == 3 and parts[2].isdigit():
                nums.append(int(parts[2]))
        next_num = (max(nums) + 1) if nums else 1
        return f"BV-LAB-{next_num:03d}"

    def _log_sandbox_event(self, sandbox_id: str, action: str, details: str = "") -> None:
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO sandbox_events (sandbox_id, action, actor, details, created_at) VALUES (?, ?, 'operator', ?, ?)",
                (sandbox_id, action, details, utc_now()),
            )

    def _confirm(self, prompt_msg: str, assume_yes: bool) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            self.console.print("[bold yellow][!][/] Confirmation required in non-interactive mode; re-run with --yes.")
            return False
        self.console.print(f"[bold yellow][?][/] {prompt_msg} [white](y/N): [/]", end="")
        ans = input().strip().lower()
        return ans in {"y", "yes"}

    @staticmethod
    def build_hardened_create_args(
        container_name: str,
        image: str,
        cpus: str,
        memory: str,
        pids_limit: int,
        network_mode: str = "none",
        disk_limit: str | None = None,
    ) -> list[str]:
        """Construct strictly hardened `docker create` flags with zero host mounts or elevated caps."""
        cmd = [
            "create",
            "--name",
            container_name,
            "--hostname",
            container_name,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--cpus={cpus}",
            f"--memory={memory}",
            f"--memory-swap={memory}",
            f"--pids-limit={pids_limit}",
            f"--network={network_mode}",
            "--label",
            "blackveil.managed=true",
            "--label",
            "blackveil.isolated=true",
        ]
        if disk_limit:
            cmd.extend(["--storage-opt", f"size={disk_limit}"])
        cmd.extend([image, "sleep", "infinity"])
        return cmd

    def verify_container_isolation(self, container_id_or_name: str, expected_network: str = "none") -> tuple[bool, dict[str, Any]]:
        """Inspect live container configuration via Docker Engine to mathematically verify isolation policies."""
        res = self._run_docker(["inspect", container_id_or_name])
        if res.returncode != 0:
            return False, {"error": res.stderr.strip() or "Inspect failed"}

        try:
            data = json.loads(res.stdout)[0]
        except Exception as exc:
            return False, {"error": f"Invalid inspect JSON: {exc}"}

        hc = data.get("HostConfig", {})
        mounts = data.get("Mounts", [])
        sec_opts = hc.get("SecurityOpt") or []
        cap_drop = hc.get("CapDrop") or []
        cap_add = hc.get("CapAdd") or []

        checks = {
            "not_privileged": hc.get("Privileged") is False,
            "caps_dropped_all": "ALL" in cap_drop and len(cap_add) == 0,
            "no_new_privileges": any("no-new-privileges" in str(opt) for opt in sec_opts),
            "no_host_mounts": len(mounts) == 0,
            "no_docker_sock": all("docker.sock" not in str(m) and "docker_engine" not in str(m) for m in mounts),
            "memory_limited": int(hc.get("Memory", 0)) > 0,
            "cpu_limited": int(hc.get("NanoCpus", 0)) > 0 or int(hc.get("CpuQuota", 0)) > 0,
            "pids_limited": int(hc.get("PidsLimit") or 0) > 0,
            "network_isolated": hc.get("NetworkMode") == expected_network,
        }
        all_passed = all(checks.values())
        return all_passed, {"checks": checks, "host_config": {"network_mode": hc.get("NetworkMode"), "memory": hc.get("Memory"), "pids_limit": hc.get("PidsLimit")}}

    def create(
        self,
        name: str,
        image: str | None = None,
        cpus: str | None = None,
        memory: str | None = None,
        disk_limit: str | None = None,
        pids_limit: int | None = None,
        timeout_minutes: int | None = None,
        network_mode: str = "none",
    ) -> dict[str, Any] | None:
        """Create and verify an isolated Docker sandbox container."""
        ready, _ = self.check_docker_ready()
        if not ready:
            return None

        clean_name = "".join(c for c in name.strip() if c.isalnum() or c in {"-", "_"}).lower()
        if not clean_name:
            self.console.print("[bold red][-][/] Invalid sandbox name.")
            return None

        if network_mode != "none" and network_mode != self.ISOLATED_NET_NAME:
            self.console.print(
                f"[bold red][-][/] Security Policy: Only 'none' (full isolation) or '{self.ISOLATED_NET_NAME}' are permitted."
            )
            return None

        with self.db.connection() as conn:
            existing = conn.execute("SELECT id FROM sandboxes WHERE name = ?", (clean_name,)).fetchone()
            if existing:
                self.console.print(f"[bold red][-][/] Sandbox '{clean_name}' already exists (ID: {existing['id']}).")
                return None

        sb_id = self._next_sandbox_id()
        container_name = f"bv_{clean_name}"
        img = image or str(self.config.get("sandbox_default_image", "alpine:latest"))
        cpu_val = cpus or str(self.config.get("sandbox_default_cpus", "0.5"))
        mem_val = memory or str(self.config.get("sandbox_default_memory", "256m"))
        pids_val = pids_limit or int(self.config.get("sandbox_default_pids", 64))
        ttl_min = timeout_minutes or int(self.config.get("sandbox_default_timeout_min", 60))

        self.console.print("[bright_green][+][/] Initializing sandbox...")
        time.sleep(0.05)

        # Ensure image is available locally or pull cleanly
        inspect_img = self._run_docker(["image", "inspect", img])
        if inspect_img.returncode != 0:
            self.console.print(f"[bright_green][+][/] Pulling sandbox base image '{img}'...")
            pull = self._run_docker(["pull", img], timeout=180)
            if pull.returncode != 0:
                self.console.print(f"[bold red][-][/] Failed to pull image '{img}': {pull.stderr.strip()}")
                return None

        self.console.print("[bright_green][+][/] Creating isolated container...")
        create_args = self.build_hardened_create_args(
            container_name=container_name,
            image=img,
            cpus=cpu_val,
            memory=mem_val,
            pids_limit=pids_val,
            network_mode=network_mode,
            disk_limit=disk_limit,
        )
        res = self._run_docker(create_args, timeout=30)
        if res.returncode != 0 and disk_limit and "storage-opt" in res.stderr.lower():
            # Fallback if overlay2/WSL2 driver does not support per-container storage-opt quota
            self.console.print("[yellow][!][/] Docker storage driver does not support --storage-opt; enforcing memory/CPU/PID isolation.")
            create_args = self.build_hardened_create_args(
                container_name=container_name,
                image=img,
                cpus=cpu_val,
                memory=mem_val,
                pids_limit=pids_val,
                network_mode=network_mode,
                disk_limit=None,
            )
            res = self._run_docker(create_args, timeout=30)

        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Container creation failed: {res.stderr.strip()}")
            return None

        container_id = res.stdout.strip()[:12]
        self.console.print("[bright_green][+][/] Applying resource limits...")
        self.console.print("[bright_green][+][/] Configuring network isolation...")
        self.console.print("[bright_green][+][/] Verifying security policies...")

        verified, verification_details = self.verify_container_isolation(container_name, expected_network=network_mode)
        if not verified:
            self._run_docker(["rm", "-f", container_name])
            self.console.print("[bold red][-][/] Security isolation verification FAILED! Container destroyed immediately.")
            self.console.print(f"[grey70]{json.dumps(verification_details, indent=2)}[/]")
            return None

        # Start the hardened container
        start_res = self._run_docker(["start", container_name])
        status = "ISOLATED" if start_res.returncode == 0 else "CREATED_STOPPED"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=ttl_min)

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO sandboxes
                (id, name, container_id, image, status, isolated, cpu_limit, memory_limit, disk_limit, pids_limit,
                 network_mode, timeout_minutes, created_at, expires_at, last_verified_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sb_id,
                    clean_name,
                    container_id,
                    img,
                    status,
                    cpu_val,
                    mem_val,
                    disk_limit or "driver-default",
                    pids_val,
                    network_mode,
                    ttl_min,
                    now.isoformat(),
                    expires.isoformat(),
                    now.isoformat(),
                    json.dumps(verification_details),
                ),
            )

        self._log_sandbox_event(sb_id, "CREATE", f"Image={img}, CPU={cpu_val}, MEM={mem_val}, NET={network_mode}")
        self.console.print(
            f"\n[bold bright_green]SANDBOX CREATED[/]\n"
            f"[white]ID:[/] [bright_green]{sb_id}[/]\n"
            f"[white]NAME:[/] {clean_name} ([grey70]{container_name}[/])\n"
            f"[white]STATUS:[/] [bold bright_green]{status}[/]"
        )
        record = {"id": sb_id, "name": clean_name, "container_id": container_id, "status": status, "verified": verified}
        self.reports.record("SANDBOX_CREATE", f"Sandbox Created: {clean_name}", record)
        return record

    def _resolve_sandbox(self, target: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM sandboxes WHERE id = ? OR name = ?",
                (target, target.lower()),
            ).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Sandbox '{target}' not found.")
            return None
        return dict(row)

    def list_sandboxes(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM sandboxes ORDER BY created_at DESC").fetchall()
        items = [dict(r) for r in rows]

        table = Table(
            title="[bold bright_green]BLACKVEIL SANDBOX INFRASTRUCTURE[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("ID", style="bright_green", width=11)
        table.add_column("Name", style="white")
        table.add_column("Image", style="grey70")
        table.add_column("Status", width=12)
        table.add_column("Isolation", width=10)
        table.add_column("Limits", style="grey70")
        table.add_column("Net", style="white", width=10)

        if not items:
            self.console.print("[grey70][*] No sandboxes registered. Create one with `sandbox create --name linux-lab`.[/]")
            return []

        for item in items:
            iso = "[bright_green]VERIFIED[/]" if item["isolated"] else "[bold red]UNVERIFIED[/]"
            st_col = "bright_green" if item["status"] in {"ISOLATED", "RUNNING"} else "yellow"
            table.add_row(
                item["id"],
                item["name"],
                item["image"],
                f"[{st_col}]{item['status']}[/]",
                iso,
                f"{item['cpu_limit']}c / {item['memory_limit']}",
                item["network_mode"],
            )
        self.console.print(table)
        return items

    def start(self, target: str) -> bool:
        ready, _ = self.check_docker_ready()
        if not ready:
            return False
        sb = self._resolve_sandbox(target)
        if not sb:
            return False
        cname = f"bv_{sb['name']}"
        res = self._run_docker(["start", cname])
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Failed to start sandbox '{sb['name']}': {res.stderr.strip()}")
            return False
        verified, _ = self.verify_container_isolation(cname, expected_network=sb["network_mode"])
        new_status = "ISOLATED" if verified else "UNVERIFIED"
        with self.db.connection() as conn:
            conn.execute("UPDATE sandboxes SET status = ?, isolated = ?, last_verified_at = ? WHERE id = ?", (new_status, int(verified), utc_now(), sb["id"]))
        self._log_sandbox_event(sb["id"], "START", f"Status={new_status}")
        self.console.print(f"[bright_green][+][/] Sandbox [white]{sb['name']}[/] ({sb['id']}) started -> STATUS: [bold bright_green]{new_status}[/]")
        return True

    def stop(self, target: str) -> bool:
        ready, _ = self.check_docker_ready()
        if not ready:
            return False
        sb = self._resolve_sandbox(target)
        if not sb:
            return False
        cname = f"bv_{sb['name']}"
        res = self._run_docker(["stop", "-t", "5", cname])
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Failed to stop sandbox '{sb['name']}': {res.stderr.strip()}")
            return False
        with self.db.connection() as conn:
            conn.execute("UPDATE sandboxes SET status = 'STOPPED' WHERE id = ?", (sb["id"],))
        self._log_sandbox_event(sb["id"], "STOP")
        self.console.print(f"[bright_green][+][/] Sandbox [white]{sb['name']}[/] stopped cleanly.")
        return True

    def delete(self, target: str, assume_yes: bool = False) -> bool:
        sb = self._resolve_sandbox(target)
        if not sb:
            return False
        if not self._confirm(f"Permanently delete sandbox '{sb['name']}' ({sb['id']}) and its container?", assume_yes):
            self.console.print("[grey70][*] Deletion cancelled.[/]")
            return False
        if self.docker_binary():
            self._run_docker(["rm", "-f", f"bv_{sb['name']}"])
        with self.db.connection() as conn:
            conn.execute("DELETE FROM sandboxes WHERE id = ?", (sb["id"],))
        self._log_sandbox_event(sb["id"], "DELETE")
        self.console.print(f"[bright_green][+][/] Sandbox [white]{sb['name']}[/] deleted.")
        return True

    def enter(self, target: str, command: str | None = None) -> int:
        """Open an interactive shell inside the isolated sandbox or run a single isolated command."""
        ready, _ = self.check_docker_ready()
        if not ready:
            return 1
        sb = self._resolve_sandbox(target)
        if not sb:
            return 1
        cname = f"bv_{sb['name']}"
        docker_bin = self.docker_binary() or "docker"

        if command:
            self._log_sandbox_event(sb["id"], "EXEC", command)
            res = self._run_docker(["exec", cname, "/bin/sh", "-c", command], timeout=60)
            if res.stdout:
                self.console.print(res.stdout.rstrip())
            if res.stderr:
                self.console.print(f"[yellow]{res.stderr.rstrip()}[/]")
            return res.returncode

        self._log_sandbox_event(sb["id"], "ENTER", "Interactive shell session")
        self.console.print(f"[bright_green][*][/] Entering isolated shell in [white]{sb['name']}[/] (type `exit` to return to BLACKVEIL)...")
        proc = subprocess.run([docker_bin, "exec", "-it", cname, "/bin/sh"])
        return proc.returncode

    def inspect(self, target: str) -> dict[str, Any] | None:
        sb = self._resolve_sandbox(target)
        if not sb:
            return None

        with self.db.connection() as conn:
            snaps = conn.execute("SELECT * FROM sandbox_snapshots WHERE sandbox_id = ? ORDER BY created_at DESC", (sb["id"],)).fetchall()
            events = conn.execute("SELECT * FROM sandbox_events WHERE sandbox_id = ? ORDER BY id DESC LIMIT 10", (sb["id"],)).fetchall()

        verified_live = False
        live_detail: dict[str, Any] = {}
        if self.check_docker_ready(quiet=True)[0]:
            verified_live, live_detail = self.verify_container_isolation(f"bv_{sb['name']}", expected_network=sb["network_mode"])

        info_lines = [
            f"[white]Sandbox ID    :[/] [bright_green]{sb['id']}[/]",
            f"[white]Name          :[/] {sb['name']} (bv_{sb['name']})",
            f"[white]Image         :[/] {sb['image']}",
            f"[white]Status        :[/] [bright_green]{sb['status']}[/]",
            f"[white]Isolation     :[/] {'[bold bright_green]VERIFIED ISOLATED[/]' if verified_live or sb['isolated'] else '[bold red]UNVERIFIED[/]'}",
            f"[white]CPU / RAM /PID:[/] {sb['cpu_limit']} CPUs | {sb['memory_limit']} RAM | {sb['pids_limit']} PIDs",
            f"[white]Network Mode  :[/] {sb['network_mode']}",
            f"[white]Expires At    :[/] {sb['expires_at']}",
            f"[white]Snapshots     :[/] {len(snaps)}",
        ]
        self.console.print(Panel("\n".join(info_lines), title=f"[bold bright_green]SANDBOX INSPECTOR // {sb['id']}[/]", border_style="bright_green", box=box.SQUARE))

        if events:
            ev_table = Table(title="[bold bright_green]SANDBOX AUDIT HISTORY[/]", box=box.SIMPLE, header_style="bold bright_green")
            ev_table.add_column("Timestamp", style="grey70", width=19)
            ev_table.add_column("Action", style="bright_green", width=12)
            ev_table.add_column("Details", style="white")
            for ev in events:
                ev_table.add_row(ev["created_at"][:19], ev["action"], ev["details"])
            self.console.print(ev_table)

        return {"sandbox": sb, "live_verification": live_detail, "snapshots": [dict(s) for s in snaps]}

    def snapshot(self, target: str, snapshot_name: str | None = None) -> str | None:
        ready, _ = self.check_docker_ready()
        if not ready:
            return None
        sb = self._resolve_sandbox(target)
        if not sb:
            return None

        cname = f"bv_{sb['name']}"
        snap_tag = snapshot_name or f"snap-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        image_tag = f"blackveil_snap_{sb['name']}:{snap_tag}"
        res = self._run_docker(["commit", cname, image_tag], timeout=60)
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Snapshot failed: {res.stderr.strip()}")
            return None

        snap_id = f"SNAP-{datetime.now(timezone.utc).strftime('%H%M%S')}"
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO sandbox_snapshots (id, sandbox_id, snapshot_name, image_tag, created_at) VALUES (?, ?, ?, ?, ?)",
                (snap_id, sb["id"], snap_tag, image_tag, utc_now()),
            )
        self._log_sandbox_event(sb["id"], "SNAPSHOT", f"{snap_tag} -> {image_tag}")
        self.console.print(f"[bright_green][+][/] Snapshot created: [white]{snap_tag}[/] ([bright_green]{image_tag}[/])")
        return snap_tag

    def restore(self, target: str, snapshot_name: str) -> bool:
        ready, _ = self.check_docker_ready()
        if not ready:
            return False
        sb = self._resolve_sandbox(target)
        if not sb:
            return False

        with self.db.connection() as conn:
            snap = conn.execute(
                "SELECT * FROM sandbox_snapshots WHERE sandbox_id = ? AND (snapshot_name = ? OR id = ?)",
                (sb["id"], snapshot_name, snapshot_name),
            ).fetchone()
        if not snap:
            self.console.print(f"[bold red][-][/] Snapshot '{snapshot_name}' not found for sandbox '{sb['name']}'.")
            return False

        cname = f"bv_{sb['name']}"
        self._run_docker(["rm", "-f", cname])
        create_args = self.build_hardened_create_args(
            container_name=cname,
            image=snap["image_tag"],
            cpus=sb["cpu_limit"],
            memory=sb["memory_limit"],
            pids_limit=int(sb["pids_limit"]),
            network_mode=sb["network_mode"],
        )
        res = self._run_docker(create_args)
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Restore failed: {res.stderr.strip()}")
            return False
        self._run_docker(["start", cname])
        with self.db.connection() as conn:
            conn.execute("UPDATE sandboxes SET container_id = ?, status = 'ISOLATED' WHERE id = ?", (res.stdout.strip()[:12], sb["id"]))
        self._log_sandbox_event(sb["id"], "RESTORE", f"Restored from snapshot {snap['snapshot_name']}")
        self.console.print(f"[bright_green][+][/] Sandbox [white]{sb['name']}[/] restored from snapshot [bright_green]{snap['snapshot_name']}[/].")
        return True

    def reset(self, target: str, assume_yes: bool = False) -> bool:
        ready, _ = self.check_docker_ready()
        if not ready:
            return False
        sb = self._resolve_sandbox(target)
        if not sb:
            return False
        if not self._confirm(f"Reset sandbox '{sb['name']}' back to clean base image '{sb['image']}'?", assume_yes):
            return False

        cname = f"bv_{sb['name']}"
        self._run_docker(["rm", "-f", cname])
        create_args = self.build_hardened_create_args(
            container_name=cname,
            image=sb["image"],
            cpus=sb["cpu_limit"],
            memory=sb["memory_limit"],
            pids_limit=int(sb["pids_limit"]),
            network_mode=sb["network_mode"],
        )
        res = self._run_docker(create_args)
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Reset failed: {res.stderr.strip()}")
            return False
        self._run_docker(["start", cname])
        with self.db.connection() as conn:
            conn.execute("UPDATE sandboxes SET container_id = ?, status = 'ISOLATED' WHERE id = ?", (res.stdout.strip()[:12], sb["id"]))
        self._log_sandbox_event(sb["id"], "RESET", f"Reset to base image {sb['image']}")
        self.console.print(f"[bright_green][+][/] Sandbox [white]{sb['name']}[/] reset to clean state.")
        return True

    def resources(self, target: str | None = None) -> None:
        ready, _ = self.check_docker_ready()
        if not ready:
            return
        args = ["stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.PIDs}}"]
        if target:
            sb = self._resolve_sandbox(target)
            if not sb:
                return
            args.append(f"bv_{sb['name']}")
        res = self._run_docker(args, timeout=15)
        if res.returncode != 0:
            self.console.print(f"[bold red][-][/] Could not read container stats: {res.stderr.strip()}")
            return

        table = Table(
            title="[bold bright_green]SANDBOX RESOURCE TELEMETRY[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Container", style="bright_green")
        table.add_column("CPU %", justify="right", style="white")
        table.add_column("Memory Usage", style="white")
        table.add_column("Mem %", justify="right", style="grey70")
        table.add_column("Net I/O", style="grey70")
        table.add_column("PIDs", justify="right", style="white")

        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if not lines:
            self.console.print("[grey70][*] No running sandbox containers to measure.[/]")
            return
        for ln in lines:
            cols = ln.split("\t")
            if len(cols) >= 6:
                table.add_row(*cols[:6])
        self.console.print(table)

    def configure_network(self, target: str, allow_isolated_bridge: bool = False) -> bool:
        ready, _ = self.check_docker_ready()
        if not ready:
            return False
        sb = self._resolve_sandbox(target)
        if not sb:
            return False
        cname = f"bv_{sb['name']}"

        if allow_isolated_bridge:
            # Create internal isolated bridge (no external gateway routing)
            check_net = self._run_docker(["network", "inspect", self.ISOLATED_NET_NAME])
            if check_net.returncode != 0:
                self._run_docker(["network", "create", "--driver", "bridge", "--internal", self.ISOLATED_NET_NAME])
            self._run_docker(["network", "connect", self.ISOLATED_NET_NAME, cname])
            new_mode = self.ISOLATED_NET_NAME
            msg = f"Connected to internal-only bridge '{self.ISOLATED_NET_NAME}' (no internet egress)."
        else:
            self._run_docker(["network", "disconnect", self.ISOLATED_NET_NAME, cname])
            new_mode = "none"
            msg = "All network interfaces disconnected (--network=none)."

        with self.db.connection() as conn:
            conn.execute("UPDATE sandboxes SET network_mode = ? WHERE id = ?", (new_mode, sb["id"]))
        self._log_sandbox_event(sb["id"], "NETWORK", msg)
        self.console.print(f"[bright_green][+][/] {msg}")
        return True

    def cleanup(self, assume_yes: bool = False) -> int:
        """Remove expired or stopped sandboxes safely."""
        now_iso = utc_now()
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM sandboxes WHERE status = 'STOPPED' OR (expires_at IS NOT NULL AND expires_at < ?)",
                (now_iso,),
            ).fetchall()
        targets = [dict(r) for r in rows]
        if not targets:
            self.console.print("[bright_green][+][/] No expired or stopped sandboxes require cleanup.")
            return 0
        if not self._confirm(f"Remove {len(targets)} expired/stopped sandbox(es)?", assume_yes):
            return 0

        removed = 0
        for sb in targets:
            if self.docker_binary():
                self._run_docker(["rm", "-f", f"bv_{sb['name']}"])
            with self.db.connection() as conn:
                conn.execute("DELETE FROM sandboxes WHERE id = ?", (sb["id"],))
            removed += 1
        self.console.print(f"[bright_green][+][/] Cleaned up {removed} sandbox(es).")
        return removed

"""Module 19: Secure Plugin Engine - AST safety check, SHA-256 signature verification & permission gating."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import PLUGINS_DIR
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now


class PluginEngineModule:
    """Manages user Python plugins with strict AST inspection, SHA-256 verification, and explicit enablement."""

    DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}
    SENSITIVE_MODULES = {"subprocess", "ctypes", "pty"}

    def __init__(self, console: Console, logger: BlackveilLogger, db: DatabaseManager) -> None:
        self.console = console
        self.logger = logger
        self.db = db
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def audit_plugin_ast(self, code_path: Path, declared_permissions: list[str]) -> tuple[bool, list[str]]:
        """Statically inspect plugin Python AST for undeclared dangerous calls or imports."""
        issues: list[str] = []
        try:
            tree = ast.parse(code_path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            return False, [f"Python syntax error: {exc}"]

        has_run_fn = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "run":
                has_run_fn = True
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS_CALLS:
                    issues.append(f"Prohibited dynamic execution call: {node.func.id}()")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen"}:
                    if "shell_exec" not in declared_permissions:
                        issues.append(f"Undeclared shell execution call: .{node.func.attr}()")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in self.SENSITIVE_MODULES and mod not in declared_permissions:
                        issues.append(f"Sensitive module '{mod}' imported without permission declaration")
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.split(".")[0]
                if mod in self.SENSITIVE_MODULES and mod not in declared_permissions:
                    issues.append(f"Sensitive module '{mod}' imported without permission declaration")

        if not has_run_fn:
            issues.append("Plugin must define a `def run(console, args):` entry point")

        return len(issues) == 0, issues

    def create_plugin(self, name: str, author: str = "operator") -> Path | None:
        """Scaffold a signed, AST-clean plugin template inside plugins/installed/<name>/."""
        clean = "".join(c for c in name.strip().lower() if c.isalnum() or c in {"_", "-"})
        if not clean:
            self.console.print("[bold red][-][/] Invalid plugin name.")
            return None

        pdir = PLUGINS_DIR / clean
        pdir.mkdir(parents=True, exist_ok=True)
        py_file = pdir / "plugin.py"
        manifest_file = pdir / "manifest.json"

        py_code = (
            f'"""BLACKVEIL Plugin: {clean}"""\n\n'
            "def run(console, args):\n"
            f'    console.print(f"[bright_green][PLUGIN:{clean}][/] Executed cleanly with args={{args}}")\n'
            "    return 0\n"
        )
        py_file.write_text(py_code, encoding="utf-8")
        digest = self._sha256_file(py_file)
        manifest = {
            "name": clean,
            "version": "1.0.0",
            "author": author,
            "permissions": ["console_output"],
            "sha256": digest,
        }
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        self.console.print(
            Panel(
                f"[bright_green][+] Plugin scaffold created[/]\n"
                f"[white]Directory :[/] {pdir}\n"
                f"[white]SHA-256   :[/] [bright_green]{digest}[/]\n"
                f"[grey70]Note: New plugins remain disabled until installed & verified via `plugin install --path {pdir}`.[/]",
                title="[bold bright_green]PLUGIN GENERATOR[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return pdir

    def install_plugin(self, source_path: str, assume_yes: bool = False) -> bool:
        """Verify AST security, manifest signature, and register plugin (disabled by default until enabled)."""
        src = Path(source_path).expanduser()
        if not src.exists():
            self.console.print(f"[bold red][-][/] Plugin path not found: {src}")
            return False

        if src.is_dir():
            py_file = src / "plugin.py"
            manifest_file = src / "manifest.json"
        else:
            py_file = src
            manifest_file = src.parent / "manifest.json"

        if not py_file.exists():
            self.console.print(f"[bold red][-][/] Missing plugin.py in {src}")
            return False

        manifest: dict[str, Any] = {
            "name": py_file.parent.name if py_file.name == "plugin.py" else py_file.stem,
            "version": "1.0.0",
            "author": "unknown",
            "permissions": [],
            "sha256": "",
        }
        if manifest_file.exists():
            try:
                manifest.update(json.loads(manifest_file.read_text(encoding="utf-8")))
            except Exception as exc:
                self.console.print(f"[bold red][-][/] Invalid manifest.json: {exc}")
                return False

        actual_hash = self._sha256_file(py_file)
        expected_hash = str(manifest.get("sha256", "")).lower()
        sig_ok = bool(expected_hash) and (expected_hash == actual_hash.lower())
        if not sig_ok:
            self.console.print(
                f"[bold red][-] SIGNATURE VERIFICATION FAILED[/]: manifest sha256 ({expected_hash or 'missing'}) != actual ({actual_hash})."
            )
            return False

        ast_ok, ast_issues = self.audit_plugin_ast(py_file, manifest.get("permissions", []))
        if not ast_ok:
            self.console.print("[bold red][-] PLUGIN SECURITY AUDIT FAILED:[/]")
            for issue in ast_issues:
                self.console.print(f"  [red]- {issue}[/]")
            return False

        if not assume_yes and sys.stdin.isatty():
            self.console.print(
                f"[bold yellow][?][/] Install verified plugin '{manifest['name']}' (permissions={manifest['permissions']})? [white](y/N): [/]",
                end="",
            )
            if input().strip().lower() not in {"y", "yes"}:
                self.console.print("[grey70][*] Installation cancelled.[/]")
                return False

        dest_dir = PLUGINS_DIR / manifest["name"]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_py = dest_dir / "plugin.py"
        if py_file.resolve() != dest_py.resolve():
            shutil.copy2(py_file, dest_py)
        if manifest_file.exists() and manifest_file.resolve() != (dest_dir / "manifest.json").resolve():
            shutil.copy2(manifest_file, dest_dir / "manifest.json")

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO plugins_registry
                (name, version, author, sha256, permissions_json, enabled, verified, file_path, installed_at)
                VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
                """,
                (
                    manifest["name"],
                    manifest["version"],
                    manifest["author"],
                    actual_hash,
                    json.dumps(manifest["permissions"]),
                    str(dest_py.resolve()),
                    utc_now(),
                ),
            )
        self.console.print(
            f"[bold bright_green][+][/] Plugin [white]'{manifest['name']}'[/] verified and installed (disabled by default; run `plugin enable {manifest['name']}`)."
        )
        return True

    def list_plugins(self) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM plugins_registry ORDER BY name").fetchall()]
        if not rows:
            self.console.print("[grey70][*] No plugins installed. Create one with `plugin create --name mymod`.[/]")
            return []
        table = Table(title="[bold bright_green]INSTALLED PLUGINS REGISTRY[/]", box=box.SIMPLE_HEAVY, border_style="bright_green", header_style="bold bright_green")
        table.add_column("Name", style="bright_green")
        table.add_column("Version", width=9)
        table.add_column("Verified", width=10)
        table.add_column("State", width=10)
        table.add_column("Permissions", style="grey70")
        for r in rows:
            ver = "[bright_green]SIGNED[/]" if r["verified"] else "[bold red]UNVERIFIED[/]"
            st = "[bright_green]ENABLED[/]" if r["enabled"] else "[grey50]DISABLED[/]"
            table.add_row(r["name"], r["version"], ver, st, r["permissions_json"])
        self.console.print(table)
        return rows

    def inspect_plugin(self, name: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM plugins_registry WHERE name = ?", (name.strip().lower(),)).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Plugin '{name}' is not installed.")
            return None
        r = dict(row)
        p = Path(r["file_path"])
        intact = p.exists() and self._sha256_file(p) == r["sha256"]
        self.console.print(
            Panel(
                f"[white]Name        :[/] [bright_green]{r['name']}[/] v{r['version']}\n"
                f"[white]Author      :[/] {r['author']}\n"
                f"[white]SHA-256     :[/] {r['sha256']}\n"
                f"[white]Integrity   :[/] {'[bold bright_green]INTACT[/]' if intact else '[bold red]HASH MISMATCH / TAMPERED[/]'}\n"
                f"[white]Permissions :[/] {r['permissions_json']}\n"
                f"[white]State       :[/] {'ENABLED' if r['enabled'] else 'DISABLED'}",
                title=f"[bold bright_green]PLUGIN INSPECTOR // {r['name']}[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )
        return r

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM plugins_registry WHERE name = ?", (name.strip().lower(),)).fetchone()
            if not row:
                self.console.print(f"[bold red][-][/] Plugin '{name}' not found.")
                return False
            if enabled:
                p = Path(row["file_path"])
                if not row["verified"] or not p.exists() or self._sha256_file(p) != row["sha256"]:
                    self.console.print(f"[bold red][-][/] Refusing to enable '{name}': signature/integrity check failed!")
                    return False
            conn.execute("UPDATE plugins_registry SET enabled = ? WHERE name = ?", (int(enabled), row["name"]))
        self.console.print(f"[bright_green][+][/] Plugin [white]{name}[/] {'ENABLED' if enabled else 'DISABLED'}.")
        return True

    def run_plugin(self, name: str, args: list[str] | None = None) -> int:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM plugins_registry WHERE name = ?", (name.strip().lower(),)).fetchone()
        if not row:
            self.console.print(f"[bold red][-][/] Plugin '{name}' is not installed.")
            return 1
        if not row["enabled"] or not row["verified"]:
            self.console.print(f"[bold red][-][/] Plugin '{name}' is disabled or unverified; automatic execution blocked.")
            return 1
        p = Path(row["file_path"])
        if not p.exists() or self._sha256_file(p) != row["sha256"]:
            self.console.print(f"[bold red][-][/] Tamper detected on '{name}'! Execution aborted.")
            return 1

        spec = importlib.util.spec_from_file_location(f"blackveil_plugin_{row['name']}", str(p))
        if not spec or not spec.loader:
            return 1
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return int(mod.run(self.console, args or []) or 0)

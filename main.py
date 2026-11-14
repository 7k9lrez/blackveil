#!/usr/bin/env python3
"""BLACKVEIL - Advanced Cybersecurity Terminal Framework Entry Point."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is always importable whether invoked via script or entry point
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _verify_dependencies() -> bool:
    """Verify core third-party dependencies before launching Rich terminal."""
    missing: list[str] = []
    for pkg in ("rich", "psutil"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[BLACKVEIL] Missing required dependencies: {', '.join(missing)}")
        print("[BLACKVEIL] Run 'install.bat' (Windows) or 'pip install -r requirements.txt'.")
        return False
    return True


def cli_entry(argv: list[str] | None = None) -> int:
    """Entry point for both interactive terminal and direct CLI execution."""
    if not _verify_dependencies():
        return 1

    from core.terminal import BlackveilTerminal

    args = sys.argv[1:] if argv is None else argv
    terminal = BlackveilTerminal()

    try:
        if args:
            return terminal.run_cli(args)
        return terminal.run_interactive()
    except KeyboardInterrupt:
        print("\n[BLACKVEIL] Session interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(cli_entry())

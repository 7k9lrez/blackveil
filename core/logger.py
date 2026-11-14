"""Structured logging and command history management for BLACKVEIL."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from core.config import HISTORY_FILE, LOGS_DIR, ensure_directories


class BlackveilLogger:
    """Handles rotating file logs and audit events."""

    def __init__(self, level: str = "INFO") -> None:
        ensure_directories()
        self.log_file: Path = LOGS_DIR / "blackveil.log"
        self.audit_file: Path = LOGS_DIR / "audit_events.jsonl"
        self._logger = logging.getLogger("BLACKVEIL")
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.propagate = False

        if not self._logger.handlers:
            handler = RotatingFileHandler(
                self.log_file,
                maxBytes=2 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            formatter = logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(module_name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def set_level(self, level: str) -> None:
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    def log(self, level: str, module_name: str, message: str, details: dict[str, Any] | None = None) -> None:
        lvl = getattr(logging, level.upper(), logging.INFO)
        self._logger.log(lvl, message, extra={"module_name": module_name})
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "module": module_name,
            "message": message,
        }
        if details:
            event["details"] = details
        try:
            with self.audit_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def info(self, module_name: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.log("INFO", module_name, message, details)

    def warning(self, module_name: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.log("WARNING", module_name, message, details)

    def error(self, module_name: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.log("ERROR", module_name, message, details)

    def read_recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.audit_file.exists():
            return []
        try:
            lines = self.audit_file.read_text(encoding="utf-8", errors="replace").splitlines()
            events: list[dict[str, Any]] = []
            for line in lines[-limit:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events
        except OSError:
            return []


class HistoryManager:
    """Persists command history across sessions."""

    def __init__(self, history_file: Path = HISTORY_FILE, max_entries: int = 250) -> None:
        ensure_directories()
        self.history_file = history_file
        self.max_entries = max_entries
        self.entries: list[dict[str, str]] = []
        self.load()

    def load(self) -> None:
        if not self.history_file.exists():
            self.entries = []
            return
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                self.entries = [item for item in data if isinstance(item, dict) and "command" in item]
            else:
                self.entries = []
        except (OSError, json.JSONDecodeError):
            self.entries = []

    def add(self, command: str) -> None:
        cleaned = command.strip()
        if not cleaned:
            return
        self.entries.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command": cleaned,
            }
        )
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries :]
        self.save()

    def clear(self) -> None:
        self.entries = []
        self.save()

    def save(self) -> None:
        ensure_directories()
        try:
            self.history_file.write_text(
                json.dumps(self.entries, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

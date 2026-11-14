"""Configuration management for BLACKVEIL X Ecosystem."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
SESSIONS_DIR = LOGS_DIR / "sessions"
REPORTS_DIR = BASE_DIR / "reports"
SANDBOX_DATA_DIR = DATA_DIR / "sandbox"
LOCAL_SITES_DIR = DATA_DIR / "local_sites"
VAULT_DIR = DATA_DIR / "vault"
LABS_DIR = BASE_DIR / "labs"
PLUGINS_DIR = BASE_DIR / "plugins" / "installed"
DB_FILE = DATA_DIR / "blackveil.db"
CONFIG_FILE = DATA_DIR / "config.json"
SECRETS_FILE = DATA_DIR / "secrets.json"
HISTORY_FILE = DATA_DIR / "history.json"
BASELINE_FILE = DATA_DIR / "integrity_baselines.json"

# Backwards compatibility alias
SANDBOX_DIR = SANDBOX_DATA_DIR

DEFAULT_CONFIG: dict[str, Any] = {
    "scan_timeout": 0.6,
    "scan_threads": 64,
    "ping_timeout": 1.0,
    "max_history": 250,
    "default_report_format": "json",
    "monitor_interval": 1.0,
    "log_level": "INFO",
    "auto_save_reports": False,
    "warroom_safe_mode": True,
    "prompt_user": "BLACKVEIL@ROOT",
    "sandbox_default_cpus": "0.5",
    "sandbox_default_memory": "256m",
    "sandbox_default_pids": 64,
    "sandbox_default_timeout_min": 60,
    "sandbox_default_image": "alpine:latest",
    "ai_model": "gemini-4-hydrogen",
    "gemini_timeout": 25,
    "gemini_retries": 2,
    "local_site_max_pages": 35,
    "local_site_max_bytes": 10485760,
    "google_cse_cx": "",
    "computer_search_threads": 8,
    "computer_search_max_file_mb": 10,
}


def ensure_directories() -> None:
    """Ensure all BLACKVEIL runtime directories exist."""
    for directory in (
        DATA_DIR,
        LOGS_DIR,
        SESSIONS_DIR,
        REPORTS_DIR,
        SANDBOX_DATA_DIR,
        LOCAL_SITES_DIR,
        VAULT_DIR,
        LABS_DIR,
        PLUGINS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


class ConfigManager:
    """Loads, validates, and persists BLACKVEIL configuration."""

    def __init__(self, config_path: Path = CONFIG_FILE) -> None:
        self.config_path = config_path
        ensure_directories()
        self.data: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)
        self.load()

    def load(self) -> dict[str, Any]:
        """Load configuration from disk or initialize defaults."""
        if not self.config_path.exists():
            self.save()
            return self.data

        try:
            raw = self.config_path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                merged = copy.deepcopy(DEFAULT_CONFIG)
                merged.update(parsed)
                self.data = merged
            else:
                self.data = copy.deepcopy(DEFAULT_CONFIG)
                self.save()
        except (OSError, json.JSONDecodeError):
            self.data = copy.deepcopy(DEFAULT_CONFIG)
            self.save()
        return self.data

    def save(self) -> None:
        """Persist current configuration to disk."""
        ensure_directories()
        self.config_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, raw_value: str) -> tuple[bool, str]:
        """Validate and set a configuration option."""
        if key not in DEFAULT_CONFIG:
            valid_keys = ", ".join(sorted(DEFAULT_CONFIG.keys()))
            return False, f"Unknown configuration key '{key}'. Valid keys: {valid_keys}"

        if key == "warroom_safe_mode" and raw_value.lower() in {"false", "0", "no", "off"}:
            return False, "warroom_safe_mode cannot be disabled; simulations remain strictly local and isolated."

        default_val = DEFAULT_CONFIG[key]
        try:
            if isinstance(default_val, bool):
                lowered = raw_value.strip().lower()
                if lowered in {"true", "1", "yes", "on"}:
                    parsed_val: Any = True
                elif lowered in {"false", "0", "no", "off"}:
                    parsed_val = False
                else:
                    return False, f"Invalid boolean value '{raw_value}' for '{key}'."
            elif isinstance(default_val, int):
                parsed_val = int(raw_value)
                if parsed_val <= 0:
                    return False, f"Value for '{key}' must be a positive integer."
                if key == "scan_threads" and parsed_val > 256:
                    return False, "scan_threads cannot exceed 256."
            elif isinstance(default_val, float):
                parsed_val = float(raw_value)
                if parsed_val <= 0:
                    return False, f"Value for '{key}' must be greater than 0."
            else:
                parsed_val = str(raw_value).strip()
                if key == "default_report_format" and parsed_val.lower() not in {"json", "txt", "csv", "pdf"}:
                    return False, "default_report_format must be 'json', 'txt', 'csv', or 'pdf'."
                if key == "log_level" and parsed_val.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
                    return False, "log_level must be DEBUG, INFO, WARNING, or ERROR."
                if key == "default_report_format":
                    parsed_val = parsed_val.lower()
                if key == "log_level":
                    parsed_val = parsed_val.upper()
        except ValueError:
            return False, f"Invalid value type '{raw_value}' for '{key}'."

        self.data[key] = parsed_val
        self.save()
        return True, f"Configuration updated: {key} = {parsed_val!r}"

    def reset(self) -> None:
        """Reset configuration back to defaults."""
        self.data = copy.deepcopy(DEFAULT_CONFIG)
        self.save()


class SecretsManager:
    """Securely stores optional API keys separate from config.json, history, and reports."""

    def __init__(self, secrets_path: Path = SECRETS_FILE) -> None:
        ensure_directories()
        self.secrets_path = secrets_path

    @staticmethod
    def _derive_mask_key() -> bytes:
        seed = f"BLACKVEIL-X::{platform.node()}::{os.environ.get('USERNAME') or os.environ.get('USER') or 'op'}"
        return hashlib.sha256(seed.encode("utf-8")).digest()

    @classmethod
    def _seal(cls, plaintext: str) -> str:
        raw = plaintext.encode("utf-8")
        key = cls._derive_mask_key()
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        return base64.urlsafe_b64encode(xored).decode("ascii")

    @classmethod
    def _unseal(cls, token: str) -> str:
        if not token:
            return ""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            key = cls._derive_mask_key()
            plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
            return plain.decode("utf-8")
        except Exception:
            return ""

    def _load_raw(self) -> dict[str, str]:
        if not self.secrets_path.exists():
            return {}
        try:
            parsed = json.loads(self.secrets_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except Exception:
            pass
        return {}

    def _save_raw(self, payload: dict[str, str]) -> None:
        self.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        self.secrets_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            if platform.system() != "Windows":
                os.chmod(self.secrets_path, 0o600)
        except OSError:
            pass

    def set_secret(self, name: str, value: str) -> None:
        cleaned = value.strip()
        data = self._load_raw()
        if not cleaned:
            data.pop(name, None)
        else:
            data[name] = self._seal(cleaned)
        self._save_raw(data)

    def get_secret(self, name: str, env_vars: tuple[str, ...] = ()) -> str:
        """Resolve secret from environment variables first, then restricted local store."""
        for env_key in env_vars:
            val = os.environ.get(env_key, "").strip()
            if val:
                return val
        raw = self._load_raw()
        token = raw.get(name, "")
        return self._unseal(token) if token else ""

    @staticmethod
    def mask_value(value: str) -> str:
        if not value:
            return "NOT SET"
        if len(value) <= 8:
            return "****"
        return f"{value[:4]}...****{value[-2:]}"


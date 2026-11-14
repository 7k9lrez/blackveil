"""Password Lab module: strength analysis, entropy, weakness detection, controlled test-hash audit, and generator."""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import string
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.config import DATA_DIR
from core.logger import BlackveilLogger
from modules.reports import ReportManager


class PasswordLabModule:
    """Offline password security analysis, controlled local test-hash auditing, and CSPRNG password generation."""

    KEYBOARD_SEQUENCES = ("qwerty", "asdfgh", "zxcvbn", "123456", "654321", "qazwsx", "1qaz2wsx")

    def __init__(self, console: Console, logger: BlackveilLogger, reports: ReportManager) -> None:
        self.console = console
        self.logger = logger
        self.reports = reports
        self.wordlist_path = DATA_DIR / "common_passwords.txt"

    def _load_wordlist(self) -> list[str]:
        if not self.wordlist_path.exists():
            return ["123456", "password", "admin", "qwerty", "letmein", "root"]
        try:
            return [line.strip() for line in self.wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        except OSError:
            return []

    def analyze_strength(self, password: str) -> dict[str, Any]:
        """Compute charset pool, Shannon/pool entropy, crack resistance estimate, and real weaknesses."""
        if not password:
            self.console.print("[bold red][-][/] Empty password provided.")
            return {}

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 33

        pool_entropy = round(len(password) * math.log2(max(pool_size, 1)), 2)

        # Effective character diversity (Shannon entropy over password chars)
        freq = {ch: password.count(ch) for ch in set(password)}
        shannon = -sum((cnt / len(password)) * math.log2(cnt / len(password)) for cnt in freq.values())
        effective_bits = round(shannon * len(password), 2)

        weaknesses: list[str] = []
        lowered = password.lower()
        common_words = set(w.lower() for w in self._load_wordlist())

        if len(password) < 8:
            weaknesses.append("Length under 8 characters (trivially brute-forced).")
        elif len(password) < 12:
            weaknesses.append("Length under 12 characters (recommended minimum: 14+ chars).")

        if lowered in common_words:
            weaknesses.append("Exact match found in common breached/default password dictionary.")
        else:
            for word in common_words:
                if len(word) >= 5 and word in lowered:
                    weaknesses.append(f"Contains common dictionary token ('{word}').")
                    break

        for seq in self.KEYBOARD_SEQUENCES:
            if seq in lowered:
                weaknesses.append(f"Contains predictable keyboard/numeric sequence ('{seq}').")
                break

        if re.search(r"(.)\1{2,}", password):
            weaknesses.append("Contains 3+ repeated identical characters.")

        if re.search(r"(?:19\d\d|20[0-2]\d)", password):
            weaknesses.append("Contains likely year pattern (19xx/20xx).")

        classes_count = sum([has_lower, has_upper, has_digit, has_symbol])
        if classes_count < 3:
            weaknesses.append("Low character-class diversity (mix uppercase, lowercase, digits, and symbols).")

        # Score 0-100
        score = min(100, int(pool_entropy * 1.15))
        score -= len(weaknesses) * 14
        score = max(0, min(100, score))

        if score >= 80 and len(password) >= 14:
            rating = "STRONG"
            rating_style = "bold bright_green"
        elif score >= 55:
            rating = "MODERATE"
            rating_style = "bold yellow"
        else:
            rating = "WEAK / CRITICAL"
            rating_style = "bold red"

        # Conservative offline GPU rate estimate (~10^10 SHA256/sec)
        combinations = max(pool_size, 1) ** len(password)
        seconds_to_exhaust = combinations / 1e10
        crack_est = self._humanize_duration(seconds_to_exhaust)

        table = Table(
            title="[bold bright_green]PASSWORD LAB // ENTROPY & WEAKNESS AUDIT[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            show_header=False,
        )
        table.add_column("Metric", style="grey70", width=24)
        table.add_column("Result", style="white")

        masked = password[0] + "*" * max(0, len(password) - 2) + (password[-1] if len(password) > 1 else "")
        table.add_row("Sample (Masked)", masked)
        table.add_row("Length", f"{len(password)} characters")
        table.add_row("Charset Pool Size", f"{pool_size} symbols ({classes_count}/4 classes)")
        table.add_row("Pool Entropy", f"[bright_green]{pool_entropy} bits[/]")
        table.add_row("Shannon Total Bits", f"{effective_bits} bits")
        table.add_row("Security Score", f"[{rating_style}]{score}/100 ({rating})[/]")
        table.add_row("Offline Brute Estimate", crack_est)
        self.console.print(table)

        if weaknesses:
            self.console.print(
                Panel(
                    "\n".join(f"[bold red][!][/] {w}" for w in weaknesses),
                    title="[bold red]DETECTED WEAKNESSES[/]",
                    border_style="red",
                    box=box.SQUARE,
                )
            )
        else:
            self.console.print("[bold bright_green][+][/] No structural weaknesses or dictionary patterns detected.")

        result = {
            "length": len(password),
            "pool_size": pool_size,
            "pool_entropy_bits": pool_entropy,
            "shannon_bits": effective_bits,
            "score": score,
            "rating": rating,
            "weaknesses": weaknesses,
            "offline_exhaust_estimate": crack_est,
        }
        self.reports.record("PASSWORD_AUDIT", "Password Strength & Entropy Analysis", result, severity="WARNING" if weaknesses else "INFO")
        return result

    @staticmethod
    def _humanize_duration(seconds: float) -> str:
        if seconds < 1:
            return "< 1 second (Instant)"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f} minutes"
        hours = minutes / 60
        if hours < 24:
            return f"{hours:.1f} hours"
        days = hours / 24
        if days < 365:
            return f"{days:.1f} days"
        years = days / 365.25
        if years > 1e9:
            return f"{years:.2e} years"
        return f"{years:,.1f} years"

    def generate_secure_password(self, length: int = 20, count: int = 3) -> list[str]:
        """Generate cryptographically secure passwords via Python secrets."""
        length = max(8, min(128, length))
        count = max(1, min(20, count))
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{}?"

        generated: list[str] = []
        for _ in range(count):
            # Guarantee at least one character from each class
            chars = [
                secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits),
                secrets.choice("!@#$%^&*()-_=+"),
            ]
            chars.extend(secrets.choice(alphabet) for _ in range(length - 4))
            secrets.SystemRandom().shuffle(chars)
            generated.append("".join(chars))

        table = Table(
            title=f"[bold bright_green]CSPRNG PASSWORD GENERATOR ({length} CHARS)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("#", style="grey70", width=4)
        table.add_column("Generated Secret", style="bold bright_green")
        table.add_column("Entropy", style="white", justify="right")

        bits = round(length * math.log2(len(alphabet)), 2)
        for idx, pw in enumerate(generated, start=1):
            table.add_row(str(idx), pw, f"{bits} bits")

        self.console.print(table)
        return generated

    def run_controlled_dictionary_test(self, test_password: str | None = None) -> dict[str, Any]:
        """
        Generate a temporary self-created SHA-256 test hash in memory and run a controlled
        dictionary audit against data/common_passwords.txt to demonstrate password resilience.
        """
        wordlist = self._load_wordlist()
        target_plain = test_password if test_password else "letmein123"
        target_hash = hashlib.sha256(target_plain.encode("utf-8")).hexdigest()

        self.console.print(
            Panel(
                f"[white]Target Hash (Self-Generated Lab Artifact):[/]\n[bright_green]{target_hash}[/]\n"
                f"[grey70]Algorithm: SHA-256 (Unsalted demonstration) | Dictionary Size: {len(wordlist)} entries[/]",
                title="[bold bright_green]PASSWORD LAB // CONTROLLED DICTIONARY AUDIT[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        start = time.perf_counter()
        cracked_value: str | None = None
        attempts = 0

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bright_green]{task.description}"),
            BarColumn(bar_width=30, complete_style="bright_green"),
            TextColumn("[white]{task.completed}/{task.total}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Auditing test hash", total=len(wordlist))
            for candidate in wordlist:
                attempts += 1
                digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                progress.advance(task)
                if digest == target_hash:
                    cracked_value = candidate
                    break

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        if cracked_value is not None:
            self.console.print(
                f"[bold red][!] MATCH FOUND[/] in {attempts} attempts ({elapsed_ms} ms): "
                f"Plaintext = '[white]{cracked_value}[/]'.\n"
                f"[grey70]Lesson: Unsalted fast hashes (SHA-256/MD5) of dictionary words fall immediately; use Argon2id/bcrypt + strong passphrases.[/]"
            )
        else:
            self.console.print(
                f"[bold bright_green][+] RESISTED DICTIONARY[/] across {attempts} entries ({elapsed_ms} ms)."
            )

        result = {
            "target_hash": target_hash,
            "dictionary_size": len(wordlist),
            "attempts": attempts,
            "matched": cracked_value is not None,
            "elapsed_ms": elapsed_ms,
        }
        self.reports.record("PASSWORD_DICT_TEST", "Controlled Lab Dictionary Audit", result)
        return result

"""Module 20: External Intelligence Search Engine - Multi-source API search, ranking, deep citations & Opera check."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ai.analyst import AISecurityAnalyst
from core.config import ConfigManager, SecretsManager
from core.logger import BlackveilLogger
from database.db import DatabaseManager, utc_now
from modules.reports import ReportManager


class _ReadableTextExtractor(HTMLParser):
    """Extracts clean readable body text and title from accessible web pages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = False
        self._in_title = False
        self.title: list[str] = []
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t in {"script", "style", "noscript", "svg"}:
            self._skip = True
        elif t == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in {"script", "style", "noscript", "svg"}:
            self._skip = False
        elif t == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self._in_title:
            self.title.append(cleaned)
        elif not self._skip:
            self.chunks.append(cleaned)

    def get_text(self, limit: int = 2500) -> str:
        return " ".join(self.chunks)[:limit]


class ExternalSearchModule:
    """Legitimate multi-source API search, deduplication, relevance ranking, cited deep summaries & Opera check."""

    SOURCE_WEIGHTS = {
        "Google CSE": 1.3,
        "NVD CVE": 1.25,
        "GitHub": 1.15,
        "StackExchange": 1.15,
        "Wikipedia": 1.05,
        "DuckDuckGo API": 1.0,
        "Direct URL": 1.1,
    }

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        secrets: SecretsManager,
        db: DatabaseManager,
        ai_analyst: AISecurityAnalyst,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.secrets = secrets
        self.db = db
        self.ai_analyst = ai_analyst
        self.reports = reports

    @staticmethod
    def detect_opera_browser() -> dict[str, Any]:
        """Accurately check whether Opera browser is genuinely installed on the OS."""
        which_path = shutil.which("opera")
        if which_path:
            return {"installed": True, "path": which_path, "method": "PATH lookup"}

        sys_name = platform.system()
        candidates: list[Path] = []
        if sys_name == "Windows":
            local_app = os.environ.get("LOCALAPPDATA", "")
            prog_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
            prog_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
            if local_app:
                candidates.append(Path(local_app) / "Programs" / "Opera" / "opera.exe")
                candidates.append(Path(local_app) / "Programs" / "Opera GX" / "opera.exe")
            candidates.append(Path(prog_files) / "Opera" / "opera.exe")
            candidates.append(Path(prog_x86) / "Opera" / "opera.exe")
        elif sys_name == "Darwin":
            candidates.append(Path("/Applications/Opera.app/Contents/MacOS/Opera"))
        else:
            candidates.extend([Path("/usr/bin/opera"), Path("/usr/local/bin/opera"), Path("/snap/bin/opera")])

        for cand in candidates:
            if cand.exists() and cand.is_file():
                return {"installed": True, "path": str(cand), "method": "Filesystem check"}

        return {"installed": False, "path": "", "method": "OS executable & standard install paths checked"}

    @staticmethod
    def _http_json(url: str, timeout: float = 7.0) -> dict[str, Any] | None:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "BLACKVEIL-X-Search/1.0", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _search_google_cse(self, query: str) -> tuple[list[dict[str, Any]], str | None]:
        api_key = self.secrets.get_secret("google_cse_api_key", ("GOOGLE_CSE_API_KEY",))
        cx = self.secrets.get_secret("google_cse_cx", ("GOOGLE_CSE_CX",)) or str(self.config.get("google_cse_cx", "")).strip()
        if not api_key or not cx:
            return [], "Google Custom Search skipped: GOOGLE_CSE_API_KEY and GOOGLE_CSE_CX not configured."
        url = (
            "https://www.googleapis.com/customsearch/v1"
            f"?key={urllib.parse.quote(api_key)}&cx={urllib.parse.quote(cx)}&q={urllib.parse.quote(query)}&num=6"
        )
        data = self._http_json(url)
        if not data:
            return [], "Google Custom Search request failed or returned empty response."
        items: list[dict[str, Any]] = []
        for it in data.get("items", []):
            items.append(
                {
                    "title": it.get("title", ""),
                    "url": it.get("link", ""),
                    "snippet": it.get("snippet", ""),
                    "source": "Google CSE",
                    "date": "-",
                }
            )
        return items, None

    def _search_github(self, query: str) -> list[dict[str, Any]]:
        url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&sort=stars&order=desc&per_page=5"
        data = self._http_json(url)
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for repo in data.get("items", []):
            out.append(
                {
                    "title": f"{repo.get('full_name', '')} (*{repo.get('stargazers_count', 0)})",
                    "url": repo.get("html_url", ""),
                    "snippet": repo.get("description") or "No repository description.",
                    "source": "GitHub",
                    "date": str(repo.get("updated_at", ""))[:10] or "-",
                }
            )
        return out

    def _search_stackexchange(self, query: str) -> list[dict[str, Any]]:
        url = (
            "https://api.stackexchange.com/2.3/search/advanced"
            f"?order=desc&sort=relevance&site=stackoverflow&q={urllib.parse.quote(query)}&pagesize=5"
        )
        data = self._http_json(url)
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for q in data.get("items", []):
            ts = q.get("creation_date")
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
            out.append(
                {
                    "title": q.get("title", ""),
                    "url": q.get("link", ""),
                    "snippet": f"Score={q.get('score', 0)}, Answers={q.get('answer_count', 0)}, Tags={','.join(q.get('tags', [])[:4])}",
                    "source": "StackExchange",
                    "date": dt,
                }
            )
        return out

    def _search_nvd_cve(self, query: str) -> list[dict[str, Any]]:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=4"
        data = self._http_json(url, timeout=8.0)
        if not data:
            return []
        out: list[dict[str, Any]] = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id", "")
            descs = [d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"]
            out.append(
                {
                    "title": cid,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                    "snippet": (descs[0][:180] if descs else "NVD CVE record"),
                    "source": "NVD CVE",
                    "date": str(cve.get("published", ""))[:10] or "-",
                }
            )
        return out

    def _search_wikipedia_and_ddg(self, query: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        wiki_url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={urllib.parse.quote(query)}&limit=4&namespace=0&format=json"
        req = urllib.request.Request(wiki_url, headers={"User-Agent": "BLACKVEIL-X-Search/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
            if isinstance(parsed, list) and len(parsed) >= 4:
                titles, descs, links = parsed[1], parsed[2], parsed[3]
                for t, d, lk in zip(titles, descs, links):
                    out.append({"title": t, "url": lk, "snippet": d or "Wikipedia reference", "source": "Wikipedia", "date": "-"})
        except Exception:
            pass

        ddg = self._http_json(f"https://api.duckduckgo.com/?q={urllib.parse.quote(query)}&format=json&no_html=1&skip_disambig=1")
        if ddg:
            if ddg.get("AbstractURL") and ddg.get("AbstractText"):
                out.append(
                    {
                        "title": ddg.get("Heading") or query,
                        "url": ddg["AbstractURL"],
                        "snippet": str(ddg["AbstractText"])[:200],
                        "source": "DuckDuckGo API",
                        "date": "-",
                    }
                )
            for topic in ddg.get("RelatedTopics", [])[:4]:
                if isinstance(topic, dict) and topic.get("FirstURL") and topic.get("Text"):
                    out.append(
                        {
                            "title": str(topic["Text"]).split(" - ", 1)[0][:80],
                            "url": topic["FirstURL"],
                            "snippet": str(topic["Text"])[:180],
                            "source": "DuckDuckGo API",
                            "date": "-",
                        }
                    )
        return out

    @staticmethod
    def _fetch_accessible_page_text(url: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"User-Agent": "BLACKVEIL-X-DeepInspector/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=7.0) as resp:
                ctype = resp.headers.get("Content-Type", "").lower()
                raw = resp.read(200_000).decode("utf-8", errors="replace")
            if "json" in ctype or "text/plain" in ctype:
                return {"ok": True, "url": url, "text": " ".join(raw.split())[:2200]}
            parser = _ReadableTextExtractor()
            parser.feed(raw)
            return {"ok": True, "url": url, "title": " ".join(parser.title), "text": parser.get_text(2200)}
        except Exception as exc:
            return {"ok": False, "url": url, "error": str(exc), "text": ""}

    def _dedup_and_rank(self, query: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        terms = [t for t in re.findall(r"[a-zA-Z0-9_-]{2,}", query.lower())]
        seen_urls: set[str] = set()
        ranked: list[dict[str, Any]] = []

        for item in items:
            url = item.get("url", "").strip()
            if not url:
                continue
            norm = url.rstrip("/").lower()
            if norm in seen_urls:
                continue
            seen_urls.add(norm)

            haystack = f"{item.get('title', '')} {item.get('snippet', '')}".lower()
            term_hits = sum(1 for t in terms if t in haystack)
            weight = self.SOURCE_WEIGHTS.get(item.get("source", ""), 1.0)
            score = round((term_hits * 10 + 5) * weight, 2)
            enriched = dict(item)
            enriched["relevance_score"] = score
            ranked.append(enriched)

        ranked.sort(key=lambda r: r["relevance_score"], reverse=True)
        return ranked

    def search(
        self,
        query: str,
        mode: str = "multi",
        urls: list[str] | None = None,
        open_opera: bool = False,
        export_fmt: str | None = None,
    ) -> dict[str, Any]:
        """Run multi-source search, compare sources, optionally inspect pages & cite via Gemini."""
        q = query.strip()
        if not q and not urls:
            self.console.print("[bold red][-][/] Provide a search query.")
            return {}

        opera_info = self.detect_opera_browser()
        raw_results: list[dict[str, Any]] = []
        notes: list[str] = []

        with self.console.status(f"[bold bright_green][*] Querying external intelligence sources for '{q}'...[/]", spinner="dots"):
            if mode == "google":
                g_res, g_note = self._search_google_cse(q)
                raw_results.extend(g_res)
                if g_note:
                    notes.append(g_note)
            else:
                g_res, g_note = self._search_google_cse(q)
                raw_results.extend(g_res)
                if g_note:
                    notes.append(g_note)
                raw_results.extend(self._search_github(q))
                raw_results.extend(self._search_stackexchange(q))
                raw_results.extend(self._search_wikipedia_and_ddg(q))
                if any(k in q.lower() for k in ("cve", "vuln", "exploit", "security", "openssl", "kernel", "ssh")):
                    raw_results.extend(self._search_nvd_cve(q))

            if urls:
                for u in urls:
                    raw_results.append({"title": u, "url": u, "snippet": "Operator-supplied reference URL", "source": "Direct URL", "date": "-"})

            ranked = self._dedup_and_rank(q or "reference", raw_results)

            deep_extracts: list[dict[str, Any]] = []
            if mode in {"deep", "sources"} and ranked:
                for idx, r in enumerate(ranked[:5], start=1):
                    ext = self._fetch_accessible_page_text(r["url"])
                    ext["rank"] = idx
                    ext["source"] = r["source"]
                    ext["title"] = r["title"]
                    if ext.get("ok") and ext.get("text"):
                        deep_extracts.append(ext)

            ai_summary = ""
            if mode == "deep" and deep_extracts:
                context_blocks = "\n\n".join(
                    f"[Source {e['rank']} | {e['source']} | {e['url']}]\n{e['text'][:1400]}"
                    for e in deep_extracts
                )
                ok, text = self.ai_analyst._call_gemini(
                    f"Summarize only the retrieved external source excerpts for query '{q}'. "
                    f"Every factual claim MUST include an inline citation like [Source 1]. "
                    f"Highlight points where sources agree or differ.\n\n{context_blocks}"
                )
                if ok:
                    ai_summary = text
                else:
                    notes.append(f"Gemini deep summary unavailable ({text}); displaying retrieved excerpts directly.")

        # Render terminal results
        table = Table(
            title=f"[bold bright_green]EXTERNAL INTELLIGENCE SEARCH // '{q}' ({len(ranked)} RESULTS)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("#", width=3, justify="right", style="grey70")
        table.add_column("Source", width=15, style="bright_green")
        table.add_column("Date", width=11, style="grey70")
        table.add_column("Title & URL / Snippet", style="white")

        for idx, r in enumerate(ranked[:18], start=1):
            table.add_row(
                str(idx),
                r["source"],
                r["date"],
                f"[bold white]{r['title'][:90]}[/]\n[bright_green]{r['url']}[/]\n[grey70]{r['snippet'][:150]}[/]",
            )
        if ranked:
            self.console.print(table)
        else:
            self.console.print("[yellow][!][/] No external results returned (check network access or optional API keys).")

        if mode == "sources" and ranked:
            by_src: dict[str, int] = {}
            for r in ranked:
                by_src[r["source"]] = by_src.get(r["source"], 0) + 1
            self.console.print(
                Panel(
                    "\n".join(f"[bright_green]{src}[/]: {cnt} result(s)" for src, cnt in by_src.items()),
                    title="[bold bright_green]SOURCE COVERAGE COMPARISON[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )

        if deep_extracts and not ai_summary:
            for e in deep_extracts[:3]:
                self.console.print(
                    Panel(
                        f"[bright_green]{e['url']}[/]\n[grey70]{e['text'][:550]}...[/]",
                        title=f"[bold bright_green]RETRIEVED EXCERPT [Source {e['rank']} - {e['source']}][/]",
                        border_style="bright_green",
                        box=box.SQUARE,
                    )
                )

        if ai_summary:
            self.console.print(
                Panel(
                    ai_summary,
                    title="[bold bright_green]CITED DEEP INTELLIGENCE SYNTHESIS (GEMINI)[/]",
                    border_style="bright_green",
                    box=box.SQUARE,
                )
            )

        opera_line = (
            f"[bright_green]INSTALLED[/] ({opera_info['path']})"
            if opera_info["installed"]
            else "[grey70]NOT INSTALLED on this OS[/]"
        )
        self.console.print(
            Panel(
                f"[white]Opera Browser :[/] {opera_line}\n"
                f"[white]Notices       :[/] [grey70]{' | '.join(notes) if notes else 'All active public APIs queried cleanly.'}[/]",
                title="[bold bright_green]SEARCH ENVIRONMENT & CITATION STATUS[/]",
                border_style="bright_green",
                box=box.SQUARE,
            )
        )

        if open_opera and ranked:
            if opera_info["installed"]:
                try:
                    subprocess.Popen([opera_info["path"], ranked[0]["url"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.console.print(f"[bright_green][+][/] Opened top result in Opera: {ranked[0]['url']}")
                except Exception as exc:
                    self.console.print(f"[bold red][-][/] Failed to launch Opera: {exc}")
            else:
                self.console.print("[yellow][!][/] Cannot open Opera: Opera browser is not installed on this system.")

        payload = {
            "query": q,
            "mode": mode,
            "result_count": len(ranked),
            "results": ranked[:25],
            "deep_extracts": deep_extracts,
            "cited_summary": ai_summary or None,
            "opera": opera_info,
            "notices": notes,
            "searched_at": utc_now(),
        }
        try:
            with self.db.connection() as conn:
                conn.execute(
                    "INSERT INTO external_search_history (id, query, sources_json, result_count, searched_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        f"SRC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                        q,
                        json.dumps(sorted({r["source"] for r in ranked})),
                        len(ranked),
                        payload["searched_at"],
                    ),
                )
        except Exception:
            pass

        self.reports.record("EXTERNAL_SEARCH", f"External Search ({mode}): {q}", payload)
        if export_fmt:
            self.reports.export_report(export_format=export_fmt, export_all=False)
        return payload

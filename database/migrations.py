"""Ordered SQLite schema migrations for BLACKVEIL X."""

from __future__ import annotations

MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "initial_ecosystem_schema",
        """
        CREATE TABLE IF NOT EXISTS sandboxes (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            container_id TEXT,
            image TEXT NOT NULL,
            status TEXT NOT NULL,
            isolated INTEGER NOT NULL DEFAULT 0,
            cpu_limit TEXT NOT NULL,
            memory_limit TEXT NOT NULL,
            disk_limit TEXT,
            pids_limit INTEGER NOT NULL DEFAULT 64,
            network_mode TEXT NOT NULL DEFAULT 'none',
            timeout_minutes INTEGER NOT NULL DEFAULT 60,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            last_verified_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS sandbox_snapshots (
            id TEXT PRIMARY KEY,
            sandbox_id TEXT NOT NULL,
            snapshot_name TEXT NOT NULL,
            image_tag TEXT NOT NULL,
            created_at TEXT NOT NULL,
            notes TEXT DEFAULT '',
            FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sandbox_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sandbox_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT 'operator',
            details TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS missions_progress (
            mission_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'AVAILABLE',
            xp_awarded INTEGER NOT NULL DEFAULT 0,
            started_at TEXT,
            completed_at TEXT,
            attempts INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS operator_profile (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            codename TEXT NOT NULL DEFAULT 'BLACKVEIL_OP',
            xp INTEGER NOT NULL DEFAULT 0,
            level INTEGER NOT NULL DEFAULT 1,
            rank_title TEXT NOT NULL DEFAULT 'Initiate Analyst',
            missions_completed INTEGER NOT NULL DEFAULT 0,
            ctf_solved INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS achievements (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            xp_bonus INTEGER NOT NULL DEFAULT 0,
            unlocked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL,
            status_code INTEGER NOT NULL DEFAULT 0,
            executed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id TEXT PRIMARY KEY,
            source_module TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reports_index (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            format TEXT NOT NULL,
            file_path TEXT,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS plugins_registry (
            name TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            author TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            permissions_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            file_path TEXT NOT NULL,
            installed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS automation_playbooks (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL,
            commands_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_run_at TEXT
        );

        CREATE TABLE IF NOT EXISTS automation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            FOREIGN KEY (playbook_id) REFERENCES automation_playbooks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS lab_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_type TEXT NOT NULL,
            lab_id TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            details_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        "vault_incidents_baselines_kb_sessions",
        """
        CREATE TABLE IF NOT EXISTS integrity_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_name TEXT NOT NULL,
            root_path TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mtime REAL NOT NULL,
            captured_at TEXT NOT NULL,
            UNIQUE(baseline_name, file_path)
        );

        CREATE TABLE IF NOT EXISTS evidence_vault (
            id TEXT PRIMARY KEY,
            original_path TEXT NOT NULL,
            vault_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            sha512 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            collector TEXT NOT NULL,
            description TEXT NOT NULL,
            custody_log_json TEXT NOT NULL,
            sealed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_baselines (
            name TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            assignee TEXT NOT NULL DEFAULT 'SOC_ANALYST',
            timeline_json TEXT NOT NULL,
            artifacts_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            closed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS knowledge_base (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            tags TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ctf_challenges (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            points INTEGER NOT NULL,
            solved INTEGER NOT NULL DEFAULT 0,
            solved_at TEXT,
            attempts INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS terminal_sessions (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            command_count INTEGER NOT NULL DEFAULT 0,
            file_path TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vuln_labs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NOT_INSTALLED',
            container_or_path TEXT,
            installed_at TEXT,
            solved INTEGER NOT NULL DEFAULT 0
        );
        """,
    ),
    (
        3,
        "advanced_intel_expansion",
        """
        CREATE TABLE IF NOT EXISTS website_scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            http_status INTEGER,
            tls_verified INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS local_websites (
            id TEXT PRIMARY KEY,
            source_url TEXT NOT NULL,
            host TEXT NOT NULL,
            local_dir TEXT NOT NULL,
            port INTEGER,
            files_count INTEGER NOT NULL DEFAULT 0,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            stopped_at TEXT
        );

        CREATE TABLE IF NOT EXISTS ai_chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            model TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS file_index (
            path TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            ext TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mtime REAL NOT NULL,
            sha256 TEXT DEFAULT '',
            indexed_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_file_index_name ON file_index(name);
        CREATE INDEX IF NOT EXISTS idx_file_index_ext ON file_index(ext);

        CREATE TABLE IF NOT EXISTS external_search_history (
            id TEXT PRIMARY KEY,
            query TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            result_count INTEGER NOT NULL DEFAULT 0,
            searched_at TEXT NOT NULL
        );
        """,
    ),
]

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use std::path::Path;
use thiserror::Error;

pub type DbPool = Pool<SqliteConnectionManager>;
pub type DbConn = r2d2::PooledConnection<SqliteConnectionManager>;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Pool creation failed: {0}")]
    Pool(String),
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Schema error: {0}")]
    Schema(String),
}

/// Initialize the database: create pool, schema, migrations, indexes, seed data
pub fn init_database(db_path: &str) -> anyhow::Result<DbPool> {
    // Ensure parent directory exists
    let path = Path::new(db_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Create connection manager
    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
        .with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA busy_timeout=5000;",
            )
            .ok();
            Ok(())
        });

    let pool = Pool::builder()
        .max_size(8)
        .build(manager)
        .map_err(|e| DbError::Pool(e.to_string()))?;

    // Create schema
    {
        let conn = pool.get().map_err(|e| DbError::Connection(e.to_string()))?;
        create_schema(&conn)?;
        run_migrations(&conn)?;
        create_indexes(&conn)?;
    }

    tracing::info!("[DB] Database initialized at {}", db_path);
    Ok(pool)
}

fn create_schema(conn: &rusqlite::Connection) -> Result<(), DbError> {
    let statements = [
        // CVE entries
        r#"CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            cvss_severity TEXT NOT NULL,
            cvss_vector TEXT,
            attack_vector TEXT,
            attack_complexity TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            scope TEXT,
            confidentiality_impact TEXT,
            integrity_impact TEXT,
            availability_impact TEXT,
            cwe_id TEXT,
            affected_product TEXT,
            affected_versions TEXT,
            patched_version TEXT,
            remediation TEXT,
            "references" TEXT,
            published_date TEXT,
            last_modified TEXT,
            is_web_vuln INTEGER DEFAULT 1,
            tags TEXT
        )"#,
        // Security events
        r#"CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            attack_type TEXT,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            destination TEXT NOT NULL,
            method TEXT,
            path TEXT,
            payload TEXT,
            user_agent TEXT,
            rule_id TEXT,
            rule_name TEXT,
            rule_description TEXT,
            matched_pattern TEXT,
            matched_cve TEXT,
            action TEXT DEFAULT 'log',
            status TEXT DEFAULT 'active',
            blocked INTEGER DEFAULT 0,
            org_id TEXT
        )"#,
        // IDS rules
        r#"CREATE TABLE IF NOT EXISTS ids_rules (
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT NOT NULL,
            rule_description TEXT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            pattern TEXT NOT NULL,
            pattern_flags TEXT,
            related_cve TEXT,
            action TEXT DEFAULT 'alert',
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )"#,
        // Alerts
        r#"CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            alert_time TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            org_id TEXT,
            FOREIGN KEY (event_id) REFERENCES security_events(id)
        )"#,
        // IP reputation
        r#"CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address TEXT PRIMARY KEY,
            reputation_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'unknown',
            country TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_events INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0,
            notes TEXT,
            org_id TEXT
        )"#,
        // Organizations
        r#"CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            plan TEXT DEFAULT 'free',
            max_users INTEGER DEFAULT 5,
            created_at TEXT DEFAULT (datetime('now')),
            settings TEXT DEFAULT '{}'
        )"#,
        // Users
        r#"CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            status TEXT DEFAULT 'active',
            last_login TEXT,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (org_id) REFERENCES organizations(id),
            UNIQUE(org_id, email)
        )"#,
        // API keys
        r#"CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            permissions TEXT DEFAULT 'read',
            last_used TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )"#,
        // Audit logs
        r#"CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            user_id TEXT,
            user_email TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )"#,
        // Incidents
        r#"CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            event_ids TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            resolved_at TEXT,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )"#,
        // Notifications
        r#"CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            user_id TEXT,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            data TEXT,
            read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )"#,
    ];

    for sql in &statements {
        conn.execute(sql, [])
            .map_err(|e| DbError::Schema(format!("{}: {}", e, sql.lines().next().unwrap_or(""))))?;
    }

    Ok(())
}

fn run_migrations(conn: &rusqlite::Connection) -> Result<(), DbError> {
    let migrations = [
        "ALTER TABLE security_events ADD COLUMN attack_type TEXT",
        "ALTER TABLE security_events ADD COLUMN org_id TEXT",
        "ALTER TABLE alerts ADD COLUMN org_id TEXT",
        "ALTER TABLE ip_reputation ADD COLUMN org_id TEXT",
        // Account lockout (Task #26). Safe to re-run: duplicate-column errors are ignored.
        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN locked_until INTEGER",
    ];

    for sql in &migrations {
        match conn.execute(sql, []) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.extended_code == 1 /* SQLITE_ERROR duplicate column */ => {}
            Err(e) => tracing::warn!("[DB] Migration skipped: {} - {}", e, sql),
        }
    }

    Ok(())
}

fn create_indexes(conn: &rusqlite::Connection) -> Result<(), DbError> {
    let indexes = [
        "CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(cvss_severity)",
        "CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_entries(affected_product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe ON cve_entries(cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_rule ON security_events(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_cve ON security_events(matched_cve)",
        "CREATE INDEX IF NOT EXISTS idx_events_org ON security_events(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_iprep_org ON ip_reputation(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_notif_org ON notifications(org_id)",
    ];

    for sql in &indexes {
        conn.execute(sql, []).ok();
    }

    Ok(())
}

/// Helper to get a connection from the pool
pub fn get_conn(pool: &DbPool) -> anyhow::Result<DbConn> {
    pool.get()
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))
}

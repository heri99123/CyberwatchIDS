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
        seed_defaults(&conn)?;
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
            key_hash TEXT,
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
        // Scheduled report delivery ledger (Task #31). The UNIQUE constraint
        // makes "once per org, per report kind, per day" atomic even when the
        // scheduler restarts mid-hour.
        r#"CREATE TABLE IF NOT EXISTS report_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            report_kind TEXT NOT NULL,
            period_key TEXT NOT NULL,
            recipients TEXT,
            rows_count INTEGER DEFAULT 0,
            sent_at TEXT DEFAULT (datetime('now')),
            UNIQUE(org_id, report_kind, period_key)
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
        // API key hashes (Task #29). Keys created before this migration have
        // NULL key_hash and must be rotated — they were never verifiable.
        "ALTER TABLE api_keys ADD COLUMN key_hash TEXT",
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
        "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)",
        "CREATE INDEX IF NOT EXISTS idx_report_runs_org ON report_runs(org_id)",
    ];

    for sql in &indexes {
        conn.execute(sql, []).ok();
    }

    Ok(())
}

/// Seed built-in IDS rules on a fresh database (Task #29 prerequisite).
///
/// Before this existed, `ids_rules` was created empty: a fresh Docker/VPS
/// deployment loaded 0 rules, so real traffic produced zero detections. The
/// patterns below are the exact 27 rules from the original deployment.
/// `INSERT OR IGNORE` keeps user-modified / disabled rules intact on upgrades.
fn seed_defaults(conn: &rusqlite::Connection) -> Result<(), DbError> {
    // (rule_id, name, description, attack_type, severity, pattern, flags, cve, action)
    const RULES: &[(&str, &str, &str, &str, &str, &str, &str, Option<&str>, &str)] = &[
        ("IDS-001", "SQL Injection - UNION SELECT", "Detects UNION-based SQL injection attempts in parameters", "SQL Injection", "CRITICAL", r#"(?i)(union\s*select|union\s+all\s+select)"#, "i", Some("CVE-2012-2122"), "block"),
        ("IDS-002", "SQL Injection - Boolean Blind", "Detects boolean-based blind SQL injection (AND 1=1 / OR 1=1)", "SQL Injection", "HIGH", r#"(?i)(\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1|\bor\s+1\s*=\s*2|\band\s+1\s*=\s*2)"#, "i", Some("CVE-2012-2122"), "block"),
        ("IDS-003", "SQL Injection - Time-based", "Detects time-based blind SQL injection using SLEEP/BENCHMARK", "SQL Injection", "HIGH", r#"(?i)(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)"#, "i", Some("CVE-2012-2122"), "block"),
        ("IDS-004", "SQL Injection - Stacked Queries", "Detects stacked SQL queries with semicolons", "SQL Injection", "HIGH", r#"(?i)(;\s*(drop|insert|update|delete|exec|execute)\s)"#, "i", Some("CVE-2012-2122"), "block"),
        ("IDS-005", "SQL Injection - Error-based", "Detects error-based SQL injection extraction patterns", "SQL Injection", "HIGH", r#"(?i)(extractvalue\s*\(|updatexml\s*\(|convert\s*\(|floor\s*\(\s*rand\s*\()"#, "i", Some("CVE-2012-2122"), "alert"),
        ("IDS-010", "XSS - Script Tag Injection", "Detects <script> tag injection attempts", "Cross-Site Scripting (XSS)", "HIGH", r#"(?i)<\s*script[^>]*>|<\s*/\s*script\s*>"#, "i", None, "block"),
        ("IDS-011", "XSS - Event Handler", "Detects XSS via inline event handlers (onerror, onload, etc.)", "Cross-Site Scripting (XSS)", "HIGH", r#"(?i)(on(error|load|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*=)"#, "i", None, "block"),
        ("IDS-012", "XSS - JavaScript URI", "Detects javascript: URI scheme in attributes", "Cross-Site Scripting (XSS)", "HIGH", r#"(?i)javascript\s*:"#, "i", None, "block"),
        ("IDS-013", "XSS - SVG Embed", "Detects XSS via SVG onload / SVG use tag", "Cross-Site Scripting (XSS)", "HIGH", r#"(?i)<\s*svg[^>]*onload|<\s*use\s"#, "i", None, "block"),
        ("IDS-014", "XSS - Data URI", "Detects XSS via data: URI scheme with text/html", "Cross-Site Scripting (XSS)", "MEDIUM", r#"(?i)data\s*:[^;]*;base64"#, "i", None, "alert"),
        ("IDS-020", "Path Traversal - Dot-Dot-Slash", "Detects directory traversal via ../ or ..\\", "Path Traversal", "HIGH", r#"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%2e%2e\\|%2e%2e%5c)"#, "i", Some("CVE-2020-3452"), "block"),
        ("IDS-021", "Path Traversal - Absolute Path", "Detects absolute path access attempts (Linux /etc/passwd, Windows C:\\\\)", "Path Traversal", "HIGH", r#"(?i)(/etc/passwd|/etc/shadow|/proc/self|c:\\windows\\system32|c:\\windows\\win\.ini)"#, "i", Some("CVE-2010-2861"), "block"),
        ("IDS-022", "Path Traversal - Null Byte", "Detects null byte injection for path truncation", "Path Traversal", "HIGH", r#"(%00|\x00|0x00)"#, "i", None, "block"),
        ("IDS-030", "Command Injection - Shell Metacharacters", "Detects OS command injection via shell metacharacters", "Command Injection", "CRITICAL", r#"([|;&`$]\s*(cat|ls|id|whoami|uname|ping|wget|curl|nc|bash|sh|cmd|powershell)\s)"#, "i", Some("CVE-2017-5638"), "block"),
        ("IDS-031", "Command Injection - Backtick Substitution", "Detects backtick command substitution", "Command Injection", "HIGH", r#"(`[^`]+`|\$\([^)]+\))"#, "", None, "block"),
        ("IDS-032", "Command Injection - PowerShell", "Detects PowerShell command injection patterns", "Command Injection", "CRITICAL", r#"(?i)(powershell\s|invoke-|iex\s|downloadstring|downloadfile|hidden\s)"#, "i", None, "block"),
        ("IDS-040", "Log4Shell - JNDI Lookup", "Detects Log4j JNDI injection (${jndi:...})", "Log4j Injection", "CRITICAL", r#"\$\{jndi:"#, "i", Some("CVE-2021-44228"), "block"),
        ("IDS-041", "JNDI - LDAP/RMI/DNS", "Detects JNDI lookups via ldap://, rmi://, dns:// protocols", "Log4j Injection", "CRITICAL", r#"(?i)(\$\{(jndi|lower|upper|env|sys|date):.*(ldap|rmi|dns)://)"#, "i", Some("CVE-2021-44228"), "block"),
        ("IDS-050", "XXE - External Entity Declaration", "Detects XML External Entity (XXE) injection via DOCTYPE/ENTITY", "XXE Injection", "HIGH", r#"(?i)(<!DOCTYPE[^>]*\[|<!ENTITY\s|SYSTEM\s+"|PUBLIC\s+")"#, "i", Some("CVE-2021-21307"), "block"),
        ("IDS-060", "OGNL Injection", "Detects Apache Struts / Confluence OGNL expression injection", "OGNL Injection", "CRITICAL", r#"(?i)(%\{|#_memberAccess|@java|@runtime|getRuntime\(\)|new\s+java)"#, "i", Some("CVE-2017-5638"), "block"),
        ("IDS-070", "SSRF - Internal IP Access", "Detects Server-Side Request Forgery to internal IPs", "SSRF", "HIGH", r#"(?i)(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254|0\.0\.0\.0|::1|fd[0-9a-f]{2}:)"#, "i", Some("CVE-2023-26605"), "alert"),
        ("IDS-080", "LFI - Local File Inclusion", "Detects attempts to include local files via php://, file://, data:// wrappers", "LFI/RFI", "HIGH", r#"(?i)(php://|file://|data://|zip://|phar://|expect://|input://)"#, "i", Some("CVE-2019-5418"), "block"),
        ("IDS-090", "Web Shell Upload", "Detects common web shell filenames being accessed", "Web Shell", "CRITICAL", r#"(?i)(c99\.php|r57\.php|wso\.php|shell\.php|b374k\.php|cmd\.php|eval\.php|zencart|weevely)"#, "i", None, "block"),
        ("IDS-091", "PHP Code Injection", "Detects PHP eval/assert/system execution in parameters", "Code Injection", "CRITICAL", r#"(?i)(eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|system\s*\(|passthru\s*\(|exec\s*\(|shell_exec\s*\()"#, "i", Some("CVE-2016-10033"), "block"),
        ("IDS-100", "Known Scanner User-Agent", "Detects automated vulnerability scanners in User-Agent", "Scanner", "MEDIUM", r#"(?i)(sqlmap|nikto|nmap|masscan|nessus|burp|acunetix|nuclei|hydra|dirbuster|gobuster|wpscan|metasploit|fimap|w3af)"#, "i", None, "alert"),
        ("IDS-101", "Directory Fuzzing", "Detects directory brute-force attempts", "Scanner", "MEDIUM", r#"(?i)(/\.git/|/\.env|/\.svn/|/backup|/admin\.php|/phpmyadmin|/wp-admin|/xmlrpc\.php|/\.well-known)"#, "i", None, "alert"),
        ("IDS-110", "RDP Brute Force (BlueKeep check)", "Detects RDP connection patterns that may target CVE-2019-0708", "RDP Attack", "HIGH", r#"(?i)(\x03\x00\x00\x0b\x06\xd0\x00\x00\x12|cookie\s*:\s*mstshash)"#, "i", Some("CVE-2019-0708"), "block"),
    ];

    let mut inserted = 0usize;
    for &(rule_id, name, description, attack_type, severity, pattern, flags, cve, action) in RULES {
        inserted += conn
            .execute(
                "INSERT OR IGNORE INTO ids_rules (rule_id, rule_name, rule_description, attack_type, severity, pattern, pattern_flags, related_cve, action, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                rusqlite::params![rule_id, name, description, attack_type, severity, pattern, flags, cve, action],
            )
            .map_err(|e| DbError::Schema(format!("seed ids_rules {}: {}", rule_id, e)))?;
    }
    if inserted > 0 {
        tracing::info!("[DB] Seeded {} built-in IDS rules", inserted);
    }
    Ok(())
}

/// Helper to get a connection from the pool
pub fn get_conn(pool: &DbPool) -> anyhow::Result<DbConn> {
    pool.get()
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))
}

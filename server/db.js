// CVE Database Schema & Initialization — using sql.js (pure JS SQLite, no native build)
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', 'data', 'cve-database.db');
let SQL = null;

// Wrapper that mimics better-sqlite3's prepare/run/get/all API
class StatementWrapper {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
    // Extract parameter names (@param) and convert to ?
    this.paramNames = [];
    let processedSql = sql.replace(/@(\w+)/g, (match, name) => {
      this.paramNames.push(name);
      return '?';
    });
    this.processedSql = processedSql;
  }

  run(...args) {
    const values = this._getValues(this._normalizeArgs(args));
    // Use prepare + bind + step for INSERT/UPDATE/DELETE
    let stmt;
    try {
      stmt = this.db.prepare(this.processedSql);
      stmt.bind(values);
      stmt.step();
    } catch(e) {
      console.error('[DB] Statement run error: ' + e.message + ' | SQL: ' + this.processedSql + ' | values: ' + JSON.stringify(values));
      throw e;
    } finally {
      if (stmt) stmt.free();
    }
    // Get last insert rowid
    let lastInsertRowid = 0;
    try {
      const result = this.db.exec('SELECT last_insert_rowid() as id');
      if (result && result.length > 0 && result[0].values.length > 0) {
        lastInsertRowid = result[0].values[0][0];
      }
    } catch(e) {}
    const changes = this.db.getRowsModified();
    return { lastInsertRowid, changes };
  }

  get(...args) {
    const values = this._getValues(this._normalizeArgs(args));
    try {
      const results = this.db.exec(this.processedSql, values);
      if (!results || results.length === 0) return undefined;
      const cols = results[0].columns;
      const vals = results[0].values[0];
      const obj = {};
      cols.forEach((c, i) => { obj[c] = vals[i]; });
      return obj;
    } catch (e) {
      return undefined;
    }
  }

  all(...args) {
    const values = this._getValues(this._normalizeArgs(args));
    try {
      const results = this.db.exec(this.processedSql, values);
      if (!results || results.length === 0) return [];
      const cols = results[0].columns;
      return results[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => { obj[c] = row[i]; });
        return obj;
      });
    } catch (e) {
      return [];
    }
  }

  // Normalizes rest-args into either [] , a single value, or an array.
  // Lets callers use .get(a, b) , .get([a, b]) or .get(single) interchangeably,
  // matching better-sqlite3 behaviour.
  _normalizeArgs(args) {
    if (args.length === 0) return [];
    if (args.length === 1) return args[0];
    return args;
  }

  _getValues(params) {
    if (params === undefined) return [];
    if (Array.isArray(params)) return params;
    // If this statement has @named params, treat params as an object
    if (this.paramNames.length > 0 && typeof params === 'object') {
      return this.paramNames.map(name => {
        let val = params[name];
        if (val === undefined || val === null) val = null;
        return val;
      });
    }
    // Primitive (string/number) or plain object with no @named params — wrap in array
    return [params];
  }
}

class DatabaseWrapper {
  constructor(db) {
    this.db = db;
  }

  prepare(sql) {
    return new StatementWrapper(this.db, sql);
  }

  exec(sql) {
    this.db.run(sql, []);
  }

  transaction(fn) {
    return (...args) => {
      this.db.run('BEGIN TRANSACTION', []);
      try {
        const result = fn(...args);
        this.db.run('COMMIT', []);
        return result;
      } catch (e) {
        this.db.run('ROLLBACK', []);
        throw e;
      }
    };
  }

  close() {
    // Persist to file before closing
    this._save();
    this.db.close();
  }

  _save() {
    const data = this.db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  }
}

async function initDatabase() {
  // Ensure data directory exists
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (!SQL) {
    const SQLModule = await initSqlJs();
    SQL = SQLModule;
  }

  let db;
  // Load existing database or create new
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(new Uint8Array(fileBuffer));
  } else {
    db = new SQL.Database();
  }

  // Create schema
  db.run(`
    CREATE TABLE IF NOT EXISTS cve_entries (
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
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS security_events (
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
      blocked INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ids_rules (
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
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL,
      alert_time TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      message TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0,
      acknowledged_by TEXT,
      acknowledged_at TEXT,
      FOREIGN KEY (event_id) REFERENCES security_events(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ip_reputation (
      ip_address TEXT PRIMARY KEY,
      reputation_score INTEGER DEFAULT 0,
      threat_level TEXT DEFAULT 'unknown',
      country TEXT,
      first_seen TEXT,
      last_seen TEXT,
      total_events INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 0,
      notes TEXT
    )
  `);

  // --- Multi-tenant auth tables ---
  db.run(`
    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      max_users INTEGER DEFAULT 5,
      created_at TEXT DEFAULT (datetime('now')),
      settings TEXT DEFAULT '{}'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      email TEXT NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'viewer',
      status TEXT DEFAULT 'active',
      last_login TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (org_id) REFERENCES organizations(id),
      UNIQUE(org_id, email)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS api_keys (
      key_id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      permissions TEXT DEFAULT 'read',
      last_used TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY (org_id) REFERENCES organizations(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
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
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS incidents (
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
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
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
    )
  `);

  // --- Migrations for existing databases ---
  const migrations = [
    'ALTER TABLE security_events ADD COLUMN attack_type TEXT',
    'ALTER TABLE security_events ADD COLUMN org_id TEXT',
    'ALTER TABLE alerts ADD COLUMN org_id TEXT',
    'ALTER TABLE ip_reputation ADD COLUMN org_id TEXT'
  ];
  for (const sql of migrations) {
    try { db.run(sql); } catch (e) { /* column already exists */ }
  }

  // Indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(cvss_severity)');
  db.run('CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_score)');
  db.run('CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_entries(affected_product)');
  db.run('CREATE INDEX IF NOT EXISTS idx_cve_cwe ON cve_entries(cwe_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_rule ON security_events(rule_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_cve ON security_events(matched_cve)');
  db.run('CREATE INDEX IF NOT EXISTS idx_events_org ON security_events(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_iprep_org ON ip_reputation(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_notif_org ON notifications(org_id)');

  return new DatabaseWrapper(db);
}

module.exports = { initDatabase, DB_PATH };

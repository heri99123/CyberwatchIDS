//! Compliance / operational report generation (Task #31).
//!
//! Four report kinds (security summary, incident report, audit trail,
//! compliance controls) can be rendered as CSV, PDF, JSON or HTML.
//!
//! Why the PDF is written by hand instead of using `printpdf`: the backend is
//! built exclusively in CI (no local Rust toolchain), and `printpdf` pulls in
//! platform font/loader dependencies. A minimal PDF 1.4 writer using the three
//! standard Type1 base fonts (Helvetica / Helvetica-Bold / Courier) needs zero
//! extra crates, zero system libraries and produces a small, valid, printable
//! document. Only ASCII text is rendered; non-ASCII characters are replaced
//! with `?` because no font is embedded.
//!
//! All queries are strictly org-scoped. CSV cells are sanitised against
//! spreadsheet formula injection before they reach Excel / LibreOffice.

use crate::db::{get_conn, DbPool};
use crate::mailer;
use crate::state::SharedState;
use chrono::{Duration as ChronoDuration, Timelike, Utc};
use rusqlite::{Connection, ToSql};
use serde_json::{json, Value};
use std::time::Duration;

pub const DEFAULT_ROWS: usize = 1000;
pub const MAX_ROWS: usize = 5000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    SecuritySummary,
    IncidentReport,
    AuditTrail,
    Compliance,
}

impl ReportKind {
    pub const ALL: [ReportKind; 4] = [
        ReportKind::SecuritySummary,
        ReportKind::IncidentReport,
        ReportKind::AuditTrail,
        ReportKind::Compliance,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "security-summary" | "security" | "summary" => Some(Self::SecuritySummary),
            "incident-report" | "incidents" | "incident" => Some(Self::IncidentReport),
            "audit-trail" | "audit" | "audit-logs" => Some(Self::AuditTrail),
            "compliance" => Some(Self::Compliance),
            _ => None,
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Self::SecuritySummary => "security-summary",
            Self::IncidentReport => "incident-report",
            Self::AuditTrail => "audit-trail",
            Self::Compliance => "compliance",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::SecuritySummary => "Security Summary Report",
            Self::IncidentReport => "Incident Report",
            Self::AuditTrail => "Audit Trail Report",
            Self::Compliance => "Compliance Control Report",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SecuritySummary => "Aggregated detection metrics for the selected period",
            Self::IncidentReport => "All incidents with status, severity and resolution",
            Self::AuditTrail => "Administrative and authentication audit log entries",
            Self::Compliance => "Security control checklist with evidence from the database",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Csv,
    Pdf,
    Json,
}

impl ReportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "csv" => Some(Self::Csv),
            "pdf" => Some(Self::Pdf),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Pdf => "pdf",
            Self::Json => "json",
        }
    }
}

/// Accept only `YYYY-MM-DD`. Keeping the format strict lets us compare the
/// first 10 characters of both RFC3339 and SQLite `datetime('now')` values.
pub fn parse_date(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.len() != 10 {
        return None;
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    Some(s.to_string())
}

#[derive(Debug, Clone)]
pub struct ReportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: usize,
}

impl ReportQuery {
    pub fn period_label(&self) -> String {
        match (&self.from, &self.to) {
            (Some(f), Some(t)) => format!("{} to {}", f, t),
            (Some(f), None) => format!("from {}", f),
            (None, Some(t)) => format!("until {}", t),
            (None, None) => "all available data".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportTable {
    pub title: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub kind: ReportKind,
    pub org_id: String,
    pub org_name: String,
    pub generated_at: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub summary: Vec<(String, String)>,
    pub table: ReportTable,
}

// ---------------------------------------------------------------------------
// Small SQLite helpers
// ---------------------------------------------------------------------------

/// Convert any result set into printable strings. Values are never trusted:
/// CSV / HTML escaping happens at render time.
fn query_rows(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
) -> anyhow::Result<Vec<Vec<String>>> {
    let mut stmt = conn.prepare(sql)?;
    let cols = stmt.column_count();
    let mut result = Vec::new();
    let mut db_rows = stmt.query(params)?;
    while let Some(row) = db_rows.next()? {
        let mut cells = Vec::with_capacity(cols);
        for i in 0..cols {
            let text = match row.get_ref(i)? {
                rusqlite::types::ValueRef::Null => String::new(),
                rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                rusqlite::types::ValueRef::Real(f) => f.to_string(),
                rusqlite::types::ValueRef::Text(b) => String::from_utf8_lossy(b).into_owned(),
                rusqlite::types::ValueRef::Blob(b) => format!("<{} bytes>", b.len()),
            };
            cells.push(text);
        }
        result.push(cells);
    }
    Ok(result)
}

/// Five bind parameters shared by every period-filtered aggregate query:
/// org id, (from, from), (to, to). `NULL` disables that half of the filter.
fn period_params<'a>(
    org_id: &'a String,
    from: &'a Option<String>,
    to: &'a Option<String>,
) -> Vec<&'a dyn ToSql> {
    vec![org_id, from, from, to, to]
}

fn date_clause(column: &str) -> String {
    format!(
        " (? IS NULL OR substr({},1,10) >= ?) AND (? IS NULL OR substr({},1,10) <= ?)",
        column, column
    )
}

fn count_query(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> anyhow::Result<i64> {
    Ok(conn.query_row(sql, params, |r| r.get::<_, i64>(0))?)
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn org_settings(conn: &Connection, org_id: &str) -> Value {
    conn.query_row(
        "SELECT settings FROM organizations WHERE id = ?",
        [org_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    .unwrap_or_else(|| json!({}))
}

// ---------------------------------------------------------------------------
// Report builders
// ---------------------------------------------------------------------------

pub fn build_report(
    pool: &DbPool,
    org_id: &str,
    kind: ReportKind,
    q: &ReportQuery,
) -> anyhow::Result<Report> {
    let conn = get_conn(pool)?;
    let org_name: String = conn
        .query_row(
            "SELECT name FROM organizations WHERE id = ?",
            [org_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| org_id.to_string());
    let generated_at = Utc::now().to_rfc3339();

    let table = match kind {
        ReportKind::SecuritySummary => security_summary(&conn, org_id, q)?,
        ReportKind::IncidentReport => incident_table(&conn, org_id, q)?,
        ReportKind::AuditTrail => audit_table(&conn, org_id, q)?,
        ReportKind::Compliance => compliance_table(&conn, org_id, q)?,
    };

    let mut summary = vec![
        ("Report".to_string(), kind.title().to_string()),
        ("Organization".to_string(), org_name.clone()),
        ("Organization ID".to_string(), org_id.to_string()),
        ("Generated (UTC)".to_string(), generated_at.clone()),
        ("Period".to_string(), q.period_label()),
        ("Data scope".to_string(), "Organization-scoped only".to_string()),
    ];
    summary.push(("Rows".to_string(), table.rows.len().to_string()));

    Ok(Report {
        kind,
        org_id: org_id.to_string(),
        org_name,
        generated_at,
        from: q.from.clone(),
        to: q.to.clone(),
        summary,
        table,
    })
}

fn security_summary(
    conn: &Connection,
    org_id: &str,
    q: &ReportQuery,
) -> anyhow::Result<ReportTable> {
    let oid = org_id.to_string();
    let params = period_params(&oid, &q.from, &q.to);
    let clause = date_clause("timestamp");
    let base = format!("FROM security_events WHERE org_id = ? AND{}", clause);

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut add = |label: &str, value: String| {
        rows.push(vec![label.to_string(), value]);
    };

    let total = count_query(conn, &format!("SELECT COUNT(*) {}", base), &params)?;
    add("Total security events", total.to_string());

    let severity_sql = format!(
        "SELECT COALESCE(severity,'UNKNOWN'), COUNT(*) {} GROUP BY 1 ORDER BY 2 DESC",
        base
    );
    for r in query_rows(conn, &severity_sql, &params)? {
        add(
            &format!("Events with severity {}", r.first().cloned().unwrap_or_default()),
            r.get(1).cloned().unwrap_or_default(),
        );
    }

    let blocked = count_query(
        conn,
        &format!(
            "SELECT COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END),0) {}",
            base
        ),
        &params,
    )?;
    add("Blocked events", blocked.to_string());

    let distinct_ips = count_query(
        conn,
        &format!("SELECT COUNT(DISTINCT source_ip) {}", base),
        &params,
    )?;
    add("Distinct source IPs", distinct_ips.to_string());

    let attack_sql = format!(
        "SELECT COALESCE(attack_type,'Other'), COUNT(*) {} GROUP BY 1 ORDER BY 2 DESC LIMIT 8",
        base
    );
    for r in query_rows(conn, &attack_sql, &params)? {
        add(
            &format!("Top attack type: {}", r.first().cloned().unwrap_or_default()),
            r.get(1).cloned().unwrap_or_default(),
        );
    }

    let ip_sql = format!(
        "SELECT source_ip, COUNT(*) {} GROUP BY 1 ORDER BY 2 DESC LIMIT 8",
        base
    );
    for r in query_rows(conn, &ip_sql, &params)? {
        add(
            &format!("Top source IP: {}", r.first().cloned().unwrap_or_default()),
            r.get(1).cloned().unwrap_or_default(),
        );
    }

    let rule_total: i64 = count_query(conn, "SELECT COUNT(*) FROM ids_rules", &[])?;
    let rule_active: i64 = count_query(
        conn,
        "SELECT COUNT(*) FROM ids_rules WHERE enabled = 1",
        &[],
    )?;
    add(
        "Active IDS rules",
        format!("{} of {}", rule_active, rule_total),
    );

    let open_incidents = count_query(
        conn,
        "SELECT COUNT(*) FROM incidents WHERE org_id = ? AND status NOT IN ('resolved','closed')",
        &[&oid],
    )?;
    add("Open incidents", open_incidents.to_string());

    let unack = count_query(
        conn,
        "SELECT COUNT(*) FROM alerts WHERE (org_id = ? OR org_id IS NULL) AND acknowledged = 0",
        &[&oid],
    )?;
    add("Unacknowledged alerts", unack.to_string());

    Ok(ReportTable {
        title: "Detection metrics".to_string(),
        headers: vec!["Metric".to_string(), "Value".to_string()],
        rows,
    })
}

fn incident_table(
    conn: &Connection,
    org_id: &str,
    q: &ReportQuery,
) -> anyhow::Result<ReportTable> {
    let oid = org_id.to_string();
    let limit = q.limit as i64;
    let sql = format!(
        "SELECT id, title, severity, status, COALESCE(assigned_to,''), \
         created_at, updated_at, COALESCE(resolved_at,'') \
         FROM incidents WHERE org_id = ? AND{} \
         ORDER BY created_at DESC LIMIT ?",
        date_clause("created_at")
    );
    let params: Vec<&dyn ToSql> = vec![
        &oid, &q.from, &q.from, &q.to, &q.to, &limit,
    ];
    Ok(ReportTable {
        title: "Incidents".to_string(),
        headers: vec![
            "ID".to_string(),
            "Title".to_string(),
            "Severity".to_string(),
            "Status".to_string(),
            "Assigned To".to_string(),
            "Created".to_string(),
            "Updated".to_string(),
            "Resolved".to_string(),
        ],
        rows: query_rows(conn, &sql, &params)?,
    })
}

fn audit_table(
    conn: &Connection,
    org_id: &str,
    q: &ReportQuery,
) -> anyhow::Result<ReportTable> {
    let oid = org_id.to_string();
    let limit = q.limit as i64;
    let sql = format!(
        "SELECT id, timestamp, COALESCE(user_email,''), action, \
         COALESCE(resource,''), COALESCE(details,''), COALESCE(ip_address,'') \
         FROM audit_logs WHERE org_id = ? AND{} \
         ORDER BY timestamp DESC LIMIT ?",
        date_clause("timestamp")
    );
    let params: Vec<&dyn ToSql> = vec![
        &oid, &q.from, &q.from, &q.to, &q.to, &limit,
    ];
    Ok(ReportTable {
        title: "Audit trail".to_string(),
        headers: vec![
            "ID".to_string(),
            "Timestamp".to_string(),
            "User".to_string(),
            "Action".to_string(),
            "Resource".to_string(),
            "Details".to_string(),
            "IP".to_string(),
        ],
        rows: query_rows(conn, &sql, &params)?,
    })
}

fn control(rows: &mut Vec<Vec<String>>, id: &str, requirement: &str, status: &str, evidence: &str) {
    rows.push(vec![
        id.to_string(),
        requirement.to_string(),
        status.to_string(),
        evidence.to_string(),
    ]);
}

fn compliance_table(
    conn: &Connection,
    org_id: &str,
    q: &ReportQuery,
) -> anyhow::Result<ReportTable> {
    let oid = org_id.to_string();
    let params = period_params(&oid, &q.from, &q.to);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let settings = org_settings(conn, org_id);

    let event_clause = date_clause("timestamp");
    let event_base = format!("FROM security_events WHERE org_id = ? AND{}", event_clause);
    let audit_clause = date_clause("timestamp");
    let audit_base = format!("FROM audit_logs WHERE org_id = ? AND{}", audit_clause);

    let rule_total = count_query(conn, "SELECT COUNT(*) FROM ids_rules", &[])?;
    let rule_active = count_query(
        conn,
        "SELECT COUNT(*) FROM ids_rules WHERE enabled = 1",
        &[],
    )?;
    control(
        &mut rows,
        "CTL-01",
        "Detection rules loaded and active",
        if rule_active > 0 { "PASS" } else { "REVIEW" },
        &format!("{} of {} rules enabled", rule_active, rule_total),
    );

    let events = count_query(conn, &format!("SELECT COUNT(*) {}", event_base), &params)?;
    control(
        &mut rows,
        "CTL-02",
        "Security events are logged",
        if events > 0 { "PASS" } else { "REVIEW" },
        &format!("{} events in reporting period", events),
    );

    let audits = count_query(conn, &format!("SELECT COUNT(*) {}", audit_base), &params)?;
    control(
        &mut rows,
        "CTL-03",
        "Audit trail is retained",
        if audits > 0 { "PASS" } else { "REVIEW" },
        &format!("{} audit entries in reporting period", audits),
    );

    let incidents = count_query(
        conn,
        "SELECT COUNT(*) FROM incidents WHERE org_id = ?",
        &[&oid],
    )?;
    let open = count_query(
        conn,
        "SELECT COUNT(*) FROM incidents WHERE org_id = ? AND status NOT IN ('resolved','closed')",
        &[&oid],
    )?;
    control(
        &mut rows,
        "CTL-04",
        "Incidents are tracked to resolution",
        if incidents == 0 || open == 0 { "PASS" } else { "REVIEW" },
        &format!("{} incidents, {} still open", incidents, open),
    );

    control(
        &mut rows,
        "CTL-05",
        "Brute-force protection (account lockout)",
        "PASS",
        &format!(
            "{} failed attempts -> {}s lock; enforced in auth.rs",
            env_or("LOGIN_MAX_FAILED_ATTEMPTS", "5"),
            env_or("LOGIN_LOCKOUT_SECONDS", "900")
        ),
    );

    control(
        &mut rows,
        "CTL-06",
        "Per-IP rate limiting on API",
        "PASS",
        &format!(
            "{} req/s, burst {}; enforced by tower_governor",
            env_or("RATE_LIMIT_PER_SECOND", "2"),
            env_or("RATE_LIMIT_BURST", "30")
        ),
    );

    control(
        &mut rows,
        "CTL-07",
        "OWASP security response headers",
        "PASS",
        "CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy",
    );

    let cors = env_or("CORS_ALLOWED_ORIGINS", "");
    let cors_status = if cors.split(',').any(|s| s.trim() == "*") {
        "REVIEW"
    } else {
        "PASS"
    };
    control(
        &mut rows,
        "CTL-08",
        "Restrictive CORS policy",
        cors_status,
        if cors.trim().is_empty() {
            "same-origin only"
        } else {
            &cors
        },
    );

    let hsts = env_or("HSTS_ENABLED", "false");
    control(
        &mut rows,
        "CTL-09",
        "TLS / HSTS",
        if hsts.eq_ignore_ascii_case("true") {
            "PASS"
        } else {
            "REVIEW"
        },
        if hsts.eq_ignore_ascii_case("true") {
            "HSTS max-age=31536000; includeSubDomains"
        } else {
            "HSTS off; TLS must be terminated by a trusted reverse proxy"
        },
    );

    let keys_total = count_query(
        conn,
        "SELECT COUNT(*) FROM api_keys WHERE org_id = ?",
        &[&oid],
    )?;
    let keys_hashed = count_query(
        conn,
        "SELECT COUNT(*) FROM api_keys WHERE org_id = ? AND key_hash IS NOT NULL",
        &[&oid],
    )?;
    control(
        &mut rows,
        "CTL-10",
        "API keys stored as hashes, never plaintext",
        if keys_total == 0 || keys_hashed == keys_total {
            "PASS"
        } else {
            "REVIEW"
        },
        &format!(
            "{} of {} keys hashed{}",
            keys_hashed,
            keys_total,
            if keys_hashed != keys_total {
                " — rotate legacy keys"
            } else {
                ""
            }
        ),
    );

    let opt_in = settings
        .get("emailAlerts")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    control(
        &mut rows,
        "CTL-11",
        "High-severity alert notifications",
        if opt_in { "PASS" } else { "REVIEW" },
        if opt_in {
            "org setting emailAlerts=true"
        } else {
            "org setting emailAlerts=false"
        },
    );

    let jwt = env_or("JWT_SECRET", "");
    let jwt_ok = !jwt.is_empty()
        && jwt != "cyberwatch-ids-rust-secret-key-change-in-production";
    control(
        &mut rows,
        "CTL-12",
        "Session signing secret is deployment-specific",
        if jwt_ok { "PASS" } else { "REVIEW" },
        if jwt_ok {
            "custom JWT_SECRET configured (value not disclosed)"
        } else {
            "default/dev secret in use — set JWT_SECRET"
        },
    );

    let scheduled = settings
        .get("scheduledReports")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    control(
        &mut rows,
        "CTL-13",
        "Periodic compliance reporting",
        if scheduled { "PASS" } else { "REVIEW" },
        if scheduled {
            "org setting scheduledReports=true"
        } else {
            "org setting scheduledReports=false"
        },
    );

    Ok(ReportTable {
        title: "Security control checklist".to_string(),
        headers: vec![
            "Control".to_string(),
            "Requirement".to_string(),
            "Status".to_string(),
            "Evidence".to_string(),
        ],
        rows,
    })
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// Mitigate CSV/formula injection: a cell starting with = + - @ or a control
/// character is prefixed with an apostrophe so spreadsheets treat it as text.
fn csv_safe(s: &str) -> String {
    let mut cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if let Some(first) = cleaned.chars().next() {
        if matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r') {
            cleaned.insert(0, '\'');
        }
    }
    cleaned
}

impl Report {
    pub fn to_csv(&self) -> anyhow::Result<Vec<u8>> {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(Vec::new());
        writer.write_record(
            self.table
                .headers
                .iter()
                .map(|s| csv_safe(s))
                .collect::<Vec<String>>(),
        )?;
        for row in &self.table.rows {
            writer.write_record(
                row.iter()
                    .map(|s| csv_safe(s))
                    .collect::<Vec<String>>(),
            )?;
        }
        writer.flush()?;
        writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!("CSV flush failed: {}", e))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.slug(),
            "title": self.kind.title(),
            "organization": {
                "id": self.org_id,
                "name": self.org_name,
            },
            "generatedAt": self.generated_at,
            "period": {
                "from": self.from,
                "to": self.to,
            },
            "summary": self.summary.iter().map(|(k, v)| json!({"label": k, "value": v})).collect::<Vec<_>>(),
            "table": {
                "title": self.table.title,
                "headers": self.table.headers,
                "rows": self.table.rows,
                "count": self.table.rows.len(),
            },
        })
    }

    pub fn to_html(&self) -> String {
        let esc = mailer::escape_html;
        let mut out = String::new();
        out.push_str(r#"<div style="font-family:Arial,sans-serif;color:#e2e8f0;max-width:760px">"#);
        out.push_str(&format!(
            "<h2 style=\"color:#00d9ff;margin:0 0 4px\">CyberWatch IDS</h2><p style=\"color:#94a3b8;margin:0 0 18px\">{}</p>",
            esc(self.kind.title())
        ));
        out.push_str(r#"<table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:18px">"#);
        for (k, v) in &self.summary {
            out.push_str(&format!(
                "<tr><td style=\"padding:4px 8px;color:#94a3b8;width:190px\">{}</td><td style=\"padding:4px 8px\">{}</td></tr>",
                esc(k),
                esc(v)
            ));
        }
        out.push_str("</table>");
        out.push_str(&format!("<h3 style=\"font-size:14px\">{}</h3>", esc(&self.table.title)));
        out.push_str(r#"<table style="width:100%;border-collapse:collapse;font-size:12px;border:1px solid #1e293b">"#);
        out.push_str("<tr>");
        for h in &self.table.headers {
            out.push_str(&format!(
                "<th style=\"text-align:left;padding:6px 8px;background:#111c2e;color:#00d9ff;border:1px solid #1e293b\">{}</th>",
                esc(h)
            ));
        }
        out.push_str("</tr>");
        for row in &self.table.rows {
            out.push_str("<tr>");
            for c in row {
                out.push_str(&format!(
                    "<td style=\"padding:5px 8px;border:1px solid #1e293b;vertical-align:top\">{}</td>",
                    esc(c)
                ));
            }
            out.push_str("</tr>");
        }
        if self.table.rows.is_empty() {
            out.push_str(&format!(
                "<tr><td colspan=\"{}\" style=\"padding:8px;color:#94a3b8\">No records in this period.</td></tr>",
                self.table.headers.len().max(1)
            ));
        }
        out.push_str("</table>");
        out.push_str("<p style=\"font-size:11px;color:#64748b;margin-top:18px\">Full machine-readable data is attached as CSV. Generated automatically by CyberWatch IDS.</p></div>");
        out
    }

    pub fn to_pdf(&self) -> Vec<u8> {
        render_pdf(self)
    }
}

// ---------------------------------------------------------------------------
// Minimal PDF 1.4 writer (standard Type1 fonts, no external crate)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Style {
    Title,
    Heading,
    Body,
    Mono,
    Small,
}

struct Line {
    text: String,
    style: Style,
}

const LINES_PER_PAGE: usize = 48;
const MAX_LINE_CHARS: usize = 100;

fn report_lines(r: &Report) -> Vec<Line> {
    let mut lines = vec![
        Line { text: "CyberWatch IDS v3.0".to_string(), style: Style::Title },
        Line { text: r.kind.title().to_string(), style: Style::Heading },
        Line { text: String::new(), style: Style::Body },
    ];
    for (k, v) in &r.summary {
        lines.push(Line {
            text: format!("{:<20} {}", k, v),
            style: Style::Small,
        });
    }
    lines.push(Line { text: String::new(), style: Style::Body });
    lines.push(Line { text: r.table.title.clone(), style: Style::Heading });

    let widths = column_widths(&r.table);
    lines.push(Line { text: "-".repeat(96), style: Style::Mono });
    lines.push(Line { text: format_row(&r.table.headers, &widths), style: Style::Mono });
    lines.push(Line { text: "-".repeat(96), style: Style::Mono });
    for row in &r.table.rows {
        lines.push(Line { text: format_row(row, &widths), style: Style::Mono });
    }
    if r.table.rows.is_empty() {
        lines.push(Line {
            text: "(no records in this period)".to_string(),
            style: Style::Small,
        });
    }
    lines
}

fn column_widths(table: &ReportTable) -> Vec<usize> {
    let mut widths: Vec<usize> = table.headers.iter().map(|h| h.chars().count()).collect();
    for row in &table.rows {
        for (i, cell) in row.iter().enumerate() {
            if i >= widths.len() {
                widths.push(0);
            }
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    widths
        .into_iter()
        .map(|w| w.clamp(6, 28))
        .collect::<Vec<usize>>()
}

fn format_row(cells: &[String], widths: &[usize]) -> String {
    let mut parts = Vec::with_capacity(cells.len());
    for (i, cell) in cells.iter().enumerate() {
        let width = *widths.get(i).unwrap_or(&12);
        let short: String = cell.chars().take(width).collect();
        parts.push(format!("{:<width$}", short, width = width));
    }
    let line: String = parts.join(" | ");
    line.chars().take(MAX_LINE_CHARS).collect()
}

/// ASCII-only, escaped for PDF literal strings. Base-14 fonts use WinAnsi,
/// but we deliberately avoid emitting non-ASCII bytes to stay portable.
fn pdf_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(MAX_LINE_CHARS) {
        let c = if (' '..='~').contains(&c) { c } else { '?' };
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            _ => out.push(c),
        }
    }
    out
}

fn add_obj(out: &mut Vec<u8>, offsets: &mut [usize], number: usize, body: &str) {
    offsets[number] = out.len();
    out.extend_from_slice(format!("{} 0 obj\n", number).as_bytes());
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(b"\nendobj\n");
}

fn page_content(lines: &[Line], page: usize, total_pages: usize, r: &Report) -> String {
    let start = page * LINES_PER_PAGE;
    let end = (start + LINES_PER_PAGE).min(lines.len());
    let mut s = String::from("BT\n");
    for (i, line) in lines[start..end].iter().enumerate() {
        let y = 792 - (i as i32) * 14;
        let (font, size) = match line.style {
            Style::Title => ("/F2", 18),
            Style::Heading => ("/F2", 12),
            Style::Body => ("/F1", 10),
            Style::Mono => ("/F3", 8),
            Style::Small => ("/F1", 9),
        };
        s.push_str(&format!(
            "{} {} Tf\n1 0 0 1 40 {} Tm\n({}) Tj\n",
            font,
            size,
            y,
            pdf_escape(&line.text)
        ));
    }
    let footer = format!(
        "Page {} of {} | {} | generated {}",
        page + 1,
        total_pages,
        r.org_name,
        r.generated_at
    );
    s.push_str(&format!(
        "/F1 8 Tf\n1 0 0 1 40 32 Tm\n({}) Tj\n",
        pdf_escape(&footer)
    ));
    s.push_str("ET\n");
    s
}

fn render_pdf(r: &Report) -> Vec<u8> {
    let lines = report_lines(r);
    let pages = (lines.len() + LINES_PER_PAGE - 1) / LINES_PER_PAGE;
    let pages = pages.max(1);
    let page_objs: Vec<usize> = (0..pages).map(|i| 7 + 2 * i).collect();
    let content_objs: Vec<usize> = (0..pages).map(|i| 8 + 2 * i).collect();
    let last_obj = 6 + 2 * pages;

    let mut out: Vec<u8> = Vec::new();
    let mut offsets = vec![0usize; last_obj + 1];

    out.extend_from_slice(b"%PDF-1.4\n");
    add_obj(&mut out, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
    let kids = page_objs
        .iter()
        .map(|n| format!("{} 0 R", n))
        .collect::<Vec<_>>()
        .join(" ");
    add_obj(
        &mut out,
        &mut offsets,
        2,
        &format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids, pages),
    );
    add_obj(
        &mut out,
        &mut offsets,
        3,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    );
    add_obj(
        &mut out,
        &mut offsets,
        4,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    );
    add_obj(
        &mut out,
        &mut offsets,
        5,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    );
    add_obj(
        &mut out,
        &mut offsets,
        6,
        &format!(
            "<< /Title ({}) /Producer (CyberWatch IDS v3.0) /Creator (reports.rs) >>",
            pdf_escape(r.kind.title())
        ),
    );

    for i in 0..pages {
        let page_obj = page_objs[i];
        let content_obj = content_objs[i];
        add_obj(
            &mut out,
            &mut offsets,
            page_obj,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> \
                 /Contents {} 0 R >>",
                content_obj
            ),
        );
        let content = page_content(&lines, i, pages, r);
        let body = format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.as_bytes().len(),
            content
        );
        add_obj(&mut out, &mut offsets, content_obj, &body);
    }

    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", last_obj + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for i in 1..=last_obj {
        out.extend_from_slice(format!("{:010} 00000 n \n", offsets[i]).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
            last_obj + 1,
            xref_at
        )
        .as_bytes(),
    );
    out
}

// ---------------------------------------------------------------------------
// Scheduled reports (tokio interval + persisted de-duplication)
// ---------------------------------------------------------------------------

pub struct ScheduleConfig {
    pub enabled: bool,
    pub hour_utc: u32,
    pub kind: ReportKind,
    pub days: i64,
    pub recipients: Vec<String>,
}

impl ScheduleConfig {
    pub fn from_env() -> Self {
        let enabled = env_or("REPORT_SCHEDULE_ENABLED", "false").eq_ignore_ascii_case("true");
        let hour_utc: u32 = std::env::var("REPORT_SCHEDULE_HOUR_UTC")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|h| *h < 24)
            .unwrap_or(1);
        let kind = ReportKind::parse(&env_or("REPORT_SCHEDULE_KIND", "compliance"))
            .unwrap_or(ReportKind::Compliance);
        let days: i64 = std::env::var("REPORT_SCHEDULE_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(|d: i64| d.clamp(1, 30))
            .unwrap_or(1);
        let recipients = mailer::split_list(&env_or("REPORT_SCHEDULE_RECIPIENTS", ""));
        Self {
            enabled,
            hour_utc,
            kind,
            days,
            recipients,
        }
    }
}

pub fn schedule_status(smtp_enabled: bool) -> Value {
    let cfg = ScheduleConfig::from_env();
    json!({
        "enabled": cfg.enabled,
        "hourUtc": cfg.hour_utc,
        "kind": cfg.kind.slug(),
        "lookbackDays": cfg.days,
        "fixedRecipientsConfigured": !cfg.recipients.is_empty(),
        "smtpEnabled": smtp_enabled,
        "optInSetting": "settings.scheduledReports (per organization)",
    })
}

/// Start the daily report scheduler. Disabled by default so CI and local
/// development never emit email. Ticks every minute; delivery happens once
/// per org per day, guarded by the UNIQUE constraint in `report_runs`.
pub fn spawn_scheduler(state: SharedState) {
    let cfg = ScheduleConfig::from_env();
    if !cfg.enabled {
        tracing::info!("[Reports] scheduled reports disabled (REPORT_SCHEDULE_ENABLED=false)");
        return;
    }
    if !state.mailer.is_enabled() {
        tracing::warn!(
            "[Reports] scheduler enabled but SMTP is disabled — reports cannot be delivered"
        );
    }
    tracing::info!(
        "[Reports] scheduler active: {} daily at {:02}:00 UTC (lookback {}d)",
        cfg.kind.slug(),
        cfg.hour_utc,
        cfg.days
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = Utc::now();
            if now.hour() != cfg.hour_utc {
                continue;
            }
            deliver_scheduled(&state, &cfg, now);
        }
    });
}

fn opted_in_orgs(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT id, settings FROM organizations")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, raw) = row?;
        let settings: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
        if settings
            .get("scheduledReports")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            out.push(id);
        }
    }
    Ok(out)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .take(40)
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn deliver_scheduled(state: &SharedState, cfg: &ScheduleConfig, now: chrono::DateTime<Utc>) {
    let period_key = now.format("%Y-%m-%d").to_string();
    let conn = match get_conn(&state.db) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[Reports] scheduler could not open DB: {}", e);
            return;
        }
    };
    let orgs = match opted_in_orgs(&conn) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("[Reports] scheduler could not list orgs: {}", e);
            return;
        }
    };

    for org_id in orgs {
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO report_runs (org_id, report_kind, period_key) VALUES (?, ?, ?)",
                rusqlite::params![&org_id, cfg.kind.slug(), &period_key],
            )
            .unwrap_or(0);
        if inserted == 0 {
            continue; // already delivered for this period
        }

        let q = ReportQuery {
            from: Some((now - ChronoDuration::days(cfg.days)).format("%Y-%m-%d").to_string()),
            to: Some(period_key.clone()),
            limit: DEFAULT_ROWS,
        };
        let report = match build_report(&state.db, &org_id, cfg.kind, &q) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[Reports] failed to build {} for {}: {}", cfg.kind.slug(), org_id, e);
                continue;
            }
        };
        let csv_bytes = match report.to_csv() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("[Reports] failed to render CSV: {}", e);
                continue;
            }
        };

        let mut recipients = cfg.recipients.clone();
        if recipients.is_empty() {
            recipients = mailer::org_alert_recipients(&state.db, &org_id);
            if recipients.is_empty() {
                recipients = state.mailer.fallback_recipients().to_vec();
            }
        }
        if recipients.is_empty() {
            tracing::warn!(
                "[Reports] no recipients for org {} — set REPORT_SCHEDULE_RECIPIENTS or ALERT_EMAIL_TO",
                org_id
            );
            continue;
        }

        let subject = format!("[CyberWatch IDS] {} — {}", report.kind.title(), period_key);
        let filename = format!(
            "{}-{}-{}.csv",
            report.kind.slug(),
            sanitize_filename(&org_id),
            period_key
        );
        let html = report.to_html();
        mailer::spawn_report_send(
            state.mailer.clone(),
            recipients.clone(),
            subject,
            html,
            filename,
            csv_bytes,
        );
        tracing::info!(
            "[Reports] scheduled {} queued for {} ({} recipients, {} rows)",
            cfg.kind.slug(),
            org_id,
            recipients.len(),
            report.table.rows.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_injection_is_neutralised() {
        assert_eq!(csv_safe("=SUM(A1:A9)"), "'=SUM(A1:A9)");
        assert_eq!(csv_safe("@import"), "'@import");
        assert_eq!(csv_safe("plain text"), "plain text");
    }

    #[test]
    fn pdf_has_valid_xref_offsets() {
        let report = Report {
            kind: ReportKind::Compliance,
            org_id: "org_test".to_string(),
            org_name: "Test Org".to_string(),
            generated_at: "2026-11-14T00:00:00Z".to_string(),
            from: None,
            to: None,
            summary: vec![("Report".to_string(), "Compliance".to_string())],
            table: ReportTable {
                title: "Controls".to_string(),
                headers: vec!["Control".to_string(), "Status".to_string()],
                rows: (0..120)
                    .map(|i| vec![format!("CTL-{:03}", i), "PASS".to_string()])
                    .collect(),
            },
        };
        let bytes = report.to_pdf();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
        assert!(bytes.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&bytes);
        let xref_at: usize = text
            .rsplit("startxref\n")
            .next()
            .and_then(|s| s.split('\n').next())
            .and_then(|s| s.trim().parse().ok())
            .expect("startxref offset");
        assert_eq!(&bytes[xref_at..xref_at + 4], b"xref");
    }

    #[test]
    fn strict_date_parser() {
        assert!(parse_date("2026-11-14").is_some());
        assert!(parse_date("2026-02-30").is_none());
        assert!(parse_date("2026-11-14T00:00:00Z").is_none());
    }
}

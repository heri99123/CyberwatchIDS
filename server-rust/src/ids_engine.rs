use crate::db::{get_conn, DbPool};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// A compiled IDS rule with its regex pattern ready for matching
#[derive(Debug)]
pub struct CompiledRule {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_description: String,
    pub attack_type: String,
    pub severity: String,
    pub action: String,
    pub related_cve: Option<String>,
    pub regex: Regex,
}

/// An attack surface entry extracted from an HTTP request
#[derive(Debug, Clone)]
struct AttackSurface {
    field: String,
    value: String,
    location: String,
    is_header: bool,
}

/// A detection result from inspecting a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub event_type: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_description: String,
    pub attack_type: String,
    pub severity: String,
    pub matched_pattern: String,
    pub matched_cve: Option<String>,
    pub action: String,
    pub source_ip: String,
    pub source_port: Option<i64>,
    pub destination: String,
    pub method: String,
    pub path: String,
    pub payload: String,
    pub user_agent: Option<String>,
}

/// Result of inspecting a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub detections: Vec<Detection>,
    pub should_block: bool,
    pub critical_count: usize,
    pub total_detections: usize,
    pub highest_severity: String,
}

/// Request data for IDS inspection
#[derive(Debug, Clone, Deserialize)]
pub struct RequestData {
    pub method: String,
    pub path: String,
    pub query: Option<serde_json::Value>,
    pub body: Option<serde_json::Value>,
    pub headers: Option<serde_json::Value>,
    pub source_ip: String,
    pub source_port: Option<i64>,
    pub destination: String,
}

/// The main IDS engine - holds compiled rules and provides detection methods
pub struct IdsEngine {
    db: DbPool,
    rules: Mutex<Vec<CompiledRule>>,
}

impl IdsEngine {
    pub fn new(db: DbPool) -> Self {
        Self {
            db,
            rules: Mutex::new(Vec::new()),
        }
    }

    /// Load and compile all enabled rules from the database
    pub fn load_rules(&self) {
        let conn = match get_conn(&self.db) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[IDS] Failed to get DB connection: {}", e);
                return;
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT rule_id, rule_name, rule_description, attack_type, severity, pattern, pattern_flags, related_cve, action FROM ids_rules WHERE enabled = 1",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("[IDS] Failed to prepare rule query: {}", e);
                return;
            }
        };

        let rule_iter = stmt.query_map([], |row| {
            let rule_id: String = row.get(0)?;
            let rule_name: String = row.get(1)?;
            let rule_description: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
            let attack_type: String = row.get(3)?;
            let severity: String = row.get(4)?;
            let pattern: String = row.get(5)?;
            let pattern_flags: String = row.get::<_, Option<String>>(6)?.unwrap_or_else(|| "i".to_string());
            let related_cve: Option<String> = row.get(7)?;
            let action: String = row.get::<_, Option<String>>(8)?.unwrap_or_else(|| "alert".to_string());
            Ok((rule_id, rule_name, rule_description, attack_type, severity, pattern, pattern_flags, related_cve, action))
        });

        let mut compiled = Vec::new();
        if let Ok(iter) = rule_iter {
            for row_result in iter {
                if let Ok((rule_id, rule_name, rule_description, attack_type, severity, pattern, pattern_flags, related_cve, action)) = row_result {
                    // Strip PCRE-style inline flags
                    let mut pattern_str = pattern.clone();
                    if pattern_str.starts_with("(?i)") {
                        pattern_str = pattern_str[4..].to_string();
                    }
                    // Remove inline flag groups like (?i:...)
                    pattern_str = regex::Regex::new(r"\(\?[a-z]+:").unwrap().replace_all(&pattern_str, "(").to_string();

                    // Build regex with flags
                    let final_pattern = if pattern_flags.contains('i') {
                        format!("(?i){}", pattern_str)
                    } else {
                        pattern_str
                    };

                    match Regex::new(&final_pattern) {
                        Ok(regex) => {
                            compiled.push(CompiledRule {
                                rule_id,
                                rule_name,
                                rule_description,
                                attack_type,
                                severity,
                                action,
                                related_cve,
                                regex,
                            });
                        }
                        Err(e) => {
                            tracing::error!("[IDS] Invalid regex for rule {}: {}", rule_id, e);
                        }
                    }
                }
            }
        }

        let count = compiled.len();
        *self.rules.lock().unwrap() = compiled;
        tracing::info!("[IDS] Loaded {} active detection rules", count);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.lock().unwrap().len()
    }

    /// Inspect an HTTP request and return detections
    pub fn inspect_request(&self, req: &RequestData) -> InspectionResult {
        let mut surfaces = Vec::new();

        // URL path
        surfaces.push(AttackSurface {
            field: "path".to_string(),
            value: req.path.clone(),
            location: "URL Path".to_string(),
            is_header: false,
        });

        // Query parameters
        if let Some(query) = &req.query {
            match query {
                serde_json::Value::Object(map) => {
                    for (key, val) in map {
                        surfaces.push(AttackSurface {
                            field: key.clone(),
                            value: val_to_string(val),
                            location: format!("Query Param: {}", key),
                            is_header: false,
                        });
                    }
                }
                serde_json::Value::String(s) => {
                    surfaces.push(AttackSurface {
                        field: "query".to_string(),
                        value: s.clone(),
                        location: "Query String".to_string(),
                        is_header: false,
                    });
                }
                _ => {}
            }
        }

        // Body
        if let Some(body) = &req.body {
            match body {
                serde_json::Value::Object(map) => {
                    for (key, val) in map {
                        surfaces.push(AttackSurface {
                            field: key.clone(),
                            value: val_to_string(val),
                            location: format!("Body Param: {}", key),
                            is_header: false,
                        });
                    }
                }
                serde_json::Value::String(s) => {
                    surfaces.push(AttackSurface {
                        field: "body".to_string(),
                        value: s.clone(),
                        location: "Request Body".to_string(),
                        is_header: false,
                    });
                }
                _ => {}
            }
        }

        // Headers (specific ones)
        if let Some(headers) = &req.headers {
            if let serde_json::Value::Object(map) = headers {
                let header_fields = [
                    "user-agent", "content-type", "content-disposition",
                    "referer", "cookie", "x-forwarded-for", "authorization", "accept",
                ];
                for h in &header_fields {
                    if let Some(val) = map.get(*h) {
                        surfaces.push(AttackSurface {
                            field: h.to_string(),
                            value: val_to_string(val),
                            location: format!("Header: {}", h),
                            is_header: true,
                        });
                    }
                }
            }
        }

        let rules = self.rules.lock().unwrap();
        let mut detections = Vec::new();

        for surface in &surfaces {
            for rule in rules.iter() {
                // SSRF rules skip headers (Referer legitimately contains hostnames)
                if surface.is_header && rule.attack_type == "SSRF" {
                    continue;
                }

                if let Some(m) = rule.regex.find(&surface.value) {
                    let user_agent = req.headers.as_ref().and_then(|h| {
                        h.get("user-agent").map(|v| val_to_string(v))
                    });

                    detections.push(Detection {
                        event_type: "attack".to_string(),
                        rule_id: rule.rule_id.clone(),
                        rule_name: rule.rule_name.clone(),
                        rule_description: rule.rule_description.clone(),
                        attack_type: rule.attack_type.clone(),
                        severity: rule.severity.clone(),
                        matched_pattern: m.as_str().to_string(),
                        matched_cve: rule.related_cve.clone(),
                        action: rule.action.clone(),
                        source_ip: if req.source_ip.is_empty() { "unknown".to_string() } else { req.source_ip.clone() },
                        source_port: req.source_port,
                        destination: if req.destination.is_empty() { req.path.clone() } else { req.destination.clone() },
                        method: if req.method.is_empty() { "GET".to_string() } else { req.method.clone() },
                        path: if req.path.is_empty() { "/".to_string() } else { req.path.clone() },
                        payload: surface.value.chars().take(2000).collect(),
                        user_agent,
                    });
                    break; // one detection per surface
                }
            }
        }

        let should_block = detections.iter().any(|d| d.action == "block");
        let critical_count = detections.iter().filter(|d| d.severity == "CRITICAL").count();
        let highest_severity = get_highest_severity(&detections);

        InspectionResult {
            total_detections: detections.len(),
            should_block,
            critical_count,
            highest_severity,
            detections,
        }
    }

    /// Log a security event to the database, create alert if CRITICAL/HIGH, update IP reputation
    pub fn log_security_event(&self, detection: &Detection, org_id: Option<&str>) -> anyhow::Result<i64> {
        let conn = get_conn(&self.db)?;
        let timestamp = Utc::now().to_rfc3339();
        let blocked = if detection.action == "block" { 1 } else { 0 };

        conn.execute(
            "INSERT INTO security_events (timestamp, event_type, attack_type, severity, source_ip, source_port, destination, method, path, payload, user_agent, rule_id, rule_name, rule_description, matched_pattern, matched_cve, action, blocked, org_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                timestamp,
                if detection.event_type.is_empty() { "attack" } else { &detection.event_type },
                &detection.attack_type,
                &detection.severity,
                &detection.source_ip,
                detection.source_port,
                &detection.destination,
                &detection.method,
                &detection.path,
                &detection.payload,
                &detection.user_agent,
                &detection.rule_id,
                &detection.rule_name,
                &detection.rule_description,
                &detection.matched_pattern,
                &detection.matched_cve,
                &detection.action,
                blocked,
                org_id,
            ],
        )?;

        let event_id = conn.last_insert_rowid();

        // Create alert for CRITICAL/HIGH
        if detection.severity == "CRITICAL" || detection.severity == "HIGH" {
            conn.execute(
                "INSERT INTO alerts (event_id, alert_time, alert_type, message, org_id) VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![
                    event_id,
                    timestamp,
                    &detection.attack_type,
                    format!("{} severity: {} from {}", detection.severity, detection.rule_name, detection.source_ip),
                    org_id,
                ],
            )?;
        }

        // Update IP reputation
        self.update_ip_reputation(&conn, &detection.source_ip, &detection.severity, org_id);

        Ok(event_id)
    }

    fn update_ip_reputation(&self, conn: &rusqlite::Connection, ip: &str, severity: &str, org_id: Option<&str>) {
        if ip.is_empty() || ip == "unknown" {
            return;
        }

        let score_add: i64 = match severity {
            "CRITICAL" => 25,
            "HIGH" => 15,
            "MEDIUM" => 5,
            "LOW" => 1,
            _ => 0,
        };

        // Check existing
        let existing: Option<i64> = conn
            .query_row(
                "SELECT reputation_score FROM ip_reputation WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)",
                rusqlite::params![ip, org_id],
                |row| row.get(0),
            )
            .ok();

        let now = Utc::now().to_rfc3339();

        if let Some(current_score) = existing {
            let new_score = (current_score + score_add).min(100);
            let threat_level = if new_score >= 75 { "critical" }
                else if new_score >= 50 { "high" }
                else if new_score >= 25 { "medium" }
                else { "low" };

            conn.execute(
                "UPDATE ip_reputation SET reputation_score = ?, threat_level = ?, last_seen = ?, total_events = total_events + 1 WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)",
                rusqlite::params![new_score, threat_level, now, ip, org_id],
            ).ok();
        } else {
            let threat_level = if score_add >= 25 { "critical" }
                else if score_add >= 15 { "high" }
                else { "low" };

            conn.execute(
                "INSERT INTO ip_reputation (ip_address, reputation_score, threat_level, first_seen, last_seen, total_events, org_id) VALUES (?, ?, ?, ?, ?, 1, ?)",
                rusqlite::params![ip, score_add, threat_level, now, now, org_id],
            ).ok();
        }
    }

    /// Get aggregate statistics, optionally scoped to an org
    pub fn get_stats(&self, org_id: Option<&str>) -> serde_json::Value {
        let conn = match get_conn(&self.db) {
            Ok(c) => c,
            Err(_) => return serde_json::json!({}),
        };

        let total_events: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE org_id = ? OR org_id IS NULL", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(*) FROM security_events", [], |r| r.get(0)).unwrap_or(0)
        };

        let blocked_events: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE (org_id = ? OR org_id IS NULL) AND blocked = 1", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE blocked = 1", [], |r| r.get(0)).unwrap_or(0)
        };

        let critical_events: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE (org_id = ? OR org_id IS NULL) AND severity = 'CRITICAL'", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'", [], |r| r.get(0)).unwrap_or(0)
        };

        let high_events: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE (org_id = ? OR org_id IS NULL) AND severity = 'HIGH'", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(*) FROM security_events WHERE severity = 'HIGH'", [], |r| r.get(0)).unwrap_or(0)
        };

        let unique_attackers: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(DISTINCT source_ip) FROM security_events WHERE org_id = ? OR org_id IS NULL", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(DISTINCT source_ip) FROM security_events", [], |r| r.get(0)).unwrap_or(0)
        };

        let active_alerts: i64 = if let Some(oid) = org_id {
            conn.query_row("SELECT COUNT(*) FROM alerts WHERE (org_id = ? OR org_id IS NULL) AND acknowledged = 0", [oid], |r| r.get(0)).unwrap_or(0)
        } else {
            conn.query_row("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0", [], |r| r.get(0)).unwrap_or(0)
        };

        serde_json::json!({
            "totalEvents": total_events,
            "blockedEvents": blocked_events,
            "criticalEvents": critical_events,
            "highEvents": high_events,
            "uniqueAttackers": unique_attackers,
            "activeAlerts": active_alerts,
        })
    }

    /// Purge runtime telemetry data (events, alerts, IP reputation)
    pub fn reset_event_data(&self, org_id: Option<&str>) -> anyhow::Result<serde_json::Value> {
        let conn = get_conn(&self.db)?;

        let (events, alerts, ips) = if let Some(oid) = org_id {
            let e: i64 = conn.query_row("SELECT COUNT(*) FROM security_events WHERE org_id = ?", [oid], |r| r.get(0)).unwrap_or(0);
            let a: i64 = conn.query_row("SELECT COUNT(*) FROM alerts WHERE org_id = ?", [oid], |r| r.get(0)).unwrap_or(0);
            let i: i64 = conn.query_row("SELECT COUNT(*) FROM ip_reputation WHERE org_id = ?", [oid], |r| r.get(0)).unwrap_or(0);
            conn.execute("DELETE FROM alerts WHERE org_id = ?", [oid])?;
            conn.execute("DELETE FROM security_events WHERE org_id = ?", [oid])?;
            conn.execute("DELETE FROM ip_reputation WHERE org_id = ?", [oid])?;
            (e, a, i)
        } else {
            let e: i64 = conn.query_row("SELECT COUNT(*) FROM security_events", [], |r| r.get(0)).unwrap_or(0);
            let a: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0)).unwrap_or(0);
            let i: i64 = conn.query_row("SELECT COUNT(*) FROM ip_reputation", [], |r| r.get(0)).unwrap_or(0);
            conn.execute("DELETE FROM alerts", [])?;
            conn.execute("DELETE FROM security_events", [])?;
            conn.execute("DELETE FROM ip_reputation", [])?;
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('security_events','alerts')", []).ok();
            (e, a, i)
        };

        tracing::info!("[IDS] Event data purged: {} events, {} alerts, {} IPs", events, alerts, ips);

        Ok(serde_json::json!({
            "events": events,
            "alerts": alerts,
            "ips": ips,
        }))
    }
}

fn val_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        _ => v.to_string(),
    }
}

fn get_highest_severity(detections: &[Detection]) -> String {
    let order = |s: &str| -> i32 {
        match s {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        }
    };
    let mut highest = "INFO";
    let mut highest_val = 0;
    for d in detections {
        let val = order(&d.severity);
        if val > highest_val {
            highest_val = val;
            highest = &d.severity;
        }
    }
    highest.to_string()
}

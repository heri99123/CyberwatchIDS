use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::routes::auth::extract_auth_user;
use crate::state::SharedState;

/// GET /api/stats — Get statistics (org-scoped if authenticated)
pub async fn stats(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());
    let user = crate::auth::extract_auth_user(auth_header, api_key);
    let org_id = user.as_ref().map(|u| u.org_id.as_str());
    Ok(Json(state.ids.get_stats(org_id)))
}

/// GET /api/events — List recent events (org-scoped)
pub async fn events(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare("SELECT * FROM security_events WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?")?;
    let rows = stmt.query_map(rusqlite::params![&user.org_id, limit], row_to_json)?;
    let events: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(events)))
}

/// GET /api/events/search — Search events with filters
pub async fn events_search(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut sql = "SELECT * FROM security_events WHERE org_id = ?".to_string();
    let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(user.org_id.clone())];

    if let Some(severity) = params.get("severity") {
        sql.push_str(" AND severity = ?");
        sql_params.push(Box::new(severity.clone()));
    }
    if let Some(attack_type) = params.get("attack_type") {
        sql.push_str(" AND attack_type = ?");
        sql_params.push(Box::new(attack_type.clone()));
    }
    if let Some(source_ip) = params.get("source_ip") {
        sql.push_str(" AND source_ip = ?");
        sql_params.push(Box::new(source_ip.clone()));
    }
    sql.push_str(" ORDER BY timestamp DESC LIMIT 200");

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), row_to_json)?;
    let events: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(events)))
}

/// GET /api/alerts — List alerts
pub async fn alerts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let unack = params.get("unacknowledged").map(|s| s == "true").unwrap_or(false);
    let sql = if unack {
        "SELECT * FROM alerts WHERE (org_id = ? OR org_id IS NULL) AND acknowledged = 0 ORDER BY alert_time DESC LIMIT 100"
    } else {
        "SELECT * FROM alerts WHERE (org_id = ? OR org_id IS NULL) ORDER BY alert_time DESC LIMIT 100"
    };

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([&user.org_id], row_to_json)?;
    let alerts: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(alerts)))
}

/// PUT /api/alerts/:id/acknowledge
pub async fn acknowledge_alert(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(alert_id): Path<i64>,
    axum::Json(body): axum::Json<Value>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let ack_by = body.get("user").and_then(|v| v.as_str()).unwrap_or(&user.email);
    conn.execute(
        "UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
        rusqlite::params![ack_by, chrono::Utc::now().to_rfc3339(), alert_id],
    )?;

    Ok(Json(json!({"acknowledged": true})))
}

/// GET /api/cve — List CVE entries with search
pub async fn cve_list(
    State(state): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let query = params.get("q").cloned().unwrap_or_default();
    let severity = params.get("severity").cloned().unwrap_or_else(|| "ALL".to_string());

    let conn = get_conn(&state.db)?;
    let mut sql = "SELECT * FROM cve_entries WHERE 1=1".to_string();
    let mut sql_params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if !query.is_empty() {
        let like = format!("%{}%", query);
        sql.push_str(" AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ? OR affected_product LIKE ? OR tags LIKE ?)");
        for _ in 0..5 {
            sql_params.push(Box::new(like.clone()));
        }
    }
    if severity != "ALL" {
        sql.push_str(" AND cvss_severity = ?");
        sql_params.push(Box::new(severity.clone()));
    }
    sql.push_str(" ORDER BY cvss_score DESC");

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), row_to_json)?;
    let cves: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(cves)))
}

/// GET /api/cve/:id — Get single CVE
pub async fn cve_detail(
    State(state): State<SharedState>,
    Path(cve_id): Path<String>,
) -> AppResult<Json<Value>> {
    let conn = get_conn(&state.db)?;
    let cve = conn.query_row("SELECT * FROM cve_entries WHERE cve_id = ?", [&cve_id], row_to_json)
        .map_err(|_| AppError::NotFound("CVE not found".to_string()))?;
    Ok(Json(cve))
}

/// GET /api/rules — List all IDS rules
pub async fn rules(
    State(state): State<SharedState>,
) -> AppResult<Json<Value>> {
    let conn = get_conn(&state.db)?;
    let mut stmt = conn.prepare("SELECT * FROM ids_rules ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, rule_id ASC")?;
    let rows = stmt.query_map([], row_to_json)?;
    let rules: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!(rules)))
}

/// PUT /api/rules/:id/toggle
pub async fn toggle_rule(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(rule_id): Path<String>,
) -> AppResult<Json<Value>> {
    let _user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let current: i64 = conn.query_row("SELECT enabled FROM ids_rules WHERE rule_id = ?", [&rule_id], |r| r.get(0))
        .map_err(|_| AppError::NotFound("Rule not found".to_string()))?;
    let new_enabled = if current == 1 { 0 } else { 1 };

    conn.execute("UPDATE ids_rules SET enabled = ? WHERE rule_id = ?", rusqlite::params![new_enabled, rule_id])?;
    state.ids.load_rules();

    Ok(Json(json!({"rule_id": rule_id, "enabled": new_enabled})))
}

/// GET /api/ip-reputation
pub async fn ip_reputation(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare("SELECT * FROM ip_reputation WHERE org_id = ? OR org_id IS NULL ORDER BY total_events DESC LIMIT 200")?;
    let rows = stmt.query_map([&user.org_id], row_to_json)?;
    let ips: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(ips)))
}

/// PUT /api/ip-reputation/:ip/block
pub async fn block_ip(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;
    conn.execute("UPDATE ip_reputation SET blocked = 1 WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)", rusqlite::params![ip, &user.org_id])?;
    Ok(Json(json!({"ip": ip, "blocked": true})))
}

/// PUT /api/ip-reputation/:ip/unblock
pub async fn unblock_ip(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;
    conn.execute("UPDATE ip_reputation SET blocked = 0 WHERE ip_address = ? AND (org_id = ? OR org_id IS NULL)", rusqlite::params![ip, &user.org_id])?;
    Ok(Json(json!({"ip": ip, "blocked": false})))
}

/// POST /api/reset — Purge event data
pub async fn reset_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let purged = state.ids.reset_event_data(Some(&user.org_id))?;
    let stats = state.ids.get_stats(Some(&user.org_id));
    state.broadcast_all("stats", &stats).await;
    Ok(Json(json!({"status": "ok", "purged": purged})))
}

/// Helper: convert a rusqlite row to a JSON object by column name
fn row_to_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let col_count = row.as_ref().column_count();
    let mut obj = serde_json::Map::new();
    for i in 0..col_count {
        let name = row.as_ref().column_name(i)?.to_string();
        let value: rusqlite::types::Value = row.get(i)?;
        let json_val = match value {
            rusqlite::types::Value::Null => Value::Null,
            rusqlite::types::Value::Integer(n) => json!(n),
            rusqlite::types::Value::Real(f) => json!(f),
            rusqlite::types::Value::Text(s) => Value::String(s),
            rusqlite::types::Value::Blob(b) => Value::String(String::from_utf8_lossy(&b).to_string()),
        };
        obj.insert(name, json_val);
    }
    Ok(Value::Object(obj))
}

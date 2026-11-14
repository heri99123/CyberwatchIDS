use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;
use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::routes::auth::{audit_log, extract_auth_user};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct CreateIncidentRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub event_ids: Option<Vec<i64>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIncidentRequest {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub assigned_to: Option<String>,
    pub description: Option<String>,
}

/// GET /api/incidents
pub async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare("SELECT * FROM incidents WHERE org_id = ? ORDER BY created_at DESC LIMIT 100")?;
    let rows = stmt.query_map([&user.org_id], row_to_json)?;
    let incidents: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(incidents)))
}

/// POST /api/incidents
pub async fn create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateIncidentRequest>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;

    if body.title.is_empty() {
        return Err(AppError::BadRequest("Title required".to_string()));
    }

    let conn = get_conn(&state.db)?;
    let id = auth::gen_id("inc_");
    let description = body.description.unwrap_or_default();
    let severity = body.severity.unwrap_or_else(|| "medium".to_string());
    let event_ids = serde_json::to_string(&body.event_ids.unwrap_or_default())?;

    conn.execute(
        "INSERT INTO incidents (id, org_id, title, description, severity, event_ids, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![id, &user.org_id, body.title, description, severity, event_ids, &user.id],
    )?;

    audit_log(&conn, &user.org_id, &user.id, &user.email, "create_incident", "incident", &json!({"id": id, "title": body.title}));

    Ok(Json(json!({"id": id, "title": body.title, "status": "open"})))
}

/// PUT /api/incidents/:id
pub async fn update(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
    Json(body): Json<UpdateIncidentRequest>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    // Verify incident belongs to org
    let existing: Option<String> = conn.query_row("SELECT id FROM incidents WHERE id = ? AND org_id = ?", rusqlite::params![&incident_id, &user.org_id], |r| r.get(0)).ok();
    if existing.is_none() {
        return Err(AppError::NotFound("Incident not found".to_string()));
    }

    let mut updates: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];

    if let Some(status) = body.status {
        updates.push("status = ?".to_string());
        params.push(Box::new(status.clone()));
        if status == "resolved" {
            updates.push("resolved_at = datetime('now')".to_string());
        }
    }
    if let Some(severity) = body.severity {
        updates.push("severity = ?".to_string());
        params.push(Box::new(severity));
    }
    if let Some(assigned_to) = body.assigned_to {
        updates.push("assigned_to = ?".to_string());
        params.push(Box::new(assigned_to));
    }
    if let Some(description) = body.description {
        updates.push("description = ?".to_string());
        params.push(Box::new(description));
    }
    updates.push("updated_at = datetime('now')".to_string());

    params.push(Box::new(incident_id.clone()));
    params.push(Box::new(user.org_id.clone()));

    let sql = format!("UPDATE incidents SET {} WHERE id = ? AND org_id = ?", updates.join(", "));
    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    conn.execute(&sql, param_refs.as_slice())?;

    audit_log(&conn, &user.org_id, &user.id, &user.email, "update_incident", "incident", &json!({"id": incident_id}));

    Ok(Json(json!({"id": incident_id, "updated": true})))
}

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

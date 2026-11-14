use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use validator::Validate;

use crate::auth;
use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::routes::auth::{audit_log, extract_auth_user};
use crate::state::SharedState;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 2, max = 100, message = "Name must be 2-100 characters"))]
    pub name: String,
    // Keep in sync with RegisterRequest / LoginRequest (Task #26).
    #[validate(length(min = 8, max = 128, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrgRequest {
    pub name: Option<String>,
    pub settings: Option<Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,
    pub permissions: Option<String>,
}

/// GET /api/admin/users — List users in organization
pub async fn list_users(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare(
        "SELECT id, email, name, role, status, last_login, created_at FROM users WHERE org_id = ? ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([&user.org_id], |row| {
        Ok(json!({
            "id": row.get::<_, String>(0)?,
            "email": row.get::<_, String>(1)?,
            "name": row.get::<_, String>(2)?,
            "role": row.get::<_, String>(3)?,
            "status": row.get::<_, String>(4)?,
            "last_login": row.get::<_, Option<String>>(5)?,
            "created_at": row.get::<_, String>(6)?,
        }))
    })?;

    let users: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!(users)))
}

/// POST /api/admin/users — Create new user
pub async fn create_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;

    body.validate()
        .map_err(|e| AppError::BadRequest(format!("Validation failed: {}", e)))?;

    let conn = get_conn(&state.db)?;

    // Check max users
    let max_users: i64 = conn.query_row("SELECT max_users FROM organizations WHERE id = ?", [&user.org_id], |r| r.get(0))?;
    let user_count: i64 = conn.query_row("SELECT COUNT(*) FROM users WHERE org_id = ?", [&user.org_id], |r| r.get(0))?;
    if user_count >= max_users {
        return Err(AppError::Forbidden(format!("Maximum user limit reached ({})", max_users)));
    }

    // Check existing email in org
    let existing: Option<String> = conn.query_row("SELECT id FROM users WHERE org_id = ? AND email = ?", rusqlite::params![&user.org_id, &body.email], |r| r.get(0)).ok();
    if existing.is_some() {
        return Err(AppError::Conflict("Email already exists in your organization".to_string()));
    }

    let user_id = auth::gen_id("usr_");
    let password_hash = auth::hash_password(&body.password)?;
    let role = match body.role.as_deref() {
        Some("admin") => "admin",
        Some("analyst") => "analyst",
        _ => "viewer",
    };

    conn.execute(
        "INSERT INTO users (id, org_id, email, name, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![user_id, &user.org_id, body.email, body.name, password_hash, role, "active"],
    )?;

    audit_log(&conn, &user.org_id, &user.id, &user.email, "create_user", "user", &json!({"email": body.email, "name": body.name, "role": role}));

    Ok(Json(json!({
        "id": user_id,
        "email": body.email,
        "name": body.name,
        "role": role,
        "status": "active",
    })))
}

/// PUT /api/admin/users/:id/role — Update user role
pub async fn update_role(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateRoleRequest>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;

    if !["admin", "analyst", "viewer"].contains(&body.role.as_str()) {
        return Err(AppError::BadRequest("Invalid role".to_string()));
    }

    let conn = get_conn(&state.db)?;
    let target: Option<String> = conn.query_row("SELECT id FROM users WHERE id = ? AND org_id = ?", rusqlite::params![&user_id, &user.org_id], |r| r.get(0)).ok();
    if target.is_none() {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    conn.execute("UPDATE users SET role = ? WHERE id = ?", rusqlite::params![body.role, &user_id])?;
    audit_log(&conn, &user.org_id, &user.id, &user.email, "update_role", "user", &json!({"userId": user_id, "role": body.role}));

    Ok(Json(json!({"id": user_id, "role": body.role})))
}

/// PUT /api/admin/users/:id/status — Enable/disable user
pub async fn update_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateStatusRequest>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;

    if !["active", "disabled"].contains(&body.status.as_str()) {
        return Err(AppError::BadRequest("Invalid status".to_string()));
    }

    if user_id == user.id && body.status == "disabled" {
        return Err(AppError::BadRequest("Cannot disable yourself".to_string()));
    }

    let conn = get_conn(&state.db)?;
    let target: Option<String> = conn.query_row("SELECT id FROM users WHERE id = ? AND org_id = ?", rusqlite::params![&user_id, &user.org_id], |r| r.get(0)).ok();
    if target.is_none() {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    conn.execute("UPDATE users SET status = ? WHERE id = ?", rusqlite::params![body.status, &user_id])?;
    audit_log(&conn, &user.org_id, &user.id, &user.email, "update_status", "user", &json!({"userId": user_id, "status": body.status}));

    Ok(Json(json!({"id": user_id, "status": body.status})))
}

/// DELETE /api/admin/users/:id — Delete user
pub async fn delete_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;

    if user_id == user.id {
        return Err(AppError::BadRequest("Cannot delete yourself".to_string()));
    }

    let conn = get_conn(&state.db)?;
    let target: Option<(String, String)> = conn.query_row("SELECT id, email FROM users WHERE id = ? AND org_id = ?", rusqlite::params![&user_id, &user.org_id], |row| {
        Ok((row.get(0)?, row.get(1)?))
    }).ok();
    let (target_id, target_email) = target.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    conn.execute("DELETE FROM users WHERE id = ?", [&target_id])?;
    audit_log(&conn, &user.org_id, &user.id, &user.email, "delete_user", "user", &json!({"userId": user_id, "email": target_email}));

    Ok(Json(json!({"deleted": true})))
}

/// GET /api/admin/org — Get organization info
pub async fn get_org(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    let org = conn.query_row(
        "SELECT id, name, slug, plan, max_users, settings, created_at FROM organizations WHERE id = ?",
        [&user.org_id],
        |row| {
            let settings_raw: String = row.get(5)?;
            // Return a JSON object (not a JSON-encoded string) so the admin UI
            // can toggle `emailAlerts` without double parsing.
            let settings: Value = serde_json::from_str(&settings_raw).unwrap_or_else(|_| json!({}));
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "slug": row.get::<_, String>(2)?,
                "plan": row.get::<_, String>(3)?,
                "max_users": row.get::<_, i64>(4)?,
                "settings": settings,
                "created_at": row.get::<_, String>(6)?,
            }))
        },
    ).map_err(|_| AppError::NotFound("Organization not found".to_string()))?;

    let user_count: i64 = conn.query_row("SELECT COUNT(*) FROM users WHERE org_id = ?", [&user.org_id], |r| r.get(0))?;

    let mut org = org;
    if let Some(obj) = org.as_object_mut() {
        obj.insert("userCount".to_string(), json!(user_count));
    }

    Ok(Json(org))
}

/// PUT /api/admin/org — Update organization settings
pub async fn update_org(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<UpdateOrgRequest>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    if let Some(name) = body.name {
        conn.execute("UPDATE organizations SET name = ? WHERE id = ?", rusqlite::params![name, &user.org_id])?;
    }
    if let Some(settings) = body.settings {
        conn.execute("UPDATE organizations SET settings = ? WHERE id = ?", rusqlite::params![settings.to_string(), &user.org_id])?;
    }

    audit_log(&conn, &user.org_id, &user.id, &user.email, "update_org", "organization", &json!({}));

    Ok(Json(json!({"updated": true})))
}

/// GET /api/admin/api-keys — List API keys
pub async fn list_api_keys(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare(
        "SELECT key_id, org_id, name, key_prefix, permissions, last_used, created_at, revoked FROM api_keys WHERE org_id = ? ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([&user.org_id], |row| {
        Ok(json!({
            "key_id": row.get::<_, String>(0)?,
            "name": row.get::<_, String>(2)?,
            "key_prefix": row.get::<_, String>(3)?,
            "permissions": row.get::<_, String>(4)?,
            "last_used": row.get::<_, Option<String>>(5)?,
            "created_at": row.get::<_, String>(6)?,
            "revoked": row.get::<_, i64>(7)?,
        }))
    })?;

    let keys: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!(keys)))
}

/// POST /api/admin/api-keys — Create API key
pub async fn create_api_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateApiKeyRequest>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;

    body.validate()
        .map_err(|e| AppError::BadRequest(format!("Validation failed: {}", e)))?;

    let conn = get_conn(&state.db)?;
    let key_id = auth::gen_id("key_");
    let full_key = auth::generate_api_key();
    let key_prefix = format!("{}...", &full_key[..10]);
    let perms = match body.permissions.as_deref() {
        Some("read-write") => "read-write",
        _ => "read",
    };

    conn.execute(
        "INSERT INTO api_keys (key_id, org_id, name, key_prefix, permissions) VALUES (?, ?, ?, ?, ?)",
        rusqlite::params![key_id, &user.org_id, body.name, key_prefix, perms],
    )?;

    audit_log(&conn, &user.org_id, &user.id, &user.email, "create_apikey", "api_key", &json!({"name": body.name, "keyId": key_id}));

    Ok(Json(json!({
        "keyId": key_id,
        "name": body.name,
        "key": full_key,
        "permissions": perms,
        "note": "Save this key securely. It will not be shown again.",
    })))
}

/// DELETE /api/admin/api-keys/:id — Revoke API key
pub async fn revoke_api_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    conn.execute("UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND org_id = ?", rusqlite::params![key_id, &user.org_id])?;
    audit_log(&conn, &user.org_id, &user.id, &user.email, "revoke_apikey", "api_key", &json!({"keyId": key_id}));

    Ok(Json(json!({"revoked": true})))
}

/// GET /api/admin/audit-logs — List audit logs
pub async fn audit_logs(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100);

    let mut stmt = conn.prepare("SELECT * FROM audit_logs WHERE org_id = ? ORDER BY timestamp DESC LIMIT ?")?;
    let rows = stmt.query_map(rusqlite::params![&user.org_id, limit], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "org_id": row.get::<_, String>(1)?,
            "user_id": row.get::<_, Option<String>>(2)?,
            "user_email": row.get::<_, Option<String>>(3)?,
            "action": row.get::<_, String>(4)?,
            "resource": row.get::<_, Option<String>>(5)?,
            "details": row.get::<_, Option<String>>(6)?,
            "ip_address": row.get::<_, Option<String>>(7)?,
            "timestamp": row.get::<_, String>(8)?,
        }))
    })?;

    let logs: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Ok(Json(json!(logs)))
}

/// GET /api/admin/export/:type — Export data as JSON
pub async fn export_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(export_type): Path<String>,
) -> AppResult<Json<Value>> {
    let user = require_admin(&headers)?;
    let conn = get_conn(&state.db)?;

    let data = match export_type.as_str() {
        "events" => {
            let mut stmt = conn.prepare("SELECT * FROM security_events WHERE org_id = ? ORDER BY timestamp DESC LIMIT 10000")?;
            let rows = stmt.query_map([&user.org_id], row_to_json)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        }
        "alerts" => {
            let mut stmt = conn.prepare("SELECT * FROM alerts WHERE org_id = ? ORDER BY alert_time DESC LIMIT 10000")?;
            let rows = stmt.query_map([&user.org_id], row_to_json)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        }
        "incidents" => {
            let mut stmt = conn.prepare("SELECT * FROM incidents WHERE org_id = ?")?;
            let rows = stmt.query_map([&user.org_id], row_to_json)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        }
        "audit" => {
            let mut stmt = conn.prepare("SELECT * FROM audit_logs WHERE org_id = ? ORDER BY timestamp DESC LIMIT 10000")?;
            let rows = stmt.query_map([&user.org_id], row_to_json)?;
            rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
        }
        _ => return Err(AppError::BadRequest("Invalid export type. Use: events, alerts, incidents, audit".to_string())),
    };

    let count = data.len();
    audit_log(&conn, &user.org_id, &user.id, &user.email, "export_data", "export", &json!({"type": export_type, "count": count}));

    Ok(Json(json!({
        "type": export_type,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "count": count,
        "data": data,
    })))
}

/// Require admin role
fn require_admin(headers: &HeaderMap) -> AppResult<auth::AuthUser> {
    let user = extract_auth_user(headers)?;
    if user.role != "admin" {
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }
    Ok(user)
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

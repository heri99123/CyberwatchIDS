use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::routes::auth::extract_auth_user;
use crate::state::SharedState;

/// GET /api/notifications
pub async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    let mut stmt = conn.prepare("SELECT * FROM notifications WHERE org_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50")?;
    let rows = stmt.query_map(rusqlite::params![&user.org_id, &user.id], row_to_json)?;
    let notifs: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!(notifs)))
}

/// PUT /api/notifications/:id/read
pub async fn mark_read(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(notif_id): Path<i64>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    let conn = get_conn(&state.db)?;

    conn.execute("UPDATE notifications SET read = 1 WHERE id = ? AND org_id = ?", rusqlite::params![notif_id, &user.org_id])?;

    Ok(Json(json!({"read": true})))
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

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use validator::Validate;

use crate::auth;
use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 100, message = "Organization name must be 2-100 characters"))]
    pub org_name: String,
    #[validate(length(min = 2, max = 100, message = "Name must be 2-100 characters"))]
    pub name: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, max = 128, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 1, max = 128, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
    pub organization: OrgInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub org_id: String,
    pub org_name: String,
}

#[derive(Debug, Serialize)]
pub struct OrgInfo {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
}

/// POST /api/auth/register — Register a new organization + admin user
pub async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<Json<Value>> {
    body.validate()
        .map_err(|e| AppError::BadRequest(format!("Validation failed: {}", e)))?;

    let conn = get_conn(&state.db)?;

    // Check existing email
    let existing: Option<String> = conn
        .query_row("SELECT id FROM users WHERE email = ?", [&body.email], |row| row.get(0))
        .ok();
    if existing.is_some() {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }

    let org_id = auth::gen_id("org_");
    let user_id = auth::gen_id("usr_");
    let slug = auth::slugify(&body.org_name);

    // Create organization
    conn.execute(
        "INSERT INTO organizations (id, name, slug, plan, max_users, settings) VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params![org_id, body.org_name, slug, "free", 5, r#"{"emailAlerts":false}"#],
    )?;

    // Hash password with Argon2
    let password_hash = auth::hash_password(&body.password)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?;

    // Create admin user
    conn.execute(
        "INSERT INTO users (id, org_id, email, name, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![user_id, org_id, body.email, body.name, password_hash, "admin", "active"],
    )?;

    // Generate JWT
    let token = auth::sign_jwt(&user_id, &body.email, &body.name, "admin", &org_id, &body.org_name)?;

    // Audit log
    audit_log(&conn, &org_id, &user_id, &body.email, "register", "organization", &json!({"orgName": body.org_name}));

    Ok(Json(json!({
        "token": token,
        "user": {
            "id": user_id,
            "email": body.email,
            "name": body.name,
            "role": "admin",
            "orgId": org_id,
            "orgName": body.org_name,
        },
        "organization": {
            "id": org_id,
            "name": body.org_name,
            "slug": slug,
            "plan": "free",
        }
    })))
}

/// POST /api/auth/login — Login with email + password
pub async fn login(
    State(state): State<SharedState>,
    Json(body): Json<LoginRequest>,
) -> AppResult<Json<Value>> {
    body.validate()
        .map_err(|e| AppError::BadRequest(format!("Validation failed: {}", e)))?;

    let conn = get_conn(&state.db)?;

    // Find user
    let user_row = conn
        .query_row(
            "SELECT id, org_id, email, name, password_hash, role, status FROM users WHERE email = ? AND status = 'active'",
            [&body.email],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,  // id
                    row.get::<_, String>(1)?,  // org_id
                    row.get::<_, String>(2)?,  // email
                    row.get::<_, String>(3)?,  // name
                    row.get::<_, String>(4)?,  // password_hash
                    row.get::<_, String>(5)?,  // role
                    row.get::<_, String>(6)?,  // status
                ))
            },
        )
        .map_err(|_| AppError::Unauthorized)?;

    let (user_id, org_id, email, name, password_hash, role, _status) = user_row;

    if !auth::verify_password(&body.password, &password_hash) {
        return Err(AppError::Unauthorized);
    }

    // Get org info
    let org_name: String = conn
        .query_row("SELECT name FROM organizations WHERE id = ?", [&org_id], |row| row.get(0))
        .map_err(|_| AppError::Internal("Organization not found".to_string()))?;

    // Update last login
    conn.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", [&user_id])?;

    let token = auth::sign_jwt(&user_id, &email, &name, &role, &org_id, &org_name)?;

    audit_log(&conn, &org_id, &user_id, &email, "login", "auth", &json!({}));

    Ok(Json(json!({
        "token": token,
        "user": {
            "id": user_id,
            "email": email,
            "name": name,
            "role": role,
            "orgId": org_id,
            "orgName": org_name,
        },
        "organization": {
            "id": org_id,
            "name": org_name,
        }
    })))
}

/// GET /api/auth/verify — Verify JWT token
pub async fn verify(headers: HeaderMap) -> AppResult<Json<Value>> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let claims = auth::verify_jwt(token).ok_or(AppError::InvalidToken)?;

    Ok(Json(json!({
        "user": {
            "id": claims.sub,
            "email": claims.email,
            "name": claims.name,
            "role": claims.role,
            "orgId": claims.org_id,
            "orgName": claims.org_name,
        },
        "organization": {
            "id": claims.org_id,
            "name": claims.org_name,
        }
    })))
}

/// GET /api/auth/me — Get current user profile
pub async fn me(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;

    let conn = get_conn(&state.db)?;
    let row = conn
        .query_row(
            "SELECT u.id, u.email, u.name, u.role, u.status, u.last_login, u.created_at, o.name, o.plan, o.max_users FROM users u JOIN organizations o ON u.org_id = o.id WHERE u.id = ?",
            [&user.id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .map_err(|_| AppError::NotFound("User not found".to_string()))?;

    let (id, email, name, role, status, last_login, created_at, org_name, plan, max_users) = row;

    Ok(Json(json!({
        "user": {
            "id": id,
            "email": email,
            "name": name,
            "role": role,
            "status": status,
            "lastLogin": last_login,
            "createdAt": created_at,
            "orgName": org_name,
            "plan": plan,
            "maxUsers": max_users,
        }
    })))
}

/// Extract authenticated user from headers
pub fn extract_auth_user(headers: &HeaderMap) -> AppResult<auth::AuthUser> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());

    auth::extract_auth_user(auth_header, api_key).ok_or(AppError::Unauthorized)
}

/// Write an audit log entry
pub fn audit_log(
    conn: &rusqlite::Connection,
    org_id: &str,
    user_id: &str,
    user_email: &str,
    action: &str,
    resource: &str,
    details: &Value,
) {
    let _ = conn.execute(
        "INSERT INTO audit_logs (org_id, user_id, user_email, action, resource, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            org_id,
            user_id,
            user_email,
            action,
            resource,
            details.to_string(),
            "",
        ],
    );
}

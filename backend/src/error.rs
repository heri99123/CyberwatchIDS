use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    /// Progressive account lockout after repeated failed logins (Task #26).
    /// Maps to HTTP 429 with a `Retry-After` header.
    #[error("Account temporarily locked")]
    AccountLocked { retry_after_secs: u64 },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, retry_after): (
            StatusCode,
            &'static str,
            String,
            Option<u64>,
        ) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "NO_TOKEN", self.to_string(), None),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", self.to_string(), None),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN", self.to_string(), None),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", self.to_string(), None),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND", self.to_string(), None),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT", self.to_string(), None),
            AppError::AccountLocked { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                "ACCOUNT_LOCKED",
                format!(
                    "Account temporarily locked. Try again in {} seconds.",
                    retry_after_secs
                ),
                Some(*retry_after_secs),
            ),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", self.to_string(), None),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", self.to_string(), None),
        };

        let mut payload = json!({
            "error": message,
            "code": code,
        });
        if let Some(secs) = retry_after {
            payload["retryAfter"] = json!(secs);
        }

        let mut response = (status, Json(payload)).into_response();
        if let Some(secs) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("[DB] SQLite error: {}", e);
        AppError::Database(e.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("[Internal] {}", e);
        AppError::Internal(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!("[JSON] {}", e);
        AppError::Internal(format!("JSON error: {}", e))
    }
}

pub type AppResult<T> = Result<T, AppError>;

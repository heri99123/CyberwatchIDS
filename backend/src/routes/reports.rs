//! Report export endpoints (Task #31).
//!
//! GET  /api/reports                 -> catalogue + scheduler status
//! GET  /api/reports/:kind           -> CSV / PDF / JSON download
//! POST /api/reports/:kind/send      -> email the report with CSV attachment
//!
//! All data is strictly scoped to the caller's organization. The older
//! `/api/admin/export/:type` JSON endpoint is kept for backward compatibility.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::db::get_conn;
use crate::error::{AppError, AppResult};
use crate::mailer;
use crate::reports::{self, ReportFormat, ReportKind, ReportQuery};
use crate::routes::auth::{audit_log, extract_auth_user};
use crate::state::SharedState;

fn parse_query(params: &HashMap<String, String>) -> AppResult<ReportQuery> {
    let mut from = None;
    let mut to = None;

    if let Some(raw) = params.get("from") {
        if !raw.trim().is_empty() {
            from = Some(
                reports::parse_date(raw)
                    .ok_or_else(|| AppError::BadRequest("`from` must be YYYY-MM-DD".to_string()))?,
            );
        }
    }
    if let Some(raw) = params.get("to") {
        if !raw.trim().is_empty() {
            to = Some(
                reports::parse_date(raw)
                    .ok_or_else(|| AppError::BadRequest("`to` must be YYYY-MM-DD".to_string()))?,
            );
        }
    }
    if let (Some(f), Some(t)) = (&from, &to) {
        if f > t {
            return Err(AppError::BadRequest(
                "`from` must not be later than `to`".to_string(),
            ));
        }
    }

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(reports::DEFAULT_ROWS)
        .clamp(1, reports::MAX_ROWS);

    Ok(ReportQuery { from, to, limit })
}

fn parse_kind(raw: &str) -> AppResult<ReportKind> {
    ReportKind::parse(raw).ok_or_else(|| {
        AppError::BadRequest(format!(
            "Unknown report kind '{}'. Use: security-summary, incident-report, audit-trail, compliance",
            raw
        ))
    })
}

fn parse_format(raw: &str) -> AppResult<ReportFormat> {
    ReportFormat::parse(raw).ok_or_else(|| {
        AppError::BadRequest("Invalid format. Use: csv, pdf, json".to_string())
    })
}

/// GET /api/reports — describe available reports and the scheduler.
pub async fn index(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let _user = extract_auth_user(&headers)?;
    let kinds: Vec<Value> = ReportKind::ALL
        .iter()
        .map(|k| {
            json!({
                "id": k.slug(),
                "title": k.title(),
                "description": k.description(),
            })
        })
        .collect();

    Ok(Json(json!({
        "kinds": kinds,
        "formats": ["csv", "pdf", "json"],
        "defaultRows": reports::DEFAULT_ROWS,
        "maxRows": reports::MAX_ROWS,
        "smtpEnabled": state.mailer.is_enabled(),
        "schedule": reports::schedule_status(state.mailer.is_enabled()),
    })))
}

/// GET /api/reports/:kind?format=csv|pdf|json&from=YYYY-MM-DD&to=YYYY-MM-DD
pub async fn download(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(kind_raw): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    let user = extract_auth_user(&headers)?;
    let kind = parse_kind(&kind_raw)?;
    let format = parse_format(params.get("format").map(|s| s.as_str()).unwrap_or("csv"))?;
    let query = parse_query(&params)?;

    let report = reports::build_report(&state.db, &user.org_id, kind, &query)
        .map_err(|e| AppError::Internal(format!("Report generation failed: {}", e)))?;

    // Every export is recorded in the audit trail for compliance evidence.
    if let Ok(conn) = get_conn(&state.db) {
        audit_log(
            &conn,
            &user.org_id,
            &user.id,
            &user.email,
            "export_report",
            "report",
            &json!({
                "kind": kind.slug(),
                "format": format.slug(),
                "rows": report.table.rows.len(),
                "from": query.from,
                "to": query.to,
            }),
        );
    }

    let filename = format!(
        "cyberwatch-{}-{}.{}",
        kind.slug(),
        chrono::Utc::now().format("%Y%m%d"),
        format.slug()
    );

    let (bytes, content_type): (Vec<u8>, &'static str) = match format {
        ReportFormat::Csv => (
            report
                .to_csv()
                .map_err(|e| AppError::Internal(format!("CSV render failed: {}", e)))?,
            "text/csv; charset=utf-8",
        ),
        ReportFormat::Pdf => (report.to_pdf(), "application/pdf"),
        ReportFormat::Json => (
            serde_json::to_vec_pretty(&report.to_json())?,
            "application/json; charset=utf-8",
        ),
    };

    let mut response = Response::new(axum::body::Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// POST /api/reports/:kind/send — admin-only on-demand email delivery.
pub async fn email(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(kind_raw): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;
    if user.role != "admin" {
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }
    let kind = parse_kind(&kind_raw)?;
    let query = parse_query(&params)?;

    // Optional explicit recipients: string "a@b,c@d" or JSON array.
    let mut recipients: Vec<String> = Vec::new();
    match body.get("recipients") {
        Some(Value::String(s)) => recipients.extend(mailer::split_list(s)),
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    recipients.push(s.trim().to_string());
                }
            }
        }
        _ => {}
    }
    recipients.retain(|s| s.contains('@') && s.len() <= 200);
    recipients.truncate(20);

    if recipients.is_empty() {
        recipients = mailer::org_alert_recipients(&state.db, &user.org_id);
        if recipients.is_empty() {
            recipients = state.mailer.fallback_recipients().to_vec();
        }
    }
    if recipients.is_empty() {
        return Err(AppError::BadRequest(
            "No recipients. Add `recipients` in the body or configure active admin emails / ALERT_EMAIL_TO."
                .to_string(),
        ));
    }

    let report = reports::build_report(&state.db, &user.org_id, kind, &query)
        .map_err(|e| AppError::Internal(format!("Report generation failed: {}", e)))?;
    let csv_bytes = report
        .to_csv()
        .map_err(|e| AppError::Internal(format!("CSV render failed: {}", e)))?;

    if let Ok(conn) = get_conn(&state.db) {
        audit_log(
            &conn,
            &user.org_id,
            &user.id,
            &user.email,
            "email_report",
            "report",
            &json!({
                "kind": kind.slug(),
                "recipients": recipients.len(),
                "rows": report.table.rows.len(),
            }),
        );
    }

    if !state.mailer.is_enabled() {
        return Ok(Json(json!({
            "queued": false,
            "reason": "SMTP is disabled (SMTP_ENABLED=false). Enable SMTP to deliver reports.",
            "kind": kind.slug(),
            "rows": report.table.rows.len(),
        })));
    }

    let subject = format!(
        "[CyberWatch IDS] {} — {}",
        report.kind.title(),
        chrono::Utc::now().format("%Y-%m-%d")
    );
    let filename = format!(
        "cyberwatch-{}-{}.csv",
        kind.slug(),
        chrono::Utc::now().format("%Y%m%d")
    );
    mailer::spawn_report_send(
        state.mailer.clone(),
        recipients.clone(),
        subject,
        report.to_html(),
        filename,
        csv_bytes,
    );

    Ok(Json(json!({
        "queued": true,
        "kind": kind.slug(),
        "recipients": recipients.len(),
        "rows": report.table.rows.len(),
    })))
}

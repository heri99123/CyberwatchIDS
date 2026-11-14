//! Real traffic ingestion (Task #29).
//!
//! External shippers (reverse-proxy mirrors, WAF, log collectors, SIEM) push
//! requests here instead of relying on the built-in attack simulator. Every
//! record is run through the same regex IDS engine and `event_pipeline` as the
//! simulator, so it lands in the database, WebSocket dashboard and email alerts.
//!
//! Endpoints (both require `X-API-Key` with read-write permission, or a JWT):
//!   POST /api/ingest/webhook  — one JSON record, an array, or {events:[...]}
//!   POST /api/ingest/syslog   — plain-text syslog lines or {lines:[...]}
//!
//! Optional UDP syslog listener is enabled with SYSLOG_UDP_PORT +
//! SYSLOG_UDP_API_KEY (see `udp_syslog_config`).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::db::{get_conn, DbPool};
use crate::error::{AppError, AppResult};
use crate::event_pipeline::publish_detections;
use crate::ids_engine::{Detection, RequestData};
use crate::routes::auth::extract_ingest_principal;
use crate::state::SharedState;

const MAX_WEBHOOK_BATCH: usize = 100;
const MAX_SYSLOG_LINES: usize = 200;
const MAX_DETECTIONS_PER_REQUEST: usize = 500;
const MAX_FIELD_CHARS: usize = 8_192;
const MAX_SYSLOG_LINE_CHARS: usize = 4_096;

fn clamp_str(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Bound attacker-controlled JSON: cap string length, key/array count and the
/// total number of characters fed to the regex engine. Without this a single
/// 1 MB field could be matched against every rule repeatedly.
fn clamp_json(value: &Value) -> Value {
    fn walk(v: &Value, budget: &mut usize) -> Value {
        if *budget == 0 {
            return Value::Null;
        }
        match v {
            Value::String(s) => {
                let take = (*budget).min(MAX_FIELD_CHARS);
                let truncated: String = s.chars().take(take).collect();
                *budget = (*budget).saturating_sub(truncated.chars().count());
                Value::String(truncated)
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, val) in map.iter().take(64) {
                    if *budget == 0 {
                        break;
                    }
                    out.insert(clamp_str(key, 128), walk(val, budget));
                }
                Value::Object(out)
            }
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items.iter().take(64) {
                    if *budget == 0 {
                        break;
                    }
                    out.push(walk(item, budget));
                }
                Value::Array(out)
            }
            other => other.clone(),
        }
    }
    let mut budget = 16_384usize;
    walk(value, &mut budget)
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Normalized HTTP request record. Aliases accept common shipper field names.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IngestRecord {
    #[serde(alias = "sourceIp", alias = "clientIp", alias = "remote_addr", alias = "ip")]
    source_ip: String,
    #[serde(alias = "sourcePort")]
    source_port: Option<i64>,
    #[serde(alias = "host", alias = "dest", alias = "target")]
    destination: String,
    #[serde(alias = "verb")]
    method: String,
    #[serde(alias = "uri", alias = "url")]
    path: String,
    #[serde(alias = "params")]
    query: Option<Value>,
    #[serde(alias = "payload")]
    body: Option<Value>,
    #[serde(alias = "httpHeaders")]
    headers: Option<Value>,
    /// Raw HTTP request line, e.g. `GET /?id=1' UNION SELECT ... HTTP/1.1`.
    #[serde(alias = "message", alias = "line")]
    raw: Option<String>,
}

fn parse_records(value: Value) -> AppResult<Vec<IngestRecord>> {
    // A bare string is treated as a raw HTTP request line.
    let value = match value {
        Value::String(s) => json!({ "raw": s }),
        other => other,
    };

    let target = match &value {
        Value::Array(_) => value.clone(),
        Value::Object(map) => ["events", "records", "logs", "requests"]
            .iter()
            .find_map(|key| map.get(*key))
            .cloned()
            .unwrap_or_else(|| value.clone()),
        _ => value.clone(),
    };

    let result = if target.is_array() {
        serde_json::from_value::<Vec<IngestRecord>>(target)
    } else {
        serde_json::from_value::<IngestRecord>(target).map(|r| vec![r])
    };
    result.map_err(|e| AppError::BadRequest(format!("Invalid ingest payload: {}", e)))
}

fn to_request_data(record: &IngestRecord, fallback_ip: Option<&str>) -> RequestData {
    let mut source_ip = record.source_ip.trim().to_string();

    // Common proxy setups put the real client in X-Forwarded-For.
    if source_ip.is_empty() {
        if let Some(Value::Object(headers)) = &record.headers {
            for name in ["x-forwarded-for", "x-real-ip"] {
                if let Some(v) = headers.get(name) {
                    let text = value_to_string(v);
                    let candidate = text.split(',').next().unwrap_or("").trim();
                    if !candidate.is_empty() {
                        source_ip = candidate.to_string();
                        break;
                    }
                }
            }
        }
    }
    if source_ip.is_empty() {
        source_ip = fallback_ip.unwrap_or("").to_string();
    }

    let mut method = clamp_str(&record.method, 32);
    let mut path = clamp_str(&record.path, MAX_FIELD_CHARS);
    let mut body = record.body.as_ref().map(clamp_json);

    if let Some(raw) = &record.raw {
        let line = clamp_str(raw, MAX_FIELD_CHARS);
        let mut parts = line.split_whitespace();
        if method.is_empty() {
            method = clamp_str(parts.next().unwrap_or("GET"), 32);
        }
        if path.is_empty() {
            path = clamp_str(parts.next().unwrap_or("/"), MAX_FIELD_CHARS);
        }
        if body.is_none() {
            body = Some(Value::String(line));
        }
    }

    RequestData {
        method: if method.is_empty() { "GET".to_string() } else { method },
        path: if path.is_empty() { "/".to_string() } else { path },
        query: record.query.as_ref().map(clamp_json),
        body,
        headers: record.headers.as_ref().map(clamp_json),
        source_ip,
        source_port: record.source_port,
        destination: clamp_str(&record.destination, 256),
    }
}

fn inspect_records(state: &SharedState, records: &[IngestRecord]) -> (Vec<Detection>, bool) {
    let mut detections = Vec::new();
    let mut truncated = false;
    for record in records {
        let request = to_request_data(record, None);
        detections.extend(state.ids.inspect_request(&request).detections);
        if detections.len() >= MAX_DETECTIONS_PER_REQUEST {
            detections.truncate(MAX_DETECTIONS_PER_REQUEST);
            truncated = true;
            break;
        }
    }
    (detections, truncated)
}

/// POST /api/ingest/webhook — normalized HTTP request(s).
pub async fn webhook(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> AppResult<Json<Value>> {
    let principal = extract_ingest_principal(&state, &headers)?;
    let records = parse_records(payload)?;

    if records.is_empty() {
        return Err(AppError::BadRequest("No records to ingest".to_string()));
    }
    if records.len() > MAX_WEBHOOK_BATCH {
        return Err(AppError::BadRequest(format!(
            "Batch too large (max {} records)",
            MAX_WEBHOOK_BATCH
        )));
    }

    let (detections, truncated) = inspect_records(&state, &records);
    let blocked = detections.iter().any(|d| d.action == "block");
    let events = publish_detections(&state, &principal.org_id, &detections).await?;

    tracing::info!(
        "[Ingest] webhook org={} via={} records={} detections={}",
        principal.org_id,
        principal.via,
        records.len(),
        detections.len()
    );

    Ok(Json(json!({
        "accepted": records.len(),
        "detections": detections.len(),
        "eventsCreated": events.len(),
        "blocked": blocked,
        "truncated": truncated,
        "via": principal.via,
    })))
}

fn syslog_lines(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            let items: Vec<Value> = match parsed {
                Value::Array(items) => items,
                Value::Object(map) => ["lines", "messages", "logs"]
                    .iter()
                    .find_map(|key| map.get(*key))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            if !items.is_empty() {
                return items
                    .iter()
                    .take(MAX_SYSLOG_LINES)
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .map(|s| clamp_str(&s, MAX_SYSLOG_LINE_CHARS))
                    .collect();
            }
        }
    }

    text.lines()
        .take(MAX_SYSLOG_LINES)
        .filter(|line| !line.trim().is_empty())
        .map(|line| clamp_str(line, MAX_SYSLOG_LINE_CHARS))
        .collect()
}

fn extract_ip(line: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    re.find(line).map(|m| m.as_str().to_string())
}

/// Shared by the HTTP syslog endpoint and the UDP listener.
async fn process_syslog_text(
    state: &SharedState,
    org_id: &str,
    text: &str,
    fallback_ip: Option<&str>,
) -> AppResult<Value> {
    let lines = syslog_lines(text);
    if lines.is_empty() {
        return Err(AppError::BadRequest("No syslog lines received".to_string()));
    }

    let mut detections: Vec<Detection> = Vec::new();
    let mut truncated = false;
    for line in &lines {
        let ip = extract_ip(line).or_else(|| fallback_ip.map(|s| s.to_string()));
        let request = RequestData {
            method: "SYSLOG".to_string(),
            path: "/syslog".to_string(),
            query: None,
            body: Some(Value::String(line.clone())),
            headers: Some(json!({ "user-agent": "syslog" })),
            source_ip: ip.unwrap_or_default(),
            source_port: None,
            destination: "syslog".to_string(),
        };
        detections.extend(state.ids.inspect_request(&request).detections);
        if detections.len() >= MAX_DETECTIONS_PER_REQUEST {
            detections.truncate(MAX_DETECTIONS_PER_REQUEST);
            truncated = true;
            break;
        }
    }

    let blocked = detections.iter().any(|d| d.action == "block");
    let events = publish_detections(state, org_id, &detections).await?;

    Ok(json!({
        "accepted": lines.len(),
        "detections": detections.len(),
        "eventsCreated": events.len(),
        "blocked": blocked,
        "truncated": truncated,
    }))
}

/// POST /api/ingest/syslog — plain-text lines or JSON {lines:[...]}.
pub async fn syslog(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<Value>> {
    let principal = extract_ingest_principal(&state, &headers)?;
    let text = String::from_utf8_lossy(&body[..]).to_string();
    let mut summary = process_syslog_text(&state, &principal.org_id, &text, None).await?;
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("via".to_string(), json!(principal.via));
    }
    Ok(Json(summary))
}

/// Resolve the optional UDP listener config from env. The UDP listener has no
/// per-request auth, so it is bound to ONE org via a read-write API key.
/// Returns None (disabled) when misconfigured — startup never fails.
pub fn udp_syslog_config(pool: &DbPool) -> Option<(u16, String)> {
    let port: u16 = std::env::var("SYSLOG_UDP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if port == 0 {
        return None;
    }

    let key = std::env::var("SYSLOG_UDP_API_KEY").unwrap_or_default();
    let key = key.trim();
    if key.is_empty() {
        tracing::warn!(
            "[Ingest] SYSLOG_UDP_PORT is set but SYSLOG_UDP_API_KEY is empty — listener disabled"
        );
        return None;
    }

    let hash = crate::auth::hash_api_key(key);
    let conn = get_conn(pool).ok()?;
    let found: Option<(String, String)> = conn
        .query_row(
            "SELECT org_id, permissions FROM api_keys WHERE key_hash = ? AND revoked = 0",
            [&hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok();

    match found {
        Some((org_id, permissions)) if permissions == "read-write" => Some((port, org_id)),
        Some(_) => {
            tracing::warn!(
                "[Ingest] SYSLOG_UDP_API_KEY needs read-write permission — listener disabled"
            );
            None
        }
        None => {
            tracing::warn!(
                "[Ingest] SYSLOG_UDP_API_KEY not found or revoked — listener disabled"
            );
            None
        }
    }
}

/// Spawn the UDP syslog listener. Bind failures are logged, never fatal.
pub fn spawn_udp_syslog_listener(state: SharedState, port: u16, org_id: String) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "[Ingest] syslog UDP bind 0.0.0.0:{} failed: {}",
                    port,
                    e
                );
                return;
            }
        };
        tracing::info!(
            "[Ingest] syslog UDP listener 0.0.0.0:{} -> org {}",
            port,
            org_id
        );

        let mut buf = vec![0u8; 65_535];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("[Ingest] syslog UDP recv failed: {}", e);
                    continue;
                }
            };
            let text = String::from_utf8_lossy(&buf[..len]).to_string();
            let peer_ip = peer.ip().to_string();
            if let Err(e) =
                process_syslog_text(&state, &org_id, &text, Some(peer_ip.as_str())).await
            {
                tracing::warn!("[Ingest] syslog UDP processing failed: {}", e);
            }
        }
    });
}

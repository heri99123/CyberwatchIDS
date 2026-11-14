use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{AppError, AppResult};
use crate::routes::auth::extract_auth_user;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct StartSimRequest {
    pub interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AttackRequest {
    pub attack_type: String,
}

/// POST /api/simulate/start
pub async fn start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<StartSimRequest>,
) -> AppResult<Json<Value>> {
    let _user = extract_auth_user(&headers)?;
    let interval = body.interval.unwrap_or(3000);

    state.simulator.start(interval, tokio::sync::broadcast::channel(100).0);

    Ok(Json(json!({"status": "running", "interval": interval})))
}

/// POST /api/simulate/stop
pub async fn stop(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let _user = extract_auth_user(&headers)?;
    state.simulator.stop();
    Ok(Json(json!({"status": "stopped"})))
}

/// GET /api/simulate/status
pub async fn status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let _user = extract_auth_user(&headers)?;
    Ok(Json(json!({"running": state.simulator.is_running()})))
}

/// POST /api/simulate/attack — Manual attack injection
pub async fn attack(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AttackRequest>,
) -> AppResult<Json<Value>> {
    let user = extract_auth_user(&headers)?;

    let req_data = state.simulator.generate_attack(&body.attack_type)
        .ok_or_else(|| AppError::BadRequest("Unknown attack type".to_string()))?;

    let result = state.ids.inspect_request(&req_data);

    let mut logged_events = Vec::new();
    for detection in &result.detections {
        let event_id = state.ids.log_security_event(detection, Some(&user.org_id))?;

        let mut detection_json = serde_json::to_value(detection).unwrap_or(json!({}));
        let event_with_id = if let Some(obj) = detection_json.as_object_mut() {
            obj.insert("id".to_string(), json!(event_id));
            obj.insert("timestamp".to_string(), json!(chrono::Utc::now().to_rfc3339()));
            Value::Object(obj.clone())
        } else {
            json!({})
        };

        logged_events.push(event_with_id.clone());

        state.broadcast("events", &event_with_id, Some(&user.org_id)).await;

        if detection.severity == "CRITICAL" || detection.severity == "HIGH" {
            let alert = json!({
                "event_id": event_id,
                "alert_type": detection.attack_type,
                "message": format!("{} severity: {} from {}", detection.severity, detection.rule_name, detection.source_ip),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            state.broadcast("alerts", &alert, Some(&user.org_id)).await;
        }
    }

    if result.total_detections > 0 {
        let stats = state.ids.get_stats(Some(&user.org_id));
        state.broadcast("stats", &stats, Some(&user.org_id)).await;
    }

    Ok(Json(json!({"fired": true, "detections": result.total_detections, "events": logged_events})))
}

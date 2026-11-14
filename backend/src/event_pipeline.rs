//! Shared detection publishing pipeline (Task #29).
//!
//! Every source of security events — the attack simulator, webhook ingest and
//! syslog ingest — goes through here so event persistence, WebSocket fan-out,
//! stats refresh and email alerts behave identically everywhere.

use crate::error::AppResult;
use crate::ids_engine::Detection;
use crate::state::SharedState;
use serde_json::{json, Value};

/// Persist detections, broadcast them, and emit alerts/email for high severity.
/// Returns the JSON event objects that were stored (with `id` + `timestamp`).
pub async fn publish_detections(
    state: &SharedState,
    org_id: &str,
    detections: &[Detection],
) -> AppResult<Vec<Value>> {
    let mut events = Vec::with_capacity(detections.len());

    for detection in detections {
        let event_id = state
            .ids
            .log_security_event(detection, Some(org_id))?;
        let timestamp = chrono::Utc::now().to_rfc3339();

        let mut event = serde_json::to_value(detection).unwrap_or_else(|_| json!({}));
        if let Some(obj) = event.as_object_mut() {
            obj.insert("id".to_string(), json!(event_id));
            obj.insert("timestamp".to_string(), json!(timestamp));
        }
        events.push(event.clone());

        state.broadcast("events", &event, Some(org_id)).await;

        if detection.severity == "CRITICAL" || detection.severity == "HIGH" {
            let alert = json!({
                "event_id": event_id,
                "alert_type": detection.attack_type,
                "message": format!(
                    "{} severity: {} from {}",
                    detection.severity, detection.rule_name, detection.source_ip
                ),
                "timestamp": timestamp,
            });
            state.broadcast("alerts", &alert, Some(org_id)).await;
            send_alert_email(state, org_id, detection, &timestamp);
        }
    }

    if !events.is_empty() {
        let stats = state.ids.get_stats(Some(org_id));
        state.broadcast("stats", &stats, Some(org_id)).await;
    }

    Ok(events)
}

/// Fire-and-forget email alert. Requires SMTP enabled, org opt-in and severity
/// threshold; SMTP failures can never fail the ingest request.
fn send_alert_email(
    state: &SharedState,
    org_id: &str,
    detection: &Detection,
    timestamp: &str,
) {
    if !state.mailer.is_enabled()
        || !crate::mailer::meets_threshold(&detection.severity, state.mailer.min_severity())
        || !crate::mailer::org_email_alerts_enabled(&state.db, org_id)
    {
        return;
    }

    let mut recipients = crate::mailer::org_alert_recipients(&state.db, org_id);
    if recipients.is_empty() {
        recipients = state.mailer.fallback_recipients().to_vec();
    }
    if recipients.is_empty() {
        return;
    }

    let (subject, html) = crate::mailer::alert_email(
        &detection.severity,
        &detection.attack_type,
        &detection.rule_name,
        &detection.source_ip,
        &detection.path,
        timestamp,
    );
    crate::mailer::spawn_send(state.mailer.clone(), recipients, subject, html);
}

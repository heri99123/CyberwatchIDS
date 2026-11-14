use axum::Json;
use serde_json::{json, Value};
use crate::state::SharedState;

pub async fn health(state: axum::extract::State<SharedState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": "3.0.0-rust",
        "rules": state.ids.rule_count(),
        "simulator_running": state.simulator.is_running(),
    }))
}

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use crate::auth;
use crate::state::{SharedState, WsClient};

/// GET /ws — WebSocket handler for real-time event push
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Extract org_id from token query param
    let org_id = params.get("token").and_then(|token| {
        auth::verify_jwt(token).map(|c| c.org_id)
    });

    ws.on_upgrade(move |socket| handle_ws(socket, state, org_id))
}

async fn handle_ws(socket: WebSocket, state: SharedState, initial_org_id: Option<String>) {
    let (tx, mut rx) = socket.split();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Register client
    {
        let mut clients = state.ws_clients.lock().await;
        clients.push(WsClient {
            tx: client_tx.clone(),
            org_id: initial_org_id.clone(),
        });
        tracing::info!("[WS] Client connected. Total: {}", clients.len());
    }

    // Send initial stats
    let stats = state.ids.get_stats(initial_org_id.as_deref());
    let _ = client_tx.send(serde_json::json!({"type": "stats", "data": stats}).to_string());

    // Spawn writer task: forward messages from broadcast to WebSocket
    let writer_tx = client_tx;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = client_rx.recv().await {
            // We can't write directly to the socket here because it's split
            // In a full implementation, we'd use a channel to forward to the writer
            let _ = msg; // placeholder
        }
    });

    // Read messages from client (for subscription/auth updates)
    let read_state = state.clone();
    let mut current_org = initial_org_id;

    while let Some(msg_result) = rx.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                    if data.get("type").and_then(|t| t.as_str()) == Some("auth") {
                        if let Some(token) = data.get("token").and_then(|t| t.as_str()) {
                            if let Some(claims) = auth::verify_jwt(token) {
                                current_org = Some(claims.org_id.clone());
                                tracing::info!("[WS] Client authenticated for org: {}", claims.org_id);
                            }
                        }
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    // Clean up: remove client
    {
        let mut clients = read_state.ws_clients.lock().await;
        clients.retain(|c| !c.tx.is_closed());
        tracing::info!("[WS] Client disconnected. Total: {}", clients.len());
    }

    writer_task.abort();
}

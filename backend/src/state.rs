use crate::db::DbPool;
use crate::ids_engine::IdsEngine;
use crate::mailer::Mailer;
use crate::simulator::AttackSimulator;
use std::sync::Arc;

/// WebSocket client holder
pub struct WsClient {
    pub tx: tokio::sync::mpsc::UnboundedSender<String>,
    pub org_id: Option<String>,
}

/// Shared application state accessible by all route handlers
pub struct AppState {
    pub db: DbPool,
    pub ids: IdsEngine,
    pub simulator: AttackSimulator,
    pub ws_clients: tokio::sync::Mutex<Vec<WsClient>>,
    pub mailer: Arc<Mailer>,
}

impl AppState {
    /// Broadcast a message to all connected WebSocket clients.
    /// If org_id is Some, only clients belonging to that org receive it.
    pub async fn broadcast(&self, msg_type: &str, data: &serde_json::Value, org_id: Option<&str>) {
        let message = serde_json::json!({
            "type": msg_type,
            "data": data,
        })
        .to_string();

        let mut clients = self.ws_clients.lock().await;
        clients.retain(|client| {
            // If org_id is specified, only send to clients of that org
            if let Some(oid) = org_id {
                if let Some(client_org) = &client.org_id {
                    if client_org != oid {
                        return true; // keep client, but skip sending
                    }
                }
            }
            let _ = client.tx.send(message.clone());
            true
        });
    }

    /// Broadcast to all clients regardless of org
    pub async fn broadcast_all(&self, msg_type: &str, data: &serde_json::Value) {
        self.broadcast(msg_type, data, None).await;
    }
}

pub type SharedState = Arc<AppState>;

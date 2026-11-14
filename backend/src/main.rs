use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod db;
mod ids_engine;
mod auth;
mod simulator;
mod routes;
mod state;
mod error;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,cyberwatch=debug")))
        .with(fmt::layer())
        .init();

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8421".to_string())
        .parse()
        .unwrap_or(8421);

    // Initialize database
    let db_path = std::env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "../data/cve-database.db".to_string());
    let pool = db::init_database(&db_path)?;

    // Initialize IDS engine
    let ids = ids_engine::IdsEngine::new(pool.clone());
    ids.load_rules();
    tracing::info!("[IDS] Loaded {} active detection rules", ids.rule_count());

    // Initialize simulator
    let simulator = simulator::AttackSimulator::new();

    // Create shared application state
    let state = Arc::new(AppState {
        db: pool,
        ids,
        simulator,
        ws_clients: tokio::sync::Mutex::new(Vec::new()),
    });

    // Build router
    let app = build_router(state.clone());

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("");
    tracing::info!("============================================");
    tracing::info!("  CyberWatch IDS v3.0 - Rust Backend");
    tracing::info!("============================================");
    tracing::info!("  Dashboard:  http://localhost:{}", port);
    tracing::info!("  WebSocket:  ws://localhost:{}/ws", port);
    tracing::info!("  API Base:   http://localhost:{}/api", port);
    tracing::info!("============================================");
    tracing::info!("");
    tracing::info!("[IDS] Engine initialized with {} rules", state.ids.rule_count());
    tracing::info!("[Auth] JWT authentication enabled");
    tracing::info!("[Multi-tenant] Organization data isolation active");
    tracing::info!("");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::permissive();
    let compression = CompressionLayer::new();

    Router::new()
        // Auth routes (public)
        .route("/api/auth/register", axum::routing::post(routes::auth::register))
        .route("/api/auth/login", axum::routing::post(routes::auth::login))
        .route("/api/auth/verify", axum::routing::get(routes::auth::verify))
        // Authenticated routes
        .route("/api/auth/me", axum::routing::get(routes::auth::me))
        // Admin routes
        .route("/api/admin/users", axum::routing::get(routes::admin::list_users))
        .route("/api/admin/users", axum::routing::post(routes::admin::create_user))
        .route("/api/admin/users/:id/role", axum::routing::put(routes::admin::update_role))
        .route("/api/admin/users/:id/status", axum::routing::put(routes::admin::update_status))
        .route("/api/admin/users/:id", axum::routing::delete(routes::admin::delete_user))
        .route("/api/admin/org", axum::routing::get(routes::admin::get_org))
        .route("/api/admin/org", axum::routing::put(routes::admin::update_org))
        .route("/api/admin/api-keys", axum::routing::get(routes::admin::list_api_keys))
        .route("/api/admin/api-keys", axum::routing::post(routes::admin::create_api_key))
        .route("/api/admin/api-keys/:id", axum::routing::delete(routes::admin::revoke_api_key))
        .route("/api/admin/audit-logs", axum::routing::get(routes::admin::audit_logs))
        .route("/api/admin/export/:type", axum::routing::get(routes::admin::export_data))
        // Incidents
        .route("/api/incidents", axum::routing::get(routes::incidents::list))
        .route("/api/incidents", axum::routing::post(routes::incidents::create))
        .route("/api/incidents/:id", axum::routing::put(routes::incidents::update))
        // Notifications
        .route("/api/notifications", axum::routing::get(routes::notifications::list))
        .route("/api/notifications/:id/read", axum::routing::put(routes::notifications::mark_read))
        // IDS data routes
        .route("/api/stats", axum::routing::get(routes::ids::stats))
        .route("/api/events", axum::routing::get(routes::ids::events))
        .route("/api/events/search", axum::routing::get(routes::ids::events_search))
        .route("/api/alerts", axum::routing::get(routes::ids::alerts))
        .route("/api/alerts/:id/acknowledge", axum::routing::put(routes::ids::acknowledge_alert))
        .route("/api/cve", axum::routing::get(routes::ids::cve_list))
        .route("/api/cve/:id", axum::routing::get(routes::ids::cve_detail))
        .route("/api/rules", axum::routing::get(routes::ids::rules))
        .route("/api/rules/:id/toggle", axum::routing::put(routes::ids::toggle_rule))
        .route("/api/ip-reputation", axum::routing::get(routes::ids::ip_reputation))
        .route("/api/ip-reputation/:ip/block", axum::routing::put(routes::ids::block_ip))
        .route("/api/ip-reputation/:ip/unblock", axum::routing::put(routes::ids::unblock_ip))
        .route("/api/reset", axum::routing::post(routes::ids::reset_data))
        // Simulator
        .route("/api/simulate/start", axum::routing::post(routes::simulator::start))
        .route("/api/simulate/stop", axum::routing::post(routes::simulator::stop))
        .route("/api/simulate/status", axum::routing::get(routes::simulator::status))
        .route("/api/simulate/attack", axum::routing::post(routes::simulator::attack))
        // Health check
        .route("/api/health", axum::routing::get(routes::health::health))
        // WebSocket
        .route("/ws", axum::routing::get(routes::ws::ws_handler))
        // Static files (Vue frontend dist/)
        .fallback_service(tower_http::services::ServeDir::new("../dist")
            .fallback(tower_http::services::ServeFile::new("../dist/index.html")))
        .layer(cors)
        .layer(compression)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

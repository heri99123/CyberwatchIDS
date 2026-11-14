use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod db;
mod ids_engine;
mod auth;
mod simulator;
mod routes;
mod state;
mod error;
mod security;
mod mailer;
mod event_pipeline;

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

    // Optional outbound email (no-op unless SMTP_ENABLED=true)
    let mailer = Arc::new(mailer::Mailer::from_env());

    // Create shared application state
    let state = Arc::new(AppState {
        db: pool,
        ids,
        simulator,
        ws_clients: tokio::sync::Mutex::new(Vec::new()),
        mailer,
    });

    // Optional UDP syslog listener (Task #29). Disabled unless both
    // SYSLOG_UDP_PORT and a valid read-write SYSLOG_UDP_API_KEY are configured.
    if let Some((port, org_id)) = routes::ingest::udp_syslog_config(&state.db) {
        routes::ingest::spawn_udp_syslog_listener(state.clone(), port, org_id);
    }

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
    tracing::info!("  Ingest:     POST /api/ingest/webhook | /api/ingest/syslog");
    tracing::info!("============================================");
    tracing::info!("");
    tracing::info!("[IDS] Engine initialized with {} rules", state.ids.rule_count());
    tracing::info!("[Auth] JWT authentication enabled");
    tracing::info!("[Mail] Email notifications: {}", if state.mailer.is_enabled() { "enabled" } else { "disabled" });
    tracing::info!("[Ingest] Webhook + syslog endpoints ready (API key or JWT)");
    tracing::info!("[Multi-tenant] Organization data isolation active");
    tracing::info!("");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Server listening on {}", addr);
    // `into_make_service_with_connect_info` exposes the client SocketAddr to
    // tower-governor's per-IP rate limiter (works behind a reverse proxy too).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    let cors = security::cors_layer();
    let compression = CompressionLayer::new();

    // --- Rate limiter (per-IP) ---
    // Defaults: 1 token replenished every 2s, burst of 30. Tunable via env.
    // NOTE: tower-governor 0.5 `per_second` takes u64, `burst_size` takes u32,
    // and `finish()` returns Option (None when a value is zero).
    let per_second: u64 = std::env::var("RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(2);
    let burst: u32 = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(30);

    // SECURITY: only trust X-Forwarded-For / X-Real-IP when explicitly enabled.
    // Those headers are client-controlled and can be spoofed to bypass rate
    // limits. Enable ONLY behind a trusted reverse proxy that overwrites them.
    let trust_proxy = std::env::var("RATE_LIMIT_TRUST_PROXY").unwrap_or_default() == "true";

    // API routes are rate-limited per IP. Health, WebSocket and static assets
    // are deliberately kept outside the limiter.
    let api_routes = Router::new()
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
        .route("/api/simulate/attack", axum::routing::post(routes::simulator::attack));

    // Scoped per-IP rate limiting.
    // Two builder branches are needed because the key extractor is a generic
    // type parameter, so the two configs have different concrete types.
    let api_routes = if trust_proxy {
        let mut builder = GovernorConfigBuilder::default();
        let mut builder = builder.key_extractor(SmartIpKeyExtractor);
        builder.per_second(per_second).burst_size(burst);
        let conf = Arc::new(
            builder
                .finish()
                .expect("invalid governor rate-limit configuration"),
        );
        api_routes.layer(GovernorLayer { config: conf })
    } else {
        let conf = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(per_second)
                .burst_size(burst)
                .finish()
                .expect("invalid governor rate-limit configuration"),
        );
        api_routes.layer(GovernorLayer { config: conf })
    };

    // --- Ingest endpoints (Task #29) ---
    // Traffic shippers need far higher throughput than the interactive API, so
    // they get a dedicated limiter and body cap. Authentication is still
    // enforced per request by API key / JWT inside the handlers.
    let ingest_per_second: u64 = std::env::var("INGEST_RATE_PER_SECOND")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(50);
    let ingest_burst: u32 = std::env::var("INGEST_RATE_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(200);
    let ingest_body_limit: usize = std::env::var("INGEST_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1_048_576);

    let ingest_routes = Router::new()
        .route("/api/ingest/webhook", axum::routing::post(routes::ingest::webhook))
        .route("/api/ingest/syslog", axum::routing::post(routes::ingest::syslog))
        .layer(axum::extract::DefaultBodyLimit::max(ingest_body_limit));

    let ingest_routes = if trust_proxy {
        let mut builder = GovernorConfigBuilder::default();
        let mut builder = builder.key_extractor(SmartIpKeyExtractor);
        builder.per_second(ingest_per_second).burst_size(ingest_burst);
        let conf = Arc::new(
            builder
                .finish()
                .expect("invalid ingest rate-limit configuration"),
        );
        ingest_routes.layer(GovernorLayer { config: conf })
    } else {
        let conf = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(ingest_per_second)
                .burst_size(ingest_burst)
                .finish()
                .expect("invalid ingest rate-limit configuration"),
        );
        ingest_routes.layer(GovernorLayer { config: conf })
    };

    Router::new()
        .merge(api_routes)
        .merge(ingest_routes)
        // Health check (not rate-limited — used by monitoring/load balancers)
        .route("/api/health", axum::routing::get(routes::health::health))
        // WebSocket (long-lived; rate limiting at handshake is not desired)
        .route("/ws", axum::routing::get(routes::ws::ws_handler))
        // Static files (Vue frontend dist/)
        .fallback_service(tower_http::services::ServeDir::new("../dist")
            .fallback(tower_http::services::ServeFile::new("../dist/index.html")))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(security::security_headers))
        .layer(compression)
        .with_state(state)
}

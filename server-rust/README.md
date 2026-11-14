# CyberWatch IDS - Rust Backend

High-performance Rust backend for CyberWatch IDS, built with Axum + tokio + rusqlite.

## Tech Stack

| Component | Technology |
|---|---|
| Web Framework | Axum 0.7 |
| Async Runtime | tokio (full) |
| Database | rusqlite (bundled SQLite) + r2d2 connection pool |
| Auth | jsonwebtoken + argon2 |
| Regex Engine | regex crate (Rust native) |
| WebSocket | tokio-tungstenite via Axum |
| Serialization | serde + serde_json |
| Logging | tracing + tracing-subscriber |

## Performance (expected vs Node.js)

| Metric | Node.js (current) | Rust (target) |
|---|---|---|
| Memory (idle) | 50-150 MB | 5-15 MB |
| Throughput | 10-20k req/s | 100k+ req/s |
| Latency | 1-5ms (GC pauses) | <0.1ms |
| Startup | 2-5s | <0.1s |
| Binary size | N/A (node_modules) | ~10-15 MB single binary |

## Project Structure

```
server-rust/
  Cargo.toml          # Dependencies and build profile
  .env                # Environment configuration
  build.sh            # Linux build script
  src/
    main.rs           # Entry point, Axum router setup
    state.rs          # Shared application state (Arc<AppState>)
    error.rs          # AppError enum + IntoResponse
    db.rs             # Database init, schema, migrations, indexes, pool
    auth.rs           # JWT, argon2, API key generation, slugify
    ids_engine.rs     # IDS detection engine (regex compilation, inspection, logging, stats)
    simulator.rs      # Attack simulator (35+ templates, tokio async timers)
    routes/
      mod.rs          # Route module declarations
      auth.rs         # POST /register, POST /login, GET /verify, GET /me
      admin.rs        # User management, org settings, API keys, audit logs, export
      ids.rs          # Stats, events, alerts, CVE, rules, IP reputation, reset
      simulator.rs    # Start/stop/status/attack endpoints
      incidents.rs    # Incident CRUD
      notifications.rs # List + mark read
      ws.rs           # WebSocket handler (real-time push)
      health.rs       # Health check endpoint
```

## Building

### Prerequisites
- Rust 1.75+ (install via https://rustup.rs)
- C compiler (gcc on Linux, Visual Studio C++ Build Tools on Windows)

### Linux / VPS
```bash
cd server-rust
cargo build --release
./target/release/cyberwatch-ids
```

### Docker
```bash
# From project root:
docker build -t cyberwatch-ids .
docker run -p 8421:8421 -v $(pwd)/data:/app/data cyberwatch-ids
```

### Windows
Requires Visual Studio C++ Build Tools (for rusqlite bundled SQLite compilation).
```powershell
cd server-rust
cargo build --release
```

## API Endpoints

All endpoints are compatible with the existing Vue frontend. No frontend changes needed.

### Auth (public)
- `POST /api/auth/register` - Register org + admin user
- `POST /api/auth/login` - Login
- `GET  /api/auth/verify` - Verify JWT

### Auth (authenticated)
- `GET  /api/auth/me` - Current user profile

### Admin (admin role)
- `GET/POST /api/admin/users` - List/create users
- `PUT  /api/admin/users/:id/role` - Change role
- `PUT  /api/admin/users/:id/status` - Enable/disable
- `DELETE /api/admin/users/:id` - Delete user
- `GET/PUT /api/admin/org` - Org settings
- `GET/POST /api/admin/api-keys` - API key management
- `DELETE /api/admin/api-keys/:id` - Revoke key
- `GET /api/admin/audit-logs` - Audit log viewer
- `GET /api/admin/export/:type` - Export data (events/alerts/incidents/audit)

### IDS Data
- `GET /api/stats` - Aggregate statistics
- `GET /api/events` - Recent events (org-scoped)
- `GET /api/events/search` - Search with filters
- `GET /api/alerts` - List alerts
- `PUT /api/alerts/:id/acknowledge` - Acknowledge alert
- `GET /api/cve` - CVE database (searchable)
- `GET /api/cve/:id` - Single CVE detail
- `GET /api/rules` - IDS rules
- `PUT /api/rules/:id/toggle` - Enable/disable rule
- `GET /api/ip-reputation` - IP reputation list
- `PUT /api/ip-reputation/:ip/block` - Block IP
- `PUT /api/ip-reputation/:ip/unblock` - Unblock IP
- `POST /api/reset` - Purge event data (org-scoped)

### Simulator
- `POST /api/simulate/start` - Start auto-attack
- `POST /api/simulate/stop` - Stop
- `GET /api/simulate/status` - Check status
- `POST /api/simulate/attack` - Manual inject

### WebSocket
- `GET /ws?token=JWT` - Real-time event push

### Health
- `GET /api/health` - Service health check

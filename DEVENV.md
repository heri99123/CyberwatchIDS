# CyberWatch IDS - Development Environment

## GitHub Codespaces (Recommended, 120 jam/bulan gratis)

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=heri99123/CyberwatchIDS)

Atau buka langsung:

```
https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=heri99123/CyberwatchIDS
```

Codespaces akan otomatis:
- Install Rust toolchain
- Install Node.js 20
- Install VS Code extensions (Rust analyzer, Vue, Tailwind)
- Install dependencies (`npm install`)
- Build Rust backend untuk cache dependencies
- Forward port 8421 (backend) dan 5173 (frontend)

## Alternatif: Gitpod

~~Gitpod URL: https://gitpod.io/#https://github.com/heri99123/CyberwatchIDS~~

⚠️ Gitpod sekarang menjadi OpenAI Ona dan new signups ditutup. Gunakan GitHub Codespaces di atas.

## Local Development (Windows/Linux/Mac)

### Prerequisites
- Node.js 18+
- **Rust 1.85+** (https://rustup.rs) — wajib, karena dependency memakai edition 2024
- gcc / build-essential (untuk rusqlite bundled)

### Commands

```bash
# Frontend
cd /path/to/project
npm install
npm run dev

# Backend (another terminal)
cp backend/.env.example backend/.env   # lalu edit JWT_SECRET
cd backend
cargo run --release
```

### Environment (backend/.env)

Lihat tabel lengkap di [README.md](README.md#konfigurasi-environment). Ringkasan:

| Variable | Default | Catatan |
|----------|---------|---------|
| `JWT_SECRET` | dev default | **Wajib diganti** di production |
| `CORS_ALLOWED_ORIGINS` | kosong | Kosong = same-origin only; `*` = semua origin (hindari) |
| `HSTS_ENABLED` | `false` | `true` hanya di belakang TLS proxy |
| `RATE_LIMIT_PER_SECOND` / `RATE_LIMIT_BURST` | `2` / `30` | Rate limit per IP pada `/api/*` |
| `RATE_LIMIT_TRUST_PROXY` | `false` | `true` hanya jika proxy menimpa `X-Forwarded-For` |
| `LOGIN_MAX_FAILED_ATTEMPTS` | `5` | Gagal login beruntun sebelum akun dikunci (3–20) |
| `LOGIN_LOCKOUT_SECONDS` | `900` | Lama kunci akun, detik (60–86400) |
| `SMTP_ENABLED` / `SMTP_HOST` | `false` / kosong | Email **nonaktif** by default; lihat tabel lengkap di README |
| `ALERT_EMAIL_MIN_SEVERITY` | `CRITICAL` | Ambang severity email alert |

> Rate limiting tidak diterapkan pada `/api/health`, `/ws`, dan static assets.
> Rate limit berlaku **per IP**, sedangkan account lockout berlaku **per akun** — keduanya saling melengkapi. Counter lockout tersimpan di tabel `users` (`failed_login_attempts`, `locked_until`) dan otomatis di-reset saat login berhasil.

## Production Build

```bash
# Frontend
npm run build

# Rust backend (Linux/macOS)
cd backend && cargo build --release

# Docker image
docker build -t cyberwatch-ids .
```

## Deploy ke VPS

1. Pastikan GitHub Actions sudah berhasil build
2. Download artifacts: Rust binary + frontend dist
3. Upload ke VPS, jalankan:

```bash
chmod +x deploy.sh
sudo ./deploy.sh
```

### Auto-deploy (opsional)

Workflow `deploy.yml` **hanya jalan manual** (`Actions > Deploy to VPS > Run workflow`),
supaya push harian tidak gagal dan tidak mengirim build yang belum lolos CI.
Workflow mengambil artefak dari run **Build CyberWatch IDS** terakhir yang sukses
(bisa juga diisi `build_run_id` secara eksplisit).

Siapkan GitHub secrets terlebih dahulu:
- `VPS_HOST`
- `VPS_USER`
- `VPS_SSH_KEY`
- `VPS_PORT` (optional, default 22)

`deploy.sh` akan membuat `/etc/cyberwatch-ids.env` (mode 600) berisi `JWT_SECRET`
acak yang dipertahankan saat redeploy, lalu menjalankan service via systemd.
Pastikan reverse proxy (nginx/Caddy) **menimpa** `X-Forwarded-For`, karena
`RATE_LIMIT_TRUST_PROXY=true` aktif di konfigurasi production.

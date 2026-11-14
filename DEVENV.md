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
- Rust toolchain (https://rustup.rs)
- gcc / build-essential (untuk rusqlite bundled)

### Commands

```bash
# Frontend
cd /path/to/project
npm install
npm run dev

# Backend (another terminal)
cd backend
cargo run --release
```

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

Atau setup auto-deploy via `.github/workflows/deploy.yml` dengan GitHub secrets:
- `VPS_HOST`
- `VPS_USER`
- `VPS_SSH_KEY`
- `VPS_PORT` (optional, default 22)

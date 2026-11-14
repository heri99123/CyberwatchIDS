#!/bin/bash
# Build script for CyberWatch IDS Rust Backend
# Run this on a Linux machine or VPS with Rust installed

set -e

echo "============================================"
echo "  CyberWatch IDS - Rust Backend Builder"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SCRIPT_DIR"

echo "[1/4] Checking Rust toolchain..."
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo "  Rust: $(rustc --version)"

echo "[2/4] Building Rust backend (release mode)..."
cargo build --release
echo "  Binary: $(ls -lh target/release/cyberwatch-ids | awk '{print $5}')"

echo "[3/4] Building Vue frontend..."
cd "$PROJECT_DIR"
npm install --silent
npm run build
echo "  Frontend: $(ls dist/ | wc -l) files"

echo "[4/4] Done!"
echo ""
echo "To run:"
echo "  cd backend"
echo "  ./target/release/cyberwatch-ids"
echo ""
echo "Or with Docker:"
echo "  docker build -t cyberwatch-ids ."
echo "  docker run -p 8421:8421 -v \$(pwd)/data:/app/data cyberwatch-ids"

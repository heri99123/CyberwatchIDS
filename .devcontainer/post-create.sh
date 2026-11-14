#!/bin/bash
# Post-create setup for GitHub Codespaces
# Runs once when the container is created

set -e

echo "=== CyberWatch IDS - Codespaces Setup ==="

# Ensure Rust is available (image has it, but make sure)
if ! command -v rustc &> /dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env"

# Install system deps for rusqlite bundled + SSL
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
  pkg-config \
  libssl-dev \
  build-essential

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Build Rust backend to cache dependencies
echo "Building Rust backend (this caches deps)..."
cd server-rust && cargo build --release 2>&1 || echo "Build will complete on first run"

echo "=== Setup complete ==="

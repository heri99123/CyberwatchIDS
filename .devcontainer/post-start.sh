#!/bin/bash
# Post-start command for GitHub Codespaces
# Runs every time the container starts

source "$HOME/.cargo/env" 2>/dev/null || true

echo ""
echo "=========================================="
echo "  CyberWatch IDS - Codespaces Ready"
echo "=========================================="
echo ""
echo "Quick commands:"
echo "  cd backend && cargo run --release      # Start Rust backend (port 8421)"
echo "  npm run dev                            # Start Vue frontend (port 5173)"
echo ""
echo "Preview URLs will appear automatically."
echo ""

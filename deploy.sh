#!/bin/bash
# CyberWatch IDS - Deployment Script
# Run on Linux VPS after downloading the build artifacts
# Usage: ./deploy.sh

set -e

APP_NAME="cyberwatch-ids"
APP_DIR="/opt/cyberwatch-ids"
APP_USER="cyberwatch"
SERVICE_NAME="cyberwatch-ids"
PORT="${PORT:-8421}"

echo "========================================"
echo "  CyberWatch IDS - Deployment Script"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root (use sudo)"
  exit 1
fi

# Create app user if not exists
if ! id "$APP_USER" &>/dev/null; then
  echo "[1/7] Creating system user: $APP_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
else
  echo "[1/7] User $APP_USER already exists"
fi

# Create app directory
echo "[2/7] Creating app directory: $APP_DIR"
mkdir -p "$APP_DIR/dist"
mkdir -p "$APP_DIR/data"

# Copy binary
echo "[3/7] Copying binary"
cp -f cyberwatch-ids "$APP_DIR/"
chmod +x "$APP_DIR/cyberwatch-ids"

# Copy frontend
echo "[4/7] Copying frontend dist"
if [ -d "dist" ]; then
  cp -rf dist/* "$APP_DIR/dist/"
fi

# Copy database seed if exists
echo "[5/7] Copying data files"
if [ -d "data" ]; then
  cp -rf data/* "$APP_DIR/data/" 2>/dev/null || true
fi

# Set ownership
echo "[6/7] Setting ownership"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# Write env file (mode 600 — JWT_SECRET must not be world-readable / in unit file)
ENV_FILE="/etc/${APP_NAME}.env"
GENERATED_SECRET=""
if [ -z "${JWT_SECRET:-}" ]; then
  if [ -f "$ENV_FILE" ] && grep -q '^JWT_SECRET=' "$ENV_FILE"; then
    # Reuse existing secret on redeploy so existing sessions stay valid
    JWT_SECRET="$(grep '^JWT_SECRET=' "$ENV_FILE" | cut -d= -f2-)"
  else
    JWT_SECRET="$(openssl rand -hex 32 2>/dev/null || echo change-me-in-production)"
    GENERATED_SECRET="yes"
  fi
fi
cat > "$ENV_FILE" << EOF
PORT=$PORT
DATABASE_PATH=$APP_DIR/data/cve-database.db
RUST_LOG=info,cyberwatch=debug
JWT_SECRET=$JWT_SECRET
CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS:-}
HSTS_ENABLED=${HSTS_ENABLED:-true}
RATE_LIMIT_PER_SECOND=${RATE_LIMIT_PER_SECOND:-2}
RATE_LIMIT_BURST=${RATE_LIMIT_BURST:-30}
RATE_LIMIT_TRUST_PROXY=${RATE_LIMIT_TRUST_PROXY:-true}
LOGIN_MAX_FAILED_ATTEMPTS=${LOGIN_MAX_FAILED_ATTEMPTS:-5}
LOGIN_LOCKOUT_SECONDS=${LOGIN_LOCKOUT_SECONDS:-900}
EOF
chmod 600 "$ENV_FILE"
chown "$APP_USER:$APP_USER" "$ENV_FILE"

if [ -n "$GENERATED_SECRET" ]; then
  echo "NOTE: Generated a random JWT_SECRET in $ENV_FILE (persisted across redeploys)."
fi

# Create systemd service
echo "[7/7] Installing systemd service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=CyberWatch IDS - Intrusion Detection System
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/cyberwatch-ids
Restart=always
RestartSec=5
EnvironmentFile=$ENV_FILE

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Check status
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
  echo ""
  echo "========================================"
  echo "  DEPLOYMENT SUCCESSFUL!"
  echo "========================================"
  echo "  Service:  $SERVICE_NAME"
  echo "  Port:     $PORT"
  echo "  App dir:  $APP_DIR"
  echo ""
  echo "  Status:   $(systemctl is-active $SERVICE_NAME)"
  echo ""
  echo "  Logs:     journalctl -u $SERVICE_NAME -f"
  echo "  Stop:     systemctl stop $SERVICE_NAME"
  echo "  Restart:  systemctl restart $SERVICE_NAME"
  echo "========================================"
else
  echo ""
  echo "ERROR: Service failed to start. Check logs:"
  echo "  journalctl -u $SERVICE_NAME -n 50"
  exit 1
fi

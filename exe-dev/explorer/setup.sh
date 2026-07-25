#!/usr/bin/env bash
# Installs the runZero Explorer on an exe.dev VM and registers it as a
# systemd service so it persists across reboots.
#
# Usage:
#   RUNZERO_TOKEN=<provisioning-token> bash setup.sh
#
# The provisioning token is a one-time token from the runZero console:
#   Explorers → Add Explorer → Copy token
#
# After running this script the Explorer will appear in the runZero console
# within ~30 seconds. The token is consumed on first use and not stored.

set -euo pipefail

RUNZERO_TOKEN="${RUNZERO_TOKEN:?RUNZERO_TOKEN must be set}"
INSTALL_DIR="/opt/runzero"
SERVICE_NAME="runzero-explorer"
EXPLORER_URL="https://console.runzero.com/download/explorer/linux/amd64/runzero-explorer"

echo "[setup] Detecting system..."
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH_SLUG="amd64" ;;
  aarch64) ARCH_SLUG="arm64" ;;
  *)        echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

EXPLORER_URL="https://console.runzero.com/download/explorer/linux/${ARCH_SLUG}/runzero-explorer"

echo "[setup] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates

echo "[setup] Downloading runZero Explorer (${ARCH_SLUG})..."
mkdir -p "$INSTALL_DIR"
curl -fsSL "$EXPLORER_URL" -o "${INSTALL_DIR}/runzero-explorer"
chmod +x "${INSTALL_DIR}/runzero-explorer"

echo "[setup] Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=runZero Explorer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/runzero-explorer
Restart=on-failure
RestartSec=15
Environment="RUNZERO_EXPLORER_TOKEN=${RUNZERO_TOKEN}"
StandardOutput=journal
StandardError=journal
SyslogIdentifier=runzero-explorer

[Install]
WantedBy=multi-user.target
EOF

echo "[setup] Enabling and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo "[setup] Done. Checking status..."
systemctl status "$SERVICE_NAME" --no-pager -l || true

echo ""
echo "[setup] Explorer started. It should appear in the runZero console"
echo "        within ~30 seconds under Explorers."

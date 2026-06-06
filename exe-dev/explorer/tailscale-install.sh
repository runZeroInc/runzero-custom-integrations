#!/usr/bin/env bash
# Installs Tailscale on a single exe.dev VM and connects it to your tailnet.
#
# Run this on each VM you want to include in the internal scan:
#
#   ssh <vm>.exe.xyz \
#     "curl -fsSL https://raw.githubusercontent.com/runZeroInc/runzero-custom-integrations/main/exe-dev/explorer/tailscale-install.sh | \
#      TAILSCALE_AUTH_KEY=<tskey-auth-...> bash"
#
# Or use install-tailscale-fleet.sh to run this across all VMs automatically.
#
# After connection the VM will be visible in your Tailscale admin console
# and reachable at its 100.x.x.x address from the RunZero Explorer VM.

set -euo pipefail

TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:?TAILSCALE_AUTH_KEY must be set}"

echo "[tailscale] Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh

echo "[tailscale] Connecting to tailnet..."
tailscale up \
  --authkey="$TAILSCALE_AUTH_KEY" \
  --hostname="$(hostname)" \
  --accept-routes

echo "[tailscale] Connected. Tailscale IP:"
tailscale ip -4

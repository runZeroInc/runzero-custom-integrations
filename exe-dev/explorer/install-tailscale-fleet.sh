#!/usr/bin/env bash
# Installs Tailscale on every running VM in your exe.dev fleet.
#
# Usage:
#   EXE_DEV_TOKEN=<token> TAILSCALE_AUTH_KEY=<tskey-auth-...> ./install-tailscale-fleet.sh
#
# Iterates the live VM list, SSHs into each running VM, and runs
# tailscale-install.sh. VMs that are stopped or already have Tailscale
# installed are skipped gracefully.
#
# Prerequisites:
#   - SSH access to each VM (your SSH key registered with exe.dev)
#   - tailscale-install.sh accessible at the URL below (update if forking)

set -euo pipefail

EXE_DEV_TOKEN="${EXE_DEV_TOKEN:?EXE_DEV_TOKEN must be set}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:?TAILSCALE_AUTH_KEY must be set}"
EXE_DEV_API="https://exe.dev/exec"
INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/runZeroInc/runzero-custom-integrations/main/exe-dev/explorer/tailscale-install.sh"

_log() { echo "[fleet] $*"; }

_log "Fetching VM list..."
response=$(curl -sf -X POST "$EXE_DEV_API" \
  -H "Authorization: Bearer ${EXE_DEV_TOKEN}" \
  -H "Content-Type: text/plain" \
  --data 'ls') || { _log "ERROR: exe.dev API call failed"; exit 1; }

# Extract running VMs
mapfile -t vms < <(echo "$response" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for vm in data.get('vms', []):
    if vm.get('status') == 'running':
        print(vm['ssh_dest'])
")

_log "Found ${#vms[@]} running VM(s): ${vms[*]:-none}"

success=0
failed=()

for ssh_dest in "${vms[@]}"; do
  _log "Installing Tailscale on ${ssh_dest}..."
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 "$ssh_dest" \
    "curl -fsSL '${INSTALL_SCRIPT_URL}' | TAILSCALE_AUTH_KEY='${TAILSCALE_AUTH_KEY}' bash" 2>&1 | \
    sed "s/^/  [${ssh_dest}] /"; then
    _log "OK: ${ssh_dest}"
    ((success++)) || true
  else
    _log "FAILED: ${ssh_dest}"
    failed+=("$ssh_dest")
  fi
done

_log ""
_log "Done: ${success} succeeded, ${#failed[@]} failed"
if [ ${#failed[@]} -gt 0 ]; then
  _log "Failed VMs: ${failed[*]}"
  exit 1
fi

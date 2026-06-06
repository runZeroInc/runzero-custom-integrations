#!/usr/bin/env bash
# Queries the exe.dev API for all VMs and writes scan targets to stdout
# (or targets.txt if OUTPUT_FILE is set).
#
# Architecture A (default) — external surface scan:
#   Outputs public hostnames. RunZero scans these via the internet through
#   exe.dev's HTTPS proxy. Discovers ports 80, 443, and 3000-9999.
#
# Architecture B — Tailscale (set SCAN_MODE=tailscale):
#   Requires TAILSCALE_API_KEY. Outputs Tailscale IPs for each VM.
#   RunZero scans these over the Tailscale overlay — full internal visibility.
#
# Usage:
#   EXE_DEV_TOKEN=<token> ./generate-targets.sh
#   EXE_DEV_TOKEN=<token> SCAN_MODE=tailscale TAILSCALE_API_KEY=<key> TAILSCALE_TAILNET=<tailnet> ./generate-targets.sh
#   EXE_DEV_TOKEN=<token> OUTPUT_FILE=targets.txt ./generate-targets.sh

set -euo pipefail

EXE_DEV_TOKEN="${EXE_DEV_TOKEN:?EXE_DEV_TOKEN must be set}"
SCAN_MODE="${SCAN_MODE:-external}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
EXE_DEV_API="https://exe.dev/exec"

_log() { echo "[targets] $*" >&2; }

# ── Fetch VM list from exe.dev ────────────────────────────────────────────────

_log "Fetching VM list from exe.dev..."

response=$(curl -sf -X POST "$EXE_DEV_API" \
  -H "Authorization: Bearer ${EXE_DEV_TOKEN}" \
  -H "Content-Type: text/plain" \
  --data 'ls') || { _log "ERROR: exe.dev API call failed"; exit 1; }

vm_count=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('vms', [])))")
_log "Found ${vm_count} VMs"

if [ "$vm_count" -eq 0 ]; then
  _log "No VMs found — nothing to output"
  exit 0
fi

# ── Generate targets ──────────────────────────────────────────────────────────

if [ "$SCAN_MODE" = "external" ]; then
  _log "Mode: external surface scan (public hostnames)"
  _log "Port recommendation for RunZero site: 80,443,3000-9999"
  _log ""

  targets=$(echo "$response" | python3 -c "
import json, sys

data = json.load(sys.stdin)
vms = data.get('vms', [])

for vm in vms:
    ssh_dest = vm.get('ssh_dest', '')
    status   = vm.get('status', 'unknown')
    region   = vm.get('region', '')
    name     = vm.get('vm_name', '')
    if ssh_dest:
        print(f'# {name} [{status}] [{region}]')
        print(ssh_dest)
")

elif [ "$SCAN_MODE" = "tailscale" ]; then
  TAILSCALE_API_KEY="${TAILSCALE_API_KEY:?TAILSCALE_API_KEY must be set for tailscale mode}"
  TAILSCALE_TAILNET="${TAILSCALE_TAILNET:?TAILSCALE_TAILNET must be set for tailscale mode}"

  _log "Mode: Tailscale overlay (internal IPs)"
  _log "Port recommendation for RunZero site: 1-65535"
  _log ""
  _log "Fetching Tailscale device list..."

  ts_response=$(curl -sf \
    -H "Authorization: Bearer ${TAILSCALE_API_KEY}" \
    "https://api.tailscale.com/api/v2/tailnet/${TAILSCALE_TAILNET}/devices") || {
    _log "ERROR: Tailscale API call failed"
    exit 1
  }

  # Build a map of hostname → Tailscale IP, then match against exe.dev VM names
  targets=$(echo "$response $ts_response" | python3 -c "
import json, sys

raw = sys.stdin.read()
# The two JSON blobs are space-separated — split on the boundary
# by finding the first '}' followed by whitespace and '{'
import re
parts = re.split(r'\}\s*\{', raw, maxsplit=1)
exe_data = json.loads(parts[0] + '}')
ts_data  = json.loads('{' + parts[1])

exe_vms = {vm['vm_name']: vm for vm in exe_data.get('vms', [])}

# Tailscale hostname is usually the short hostname without domain
ts_by_hostname = {}
for dev in ts_data.get('devices', []):
    h = dev.get('hostname', '').split('.')[0].lower()
    addrs = dev.get('addresses', [])
    ipv4 = next((a.split('/')[0] for a in addrs if ':' not in a), None)
    if h and ipv4:
        ts_by_hostname[h] = ipv4

matched = 0
unmatched = []
output = []
for vm_name, vm in exe_vms.items():
    ts_ip = ts_by_hostname.get(vm_name.lower())
    status = vm.get('status', 'unknown')
    region = vm.get('region', '')
    if ts_ip:
        output.append(f'# {vm_name} [{status}] [{region}] -> {ts_ip}')
        output.append(ts_ip)
        matched += 1
    else:
        unmatched.append(vm_name)

for line in output:
    print(line)

if unmatched:
    import sys
    print(f'# WARNING: no Tailscale match for: {', '.join(unmatched)}', file=sys.stderr)
print(f'# Matched {matched}/{len(exe_vms)} VMs', file=sys.stderr)
")

else
  _log "ERROR: Unknown SCAN_MODE '${SCAN_MODE}'. Use 'external' or 'tailscale'."
  exit 1
fi

# ── Output ────────────────────────────────────────────────────────────────────

if [ -n "$OUTPUT_FILE" ]; then
  echo "$targets" > "$OUTPUT_FILE"
  _log "Wrote targets to ${OUTPUT_FILE}"
  _log "$(echo "$targets" | grep -c '^[^#]') scan targets"
else
  echo "$targets"
fi

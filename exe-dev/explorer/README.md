# RunZero Explorer on exe.dev

This directory contains tooling to deploy a RunZero Explorer onto an exe.dev
VM so it can scan your fleet's attack surface.

## Network constraints

**exe.dev VMs are network-isolated from each other** — there is no shared
private network. An Explorer on VM A cannot reach VM B's internal ports
directly. The exe.dev HTTP proxy integration is HTTP-only and cannot be used
for raw TCP port scanning.

This means there are two distinct deployment models with different coverage:

| | Architecture A: External scan | Architecture B: Tailscale |
|---|---|---|
| What's visible | Public-facing surface only | All listening ports on every VM |
| Setup effort | Low | Medium (Tailscale on every VM) |
| Best for | EASM — what attackers can reach | Internal audit and compliance |
| Scan targets | `<vm>.exe.xyz` hostnames | Tailscale IPs (`100.x.x.x`) |
| Port coverage | 80, 443, 3000–9999 (proxy range) | All ports |

Both architectures use a single RunZero Explorer VM. Targets are generated
dynamically from the exe.dev API so the scan stays current as VMs are added
or removed.

---

## Architecture A: External surface scan

### Prerequisites

- A RunZero account with an Explorer provisioning token (from the RunZero
  console under **Explorers → Add Explorer**)
- An exe.dev API token with at least `ls` permission (see the root README)

### 1. Create a dedicated Explorer VM

From your local machine:

```bash
ssh exe.dev new --name runzero-explorer
```

### 2. Deploy the Explorer

SSH into the new VM and run `setup.sh`:

```bash
ssh runzero-explorer.exe.xyz
```

Then from inside the VM:

```bash
curl -fsSL https://raw.githubusercontent.com/runZeroInc/runzero-custom-integrations/main/exe-dev/explorer/setup.sh | \
  RUNZERO_TOKEN=<your-provisioning-token> bash
```

The script installs the Explorer binary and registers it with RunZero as a
persistent systemd service.

### 3. Generate scan targets

Run `generate-targets.sh` with your exe.dev API token. It queries the live
VM list and writes a target file consumable by the RunZero API or UI:

```bash
EXE_DEV_TOKEN=<your-exe-dev-token> ./generate-targets.sh
```

Output: `targets.txt` — one hostname per line, ready to paste into a RunZero
site's **Scan targets** field, or POST via the RunZero API.

### 4. Configure the scan in RunZero

In the RunZero console:
1. Go to **Sites → your site → Edit**
2. Under **Scan targets**, add the contents of `targets.txt`
3. Under **Scan ports**, add the exe.dev proxy range: `80,443,3000-9999`
4. Assign the Explorer VM as the scanner for this site
5. Schedule or trigger a scan

### What the scan will find

The Explorer scans each VM's public hostname over the internet through exe.dev's
HTTPS proxy. It will discover:

- Port 80/443 — the primary HTTPS proxy (always present on running VMs)
- Ports 3000–9999 — any additional services the VM is transparently exposing
  via the exe.dev proxy

Each discovered service is correlated with the asset data imported by the
custom integration (`custom-integration-exe-dev.star`), giving you a unified
view of each VM's identity and exposed services.

---

## Architecture B: Tailscale overlay

Tailscale creates an encrypted mesh network between all your VMs, giving the
Explorer direct access to internal ports.

### Prerequisites

- Everything from Architecture A
- Tailscale account and auth key (`tskey-auth-...`)

### 1. Install Tailscale on every VM

The `tailscale-install.sh` script installs and connects Tailscale on a single
VM. Run it on each VM in your fleet:

```bash
ssh <vm>.exe.xyz \
  "curl -fsSL https://raw.githubusercontent.com/runZeroInc/runzero-custom-integrations/main/exe-dev/explorer/tailscale-install.sh | \
   TAILSCALE_AUTH_KEY=<tskey-auth-...> bash"
```

Or loop over all VMs using the exe.dev API:

```bash
EXE_DEV_TOKEN=<token> TAILSCALE_AUTH_KEY=<tskey-auth-...> ./install-tailscale-fleet.sh
```

### 2. Deploy the Explorer (same as Architecture A)

The Explorer VM also needs Tailscale installed. After setup, it will see all
other fleet VMs at their `100.x.x.x` Tailscale addresses.

### 3. Generate Tailscale scan targets

```bash
EXE_DEV_TOKEN=<token> \
  SCAN_MODE=tailscale \
  TAILSCALE_API_KEY=<tskey-api-...> \
  TAILSCALE_TAILNET=<tailnet> \
  ./generate-targets.sh
```

This queries the Tailscale API for the fleet's Tailscale IPs and matches them
against your exe.dev VM list, writing the results to `targets.txt`.

### 4. Configure the scan in RunZero

Same as Architecture A, but:
- **Scan targets**: Tailscale IPs from `targets.txt` (or the `100.64.0.0/10` CIDR)
- **Scan ports**: `1-65535` (full internal visibility)

---

## Files

| File | Purpose |
|---|---|
| `setup.sh` | Install and register RunZero Explorer on an exe.dev VM |
| `generate-targets.sh` | Query exe.dev API and output scan targets |
| `tailscale-install.sh` | Install Tailscale on a single VM |
| `install-tailscale-fleet.sh` | Install Tailscale across all fleet VMs |

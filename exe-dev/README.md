# exe.dev Integration for runZero

Imports exe.dev virtual machines as assets into runZero, giving you visibility over your VM fleet alongside the rest of your infrastructure.

Each VM appears as an asset with its hostname, region, status, HTTPS URL, and SSH destination as custom attributes, searchable via `custom_integration:exe.dev`.

## Security considerations

**Do not use a default API token for this integration.**

Tokens generated with `ssh exe.dev ssh-key generate-api-key` carry the default `cmds` permission set, which includes commands this integration does not need:

| Command | Risk if token is compromised |
|---|---|
| `new` | Attacker can spin up VMs at your cost |
| `ssh-key list` | Exposes your registered public keys |
| `share show` | Reveals what services you've made public (grant only if you want proxy visibility enrichment) |
| `team members` | Enumerates your organisation's users |

At minimum this integration needs `ls`. Optional enrichment commands and what they add:

| Command | Enrichment |
|---|---|
| `domain ls` | Custom domains added as additional hostnames |
| `share show` | Proxy visibility (`public`/`private`), port, email-enabled status; publicly exposed VMs get a `proxy:public` tag |

Use a dedicated SSH key and a minimal-scope token as described below, so that a leaked credential cannot do anything beyond what the integration actually requires.

Tokens are bearer tokens — possession grants access with no further proof of identity. Store them with the same care as a password.

## Requirements

### runZero
- Superuser access to the Custom Integrations configuration

### exe.dev
- An exe.dev account with one or more VMs
- A minimal-scope API token (see below)

## Generating a minimal-scope API token

Two methods are available. The web dashboard is simpler but supports fewer
enrichment commands. Use the SSH key method if you need custom domain hostnames
or integration/CAASM metadata.

| Method | `ls` | `share show` | `domain ls` | `integrations list` |
|---|:---:|:---:|:---:|:---:|
| Web dashboard | ✓ | ✓ | — | — |
| SSH key signing | ✓ | ✓ | ✓ | ✓ |

### Method A: Web dashboard (simpler)

1. Log in to [exe.dev](https://exe.dev) and go to **API Keys → Create API Key**.
2. Set a **Label** (e.g. `runzero-integration`) and choose an **Expiry** (30–90 days recommended).
3. Under **Allowed commands**, uncheck everything, then check only what you need:
   - **Always required:** `ls`
   - **Optional — proxy visibility enrichment:** `share show`
4. Click **Create** and copy the generated token.

> The dashboard does not offer `domain ls` or `integrations list`. If you want
> custom domain hostnames or CAASM integration metadata, use Method B instead.

### Method B: SSH key signing (full enrichment)

> **All commands in this section run on your local machine** (laptop or
> workstation), not inside an exe.dev VM or the exe.dev lobby. You need an
> existing SSH key registered with exe.dev on that machine to run
> `ssh exe.dev ...` commands.

#### 1. Create a dedicated SSH key for this integration

Using a separate key means you can revoke RunZero's API access independently
of your regular exe.dev SSH access.

```bash
ssh-keygen -t ed25519 -C runzero-integration -f ~/.ssh/exe_dev_runzero
cat ~/.ssh/exe_dev_runzero.pub | ssh exe.dev ssh-key add
```

#### 2. Set a 90-day expiry timestamp

```bash
export EXPIRY=$(date -d '+90 days' +%s 2>/dev/null || date -v+90d +%s)
```

#### 3. Sign a minimal permissions payload

Choose the permission tier that matches the enrichment you want (see the
enrichment table above), then run the signing block:

```bash
b64url() { tr -d '\n=' | tr '+/' '-_'; }

# VM list only (core CAASM — tags, comments, Shelley status):
export PERMISSIONS='{"exp":'"$EXPIRY"',"cmds":["ls"]}'

# + custom domain hostnames:
# export PERMISSIONS='{"exp":'"$EXPIRY"',"cmds":["ls","domain ls"]}'

# + proxy exposure visibility:
# export PERMISSIONS='{"exp":'"$EXPIRY"',"cmds":["ls","domain ls","share show"]}'

# Full EASM/CAASM (recommended):
# export PERMISSIONS='{"exp":'"$EXPIRY"',"cmds":["ls","domain ls","share show","integrations list"]}'

export PAYLOAD=$(printf '%s' "$PERMISSIONS" | base64 | b64url)
export SIG=$(printf '%s' "$PERMISSIONS" | ssh-keygen -Y sign -f ~/.ssh/exe_dev_runzero -n v0@exe.dev)
export SIGBLOB=$(echo "$SIG" | sed '1d;$d' | b64url)
export TOKEN="exe0.$PAYLOAD.$SIGBLOB"
```

#### 4. Convert to a short opaque token (recommended)

The `exe0` token contains your permissions in plaintext. Converting it to an
`exe1` token makes it opaque and shorter:

```bash
ssh exe.dev exe0-to-exe1 "$TOKEN"
```

Copy the resulting `exe1.` token — this is what you will store in runZero.

#### 5. Verify

```bash
curl -X POST https://exe.dev/exec \
     -H "Authorization: Bearer $TOKEN" \
     -d 'ls'
```

### Token rotation

Tokens expire based on the expiry you set at creation. Set a calendar reminder
to rotate before expiry by repeating the relevant method above and updating the
credential in runZero.

## runZero configuration

1. In runZero, go to **Custom Integrations** and create a new integration.

2. Paste the contents of `custom-integration-exe-dev.star` as the script.

3. Create a credential of type **Custom Integration Script Secrets** with:
   - **access_key**: your exe.dev token (the `exe1.` string)
   - **access_secret**: enter any non-empty value (e.g. `unused`) — the field is required by the platform but is not used by this integration

4. Attach the credential to the integration and save.

5. Create an integration task, select your Explorer, and set a schedule.

## Asset fields

### Core (from `ls -l` — always populated)

| runZero attribute | Value |
|---|---|
| `hostname` | `<vm_name>.exe.xyz` |
| `os` | Linux |
| `exe_dev_vm_name` | VM name |
| `exe_dev_status` | `running`, `stopped`, etc. |
| `exe_dev_region` | Region code (e.g. `lon`) |
| `exe_dev_region_display` | Human-readable region (e.g. `London, UK`) |
| `exe_dev_https_url` | Public HTTPS URL |
| `exe_dev_ssh_dest` | SSH hostname |
| `exe_dev_comment` | Free-text comment set on the VM |
| `exe_dev_tags` | Comma-separated exe.dev tags on the VM |
| `exe_dev_shelley` | `True` / `False` — Shelley AI agent installed (detected via `ls -l` or integration type) |

### Exposure (requires `share show` token permission)

| runZero attribute | Value |
|---|---|
| `exe_dev_proxy_public` | `True` / `False` — whether the HTTPS proxy is publicly accessible |
| `exe_dev_proxy_port` | Port the HTTPS proxy is bound to |
| `exe_dev_email_enabled` | `True` / `False` — whether inbound email is enabled |

### Custom domains (requires `domain ls` token permission)

| runZero attribute | Value |
|---|---|
| `exe_dev_custom_domains` | Comma-separated custom domains pointing to this VM (also added as hostnames) |

### Integrations / CAASM (requires `integrations list` token permission)

| runZero attribute | Value |
|---|---|
| `exe_dev_integrations` | Comma-separated integration names attached to this VM |
| `exe_dev_integration_types` | Comma-separated integration types (`github`, `http-proxy`, `reflection`, …) |
| `exe_dev_github_repos` | Comma-separated GitHub repositories this VM has access to |
| `exe_dev_http_proxy_targets` | Comma-separated external domains this VM can proxy to |

## Tags applied by this integration

| Tag | Meaning |
|---|---|
| `exe.dev` | All assets from this integration |
| `status:<running\|stopped\|…>` | VM operational status |
| `region:<code>` | Region (e.g. `region:lon`) |
| `tag:<name>` | exe.dev tags on the VM (e.g. `tag:prod`) |
| `proxy:public` | HTTPS proxy is publicly accessible |
| `integration:github` | GitHub integration attached |
| `integration:http-proxy` | HTTP proxy integration attached |
| `agent:shelley` | Shelley AI agent is installed |

## Searching in runZero

```
custom_integration:exe.dev
custom_integration:exe.dev AND attribute.exe_dev_status:running
custom_integration:exe.dev AND attribute.exe_dev_proxy_public:True
custom_integration:exe.dev AND attribute.exe_dev_shelley:True
custom_integration:exe.dev AND tag:agent:shelley AND tag:proxy:public
custom_integration:exe.dev AND attribute.exe_dev_github_repos:*
```

## Development and testing

### Logic tests (no token required)

A Python test harness in `test_integration.py` mocks the RunZero Starlark
runtime and exercises the integration logic locally:

```bash
python3 test_integration.py
```

Covers `parse_hostname_from_url`, HTTP error handling (401/403/429/500/None),
VM→asset mapping, custom domain enrichment, share/proxy visibility enrichment,
graceful degradation when optional permissions are absent, hostname deduplication,
and edge cases (empty `vm_name`, missing token, partial VM records).

### Live API verification (token required)

Confirm the exe.dev API response schema matches what the script expects:

```bash
# Verify VM list shape
curl -s -X POST https://exe.dev/exec \
     -H "Authorization: Bearer $TOKEN" \
     -d 'ls' | jq .

# Verify custom domain shape (if using domain ls permission)
curl -s -X POST https://exe.dev/exec \
     -H "Authorization: Bearer $TOKEN" \
     -d 'domain ls -a' | jq .

# Verify share shape for a specific VM (if using share show permission)
curl -s -X POST https://exe.dev/exec \
     -H "Authorization: Bearer $TOKEN" \
     -d 'share show <vm-name>' | jq .
```

### End-to-end (RunZero sandbox)

The Starlark runtime cannot be exercised outside RunZero. Before sharing
publicly, validate in a RunZero trial or sandbox instance by pasting the
script into a Custom Integration, attaching credentials, and running a task.
Check that assets appear and that `custom_integration:exe.dev` returns results.

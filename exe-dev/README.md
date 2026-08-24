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

> **Verification note.** exe.dev's published documentation (served at
> `https://exe.dev/docs/`, including raw markdown and an `llms.txt` index)
> documents only the CLI and SSH-key paths below — `/docs/api-keys.md` and
> `/docs/dashboard.md` both 404, and no dashboard token flow appears anywhere
> in it. The steps in this section could **not** be confirmed against vendor
> documentation. They may describe an undocumented UI, or they may be out of
> date. If the dashboard does not look like this, use Method B, which is fully
> documented. The single-command CLI equivalent is:
>
> ```bash
> ssh exe.dev ssh-key generate-api-key --label=runzero-integration --cmds='ls' --exp=90d
> ```

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

Using a separate key means you can revoke runZero's API access independently
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

2. Paste the contents of `exe-dev.star` as the script. The script embeds its
   `CONFIG` block, so the credential form is generated automatically.

3. Create a credential of type **Custom Integration Script Secrets** with:
   - **API token** (`api_token`): **required**, stored as a secret — your exe.dev token (the `exe1.` string)
   - **exe.dev API URL** (`url`): optional, defaults to `https://exe.dev/exec`. Leave it alone unless you are pointing at a proxy or a non-production endpoint.

4. Attach the credential to the integration and save.

5. Create an integration task, select your Explorer, and set a schedule.

## Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token's scope and see what the account returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename exe-dev/exe-dev.star \
  --kwargs url=https://exe.dev/exec \
  --kwargs api_token=exe1.0000000000000000000000000000000000000000000000000000000000000000 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./exe-dev-run
```

`url` defaults to `https://exe.dev/exec`, so in practice only `api_token` is
needed. There are just two parameters here; nothing in this integration is
tuned by configuration.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**This is where you verify the token's `cmds` list.** A token minted with only
`["ls"]` succeeds and produces assets that are simply missing their custom
domain hostnames, proxy exposure, and CAASM attributes — it does not fail, and
the gap is invisible from the console. Run it here and check the output for
`exe_dev_proxy_public`, the custom-domain hostnames, and
`exe_dev_github_repos`. If they are absent, the token's permissions are
narrower than you intended; re-mint it with the fuller `cmds` list from the
table above.

`--kwargs` takes the value verbatim as long as the whole argument holds a single
`=`, so a comma inside a value is passed through intact. Only a value that
*also* contains an `=` flips the flag into comma-separated parsing, and then the
value is cut at the first comma — the remainder either becomes a fabricated
second parameter or aborts the run with `must be formatted as key=value`. An
`exe1.` token is hex and contains neither character, so this is not a practical
problem for this integration.

To check the `CONFIG` block and the HTTP and TLS wiring without touching
exe.dev:

```bash
runzero script --filename exe-dev/exe-dev.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove the token is valid, does not
reveal which `cmds` it carries, and never parses a real VM.

Offline parsing tests live in `exe-dev/tests/fixtures/` and run with
`python3 tests/run.py exe-dev` from the repository root; they stand up a fixture
server, replay the command responses, and assert on the assets that come out.
The command-line run against a real token remains the only test of the token
itself and of the vendor's live contract.

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat exe-dev/exe-dev.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_token=exe1.0000000000000000000000000000000000000000000000000000000000000000' \
  --output ./exe-dev-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`.

## Asset fields

### Core (from `ls -l` — always populated)

| runZero attribute | Value |
|---|---|
| `hostnames` | Up to four sources, de-duplicated in this order: the host parsed out of `https_url`, the `ssh_dest` value, any custom domains (requires `domain ls`), and finally the bare `vm_name` |
| `os` | Linux |
| `deviceType` | `Server` — every exe.dev record is a hosted VM |
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

## Asset identity

- Target entity: an **exe.dev virtual machine** — a hosted Linux host reached over SSH and published over HTTPS. The `ls` collection holds nothing else, which is why the device type comes from the resource itself rather than being guessed from a name or an attached integration.
- Source ID field: **exe.dev publishes no opaque identifier.** The script composes one as `"exedev-" + vm_name`, e.g. `exedev-build01`.
- Documentation evidence — and this is the part that makes the choice defensible rather than a workaround: **every cross-reference in exe.dev's own API is by VM name.** `domain ls -a` returns `vm_name` on each domain record; `share show <vm>` is addressed by name; and `integrations list` attaches integrations with the spec strings `vm:<name>`, `tag:<tag>`, and `auto:all`. The name is the platform's primary key, not merely a label on it. No numeric id, UUID, or serial appears anywhere in the four response shapes this integration consumes.
- Uniqueness scope: the account (or team) the token belongs to. Names must be unique within it, or `share show <vm>` could not address a single VM.
- Cardinality: one asset per VM. Domains, share settings, and integrations are all many-to-one enrichments keyed by the same name.
- Stability: **stable exactly as long as the name is.** A VM renamed in exe.dev gets a new foreign id, which forks a second runZero asset — and no `matchBehavior` flag recovers that merge, because runZero refuses any merge placing two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`.
- **Reuse behavior is the real hazard here, and it is the inverse of the rename case.** Destroying a VM and creating a new one with the same name produces the *same* foreign id, so a genuinely different machine inherits the previous one's runZero asset — its history, its tags, and anything an operator recorded against it. On a fleet where VMs are treated as disposable and names are recycled from a fixed pool (`build01`, `build02`, …), this happens routinely rather than exceptionally. Once a foreign id matches, that match cannot be vetoed by a conflicting hostname or address, so no flag prevents it either. If the platform ever exposes a per-VM identifier, switching to it is the single most valuable change this integration could make.
- Presence: a record whose `vm_name` is empty is dropped by `build_asset` returning `None`. Note that this happens **silently** — unlike the other integrations in this repository there is no log line naming the skipped record.
- Final runZero ID: `exedev-<vm_name>`.
- Missing-ID behavior: skip, without a log line.
- Match behavior: **not set** — the platform default, all match and break dimensions on.
- Verdict: **authoritative for a VM name within one account; not authoritative for a machine**, because the identity is recycled with the name. The default setting is the right call given that the name is the platform's own key, and the recycling hazard is a property of the source rather than something the flags could fix.

**exe.dev publishes no IP addresses and no MAC addresses**, so these assets carry no network interface at all and correlate on hostname alone. That is why the hostname list matters so much here — the HTTPS host, the SSH destination, and any custom domains are the only signals that can merge an exe.dev VM with an asset runZero scanned directly. A token without `domain ls` narrows that set, which is one more reason to check the enrichment attributes after a first run.

## Future

The API is a single command proxy: `POST /exec` with a shell-style command in the body. This integration issues four — `ls -l`, `domain ls -a`, `share show <vm>` (once per VM), and `integrations list`. Everything below is expressed in terms of commands rather than REST paths, because that is the shape of the interface.

- **Resolve the hostnames to addresses so these assets can merge with scanned ones — the highest-value change available.** With no IP data from the API, an exe.dev VM and the same VM discovered by a runZero scan will not correlate unless the hostnames happen to match exactly. The `https_url` host, the `ssh_dest`, and any custom domains are all publicly resolvable names, and the Starlark runtime exposes a resolver, so the addresses could be looked up at import time and attached as a network interface. That single change would turn this from a standalone inventory into something that enriches assets runZero already has.
- **Publicly exposed VMs as scan scope.** `share show` already tells this integration which VMs have a public HTTPS proxy and on what port — the `proxy:public` tag exists for exactly that. Feeding those hostnames into runZero's own external scanning would close the loop: exe.dev says what is *meant* to be exposed, runZero establishes what actually answers. A VM exposed in exe.dev that runZero cannot reach, or one runZero can reach that exe.dev believes is private, are both findings.
- **`share show` is an N+1 and will be the scaling limit.** One request per VM, issued before any asset is built, and a single `403` on the first VM abandons the whole enrichment for the run. If the platform offers a bulk form of the same query it should be preferred; if it does not, the per-VM walk should at least tolerate a partial failure rather than returning early.
- **Team membership for ownership attribution.** `team members` is on the default token's command list — which is why the security section above tells you to remove it — but it is also the only route to knowing *who* owns a VM. If ownership attribution is worth more than the reduced token scope, that is a deliberate trade to make explicitly rather than by accident.
- **The integrations data is already a supply-chain signal and is under-used.** `integrations list` yields the GitHub repositories a VM can reach and the external domains its HTTP proxy is allowed to target; both are imported today as flat comma-separated attributes. Those describe what code runs on a host and what it may talk to — a VM with access to a production repository is a materially different asset from one without, and modelled as tags rather than text that becomes a searchable distinction.
- **VM creation and share configuration are reachable and deliberately out of scope.** A default-scope token can create VMs (`new`) and change exposure settings. Creating VMs costs money and changing a share setting can publish something that was private, so neither belongs behind a scheduled task; this is the reasoning behind the minimal-scope token guidance at the top of this document, and it applies just as strongly to any future outbound work.
- **The two fixtures assert hypothesised shapes, not recorded ones.** `happy` and `malformed` exercise all four commands offline, but exe.dev publishes no API reference, so those shapes are this repository's best guess. A response-shape change therefore still leaves the suite green and the run broken; a capture from a real token is what would close that gap.

## Development and testing

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

### End-to-end (runZero sandbox)

Most of the runtime can be exercised locally with
`runzero script --filename exe-dev/exe-dev.star`; see
[Running it from the command line](#running-it-from-the-command-line) above.
What that does **not** cover is the ingest side — asset merging, tag
application, and the console search behavior. Before sharing publicly, validate
in a runZero trial or sandbox instance by pasting the script into a Custom
Integration, attaching credentials, and running a task. Check that assets appear
and that `custom_integration:exe.dev` returns results.

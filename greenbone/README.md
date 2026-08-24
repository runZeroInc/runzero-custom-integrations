# Greenbone (GMP) Import

Inbound integration that connects to a Greenbone / OpenVAS scanner over the
**Greenbone Management Protocol (GMP)** and imports the latest scan results as
runZero assets, complete with services, software, and vulnerabilities.

It pairs with **[Greenbone (GMP) Scan Launch](../greenbone-scan/README.md)**:
assets discovered by runZero can be scanned in Greenbone, and the results
scanned in Greenbone can be imported back into runZero.

## What it imports

For each task's most recent report (within the configured age window):

- **Assets** — one per scanned host, keyed by the Greenbone host asset ID
  (falling back to `greenbone:<ip>`), with OS name/CPE, hostnames, and MAC/IP
  network interfaces.
- **Services** — open ports (TCP/UDP) with detected service name, banner, and
  per-port severity.
- **Software** — application CPEs detected on the host (`cpe:/a:…`), parsed into
  vendor / product / version.
- **Vulnerabilities** — one per CVE (or per NVT when no CVE), with name,
  description, solution, CVSS base score, severity rank, QoD, and the NVT OID.

Reports are streamed page-by-page and assets are emitted with `report_asset`
as each host completes, so memory stays bounded regardless of report size.

## Transports

Choose one with the **Transport** setting:

- **`ssh`** (default) — SSH into the appliance and forward to the local gvmd
  UNIX socket (`/run/gvmd/gvmd.sock` by default). No `socat`/`netcat` helper is
  required on the appliance; the forward uses the SSH `direct-streamlocal`
  channel (equivalent to `ssh -L localport:/run/gvmd/gvmd.sock`). Authenticate
  with an SSH password or private key, and pin the appliance host key with
  `ssh_host_key` (authorized_keys format from `ssh-keyscan`).
- **`tls`** — connect directly to the GMP TLS listener (port `9390` by default).
  Uses the standard runZero TLS options (`tls_disable_validation`, `tls_ca_cert`,
  `tls_peer_hash` thumbprint pinning, and client certificates).

Both transports authenticate to GMP with **`gmp_username`** / **`gmp_password`**.

## Selecting what to import

- **Maximum report age (days)** — only import a task's latest report if it
  finished within this window (default `30`; `0` disables the limit).
- **Task filter (GMP)** — optional GMP filter selecting which tasks to import,
  e.g. `name~Production`.
- **Report result filter (GMP)** — optional extra GMP filter terms applied to
  report results, e.g. `os~Windows`.
- **Severity levels** — `h`igh, `m`edium, `l`ow, lo`g`. Include `g` (the
  default) so hosts with no vulnerabilities are still imported as assets.
- **Minimum QoD** — minimum Quality of Detection (default `70`).
- **Results per page** — GMP page size (default `100`); larger values reduce
  round-trips at the cost of more memory per page.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Greenbone appliance — over SSH for the
  `ssh` transport, or to the GMP TLS port for the `tls` transport.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon (e.g. "Greenbone").
   - Toggle `Enable custom integration script` and paste in `greenbone.star`.
   - Click `Validate`, then `Save`. The script embeds its `CONFIG` block, so the
     credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials),
   of type `Custom Integration Script Secrets`. The form hides the fields that do
   not apply to the transport you pick.

   | Parameter | Required | Notes |
   |---|---|---|
   | `transport` | yes | `ssh` (default) or `tls`. |
   | `gmp_username` | yes | GMP user with access to the scans to import. |
   | `gmp_password` | yes | Secret. |
   | `ssh_host` | when `transport=ssh` | Appliance hostname or IP. |
   | `ssh_port` | no | Default `22`. |
   | `ssh_username` | when `transport=ssh` | |
   | `ssh_password` | no | Secret. Use this **or** `ssh_private_key`. |
   | `ssh_private_key` | no | PEM, as a textarea. |
   | `ssh_private_key_passphrase` | no | Secret. |
   | `ssh_host_key` | no | Appliance host key in `authorized_keys` format, from `ssh-keyscan`. Required unless the check is disabled. |
   | `ssh_insecure_ignore_host_key` | no | Default `False`. Accepts **any** host key — testing only. |
   | `gmp_socket_path` | no | Default `/run/gvmd/gvmd.sock`. |
   | `gmp_host` | when `transport=tls` | Hostname or IP of the GMP TLS listener. |
   | `gmp_port` | no | Default `9390`. |
   | `max_age_days` | no | Default `30`; `0` disables the limit. |
   | `task_filter` | no | GMP filter over tasks. |
   | `report_filter` | no | Extra GMP filter terms over report results. |
   | `severity_levels` | no | Default `hmlg`. |
   | `min_qod` | no | Default `70`, range 0–100. |
   | `page_size` | no | Default `100`, range 1–5000. |
   | `tls_*` | no | Shared TLS options; used by the `tls` transport. |

3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above.
   - Set the schedule and pick the Explorer that can reach the appliance.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
see what would be imported before scheduling anything. `--kwargs` is repeated
once per parameter. Over SSH, with a key:

```bash
runzero script --filename greenbone/greenbone.star \
  --kwargs transport=ssh \
  --kwargs ssh_host=greenbone.example.com \
  --kwargs ssh_username=runzero \
  --kwargs ssh_private_key="$(cat ~/.ssh/id_ed25519)" \
  --kwargs ssh_host_key="$(ssh-keyscan -t ed25519 greenbone.example.com)" \
  --kwargs gmp_username=admin \
  --kwargs gmp_password=NotTheRealPassword1 \
  --kwargs max_age_days=30 \
  --kwargs min_qod=70 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./greenbone-run
```

Over TLS instead:

```bash
runzero script --filename greenbone/greenbone.star \
  --kwargs transport=tls \
  --kwargs gmp_host=greenbone.example.com \
  --kwargs gmp_port=9390 \
  --kwargs gmp_username=admin \
  --kwargs gmp_password=NotTheRealPassword1 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./greenbone-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported. It requires `--custom-integration-id` to be a well-formed UUID — any
UUID will do for a local run. Add `--overwrite` to re-run into a directory that
already exists. Omit `--output` to see only the log lines, and add `--verbose`
for the request-by-request log.

Bound the first run. `max_age_days` and `task_filter` are the two switches that
matter: an appliance that has been scanning for years holds a long tail of old
reports, and importing all of them is not a smoke test. `severity_levels=hml`
(dropping `g`) additionally restricts the import to hosts that actually have
findings, at the cost of not importing clean hosts as assets.

`--kwargs` takes the value verbatim as long as the whole argument holds a single
`=`, so a comma inside a value is passed through intact — which matters here,
because GMP filter strings and PEM keys both contain characters that look
alarming. Only a value that *also* contains an `=` flips the flag into
comma-separated parsing, and then the value is cut at the first comma; the
remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. **A GMP filter such as
`apply_overrides=1,levels=hml` contains both**, so wrap the whole argument in a
second pair of quotes: `--kwargs '"task_filter=apply_overrides=1,levels=hml"'`.

To check the `CONFIG` block without an appliance:

```bash
runzero script --filename greenbone/greenbone.star --validate
```

This integration sets `"validationMode": "compile"`, because it speaks a direct
protocol over SSH and TLS rather than HTTP. Validation therefore proves the
script compiles and declares its parameters correctly; it does not stand up a
dummy GMP server and confirms nothing about the connection, the credential, or
the parsing.

### What's next?

- The task will kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Greenbone, and create new ones where nothing meets the merge criteria.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:greenbone`.

## Asset identity

- Target entity: a **host as it appeared in one Greenbone scan report** — a scan observation, not a managed device. Greenbone learns about the host by scanning an address; it has no agent and no enrollment step.
- Source ID field: the report host's `<asset asset_id="…">` attribute, falling back to the composed value `greenbone:<ip>` when the report carries no asset element for that host.
- Documentation evidence: the asset id is Greenbone's own host-asset identifier, present on a report host only when asset management is enabled and the host has been promoted into the asset store. That it is optional is why the fallback exists: with asset management off, no host in a report carries one, and the composed `greenbone:<ip>` is all there is.
- Uniqueness scope: one gvmd instance. Neither form is qualified by the appliance, so two Greenbone appliances imported through the same custom integration share an id space — and the fallback form makes that concrete, because `greenbone:10.0.0.5` means a different machine on each of two appliances scanning overlapping RFC 1918 ranges.
- Cardinality: one asset per host per report, de-duplicated **within a run**: a host that appears in several imported reports (overlapping tasks' latest reports) is emitted once per run, first report wins, and the skipped duplicates are counted in the log. Across runs the same physical host scanned by three tasks still converges by address rather than by id.
- Stability: **not stable, in either form.** The fallback is an IP address, so it changes whenever DHCP does and is reassigned to an unrelated machine whenever the address is. The `asset_id` form is more durable, but it identifies a Greenbone host-asset record — purging the asset store, which is routine housekeeping on a busy appliance, discards it.
- Reuse behavior: the `greenbone:<ip>` form is **guaranteed** to be reused, since an address handed to a different machine composes the same id.
- Presence: `asset_id` is present only when asset management is on; the fallback always applies otherwise. Both are truncated to 256 characters.
- Final runZero ID: `<asset_id>` or `greenbone:<ip>`, and the `asset_id` is additionally preserved as the `greenbone.asset_id` custom attribute.
- Missing-ID behavior: none needed — the fallback always produces a value.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`**, declared once in `CONFIG` with the comment "The Greenbone host id is not a stable runZero identity; always merge scan results into existing assets by IP/MAC/hostname instead."
- Verdict: **not authoritative, and correctly declared as such.** This is exactly the case the governing rule describes: scan-derived data with no stable per-device identifier must not drive matching. `no-id-match` prevents the composed id from ever finding a merge candidate — which matters most for the `greenbone:<ip>` form, since matching on it would attach this scan's findings to whichever machine held that address when a previous scan ran. Correlation is left to the IP, MAC, and hostnames the report itself supplies, which are the signals a scan is actually good at.

The setting also protects against the opposite failure. Because a foreign-id match can never be vetoed by a conflicting MAC or hostname, an address-derived id that *did* drive matching would merge unrelated machines with no way for any break flag to stop it. Excluding it from matching is the only defence available.

## Future

- **Import the asset store directly, not just report hosts.** gvmd's `get_assets` command returns the promoted host assets — including hosts whose most recent report falls outside the age window this integration applies. That would separate "what Greenbone has ever seen" from "what the last scan found", and it is where the more durable `asset_id` actually lives.
- **Incremental import instead of latest-report-per-task.** Today each run walks every selected task's most recent report from the beginning. gvmd exposes report metadata including scan end times, so a high-water mark would let a scheduled task import only reports that finished since the last run. On an appliance with many tasks this is the difference between a proportional sync and a full re-read.
- **Scan configuration and coverage as reportable data.** `get_targets`, `get_tasks`, and `get_schedules` describe what the appliance is *configured* to scan and how often. Diffed against runZero's inventory that answers the question a vulnerability programme actually cares about: which assets runZero knows about are in no Greenbone target at all, and which targets point at address ranges that no longer hold anything. Neither is answerable from report results alone.
- **Scanner and feed health.** `get_scanners` and the NVT feed version tell you whether the appliance's vulnerability data is current. A report from an appliance whose feed is six months stale is misleading in a way that is invisible from the results themselves, and surfacing the feed date alongside imported findings would make that visible.
- **Override and false-positive state.** Greenbone supports overrides and notes that suppress or re-rank a result, and this integration currently pins `apply_overrides=0` in its result filter, so it imports the raw severity rather than the operator-adjusted one. Making that a parameter — or importing the overrides themselves — would let runZero reflect the triage decisions an analyst has already made instead of re-presenting findings they have dismissed.
- **The outbound direction already exists.** Launching scans against runZero-selected targets is implemented as a separate integration, [Greenbone (GMP) Scan Launch](../greenbone-scan/README.md), which is the natural other half of this loop. What is *not* implemented in either direction is closing it automatically: scanning newly discovered runZero assets and importing the results without an operator sequencing the two tasks.
- **The transport, not the API, is the constraint on anything added here.** GMP is a stateful XML protocol over a single connection, with no batch wrapper in current gvmd, so every additional command is another sequential round trip on the same socket. That argues for adding a small number of list commands over a large number of per-object lookups.

## Notes

- The integration runs on the selected Explorer and connects to the Greenbone
  appliance, which is typically on an internal network. Scope the Explorer and
  credentials accordingly.
- Tested against Greenbone Community Edition (gvmd 22.6 / GVM 25.2.1).

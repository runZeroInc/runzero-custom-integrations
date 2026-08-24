# Greenbone (GMP) Scan Launch

Internal integration that reads matching assets from runZero, exports their
**primary addresses**, and launches a Greenbone / OpenVAS scan against them over
the **Greenbone Management Protocol (GMP)**.

It pairs with **[Greenbone (GMP) Import](../greenbone/README.md)**: addresses
scanned by runZero can be scanned in Greenbone, and the Greenbone results can be
imported back into runZero — a closed loop between the two systems.

## What it does

1. Calls the runZero **export CSV** endpoint
   (`/api/v1.0/export/org/assets.csv`) with your search filter and collects the
   primary `address` of each matching asset (de-duplicated, validated, capped at
   **Maximum hosts**).
2. Connects to Greenbone over GMP and authenticates.
3. Creates a **target** containing those addresses (using the configured port
   list), creates a **task** (using the configured scan config and scanner), and
   — unless disabled — **starts** the scan. The new report ID is logged.

If task creation fails, the just-created target is rolled back so a failed run
does not leave orphaned objects on the appliance. That holds even when gvmd
rejects the command by hanging up instead of replying (recorded gvmd behavior):
the hangup is reported as an error rather than aborting the run, and the
rollback reconnects, re-authenticates, and deletes the orphaned target.

## runZero export

- **runZero console URL** — e.g. `https://console.runzero.com`.
- **runZero Export API key** — an organization Export API key.
- **Export search filter** — runZero asset search selecting the scan targets.
  Empty means all assets. Examples: `os:Windows`, `last_seen:<30d`,
  `first_seen:<3d`.
- **Maximum hosts** — cap on the number of addresses sent to Greenbone.

The export request uses the standard runZero HTTP/TLS options (prefixed
`rz_http_` / `rz_tls_`).

## Transports

Same as the import integration — choose **`ssh`** (forward to the gvmd UNIX
socket over SSH; no remote helper needed) or **`tls`** (connect to the GMP TLS
port directly with the standard runZero TLS trust/thumbprint/client-cert
options). Authenticate to GMP with **`gmp_username`** / **`gmp_password`**.

## Scan definition

- **Target/task name prefix** — a timestamp is appended to keep each run unique.
- **Scan config ID** — default `daba56c8-73ec-11df-a475-002264764cea`
  (*Full and fast*).
- **Scanner ID** — default `08b69003-5fc2-4037-a479-93b440211c73`
  (*OpenVAS Default*).
- **Port list ID** — default `33d0cd82-57c6-11e1-8ed1-406186ea4fc5`
  (*All IANA assigned TCP*).
- **Start scan immediately** — create-only when disabled.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An organization **Export API key**, created on the
  [organization API keys page](https://console.runzero.com/organizations). It is
  read-only over the asset inventory, which is all this integration needs from
  runZero.
- An Explorer with network access both to the runZero console URL and to the
  Greenbone appliance.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon (e.g. "Greenbone Scan Launch").
   - Toggle `Enable custom integration script` and paste in
     `greenbone-scan.star`.
   - Click `Validate`, then `Save`.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials),
   of type `Custom Integration Script Secrets`. The GMP transport fields are the
   same as the import integration's; the runZero export fields are additional.

   | Parameter | Required | Notes |
   |---|---|---|
   | `runzero_url` | yes | Default `https://console.runzero.com`. |
   | `runzero_export_token` | yes | Secret. Organization Export API key. |
   | `export_filter` | no | runZero asset search. Empty means **all assets**. |
   | `max_hosts` | no | Default and maximum `1000000`. |
   | `transport` | yes | `ssh` (default) or `tls`. |
   | `gmp_username`, `gmp_password` | yes | GMP credential; the password is a secret. |
   | `ssh_host`, `ssh_username` | when `transport=ssh` | |
   | `ssh_port` | no | Default `22`. |
   | `ssh_password`, `ssh_private_key`, `ssh_private_key_passphrase` | no | Password **or** key. |
   | `ssh_host_key` | no | `authorized_keys` format. Required unless the check is disabled. |
   | `ssh_insecure_ignore_host_key` | no | Default `False`. Testing only. |
   | `gmp_socket_path` | no | Default `/run/gvmd/gvmd.sock`. |
   | `gmp_host` | when `transport=tls` | |
   | `gmp_port` | no | Default `9390`. |
   | `target_name` | no | Default `runZero`; a timestamp is appended. |
   | `scan_config_id` | no | Default *Full and fast*. |
   | `scanner_id` | no | Default *OpenVAS Default*. |
   | `port_list_id` | no | Default *All IANA assigned TCP*. |
   | `start_scan` | no | Default `True`. Set `False` to create the target and task without starting. |
   | `rz_http_*`, `rz_tls_*` | no | HTTP and TLS options for the **runZero export** call. |
   | `tls_*` | no | TLS options for the **GMP** connection. |

   Note the three separate option prefixes: `rz_http_` and `rz_tls_` govern the
   call to runZero, and the bare `tls_` prefix governs the GMP TLS transport.
   They are deliberately independent — the console and the appliance rarely share
   a trust configuration.

3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above.
   - Set the schedule and pick the Explorer that can reach both endpoints.

### Running it from the command line

**This run really launches a scan.** Unlike the inbound integrations in this
repository, executing this script has an external side effect: it creates a
target and a task on the appliance and, unless `start_scan=false`, starts an
active vulnerability scan against every address the filter selected. Use
`start_scan=false` and a narrow `export_filter` the first time.

```bash
runzero script --filename greenbone-scan/greenbone-scan.star \
  --kwargs runzero_url=https://console.runzero.com \
  --kwargs runzero_export_token=RZ0EXAMPLEFAKEEXPORTTOKEN000000 \
  --kwargs export_filter=first_seen:\<3d \
  --kwargs max_hosts=25 \
  --kwargs transport=ssh \
  --kwargs ssh_host=greenbone.example.com \
  --kwargs ssh_username=runzero \
  --kwargs ssh_private_key="$(cat ~/.ssh/id_ed25519)" \
  --kwargs ssh_host_key="$(ssh-keyscan -t ed25519 greenbone.example.com)" \
  --kwargs gmp_username=admin \
  --kwargs gmp_password=NotTheRealPassword1 \
  --kwargs target_name=runZero-smoketest \
  --kwargs start_scan=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` is close to useless here — this integration imports nothing, so the
directory is written but holds nothing interesting. Use `--verbose` instead; the
log is the only real feedback, and it reports the number of addresses selected,
the created target id, and the new report id when a scan starts.

An `export_filter` value containing a comma is passed through intact, because
`--kwargs` only switches to comma-separated parsing when the value *also*
contains an `=`. runZero search syntax uses `:` rather than `=` for most
comparisons, so the common cases are safe — but a filter that does contain both
needs a second pair of quotes around the whole argument:
`--kwargs '"export_filter=a=b,c"'`. Note also that `<` and `>` are shell
metacharacters and need escaping or quoting, as in the `first_seen:\<3d` above.

To check the `CONFIG` block without touching either system:

```bash
runzero script --filename greenbone-scan/greenbone-scan.star --validate
```

This integration sets `"validationMode": "compile"`, because it speaks a direct
protocol rather than HTTP. Validation proves the script compiles and declares its
parameters correctly; it does not exercise the export call or the GMP connection.

## Asset identity

**This integration has no asset identity, because it creates no assets.**

- Target entity: none. `CONFIG["type"]` is `internal`. The script never loads
  `runzero.types`, never constructs an `ImportAsset`, and never calls
  `report_asset`. It reads addresses out of runZero and writes objects into
  Greenbone.
- Source ID field: not applicable. The only identifiers it handles are the
  Greenbone target, task, and report ids it creates, and those are logged rather
  than imported.
- Match behavior: not applicable — `matchBehavior` exists only on an
  `ImportAsset`, and none is built here.
- Verdict: **not an identity-bearing integration.** Nothing merges, nothing
  forks, and no `custom_integration:` search returns anything as a result of
  running it. The results of the scan it launches come back through
  [Greenbone (GMP) Import](../greenbone/README.md), and the identity decisions
  are documented there.

What this integration *does* select on is the runZero asset's **primary
address**, exported one per asset with `fields=address` and de-duplicated and
validated before being sent. That has two consequences worth knowing: a
multi-homed asset is scanned on one interface only, and an asset whose primary
address is stale is scanned at whatever now holds that address. Neither is
visible from the Greenbone side, where the target is simply a list of addresses
with no provenance.

## Future

- **Send hostnames, not only addresses.** The export requests `fields=address`
  and Greenbone targets accept hostnames as readily as IPs. For assets behind
  DHCP a name is the more durable target, and for virtual-hosted web services it
  is the only one that reaches the right application.
- **Reuse a target instead of creating a new one per run.** Each run creates a
  fresh timestamped target and task. That is safe and self-contained, but it
  accumulates objects on the appliance indefinitely, and it discards the report
  history that makes a task's trend view useful. `modify_target` and re-running
  an existing task would keep one task's history intact; the trade-off is that a
  failed run then mutates something that already existed, which is why the
  current design does not do it.
- **Wait for the scan and hand off to the import.** `get_tasks` reports task
  status and progress, so this integration could poll to completion and trigger
  the import side rather than leaving an operator to schedule the two tasks far
  enough apart. That closes the loop properly, at the cost of a long-running
  task; a status check that reports "the previous run's scan is still going" is
  a cheaper first step and avoids stacking scans.
- **Scan-scope safety rails.** The only guard today is `max_hosts`, which
  defaults to one million — effectively unbounded. An address-range allowlist,
  or a refusal to proceed when the selected set exceeds some multiple of the
  previous run, would make an over-broad `export_filter` a failed task rather
  than an unplanned scan of the whole estate. This is the most valuable
  robustness change available, because the failure mode is an active scan of
  something nobody intended to scan.
- **Alert and schedule objects.** gvmd can attach an alert to a task, so the
  appliance itself notifies when a scan finishes, and schedules can make a task
  recur without runZero re-launching it. Either would reduce this integration to
  managing target membership only, which is a smaller and more robust job than
  orchestrating the whole scan lifecycle.
- **Push runZero context into the target metadata.** A Greenbone target takes a
  comment, which this integration uses for the host count. It could carry the
  runZero search that produced the set and the time it was taken, so that months
  later the appliance itself records why those addresses were scanned. Cheap, and
  it makes the objects self-documenting.

## Notes

- The integration runs on the selected Explorer and connects to the Greenbone
  appliance, which is typically on an internal network. Scope the Explorer and
  credentials accordingly.
- Tested against Greenbone Community Edition (gvmd 22.6 / GVM 25.2.1).

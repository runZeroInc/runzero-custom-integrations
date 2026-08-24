# Custom Integration: Uptycs

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Uptycs requirements

- An Uptycs API key pair (a `key` and `secret`) downloaded from the Uptycs console.
- The API user must be able to run global queries against the Uptycs data lake (`POST /query` with `queryType: global`).
- Read access to the `upt_assets` table is required. Read access to the osquery tables `interface_details`, `interface_addresses`, `system_info`, `programs`, `apps`, `deb_packages`, `rpm_packages`, and `listening_ports` is optional; each is queried independently and is skipped with a warning if it is absent or unauthorized.

## Steps

### Uptycs configuration

1. In the Uptycs console, open **Configuration** > **User Management** and create or select an API user with query permissions.
2. Generate and download the API key file. It contains the `key`, `secret`, `domain`, and `customerId` values used below.
3. Confirm the tenant answers a global query:
   `POST https://<domain>/public/api/customers/<customerId>/query` with body
   `{"query": "SELECT * FROM upt_assets LIMIT 1", "queryType": "global"}`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Uptycs").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Uptycs URL** (`url`): the tenant URL built from the `domain` value in the API key file, for example `https://tenant.uptycs.io`.
   - **Customer ID** (`customer_id`): the `customerId` value from the API key file.
   - **API key** (`api_key`): the `key` value from the API key file. Used as the JWT issuer claim.
   - **API secret** (`api_secret`): the `secret` value from the API key file. Used to sign the JWT.
   - **Import MAC addresses, IP addresses, and serials** (`include_host_details`): optional; queries `interface_details`, `interface_addresses`, and `system_info` (default: on).
   - **Import software inventory** (`include_software`): optional; queries `programs`, `apps`, `deb_packages`, and `rpm_packages` (default: on).
   - **Import listening services** (`include_services`): optional; queries `listening_ports` (default: off).
   - **Import vulnerabilities** (`include_vulnerabilities`): optional; queries the vulnerability table named below (default: off).
   - **Vulnerability table name** (`vulnerability_table`): optional; the data lake table to read findings from (default: `upt_vulnerabilities_state`).
   - **Enrichment lookback (days)** (`lookback_days`): optional; how many days of the `upt_day` partition to scan for software, service, and interface rows (default: 3).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Uptycs.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:uptycs`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm an
API key pair and see what a real tenant returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair, and all four required values come straight out of the
API key file downloaded from the Uptycs console:

```bash
runzero script --filename uptycs/uptycs.star \
  --kwargs url=https://tenant.uptycs.io \
  --kwargs customer_id=11111111-2222-3333-4444-555555555555 \
  --kwargs api_key=Ab1CdEf2GhIjKlMn \
  --kwargs api_secret=Zy9XwVu8TsRqPoNmLkJiHgFeDcBa7654 \
  --kwargs lookback_days=1 \
  --kwargs include_software=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/uptycs-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

`api_key` and `api_secret` are not sent as credentials in their own right: the
script signs a JWT with the secret and puts the key in the issuer claim. A
mistyped secret therefore surfaces as a rejected token rather than as a "bad
password" message.

Drop `lookback_days` to 1 for a first run. It controls how many days of the
`upt_day` partition each enrichment query scans, and it is the parameter that
decides whether a smoke test reads a day of the data lake or three. Leave
`include_software` off too, then turn the enrichments on one at a time — each is
an independent query, and each is skipped with a warning if the tenant does not
grant the table, so enabling them individually is how you find out which tables
your API user can actually read. `get_bool` accepts `true/false`, `1/0`,
`yes/no`, and `on/off`.

`include_vulnerabilities` is off by default because `vulnerability_table` is
tenant specific. `upt_vulnerabilities_state` is the default, but confirm the name
against your own tenant before enabling it — a wrong table name produces a
warning and no findings rather than an error.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real tenant:

```bash
runzero script --filename uptycs/uptycs.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never runs a real data lake
query, so it confirms nothing about table access or the JWT the tenant will
accept.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://tenant.uptycs.io,customer_id=...,api_key=...,api_secret=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py uptycs
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a host with an enrolled Uptycs osquery agent (physical machine, VM, or container host).
- Source ID field: `upt_assets.id`
- Documentation evidence: Uptycs' own API reference requires a customer login, so the contract is taken from public code. The Cortex XSOAR Uptycs content pack (`Uptycs.py`) queries `SELECT * FROM upt_assets`, treats `id` as the asset key, filters with `{"id": <asset_id>}`, and joins every other lake table with `... JOIN upt_assets u ON a.upt_asset_id = u.id`. Uptycs' own ServiceNow integration (`github.com/uptycslabs/servicenow`) does the same — `join upt_assets ua on ua.id = uvs.upt_asset_id` — and maps `asset.id` into the ServiceNow CMDB `correlation_id` field, which is exactly the "stable foreign key for this device" role. `id` is a UUID and is the only column either integration uses to address an asset.
- Uniqueness scope: tenant. Every request is scoped to `/public/api/customers/<customer_id>`, and the pack never qualifies `id` beyond the customer path, so uniqueness outside a customer is not established.
- Cardinality: one `upt_assets` row per enrolled agent. All enrichment tables are child rows keyed by `upt_asset_id`, so many software, port, interface, and finding rows collapse onto a single asset.
- Stability: the id survives rename, reboot, IP/MAC change, and osquery agent upgrade — it is the join key the entire lake schema is built on, and the pack's per-asset history queries assume it persists across days.
- Reuse behavior: not documented. It is a UUID, so accidental reuse after deletion is not a practical concern, but re-enrollment is. Nothing public states whether a full agent uninstall and reinstall preserves the id; `upt_assets` also carries a `deleted_at` column described as the time the asset was unenrolled, which implies unenrollment is a terminal state for a record rather than something a new install reuses. Suggestive but not conclusive counter-evidence: the osquery `hostIdentifier` that Uptycs agents report is the hardware UUID (`system_info.uuid`), so identity is at least anchored to hardware somewhere in the pipeline — but `upt_assets.id` is a different UUID and the derivation is not published. Assume a reinstall can mint a new id. That produces a second runZero asset rather than a collision, and it is why `matchBehavior` is relaxed rather than defaulted (see below).
- Presence: required. `id` is present on every `upt_assets` row returned by the pack's queries.
- Final runZero ID: `uptycs:<customer_id>:<upt_assets.id>`
- Missing-ID behavior: skip the record and print `uptycs: skipping asset with no id: host_name=<name>`. No fallback id is synthesized.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The Uptycs id is authoritative, and once it matches, nothing here can fragment the asset — a foreign-ID match is never disqualified by a conflicting MAC, IP, or hostname. These flags govern first contact, before an ID has matched, where they let a re-enrolled agent merge onto the existing runZero asset through its MAC or hostname rather than creating a duplicate.

  This deliberately does **not** rest on the churn caused by osquery reporting every interface on a host. Virtual, container, and VPN adapters are now filtered out of `interface_details` and `interface_addresses` by name before they can become network interfaces (see Notes), because the correct response to importing a non-unique MAC — a container bridge such as `docker0` carries the same deterministic address on every host running Docker — is to not import it, rather than to disable the break that guards against it.
- Verdict: scoped authoritative.

### Notes

- Everything is read through a single endpoint, `POST /public/api/customers/<customer_id>/query`, with `{"query": "<SQL>", "queryType": "global"}`. Results arrive under `items`.
- Authentication is a locally-signed HS256 JWT — there is no token exchange. The script mints `{"iss": <api_key>, "exp": <epoch seconds>}` signed with the API secret, sends it as `Authorization: Bearer <jwt>`, and sends an RFC 1123 UTC `date` header alongside it. A fresh one-hour token is minted at the start of every asset page, so a long run never presents an expired assertion.
- Imported objects:
  - **Assets** from `upt_assets` — hostname, OS, OS version, hardware vendor and model, plus `os_flavor`, `osquery_version`, `status`, `live`, `deleted_at`, `location`, `latitude`, `longitude`, `gateway`, `cores`, `memory_mb`, `cpu_brand`, `object_group_id`, `created_at`, `last_enrolled_at`, and `last_activity_at` as `uptycs_` custom attributes. `created_at` also becomes `firstSeenTS` and `last_activity_at` becomes `lastSeenTS`. Both are parsed as the bare date and time, without any offset the value may carry, so they are read as UTC and then **clamped to the current time** before assignment: runZero rejects an asset whose first- or last-seen time is in the future and the error fails the entire record, so a column written in a timezone east of UTC would otherwise have every asset dropped. The clamp skews first-seen and last-seen toward the present instead of losing the asset, and the raw values remain available as the `uptycs_created_at` and `uptycs_last_activity_at` custom attributes.
  - **Network interfaces** from `interface_details` (`mac`) paired with `interface_addresses` (`address`) on the interface name. Loopback, unspecified, and all-zero addresses are dropped, as are all-zero MACs.

    Virtual adapters are also dropped, matched on the osquery interface name: the container, VPN, hypervisor, and tunnel families (`docker*`, `veth*`, `br-*`, `cni*`, `flannel*`, `cali*`, `virbr*`, `vmnet*`, `vboxnet*`, `vEthernet (*)`, `tun*`, `tap*`, `utun*`, `wg*`, `zt*`, `tailscale*`, `awdl*`, `llw*`, `bridge*`, and `lo`). These are not the host's own hardware and their addresses are frequently identical across hosts — `docker0` gets the same deterministic MAC on every machine running Docker, and a hypervisor's virtual switch address is shared with every guest — so importing them would attach one host's adapters to unrelated assets. A name is only treated as virtual when it is the bare prefix or the prefix followed by a digit, separator, or parenthesised label, so a real adapter such as `lom1` is not swallowed by the `lo` entry.
  - **Hardware serial, system UUID, and computer name** from `system_info`. The serial and UUID land in custom attributes; the computer name is added as a second hostname.
  - **Software** from `programs` (Windows), `apps` (macOS), `deb_packages`, and `rpm_packages` (Linux). Each table is aliased onto a common product/version/vendor shape; rows are deduplicated per asset on product plus version.
  - **Services** from `listening_ports`. `protocol` is the IANA IP protocol number, so 6 becomes `tcp`, 17 `udp`, and 132 `sctp`; anything else is skipped. UNIX-socket rows (port 0) are skipped. A wildcard bind (`0.0.0.0` or `::`) is rewritten to the asset's first IPv4 address from `interface_addresses`, and skipped when no such address is known.
  - **Vulnerabilities** from `upt_vulnerabilities_state` (configurable), when enabled. CVE, severity, CVSS score, description, and affected package are read from a list of candidate column spellings rather than a fixed schema. Uptycs stores `cvss_score` and `uptycs_score` as strings, so scores are only used when they parse as numbers; when no severity word maps, the rank is derived from the score.
- Pagination is SQL-native. `upt_assets` is paged with `ORDER BY id LIMIT 200 OFFSET n`. Each enrichment table is then queried once per asset page with a `WHERE upt_asset_id IN (...)` filter and its own `LIMIT 2000 OFFSET n` loop, capped at 20,000 rows per table per page; hitting the cap prints which table was capped. Software, services, and vulnerabilities are additionally capped at 99 per asset by the platform.
- The osquery tables are re-collected every few hours, so each *osquery* enrichment query (software, services, interfaces, system info) is `SELECT DISTINCT ... AND upt_day >= <YYYYMMDD>` over the lookback window. The vulnerability query is a plain `SELECT *` with no time bound, because the state table's own time column is an epoch integer rather than a `upt_day` partition and its schema is the least certain part of this integration. `upt_day` is an integer partition column the Uptycs agent pipeline injects into osquery tables (alongside `upt_asset_id`, `upt_hostname`, `upt_time`, `upt_added`, and others); it is not part of osquery itself. If a table rejects the predicate, the query is retried once without it and a warning names the table — in that case the results may include stale rows, because the time bound is what filters old snapshots out.
- Rate limiting and transient errors (408/425/429/5xx) are retried with exponential backoff by the shared HTTP helper, which honors `Retry-After`. `retries` defaults to 3, which is what this integration uses.
- Every table is queried independently and failure is non-fatal: a missing, renamed, or unauthorized table prints one `uptycs: skipping ...` warning and the run continues with the remaining data. Only a failure on `upt_assets` itself ends the run.
- Asset ids are stripped to `[0-9A-Za-z_.-]` before they are interpolated into a SQL `IN` list, so API data cannot alter the shape of a query.

#### Unverified assumptions — read this before trusting the enrichment

Uptycs' API documentation is gated behind a customer login and could not be read. Every contract below therefore comes from public code rather than from vendor documentation, and it is worth knowing which parts rest on what.

**Confirmed by the Cortex XSOAR Uptycs pack** (public, vendor-reviewed): the base URL `https://<domain>/public/api/customers/<customer_id>`, the JWT signing scheme and the `Authorization` + `date` headers, `POST /query` with `{"query": ..., "queryType": "global"}`, results under `items`, `SELECT * FROM upt_assets`, and `upt_asset_id` as the column that joins every other lake table to an asset. It also documents the full set of `upt_*` metadata columns injected into osquery tables: `upt_counter`, `upt_asset_id`, `upt_hostname`, `upt_asset_tags`, `upt_hash`, `upt_asset_group_id`, `upt_time`, `upt_added`, `upt_server_time`, `upt_asset_group_name`, `upt_day`, `upt_epoch`.

**Confirmed by Uptycs' own public integrations** (`github.com/uptycslabs/servicenow`, `github.com/uptycslabs/uptapi`): the `upt_vulnerabilities_state` table and its `cve_list`, `uptycs_severity`, `cvss_score`, `uptycs_score`, `package_name`, `package_version`, `description`, and `upt_asset_id` columns; that `cvss_score`/`uptycs_score` are strings needing a cast; the `gateway`, `hardware_model`, and `hardware_vendor` columns on `upt_assets`; and that `/query` returns `items` with no total or paging metadata.

**Confirmed only by the osquery schema, not by Uptycs:** the column names in `programs`, `apps`, `deb_packages`, `rpm_packages`, `listening_ports`, `interface_details`, `interface_addresses`, and `system_info`, including that `listening_ports.protocol` is an IP protocol number. All eight appear in an Uptycs engineer's public production table list, and an Uptycs threat-research post runs a global query directly against `deb_packages`, so these tables do exist in the lake. That every one of them is queryable and permitted in *your* tenant is still an assumption; any that are not produce a warning and are skipped.

**Still not confirmed, and this is where to be careful:**

- **Vulnerability import is off by default.** `upt_vulnerabilities_state` is attested in exactly one place — Uptycs' own ServiceNow integration — and never appears in Uptycs' published documentation. Names that sound plausible but have *no* public attestation, and which this integration deliberately does not use, include `upt_vulnerabilities`, `upt_asset_vulnerabilities`, and `cve_*`. The table name is a credential field so an operator can redirect it without editing the script. Turn the feature on once you have confirmed the table exists in your tenant; `SELECT * FROM information_schema.tables` will tell you.
- **`upt_assets.cpu_brand`, `cores`, `memory_mb`, and `object_group_id` are not attested** in any public source, only `id`, `host_name`, `os`, `os_version`, `os_flavor`, `osquery_version`, `status`, `live`, `created_at`, `last_enrolled_at`, `last_activity_at`, `deleted_at`, `location`, `latitude`, `longitude`, `gateway`, `hardware_model`, and `hardware_vendor` are. Because the asset query is `SELECT *` and each field is read with a default, an absent column simply yields an empty custom attribute rather than an error.
- **`upt_assets` carries no MAC, serial, or IP column.** Uptycs' own ServiceNow CMDB mapping populates the IP field from `gateway`, which is the strongest available evidence that no host IP column exists. MAC, IP, and serial therefore come from `interface_details`, `interface_addresses`, and `system_info` — which is why `include_host_details` defaults on: without it, correlation rests on hostname alone.
- **Current-state semantics.** `upt_day` is a partition convention, not a syntactic requirement — Uptycs' own threat research queries `deb_packages` globally with no `upt_day` at all — but Uptycs collects these tables from every asset every few hours, so an unbounded query returns many stale snapshots. This integration bounds them with `upt_day >= <lookback>` and `SELECT DISTINCT`, and falls back to an unbounded query with a warning if the predicate is rejected. It deliberately does *not* use `upt_added`: the agent's payload templates show package and inventory tables emit `added` events only, so the add/remove interval reconstruction the XSOAR pack applies to `processes` does not transfer. The consequence is that a package removed during the lookback window can still be imported, and a package upgraded during it can appear at two versions. Shorten `lookback_days` if that matters more than coverage.
- **The `queryType` key is inconsistent across the three public Uptycs clients.** XSOAR sends `queryType: global`, Uptycs' ServiceNow integration sends `type: global` (to `/queryJobs`), and `uptapi` sends no type field at all and still gets global results. This integration follows XSOAR. Global appears to be the default for `/query`; realtime is a separate endpoint (`POST /assets/query`).
- **The SQL dialect is Presto/Trino, not SQLite**, despite the XSOAR docs saying otherwise — the queries here stay within plain ANSI SQL (`SELECT DISTINCT`, `IN`, `ORDER BY`, `LIMIT`/`OFFSET`) so the distinction does not bite, but it matters if you extend them.
- This integration was validated against local fixtures, not a live Uptycs tenant.

## Future

- **Any osquery table as a runZero enrichment source.** `POST /query` runs arbitrary SQL over the whole osquery schema, which makes this the broadest enrichment surface of any integration here. Beyond what is imported today: `certificates` (expiring and self-signed certs per host), `kernel_modules` / `kernel_extensions` (driver inventory), `users` and `logged_in_users` (account attribution), `chrome_extensions` and `firefox_addons` (browser extension risk), `disk_encryption` (FileVault/BitLocker posture), `docker_containers` and `docker_images` (container inventory), `python_packages` / `npm_packages` / `chocolatey_packages` (language-level SBOM), and `arp_cache` / `routes` (adjacency data that could seed runZero scan scope). Each would be another guarded query in the same collector pattern.
- **The async `/queryJobs` endpoint for full-inventory pulls.** Uptycs' own ServiceNow integration uses `POST /queryJobs` -> poll `GET /queryJobs/{id}` for `QUEUED`/`RUNNING`/`FINISHED` plus a `rowCount` -> page `GET /queryJobs/{id}/results?offset=n` in 10,000-row pages. That is a strictly better shape than the synchronous `/query` used here: a row count up front instead of paging blind, and no risk of a large scan timing out inside a single request. Note the result rows are wrapped in `rowData` there, unlike `/query`. Worth switching to if very large tenants prove slow.
- **Alert and detection ingestion.** `upt_alerts` is queryable via the same `/query` endpoint and already joins to `upt_assets` on `upt_asset_id` in the XSOAR pack (`SELECT a.*, u.host_name FROM upt_alerts a JOIN upt_assets u ON a.upt_asset_id = u.id`). `upt_events` is the same shape for raw detections, and the pack also exposes `/threatSources` and `/threatIndicators` for managing the threat intel sources that generate them. An alert-oriented integration could surface active detections as runZero attributes or as findings, scoped by severity and time window.
- **Outbound: runZero asset lists as an Uptycs detection input.** This is the genuinely novel direction. Uptycs supports operator-defined lookup tables that can be referenced from detection rules, populated through `POST /lookupTables` and `POST /lookupTables/{id}/csvdata` (both present in the XSOAR pack as `uptycs-post-lookuptable` / `uptycs-post-lookuptable-data`). An outbound integration could push a runZero asset list — unmanaged devices, assets on a sensitive subnet, expired-certificate hosts, or anything expressible as a runZero query — into a lookup table, letting Uptycs detection rules join live endpoint telemetry against runZero's view of the network. Very few EDR platforms accept an external asset list as a first-class detection input; this one does.
- **Agent coverage-gap reporting.** Because runZero discovers hosts without any agent and Uptycs only knows about hosts that enrolled one, the difference is directly actionable. Importing `upt_assets` establishes which runZero assets carry the Uptycs attribute; everything else in scope is an osquery deployment gap. `upt_assets.osquery_version` and `last_activity_at` additionally identify stale and outdated agents on hosts that *are* enrolled.
- **Asset tagging round-trip.** The pack exposes `/assets/{id}` tag reads plus `uptycs-set-asset-tag` and `uptycs-post-tag` for writes, so runZero ownership, site, or criticality data could be pushed onto Uptycs assets as tags to drive Uptycs policy scoping. This is a smaller win than the lookup table path but uses a documented, stable endpoint.

## API documentation

- Uptycs' API reference (`https://<tenant>.uptycs.io/help/`, and the Uptycs documentation portal) requires an authenticated customer account and could not be read. Everything below stands in for it.
- Cortex XSOAR Uptycs content pack — the public, vendor-reviewed API client used as the contract for authentication, the base URL, the `/query` endpoint, and the `upt_assets` schema: <https://github.com/demisto/content/blob/master/Packs/Uptycs/Integrations/Uptycs/Uptycs.py>
- Cortex XSOAR Uptycs pack command reference, used for the `upt_*` metadata column list and the endpoint inventory cited under Future: <https://github.com/demisto/content/blob/master/Packs/Uptycs/Integrations/Uptycs/README.md>
- Uptycs' own ServiceNow integration — the source for `upt_vulnerabilities_state` and its columns, the `upt_assets` to CMDB field mapping, and the `/queryJobs` async paging contract: <https://github.com/uptycslabs/servicenow>
- Uptycs' own Python API library — the source for the `/query` response shape (`items`, no total) and the base URL construction: <https://github.com/uptycslabs/uptapi>
- Uptycs threat research, showing a global query run directly against `deb_packages` with no `upt_day` predicate: <https://www.uptycs.com/blog/threat-research-report-team/dirtypipe-linux-exploit>
- Uptycs asset-management query tutorial, the source for `upt_assets.live`, `upt_asset_tags`, and `upt_asset_activity`: <https://www.uptycs.com/blog/osquery-tutorial-building-sql-queries-for-asset-management>
- osquery schema, used for every non-`upt_` table's column names, types, and platform availability: <https://osquery.io/schema/>
- osquery `listening_ports` specification, confirming `protocol` is an IANA IP protocol number rather than a name: <https://github.com/osquery/osquery/blob/master/specs/listening_ports.table>

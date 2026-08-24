# Custom Integration: Nozomi Networks

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Nozomi Networks requirements

- A Guardian or CMC appliance reachable from the runZero Explorer over HTTPS. The `/api/open/*` paths this integration uses are the on-premise N2OS Open API; Vantage (the SaaS offering) exposes its own, different API and is not supported by this script.
- An Open API key pair (`key_name` and `key_token`) belonging to a **local** user. Nozomi does not issue Open API keys to remotely authenticated users.
- The user's group needs the **Queries and exports** permission. Nozomi additionally supports per-table query restrictions, so the group must be allowed to query the `assets` table, and the `asset_cves` table if CVE import is enabled.

## Steps

### Nozomi Networks configuration

1. Sign in to the Guardian or CMC web interface as an administrator.
2. Create or select a **local** user and confirm its group holds the **Queries and exports** permission.
3. Generate an Open API key for that user and record both halves: the **key name** and the **key token**. The token is shown once.
4. Confirm API access from the Explorer host, for example:
   `curl -u '<key_name>:<key_token>' 'https://guardian.example.com/api/open/query/do?query=assets%20%7C%20head%201'`

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Nozomi Networks").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Nozomi Networks URL** (`url`): base URL of the Guardian or CMC appliance, for example `https://guardian.example.com`.
   - **API key name** (`key_name`): the `key_name` half of the Open API key pair.
   - **API key token** (`key_token`): the `key_token` half of the Open API key pair.
   - **Asset query filter** (`asset_filter`): optional; an N2OS filter appended to the assets query, for example `where level == 4`.
   - **Import CVE findings** (`include_cves`): optional; also query `asset_cves` and attach unresolved CVEs (default: enabled).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename nozomi-networks/nozomi-networks.star \
  --kwargs url=https://guardian.example.com \
  --kwargs key_name=exampleFakeKeyName01 \
  --kwargs key_token=exampleFakeKeyToken0123456789abcdef \
  --kwargs asset_filter='where level == 4' \
  --kwargs include_cves=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./nozomi-networks-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. Turning `include_cves` off on a first run skips the second `asset_cves` query,
which on a large Guardian is the expensive half of the import.

**One CLI caveat, and `asset_filter` is where it bites:** `--kwargs` takes the value
verbatim as long as the whole argument holds a single `=`, so a comma on its own is
harmless — `--kwargs 'asset_filter=where type in [plc, rtu]'` arrives intact, and so does
`--kwargs 'asset_filter=where level == 4'`. The breakage needs *both* a second `=` and a
comma, which is exactly what an N2QL filter that tests two fields looks like, because
`==` is its equality operator:

```
--kwargs "asset_filter=where level == 4, type == 'plc'"
```

That one is parsed as a comma-separated list: the script receives a truncated
`asset_filter` of `where level == 4` plus a fabricated ` type ` parameter, and it filters
on half of what you asked for without saying so. Wrap the whole argument in a second pair
of quotes to keep it as one field:

```bash
  --kwargs "\"asset_filter=where level == 4, type == 'plc'\""
```

Use escaped double quotes for the inner pair as shown. Wrapping in single quotes instead
(`'"…''plc''…"'`) looks equivalent but is not — the shell closes and reopens the string
at each `'`, so the quotes around `plc` are stripped before the scanner ever sees them
and the filter reaches N2QL comparing against a bare identifier.

To check the `CONFIG` block and the HTTP and TLS wiring without a live appliance:

```bash
runzero script --filename nozomi-networks/nozomi-networks.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Nozomi accepts the key pair, that the key's group holds the
**Queries and exports** permission, or that any asset is parsed. The fixture scenarios
are what exercise the parsing:

```bash
python3 tests/run.py nozomi-networks
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat nozomi-networks/nozomi-networks.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://guardian.example.com,key_name=exampleFakeKeyName01,key_token=exampleFakeKeyToken0123456789abcdef' \
  --output ./nozomi-networks-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string — genuinely, and with no single-`=` exemption. Here a
comma in *any* value splits it, so an `asset_filter` that lists two conditions cannot be
passed this way at all, `==` or not. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with OT context pulled from Nozomi Networks.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:nozomi-networks`.

## Asset identity

- Target entity: a physical or virtual OT, IoT, or IT device observed by a Nozomi sensor. Nozomi models this as an *asset*, which is a grouping over one or more *nodes*.
- Source ID field: `assets.id`
- Documentation evidence: the Nozomi data-model page for the `assets` table does not list `id`, but the vendor's own XSOAR client treats it as the asset key — it sorts on it (`query=assets | sort id`), pages on it, and its command reference documents the field as "uniq id of an asset" (`NozomiNetworks.yml`). The captured API response in that pack shows UUIDv4 values such as `03a0c54b-f196-4817-8198-66b06fba8739`.
- Uniqueness scope: the appliance the credential points at. Asset ids are generated per installation; a CMC or Vantage instance aggregating several Guardians presents its own asset set with its own ids.
- Cardinality: one row per asset. An asset groups one or more nodes, so the node-to-asset relationship is many-to-one, but nothing splits a single asset across rows.
- Stability: survives rename, IP change, and MAC change, since the id belongs to the asset record rather than to any observed address. Rebuilding an appliance's database regenerates the asset set and therefore the ids.
- Reuse behavior: not documented. UUIDv4 allocation makes reassignment of a deleted id implausible.
- Presence: present on every row of the captured response, and required by the vendor's own paging, so a row without it is malformed.
- Final runZero ID: `nozomi-networks:<appliance-host>:<assets.id>`, where the appliance host is the hostname of the configured URL.
- Missing-ID behavior: the row is skipped and only its `name` is logged.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`
- Verdict: scoped authoritative.

The match behavior is not a precaution here, it is required by the data. In the captured eight-asset response, two distinct assets (`2bec30cc-…` and `f730f58a-…`) carry the **same** MAC address `00:02:3e:99:f2:89`, and six of the eight assets have no name other than their own IP address. Passive OT monitoring re-observes addresses constantly, so MAC, IP, and name churn must not be allowed to disqualify a merge that the asset id already justifies.

### Notes

- **Imported objects.** Assets come from `GET /api/open/query/do?query=assets | sort id`. Each row maps to one runZero asset: `name` to hostnames, `ip[]` and `mac_address[]` to network interfaces, `vendor` to manufacturer, `product_name` to model, `os` to os, and `type` to device type. `vendor`, `product_name`, `firmware_version`, and `serial_number` also produce one **Software** record representing the device firmware. When CVE import is enabled, unresolved rows from the `asset_cves` table are attached as **Vulnerability** findings.
- **Purdue level and zones are tags.** `level` becomes `purdue-level:<n>`, each entry of `zones` becomes `zone:<name>`, each entry of `roles` becomes `role:<name>`, and each observed protocol becomes `protocol:<name>`. Every asset also carries the `nozomi-networks` and `ot` tags. This matches the tagging convention used by the Forescout eyeInspect integration so the two OT sources can be searched together.
- **No services are emitted.** The `assets` table records *which* protocols were observed on a device but never the ports they ran on, and `Service` requires an address, a port, and a transport. Rather than synthesize a port from a protocol name, the protocol names are kept as tags and as the `nozomi_protocols` attribute. See `## Future` for the tables that would supply real ports.
- **No timestamps are set.** The `assets` table publishes no first-seen or last-seen column, so neither `firstSeenTS` nor `lastSeenTS` is populated. The `last_activity_time` field is **not** part of the assets schema despite appearing in some third-party descriptions.
- **Not-determined placeholders are dropped.** Nozomi writes a literal `-` into `type` and leaves other properties as empty strings when it never determined them. Those values are discarded rather than imported as real data — five of the eight assets in the captured response have `type` of `-`.
- **IP-only names are not imported as hostnames.** When Nozomi has no name for a device it falls back to the device's own IP address in the `name` field. Those values are kept as the `nozomi_name` attribute but are not sent as hostnames.
- **Collection provenance is preserved.** Nozomi annotates `vendor`, `firmware_version`, `product_name`, `serial_number`, and `type` with a companion `<field>:info` object recording whether the value was observed passively or collected by active polling. That provenance is imported as `nozomi_<field>_source`. `capture_device` and `appliance_hosts` are imported so multi-sensor deployments stay diagnosable.
- **Authentication.** `POST /api/open/sign_in` is called with `{"key_name": …, "key_token": …}`. Nozomi returns the bearer token in the **`Authorization` response header** rather than in the body, so the script uses the raw `http.post` builtin to read it. The header value is reused **verbatim** and no scheme prefix is added, matching the vendor's XSOAR client. If sign-in fails or returns no such header, the script falls back to HTTP Basic with the same key pair, which the Open API also accepts.
- **Token expiry is handled.** The issued JWT expires after 30 minutes, which a large inventory walk can outlive. A query rejected with 401 or 403 triggers one re-sign-in and a retry of that page, bounded to three sign-in attempts per run.
- **Pagination.** Paging uses the documented `page` and `count` parameters over an id-sorted query. `count` is set to 500; the API caps it at 10,000 and Nozomi recommends staying under 1,000. `page` is rejected past 1,000, so on reaching that ceiling the script appends `| where id > <last id seen>` and restarts at page 1 — the same pivot-and-restart pattern Nozomi documents, applied to `id` because the `assets` table has no time column to pivot on. A short page ends the walk.
- **Rate limiting.** `/api/open/` is throttled to 60 requests per minute per client IP and answers `429` with a `Retry-After` header. The shared HTTP helper does not retry unless given a budget, so the script opts in explicitly with three retries and a two-second backoff; `Retry-After` is honored.
- **Error envelope.** A rejected N2OS query still answers HTTP 200 with the reason in the `error` field of the response body, so the body is inspected rather than only the status code.
- **CVE handling.** `asset_cves` is queried once for the whole run and indexed by `asset_id`, not once per asset. Rows with `resolved` set are skipped so remediated findings are not reported as live. `is_kev` sets `exploitable`. `score` drives `severityScore`, `riskScore`, and the 0-4 ranks, but is **not** asserted as a CVSS 2 or CVSS 3 base score because `asset_cves` does not publish which CVSS version produced it; the raw value is kept as `nozomi_cve_score`. `matching_cpes` is assigned to `Vulnerability.cpe23` only when it actually begins with `cpe:`, and is otherwise kept as an attribute. `Software.cpe23` is never set, because it accepts only the CPE 2.2 `cpe:/a:` binding and Nozomi publishes no CPE on the `assets` table at all.
- **Unverified assumptions.** Nozomi renders the sign-in request and response as screenshots in its documentation, so neither the `{"key_name", "key_token"}` body shape nor the presence of a `Bearer ` prefix on the returned header is confirmed by primary documentation — both come from the vendor's XSOAR client and its test fixtures. The `assets` columns `id`, `zones`, and `_asset_kb_id` appear in real API responses but are absent from the published data-model page. There is no published list of valid `assets.type` or `assets.level` values, and `type` is user-extensible via CSV import, so both are treated as free-form strings. The `| where id > <id>` keyset filter used for the page-ceiling pivot is not documented; it is taken from the vendor's XSOAR client, where it is used the same way.
- **There is no `vulnerabilities` table.** Vulnerability data lives in `asset_cves` (asset-grained) and `node_cves` (node-grained). A query against `vulnerabilities` returns an `Unknown data source` error.
- This integration was validated against local fixtures derived from the captured API responses in the Nozomi XSOAR pack, not a live Nozomi tenant.

## Future

- **Alert ingestion.** The `alerts` table is the richest unexploited surface. A captured 126-alert response shows each alert carrying `ip_src`/`ip_dst`, `mac_src`/`mac_dst`, `port_src`/`port_dst`, `transport_protocol`, `protocol`, `risk`, `severity`, `status`, `ack`, `threat_name`, `zone_src`/`zone_dst`, and `is_incident`. Alerts are keyed to *nodes* rather than assets, but they can be correlated to assets without extra requests: the `assets.nodes[]` array holds exactly the node identifiers that appear in the alert `id_src` and `id_dst` fields. Alerts page with `sort record_created_at asc` plus `| where record_created_at > <last>`, which is the time pivot Nozomi documents.
- **Bidirectional alert workflow.** `POST /api/open/alerts/close` accepts `{"ids": [...], "close_action": "learn_rules" | "delete_rules"}` — closing as a change or as a security event respectively — with `GET /api/open/alerts/close/status/:id` to poll the result. `POST /api/open/alerts/ack` acknowledges or un-acknowledges alerts. An outbound integration could close or acknowledge a Nozomi alert once runZero confirms the underlying asset was remediated or retired.
- **Pushing runZero context into Nozomi.** This is supported, with real constraints. `POST /api/open/nodes/import_from_json` takes `{"nodes": [...]}` and matches rows **by IP only**; rows that match nothing create new nodes. It accepts exactly `ip`, `label`, `firmware_version`, `vendor`, `product_name`, `serial_number`, `os`, `mac_address`, `type`, plus custom fields — and the custom fields must already be defined in Nozomi's Custom fields configuration or they are silently discarded. Anything else in the payload is dropped. The caller needs the admin role. `POST /api/open/nodes/import` is the CSV form of the same operation. `PATCH /api/open/nodes/{id}` updates a single node's properties but is documented only under the Vantage tree, so it likely does not exist on on-premises Guardian or CMC. All of these write to *nodes*, not assets, and there is no documented delete or deprovision path.
- **Real services and ports.** The `links` and `sessions` tables carry observed communication rather than device inventory, and `node_cpes` carries per-node CPE data. Any of the three could supply the address, port, and transport that `Service` requires, turning the protocol names this integration currently keeps as tags into real service records. Their column names were not verified, so nothing was built on them here.
- **`query/do` as a general enrichment surface.** Twenty-two tables are queryable through the same endpoint: `alerts`, `appliances`, `assertions`, `assets`, `asset_cves`, `captured_logs`, `captured_urls`, `function_codes`, `health_log`, `link_events`, `links`, `node_cpe_changes`, `node_cpes`, `node_cpes_values_cpe_translator`, `node_cves`, `node_points`, `nodes`, `report_files`, `sessions_history`, `sessions`, `variable_history`, and `variables`. `variables` and `node_points` in particular expose process-variable data that has no equivalent anywhere else in a runZero inventory.
- **OT coverage-gap reporting.** Every asset records the `capture_device` and `appliance_hosts` that observed it, and the `appliances` table enumerates the sensors themselves. Comparing runZero's own view of a subnet against the set of assets any Nozomi sensor has ever observed would identify OT segments with no passive monitoring coverage — the sensor-placement blind spots that a passive-only tool cannot detect on its own.

## API documentation

- Open API setup and authentication (sign-in, key pairs, Basic authentication): https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/open-api/r_n2os-sdk_open-api_setup.html
- Query endpoint, `page` and `count` pagination, and the time-pivot guidance: https://technicaldocs.nozominetworks.com/products/nozomi/topics/sdk/open-api/r_nozomi-sdk_open-api_query.html
- Open API throttling (60 requests/minute, 429 with `Retry-After`): https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/open-api/r_n2os-sdk_open-api_throttling.html
- N2OS query command reference (`sort`, `where`, `head`, `select`): https://technicaldocs.nozominetworks.com/products/n2os/topics/queries/r_n2os_queries_commands.html
- `assets` data model: https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/data-model/r_n2os-sdk_data_model_assets.html
- `asset_cves` data model: https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/data-model/r_n2os-sdk_data_model_asset_cves.html
- `node_cves` data model: https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/data-model/r_n2os-sdk_data_model_node_cves.html
- Node import for pushing external context into Nozomi: https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/open-api/r_n2os-sdk_open-api_import-json.html
- Data integration best practices (Basic authentication examples): https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/data-integ-bp/r_n2os-sdk_dibp_openapi.html
- Vendor XSOAR client used as the reference implementation for the sign-in body shape, the header-borne token, and the asset field descriptions: https://github.com/demisto/content/tree/master/Packs/NozomiNetworks/Integrations/NozomiNetworks

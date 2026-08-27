# Custom Integration: Forescout eyeInspect

Forescout eyeInspect (formerly SilentDefense) is the passive OT/ICS deep-packet-inspection
product. Sensors watch industrial network traffic and report to an eyeInspect Command Center,
which exposes the `/api/v1/` REST API this integration reads.

> **Not the same product as `forescout-counteract`.** CounterACT (marketed as eyeSight) is
> Forescout's IT+OT network access control and device-classification product: an Enterprise
> Manager, an `/api/` Web API secured with a short-lived JWT, and an inventory of every endpoint
> on the corporate network, classified by its profiling engine. eyeInspect is the OT monitoring
> product: separate sensors, a separate Command Center, HTTP Basic authentication, and an
> inventory of industrial hosts with Purdue levels, firmware detail, and protocol alerts. A
> customer who owns both should run both integrations; they cover different estates and neither
> is a superset of the other.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the eyeInspect Command Center, which normally lives inside the OT/DMZ network.

## Forescout eyeInspect requirements

- An eyeInspect Command Center (formerly SilentDefense) reachable over HTTPS.
- A Command Center user account with API read access to the `hosts`, `alerts`, and `cve_info` resources. The API uses HTTP Basic authentication with the Command Center username and password.

## Steps

### Forescout eyeInspect configuration

1. Create (or select) a Command Center user with read-only access to the host inventory and alerts. eyeInspect authenticates the REST API with the same credentials used for the Command Center UI.
2. Confirm API access from the Explorer host, for example `https://<command-center>/api/v1/hosts?limit=1`. The integration appends `/api/v1/` to the URL you configure.
3. If the Command Center uses a private certificate authority, either add the CA to the integration's TLS options or disable TLS validation on the credential.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Forescout eyeInspect").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **eyeInspect Command Center URL** (`url`): base URL of the Command Center, for example `https://eyeinspect.example.com`.
   - **Username** (`username`): Command Center user with read access to the hosts, alerts, and CVE APIs.
   - **Password** (`password`): password for that user.
   - **Lookback window (days)** (`last_seen_days`): optional; only import hosts last seen within this many days. `0` (the default) imports every host.
   - **Request full host records** (`full_host_details`): optional; default enabled. Sends `full=true` on the hosts request so the Command Center returns the Full-only host properties (`software`, `patches`, `open_ports`, `cves`, `main_role`, `purdue_level`, `criticality`, `main_vendor_model`, `firmware_version`, `security_risk`, `operational_risk`). Turn it off only if an older Command Center rejects the parameter.
   - **Import alerts as vulnerabilities** (`include_alerts`): optional; default enabled. Attaches eyeInspect alerts to their host as findings, at the cost of one request per host.
   - **Enrich CVEs from eyeInspect** (`include_cve_details`): optional; default disabled. Looks up CVE detail for every CVE referenced by a host or an alert.
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
runzero script --filename forescout-eyeinspect/forescout-eyeinspect.star \
  --kwargs url=https://eyeinspect.example.com \
  --kwargs username=runzero \
  --kwargs password=NotTheRealPassword1 \
  --kwargs last_seen_days=30 \
  --kwargs full_host_details=true \
  --kwargs include_alerts=true \
  --kwargs include_cve_details=false \
  --kwargs tls_disable_validation=true \
  --output ./eyeinspect-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID -- any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Set `last_seen_days` on a first run. A Command Center that has been watching an OT segment
for years holds a long tail of hosts that have not been seen in a very long time, and
bounding the window keeps a smoke test small. Leave `include_cve_details` off until the
host and alert import looks right -- it adds a lookup for every CVE referenced anywhere in
the response.

A Command Center normally presents a certificate from a private CA, so a command-line run
usually needs either `tls_disable_validation=true` or `tls_ca_cert=/path/to/ca.pem`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live Command Center:

```bash
runzero script --filename forescout-eyeinspect/forescout-eyeinspect.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove eyeInspect accepts the credential or that any host is parsed.

The recorded API shapes, including CVE enrichment and future timestamps, are exercised by
the fixture suite:

```bash
python3 tests/run.py forescout-eyeinspect
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat forescout-eyeinspect/forescout-eyeinspect.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://eyeinspect.example.com,username=runzero,password=<password>' \
  --output ./eyeinspect-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Forescout eyeInspect.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:forescout-eyeinspect`.

## Asset identity

- Target entity: a host in the eyeInspect Command Center inventory, which is a network endpoint the passive sensors have observed on the monitored OT network.
- Source ID field: `results[].id` from `GET /api/v1/hosts`.
- Documentation evidence: the eyeInspect API Guide's Host record definition lists `id | integer | Full-only: No | "The unique ID of the Host within the eyeInspect Command Center"` as the first property, present with or without `full=true`. `GET /hosts` documents an `id_min` filter -- "Retrieve hosts from a minimum ID value onward. Useful for check-pointing data" -- which only makes sense for a stable, monotonically assigned identifier, and states that a result list with no `sort_field` "will be sorted by ID only, ascending". The Cortex XSOAR `ForescoutEyeInspect` content pack, an implemented client against this API, agrees: its host command declares `outputs_key_field="id"`.
- Uniqueness scope: one Command Center database. The host record carries `ip_reuse_domain_id`, so the same IP address can legitimately exist as several host rows in different IP reuse domains; the `id` is what separates them. It is not globally unique across Command Centers.
- Cardinality: one source row per host record. Note the inverse case: because eyeInspect learns hosts passively, one physical device that is re-addressed can accumulate more than one host row over time. That produces multiple eyeInspect ids for one device rather than one id for several devices, and runZero's MAC/IP merging is what collapses them.
- Stability: the id is assigned when the Command Center first learns the host and is preserved across polls, renames, re-profiling, and sensor changes. Purging the host from the Command Center database and re-learning it produces a new id.
- Reuse behavior: not documented. The `id_min` filter and the ID-ascending default sort together imply ids are assigned in ascending order, which makes recycling unlikely, but Forescout does not publish a guarantee. Treated as non-recycling; this is the one identity property that could not be verified.
- Presence: `id` is present on every documented host output and on every sample response in the vendor pack. Records that arrive without one are skipped.
- Final runZero ID: `forescout-eyeinspect:<command-center-host>:<id>`, where the scope is the hostname parsed from the configured URL.
- Missing-ID behavior: skip the record with a log line naming only its IP. A host id of `0` is explicitly treated as valid, not as missing.
- Match behavior (set once in `CONFIG`): `no-name-break`. `main_name` is inferred from protocol traffic rather than from a name service, so it churns as the sensors observe more of a host and should not veto a merge.

  `mac-break` and `ip-break` are deliberately **kept on**. eyeInspect has two documented ways of reporting the same identifier for genuinely different devices: `ip_reuse_domain_id` means one IP address can legitimately belong to several distinct hosts in different reuse domains, and hosts reached through a router or serial gateway present the gateway's MAC rather than their own. Those two breaks are the only thing that separates such devices when a merge is attempted by MAC or IP -- the path taken before the host id has ever matched, typically on first contact with an already-scanned estate -- so relaxing them lets exactly the collisions this source is known to produce merge unrelated OT assets.

  Churn is not a reason to relax them: a foreign-ID match is never disqualified by a conflicting MAC, IP, or hostname, because those checks exist only on the MAC, IP, and hostname match paths. Once the host id matches, network churn cannot fragment the asset regardless of these flags.
- Verdict: scoped authoritative.

### Notes

- **Assets** come from `GET /api/v1/hosts`. Mapped fields: `id` (identity), `ip` plus `mac_addresses` and `host_mac_address` (network interfaces), `main_name` (hostname), `os_version` (`os`), `main_role` (`deviceType`), and `first_seen`/`last_seen` (`firstSeenTS`/`lastSeenTS`). `vlan`, `sensors_ids`, `nested_address`, `ip_reuse_domain_id`, and `description` become custom attributes prefixed `forescout_eyeinspect_`, along with the other host properties listed below.
- **The Host record vocabulary is not the `sort_field` vocabulary.** Sorting on `name`, `role`, and `vendor_model` returns properties actually named `main_name`, `main_role`, and `main_vendor_model`; the plain spellings are read as fallbacks but are not what a Command Center sends. Three names that look like host properties are *only* sort keys and are never present in a response, so they are not read: **`alert_count`, `ip_type`, and `monitored_networks`**. `mac_addresses` is a `string[]`, but `host_mac_address` is a `HostMacAddress[]` of `{mac_address, last_seen}` objects, so its elements are unwrapped before use -- handing the object itself to `network_interface` yields no interface at all. The guide's own Host table also carries three typos (`critically` for `criticality`, `sercurity_risk` for `security_risk`, `firmwareçversion`), so both spellings of the first two are read.
- **Services** come from the host `open_ports` field, using the host `ip` as the service address. The documented element is an `OpenPortsInfo` object of `{port, l4_protocol, app}` -- all three typed as strings -- where `app` is "The service/application running on the port. Example: HTTP". `app` becomes the service's protocol name (`http`, `modbus`, `snmp`) and is also kept verbatim as `forescout_eyeinspect_app`. Older Command Centers and the vendor's own diagnostics record hand back bare port strings instead, so ints, `"443"`, `"502/tcp"`, `"tcp/502"`, `"161 (UDP)"`, and `{"port": ..., "protocol": ...}` dicts are accepted as well. **Assumption:** an entry that names no transport is recorded as `tcp` and tagged `forescout_eyeinspect_transport_source=assumed`; entries whose transport was stated carry `reported`. Port ranges such as `"10-20"` are skipped rather than guessed.
- **Software** comes from three places, all capped at 99 rows per asset:
  - `software`, a `SoftwareInfo[]` of `{install_date, version, name, vendor}` -- a direct match for runZero's `Software`, with `name` mapping to `product` and `vendor`/`version` carried through. `software_source` (`UNKNOWN`, `PASSIVE`, `ACTIVE_DISCOVERY`, `ACTIVE_WMI`, `EDITED`) records how eyeInspect learned of the software; it is a detection source, not an install source, so it stays a custom attribute rather than becoming `installedFrom`.
  - `patches`, a `PatchesInfo[]` of `{hot_fix_id, installed_by, install_date, service_pack}`, one row each with the hotfix id (`KB4477137`) as the product.
  - A synthetic firmware row built from `main_vendor_model` and `firmware_version`, with `hardware_version`, `serial_number`, and `project` as attributes. It is synthetic because eyeInspect reports firmware as a host property, and an embedded device has no installed-application list at all.

  Every row carries `forescout_eyeinspect_software_kind` (`software`, `patch`, or `firmware`) so the three are distinguishable. `software` and `patches` are Full-only, so turning `full_host_details` off leaves the firmware row as the only software.
- **Vulnerabilities** come from two places. Every alert the Command Center associates with the host (`GET /api/v1/alerts?host_id=<id>`) becomes a finding, keeping the sensor's own severity (eyeInspect's 0-5 scale is mapped onto runZero's 0-4 ranks using the same mapping the vendor's XSOAR pack uses). The host's own `cves` -- a `HostCVEInfo[]` of `{id, cve_id, icsa_id, vendor_specific_id, suppressed, matching_confidence}` -- become the second kind, with the deprecated comma-joined `complex_cves` string read as a fallback. A `suppressed` entry is a match an operator has dismissed and is skipped; an ICS-CERT-only advisory carries an empty `cve_id` and is skipped too, because runZero's `cve` field is CVE-only. Alerts are correlated server-side by `host_id` -- the Command Center resolves that against both the IP and the MAC addresses of the host -- rather than by matching `src_ip`/`dst_ip` locally, which would be ambiguous when IP reuse domains are in play.
- A finding is bound to a port (`serviceAddress`/`servicePort`/`serviceTransport`) only when the alert names this host as the destination and carries a non-zero `dst_port` with a TCP/UDP `l4_proto`. Most alerts are not port-scoped and are left unbound.
- **Alerts carry no CVE field** in the documented output contract, so CVE identifiers are extracted by pattern from the alert's `event_type_ids`, `event_type_names`, `description`, and `notes`. When an alert references several CVEs, the first becomes the finding's `cve` and the full list is preserved in `forescout_eyeinspect_alert_cves`.
- **CVE enrichment** (`include_cve_details`, off by default) adds title, summary, solution, CVSS base and temporal scores, and publication date. `cvss_version` decides whether the score lands in the CVSS v2 or v3 fields. CVSS drives the severity rank only for host CVE findings -- an alert keeps the severity its sensor assigned.

  The CVE database is keyed on `CVEInfo.id`, which equals the CVE id only for an NVD-sourced record; a match published as a vendor advisory carries that repository's own id (the guide's example is `2PAA123981-2020-8471`). Lookups therefore use `HostCVEInfo.id`, recorded as `forescout_eyeinspect_cve_record_id`, and fall back to the CVE id when it is absent. Each page's host CVEs are pre-loaded in one `POST /api/v1/cve_info/list` ("Export multiple vulnerabilities at once", up to 1000 ids per call). Anything the bulk call cannot cover -- an alert's CVEs are not known until its alerts request has been made -- falls through to `GET /api/v1/cve_info/{id}`. Both paths share a run-scoped cache, so an advisory on a hundred hosts costs one lookup, and an id the Command Center does not hold is cached as a miss and not retried.

  The guide lists `X-CSRF-Token` among the bulk endpoint's required headers, grouped with the modifying services even though it only reads, and that nonce needs a cookie session the JSON helpers do not expose. A Command Center that enforces it rejects the POST; the integration logs one line, disables bulk for the rest of the run, and completes on the per-id `GET`. The cost of a CSRF-enforcing deployment is therefore exactly one failed request.
- **Value domains follow the guide, not intuition.** `purdue_level` is a **string enum** (`LEVEL0`, `LEVEL1`, `LEVEL2`, `LEVEL3`, `LEVEL35`, `LEVEL4`, `LEVEL5`, `UNDEFINED`), not a number. `criticality` is an **integer in [0-5]** derived from the host's role, not a severity word. `security_risk` and `operational_risk` are **floats**. The raw value always survives as a custom attribute, but only a value inside its documented domain becomes a tag: `purdue-level:LEVEL1` and `criticality:4` are emitted, `UNDEFINED` and anything out of range are not, alongside the constant `forescout-eyeinspect` and `ot` tags and `role:<main_role>`. `all_roles` and `all_vendors_models` -- the full sets behind the winning `main_role` and `main_vendor_model` -- are kept as custom attributes.
- **`full_host_details` (on by default) sends `full=true` on `GET hosts`.** The guide documents the parameter as "Whether to retrieve all the host properties or only the key properties. Default is false", and marks each Host property with a **Full-only** column. Everything this integration reads beyond the base record is Full-only: `software`, `patches`, `open_ports`, `cves`, `main_name`, `main_role`, `main_vendor_model`, `all_roles`, `all_vendors_models`, `os_version`, `purdue_level`, `criticality`, `firmware_version`, `hardware_version`, `serial_number`, `project`, `labels`, `first_seen`, `security_risk`, and `operational_risk`. Only `id`, `ip`, `nested_address`, `vlan`, `mac_addresses`, `host_mac_address`, `mac_vendors`, `ip_reuse_domain_id`, `sensors_ids`, and `last_seen` come back without it.

  Turn the parameter off if an older Command Center rejects it; the integration then imports the base fields only, and services, software, patches, and host-CVE findings will be empty.
- **Pagination walks by check-point, not by position.** The first request sends `offset=0`; every later one sends `id_min`, documented as "Retrieve hosts from a minimum ID value onward. Useful for check-pointing data". An offset walk silently skips a row every time the Command Center inserts a host behind the cursor, and a Command Center writes that table continuously. `sort_field` is deliberately not sent: `id` is not one of its accepted values, and with the parameter omitted the guide specifies the result is sorted by ID only, ascending -- exactly the order `id_min` needs. `id_min` reads as inclusive, so the check-point passed is the last id seen rather than one past it, which is correct whether the Command Center treats it as `>=` or `>`; the duplicate boundary row is dropped locally. `offset` remains the fallback for a page that carries no numeric id to advance from, and a page whose ids do not advance past the check-point stops the walk with a log line rather than looping. Each page is streamed as it is parsed, so the full inventory is never held in memory. The optional lookback window is passed as the endpoint's `last_seen` filter.
- **The page size of 100 is a default, not a maximum.** The guide documents `limit` as "Fetch only up to *limit* records. Default is 100" and states no ceiling; the 100 in the XSOAR pack is that client's own constant, not a vendor limit. It is kept anyway. The walk ends on a page shorter than the requested limit, which is only sound while the Command Center honors that limit -- a deployment that silently capped a larger request would end the walk on its first page and lose the rest of the inventory. 100 is the only value the guide guarantees is honored, so raising it would trade a real correctness property for a request-count saving.
- Request cost: one request per page of 100 hosts, plus -- when `include_alerts` is on -- **one alerts request per host, with no way to skip a quiet one.** There is no per-host alert-volume property to short-circuit on: `alert_count` is a sort key, not a Host record field, so it is never present in a response and any check keyed on it never fires. On a large Command Center the alerts fan-out dominates the run time, so turn `include_alerts` off for a fast inventory-only sync.
- Rate limiting is not documented for this API. The shared HTTP helper retries 408/425/429 and 5xx with exponential backoff and honors `Retry-After`, three additional attempts by default. Authentication failures (401/403) are reported and stop the run rather than being retried.
- Timestamps are validated before parsing and the eyeInspect epoch sentinel (`1970-01-01T01:00:00.000+01:00`, meaning "never seen") is treated as absent, as is the year-1 value that is Go's zero time. Neither is rejected by a `!= None` check -- `parse_ts` returns a real timestamp for both -- so the guard tests the unix value. Timestamps are preserved verbatim as `forescout_eyeinspect_first_seen` / `forescout_eyeinspect_last_seen` custom attributes whether or not they parse, since a future timestamp is clamped to now and the attribute is the only place the reported value survives.
- `GET /api/v1/links` is deliberately not imported. Links are host-to-host communication records, not assets, and importing them would create duplicate assets for endpoints already returned by `GET hosts`.
- This integration was validated against local fixtures, not a live Forescout eyeInspect tenant.

## Future

- **Outbound: push runZero discovery back into eyeInspect group policies.** `POST /api/v1/group_policy` and `PUT /api/v1/group_policy/{id}` create and update group policies, and `POST /api/v1/group_policy/{id}/add_hosts` assigns hosts matching a `{"type": ..., "value": ...}` filter to a policy (`remove_hosts` reverses it). An outbound integration could file the hosts behind a runZero query -- every asset runZero classifies as a PLC, say -- into a group policy so the sensors alert on deviations from a runZero-derived baseline. The constraint model (`os_version`, `firmware_version`, `open_ports` with `equals`/`contains`/`allowed`) means runZero's inventory could also seed a segment's allowed-ports baseline. The limitation: `add_hosts` selects by filter expression, not by host id, so the push is only as precise as the filter types eyeInspect exposes.
- **Alert ingestion as a runZero-side event feed.** `GET /api/v1/alerts` supports `start_timestamp`/`end_timestamp` plus `offset`/`limit` and returns monotonically increasing `alert_id` values -- exactly the shape an incremental event poller needs, rather than the per-host correlation this integration does. A dedicated feed could stream new OT alerts continuously and leave per-host correlation to scheduled inventory syncs. `GET /api/v1/alert_pcaps/{alert_id}` returns the packet capture behind an alert, letting an analyst pivot from a runZero finding straight to the traffic.
- **`cve_info` as a shared CVE enrichment service.** The endpoint returns title, summary, solution, CVSS v2/v3 scoring, the ICS-CERT advisory id (`icsa_id`), and the vendor-specific advisory id -- the ICS advisory linkage in particular is not something a generic CVE feed provides. Any runZero integration ingesting bare CVE ids from another scanner could enrich them through a Command Center the customer already owns, and `POST /api/v1/cve_info/list` batches 1000 ids per call. Two things would need solving first: the CSRF handshake the bulk endpoint documents, which needs a cookie session rather than the stateless JSON helpers; and a cache that persists between runs.
- **Alert-derived CVEs are not batched.** The bulk pre-load covers a page's host CVEs, which is where the N+1 actually hurts, but an alert's CVEs are only discovered after its per-host alerts request and so still cost a cached `GET` each. Collecting a page's alerts first and enriching in a second pass would fold them into the same bulk call, at the cost of holding a page of alerts in memory.
- **OT coverage-gap reporting.** Diffing runZero's inventory against `GET /api/v1/hosts` in both directions identifies assets runZero sees that no sensor has ever observed -- OT segments where sensor placement or SPAN configuration has a blind spot -- and, in reverse, eyeInspect hosts runZero's active scanning never reaches. Combining that with `GET /api/v1/sensors` (each sensor's `state`, `health_status`, throughput, dropped-packet counters) and `GET /api/v1/sensors/{id}/modules` would attribute each gap to a specific sensor rather than just counting. `GET /api/v1/host_change_logs` and `GET /api/v1/ip_reuse_domains` would distinguish a genuinely new host from a re-addressed one.
- **Sensor and threat-library management as an outbound policy surface.** Each sensor exposes an Industrial Threat Library through `GET`/`POST /api/v1/sensors/{id}/itl/.../blacklist` for IP, domain, SSL client JA3, and file operations, and runZero threat-intelligence or policy data could be pushed into those so eyeInspect alerts on runZero-identified indicators. `PUT /api/v1/sensors/{id}/modules/{module_id}` can also start, stop, or change a sensor module's operational mode. This is a destructive surface -- it changes detection behavior on production OT monitoring -- so it needs a much tighter confirmation model than a scheduled inbound sync.

## API documentation

- **The vendor contract for this integration is the Forescout eyeInspect API Guide**, which *is* publicly retrievable: <https://docs.forescout.com/eyeinspect/eyeinspect-rn-api-user-guide/Resources/PDFs/eyeinspect-api-guide.pdf> (74 pages, covering eyeInspect 5.5.0/5.9/5.11 and Edge Collector 24.1.1-25.2.1). Topic pages live under `https://docs.forescout.com/eyeinspect/eyeinspect-rn-api-user-guide/eyeinspect-api-guide/`, for example [`fetch-hosts.htm`](https://docs.forescout.com/eyeinspect/eyeinspect-rn-api-user-guide/eyeinspect-api-guide/fetch-hosts.htm) and [`fetch-alerts.htm`](https://docs.forescout.com/eyeinspect/eyeinspect-rn-api-user-guide/eyeinspect-api-guide/fetch-alerts.htm). Do not guess the slugs: the bundle names its own contents at `.../Data/HelpSystem.xml`.
  - "Fetch hosts" is the source for `full` ("Whether to retrieve all the host properties or only the key properties. Default is false"), `limit` ("Fetch only up to *limit* records. Default is 100" -- a default, with no maximum stated), `id_min` ("Retrieve hosts from a minimum ID value onward. Useful for check-pointing data"), the `sort_field` enum, and the `{"total_count": ..., "results": [...]}` envelope.
  - "Record Type Definitions" is the source for the Host record and its per-property **Full-only** column, and for `SoftwareInfo`, `PatchesInfo`, `OpenPortsInfo`, `HostCVEInfo`, `HostMacAddress`, and `CVEInfo`. `full=true` is therefore documented, not inferred.
  - "Export multiple vulnerabilities at once" documents `POST /cve_info/list`, its 1000-id limit, and its `X-CSRF-Token` requirement.
  - The PDF renders every lowercase `l` as a capital `I`, so `l4_protocol` reads as `I4_protocol` and `l7_proto` as `I7_proto` throughout. The Host record table also misspells three properties -- `critically`, `sercurity_risk`, and (in the AssetBaselineHostFilter table) `firmwareçversion` -- while the `sort_field` enum spells the first two correctly. Both spellings of the first two are read.
- The Cortex XSOAR `ForescoutEyeInspect` content pack is an implemented and tested client for this API and remains useful as a cross-check on recorded response shapes: <https://github.com/demisto/content/tree/master/Packs/ForescoutEyeInspect/Integrations/ForescoutEyeInspect>. Note that its `MAX_LIMIT = 100` is the pack's own constant, not a documented vendor ceiling, and that it does not send `full=true`, which is why none of its recorded `test_data` fixtures carry the Full-only properties.
- Brinqa's eyeInspect connector documentation corroborates `full=true` in production use: <https://docs.brinqa.com/docs/connectors/forescout-eyeinspect/>. It sends it as a default filter on both `GET /api/v1/hosts` and `GET /api/v1/alerts` and maps `criticality`, `purdue_level`, `open_ports`, `firmware_version`, `security_risk`, `operational_risk`, and `serial_number`. Its `main_role` / `main_vendor_model` naming matches the guide; the plain `role` / `vendor_model` spellings belong to the `sort_field` vocabulary.
- Product overview for eyeInspect (formerly SilentDefense): <https://www.forescout.com/products/eyeinspect/>

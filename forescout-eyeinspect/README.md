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
   - **Import alerts as vulnerabilities** (`include_alerts`): optional; default enabled. Attaches eyeInspect alerts to their host as findings.
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
  --kwargs include_alerts=true \
  --kwargs include_cve_details=false \
  --kwargs tls_disable_validation=true \
  --output ./eyeinspect-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Set `last_seen_days` on a first run. A Command Center that has been watching an OT segment
for years holds a long tail of hosts that have not been seen in a very long time, and
bounding the window keeps a smoke test small. Leave `include_cve_details` off until the
host and alert import looks right — it adds a lookup for every CVE referenced anywhere in
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
- Documentation evidence: the eyeInspect API reference is published behind Forescout's customer portal and is not publicly retrievable, so the contract used here is the Cortex XSOAR `ForescoutEyeInspect` content pack, which is an implemented client against this API. Its integration definition documents `ForescoutEyeInspect.Host.id` as "The unique ID of the host in the eyeInspect CC" (type Number), and the host command declares `outputs_key_field="id"`, meaning the vendor's own integration treats `id` as the primary key for a host record. The list endpoint also exposes an `id_min` filter ("Retrieve hosts from a minimum ID value onward"), which only makes sense for a stable, monotonically assigned identifier.
- Uniqueness scope: one Command Center database. The host record carries `ip_reuse_domain_id`, so the same IP address can legitimately exist as several host rows in different IP reuse domains; the `id` is what separates them. It is not globally unique across Command Centers.
- Cardinality: one source row per host record. Note the inverse case: because eyeInspect learns hosts passively, one physical device that is re-addressed can accumulate more than one host row over time. That produces multiple eyeInspect ids for one device rather than one id for several devices, and runZero's MAC/IP merging is what collapses them.
- Stability: the id is assigned when the Command Center first learns the host and is preserved across polls, renames, re-profiling, and sensor changes. Purging the host from the Command Center database and re-learning it produces a new id.
- Reuse behavior: not documented. The `id_min` pagination filter implies ids are assigned in ascending order, which makes recycling unlikely, but Forescout does not publish a guarantee. Treated as non-recycling; this is the one identity property that could not be verified.
- Presence: `id` is present on every documented host output and on every sample response in the vendor pack. Records that arrive without one are skipped.
- Final runZero ID: `forescout-eyeinspect:<command-center-host>:<id>`, where the scope is the hostname parsed from the configured URL.
- Missing-ID behavior: skip the record with a log line naming only its IP. A host id of `0` is explicitly treated as valid, not as missing.
- Match behavior (set once in `CONFIG`): `no-name-break`. `main_name` is inferred from protocol traffic rather than from a name service, so it churns as the sensors observe more of a host and should not veto a merge.

  `mac-break` and `ip-break` are deliberately **kept on**, which is a change from this integration's first release. eyeInspect has two documented ways of reporting the same identifier for genuinely different devices: `ip_reuse_domain_id` means one IP address can legitimately belong to several distinct hosts in different reuse domains, and hosts reached through a router or serial gateway present the gateway's MAC rather than their own. Those two breaks are the only thing that separates such devices when a merge is attempted by MAC or IP — which is the path taken before the host id has ever matched, typically on first contact with an already-scanned estate. Relaxing them let exactly the collisions this source is known to produce merge unrelated OT assets.

  Note that the churn argument does not require relaxing them: a foreign-ID match is never disqualified by a conflicting MAC, IP, or hostname, because those checks exist only on the MAC, IP, and hostname match paths. Once the host id matches, network churn cannot fragment the asset regardless of these flags.
- Verdict: scoped authoritative.

### Notes

- **Assets** come from `GET /api/v1/hosts`. Mapped fields: `id` (identity), `ip` and `mac_addresses`/`host_mac_addresses` (network interfaces), `main_name` (hostname), `os_version` (`os`), `role` (`deviceType`), and `first_seen`/`last_seen` (`firstSeenTS`/`lastSeenTS`). `vlan`, `sensor_ids`, `nested_address`, `ip_reuse_domain_id`, and `description` become custom attributes prefixed `forescout_eyeinspect_`, along with the other host properties listed below.
- **Services** come from the host `open_ports` field, using the host `ip` as the service address. The API contract types this field as a string and describes it as "The open TCP and UDP ports of the host", but Forescout does not publish its element shape, and the only concrete sample of an `open_ports` field anywhere in the vendor pack is the Command Center's own diagnostics record, where it is a list of bare port strings (`["443"]`). The parser therefore accepts ints, `"443"`, `"502/tcp"`, `"tcp/502"`, `"161 (UDP)"`, and `{"port": ..., "protocol": ...}` dicts. **Assumption:** an entry that names no transport is recorded as `tcp` and tagged `forescout_eyeinspect_transport_source=assumed`; entries whose transport was stated carry `reported`. Port ranges such as `"10-20"` are skipped rather than guessed.
- **Vulnerabilities** come from two places. Every alert the Command Center associates with the host (`GET /api/v1/alerts?host_id=<id>`) becomes a finding, keeping the sensor's own severity (eyeInspect's 0-5 scale is mapped onto runZero's 0-4 ranks using the same mapping the vendor's XSOAR pack uses). Any CVE listed in the host's `complex_cves` field becomes a second kind of finding. Alerts are correlated server-side by `host_id` — the Command Center resolves that against both the IP and the MAC addresses of the host — rather than by matching `src_ip`/`dst_ip` locally, which would be ambiguous when IP reuse domains are in play.
- A finding is bound to a port (`serviceAddress`/`servicePort`/`serviceTransport`) only when the alert names this host as the destination and carries a non-zero `dst_port` with a TCP/UDP `l4_proto`. Most alerts are not port-scoped and are left unbound.
- **Alerts carry no CVE field** in the documented output contract, so CVE identifiers are extracted by pattern from the alert's `event_type_ids`, `event_type_names`, `description`, and `notes`. When an alert references several CVEs, the first becomes the finding's `cve` and the full list is preserved in `forescout_eyeinspect_alert_cves`.
- **CVE enrichment** (`include_cve_details`, off by default) adds title, summary, solution, CVSS base and temporal scores, and publication date from `GET /api/v1/cve_info/{cve_id}`. `cvss_version` decides whether the score lands in the CVSS v2 or v3 fields. Lookups are cached for the whole run, so a CVE that appears on a hundred hosts costs one request; a CVE the Command Center does not know (404) is cached as a miss and not retried. CVSS drives the severity rank only for host CVE findings — an alert keeps the severity its sensor assigned.
- **Software** is emitted only when the host record actually carries `vendor_model` or `firmware_version`, mapped to a single firmware record with `hardware_version`, `serial_number`, and `project` as attributes. Those fields are documented as host properties (they appear in the `sort_field` enum for `GET hosts`) but are not part of the published host output contract, so nothing is fabricated when they are absent — which is the case for every sample response in the vendor pack.
- The same caveat applies to `role`, `purdue_level`, `criticality`, `labels`, `ip_type`, `monitored_networks`, `alert_count`, `security_risk`, `operational_risk`, and `complex_cves`: each is a documented sortable host property whose response key name and shape are unconfirmed. All are read defensively and simply omitted when missing. `role`, `purdue_level`, and `criticality` also become tags when present, alongside the constant `forescout-eyeinspect` and `ot` tags.
- Pagination is `offset`/`limit` with a documented maximum page size of 100 for every list endpoint, sorted by `id` ascending; paging stops on a short or empty page. Each page of hosts is streamed with `report_asset` so the full inventory is never held in memory. The optional lookback window is passed as the endpoint's `last_seen` filter.
- Request cost: one request per page of 100 hosts, plus — when `include_alerts` is on — one alerts request per host, skipped for hosts whose `alert_count` is reported as zero. On a large Command Center this dominates the run time, so turn `include_alerts` off for a fast inventory-only sync.
- Rate limiting is not documented for this API. The shared HTTP helper retries 408/425/429 and 5xx with exponential backoff and honors `Retry-After`, three additional attempts by default. Authentication failures (401/403) are reported and stop the run rather than being retried.
- Timestamps are validated before parsing and the eyeInspect epoch sentinel (`1970-01-01T01:00:00.000+01:00`, meaning "never seen") is treated as absent. Values that do not parse are preserved verbatim as `forescout_eyeinspect_first_seen` / `forescout_eyeinspect_last_seen` custom attributes.
- `GET /api/v1/links` is deliberately not imported. Links are host-to-host communication records, not assets, and importing them would create duplicate assets for endpoints already returned by `GET hosts`.
- This integration was validated against local fixtures, not a live Forescout eyeInspect tenant.

## Future

- **Outbound: push runZero discovery back into eyeInspect group policies.** `POST /api/v1/group_policy` and `PUT /api/v1/group_policy/{id}` create and update group policies, and `POST /api/v1/group_policy/{id}/add_hosts` assigns hosts matching a `{"type": ..., "value": ...}` filter to a policy (`POST /api/v1/group_policy/{id}/remove_hosts` reverses it). An outbound integration could take a runZero query — say, every OT asset runZero classifies as a PLC, or every asset missing an expected patch level — and file those hosts into an eyeInspect group policy so the sensors alert on deviations from the runZero-derived baseline. The constraint model (`os_version`, `firmware_version`, `open_ports` with `equals`/`contains`/`allowed` operators) means runZero's inventory could also seed the allowed-ports baseline for a segment instead of an operator typing it by hand. Note the limitation: `add_hosts` selects hosts by filter expression, not by a list of host ids, so the push is only as precise as the filter types eyeInspect exposes.
- **Alert ingestion as a runZero-side event feed.** `GET /api/v1/alerts` supports `start_timestamp`/`end_timestamp` plus `offset`/`limit` and returns monotonically increasing `alert_id` values, which is exactly the shape needed for an incremental event poller rather than the per-host correlation this integration does. A dedicated feed integration could stream new OT alerts continuously and reserve the per-host correlation for scheduled inventory syncs. `GET /api/v1/alert_pcaps/{alert_id}` returns the packet capture behind an alert, which would let an analyst pivot from a runZero finding straight to the traffic.
- **`cve_info/{cve_id}` as a shared CVE enrichment service.** The endpoint is a plain CVE lookup returning title, summary, solution, CVSS v2/v3 scoring, the ICS-CERT advisory id (`icsa_id`), and the vendor-specific advisory id — the ICS advisory linkage in particular is not something a generic CVE feed provides. Any runZero integration that ingests bare CVE ids from another scanner could enrich them through an eyeInspect Command Center the customer already owns. It is a per-CVE GET with no batch form, so such a service would need the same run-scoped cache used here, ideally with persistence between runs.
- **OT coverage-gap reporting.** Diffing runZero's own inventory against `GET /api/v1/hosts` in both directions identifies assets runZero sees that no eyeInspect sensor has ever observed — OT segments where sensor placement or SPAN configuration has a blind spot — and, in reverse, eyeInspect hosts that runZero's active scanning never reaches. Combining that with `GET /api/v1/sensors` (which reports each sensor's `state`, `health_status`, throughput, and dropped-packet counters) and `GET /api/v1/sensors/{id}/modules` would attribute each gap to a specific sensor rather than just reporting a count. `GET /api/v1/host_change_logs` and `GET /api/v1/ip_reuse_domains` would let the same report distinguish a genuinely new host from one that was re-addressed.
- **Sensor and threat-library management as an outbound policy surface.** Each sensor exposes an Industrial Threat Library through `GET`/`POST /api/v1/sensors/{id}/itl/itl_sec_udb_bip/blacklist` (IP), `.../itl_sec_udb_dns_bd/blacklist` (domain), `.../itl_sec_udb_ssl_bja3/blacklist` (SSL client JA3), and `.../itl_sec_udb_bfo/blacklist` (file operations). runZero threat-intelligence or policy data could be pushed into those blacklists so eyeInspect alerts on runZero-identified indicators. `PUT /api/v1/sensors/{id}/modules/{module_id}` can also start, stop, or change the operational mode of a sensor module. This is a genuinely destructive surface — it changes detection behavior on production OT monitoring — so it would need a much tighter confirmation model than a scheduled inbound sync.

## API documentation

- The Forescout eyeInspect REST API reference (`/api/v1/`) is distributed through the Forescout customer portal at <https://docs.forescout.com/> and is not publicly retrievable, so it could not be read directly.
- The contract used for this integration is the Cortex XSOAR `ForescoutEyeInspect` content pack, which is an implemented and tested client for this API: <https://github.com/demisto/content/tree/master/Packs/ForescoutEyeInspect/Integrations/ForescoutEyeInspect>
  - Authentication and base URL (`urljoin(base_url, "/api/v1/")` with HTTP Basic auth), pagination (`offset`/`limit`, `MAX_LIMIT = 100`), and the `{"total_count": ..., "results": [...]}` response envelope: `ForescoutEyeInspect.py`.
  - Host, alert, sensor, and CVE object schemas, including the `sort_field` enum that enumerates the sortable host properties: `ForescoutEyeInspect.yml` and the pack `README.md`.
  - Sample host, alert, and CVE responses: the pack's `test_data/` fixtures.
- Product overview for eyeInspect (formerly SilentDefense): <https://www.forescout.com/products/eyeinspect/>

# Custom Integration: Cisco Secure Endpoint

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cisco Secure Endpoint requirements

- A Secure Endpoint API credential, which issues a **3rd Party API Client ID** and an **API Key**. `Read-only` scope is sufficient; this integration never writes.
- The API key is displayed once, at creation time, and cannot be retrieved afterwards. Record it before closing the dialog.
- The credential is scoped to one business in one regional cloud. Importing several businesses means one runZero credential and one task per business.
- Only a user with administrative access to the Secure Endpoint console can create API credentials.

## Steps

### Cisco Secure Endpoint configuration

1. Sign in to the Secure Endpoint console for your region.
2. Go to **Accounts** > **API Credentials**, then click **New API Credential**.
3. Give the credential an application name, select the **Read-only** scope, and click **Create**.
4. Copy the **3rd Party API Client ID** and the **API Key** from the confirmation page. The key is not shown again.
5. Note which console you signed in to, so you can pick the matching API host below:

   | Region | API host |
   | --- | --- |
   | North America | `https://api.amp.cisco.com` |
   | Europe | `https://api.eu.amp.cisco.com` |
   | Asia Pacific, Japan, and China | `https://api.apjc.amp.cisco.com` |
   | Consumer | `https://api.consumer.amp.cisco.com` |

   Canada is served by the North America host and Australia by the APJC host; there are no separate hosts for them. The Consumer host is declared in Cisco's own v1 OpenAPI document but is not otherwise documented, and it does not exist in the v3 API — leave it alone unless Cisco told you to use it.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Cisco Secure Endpoint").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Secure Endpoint API host** (`api_host`): the regional API endpoint that matches your console.
   - **3rd Party API Client ID** (`client_id`): the Client ID from Accounts > API Credentials.
   - **API key** (`api_key`): the API key issued alongside the Client ID.
   - **Import vulnerable application findings** (`import_vulnerabilities`): optional; attach the CVEs Secure Endpoint observed on each computer. Costs one extra request per computer (default: false).
   - **Vulnerability enrichment limit** (`vulnerability_limit`): optional; maximum number of computers to enrich. Computers past the limit are still imported, without vulnerabilities. 0 removes the cap (default: 1000).
   - **Only import active connectors** (`active_only`): optional; skip computers the console reports as inactive (default: false).
   - **Include demo computers** (`include_demo`): optional; import the fabricated sample computers Cisco seeds into evaluation businesses (default: false).
   - **Page size** (`page_size`): optional; records requested per page, capped at 500 by the API (default: 500).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a credential and see what a real business returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename cisco-secure-endpoint/cisco-secure-endpoint.star \
  --kwargs api_host=https://api.eu.amp.cisco.com \
  --kwargs client_id=a1b2c3d4e5f60718 \
  --kwargs api_key=9f8e7d6c-5b4a-3928-1706-abcdef012345 \
  --kwargs active_only=true \
  --kwargs page_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cisco-secure-endpoint-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**Watch the request budget when testing.** Cisco documents that API clients are
allowed a limited number of requests per hour but does not publish the number;
the authoritative value for your credential is the `X-RateLimit-Limit` and
`X-RateLimit-Remaining` headers on any response, which `--verbose` shows. The
computer listing is cheap, but `import_vulnerabilities=true` costs **one extra
request per computer**, so a careless command-line run against a large business
can consume the whole hourly budget and then leave the scheduled task
rate-limited behind an HTTP 429. Test with `vulnerability_limit` set low:

```bash
runzero script --filename cisco-secure-endpoint/cisco-secure-endpoint.star \
  --kwargs api_host=https://api.eu.amp.cisco.com \
  --kwargs client_id=a1b2c3d4e5f60718 \
  --kwargs api_key=9f8e7d6c-5b4a-3928-1706-abcdef012345 \
  --kwargs import_vulnerabilities=true \
  --kwargs vulnerability_limit=10 \
  --kwargs page_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cisco-secure-endpoint-vulns --overwrite
```

If an evaluation business returns computers you do not recognize, they are
probably Cisco's seeded demo hosts; add `--kwargs include_demo=true` to confirm
by seeing the count change.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename cisco-secure-endpoint/cisco-secure-endpoint.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Cisco accepts the client ID
and key, or that any computer is parsed.

The fixtures under `cisco-secure-endpoint/tests/fixtures/` exercise the parsing
offline, including the paging, detail-cap, and golden-image cases:

```bash
python3 tests/run.py cisco-secure-endpoint
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat cisco-secure-endpoint/cisco-secure-endpoint.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_host=https://api.eu.amp.cisco.com,client_id=a1b2c3d4e5f60718,api_key=<key>' \
  --output ./cisco-secure-endpoint-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way; prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Cisco Secure Endpoint.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:cisco-secure-endpoint`.

## Asset identity

- Target entity: one **installation of the Secure Endpoint connector** on a computer — not the computer itself. That distinction is the whole story here; see below.
- Source ID field: `connector_guid`
- Documentation evidence: Cisco's v1 OpenAPI document for the Computers resource (`computer_oas.yaml`) types `connector_guid` as a UUID and uses it as the resource key for every per-computer path — `GET /v1/computers/{connector_guid}`, `/trajectory`, `/vulnerabilities`, `/isolation`. It is the value the connector registers with and stores locally in `local.xml` at `/config/agent/uuid`.
- Uniqueness scope: the business the API credential belongs to, within one regional cloud. Values are UUIDs.
- Cardinality: one row per connector in `GET /v1/computers`. `GET /v1/computers/{connector_guid}/vulnerabilities` returns many vulnerable-application rows for one connector, all under the same GUID, which is what the enrichment pass groups on.
- Stability: **weaker than it looks, in both directions.** Cisco's own deployment guidance states that a full uninstall followed by a reinstall registers a *new* GUID, while a partial uninstall that preserves configuration re-registers with the same one. The Windows uninstaller asks whether you intend to reinstall precisely to decide whether to keep the UUID in the registry. Separately, a golden image captured with a populated `local.xml` gives *every* cloned endpoint the *same* GUID (Cisco Doc ID 214462; the documented prevention is the `/goldenimage` install flag).
- Reuse behavior: deliberately reusable when **Identity Persistence** is enabled (Cisco Doc ID 217557), which re-binds an existing GUID to a re-imaged machine by matching MAC address or hostname, scoped per policy or per business. The feature is not exposed in the console by default and requires a TAC case, so most tenants have it off. Orphaned GUIDs are otherwise retired by the **Inactive Computer Threshold** (Administration > Organization Settings, default 90 days, with deletion lagging up to a further 7 days), so stale duplicates persist for roughly a quarter.
- Presence: always returned by `GET /v1/computers`. Any record arriving without it is skipped.
- Final runZero ID: `cisco-secure-endpoint:<api-hostname>:<connector_guid>` — for example `cisco-secure-endpoint:api.eu.amp.cisco.com:d6838e26-2efe-48f1-a771-c7dcbacc77ec`.
- Missing-ID behavior: skip the record and log only its hostname; no identifier is ever synthesized.
- Match behavior (set once in `CONFIG`): `no-id-break no-ip-break`
- Verdict: scoped authoritative for a connector installation; **derived** for the underlying machine.

The namespace is the configured regional API hostname rather than a business or organization identifier, because **the v1 API exposes no business identifier at all** — there is no `/v1/organizations` resource, and `/v1/version` and `/v1/license_summaries` return neither a business GUID nor a business name. The hostname is the only scope token that is known from configuration before any record is parsed, so it can never go missing mid-import. Since `connector_guid` is a UUID, a collision between two businesses in the same region is implausible; the hostname exists to separate the regional clouds, which are genuinely separate systems.

`matchBehavior` deviates from the usual "authoritative foreign ID" recipe because the evidence above says the ID is not authoritative for a machine:

- **`no-id-break`** — set so that a differing `connector_guid` does not disqualify a merge. Be aware of what it does **not** buy: it disables `MatchBreakByForeignID` only, and a separate unconditional gate still applies. `ForeignIDSetsHaveMergeConflict`, reached from `Asset.CanMergeWithDevice`, refuses any merge that would place two different foreign IDs from the same custom integration on one asset, and it never consults `matchBehavior` because `SourceAllowsConflictingForeignIDs` returns false for custom integrations. So the documented reinstall path (uninstall, reinstall, new GUID, same hardware and hostname) still forks the machine into a second runZero asset, and the old one lingers for the 90-day inactivity window. An earlier revision of this document claimed this flag prevented that; it does not. The flag remains correct for the case it does cover — a candidate found by MAC or hostname that carries an unrelated source's foreign id — but the reinstall duplicate has to be reconciled in runZero.
- **`mac-break` and `name-break` are deliberately left ON.** They are what stops the opposite failure — a golden image that hands one GUID to a hundred clones — from collapsing the fleet onto a single asset. Turning them off, as the usual recipe would, converts a misconfigured image from a nuisance into an estate-merging incident.
- **`no-ip-break`** — these are roaming endpoints. `internal_ips` is a last-known DHCP address that changes with every network, and a stale address is not evidence of a different machine.
- `id-match` stays on, so a connector that keeps its GUID still merges on it directly.

`windows_processor_id` and `mac_hardware_id` are the two hardware-derived fields Secure Endpoint reports, and Cisco's own duplicate-finding script matches on MAC rather than either of them. Both are kept as custom attributes rather than folded into the asset ID: `windows_processor_id` is Windows-only and is sometimes reported as `0000000000000000`, and `mac_hardware_id` only appears on macOS, so neither is present across the fleet.

### Notes

- Assets come from `GET /v1/computers`. Imported fields are `hostname`, `operating_system` and `os_version` (split into os/osVersion), `install_date` as first-seen, `last_seen` as last-seen, and network interfaces built from `network_addresses[]`. Everything else — `connector_version`, `policy`, `groups`, `group_guid`, `isolation`, `orbital`, `demo`, `active`, `is_compromised`, `faults`, `csc_id`, `risk_score`, `av_update_definitions`, `host_firewall`, `windows_processor_id`, `mac_hardware_id`, and the raw address lists — is preserved as `cisco_secure_endpoint_*` custom attributes. Tags carry `policy:`, `group:`, and, when relevant, `isolation:`, `demo`, and `compromised`.
- **This integration targets API v1, not v3.** `GET /v1/computers` is not deprecated, allows 500 records per page, and — decisively — is the only one of the two that returns MAC addresses. The v3 Devices object (`GET /v3/organizations/{organizationIdentifier}/devices`) has no MAC field at all; it carries `guid`, `name`, `osType`, `osVersion`, `publicIp`, `localIps[]`, and `lastActive`, and caps `size` at 100. Importing MAC-less devices whose only address is a NAT egress IP would be a much weaker asset record. v3 also authenticates differently: OAuth2 client-credentials against `https://visibility.{region}.amp.cisco.com/iroh/oauth2/token`, then an exchange at `POST /v3/access_tokens` for a 10-minute Secure Endpoint token, with API clients created in Cisco XDR or Secure Client Cloud Management rather than the Secure Endpoint console.
- **The vulnerability endpoints this integration uses are deprecated.** Cisco marked `GET /v1/vulnerabilities`, `GET /v1/vulnerabilities/{sha256}/computers`, `GET /v1/computers/{guid}/vulnerabilities`, and `GET /v1/computers/{guid}/os_vulnerabilities` as `deprecated` in May 2025, when the v3 Devices API shipped. No sunset date has been announced and they still respond, but the feature is opt-in and off by default partly for this reason. If Cisco does retire them, computer import is unaffected — only the `import_vulnerabilities` pass stops producing findings.
- Vulnerabilities come from `GET /v1/computers/{connector_guid}/vulnerabilities`, which returns `data.connector_guid` alongside `data.vulnerabilities[]` and therefore ties every finding to exactly one computer with no guesswork. The alternative, `GET /v1/vulnerabilities`, is application-centric and its embedded `computers[]` array is capped — Cisco's spec says it returns information about the last 1000 connectors — so it cannot enumerate affected computers without a further call per SHA-256. The per-computer endpoint was chosen for that reason, at the cost of one request per computer.
- Each CVE becomes one `Vulnerability` keyed on `<connector_guid>:<CVE>:<sha256>`, so the same CVE reported for two different vulnerable files stays two findings. CVE identifiers are upper-cased and screened against `^CVE-[0-9]{4}-[0-9]{4,19}$` before assignment, because the platform rejects the whole record on a malformed value and the API has been observed emitting lower-case ids.
- The `cves[].cvss` number is stored as `severityScore`/`riskScore` with a 0-4 rank, and **not** as `cvss2BaseScore` or `cvss3BaseScore`. Cisco documents the field only as "the most recent CVSS score" with no version attached, and the data is genuinely mixed: the spec's own examples are CVSS v2 scores while community samples include v3.1 scores. Guessing a version would put wrong data in a typed field.
- **No installed-software inventory and no ports or services are imported, because the API does not expose them.** The v1 Computer schema contains no package list and no listening-port data. The vulnerability endpoint reports an `application` name and `version`, but only for applications Cisco tracks CVEs for, so it is a vulnerable-application list rather than an inventory — presenting three vulnerable apps as a machine's software would be actively misleading, and no `Software` objects are emitted. A real software inventory requires Cisco Orbital, a separate product with its own API.
- `external_ip` is deliberately **not** attached to a network interface. It is the NAT egress address shared by every connector behind one gateway, and adding it as an interface address would invite unrelated endpoints to merge together. It is kept as the `cisco_secure_endpoint_external_ip` custom attribute instead.
- Loopback, unspecified, and link-local addresses (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`) are filtered out of `network_addresses[]` and `internal_ips[]` before any interface is built, and the raw lists are kept as custom attributes. An adapter whose only address is loopback still contributes its MAC; an adapter with neither a usable MAC nor a usable address contributes nothing.
- `network_addresses[].ip` is frequently an empty string in real responses, and MAC case is inconsistent within a single response. Both are handled by the shared `network_interface()` helper. Real captures also contain `internal_ips` entries with a leading space, which are trimmed.
- Pagination is `limit`/`offset`. The API documents `limit` with a maximum of 500 and a default of 500, and reports `metadata.results.total` and `current_item_count`. Each page is streamed to runZero before the next is requested, so the full inventory is never held in memory.
- Secure Endpoint allows **3000 requests per hour** per business and reports the budget in the `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`, and `x-ratelimit-resetdate` response headers, returning HTTP 429 once it is spent. Transient failures including 429 are retried by the shared HTTP helper with exponential backoff starting at two seconds. A full computer sync costs roughly one request per 500 endpoints and is nowhere near the limit; the vulnerability pass costs one request per computer, which is why it is off by default and capped at 1000 computers. A 20,000-endpoint fleet would exhaust the hourly budget several times over with the cap removed.
- Cisco does **not** document a `Retry-After` header on 429 — the documented mechanism is `x-ratelimit-reset`, in seconds. The retry helper honors `Retry-After` when present and falls back to exponential backoff when it is not, which is the case that applies here.
- A failed vulnerability request for one computer is logged and skipped rather than aborting the run, so a single connector with no vulnerability history does not cost the whole import.
- The `demo` computers Cisco seeds into evaluation businesses are excluded by default. They are fabricated hosts, and importing them creates phantom assets in runZero. Set `include_demo` to import them anyway.
- Timestamps are shape-checked with a regular expression before parsing, because an unparseable value aborts the script and Starlark cannot catch it. Both offset forms the API emits are accepted — `install_date` and `last_seen` use `Z`, while the vulnerability feed's `latest_date` uses `+00:00`. A value with no offset at all, or a `0001-01-01` sentinel, is left unset rather than risking the run.
- Unverified assumption: `orbital.status` and `isolation.status` have no `enum` in Cisco's spec. Only `enabled`/`not_enabled` and `not_isolated`/`isolated`/`pending_start`/`pending_stop` have been observed. The status is stored verbatim and only compared against `not_isolated` when deciding whether to tag, so an unknown value tags rather than being silently dropped.
- Unverified assumption: whether the API clamps `limit` above 500 or rejects it. The script caps the configured page size at 500 itself, so this is never exercised.
- Unverified assumption: `operating_system` has no documented format and varies by connector generation — `Windows 10`, `Windows 10, SP 0.0`, `Windows 10 (Build 19044.1466)`, `Windows Server 2019 Datacenter`, `OS X 10.14.6` are all real. Only the trailing `, SP x.y` and `(Build x.y)` suffixes are trimmed, plus a trailing copy of `os_version`; every other shape is passed through as reported, and the raw string is kept as an attribute.
- This integration was validated against local fixtures, not a live Cisco Secure Endpoint business.

## Future

- **Endpoint isolation as an outbound integration — and a warning about it.** `GET/PUT/DELETE /v1/computers/{connector_guid}/isolation` starts and stops network isolation, and `GET /v1/computers/{connector_guid}/isolation` reports availability and current state. runZero already resolves every asset to its `connector_guid`, so an outbound script could isolate a host that runZero has just found exposing something it should not. **This is disruptive and must not be driven by an unattended scheduled task.** Isolation cuts a machine off the network except for its connection to Cisco, which means a false positive takes a user offline, and recovery needs the unlock code the isolation request returns. It would need explicit per-device operator approval, a dry-run mode, an audit trail, and a documented un-isolate path before it belonged anywhere near a sync job. `DELETE /v1/computers/{connector_guid}` (connector removal) is worse and should stay out of scope entirely.
- **Orbital query as a lookup integration.** Cisco Orbital runs osquery on Secure Endpoint connectors, and each computer already reports its `orbital.status`. Orbital is the missing half of this import: it can answer the software-inventory and listening-port questions the Secure Endpoint API cannot, on demand, for a named `connector_guid`. That is a separate product with its own API and licence tier, but it is the natural way to turn a Secure Endpoint asset record into a full one.
- **Event and threat-stream ingestion.** `GET /v1/events` returns the business's event stream with `limit`/`offset` pagination, `start_date`, and an `event_type[]` filter, and `GET /v1/event_types` enumerates the type ids to filter on. Every event carries a `connector_guid` and an embedded `computer` object, so a scheduled integration carrying a high-water mark between runs could attach detections, quarantine failures, policy updates, and connector faults to the originating asset. `GET /v1/computers/{guid}/trajectory` gives the same picture per host. This is the highest-value addition after the plain import: it turns a static inventory into a record of what actually happened on each endpoint.
- **Migrating vulnerabilities to v3.** `GET /v3/organizations/{organizationIdentifier}/devices/{device_guid}/vulnerabilities` is the non-deprecated successor to the endpoint this integration uses, and it is materially better data: explicitly versioned scores (`cvssScores.v2`, `cvssScores["v3.1"]`, each with base and temporal), a `riskScore`, `fixes[{id, url}]` suitable for the `solution` field, and exploitability facets (`activeInternetBreach`, `easilyExploitable`, `malwareExploitable`) that map cleanly onto `exploitable` and `riskRank`. It was not used here because it would drag the whole integration onto the v3 OAuth2 flow and a different credential type, for a feature that is off by default — but if the v1 vulnerability endpoints are sunset, this is the migration path, most likely as a second, v3-only integration rather than a rewrite of this one.
- **EDR coverage-gap reporting.** The most useful thing runZero can do with this data is not enrichment but subtraction. Diffing the Secure Endpoint inventory against runZero's own discovery separates two populations that matter to different people: endpoints Secure Endpoint knows about that runZero has never seen on a network (remote, dormant, or decommissioned but still holding a licence seat — `active`, `last_seen`, and the Inactive Computer Threshold already describe this), and endpoints runZero discovers that carry no connector at all, which is the actual EDR coverage gap. `GET /v1/license_summaries` supplies `number_of_connectors_registered`, `number_of_connectors_seen_in_the_last_30_days`, and `licensed_seats_count`, so the same report can put a licence cost against the stale half.
- **Group and policy hygiene.** `GET /v1/groups` and `GET /v1/policies` expose the group tree and the policy objects behind the `policy.guid` and `group_guid` this integration already tags with. Resolving them would let runZero report on endpoints sitting in an audit-only or unprotected policy — a common and quiet misconfiguration — without any further per-computer requests.

## API documentation

- Secure Endpoint API overview, authentication, and rate limits: <https://developer.cisco.com/docs/secure-endpoint/overview/>
- v1 Computers reference (pagination, filters, and the computer object schema): <https://developer.cisco.com/docs/secure-endpoint/computers/>
- v1 Computers OpenAPI document, used to verify `limit`'s 500 maximum, the regional host list, and the full field set: <https://pubhub.devnetcloud.com/media/secure-endpoint-api/docs/legacy-apis/v1/computer_oas.yaml>
- v1 Vulnerabilities OpenAPI document, used to verify the per-computer response envelope, the 1000-connector cap on the list endpoint, the `cves[]` shape, and the deprecation flags: <https://pubhub.devnetcloud.com/media/secure-endpoint-api/docs/legacy-apis/v1/vulnerabilities_oas.yaml>
- v3 authentication flow and token exchange: <https://developer.cisco.com/docs/secure-endpoint/authentication/>
- v3 API changes and the May 2025 deprecation of the v1 vulnerability endpoints: <https://developer.cisco.com/docs/secure-endpoint/whats-new/>
- API credential creation, console navigation, and the rate-limit response headers: <https://ciscosecurity-amp-00-integration-workflows.readthedocs-hosted.com/en/latest/amp/intro.html>
- Connector uninstall and reinstall behavior, used for the GUID stability record: <https://ciscosecurity-amp-00-integration-workflows.readthedocs-hosted.com/en/latest/amp/deployment.html>
- Cisco's own duplicate-GUID diagnostic script, which matches on MAC rather than on any hardware id field: <https://github.com/CiscoSecurity/amp-04-find-duplicate-guids>
- Isolation status values: <https://github.com/CiscoSecurity/amp-03-isolation-status>

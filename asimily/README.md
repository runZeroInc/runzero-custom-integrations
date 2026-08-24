# Custom Integration: Asimily Insight

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Asimily Insight requirements

- An Asimily Insight portal URL in the form `https://<customer>-portal.asimily.com`.
- An Asimily Insight API user (username plus password/API key) with read access to the
  external API (`/api/extapi/...`). The integration only issues read requests.
- Network reachability from the selected runZero Explorer to the Asimily portal.

## Steps

### Asimily Insight configuration

**Asimily does not publish a self-service path for creating API credentials.** Its
own integration collection says to "contact your Asimily partner program
representative to get access to a test environment and API credentials", and its
support portal requires a customer login. So the honest instruction is:

1. **Ask Asimily for API credentials.** Raise it with your Asimily
   representative or through Asimily support. What you need is a username and a
   password/API key with **read** access to the external API (`/api/extapi/...`);
   this integration only issues reads. Asimily publishes no role names, so there
   is no least-privilege role to request by name — ask for read-only access to
   assets, applications, and device CVEs.
2. Record the username and password/API key. The API uses HTTP Basic authentication.
3. Note your portal URL. It follows the pattern
   `https://<customer>-portal.asimily.com`, and that is the `url` value.
4. Confirm the account can reach `https://<customer>-portal.asimily.com/api/extapi/assets`.

An earlier version of this document described a **Settings > Users > Add User**
path in the Asimily portal. No vendor source for that path could be found, so it
has been removed rather than left in place — if your portal does offer it, it
will be quicker than a support request, but do not expect it.

> **The mandatory `source` header.** Asimily requires a `source` HTTP header on
> every REST call, carrying an identifier for "the client or organization making
> the request", and set a mandatory enforcement date of **1 May 2026** after which
> a request without a compliant value "will be rejected by the Asimily API". The
> script sends it on every request, with a default value of `runzero` that is
> compliant as shipped — **there is normally nothing to configure here.** Override
> it with the **Source header** (`source`) parameter only if your Asimily
> representative assigns your organization a specific identifier. Any value you
> set must be **alphabetic characters only** (A-Z, a-z): Asimily forbids spaces,
> commas, dots, hyphens, underscores and digits, so the script checks the value
> and refuses to start rather than issuing a whole run of requests that would each
> be rejected.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Asimily").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Asimily portal URL** (`url`): base URL of the portal, e.g. `https://acme-portal.asimily.com`.
   - **API username** (`username`): the Asimily Insight API user.
   - **API key** (`api_key`): the password or API key for that user.
   - **Source header** (`source`): optional; the client identifier sent in Asimily's mandatory `source` header (default: `runzero`). Alphabetic characters only — see the note above.
   - **Import open CVEs** (`include_vulnerabilities`): optional; fetch unfixed device CVEs and attach them to assets (default: enabled).
   - **Import installed software** (`include_software`): optional; fetch installed applications (default: disabled — see Notes, this costs one request per device).
   - **Software device limit** (`software_device_limit`): optional; maximum devices to query for software (default: 100).
   - **Asset page size** (`page_size`): optional; devices per asset page (default: 200).
   - **Request timeout (seconds)** (`request_timeout`): optional; per-request timeout (default: 180).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Asimily Insight.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:asimily`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real portal returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename asimily/asimily.star \
  --kwargs url=https://acme-portal.asimily.com \
  --kwargs username=runzero-api \
  --kwargs api_key=8f14e45fceea167a5a36dedd4bea2543 \
  --kwargs page_size=25 \
  --kwargs include_vulnerabilities=false \
  --kwargs include_software=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/asimily-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Turning `include_vulnerabilities` and `include_software` off for a first run
matters more here than on most sources. The Asimily API is slow and rate
limited, the CVE pass is a second full walk of the inventory, and software is an
N+1 fetch keyed on MAC address. Get authentication and asset shape confirmed
first, then switch them on. `get_bool` accepts `true/false`, `1/0`, `yes/no`,
and `on/off`.

The example omits `source`, which is deliberate: the script applies the `runzero`
default itself, because this CLI path passes `--kwargs` straight to `main` without
applying the `CONFIG` defaults or running its validation. Add
`--kwargs source=acmehealth` to try an identifier Asimily has assigned you.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real portal:

```bash
runzero script --filename asimily/asimily.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real device
row, so it tells you nothing about field mapping.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://acme-portal.asimily.com,username=runzero-api,api_key=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py asimily
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: physical device on the customer network — predominantly medical (IoMT),
  laboratory, and OT equipment, plus the IT endpoints Asimily observes alongside them.
- Source ID field: `deviceID` on `GET /api/extapi/assets` (the same device is spelled
  `deviceId` on the `device-cves` and `anomalies` payloads).
- Documentation evidence: Asimily's API reference is not public — the vendor documents the
  external API through its Zendesk support portal, which requires a customer login. The
  contract used here is the vendor-authored Cortex XSOAR pack
  `Packs/Asimily_Insight/Integrations/AsimilyInsight`, which is Asimily's own supported
  client. In it, `map_asimily_asset_entity_from_asimily_assets_json` reads
  `raw_data.get("deviceID")` as `asimilydeviceid`, the asset command declares
  `outputs_key_field="asimilydeviceid"` (i.e. the vendor treats it as the primary key for
  deduplicating asset records), and `construct_asimily_asset_portal_url` builds a permanent
  portal deep link `"/index.html#/asset/1/{deviceID}"` from it. The anomaly and CVE
  commands key their incidents on `["asimilydeviceid", ...]` and use `deviceId` as a
  resumable high-water mark (`deviceRangeId` with the `Grt` operator), which only works if
  the id is stable and monotonically assigned.
- Uniqueness scope: tenant. Each customer has a dedicated portal host
  (`<customer>-portal.asimily.com`), and the id is an integer assigned by that tenant's
  instance, so it is not globally unique.
- Cardinality: one source row per device on `/api/extapi/assets`. The `device-cves` and
  `anomalies` endpoints return one row per device with nested `cves` / `anomalies` arrays,
  and a device can appear on more than one page of those endpoints — those rows are merged
  onto the single asset rather than emitted as additional assets.
- Stability: the id survives rename, re-addressing, and moves between facilities — Asimily
  is a passive/network-observation product, and the reference client relies on the id
  remaining fixed across fetch cycles to resume paging. It is not derived from MAC, IP, or
  hostname.
- Reuse behavior: not documented. The id is an incrementing tenant-local integer, so
  reassignment of a deleted device's id is unlikely but unverified. This is an accepted
  residual risk and is called out in Notes.
- Presence: present on every asset row observed in the reference client and its fixtures.
  Records without it are skipped rather than given a synthesized id.
- Final runZero ID: `asimily:<portal-host>:<deviceID>` (e.g.
  `asimily:acme-portal.asimily.com:1001`). The scheme is stripped from the configured URL
  so that switching between `http` and `https` does not change asset identity.
- Missing-ID behavior: skip the record and log `asimily: skipping device with no deviceID:
  mac=<mac>`. No UUID or composite fallback is generated.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The id is authoritative, but
  clinical devices are routinely re-addressed by DHCP, moved between facilities, and
  re-imaged with a new hostname, and many have no hostname at all. Keeping id-based merging
  while preventing MAC/IP/name differences from disqualifying a merge avoids fragmenting a
  device into several runZero assets across polls. Verified with a fixture in which
  `deviceID` 1001 kept its identity after its MAC, IPv4 address, and hostname all changed.
- Verdict: scoped authoritative.

### Notes

- **What is imported.** Assets come from `GET /api/extapi/assets`. Vulnerabilities come
  from `POST /api/extapi/assets/device-cves` and are joined to assets on the device id.
  Software comes from `GET /api/extapi/assets/application?macAddr=<mac>` and is only
  fetched when **Import installed software** is enabled.
- **Every request carries the `source` header.** Asimily made it mandatory on 1 May
  2026 for "identifying the origin of API calls", so it rides on all three endpoints,
  including the per-MAC applications call. The value is self-declared — nothing Asimily
  publishes issues, registers, or validates a per-customer identifier, and the vendor's
  own sample client simply hardcodes one (`SOURCE = '<YourOrganizationName>'`) with no
  validation — so the default `runzero` identifies the client making the call, which is
  what the header is for. The alphabetic-only rule is enforced twice: as a `pattern` on
  the parameter, which the console applies to the credential form before a task can run,
  and again in the script, because the CLI path (`runzero script --kwargs`) applies
  neither declared defaults nor declared validation. A bad value fails *every* request in
  the run rather than one, which is why it is screened before the first call instead of
  being discovered from a rejected response.
- **Field mapping.** `hostName` → hostnames; `macAddr` + `v4IpAddrs` + `v6IpAddrs` →
  `networkInterfaces`; `manufacturer` → manufacturer; `deviceModel` → model; `os` → os;
  `osVersion` → osVersion; `lastDiscoveredAt` → lastSeenTS. `deviceType` is used for
  `deviceType` because it carries the specific clinical/OT device type ("Infusion Pump",
  "Lab Analyzer"); the coarser `deviceClass` is carried as the `class:` tag and falls back
  into `deviceType` only when `deviceType` is empty. Tags are `asimily`, `facility:<...>`,
  `department:<...>`, and `class:<...>`. Everything else — `location`, `facility`,
  `department`, `region`, `riskScore`, `likelihood`, `impact`, `isConnected`, `isWireless`,
  `isNetworkingDevice`, `discoverySourceValue`, `mds2`, `storesEphi`, `transmitEphi`,
  `cmmsId`, `deviceFamilies`, `deviceMasterFamily`, `deviceTag`, `serialNumber`,
  `hardwareArchitecture`, `softwareVersion`, `managedBy`, `anomalyPresent`, plus a deep
  link back to the device in the portal — becomes a custom attribute prefixed `asimily_`.
- **The device id is spelled two different ways.** The asset payload uses `deviceID` while
  the `device-cves` and `anomalies` payloads use `deviceId`. Both spellings are normalized
  at the join point in the script; getting this wrong silently produces zero vulnerability
  matches rather than an error.
- **Vulnerability scoring.** `cveName` → `cve`, `description` → description, `fixedBy` →
  solution, `exploitableInWild` → exploitable, `nvdPublishDate` → publishedTS, `openDate` →
  firstDetectedTS. Two different scores are published per finding and both are mapped:
  `cvssBaseScore` → `cvss3BaseScore` and `severityScore`/`severityRank` (CVSS v3 bands:
  9.0 critical, 7.0 high, 4.0 medium), and Asimily's own prioritized `score` →
  `riskScore`/`riskRank` (Asimily bands from the reference client: 7.5 high, 3.5 medium,
  with 9.0 treated as critical on the runZero side). The CVSS *version* is not stated in
  the API payload; it is mapped to v3 because the vendor's own XSOAR incident field for
  `cvssBaseScore` is named "Asimily CVE CVSS 3 Base Score". Treat that as strong but
  indirect evidence. `productName` and `productType` identify which installed product the
  CVE applies to and are kept as custom attributes, which is what ties a finding back to an
  entry in the software inventory.
- **No port or service data.** This API exposes no listening ports, transports, or service
  banners anywhere, so no `Service` objects are created and the `serviceAddress`,
  `servicePort`, and `serviceTransport` fields on each Vulnerability are deliberately left
  unset rather than stuffed with a placeholder.
- **Only open CVEs are imported.** Asimily encodes fix state as a sentinel integer — 55
  means fixed, 56 means not fixed — and the request always carries the
  `{"filters": {"isFixed": [{"operator": ":", "value": 56}]}}` filter, matching the
  reference client, which applies it unconditionally. Remediated findings are therefore
  not imported and will age out of runZero.
- **Software import is off by default because it is an N+1 fetch.** The applications
  endpoint accepts a single MAC address, so populating software inventory costs one extra
  HTTP request per device. The vendor's own client caps this at 100 devices for exactly
  this reason. Enabling **Import installed software** applies the same default cap via
  **Software device limit**; devices past the cap are still imported, just without
  software, and the script logs how many were skipped
  (`asimily: skipped software for N devices; raise the software device limit ...`) rather
  than truncating silently. Devices with no MAC address are never queried. A version of
  `*` means "any version" in this payload and is normalized to an empty version.
- **Pagination.** Both list endpoints are zero-based and return
  `{content: [...], totalPages, totalElements}`. The script pages until
  `page + 1 >= totalPages` or a page comes back empty, so the full inventory is retrieved.
  The low ceilings in the vendor's XSOAR pack (assets 400/page and 1200 total, CVEs
  25-50/page and 200 total) are limits of the XSOAR command surface, not of the API, and
  are deliberately **not** reproduced here. Asset page size is configurable (default 200);
  CVE pages use a fixed size of 50 because each row carries a nested array of findings and
  is much heavier than an asset row.
- **Rate limiting and latency.** The Asimily API is slow and rate limited. `get_json` and
  `post_json` retry `408/425/429/500/502/503/504` with exponential backoff and honor
  `Retry-After`, three additional attempts by default. This script raises that to
  `retries=4` with a 7.5 second backoff factor and a 180 second timeout, matching the
  reference client's
  `TOTAL_RETRIES`, `BACKOFF_FACTOR`, and `REQUEST_TIMEOUT`. All retry and backoff behavior
  is the shared helper's; none of it is hand-rolled. On a large tenant, expect this task to
  run for a long time and schedule it accordingly.
- **Memory.** Assets are streamed to runZero one page at a time via `report_asset`. The
  CVE map is built first and holds only finished `Vulnerability` objects (capped at 99 per
  device), not raw API responses.
- **Unverified assumptions.** These could not be checked without a live tenant:
  (1) Asimily's API reference is behind a customer login, so every endpoint, parameter, and
  field name here is taken from the vendor's XSOAR client rather than from published
  documentation. (2) The CVSS version behind `cvssBaseScore` is inferred, as described
  above. (3) The format of `lastDiscoveredAt`, `nvdPublishDate`, and `openDate` is not
  documented — the reference client runs them through `dateparser`, which accepts almost
  anything. The script only converts RFC 3339 strings and epoch integers into timestamps;
  any other format is left off `lastSeenTS`/`publishedTS` and preserved verbatim as a
  custom attribute instead of risking a parse failure. (4) Whether a deleted device's
  `deviceID` can be reassigned to a different device. (5) With invalid credentials the API
  may redirect to an HTML login page instead of returning 401 — the reference client
  detects this by looking for `loginStyle` in the response body — in which case the failure
  surfaces as a JSON decode error rather than the explicit "check the API username and key"
  message. (6) How Asimily actually enforces the `source` header. The rule and its 1 May
  2026 enforcement date are quoted from the vendor's own Postman collection, but the
  behaviour on a live tenant — hard rejection versus a warning, and which status code comes
  back — has not been observed, nor has it been confirmed that a self-declared `runzero`
  is accepted in place of the customer's own organization name. (7) Header-name casing.
  The vendor sends `source` lower-case; the runZero HTTP helper canonicalizes header names,
  so it goes on the wire as `Source`. Header names are case-insensitive per RFC 7230 and
  Asimily's stack appears to be Spring (whose header map is case-insensitive), so this
  should not matter — but a gateway doing an exact-match check would reject it, and that
  is the first thing to test if a current tenant rejects every request.
- This integration was validated against local fixtures, not a live Asimily Insight tenant.

## Future

- **Anomaly / alert ingestion.** `POST /api/extapi/assets/anomalies` (paged, sorted by
  `deviceRangeId`) returns one row per device with a nested `anomalies` array carrying
  `anomaly`, `description`, `criticality` (Low/Medium/High), `anomalyScore`,
  `earliestTriggerTime`, `latestTriggerTime`, `alertId`, `anomalyCategory`, `mitreTactic`,
  and `mitreTechnique`. This is the one endpoint deliberately not imported in v1: these are
  time-bounded behavioral detections, not properties of a device, so folding them into
  asset attributes would produce a field that is stale the moment it is written. They are a
  natural fit for a runZero-side event feed, where the MITRE ATT&CK tactic/technique
  mapping and the `deviceRangeId` high-water-mark cursor (`{"operator": "Grt"}`) would
  support efficient incremental polling. `customerAnomalyId` is documented by the vendor as
  the handle for future fix actions.
- **CVE enrichment / lookup.** `POST /api/extapi/assets/device-cves` accepts filters on
  `macAddr`, `ipAddr`, `deviceInfoId`, `deviceFamily`, `deviceTag`, `cveScore`, and
  `cvesLastUpdatedSince`. A lookup integration could answer "what does Asimily know about
  this device" on demand for a single asset instead of importing the whole tenant, and
  `cvesLastUpdatedSince` (with the `>` operator) would enable a delta-only vulnerability
  refresh between full imports — a meaningful saving given how slow the full pass is.
- **Outbound push-back: not currently possible.** The external API surface exposed by the
  vendor's own client is four endpoints — `assets`, `assets/application`,
  `assets/device-cves`, `assets/anomalies` — and only `assets` and `assets/application` are
  reads via GET; the other two are POSTs that carry a *query filter* body, not a mutation.
  There is no create, update, tag, or annotate endpoint in evidence, so runZero data cannot
  be pushed back into Asimily today. The vendor's note that `customerAnomalyId` "can be
  used in future operations such as invoking anomaly fix actions" implies a write API is
  planned but not yet available. This should be re-checked with Asimily directly rather
  than assumed.
- **IoMT coverage-gap reporting.** This is the highest-value follow-on. In healthcare the
  core risk is the clinical device nobody manages, and Asimily's `discoverySourceValue`,
  `isUsingEndpointSecurity`, `managedBy`, and `cmmsId` fields describe exactly that. Because
  runZero discovers devices independently, comparing the two inventories surfaces devices
  runZero sees that Asimily does not (outside the monitored VLANs, so unmonitored for
  anomalies), devices Asimily sees that no CMMS record covers (`cmmsId` empty — owned by
  nobody, so unpatched), and devices carrying `storesEphi`/`transmitEphi` with no endpoint
  security. Segmentation and HIPAA risk-assessment work all key off those gaps.

## API documentation

Asimily does not publish its API reference publicly; the vendor documentation portal
(<https://asimily.zendesk.com/>) requires a customer login, and Asimily's product site
(<https://asimily.com/>) carries no API reference. Every endpoint, parameter, field name,
and sentinel value used by this integration was therefore taken from Asimily's own
vendor-authored and vendor-supported Cortex XSOAR integration, read directly from source:

- Client, endpoints, authentication, pagination, retry/timeout constants, and the
  `isFixed` sentinels — `Packs/Asimily_Insight/Integrations/AsimilyInsight/AsimilyInsight.py`
  in <https://github.com/demisto/content>.
- Asset, CVE, and anomaly field names and the identity/output key fields —
  `AsimilyInsight.yml` and `AsimilyInsight_description.md` in the same directory.
- Response shapes (including the `applications` array and the device-row-with-nested-cves
  shape) — `AsimilyInsight_test.py` in the same directory.
- The "CVSS 3" reading of `cvssBaseScore` —
  `Packs/Asimily_Insight/IncidentFields/incidentfield-Asimily_CVE_CVSS_3_Base_Score.json`.
- Portal URL format and credential setup — `Packs/Asimily_Insight/Integrations/AsimilyInsight/README.md`.

Two further vendor-published sources cover the mandatory `source` header, which the XSOAR
pack predates and does not send:

- The rule, the permitted and prohibited characters, and the 1 May 2026 enforcement date —
  the "Mandatory Source Header in REST API Calls" section of Asimily's own **Asimily API
  Toolkit** Postman collection, linked from the README of
  <https://github.com/AsimilyInc/asimily-api-python-examples>. Every request in that
  collection carries a `source` header.
- The header name, its lower-case spelling, and that it is sent on every request — Asimily's
  sample client `asset/asset_export.py` in the same repository, which declares
  `SOURCE = '<YourOrganizationName>'`, documents it as "Organisation name sent in the
  'source' header", and sets it once in `ApiClient.__init__` so it rides on every call.

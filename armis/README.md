# Custom Integration: Armis Centrix

Armis Centrix is a cloud asset intelligence platform that builds a device inventory
from network traffic inspection and from the security tools a customer already runs.
This integration imports that inventory into runZero through the per-tenant Armis
API v1.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Armis requirements

- An Armis Centrix tenant and its URL, which is per-customer: `https://<tenant>.armis.com`.
- An **API secret key**, created in the Armis console under **Settings > API Management**.
  The token minted from it carries the permissions of the user who created the key, so
  create it as a user that can read the device inventory.
- **A secret key per configured task.** Armis prohibits sharing one secret key across
  concurrent clients and treats it as an authentication conflict rather than as
  contention, so a key shared with another integration causes both to fail
  intermittently. Give runZero its own key.
- An **Armis Centrix for Vulnerability Prioritization and Remediation (ViPR)** licence,
  *only* if you enable **Import vulnerabilities**. Without it the vulnerability
  endpoints return no data; the device import is unaffected.
- Network egress from the Explorer to `https://<tenant>.armis.com`.

This integration deliberately uses **API v1, not v3**. v3 requires a `vendor_id` that
Armis issues only to registered partners, on top of the customer's own credentials,
which is a business dependency a self-service integration cannot satisfy. v1 is
per-tenant, needs only the customer's secret key, is explicitly not deprecated, and is
the only version with the `/search/` endpoint this integration is built on.

## Steps

### Armis configuration

1. In the Armis console, open **Settings > API Management** and create a secret key.
   Record it; the console shows it once.
2. Confirm the key works. The token exchange and the inventory call are two requests:

   ```bash
   ARMIS_TENANT="https://example.armis.com"
   ARMIS_SECRET_KEY="<secret key>"

   ACCESS_TOKEN=$(curl -s -X POST "${ARMIS_TENANT}/api/v1/access_token/" \
     -d "secret_key=${ARMIS_SECRET_KEY}" \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")

   curl -s "${ARMIS_TENANT}/api/v1/search/" \
     -H "Authorization: ${ACCESS_TOKEN}" \
     -G \
     --data-urlencode "aql=in:devices" \
     --data-urlencode "length=1" \
     --data-urlencode "orderBy=lastSeen"
   ```

   Two details in that snippet are easy to get wrong. The `Authorization` header
   carries the **bare token with no `Bearer` prefix** (v1 rejects the prefixed form;
   `Bearer` applies only to v3), and every v1 path ends in a **trailing slash**.

   The access token lives **30 minutes**, so expect to mint a new one while testing.
   The integration handles this itself: a 401 mid-run re-mints the token and retries
   the failed request once, so a walk longer than one token lifetime still completes.
3. If you want to scope the import, build the query in the Armis console search bar
   and copy the ASQ string it generates into the **Additional ASQ filter** field. The
   integration always prefixes `in:devices`, so supply only the filter tokens:
   `timeFrame:"30 Days"`, `riskLevel:Medium,High`, `type:"Laptops","Servers"`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Armis Centrix").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Armis tenant URL** (`url`): the tenant base URL, `https://<tenant>.armis.com`.
   - **API secret key** (`secret_key`): the key created above.
   - **Additional ASQ filter** (`device_filter`): optional; ASQ tokens AND-ed onto `in:devices`. Empty imports the whole inventory.
   - **Page size** (`page_size`): optional; default 1000. See the note on the undocumented ceiling below.
   - **Import vulnerabilities** (`include_vulnerabilities`): optional; default off. Requires a ViPR licence.
   - **User-Agent** (`http_user_agent`): optional; the standard HTTP option, if the tenant rejects the default agent.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a secret key and see what a tenant actually returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename armis/armis.star \
  --kwargs url=https://example.armis.com \
  --kwargs secret_key=EXAMPLEsecretkeyEXAMPLEsecretkey \
  --kwargs page_size=1000 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./armis-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a directory
from a previous run (the scanner refuses an existing `--output` directory otherwise).
Add `--verbose` for the request-by-request log. Omit `--output` to see only the log
lines.

To include CVE findings, and to scope a large tenant to recent activity:

```bash
runzero script --filename armis/armis.star \
  --kwargs url=https://example.armis.com \
  --kwargs secret_key=EXAMPLEsecretkeyEXAMPLEsecretkey \
  --kwargs 'device_filter=timeFrame:"30 Days"' \
  --kwargs include_vulnerabilities=true \
  --output ./armis-vulns --overwrite
```

`--kwargs` hands the value to the script verbatim, commas included, as long as the
pair contains a single `=`. A value carrying a *second* `=` as well as a comma is
re-read as CSV: it is cut off at the comma and the remainder becomes a fabricated
second parameter rather than an error. ASQ filters can hit this
(`type:"Laptops","Servers"` is fine; a filter with both a comma and an `=` is not), so
wrap such a value in double quotes, `--kwargs '"device_filter=a=b,c"'`, doubling any
double quote inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename armis/armis.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly, and
issues a request. It does not prove Armis accepts the secret key, that the tenant URL
resolves, or that any device is parsed.

The fixtures under `armis/tests/fixtures/` exercise the parsing offline, including the
paging, token-refresh, rate-limit, and malformed-record cases:

```bash
python3 tests/run.py armis
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat armis/armis.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://example.armis.com,secret_key=<secret>' \
  --output ./armis-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes one
comma-separated string, so no value containing a comma at all can be passed that way,
which rules out most ASQ filters. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Armis Centrix.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:armis`.

## Asset identity

- Target entity: physical and virtual devices (IT, IoT, OT, and medical) that Armis
  observes on the network or learns about from a connected security tool.
- Source ID field: `data.results[].id` on `GET /api/v1/search/?aql=in:devices`.
- Documentation evidence: Armis publishes no OpenAPI spec for v1, so the contract comes
  from three independently maintained clients that run against real tenants (Cortex
  XSOAR, Elastic, Google SecOps) plus the vendor's v3 documentation. `id` is an integer
  in every published payload (`469`, `2172`, `74745`) and the ASQ filter for it is
  `deviceId:`. The v3 documentation
  ([extracting device information](https://dev.armis.com/docs/extracting-device-information))
  treats the internal asset ID, IP, MAC, and serial as four *separate* identifier
  classes, so the internal id is not derived from any observable attribute.
- Uniqueness scope: **tenant.** v1 is addressed per-tenant and a v1 token has no
  cross-tenant reach at all. The observed values are small, dense integers, the
  signature of a per-tenant sequence, so two tenants imported into one runZero
  organization would collide on low integers almost immediately. The tenant host is
  therefore part of the id.
- Cardinality: one `in:devices` row per device. Vulnerability findings are many-to-one
  children joined on the same id and attached to the asset rather than emitted as
  separate assets. Note that v1 shows only **one** representative `ipAddress` and
  `macAddress` per row even when Armis knows several, so a multi-homed device is one
  row with one address, not several rows.
- Stability: `id` survives reboot, rename, and IP change; `firstSeen` persists while
  `lastSeen` advances, which only makes sense for a durable record. A MAC change on a
  device Armis only ever saw passively is plausibly indistinguishable from a new device
  and would produce a new id, but that failure mode is a duplicate, not a hijack.
- Reuse behavior: **unverified, and treated as possible rather than proven.** One
  ServiceNow community field report describes the same Armis device id later naming a
  completely different device, with a different serial number and MAC, after which
  ServiceNow found the existing row and overwrote the first device with the second's
  data. That is the entire evidence base, and an exhaustive second search found **no
  independent corroboration and no refutation**. Armis does publish
  `device-merge-events` and `device-delete-events` as first-class exportable entities,
  but that proves merges and deletions happen, **not** that a retired id is ever handed
  to another device. The distinction decides the integration: if an id survives a merge
  and now describes the union of two records, id matching is *correct*, and only genuine
  reallocation makes it wrong. The question is open, so the conservative branch is taken
  and the cost of taking it is stated below.
- Presence: always present. Every published payload carries it and every reference
  client dereferences it without a null guard. A defensive skip is implemented anyway.
- Final runZero ID: `armis:<tenant-host>:<id>`, for example
  `armis:example.armis.com:469`. The host is taken **without its port**: the port is
  not part of the tenant's identity, and folding it in would re-key an entire estate
  the day the console moved.
- Missing-ID behavior: skip. The record is logged as
  `skipping device record with no id, name=<name>` and dropped; no random or synthesized
  id is ever generated. Separately, a record with **no MAC, no IP, and no hostname** is
  also skipped and counted, because the id is barred from matching and such a record
  gives runZero nothing to correlate on: it would create a fresh orphan asset on every
  poll.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. A foreign-ID match
  in runZero is **never** disqualified by a conflicting MAC, IP, or hostname, because
  the break helpers are consulted only on the MAC, IP, and name match paths. So if the
  id is reused, an id match merges an unrelated device into an existing asset and no
  flag can veto it. The two outcomes are not symmetric: that failure is silent and
  unrecoverable, while the cost of avoiding it is neither. The id is therefore taken out
  of the matching path and correlation is delegated to the MAC, IP, and hostname each
  record already carries. `palo-alto-device-security`, `aruba-clearpass`, and
  `forescout-counteract` reach the same conclusion for the same class of identifier. The
  id is still emitted, so every record keeps a stable key and remains searchable.
- **What this choice costs.** A record with no MAC, no IP, and no hostname has nothing
  left to correlate on, so it is skipped and counted, where default matching would have
  imported it on its foreign id. Armis rows marked `visibility: "Limited"` are exactly
  that shape: Armis learned of the device from a connected tool rather than from
  traffic, so it can carry an id, a site, a `riskLevel` and a `type` and no address at
  all. `armis/tests/fixtures/no-correlator-loss.json` pins that loss with a count, so it
  cannot become silent, and it is the scenario to re-point if this decision is ever
  revisited.
- Verdict: **scoped, and treated as non-authoritative pending verification.** The id is
  unique within a tenant at any one moment. Whether it is unique across time is exactly
  the property that is unproven, and an identity key is not something to assume that
  about.

### Notes

- **Assets** come from `GET /api/v1/search/` with `aql=in:devices`, `orderBy=lastSeen`,
  and `includeTotal=false`, paged with `length` and `from` and streamed to runZero one
  page at a time. `name` and `names` become hostnames; `ipAddress` and `ipv6` become the
  addresses and `macAddress` the MAC; `operatingSystem` and `operatingSystemVersion`
  become the OS and OS version; `manufacturer` and `model` map directly; `firstSeen` and
  `lastSeen` become `firstSeenTS` and `lastSeenTS`.
- **`deviceType` is mapped from `type`, not `category`.** Armis' `type` is the device
  taxonomy ("Laptops", "Servers", "Access Points"), which is the grain runZero's device
  type expects. `category` is a much coarser grouping ("Computers", "Network Equipment")
  and is kept as an attribute. `typeEnum` is the machine-readable spelling of the same
  value and only stands in when `type` itself is absent.
- **Both the scalar and the array shape are accepted for every address field.** v1
  documents `ipAddress` and `macAddress` as scalars while v3 uses arrays, and `ipv6`
  changed from a scalar to an array between Armis releases, so `"ipv6": "fe80::..."`,
  `"ipv6": null`, and `"ipv6": ["::ffff:..."]` all parse. A v1 scalar is also not always
  single-valued: Armis comma-joins several addresses into the one string, and those are
  split apart. Where an array of MACs arrives, the first becomes the primary interface
  alongside the addresses and the rest become MAC-only interfaces, up to 32.
- **Link-local and loopback addresses never reach an interface.** v1 rows routinely
  carry an `fe80::` address in `ipv6`, and an APIPA or loopback address identifies
  nothing while correlating every host that reports one onto a single asset. The raw
  value is preserved in the `armis_ipv6` attribute so it is still searchable.
- **Vulnerabilities are opt-in and are a two-call chain.** `GET /api/v1/search/` with
  `aql=in:vulnerabilities` returns one row per **CVE**, not per device finding; the
  devices each CVE was found on come from
  `GET /api/v1/vulnerability-match/?vulnerability_ids=<CVE,CVE,...>`, joined back on
  `deviceId`. That endpoint answers with a different envelope from every other v1 path:
  `data.sample` rather than `data.results`, and `data.paging.next` rather than
  `data.next`. `cveUid` becomes the `cve` (upper-cased, and only when it matches the
  pattern the platform validates, so a non-CVE advisory id is carried as the name
  instead of failing the whole record); `cvssScore` becomes the severity score and the
  risk score; `severity` drives both the severity rank and the risk rank, because Armis
  publishes nothing that separates exploitability from impact; `recommendedSteps`
  becomes the solution. Up to 99 findings are attached per asset. Armis' own ratings
  (`avmRating`, EPSS, weaponization, ransomware) are preserved as attributes rather than
  folded into the runZero severity.
- **The vulnerability pass inherits the `device_filter` time bound.** `in:vulnerabilities`
  is tenant-wide and has no site or risk field, so an arbitrary device filter cannot be
  applied to it, but the collection does carry `lastDetected`, so a `timeFrame:"N Days"`
  token in `device_filter` is carried across as `lastDetected:"N Days"`. Without it,
  scoping devices to one site still walks and joins the tenant's entire CVE catalogue,
  which against the documented 200-requests-per-5-minute budget is what dominates a run.
  Only the fields a finding actually needs are indexed, rather than every CVE row whole.
- **CVE ids are batched 100 at a time** into `vulnerability_ids`, **worst first**. That
  parameter travels in the query string and integration authors report 414 responses
  from this endpoint; a CVE id is about 15 bytes, so this batch size stays well inside
  any URL limit. Order matters because the 99-findings-per-device cap keeps whatever
  arrives first, so batches are ordered by severity rank and then CVSS score, both
  descending, with the id as a deterministic tiebreak.
- **A finding whose device is not in the inventory result is dropped, and counted.** A
  vulnerability-match row carries only a `deviceId` and no device attributes at all, so
  there is nothing to build a correlatable asset from. The run logs
  `dropped findings for N devices absent from the inventory query`; widening
  `device_filter` is the fix.
- **A disappeared asset means "unknown", not "decommissioned".** Armis merges and
  deletes devices, each with its own event stream, and this integration sees only
  `/search/`, so it cannot tell "merged away" from "deleted" from "aged out of the ASQ
  filter". Do not drive decommissioning from an Armis asset's absence. Reconciling it
  properly would need the v3 `device-merge-events` data export, which is v3-only,
  Parquet, scope-gated, and disabled by default. `firstSeen` is imported so that an id
  whose device history restarts, which is what a reused id would look like from here, is
  at least visible downstream.
- **Provenance is imported.** `dataSources` names which Armis connectors and sensors
  contributed the record (`Active Directory`, `CrowdStrike`, `SCCM`, `Qualys`,
  `Traffic Inspection`), and `protections` names the endpoint agents found on it. Both
  land as `armis_data_sources` and `armis_protections`, which is what an operator needs
  to judge how much of the record is observed versus imported.
- Site, sensor, access switch, boundaries, Purdue level, business impact, visibility,
  risk level, category, type, display title, user ids, and any tenant-defined
  `customProperties` are carried as custom attributes prefixed `armis_`. Armis `tags`
  are imported verbatim as runZero tags (some are `key=value` shaped, which is how Armis
  emits them) alongside a `site:` tag. The `user` field populates asset ownership
  through `ownershipAttributes`.
- **`riskLevel` is passed through without interpretation.** The published payloads show
  `5` and `10` from 2021-era tenants and `80` from 2025-era ones, so the scale appears to
  have changed and any threshold logic would be version-dependent.
- Pagination: `data.next` is an **absolute row offset** to feed back as `from`, not an
  opaque cursor and not a URL. The walk ends when `next` is null; an empty page and a
  `next` that fails to move forward are guarded as well, because either would otherwise
  re-request the same offset until the page ceiling fired.
- **`orderBy=lastSeen` is not a stable sort key for an offset walk.** Every reference
  client uses it and there is no documented sort by id, but a device whose `lastSeen`
  advances mid-walk shifts position and can be skipped or repeated. runZero reconciles
  the duplicate on the next poll; a `before:` bound in `device_filter` freezes the
  window if that matters for a particular tenant.
- Rate limiting: Armis documents 200 requests per 5 minutes per sender across all
  endpoints, answering 429 with `Retry-After`. Nothing in this script handles that. The
  shared HTTP helper already retries 429 and 5xx with exponential backoff and honors
  `Retry-After`, and a second backoff layered on top is how one throttle becomes a retry
  storm.
- Unverified assumptions, all of which would need a live tenant to settle:
  1. **The maximum `length`.** No vendor documentation states a ceiling. XSOAR calls
     10000 the "Armis recommended max page size", Query.ai observed roughly 5000 as the
     practical limit, Elastic defaults to 2000 and Google SecOps to 1000. This
     integration defaults to **1000** and caps the parameter at 10000. Elastic's
     documented remedy for `502 Bad Gateway` and `414 Request-URI Too Large` is "reduce
     the page size", so lower it if a tenant misbehaves.
  2. **The `fields=` projection parameter is not used.** Google Cloud's Armis onboarding
     page shows a vendor `curl` carrying it, so it is a published working request, but
     no other reference client uses it and whether *this* tenant honours it is untested.
     If it works it would cut payload size and might surface `serialNumber` and
     `firmwareVersion`, which exist in v3's field enum but in no v1 payload.
  3. **Whether a v1 device row can carry multiple IPs or MACs.** Every published payload
     shows scalars. The parser accepts arrays anyway; if v1 really does drop extra
     addresses silently, merging on the single visible MAC will under-merge multi-homed
     devices and no client-side change can fix it.
  4. **Whether an id is ever reused, and what a merge does to the losing id.** Neither
     is publicly documented. This is the single question that would settle the identity
     decision above: if the surviving id describes the union, id matching is right. The
     match behavior chosen is conservative under every answer.
  5. **Whether the documented 200-request budget applies to v1.** The rate-limit page
     lives in the v3 developer portal and does not scope itself. Assumed to apply.
  6. **`names` semantics.** A plural-sounding field that holds a scalar string, which in
     one published payload differs from `name`. It is parsed as either shape and
     imported as an additional hostname.
- This integration was validated against local fixtures, not a live Armis tenant.

## Future

- **Alerts as an event feed.** `GET /api/v1/search/?aql=in:alerts` returns policy alerts
  carrying `deviceIds`, an array joining one alert to several devices. That shape suits
  an event feed rather than an inventory import, which is why alerts are not imported
  here: a policy alert is not a property of a device. Fanning them back onto assets
  would mean collecting `deviceIds` across a page, deduplicating, and bulk-fetching with
  `in:devices deviceId:<comma-list>`, minding the same 414 ceiling the vulnerability
  path has.
- **Incremental sync with `after:`.** ASQ supports `after:2026-08-01T00:00:00` (no
  timezone suffix), which is what the Elastic and XSOAR collectors use for incremental
  runs. A future version could persist the high-water `lastSeen` between tasks and pull
  only what changed. It needs somewhere to keep the watermark, which is why this version
  pulls the full inventory and lets the operator narrow it with `device_filter` instead.
- **Resolving merges and deletions.** The v3 data export publishes `device-merge-events`
  and `device-delete-events` with up to 90 days of retention. Consuming them is the only
  way to tell a merged-away device from a deleted one. It needs v3 access, the export
  enabled on the tenant, and a Parquet reader, so it is out of scope until v3 is usable.
- **Outbound: tagging Armis devices from runZero.** `POST /api/v1/devices/{id}/tags/`
  and `DELETE /api/v1/devices/{id}/tags/` add and remove device tags. Since this
  integration already keeps the Armis device id as its foreign key, an outbound
  integration could push runZero's own classification or ownership back onto the record.
- **Users.** `in:users` is a documented ASQ collection and device rows carry `userIds`,
  which are currently imported as opaque integers. Resolving them would give real
  ownership attribution rather than only the `user` string some device rows carry.

## API documentation

Armis publishes no OpenAPI specification and no Postman collection for v1, so several
entries below are third-party clients that call the live API. They are listed because
they are the actual source of the request and response contract implemented here.

- Documentation index (also lists the exportable entities): https://dev.armis.com/llms.txt
- Migration from API v1 (v1 base URL, v1 is not deprecated, the v1-to-v3 endpoint map, and the confirmation that `/search/` has no v3 equivalent): https://dev.armis.com/docs/migration-from-api-v1
- Authentication (v3 OAuth2, the partner `vendor_id` requirement, and the `Bearer` scheme that applies to v3 only): https://dev.armis.com/docs/authentication
- Rate limiting (200 requests / 5 minutes, 429, backoff guidance): https://dev.armis.com/docs/rate-limiting
- Best practices (4xx/5xx handling, batch requests): https://dev.armis.com/docs/best-practices
- Data export (`device-merge-events` and `device-delete-events` as first-class entities, and their retention): https://dev.armis.com/docs/data-export
- Glossary (the definition of a tenant, which is the identity scope): https://dev.armis.com/docs/glossary
- Extracting device information (the four identifier classes Armis recognises): https://dev.armis.com/docs/extracting-device-information
- v3 asset search OpenAPI (the field enum showing what Armis holds but v1 does not expose): https://dev.armis.com/reference/search_assets__search_post
- Cortex XSOAR Armis pack (v1 auth, the bare `Authorization` header, `/search/` parameters, the `data.results`/`data.next` envelope, the 401 retry, and the vendor-confirmed 30-minute token TTL): https://github.com/demisto/content/tree/master/Packs/Armis
- Elastic Armis integration (independent confirmation of the same v1 flow, plus the `in:vulnerabilities` to `/vulnerability-match/` chain and its different envelope): https://www.elastic.co/docs/reference/integrations/armis
- Google SecOps Armis parser and onboarding (the working curl, `data.total`/`data.count`, `Retry-After` handling, and the only mention of the `fields` parameter): https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/armis-devices
- Query.ai Armis Centrix notes (tenant URL scheme, the ViPR licence gate on vulnerability data, and the observed ~5000-result page limit): https://docs.query.ai/docs/armis-centrix
- Vulcan Cyber Armis connector (vulnerability uniqueness via `cveUid`, and the note that Armis has no mechanism to export all active vulnerabilities): https://help.vulcancyber.com/en/articles/8238327-armis-connector
- ServiceNow community thread on Armis id instability and CI hijacking (the single, uncorroborated field report behind the identity decision above, and the only source that describes reuse at all): https://www.servicenow.com/community/service-graph-connectors-forum/armis-id-instability-causing-ci-hijacking-in-cmdb-armis-issue-or/m-p/3432078

# Custom Integration: Forescout Risk and Exposure Management

Forescout Risk and Exposure Management (REM), marketed as **eyeFocus**, is the
cross-product aggregation layer of the Forescout Cloud platform. Its inventory
spans eyeSight, eyeInspect, Edge Collectors and the medical device capability at
once, and it carries a risk score per asset that neither on-premise product can
produce. This integration imports that inventory into runZero through the REM
Asset Search API.

It is a third Forescout integration rather than an addition to either existing
one, because it is a different product on a different deployment model with a
different credential and a different query model:

| Integration | Product | Endpoint | Credential |
| --- | --- | --- | --- |
| `forescout-counteract` | CounterACT / eyeSight | on-premise Enterprise Manager, `/api/hosts` | Web API user, JWT |
| `forescout-eyeinspect` | eyeInspect OT sensors | on-premise Command Center, `/api/v1/hosts` | Command Center user, HTTP Basic |
| `forescout-rem` (this one) | REM / eyeFocus | Forescout Cloud tenant, `/api/data-exchange/v3/rem-asset-search` | Risk Sharing API key, bearer |

**Forescout publishes no REST API reference for this API.** Every endpoint,
parameter and field name below comes from a shipped third-party client whose
comments record behaviour verified against a live demo tenant, cross-checked
against Forescout's documentation of the surrounding plumbing. That is enough to
build against and it is not a specification; the open assumptions are listed
under [Notes](#notes).

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Forescout requirements

- A Forescout Cloud tenant with Risk and Exposure Management (eyeFocus) enabled.
- An API key generated with the key type **Risk Sharing API**. This is the only
  one of the three key types that returns assets -- Health Alerts covers
  appliance health, and Log Query covers log ingestion. Forescout's own Cloud
  Data Exchange settings page says it outright: "In the API Key Type, select
  Risk Sharing API."
- The **API endpoint URL** the console prints beneath the generated key. It is
  the tenant's own regional host, so treat it as a value to copy rather than one
  to derive.
- Network egress from the Explorer to that host on 443.

## Steps

### Forescout configuration

1. In the Forescout Cloud console, open **Administration > Integrations**.
2. Click **Generate API Key** next to the **IoT/OT** category, choosing the
   **Risk Sharing API** key type.
3. Choose an expiry, or **Never Expires**. The key is shown once and is not
   retrievable after the window closes, so copy it now.
4. Copy the **API Endpoint URL** printed below the key. It looks like
   `https://<instance>.cloud.forescout.com`.
5. Confirm access. The window bounds are required in practice, and the API
   answers HTTP 400 when `from` equals `to`:

   ```bash
   curl -s -H 'Authorization: Bearer <api-key>' \
     'https://<instance>.cloud.forescout.com/api/data-exchange/v3/rem-asset-search?from_date_time_iso_utc=2026-05-01T00:00:00.000Z&to_date_time_iso_utc=2026-05-08T00:00:00.000Z&order_by=risk_score&sort_order=ASCENDING'
   ```

   A working response is `{"entities": [...], "total_hits": <int>}`. If it
   returns 401, try the same request with the key pasted bare --    `-H 'Authorization: <api-key>'` -- and see the header note under
   [Notes](#notes); the integration tries both by itself.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Forescout Risk and Exposure Management").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Forescout Cloud API endpoint URL** (`url`): the endpoint URL from step 4 above, for example `https://demo.cloud.forescout.com`.
   - **Risk Sharing API key** (`api_key`): the key from step 3.
   - **Sync strategy** (`sync_strategy`): optional; `incremental` (default) or `full`. `full` is a backfill, not a guarantee -- see [below](#assumptions-and-what-is-not-imported).
   - **Lookback window (days)** (`lookback_days`): optional; default 7.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

**Set `lookback_days` to at least the task interval.** The window is a
`last_seen` range, and there is no server-side checkpoint to resume from, so an
asset that has been quiet for longer than the window is not returned at all.
Forescout's own guidance for polling this service is an interval of 15 minutes
to 24 hours, so a daily task with the default 7-day lookback has a wide margin.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
see what a tenant returns before scheduling anything. `--kwargs` is repeated
once per parameter:

```bash
runzero script --filename forescout-rem/forescout-rem.star \
  --kwargs url=https://demo.cloud.forescout.com \
  --kwargs api_key=<risk-sharing-api-key> \
  --kwargs sync_strategy=incremental \
  --kwargs lookback_days=7 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./forescout-rem-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run. Add `--verbose` for the request-by-request log,
or omit `--output` to see only the log lines.

The log is where this integration says whether the import was complete, so read
it. A run that covered everything ends with a line like:

```
forescout-rem: reported 8412 assets from 137 search windows
```

A run that could not ends with a counted shortfall as well:

```
forescout-rem: 6 windows were still truncated after the maximum number of splits; about 8988 assets were not imported. Shorten the lookback and run the task more often.
```

`sync_strategy=full` searches a fixed ten-year window instead of the lookback.
It is the right setting for a first import and the wrong one for a schedule: the
number of search windows grows with the number of assets in range, so on a large
tenant it can exhaust its budget before reaching the whole estate. Check the log
for `windows were still truncated` and `windows never searched`, which name and
count the shortfall. Follow a `full` backfill with `incremental` on a schedule.

```bash
runzero script --filename forescout-rem/forescout-rem.star \
  --kwargs url=https://demo.cloud.forescout.com \
  --kwargs api_key=<risk-sharing-api-key> \
  --kwargs sync_strategy=full \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./forescout-rem-full --overwrite
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename forescout-rem/forescout-rem.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the key is accepted or that any asset is
parsed.

The fixtures under `forescout-rem/tests/fixtures/` exercise the parsing offline,
including the whole window-splitting strategy and the truncation report:

```bash
python3 tests/run.py forescout-rem
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat forescout-rem/forescout-rem.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://demo.cloud.forescout.com,api_key=<risk-sharing-api-key>,lookback_days=7' \
  --output ./forescout-rem-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Forescout Risk and Exposure Management.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:forescout-rem`.

## Asset identity

- Target entity: a physical device -- IT, OT, IoT, medical, or network -- as REM
  holds it after correlating what eyeSight, eyeInspect, the Edge Collectors and
  the medical device capability each saw.
- Source ID field: `entities[].id`
- Documentation evidence: **none exists.** Forescout publishes no schema for
  this API, so there is no sentence to quote. The evidence is behavioural, from
  the one shipped public client: its field mapping names `id` "Asset ID", it
  de-duplicates results across separate API responses keyed on `id` -- meaning
  the implementer treated it as an asset's identity across calls -- and it drops
  any entity that lacks one.
- Uniqueness scope: **tenant.** The base URL is a per-customer instance on a
  regional Forescout Cloud deployment, so an id means nothing outside it.
- Cardinality: one entity per device within one response. The same asset does
  come back from several *queries* -- adjacent risk bands and overlapping time
  windows -- which is a pagination artifact rather than a data-model statement,
  and the integration de-duplicates on `id` for exactly that reason.
- Stability: **not verified.** The plausible reading is that it survives
  re-addressing, rename and reboot, because REM is a correlation layer built to
  hold one record per device across sources, and because `ip_addresses` and
  `mac_addresses` are plural lists -- the shape of a record that accumulates
  addresses rather than being keyed by one. No source states it.
- Reuse behavior: **unknown.** Not documented, and not observable from the
  client.
- Presence: present in practice; the reference client defends against absence
  anyway, and so does this integration.
- Final runZero ID: `forescout-rem:<instance-hostname>:<entities[].id>`. The
  hostname is taken from the configured URL with the port stripped, because the
  port is not part of a tenant's identity and including it would re-key an
  entire estate the day the endpoint moved.
- Missing-ID behavior: skip. Entities with no `id` are counted and reported once
  at the end of the run as `skipped N entities with no asset id`. No random or
  synthesized ID is ever generated.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. See below.
- Verdict: **scoped authoritative but unproven.**

### Notes

- **Why `no-id-match no-id-break` when the id looks opaque and well-behaved.**
  A foreign-ID match in runZero is never disqualified by a conflicting MAC, IP,
  or hostname -- the break helpers are consulted only on the MAC, IP, and name
  match paths. So an id that turns out to be recycled after deletion, or to be
  issued more than once per physical device, merges two unrelated devices
  together and *nothing can veto it*. Both properties are unverified here, and
  REM ingests eyeInspect data, whose own integration documents two ways that
  source can hand different devices the same identifier. Given a question only
  a tenant can settle, the reversible choice is to leave the id out of matching
  and correlate on the MAC, IP, and hostname the entity already carries; the id
  is still emitted, so every record keeps a stable key across polls.
  `palo-alto-device-security`, `armis`, and `forescout-counteract` reach the
  same conclusion for their own identifier classes.

  If a tenant later shows `id` is stable and never recycled, the correct change
  is to drop `matchBehavior` back to the default (optionally with
  `no-mac-break no-ip-break no-name-break` for first-contact churn) and remove
  the correlator skip below. The conservatism is deliberately in the direction
  that can be undone: too little merging is a config change away, while a wrong
  merge has already destroyed the distinction.
- **Records with no MAC, IP, or hostname are skipped.** Because the id is barred
  from matching, such a record can never merge with anything -- it would create a
  fresh orphan asset on every poll. The count is reported once at the end as
  `skipped N assets with no MAC, IP, or hostname to correlate on`.
- **Assets** come from `GET /api/data-exchange/v3/rem-asset-search`.
  `hostname` becomes the hostname, `ip_addresses` and `mac_addresses` become the
  network interfaces, `rem_vendor` becomes the manufacturer, `rem_os` becomes
  the OS, `rem_model` becomes the model, and `last_seen` becomes `lastSeenTS`.
  `rem_function` becomes the device type, with `rem_category` standing in when
  it is absent. `rem_category`, `rem_function`, `rem_firmware`, `risk_score`,
  `risk_severity`, `risk_device_criticality`, `last_seen` and `last_seen_online`
  are kept as custom attributes prefixed `forescout_rem_`, and the category,
  severity and criticality also become `category:`, `risk:` and `criticality:`
  tags.
- **`deviceType` comes from `rem_function`, not `rem_category`.** `rem_function`
  is the device's role ("Infusion Pump", "PLC"), which is the grain runZero's
  device type expects. `rem_category` is a six-value estate class -- `IT`, `OT`,
  `IoT`, `Medical Device`, `Network Device`, `Unknown`, mirroring the Forescout
  UI's own Category filter -- which is more useful as a tag, and stands in as the
  device type only when the function is missing.
- **`rem_firmware` becomes a single `Software` record** with `rem_model` as the
  product and `rem_vendor` as the vendor, matching how `forescout-eyeinspect`
  handles `firmware_version`. It is the only software-shaped field this endpoint
  is known to return.

#### How this integration pages, and when it cannot

This is the part worth understanding before trusting a run.

- **The API has no pagination.** It caps every response at 1000 entities and
  honours no `limit`, `offset` or `page` parameter -- verified by the reference
  client against a live demo instance. The only completeness signal is
  `total_hits`: a response is complete when `total_hits` is absent or
  `len(entities) >= total_hits`.
- **So coverage comes from narrowing the query, not from turning pages.** When a
  response is truncated, the integration replaces that window with two narrower
  ones and asks again, driving the work from an explicit stack rather than
  recursion, which Starlark forbids.
- **Risk score is the primary narrowing axis.** Assets are stamped in
  `last_seen` bursts -- over a thousand can share a 20-second span -- that no
  datetime split can separate, while their risk scores still spread across the
  0.0-10.0 scale. Bands are halved in tenths, which is the API's own precision.
- **The time window is the fallback**, used only once a band has narrowed to a
  single tenth and is still truncated.
- **One call carries no risk bound at all, and it is not optional.** Sending
  *either* `risk_score_min` or `risk_score_max` makes the API drop assets scored
  exactly 0 -- the vendor's "risk score not available" class, unbounded in size
  and largest on freshly onboarded or passive-only estates -- and no later banded
  query can recover them. The unbounded call is ordered by `risk_score`
  ASCENDING so its page starts at the bottom of the scale. The reference client
  verified this live: over a 14-day window, `last_seen` ordering surfaced 0
  zero-score assets and `risk_score` ordering surfaced all 8. When that probe
  is itself truncated it is narrowed on time rather than accepted, since
  nothing else can see what it missed.
- **Assets returned by more than one window are imported once**, de-duplicated
  on `id`, and the count is logged.
- **The split allowance follows the size of the search window.** The two axes
  share one depth counter, and the risk axis always costs seven halvings to
  reduce 0.0-10.0 to a single tenth, so a fixed ceiling would leave a fixed
  number of time bisections whatever the window is: the five that give the
  7-day default a floor of about five hours give a ten-year window a floor of
  **114 days**, which is not coverage of anything. The time allowance is
  therefore derived -- halve until a slice is no longer than six hours -- which
  leaves the 7-day default at five halvings and gives `sync_strategy=full`
  fourteen. `tests/fixtures/window-scaled-depth.json` pins the derivation by
  running the same estate over a one-day window.
- **A truncated window is never passed off as a complete one.** When even the
  finest slice comes back truncated, the shortfall is counted and reported:

  ```
  forescout-rem: 6 windows were still truncated after the maximum number of splits; about 8988 assets were not imported. Shorten the lookback and run the task more often.
  ```

  Depth is not what bounds a run -- `CONFIG["maxPages"]` (5000) is, and a run
  that exhausts it reports `gave up with N windows never searched`. Either way
  the remedy is the same: a shorter `lookback_days` and a more frequent task,
  which puts fewer assets in each window.

#### Assumptions and what is not imported

- **The whole contract is a reconstruction.** Forescout publishes no REST API
  reference for the cloud platform and no Swagger for this API is public. The
  endpoint, query parameters, `{"entities": [...], "total_hits": N}` envelope,
  1000-entity cap, zero-score trap and all fifteen field names come from the
  Netskope Cloud Exchange plugin **Forescout eyeFocus** v1.0.0, a working client
  whose comments record behaviour verified against a live demo tenant. This
  integration was validated against local fixtures, not a live Forescout tenant.
- **The `Authorization` header form is ambiguous, so both are tried.** The
  reference client sends `Bearer <key>` and works; Forescout's prose for the
  sibling SCIM API says to paste the key bare, and it documents no header for
  this API at all. The integration sends `Bearer` first and retries once with
  the bare key on a 401. `tests/fixtures/auth-fallback.json` covers that path:
  its fixture server answers 401 to anything carrying a `Bearer` prefix and 200
  otherwise, so an asset coming back at all is what proves the retry dropped the
  prefix.
- **`sync_strategy=full` is a fixed ten-year window, not an absent one**,
  because `from_date_time_iso_utc` is required in practice. Ten years is longer
  than Forescout Cloud has existed, so no asset falls outside the window -- but
  that is not the same as retrieving every one of them, since the run is bounded
  by `CONFIG["maxPages"]` and a large tenant can exhaust it. The log says so and
  counts what was missed. Treat `full` as a first backfill, not a guarantee, and
  run `incremental` on a schedule after it.
- **No vulnerabilities are imported.** REM certainly has them -- eyeFocus has a
  Vulnerabilities chapter, Microsoft's Security Copilot plugin documents a
  CVE-search prompt against its "Get REM assets" capability, and the eyeFocus
  properties page lists Vulnerability ID, Title, Score, Details and
  Exploitability. But those are eyeSight host-property display names, not JSON
  keys, and they describe the cloud-to-appliance enrichment channel rather than
  this response. No public source names a field on a `rem-asset-search` entity
  that carries a CVE, and guessing one would produce an integration that
  quietly imports nothing.
- **No services are imported.** The same properties page names **Exposed
  Services**, which suggests REM tracks something service-shaped, but no port,
  protocol or transport field appears in any source. Synthesizing services from
  nothing would be worse than omitting them.
- **The entity may well carry more than fifteen fields.** Microsoft's Defender
  Exposure Management connector for Forescout states that it ingests serial
  number and associated edge collectors alongside everything mapped here, which
  implies at least two more fields under names nobody has published. Absence
  from the field list means "not read by the one public client", not "does not
  exist".
- **The path may be migrating.** The reference client's own comment records that
  a Swagger reference lists this operation under `/api/risk-sharing/v3/`, and
  that the path returns HTTP 400 on the demo instance, while
  `/api/data-exchange/v3/` is what the working cURL samples use. This
  integration calls `data-exchange/v3` only.
- **Rate limits are undocumented.** The reference client treats 429 and 5xx as
  retryable and honours `Retry-After`; `get_json` already does the same, so no
  retry or backoff is hand-rolled here. Forescout's only quantitative pacing
  guidance for this service is a polling interval of 15 minutes to 24 hours.

## Future

- **Vulnerabilities, once a real response body is available.** This is the
  single change that would most alter the integration: it decides whether this
  is an inventory-plus-risk-score import or a full inventory-plus-findings one.
  The answer is one `curl` against a tenant.
- **`GET /api/data-exchange/v3/active-detections`.** Same namespace, polled
  *downward* by the on-premise Cloud Data Exchange plugin on a "Detection
  Polling Interval", and sounds like a findings feed. The CDE documentation
  frames every listed path as an upload direction, so whether a Risk Sharing key
  can read it is unresolved.
- **`GET /api/data-exchange/v3/rem-assets`, the "REM Properties API".** The CDE
  troubleshooting page names it that, which reads as risk and classification
  properties keyed to an asset rather than standalone inventory. If it carries
  the vulnerability and exposed-service properties the eyeFocus properties page
  lists, it is the natural enrichment pass to run alongside the search.
- **Serial number and edge-collector attribution.** Microsoft's connector
  ingests both, so both exist under some key. Edge-collector attribution would
  let a coverage report blame a gap on a specific collector.
- **A path fallback.** If Forescout is migrating this operation to
  `/api/risk-sharing/v3/`, trying one path and falling back to the other would
  survive the change without a script edit.
- **Narrowing by category.** There is no documented category parameter -- the
  reference client filters `rem_category` client-side. If one exists, it would
  be a much cheaper narrowing axis than risk banding for an operator who wants
  only the OT or medical estate.

## API documentation

Forescout publishes no REST reference for this API. These are the sources the
contract was reconstructed from.

- Reference client (endpoint, cap, parameters, field mapping, pagination behaviour, zero-score trap): https://github.com/netskopeoss/ta_cloud_exchange_plugins/tree/main/forescout_eyefocus_ztre
- Cloud Data Exchange plugin, API endpoint list (independently contains `/rem-assets`): https://docs.forescout.com/fs-cloud/cloud-data-exchange-plugin/cloud-data-exchange-plugin/api-endpoints.htm
- Cloud Data Exchange plugin, regional base URLs: https://docs.forescout.com/fs-cloud/cloud-data-exchange-plugin/cloud-data-exchange-plugin/url-endpoints.htm
- Cloud Data Exchange settings ("In the API Key Type, select Risk Sharing API"): https://docs.forescout.com/fs-cloud/cloud-data-exchange-plugin/cloud-data-exchange-plugin/cloud-data-exchange-settings.htm
- Generating an API key, and the three key categories: https://docs.forescout.com/fs-cloud/cloud-admin-guide/cloud-admin-guide/generate-an-api-key-for-application-integration.htm
- eyeFocus properties pushed back into eyeSight (the evidence that vulnerability and exposed-service data exists): https://docs.forescout.com/fs-cloud/eyefocus/eyefocus/properties.htm
- eyeFocus assets documentation: https://docs.forescout.com/fs-cloud/eyefocus/eyefocus/assets.htm
- Microsoft Security Copilot plugin for Forescout REM ("Get REM assets", key generation): https://learn.microsoft.com/en-us/copilot/security/plugin-forescout-rem
- Microsoft Defender Exposure Management Forescout connector (the field list that implies serial number and edge collectors): https://learn.microsoft.com/en-us/defender/exposure-management/forescout-data-connector

# Custom Integration: Cisco Cyber Vision

Cisco Cyber Vision is the OT/ICS visibility product that runs on a Center appliance
and passively builds an inventory of industrial devices from network sensors. This
integration imports that inventory into runZero over the Center's v3.0 API, together
with the hardware and firmware properties the Center normalizes and the
vulnerabilities it attributes to each device.

**Read this before deploying it.** No public sample response exists for the Cyber
Vision device API: Cisco's OpenAPI specification is only downloadable from inside a
Center (Admin > API > Documentation). Every field name this integration reads is real,
taken from DevNet or from Cisco's own published export script, but the response
*shapes* in `tests/fixtures/` were constructed from those names rather than recorded
from a Center. The parser is defensive for that reason: every field is optional, both
a bare array and a wrapped object are accepted, and no single malformed row can end
the run. Confirm the shapes against a live Center before treating a green import as
proof of completeness. The open questions are listed under
[Asset identity > Notes](#notes).

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Cyber Vision Center's HTTPS interface.

## Cisco Cyber Vision requirements

- A Cyber Vision Center, version 4.x or 5.x, reachable over HTTPS from the Explorer.
- An API token created on the Center under **Admin > API > Token**. The token is sent
  in the `x-token-id` header on every request, which is what Cisco documents and what
  Cisco's own sample client does.
- Centers ship with a self-signed certificate unless one has been installed, so the
  standard **Disable TLS validation** option (`tls_disable_validation`) may be needed.
  Prefer installing a trusted certificate on the Center.
- One credential covers one Center. Device ids are allocated per Center, so a
  multi-Center estate needs one credential and one task per Center. See the note on
  Global Center below.

## Steps

### Cisco Cyber Vision configuration

1. Sign in to the Cyber Vision Center as an admin and open **Admin > API > Token**.
2. Create a token and record it. Cisco's documented header example looks like this,
   and the `ics-` prefix is part of the token value:

   ```
   x-token-id: ics-458dfdf1d26241dadc7428ad1deca7e9ce3fdd47ca6bae
   ```

3. Confirm the token works, and find out which of the two inventory routes this
   Center serves:

   ```bash
   # The bare device list. Preferred, and what this integration tries first.
   curl -sk -H 'x-token-id: <token>' \
     'https://<center>/api/3.0/devices?page=1&size=5'

   # The route Cisco's own export script uses, via the "All data" preset.
   curl -sk -H 'x-token-id: <token>' 'https://<center>/api/3.0/presets'
   curl -sk -H 'x-token-id: <token>' \
     'https://<center>/api/3.0/presets/<all-data-preset-id>/visualisations/networknode-list?page=1&size=5'

   # The findings for one device, which is where the CVSS scores come from.
   curl -sk -H 'x-token-id: <token>' \
     'https://<center>/api/3.0/devices/<device-uuid>/vulnerabilities'
   ```

   Look at what comes back before scheduling anything. Three things could not be
   settled from public documentation and are worth checking in that output: whether
   the rows carry an `isDevice` flag, whether `page`/`size` or `limit`/`offset` is the
   pagination the Center honours, and whether a device's vulnerability list already
   includes the findings its components carry. See [Notes](#notes).

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Cisco Cyber Vision").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Cyber Vision Center URL** (`url`): the Center's base URL, for example
     `https://cybervision.example.com`. The `/api/3.0` path is appended automatically.
   - **API token** (`api_token`): the token from **Admin > API > Token**.
   - **Inventory source** (`inventory_source`): optional; `auto` (default), `devices`,
     or `preset`. `auto` reads `/api/3.0/devices` and falls back to the preset network
     node list if the Center refuses it. Pin one route once you know which one the
     Center serves.
   - **Preset label** (`preset_label`): optional; default `All data`. Only used on the
     preset route.
   - **Collect vulnerabilities** (`collect_vulnerabilities`): optional; default on.
     Costs one extra request per device that reports a non-zero
     `vulnerabilitiesCount`. Turn it off for a fast inventory-only import.
   - **Page size** (`page_size`): optional; default 500, maximum 2000.
   - **Disable TLS validation** (`tls_disable_validation`): set it if the Center still
     uses its self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token and see what a Center actually returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename cisco-cyber-vision/cisco-cyber-vision.star \
  --kwargs url=https://cybervision.example.com \
  --kwargs api_token=ics-458dfdf1d26241dadc7428ad1deca7e9ce3fdd47ca6bae \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cyber-vision-run
```

`--output` writes the assets the run produced, `--overwrite` replaces a directory from
a previous run (the scanner refuses an existing one otherwise), and `--verbose` adds
the request-by-request log. Add `--kwargs inventory_source=preset`,
`--kwargs preset_label='All data'`, or `--kwargs collect_vulnerabilities=false` to pin
one route or skip the per-device vulnerability walk.

The run log says what happened to every row it did not import. Component rows, rows
with no id, and devices with nothing to correlate on are each counted and reported on
one line, so a surprising asset count has an explanation in the log.

To check the `CONFIG` block and the HTTP and TLS wiring without a live Center:

```bash
runzero script --filename cisco-cyber-vision/cisco-cyber-vision.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly, and
issues a request. It does not prove the token is accepted or that any device is
parsed. The fixtures under `cisco-cyber-vision/tests/fixtures/` exercise the parsing
offline, covering the device/component case, both inventory routes, paging, rate
limiting, malformed records, the vulnerability field mapping, and the millisecond
activity timestamps:

```bash
python3 tests/run.py cisco-cyber-vision
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat cisco-cyber-vision/cisco-cyber-vision.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://cybervision.example.com,api_token=<token>' \
  --output ./cyber-vision-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page and
`--custom-integration-entry-function-name` defaults to `main`.
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes one
comma-separated string, so no value containing a comma can be passed that way. Prefer
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Cisco Cyber Vision.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:cisco-cyber-vision`.

## Asset identity

- Target entity: the physical industrial device Cyber Vision has learned about (a
  PLC, RTU, HMI, drive, engineering workstation, or network device), and **not** its
  constituent components.
- Source ID field: `id`
- Documentation evidence: https://developer.cisco.com/docs/cyber-vision/5-3/risk-score-of-a-device/
  declares the path parameter `id` as a required `string` described as **"device id
  (uuid)"**. The same `id` is the path parameter of every per-device route, including
  `/api/3.0/devices/{id}/vulnerabilities` and the label patch route used by Cisco's
  own export script.
- Uniqueness scope: **per Center.** Ids are allocated by one Cyber Vision Center; the
  API has no tenant above it, and there is no evidence that a Global Center preserves
  the ids of the Centers it aggregates. The Center hostname is therefore folded into
  the runZero id.
- Cardinality: one row per device *after* components are filtered out, which is the
  hazard in this API. See the first note below.
- Stability: **survives rename, structurally.** The model keeps `originalLabel` and
  `customLabel` as separate fields from `label`, and Cisco's own script renames a
  device by patching `label` while addressing it by `id`. Survival of an IP or MAC
  change is an **assumption, not a documented fact**: `ip` and `mac` are ordinary
  attributes and `id` is a UUID rather than a derived key, which is strong
  circumstantial evidence, but Cisco does not state it.
- Reuse behavior: **not documented.** UUID allocation makes deliberate reuse
  unlikely, but it has not been confirmed that a deleted device's id can never be
  issued again.
- Presence: always present. It is the required path parameter of every per-device
  route, so a row without one is malformed.
- Final runZero ID: `cisco-cyber-vision:<center-hostname>:<id>`, for example
  `cisco-cyber-vision:cybervision.example.com:0f3c1a8e-6d2b-4c19-9a77-3f5b1c2d4e60`.
  The hostname comes from the configured URL with the scheme and **port stripped**, so
  moving the Center to a different port does not re-key its whole estate.
- Missing-ID behavior: **skip.** Rows with no id are counted and reported as
  `skipped N rows with no device id`. No id is ever synthesized, and `new_uuid()` is
  never used, because a random id would create a fresh asset on every poll.
- Match behavior: **the platform default**, so `matchBehavior` is deliberately absent
  from `CONFIG`. The id is an opaque Center-allocated UUID rather than an address, so
  it cannot be recycled onto a different device the way a MAC- or IP-derived key can,
  and `no-id-match` would discard the best signal this source has. The `-break` flags
  were considered and rejected: a break flag governs only **first contact**, since
  nothing can veto a merge once the foreign id matches, and before the first import
  the single primary MAC and IP on each row are real observations off the wire and are
  the right signals for finding the asset runZero already has.
- Verdict: **scoped authoritative.** The id identifies a device and only a device,
  within one Center, once component rows have been removed.

### Notes

- **Devices and components are siblings in the same list, and importing both would
  double-count the estate.** Cyber Vision models a physical device as a container for
  one or more components, and the preset network node list returns both as flat rows
  told apart only by the `isDevice` boolean, so one PLC with two Ethernet ports and a
  backplane module arrives as four rows carrying overlapping addresses. Only rows
  where `isDevice` is not false are imported; the dropped components are counted and
  reported on one line. `tests/fixtures/happy.json` and
  `tests/fixtures/preset-fallback.json` both assert that a device plus its components
  yields exactly one asset, and that the component ids are absent from the result.
  - A row with **no** `isDevice` field is treated as a device. `/api/3.0/devices` is
    not documented to include or exclude components, so the flag is honoured on both
    routes; assuming its presence would import nothing from a Center that omits it.
  - **Component detail is not attached to its parent.** No public field relates a
    component to its device, so rather than guess at a name, components are dropped.
    The cost is the addresses that live only on a component, meaning a multi-homed
    device's secondary interfaces. `/api/3.0/components` is listed under Future.
  - **Component-scoped findings may be missing.** Cisco's own script calls
    `/api/3.0/components/{id}/vulnerabilities` for component rows; here only the
    device route is ever called, and whether it rolls its components' findings up
    **could not be verified**. The one hint points at a rollup: on that route's DevNet
    page `matchingTime` is described as *"at which time the **component** has been
    found vulnerable"*. Check it on a live Center by comparing a device's
    `vulnerabilitiesCount` against its vulnerability list and its components' counts.
- **Assets** come from `GET /api/3.0/devices` with `page` and `size`, streamed to
  runZero one page at a time. `label`, `customLabel`, and `originalLabel` become
  hostnames after `clean_hostnames` drops placeholders and values that are really IP
  addresses: Cyber Vision names an unidentified node after its address, and such a
  name would follow the address to whichever node holds it next. `ip` and `mac` become
  the network interface, with loopback and link-local addresses filtered out. A device
  with no usable address and no usable name is skipped, since it could never merge
  with anything and would only accumulate as a stub.
- **Hardware detail comes from `normalizedProperties`**, a documented list of
  `{key, value}` pairs. `vendor-name` becomes the manufacturer, `model-name` the
  model, and `vendor-name`/`model-name`/`fw-version` together produce one firmware
  `Software` record (`hw-version` and `model-ref` ride along as attributes). Every
  property is also copied to a `cisco_cyber_vision_property_*` attribute, so
  properties beyond the five Cisco's script names are preserved. **`otherProperties`**
  carries whatever the Center learned but did not normalize; its entries become
  `cisco_cyber_vision_other_property_*` attributes, bounded at 32 per device and
  sorted by key so the same 32 are chosen on every poll.
- **`deviceType` is the Center's own device class** and is set on the asset when the
  row carries one; the longer `deviceTypeDescription` is kept as a custom attribute
  beside it. The `icon` path is never used for this, because deriving a class from a
  filename such as `library/default.svg` would label most of an estate "default". The
  icon is kept as an attribute.
- **`os` and `osVersion` are deliberately not set.** `fw-version` is a firmware
  revision, not an operating system version, and an `osVersion` with no `os` beside it
  reads as a fingerprinting result the Center never produced. Firmware is carried on
  the `Software` record and as an attribute instead.
- **Vulnerabilities** come from `GET /api/3.0/devices/{id}/vulnerabilities`, one
  request per device, gated on `vulnerabilitiesCount > 0` exactly as Cisco's own
  script gates it and gated again on the `collect_vulnerabilities` toggle. Up to 99
  findings are attached per asset.
  - **The response schema for this route is published**, and the fields are read by
    name: `cve`, `title`, `summary` (falling back to `fullDescription`), and
    `solution`. `CVSSVersion`, `CVSSVectorString`, `CVSSTemporal`, `vendorId`, the
    finding's own `id`, the acknowledgement fields, and the raw `cve` string become
    custom attributes; `publishTime`, `matchingTime`, and `lastUpdate` become the
    published, first-detected, and last-detected times. DevNet spells these in camel
    case while Cisco's own script reads `CVSS_vector_string` and `full_description`
    off the same route, so both spellings are accepted.
  - **A finding that names no CVE is still imported**, under its title. A Cisco vendor
    advisory arrives with `cve` null and a real `title`, `CVSS`, `summary`, `solution`
    and `vendorId`. Only a row with no CVE, no id, no `vendorId` and no title is
    skipped, because nothing stable would key it. The run log reports both counts.
  - **`cve` is read from the `cve` field first**, with a scan of the rest of the row
    as a fallback for a Center that records the identifier elsewhere. Either way the
    value is upper-cased and checked against `^CVE-[0-9]{4}-[0-9]{4,19}$` before it is
    asserted, because `Vulnerability.cve` is validated by the platform, is not
    upper-cased for the script, and a malformed value fails the whole record. A
    finding that fails the check imports under its title with the raw string kept as
    `cisco_cyber_vision_cve_raw`.
  - **Severity comes from `CVSS`**, a documented 0-10 double. It sets
    `severityScore`/`riskScore` and drives the 0-4 `severityRank`/`riskRank` (9.0+
    critical, 7.0+ high, 4.0+ medium, above 0 low), so nothing is guessed from an
    unpublished vocabulary. The platform accepts a score above 10 without complaint,
    so an out-of-range value is capped at 10.
  - Finding ids are namespaced like asset ids:
    `cisco-cyber-vision:<center-hostname>:<device-id>:cve:<CVE>`, or `:finding:<id>`
    for an advisory with no CVE.
- **Tags** come from the `tags` array (`label` on each entry, with bare strings
  accepted as a fallback shape) and from `group.label` as a `group:` tag. `group`'s
  `color` and `criticalness` become custom attributes, as do `riskScore`,
  `bestAchievableScore`, `vulnerabilitiesCount`, and `icon`.
- **Timestamps come from `firstActivity` and `lastActivity`** and become `firstSeenTS`
  and `lastSeenTS`. **They are epoch milliseconds**: the activity list documents its
  sibling `from` and `to` parameters as *"ms since January 1, 1970 UTC"*, so the value
  is parsed with an explicit millisecond unit rather than by guessing at its
  magnitude. Two guards ride along, because a bad timestamp is worse than none:
  - A zero, or a year-1 `0001-01-01T00:00:00Z`, is what a Center writes for "never",
    and both survive a plain null check, so anything resolving before 2000-01-01 is
    treated as unusable. That floor also catches a Center reporting seconds instead of
    milliseconds, which would otherwise import an estate last seen in January 1970.
  - A future timestamp is clamped to now by the shared parser, because the platform
    drops **the entire record** when first- or last-seen is ahead of now. The raw
    values are always kept as `cisco_cyber_vision_first_activity` and
    `cisco_cyber_vision_last_activity`, the only place what the Center sent survives.
- **No service or port data is imported.** Cyber Vision derives connectivity from its
  activity and flow endpoints rather than from the device object, and it could not be
  verified that those expose listening ports in a form worth importing as services.
- **Pagination is the largest unverified assumption in this integration.** DevNet
  documents `page` and `size`, while Cisco's own sample client sends `limit` and
  `offset` with a batch size of 2000. Which of the two `/api/3.0/devices` honours
  could not be verified, so `page` and `size` are sent on both routes: they are what
  DevNet documents and what the one public client that calls the device list sends.
  Termination matches Cisco's client and is the same in both styles: stop on an empty
  page, or on a page shorter than the one requested. **A Center that ignores the
  parameters would return page 1 forever**; on the preset route a repeat-page guard
  compares each page's row count and its first and last id against the previous page
  and stops with a log line, and `maxPages` (10000) bounds the rest. If the first
  import returns one page of data over and over, this is the thing to check.
- **Two inventory routes, and the Center decides which one works.** The DevNet page
  for the bare list route could not be located, and its query shape is corroborated
  only by a third-party client; the preset network node list is what Cisco's *own*
  published script uses, under a candid comment calling it a hack to get all devices
  via the "All data" preset. `inventory_source=auto` therefore tries
  `/api/3.0/devices` and falls back to the preset route when the Center refuses it.
  The fallback fires only when the **first** request fails and nothing has been
  imported yet, so a failure part-way through a walk cannot restart the inventory on
  the other route and report every device twice.
- **The per-device vulnerability walk is an N+1, and the one candidate for removing it
  did not survive checking.** A third-party client (`mevlut36/Cisco-Cyber-Vision-API`)
  builds `/devices?from={}&to={}&page={}&size={}&vulnerabilities={}`, which would
  inline the findings and, with `from`/`to`, allow an incremental sync. Nothing
  corroborates it: Cisco's own export script walks the per-device route instead, the
  Faraday connector does not send it, and the DevNet page for
  `/devices/{id}/vulnerabilities` documents no query parameters at all. That same
  client is demonstrably unreliable elsewhere, sending `Authorization: Bearer` where
  Cisco documents `x-token-id` and doubling the `/api/3.0` prefix in one function, so
  its header choice is not followed either. Since a Center that rejects an unknown
  query parameter would fail the whole device walk rather than ignoring it, the
  parameter is **not** sent. If a live Center accepts `vulnerabilities=true`, this
  collapses to zero extra requests and is the first optimisation worth making.
- **Rate limits are not published.** Cisco's own script pulls 2000 rows per call with
  no throttling, which suggests the Center tolerates large pages. Requests use the
  shared HTTP helper's default retry behaviour (three retries with exponential backoff
  on 408/425/429/5xx, honouring `Retry-After`).
- **Token lifetime is not published.** The token is a static header credential, so the
  integration builds its request options once and has no refresh flow. If a future
  Center expires tokens, the symptom is a run that fails part-way with a 401, not
  silent data loss. There is deliberately no `auth-refresh` fixture.
- **One Center per credential.** Ids are Center-scoped and are namespaced on the
  Center hostname, so two Centers imported into one runZero account stay distinct.
  Cyber Vision Site Manager is the newer multi-site plane, but its published
  capabilities are fleet management rather than aggregate inventory, and it could not
  be verified that it exposes a cross-Center asset API. Whether a Global Center
  re-keys the assets it aggregates is likewise unverified; if it does, importing both
  a Global Center and its member Centers would produce two assets per device with no
  shared id, and the merge would have to happen on MAC and IP.
- **The API is titled "Classic API" as of 5.5**, which implies a successor exists. No
  public documentation for one was found, so an integration built on v3.0 may face a
  migration.

## Future

- **Import components as their own asset population.** `/api/3.0/components` is a
  documented route, and components carry the addresses a multi-homed device's device
  row does not. The blocker is not the fetch but the relationship: nothing public
  relates a component to its parent device, so importing them today would produce
  unattached assets that merge into their parents by MAC and IP unpredictably. If a
  live Center publishes a parent reference, the clean shape is to keep devices as the
  primary population and attach each component's id, label, and addresses to its
  parent; if they must be separate assets, label them `assetType="component"` and give
  that population its own `assetTypeBehavior` policy so a component never merges into
  its own parent.
- **Protocol and credential observations.** `GET /api/3.0/devices/{id}/credentials`
  names the protocols a device speaks, which is genuinely useful OT context, but it is
  another N+1 walk with an undocumented response shape.
- **Activities as connectivity.** `/api/3.0/presets/{id}/visualisations/activity-list`
  and the activity routes describe which devices talk to which, with protocol detail.
  That is edge data rather than asset data, but it is the raw material for a
  segmentation or Purdue-level report.
- **Sensors as assets.** `/api/3.0/sensors` enumerates the Cyber Vision sensors
  themselves: IE3400s, IC3000s, and Catalyst switches running the sensor application.
  Those are real network devices carrying the Center's own view of their health.
- **Groups and networks as tags.** `/api/3.0/groups` and `/api/3.0/networks` carry the
  operator's own segmentation of the plant. The device row already exposes its group,
  so the marginal value is the hierarchy and the network definitions.
- **Vulnerability-first collection.** `/api/3.0/vulnerabilities` and the preset
  `vulnerability-list` routes invert the walk: fetch the findings once and expand each
  to the devices it affects, which is what the Faraday connector does. On a Center
  where most devices are clean that is far fewer requests, but it trades one request
  per affected device for one per distinct finding, and the per-device route is the
  one whose response schema is published.
- **Incremental sync.** If `/api/3.0/devices` accepts the `from` and `to` parameters
  the activity routes document, a scheduled task could read only what changed since
  the last run. Their acceptance on the device route is unverified.
- **Component-scoped findings.** See the known gap under Notes. If a live Center shows
  that a device's vulnerability list does not include what its components carry, the
  component route has to be walked as well.

## API documentation

- Cyber Vision API index: https://developer.cisco.com/docs/cyber-vision/
- Getting started, base URL `https://<center>/api/3.0/`: https://developer.cisco.com/docs/cyber-vision/getting-started/
- Authentication, the `x-token-id` header, and Admin > API > Token: https://developer.cisco.com/docs/cyber-vision/authentication/
- Activity list, documenting the `page` and `size` pagination parameters, `from`/`to` as "ms since January 1, 1970 UTC", and the `ShortComponent` schema: https://developer.cisco.com/docs/cyber-vision/5-3/activity-list/
- Risk score of a device, documenting `id` as "device id (uuid)" and carrying `deviceType` on the embedded device object: https://developer.cisco.com/docs/cyber-vision/5-3/risk-score-of-a-device/
- Vulnerability list of a device, the response schema every finding field is read from (`cve`, `CVSS`, `CVSSVersion`, `CVSSVectorString`, `CVSSTemporal`, `title`, `summary`, `fullDescription`, `solution`, `vendorId`, `publishTime`, `matchingTime`, `lastUpdate`, `links`, `reasons`, and the acknowledgement fields): https://developer.cisco.com/docs/cyber-vision/5-3/vulnerability-list-of-a-device/ and https://developer.cisco.com/docs/cyber-vision/5-2/vulnerability-list-of-a-device/
- Cisco's own published API scripts, the source for the device field names, the
  preset network node list route, the per-device vulnerability route, and the
  `limit`/`offset` paging: https://github.com/CiscoDevNet/cisco-cyber-vision-api-scripts
  (`api.py` for the session and paging, `device.py` for the device and vulnerability
  export)
- The full OpenAPI specification is not published on the web. Download it from a
  Center at **Admin > API > Documentation** and confirm the shapes noted above
  against it.

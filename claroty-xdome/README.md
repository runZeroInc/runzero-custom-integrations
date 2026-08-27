# Custom Integration: Claroty xDome

Claroty xDome (formerly Medigate) is the cloud healthcare, IoT and OT device
security platform. This integration imports its device inventory, and the
vulnerabilities attached to each device, into runZero through the xDome public
API at `/api/v1/`.

This is **not** the Claroty CTD/EMC on-premise appliance, which speaks a
different API entirely (`/ranger/` paths, a login endpoint, session cookies) and
ships as `claroty-ctd`. Point this integration only at a cloud xDome tenant.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Claroty xDome requirements

- An xDome tenant and the regional API host it is served from: `https://api.claroty.com`
  for US, `https://eu.api.claroty.com` for EU, and `https://api.medigate.io` for
  legacy Medigate tenants. Regional hosts of the form `https://<region>.medigate.io`
  also exist (for example `demo-api.medigate.io`).
- An **API User** created under **Admin Settings > User Management**, holding the
  **Read-Only User** role.
- **Site permissions** granted to that user for every site the integration should
  see. This is not cosmetic: site-level permissions decide which assets and which
  vulnerabilities the token can read, so a token scoped to a subset of sites
  returns a subset of the inventory silently and successfully. Enable
  "Including future sites" if new sites should be picked up automatically.
- An API token generated for that user. The expiry date is chosen when the token
  is created, the value is displayed exactly once, and **there is no refresh
  endpoint**: remediation for an expired token is generating a new one.
- Network egress from the Explorer to the chosen API host over HTTPS.

## Steps

### Claroty xDome configuration

1. In xDome, open **Settings > Admin Settings > User Management** and add a user
   whose type is **API User**, with the **Read-Only User** role.
2. Grant the user **Site Permissions** for the sites to import.
3. Click **Generate Token**, choose a **Token Expiration** date, and copy the
   token. It cannot be viewed again.
4. Confirm access. Every xDome endpoint is a `POST` carrying a JSON body (there are
   no `GET` routes and no query-string parameters) and `fields` is required:

   ```bash
   curl -s -X POST https://api.claroty.com/api/v1/devices/ \
     -H "Authorization: Bearer <your token>" \
     -H 'Content-Type: application/json' \
     -d '{"fields":["uid","asset_id","device_name","ip_list","mac_list"],
          "offset":0,"limit":5,"include_count":true,
          "filter_by":{"field":"retired","operation":"in","value":[false]},
          "sort_by":[{"field":"uid","order":"asc"}]}'
   ```

   The trailing slash on `/api/v1/devices/` is part of the documented path. A
   `422` response means one of the `fields` values was rejected; see
   **The `fields` parameter** below, which is the single most likely thing to go
   wrong on a first run.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Claroty xDome").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **xDome API URL** (`url`): the regional API host, default `https://api.claroty.com`. The `/api/v1` path is appended automatically.
   - **API token** (`api_token`): the token generated for the API user.
   - **Import vulnerabilities** (`import_vulnerabilities`): optional; default on. Turning it off removes a second full pagination pass over the tenant.
   - **Include retired devices** (`include_retired`): optional; default off. See the note below; this one matters.
   - **Include irrelevant vulnerabilities** (`include_irrelevant_vulnerabilities`): optional; default off.
   - **Page size** (`page_size`): optional; default 5000, which is the documented maximum.
   - **Device fields** (`device_fields`): optional; comma-separated override for the requested device field list. Leave blank unless a request is rejected with a 422.
   - **Vulnerability fields** (`vulnerability_fields`): optional; the same override for the relation endpoint.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token and see what the tenant returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename claroty-xdome/claroty-xdome.star \
  --kwargs url=https://api.claroty.com \
  --kwargs api_token=exampletokenvalue1234567890 \
  --kwargs page_size=500 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./claroty-xdome-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run (the scanner refuses an existing `--output` directory
otherwise). Add `--verbose` for the request-by-request log. Omit `--output` to see
only the log lines.

To skip the vulnerability pass and import the inventory alone, which halves the
request count on a large tenant:

```bash
runzero script --filename claroty-xdome/claroty-xdome.star \
  --kwargs url=https://api.claroty.com \
  --kwargs api_token=exampletokenvalue1234567890 \
  --kwargs import_vulnerabilities=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./claroty-xdome-devices
```

`--kwargs` hands the value to the script verbatim, commas included, as long as
the pair contains a single `=`. Only a value carrying a *second* `=` as well as a
comma is re-read as CSV: it is cut off at the comma, with the remainder becoming a
second, fabricated parameter rather than rejected. `device_fields` and
`vulnerability_fields` are comma-separated by design and are safe; wrap an opaque
token in double quotes if it happens to be that shape,
`--kwargs '"api_token=a=b,c"'`, doubling any double quote inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename claroty-xdome/claroty-xdome.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove the token is accepted, that
the field list is valid for a tenant, or that any device is parsed.

The fixtures under `claroty-xdome/tests/fixtures/` exercise the parsing offline,
including the paging, `null`-array, malformed-record, rate-limit, 422 field-list
and identity-stability cases:

```bash
python3 tests/run.py claroty-xdome
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat claroty-xdome/claroty-xdome.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.claroty.com,api_token=<token>' \
  --output ./claroty-xdome-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so `device_fields` cannot be passed this way at all.
Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Claroty xDome.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:claroty-xdome`.

## Asset identity

- Target entity: physical IT, OT, IoT and medical devices observed on the network by xDome.
- Source ID field: `devices[].uid`
- Documentation evidence: Claroty's own OpenAPI 3.1 document for the Medigate/xDome API describes `uid` as "A universal unique identifier (UUID) for the device". Three independent facts confirm it is *the* key rather than merely *a* key: it is the **default sort order** for `/api/v1/devices/` (`[{"field": "uid", "order": "asc"}]`), the write endpoint `/api/v1/device-alert-status/set` **addresses devices by it** (`{"field": "uid", "operation": "in", "value": [<uuids>]}`), and the Cortex XSOAR pack documents its `device_uids` argument as "Device UUIDs, as indicated in the `uid` field of a device", joining the relation endpoints back to the inventory on that value.
- Uniqueness scope: **effectively global.** The value is a canonical v4-shaped UUID (`0d4b011f-fe47-46d0-9b9c-b102e3309aaa`, `8e7354b2-c6e9-46a0-bca6-3bb9c7bb05c9`), so a collision between two tenants would require a deliberately reissued random value. No vendor statement addresses cross-tenant uniqueness either way; the UUID format is the only evidence.
- Cardinality: **one row per device, documented.** A multi-homed device stays a single row and expresses its interfaces as parallel arrays rather than as several rows; see the multi-NIC note below. The relation endpoints are a different grain (one row per device/vulnerability pair) and are never used to build inventory.
- Stability: `uid` is a distinct field from every mutable one. `device_name` is explicitly user-editable ("You can also set it manually"), as are `labels`, `assignees` and `note`. `ip_list` retains a device's prior addressing on the same record (the vendor documents entries suffixed `(Last Known IP)`) and `mac_list`/`number_of_nics` accumulate interfaces "seen on the network" over time, so readdressing and NIC changes extend the existing record rather than creating a new one. `is_online` and `last_seen_list` are separate fields, so a reboot is not an identity event. **Caveat: no source states outright "the uid survives a MAC change."** This is inference from the data model, but well-supported inference: xDome is a passive-discovery platform whose value is longitudinal tracking, and `first_seen_list` records first observation per NIC.
- Reuse behavior: **not documented; treated as no reuse.** Devices are *retired*, not deleted: `retired` and `retired_since` are fields on the device, and the endpoint returns retired devices by default, so a retired record stays addressable by its `uid` indefinitely and that value is not free to be reissued. Whether a hard-delete path exists at all is unaddressed by every source consulted.
- Presence: present on every row, **subject to one structural caveat**: the response contains only the fields the request asked for, and `uid` is not implicitly always-returned. The script therefore forces `uid` into the requested field list even when an operator overrides it.
- Final runZero ID: `claroty-xdome:<uid>`, **with no tenant or host component, deliberately.** A UUID has nothing left to scope. The API host would be actively misleading as a scope, because `api.claroty.com` is shared by every US tenant and therefore distinguishes nothing; two US tenants would get the same "scope" while one tenant read through the legacy `api.medigate.io` host would fragment against itself. The slug prefix keeps these ids distinct from every other integration's, which is the part that matters.
- Missing-ID behavior: **skip.** A row with a null, empty or non-string `uid` is dropped, and the count is reported as one line (`skipped N device records with no uid`) rather than one line per record. No random or synthesized id is ever generated.
- Match behavior: **the default**, `id-match id-break mac-match mac-break ip-match ip-break name-match name-break`. `matchBehavior` is deliberately omitted from `CONFIG` rather than relaxed, because the obvious relaxation is wrong here. Once a foreign id matches, no break flag can veto the merge, so the break flags govern **first contact only**: the moment runZero has never seen this `uid` and must decide whether to merge the record into an asset it found by MAC, IP or hostname. The usual argument for `no-mac-break no-ip-break no-name-break` is address churn, but churn on an already-matched asset is not what those flags control. xDome retains historical addressing on the live record (`(Last Known IP)`, accumulating `mac_list`), so a record can legitimately carry an address that now belongs to a *different* host. With the break flags on, that conflict refuses the first merge and creates a separate asset, which is recoverable. With `no-ip-break` it merges onto the wrong device, which is not.
- Verdict: **authoritative.** A vendor-assigned, vendor-addressable, globally-unique-by-construction UUID with a documented one-row-per-device grain.

### Notes

- **Assets** come from `POST /api/v1/devices/`, paged with `offset` and `limit` in
  the request body and streamed to runZero one page at a time. `sort_by` is sent
  explicitly on `uid` rather than left to the endpoint default, because offset
  pagination over a live table can skip or duplicate rows when the ordering is
  not a total order.
- **The termination rule is the documented one**: stop when fewer than `limit`
  rows come back, not when an empty page arrives. That saves one request per run
  per endpoint.
- **`"devices": null` is a real response.** The schema declares `devices`
  required and typed as an array, but an exhausted page can answer with `null`,
  and the same is assumed for `devices_vulnerabilities`. Both are treated as
  end-of-data rather than as an error.
- **Multi-NIC devices are zipped by index, never cross-producted.** The vendor
  documents that `_list` fields carry one entry per interface and that "entries
  in corresponding indexes refer to the same interface", so `ip_list[i]` and
  `mac_list[i]` are one NIC and become one `NetworkInterface`. Building an
  interface per MAC and attaching every IP to each would invent interfaces the
  device does not have. Equal array lengths are never promised, so a ragged pair
  produces an address-only or MAC-only interface instead of being dropped.
- **`ip_list` entries can carry an annotation.** The vendor documents that IPs
  "may be suffixed by a ` / (annotation)`, where `annotation` may be a child
  device ID or `(Last Known IP)`". Everything from the first `/` is stripped
  before the value is parsed. `routable_ips` then drops loopback, unspecified and
  link-local addresses, since an APIPA address a device invents when DHCP fails
  identifies nothing and would correlate unrelated hosts to each other.
- **`device_name` is not imported as a hostname.** The vendor describes it as
  "the device's IP, hostname, etc.", it is user-editable, and both published
  sample devices carry a bare IP address in it. Importing it would put the same
  string on whichever device holds that address next, or merge unrelated devices
  on a shared display name. Hostnames come from the protocol-derived fields
  instead, best first: `windows_last_seen_hostname`, `dhcp_last_seen_hostname`,
  `http_last_seen_hostname`, `snmp_last_seen_hostname`, `local_name`, then
  `other_hostnames`. Each is rejected if it is a placeholder or parses as an IP.
  `device_name` is kept as the `claroty_xdome_device_name` attribute.
- **Retired devices are excluded by default.** The endpoint returns them unless
  filtered, and filtering is documented as the caller's job. Leaving
  **Include retired devices** off applies
  `{"field": "retired", "operation": "in", "value": [false]}` server-side;
  without it the runZero inventory accumulates decommissioned assets forever.
  The `in` spelling is deliberate: it is the only equality operation in the
  spec's own conventions table and is what Claroty's shipping XSOAR client
  sends, whereas `equals` appears only in a documentation example and in a
  third-party connector. A rejected filter is a failed request, not a degraded
  one, so the run would import nothing at all.
- **Vulnerabilities** come from `POST /api/v1/device_vulnerability_relations/`,
  joined back to the inventory on `device_uid`. Findings are indexed first and
  then attached to the matching device. Relations whose device does not appear in
  the inventory are dropped and counted, not turned into assets: that endpoint is
  a different grain, and building inventory from it would resurrect exactly the
  retired devices the device filter just excluded. The index is bounded twice: 99
  relations per device, and 50,000 relations in total. The second bound is the one
  that matters on a large tenant, because the index is held in Explorer memory for the
  whole device walk that follows.
- **One Claroty `vulnerability_id` can carry many CVEs** (the vendor's own FragAttacks
  example carries twelve), so each relation row fans out to one runZero
  `Vulnerability` per CVE, with the Claroty id and name kept on every one. A row with
  no usable CVE still produces a single finding under Claroty's own id, so an advisory
  tracked outside the CVE system is not silently lost. Each CVE is upper-cased and
  shape-checked before it is asserted, because `Vulnerability.cve` is validated and a
  malformed value fails the whole record. Up to 99 findings are attached per asset.
- **Irrelevant findings are excluded by default**, matching what the vendor's own
  XSOAR pack does unconditionally: only `Confirmed` and `Potentially Relevant`
  relevance levels are imported. Including `Irrelevant` badly inflates CVE counts
  on OT gear. Turn it on with **Include irrelevant vulnerabilities** if the
  dashboard's own totals need to be reproduced.
- `vulnerability_cvss_v3_score` drives the severity and risk scores, falling back
  to `vulnerability_cvss_v2_score` and then to a score derived from
  `vulnerability_adjusted_vulnerability_score_level`. That level drives the ranks.
  `vulnerability_is_known_exploited` sets `exploitable`.
  `vulnerability_recommendations` becomes the solution,
  `vulnerability_published_date` becomes `publishedTS`, and
  `device_vulnerability_detection_date` becomes `firstDetectedTS`.
- **No software inventory and no service or port data exist in this API**, so no
  `Software` and no `Service` objects are produced and none should be expected. What
  the device row offers is adjacent but not an inventory: `software_or_firmware_version`
  is a bare version string with no product name, `endpoint_security_names` lists EDR/AV
  agent names with no versions, and `insecure_protocols` is a risk *level* ("Very Low")
  despite the name. All of these are preserved as custom attributes. runZero's own scan
  data is the better source for both software and services.
- Other device detail is mapped to custom attributes prefixed `claroty_xdome_`:
  `asset_id`, `device_name`, the category/subcategory/type/family classification,
  `site_name`, `purdue_level`, the network, VLAN, OUI and IP-assignment arrays,
  `number_of_nics`, `serial_number`, `hw_version`, `machine_type`, the OS
  category/subcategory/EOL fields, `risk_score`, `risk_score_points`,
  `known_vulnerabilities`, `insecure_protocols`, `is_online`, `retired`,
  `retired_since`, `assignees`, and the per-NIC first/last-seen arrays. `labels`
  become tags, alongside `site:`, `risk:` and `purdue:` tags.
- **Switch and wireless topology is imported as attributes.** `switch_name_list`,
  `switch_port_list`, `switch_mac_list`, `switch_ip_list`, `switch_location_list`,
  `connection_type_list`, `ssid_list`, `bssid_list` and `ap_name_list` are per-NIC
  `_list` fields like the addressing arrays, so entry *i* describes the same interface
  as `mac_list[i]`, and the attribute preserves that order. This is the part of an
  xDome record a runZero scan cannot recover on its own: which switch and which port a
  device is cabled to. `ad_distinguished_name`, `last_domain_user`, `dhcp_fingerprint`,
  `ae_titles`, `note`, `internet_communication` and `last_scan_time` come across the
  same way, since runZero has no first-class field for any of them.
- `first_seen_list` and `last_seen_list` are per-NIC arrays; the earliest and
  latest parseable values become `firstSeenTS` and `lastSeenTS`.
- Authentication is a static bearer token. There is no login endpoint and no
  refresh, so there is no re-authentication path to exercise; a 401 or 403 is
  reported as a token that expired or was revoked, with the reminder that a new
  one must be generated.

#### The `fields` parameter

`fields` is a **required** member of the request body, validated against an
enum, so a single unsupported name rejects the **entire request** with a `422`.
The failure mode is zero assets imported, not one missing column, which makes
this the most likely thing to go wrong against a tenant this integration has not
been run against before.

- The script requests a deliberately conservative core set of 67 device fields
  and 18 relation fields. Every one is documented in the vendor's own per-field
  table, and nothing is requested that the script does not actually map.
- Fields **known to diverge** between the recovered spec and live tenants are left out
  on purpose: `site_group_name`, `purdue_level_source`, `last_seen_reported`, the
  `*_reported_from` group, the end-of-life and end-of-sale dates, the visibility
  scores, `connection_paths`, `product_code` and `model_family`. Several appear in
  real tenant responses but are absent from the recovered enum, which suggests
  availability varies by tenant release or licensing.
- On a `422`, the run stops with a message naming the endpoint and the parameter
  that fixes it. The response body is **not** echoed: a FastAPI validation dump
  can carry the whole submitted request back, and that does not belong in a log.
- The fix needs no code change. Set **Device fields** (`device_fields`) or
  **Vulnerability fields** (`vulnerability_fields`) to a comma-separated list.
  The list replaces the built-in one entirely, so use it to trim a rejected name
  *or* to add a tenant-specific `custom_attribute_<name>` field. `uid` and
  `device_uid` are always requested regardless of what the override says, because
  a response carries only the fields it was asked for and a list without them
  would leave every record unidentifiable.
- The tenant's own field enum can be read from **Help Center > API
  Documentation** inside the xDome dashboard, which is the authoritative list for
  that tenant.

#### Rate limiting

**Claroty documents no rate limit anywhere.** No `429` response is declared on any
operation, and none of the partner integrations consulted mention throttling or
implement backoff; one fires remaining pages concurrently with no retry logic at all,
which suggests limits are either absent or generous.

This integration pages **sequentially** and hand-rolls nothing. `post_json` already
retries transient failures three times by default with exponential backoff, covering
`408, 425, 429, 500, 502, 503, 504` and honouring `Retry-After`, so a limit that does
exist is absorbed rather than failing the task. Treat a 429 as possible but unproven,
and confirm against a live tenant before raising throughput.

#### Unverified assumptions

These are the points where the documentation runs out. Each is handled
defensively rather than guessed at, but each is worth confirming against a live
tenant.

1. **Rate limits are completely unknown**, see above. The biggest unknown.
2. **The live field enum is not the one in the recovered spec.** Handled by
   keeping the requested list conservative, by failing loudly and actionably on
   422, and by making both lists operator-tunable.
3. **Cross-tenant uniqueness of `uid` is not documented**, only inferred from the
   UUID format. Handled by prefixing the id with the integration slug.
4. **Long-term stability of `uid` is inferred, not stated.** No source says the
   uid survives a MAC change; the data model strongly implies it.
5. **Recycling of a hard-deleted `uid` is unaddressed.** Retirement demonstrably
   preserves it; whether a hard delete exists at all is unknown.
6. **The `ip_list` annotation suffix is documented but never exemplified.** The
   exact spacing and whether the annotation is always parenthesised are unknown,
   so everything from the first `/` is dropped and the remainder is validated as
   an address.
7. **Array-length parity across `_list` fields is not promised**, only index
   correspondence. Handled by zipping defensively over the longer array.
8. **The token-expiry failure mode was not observed.** Both 401 and 403 are
   treated as authentication failures, since the vendor's XSOAR client
   pattern-matches on "Forbidden" and "Authorization" in the error.
9. **`filter_by` has a known server-side defect.** The XSOAR pack records that
   `not_equals` and `greater` "are currently not working" and patches around them
   with `greater_or_equal`. This integration uses only `in`, which is what the
   vendor's own client sends and the one equality operation the spec's
   conventions table lists.
10. This integration was validated against local fixtures, not a live Claroty
    xDome tenant.

## Future

- **Alert ingestion.** `POST /api/v1/device_alert_relations/` returns one row per
  (device, alert) pair keyed on `alert_id` and `device_uid`, with
  `alert_type_name`, `alert_category`, `alert_class`, `device_alert_status`,
  detection and update timestamps, and MITRE ATT&CK enterprise and ICS technique
  mappings. That shape suits an event feed keyed to the same asset identity
  rather than an inventory import, which is why alerts are not imported here: a
  policy alert is a thing that happened, not a property of a device.
- **Site enrichment.** Brinqa documents and uses `POST /api/v1/sites/get` for site
  location, timezone and country. It is absent from the recovered OpenAPI
  document, so it is credible but unverified. `site_name` and `purdue_level`
  already arrive on the device row, so this would only add geography.
- **`slot_cards` as a software or component inventory.** For PLCs, this nested
  array carries per-card `name`, `card_type`, `model`, `vendor`, `sw_version`,
  `serial_number`, `combined_os`, `ip` and `mac`. It is the richest nested
  inventory the API offers and is a plausible `Software` source for OT gear,
  the reason it is not imported today is that it is a nested object array whose
  exact shape none of the recovered samples exhibit. The same applies to pairing
  `endpoint_security_names` with `edr_is_up_to_date_text` for EDR posture.
- **Observed services from OT activity events.** `POST /api/v1/ot_activity_events/`
  carries `protocol`, `src_ip`, `dst_ip` and `dst_port` per event. Aggregating
  that into per-device observed services is a synthesis the API does not offer
  and would need its own time-window paging, but it is the only path to service
  data from this source at all.
- **Outbound: write runZero context back into xDome.**
  `POST /api/v1/custom-attributes/set`, `/api/v1/user-actions/labels/set`,
  `/api/v1/user-actions/notes/set` and `/api/v1/user-actions/assignees/set` all
  address devices by `uid`, which this integration already carries as the foreign
  id, so a runZero-discovered attribute, tag or note could be pushed onto the
  matching xDome device.
- **Incremental imports.** `filter_by` supports `after_seconds_ago` and
  `greater_or_equal` on timestamp fields, so a lookback window over
  `last_seen_list` would cut the request count on a large tenant. It is not
  shipped because a lookback window silently truncates a full inventory pull, and
  a quiet OT segment then looks exactly like a broken credential.

## API documentation

- Vendor API documentation home (login-walled): https://partner.dashboard.medigate.io/help-center/api-documentation (also reachable as **Help Center > API Documentation** inside the xDome dashboard, which is where a tenant's own field enum can be read).
- Claroty's OpenAPI 3.1 document ("Medigate API", v1.0.0), as recovered by a third-party client generator; the authoritative source for the paths, the request/response schemas, the device field enum, the filter grammar, the pagination rule and the multi-NIC array semantics: https://raw.githubusercontent.com/guruevi/medigate_api/master/medigate_openapi.json
- Cortex XSOAR pack (working client: bearer header construction, offset/limit loop at 5000, `filter_by`/`sort_by` grammar, relevance filter, retired filter, relation dedupe keys): https://github.com/demisto/content/tree/master/Packs/ClarotyXDome/Integrations/XDome
- Elastic integration package (literal request bodies, real raw tenant device JSON, and the `{"devices": null}` exhausted-page shape): https://github.com/elastic/integrations/tree/main/packages/claroty_xdome
- Brinqa connector (endpoint list, API user creation, Read-Only role, site permissions, page size): https://docs.brinqa.com/docs/connectors/claroty-xdome/
- Qualys connector (regional host pattern, Read-Only role, and that site permissions scope what the connector can see): https://docs.qualys.com/en/conn/latest/integrations/claroty_xdome.htm
- Safe Security (US and EU production hostnames): https://docs.safe.security/docs/claroty-xdome
- Hunters (US/EU split, collectable object types): https://docs.hunters.ai/docs/claroty-xdome
- FortiSOAR connector (limit default 100, maximum 5000): https://docs.fortinet.com/document/fortisoar/1.0.0/claroty-xdome/850/claroty-xdome-v1-0-0
- Rapid7 InsightIDR (default host `api.claroty.com`): https://docs.rapid7.com/insightidr/claroty-xdome/
- Axonius (hostnames are synthesized from the protocol-derived fields, not from `device_name`): https://docs.axonius.com/docs/claroty-cloud

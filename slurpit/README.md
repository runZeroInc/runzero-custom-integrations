# Custom Integration: Slurp'it

Slurp'it is a network discovery platform that logs into devices over SSH or telnet and parses their CLI output with 117+ vendor TextFSM templates. It ships a "free for life" licence permitting unlimited device *discovery*, which makes it an unusually cheap source of authoritative network-device inventory.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Slurp'it portal over HTTPS.

## Slurp'it requirements

- A self-hosted Slurp'it installation with the portal reachable from the Explorer.
- An **API key**, created in the portal under **Settings → API keys**. A read-capable key is sufficient; this integration issues only `GET` requests.
- At least one completed scrape, so `/api/devices` has rows.

### Confirm access before configuring runZero

```bash
curl -s -H 'Authorization: Bearer <api-key>' \
     'https://slurpit.example.com/api/platform/ping'
# -> {"status":"up"}

curl -s -H 'Authorization: Bearer <api-key>' \
     'https://slurpit.example.com/api/devices?offset=0&limit=5'
# -> [ { "id": 1, "hostname": "sw01", ... } ]     (a bare array, no envelope)
```

`/api/devices` answers with a **bare JSON array**, not a paginated envelope. If you get an object back, the URL is pointing at something other than the Slurp'it portal.

## Steps

### Slurp'it configuration

1. Sign in to the Slurp'it portal as an administrator.
2. Go to **Settings → API keys** and create a key for runZero. Copy the value.
3. Confirm the two `curl` calls above succeed from the Explorer host.
4. Note the portal URL, including any path prefix it is reverse-proxied under.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Slurp'it").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Slurp'it URL** (`url`): base URL of the portal, e.g. `https://slurpit.example.com`. The `/api` path is appended automatically.
   - **API key** (`api_key`): the key created above.
   - **Include disabled devices** (`include_disabled`): optional; default **disabled**. See the note below.
   - **Collect site details** (`collect_sites`): optional; default enabled. One extra request per run.
   - **Page size** (`page_size`): optional; default 512.
   - **Maximum devices** (`max_devices`): optional; default 50000, 0 removes the cap.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the CLI

```bash
runzero script --filename slurpit/slurpit.star \
  --kwargs url=https://slurpit.example.com \
  --kwargs api_key='<api-key>' \
  --kwargs include_disabled=false \
  --kwargs collect_sites=true \
  --kwargs page_size=512 \
  --kwargs max_devices=5000 \
  --kwargs tls_disable_validation=true
```

Wiring check only, without touching a portal:

```bash
runzero script --filename slurpit/slurpit.star --validate
```

Two notes on the CLI:

- **`--kwargs` cannot carry a value containing both `=` and `,`.** The flag parser reads such a pair as CSV, splits on the comma, and invents a parameter from the remainder — which the integration then rejects under a name nobody set. Set such a key through the console credential form instead.
- **`scan` is a different command and is not what runs this.** `runzero scan` performs active network discovery against a target list and never loads a custom integration script. Inbound integrations run through `runzero script` as above, or as a scheduled Custom Integration task on an Explorer.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with vendor, OS, serial, site, and SNMP location data from Slurp'it.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:slurpit`.

## Asset identity

- Target entity: one **network device Slurp'it has discovered** and logs into — a switch, router, firewall, or wireless controller.
- Source ID field: `id`, an integer primary key on the portal's own device table. The SDK coerces it with `int(id)`, and it is present on every row.
- Uniqueness scope: one Slurp'it instance. The portal hostname is part of the runZero id so two instances polled into one organization cannot collide.
- Cardinality: one row per device.
- Stability: **survives a re-scan.** Slurp'it updates existing rows rather than recreating them — `POST /api/devices/resync` is documented as resyncing from warehouse to portal — and an unreachable device is aged out gently: the platform's `device_disabled_after_days` setting flips `disabled` to `1` first, and `device_removed_after_days` deletes the row only later. The id also survives a hostname change, an address change, and a firmware upgrade.
- Reuse behavior: **no.** The integer is an auto-increment key and is not reissued.
- Presence: `id` is one of the fields Slurp'it's own validator treats as always present. A row without one is skipped and logged with the slug only.
- Final runZero ID: `slurpit:<portal-host>:device:<id>` — for example `slurpit:slurpit.example.com:device:1`.
- Missing-ID behavior: skip. `new_uuid()` is not used anywhere in this script.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**. The id is one-per-physical-device and stable across rescans, so it is a legitimate foreign id and may drive merging; the break flags stop a disagreeing address or name from disqualifying a merge at first contact. Slurp'it's own NetBox and Nautobot plugins reconcile on this id rather than on hostname, across all three of their add/change/remove passes — which is the strongest available evidence that it is durable.
- Known limitation: **hostname is the de-facto natural key on the Slurp'it side.** The snapshot endpoints are addressed by hostname, the plugins' delete action is keyed on hostname, and the platform has a `rewrite_duplicate_hostnames` setting. A device deleted and re-discovered therefore gets a new `id` and forks the asset. That is unavoidable rather than a tuning mistake — the platform refuses, unconditionally and without consulting `matchBehavior`, to place two different foreign ids from the same custom integration on one asset.
- Verdict: **authoritative for the devices Slurp'it can log into.** Unlike an IPAM, this is genuine discovery — Slurp'it reached the device, authenticated, and parsed its CLI — so the records describe hardware that demonstrably exists. Its blind spot is everything it has no credentials for.

### Why `include_disabled` defaults to off

Slurp'it sets `disabled = 1` automatically once a device has been unreachable for the configured number of days. Those rows are mostly decommissioned hardware waiting for the removal timer, and importing them by default would resurrect departed devices on every poll. They are still available behind the parameter, and every asset carries `slurpit_disabled` regardless.

## Notes

- **What is imported.** One asset per device: `hostname` and `fqdn` as hostnames, `address` as the management IP, `brand` as manufacturer, `device_os`/`os_version` as OS and version, `serial`, `device_type`, `site`, `group_name`, `description`, `parent`, the SNMP contact/location/description/uptime, tags, and the discovery timestamps. With **Collect site details** enabled, the device's site is resolved against `/api/sites` and its street, city, country, and description are attached.
- **Two field names differ from what the planning documents suggest.** The device record has **`address`**, not `ipv4`, and **`os_version`**, not `version`. `ipv4` is a rename applied by Slurp'it's *NetBox plugin* on its way into NetBox, not something the API emits.
- **Booleans arrive as the strings `'0'` and `'1'`**, not as JSON booleans — `disabled`, `blacklisted`, and `telnet` all behave this way, and Slurp'it's own validator asserts the string form. A truthiness helper handles both.
- **The free tier substitutes licence placeholders into unparsed fields.** Discovery is unlimited but *parsing* is licensed by device count, and beyond that count the portal writes the literals `License Required` and `License limit reached` into fields such as `serial` and `os_version` rather than leaving them blank. Imported naively these become a serial number and an OS version on every asset over the limit. They are screened out; `tests/fixtures/paged.json` asserts it.
- **Timestamps are local time with no zone.** `createddate`, `changeddate`, `added`, and `last_seen` are all `%Y-%m-%d %H:%M:%S` in the portal server's local time. Read as UTC on a server east of Greenwich they land in the future, and the platform rejects the **entire asset record** on a future timestamp rather than just the field. Every parsed value is clamped to now, and the raw strings are preserved as `slurpit_*_raw` attributes.
- **Pagination is offset/limit with no total count**, so a short page ends the walk — the same termination rule Slurp'it's own SDK pager uses. `/api/devices`, `/api/sites`, and `/api/planning` return bare arrays; some other endpoints wrap rows in `{"rows": [...]}`, and both shapes are accepted. Each page is streamed with `report_asset`, so memory stays bounded by one page.
- **Slurp'it reports no MAC on the device record.** It discovers over SSH and telnet, so a device's correlators here are its management address and its names. MAC-level data exists, but only inside planning results — see *Future*.
- `deviceType` is mapped only from values this integration recognises; `device_type` is free text from Slurp'it's vendor templates, so an unrecognised value leaves `deviceType` unset rather than guessing.
- Request volume is `2 + ceil(devices / page_size)` — one ping, one site read, and one page per batch.
- Rate limiting: Slurp'it publishes no documented rate limit. The shared HTTP helper retries transient statuses three times with exponential backoff and honors `Retry-After`.
- Self-signed certificates are common on self-hosted installs. `OPTIONS_TLS` is exposed for that; it never defaults to insecure.
- **Verification status:** **this integration was not exercised against a live Slurp'it instance.** Slurp'it publishes container images, but bringing the stack up requires a licence key, and obtaining one requires registering an account with the vendor — not something to do unattended. Endpoint paths, the `Authorization: Bearer` header, exact field names, the string-boolean encoding, the licence placeholders, the pagination scheme, and the identity reasoning were all taken from the **official `slurpit` Python SDK** and Slurp'it's own open-source NetBox, Nautobot, and Infrahub plugins, which are the authoritative clients for this API. The fixtures encode those shapes; they are a well-grounded hypothesis, not a capture. A live run is the outstanding validation step.

## Future

- **Planning results are the other half of this integration, and the reason it is worth revisiting.** Slurp'it's plannings are the parsed CLI output — ARP tables, MAC address tables, interfaces with MACs, CDP/LLDP neighbours, VLANs, routing tables, hardware inventory. `POST /api/planning/search` with `{planning_id, unique_results: true, latest: true}` returns them in bulk for every device at once, so it is one request per planning rather than N+1.

  That data would let this integration emit **discovered endpoint assets keyed on MAC** — the same high-value layer-2 correlation the [`netdisco`](../netdisco/) integration produces — and attach real interface MACs to the device assets it already imports.

  It is deliberately **not** implemented yet, for one concrete reason: a planning's result columns are the TextFSM template's column names, and both the columns and the planning `slug` are per-install and user-editable. Guessing that a MAC lives in a column called `MAC_normalized` would work on a default install and silently import nothing on a customised one. The sound design is to discover rather than guess — `GET /api/planning` returns each planning's `columns` array alongside its `slug`, so the integration can read the schema at runtime and match columns by shape. That needs a live instance to validate against before shipping.
- **`/api/devices/vendors` and `/api/devices/types`** are small reference tables that would let `deviceType` and `manufacturer` mapping be driven by the instance rather than by a table in this script. Note the path is `/api/devices/vendors`, not `/api/vendors`.
- **Sites as runZero sites.** `/api/sites` already carries street, city, state, country, and latitude/longitude, and is read for enrichment today. That maps directly onto runZero sites rather than onto per-asset attributes.
- **`GET /api/devices?include_raw_json=1`** returns the raw CLI capture alongside the parsed record. Too large to import wholesale, but it is where anything the templates did not parse still lives.
- **`/api/platform/version` and `/api/platform/license`** would let the integration record which Slurp'it release produced the data and warn when the parse licence is saturated — which, given the placeholder behaviour above, is a condition worth surfacing rather than silently working around.

## API documentation

- Product overview: https://slurpit.io/product/
- Licensing and FAQ: https://slurpit.io/knowledge-base/frequently-asked-questions/
- Official Python SDK — authoritative for endpoint paths, the auth header, model field names, and the pagination scheme: https://pypi.org/project/slurpit/ (source at https://gitlab.com/slurpit.io/slurpit_sdk)
- Slurp'it GitLab organisation: https://gitlab.com/slurpit.io
- Open-source NetBox plugin, the reference consumer of this API: https://slurpit.io/netbox-plugin/

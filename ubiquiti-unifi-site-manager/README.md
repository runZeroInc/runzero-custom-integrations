# Custom Integration: Ubiquiti UniFi Site Manager

One API key, every console on a UI account. Site Manager is Ubiquiti's cloud
rollup: instead of holding a credential for each controller and reaching each
one on its own management address, the Explorer makes three calls to
`https://api.ui.com` and gets back every UniFi OS console the account has
adopted, every site on those consoles, and every device those consoles manage —
gateways, switches, access points, and Protect cameras alike.

That is the MSP and multi-site story, and it is the reason to run this rather
than N copies of the local integration. The trade is fidelity: the cloud holds a
**cache** that each console refreshes on its own schedule, so it lags the local
controller, it carries no client-level detail at all, and its device rows are a
subset of what the Network API returns. Position it as coverage, not as depth.

This is the **cloud** API. The Explorer needs outbound internet to
`api.ui.com`; it does not need a route to any controller. That is the opposite
of [`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/README.md), which
speaks to one controller directly and is the one to use when you want clients.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with outbound HTTPS (TCP 443) to `api.ui.com`. No inbound access and no route to any UniFi console is required.
- One task per UI account. The credential is account-wide, so an MSP with several UI logins needs several tasks — and should read the namespace note under **Asset identity** first.

## UniFi Site Manager requirements

- A **UI account** (`unifi.ui.com`) with consoles adopted to it. A console that was never cloud-adopted, or that has had remote access turned off, is not in the cloud's inventory and no API key can reveal it.
- **UniFi OS consoles**, not the legacy self-hosted Network application. Art of WiFi's authentication comparison states it plainly: Site Manager needs "A **UniFi OS console or UniFi OS Server**. The legacy self-hosted Network Application is not supported via Site Manager," and the console "must be **adopted to a UI.com account** and connected to Ubiquiti's cloud." A self-hosted UniFi OS Server does appear, with a different payload shape — see the notes.
- A **Site Manager API key**. It carries the console access of the UI account that made it and is read-only.
- No minimum UniFi OS version was established from vendor documentation. Ubiquiti's List Hosts reference says only that its example "is based on UniFi OS 4.1.13" and that the `userData` and `reportedState` shapes "may vary depending on the UniFi OS or Network Server version" — which is a statement that the payload moves, not a floor. Treat any console that shows up in the Site Manager web UI as one this integration will see.

### Creating the credential in UniFi Site Manager

1. Sign in to **https://unifi.ui.com** with the UI account that owns (or has been invited to) the consoles you want.
2. Open the **API** section from the left navigation bar, then **Create API Key**. Name it something you will recognise in an audit — `runZero`, for instance.
3. **Copy the key immediately.** Ubiquiti's own guidance is that it "will only be displayed once"; after you click Done it is hashed and cannot be read back. A lost key is replaced, not recovered.
4. Note the navigation, because it has moved. Ubiquiti's help article describes the left-nav **API** entry above; Art of WiFi's walkthrough describes **Settings → API Keys** on the same portal, and one published Go client says "sitemanager.ui.com → Navigate to API section". All three are the same key. If the path in your tenant matches none of them, look for whatever the portal calls API keys — this README could not establish a single current path from vendor documentation, and it changes.
5. There is no scope or role to choose. The key inherits the account's console access, which means a key made by an account invited to two of five consoles returns two consoles and no error. If a run imports less than you expect, check the account's console list before you suspect the integration.
6. Confirm the key from the Explorer host before you configure anything in runZero:

   ```bash
   curl -s -H 'X-API-Key: 8mR2vQ7pL0xTn4dW1sYb6KfJhE3aZgUc' \
        -H 'Accept: application/json' \
        'https://api.ui.com/v1/hosts?pageSize=1'
   ```

   A good key returns `{"data":[...],"httpStatusCode":200,"traceId":"..."}`. A
   bad one returns a JSON body carrying `code` and `message` rather than `data`,
   which is exactly what this integration prints when it sees it. The header is
   sent as `X-API-Key` here and written `X-API-KEY` in Ubiquiti's reference;
   header names are case-insensitive and both work.

### Which UniFi integration do you want?

Both. They do not overlap, and the repo ships them separately for that reason.

| | Site Manager (this one) | [`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/README.md) |
|---|---|---|
| Reaches | `api.ui.com` over the internet | one controller, directly |
| Credential | one API key per UI account | one API key per controller |
| Covers | every console on the account | one controller's site |
| Devices | yes, cached, reduced field set | yes, live, full field set |
| Clients | **no** | yes, wired and wireless |
| Sites | names, timezone, ISP | the configured site |

Run Site Manager for breadth — "which consoles and devices exist anywhere" —
and the Network integration against the controllers whose clients you care
about. They produce different assets and merge on MAC and address.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "UniFi Site Manager").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Site Manager API URL** (`url`): the vendor endpoint, `https://api.ui.com`, which is also the default. Override it only to reach the API through a proxy.
   - **API key** (`api_key`): the key from step 3 above. Required.
   - **Import UniFi devices** (`extract_devices`): read `GET /v1/devices` (default: true). This is where nearly every asset comes from.
   - **Read console detail** (`extract_hosts`): read `GET /v1/hosts` to enrich each console with hardware model, serial, firmware, LAN addresses, and timezone, and to import a console the device list never mentions (default: true).
   - **Attach site names** (`extract_sites`): read `GET /v1/sites` and attach site name, description, timezone, and ISP to that console's devices (default: true).
   - **Page size** (`page_size`): rows per page (default: 100, maximum 500).
   - **Maximum pages per collection** (`max_pages`): hard stop per collection (default: 200).
   - **TLS and HTTP options** (`tls_*`, `http_*`): normally leave alone. `api.ui.com` presents a publicly trusted certificate; these exist for the proxy case.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. The cloud copy is a cache refreshed by the consoles themselves, so polling it every few minutes buys nothing; hourly or daily is the honest cadence.
   - Select the Explorer you would like the Custom Integration to run from — one with internet egress.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with the models, firmware versions, addresses, and site names Site Manager holds.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:ubiquiti-unifi-site-manager`.
- Consoles carry their serial as a tag, so `tag:serial:f4e2c6c23f13` finds an appliance by the number printed on it.
- Every field lands under the `unifi_` prefix: `unifi_site_name:"Head office"`, `unifi_product_line:protect` for Protect cameras, `unifi_status:offline`, `unifi_firmware_status:updateAvailable`, `unifi_update_available:7.1.26` for the fleet that is behind, `unifi_is_console:true` for the appliances themselves, and `unifi_covered_by_device_list:false` for a console only the host collection knew about.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
key and see what a real account returns. Each `CONFIG` parameter is one
`--kwargs key=value` pair:

```bash
runzero script --filename ubiquiti-unifi-site-manager/ubiquiti-unifi-site-manager.star \
  --kwargs url=https://api.ui.com \
  --kwargs api_key=8mR2vQ7pL0xTn4dW1sYb6KfJhE3aZgUc \
  --kwargs page_size=25 \
  --kwargs extract_sites=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/unifi-site-manager-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; `--overwrite` replaces a directory from an
earlier run. Turning `extract_sites` off on a first run drops one call and one
attribute group, which is a useful way to see the device rows unadorned.

To check only that the `CONFIG` block and the HTTP and TLS wiring are sound,
without touching Ubiquiti:

```bash
runzero script --filename ubiquiti-unifi-site-manager/ubiquiti-unifi-site-manager.star --validate
```

Validation answers from a local dummy server whose collections are always
empty, so it proves the script initializes, declares its parameters, and issues
a request. It parses no rows. The fixture suite is what proves the parsing:

```bash
python3 tests/run.py ubiquiti-unifi-site-manager
```

That runs the six scenarios in
`ubiquiti-unifi-site-manager/tests/fixtures/` — `happy`, `empty`, `malformed`,
`orphan-host`, `paged`, and `rate-limit` — against the real scanner.

To run it the way the platform does, as an integration task that uploads its
results, use the `scan` command. `--custom-integration-id` is the UUID shown on
the integration's page in the console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://api.ui.com,api_key=8mR2vQ7pL0xTn4dW1sYb6KfJhE3aZgUc'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

### UniFi devices

- Target entity: one adopted device on a UniFi console — a gateway, switch, access point, Protect camera, or the console appliance itself, which reports as a device with `isConsole: true`.
- Source ID field: **`devices[].id`** on `GET /v1/devices`, taken verbatim.
- Documentation evidence: `id` is present on every device row in Ubiquiti's own List Devices example, and it is the field the response uses to name a device. In every published example the value is that device's MAC address in uppercase with no separators. Ubiquiti does not document `id` as being defined that way, so the script reads the field and never reconstructs it.
- Uniqueness scope: one UI account in principle, but the runZero id is scoped on the **hostname of the configured base URL** — which for the vendor endpoint is always `api.ui.com`. Two UI accounts imported into one runZero account therefore share a namespace. The values are MAC-derived and globally unique in practice, so a collision means the same physical device is genuinely in both accounts, but the namespace is not doing tenant separation here and should not be relied on for it.
- Cardinality: one row per device per host group. A device adopted by two consoles would appear twice; the run collapses repeats on the composed id and logs `skipping duplicate device id <id>`.
- Stability: survives a rename, a firmware upgrade, a DHCP change, and the device going offline. Whether it survives being forgotten and re-adopted was **not established from vendor documentation** — assume it does not, as with any adoption record.
- Reuse behavior: not documented by Ubiquiti. If the value is the MAC, reuse would require TP-Link-style hardware duplication rather than a counter wrapping, which is the safe direction to be uncertain in.
- Presence: on every device row in every published example. A row without one is skipped with `skipping device with no id under host <hostId>`.
- Final runZero ID: `unifi-site-manager:api.ui.com:device:F4E2C6C23F13`.
- Missing-ID behavior: skip and log. No identity is synthesized and `new_uuid()` is never used.
- Match behavior: **`no-id-match no-id-break`**. The `id` field is issued by Ubiquiti, but in every published example its *value* is the device's MAC with the separators removed, and the script cannot tell an issued opaque id from a MAC. An identifier derived from an address identifies an address, not a device — `normalize_mac` clears the locally administered bit for cross-source matching, so two distinct endpoints can fold onto one value, which is right for an interface and wrong for identity. The id is therefore kept as the stable record key and is not allowed to drive **or** block a merge; correlation falls back to the MAC, the reported address, and the name. `aruba-clearpass` and `forescout-counteract` take the same posture for the same class of identifier. Pinned by the `mac-derived-id` scenario.
- Verdict: **derived, and not trusted to match.** It escapes the repo's `no_mac_in_id` invariant only because that check deliberately matches separator-bearing MACs — a bare twelve-hex run is indistinguishable from a legitimate opaque id — so this one had to be caught by review.

### Consoles the device list does not cover

This is what the `orphan-host` scenario exists to pin down. A console can be in
`GET /v1/hosts` and absent from `GET /v1/devices` — because it is offline,
because it is a self-hosted UniFi OS Server rather than adopted hardware, or
simply because the two cached collections disagree. Left alone it would be
invisible, so the run emits it after the device pages are done.

- Target entity: a console, gateway appliance, or Network Server that the device collection never mentioned.
- Source ID field: **`reportedState.hardware.mac`** when the host has one, uppercased with separators removed — that is, the exact string the device collection would have used as `id`. Otherwise **`id`**, the host id.
- Documentation evidence: Ubiquiti's List Hosts example shows `reportedState.hardware.mac` as an uppercase colonless MAC on a UniFi OS console, and the same appliance's device row carries that value as its `id`. `hardware.mac` is preferred over `reportedState.mac` deliberately: the two differ in Ubiquiti's own example, and it is `hardware.mac` that agrees with `hardware.serialno` and with the device list.
- Uniqueness scope: as above.
- Cardinality: one per console, and only for consoles the device pass did not already claim. The device pass marks each host it covered, so a console that appears in both collections is emitted **once**, from the device list.
- Stability: it is a burned-in hardware address, so it survives everything short of a board swap.
- Reuse behavior: none in practice.
- Presence: `hardware.mac` is present on UniFi OS consoles and absent on a self-hosted Network Server, whose `reportedState` is a snake_case document sharing no field names with the console shape. Those keep their host id.
- Final runZero ID: `unifi-site-manager:api.ui.com:device:AABBCC000003` for a console with a hardware MAC, `unifi-site-manager:api.ui.com:host:1d9cf3ee-0c0f-466e-933c-9af829f09b50` for a Network Server without one. Note the `device:` segment on the first: it is deliberate, and it is the whole point.
- Missing-ID behavior: a host with no id is skipped and logged. A host that survives with no address, no MAC, and no usable hostname is also skipped, because an asset with nothing to correlate on can never merge with anything.
- Match behavior: it depends on which of the two ids the host got, and the split is deliberate. A console with a `hardware.mac` gets the MAC-derived `device:` id and **`no-id-match no-id-break`**, exactly as a device does. A self-hosted Network Server has no MAC, keeps its opaque host UUID, and therefore retains **`no-mac-break no-ip-break no-name-break`** — that id is a real vendor identifier rather than an address, so it may drive a merge, and the single address it publishes must not veto one.
- Verdict: **derived, and derived on purpose — but no longer trusted to match.** Constructing the identifier from a MAC is what the repo's `no_mac_in_id` invariant exists to discourage, and the reason it is done anyway is that the alternative is worse: an offline console imported under its host id, then imported under its device id the week it comes back, is two assets for one appliance. What has changed is that the derived id no longer drives or blocks merging, so the risk it carries is now bounded by the flags rather than by the assumption behind it. That assumption — that `devices[].id` really is the console's MAC — still governs whether an offline console and the same console online land on one id.

## Notes

### What is imported

Three calls, joined on `hostId`:

| runZero | Site Manager |
|---|---|
| `id` | `devices[].id`, or a console's `reportedState.hardware.mac` |
| `hostnames` | device `name`, falling back to the console's `reportedState.hostname` |
| `networkInterfaces` | device `mac` and `ip`, plus every routable address in the console's `reportedState.ip` and `ipAddrs` |
| `manufacturer` | the literal `Ubiquiti` |
| `model` | device `model`, or the console's `hardware.name` |
| `osVersion` | device `version`, or the console's `hardware.firmwareVersion` |
| `deviceType` | derived from `shortname`, with `productLine` as a fallback |
| `tags` | `serial:<hardware.serialno>` on consoles |
| `customAttributes` | the device row, the console's hardware and state, and the site's name, description, timezone, and ISP |

No `Service`, `Software`, or `Vulnerability` records are emitted. The cloud
knows what a device is, not what it is listening on.

### The console is in both collections, and is emitted once

A console appears as a host in `/v1/hosts` and as a device with
`isConsole: true` in `/v1/devices`. Neither view is complete: the device row
carries only the management address, while the host record knows every address
the appliance holds. So the device row wins the identity and the host record is
folded into it — extra addresses, the hardware MAC if the device row lacked one,
the hostname if the device had no usable name, the serial as a tag, and the
serial, firmware, state, timezone, direct-connect domain, and registration time
as attributes. That is what the `happy` scenario asserts: four devices out, not
five, with the console's `unifi_console_serial` present.

### The address the cloud saw is not an address the device has

Every host row carries a top-level `ipAddress`, and for a console behind NAT it
is the site's **public WAN address** — shared by every device at that site. Put
on an interface it would correlate the whole branch office into one asset. It is
recorded as `unifi_console_cloud_address` and deliberately never reaches a
network interface. Link-local is filtered for the same class of reason: a
console reports an `fe80::` address for every bridge port it owns, and the
platform keeps link-local rather than dropping it, so two consoles that both
failed DHCP would otherwise correlate to each other.

### Pagination, and why the query is built onto the URL

Each collection pages with `pageSize` out and `nextToken` back, and the token is
opaque — a real one contains a colon and looks like
`602232A870250000000006C514FF00000000073DD8DB000000006369FDA2:1467082514`. The
query string is assembled onto the URL with `url_encode` rather than passed as
`params=`, and that is not a style choice: `params=` **replaces** a URL's query
string instead of merging with it, so passing it alongside a cursor silently
wipes the cursor and restarts pagination from page one. That is an infinite loop
rather than an error, which is why `max_pages` exists as a backstop and why the
`paged` scenario asserts that `pageSize` and `nextToken` arrive together. Each
walk is guarded by `pager()`, so exhausting `max_pages` with a cursor still
pending fails the task with a message naming the exhausted collection rather
than silently importing a truncated set.

The **Page size** parameter is bounded at 500 by the script. Whether the API
itself caps `pageSize` at that number was **not established from vendor
documentation** — the published example uses 10 and states no maximum — so if a
large page is rejected, lower it.

### Rate limits

The `/v1/` endpoints are documented at **10,000 requests per minute**, answering
`429` with a `Retry-After` header and a body of
`{"code":"rate_limit","message":"rate limit exceeded, retry after 1.372786998s"}`.
Early Access paths under `/ea/` are a separate, far tighter **100 requests per
minute**; this integration calls none of them. Nothing here hand-rolls a retry:
`get_json` retries transient statuses three times by default and honours
`Retry-After`, which is what the `rate-limit` scenario proves. A handful of
requests per run against a 10,000/minute budget is not a limit anyone will
reach.

### Timestamps are screened before they are parsed

`parse_time` aborts the entire script on input it cannot read, and this API
emits an **empty string** for a date-time it does not have — `registrationTime`
and `latestBackupTime` both appear as `""` in Ubiquiti's own examples. Every
timestamp is therefore matched against a regex first and only parsed if it
passes, then clamped to the current time, because a future timestamp does not
fail the field, it fails the whole `ImportAsset`.

`updatedAt` on a device group is when the cloud last refreshed that console's
device list, not when the device was last seen. It is claimed as `lastSeenTS`
only for a device the same refresh reported `online`; for an offline device it
says when the cloud last looked, which is a different fact. A console imported
from the host collection gets `lastConnectionStateChange` as its last-seen, and
only when its state is `connected`.

### Device type is mapped where the family is unambiguous

`shortname` prefixes decide: `UVC` is an IP Camera, `UVP` a VoIP Phone, `UDM`
`UXG` `USG` `UCG` `UDW` a Router, `USW` `USL` `US-` `USMINI` a Switch, `UAP`
`UALR` `UWB` `U6` `U7` a Wireless Access Point, `UCK` a Server. Anything else is
left **unset** rather than guessed at, with `productLine: protect` as a last
resort for a camera whose shortname says nothing. The raw `shortname` and
`productLine` are always kept as attributes, so a family this list does not know
is still searchable.

### Malformed rows are survivable, because Ubiquiti says they will happen

Ubiquiti's own guidance is to design for unfamiliar properties, null values, and
missing attributes, and its schema marks `data` items nullable on both
`/v1/sites` and `/v1/devices` — including the nested `devices` list. The
`malformed` scenario feeds exactly that: a null array element, a bare string
where an object belongs, `reportedState: null`, a `meta` that is a string, a
host with no id, a device with no id, a `devices` key that is null, a duplicate
device row, and a `lastConnectionStateChange` in 2099. One asset comes out and
the run does not abort.

### What is not here

Clients. Site Manager has no client-level endpoint, so anything about who is
attached to an access point comes from
[`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/README.md) against that
console. Protect cameras arrive as devices with `unifi_product_line:protect`,
but nothing about recordings, sensors, or Protect-specific state.

### Verification status

Verified against the six local fixture scenarios and against vendor
documentation and third-party clients — **not** against a live UI account. The
fixture payloads are built from Ubiquiti's own published examples: the
`reportedState` block is the console shape from List Hosts, the site row is from
List Sites, the device group is from List Devices, and the `nextToken` is a real
one from the vendor's pagination example. The rate limit numbers, the response
envelope fields, and the `/v1` versus `/ea` split come from a published Go
client for this API rather than from developer.ui.com, whose pages are a
JavaScript application this write-up could not render; treat them as
well-corroborated but second-hand. The API key navigation path could not be
pinned to one current answer at all — three sources give three phrasings, all
recorded above. No claim here rests on a live capture.

## Future

- **`GET /v1/hosts/{id}` for the full console record.** The list endpoint's `reportedState` is already several kilobytes per console and the per-host endpoint returns more — the complete controller inventory the console reports upward. It would cost one request per console (an N+1 that needs a cap) and would mostly duplicate what the device list already gives, which is why it is not built.
- **ISP metrics.** `GET /ea/isp-metrics/{type}` returns WAN uptime, latency, and throughput per site, which is genuine operational context for a gateway asset. Two obstacles: it is an Early Access path, so its shape can move without notice, and it is on the 100 requests per minute budget rather than the 10,000 one, so it needs its own pacing.
- **SD-WAN configuration.** `GET /ea/sd-wan/configs` and its `/status` sibling describe the hub-and-spoke topology between consoles. That is a relationship between assets rather than an asset, so it needs a decision about representation before it is worth collecting. Early Access, same caveats.
- **Site statistics as attributes.** The site rows already fetched carry `counts` — total, offline, gateway, wired-client, and wifi-client tallies — and `internetIssues`. Attaching "this site has 12 wifi clients and 1 offline device" to the console asset is nearly free, since the call is already being made; it was left out because a count is a metric, not an asset fact, and it goes stale between polls.
- **Ownership and permission.** Host rows carry `owner` and `userData` (email, role, status), and site rows carry `permission` and `isOwner`. For an MSP that is real administrative context — who can change this console — but it is personal data, so importing it should be a deliberate opt-in parameter rather than a default.
- **Outbound is not worth building.** The Site Manager API is read-oriented, and writing device configuration from an inventory tool is not a defensible pairing regardless.

## API documentation

- Site Manager API overview — https://developer.ui.com/site-manager-api/. Source for the `https://api.ui.com/v1/` base and the endpoint set this integration calls.
- List Hosts — https://developer.ui.com/site-manager-api/listhosts/. The `reportedState` and `hardware` shapes, the `pageSize`/`nextToken` pagination, and the "based on UniFi OS 4.1.13" caveat about payloads varying by version.
- List Sites — https://developer.ui.com/site-manager-api/list-sites. The `hostId` join key, and the `meta` and `statistics.ispInfo` blocks.
- List Devices — https://developer.ui.com/site-manager-api/listdevices. The host-grouped response with `hostId`, `hostName`, `devices[]`, and `updatedAt`.
- Response format and error handling — https://developer.ui.com/site-manager-api/responseformat/. The `data`/`httpStatusCode`/`traceId`/`nextToken` envelope and the `rate_limit` error body.
- Getting Started with the Official UniFi API — https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API. Source for creating the key from the left-nav **API** entry and for the key being displayed only once.
- UniFi Remote Management via Site Manager — https://help.ui.com/hc/en-us/articles/20680072882967-UniFi-Remote-Management-via-Site-Manager. What cloud adoption is and what turning it off does.
- Art of WiFi, "UniFi API Authentication: Local Admin vs. API Key vs. Site Manager" — https://artofwifi.net/blog/unifi-api-authentication-local-admin-vs-api-key-vs-site-manager. The UniFi OS console requirement, the cloud-adoption requirement, and the second reading of the key-creation path.
- `lexfrei/go-unifi` Site Manager client — https://pkg.go.dev/github.com/lexfrei/go-unifi/api/sitemanager. The 10,000 req/min `/v1` limit, the 100 req/min Early Access limit, and the endpoint inventory including `/hosts/{id}` and the SD-WAN paths.

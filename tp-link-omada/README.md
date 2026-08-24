# Custom Integration: TP-Link Omada

Omada is the SMB competitor to UniFi, and the same argument applies: the
controller that adopts the access points, switches, and gateways also watches
every client attached to them, so one credential yields both the infrastructure
and the population using it. This integration reads both — devices and clients,
across every site the credential can see.

It speaks the **Open API** exclusively: the OAuth2 client-credentials surface
TP-Link added in controller v5.12 under Platform Integration, addressed as
`/openapi/v1/{omadacId}/...`. It does not implement the older `/api/v2/login`
session API, and the two do not mix — a token from one is rejected by the other,
and the same field name means different things on each. `status` is the sharp
example: on the Open API path `1` means connected, and on the legacy path the
value carrying that meaning is `14`.

The cost of that choice is that the Open API's device rows are a **reduced**
field set: per-radio detail, per-band client counts, and the numeric
`uptimeLong` live on the legacy path and are simply absent here. What is left is
clean, stable, and enough to inventory a network.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Omada controller's web interface over HTTPS — **TCP 8043** for a self-hosted software controller, which is its default, or 443 for a hardware controller or a regional cloud northbound host.
- A self-hosted controller ships a self-signed certificate, so plan on supplying it as the credential's CA certificate. `OPTIONS_TLS` is exposed for exactly this and nothing is skipped by default.

## Omada requirements

- **Controller v5.12 or newer.** Open API arrived in that release, listed in TP-Link's own V5.12 notes as new feature 5: "Omada Controller now supports Open API integration. You can access it through Global view > Settings > Platform Integration, which allows you to utilize the REST API." That release covered the software controller as V5.12.7 and the OC200 V1/V2 and OC300 V1 as built-in V5.12.9.
- A **controller that actually exposes it**, which is where the sources disagree and where you should check your own box before anything else. TP-Link's V5.12 release covers the OC200, and a local capture from an OC200 on firmware 5.13.30.20 answered Open API device calls. Against that, a widely used third-party Omada integration states flatly that OC200 controllers do not support Open API "regardless of licensing — a hardware limitation," and recommends an OC300 or the free software controller instead. This README cannot settle it. **Open Global View → Settings → Platform Integration; if there is no Open API entry there, this integration cannot run on that controller.** The software controller is the safe answer.
- The **Omada Cloud-Based Controller** is reported not to expose Open API — the `url` parameter accepts a regional northbound host such as `https://use1-omada-northbound.tplinkcloud.com` because that host exists and serves the same path shapes, but no Open API access to it was confirmed for this write-up. Omada Cloud Essentials, the free tier, is reported to have no Open API at all.
- An **Open API application** in Client mode, with a role that can read and site privileges covering the sites you want.
- The controller's **Omada ID** (`omadacId`). Every Open API path contains it.

### Creating the credential in Omada

1. Log in to the controller as an administrator and switch to **Global View** — the Open API settings are global, not per-site.
2. Go to **Settings → Platform Integration → Open API** and click **Add New App**.
3. Name the app (`runZero`) and choose **Client Mode**. The alternative, Authorization Code Mode, asks for a "Redirect URL for Oauth2.0 authorization flow" and drives a browser round trip; this integration implements the client-credentials grant and cannot use it.
4. Set **Role** and **Site Privileges**. TP-Link's own wording is that Role "Specify the client's authority role via the Open API" and Site Privileges "Specify the client's site privileges via the Open API". A **Viewer** role is sufficient — every read this integration performs works under Viewer, confirmed against a live controller; writes are what require Administrator, and this integration performs none. Site privileges are the trap: an application authenticates perfectly with no sites granted and then imports nothing, because the sites collection comes back empty and there is nothing to walk.
5. **Record the Client ID and Client Secret.** The secret is shown when the application is created and not afterwards.
6. Reveal the **Omada ID**. On the Open API page, the view icon next to the application shows "Omada ID and the Interface Access Address". It is also the long hex segment in the controller's own web URL, and it is returned unauthenticated by `GET /api/info`:

   ```bash
   curl -sk 'https://omada.example.com:8043/api/info'
   # {"errorCode":0,"msg":"Success.","result":{"controllerVer":"5.13.30.20","omadacId":"a5df88fd23ca87e694ceabac309add4b","configured":true}}
   ```

7. Confirm the whole flow from the Explorer host before configuring anything in runZero. The grant type travels in the **query string** and the three credentials in the **JSON body** — sending the credentials as query parameters is rejected — and the resulting token is presented with a non-standard scheme. TP-Link's guide is explicit: "The prefix in the Authorization header must be `AccessToken=`". It is not `Bearer`.

   ```bash
   OMADAC=a5df88fd23ca87e694ceabac309add4b

   TOKEN=$(curl -sk -X POST \
     "https://omada.example.com:8043/openapi/authorize/token?grant_type=client_credentials" \
     -H 'Content-Type: application/json' \
     -d "{\"omadacId\":\"$OMADAC\",\"client_id\":\"7f3a91c04e8b4d62\",\"client_secret\":\"c1d5e9b70a2f4836\"}" \
     | jq -r .result.accessToken)

   curl -sk -H "Authorization: AccessToken=$TOKEN" \
     "https://omada.example.com:8043/openapi/v1/$OMADAC/sites?page=1&pageSize=10" | jq .
   ```

   Success is `{"errorCode":0,"msg":"Success.","result":{"totalRows":1,...}}`.
   An `errorCode` of `-44106` is reported in TP-Link's community as an invalid
   client id or secret. A `-1600` on the sites path means this firmware does not
   implement it.

8. Your controller serves its own API reference. A software controller publishes it at `https://<controller>:8043/doc.html#/home`, and the controller UI links it as "Online API Document" from the Platform Integration page. That is the authority for your firmware; the public documentation is thin and lags.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Omada").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Omada controller URL** (`url`): base URL of the controller, for example `https://omada.example.com:8043`. Required.
   - **Omada controller ID (omadacId)** (`omadac_id`): the value from step 6. Required.
   - **Open API client ID** (`client_id`): from step 5. Required.
   - **Open API client secret** (`client_secret`): from step 5. Required.
   - **Site IDs** (`site_ids`): optional, comma-separated `siteId` values. Leave blank to walk every site the application has privileges for.
   - **Import Omada devices** (`extract_devices`): the access points, switches, and gateways (default: true).
   - **Import clients** (`extract_clients`): the wired and wireless clients attached to them (default: true).
   - **Page size** (`page_size`): rows per page (default: 100).
   - **Maximum pages per collection** (`max_pages`): hard stop per collection (default: 200). Hitting it fails the run with a `pagination limit reached` error rather than truncating silently.
   - **TLS options** (`tls_*`): set the CA certificate here if the controller uses its own. Turning validation off is a last resort.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Devices change rarely; clients change constantly, so the cadence is really a question about how fresh you want the client population.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with the MACs, addresses, models, and firmware versions the controller holds.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:tp-link-omada`.
- Devices carry their serial as a tag, so `tag:serial:22394A7000123` finds an access point by the label on its back.
- Everything else lands under the `omada_` prefix. `omada_site_name:"Branch-Hamburg"` scopes to a site, `omada_ssid:Guest-WiFi` finds everything on the guest network, `omada_vlan_id:20` finds a VLAN's population, `omada_ap_name` / `omada_switch_name` / `omada_port` say which port or radio a client is on, `omada_guest:true` and `omada_blocked:true` find the policy edges, and `omada_need_upgrade:true` finds the fleet that is behind.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm the
application's credentials and privileges. Each `CONFIG` parameter is one
`--kwargs key=value` pair:

```bash
runzero script --filename tp-link-omada/tp-link-omada.star \
  --kwargs url=https://omada.example.com:8043 \
  --kwargs omadac_id=a5df88fd23ca87e694ceabac309add4b \
  --kwargs client_id=7f3a91c04e8b4d62 \
  --kwargs client_secret=c1d5e9b70a2f4836 \
  --kwargs extract_clients=false \
  --kwargs tls_ca_cert=/etc/omada/controller.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/tp-link-omada-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; `--overwrite` replaces a directory from an
earlier run. Turning clients off on a first run is the cheapest way to check
that the credential and the site privileges work, because devices are a much
smaller collection.

**One CLI caveat, and it no longer lands on Site IDs.** `--kwargs` passes a value
through verbatim, commas included, as long as the pair contains a single `=`, so
a multi-value **Site IDs** (`site_ids`) value goes on the command line exactly as
the console takes it — `--kwargs site_ids=<siteId>,<siteId>`. What breaks is a
value carrying a *second* `=` **as well as** a comma: that pair is re-read as CSV,
so the value is cut off at the comma and the remainder becomes a parameter the
integration never declared and then rejected by a name nobody set. A client
secret is the value here that could be that shape; wrap it in double quotes to
keep it a single field, `--kwargs '"client_secret=a=b,c"'`.
`--custom-integration-script-kwargs` is the stricter flag — one comma-separated
string for everything, so a `site_ids` list cannot go through it at all.

To check only that the `CONFIG` block and the HTTP and TLS wiring are sound,
without touching a controller:

```bash
runzero script --filename tp-link-omada/tp-link-omada.star --validate
```

Validation answers from a local dummy server whose collections are always
empty, so it proves the script initializes, declares its parameters, and issues
a request. It parses no rows, and it never exercises the token exchange against
anything that behaves like Omada. The fixture suite is what proves that:

```bash
python3 tests/run.py tp-link-omada
```

That runs the six scenarios in `tp-link-omada/tests/fixtures/` — `happy`,
`empty`, `malformed`, `mac-identity`, `auth-refresh`, and `paged` — against the
real scanner.

To run it the way the platform does, as an integration task that uploads its
results, use the `scan` command. `--custom-integration-id` is the UUID shown on
the integration's page in the console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://omada.example.com:8043,omadac_id=a5df88fd23ca87e694ceabac309add4b'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two kinds of asset are emitted as two declared asset types — `device` and
`client` — selected per record with `ImportAsset(assetType=...)`, and each
type's merge policy is declared under that key in
`CONFIG["assetTypeBehavior"]`.

`type-break` is left ON (the default), so a `device` and a `client` never merge
with each other. The controller itself partitions the two populations: adopted
Omada hardware is listed under devices and never appears in the client list of
the switch or gateway it is plugged into, so a MAC is only ever on one side.
Keeping the break on is what stops a client record — whose id is a randomized
MAC, and which merges purely on MAC, address, and hostname — from folding a
managed access point or gateway into a station record when an address is
reassigned.

### Omada devices

- Target entity: one device the controller manages — an access point, a switch, or a gateway.
- Source ID field: **`mac`**, canonicalised to uppercase colon-separated form. There is no other candidate: the Open API device row carries `sn`, but the controller does not route by it.
- Documentation evidence: every per-device Omada path is addressed by MAC — the legacy detail endpoint is `/{oid}/api/v2/sites/{sid}/eaps/{MAC}` and the write path is the same URL — so the MAC is the controller's own handle for a device, not merely a field on it. The Open API returns it hyphenated and uppercase (`50-D4-F7-66-0D-9C`); the script re-separates it to colons and changes nothing else.
- Uniqueness scope: one controller. The `omadacId` is part of the runZero id, so two controllers that both manage a device — a device moved between deployments, or an MSP importing two customers — do not collide.
- Cardinality: one row per device per site. A device appearing in two sites' listings is collapsed on the composed id with `skipping duplicate device <mac>`.
- Stability: it is burned in. It survives a rename, an address change, a firmware upgrade, a site move, and a factory reset.
- Reuse behavior: none, short of a manufacturing collision.
- Presence: on every device row. A row with no MAC, or with the all-zero or broadcast MAC, is skipped with `skipping device with no usable mac in site <siteId>`.
- Final runZero ID: `tp-link-omada:a5df88fd23ca87e694ceabac309add4b:device:50:D4:F7:66:0D:9C`.
- Missing-ID behavior: skip and log. No identity is synthesized and `new_uuid()` is never used.
- Asset type: **`device`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**. The identifier is what the controller itself keys the device by, so it may drive a merge; a changed address or a renamed access point must not veto one.
- Verdict: **a MAC in the foreign id, deliberately, on hardware where that is safe.** The repo's `no_mac_in_id` invariant exists because `normalize_mac` clears the locally administered bit, folding two randomized endpoints into one asset. Neither half of that applies here: TP-Link infrastructure MACs are burned in and never randomized, and the script never normalizes — see below. Every Omada fixture declares the skip explicitly rather than passing quietly.

### Omada clients

- Target entity: one endpoint attached to an Omada device — a laptop on a radio, a sensor on a switch port, a phone on the guest SSID.
- Source ID field: **`mac`**, canonicalised the same way.
- Documentation evidence: it is the only identifier a client row has. There is no client id, no lease id, and no persistent handle of any kind.
- Uniqueness scope: one controller, via `omadacId`.
- Cardinality: one row per client. A client that roams between access points is still one row.
- Stability: **poor, and that is the whole point of this entry.** A modern phone or laptop invents a new MAC per SSID, and rotates it. The same physical device is a different id next month, and two ids that differ can be one device.
- Reuse behavior: a randomized MAC is drawn from a 46-bit space, so exact reuse is improbable — but the value does not name a device durably, which is the failure mode that matters here.
- Presence: on every client row. A row with an unparseable, all-zero, or broadcast MAC is skipped with `skipping client with no usable mac in site <siteId>`.
- Final runZero ID: `tp-link-omada:a5df88fd23ca87e694ceabac309add4b:client:3C:22:FB:11:22:33`.
- Missing-ID behavior: skip and log.
- Asset type: **`client`**.
- Match behavior: **`no-id-match no-id-break`**. The identifier is derived rather than issued, so it must neither drive a merge nor block one; correlation falls back to the MAC on the interface, the address, and the hostname, which the platform handles with its own MAC semantics. The id is still emitted so an asset can be traced back to the row it came from.
- Verdict: **derived / non-authoritative.** Treat client assets as evidence that something was on this network at this SSID and VLAN, not as an inventory record.

### Why the MAC is canonicalised rather than normalized

This is what the `mac-identity` scenario exists to lock down, and it is the one
identity decision here worth arguing about. The script deliberately does **not**
use `net.normalize_mac`. That helper clears the locally administered bit so a
randomized MAC can match across sources, which is right for a network interface
and wrong for an identifier: every randomized client MAC sets that bit, so
`02:1A:2B:3C:4D:5E` and `00:1A:2B:3C:4D:5E` normalize to one value and two
genuinely different endpoints fold into a single asset. The canonicaliser here
only changes separators and case, so nothing is lost and the two stay apart. The
scenario feeds exactly that pair, plus the same client seen again with a changed
address and a changed name, and asserts three assets out with the identifier
unmoved.

## Notes

### What is imported

One token exchange, one sites call, then devices and clients per site:

| runZero | Omada Open API |
|---|---|
| `id` | `mac`, canonicalised |
| `hostnames` | device `name`; client `name` then `hostName` |
| `networkInterfaces` | `mac`, `ip`, and `ipv6List` |
| `manufacturer` | the literal `TP-Link` on devices; the client's own `vendor` on clients |
| `model` | `model` |
| `osVersion` / `os` | device `firmwareVersion` / client `osName` |
| `deviceType` | `ap` and `eap` to Wireless Access Point, `switch` to Switch, `gateway` to Router |
| `tags` | `serial:<sn>` on devices |
| `customAttributes` | the site, the row's state and counters, and for a client its SSID, VLAN, network name, and the access point, switch, or gateway it is attached to |

Clients get no `deviceType`. Omada's `deviceType` and `deviceCategory` are its
own fingerprinting guesses — "MacBook", "Linux Device" — which do not map onto
runZero's device type vocabulary cleanly, so they are kept verbatim as
`omada_device_type` and `omada_device_category` and nothing is inferred. No
`Service`, `Software`, or `Vulnerability` records are emitted.

### An HTTP 200 is not a success

Every Open API response is wrapped in `{"errorCode": N, "msg": "...", "result":
...}`, and the controller reports failures inside that envelope with a 200
status. Checking status codes alone would report success while importing
nothing, so every response here is unwrapped and its `errorCode` inspected; a
response that is not an object, or that carries no integer `errorCode`, is
reported as such rather than having a missing field read as zero.

Two codes are handled specially. **`-1600`** is what the controller answers for
a path this firmware does not implement — confirmed against a live controller,
where every guessed endpoint returned it — and is treated as "this collection is
unavailable here, skip it" rather than as a run failure. The **`-441xx` family**
is the token error set: `-44112` and `-44113` on a data request, and `-44111`,
`-44114`, and `-44106` from the refresh path. TP-Link does not publish a
complete error code table publicly; these are the values seen in practice and in
community reports, and `-44106` in particular is reported there as an invalid
client id or secret, in which case the refresh fails too and the run says so.

### Token lifetime and refresh

The `client_credentials` grant returns an `accessToken` with `expiresIn: 7200`
— two hours, verified against a live controller. A collection run is far shorter
than that, so the token is minted once at the start of a run and the refresh
path exists for the case the token is rejected anyway: a controller restarted
mid-run, a clock skew, an administrator revoking the application.

The refresh is reactive and bounded to **one** extra attempt per request. The
`auth-refresh` scenario proves it the way the controller really behaves — HTTP
200 with `errorCode -44112` in the envelope, not a 401 — and asserts that
exactly one extra token exchange happens and that the retried request carries
the *new* token. A plain 401 is also handled, for firmwares that answer that
way. The `refreshToken` the grant returns is not used: the run re-mints with the
same client-credentials call, which is one request either way and one less piece
of state to carry across a retry.

### Pagination

Each collection is walked with `page` and `pageSize`, and a page is turned into
assets and handed to `report_asset` before the next page is requested, so peak
memory is one page rather than one estate. The walk stops on whichever comes
first: `page * pageSize >= totalRows`, a page shorter than requested, or an
empty page. The `max_pages` ceiling is enforced by a `pager()` loop guard, so
hitting it **fails the run with an error naming the collection** — the pages
already streamed are still imported, but a truncated import no longer looks
like a complete one.

There is one defensive case worth naming. A response whose `result` is a **bare
list** rather than a paginated envelope is treated as the whole collection and
the walk stops after it. Without that check, a firmware that ignores the `page`
parameter would answer page 2 with the same rows forever, which is a loop rather
than an error. The `malformed` scenario serves exactly that shape and asserts
the walk ends after one page.

`page_size` is bounded at 1000 by the parameter itself; the Open API's actual
maximum was **not established from vendor documentation**, so if your controller
rejects a large page, lower it.

### Sites

With **Site IDs** blank, the run lists sites from `/openapi/v1/{omadacId}/sites`
and walks each one, reading the identifier as `siteId` and falling back to `id`
— the legacy path uses `id` where the Open API uses `siteId`, which is an easy
thing to get backwards. With **Site IDs** set, the list is used verbatim and the
sites collection is never called at all. That is not an optimization but an
escape hatch, for an application whose privileges cover the sites themselves and
not the collection that lists them; the `empty` scenario asserts the sites path
is never requested when the list is configured.

### Addresses and hostnames

Link-local is filtered here rather than by the platform, which drops loopback,
multicast, and unspecified addresses but deliberately keeps link-local — and two
clients that both failed DHCP and hold `169.254.x.x` would otherwise correlate
to each other. Omada also names an unnamed device or client after its own MAC,
so a name that parses as a MAC, or that equals the row's own MAC in any
separator style, is rejected rather than imported as a hostname, along with
`localhost`, `unknown`, `unknown device`, and bare addresses.

### Timestamps

`lastSeen` is an integer epoch and the unit is **not documented**. The
controller sends milliseconds on the paths where it has been observed, so the
magnitude decides: a seconds value of the present era is about 1.8e9 and a
milliseconds value about 1.8e12, which any threshold between them separates
cleanly for this century. The result is clamped to the current time, because a
future timestamp does not fail the field — it fails the entire `ImportAsset`,
and a controller with a skewed clock would import nothing. The `malformed`
scenario feeds a `lastSeen` of 4102444800000, the year 2100, and asserts the
asset survives.

### Verification status

Verified against the six local fixture scenarios and against a combination of
vendor documentation and a **live-captured** Omada client library — not against
a live controller from this repo. The authentication flow, the
`Authorization: AccessToken=` scheme, the 7200-second token lifetime, the
`errorCode -1600` behavior, the Viewer-role sufficiency for reads, and the Open
API device row's reduced field set all come from that library's notes, which
record a verification pass against a real OC200 on firmware 5.13.30.20. The
token and envelope shapes in the fixtures follow a published capture from an
Omada software controller. The controller-model question is the one genuinely
unsettled item and is flagged above rather than papered over. The Open API
maximum page size, and Open API availability on the Cloud-Based Controller,
were not established at all.

## Future

- **Per-device detail for access points.** The legacy `/{oid}/api/v2/sites/{sid}/eaps/{MAC}` endpoint returns everything the list row has plus `ssidOverrides`, `lanPortSettings`, and per-radio configuration. It is genuinely richer, but it is on the other authentication surface, so reaching it means implementing the session-and-CSRF login as a second credential path. That is a real feature, not a small one.
- **Per-radio state as attributes.** `wp2g` and `wp5g` carry the actual channel, transmit power, bandwidth, and channel utilization. They are absent from the Open API entirely. Worth having for an RF-aware inventory; same obstacle as above. Note the trap if it is ever built: on the 5GHz radio the channel half of `actualChannel` is an internal index rather than the channel number an operator would recognise, and the frequency in MHz is the only unambiguous value.
- **Insight clients.** `/{oid}/api/v2/sites/{sid}/insight/clients` returns historically known clients rather than only currently associated ones, which would surface devices that were on the network last week and are not on it now. Legacy path again, and it makes the client population much larger — so it needs a bound and a decision about what a client that has not been seen in months should look like as an asset.
- **Gateway WAN and DHCP detail.** A gateway's WAN addressing and its DHCP client list would identify hosts the controller can see but has not adopted. No Open API endpoint for either was confirmed, so this starts with endpoint discovery against a real controller rather than with code. Switch port topology is a related and cheaper win: client rows already carry `switchMac` and `port`, imported as attributes today, and turning that pair into a modelled relationship rather than two strings is a platform question more than an integration one.
- **Outbound is not worth building.** The Open API can write configuration, and one write is known to report `errorCode 0` while silently discarding the change unless a companion field is filled in exactly right. Pushing configuration from an inventory tool would be indefensible even without that.

## API documentation

- How to Configure OpenAPI via Omada Controller — https://community.tp-link.com/en/business/kb/detail/412930. Source for the **Global View → Settings → Platform Integration → Open API → Add New App** path, and for Client Mode versus Authorization Code Mode with their Role and Site Privileges fields.
- How to Create Site in Omada Controller via Open API — https://support.omadanetworks.com/sg/document/109315/. Source for the `AccessToken=` Authorization prefix, for recording the Client ID and Client Secret at creation, and for the view icon that reveals the Omada ID.
- Omada SDN Controller V5.12 release announcement — https://community.tp-link.com/en/business/forum/topic/619304. Source for Open API being introduced in v5.12 and for which controller builds that release covered.
- Omada software controller release notes — https://github.com/omada-dev/omada-software-controller/blob/master/release_note.txt. Version history, and the later Open API bug fixes that show it is actively maintained.
- `bullitt186/ha-omada-open-api` — https://github.com/bullitt186/ha-omada-open-api. A production Open API consumer; source for the claim that the OC200 does not support Open API, which is the one contested point above.
- `tplink-omada-client` — https://pypi.org/project/tplink-omada-client/. The most complete public client for the legacy `/api/v2` surface, and the reference for what that path returns that the Open API does not.
- Open API authentication walkthrough with real request and response bodies — https://gist.github.com/mbentley/03c198077c81d52cb029b825e9a6dc18 and its Open API transcription. Source for the token response shape (`accessToken`, `tokenType`, `expiresIn`, `refreshToken`) and for the `siteId` spelling on the Open API sites collection.
- Your own controller's API reference, at `https://<controller>:8043/doc.html#/home` or via the "Online API Document" link on the Platform Integration page. The authority for your firmware, and better than any of the above.

# Custom Integration: HPE Aruba ClearPass

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the ClearPass Policy Manager appliance over HTTPS.

## HPE Aruba ClearPass requirements

- An API client created under **Guest > Administration > API Services > API Clients** with the **Client Credentials** grant type enabled. The client's operator profile determines what the token can read.
- The operator profile must grant read access to the **Endpoints** (Platform / Identity) API. Read access to **Active Sessions** is additionally required only when the session join is enabled.
- The integration issues `GET` requests only. No write permission is needed, and none should be granted.
- The client secret is displayed once, when the API client is created. If it was not recorded, generate a new one.

## Steps

### HPE Aruba ClearPass configuration

1. Sign in to ClearPass Guest and go to **Administration > API Services > API Clients**.
2. Click **Create API Client** and give it a name, for example `runzero-import`.
3. Set **Operating Mode** to `ClearPass REST API` and **Grant Type** to `Client credentials (grant_type = client_credentials)`.
4. Select an **Operator Profile** with read-only access to the endpoint database (and to active sessions if the session join will be used).
5. Set an **Access Token Lifetime** long enough to cover a full import. The integration authenticates once per task and does not refresh the token mid-run, so a short lifetime can end a large import partway; the script prints a warning when the returned lifetime is under 15 minutes.
6. Save the client and record the **Client ID** and **Client Secret**.
7. Confirm access from the Explorer host, for example:
   `curl -sk -X POST https://<cppm>/api/oauth -H 'Content-Type: application/json' -d '{"grant_type":"client_credentials","client_id":"<id>","client_secret":"<secret>"}'`

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "HPE Aruba ClearPass").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **ClearPass URL** (`url`): base URL of the Policy Manager appliance, e.g. `https://cppm.example.com`. The `/api` path is appended automatically.
   - **API client ID** (`client_id`): Client ID of the API client.
   - **API client secret** (`client_secret`): client secret for that API client.
   - **Endpoint status** (`status_filter`): optional; import only endpoints with this status — `any`, `known`, `unknown`, or `disabled` (default: `any`).
   - **Join active RADIUS sessions** (`include_sessions`): optional; join the active session table for the live client IP, NAS address and port, SSID, and assigned role (default: disabled).
   - **Maximum profile age (days)** (`max_profile_age_days`): optional; drop the profiled IP addresses of any endpoint last profiled longer ago than this, keeping the asset MAC-only (default: `0`, meaning no age limit).
   - **Page size** (`page_size`): optional; value sent as `limit` on every paged read, capped at 1000 by the API (default: 500).
   - **Maximum pages to retrieve** (`max_pages`): optional; safety ceiling on the paging walk (default: 20000, which is ten million endpoints at the default page size). Raise it if a run logs `page limit of ... hit (integration safety limit`. Left unset, the ceiling scales with `page_size` so a smaller page still reaches the same ten-million-record target.
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
runzero script --filename aruba-clearpass/aruba-clearpass.star \
  --kwargs url=https://cppm.example.com \
  --kwargs client_id=runzero-import \
  --kwargs client_secret=8f3c19d4e6b7a05f2c81d93e4a7b6f5c0d2e9a48 \
  --kwargs status_filter=known \
  --kwargs include_sessions=false \
  --kwargs page_size=100 \
  --output ./clearpass-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Start with a small `page_size` and `include_sessions=false`. The session join adds a
second full table read and its addresses are transient, so it is worth confirming the
endpoint import first.

To check the `CONFIG` block and the HTTP and TLS wiring without a live appliance:

```bash
runzero script --filename aruba-clearpass/aruba-clearpass.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove ClearPass accepts the API client or that any endpoint is
parsed.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py aruba-clearpass
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat aruba-clearpass/aruba-clearpass.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://cppm.example.com,client_id=runzero-import,client_secret=<secret>' \
  --output ./clearpass-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a client secret
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with endpoint, profiling, and NAC data pulled from HPE Aruba ClearPass.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:aruba-clearpass`.

## Asset identity

- Target entity: a network endpoint as ClearPass knows it — the physical or virtual device behind one MAC address that has authenticated to, or been profiled on, the network. It is a network-access record, not a hardware inventory record.
- Source ID field: `endpoint.mac_address`. The numeric `endpoint.id` is deliberately **not** used.
- Documentation evidence: the `GET /endpoint` reference types `id` as "Numeric ID of the endpoint" and `mac_address` as "MAC Address of the endpoint". The endpoint database is addressed by MAC throughout the rest of the API — `GET`/`PUT`/`DELETE /endpoint/mac-address/{mac_address}` operate on an endpoint by MAC alone, which is the API's own statement that the MAC is the natural key of this collection. The numeric id has no such addressing role outside `/endpoint/{endpoint_id}`.
- Uniqueness scope: one ClearPass cluster. The endpoint database is replicated from the publisher across the cluster, and the numeric id is allocated by that publisher, so it means nothing on another cluster — two appliances polled into one runZero organization would collide on it. The MAC is globally scoped in principle, so only the appliance hostname is added, to keep two ClearPass deployments that both know a device from merging their differing views into one identity.
- Cardinality: one endpoint row per MAC, and therefore one asset per MAC. A device with several NICs appears as several endpoints and produces several assets; runZero merges them if it has other evidence. Several `session` rows can point at one endpoint — those collapse into a single asset, with the most recent active session winning.
- Stability: the id survives a status change, a description or attribute edit, a re-profile, an IP change, a hostname change, a device_insight_tag change, and a change in how the appliance formats the MAC (`aabbccddeeff`, `AA:BB:CC:DD:EE:FF`, and `aabb.ccdd.eeff` all normalize to one value). It does **not** survive a NIC replacement or a client rotating its randomized MAC — either produces a new endpoint and a new asset.
- Reuse behavior: yes, in the sense that matters. A MAC is reused when a NIC moves to another chassis, and a randomized MAC is invented per network by the client. Deleting an endpoint and re-authenticating the same device recreates the row with the same MAC and a *new* numeric id, which is a further reason not to key on the id.
- Presence: `mac_address` is present on every endpoint in the database — the row cannot exist without one. Rows that arrive without a parseable MAC, and rows that are not objects at all, are skipped and counted.
- Final runZero ID: `aruba-clearpass:<cppm-hostname>:<mac>` — for example `aruba-clearpass:cppm.example.com:00:11:22:33:44:55`. The MAC is lower-cased and colon-separated by the script's own normalizer rather than by the shared `net.normalize_mac` helper, because that helper clears the locally-administered bit of the first octet (`02:00:00:00:00:01` normalizes to `00:00:00:00:00:01`, verified against the Explorer runtime), which would fold two genuinely different endpoints onto one id. Randomized client MACs all carry that bit, and ClearPass sees a great many of them.
- Missing-ID behavior: skip. The endpoint is logged by its numeric id only, never the record body, and no id is invented. `new_uuid()` is not used anywhere in the script.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. The id is derived from the MAC rather than issued by ClearPass, so it must not drive or block merging; correlation falls back to the MAC, the profiled addresses, and the profiled hostname. Every emitted record carries a usable MAC by construction, so runZero always has a correlation signal.
- Verdict: **derived / non-authoritative.** ClearPass is an access-control system, not an asset inventory. Its only durable handle on a device is the MAC, which it does not own and cannot guarantee; the identifier it does own is cluster-local and is recycled on delete. Treat this integration as an enrichment source that layers NAC status, device profiling, and network-attachment context onto assets runZero already knows about.

### Notes

- What is imported: one asset per endpoint from `GET /api/endpoint`. Each asset carries the MAC, the ClearPass status, the description, the randomized-MAC flag, Device Insight tags, the endpoint's free-form `attributes` map, the `profile` block (addresses, hostname, device category / OS family / device name, who profiled it and when), and the `nad_detail` block (`nad_ip`, `nad_port`). Custom attributes are prefixed `aruba_clearpass_`.
- **No software, no services, and no vulnerabilities are imported.** ClearPass does not hold any of them. It records how a device authenticates and what the profiler infers about it, not what is installed on it or what is listening on it. There is no endpoint in the API that would supply them.
- Addresses: `profile.ipv4_address` and `profile.ipv6_address` are the endpoint's own profiled addresses and are attached to the network interface by default. This is a stored profiling result, not a live observation — the profiler updates it when it next sees the device. **Maximum profile age (days)** drops those addresses (keeping them as custom attributes and tagging the asset `aruba-clearpass-stale-profile`) when `profile.last_profiled_at` is older than the limit. An endpoint with no `profile` block at all, which is what an unprofiled endpoint and older ClearPass releases return, becomes a MAC-only asset; that is a supported and useful outcome, because runZero correlates on MAC.
- Loopback, unspecified, and link-local addresses (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`) are filtered out of every address list before an interface is built, and are kept verbatim as custom attributes. An endpoint whose only profiled address is loopback becomes a MAC-only asset rather than sharing an address with every other such endpoint.
- Session join (**Join active RADIUS sessions**, off by default): indexes `GET /api/session` by client MAC and attaches the NAS address and name, NAS port and port type, SSID, AP name, service type, assigned roles (`tipsrole`, `arubauserrole`, `arubauservlan`, `role_name`), `username`, and the accounting start time. **Only sessions with `state` of `active` are joined at all.** A `stale` or `closed` row describes where a device used to be, and importing its `framedipaddress` is worse than importing no IP: it would merge the ClearPass endpoint onto whichever asset holds that address now. The state filter is applied server-side via `filter={"state":"active"}` to keep closed accounting history off the wire, and re-checked client-side so an appliance that ignores the filter still cannot contribute a stale address. When a MAC has several active sessions the one with the latest `acctstarttime` wins, with the accounting `id` breaking a tie, so the choice does not depend on the server honoring `sort=-id`. Sessions are matched on `mac_address`, falling back to `callingstationid`.
- Privacy: the session table doubles as the guest registration store. The script copies a fixed allowlist of network and authorization fields off a joined session and never reads `visitor_name`, `visitor_company`, `visitor_carrier`, `visitor_phone`, `sponsor_name`, `sponsor_email`, or `sponsor_profile_name`. `username` and the role fields *are* imported, as the NAC identity is the point of the join; if that is not wanted, leave the session join disabled.
- Classification: `profile.device_category` sets `deviceType` only for the categories that name a runZero device type outright (printer, access point, router, switch, firewall, IP phone, IP camera, smart device, server, storage, game console, scanner, UPS, virtual machine). `Computer` is deliberately not mapped, because runZero separates server, desktop, and laptop and the category cannot tell them apart. Device Insight tags are consulted for a device type only when the profile carries no category, and only for substrings that name a device class outright. Every classification value is kept as a custom attribute and as a tag regardless: `device-category:`, `device-os-family:`, `device-name:`, and one `device-insight:` tag per Device Insight tag.
- `profile.device_os_family` and `profile.device_name` are **not** mapped to `os` or `model`. They are profiler family labels such as `Apple` or `Apple iPad`, not an OS product and version or a hardware model, and runZero's own fingerprinting produces better values. Both are preserved as attributes and tags.
- `device_insight_tags` is typed as a string in the API reference while the appliance and Aruba's own clients treat it as a list. Both shapes are accepted; a string is split on commas.
- Timestamps: `added_at` becomes `firstSeenTS` (falling back to `profile.first_profiled_at`), and `updated_at` becomes `lastSeenTS` (falling back to `profile.last_profiled_at`). These four fields are typed only as `string` in the API reference, so the wire format is not contractual: every value is shape-checked before parsing, "never" sentinels such as `0001-01-01T00:00:00` are discarded, and a value carrying no UTC offset is read as UTC — the appliance's own time zone is not exposed anywhere in the response. Every raw value is also kept verbatim as a custom attribute. Because of that UTC assumption, both timestamps are **clamped to the current time** before assignment: runZero rejects an asset whose first- or last-seen time is in the future and the error fails the entire record, so an appliance east of UTC would otherwise have every asset dropped. The clamp skews first-seen and last-seen toward the present instead of losing the asset.
- Pagination: `offset` and `limit` with `calculate_count=false`, which keeps the appliance from scanning the table for a total nothing here needs. Responses are HAL+JSON; rows are read from `_embedded.items` and the walk stops on a short page or on the absence of `_links.next`. `sort` is sent explicitly (`+id` for endpoints, `-id` for sessions). An appliance that ignores `offset` produces none of those exits, so the primary guard is a page-signature check: a page whose length and end ids match the previous page stops the walk on the first repeat with `paging stopped after N pages (API returned the same page twice ...)`. Behind it, `max_pages` is a backstop that logs `page limit of N hit (integration safety limit, ...) - raise the max_pages parameter to import the rest`. Because no total is requested, both lines say `total not reported` rather than inventing a denominator.
- The `filter` parameter is a JSON-encoded string, not repeated query parameters, so an unfiltered read sends the literal `{}` and a status-scoped read sends `{"status":"Known"}`. This was confirmed on the wire against a local fixture.
- Rate limiting: ClearPass publishes no documented API rate limit. The shared HTTP helper's default retry budget covers 408/425/429/500/502/503/504 and transport errors and honors `Retry-After`; the backoff is raised to 2 seconds because the appliance answering the API is the same node authenticating the network.
- Authentication is a single `client_credentials` exchange at `POST /api/oauth` with a JSON body, per the API reference. The resulting bearer token is used for the whole task; there is no mid-run refresh, so a very large import under a short token lifetime can end early with a 401. The script warns when the returned `expires_in` is under 15 minutes.
- Unverified assumptions: the endpoint `status` values used by the filter are assumed to be matched with the API's own capitalization (`Known`, `Unknown`, `Disabled`); the `state` values used for the session filter are assumed to be lower case as documented, though the client-side re-check is case-insensitive and covers the alternative; and the wire format of the four endpoint timestamp fields is inferred rather than documented.
- Evidence base: ClearPass's Swagger definitions are served from the appliance itself at `https://<cppm>/api-docs` and the rest of the documentation sits behind the HPE support portal, so neither can be linked here. The object schemas, query parameters, and OAuth contract below were taken from the public Aruba Developer Hub mirror of those definitions, and corroborated against Palo Alto's open-source XSOAR client for ClearPass, whose test fixtures show the actual HAL envelope.
- This integration was validated against local fixtures, not a live HPE Aruba ClearPass appliance.

## Future

- **Outbound: push runZero classification into ClearPass so NAC policy can act on it.** This is by far the strongest pairing available here. `PATCH /api/endpoint/{endpoint_id}` accepts `status`, `description`, `device_insight_tags`, and the free-form `attributes` map, and `PUT /api/endpoint/mac-address/{mac_address}` additionally replaces the profile's `device_category`, `device_os_family`, and `device_name`. Endpoint attributes are first-class inputs to ClearPass Enforcement Policy, so writing a runZero device type, hardware fingerprint, or risk signal into an endpoint attribute lets a policy assign a role or VLAN from evidence ClearPass could not gather itself — runZero regularly identifies devices the profiler leaves as `Unknown`. **Treat this as operationally sensitive and default it off:** these fields are policy inputs, so a bad write does not pollute an inventory, it changes who gets on the network. A rollout should write to a single dedicated endpoint attribute that a purpose-built policy rule consumes, never to `status` or to the profile triple, and should be piloted against one test rule before it is scheduled.
- **Session disconnect as a response action.** `POST /api/session/{id}/disconnect` (with `{"id": ..., "confirm_disconnect": true}`) terminates an active session and forces reauthentication. That is a real containment primitive — a runZero detection could kick a device off the network — but it is disruptive, immediate, and aimed at a session id that may already have rolled over. It belongs behind an explicit operator action, not a scheduled task, and the request must be issued with retries disabled since it is not idempotent.
- **Device profiling as classification enrichment.** The `profile` block is ClearPass's own DHCP, HTTP User-Agent, MAC OUI, SNMP, and Device Insight fingerprinting output, expressed as the documented `device_category` / `device_os_family` / `device_name` hierarchy. This integration promotes only unambiguous categories to `deviceType`. Feeding the full triple, plus the Device Insight tags, into runZero's own fingerprint engine as corroborating evidence would classify a large slice of endpoints that never respond to a scan — exactly the quiet IoT and OT devices where NAC has visibility and active scanning does not.
- **NAC coverage-gap reporting.** This needs no new endpoint and is the most valuable thing the two datasets do together. Devices runZero sees on the wire whose MAC has no ClearPass endpoint row have never been authenticated — unmanaged devices on a segment that NAC does not cover, or ports where enforcement is not enabled. The inverse, endpoints ClearPass holds with `status=Unknown` and no recent profile, are stale rows or devices that have left. Endpoints with `randomized_mac` set are flagged with the `aruba-clearpass-randomized-mac` tag already, because their MAC is a per-network address the client invented and neither system should treat it as durable device identity.
- **Alert and event ingestion is limited.** There is no webhook or subscription API. `GET /api/system-events` exposes the appliance's own system event log, which is useful for monitoring the ClearPass deployment but describes the appliance rather than the endpoints on it. ClearPass's real event stream is syslog in CEF form, sent out of Policy Manager rather than polled, so ingesting authentication successes and failures belongs in a log pipeline and not in a custom integration script.
- **Attribute dictionary as schema context.** `GET /api/attribute` enumerates the endpoint attribute dictionary — name, `entity_name`, and `data_type` for every custom attribute defined on the deployment. Reading it would let an import validate or type the free-form `attributes` map instead of flattening it verbatim, and would be a prerequisite for any outbound write that needs to create the attribute it writes to (`POST /api/attribute`).

## API documentation

ClearPass serves its own Swagger/OpenAPI definitions from the appliance at `https://<cppm>/api-docs`, and the Policy Manager and Guest guides are behind the HPE support portal. The public mirrors below are the definitions actually used.

- Getting started with the ClearPass Policy Manager API (API client creation, grant types, operator profiles): https://developer.arubanetworks.com/cppm/docs/getting-started-with-the-clearpass-policy-manager-api
- OAuth token endpoint (`POST /oauth`, JSON body, `client_credentials`, `access_token` / `expires_in` / `token_type`): https://developer.arubanetworks.com/cppm/reference/tokenendpointpost
- `GET /endpoint` (query parameters `filter`, `sort`, `offset`, `limit`, `calculate_count`; `EndpointResult` with `profile` and `nad_detail`): https://developer.arubanetworks.com/cppm/reference/endpointget
- `PUT /endpoint/mac-address/{mac_address}` (MAC as the addressable key; only `device_category`, `device_os_family`, and `device_name` are writable within the profile): https://developer.arubanetworks.com/cppm/reference/endpointmac-addressbymac_addressput
- `GET /session` (active session schema — `state`, `framedipaddress`, `nasipaddress`, `nasportid`, `ssid`, `acctstarttime`, and the visitor and sponsor fields this integration excludes): https://developer.arubanetworks.com/cppm/reference/activesessionget
- `POST /session/{id}/disconnect`: https://developer.arubanetworks.com/cppm/reference/activesessiondisconnectbyiddisconnectpost
- ClearPass Device Profiler overview (the `DeviceCategory` / `DeviceFamily` / `DeviceName` hierarchy): https://arubanetworking.hpe.com/techdocs/ClearPass/6.12/PolicyManager/Content/CPPM_UserGuide/PolicyProfile/Profile_overview.htm
- Adding and modifying endpoints (endpoint database, status values): https://www.arubanetworks.com/techdocs/ClearPass/6.7/PolicyManager/Content/CPPM_UserGuide/Admin/EndpointsHelp.html
- Palo Alto's open-source XSOAR client for ClearPass, used to confirm the `/api` base path, the JSON OAuth body, the JSON-encoded `filter` parameter, and the `_embedded.items` / `_links` HAL envelope in its recorded test fixtures: https://github.com/demisto/content/blob/master/Packs/HPEArubaClearPass/Integrations/HPEArubaClearPass/HPEArubaClearPass.py

# Custom Integration: Infoblox NIOS

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Grid Manager (or a Grid member running WAPI) over HTTPS.

## Infoblox NIOS requirements

- A NIOS admin user whose admin group has the **API** interface enabled. This is a hard prerequisite: NIOS states that all WAPI users must hold permissions granting them API access, and an admin group without it authenticates against the GUI and is refused by WAPI.
- Read-only permission on IPAM and DHCP data, and — if host records are imported — on DNS host records. The integration only issues `GET` requests; no write permission is needed.
- A WAPI version the Grid supports.

## Steps

### Infoblox NIOS configuration

Only a superuser can create admin groups.

1. Create the limited-access admin group. Go to the **Administration** tab → **Administrators** tab → **Groups** tab → the **Add** icon. In the Add Admin Group wizard, give it a name and **clear the Superusers checkbox** — that is what makes it a limited-access group.
2. In the **Allowed Interfaces** section of the same wizard, tick **API** ("select this to allow the admin group access to the Infoblox API"). GUI and CLI are separate checkboxes; this integration needs only API.
3. Grant the group **Read-Only** permission on:
   - **IPAM permissions** — network views, IPv4 and IPv6 networks, and host records.
   - **DHCP permissions** — network views, IPv4 networks, host records, ranges, fixed addresses, leases and lease history.

   Permission levels are Read/Write, Read-Only, and **Deny**, and **Deny is the
   default for every resource**. A limited-access group therefore sees *nothing*
   until permissions are defined, which is the usual reason a correct username and
   password return an empty import. Permissions are hierarchical, so a permission
   on a network is inherited by the ranges and fixed addresses inside it.
4. Create (or reuse) a NIOS admin user for runZero and assign it to that group.
5. Find the WAPI version the Grid supports. Ask the appliance for its schema — the version list comes back regardless of which version you request:

   ```bash
   curl -k -u '<user>' 'https://<grid>/wapi/v1.0/?_schema'
   ```

   The response carries `requested_version`, `supported_objects`, and
   `supported_versions`. The highest entry in `supported_versions` is the newest
   the appliance supports; use it, or any version in that list, as the **WAPI
   version** field.
6. Confirm a real read works at the version you chose:
   `curl -k -u '<user>' 'https://<grid>/wapi/v2.13.1/networkview?_return_as_object=1'`

`-k` is used above because NIOS presents a **self-signed certificate** by default
— Infoblox's own reference examples use `-k` throughout, and the default
certificate is issued to `CN=www.infoblox.com` rather than to your Grid's
hostname. Set the `tls_` options on the runZero credential accordingly, or
install a trusted certificate on the appliance.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Infoblox NIOS").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Grid Manager URL** (`url`): base URL of Grid Manager, e.g. `https://gridmaster.example.com`. The `/wapi/<version>/` path is appended automatically.
   - **WAPI version** (`wapi_version`): optional; WAPI version segment of the request URL (default: `v2.13.1`).
   - **Username** (`username`): NIOS user with API access.
   - **Password** (`password`): password for that user.
   - **Network view** (`network_view`): optional; import only this network view. Leave blank to enumerate and import every view on the Grid.
   - **Import DHCP leases** (`include_leases`): optional; join lease records for MAC, client hostname, lease timing, and DHCP fingerprint (default: enabled).
   - **Import host records** (`include_host_records`): optional; join `record:host` objects for aliases, device vendor, device type, and location (default: disabled).
   - **Import unused addresses** (`include_unused_addresses`): optional; import every address IPAM knows about instead of only those with status `USED` (default: disabled).
   - **Page size** (`page_size`): optional; value sent as `_max_results` on every paged read (default: 1000).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with IPAM, DHCP, and DNS data pulled from Infoblox NIOS.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:infoblox`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real Grid returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename infoblox/infoblox.star \
  --kwargs url=https://gridmaster.example.com \
  --kwargs wapi_version=v2.13.1 \
  --kwargs username=runzero-api \
  --kwargs password=hunter2-not-a-real-password \
  --kwargs network_view=default \
  --kwargs page_size=50 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/infoblox-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Three things are worth knowing before the first run:

- **`wapi_version` is part of the request path, not a hint.** It becomes
  `/wapi/<version>/` verbatim, and a Grid rejects a version it does not
  implement rather than negotiating down. If the run fails immediately with a
  404 or an unknown-version error, take the version from `https://<grid>/wapidoc/`
  on the appliance itself and pass that. This is the single most common reason a
  correct username and password still produce nothing.
- **Set `network_view` on a first run.** Left blank the script enumerates every
  view on the Grid and walks all of them, which on a large Grid is a long run.
  Naming one view keeps the smoke test small, and on a Grid with overlapping
  address space it is how the integration is meant to be scheduled anyway — one
  task per view.
- **NIOS ships a self-signed certificate.** `tls_disable_validation=true` is
  shown above because that is the state most Grids are actually in; drop it if
  the appliance presents a certificate your Explorer trusts.

`get_bool` accepts `true/false`, `1/0`, `yes/no`, and `on/off`.

Because this integration is enrichment-shaped — its `matchBehavior` is
`no-id-match no-id-break`, and it emits one asset per address rather than per
device — a local run is the easiest way to see how many assets a given view
produces before pointing it at a production organization. Turning
`include_unused_addresses` on multiplies that count by every unused address in
every managed network, so check the number here first.

**One `--kwargs` caveat, for the password specifically.** A comma in a value is
harmless on its own — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks is a value
carrying **both** an `=` and a comma: the flag parses an argument containing a
second `=` as a CSV record, so `password=a=b,c=d` yields `password=a=b` plus a
fabricated `c=d`. Wrap the whole argument in double quotes to pass such a value
as one field — `--kwargs '"password=a=b,c=d"'` — and double any quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real Grid:

```bash
runzero script --filename infoblox/infoblox.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real address
row, and in particular it does not check that `wapi_version` is a version your
Grid supports.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://gridmaster.example.com,username=runzero-api,password=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma — which for this integration means a network view
whose name contains a comma has to be configured through the console credential
form rather than on the command line.

The recorded fixtures run without a Grid:

```bash
python3 tests/run.py infoblox
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: an IP address under Infoblox IPAM management, standing in for whatever device currently holds that address in a given network view. It is not a device record.
- Source ID field: the composite of `ipv4address.ip_address` and `ipv4address.network_view`. The WAPI object reference `_ref` is deliberately **not** used.
- Documentation evidence: the WAPI reference for `ipv4address` states that "The name part of a ipv4address object reference has the following components: IP address / Name of the network view", with the example `ipv4address/Li5pcHY0X2FkZHJlc3MkMTAuMC4wLjEvMQ:10.0.0.1/external`. Address and network view are therefore the natural key WAPI itself uses for the object. Both are documented as part of the base object, so both are returned on every read. The opaque `_ref` prefix is a base64 encoding of the object's current name, so it changes when the underlying object is renamed, which disqualifies it as a foreign id.
- Uniqueness scope: one Grid, one network view. A network view is a separate routing domain, and Grids routinely carry the same RFC 1918 space in several views, so the view is a mandatory part of the key. The Grid hostname is also included so two Grids polled into one runZero organization cannot collide.
- Cardinality: one source row per address per view — **not** one row per device. A device with several addresses produces several assets, and a `record:host` object holding several addresses is joined onto each of them. Two `lease` rows for the same address collapse into one asset; the most current binding (`ACTIVE` > `STATIC` > `BACKUP` > other, then the highest `cltt`) wins.
- Stability: the id survives a MAC change, a host-record rename, an alias or extensible-attribute edit, and a lease renewal at the same address. It does **not** survive the device moving to a different address or a different view; that produces a different id.
- Reuse behavior: yes. An address that is released and re-leased to a different device reuses the same composite. This is the single strongest reason the verdict below is not "authoritative".
- Presence: `ip_address` and `network_view` are basic fields on `ipv4address` and are returned on every read. Rows that arrive without an `ip_address`, and rows that are not objects at all, are skipped and counted.
- Final runZero ID: `infoblox:<grid-host>:<network_view>:<ip_address>` — for example `infoblox:gridmaster.example.com:corp-b:10.0.0.5`.
- Missing-ID behavior: skip. The record is logged with its view and network only, never the record body, and no id is invented. `new_uuid()` is not used anywhere in the script.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. The composite is deterministic but address-based, so it must not drive or block merging. Correlation falls back to the MAC, IP, and hostnames on the record; every emitted record carries at least the IP.
- Verdict: **derived / non-authoritative.** Infoblox NIOS is an address-management system, not a device inventory, and it publishes no device-level identifier. Treat this integration as an enrichment source that layers IPAM ownership, DNS naming, DHCP fingerprints, and extensible attributes onto assets runZero already knows about.

### Notes

- What is imported: one asset per IPv4 address from the `ipv4address` object, filtered to `status=USED` unless **Import unused addresses** is enabled. Each asset carries the address, MAC, DNS names, network, network view, IPAM status/usage/types, conflict flag, DHCP fingerprint, comment, and extensible attributes, plus the parent `network` object's comment and extensible attributes.
- Optional joins, keyed on address within a single network view:
  - `lease` (**Import DHCP leases**, on by default) contributes the MAC when IPAM has none, the DHCP client hostname, binding state, serving member, DHCP option 61 uid, and the fingerprint. `starts` becomes `firstSeenTS`, and `cltt` (falling back to `ends`) becomes `lastSeenTS`. These are the only lifecycle timestamps available — the `ipv4address` object has none.
  - `record:host` (**Import host records**, off by default) contributes aliases, DNS view, zone, `device_vendor` (mapped to `manufacturer`), `device_type`, `device_description`, `device_location`, and extensible attributes. It is joined on `ipv4addrs[].ipv4addr` only.
- `deviceType` is set from the host record's operator-maintained `device_type` when present. Otherwise a small, deliberately conservative keyword table promotes only the DHCP fingerprints that name a device class outright (printer, IP phone, IP camera, access point, firewall, router). Every fingerprint is preserved verbatim as `infoblox_fingerprint` and as a `dhcp-fingerprint:` tag regardless.
- Every asset is tagged `network-view:<name>`, and `infoblox_network_view` records the same value. **In a Grid with overlapping address space, run one task per network view** and point each at the runZero site that matches that routing domain. The integration keeps the views apart in the ids it emits, but runZero's own IP-based merging is site-scoped, so two views sharing `10.0.0.0/8` in one site can still merge into a single asset.
- Pagination: every read sends `_return_as_object=1`, `_paging=1`, and `_max_results=<page size>`. The response is `{"result": [...], "next_page_id": "..."}`; the follow-up request sends `_page_id` (plus `_return_as_object=1`) and nothing else, because WAPI resumes a paged read from the page id alone. The server omits `next_page_id` on the last page, which is the loop's termination condition.
- Field selection uses `_return_fields+=<csv>`, with the literal trailing `+` that asks for those fields *in addition to* the object's basic fields. Plain `_return_fields` would replace the basic set and drop `ip_address` and `network_view`. The `+` is sent percent-encoded as `_return_fields%2B`, which is byte-for-byte what Infoblox's own Python clients send.
- Traversal order: network views → networks in each view → addresses in each network. A WAPI `ipv4address` search cannot be qualified by `network_view` alone; it must also be filtered by `network` or `ip_address`, so the networks are enumerated first. This is stated in Infoblox community guidance rather than in the object field table, and is the one contract detail here that is not confirmed by the official reference — see the linked thread below. Enumerating networks is required either way to keep the view scoping explicit.
- Request volume follows from that traversal: roughly `1 + (views x 3) + (networks x address pages)`. A Grid with thousands of networks will issue thousands of requests, so schedule accordingly and consider scoping the task with **Network view**.
- Rate limiting: WAPI publishes no documented rate limit. The shared HTTP helper is given a retry budget of 3 with a 2-second backoff, which covers 429 and 5xx responses and honors `Retry-After`.
- Authentication is HTTP Basic on every request; there is no token exchange and no session cookie is reused between requests.
- IPv6 is not imported. The `ipv6address` object exposes `duid` rather than a returnable `mac_address` (`mac_address` is search-only there) and lives under `ipv6network`, so it needs its own traversal; `record:host.ipv6addrs` is likewise not joined.
- Unverified assumptions: the default `wapi_version` of `v2.13.1` is taken from Infoblox's own XSOAR client and may not be supported on older Grids; `discovered_data` from Network Insight is not requested; and this integration was validated against local fixtures, not a live Infoblox NIOS Grid.

## Future

- **DHCP fingerprint as a classification signal.** `ipv4address.fingerprint` and `lease.fingerprint` are Infoblox's own DHCP device fingerprints, and `lease` also exposes `discovered_data.device_type` / `discovered_data.device_vendor` from Network Insight. Today only unambiguous fingerprints set `deviceType`. A richer mapping table, or feeding the raw fingerprint into runZero's own fingerprint engine as corroborating evidence, would classify a large slice of DHCP-managed endpoints that never respond to a scan.
- **Outbound write-back to `record:host`.** The WAPI reference documents `record:host` as supporting Create (POST, requiring `name` and `ipv4addrs`) and Update (PUT, with `network_view`, `zone`, `dns_name`, `creation_time`, and `last_queried` immutable), and Infoblox's own XSOAR client issues `POST record:host`. An outbound integration could therefore create or annotate host records for assets runZero discovers. This should be built with care and defaulted off: NIOS is usually the authoritative DNS and IPAM system of record, and a bad write there breaks name resolution rather than just polluting an inventory. Annotating `extattrs` or `comment` on existing objects is a far safer first step than creating records.
- **`network` import as site and subnet context.** The integration already reads the `network` object for traversal and attaches its comment and extensible attributes to each asset. Those same rows — CIDR, view, comment, and EAs such as Site or Region — map cleanly onto runZero sites and subnet metadata, and `networkcontainer` would supply the supernet hierarchy above them.
- **IPAM reconciliation.** This is the most valuable thing the two datasets can do together, and it needs no new endpoint. Addresses runZero observes that have no `ipv4address` row, or a row with `status=UNUSED`, are unmanaged address space — shadow IT, stale DHCP scopes, or a device on a subnet nobody registered. The inverse, `ipv4address` rows with `status=USED` that runZero has never seen, are stale IPAM entries or unreachable segments. `ipv4address.is_conflict` already flags Infoblox's own MAC and lease conflicts and is imported as `infoblox_is_conflict` and an `infoblox-conflict` tag.
- **Alert and event ingestion is not available.** WAPI is a synchronous object API with no event stream, webhook, or subscription endpoint. Change tracking would have to be built from polling plus the `_return_fields` timestamps that individual objects happen to expose, and Infoblox's RPZ objects (`zone_rp`, `record:rpz:cname`) describe DNS firewall policy rather than assets, so they are out of scope here.

## API documentation

- WAPI reference (objects, fields, `_ref` format, paging, `_return_fields+`, authentication): https://ipam.illinois.edu/wapidoc/ — the same reference ships on every appliance at `https://<grid>/wapidoc/`
- `ipv4address` object and reference format: https://ipam.illinois.edu/wapidoc/objects/ipv4address.html
- `ipv6address` object (search-only `mac_address`): https://ipam.illinois.edu/wapidoc/objects/ipv6address.html
- `lease` object (`hardware`, `binding_state`, `starts`/`ends`/`cltt`, `fingerprint`): https://ipam.illinois.edu/wapidoc/objects/lease.html
- `record:host` object (basic fields, POST/PUT support, immutable fields): https://ipam.illinois.edu/wapidoc/objects/record.host.html
- `network` object: https://ipam.illinois.edu/wapidoc/objects/network.html
- `networkview` object: https://ipam.illinois.edu/wapidoc/objects/networkview.html
- NIOS WAPI reference guide (PDF): https://docs.infoblox.com/download/attachments/15433773/Infoblox%20NIOS%20WAPI%209.x%20Reference%20Guide.pdf
- Community guidance on searching addresses without a subnet: https://community.infoblox.com/t5/api-integration-devops-netops/how-to-search-all-ip-addresses-without-defining-a-subnet-network/td-p/25145
- Infoblox's own XSOAR client, used to confirm the WAPI base path, Basic auth, `_return_fields+` usage, and the lease and host return-field sets: https://github.com/demisto/content/blob/master/Packs/Infoblox/Integrations/Infoblox/Infoblox.py

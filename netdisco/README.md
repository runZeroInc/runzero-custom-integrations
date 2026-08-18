# Custom Integration: Netdisco

Imports the switches and routers Netdisco manages, plus the layer-2 **nodes** it
has located on their switchports — MAC to switch to port to VLAN.

That location data is the reason this integration exists. Nothing else in this
repository produces it. runZero can tell you a device is on the network;
Netdisco can tell you which port it is plugged into.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Netdisco web application, normally an internal host on port 5000 or behind a reverse proxy.

## Netdisco requirements

- Netdisco **2.45 or newer**. The REST API was added in 2.45 and is enabled by default from that release forward — there is no plugin to install and no `api_token_lifetime` to set before it will answer.
- A Netdisco user holding the **`api` role**. Roles are set per user in *Admin → User Management*; the `api` role is separate from `admin` and from ordinary web login, and a user without it authenticates successfully and is then refused on every `/api/` call.
- A Netdisco recent enough to support **offset paging on the device search**. The `limit` and `offset` parameters, and the rule that `q` becomes optional when both are supplied, were added to `/api/v1/search/device` after the original API shipped; the exact release was not established, so treat this as "current" rather than a version number. On an older install the first device request answers `400 Missing query - provide "q", a filter parameter, or both "limit" and "offset"`, and this integration says so explicitly rather than importing nothing in silence. Check your own instance's `/swagger-ui` for whether `limit` and `offset` are listed under the device search.

### Creating the credential in Netdisco

Netdisco authenticates the API with a token, and there are two ways to get one.

**Option A — an ordinary user, token minted per run (default).**

1. In Netdisco, go to *Admin → User Management*.
2. Create a user (or edit an existing one) and tick the **API** role. Leave **Admin** off; this integration only reads.
3. Give the runZero credential that username and password. Each run exchanges them at `POST /login` for a token that is valid for `api_token_lifetime` — one hour by default, which is far longer than a collection run needs.

**Option B — a permanent API key (recommended for automation).**

1. On the Netdisco host, set `allow_permanent_tokens: true` in `~netdisco/environments/deployment.yml` and restart the web service.
2. Mint a key for the user:

   ```bash
   ~netdisco/bin/netdisco-do getapikey -e runzero -p permanent
   ```

3. Put that key in the runZero credential's **Password or API key** field with the same username. `POST /login` accepts a permanent key in place of the password, so nothing else changes.

Confirm the credential from the Explorer host:

```bash
curl -s -u 'runzero:<password-or-key>' -H 'Accept: application/json' \
  https://netdisco.example.com/login
# -> {"api_key":"9d8ff4b68dbedb804c90e9b375eea48a"}

curl -s -H 'Authorization: 9d8ff4b68dbedb804c90e9b375eea48a' \
  'https://netdisco.example.com/api/v1/search/device?limit=1&offset=0'
```

Note the second header: the token goes in `Authorization` **as plain text**.
Netdisco tolerates an optional `Apikey ` prefix and nothing else — a `Bearer `
prefix is not recognised and the call is refused.

Every instance also serves its own OpenAPI 2.0 document at `/swagger.json` and
an interactive browser at `/swagger-ui`, which is the fastest way to confirm
what a particular release supports.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Netdisco").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Netdisco URL** (`url`): base URL of the web application, including any path prefix it is mounted under, for example `https://netdisco.example.com`.
   - **Username** (`username`) and **Password or API key** (`password`).
   - **Collect layer-2 nodes** (`collect_nodes`): optional, default enabled.
   - **Active nodes only** (`active_only`): optional, default enabled.
   - **Maximum node age in days** (`max_age_days`): optional, default 30, `0` disables the filter.
   - **Collect device interface addresses** (`collect_device_ips`): optional, default enabled.
   - **Collect switchport MACs** (`collect_ports`): optional, default **disabled**.
   - **IP inventory subnets** (`ip_inventory_subnets`): optional, comma-separated CIDRs.
   - **Maximum devices** (`max_devices`) / **Maximum nodes** (`max_nodes`) / **Device page size** (`page_size`) / **Device fields** (`device_fields`): optional tuning.
   - **TLS options** (`tls_*`): set these if Netdisco is behind a self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Schedule it to run after Netdisco's own `macsuck` and `arpnip` jobs, so the node data is fresh.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Netdisco.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:netdisco`.
- Split the two asset kinds with `tag:netdisco-device` and `tag:netdisco-node`.
- Find everything plugged into one switch with `tag:netdisco-switch:198.51.100.11`, or look up a single host's port with `netdisco_port:GigabitEthernet1/0/12`.

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
credential and see what a real instance returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename netdisco/netdisco.star \
  --kwargs url=https://netdisco.example.com \
  --kwargs username=runzero \
  --kwargs password=9d8ff4b68dbedb804c90e9b375eea48a \
  --kwargs page_size=50 \
  --kwargs max_devices=10 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/netdisco-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory. Capping
`max_devices` on a first run keeps a large estate from turning a smoke test into
a full collection.

**One CLI caveat, and it leaves the comma-separated parameters alone.**
`--kwargs` passes a value through verbatim, commas included, as long as the pair
contains a single `=`, so `device_fields` and `ip_inventory_subnets` can both be
given as full comma-separated lists from the command line. What breaks is a
value carrying a *second* `=` **as well as** a comma: that pair is re-read as
CSV, so the value is cut off at the comma and the remainder becomes a parameter
the integration never declared, with no error. A password is the value here most
likely to be that shape; wrap it in double quotes to keep it a single field
(`--kwargs '"password=a=b,c"'`), doubling any double quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real instance:

```bash
runzero script --filename netdisco/netdisco.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://netdisco.example.com,username=runzero,password=...'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, and — unusually for this repository — **both use
`no-id-match no-id-break`**. That is a deliberate departure from the
"stable vendor id" default, and the reasoning is below.

### Devices (switches and routers)

- Target entity: one row of Netdisco's `device` table.
- Source ID field: **`ip`**, the device's canonical management address. This genuinely is the vendor's identity: `device.ip` is the table's primary key (`__PACKAGE__->set_primary_key("ip")`), and every per-device route is addressed by it — `/api/v1/object/device/{ip}`, `/{ip}/ports`, `/{ip}/nodes`, `/{ip}/device_ips`.
- Uniqueness scope: one Netdisco installation. Two installations both numbering a switch `10.0.0.1` mean two different switches, so the id is scoped on the configured Netdisco hostname.
- Final runZero ID: `netdisco:<netdisco-hostname>:device:<management-ip>`.
- **Why `no-id-match` despite that being a real primary key.** The key is an *IP address*, and management addresses are recycled. Decommission a switch, give its address to its replacement, and Netdisco keeps one row: same primary key, different physical device. If the id were allowed to drive merges, the replacement would be merged onto the retired switch's runZero asset and **nothing could veto it** — the platform's foreign-id match path consults only a site check and a collision helper whose allowlist does not include custom integrations at all, so the MAC, IP, and name break flags are never even consulted once an id matches. Turning id matching off costs almost nothing here, because Netdisco supplies an unusually strong correlation set: the management IP, every interface alias from `device_ip`, the chassis MAC, the DNS name, and the SNMP `sysName`. There is more than enough to merge on without the id.
- The same choice also handles the opposite case gracefully. When a switch's management address genuinely changes, Netdisco creates a *new* row under a new key and the old one is deleted, so id matching would have forked the asset anyway; correlating on the chassis MAC keeps it whole.
- Missing-ID behavior: a row with no `ip` is skipped with `netdisco: skipping device with no ip: name=<name>`. Nothing is invented and `new_uuid()` is never used.
- Verdict: **address-derived vendor key, deliberately inert.**

### Located nodes

- Target entity: one row of Netdisco's `node` table — a MAC observed on a switchport.
- Source ID field: the **MAC**. It is the leading column of the composite primary key `(mac, switch, port, vlan)`, and it is the only identifier a node has.
- Final runZero ID: `netdisco:<netdisco-hostname>:node:<mac>`.
- **Cardinality is the interesting part.** The table's key is the four-tuple, not the MAC, so one host that has moved between ports — or that is visible through an uplink on several switches — has several rows. Those rows are one device, so they are folded into **one** asset before anything is emitted. Without that fold the `unique_ids` invariant would fire, and more importantly runZero would be told about the same laptop three times.
- The most recent sighting wins as the primary location (`netdisco_switch`, `netdisco_port`, `netdisco_vlan`), because an uplink port sees every MAC behind it and the newest sighting is the closest thing available to the real access port. Up to ten `switch/port` pairs are kept in `netdisco_sightings`, with `netdisco_sighting_count` recording how many there were.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`, for the reason a MAC always demands it — MACs are reassigned when a NIC moves, spoofed, and randomized per network by modern clients. Correlation on MAC, IP, and hostname is what should decide a merge, and it does.
- The MAC in the id is canonicalized **losslessly** — lowercased, separators stripped, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately not used for this, because they clear the locally administered bit of the first octet to help cross-source matching. Every randomized client MAC sets that bit, so `aa:bb:cc:dd:ee:01` and `a8:bb:cc:dd:ee:01` would normalize to one value and two real endpoints would collapse into one record. The emitted `NetworkInterface` still goes through `network_interface`, which is correct there.
- Missing-ID behavior: a row with no parseable MAC is skipped. Multicast MACs (odd first octet), the all-zeros MAC, and the broadcast MAC are skipped too, because none of them is an endpoint.
- Verdict: **address-derived, deliberately inert.**

The `no_mac_in_id` fixture invariant is skipped for this integration, with the
reason recorded in each scenario. It exists to catch a MAC used as an id
*without* these safeguards.

## Notes

### What is imported

| Endpoint | Gated by | What it gives |
|---|---|---|
| `POST /login` | always | Exchanges Basic credentials for the API token |
| `GET /api/v1/search/device` | always | The device rows, paged with `limit`/`offset` |
| `GET /api/v1/object/device/{ip}/device_ips` | `collect_device_ips` | Interface IP aliases and their DNS names |
| `GET /api/v1/object/device/{ip}/ports` | `collect_ports` | Per-port interface MACs |
| `GET /api/v1/object/device/{ip}/nodes` | `collect_nodes` | The located MACs, with switch, port, VLAN, and sighting times |
| `GET /api/v1/report/ip/ipinventory` | `ip_inventory_subnets` | MAC to IP to DNS to NetBIOS name, per subnet |

Only `ImportAsset` objects are produced. Netdisco is an SNMP layer-2/3
discovery tool: it inventories no installed software, no listening services,
and no vulnerabilities, so no `Software`, `Service`, or `Vulnerability` records
are emitted. Device modules and their serial numbers, which are the closest
thing it has to a software inventory, land as tags and attributes.

Field mapping: `dns` and `name` become hostnames; `ip` plus every `device_ip`
alias become addresses; `mac` becomes the chassis interface MAC; `os` and
`os_ver` become the OS and version; `vendor` becomes the manufacturer; `model`
becomes the model; `serial` and every module serial become `serial:` tags;
`location`, `contact`, `description`, `layers`, `num_ports`, `uptime`,
`snmp_ver`, and `snmp_class` become `netdisco_` attributes.

`deviceType` is derived from the `layers` column, which is an eight-character
MSB-first rendering of the SNMP `sysServices` bitmask: position *i* carries
layer *8−i*, so layer 3 is index 5 and layer 2 is index 6. A device claiming
layer 2 is a Switch; one claiming only layer 3 is a Router. Netdisco has no
device type field of its own.

### Discrepancies with the research notes

The research notes for this integration named a few things that the source does
not support, and source wins:

- **`GET /api/v1/search/node` cannot enumerate nodes.** Its `q` parameter is declared `required => 1` and the handler answers `400 Missing node` without it: it is a lookup for one MAC, IP, or hostname, not a listing. Nodes are therefore collected per device from `/api/v1/object/device/{ip}/nodes`, which is what the API actually offers.
- **`age_num` / `age_unit` are not parameters of any endpoint used here.** Netdisco's age filtering is `daterange` plus `age_invert` on the *search* endpoints. The node object endpoint accepts only `active_only`. So `max_age_days` is applied by this script against each row's `time_last`, and `active_only` is passed through. The effect is the same and the mechanism is honest.
- **The token is not a Bearer token.** `Authorization: <token>` in plain text, optionally `Apikey <token>`. A `Bearer ` prefix fails.
- **The REST API needs no enabling.** It has shipped on by default since 2.45. `api_token_lifetime` only controls how long a token lasts, and `allow_permanent_tokens` only enables the permanent variety.
- **`/api/v1/report/...` paths carry a category segment**, lower-cased and hyphenated from the report's registered category. The IP Inventory report is registered under category `IP`, so the path is `/api/v1/report/ip/ipinventory` — not `/api/v1/report/ipinventory`.

### `fields=all` is not used, on purpose

The device search accepts `fields=all`, and it would be the obvious thing to
send. It is not sent, because Netdisco's `device` table holds **`snmp_comm`** —
the SNMP community string in cleartext — alongside `snmp_engineid` and a
free-text `log` column. `fields=all` returns all of them. This integration
requests an explicit column list instead, and that list is exposed as the
`device_fields` parameter so an operator can add columns without ever being
handed `snmp_comm` by default. Any column of the `device` table is valid;
naming one that does not exist in your release makes the query fail, which is
why the default sticks to long-established columns.

### Streaming and pagination

Devices are paged with `limit`/`offset` and each page is streamed to runZero
with `report_asset` as it is built, so the device side holds one record at a time.
The response is a bare JSON array with no total and no next link, so the walk
stops on the first page shorter than the one requested.

Nodes are different and cannot be streamed page by page, because the same MAC
legitimately appears on several devices and must be folded into one asset before
it is emitted. The fold happens in an index of compact dicts — not
`ImportAsset` objects — and each finished asset is handed to `report_asset` as it
is built, so peak allocation is one record rather than the estate. `max_nodes`
bounds the index itself.

### Costs and caps

Node collection is one request per device, and the optional `device_ips` and
`ports` calls add one each. A 500-switch estate with everything on costs about
1,500 requests. `collect_ports` is **off by default** because a chassis switch
returns hundreds of port rows and the device already carries a base MAC;
turn it on when you want per-port interface MACs to correlate with.
`max_devices` and `max_nodes` bound the run and print exactly what was dropped
when they trip.

### Timestamps

Every Netdisco timestamp is a bare PostgreSQL `timestamp` written with
`LOCALTIMESTAMP`, so it arrives as `2026-08-15 03:00:11` with **no timezone**
and is the database server's local time. Two consequences shaped the code:

- `parse_time` aborts the entire script on an unparseable layout, and Starlark
  has no exception handling. Every field is validated — including the calendar,
  so `2026-02-30` is rejected rather than parsed — before the call is made.
- Reading a local time as UTC puts the value in the future for any server east
  of Greenwich, and the platform rejects the **entire asset record** on a future
  timestamp, not just the field. Parsed values are therefore clamped to now, and
  the raw string is preserved as `netdisco_creation_raw`,
  `netdisco_last_discover_raw`, `netdisco_time_first_raw`, and
  `netdisco_time_last_raw` so nothing is lost.

### Node addresses

A located node's row is `(mac, switch, port, vlan)` plus sighting times — **no
IP address**. Netdisco keeps addresses in a separate `node_ip` table, and the
only API surface that joins the two is the IP Inventory report, which works one
subnet at a time. So a node imports with its MAC alone unless
`ip_inventory_subnets` is set; a MAC is a perfectly good correlator, but adding
the address makes a node far more likely to merge with something runZero
scanned. Set it to the CIDRs you care about. The report caps itself at 8192 rows
server-side, and this integration says so when a subnet hits the cap instead of
silently truncating.

### Verification status

Verified against local fixtures and against the Netdisco source, not against a
live installation. Every response shape used in the fixtures was taken from the
DBIC result class that defines the table the API serialises —
`lib/App/Netdisco/DB/Result/Device.pm`, `DeviceIp.pm`, `DevicePort.pm`,
`Node.pm` — and from the route definitions in `lib/App/Netdisco/Web/API/Objects.pm`
and `lib/App/Netdisco/Web/Plugin/Search/Device.pm`. The project wiki documents
the auth flow and the endpoint list but publishes almost no response bodies.

## Future

- **The PostgreSQL fallback.** `runzero.sql.connect("postgres", ...)` against the `device`, `device_port`, `node`, and `node_ip` tables would collect the same data in a handful of queries instead of one request per device, and would sidestep the API version floor entirely. The schema is public and stable — it is defined by the DBIC result classes cited above. This is the natural answer for a very large estate, and the one case where the N+1 above becomes genuinely painful.
- **Node IPs without the report.** The same SQL path would join `node` to `node_ip` directly, removing the `ip_inventory_subnets` parameter and the 8192-row cap along with it.
- **Neighbor topology.** `/api/v1/object/device/{ip}/neighbors` returns LLDP/CDP adjacency with a configurable hop depth. runZero has no topology model today, but the immediate neighbor of each device is a useful attribute and would let a runZero user see the uplink chain without opening Netdisco.
- **Wireless clients.** Netdisco tracks `node_wireless` with SSID, channel, and signal strength, exposed through `/object/device/{ip}/port/{port}/ssid` and the `portssid` report. Those are wireless endpoints with an association point, which is the same class of data as a switchport location.
- **NetBIOS names for every node.** The `netbios` report returns `node_nbt` rows estate-wide with no subnet parameter, which would give NetBIOS names to nodes without needing the IP Inventory report at all.
- **Port-level service hints.** `device_port` carries `remote_ip`, `remote_port`, and `remote_id` from LLDP/CDP, plus PoE state from `device_port_power`. A PoE-powered port with a phone's MAC is a strong device-type signal that this integration does not currently use.
- **`is_pseudo` devices.** Netdisco supports operator-created placeholder devices for equipment it cannot poll. They import today, tagged `netdisco-pseudo-device`, but a future version could skip them by default since they represent belief rather than observation.

## API documentation

- API wiki — https://github.com/netdisco/netdisco/wiki/API. Source for the `POST /login` flow, the plain-text `Authorization` header, `api_token_lifetime`, `allow_permanent_tokens`, and the endpoint categories.
- Per-instance OpenAPI 2.0 spec at `/swagger.json`, interactive at `/swagger-ui`.
- Concepts — https://github.com/netdisco/netdisco/wiki/Concepts. Explains devices, nodes, `macsuck`, and `arpnip`.
- **Response shapes** come from the source: [`lib/App/Netdisco/Web/API/Objects.pm`](https://github.com/netdisco/netdisco/blob/master/lib/App/Netdisco/Web/API/Objects.pm) (the object routes and their relations), [`lib/App/Netdisco/Web/Plugin/Search/Device.pm`](https://github.com/netdisco/netdisco/blob/master/lib/App/Netdisco/Web/Plugin/Search/Device.pm) (the device search, its `limit`/`offset` contract, and the `fields` parameter), [`lib/App/Netdisco/Web/Plugin/Search/Node.pm`](https://github.com/netdisco/netdisco/blob/master/lib/App/Netdisco/Web/Plugin/Search/Node.pm) (which is where `q` is proved required), [`lib/App/Netdisco/Web/Plugin/Report/IpInventory.pm`](https://github.com/netdisco/netdisco/blob/master/lib/App/Netdisco/Web/Plugin/Report/IpInventory.pm) (the report's select list and its 8192-row cap), and [`lib/App/Netdisco/Web.pm`](https://github.com/netdisco/netdisco/blob/master/lib/App/Netdisco/Web.pm) (the `before_layout_render` and `after` hooks that turn a web template into a JSON array and substitute `[]` for an empty body).
- Table definitions — [`lib/App/Netdisco/DB/Result/`](https://github.com/netdisco/netdisco/tree/master/lib/App/Netdisco/DB/Result). `Device.pm`, `DeviceIp.pm`, `DevicePort.pm`, `Node.pm`, and `NodeIp.pm` are the authoritative field lists, including which columns are marked non-serializable and therefore never appear in a response.
- Project site — http://netdisco.org/.

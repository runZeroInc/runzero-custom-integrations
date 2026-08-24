# Custom Integration: LibreNMS

Imports the devices LibreNMS monitors — with their OS, version, hardware model,
serial, sysDescr, location, and per-port interface MACs — plus the **endpoints**
it has learned from their ARP and MAC forwarding tables.

The second half is the interesting one. LibreNMS polls every switch and router
in the estate over SNMP, which means it already holds the IP-to-MAC-to-switchport
correlation for hosts nobody has ever scanned.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the LibreNMS web interface, normally an internal host.

## LibreNMS requirements

- Any currently supported LibreNMS release. The `api/v0` surface used here has been stable for years.
- An **API token**, and a user whose device access covers what you want imported.
- LibreNMS is normally behind whatever TLS the site configured, which for an internal install is frequently a self-signed or internal-CA certificate, so `OPTIONS_TLS` is exposed. Nothing is skipped by default.

### Creating the credential in LibreNMS

1. Log in to LibreNMS as an administrator.
2. Open the gear menu and choose **API → API Settings** (the direct URL is `/api-access`).
3. Press **Create API access token**.
   - **User**: the account the token acts as. LibreNMS scopes API access to that user's device permissions, so a normal user sees only their devices while an admin sees everything. If the integration imports far fewer devices than you expect, this is almost always why.
   - **Description**: something identifiable, e.g. `runZero`.
4. Press **Create Token**. The token is listed on the same page and can be re-read later, unlike most vendors.
5. Confirm it from the Explorer host:

   ```bash
   curl -s -H 'X-Auth-Token: <token>' \
     https://librenms.example.com/api/v0/devices | head -c 400
   ```

   A working token returns `{"status":"ok","devices":[...],"count":N}`. A bad
   one returns `{"message":"Unauthenticated."}` with HTTP 401 — note that this
   is a **different envelope** from every other error the API produces.

> **Read this before you point it at production.** `GET /api/v0/devices` is
> built from a plain `SELECT d.*` and the LibreNMS `Device` model declares no
> hidden attributes, so the response includes `community`, `authname`,
> `authpass`, `authalgo`, `cryptopass`, and `cryptoalgo` — **the SNMP
> credentials for every monitored device, in cleartext**. This is a known
> upstream issue ([librenms#16048](https://github.com/librenms/librenms/issues/16048),
> closed, still present on master). This integration builds its custom
> attributes from an explicit allowlist and never reads those fields, so they
> are not stored in runZero. Treat the token as a credential that can read all
> your SNMP credentials, and scope its user accordingly.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "LibreNMS").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **LibreNMS URL** (`url`): base URL of the web interface, for example `https://librenms.example.com`. A path prefix is honoured, so `https://nms.example.com/librenms` works for a reverse-proxied install; `/api/v0` is appended to whatever you give.
   - **API token** (`api_token`): the token from step 4.
   - **Device filter** (`device_filter`): optional; `active`, `up`, `down`, `ignored`, `disabled`, and others.
   - **Collect device IP addresses** (`collect_addresses`): optional, default enabled.
   - **Collect device ports** (`collect_ports`): optional, default enabled.
   - **Collect the global ARP table** (`collect_arp`): optional, default enabled.
   - **Collect the global MAC forwarding table** (`collect_fdb`): optional, default **disabled**.
   - **Port columns** (`port_columns`) / **Maximum devices** (`max_devices`) / **Maximum discovered endpoints** (`max_discovered`): optional tuning.
   - **TLS options** (`tls_*`): set these if LibreNMS uses an internal certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Schedule it to run after LibreNMS's own discovery, so the port and ARP data is fresh. ARP entries age out in minutes, so a frequent schedule finds more endpoints than a nightly one.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from LibreNMS.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:librenms`.
- Split the two asset kinds with `tag:librenms-device` and `tag:librenms-endpoint`, and narrow endpoints by where they were learned with `tag:librenms-arp` or `tag:librenms-fdb`.
- Devices LibreNMS currently considers down carry `tag:librenms-down`; ignored and administratively disabled devices carry `tag:librenms-ignored` and `tag:librenms-disabled`.
- Locations become tags, so `tag:location:Building A / MDF` works directly.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename librenms/librenms.star \
  --kwargs url=https://librenms.example.com \
  --kwargs api_token=8d2f1c93b7a54e6f8c0d1e2a3b4c5d6e \
  --kwargs device_filter=active \
  --kwargs max_devices=10 \
  --kwargs collect_arp=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/librenms-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory. Capping
`max_devices` and turning ARP off keeps a first run from pulling the whole
estate while you are still checking the credential.

**One CLI caveat, and `port_columns` is not caught by it.** `--kwargs` passes a
value through verbatim, commas included, as long as the pair contains a single
`=` — so a full comma-separated `port_columns` list can be given on the command
line as written. What breaks is a value carrying a *second* `=` **as well as** a
comma: that pair is re-read as CSV, so the value is cut off at the comma and the
remainder becomes a parameter the integration never declared, with no error. A
LibreNMS API token cannot be that shape, but a password could. Wrap such an
argument in double quotes to keep it a single field: `--kwargs '"password=a=b,c"'`.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename librenms/librenms.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://librenms.example.com,api_token=...'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, with different identity stories. They are emitted as two
declared asset types — `device` and `endpoint` — selected per record with
`ImportAsset(assetType=...)`, and each type's merge policy is declared under
that key in `CONFIG["assetTypeBehavior"]`.

`CONFIG["matchBehavior"]` carries `no-type-break`, which lets the two types
merge with each other. The populations overlap rather than partition: LibreNMS
learns ARP and FDB entries from the very devices it polls, so a monitored
switch, router, or server routinely appears a second time as an endpoint MAC in
a neighbour's table. An endpoint carries no hostname, so the only way it merges
at all is on a MAC it shares with that host, which means the merge is right
whenever it happens. Leaving `type-break` on would veto exactly that merge and
fork every dual-seen device into a bare MAC-only duplicate — the same
fragmentation `no-id-break` already exists to prevent.

### Devices

- Target entity: one row of the LibreNMS `devices` table — a host LibreNMS polls over SNMP.
- Source ID field: **`device_id`**, the table's `AUTO_INCREMENT` primary key (`PRIMARY KEY (device_id)`).
- Documentation evidence: every per-device route accepts it — `/devices/{id}`, `/devices/{id}/ports`, `/devices/{id}/ip`, `/devices/{id}/fdb`, `/inventory/{id}` — and `/devices?type=device_id` filters on it. It is returned on every device row.
- Uniqueness scope: one LibreNMS installation. It is a database sequence, so two installations both numbering a switch `1` mean two different switches; the id is scoped on the LibreNMS hostname from the configured URL.
- Cardinality: exactly one row per device. `list_devices` groups by hostname, so a device cannot appear twice in one response.
- Stability: survives rename, re-address (`overwrite_ip`), OS upgrade, re-discovery, going down, being ignored, and being disabled. It changes only when the device is deleted from LibreNMS and re-added.
- Reuse behavior: not documented. A MySQL `AUTO_INCREMENT` is not recycled in normal operation, but that is an implementation property rather than a published contract, and it is the weakest link in this record.
- Presence: required, and non-null by schema.
- Final runZero ID: `librenms:<librenms-hostname>:device:<device_id>` — for example `librenms:librenms.example.com:device:1`.
- Missing-ID behavior: skip the record and print `librenms: skipping device with no device_id: hostname=<hostname>`. Nothing is invented and `new_uuid()` is never used.
- Asset type: **`device`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**. `device_id` is a genuine, stable, non-address identifier and is allowed to drive merges. The break flags are relaxed because the correlating data is genuinely patchy: a device polled by DNS name may publish no address of its own, `ifPhysAddress` is empty on virtual, aggregate, and many vendor interfaces, and `hostname` is often an IP literal rather than a name. An absent MAC or a changed polling address must not disqualify a merge against an asset runZero already discovered.
- Verdict: **scoped authoritative.**

### Discovered endpoints

- Target entity: one MAC address LibreNMS has learned from a monitored device's ARP cache (`ipv4_mac`) or MAC forwarding table (`ports_fdb`).
- Source ID field: the **MAC**. Neither table offers anything else usable — `ipv4_mac.id` and `ports_fdb.ports_fdb_id` are per-row surrogate keys that change when the entry ages out and is relearned, so they identify a *sighting*, not a device.
- Final runZero ID: `librenms:<librenms-hostname>:endpoint:<mac>`.
- Cardinality: one MAC appears in many rows — once per switch that sees it, once per VLAN, and in both tables. Those rows are folded into **one** asset before anything is emitted, which is what keeps the `unique_ids` invariant satisfied and, more importantly, stops runZero being told about the same laptop five times.
- Asset type: **`endpoint`**.
- Match behavior: **`no-id-match no-id-break`**. A MAC is not a durable device identity: it is reassigned when a NIC moves, it is spoofed, and modern clients randomize it per network. If the id drove merges, a recycled MAC would pull a different physical device onto an existing asset and **no break flag could veto it** — the platform's foreign-id match path consults only a site check and a collision helper whose allowlist does not cover custom integrations, so the MAC, IP, and name break flags are never consulted once an id matches. `no-id-match` takes the id out of matching entirely and lets the MAC and IP correlate, which is what they are good at.
- The MAC in the id is canonicalized **losslessly** — lowercased, separators stripped, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately not used for this, because they clear the locally administered bit of the first octet. Every randomized client MAC sets that bit, so `aa:bb:cc:dd:ee:01` and `a8:bb:cc:dd:ee:01` would normalize to one value and two real endpoints would collapse into one record. The emitted `NetworkInterface` still goes through `network_interface`, which is correct there.
- Missing-ID behavior: a row with no parseable MAC is skipped. Multicast MACs (odd first octet), the all-zeros MAC, and the broadcast MAC are skipped too, because none of them is an endpoint.
- Verdict: **address-derived, deliberately inert.**

The `no_mac_in_id` fixture invariant is skipped for scenarios covering endpoint
assets, with the reason recorded in each. It exists to catch a MAC used as an id
*without* these safeguards.

## Notes

### What is imported

| Endpoint | Gated by | What it gives |
|---|---|---|
| `GET /api/v0/devices` | always | The device table. `?type=` applies the device filter |
| `GET /api/v0/devices/{id}/ip` | `collect_addresses` | Every address bound to the device's ports |
| `GET /api/v0/devices/{id}/ports?columns=…` | `collect_ports` | Port names and `ifPhysAddress` |
| `GET /api/v0/resources/ip/arp/all` | `collect_arp` | The estate-wide ARP table, in one request. An older LibreNMS that answers 400 without a `device` parameter is retried once per imported device |
| `GET /api/v0/resources/fdb` | `collect_fdb` | The estate-wide MAC forwarding table, in one request |

Only `ImportAsset` objects are produced. LibreNMS is an SNMP monitoring system:
it holds no installed-software inventory, no per-host listening services, and no
vulnerability data, so no `Software`, `Service`, or `Vulnerability` records are
emitted.

Field mapping: `sysName`, `display`, and `hostname` (when it is a name) become
hostnames; `ip`, `hostname` (when it is an address), and every address from
`/ip` become addresses; each port's `ifPhysAddress` becomes an interface MAC;
`os` and `version` become the OS and version; `hardware` becomes the model;
`type` becomes the device type where it maps; `serial` and `location` become
tags; and `sysDescr`, `sysObjectID`, `sysContact`, `features`, `purpose`,
`notes`, `uptime`, `snmpver`, `poller_group`, and the status fields become
`librenms_` attributes.

### Corrections to the documented endpoint set

Several of the paths in circulation — including in this repository's own
research notes — do not exist. These were checked against `routes/api.php` and
`includes/html/api_functions.inc.php` on master:

- **`GET /api/v0/devices/{id}/arp/all` does not exist.** There is no `arp` route under `/devices` at all. Worse, the catch-all `Route::get('{hostname}/{type}', 'get_graph_generic_by_hostname')` is registered first and would swallow such a request into the graph handler. The correct paths are `/api/v0/resources/ip/arp/all` (optionally `?device=<hostname|id>`) and `/api/v0/resources/ip/arp/{ip}`.
- **`GET /api/v0/devices/{id}/ports` returns only `ifName` by default.** `validate_column_list($request->input('columns'), 'ports', ['ifName'])` returns that default whenever no `columns` parameter is supplied, so `ifPhysAddress` — the entire reason to call this endpoint — is simply absent unless you ask for it. This integration always names its columns. A column the schema does not have raises `InvalidTableColumnException` and answers **400**; the first 400 disables port collection for the rest of the run and says so, rather than repeating the same failure once per device.
- **Inventory lives at `/api/v0/inventory/{id}/all`, not under `/devices/`.** It is not collected today; see [Future](#future).
- The documented "full port object" example is **stale** — it shows `ifPromiscuousMode`, `ifHighSpeed`, `ifHardType`, `counter_in`, `counter_out`, and `detailed`, none of which are current `ports` columns. The default `port_columns` here sticks to long-established ones.
- The envelope key order is `status`, `devices`, `count`, from `api_success()`. The doc prints `status`, `count`, `devices`. Both parse the same, but the doc's `"message": ""` never actually appears — `api_success` only emits `message` when it is non-empty.

### Pagination: there is none

`GET /api/v0/devices` builds `SELECT … FROM devices AS d … GROUP BY d.hostname
ORDER BY $order` with **no `LIMIT` and no `OFFSET`**, and accepts no `limit`,
`offset`, `page`, or `per_page` parameter. Grepping the whole 4000-line API
implementation for paging finds exactly two things: a hard, non-user-controllable
`limit(1000)` inside `list_fdb_detail`, and `start`/`limit` on `list_logs` —
**the event log is the only paginated endpoint in the API**.
`/resources/ip/arp/all` and `/resources/fdb` are likewise whole-table reads.

So the three big endpoints are fetched with raw `http.get` and walked with
`jsonstream.iter_array(body, path=…)`, which yields one row at a time instead of
materializing every row as a decoded value at once, and assets are handed to
`report_asset` one record at a time. Dropping to raw `http.get` costs the retry
budget — it accepts no `retries` kwarg — so those three calls get a single
attempt each, while the per-device calls keep the default three. `iter_array`
**aborts the script** when its path is missing, so each body is checked for its
collection key before it is streamed.

`max_devices` and `max_discovered` bound the run regardless, and say what they
dropped when they trip.

### `type` is a filter, not a page

`/devices?type=` accepts far more values than the docs list: `all`, `active`,
`ignored`, `up`, `down`, `disabled`, `os`, `mac`, `ipv4`, `ipv6`, `location`,
`location_id`, `hostname`, `sysName`, `display`, `device_id`, `type`, `serial`,
`version`, `hardware`, and `features`. An unrecognised value **silently falls
through to "all"** rather than erroring, so a typo imports everything instead of
failing. Note also that `type=mac|ipv4|ipv6` appends `p.*` to the SELECT and
merges port columns into the device objects, which changes the response shape —
avoid those three unless you mean it. `active` means `ignore=0 AND disabled=0`,
and is the usual choice.

### Empty means 404

LibreNMS returns **404 with a message** rather than an empty collection when a
resource has no rows: `No ports found`, `Fdb entry does not exist`,
`Device <hostname> does not exist`. Every collection read here treats 404 as
empty and logs it at info level. An integration that treats 404 as a failure
would report an error on every device with no ports, which on a real estate is
most of the virtual ones.

Authentication failures use a **different envelope again**. They never reach
`api_error()`, so they arrive in Laravel's default shape —
`{"message": "Unauthenticated."}` for 401 and
`{"message": "This action is unauthorized."}` for 403 — with **no `status`
key**. Both shapes are handled.

### MAC format

LibreNMS stores MACs as **bare 12-character lowercase hex with no separators**:
`Mac::hex()` is documented as "12 digit hex string 000a1fa3cc14", and the colon
form exists only for display. This integration accepts either and canonicalizes
to the colon form. One asymmetry worth knowing if you extend this: `list_arp`
normalizes a MAC query through `Mac::parse()->hex()`, but `list_fdb` does
**not** — it matches the raw route value, so a lookup there must already be bare
hex.

### `/devices/{id}/ip` is one array with two row shapes

The handler is `array_merge($ipv4, $ipv6)`, so v4 rows carry `ipv4_address` and
`ipv4_prefixlen` while v6 rows carry `ipv6_address`, `ipv6_compressed`, and
`ipv6_prefixlen`, all in a single `addresses` array. Both shapes are read here.

### Address filtering

The platform already drops loopback, multicast, and unspecified addresses before
they reach an asset, but it deliberately **keeps link-local** — and a device's
address list is full of `fe80::/10`. Two hosts that both failed DHCP would
correlate to each other on an APIPA address. `169.254.0.0/16`, `fe80::/10`,
loopback, `0.0.0.0`, and `255.255.255.255` are filtered here, and the surviving
list is preserved as `librenms_addresses`.

### Timestamps

`last_polled` and `last_discovered` are MySQL timestamps written without a zone.
Reading one as UTC can put it in the future, and a future timestamp makes the
platform reject the **entire asset record**, not just the field. Neither is
mapped to `firstSeenTS` or `lastSeenTS`; both are kept verbatim as
`librenms_last_polled_raw` and `librenms_last_discovered_raw`.

### Costs

Device collection is one request. Addresses and ports add one each per device,
so a 500-device estate with both on costs about 1,001 requests. ARP and FDB are
**one request each for the whole estate**, not one per device, which is why ARP
is on by default. FDB is off by default only because a switching estate's
forwarding table is the largest single response the API can produce and there is
no way to ask for less of it.

### Verification status

Verified against local fixtures and against the LibreNMS source, not against a
live server. Response shapes come from the vendor's own documented examples
(ARP, FDB, ports, `/ip`, inventory, VLANs, errors) corroborated by LibreNMS's
own PHPUnit assertions in `tests/BasicApiTest.php`. The complete device field
list was reconstructed from the `SELECT d.*` in `list_devices()` plus the
authoritative MySQL schema, because no complete unredacted `/devices` payload is
public — operators redact them, for the SNMP-credential reason described above.

## Future

- **Hardware inventory via `/api/v0/inventory/{id}/all`.** entPhysical rows give module descriptions, model names, manufacturers, and per-module serial numbers — SFPs, line cards, power supplies. That is real hardware inventory runZero has no other source for on network gear. It is one more request per device, so it belongs behind its own flag with a cap. Note `entPhysicalIsFRU` is a `varchar(8)` holding the strings `"true"`/`"false"`, not a boolean.
- **VLAN correlation.** `/devices/{id}/vlans` deliberately omits `vlan_id` and `device_id`, so its rows cannot be joined back to `ports_fdb.vlan_id`. The global `/resources/vlans` includes both and would let an FDB endpoint carry its VLAN *name* rather than just its numeric id.
- **Port-level services.** `ports` carries `ifType`, `ifSpeed`, `ifOperStatus`, and `ifAlias`. A future version could emit per-port detail as something richer than the flat `librenms_port_names` attribute used today, once there is a runZero model for it.
- **`/resources/links` for LLDP/CDP topology.** LibreNMS records discovered neighbor relationships. runZero has no topology model today, but the immediate neighbor of each device is a useful attribute.
- **Alert state.** `/alerts` and `/rules` expose current alerts per device. Attaching "this device has 2 active critical alerts" would let a runZero user see monitoring health beside inventory, in the same way Zabbix problem state would.
- **Wireless clients.** `/devices/{id}/wireless/{type}` exposes per-AP client counts and, on some platforms, client MACs — another endpoint class with an association point, like an FDB entry.
- **Per-device ARP instead of global.** `/resources/ip/arp/all?device={hostname}` restricts the ARP read to one device. That is N+1 and therefore worse in aggregate, but on an estate where the global table is too large to fetch it would let the read be capped and spread across runs.
- **Reporting the credential exposure.** The integration could warn once per run when `/devices` returns a populated `community` or `authpass`, so an operator learns their API is handing out SNMP credentials to any token holder. Deliberately not done yet: it needs a decision about how loud to be about someone else's upstream bug.

## API documentation

- API overview and authentication — https://docs.librenms.org/API/. Source for the `X-Auth-Token` header and token creation.
- Devices endpoints — https://docs.librenms.org/API/Devices/. `/devices`, `/devices/{id}/ports`, `/devices/{id}/ip`, and the `type` filter values.
- Switching endpoints — https://docs.librenms.org/API/Switching/. `/resources/fdb` and its response shape.
- ARP endpoints — https://docs.librenms.org/API/ARP/.
- Inventory endpoints — https://docs.librenms.org/API/Inventory/.
- **Behavioral ground truth** comes from the source. The route table is [`routes/api.php`](https://github.com/librenms/librenms/blob/master/routes/api.php); every handler is in [`includes/html/api_functions.inc.php`](https://github.com/librenms/librenms/blob/master/includes/html/api_functions.inc.php) — `api_success()` for the envelope, `list_devices()` for the absence of paging and the `SELECT d.*`, `get_device_ports()` and `validate_column_list()` for the `ifName`-only default, `list_arp()` and `list_fdb()` for the global tables. `app/Api/Controllers/LegacyApiController.php` is a 46-line `__call` shim, not the implementation.
- Table definitions — [`database/schema/mysql-schema.sql`](https://github.com/librenms/librenms/blob/master/database/schema/mysql-schema.sql), plus the migrations that postdate that baseline.
- Envelope assertions — [`tests/BasicApiTest.php`](https://github.com/librenms/librenms/blob/master/tests/BasicApiTest.php).
- SNMP credential exposure — [librenms#16048](https://github.com/librenms/librenms/issues/16048).

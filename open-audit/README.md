# Custom Integration: Open-AudIT Community

Imports audited devices from an **Open-AudIT Community** server, together with
every address and MAC they hold, the adapters those addresses are bound to, and
optionally the installed software inventory.

Open-AudIT is worth having because of *how* it collects. It audits agentlessly
over SSH, WMI, and SNMP as well as by agent, and writes the result into a
relational schema rather than a document store — `devices` has a hundred-odd
columns, and `ip`, `network`, and `software` are separate tables keyed on
`device_id`. One device row carries the serial number, the chassis form factor,
the OS build, the VM host it runs on, and the SNMP `sysObjectID` at once, and
the sub-tables carry the multi-homed reality a discovery-only record never sees.
For an estate already running it, this is a genuine CMDB, not a monitoring side
effect. The vendor is now **FirstWave**, which acquired Opmantek; Community is
still open source (AGPL) and still actively released. Everything below was read
against the 6.0.4 source.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Open-AudIT web server — Apache on port 80 or 443. Open-AudIT is very commonly reached over plain HTTP on a management network, so `http://` is a normal value for the URL.
- `OPTIONS_TLS` is exposed for installs that put Open-AudIT behind an internal certificate. Nothing is skipped by default.

## Open-AudIT requirements

- **An Open-AudIT user with `read` on the `devices` collection**, and access to the organisations whose devices you want.
- **No API module to enable, and no licence tier.** The API is the web application: every page in the UI is the same controller answering with `format=html` instead of `format=json`. There is nothing to switch on first.
- **There is no bearer token.** This is the one thing worth reading twice, because almost every other integration in this repository has one.

### There is no API token in Community

Authentication is a **session cookie and nothing else**. The vendor documents it
plainly — *"The API uses a cookie. You can retrieve a cookie by sending a `POST`
request to the URL below, passing the `username` and `password` attributes."* —
and the source agrees: no `Authorization` header, no `Bearer` handling, no token
guard anywhere in the request path.

The `users` table *does* have an `access_token` column and the API docs *do*
mention an access token, which is exactly why this needs stating: that token is
a **CSRF token for writes**, not a credential. It is checked only on `POST`,
only when `access_token_enable` is `y`, and only against a value the server put
in your session moments earlier. This integration issues nothing but `GET` and
never touches it.

So the credential is a username and a password, exchanged once at
`POST /index.php/logon` for the `ci_session` cookie, which is replayed as a
`Cookie` header on every data call.

### Which role grants read on devices

Open-AudIT ships **four** roles, and a role is a JSON map of collection name to
some subset of the letters `c`, `r`, `u`, `d`:

| Role | `devices` permission | Use for this integration |
|---|---|---|
| `user` | `r` | **Yes — this is the right one.** Read on devices, locations, networks, orgs, and the rest of the org-scoped collections. |
| `org_admin` | `crud` | Works, but grants delete on your inventory for no reason. |
| `admin` | `r` | Works for devices, but this role exists to change global options; it is the wrong shape for a collector. |
| `collector` | `crud` | Meant for Open-AudIT's own collectors. Not this. |

A user with none of these authenticates fine and is then refused: the response
helper answers **HTTP 403** with a JSON body reading *"User … requested to
perform collection on devices, but has no permission to do so."* This
integration recognises that failure and prints `open-audit: check that the user
has read permission on the devices collection` rather than reporting an empty
inventory. Organisations are a second, independent gate — a user with the `user`
role but no organisation sees no devices.

### Creating the credential in Open-AudIT

1. Log in to Open-AudIT as an administrator and go to
   **Manage → Users → Create Users**.
2. Fill in at least the **username** and **password**. A dedicated user
   (`runzero`) beats reusing a human account, because the audit log then shows
   which collection ran.
3. Assign at least one **Role**. Choose **`user`** unless you have a reason not
   to — it is the shipped read-only role and its `devices` permission is `r`.
   Several roles can be selected and their permissions combine.
4. Grant access to at least one **Organisation**; selecting a parent
   organisation automatically includes its children. Leave the user **active**.
5. Confirm the credential from the Explorer host before configuring anything in
   runZero. The first call logs in and keeps the cookie; the second uses it:

   ```bash
   curl -s -c /tmp/oa-cookies.txt \
     -H 'Accept: application/json' \
     --data-urlencode 'username=runzero' \
     --data-urlencode 'password=ExamplePassword123' \
     'https://openaudit.example.com/open-audit/index.php/logon'

   curl -s -b /tmp/oa-cookies.txt \
     -H 'Accept: application/json' \
     'https://openaudit.example.com/open-audit/index.php/devices?format=json&limit=1&properties=devices.id,devices.name,devices.ip'
   ```

   A successful logon answers **200 with the user object as JSON**; a wrong
   password answers **401**, after a deliberate five-second delay, so a hang
   before the error is the server rate-limiting you rather than a network
   problem. The second call should answer an envelope with `meta`, `included`,
   `logs`, and `data`; **HTML instead of JSON** means the cookie was not
   accepted and you were bounced back to the login page.

   The `Accept: application/json` header on the logon is not optional. Without
   it the controller answers HTML and **redirects on both success and failure**,
   which makes the two outcomes indistinguishable from the client's side.

### The application path

The default installer serves the application under **`/open-audit`** on both
Linux and Windows, so the default URL is `http://<server>/open-audit/index.php`.
That is what `app_path` defaults to; a site that re-hosted the application at
the web root should set it to a single `/`.

### Community versus Professional and Enterprise

Everything this integration reads — the devices collection, the per-device read,
and the `ip`, `network`, and `software` sub-tables — is Community. Professional
adds Business Dashboards, report filtering, scheduled discovery, scheduled
reports, and maps; Enterprise adds file auditing, baselines, and *"Role Based
Access Control"*.

That last item needs an honest note rather than a confident restatement.
Community demonstrably ships the four roles above and enforces per-collection
permissions in code, so the Enterprise line is most likely about **creating and
editing custom roles** rather than about roles existing at all — but that
reading was **not** confirmed, because the vendor's comparison page is truncated.
If your server does not offer role editing, the shipped `user` role is all this
integration needs.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Open-AudIT").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Open-AudIT server URL** (`url`): the base URL of the web server *without* the application path, e.g. `https://openaudit.example.com`.
   - **Application path** (`app_path`): optional, default `/open-audit`. Set to `/` when the application is served from the web root.
   - **Username** (`username`) and **Password** (`password`): the user from the steps above.
   - **Organisation ID** (`org_id`): optional. Import only devices in this Open-AudIT organisation id; blank imports every organisation the user can see.
   - **Include retired devices** (`include_retired`): optional, default **disabled**. Off because Open-AudIT keeps `deleted`, `lost`, and `retired` rows so their history survives, not because the device is still on the network.
   - **Collect addresses and adapters** (`collect_interfaces`): optional, default **enabled**. This is what supplies MACs and secondary addresses, at one extra request per device.
   - **Collect installed software** (`collect_software`): optional, default **disabled**. Adds no requests when addresses are already being collected, but makes each response substantially larger.
   - **Detail request cap** (`max_detail_devices`): optional, default 2000.
   - **Page size** (`page_size`): optional, default 500.
   - **TLS options** (`tls_*`): set these if Open-AudIT is behind an internal certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Schedule it to run **after** your Open-AudIT discovery, so the inventory is fresh. Open-AudIT inventories change slowly, so daily is usually plenty.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Open-AudIT.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:open-audit`, or with the `tag:open-audit` every asset carries.
- The device row's own vocabulary becomes tags: `tag:type:switch`, `tag:class:virtual server`, `tag:status:production`, `tag:environment:staging`. Devices Open-AudIT considers gone carry `tag:open-audit-retired`, and a host whose audit found a hypervisor, VPN, or container adapter carries `tag:open-audit-virtual-adapters`.
- Every device column is searchable under the `open_audit_` prefix: `open_audit_serial`, `open_audit_form_factor`, `open_audit_vm_server_name`, `open_audit_cluster_name`, `open_audit_os_arch`, `open_audit_org_name`, `open_audit_location_name`, `open_audit_sys_location`, `open_audit_snmp_enterprise_name`, `open_audit_last_seen_by`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename open-audit/open-audit.star \
  --kwargs url=https://openaudit.example.com \
  --kwargs app_path=/open-audit \
  --kwargs username=runzero \
  --kwargs password=ExamplePassword123 \
  --kwargs collect_interfaces=true \
  --kwargs page_size=50 \
  --kwargs max_detail_devices=10 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/open-audit-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; without it the assets are parsed and discarded.
Capping `max_detail_devices` on a first run is the difference between a smoke
test and one request per device across the whole estate.

**One CLI caveat:** none of these parameters is a list, so the usual
comma-splitting problem does not apply — but `--kwargs` still mangles a value
holding both `=` and a comma, and the password is the one free-text secret here.
If yours has that shape, set it through the console credential form instead.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename open-audit/open-audit.star --validate
```

`python3 tests/run.py open-audit` exercises the fixture scenarios in
`open-audit/tests/fixtures/` — a full collection with sub-table joins, an empty
estate, five malformed row shapes, `limit`/`offset` paging, a session that
expires mid-run, and the detail cap — against the real scanner.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://openaudit.example.com,username=runzero,password=ExamplePassword123'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: one row of Open-AudIT's **`devices`** table — an audited device, which may be a server, a workstation, a switch, a printer, a UPS, or anything else its discovery classified.
- Source ID field: **`devices.id`**, the table's `AUTO_INCREMENT` primary key.
- Documentation evidence: it is the primary key in the schema, the value the JSON:API envelope repeats as both `data[].id` and `data[].attributes.id`, the path segment every per-device route takes (`/index.php/devices/{id}`), and the `device_id` foreign key that `ip`, `network`, and `software` join on with `ON DELETE CASCADE`. Nothing else in the record is treated as identity by the application.
- Uniqueness scope: **one Open-AudIT server**. It is a database sequence, so two servers both numbering a device `14` mean two different devices. The id is therefore scoped on the server hostname taken from the configured URL.
- Cardinality: exactly one row per device per response. The collection is paged with a pinned sort, so a device appears once per run.
- Stability: survives **re-audit, rename, and re-address** — which is the whole reason it is trusted here. Open-AudIT matches an incoming audit against its existing rows and updates in place; the address moving, the hostname changing, or a NIC being swapped does not mint a new row. It changes only when the device is deleted and re-discovered.
- Reuse behavior: not documented by the vendor. It is a MySQL `AUTO_INCREMENT` and is not recycled in practice, but that is an inference from the schema rather than a published contract, and it is the weakest link in this record.
- Presence: required, and the server guarantees it — the response helper force-appends `devices.id` to the requested `properties` list when the caller omits it, so the column is present even if that list is edited.
- Final runZero ID: `open-audit:<server-hostname>:<devices.id>` — for example `open-audit:openaudit.example.com:14`.
- Missing-ID behavior: **skip and count.** In `fetch_and_report` the id is read from `attributes.id`, then from the envelope's own `data[].id` as a fallback, and the row is skipped when both are empty *or when the value is `"0"`* — zero is not device zero, it is what PHP's `intval()` produces for anything unparseable, so importing it would collide every such row onto one asset. Each skip prints `open-audit: skipping a devices row with no id at offset <n>`, and the run ends with `open-audit: skipped <n> rows with no usable device id`. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**.
- Verdict: **scoped authoritative.** A real, stable, non-address vendor identifier, and one of the few in this repository allowed to drive merges.

The match behavior follows from that stability, and it governs **first
contact** — the moment before any foreign id has matched, when runZero is
deciding whether this Open-AudIT record belongs to an asset it already
discovered. `devices.id` outlives MAC, IP, and hostname churn, and this
integration reports the *current* audit state, so an arriving record may
legitimately disagree with what runZero last scanned: a laptop that moved
subnets, a server renamed mid-migration, a replaced NIC. Letting any of those
disqualify the merge would fork the asset for reasons the id already tells us to
ignore. Once the id has matched, break flags no longer participate at all.

Installed software gets ids of the form
`open-audit:<server-hostname>:<devices.id>:software:<name>:<version>` — the
natural key of the `software` table's own content, which collapses the duplicate
rows described below.

## Notes

### What is imported

| Request | Gated by | What it gives |
|---|---|---|
| `POST /index.php/logon` | always | The `ci_session` cookie |
| `GET /index.php/devices` | always | One page of device rows, ~50 columns each |
| `GET /index.php/devices/{id}?include=ip,network` | `collect_interfaces` | Every address and MAC, and the adapters they are bound to |
| `GET /index.php/devices/{id}?include=ip,network,software` | plus `collect_software` | …and the installed package list |

| runZero | Open-AudIT |
|---|---|
| `id` | `devices.id` |
| `hostnames` | `fqdn`, `dns_fqdn`, `name`, `hostname`, `dns_hostname`, `sysName` — most specific first, de-duplicated |
| `networkInterfaces` | the `ip` table joined to `network` on `net_index`, plus the device row's own `ip` |
| `os` / `osVersion` | `os_name` / `os_version` |
| `manufacturer` / `model` | `manufacturer` / `model`, placeholders stripped |
| `deviceType` | `type`, falling back to `class` |
| `software` | the `software` table's `name`, `version`, `publisher` |
| `firstSeenTS` / `lastSeenTS` | `first_seen` / `last_seen`, clamped |
| `tags` | `type`, `class`, `status`, `environment`, plus retired and virtual-adapter markers |
| `customAttributes` | ~50 device columns under the `open_audit_` prefix |

No `Service` or `Vulnerability` records are emitted: Open-AudIT audits what is
installed, not what is listening, and its vulnerability collection is a separate
feature outside what this integration reads.

### The N+1 read, and why it exists

Addresses and adapters are only available from the **per-device** read: the
collection query joins a table only when a filter names it, so no `include`
would attach `ip` and `network` rows to a collection response. Enrichment is one
request per device by construction — thousands of requests on an estate of
thousands. Hence `max_detail_devices`, default 2000. Devices past the cap are
**still imported** from the collection response, keeping their primary address
and every column on the device row; only their extra addresses, MACs, and
software are missing, and the run says what it dropped:
`open-audit: detail cap of <n> reached, <n> devices imported without addresses`.
Turning `collect_interfaces` off removes the per-device call entirely — one
request per page, no MACs.

The read returns only **current** rows. Open-AudIT keeps history by marking
superseded sub-table rows `current = 'n'` and the read filters
`WHERE device_id = ? and current = 'y'`, so a decommissioned NIC does not come
back as a live interface.

### `included` is an array when it is empty and an object when it is not

This is the trap that would abort a run, and it is not hypothetical — an
SNMP-discovered switch with no `ip` or `network` rows hits it every time.
Open-AudIT builds `included` as a **PHP array** and assigns a key only when a
sub-table query returned rows, so `json_encode` renders it `[]` when empty and
as an object keyed by table name when not. Subscripting the list form aborts the
script, so every access goes through a helper returning an empty dict unless the
value really is one, and every row inside is type-checked before it is read.

### Addresses, adapters, and the `net_index` join

The `ip` and `network` tables are joined to each other by **`net_index`**, not
by a shared key, so adapters are indexed first and each address is attached to
the adapter owning its index. Three consequences:

- An address whose index names no adapter still becomes an interface, because the address is the part runZero can merge on.
- An adapter with a MAC and **no** bound address still becomes an interface. A MAC is the strongest merge signal there is, and a switch port only ever sees that.
- The device row's own `ip` is added as its own interface when it is not already among the `ip` rows — the only address a discovery-only record ever carries.

**Virtual adapters are dropped, and their addresses go with them.** An adapter
whose description, name, alias, or model matches a hypervisor, VPN, or container
runtime — VMware, VirtualBox, Hyper-V, `vEthernet`, `docker`, WAN Miniport,
OpenVPN, Wintun, Tailscale, ZeroTier, Teredo, ISATAP and the rest — is a
software construct whose MAC belongs to the hypervisor's switch or the container
bridge. Attaching it to the host merges unrelated assets: every Docker host
carries a `docker0` bridge, and half of them carry the same `172.17.0.1`. The
filtered names are preserved as `open_audit_virtual_adapters`.

Link-local addresses are filtered here rather than left to the platform, which
drops loopback, multicast, and unspecified addresses itself but deliberately
**keeps** link-local — an estate of DHCP-failed hosts would otherwise all
correlate to each other through `169.254/16`.

### Paging and filtering

The collection is walked with `limit` and `offset`, with **`sort=devices.id`**
pinned. That sort is not decoration: without a stable ordering MySQL may return
the same row on two pages and omit another. `meta.total` counts the filtered set
rather than pointing at a page, so the walk advances the offset itself and stops
on the first page shorter than the limit.

Filters go on the query string as `<table>.<column>=<operator><value>`, and the
operator is read off the **front of the value**: `=`, `!=`, `>`, `<`, `>=`,
`<=`, `like`, `!like`, `in(...)`, `notin(...)`. Open-AudIT parses
`$_SERVER['QUERY_STRING']` by hand rather than reading `$_GET`, because PHP
replaces `.` with `_` in incoming variable names
([PHP bug 45272](https://bugs.php.net/bug.php?id=45272)) and a dotted column name
would otherwise be unusable. Two filters are sent:

- `devices.org_id=<id>` when **Organisation ID** is set.
- `devices.status=notin(deleted,lost,retired)` unless **Include retired devices** is on. Set exclusion has no dedicated syntax; `notin(...)` is it, and it maps to a `whereNotIn` clause. A server version that fails to parse `notin(...)` as an operator would treat it as a literal equality matching nothing, so an empty **first** page with this filter applied is retried once without it and the same exclusion is applied per record client-side — a genuinely empty estate answers empty both ways.

`properties` names the ~50 columns to return. Open-AudIT **validates each one
against the actual table and silently removes any it does not recognise**,
warning rather than failing — so naming a column a 4.x server lacks is safe.
`format`, `properties`, `limit`, `offset`, `sort`, `include`, `current`,
`search`, and `ids` are reserved words and are never treated as filters.

### Session expiry, and how it is detected

An expired Open-AudIT session does **not** answer 401 on a data path. The
session filter redirects to `/index.php/logon`, the client follows it, and the
login page comes back as a **200 carrying HTML**. The response struct exposes no
final URL to inspect, so the only available signal is that a 200 failed to
decode as JSON — which is what this integration keys on, alongside a genuine 401
or 403. On that signal it logs in again once and retries; a second failure is
reported rather than looped.

The login itself runs on the same HTTP option set as the data calls — proxy,
timeout, custom CA, client certificate — so an HTTPS server behind a private CA
authenticates at logon exactly as it does on every later request. (It used to
run on a `requests.Session` for the cookie jar, but `Session` accepts only
`insecure_skip_verify`, so the `tls_*` CA and client-certificate options never
reached the logon and a private-CA install failed at step one.) With
`Accept: application/json` the logon controller answers JSON directly on both
success and failure rather than redirecting, so the `ci_session` cookie is read
straight off that one response's `Set-Cookie` header and then replayed as a
plain `Cookie` header on the data calls.

### Timestamps

Open-AudIT stores every datetime as a **MySQL `DATETIME` with no offset**, so
`2026-08-14 03:11:07` is the database server's local wall clock. Two things
follow, and both shaped the code:

- Reading a zone-less local time as UTC puts it in the future for any server east of Greenwich, and the platform rejects the **entire asset record** on a future timestamp — not just the field. Parsed values are therefore clamped to now, and the unmodified vendor strings are kept as `open_audit_first_seen` and `open_audit_last_seen` so nothing is lost.
- `parse_time` aborts the whole script on anything it cannot read, and Starlark has no exception handling. So the string's shape is checked character by character before the call, the schema's `2000-01-01 00:00:00` "never" sentinel is screened out, and the date is validated against the **real length of the month, leap year included** — MySQL will happily store `2026-02-30` in a non-strict mode, and `parse_time` would reject it as "day out of range" and take the run down with it.

### Field-level cleanups

**Placeholders never become identity.** SMBIOS fields the manufacturer left
blank appear on thousands of unrelated machines, so `To Be Filled By O.E.M.`,
`Default String`, `System Serial Number`, `Not Specified`, `0`, `123456789` and
a dozen more are stripped from `serial`, `service_tag`, `manufacturer`, and
`model`. Hostnames get the same treatment — `localhost`,
`localhost.localdomain`, `unknown`, `none`, and any "hostname" that parses as a
bare IP address, which is what Open-AudIT records for a host that never resolved.

**Device types.** Only `type` values naming a runZero device class outright are
translated — about seventy, from `access point` and `ip phone` through `ups`,
`pdu`, `kvm`, and `point of sale`. An unknown `type` passes through
**title-cased**, so an operator still sees the vendor's own word. Values that
classify nothing (`computer`, `unknown`, `unclassified`, `general purpose`) are
suppressed and the coarser `class` column is consulted instead — that is where
`server`, `virtual server`, `hypervisor`, `desktop`, and `laptop` come from.

**Software rows repeat.** Open-AudIT re-inserts a `software` row on every audit,
so one product and version routinely appears several times on one device. The
product/version pair is the natural key and duplicates collapse onto it; the
list is capped at 99 per asset, because the platform rejects a record with more.

### Verification status

Verified against the local fixture scenarios, FirstWave's own documentation, and
the **Open-AudIT 6.0.4 source plus a real MariaDB schema dump of an `openaudit`
database** — not against a live server.

- The `devices`, `ip`, `network`, and `software` definitions, their `device_id` foreign keys, and the `2000-01-01 00:00:00` datetime default come from the schema dump; the four shipped roles and their permission maps from the `roles` seed rows.
- The logon behavior — credentials as POST fields *or* as `Username:`/`Password:` headers, JSON on success versus a redirect for HTML, 401 after a five-second sleep on failure — comes from the logon controller.
- The 403 permission response, the `notin(...)` operator, the reserved-word list, the forced `devices.id` property, the silent removal of unknown properties, and `access_token` being CSRF-only come from the response helper. The `current = 'y'` sub-table filter and the array-versus-object shape of `included` come from the devices model's per-device read.
- **Not verified:** the exact HTTP behavior of an *expired* session on a data path. The redirect-to-login description above is the integration's stated assumption and what the `auth-refresh` fixture reproduces, but the CodeIgniter filter performing it was not among the source files available. The integration handles 401, 403, and HTML-on-200, so it is covered either way.
- **Also not verified:** whether the vendor documents the `include` parameter under that name. It is proven from source, but the published API page calls the same feature "sub_resource_names / component types".

## Future

- **`Service` records from the `netstat` sub-table.** Open-AudIT audits listening sockets into a `netstat` table with the program that owns each one. That is exactly a runZero service list, and it is a supported `include` value, so it costs nothing beyond a longer response on a call already being made. The open question is how to reconcile a socket the audit saw locally with a port runZero could not reach.
- **Vulnerabilities.** The schema carries `vulnerabilities` and the `user` role already grants `r` on it. Whether those rows carry a CVE in the strict `CVE-YYYY-NNNN` form the platform validates is the thing to settle first, since a malformed CVE fails the whole record rather than the field.
- **`os_cpe` and `hw_cpe` as `Software.cpe23`.** The device row already carries CPE strings. `Software.cpe23` is validated against the CPE **2.2** URI binding (`^cpe:/a:`), so a modern `cpe:2.3:a:...` value would fail validation and drop the record — this needs a converter, not a field mapping.
- **Location as a runZero site.** `location_id` resolves through the `locations` table to a name, address, latitude, and longitude, and rack position down to `location_rack_position`. That is a better site mapping than most sources can offer, and today only the id and name are imported.
- **The `arp` sub-table for layer-2 neighbours.** Open-AudIT stores ARP caches per device, joined to the `ip` table on MAC. On a switch or router that is a MAC-to-IP map for everything downstream — the same class of data as the [`netdisco/`](../netdisco/) integration's node locations — and it would give addresses to endpoints Open-AudIT never audited directly.
- **A direct MySQL path for very large estates.** `runzero.sql.connect("mysql", ...)` against `devices`, `ip`, `network`, and `software` would replace one request per device with four queries and remove the detail cap entirely. The schema is stable and public. The cost is a second credential type and a database port the Explorer must reach.
- **Filtering by `last_seen` for incremental collection.** The filter grammar supports `devices.last_seen=>2026-08-01 00:00:00`, which would let a scheduled task import only what changed since the previous run. The trap is the zone-less timestamp: the comparison happens in the database server's local time, not the Explorer's.

## API documentation

- The Open-AudIT API — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163947960/The+Open-AudIT+API. Source for *"The API uses a cookie"*, the `POST` logon with `username`/`password`, the `format`/`sort`/`limit`/`offset`/`properties`/`filter` parameter list, and the statement that the access token exists for POSTing data.
- Community documentation home — https://docs.community.firstwave.com/wiki/spaces/OA.
- Users — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163948430/Users. Source for the **Manage → Users → Create Users** path and for organisation assignment inheriting to child organisations.
- Role Based Access Control — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163948121/Role+Based+Access+Control+(RBAC). Source for a role being a set of `c`/`r`/`u`/`d` permissions per endpoint, and for four roles shipping by default.
- Community versus Professional / Enterprise — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163947702/Open-AudIT+Community+versus+Professional+Enterprise. Source for the edition split quoted above, and the page whose truncation is the reason the RBAC line is reported as uncertain.
- How to install or upgrade (Linux) — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163949113/How+To+Install+or+Upgrade+Open-AudIT+(Linux) — and (Windows) — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163949038/How+To+Install+or+Upgrade+Open-AudIT+Windows. Source for the default `/open-audit/index.php` application path on both platforms.
- Open-AudIT FAQ — https://docs.community.firstwave.com/wiki/spaces/OA/pages/3163947331/Open-AudIT+FAQ. Source for the default URL `http://<server>/open-audit/index.php/`.
- Source — [`Opmantek/open-audit`](https://github.com/Opmantek/open-audit). The authoritative reference for everything the wiki truncates: the devices controller and model (`includedRead`, the `current = 'y'` filter, the shape of `included`), the response helper (`response_get_query_filter`, `response_get_properties`, `response_valid_reserved_words`, the 403 permission path, the CSRF `access_token`), the logon controller, and the schema.

# Custom Integration: OCS Inventory NG

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## OCS Inventory NG requirements

- An OCS Inventory server with the **REST API** installed. The API is a separate
  mod_perl application offered by the server installer from OCS **2.4** onward; the
  routes this integration uses were verified against **2.12.5**.
- The `/ocsapi` Apache location reachable from the runZero Explorer. The shipped
  configuration restricts it to `127.0.0.1`, so it must be widened before any remote
  client can use it.
- Optionally, an HTTP Basic credential on that location. OCS ships no user database for
  the REST API, so a username and password are only needed if the administrator added
  `AuthType Basic` themselves.
- The REST API reads the OCS database directly through its own `OCS_DB_*` connection and
  has no concept of an OCS console user or role. There is nothing to grant inside the OCS
  web console.

## Steps

### OCS Inventory NG configuration

1. Confirm the REST API is installed. `setup.sh` asks `Do you wish to setup Rest API
   server on this computer ([y]/n)?`; answering yes installs
   `Api/Ocsinventory/Restapi/Loader.pm` and drops
   `zz-ocsinventory-restapi.conf` into `/etc/apache2/conf-available/`.
2. Edit that file. The `<Perl>` block must carry working `OCS_DB_HOST`, `OCS_DB_PORT`,
   `OCS_DB_LOCAL`, `OCS_DB_USER`, and `OCS_DB_PWD` values, and `REST_API_PATH` /
   `REST_API_LOADER_PATH` must be replaced with the real installation paths.
3. Widen the `<Location /ocsapi>` block so the Explorer can reach it. The shipped block
   contains `Require ip 127.0.0.1`. Either add the Explorer's address
   (`Require ip 127.0.0.1 10.0.0.0/8`) or add a Basic credential:

   ```apache
   <Location /ocsapi>
     SetHandler perl-script
     PerlResponseHandler Plack::Handler::Apache2
     PerlSetVar psgi_app '/usr/local/share/perl/5.36.0/Api/Ocsinventory/Restapi/Loader.pm'
     AuthType Basic
     AuthName "OCS REST API"
     AuthUserFile /etc/apache2/ocsapi.htpasswd
     Require valid-user
   </Location>
   ```

4. Run `a2enconf zz-ocsinventory-restapi` and restart Apache, then confirm
   `curl https://ocs.example.com/ocsapi/v1/computers?start=0&limit=1` returns JSON.
   Serve `/ocsapi` over HTTPS: the API answers with the full inventory of every host,
   including Windows product keys, and Basic credentials are sent on every request.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "OCS Inventory NG").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OCS Inventory URL** (`url`): base URL of the OCS server, for example `https://ocs.example.com`. The `/ocsapi/v1` path is appended automatically.
   - **Username** (`username`): optional; HTTP Basic user for the `/ocsapi` location. Leave blank when the server authorizes the Explorer by IP address instead.
   - **Password** (`password`): optional; used only together with the username.
   - **Import installed software** (`include_software`): optional; fetch the per-computer software inventory (default: false).
   - **Software enrichment limit** (`software_limit`): optional; maximum number of computers to enrich with software (default: 1000, 0 removes the cap).
   - **Ignore computers not seen in (days)** (`stale_days`): optional; skip computers whose last agent contact is older than this (default: 0, which imports every computer).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from OCS Inventory NG.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ocs-inventory`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm the
`/ocsapi` location is reachable and see what a real server returns. Each `CONFIG`
parameter is a `--kwargs key=value` pair:

```bash
runzero script --filename ocs-inventory/ocs-inventory.star \
  --kwargs url=https://ocs.example.com \
  --kwargs username=runzero \
  --kwargs password=hunter2-not-a-real-password \
  --kwargs include_software=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/ocs-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

`username` and `password` are both optional, because OCS authenticates the REST
API at the Apache layer rather than against an OCS console account. On a server
that authorizes clients by address instead of Basic credentials, leave them out
entirely:

```bash
runzero script --filename ocs-inventory/ocs-inventory.star \
  --kwargs url=https://ocs.example.com \
  --kwargs stale_days=90
```

Note that this makes the command-line run only as representative as the host you
run it from. `Require ip` matches the *client's* address, so a run from your
workstation can fail with a 403 while the same credential works from the Explorer,
and vice versa. Run it from the Explorer host when the result needs to mean
something.

Leave `include_software` off for a first run — it is one extra request per
computer, and a single Windows host reports hundreds of titles. `get_bool`
accepts `true/false`, `1/0`, `yes/no`, and `on/off`.

**One `--kwargs` caveat, for the password specifically.** A comma in a value is
harmless on its own — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks is a value
carrying **both** an `=` and a comma: the flag parses an argument containing a
second `=` as a CSV record, so `password=a=b,c=d` yields `password=a=b` plus a
fabricated `c=d`. Wrap the whole argument in double quotes to pass such a value
as one field — `--kwargs '"password=a=b,c=d"'` — and double any quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename ocs-inventory/ocs-inventory.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real computer
row, and it cannot tell you whether the `/ocsapi` location has been widened past
`127.0.0.1`.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://ocs.example.com,username=runzero,password=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without an OCS server:

```bash
python3 tests/run.py ocs-inventory
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a physical or virtual computer that has reported an inventory to OCS
  through the OCS agent.
- Source ID field: `hardware.ID` on each record returned by
  `GET /ocsapi/v1/computers?start=&limit=`, which is also the string the response is
  keyed by.
- Documentation evidence: the REST route builds its response as
  `$json_return{"$computer->{ID}"}{"hardware"} = $computer`
  (`Api/Ocsinventory/Restapi/Computer/Get/Computers.pm`), so the id is both the payload
  field and the response key, and every other route addresses a computer by it
  (`GET /ocsapi/v1/computer/:id`). The schema declares
  `` `ID` int NOT NULL AUTO_INCREMENT, PRIMARY KEY (`ID`) `` on the `hardware` table
  (`files/ocsbase.sql` in `OCSInventory-ocsreports`). Confirmed against a live OCS
  2.12.5 server.
- Uniqueness scope: one OCS server. OCS has no tenant or entity partitioning of the
  `hardware` table.
- Cardinality: one row per computer. The networks, bios, storages, drives, memories,
  controllers, monitors, printers, videos, and software sections are child rows keyed by
  `HARDWARE_ID` and are folded into the same asset rather than becoming assets of their
  own. The reverse failure — one computer appearing as *several* rows — is real and is
  covered under "Reuse behavior".
- Stability: survives rename, reboot, IP and MAC change, OS upgrade, agent upgrade, and
  ordinary re-inventory. The server matches an incoming agent report to an existing row
  by `DEVICEID` and updates that row in place, so the id follows the record for as long
  as the agent keeps its local state.
- Reuse behavior: `ID` comes from a MySQL `AUTO_INCREMENT` column, which does not reissue
  values for deleted rows while the table exists. The genuine hazard runs the other way:
  **OCS is well known for duplicate records.** The agent mints its `DEVICEID` once, as
  `<hostname>-YYYY-MM-DD-HH-MM-SS`, and keeps it in its own state file
  (`Ocsinventory/Agent.pm`). Reimage the machine, reinstall the agent, or lose that state
  file, and the next report arrives with a new `DEVICEID`, so the server inserts a
  **second** `hardware` row with a new `ID` for the same physical machine. Both rows are
  imported, as two assets with two ids. See the note on duplicates below.
- Presence: always present. It is the primary key and the field every other route is
  addressed by. When a record somehow arrives without it, the response key is used, which
  the route derives from the same value; a record with neither is skipped.
- Final runZero ID: `ocs-inventory:<ocs-host>:<ID>`, for example
  `ocs-inventory:ocs.example.com:2481`. The host comes from the configured URL, so two
  OCS servers imported into one runZero account cannot collide.
- Missing-ID behavior: the record is skipped and one line is logged with the computer name
  only. No identity is synthesized and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The OCS id is authoritative
  for the server, but an OCS record is renamed by hand, keeps whatever addressing it had
  when the agent last reported, and may be one of two rows describing the same machine, so
  network churn must not disqualify a merge. This is also what lets runZero reconcile a
  duplicated OCS record against the asset it already knows about by MAC or serial.
- Verdict: scoped authoritative — authoritative within one OCS server, namespaced by the
  server host. Authoritative for the *record*, which is not always one-to-one with the
  machine.

### Notes

- **Which interface this targets, and why.** OCS exposes two. This integration targets the
  **REST API** at `/ocsapi/v1`, not the legacy `ocsinterface` SOAP/XML endpoint. The REST
  API returns JSON, so `get_json` applies and brings its retry budget with it; the XML
  endpoint would force raw `http.get`, which accepts no `retries` argument at all and gets
  one attempt per request. The REST API also pages natively and hands back the whole
  inventory tree per computer in a single response. Its cost is a hard version floor: a
  server older than 2.4, or one where the administrator declined the REST API at setup,
  cannot use this integration at all. There is no fallback path in the script — a missing
  `/ocsapi` fails the run with a clear message rather than silently degrading.
- **What is imported.** Assets from `GET /ocsapi/v1/computers?start=&limit=`. That one
  response carries the `hardware` row plus every inventory section OCS keeps for the
  computer, so network adapters, BIOS, disks, memory, monitors, and printers cost no extra
  requests. Software comes from `GET /ocsapi/v1/computer/{id}/software` and is off by
  default.
- **Pagination.** `limit` is **mandatory and must be greater than zero**. A request without
  it, or with `limit=0`, returns HTTP 200 with a four-byte body of the literal text `Argu`
  — the server's truncated "Arguments missing" message, not JSON. A 200 carrying an
  unparseable body is the worst shape an error can take, so it is reported as a fetch
  failure rather than treated as an empty inventory. Paging advances in fixed steps of 50 and stops on the first page that returns fewer than
  50 records. An offset past the end of the table is answered with a bare JSON `null`
  rather than an empty object, which decodes to `None` and is handled as a clean end of
  data. The page size is deliberately small: the route issues roughly thirty separate SQL
  queries per computer to assemble the inventory sections, so a large page is expensive on
  the server rather than on the Explorer.
- **The listing has no `ORDER BY`.** The route runs `SELECT * FROM hardware LIMIT ? OFFSET ?`
  with no ordering clause, so stable paging depends on InnoDB returning a full table scan
  in primary-key order. That holds in practice and held on the live server, but it is not
  a guarantee the server makes. A computer deleted mid-walk can shift the window and cause
  one record to be missed until the next run.
- **Computer groups live in the same table.** OCS stores its static and dynamic computer
  groups as rows in `hardware`, marked with the reserved device identifiers
  `_SYSTEMGROUP_` and `_DOWNLOADGROUP_`. The REST collection routes do **not** filter them
  — only the `search` route does — so both are dropped here. Importing them would produce
  assets named after group definitions with no addressing at all.
- **Software needs a second request, and it is opt-in.** The bulk listing does include a
  `software` array, but OCS 2.9 normalized that table: the rows carry only `NAME_ID`,
  `PUBLISHER_ID`, and `VERSION_ID` foreign keys into `software_name`,
  `software_publisher`, and `software_version`. Only `GET /ocsapi/v1/computer/{id}/software`
  joins those tables and returns `NAME`, `PUBLISHER`, and `VERSION`, so software costs one
  request per computer. A Windows host reports hundreds of titles, so the option defaults
  to off, is capped at 99 records per asset, and is bounded by `software_limit`
  (default 1000) across the run. Computers past the limit are still imported, without
  software, and the number skipped is printed. Note the route is `/software`, singular —
  `/softwares` returns 200 with no software at all. OCS publishes no CPE for an
  installation, so `Software.cpe23` is deliberately left unset rather than synthesized.
- **Timestamps carry no timezone, and a future one drops the whole asset.** OCS serializes
  MySQL `DATETIME` as `2026-08-15 08:44:01`, with a space and no offset, which `parse_time`
  rejects with an error that would abort the script; each value is validated field by field
  and a `Z` is appended before parsing. OCS keeps these in the timezone of its database
  server and publishes no offset, so **they are read as UTC**. That is not merely cosmetic
  here: runZero rejects an `ImportAsset` whose first- or last-seen time is in the future
  and drops the entire record, so a server east of UTC would lose every asset it imported.
  Any timestamp ahead of the Explorer's clock is therefore capped at the current time, and
  the unmodified string is always kept in `ocs_inventory_last_contact` and
  `ocs_inventory_last_inventory`. This was found by running against a live server, not by
  reading.
- **`LASTCOME` is the last-seen time.** OCS writes `LASTCOME` every time the agent contacts
  the server and `LASTDATE` only when it delivers a full inventory, so `LASTCOME` becomes
  `lastSeenTS` with `LASTDATE` as the fallback.
- **`firstSeenTS` is derived from `DEVICEID`.** OCS records no creation date for a computer.
  The agent builds its `DEVICEID` once, on first run, as `<hostname>-YYYY-MM-DD-HH-MM-SS`,
  so the trailing timestamp is when this record's agent first registered. The hostname may
  itself contain dashes, so the six fields are taken from the end and every one is validated
  before parsing. It comes from the *agent's* clock at install time, so treat it as
  approximate; the raw value is kept in `ocs_inventory_deviceid`.
- **Virtual and loopback adapters are filtered, and this matters.** OCS reports every
  adapter the host has, which on a developer workstation or a hypervisor means VMware
  VMnet, Hyper-V vEthernet, `docker0`, `veth`, tunnels, WAN miniports, and the loopback
  interface. Those MACs belong to the virtualization stack, are frequently identical across
  machines (every VMware Workstation install has the same VMnet1 subnet), and would invent
  merge signals pointing at the wrong asset. An adapter is dropped when the Unix agent's
  own `VIRTUALDEV` flag is set — it is derived from `/sys/devices/virtual/net`, which
  catches `lo`, `docker0`, `veth`, `virbr`, and `tun` — or when its description matches a
  known software adapter, which is how the Windows agent's devices are caught because it
  does not populate `VIRTUALDEV` reliably. The names of everything dropped are kept in
  `ocs_inventory_virtual_adapters` so the filter is auditable rather than silent.
- **Loopback is filtered from addresses as well.** Loopback, unspecified, and link-local
  addresses are removed from every adapter and from `hardware.IPADDR` before interfaces are
  built. A host whose only address is `127.0.0.1` is imported with no network interface
  rather than sharing an address with every other such host. The placeholder MAC
  `00:00:00:00:00:00` that the agent writes when an adapter reports no hardware address is
  dropped the same way.
- **A disabled adapter keeps its MAC but loses its addresses.** `STATUS` is `Up` or `Down`.
  A down adapter's MAC is real hardware and a good merge key; the address recorded against
  it is not bound to anything and is often stale, so it is discarded.
- **One interface per adapter.** Each surviving adapter becomes its own runZero network
  interface, so a multi-homed host keeps its per-NIC addressing instead of collapsing into
  one interface. When no adapter survives the filter, the joined `hardware.IPADDR` list
  becomes a single address-only interface so the host does not lose its addressing
  entirely. `IPADDR` is a joined string, not one address — the Unix agent joins with `/`
  and other agents have used commas — so it is split on all of those and each candidate is
  validated, because the agent's IPv6 branch is known to emit malformed values.
- **SMBIOS placeholders are stripped.** `To Be Filled By O.E.M.`, `Default string`,
  `System Product Name`, `No Asset Tag`, `Not Settable`, `None`, and the rest arrive from
  the agent as ordinary values. Left alone, a `serial:To Be Filled By O.E.M.` tag would be
  shared by every whitebox machine in the estate and would read as a real hardware
  identifier. Every serial, asset tag, UUID, manufacturer, and model is checked against that
  list and blanked when it matches.
- **The Windows product key is never copied.** `hardware.WINPRODKEY` is returned by the API
  alongside everything else. It is a licence secret, so it is not written to a tag, an
  attribute, or a log line. `WINPRODID`, `WINCOMPANY`, and `WINOWNER` are imported.
- **Device type comes from the SMBIOS chassis.** `bios.TYPE` is the chassis type — the Unix
  agent resolves the numeric DMI value through the SMBIOS table before storing it, and both
  the label and the raw number are handled here. When the chassis is absent or reported as
  `Other`, which is what a hypervisor guest reports, the system manufacturer and model are
  checked for VMware, VirtualBox, QEMU/KVM, Xen, Hyper-V, Parallels, and the major cloud
  hypervisors, and the asset is typed as a Virtual Machine.
- **A `WORKGROUP` of "WORKGROUP" is not a domain.** A Windows host that joined no domain
  reports the literal string, which would otherwise become a domain shared by every
  standalone machine, so that exact value is not mapped to `domain`.
- **Deep hardware detail becomes attributes, not objects.** OCS's drives, storages,
  memories, controllers, monitors, printers, videos, CPUs, and virtual machines have no
  home in the runZero asset model, so they are summarized: total and free volume space,
  installed memory and module count, disk models and serials, monitor models and serials,
  printer names, controller names, and the names of any guests the host is running. Nothing
  is forced into `Software` or `Service` to make it fit.
- **No services and no listening ports.** OCS has no port or listener inventory of any
  kind. Its `ports` table describes physical serial and parallel ports from SMBIOS, not
  sockets. Nothing is synthesized, so assets from this integration carry no `Service`
  records.
- **No vulnerabilities, though OCS 2.9+ can produce them.** OCS has an optional CVE Search
  feature that matches installed software against an NVD feed into a `cve_search_computer`
  table, exposed at `GET /ocsapi/v1/cve/computer`. It is not mapped, for three reasons.
  It is off unless an administrator enabled it and downloaded the feed, so most servers
  return an empty list. The route **ignores its `start` and `limit` parameters entirely**
  and returns the whole table in one response — verified live by seeding a row and
  requesting it with `start=0&limit=100`, which returned the row regardless — so there is
  no way to stream it and a large estate would return a match per software title per host
  in a single body. And the `CVSS` column is a bare varchar with no indication of whether
  it holds a v2 or a v3 score, so it cannot be assigned to `cvss2BaseScore` or
  `cvss3BaseScore` without guessing. See the Future section.
- **Authentication is Apache's, not the API's.** The REST API has no user model. Access is
  whatever the `<Location /ocsapi>` block enforces, which by default is an IP allow list
  with no credential at all. Username and password are therefore both optional, and are
  only sent as a Basic header when both are supplied; supplying only one is rejected before
  any request is made. On the live 2.12.5 server used for testing, requests with no
  credentials, with valid credentials, and with deliberately wrong credentials all returned
  identical 200 responses, which is worth knowing before assuming the API is protected.
  401 and 403 are reported with a message pointing at the `Require` directive.
- **Rate limiting.** OCS publishes no rate limit and returns no rate-limit headers.
  Transient failures (408, 425, 429, 5xx) are retried with exponential backoff by the
  shared HTTP helper, which honors `Retry-After`.
- **Duplicates, plainly.** If a machine was reimaged and its agent re-registered, OCS holds
  two `hardware` rows for it and this integration imports both, because both are real rows
  and inventing a merge would be worse than reporting what OCS says. Three things mitigate
  it. `matchBehavior` lets runZero merge them against an asset it already knows by MAC or
  serial. The `stale_days` option drops records whose agent stopped checking in, which is
  exactly the abandoned half of a duplicate pair. And OCS's own console has a duplicate
  resolution page under **Inventory > Duplicates** that merges records at the source, which
  is the right place to fix it.
- This integration was validated against a live OCS Inventory NG **2.12.5** server running
  locally in Docker (`ocsinventory/ocsinventory-docker-image`, schema loaded from
  `ocsbase_new.sql`, inventory seeded by direct SQL), and additionally against local
  fixtures for pagination across three pages, 401 and 403, a 429 with `Retry-After`, a
  non-JSON body, an empty inventory, malformed records, a computer whose only address is
  loopback, a hypervisor host with six software adapters, groups, SMBIOS placeholders,
  future and unparseable timestamps, and the six duplicate-identity cases. It has not been
  run against a large production estate, against an OCS server older than 2.12, or against
  a `/ocsapi` location that actually enforces Basic authentication.

## Future

- **Outbound: package deployment.** OCS's Deployment feature can push a file and run a
  command on any agent, targeted by computer or by group. It would let runZero act on what
  it finds — deploy an agent to a host runZero discovered but OCS has never seen, or push a
  remediation to every asset matching a runZero query. **This deserves a warning rather
  than encouragement:** it executes arbitrary code as SYSTEM or root on every targeted
  endpoint, and an outbound integration wiring a search result straight into a deployment
  target list is one bad query away from a fleet-wide incident. It is also not reachable
  from the REST API, which is read-only and exposes no deployment routes at all — the
  activation flow lives in the `ocsreports` PHP console and the download protocol between
  the agent and server. Any such integration would have to drive the console rather than
  the API, which is a much weaker contract. If it is ever built it should be opt-in per
  package, require an explicit confirmation step, and default to a dry run.
- **SNMP-scanned network devices as a second asset class.** This is the most interesting
  unclaimed surface. OCS agents can be told to SNMP-sweep their local network, and the
  server stores what they find in typed tables — `snmp_printers`, `snmp_switches`,
  `snmp_firewalls`, `snmp_blades`, `snmp_loadbalancers`, `snmp_storages`, and more — with
  MAC, IP, sysDescr, serial, and uptime. They are already exposed:
  `GET /ocsapi/v1/snmps/typeList` lists the types and
  `GET /ocsapi/v1/snmp/{TABLE_TYPE_NAME}?start=&limit=` pages each one. That is a
  population runZero cares about a great deal — the printers, switches, and appliances that
  cannot run an agent — and it is a clean second import that reuses the same connection.
  It was left out of this first version only because it is a different identity problem:
  `snmp_laststate` keys on a `SNMPDEVICEID` derived from the scanning agent, so the same
  switch seen by two agents can appear twice, and that needs its own decision record.
  `GET /ocsapi/v1/ipdiscover/network/{NETID}` is a lighter-weight cousin: OCS's IpDiscover
  feature has agents ARP-sweep their subnet and record IP, MAC, and hostname for everything
  they see, including devices with no agent, which is essentially a free unmanaged-device
  feed.
- **Vulnerabilities from CVE Search.** If the unpaginated `GET /ocsapi/v1/cve/computer`
  response is acceptable for a given estate, its rows already carry `HARDWARE_ID`, `CVE`,
  `CVSS`, `SOFTWARE_NAME`, `PUBLISHER`, `VERSION`, and a `LINK`, which is enough for a
  `Vulnerability` attached to the right asset. Two problems have to be solved first: the
  route returns the entire table in one body with no way to page it, and the `CVSS` column
  gives no indication of its scoring version. A future revision could fetch it once, index
  it by `HARDWARE_ID`, and attach findings during the main walk, gated behind an option and
  a size guard, with the score kept as a custom attribute rather than guessed into a typed
  CVSS field.
- **GLPI interop, and the duplicate-source question.** OCS-to-GLPI synchronization is a
  standard deployment: OCS collects the inventory and pushes it into GLPI as the ITAM
  system of record. A customer running that pattern may well have **both** this integration
  and the GLPI one enabled, importing the same physical machines from two sources with two
  different foreign ids. That does not break anything — runZero merges them on MAC, serial,
  and hostname, and each source contributes its own attribute namespace — but it does mean
  attribute counts and asset ownership look doubled unless it is expected. Where they
  overlap GLPI is the better source for ownership, location, contracts, and ticket history,
  and OCS is the better source for deep hardware detail: memory modules, controllers,
  monitor serials, BIOS versions. A deployment running both should consider importing
  computers from GLPI and using OCS only for the hardware detail GLPI does not carry.
- **Agent coverage gap reporting.** The most valuable thing this integration enables is
  read in the negative. Once OCS computers are in runZero, `custom_integration:ocs-inventory`
  splits the estate into what the agent covers and what it does not, and the complement of
  that set — assets runZero found on the network with no OCS record — is the agent coverage
  gap, which is precisely the number an IT asset team cannot get from OCS itself.
  `ocs_inventory_last_contact` sharpens it further: an OCS record whose agent stopped
  reporting three months ago, on an asset runZero still sees actively on the network, is a
  broken agent rather than a decommissioned machine. Neither query needs any new code, only
  the attributes this integration already imports.
- **Incremental import.** `GET /ocsapi/v1/computers/lastupdate/{unix-timestamp}` returns the
  ids of computers whose `LASTDATE` is newer than the timestamp, which would let a frequent
  schedule fetch only what changed. It returns bare ids, so each one still costs a
  `GET /ocsapi/v1/computer/{id}` — a win only when the changed fraction is small. Note the
  route is lowercase `lastupdate`; `lastUpdate` returns 404.

## API documentation

- OCS Inventory REST API introduction, configuration, and authentication:
  https://wiki.ocsinventory-ng.org/11.Rest-API/Introduction/,
  https://wiki.ocsinventory-ng.org/11.Rest-API/Configuration/,
  https://wiki.ocsinventory-ng.org/11.Rest-API/Authentification/
- GET route reference (computers, computer sections, softwares, snmp, ipdiscover, cve):
  https://wiki.ocsinventory-ng.org/11.Rest-API/GET-Routes/
- Route definitions and response construction, read directly because the wiki does not
  document response shapes: https://github.com/OCSInventory-NG/OCSInventory-Server/blob/master/Api/Ocsinventory/Restapi/Loader.pm
  and `Api/Ocsinventory/Restapi/ApiCommon.pm` in the same repository.
- Inventory section and column names (`hardware`, `bios`, `networks`, and the rest):
  https://github.com/OCSInventory-NG/OCSInventory-Server/blob/master/Apache/Ocsinventory/Map.pm
- Database schema, for column types and the `AUTO_INCREMENT` primary key:
  https://github.com/OCSInventory-NG/OCSInventory-ocsreports/blob/master/files/ocsbase.sql
- Agent behaviour — `DEVICEID` generation, `VIRTUALDEV`, adapter `STATUS`, and the SMBIOS
  chassis table: https://github.com/OCSInventory-NG/UnixAgent
- Shipped Apache configuration for the `/ocsapi` location:
  https://github.com/OCSInventory-NG/OCSInventory-Server/blob/master/etc/ocsinventory/ocsinventory-restapi.conf

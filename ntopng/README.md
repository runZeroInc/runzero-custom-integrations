# Custom Integration: ntopng

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the ntopng web interface, by default HTTP on port 3000.

## ntopng requirements

- ntopng 4.2 or later. The REST v2 API was introduced in 4.2. Community Edition is
  sufficient: every endpoint used here is under `/lua/rest/v2/`, and the Pro and
  Enterprise endpoints live under the separate `/lua/pro/rest/v2/` prefix, which this
  integration never calls.
- An ntopng user with read access, or that user's API token.
- **Local networks configured correctly.** ntopng only calls a host "local" if its address
  falls inside the networks given to `-m` / `local networks`. On a sensor where that is
  left at the default, the local host table will be almost empty and the remote table
  will contain the entire internet. This is the single most important configuration
  detail for this integration.

## Steps

### ntopng configuration

1. Confirm the local networks are set. In the ntopng interface, **Settings → Preferences
   → Network Interfaces**, or the `-m` startup flag / `local networks` line in
   `/etc/ntopng/ntopng.conf`:

   ```
   -m=192.0.2.0/24,198.51.100.0/24
   ```

   Restart ntopng after changing it. Without this the **local** host selection this
   integration defaults to returns nothing useful.

2. Create or choose the user the integration will authenticate as. In
   **Settings → Manage Users**, add a user with a read-only role.

3. Optional but preferred: generate that user's API token. Open the user's own
   preferences page and generate an API token. It is sent as
   `Authorization: Token <token>`, which avoids putting a reusable password on the
   Explorer.

4. Confirm the credential and discover the interface ids from the Explorer host. The
   REST v2 endpoints are **POSTs carrying a JSON body even though they are reads**:

   ```bash
   curl -s -H 'Content-Type: application/json' \
     -H 'Authorization: Token <token>' \
     -d '{}' \
     'http://ntopng.example.com:3000/lua/rest/v2/get/ntopng/interfaces.lua'

   curl -s -H 'Content-Type: application/json' \
     -H 'Authorization: Token <token>' \
     -d '{"ifid":"1","mode":"local","currentPage":1,"perPage":50}' \
     'http://ntopng.example.com:3000/lua/rest/v2/get/host/active.lua'
   ```

   A healthy response is wrapped in ntopng's envelope:
   `{"rc":0,"rc_str":"OK","rc_str_hr":"Success","rsp":{...}}`.

5. **Check that you actually authenticated.** ntopng's own source carries this comment on
   every v2 endpoint: *"NOTE: in case of invalid login, no error is returned but
   redirected to login"*. A bad credential produces an HTML login page with an HTTP 200
   status, not a 401. If the curl above prints HTML, the credential was rejected — the
   status code will not tell you.

6. If ntopng is behind TLS, either supply the certificate as the **CA certificate** in the
   runZero credential or run the integration against the plaintext listener on a trusted
   segment. ntopng serves plain HTTP on 3000 by default.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "ntopng").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **ntopng URL** (`url`): base URL of the web interface, for example `http://ntopng.example.com:3000`.
   - **Username** (`username`): optional; ntopng user with read access. Leave blank when a token is supplied.
   - **Password** (`password`): optional; that user's password.
   - **API token** (`api_token`): optional; the user's API token, sent as `Authorization: Token <token>`. Preferred over a password.
   - **Interface ids** (`interface_ids`): optional; comma-separated ntopng interface ids. Leave blank to enumerate every monitored interface.
   - **Host selection** (`host_mode`): optional; `local`, `broadcast_domain`, or `all` (default: `local`). See the note below before choosing `all`.
   - **Page size** (`page_size`): optional; hosts per page, sent as `perPage` (default: 250).
   - **Maximum hosts per interface** (`max_hosts`): optional; stop paging an interface after this many hosts (default: 25000).
   - **Join the MAC table** (`include_macs`): optional; fold each MAC's manufacturer and device type onto the hosts using it (default: true).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.
   - **Schedule this more frequently than a CMDB import.** ntopng's active-host table is a
     live view, not a record: a host that stops sending traffic ages out. An hourly or
     four-hourly task sees a materially different population than a daily one.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename ntopng/ntopng.star \
  --kwargs url=http://ntopng.example.com:3000 \
  --kwargs api_token='<token>' \
  --kwargs host_mode=local \
  --kwargs page_size=250 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./ntopng-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a directory
from a previous run. Add `--verbose` for the request-by-request log. Omit `--output` to
see only the log lines.

Note that `--kwargs` splits a single flag's value on commas, so a multi-interface list
such as `interface_ids=1,2` cannot be passed on the command line. Name one id at a time,
or leave it blank to enumerate every interface. The console's credential form has no such
limitation.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename ntopng/ntopng.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove ntopng accepts the credential or that any host is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat ntopng/ntopng.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=http://ntopng.example.com:3000,api_token=<token>' \
  --output ./ntopng-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. This flag takes one
comma-separated string and has the same limitation described above.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with passively observed addressing and traffic context.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ntopng`.

## Asset identity

- Target entity: an ntopng **host** — an address ntopng has observed sending or receiving
  traffic on a monitored interface, within its VLAN. It is an observation, not a device
  record; ntopng has no concept of a device that exists but is quiet.
- Source ID field: the composite of the host's `ip` and `vlan`. ntopng's own host key is
  `ip@vlan`, which is what `active.lua`'s `key` field encodes in an HTML-id-safe form
  (`192_0_2_41@0`). The `key` field itself is not used, because its escaping is a
  presentation detail of the endpoint rather than a stable identifier.
- Documentation evidence: `active.lua` builds each record's `ip` with `stripVlan(key)`
  and carries `vlan` alongside it, and every per-host endpoint
  (`get/host/data.lua` and its peers) is addressed by `host` plus `vlan`. Those two
  fields are the pair ntopng itself uses to name a host.
- Uniqueness scope: one ntopng sensor and one VLAN. The sensor's hostname is part of the
  runZero id, so two sensors imported into one account cannot collide — which matters,
  because two sensors watching different segments of the same RFC 1918 space will
  otherwise report the same addresses.
- Cardinality: one source row per address per VLAN, **not** one per device. A dual-stack
  host produces two rows and therefore two assets, which then merge in runZero on their
  shared MAC. A host seen through two monitored interfaces is deduplicated to one asset,
  and the interface id is deliberately kept out of the id so that an interface renumbered
  by an ntopng restart does not re-key the estate.
- Stability: the id survives a MAC change, a rename, and traffic going quiet and
  resuming. It does **not** survive the device getting a different address, which
  produces a different id.
- Reuse behavior: **yes, and this is decisive.** An address released by DHCP and handed to
  a different device produces the same composite for a different machine. A foreign-id
  match cannot be vetoed by a conflicting MAC or hostname once it lands, so an
  address-derived id used for matching would silently merge two unrelated devices.
- Presence: `ip` is present on every record; `vlan` defaults to 0 when absent. A record
  with no parseable address is skipped and counted.
- Final runZero ID: `ntopng:<sensor-host>:<vlan>:<ip>`, for example
  `ntopng:ntopng.example.com:30:192.0.2.42`.
- Missing-ID behavior: skip and count. No identity is synthesized and `new_uuid()` is
  never used.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`.** The composite is deterministic but
  address-based, so it must neither drive nor block merging. Correlation falls back to the
  MAC, the address, and the hostname on the record; every emitted asset carries at least
  an address, and the ones ntopng observed at layer 2 carry a MAC.
- Verdict: **derived / non-authoritative.** ntopng is a traffic monitor. Its hosts are
  *addresses seen sending packets*, and its evidence is strongest exactly where runZero's
  active scanning is weakest — devices that never answer a probe but do talk. Treat it as
  a passive-discovery source layered onto assets runZero already knows about, and as a way
  to notice addresses in use that nothing else has reported.

### Notes

- **What is imported.** One asset per active host from
  `POST /lua/rest/v2/get/host/active.lua`, carrying its address and VLAN, the MAC when
  ntopng saw one, the fingerprinted operating system, hostnames, host pool, country,
  alert count, active flow counts, byte counters, throughput, and first- and last-seen
  times. With **Join the MAC table** enabled,
  `POST /lua/rest/v2/get/mac/macs_list.lua` contributes the OUI manufacturer and the
  device type ntopng's own discovery assigned.
- **Observed protocols are not services, and are not imported as services.** This is the
  central design decision and it is deliberate. ntopng knows which L7 protocols a host's
  *flows* used. A flow is directional: a workstation that made an HTTPS request appears
  with TLS traffic, and importing that as a `Service` on port 443 would assert the
  workstation is a web server, which is false. Even for genuine servers, an observed flow
  proves a port was reachable from one client at one moment, not that a listener is
  present now — and runZero's active scanning is authoritative for exactly that question.
  Fabricating services from flow observations would corrupt the data runZero is best at.
  Traffic context is preserved instead as custom attributes: `ntopng_active_flows`,
  `ntopng_active_flows_as_client`, `ntopng_active_flows_as_server`, `ntopng_bytes_sent`,
  `ntopng_bytes_received`, and `ntopng_throughput_bps`. The client/server flow split in
  particular is a real signal about a host's role, without claiming a port.
- **`host_mode` defaults to `local`, and `all` is almost never what you want.**
  `active.lua` accepts `all`, `local`, `remote`, `broadcast_domain`, `filtered`,
  `blacklisted`, and `dhcp`. In `all` mode the response includes every *remote* peer the
  monitored network exchanged traffic with — which is the public internet. Importing that
  would create a runZero asset for every web server, CDN edge, and API endpoint anyone
  browsed to. `local` restricts the result to hosts inside ntopng's configured local
  networks, which is the population that describes the estate. Choosing `all` is allowed
  and logs a warning line.
- **Multicast, broadcast, and loopback are not endpoints.** ntopng tracks multicast groups
  (`224.0.0.251` for mDNS is on every network) and broadcast addresses in the same table
  as real hosts, flagged with `is_multicast` and `is_broadcast`. Those are traffic
  destinations, not devices, and are skipped. Loopback and link-local are filtered from
  addressing before an interface is built; the platform drops loopback itself but
  deliberately keeps link-local, so APIPA has to be filtered here.
- **`00:00:00:00:00:00` is ntopng saying it has no MAC.** A host reached through a router
  rather than observed on the monitored segment has no layer 2 address from the sensor's
  vantage point, and ntopng reports the all-zero placeholder. It is rejected rather than
  passed to the MAC parser, so those hosts are imported as address-only observations.
- **The `name` field is not reliably a name.** `active.lua` fills it from reverse DNS,
  then from a configured alias, and finally from the host key itself — so a host with no
  name arrives carrying **its own IP address** in the name field, which the platform would
  reject as a hostname. The endpoint also appends a bracketed label when the resolved name
  and the configured label differ, producing values like
  `desk-4101.corp.example.com [Reception PC]`. Both halves are split out and each is
  validated on its own; addresses, placeholders, and values containing spaces or brackets
  contribute nothing.
- **The v2 endpoints are POSTs that read.** Every `/lua/rest/v2/get/...` endpoint takes
  its parameters as a JSON request body despite being a read, which is why this
  integration posts. They are idempotent, so the shared HTTP helper's retry budget is
  kept.
- **An authentication failure is an HTML page with a 200 status.** ntopng's source carries
  the comment *"in case of invalid login, no error is returned but redirected to login"*
  on `active.lua` and `interfaces.lua` alike. The response is the login page, not a 401,
  and a run that trusted the status code would report a healthy empty network. The JSON
  helper surfaces it as a decode failure, and that specific case is named explicitly in
  the log rather than reported as a malformed response.
- **Token authentication works but is not in the specification.** ntopng's published REST
  v2 specification documents only HTTP Basic (`curl -u <user>:<password>`). The token form
  is real nonetheless: `HTTPserver.cpp` reads the `Authorization` header and accepts
  `auth_type == "Token" || auth_type == "Bearer"`, looking the value up against the API
  token store in Redis. This integration sends `Authorization: Token <token>` and falls
  back to Basic when only a username and password are configured. Because the token form
  is undocumented, an instance where it does not work should fall back to Basic rather
  than be treated as broken.
- **`rc` is checked, not just the HTTP status.** Every response is wrapped in
  `{"rc":0,"rc_str":"OK","rc_str_hr":"...","rsp":{...}}`, and `rc` carries a negative code
  from `rest_utils.consts.err` on failure: -1 NOT_FOUND, -2 INVALID_INTERFACE, -3
  NOT_GRANTED, -4 INVALID_HOST, -5 INVALID_ARGUMENTS, -6 INTERNAL_ERROR, -59
  MISSING_PARAMETERS. These are read from ntopng's source rather than from prose
  documentation, and are reported by name.
- **There is no usable total, so paging stops on a short page.** `active.lua` builds its
  response as `res = { perPage = perPage, currentPage = currentPage, totalRows = total,
  data = data, ... }` — but `total` is never assigned anywhere in that script. In Lua an
  unassigned global is `nil`, and a `nil` value is simply absent from the encoded JSON, so
  `totalRows` does not appear in the response at all. Paging therefore advances on
  `currentPage` and stops on the first page shorter than `perPage`, with **Maximum hosts
  per interface** as a backstop against a very busy sensor.
- **The `all` parameter is deliberately not used.** Passing `all` to `active.lua` sets
  `perPage = -1` and returns every host in a single response. That is precisely the
  unbounded response this integration exists to avoid; paging keeps memory bounded to one
  page.
- **Operating system is an nDPI enumeration.** `os` is an integer from nDPI's `ndpi_os`
  type — 0 unknown, 1 Windows, 2 macOS, 3 iOS/iPadOS, 4 Android, 5 Linux, 6 FreeBSD —
  inferred from TCP and TLS fingerprints. It is a fingerprint guess, not an interrogated
  answer, and is imported as `os` with the raw integer kept as `ntopng_os_id`.
- **Device type comes from the MAC table.** ntopng's `DeviceType` enumeration (0 unknown,
  1 printer, 2 video, 3 workstation, 4 laptop, 5 tablet, 6 phone, 7 tv, 8 networking, 9
  wifi, 10 nas, 11 multimedia, 12 iot) lives on the layer 2 device record, not on the
  host record, which is why the two tables are joined. `macs_list.lua` resolves the
  integer to a label server-side, so the label is used as-is.
- **The MAC table's `manufacturer` may carry a model.** `macs_list.lua` appends a detected
  model in brackets — `Dell Inc. [ OptiPlex 7090 ]` — when it has one. The composed string
  is imported verbatim rather than being split, because the separator is not escaped and
  a manufacturer name containing a bracket would be mangled by a parser.
- **Data is volatile, and that changes what a run means.** A host ages out of the active
  table after an idle period, so two runs an hour apart legitimately see different
  populations. This is not a source to reconcile presence against — an asset missing from
  today's run has gone quiet, not away.
- **`get/mac/active.lua` does not exist.** Earlier planning notes referenced it; the
  layer 2 device table is served by `get/mac/macs_list.lua`, which paginates with `start`
  and `length` rather than `currentPage` and `perPage`, and returns its totals as
  `recordsTotal` and `recordsFiltered` merged into the top level of the envelope
  alongside `rc`.
- **Timestamps are clamped.** `first_seen` becomes `firstSeenTS` and `last_seen` becomes
  `lastSeenTS`, both clamped to the current time first, because runZero rejects an asset
  whose first- or last-seen time is in the future and drops the **entire record** rather
  than the field.
- **No vulnerabilities.** ntopng raises alerts, not findings against a CVE, and its
  blacklist flags are threat-intelligence matches on an address rather than a
  vulnerability of the host. The blacklist flag is imported as the `ntopng-blacklisted`
  tag and `ntopng_is_blacklisted`, and no `Vulnerability` records are synthesized.
- This integration was validated against local fixtures built from ntopng's own endpoint
  implementations — `scripts/lua/rest/v2/get/host/active.lua`,
  `scripts/lua/rest/v2/get/mac/macs_list.lua`,
  `scripts/lua/rest/v2/get/ntopng/interfaces.lua`, and `scripts/lua/modules/rest_utils.lua`
  — read from the source tree, because ntop.org's rendered API documentation was
  unreachable while this was written. It has **not** been run against a live ntopng
  sensor.

## Future

- **Per-host detail from `get/host/data.lua`.** The list endpoint is a summary; the
  per-host endpoint returns far more, including DHCP fingerprints, TLS and HTTP client
  fingerprints (JA3/JA4), the host's observed services breakdown, and its DNS query
  behaviour. That is a rich device-classification signal and complements runZero's own
  fingerprinting from a completely different vantage point. It costs one request per
  host, so it needs the capped opt-in enrichment pattern this repository already uses
  elsewhere.
- **Feeding fingerprints into runZero's classification.** ntopng's nDPI OS guess and its
  device-type inference are imported today as attributes. The higher-value form is
  corroborating evidence for runZero's own fingerprint engine, particularly for devices
  that never answer an active probe — which is exactly the population passive monitoring
  is best at and active scanning is worst at.
- **ARP and layer 2 topology.** The MAC table already counts ARP requests and replies per
  device, and ntopng tracks which MACs were seen on which interface. That is the raw
  material for a segment map: which devices share a broadcast domain, and which addresses
  a given MAC has held over time.
- **SNMP device inventory.** ntopng's SNMP module polls switches and routers it is
  configured for, exposing interfaces, port status, and — in the versions that support it
  — the MAC-to-port forwarding table. That last one is a genuinely distinct data class
  that this repository does not reach anywhere else: it says which physical switch port a
  device is plugged into. The endpoints live under `/lua/rest/v2/get/snmp/`, and some are
  Enterprise-only, which is what keeps this out of scope here.
- **Alerts as context, not as vulnerabilities.** ntopng's alert endpoints report scans,
  suspicious flows, and blacklist hits. These are not vulnerabilities and should not be
  imported as such, but "this host was seen port-scanning the network" is a fact worth
  attaching to an asset.
- **Host pools as site or ownership mapping.** ntopng's host pools group addresses into
  named sets that operators maintain for policy purposes. The pool name is imported as an
  attribute today; mapping pools onto runZero sites or ownership tags would let a
  multi-segment sensor drive site assignment automatically.

## API documentation

- REST API v2 specification: https://www.ntop.org/guides/ntopng/api/rest/api_v2.html
- REST API v2 examples: https://www.ntop.org/guides/ntopng/api/rest/examples_v2.html
- Python API guide: https://www.ntop.org/guides/ntopng/api/python/index.html
- Source of every field, code, and behaviour described above:
  - active host list, its parameters and its record fields, and the unassigned
    `totalRows`:
    https://github.com/ntop/ntopng/blob/dev/scripts/lua/rest/v2/get/host/active.lua
  - layer 2 device list, its `start`/`length` paging and its record fields:
    https://github.com/ntop/ntopng/blob/dev/scripts/lua/rest/v2/get/mac/macs_list.lua
  - interface enumeration:
    https://github.com/ntop/ntopng/blob/dev/scripts/lua/rest/v2/get/ntopng/interfaces.lua
  - the response envelope and the full `rc` code table:
    https://github.com/ntop/ntopng/blob/dev/scripts/lua/modules/rest_utils.lua
  - the `DeviceType` enumeration:
    https://github.com/ntop/ntopng/blob/dev/include/ntop_typedefs.h
  - the device type id-to-label table:
    https://github.com/ntop/ntopng/blob/dev/scripts/lua/modules/discover_utils.lua
  - the `Authorization: Token` / `Bearer` handling that the specification omits:
    https://github.com/ntop/ntopng/blob/dev/src/HTTPserver.cpp
  - the specification's own authentication and request-format section:
    https://github.com/ntop/ntopng/blob/dev/doc/src/api/rest/api_v2.rst
- The `ndpi_os` operating system enumeration:
  https://github.com/ntop/nDPI/blob/dev/src/include/ndpi_typedefs.h

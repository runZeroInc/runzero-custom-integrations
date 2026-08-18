# Custom Integration: Pi-hole

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Pi-hole web interface over HTTP or HTTPS.

## Pi-hole requirements

- **Pi-hole v6 or later.** The REST API described here is served by `pihole-FTL` itself
  and was introduced in v6; v5 and earlier exposed a PHP page (`admin/api.php`) with an
  entirely different shape and no network device endpoint.
- A web interface password, or — strongly preferred — an **application password**.
- Enough free API sessions. Pi-hole caps concurrent sessions, and each one lasts 30
  minutes unless it is deleted.

## Steps

### Pi-hole configuration

1. Confirm the API is reachable and note which scheme and port answer. Every Pi-hole
   self-hosts its own interactive API documentation:

   ```
   http://pi.hole/api/docs
   ```

   The default listeners are HTTP on 80 and HTTPS on 443, with a self-signed certificate
   on the HTTPS one.

2. Create an **application password** rather than handing over the web password. In the
   admin interface go to **Settings → Web interface / API**, switch to Expert mode, and
   use **Configure app password**. Pi-hole shows the generated password once. An
   application password can be revoked on its own without changing the password an
   administrator uses to log in.

3. Confirm the credential and the endpoint from the Explorer host. The login returns a
   session id which every other call carries:

   ```bash
   SID=$(curl -sk -X POST 'https://pi.hole/api/auth' \
          -H 'Content-Type: application/json' \
          -d '{"password":"<app password>"}' | jq -r .session.sid)

   curl -sk -H "X-FTL-SID: $SID" \
     'https://pi.hole/api/network/devices?max_devices=10000&max_addresses=32' | jq .

   curl -sk -X DELETE -H "X-FTL-SID: $SID" 'https://pi.hole/api/auth'
   ```

   Deleting the session at the end matters — see the session note below.

4. If the API answers `{"error":{"key":"api_seats_exceeded", ...}}`, raise
   `webserver.api.max_sessions` in **Settings → All settings**, or wait for the stale
   sessions to expire.

5. Note the certificate situation. Pi-hole's HTTPS listener uses a self-signed
   certificate by default, so either supply it as the **CA certificate** in the runZero
   credential or use the HTTP listener on a trusted network segment. Turning validation
   off is a last resort.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Pi-hole").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Pi-hole URL** (`url`): base URL of the web interface, for example `https://pi.hole`. The `/api` path is appended automatically.
   - **Password or application password** (`password`): the application password created above, or the web password.
   - **Maximum devices** (`max_devices`): optional; value sent as `max_devices` (default: 10000).
   - **Maximum addresses per device** (`max_addresses`): optional; value sent as `max_addresses` (default: 32).
   - **Join DHCP leases** (`include_leases`): optional; fold active DHCP lease detail onto matching devices (default: true).
   - **Import devices with no MAC** (`include_ip_only_devices`): optional; import the rows Pi-hole records for clients it never saw at layer 2 (default: false).
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
runzero script --filename pihole/pihole.star \
  --kwargs url=https://pi.hole \
  --kwargs password='<app password>' \
  --kwargs max_devices=10000 \
  --kwargs include_leases=true \
  --kwargs tls_ca_cert=/etc/pihole/tls.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./pihole-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a directory
from a previous run. Add `--verbose` for the request-by-request log. Omit `--output` to
see only the log lines. Each command-line run consumes and then releases one API
session, so avoid running several at once against the same Pi-hole.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename pihole/pihole.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Pi-hole accepts the password or that any device is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat pihole/pihole.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://pi.hole,password=<app password>' \
  --output ./pihole-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with the addresses, MACs, and hostnames Pi-hole has observed.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:pihole`.

## Asset identity

- Target entity: a row in Pi-hole's **network table** — a device `pihole-FTL` has seen on
  the local network, identified by its hardware address and carrying every IP address and
  hostname it has held.
- Source ID field: the network table's `id`, a SQLite `INTEGER PRIMARY KEY` in
  `pihole-FTL.db`. The `hwaddr` is deliberately **not** used as the id.
- Documentation evidence: the FTL OpenAPI specification for `GET /api/network/devices`
  documents `id` as "Device network table ID" and it is the key `DELETE /api/network/devices/{id}`
  routes on, so it is the API's own handle for the row.
- Uniqueness scope: one Pi-hole server, and more precisely one `pihole-FTL.db` file. The
  Pi-hole's hostname is part of the runZero id, so two Pi-holes imported into one account
  cannot collide — which matters because a redundant pair of Pi-holes on the same network
  sees an overlapping set of devices and assigns each of them unrelated ids.
- Cardinality: one row per hardware address, holding many addresses. A dual-stack device
  with a v4 lease, a stable v6 address, and SLAAC privacy addresses is **one** row, and
  becomes one asset carrying all of them. Devices Pi-hole never saw at layer 2 get one
  row per address instead.
- Stability: survives an address change, a rename, a lease renewal, and a Pi-hole
  restart. The row is keyed internally on the MAC, so a device that changes address keeps
  its row and its id.
- Reuse behavior: **yes, and this is decisive.** The id is a SQLite rowid assigned in
  first-seen order. Deleting `pihole-FTL.db` is a routine Pi-hole troubleshooting step
  and reinstalling is common on the hardware Pi-hole typically runs on; either one
  restarts the sequence at 1 and reassigns the numbers in a different order, so the
  device that was id 5 becomes id 2 and every previously imported id now names a
  different device. FTL also ages the table out on its own: `database.network.expire`
  ("How long should IP addresses be kept in the network_addresses table [days]?", default
  inherited from `database.maxDBdays`) removes rows that have not been seen recently,
  which frees ids for reuse without any operator action at all.
- Presence: always present on the list response. A row that arrives without one is
  skipped with a log line carrying the hardware address only.
- Final runZero ID: `pihole:<pihole-host>:<network-table-id>`, for example
  `pihole:pi.hole:12`.
- Missing-ID behavior: skip and log. No identity is synthesized and `new_uuid()` is never
  used.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`.** The id is deterministic within one
  database, but it is not durably one-per-device across the database rebuilds this
  product invites, and a foreign-id match cannot be vetoed once it lands — a recycled id
  would silently merge two unrelated devices. Correlation therefore falls back to the
  MAC, the addresses, and the hostnames, all of which Pi-hole reports directly and none
  of which depend on the rowid. The id is still emitted so an asset can be traced back to
  the row it came from.
- Verdict: **derived / non-authoritative.** Pi-hole is a DNS server that happens to keep
  an ARP and neighbour table, not a device inventory. Treat this as an enrichment source
  that layers MAC-to-address bindings, vendor names, DHCP leases, and query activity onto
  assets runZero already knows about — while still being genuinely capable of surfacing a
  device nothing else has seen, because a device that resolves a name has announced
  itself on the segment.

### Notes

- **What is imported.** One asset per row of `GET /api/network/devices`, carrying the
  hardware address, every address and hostname on the row, the MAC vendor, the interface
  the Pi-hole saw it on, the query count, and the first-seen and last-query times. With
  **Join DHCP leases** enabled, `GET /api/dhcp/leases` contributes the DHCP client name,
  the lease expiry, and the DHCP client id.
- **`max_devices` is the single most important parameter.** The endpoint's own
  description states that "this number of shown devices is limited to 10" by default. A
  run that omitted it would import four devices from a forty-device home network and
  report success. It is always sent, and when the response comes back exactly at the
  limit the run says so, because that is indistinguishable from truncation.
- **`hwaddr` is not always a MAC.** When FTL has never observed a client at layer 2 — a
  client behind a router, or an upstream resolver — it stores a synthetic hardware
  address instead. The FTL source is explicit: *"Create mock hardware address in the
  style of `ip-<IP address>`, like `ip-127.0.0.1`"* (`src/database/network-table.c`).
  Those values are rejected outright rather than being handed to the MAC parser, and the
  rows are skipped unless **Import devices with no MAC** is enabled, because a row with
  an address and nothing else is a weaker observation than the rest of the table. When
  they are imported they are tagged `no-layer2-identity` and carry
  `pihole_has_layer2_identity=false`.
- **The names in the table are not all names.** `ips[].name` is whatever reverse DNS or
  the DHCP client last supplied, so it includes bare IP addresses, dnsmasq placeholders,
  `ip6-localhost`, and `pi.hole` — the Pi-hole's own alias for itself, which resolves on
  every Pi-hole network and says nothing about the client. All of those are filtered, as
  are values made only of digits and dots.
- **Link-local and loopback are filtered here, not by the platform.** runZero drops
  loopback, multicast, and unspecified addresses itself but deliberately keeps
  link-local, and a Pi-hole network table is full of `fe80::` SLAAC addresses. Left in,
  two devices that both failed DHCP would correlate to each other.
- **A device with nothing to correlate on is skipped.** The row for the Pi-hole's own
  loopback interface has only `127.0.0.1` and the name `localhost`; after filtering there
  is no MAC, no routable address, and no usable hostname left, so it is dropped with a log
  line rather than imported as an asset that can never merge.
- **Sessions are opened and always closed.** `POST /api/auth` exchanges the password for a
  session id which travels in the `X-FTL-SID` header — not the `sid` query parameter,
  which the API also accepts but which would put the credential in every proxy access
  log. `DELETE /api/auth` runs at the end of every run, including a run that imported
  nothing. This is not tidiness: Pi-hole caps concurrent sessions at a small number and
  each one survives 30 minutes, so a task that logs in without logging out will
  eventually exhaust the seats and lock the administrator out of the web interface. The
  API reports that as HTTP 429 with `{"error":{"key":"api_seats_exceeded","hint":"increase
  webserver.api.max_sessions"}}`, and the run names both the cause and the setting.
- **A Pi-hole with no password is handled.** Such an instance answers the login with
  `{"session":{"valid":true,"sid":null,"message":"no auth for local user"}}` and then
  expects no session header at all. The run recognises the null session id rather than
  treating it as a failure, and skips the logout.
- **DHCP leases join, they do not create.** A lease is matched to a device first by MAC
  and then by address, and contributes the client hostname and lease detail. Leases that
  match no device do **not** become assets of their own: the only identity such a row has
  is its MAC, and a MAC must not be used as a foreign id — `normalize_mac` clears the
  locally administered bit, so two randomized client MACs can normalize to the same
  value. Leases are only present when the Pi-hole is itself the network's DHCP server;
  when it is not, the endpoint returns an empty list and nothing is lost. Lease rows
  carrying the all-zero hardware address are ignored.
- **`GET /api/clients` is deliberately not used.** Despite the name it returns Pi-hole's
  *configured* client entries — the per-client group and filtering assignments managed in
  the admin interface — not the clients Pi-hole has observed. Its schema is a `client`
  string plus `comment` and `groups`, which is configuration, not inventory. The
  observed-client data lives in the network table this integration reads.
- **No services and no vulnerabilities.** Pi-hole knows which names a client resolved. It
  does not know what any client is listening on, and a DNS query is evidence of an
  outbound client, never of an open port. Nothing is synthesized for either, so these
  assets carry no `Service` or `Vulnerability` records.
- **Timestamps are clamped.** `firstSeen` becomes `firstSeenTS` and `lastQuery` becomes
  `lastSeenTS`, taking the most recent `ips[].lastSeen` when it is newer. Both are
  clamped to the current time first, because runZero rejects an asset whose first- or
  last-seen time is in the future and drops the **entire record** rather than the field —
  and Pi-hole runs overwhelmingly on hardware with no real-time clock, where a boot
  before NTP converges leaves exactly that kind of skew. The raw epochs are kept as
  `pihole_first_seen_epoch` and `pihole_last_query_epoch`.
- **Neither endpoint paginates.** `GET /api/network/devices` bounds its response with
  `max_devices` and `max_addresses` rather than paging, and `GET /api/dhcp/leases` takes
  no parameters at all. Both are bounded by the size of one broadcast domain, which is
  why the plain JSON helper is used rather than a streaming parser.
- **Rate limiting.** FTL rate-limits *login attempts* specifically, answering 429 with
  `{"error":{"key":"rate_limiting"}}`. The shared HTTP helper retries transient failures
  with exponential backoff and honours `Retry-After`.
- This integration was validated against local fixtures built directly from the OpenAPI
  specification `pihole-FTL` publishes and serves at `/api/docs`, using that
  specification's own field examples. It has **not** been run against a live Pi-hole v6
  server.

## Future

- **Query-log-derived context.** `GET /api/queries` returns individual DNS queries with
  the client, the queried name, the upstream, and the block decision. Two things there
  are genuinely useful for asset intelligence and neither is available anywhere else:
  the *names a device resolves* are a strong device-type signal (a device that resolves
  `*.icloud.com` on boot is an Apple device; one that resolves an NTP pool and a vendor
  telemetry endpoint often names its own manufacturer), and a device that suddenly
  resolves a domain nothing else on the network resolves is worth surfacing. The obstacle
  is volume — a busy Pi-hole logs millions of queries a day — so this needs aggregation
  server-side, or a bounded sample per client.
- **`GET /api/clients/_suggestions`.** Returns the same device population pre-joined into
  `hwaddr`, `macVendor`, `lastQuery`, and comma-separated `addresses` and `names`, which
  is a cheaper single call than the network table when only the summary is wanted. It is
  intended to populate a UI dropdown, so its stability as an integration surface is
  unclear.
- **Pi-hole as a DHCP server of record.** When Pi-hole runs the network's DHCP, its
  static-lease configuration (`GET /api/config/dhcp`) is an authoritative statement of
  which MAC should hold which address and what it should be called. Comparing that to
  what runZero observes would surface both stale reservations and devices using an
  address nobody reserved.
- **Group and blocking policy as asset context.** The client entries under
  `GET /api/clients`, dismissed above as configuration rather than inventory, become
  interesting *as an attribute of an asset runZero already has*: which filtering group a
  device is in is a statement about how the organization classifies it — guest, IoT,
  kids' devices, unrestricted.
- **Multi-Pi-hole reconciliation.** A redundant pair of Pi-holes sees overlapping but not
  identical device populations, and a device present on one and absent from the other is
  frequently a segment or routing problem rather than a device problem. Two tasks import
  cleanly today because the ids are namespaced per server and matching falls back to MAC
  and address, but nothing yet reports on the difference between them.
- **Outbound is not worth building.** The API can add clients, groups, and blocklists,
  but none of those describes an asset, and writing DNS blocking policy from an inventory
  tool is not a defensible pairing.

## API documentation

- Pi-hole API overview and self-hosted interactive documentation:
  https://docs.pi-hole.net/api/ — every instance also serves its exact specification at
  `http://pi.hole/api/docs`
- Rendered FTL API reference: https://ftl.pi-hole.net/master/docs/
- OpenAPI source for the endpoints used here (`network.yaml` for
  `GET /api/network/devices` and its `max_devices` / `max_addresses` parameters,
  `auth.yaml` for the session flow and the `api_seats_exceeded` error, `dhcp.yaml` for
  the lease schema, `clients.yaml` for the configured-client schema, `main.yaml` for the
  `X-FTL-SID` security scheme):
  https://github.com/pi-hole/FTL/tree/master/src/api/docs/content/specs
- The `ip-<address>` synthetic hardware address, in FTL's network table implementation:
  https://github.com/pi-hole/FTL/blob/master/src/database/network-table.c
- Sample client: https://github.com/sbarbett/pihole6api

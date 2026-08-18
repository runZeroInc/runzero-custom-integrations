# Custom Integration: AdGuard Home

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the AdGuard Home web interface over HTTP or HTTPS.

## AdGuard Home requirements

- AdGuard Home 0.107 or later. The `/control/` HTTP API and its OpenAPI description have been stable across the 0.107 series and the 0.108 betas.
- **Not 0.107.65.** That release increments the failed-login counter on *every* Basic-auth request rather than only on failure, so a polling client trips the `auth_attempts: 5` limit and is blocked for `block_auth_min: 15` minutes. It was fixed in 0.107.66. Any other 0.107.x is fine.
- A web interface user name and password. AdGuard Home protects `/control/` with HTTP Basic authentication, and any account that can open the dashboard can read these endpoints; there is no separate API token and no read-only role.
- The DHCP server enabled, if you want MAC addresses for clients. `GET /control/dhcp/status` is the only endpoint that returns a client MAC. Without it this integration imports query sources by IP alone.

## Steps

### AdGuard Home configuration

1. Note the URL you use to reach the dashboard, including the port. AdGuard Home listens on port 3000 during setup and on the port you chose in the wizard afterwards (commonly 80 or 443).
2. Create or choose an account for runZero. AdGuard Home has a single class of web user, so use a dedicated account rather than sharing the administrator's:
   - In the dashboard, open **Settings → General settings**, or edit `AdGuardHome.yaml` directly and add an entry under `users:` with a bcrypt password hash.
   - Restart AdGuard Home after editing the YAML file.
3. Confirm the credential works from the Explorer host:

   ```bash
   curl -s -u 'runzero:<password>' 'http://adguard.example.com:3000/control/status'
   curl -s -u 'runzero:<password>' 'http://adguard.example.com:3000/control/dhcp/status'
   curl -s -u 'runzero:<password>' 'http://adguard.example.com:3000/control/dhcp/interfaces'
   curl -s -u 'runzero:<password>' 'http://adguard.example.com:3000/control/clients'
   ```

   A wrong user name or password produces a bare **401 with an empty body** — AdGuard Home's API middleware writes the status and nothing else, and never sends a `WWW-Authenticate` challenge, so `curl` prints no error text at all. (The `/control/login` form endpoint answers 403 instead; do not use the 403 to tell the two apart.) A 501 from `/control/dhcp/status` means DHCP is unsupported on that platform; the integration treats that as a normal outcome and continues.
4. If AdGuard Home is behind a reverse proxy terminating TLS with a private or self-signed certificate, either supply the CA under the TLS options or, as a last resort, enable **Disable TLS validation**.

### Trying it from the command line

The runZero CLI runs the script directly, which is the fastest way to check a credential and see what the integration would import:

```bash
runzero script --filename adguard-home/adguard-home.star \
  --kwargs url=http://adguard.example.com:3000 \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs collect_dhcp=true \
  --kwargs collect_clients=true \
  --kwargs max_clients=500 \
  -o /tmp/adguard-out
```

`-o` writes the serialized assets to a directory so you can inspect exactly what would be imported; add `--overwrite` to reuse it. To check the CONFIG block and the HTTP/TLS wiring without touching a real instance, run:

```bash
runzero script --filename adguard-home/adguard-home.star --validate
```

Two things to know about `--kwargs`. It is repeated once per parameter, and a value containing both a comma and an `=` is split by the flag parser and silently turns into an extra parameter the script never declared — no parameter here needs one, but quote passwords and avoid that shape.

The same script runs as a task through the `scan` command, which is what the Explorer does on a schedule:

```bash
runzero scan --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-source "$(cat adguard-home/adguard-home.star)" \
  --custom-integration-script-kwargs 'url=http://adguard.example.com:3000,username=runzero' \
  --api-key <runzero-api-key>
```

In normal operation you do not assemble this by hand: create the integration and credential in the console as below, and the Explorer builds the equivalent task itself.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "AdGuard Home").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **AdGuard Home URL** (`url`): base URL of the web interface, e.g. `http://adguard.example.com:3000`. The `/control/` path is appended automatically.
   - **Username** (`username`): AdGuard Home web interface user.
   - **Password** (`password`): password for that user.
   - **Collect DHCP leases** (`collect_dhcp`): optional; read `/control/dhcp/status` for dynamic and static leases (default: enabled).
   - **Collect observed DNS clients** (`collect_clients`): optional; read `/control/clients` for runtime clients and the persistent client list (default: enabled).
   - **Import persistent clients with no observation** (`include_persistent_only`): optional; also import configured client entries whose address AdGuard Home has never seen (default: disabled).
   - **Maximum clients** (`max_clients`): optional; cap on client assets imported per run, 0 for no cap (default: 20000).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with DHCP and DNS-client data pulled from AdGuard Home.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:adguard-home`.

## Asset identity

- Target entity: a host on a segment AdGuard Home serves — seen either as a DHCP lease it issued, or as the source address of a DNS query it answered. It is not a device record; AdGuard Home keeps no device inventory.
- Source ID field: the lease's `mac` when a DHCP lease covers the host, otherwise the observed address (`auto_clients[].ip`, or a lease `ip` whose `mac` was unusable). AdGuard Home publishes no identifier of its own for a client, and no identifier at all for itself.
- Documentation evidence: the project's `openapi/openapi.yaml` defines `DhcpLease` with `mac`, `ip`, `hostname`, and `expires`, and `Clients` as `{clients, auto_clients, supported_tags}` where an auto-client is `{ip, name, source, whois_info}`. There is no id field on either object. The persistent `Client` object is keyed by `name` and carries an `ids` array documented as accepting an IP, a CIDR, a MAC, or a ClientID — an addressing rule, not an identity.
- Uniqueness scope: one AdGuard Home instance. The hostname from the configured URL is part of every id so two instances polled into one runZero organization cannot collide. Overlapping RFC 1918 space across two instances is otherwise indistinguishable.
- Cardinality: one asset per MAC, and one per observed address that no lease claims. A host that holds a lease and also queries from that address produces one asset, because the lease's address is indexed to the MAC-keyed record before the client list is read. A host that queries from two addresses with no lease produces two assets.
- Stability: a MAC-keyed id survives a lease renewal, an address change, a hostname change, and a rename of the persistent client entry. An address-keyed id survives only as long as the host keeps that address.
- Reuse behavior: yes, in both forms. A DHCP address released and re-leased to a different device reuses the address-keyed id, and a randomized MAC is re-drawn by the client itself on every network join.
- Presence: `mac` and `ip` are required fields on a lease and `ip` is required on an auto-client, but the API is served by a Go program that will emit an empty string rather than omit a key, so both are re-validated. Records with neither a usable MAC nor a usable routable address are skipped and counted; the log names the count, never the record.
- Final runZero ID: `adguard-home:<adguard-host>:client:<mac>` or `adguard-home:<adguard-host>:client-ip:<ip>`, plus `adguard-home:<adguard-host>:appliance` for the AdGuard Home host itself — for example `adguard-home:adguard.example.com:client:aa:bb:cc:00:11:01`.
- Missing-ID behavior: skip. No id is invented and `new_uuid()` is not used anywhere in the script.
- Asset types: two, declared in `CONFIG["assetTypeBehavior"]` and selected per record with `ImportAsset(assetType=...)`, because the two kinds need opposite reconciliation.
  - `appliance` — the AdGuard Home host itself. `no-mac-break no-ip-break no-name-break`: its id is derived from the configured URL rather than from a vendor identifier, and its bound addresses and hostname are exactly what should let it merge with an asset runZero scanned directly.
  - `client` — every DHCP lease and observed DNS client. `no-id-match no-id-break`: both id forms are address-derived, a DHCP address is reassigned and every current phone and laptop randomizes its MAC per network, so the id must neither drive nor block a merge. Correlation falls back to the MAC, IP, and hostname carried on the record, and a record carrying none of those is not emitted.
- Cross-type merging: `type-break` is left ON (the default), so an `appliance` and a `client` never merge into one asset. The appliance is the DNS server and a client is one of the devices whose queries it answers; neither becomes the other. Because a client is keyed on an address, this is also what stops the appliance's own loopback or LAN address appearing in the client list from pulling the server's asset into a query-source record.
- Verdict: **derived / non-authoritative.** AdGuard Home is a DNS filter with an optional DHCP server, not an inventory. Its DHCP half is genuinely authoritative for MAC↔IP↔hostname on the segments it serves; its DNS half only proves that something at an address asked a question. Treat this as an enrichment source that names and locates hosts runZero finds by other means, and as a discovery source of last resort on segments no Explorer can scan.

### Notes

- What is imported:
  - One asset for the AdGuard Home host, from `GET /control/status` and `GET /control/dhcp/interfaces`. `status` supplies the product version, the addresses the DNS server is bound to, the listening ports, and the protection and DHCP flags; `dhcp/interfaces` is the only endpoint that reports the host's own NICs, as a map of interface name to `{name, hardware_address, flags, gateway_ip, ipv4_addresses, ipv6_addresses}`, and is what gives the appliance a MAC. Container plumbing (`docker0`, `veth*`, `br-*`, `lo`) is filtered by name, because AdGuard Home is very often itself a container beside others. When that endpoint is unavailable the interface falls back to the bound `dns_addresses`, and then to the address in the configured URL. AdGuard Home reports no serial and no hostname of its own, so the hostname comes from the configured URL.
  - One asset per DHCP lease, from `GET /control/dhcp/status`. Both `leases` and `static_leases` are read; `adguard_dhcp_static` records which array a host came from and `adguard_dhcp_expires` keeps the lease expiry verbatim.
  - One asset per observed DNS client, from `auto_clients[]` in `GET /control/clients`. `source` — AdGuard Home's own word for how it learned the address, one of rDNS, ARP, WHOIS, DHCP, or the hosts file — is kept as `adguard_client_source`, and any WHOIS organisation, country, and city are kept alongside it.
  - Persistent client entries from `clients[]` contribute their name, tags, and per-client filtering flags to whichever observed record their `ids` match. They do not create assets unless **Import persistent clients with no observation** is enabled, because a persistent client is a policy rule that may be written before the device ever appears.
- Two deliberate omissions in the persistent-client merge. The entry's other `ids` are **not** copied onto the record: an operator may group several devices under one entry, and copying the whole array would give several assets the same set of addresses and let runZero merge them into one. The entry's `name` is **not** imported as a hostname: it is free text such as "Kids tablet", and a name shared by several devices is a correlation hazard. Both are kept as `adguard_persistent_client` and `adguard_persistent_client_ids`.
- A persistent client whose only identifier is a CIDR or a ClientID names a range or a DNS-over-TLS session rather than a host. Those values are preserved in `adguard_persistent_client_other_ids` and never key an asset.
- Address filtering: loopback, unspecified, broadcast, and link-local (`127.0.0.0/8`, `169.254.0.0/16`, `fe80::/10`, `::1`) are dropped before an interface is built. The platform already discards loopback and multicast, but it deliberately keeps link-local, and an AdGuard Home client list on a v6-enabled segment is full of `fe80::` query sources — an address every host invents for itself, which correlates nothing.
- The MAC is handled two ways on purpose. The foreign id uses a lossless canonicalisation (separators stripped, lower-cased) so that a randomized client MAC, which always sets the locally administered bit, stays distinct. The emitted `NetworkInterface` goes through `network_interface`, which clears that bit so the address matches the same host seen by another source. `aa:bb:cc:00:11:09` is therefore the id and `a8:bb:cc:00:11:09` is the interface address, and that is correct in both places.
- Pagination: none. All three endpoints return a single JSON document with no cursor, page, or limit parameter. Memory is bounded instead at the asset boundary — records are merged into one index and streamed to runZero through `report_asset` one record at a time — and by **Maximum clients**, which caps the run.
- Rate limiting: AdGuard Home publishes no rate limit and applies none. `get_json` still retries `408, 425, 429, 500, 502, 503, 504` and transport errors three times with exponential backoff and honors `Retry-After`, which covers a reverse proxy in front of it; the script passes no `retries` argument and hand-rolls no retry loop.
- No timestamp from AdGuard Home is parsed. A lease's `expires` is a time in the **future**, and the platform rejects the entire asset record if a future timestamp reaches `firstSeenTS` or `lastSeenTS`, so it is kept verbatim as a string attribute and never converted.
- A failing endpoint does not end the run: `/control/dhcp/status` returns 501 where DHCP is unsupported and can 403 for a user without access, and either is logged and skipped. The run stops only when all three endpoints fail, which is the signal that the URL or the credential is wrong.
- Empty collections come back as JSON `null`, not `[]`. `handleGetClients` builds its response by appending to nil slices, so a fresh instance answers `{"clients": null, "auto_clients": null, "supported_tags": null}`. Every array read here is type-checked before it is walked, which is also what keeps a scalar in an array's place from ending the run.
- Authentication is preemptive HTTP Basic on every request, and no cookie is ever sent. That ordering matters: AdGuard Home's `userFromRequest` checks the `agh_session` cookie **first** and only falls back to Basic, so a stale session cookie would produce a 401 even with a correct user name and password.
- Unverified assumptions: instances fronted by a reverse proxy that strips or rewrites `Authorization` will need that proxy configured to pass it through. The `whois_info` sub-fields read here (`orgname`, `country`, `city`) are the only three AdGuard Home populates, and an instance with WHOIS disabled returns an empty object. This integration was validated against local fixtures, not a live AdGuard Home instance.

## Future

- **Query log as a discovery and behaviour source.** `GET /control/querylog` returns per-query records with the client address, the question, the upstream, and the answer. Two things fall out of it that this integration does not attempt: hosts that queried once and never appeared in a lease or the client cache, and a per-asset view of which domains a device talks to — which is close to a passive service inventory for IoT devices that never answer a scan. It is a paging endpoint with `older_than` cursors and can be very large, so it needs its own integration with its own cap rather than being folded in here.
- **Per-client statistics as an activity signal.** `GET /control/stats` returns `top_clients` as a list of address-to-count pairs. Joined onto the assets this integration already emits, that is a cheap "last active / how active" attribute, and a client with zero queries over a long window is a decommissioned device the DHCP table has not forgotten.
- **Outbound: write persistent clients back.** `POST /control/clients/add` and `POST /control/clients/update` take the same `Client` object this integration reads. runZero knows what a device is; AdGuard Home only knows an address. An outbound integration could name and tag AdGuard clients from runZero's classification, which would make the filtering rules readable and would flow back into the next inbound run. This should default to off — it writes to the filtering policy, and a wrong `ids` entry silently changes which rules apply to which device.
- **Blocked-service and filtering policy as asset context.** Per-client `blocked_services`, `filtering_enabled`, and `parental_enabled` are already imported as attributes. The Future item is the inverse view: a runZero query for assets whose AdGuard policy differs from the site default is a policy-drift report that no other source in the estate can produce.
- **Alerts and events are not available.** AdGuard Home has no webhook, no event stream, and no subscription endpoint. Change detection would have to be built from polling, and the only endpoint with a time dimension is the query log.

## API documentation

- OpenAPI description (`openapi/openapi.yaml`) — the authoritative definition of `/control/status`, `/control/clients`, `/control/dhcp/status`, and the `Client`, `DhcpLease`, and `ServerStatus` schemas: https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
- OpenAPI directory and how to browse the description locally: https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi
- Project source, including the client-cache implementation behind `auto_clients` and its `source` values: https://github.com/AdguardTeam/AdGuardHome
- AdGuard Home DHCP server documentation, for the lease and static-lease model: https://github.com/AdguardTeam/AdGuardHome/wiki/DHCP
- Configuration file reference, for the `users:` block that defines web interface accounts: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration

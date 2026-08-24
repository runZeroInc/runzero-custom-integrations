# Custom Integration: EfficientIP SOLIDserver

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with HTTPS reachability to the SOLIDserver appliance.

## EfficientIP SOLIDserver requirements

- SOLIDserver 7.x or later (the `/rest` interface used here is the same across
  7.x, 8.x, and 9.x).
- A SOLIDserver user with **read access to the IPAM module**, plus DHCP and
  DNS read access if those joins are enabled.
- SOLIDserver appliances ship with a self-signed certificate by default; set
  the `tls_` options on the runZero credential accordingly, or install a
  trusted certificate.

## Steps

### SOLIDserver configuration

1. Create (or reuse) a group with read-only rights on IPAM (and DHCP/DNS if
   those joins will be used), and a user for runZero in that group.
2. Confirm a real read works:

   ```bash
   curl -k \
     -H "X-IPM-Username: $(echo -n '<user>' | base64)" \
     -H "X-IPM-Password: $(echo -n '<pass>' | base64)" \
     'https://<solidserver>/rest/ip_site_list?limit=10'
   ```

   A `200` with a JSON array of spaces means the credentials and permissions
   are right. A `204` means the user can authenticate but sees no spaces —
   check group permissions.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "EfficientIP SOLIDserver").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **SOLIDserver URL** (`url`): base URL of the appliance, e.g. `https://solidserver.example.com`. The `/rest/` path is appended automatically.
   - **Username** (`username`) / **Password** (`password`): sent base64-encoded in the `X-IPM-Username` / `X-IPM-Password` headers on every request.
   - **Space name** (`space`): optional; import only this IPAM space. Deployments with overlapping address space should run one task per space.
   - **Import IPv6 addresses** (`include_ipv6`): default on.
   - **Join DHCP leases and reservations** (`include_dhcp`): default on.
   - **Join DNS records** (`include_dns`): join A/AAAA names onto addresses (default: off; large DNS estates make this a long walk).
   - **Page size** (`page_size`): rows per request (default 1000). SOLIDserver documents no server-side default, so an explicit limit is always sent.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with IPAM, DHCP, and DNS data pulled from SOLIDserver.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:efficientip-solidserver`.

## Running it from the command line

```bash
runzero script --filename efficientip-solidserver/efficientip-solidserver.star \
  --kwargs url=https://solidserver.example.com \
  --kwargs username=runzero-api \
  --kwargs password=not-a-real-password \
  --kwargs space=Local \
  --kwargs page_size=100 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/eip-run --overwrite
```

Set `space` on a first run — left blank the script enumerates every space and
walks all of them. `tls_disable_validation=true` reflects the self-signed
certificate most appliances actually present; drop it if yours is trusted.

To check only the CONFIG block and HTTP/TLS wiring without an appliance:

```bash
runzero script --filename efficientip-solidserver/efficientip-solidserver.star --validate
```

The recorded fixtures run without an appliance:

```bash
python3 tests/run.py efficientip-solidserver
```

## Asset identity

- Target entity: an assigned IPAM address, standing in for whatever device
  currently holds that address in a given space. It is not a device record.
- Source ID field: the composite of the space name and the printable address
  (`hostaddr`). The row id (`ip_id`/`ip6_id`) is deliberately **not** used: a
  delete-and-recreate of the same address mints a new row id, and the row id
  says nothing an operator can read.
- Uniqueness scope: one appliance, one space. Spaces are separate routing
  domains and routinely carry the same RFC 1918 ranges, so the space is a
  mandatory part of the key. The appliance host keeps two appliances polled
  into one runZero organization from colliding.
- Cardinality: one source row per address per space — not one per device. A
  device with several addresses produces several assets.
- Reuse behavior: yes. An address released and re-assigned to a different
  device reuses the same composite. This is the single strongest reason the
  verdict below is not "authoritative".
- Stability: survives renames, MAC changes, and lease renewals at the same
  address; does not survive the device moving to a different address or
  space. Renaming a **space** renames every id in it — schedule that with the
  same care as renaming a runZero site.
- Final runZero ID: `efficientip:<appliance-host>:<space>:<address>` — for
  example `efficientip:solidserver.example.com:Local:10.211.132.72`.
- Missing-ID behavior: rows with no usable address are skipped; no id is
  invented. IPv6 rows fall back to converting the bare 32-hex-digit `ip6_addr`
  column when `hostaddr` is absent, since installs differ in whether the
  printable form is exposed; the id uses the canonical colon form either way.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. The
  composite is deterministic but address-based, so it must not drive or block
  merging; correlation falls back to the MAC, IP, and hostnames on the record.
- Verdict: **derived / non-authoritative.** SOLIDserver is a DDI system, not a
  device inventory. Treat this integration as an enrichment source that layers
  IPAM ownership, DHCP evidence, and DNS naming onto assets runZero already
  knows about.

### Notes

- What is imported: assigned IPv4 addresses (`ip_address_list` rows with
  `type='ip'`; the interleaved `free` gap rows are filtered both server-side in
  the WHERE clause and client-side) and, when enabled, IPv6 addresses
  (`ip6_address6_list`). Each asset carries the address, MAC, IPAM name,
  space, subnet, and the raw class parameters string.
- MAC selection: the IPAM row's `mac_addr` first, then the DHCP reservation's
  `dhcphost_mac_addr`, then the lease's `dhcplease_mac_addr`. Values with the
  `EIP:` prefix are pseudo-MACs SOLIDserver mints for reservations without a
  real hardware address and are dropped, exactly as EfficientIP's own
  Terraform provider and Ansible collection do.
- DHCP joins (`include_dhcp`, on by default): leases
  (`dhcp_range_lease_list` / `dhcp6_lease6_list`) and reservations
  (`dhcp_static_list` / `dhcp6_static6_list`) are indexed by address and
  joined onto matching IPAM rows for client hostname, client identifier/DUID,
  MAC vendor, the Fingerbank OS fingerprint (`dhcplease_fingerbank_os`,
  recorded as an attribute, deliberately not promoted to the OS field), and
  lease timing. `dhcplease_first_time` becomes `firstSeenTS` and the last
  renewal (`dhcplease_time`) becomes `lastSeenTS`; the lease **end** time is a
  future expiry, not an observation, and is kept only as an attribute.
- **The DHCP join is appliance-global.** SOLIDserver's DHCP services are not
  space-scoped the way IPAM is, so in an estate with overlapping address
  space across spaces the joined DHCP details can belong to the twin address
  in another space. The IPAM row's own fields always win where both exist.
- DNS join (`include_dns`, off by default): A and AAAA records
  (`dns_rr_list`, `WHERE rr_type='A' OR rr_type='AAAA'`) contribute
  additional hostnames, keyed on the canonicalized address so the long-form
  IPv6 DNS emits still joins.
- Pagination: every list call sends explicit lowercase `limit`/`offset` (the
  uppercase `WHERE`/`ORDERBY` casing matters too) and an `ORDERBY` for stable
  offsets. A page shorter than the limit, or a **204 No Content** — which is
  how SOLIDserver answers a query with zero matches — ends each walk.
- Every JSON value SOLIDserver returns is a string, including counts and epoch
  timestamps; the script parses accordingly.
- Rate limiting: SOLIDserver 9 rate-limits the API and answers 429 with
  `Retry-After`, which the shared HTTP helper honors with backoff.
- Unverified assumptions: validated against recorded fixtures built from
  EfficientIP's official SDK and provider sources, not a live appliance. The
  `type='ip'` WHERE clause on the IPv6 list is not confirmed for older
  releases, so the client-side `free` filter is load-bearing there; and
  `ip_class_parameters` is imported raw (URL-encoded) rather than parsed.

## Future

- **Device Manager import.** `hostdev_list` / `hostiface_list` model actual
  devices with interfaces; on estates that use Device Manager those rows are
  device-shaped (one id per device) and deserve their own asset type with an
  id-driven merge policy.
- **Class parameters as attributes.** `ip_class_parameters` is a URL-encoded
  string of the extended attributes; parsing it into individual custom
  attributes (and the `TAGS` request parameter to select which) would surface
  owner/location metadata operators actually search on.
- **Subnets as context.** `ip_block_subnet_list` carries names, VLSM
  hierarchy, and utilization that map onto runZero subnet metadata.
- **Token authentication.** SOLIDserver 8.4+ supports API keys with SHA3-256
  request signing (`X-SDS-TS` / `Authorization: SDS`), which beats shipping a
  password once the key-signing flow is worth the extra code.
- **IPAM reconciliation.** Addresses runZero observes that IPAM does not hold
  are unmanaged address space; assigned IPAM rows runZero has never seen are
  stale entries. Both fall out of comparing the two inventories.

## API documentation

- Official Python SDK (service names, native auth headers, paging loop): https://gitlab.com/efficientip/solidserverrest
- Official OpenAPI client (query parameters, lowercase limit/offset, 204 semantics): https://github.com/EfficientIP-Labs/solidserver-go-client
- Official Terraform provider (EIP: MAC filtering, class-parameter parsing, auth): https://github.com/EfficientIP-Labs/terraform-provider-solidserver
- Official Ansible collection (WHERE syntax, field names): https://gitlab.com/efficientip/efficientip-ansible-collection
- Getting started with SOLIDserver REST APIs: https://efficientip.com/blog/getting-started-with-solidserver-rest-apis/

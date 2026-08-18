# Custom Integration: OPNsense

Imports the OPNsense firewall itself, plus every host it can see on its attached
segments through the ARP table, the NDP table, and the Kea and dnsmasq DHCP
lease pools.

This is the sibling of the shipped [`pfsense/`](../pfsense/) integration and
covers the same ground from the other fork of the project.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the OPNsense web interface, which is normally an internal management address.

## OPNsense requirements

- OPNsense 24.7 or newer. The `kea` and `dnsmasq` lease endpoints this integration probes were added over the 24.x/25.x series; older releases simply answer 404 and the run degrades to ARP and NDP.
- An **API key and secret pair** belonging to a user that can read the diagnostics and DHCP pages.
- OPNsense ships a **self-signed certificate** by default, so either import its CA into the Explorer trust store or set the TLS options this integration exposes. Nothing is skipped by default — you have to opt in.

### Creating the credential in OPNsense

1. Log in to the OPNsense web interface as an administrator.
2. Go to **System → Access → Users** and open the user the integration should run as. Creating a dedicated read-only user is recommended over reusing `root`.
3. Under **Effective Privileges**, grant the ones covering the endpoints this integration reads. These were taken from OPNsense's own ACL definitions, so the privilege names and the API patterns they cover are exact:

   | Privilege | Covers |
   |---|---|
   | **Diagnostics: ARP Table** (`page-diagnostics-arptable`) | `api/diagnostics/interface/get_arp*` |
   | **Diagnostics: NDP Table** (`page-diagnostics-ndptable`) | `api/diagnostics/interface/get_ndp*` |
   | **Lobby: Dashboard** (`page-system-login-logout`) | `api/diagnostics/system/system_information` — every user effectively has this |
   | **Services: DHCP: Kea(v4)** (`page-dhcp-kea-v4`) | `api/kea/leases4/*` |
   | **Services: DHCP: Kea(v6)** (`page-dhcp-kea-v6`) | `api/kea/leases6/*` |
   | **Services: Dnsmasq DNS/DHCP** | `api/dnsmasq/leases/*` |

   Two things are worth knowing here. OPNsense normalises the camelCase action name to snake_case when it matches an ACL pattern, which is why the patterns read `get_arp` while the URL reads `getArp`. And **`getInterfaceConfig` is not covered by any dedicated privilege at all** — no ACL pattern in OPNsense matches `api/diagnostics/interface/get_interface_config`, so only a user holding **All pages** (`page-all`), effectively an administrator, can call it. That call is what gives the firewall asset its own interface addresses and MACs. A non-admin user is fine otherwise: the call fails, the failure is logged, and the firewall still imports with its hostname and version while every discovered host imports normally. Grant `page-all` only if you want the firewall's own interfaces.
4. Scroll to **API keys** at the bottom of the user page and press **+**.
5. OPNsense immediately downloads an `apikey.txt` file. It contains two lines:

   ```
   key=Ai1B4kJ8vQm2sXo0pRt7YcNfLdWqZbHgUeKxTr3M
   secret=Jd9WsQ2mNb7VkPz1LxRt5YcAeFgHu0iOoPq4Xn6T
   ```

   The **secret is shown only once** — this download is the only copy.
6. Confirm the pair works from the Explorer host:

   ```bash
   curl -k -u 'Ai1B4kJ8...:Jd9WsQ2m...' \
     https://opnsense.example.com/api/diagnostics/interface/getArp
   ```

   A working key returns a JSON array. A bad key returns HTTP 401 with an empty body.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "OPNsense").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OPNsense URL** (`url`): base URL of the web interface, for example `https://opnsense.example.com`.
   - **API key** (`api_key`): the `key=` line from `apikey.txt`.
   - **API secret** (`api_secret`): the `secret=` line from `apikey.txt`.
   - **Collect the ARP table** (`collect_arp`): optional, default enabled.
   - **Collect the NDP table** (`collect_ndp`): optional, default enabled.
   - **Collect DHCP leases** (`collect_leases`): optional, default enabled.
   - **Include expired neighbors** (`include_expired`): optional, default disabled.
   - **Maximum discovered hosts** (`max_hosts`): optional, default 20000, `0` removes the cap.
   - **TLS options** (`tls_*`): set these if the firewall keeps its self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. An ARP cache turns over in minutes, so a frequent schedule finds more hosts than a nightly one.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from OPNsense.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:opnsense`.
- Hosts the firewall saw but runZero has never scanned are found with `tag:opnsense-discovered`, and can be narrowed by observation source with `tag:opnsense-arp`, `tag:opnsense-ndp`, `tag:opnsense-kea4`, or `tag:opnsense-dnsmasq`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to check a
credential and see what a real firewall returns before wiring up a task. Every
`CONFIG` parameter is passed as a `--kwargs key=value` pair, and repeating the
flag adds more:

```bash
runzero script --filename opnsense/opnsense.star \
  --kwargs url=https://opnsense.example.com \
  --kwargs api_key=Ai1B4kJ8vQm2sXo0pRt7YcNfLdWqZbHgUeKxTr3M \
  --kwargs api_secret=Jd9WsQ2mNb7VkPz1LxRt5YcAeFgHu0iOoPq4Xn6T \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/opnsense-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; without it the assets are parsed and discarded.
`--overwrite` lets you re-run into the same directory. To check only that the
`CONFIG` block and the HTTP/TLS wiring are sound, without touching a real
firewall, use `--validate`, which routes every request to a local dummy server:

```bash
runzero script --filename opnsense/opnsense.star --validate
```

To run it the way the platform does — as a scheduled integration task that
uploads its results — use the `scan` command with the custom integration flags
instead. `--custom-integration-id` is the UUID shown on the integration's page
in the console, and `--custom-integration-script-kwargs` takes the same
key/value pairs as one string:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://opnsense.example.com,api_key=...,api_secret=...'
```

Use `runzero script --help` and `runzero scan --help` on your own scanner build
to confirm the flags, since the set does change between releases.

## Asset identity

This integration emits **two kinds of asset**, and they have different identity
stories. Both are decided at the id, not with break flags, because a
foreign-id match can never be vetoed once it happens.

They are emitted as two declared asset types — `firewall` and `host` — selected
per record with `ImportAsset(assetType=...)`, and each type's merge policy is
declared under that key in `CONFIG["assetTypeBehavior"]`.

`type-break` is left ON (the default), so the two types never merge with each
other. They are disjoint by construction rather than by convention: building the
appliance asset also collects its own interface MACs, and the ARP, NDP, and
lease readers drop every entry whose MAC is in that set, so the firewall can
never also surface as a discovered host. Keeping the break on means a host
record that reaches the firewall's asset on some other signal — the firewall's
LAN address leased to something else, a spoofed MAC — cannot fold the gateway
into a DHCP client.

### The firewall itself

- Target entity: the OPNsense appliance.
- Source ID field: **none exists.** This is the finding that shaped the design. OPNsense publishes no device identifier anywhere in its API. `/api/core/firmware/status` and `/api/core/firmware/info` return only `product_id`, `product_version`, `product_abi`, `product_arch`, `product_name`, `product_series`, and `product_hash`, all of which describe the *software release* and are identical on every install of that release. `/api/diagnostics/system/systemInformation` returns only `name` (the configured hostname plus domain) and a `versions` array. `/api/core/system/status` returns subsystem health. There is no serial number, no hardware UUID, no SMBIOS passthrough, and no equivalent of pfSense's `netgate_id`.
- Final runZero ID: `opnsense:<url-hostname>:appliance`, for example `opnsense:opnsense.example.com:appliance`. The hostname comes from the configured `url` with the scheme and port stripped, so reaching the same firewall on a different port does not re-identify it.
- Stability: stable for as long as the credential points at the same URL. It survives reboot, firmware upgrade, hostname change, interface reconfiguration, and NIC replacement. It does **not** survive an operator changing the configured URL — for example from an IP literal to a DNS name — which mints a new id and forks the asset in runZero. That fork cannot be repaired with match behavior flags, because the platform unconditionally refuses to place two foreign ids from one custom integration on a single asset. Pick the URL form you intend to keep.
- Asset type: **`firewall`**.
- Match behavior: `no-mac-break no-ip-break no-name-break`. The id is one-per-appliance, and the interface MACs and hostname are exactly the signals that should let it merge with an asset runZero scanned directly, so none of them may disqualify that merge.
- Verdict: **scoped synthetic** — deterministic and one-per-appliance, but derived from configuration rather than issued by the vendor.

### Discovered hosts

- Target entity: one endpoint the firewall has observed, as a MAC address.
- Source ID field: the MAC. `mac` in the ARP and NDP tables, `hwaddr` in a Kea or dnsmasq lease. This is the primary key of all three tables and the only identifier any of them carries.
- Final runZero ID: `opnsense:<url-hostname>:host:<mac>`, for example `opnsense:opnsense.example.com:host:aa:bb:cc:00:11:01`.
- Asset type: **`host`**.
- Match behavior: **`no-id-match no-id-break`**, and this is the whole point. A MAC is not a durable device identity: it is reassigned when a NIC moves, it is spoofed, and modern clients randomize it per network. If the id were allowed to drive merges, a recycled MAC would pull a different physical device onto an existing asset and **no break flag could veto it** — the platform consults only a site check and a foreign-id-collision helper on the foreign-id match path, and that helper does not cover custom integrations at all. `no-id-match` takes the id out of matching entirely and lets the MAC, IP, and hostname do the correlating, which is what they are actually good at.
- The MAC in the id is canonicalized **losslessly** — lowercased, separators removed, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately *not* used for this, because they clear the locally administered bit of the first octet to improve cross-source matching. Every randomized client MAC sets that bit, so `aa:bb:cc:dd:ee:01` and `a8:bb:cc:dd:ee:01` would normalize to the same value and two genuinely different endpoints would collapse into one record. That bit-clearing is correct on the emitted `NetworkInterface`, which is why the interface still goes through `network_interface`, and wrong for identity.
- Missing-ID behavior: a row with no parseable MAC is skipped. Multicast MACs (odd first octet, which covers the `33:33:…` solicited-node entries that fill an NDP table), the all-zeros MAC, and the broadcast MAC are also skipped, because none of them is an endpoint. Nothing is invented and `new_uuid()` is never used.
- Verdict: **address-derived, deliberately inert.** The id exists so the record has a stable key across polls; it is never allowed to decide a merge.

The `no_mac_in_id` fixture invariant is skipped for this integration, with the
reason recorded in every scenario file. It exists to catch a MAC used as an id
*without* the safeguards above; here they are all present and deliberate.

## Notes

### What is imported

| Endpoint | Method | What it gives |
|---|---|---|
| `/api/diagnostics/system/systemInformation` | GET | The firewall's FQDN and its `OPNsense <version>-<arch>` version string |
| `/api/diagnostics/interface/getInterfaceConfig` | GET | The firewall's own interfaces: `macaddr`, `ipv4[].ipaddr`, `ipv6[].ipaddr` |
| `/api/diagnostics/interface/getArp` | GET | IPv4 neighbors: `mac`, `ip`, `intf`, `intf_description`, `expired`, `expires`, `permanent`, `type`, `manufacturer`, `hostname` |
| `/api/diagnostics/interface/getNdp` | GET | IPv6 neighbors: `mac`, `ip`, `intf`, `intf_description`, `manufacturer` |
| `/api/kea/leases4/search` | POST | Kea DHCPv4 leases |
| `/api/kea/leases6/search` | POST | Kea DHCPv6 leases |
| `/api/dnsmasq/leases/search` | POST | dnsmasq leases |

Only `ImportAsset` objects are produced. OPNsense's diagnostics API exposes no
installed software, no per-host listening services, and no vulnerability data,
so no `Software`, `Service`, or `Vulnerability` records are emitted. The
firewall's own listening sockets are available at
`/api/diagnostics/interface/getSocketStatistics`; see [Future](#future).

### Discrepancies with the research notes

`OPEN-NEXT.md` named a few endpoints that do not match the current source, and
vendor source wins:

- **`POST /api/kea/leases/search` does not exist.** The controller class is `Leases4Controller` (and `Leases6Controller`), so the paths are `/api/kea/leases4/search` and `/api/kea/leases6/search`. `LeasesController` is an abstract base with no route of its own.
- **`/api/dhcpv4/leases/searchLease` does not exist in current OPNsense.** There is no ISC dhcpd API controller in core at all; ISC dhcpd never exposed a lease API, which is why probing is necessary rather than optional.
- The `search` endpoints are **grid** endpoints, and their paging parameters are read from the POST body only. A GET works but silently applies the server-side default of `rowCount=9999`. This integration POSTs `{"current": 1, "rowCount": -1}` so nothing is truncated on a large pool.
- `getArp` and `getNdp` return a **bare JSON array**, not a grid envelope. The `searchArp` and `searchNdp` actions are the wrapped variants; the plain ones are used here because there is nothing to page.

### Merging and streaming

One physical host commonly appears in all three tables: ARP gives its IPv4
address, NDP gives its IPv6 address, and the lease gives its DHCP hostname. The
three views are folded into one record keyed on the canonical MAC, so a
dual-stack host produces one asset carrying both addresses rather than three
partial ones. `opnsense_sources` records which tables contributed.

Merging inherently requires an index, but the index holds compact dicts rather
than `ImportAsset` objects, and finished assets are handed to `report_asset` in
one record at a time. Peak allocation is therefore bounded by a batch, not by the size
of the estate. There is no pagination to walk: an ARP cache is a kernel table
returned whole, and the lease endpoints return their whole pool in one grid
response.

### Filtering, and why each filter is there

- **The firewall's own entries are excluded from discovered hosts.** A FreeBSD ARP table lists the firewall's own interface addresses with `permanent: true`; importing those would attach the firewall's addresses to a second asset. Any MAC that also appears in `getInterfaceConfig` is excluded for the same reason.
- **Expired ARP entries are skipped by default.** An expired entry is a host that has stopped answering. Set `include_expired` to import them anyway, which is useful for a one-off sweep of a segment.
- **Link-local addresses are dropped from interfaces.** The platform filters loopback, multicast, and unspecified before an asset is built, but it deliberately *keeps* link-local — and an NDP table is mostly `fe80::/10`, an address every host invents for itself. Two hosts that both failed DHCP would correlate to each other on APIPA. `169.254.0.0/16`, `fe80::/10`, loopback, `0.0.0.0`, and `255.255.255.255` are all filtered here, and the surviving list is preserved verbatim as `opnsense_addresses`.
- **An NDP entry with only a link-local address still imports.** It has no usable IP after filtering, but its MAC is a real correlator and the entry is proof the host is on the segment.
- **Placeholder hostnames are dropped.** dnsmasq writes a literal `*` into its lease file when the client sent no hostname option; the ARP collector writes `""` when the reverse lookup returned `?`. `localhost`, `unknown`, `none`, `null`, and `-` are dropped too, along with any "hostname" that is really an IP address — that is a dimension runZero already has, presented as one it does not.
- **`%zone` suffixes are stripped** before an NDP address is parsed, because `ndp -an` reports scoped addresses such as `fe80::3e22:fbff:feaa:bbcc%igb1`.

### Degrading gracefully

Every collection step is independent and failure-tolerant. A 404 from
`/api/kea/leases4/search` on an install that uses dnsmasq is a normal outcome,
not an error, and is logged as such — the DHCP backend is genuinely not fixed
across the OPNsense fleet. A permissions gap that blocks one endpoint costs you
that endpoint's data and nothing else. If no lease backend answers, the run says
so and continues on ARP and NDP alone.

### Rate limiting and retries

OPNsense documents no rate limit. The shared HTTP helper retries 408, 425, 429,
500, 502, 503, and 504 with exponential backoff and honours `Retry-After`;
`retries` defaults to 3 and nothing here overrides it. No backoff is hand-rolled.

### Verification status

This integration was verified against local fixtures and against the OPNsense
source, not against a live firewall. Every response shape used in the fixtures
was taken from the collector that produces it — `src/opnsense/scripts/interfaces/list_arp.py`,
`list_ndp.py`, `src/opnsense/scripts/kea/get_kea_leases.py`, and
`src/opnsense/scripts/dnsmasq/get_dnsmasq_leases.py` — rather than from prose
documentation, because the OPNsense API reference documents endpoint paths but
not response bodies.

## Future

- **The firewall's own listening services.** `/api/diagnostics/interface/getSocketStatistics` returns the appliance's open sockets and could be mapped onto `Service` objects for the firewall asset, giving runZero a first-party view of the management plane it usually has to scan for.
- **Unbound DNS observations.** `/api/unbound/diagnostics/dumpinfra` and the Unbound query log expose hosts the resolver has seen that never appeared in ARP — clients behind a downstream router, for instance. This is a genuinely different vantage point from the neighbor tables and would extend reach past the directly attached segments.
- **Static DHCP reservations as expected inventory.** The Kea and dnsmasq settings endpoints list configured reservations. A reservation with no matching lease is a device that is *supposed* to be on the network and is not, which is a coverage-gap signal rather than an asset.
- **Interface-to-site mapping.** Every observation already records which OPNsense interface it came from (`opnsense_segments`). Mapping those onto runZero sites would place discovered hosts in the right site automatically instead of all landing in the task's site.
- **Neighbor discovery data from LLDP.** The `lldpd` plugin exposes `/api/lldpd/service/neighbor`, which names the switch and port on the other end of each firewall interface. That is layer-2 topology this integration does not currently import.
- **CARP-aware deduplication.** A CARP pair reports overlapping ARP tables from both members. `/api/diagnostics/interface/getVipStatus` distinguishes MASTER from BACKUP and could be used to import from the master only, or to tag which member observed each host.
- **HA and multi-firewall estates.** The appliance id is scoped on the configured URL, so two firewalls are two credentials and two tasks today. A future version could accept several URLs behind one credential.

## API documentation

- API introduction and authentication — https://docs.opnsense.org/development/api.html. Source for the HTTP Basic key/secret model and the `/api/<module>/<controller>/<command>` path convention.
- Diagnostics API reference — https://docs.opnsense.org/development/api/core/diagnostics.html. Lists `getArp`, `getNdp`, `searchArp`, `searchNdp`, `getInterfaceNames`, `getInterfaceConfig`, and `systemInformation`, but not their response bodies.
- Kea API reference — https://docs.opnsense.org/development/api/core/kea.html.
- Dnsmasq API reference — https://docs.opnsense.org/development/api/core/dnsmasq.html.
- Core firmware API reference — https://docs.opnsense.org/development/api/core/firmware.html. Read to establish that no appliance identifier is published; the fields come from `/usr/local/opnsense/version/core` via `src/opnsense/scripts/firmware/product.php` and describe the release, not the box.
- Privilege names and the API patterns each one covers — the ACL definitions in [`opnsense/core`](https://github.com/opnsense/core): `src/opnsense/mvc/app/models/OPNsense/Diagnostics/ACL/ACL.xml`, `.../Core/ACL/ACL.xml`, `.../Kea/ACL/ACL.xml`, and `.../Dnsmasq/ACL/ACL.xml`.
- **Response shapes** come from the collectors in [`opnsense/core`](https://github.com/opnsense/core): `src/opnsense/scripts/interfaces/list_arp.py`, `src/opnsense/scripts/interfaces/list_ndp.py`, `src/opnsense/scripts/kea/get_kea_leases.py`, `src/opnsense/scripts/dnsmasq/get_dnsmasq_leases.py`, and the controllers `src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/InterfaceController.php`, `.../Kea/Api/LeasesController.php`, `.../Dnsmasq/Api/LeasesController.php`.
- Grid envelope and the `rowCount` default of 9999 — `src/opnsense/mvc/app/controllers/OPNsense/Base/ApiControllerBase.php`, `searchRecordsetBase()`. The same file's `parseJsonBodyData()` is why a JSON POST body reaches those parameters at all.
- Reference client — [`pyopnsense`](https://github.com/mtrdesign/pyopnsense).
- Sibling implementation in this repository — [`pfsense/pfsense.star`](../pfsense/pfsense.star).

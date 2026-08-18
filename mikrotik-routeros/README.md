# Custom Integration: MikroTik RouterOS

Imports a MikroTik router and — the reason this integration exists — **the
devices that router has observed**: its ARP table, its DHCP leases, the CDP,
LLDP, and MNDP neighbors it has discovered, and the stations associated to its
radios.

MikroTik is everywhere in homelab, WISP, and small-office networks, and in most
of those networks the router is the only thing with a complete picture of what
is attached. The discovery neighbor table in particular is unusually rich: a
neighbor announces its own identity, platform, board model, and software
version, so those assets arrive already described rather than as a bare address.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the router's web service.

## RouterOS requirements

- **RouterOS 7.1 or newer.** The REST API was introduced in 7.1beta4 as a JSON wrapper over the console. RouterOS 6 has no REST API at all — its only programmatic interface is the binary API on 8728/8729, which this integration does **not** implement and which is out of scope. Point this at a v6 device and the first request fails; the log says so and names the version floor.
- **The web service must be enabled.** REST is served by `www-ssl` (HTTPS) or `www` (plain HTTP).
  - `www-ssl` **will not start without a certificate assigned**, which is the single most common reason a first attempt fails.
  - Plain HTTP on `www` only serves REST from **RouterOS 7.9 onward** (`*) www - allow unsecure HTTP access to REST API;`). On 7.1–7.8, HTTPS is the only option.

### Enabling the service

With a self-signed certificate:

```
/certificate add name=rest-tmpl common-name=rest-api days-valid=3650 key-size=2048
/certificate sign rest-tmpl name=rest-api
/ip service set www-ssl certificate=rest-api disabled=no
```

Or, on 7.9+, plain HTTP if you accept that Basic credentials cross the network
unencrypted:

```
/ip service set www disabled=no
```

### Creating the credential

`rest-api` is a **separate policy** from `api`, and both are separate from
`web`. A read-only user needs `read` and `rest-api`; the built-in `read` group
already contains both, but a dedicated group is better because it can be pinned
to the Explorer's address:

```
/user group add name=runzero-ro policy=read,rest-api,api
/user add name=runzero group=runzero-ro password=<secret> address=192.0.2.10/32
```

- `read` and `rest-api` are the load-bearing pair.
- `api` is harmless and only matters if you ever fall back to the binary API.
- `web` is **not** required for `/rest`.
- `sensitive` is **not** required and should not be granted — it exposes stored passwords and keys, and no table this integration reads needs it.
- `address=` restricts the account to the Explorer, which is worth doing.

Confirm the credential from the Explorer host:

```bash
curl -sk -u 'runzero:<secret>' https://192.168.88.1/rest/system/resource
```

A success returns a **JSON array with one object** — every RouterOS REST read
returns an array, even for a single-record menu. A wrong password returns HTTP
401 with no body. A missing policy returns **HTTP 500**, not 403:

```json
{"detail": "not enough permissions (9)", "error": 500, "message": "Internal Server Error"}
```

### TLS

RouterOS serves `www-ssl` with whatever certificate you assigned, which is
normally self-signed. Set the TLS options accordingly rather than assuming
validation will pass. Do not disable validation without deciding that is
acceptable for your environment.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "MikroTik RouterOS").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **RouterOS URL** (`url`): base URL of the device, for example `https://192.168.88.1`. The API is resolved as `<url>/rest`.
   - **Username** (`username`) and **Password** (`password`).
   - **Import the router itself** (`import_router`): optional, default enabled.
   - **Collect ARP entries** (`collect_arp`) / **Collect DHCP leases** (`collect_dhcp_leases`) / **Collect discovery neighbors** (`collect_neighbors`) / **Collect wireless stations** (`collect_wireless`): optional, all default enabled.
   - **Bound DHCP leases only** (`bound_leases_only`): optional, default **disabled**.
   - **Maximum hosts** (`max_hosts`): optional, default 10000, `0` removes the cap.
   - **TLS options** (`tls_*`): set these for the device's self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Select the Explorer you would like the Custom Integration to run from.
   - Schedule it. ARP entries and wireless associations age out in minutes, so an hourly run sees substantially more of a busy network than a daily one.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from RouterOS.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:mikrotik-routeros`.
- Split the two asset kinds with `tag:mikrotik-router` and `tag:mikrotik-host`.
- Find how a device was seen with `tag:mikrotik-arp`, `tag:mikrotik-dhcp-lease`, `tag:mikrotik-neighbor`, or `tag:mikrotik-wireless`.
- Find everything on one SSID with `tag:ssid:corp-wifi`, or find weak wireless clients with `mikrotik_wifi_signal_dbm:<-75`.
- Find the router by serial with `tag:serial:HGT08ABCDEF`.

## Running it from the command line

```bash
runzero script --filename mikrotik-routeros/mikrotik-routeros.star \
  --kwargs url=https://192.168.88.1 \
  --kwargs username=runzero \
  --kwargs password='correct horse battery staple' \
  --kwargs tls_disable_validation=true \
  --kwargs collect_wireless=false \
  --kwargs max_hosts=200 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/mikrotik-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real device:

```bash
runzero script --filename mikrotik-routeros/mikrotik-routeros.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://192.168.88.1,username=runzero,password=...'
```

**One CLI caveat:** `--kwargs` passes a value through verbatim, commas included,
until the value contains a *second* `=` -- at which point it is parsed as CSV,
so a password containing a comma *and* an `=` is silently torn into extra
parameters. Test such a credential through the console form rather than the CLI.

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, and — unusually — **they use different match behavior**, because
MikroTik publishes a genuine hardware identifier for one of them and nothing at
all for the other.

There are three declared asset types, because the router itself splits at
**runtime**: the script picks `router` when `/system/routerboard` yielded a
serial and `router-unkeyed` when it did not, and observed devices are `host`.
The type is selected per asset with `ImportAsset(assetType=...)`, and each
type's complete merge policy is declared under that key in
`CONFIG["assetTypeBehavior"]`:

| type | when | match behavior |
|---|---|---|
| `router` | `/system/routerboard` returned a serial | `no-mac-break no-ip-break no-name-break` |
| `router-unkeyed` | CHR / x86, no serial | `no-id-match no-id-break` |
| `host` | an observed ARP, lease, neighbor, or wireless entry | `no-id-match no-id-break` |

Each type states its *complete* policy rather than only what differs from the
integration-wide value. Levels layer, and a broader level survives wherever the
type-specific one is silent, so splitting one kind's flags across the two levels
would silently leak them onto the other kind.

`CONFIG["matchBehavior"]` carries **`no-type-break`**, which lets the types merge
with each other. The reason is the router pair: `router` and `router-unkeyed`
are the same device under two grades of identifier, and the grade is not a
permanent property of the hardware — it is whatever `/system/routerboard`
answered on *this* run, and that menu can fail to read on a router that answered
it last time. A device can therefore move between the two types without anything
about it changing, and a type boundary must not be a reason to refuse the merge
back.

That is necessary but **not sufficient**, and it is worth being clear about the
limit: the grade also decides the id (`mikrotik:routerboard:<serial>` versus
`mikrotik:<host>:router`), and two foreign ids from one custom integration
cannot sit on one asset whatever the break flags say — so that flip still forks
and is reconciled in runZero. `no-type-break` only stops the type boundary being
a *second*, independent reason for the same fork.

Relaxing `type-break` is safe for the router/host pair because those populations
are disjoint by construction rather than by convention: the router's own
interface MACs are collected first into `ctx["router_macs"]`, and the ARP, lease,
neighbor, and wireless readers all skip any row whose MAC is in that set, so the
router can never also appear as an observed host.

### The router

- Target entity: the RouterOS device itself.
- Source ID field: **`serial-number` from `/system/routerboard`**. This is the serial printed on the RouterBOARD, assigned by MikroTik at manufacture. It is globally unique, it survives a reinstall, a re-address, a rename, and a RouterOS upgrade, and it is exactly the "stable vendor device id" case the platform's default match behavior is designed for.
- Final runZero ID: `mikrotik:routerboard:HGT08ABCDEF`. No host scope is needed, and deliberately so — the serial is unique across all MikroTik hardware, so the same router polled from two tasks, by IP in one and by DNS name in the other, produces **one** asset rather than two.
- Asset type: **`router`**, or **`router-unkeyed`** when no serial is available (see below).
- Match behavior: `"no-mac-break no-ip-break no-name-break"`. The id drives merges, and a changed address, MAC, or identity does not disqualify a merge against the existing asset. That is the right trade for a device whose whole job is to be re-addressed.
- Verdict: **authoritative vendor identifier.**

#### CHR and x86 have no serial, and that changes the verdict

`/system/routerboard` **does not exist** on Cloud Hosted Router or x86 builds —
not empty, not `routerboard=false`, the menu is absent and RouterOS answers
`no such command or directory`. There is no other stable identifier: `/system/resource`
reports a board name shared by every CHR instance, and `/system/identity`
returns an operator-set name that defaults to `MikroTik` on every unconfigured
device.

So on those builds the id falls back to `mikrotik:<configured-host>:router` and
the match behavior flips to **`no-id-match no-id-break`**. That fallback id is
an *address*, and addresses are recycled — retire a CHR instance and its
successor inherits `10.20.30.1`. If the id were allowed to drive merges the new
instance would merge onto the retired one's asset and **nothing could veto it**:
the platform's foreign-id match path consults only a site check and a collision
helper whose allowlist does not include custom integrations at all, so the MAC,
IP, and name break flags are never consulted once an id matches.

**Be aware of one consequence.** If a device moves between the two forms — a
CHR that starts reporting a serial, or a RouterBOARD whose `routerboard` menu
becomes unreadable — its id changes, and a changed foreign id from the same
custom integration always **forks** the asset. `no-id-break` does not prevent
this; a separate unconditional gate refuses any merge that would place two
different foreign ids from one custom integration on a single asset. In practice
the two cases are hardware and do not flip: a RouterBOARD always has the menu,
CHR never does, and the `read` policy is sufficient to see it. The run logs
which branch it took whenever the serial is missing.

The factory identity `MikroTik` is treated as a placeholder hostname and is not
imported, for the same reason `localhost` is not: on the host-derived branch
there is no stable id, so merging falls back to MAC, IP, and hostname, and a
name shared by every unconfigured RouterOS device would merge unrelated routers.

### Observed devices

- Target entity: one MAC the router has seen, from any of ARP, a DHCP lease, the discovery neighbor table, or a wireless registration table.
- Source ID field: the **MAC**. RouterOS's own `.id` values (`*1`, `*A`, `*1A`) are deliberately **not** used — they are per-menu row handles that are **not stable across a reboot**, so keying on one would give the same laptop a new asset every time the router restarts.
- Final runZero ID: `mikrotik:<router-host>:host:<mac>`.
- Cardinality: one asset per MAC. A single laptop routinely appears in all four tables at once, so the four are folded into **one** record before anything is emitted, with `mikrotik_observed_by` recording which sources contributed. Without that fold the `unique_ids` invariant would fire and runZero would hear about the same laptop four times.
- Asset type: **`host`**.
- Match behavior: `no-id-match no-id-break`, for the reason a MAC always demands it. MACs move with a NIC, are spoofed, and are randomized per-SSID by every current phone. Correlation on MAC, IP, and hostname is what should decide a merge, and it does.
- The MAC in the id is canonicalized **losslessly** — lower-cased, separators stripped, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately not used for this, because they clear the locally administered bit of the first octet to help cross-source matching. Every randomized client MAC sets that bit, so two distinct phones on the guest SSID would collapse into one record. The emitted `NetworkInterface` still goes through `network_interface`, which is correct there.
- Missing-ID behavior: a record with no parseable MAC is skipped and counted. That covers an ARP entry with `complete=false` (a failed resolution, not a device), a multicast MAC, the all-zeros MAC, and a neighbor that announced no chassis address. Nothing is invented and `new_uuid()` is not used anywhere in this script.
- **The router's own MACs are excluded.** A router's ARP table contains its own interface addresses, so those MACs are collected first from `/interface` and filtered out of the device set — otherwise the router would also appear as one of its own clients.
- Verdict: **address-derived, deliberately inert.**

The `no_mac_in_id` fixture invariant is skipped for this integration, with the
reason recorded in each scenario. It exists to catch a MAC used as an id
*without* these safeguards.

## Notes

### What is imported

| Menu | Gated by | What it gives |
|---|---|---|
| `/system/resource` | always | Version, board name, platform, architecture, CPU, memory, uptime |
| `/system/identity` | always | The router's name |
| `/system/routerboard` | always | Model, serial, firmware — **absent on CHR and x86** |
| `/interface` | always | The router's own interface MACs and types |
| `/ip/address` | always | The router's own addresses, joined to interfaces by name |
| `/ip/arp` | `collect_arp` | Address to MAC, with interface and neighbor state |
| `/ip/dhcp-server/lease` | `collect_dhcp_leases` | Address, MAC, hostname, lease state, DHCP option 82 relay ids |
| `/ip/neighbor` | `collect_neighbors` | CDP/LLDP/MNDP: identity, platform, board, version, capabilities |
| `/interface/wifi/registration-table` | `collect_wireless` | Stations on RouterOS 7.13+ `wifi` radios |
| `/interface/wireless/registration-table` | `collect_wireless` | Stations on legacy `wireless` radios |
| `/interface/wireless` | `collect_wireless` | SSIDs for legacy radios — fetched only when the legacy table returned rows |
| `/caps-man/registration-table` | `collect_wireless` | Stations on CAPsMAN v1 |

Only `ImportAsset` objects are produced. RouterOS inventories no installed
software on other hosts and no vulnerabilities, so no `Software` or
`Vulnerability` records are emitted. Listening services are not emitted either —
`/ip/firewall/nat` would be the source for that, and it is listed under
[Future](#future).

### Every value is a string

This is the trap that shapes the whole parser. RouterOS documents it plainly:
in JSON replies **all object values are encoded as strings, even if the
underlying data is a number or a boolean.** So a response contains
`"disabled":"false"` — a non-empty, and therefore *truthy*, string. A script
that tests these the obvious way inverts the meaning of every flag it reads.
Booleans are compared against the literal `"true"` here, never tested for
truthiness.

Two companion rules follow from the same design:

- **An unset property is omitted entirely**, not sent empty. Every field read goes through a helper that supplies a default, and `.get(key, default)` is avoided because it returns `None` when the key exists holding a null.
- **Every read returns an array**, including `/system/resource` and `/system/identity`, which hold exactly one record.

### Degradation is not uniform, so status codes are not trusted

RouterOS signals four different problems four different ways, and the status
code is not a reliable discriminator:

| Situation | Response |
|---|---|
| Wrong password | HTTP 401, **no body** |
| Missing policy | HTTP **500**, `{"detail":"not enough permissions (9)", ...}` |
| Menu belongs to an uninstalled package | HTTP 4xx, `{"detail":"no such command or directory (wireless)", ...}` |
| No DHCP server configured | HTTP **200** with `[]` — the menu is in the base bundle and always exists |

Note the asymmetry in the last two rows: an empty table and an absent menu are
completely different responses. This integration classifies on the `detail`
text rather than the status, reports a missing policy with the exact
`/user group add` command that fixes it, treats an absent menu as "this router
does not have that feature" and moves on, and never lets a single unavailable
table end the run.

### Three wireless registration tables

RouterOS 7.13 split the wireless packages: `wifiwave2` became `wifi-qcom` and
its management utilities moved into the base bundle, while legacy `wireless` and
CAPsMAN v1 moved *out* into a separate `wireless` package that **conflicts with**
the new drivers. A given router therefore has at most two of the three tables
and usually only one, and each names its signal field differently — `signal` on
`wifi`, `signal-strength` on legacy `wireless`, `rx-signal` on CAPsMAN. All
three are probed, whichever exist are read, and the rest are skipped silently.

The legacy `wireless` table also carries **no SSID at all**, so when it returns
rows the SSID is joined from `/interface/wireless` on the interface name. That
extra request is made only in that case.

### Timestamps

RouterOS reports `last-seen`, `uptime`, and `last-activity` as **durations
relative to the moment of the request** — `19m50s`, `2d23h40m10s`, `7w6d9h34m` —
never as wall-clock times. Subtracting from now therefore always yields a time
in the **past**, which is what makes them safe to use: the platform rejects the
**entire asset record**, not the field, on a future timestamp. The most recent
sighting across all sources becomes `lastSeenTS`, and the router's uptime
becomes its `firstSeenTS` (the boot time). Every raw duration is also kept
verbatim as a `_raw` attribute.

`time.parse_duration` is deliberately not used: Go durations have no week or day
unit, so it would reject the most common RouterOS forms outright. The hand-rolled
parser returns a sentinel on anything it does not recognise rather than
aborting, tolerates the omission of any zero component, and ignores `ms`/`us`
rather than misreading the `m` as minutes.

### Request volume and memory

The cost is a fixed **eight to twelve requests** regardless of estate size —
every table returns in one call. RouterOS REST has **no pagination**: a print
returns the whole table. That is convenient and is also the memory risk, so
`max_hosts` bounds the fold index and the run reports when it trips.

Records are accumulated as compact dicts rather than `ImportAsset` objects,
because the same MAC appears in several tables and must be folded before it is
emitted, and each finished asset is handed to `report_asset` as it is built.
The fold index, not any single response, is what dominates memory on a
large router; `max_hosts` is the control for it.

### Verification status

Verified against local fixtures and against RouterOS's own property namespace —
**not** against a live router. The field names in the fixtures were taken from
per-version dumps of RouterOS 7.23.3's own `proplist` completion namespace
harvested over REST from real routers, cross-checked against MikroTik's
documentation, and preferred over the documentation wherever the two disagreed.
Several doc pages are stale: the ARP page omits `status` and `complete` detail
and writes `VRF` upper-case where the console uses `vrf`, the neighbor page
omits `system-description`, and the CAPsMAN page has no property table at all.

Two response bodies are quoted verbatim from MikroTik's own manual and from a
published capture — `/system/resource`, and a `waiting` DHCP lease showing that
`active-*` and `expires-after` are omitted on an inactive lease. The rest are
reconstructed with authoritative key names and illustrative values.

**One field is explicitly unresolved.** The case of the ARP `dhcp` key differs
between the console namespace (`dhcp`) and observed wire captures (`DHCP`), and
the same ambiguity affects `vrf`/`VRF`. Both spellings are read.

**No container was run for this integration, deliberately.** MikroTik publishes
`mikrotik/chr` on Docker Hub, but it is not container-native RouterOS — the
image is Alpine plus `qemu-system-x86_64` wrapping the same CHR VM disk you
would otherwise download, and it requires `--privileged`. Every community
alternative is the same QEMU wrapper. On the arm64 host this work was done on,
the x86 CHR disk would need full CPU emulation, so booting it is a heavyweight
VM rather than a container, and the host-hygiene constraints for this work made
that the wrong trade. A live RouterOS device remains the best next validation
step, and the two things most worth confirming there are the ARP `dhcp` key
casing and the populated shape of whichever registration table the device has.

## Future

- **Confirm against a live router**, particularly the ARP `dhcp`/`DHCP` casing and one populated wireless registration table.
- **`.proplist` field selection.** Every read currently fetches all properties; `/interface` alone returns 34 including per-interface byte and packet counters that are discarded. `GET /rest/ip/arp?.proplist=address,mac-address,interface` would cut the payload substantially on a large router. It is not used today because naming a property that does not exist in an older release risks failing the whole query, and robustness across 7.1 → 7.20 mattered more than bytes for a first version.
- **Streaming very large tables.** A WISP-scale CCR can hold tens of thousands of ARP entries in a single unpaginated response. `jsonstream.iter_array` over a raw `http.get` body would bound the per-response allocation; today the bound is `max_hosts` on the fold index, which is what actually dominates. Worth doing together with `.proplist`.
- **Port forwards as services.** `/ip/firewall/nat` destination-NAT rules name an internal host and port, which are `Service` objects on devices this integration already imports and describe real inbound exposure.
- **IPv6 neighbors.** `/ipv6/neighbor` is the v6 counterpart of the ARP table and is not read today, so a v6-only host is seen only if it also appears in the discovery or DHCP tables.
- **Wireless access-list and connect-list.** These carry operator-assigned comments per MAC, which are often the only human-meaningful name a wireless-only device has.
- **The router's own services.** `/ip/service` lists which management services are enabled and on which ports — a genuinely useful exposure signal for the router asset, and a natural `Service` list.
- **CAPsMAN-managed APs.** `/caps-man/remote-cap` enumerates the access points a CAPsMAN controller manages, each a real device with a MAC, model, and version. Today those APs appear only if they also show up as discovery neighbors.
- **RouterOS 6 via the binary API.** Out of scope here, and it would need a hand-rolled protocol over `socket.tcp`. Worth revisiting only if v6 demand is real; the version floor is stated plainly instead.

## API documentation

- [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API) — the base path, the JSON-string encoding rule, the `.proplist`/`.query` forms, the error envelope, and the verbatim `/system/resource` example.
- [RouterOS documentation home](https://help.mikrotik.com/docs/spaces/ROS/overview) — per-menu property tables for IP/ARP, IP/DHCP Server, IP/Neighbor discovery, Wireless, WifiWave2, CAPsMAN, System/Resource, and System/RouterBOARD.
- [User management and policies](https://help.mikrotik.com/docs/spaces/ROS/pages/2555971/User) — the policy list, including `rest-api` as distinct from `api` and `web`.
- [IP services](https://help.mikrotik.com/docs/spaces/ROS/pages/328059/Services) — `www` and `www-ssl`, and the certificate requirement.
- Reference clients worth reading for real payload shapes: [`socialwifi/RouterOS-api`](https://github.com/socialwifi/RouterOS-api), [`librouteros`](https://github.com/luqasz/librouteros), and the [`community.routeros`](https://github.com/ansible-collections/community.routeros) Ansible collection.
- [`tikoci/restraml`](https://github.com/tikoci/restraml) — per-version dumps of RouterOS's own property namespace, harvested over REST from real routers on both x86 and arm64. This is the source of the field names used here and is more current than the documentation pages.

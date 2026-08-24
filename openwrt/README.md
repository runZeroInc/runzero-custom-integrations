# Custom Integration: OpenWrt

Imports an OpenWrt router and — the reason this integration exists — **every
host that router has observed**: DHCP leases, the neighbor/ARP table, static
`/etc/ethers` entries, and associated wireless stations.

A home or branch router is often the only device that has seen the phone that
joined the guest SSID for ten minutes, the thermostat that never answers a scan,
and the printer that sat on a static address for three years. OpenWrt publishes
all of it over `ubus`.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the OpenWrt device's web interface (port 80 or 443 by default).

## OpenWrt requirements

**A stock OpenWrt install works. No extra packages are required.** This was
established empirically rather than assumed — see
[Verification status](#verification-status).

The default image ships `uhttpd`, `uhttpd-mod-ubus`, `rpcd`, `rpcd-mod-luci`,
`rpcd-mod-iwinfo`, and the LuCI web interface, and the stock
`/etc/config/uhttpd` already contains:

```
config uhttpd 'main'
	list listen_http '0.0.0.0:80'
	list listen_https '0.0.0.0:443'
	option cert '/etc/uhttpd.crt'
	option key  '/etc/uhttpd.key'
	option ubus_prefix '/ubus'
```

That last line is what publishes the JSON-RPC endpoint this integration speaks
to. LuCI's own web interface is a JavaScript client that talks to `/ubus`, so
any device you can administer through LuCI already exposes it.

Confirm on your own device in one command:

```bash
uci get uhttpd.main.ubus_prefix     # -> /ubus
```

If that returns nothing, the device is running a stripped custom build. Restore
it with:

```bash
opkg update && opkg install uhttpd-mod-ubus rpcd-mod-luci rpcd-mod-iwinfo
uci set uhttpd.main.ubus_prefix='/ubus'
uci commit uhttpd && /etc/init.d/uhttpd restart
```

### Version support

Verified against **OpenWrt 24.10.8**. The `ubus` HTTP transport, the `luci-rpc`
object, and the ACL model have been stable since 19.07, when LuCI moved to a
client-side JavaScript architecture that made `/ubus` mandatory. Releases older
than 19.07 used a server-rendered LuCI and are not supported.

### Creating the credential

Two options. The second is strongly preferred.

**Option A — the `root` account.** The password you use for LuCI works as-is.
Simple, but it is a full administrative credential and its session can write
configuration, reboot, and flash firmware.

**Option B — a dedicated read-only account (recommended).**

`rpcd` grants access per *ACL group*, not per user role, and the groups this
integration needs are all read-only. Add a login to `/etc/config/rpcd`:

```
config login
	option username 'runzero'
	option password '$p$runzero'
	list read 'luci-base-network-status'
	list read 'luci-mod-status-index'
	list read 'luci-mod-status-index-dhcp'
	list read 'luci-mod-status-index-wifi'
```

Then create the matching system user and set its password:

```bash
echo 'runzero:x:0:0:runzero:/root:/bin/false' >> /etc/passwd
passwd runzero
/etc/init.d/rpcd restart
```

The `$p$runzero` value is not a literal password — it tells `rpcd` to verify
against `/etc/shadow` for the user named after the `$p$` prefix. A crypt hash
may be used in its place if you would rather not create a system user.

Those four groups grant exactly what this integration reads, and nothing else:

| ACL group | Grants |
|---|---|
| `luci-base-network-status` | `luci-rpc` `getBoardJSON`, `getHostHints`, `getNetworkDevices`, `getWirelessDevices` |
| `luci-mod-status-index` | `system` `board`, `info` |
| `luci-mod-status-index-dhcp` | `luci-rpc` `getDHCPLeases` |
| `luci-mod-status-index-wifi` | `iwinfo` `assoclist` |

Note there is **no `write` list** — this account cannot change anything.

Confirm the credential from the Explorer host. The endpoint is a single POST;
the all-zero session id is the documented "no session" value:

```bash
curl -sk https://192.168.1.1/ubus -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"call",
  "params":["00000000000000000000000000000000","session","login",
            {"username":"runzero","password":"<password>"}]}'
```

A success returns `{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"…","acls":{…}}]}`.
A bad password returns `{"jsonrpc":"2.0","id":1,"result":[6]}` — HTTP 200, no
error object, just ubus status 6. See [Notes](#error-handling) for why that
matters.

### TLS and reachability

- OpenWrt generates a **self-signed certificate** at first boot (`/etc/uhttpd.crt`, EC P-256, `CN=OpenWrt`). Either point the integration at `http://` on port 80, or use `https://` and set the TLS options accordingly. Do not disable validation without deciding that is acceptable for your environment.
- `uhttpd` ships with `option rfc1918_filter '1'`, which rejects requests that arrive from a public source address for an RFC1918 destination. This is DNS-rebinding protection and is normally invisible, but it means the Explorer must reach the router over the internal network rather than through a public forward.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "OpenWrt").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OpenWrt URL** (`url`): base URL of the web interface, for example `https://192.168.1.1`. The endpoint is resolved as `<url>/ubus`, so include any path prefix if the device is behind a reverse proxy.
   - **Username** (`username`) and **Password** (`password`).
   - **Import the router itself** (`import_router`): optional, default enabled.
   - **Collect DHCP leases** (`collect_leases`): optional, default enabled.
   - **Collect host hints** (`collect_host_hints`): optional, default enabled.
   - **Collect wireless stations** (`collect_wireless`): optional, default enabled.
   - **Maximum hosts** (`max_hosts`): optional, default 5000, `0` removes the cap.
   - **Session timeout in seconds** (`session_timeout`): optional, default 900.
   - **TLS options** (`tls_*`): set these if you are connecting over HTTPS to the device's self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Select the Explorer you would like the Custom Integration to run from — it must be on a network that can reach the router.
   - Schedule it. Wireless associations and neighbor entries age out quickly, so an hourly or four-hourly run captures far more than a daily one.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from OpenWrt.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:openwrt`.
- Split the two asset kinds with `tag:openwrt-router` and `tag:openwrt-host`.
- Find how a host was seen with `tag:openwrt-dhcp-lease`, `tag:openwrt-wireless`, or `tag:openwrt-host-hints`.
- Find everything on one SSID with `tag:ssid:branch-wifi`, or look at signal strength with `openwrt_wifi_signal_dbm:<-70`.

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
credential and see what a real device returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename openwrt/openwrt.star \
  --kwargs url=https://192.168.1.1 \
  --kwargs username=runzero \
  --kwargs password='correct horse battery staple' \
  --kwargs tls_disable_validation=true \
  --kwargs max_hosts=100 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/openwrt-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real device:

```bash
runzero script --filename openwrt/openwrt.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://192.168.1.1,username=runzero,password=...'
```

**One CLI caveat:** `--kwargs` passes a value through verbatim, commas included,
until the value contains a *second* `=` -- at which point it is parsed as CSV,
so a password containing a comma *and* an `=` is silently torn into extra
parameters. Test such a credential through the console form rather than the CLI.

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, and **both use `no-id-match no-id-break`**. That is a
deliberate departure from the "stable vendor id" default, and unavoidable here.

### The router

- Target entity: the OpenWrt device itself.
- **OpenWrt publishes no device identifier at all.** `ubus call system board` returns `kernel`, `hostname`, `system`, `model`, `board_name`, and a `release` object. There is no serial number, no machine id, and no UUID. `board_name` (`tplink,archer-c7-v2`) and `model` (`TP-Link Archer C7 v2`) are shared by every unit of that hardware ever built, so neither can identify one device.
- Source ID field: none exists. The id is built from the **configured URL's hostname**: `openwrt:<host>:router`.
- Uniqueness scope: one configured target. Two routers polled by two tasks get two ids because they are addressed differently; the same router polled by IP in one task and by DNS name in another would get two ids, which is why the ids must not drive merges.
- Final runZero ID: `openwrt:192.168.1.1:router`.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. The id is an *address*, and addresses are recycled — replace a branch router and its successor inherits `192.168.1.1`. If the id were allowed to drive merges, the new device would merge onto the retired one's asset and **nothing could veto it**: the platform's foreign-id match path consults only a site check and a collision helper whose allowlist does not include custom integrations, so the MAC, IP, and name break flags are never consulted once an id matches. Correlation instead runs on the router's interface MACs, its LAN and WAN addresses, and its hostname, which is plenty.
- Missing-ID behavior: a device that yields neither a usable hostname nor any MAC or address is skipped with a log line. Nothing is invented and `new_uuid()` is not used anywhere in this script.
- Verdict: **address-derived, deliberately inert.**

#### The factory-default hostname is dropped on purpose

Every unflashed OpenWrt reports `hostname: "OpenWrt"`. Because there is no
stable id, merging falls back to MAC, IP, and hostname — and a hostname shared
by every OpenWrt in an estate is exactly the kind of value that merges unrelated
devices into one asset. `openwrt` and `lede` are therefore treated as
placeholder names and are not imported as hostnames, the same way `localhost`
is. The router still correlates on its MACs and addresses, the raw value is
preserved as `openwrt_reported_hostname`, and a log line says it happened. Set a
real hostname on the device and it is imported normally.

### Observed hosts

- Target entity: one MAC the router has seen, whether through a DHCP lease, the neighbor table, `/etc/ethers`, or a wireless association.
- Source ID field: the **MAC**. It is the only identifier any of these records carries — `getHostHints` is literally an object *keyed* by MAC.
- Final runZero ID: `openwrt:<router-host>:host:<mac>`.
- Cardinality: one asset per MAC. The same host routinely appears in all three collections — a laptop has a lease, a neighbor entry, and a wireless association — so the three are folded into **one** record before anything is emitted, with `openwrt_observed_by` recording which sources contributed. Without that fold the `unique_ids` invariant would fire and runZero would be told about the same laptop three times.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`, for the reason a MAC always demands it. MACs move with a NIC, are spoofed, and are randomized per-SSID by every current phone and laptop. Correlation on MAC, IP, and hostname is what should decide a merge, and it does.
- The MAC in the id is canonicalized **losslessly** — lower-cased, separators stripped, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately not used for this, because they clear the locally administered bit of the first octet to help cross-source matching. Every randomized client MAC sets that bit, so `de:ad:be:ef:00:01` and `dc:ad:be:ef:00:01` would normalize to one value and two real phones would collapse into one record. The emitted `NetworkInterface` still goes through `network_interface`, which is correct there — the `happy` fixture asserts both halves of that divergence so a future refactor cannot quietly undo it.
- Missing-ID behavior: a record with no parseable MAC is skipped. Multicast MACs (odd first octet) and the all-zeros MAC are skipped too, because neither is an endpoint.
- **The router's own MACs are excluded.** `getHostHints` includes the router's own interfaces — it is reading a neighbor table that contains itself. Those MACs are collected first from `getNetworkDevices` and filtered out of the host set, so the router does not also appear as one of its own clients.
- Verdict: **address-derived, deliberately inert.**

The `no_mac_in_id` fixture invariant is skipped for this integration, with the
reason recorded in each scenario. It exists to catch a MAC used as an id
*without* these safeguards.

## Notes

### What is imported

| ubus call | Gated by | What it gives |
|---|---|---|
| `session login` | always | Exchanges the credential for a session id, and returns the ACL set that session was granted |
| `system board` | always | Model, board name, hostname, kernel, OpenWrt version, target |
| `system info` | always | Uptime, memory, local time |
| `luci-rpc getNetworkDevices` | always | The router's own interfaces: MAC, IPv4/IPv6, type, flags |
| `luci-rpc getHostHints` | `collect_host_hints` | MAC → addresses → name, merged from leases, neighbors, and `/etc/ethers` |
| `luci-rpc getDHCPLeases` | `collect_leases` | DHCPv4 and DHCPv6 leases with hostname, address, DUID, remaining lease time |
| `luci-rpc getWirelessDevices` | `collect_wireless` | Radios and their interfaces, with SSID |
| `iwinfo assoclist` | `collect_wireless` | Associated stations per wireless interface, with signal, noise, and idle time |

Only `ImportAsset` objects are produced. OpenWrt's `ubus` surface inventories no
installed software on other hosts, no listening services, and no
vulnerabilities, so no `Software`, `Service`, or `Vulnerability` records are
emitted.

### The ACL set is read before it is needed

`rpcd` returns the session's granted ACLs inside the `session.login` reply. This
integration reads that list and **skips any call the account cannot make**,
naming the missing grant:

```
openwrt: skipping DHCP leases (luci-rpc.getDHCPLeases): the account's rpcd ACL
does not grant luci-rpc.getDHCPLeases
```

That turns the most common misconfiguration — a hand-built read-only account
missing one group — into a message that says which line to add, instead of a
run that quietly imports less than it should. If the login reply carries no ACL
data at all, every call is attempted rather than refused.

`rpcd` wildcard grants are honored in both of their forms: a `"*"` object key
covers every object (a login granted only the `superuser` ACL group returns
exactly `{"*": ["*"]}`), and a `"*"` entry in an object's method list covers
every method on that object.

### Error handling

`ubus` over HTTP returns **HTTP 200 for everything**, and encodes the outcome
four different ways. All four are handled, and all four were captured from a
real device:

| Response | Meaning |
|---|---|
| `{"result":[0,{…}]}` | Success with a payload |
| `{"result":[0]}` | Success with an **empty** payload — a one-element array |
| `{"result":[6]}` | Failure, ubus status 6 (permission denied). No `error` key at all |
| `{"error":{"code":-32002,"message":"Access denied"}}` | Expired session, or an ACL that forbids the method |
| `{"error":{"code":-32000,"message":"Object not found"}}` | The object is not registered on this device |

Two traps follow. A script that reads `result[1]` without checking the length
aborts on both the empty-payload and the bad-password cases — and Starlark has
no exception handling, so that ends the entire run. A script that only inspects
the `error` key treats a wrong password as a successful, empty collection. The
`auth-failure` and `empty` scenarios exist to pin exactly these two.

### Address filtering

The platform drops loopback, multicast, and unspecified addresses before they
reach an asset, but deliberately **keeps** link-local. APIPA (`169.254.0.0/16`)
and IPv6 link-local (`fe80::/10`) are therefore filtered here: an address a host
invents when DHCP fails identifies nothing, and two such hosts would correlate
to each other. A host whose only addresses are link-local still imports, with
its MAC alone.

On the router's own interfaces, `lo` is dropped via the `flags.loopback` field
the API supplies, and container and VPN adapters (`docker0`, `veth*`, `wg*`,
`tun*`, and peers) are dropped by name — `docker0` in particular carries a
deterministic MAC on every host that runs Docker, so importing it would
correlate unrelated devices. `br-lan` and its bridge members are deliberately
**kept**: on OpenWrt the LAN bridge is where the device's real address lives.

### Lease expiry is not a timestamp

`getDHCPLeases` returns `expires` as **seconds remaining**, not an absolute
time. It is preserved per address family as
`openwrt_lease_ipv4_expires_seconds` / `openwrt_lease_ipv6_expires_seconds`
(so a dual-stack client holding both a DHCPv4 and a DHCPv6 lease keeps both)
and is never converted
into a timestamp, because `now + expires` is by definition in the future and the
platform rejects the **entire asset record** on a future timestamp — not the
field, the record. No `firstSeenTS` or `lastSeenTS` is set by this integration,
because OpenWrt exposes no trustworthy absolute time for any of these
observations.

### Request volume

Fixed cost is five requests (login, `system board`, `system info`,
`getNetworkDevices`, plus one each for hints and leases), and one further
request per wireless interface. A two-radio router costs about eight requests
per run; the number does not grow with the size of the estate, because every
host collection returns in a single call. `max_hosts` bounds the number of
assets built, and the run reports when it trips.

### Streaming

Host records are accumulated as compact dicts — not `ImportAsset` objects —
because the same MAC legitimately appears in several collections and must be
folded before it is emitted. The finished assets are handed to `report_asset`
one asset at a time, so peak allocation is one record rather than the estate.

### Discrepancies with the research notes

The planning notes for this integration made three claims that a real device
contradicts, and the device wins:

- **"`ubus` requires `uhttpd-mod-ubus` and ACL configuration."** Both ship and are configured on a stock image. `ubus_prefix` is already set to `/ubus` in the default `/etc/config/uhttpd`, and the `root` account already holds every ACL group needed. Nothing has to be installed or enabled.
- **"Implement the SSH path first — it works on a stock install with no extra packages."** The HTTP path also works on a stock install, and it is strictly better here: it is fixture-testable, it needs no shell access, it carries no risk of a command-injection mistake, and a least-privilege read-only account is expressible in `rpcd`'s ACL model in a way it is not over SSH, where any account that can run `ubus call` can generally run anything.
- **"`ubus call luci-rpc getDHCPLeases`."** That method takes a **required** `family` integer argument. Called without it, it fails with ubus status 4 — `Not found` — which reads exactly like the method being absent and is very easy to misdiagnose. This integration sends `{"family": 0}` to get both address families.

### Verification status

The response shapes here are not derived from documentation. They were
**captured from a real OpenWrt 24.10.8** running in a container
(`openwrt/rootfs`, `aarch64_generic`, image digest
`sha256:f6dd33c1d9b7d6f1e0848f2fbb92b8d03fc9b425dc08c3574a44936b93133704`), with
`procd` as PID 1 and the stock `uhttpd` serving `/ubus`. Confirmed against that
device:

- the default installed package set, including `uhttpd-mod-ubus`, `rpcd-mod-luci`, and `rpcd-mod-iwinfo`
- the stock `ubus_prefix` setting and the ports `uhttpd` binds
- the `session.login` request and response, including the ACL block
- the exact field names of `system board`, `system info`, `getHostHints`, `getDHCPLeases`, `getNetworkDevices`, and `getBoardJSON`
- that `getDHCPLeases` requires `family`
- that MACs are returned upper-cased, and that `getHostHints` keys its object by MAC
- all five response and error envelopes listed under [Error handling](#error-handling)

The fixture data is that capture, scrubbed: the board model, hostname, and MAC
addresses were replaced with router-shaped synthetic values, and the container's
own Docker-bridge addressing was replaced with a plausible LAN.

**Two things were not exercised on real hardware**, because the container has no
radios: `luci-rpc getWirelessDevices` returning a populated radio list, and
`iwinfo assoclist` returning stations. Their empty-payload behavior *was*
observed (`{"result":[0]}` for `getWirelessDevices` on a device with no
wireless, which is the case this integration must not break on). The populated
shapes in the fixtures come from the LuCI and `rpcd-mod-iwinfo` sources and are
the one part of this integration that a real access point should confirm. The
ACL group names in the setup instructions above were read from the LuCI source
tree, not guessed.

## Future

- **Confirm the wireless shapes against real hardware.** `getWirelessDevices` and `iwinfo assoclist` are the only calls whose populated responses were not captured from a device. An access point run would settle the `interfaces[].config.ssid` nesting and the `assoclist` station fields.
- **`iwinfo info` per radio** would add channel, band, HT mode, TX power, and country to the router asset, and would let a wireless station record which band it is actually on rather than only which SSID.
- **DHCPv6 and DUID correlation.** `luci-rpc getDUIDHints` maps DHCPv6 DUIDs to hostnames, which would let an IPv6-only client be named. Today a DHCPv6 lease imports with its MAC and address but takes its name only if the same host also appears in the v4 hints.
- **`luci getConntrackList`** enumerates live connection tuples, which would reveal hosts that have neither a lease nor a neighbor entry — a device on a foreign subnet routing through the box. It is granted by the `luci-mod-status-realtime` ACL group. It is also large and extremely volatile, so it would need its own parameter and a firm cap.
- **Services from port forwards.** The firewall configuration (`uci get firewall`) lists destination NAT rules, each naming an internal host and port. Those are `Service` objects on hosts this integration already imports, and they describe real exposure.
- **Multi-AP estates.** A site with several OpenWrt APs needs one task per device today. Since hosts are keyed on the router's hostname, the same phone seen by three APs becomes three assets that then merge on MAC. Keying hosts on the MAC alone across a fleet would be cleaner but would need a shared-scope parameter.
- **The `dhcp` ubus object.** Recent dnsmasq builds register their own `dhcp` object with `ipv4leases`/`ipv6leases`, which would remove the dependency on `rpcd-mod-luci` for lease data. It was not present on the tested build and is not in the default LuCI ACL set.

## API documentation

- [ubus reference](https://openwrt.org/docs/techref/ubus) — the object model, and the `POST /ubus` JSON-RPC transport including the all-zero session id convention.
- [`rpcd` reference](https://openwrt.org/docs/techref/rpcd) — the ACL model, `/etc/config/rpcd` login sections, the `$p$<user>` password form, and the `/usr/share/rpcd/acl.d/` group files.
- [uhttpd configuration](https://openwrt.org/docs/guide-user/services/webserver/uhttpd) — `ubus_prefix`, the listen options, `rfc1918_filter`, and the self-signed certificate.
- [LuCI JSON-RPC howto](https://github.com/openwrt/luci/wiki/JsonRpcHowTo) — background on the older `luci/rpc` interface that `uhttpd-mod-ubus` replaced.
- **ACL group definitions** come from the LuCI source: [`luci-base.json`](https://github.com/openwrt/luci/blob/master/modules/luci-base/root/usr/share/rpcd/acl.d/luci-base.json) defines `luci-base-network-status`; [`luci-mod-status-index.json`](https://github.com/openwrt/luci/blob/master/modules/luci-mod-status/root/usr/share/rpcd/acl.d/luci-mod-status-index.json) defines `luci-mod-status-index`, `luci-mod-status-index-dhcp`, and `luci-mod-status-index-wifi`.
- **`luci-rpc` method implementations** — [`modules/luci-base/root/usr/libexec/rpcd/luci`](https://github.com/openwrt/luci/tree/master/modules/luci-base/root/usr/libexec/rpcd) is where `getHostHints`, `getDHCPLeases`, and `getNetworkDevices` are defined, including the `family` argument and the sources `getHostHints` merges.

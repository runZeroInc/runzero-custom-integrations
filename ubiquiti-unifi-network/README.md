# Custom Integration: Ubiquiti Unifi Network
Custom Integration for retrieving clients and Unifi devices from the Unifi Network API
## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Ubiquiti Unifi Network requirements

- A **Network API key**, created inside the UniFi Network application. It is sent as the `X-API-KEY` header.
- The URL of the **UniFi OS console** — the Dream Machine, Cloud Key, or self-hosted host that fronts the Network application. This integration reads the UniFi OS integration API under `/proxy/network/integration/v1/`, so it needs the console's address, not a bare Network-application port.
- The **site name** exactly as it appears in the Network application. The integration lists the sites the key can see and matches on the name to find the site's UUID, so a mismatch fails with `Could not find a site with the name '<name>'` rather than importing the wrong site. The default is `Default`.
- Network reachability from the Explorer to the console over HTTPS. UniFi OS consoles present a self-signed certificate unless one has been installed, so the TLS options usually need attention.

## Steps

### Ubiquiti Unifi Network configuration

1. Sign in to the UniFi Network application on your console.
2. Go to **Settings > Control Plane > Integrations**, find **Your API Keys**, enter a name (for example `runzero`), and click **Create API Key**.
   - The key is shown **once**. Copy it immediately; if it is lost the only remedy is to delete it and create a new one.
   - The exact placement of this screen moves between Network application versions — on some releases API settings sit under **Control Plane** and on others under **Advanced**. If it is not where this document says, search the settings for "API".
   - A key created in the **UniFi Site Manager** at `unifi.ui.com` (**Settings > API Keys**) is a *different* credential for a *different*, cloud-hosted API. It is not what this integration uses.
3. Note the site name from the site selector in the Network application.
4. Confirm the key and find the site UUID from the Explorer host:

   ```bash
   curl -sk -H 'X-API-KEY: <key>' -H 'Accept: application/json' \
     https://controller.example.com/proxy/network/integration/v1/sites
   ```

   The response carries a `data` array; each entry has a `name` and an `id`. The `name` is what goes in the site name field.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **UniFi controller URL** (`url`): the UniFi OS console base URL, e.g. `https://controller.example.com`. The `/proxy/network/integration/v1/` path is appended automatically.
    - **API key** (`api_key`): the Network API key, sent as `X-API-KEY`.
    - **Site name** (`site_name`): optional; the site to import, matched by name against the sites list (default: `Default`).
    - **Extract clients** (`extract_clients`): optional; import connected clients (default: enabled).
    - **Extract devices** (`extract_devices`): optional; import UniFi devices — access points, switches, gateways (default: enabled).
    - **Client API filter** (`client_api_filter`): optional; a UniFi filter expression passed straight through as the `filter` query parameter on the clients call.
    - **Page size** (`page_limit`): optional; records requested per page, 1–200 (default: 100). The Integration API documents a 200-row maximum, and the script clamps a larger value down to 200 with a log line.
    - **TLS options** (`tls_*`): set `tls_disable_validation` or supply `tls_ca_cert` if the console uses its stock self-signed certificate.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "unifi").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
    - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields above.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 1 and 2.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename ubiquiti-unifi-network/ubiquiti-unifi-network.star \
  --kwargs url=https://controller.example.com \
  --kwargs api_key=Xy7Qa2Lm9PdR4Tz1Nk6Vb8Wc \
  --kwargs site_name=Default \
  --kwargs extract_clients=true \
  --kwargs extract_devices=true \
  --kwargs page_limit=50 \
  --kwargs tls_disable_validation=true \
  --output ./unifi-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

The run starts by resolving the site name to a UUID and logs both, so
`Could not find a site with the name '<name>'` in the output means the name does not match
any site the key can see — list them with the `curl` command above and use the `name` value
verbatim. `tls_disable_validation=true` is usually needed against a stock console
certificate.

**`client_api_filter` is the one parameter that needs care on the command line.** `--kwargs`
takes its value verbatim as long as the whole argument holds a single `=`, so a comma on its
own is harmless — `--kwargs 'client_api_filter=eq(type,WIRED)'` arrives intact. What breaks is
a value carrying **both** a second `=` and a comma: the flag then parses the argument as a CSV
record, so `--kwargs 'x=a=b,c=d'` yields `x=a=b` plus a fabricated parameter `c="d"`. UniFi
filter expressions can easily contain both. Wrap the whole argument in a second pair of quotes
when one does:

```bash
  --kwargs '"client_api_filter=eq(type,WIRED),eq(x,y=z)"'
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live console:

```bash
runzero script --filename ubiquiti-unifi-network/ubiquiti-unifi-network.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove UniFi accepts the key or that any client or device is parsed.

The recorded API shapes, including paging, are exercised by the fixture suite:

```bash
python3 tests/run.py ubiquiti-unifi-network
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat ubiquiti-unifi-network/ubiquiti-unifi-network.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://controller.example.com,api_key=<key>,site_name=Default' \
  --output ./unifi-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
`client_api_filter` expression containing a comma cannot be passed this way; prefer
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ubiquiti-unifi-network`. The slug is the script's `CONFIG` id (`runzero-ubiquiti-unifi-network`) with the `runzero-` prefix removed, not the display name you type; if it returns nothing, check the name you gave the integration in the console.

## Asset identity

This integration emits **two kinds of asset** from one run — UniFi devices (the infrastructure:
access points, switches, gateways) and clients (everything connected to them) — and both use
**the same identity scheme**, which is the thing worth understanding here.

- Target entity:
  - **Devices**, from `GET /proxy/network/integration/v1/sites/{site}/devices` — UniFi hardware the console adopted and manages.
  - **Clients**, from `GET /proxy/network/integration/v1/sites/{site}/clients` — anything the controller has seen attached, wired or wireless, UniFi or not.
- Source ID field: **`id`, for both kinds** — the controller's own per-site record identifier, returned on every client and every device row.
- Documentation evidence: it is the API's own answer. Both collections are addressed as `/sites/{siteId}/{clients,devices}`, and the `id` on each row is the value the console keys that record by. It is a UUID on every controller release observed.
- Uniqueness scope: **one site on one controller.** The id is issued per site, so the site id is part of the key. That also namespaces the value: two controllers, or two sites on one controller, cannot collide in a single runZero account.
- Cardinality: one asset per record per collection. Note the change from the previous scheme here: a switch that the controller reports **both** as a device and as a client of its uplink now produces **two** assets rather than one, because it holds a different `id` in each collection. Under the old MAC-keyed scheme those collided into a single asset. The two still merge on the shared MAC and address unless something else disqualifies it — but that merge is now runZero's decision, made on real correlating evidence, rather than an artifact of two records happening to be keyed by the same string.
- Stability: **survives the churn that broke the old scheme.** A Wi-Fi client that re-randomizes its per-SSID MAC keeps its `id`, as does one that renews onto a different address or gets renamed. iOS, Android, Windows, and macOS all randomize by default, so on a client-heavy site this was the dominant source of asset churn.
- Reuse behavior: not documented by Ubiquiti. A UUID makes reassignment implausible on shape alone. A client the controller forgets and later re-learns does get a new record, and therefore a new asset.
- Presence: on every row in both collections.
- Final runZero ID: `unifi:<siteId>:client:<id>` and `unifi:<siteId>:device:<id>`, for example `unifi:4f1a…site:device:d0000000-…-0000000000sw`.
- Missing-ID behavior: skip and log — `unifi: skipping client with no id: mac=…` / `unifi: skipping device with no id: mac=…`. No identity is synthesized and `new_uuid()` is never used.
- A record with **no MAC** is also skipped, and now logged (`unifi: skipping client <id> with no MAC: name=…`). This is unchanged behavior: such a record has nothing to correlate on beyond a lease address the controller may already have handed to something else.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`.** The controller's id is authoritative and drives the merge; the network identifiers must not veto one, because the whole point of moving off the MAC was that a client's MAC and address change underneath a stable record.
- Verdict: **authoritative within one site**, namespaced by the site id.

### This is a breaking change for existing deployments

**Every asset this integration has ever imported changes its foreign id in one run.** The old id was the raw MAC string; the new one is `unifi:<siteId>:<kind>:<id>`. There is no migration path inside the script, because the old id cannot be derived from the new one for a client whose MAC has since changed — which is exactly the population the change exists to fix.

What to expect on the first run after upgrading:

- Every UniFi-sourced asset is imported under a new foreign id. Where the MAC and address still agree, `no-mac-break no-ip-break no-name-break` lets the new record merge onto the existing runZero asset, so most of the estate lands where it should.
- The old MAC-keyed foreign id remains attached to whatever asset carried it until it ages out. Assets that no longer correlate — a client that re-randomized its MAC since the last import — will not merge, and the stale one should be retired.
- A switch reported in both collections splits from one asset into two records, as described above.

Plan the first run after upgrading like a re-import rather than an incremental poll, and expect the asset count to move.

### Why the id and not the MAC

The governing rule has two branches, and the previous scheme sat between them without satisfying either.

The UniFi `id` is a persistent remote identifier — a per-site UUID, surviving a client's MAC randomizing, and the value the API itself addresses a record by. The rule for that case says: key on `id`, and set `no-mac-break no-ip-break no-name-break` so churn in the network identifiers cannot fragment the asset. That is what the script now does.

The alternative branch — treat the MAC as scan-derived data, set `no-id-match no-id-break`, and correlate on MAC, IP, and hostname, as `opnsense`, `openwrt`, `pihole`, `adguard-home`, `netdisco`, and `ntopng` do — is the right answer for a source that has *no* vendor-assigned identifier. UniFi has one, so it is not the right answer here.

The old code did neither: it used the MAC *as* the foreign id with `id-match` on, collapsing the two paths onto one value. That was stable for wired infrastructure and merged reliably onto scanned assets, but it carried three costs the change removes:

- **It fragmented on Wi-Fi client randomization.** A new MAC was a new foreign id and a new runZero asset, with the old one going stale.
- **It was sensitive to formatting.** The raw string went in with no normalization — not lower-cased, not stripped of separators, never passed through `normalize_mac` — so a controller release that changed the casing or separator it returns would have changed every asset's identity in one run.
- **It put a MAC in an identity field.** `network_interface` and `normalize_mac` clear the locally administered bit for cross-source matching, so two distinct randomizing endpoints can normalize to one value. That is correct for an interface and wrong for identity, and it is what the repository's `no_mac_in_id` invariant exists to catch — an invariant this integration's scenarios previously had to skip, and no longer do.

`tests/run.py ubiquiti-unifi-network` covers this: `identity-stability` asserts the emitted ids are the controller's, asserts by id that no MAC-keyed asset appears, and pins the resolved `_match.behavior`.

### Notes

- **Client and device names are screened before use.** UniFi names an unnamed client after the last two octets of its MAC (`Some Device a1:b2`), so when `name` ends with that suffix the suffix is stripped. After that, a name is imported as a hostname **only when it is shaped like one**: free-text display labels such as `Kitchen TV` — a space or any other character that cannot appear in a DNS name — stay in the `unifi_name` attribute instead of becoming a weak merge key. The same screening applies to device names.
- **Pagination stops are visible.** `totalCount` is the only forward signal the clients and devices walks have; a response that omits it, or reports zero alongside a non-empty page, stops the walk after that page **and says so** (`carried no usable totalCount; stopping after this page`). Each walk is also guarded by a `pager()` bound so a controller that ignored `offset` cannot spin a run forever.
- **The site lookup is paginated too.** The lookup walks `/sites` with `offset`/`limit` until the named site is found, so an MSP console with more sites than one page can still resolve a site beyond page one.
- **A client contributes at most one address**, from `ipAddress`, and a device likewise. Neither endpoint returns an address list.
- **`deviceType` for UniFi hardware is inferred from the model string** — `USW` becomes `Switch`, `UAP` or `U6` becomes `WAP`, `UDM` or `USG` becomes `Gateway`, and **an unrecognized model leaves the field unset**. Clients get no device type at all, which is correct: the controller does not classify them and runZero's own fingerprinting is better placed to.

  The field used to be set to the literal `"Unknown"`, which is not one of runZero's device types. Asserting it overwrote whatever the platform's own fingerprinting had worked out with a value that means nothing, so a UXG, a UCG, a UniFi camera, or any model added after this mapping was written arrived typed as `Unknown` rather than as whatever runZero could tell it was. Leaving the field unset lets runZero keep its own answer.
- **`connectedAt` is screened before parsing.** The controller omits it for a client it has a record of but no active session — a wired client seen only in the ARP table, or one whose session predates a controller restart — and `parse_time(None)` aborts the entire run. The value is regex-checked first and `connectedAt.unix` is only read when it parsed.
- **The site is resolved by name to a UUID on every run**, so renaming a site in the Network application breaks the task until the credential is updated. The failure is explicit (`Could not find a site with the name '<name>'`) rather than silent.
- **`extract_clients` and `extract_devices` are independent and both default on.** Turning clients off leaves only managed infrastructure, which is a much smaller and much more stable import — a reasonable first configuration on a large wireless site.

## Future

- **Per-device port and radio detail.** `GET /proxy/network/integration/v1/sites/{site}/devices/{deviceId}` returns the full device record — per-port status, PoE state, radio configuration, uplink relationships. The `interfaces` and `features` lists this integration currently flattens into comma-joined attributes are the summary of it. Port-level data would let runZero describe **which switch port a client is on**, which is topology information no scan can produce and which is the single most requested thing from a network-controller integration.
- **Client uplink as a topology graph.** The client record already carries `uplinkDeviceId`, and this integration imports it as an attribute without resolving it. Joining it to the device collection — both are already fetched — would turn a flat list of clients into a map of what is attached to what, with no additional API call at all.
- **WLAN and network configuration.** The integration API exposes the site's networks and WLANs, which describe VLANs, subnets, and SSIDs. That is segmentation context: it would let runZero say which VLAN a client sits in rather than inferring it from an address, and it would identify guest and IoT networks explicitly.
- **Device statistics and health.** The device endpoints carry uptime, load, temperature, and traffic counters. Useful as attributes, and `state` (already imported) plus uptime would separate an access point that is down from one that was never adopted.
- **Historical clients rather than current ones.** The clients endpoint returns what the controller currently knows about. UniFi retains far more history than that, and a device that connects once a week is easy to miss entirely on a scheduled poll. If the integration API exposes a time-bounded client query, using it would materially improve coverage of intermittent devices — this is the most likely cause of "runZero sees a device that UniFi does not".
- **Outbound: runZero verdicts as UniFi client policy.** This is where the leverage is, and also where the risk is. UniFi supports per-client naming, notes, blocking, and firewall-group membership, and the integration API's write surface can reach them. A runZero query — an unmanaged device, a device on the wrong VLAN, a rogue access point — could name, tag, or block a client through `POST`/`PUT` on the client and firewall-group resources. Naming and tagging are safe and immediately useful; **blocking cuts network access for a real device** and needs a far tighter confirmation model than a scheduled read, plus an API key with write scope rather than the read key this integration asks for.
- **Rogue and neighbouring access points.** UniFi scans for nearby APs it does not manage. That is a discovery source runZero has no equivalent for — wireless infrastructure that is physically present but not on any wired segment an Explorer can reach — and it is one of the few places a network controller can tell runZero about something genuinely invisible to it.
- **There is no event or alert feed on this API.** The integration API is a paged resource interface with `offset`/`limit` and no change cursor, webhook, or event stream. UniFi's own alerting is internal to the console. Anything near-real-time would be re-paging the clients collection on a short schedule, which on a large site is the most expensive thing this integration does.
- **Site Manager is a different API and already has its own integration.** A key created at `unifi.ui.com` addresses Ubiquiti's cloud-hosted Site Manager API, which is covered by `ubiquiti-unifi-site-manager` in this repository. It gives a multi-console view without an Explorer inside each site's network; it is not a substitute for this one, because it does not expose per-client detail at this depth.

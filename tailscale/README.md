# Custom Integration: Tailscale API

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with outbound HTTPS access to `api.tailscale.com`.

## Tailscale requirements

- A tailnet, and an account holding one of the roles that can mint credentials for it: **Owner**, **Admin**, **Network admin**, or **IT admin**.
- Your **tailnet** name or ID. This is a required parameter — see below for where to find it.
- **Either** an API access token **or** an OAuth client. Both are described below; the choice matters for how often the credential has to be replaced.

### Choosing between an API access token and an OAuth client

| | API access token | OAuth client |
|---|---|---|
| Created under | **Settings → Keys** | **Settings → Trust credentials** |
| Value looks like | `tskey-api-…` | a client ID plus a client secret |
| Lifetime | 1–90 days, chosen at creation; **90 days is the maximum** | the client does not expire; the access token it mints lasts **one hour**, and this cannot be changed |
| Rotation | manual, at least every 90 days | none — the script exchanges the client for a fresh token on every run |

For a scheduled integration the OAuth client is the better choice. An API access
token has to be replaced by hand at least four times a year, and the task starts
failing silently on the day it lapses. The one-hour token life is not a drawback
here because the script performs the exchange itself at the start of each run.

The page for OAuth clients is now called **Trust credentials**
(`https://login.tailscale.com/admin/settings/trust-credentials`). Older
documentation calls it "OAuth clients"; it is the same page under a new name.

### Finding your tailnet

The **Tailnet ID** is on the **General** page of the admin console, and the
tailnet DNS name is on the **DNS** page. Either is accepted. A tailnet name takes
one of these forms:

- a default name: `tailnet-fe8c.ts.net`
- a randomized name: `cat-crocodile.ts.net`
- a legacy custom domain or email address: `example.com`

Some Tailscale tooling accepts `-` as an alias for "the default tailnet of the
authenticated user". That alias could not be confirmed in Tailscale's own
documentation, so this integration requires an explicit tailnet and does not
default to it.

## Steps

### Tailscale configuration

1. Log into the [Tailscale admin console](https://login.tailscale.com/admin/settings).
2. Note your tailnet from the **General** page, as described above.
3. Create **one** of the following:

   * **Option 1 – OAuth client (recommended):**
     Go to **Settings → Trust credentials** and create a client with the single
     scope **`devices:core:read`** ("read devices in the tailnet"). Record the
     client ID and secret; the secret is shown once.

     Grant only that scope. This integration requests `devices:core:read` and
     nothing else when it exchanges the client for a token, so `devices:routes`
     and `devices:posture_attributes` add permission the script will not use.
     Tags are not needed either: Tailscale requires them only for the
     `devices:core`, `auth_keys`, and `all` **write** scopes, and the read-only
     scope is not one of them.
   * **Option 2 – API access token:**
     Go to **Settings → Keys → Generate access token**, choose an expiry between
     1 and 90 days, and record the `tskey-api-…` value. An access token carries
     the permissions of the user who created it rather than a narrowed scope,
     which is the second reason to prefer the OAuth client.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).

   * Select **Custom Integration Script Secrets**.
   * **Tailscale API URL** (`url`): optional; defaults to `https://api.tailscale.com`. The `/api/v2` path is appended automatically, so give a host only.
   * **Tailnet** (`tailnet`): **required**; the tailnet ID or name from the General page, for example `cat-crocodile.ts.net` or `example.com`.
   * **OAuth client ID** (`client_id`): the OAuth client ID. **Leave blank when using an API access token** — its presence is what selects OAuth mode.
   * **API key / OAuth client secret** (`api_key_or_client_secret`): the OAuth client secret, or the `tskey-api-…` token.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).

   * Add a descriptive name (e.g., `tailscale-sync`).
   * Toggle **Enable custom integration script** and paste the finalized script.
   * Click **Validate** to confirm syntax, then **Save**.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).

   * Select the Credential and Custom Integration created above.
   * Adjust the task schedule to your preferred frequency.
   * Select an Explorer to execute the task.
   * Click **Save** to start the integration.

### Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real tailnet returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair. With an OAuth client:

```bash
runzero script --filename tailscale/tailscale.star \
  --kwargs tailnet=cat-crocodile.ts.net \
  --kwargs client_id=k7Hs2Qw9Lp1CNTRL \
  --kwargs api_key_or_client_secret=tskey-client-k7Hs2Qw9Lp1CNTRL-b3F5aXplZmFrZXNlY3JldA \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/tailscale-run --overwrite
```

With an API access token, omit `client_id` entirely — its presence is the switch
that selects OAuth mode, and an empty value is treated the same as absent:

```bash
runzero script --filename tailscale/tailscale.star \
  --kwargs tailnet=cat-crocodile.ts.net \
  --kwargs api_key_or_client_secret=tskey-api-....
```

The script logs which mode it chose — `Detected OAuth client credentials mode.`
or `Detected API key mode.` — as its first line, which is the quickest way to
confirm the credential was interpreted the way you intended.

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

There is no page-size or limit parameter: the Tailscale devices endpoint returns
the whole tailnet in one response, requested with `?fields=all`. A first run
therefore reads every device regardless of what you pass.

`url` is optional and defaults to `https://api.tailscale.com`. It is read with
`get_url_base()`, so it takes a host and the script appends `/api/v2` and
`/api/v2/oauth/token` itself.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching Tailscale:

```bash
runzero script --filename tailscale/tailscale.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never completes a real token
exchange and never parses a real device row.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'tailnet=cat-crocodile.ts.net,client_id=k7Hs2Qw9Lp1CNTRL,api_key_or_client_secret=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tailnet:

```bash
python3 tests/run.py tailscale
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

### What's next?

* The task will execute and retrieve device data from the Tailscale API.
* Each Tailscale device will be imported as a `runZero ImportAsset`.
* You can view the integration run under [Tasks](https://console.runzero.com/tasks) in the runZero console.
* You can search for assets enriched by this custom integration with the runZero search `custom_integration:tailscale`.

## Asset identity

- Target entity: a node in a Tailscale tailnet — any machine, container, or appliance running the Tailscale client, plus subnet routers and exit nodes. Devices **shared into** the tailnet from another tailnet also appear, flagged `isExternal`; see below.
- Source ID field: `id` on each device from `GET /api/v2/tailnet/{tailnet}/devices?fields=all`. A device whose `id` is empty is skipped.
- Documentation evidence: `id` is the device identifier the v2 API addresses individual devices with — `GET`, `DELETE`, and the routes, tags, key, and IP sub-resources are all `/api/v2/device/{deviceId}/...`. Tailscale documents it as the device's unique identifier and, in current API documentation, describes it as the legacy numeric form alongside a newer `nodeId` (the `n`-prefixed value). Both address the same device; this integration uses `id`.
- Uniqueness scope: **none is asserted, and this is the honest weakness of this integration.** The final id is `"tailscale-" + device_id` — a constant prefix and the raw device id, with **no tailnet in it**, even though `tailnet` is a required parameter, is validated against a pattern, and is already recorded on every asset as the `tailscale_tailnet` custom attribute.

  Two things make this less alarming than it sounds, and neither makes it correct:

  - Tailscale device ids appear to be allocated from a single global namespace across the coordination server rather than per tailnet, so an accidental collision between two tailnets is unlikely. But that is an inference from how the ids look and behave, not a published guarantee, and the API reference does not state it.
  - One credential addresses one tailnet, so the exposure is limited to an organization importing two tailnets into one runZero organization.

  Every other integration in this library that faces this choice scopes its ids — `snipe-it` on the instance hostname, `proxmox` and `nutanix-prism` on the cluster, `uptycs` on the customer. This one relies on the value instead of on the namespace, which is a weaker position to be in and is worth recording plainly rather than glossing.
- Cardinality: one asset per device. A device with several Tailscale addresses is still one record with one interface; its physical endpoints ride along as an attribute.
- Stability: the device id survives rename, address change, key rotation, OS upgrade, and re-authentication. **Removing a device from the tailnet and re-joining it mints a new id** — a fresh `tailscale up` after a removal is a new node, not the old one returning — so an estate that re-enrolls devices routinely will accumulate stale assets. That produces duplicates rather than collisions.
- Reuse behavior: not documented. The ids are opaque and there is no evidence of recycling.
- Presence: present on every device in the documented response. The guard exists because a missing id would otherwise produce `"tailscale-"` as an id, shared by every such record.
- Final runZero ID: `tailscale-<device id>`.
- Missing-ID behavior: `transform_device_to_importasset` returns `None` and the device is dropped from the batch. Note that this one is silent — unlike the no-interface case immediately below it, which logs.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative in practice, unscoped by construction.

### Why the default `matchBehavior` is kept, and what these interfaces actually are

The device id is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it. What deserves more attention than the flags is **what this source contributes to match on**, because it is unlike every other integration here.

One interface is built, and one address set deliberately is not:

- **The Tailscale interface**, from `addresses` — the node's `100.64.0.0/10` CGNAT address and its `fd7a:115c:a1e0::/48` IPv6 address. These are **overlay** addresses. They exist only inside the tailnet, they are not routable anywhere runZero scans, and no active scan will ever observe one. They are excellent for identity and useless for correlating against a scanned asset.
- **The physical endpoints**, from `clientConnectivity.endpoints` — the public and private addresses the client last advertised for direct connections — are kept as the `tailscale_client_endpoints` custom attribute and **never placed on an interface**. The list includes the public NAT egress address, which every device in the same office shares; importing it as interface data made dozens of devices carry the same public IP and invited cross-device correlation under the default `matchBehavior`. The private endpoint (`192.168.1.20:41641`, the device's real LAN address) is still in the attribute for an operator to pivot on.

That has a direct consequence: a Tailscale device carries only overlay addresses as interface data and effectively cannot merge onto a scanned asset by IP at all. **No MAC address is available from this API**, so hostname is the only remaining signal.

The hostname situation is itself a deliberate choice worth knowing. Tailscale exposes two names and the script uses them differently:

- `name` is the **MagicDNS FQDN** (`my-laptop.tailnet.ts.net`), a valid DNS hostname, and it is what gets asserted as the runZero hostname.
- `hostname` is the **raw machine name**, which can contain spaces and apostrophes (`Andrew's Work Laptop (2)`) and would be rejected as a bogus hostname. It is kept as the `tailscale_machine_name` attribute only.

That is correct, and it also means the asserted hostname is a `.ts.net` name that no scan will ever resolve — so `name-break` staying on is harmless here rather than protective, and relaxing it would buy nothing.

The last thing to note is **`isExternal`**. Devices shared into your tailnet from another tailnet are returned by this endpoint and are imported like any other, carrying `tailscale_is_external=True`. They are somebody else's machines. Filtering them out is not currently possible from the credential and would be a reasonable parameter to add.

### Notes

* The integration selects its authentication mode from `client_id`: supply it and the script exchanges the client credentials for an access token, leave it blank and `api_key_or_client_secret` is used directly as a bearer token. A failed exchange (revoked secret, wrong client id) ends the run with a printed `OAuth token exchange failed: ...` diagnostic and zero assets rather than a raw abort.
* Assets are streamed one device at a time via `report_asset`, so a malformed record late in the walk costs only itself, and everything reported before an interruption survives.
* The OAuth exchange requests the scope `devices:core:read` and no other. A client granted `devices:routes:read` or `devices:posture_attributes:read` as well will not have those scopes on the token this script mints, so any data gated behind them is not returned.
* A `403` means the credential authenticated but is not permitted to read devices in this tailnet — check the scope on the OAuth client, or the role of the user who created the access token.
* An empty result with no error is usually the wrong `tailnet`, not a bad credential. The API answers for the tailnet you name, and naming one you cannot see returns nothing useful.
* `tailnet` is a required `CONFIG` parameter, not a constant in the script. There is nothing to edit in the source to point this at a different tailnet — create a second credential and a second task instead.
* Device metadata, tags, and IP addresses from Tailscale are mapped to `runZero` custom attributes and interfaces.
* **A device with no usable interface is skipped**, with `WARN: Skipping device <id> - no network interfaces available`. Since the Tailscale addresses are effectively always present, this fires only for a genuinely malformed record.
* The Tailscale client itself is reported as installed `Software`, versioned from `clientVersion`, so client-version drift across a fleet is searchable in runZero's software inventory.
* `CONFIG` sets three forward-looking keys — `assetType: "device"`, `ownershipAttributes: ["tailscale_user"]`, and `trustOS: True`. A runZero build that predates them ignores them and the integration behaves exactly as before. `sourceId`/`sourceName` are deliberately **not** set: they bind a script to a fixed native source identity and are reserved for platform-embedded integrations.
* DERP relay latency per region is flattened into `tailscale_latency_ms_<region>` attributes, with the preferred region recorded separately — useful for spotting devices relaying rather than connecting directly.

## Future

- **Scope the id on the tailnet.** Not a new capability, but the change with the clearest justification: `tailnet` is required, validated, and already stored on every asset. Making the id `tailscale:<tailnet>:<device id>` would bring this in line with the rest of the library and remove a reliance on an undocumented property of Tailscale's id allocation. It is a breaking change for existing assets, which is the only reason to think about it carefully rather than just doing it.
- **Subnet routes as network topology — the highest-value addition.** `GET /api/v2/device/{deviceId}/routes` returns each device's advertised and enabled subnet routes, and the device record this integration already reads carries `advertisedRoutes` and `enabledRoutes` (both currently imported only as flattened string attributes). Those routes are a **map of which internal networks are reachable through which node**, which is exactly the input a runZero scan-scope decision wants: a subnet router advertising `10.20.0.0/16` is telling you there is an estate behind it that no Explorer may be covering. Turning that into a coverage report, or into suggested scan targets, is the most distinctive thing this pairing could do.
- **Device posture attributes as findings.** `GET /api/v2/device/{deviceId}/attributes` returns posture attributes — OS version, disk encryption state, and custom attributes an operator sets — behind the `devices:posture_attributes:read` scope this integration deliberately does not request. Posture data is directly expressible as runZero findings on the assets already created, and the join key is the device id already in hand. Adding it means widening the requested scope, which is a real trade against the least-privilege position the setup notes argue for.
- **ACL and tag data as segmentation context.** `GET /api/v2/tailnet/{tailnet}/acl` returns the tailnet policy file, which defines which tags may reach which. Device tags are already imported (as runZero tags and as `tailscale_tags`), so joining them against the policy would let runZero describe what a device is *permitted* to reach, not just what it is. Very few sources can supply intended-segmentation data at all.
- **Key expiry and device lifecycle as an operational report.** The device record carries `keyExpiryDisabled`, `expires`, `authorized`, and `updateAvailable`, and this integration imports the first, third, and fourth as attributes. `GET /api/v2/tailnet/{tailnet}/keys` covers the auth keys themselves. Together they answer "which nodes are about to lose access", "which are running an outdated client", and "which have key expiry disabled" — the last being a standing security exception that nobody tracks.
- **Outbound: authorize, tag, or remove devices from runZero.** This is where the API is genuinely writable. `POST /api/v2/device/{deviceId}/authorized` approves a node on a tailnet with device approval enabled; `POST /api/v2/device/{deviceId}/tags` sets its tags; `DELETE /api/v2/device/{deviceId}` removes it. A runZero verdict could drive any of them — tagging is the safe and useful one, since Tailscale ACLs are written against tags, so runZero's classification could directly shape network policy. Authorization and deletion are a different matter: both change live network access, and deletion is irreversible in the sense that the node must re-enroll and will get a new id. Any such integration needs a far tighter confirmation model than a scheduled read, and a much broader OAuth scope than `devices:core:read`.
- **Audit log ingestion as an event feed.** Tailscale exposes tailnet audit logging, and it is the only push-shaped surface in the product — the devices endpoint has no webhook, no cursor, and no change token, so this integration is a full sweep on every run by necessity. An audit-log consumer would catch node joins, removals, tag changes, and key events as they happen, which is what a security team actually wants from a network overlay.
- **Coverage-gap reporting works in both directions today.** Devices imported here whose physical endpoints have never appeared in a runZero scan are machines connected to the corporate estate over the overlay that no Explorer reaches — remote workers, cloud instances, contractor laptops. In reverse, runZero assets that ought to be on the tailnet and carry no `custom_integration:tailscale` source are Tailscale deployment gaps. The first direction is the interesting one and it needs no new endpoint, only the `tailscale_client_endpoints` attribute already imported.
- **There is no paging to add and none needed.** `GET /api/v2/tailnet/{tailnet}/devices?fields=all` returns the whole tailnet in one response. That is simple and it is also the ceiling: a very large tailnet is a single large response with no way to bound it from the credential.
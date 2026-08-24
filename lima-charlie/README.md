# Custom Integration: Lima Charlie

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Lima Charlie requirements

- The **Organization ID** (`oid`) of the LimaCharlie organization to import from. This is a UUID identifying the tenant.
- An **Organization API key** with permission to list sensors.
- Two endpoints, both defaulted in the script and rarely changed: the token-exchange host `https://jwt.limacharlie.io` and the API base `https://api.limacharlie.io/v1`.

### Creating the API key

LimaCharlie manages API keys through the **Organization view** of the
[limacharlie.io](https://limacharlie.io) web interface; the per-key privilege
list is under the **REST API** section of the organization. LimaCharlie's
documentation does not enumerate the exact left-navigation items, so a
click-by-click path is not reproduced here — look for API keys within the
organization you want to import.

Prefer an **Organization API key** over a User API key. LimaCharlie describes
user keys as "very powerful but also riskier to manage", because they carry that
user's access across every organization they belong to rather than being scoped
to one tenant.

**Permissions.** API keys are individual permission toggles rather than roles.
Grant:

- **`sensor.list`** — "List all sensors in organization". This is what
  `GET /v1/sensors/{oid}`, the only endpoint this integration calls, is for.

Add **`sensor.get`** ("View detailed sensor information") only if fields come
back missing. LimaCharlie's API specification carries no per-endpoint permission
annotations, so the precise requirement for the sensor list endpoint could not be
confirmed from vendor documentation; `sensor.list` is the documented match by
description. Do not grant `sensor.task`, `sensor.del`, or `sensor.tag` — this
integration never writes.

The predefined roles (Owner, Administrator, Operator, Viewer, Basic) apply to
**users**, not to API keys, so they are not the right lever here.

### Finding the Organization ID

The `oid` is a UUID identifying your tenant. LimaCharlie's reference defines what
it is but does not document where the web interface displays it, so no menu path
is given here. It appears in the URL of the organization view and in the
organization's settings; if you cannot find it, it is also returned by
LimaCharlie's own CLI and API for any authenticated user.

## Steps

### Lima Charlie configuration

1. Note the Organization ID (`oid`) of the organization to import.
2. Create an Organization API key with `sensor.list`, as described above, and copy its secret.
3. Test the credentials by hand. The exchange returns a JWT that is valid for **one hour**:

   ```bash
   curl -s -X POST 'https://jwt.limacharlie.io' \
     --header 'Content-Type: application/x-www-form-urlencoded' \
     --data 'oid=11111111-2222-3333-4444-555555555555&secret=<api key>'
   ```

   The response is `{"jwt": "..."}`. Use that value to read the sensor list:

   ```bash
   curl -s -H 'Authorization: Bearer <jwt>' \
     'https://api.limacharlie.io/v1/sensors/11111111-2222-3333-4444-555555555555'
   ```

   The integration performs the same exchange, passing the organization as a
   query parameter and the secret BOTH in an `X-LC-Secret` header and in the
   form body shown above. The header form is undocumented but accepted; the
   body form is the one LimaCharlie documents and both official SDKs use.
   Sending both means a vendor-side tightening to the documented contract
   cannot break the exchange.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Set CUSTOM_ATTRIBS_TO_IGNORE. By default, sid, hostname, mac_addr, int_ip and ext_ip are ignored because they are redundant with core runZero attributes. All other attributes returned by API will be imported.
    - Set boolean values in ARCHITECTURE to control what sensor architectures are imported. By default, chromium and usp_adapter sensors are not imported because they do not represent traditional cyber assets. Only architectures explicitly set to False are filtered; a sensor with no arch field, or a value the map does not list, is imported. 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Organization ID (OID)** (`organization_id`): the UUID of the LimaCharlie organization to import.
    - **API access token** (`api_token`): the Organization API key secret.
    - **LimaCharlie API URL** (`url`): optional; defaults to `https://api.limacharlie.io/v1`. Override only for a regional or self-hosted deployment. Note the `/v1` is part of the value.
    - **LimaCharlie JWT URL** (`jwt_url`): optional; defaults to `https://jwt.limacharlie.io`. Token exchange lives on a different host to the API, which is why there are two URL parameters rather than one.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "lima-charlie").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:lima-charlie`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm an
API key and see what a real organization returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair. Only two are required — both URLs have working
defaults:

```bash
runzero script --filename lima-charlie/lima-charlie.star \
  --kwargs organization_id=11111111-2222-3333-4444-555555555555 \
  --kwargs api_token=7c1f9ab4-3d52-4e08-9a6b-0f2e8d47c3b1 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/limacharlie-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

To point at a regional or self-hosted deployment, override both hosts — they are
separate services and overriding only one will not work:

```bash
runzero script --filename lima-charlie/lima-charlie.star \
  --kwargs url=https://api.limacharlie.io/v1 \
  --kwargs jwt_url=https://jwt.limacharlie.io \
  --kwargs organization_id=11111111-2222-3333-4444-555555555555 \
  --kwargs api_token=7c1f9ab4-3d52-4e08-9a6b-0f2e8d47c3b1
```

The run has two distinct failure points, and the log distinguishes them:

- `No JWT returned for organization <oid>` means the **token exchange** failed —
  a wrong `oid`, a wrong secret, or a key without the necessary permission. The
  run stops there and reads no sensors.
- `Failed to fetch sensors` means the JWT was minted but the sensor list call was
  refused, which points at the key's permissions rather than its identity. Grant
  `sensor.list`.

`GET /v1/sensors/{oid}` is paged with a continuation token and the script follows
it, so a first run reads the whole organization however large it is. See
**Pagination** below. There is no credential field for the page size — LimaCharlie
documents no default or maximum for `limit`, so the script leaves it unset and
takes the backend default.

Two filters live in the script rather than in parameters, and both affect what
you see in the output:

- `ARCHITECTURE` selects which sensor architectures are imported. `chromium` and
  `usp_adapter` are **excluded by default** because they do not represent
  traditional assets, so the imported count is normally lower than the sensor
  count in the LimaCharlie console. That difference is expected, not a bug.
- `CUSTOM_ATTRIBS_TO_IGNORE` drops `sid`, `hostname`, `mac_addr`, `int_ip`, and
  `ext_ip` from custom attributes, because they are already mapped onto core
  runZero fields.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching LimaCharlie:

```bash
runzero script --filename lima-charlie/lima-charlie.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never completes a real token
exchange and never parses a real sensor.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'organization_id=11111111-2222-3333-4444-555555555555,api_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a LimaCharlie organization:

```bash
python3 tests/run.py lima-charlie
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a **LimaCharlie sensor** — one row per enrolled agent in the organization. Note that LimaCharlie's sensor concept is broader than an endpoint agent: the same collection carries the roughly fifty telemetry-source adapters (CrowdStrike, Okta, Office 365, and the rest), which are log connectors rather than devices. The `ARCHITECTURE` filter is what keeps `chromium` and `usp_adapter` out; the remaining adapter platforms are simply left untyped.
- Source ID field: `sid`, from `GET /v1/sensors/{oid}`.
- Documentation evidence: `sid` is LimaCharlie's sensor identifier and the value every per-sensor operation in the API is addressed by. It is a UUID.
- Uniqueness scope: **global.** Because it is a UUID rather than an organization-scoped counter, two LimaCharlie organizations imported through one custom integration cannot collide, even though the value is used bare with no `oid` prefix.
- Cardinality: one source row per sensor.
- Stability: the id is assigned at sensor enrollment and survives rename, address change, reboot, and sensor upgrade. It does **not** survive an uninstall and reinstall, which enrolls a new sensor with a new `sid`.
- Reuse behavior: not documented; a UUID makes reassignment implausible on shape alone.
- Presence: expected on every sensor. A record without one — the shape returned for a partially provisioned or deleted sensor — is skipped and logged. It used to reach `ImportAsset` with `id=None`, which the runtime rejects with `id must be a string`; with no exceptions in Starlark that aborted the whole run, so one malformed row cost every sensor in the response.
- Final runZero ID: the raw `sid`.
- Missing-ID behavior: skip and log — `lima-charlie: skipping sensor with no sid: hostname=…`. No identity is synthesized and `new_uuid()` is never used. Pinned by the `null-sid` scenario.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: a persistent per-sensor UUID issued by the platform, used directly, is exactly the case where matching on the foreign id is right.
- Verdict: **authoritative for a sensor installation**; derived for the machine, because a reinstall mints a new `sid`. On the reinstall path the result is a second runZero asset, and no `matchBehavior` flag prevents it — runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`.

### Two things that affect how these assets correlate

- **`ext_ip` is a custom attribute, not an interface address.** The interface is built from `int_ip` and `mac_addr` only. LimaCharlie documents `ext_ip` as the "External (public-facing) IP address of the endpoint" and `int_ip` as the internal one, so `ext_ip` is the NAT egress address of whatever gateway the sensor sits behind and **every endpoint in one office reports the same value**. It used to go onto the interface alongside the endpoint's own MAC, which invited unrelated machines to correlate on a shared address and left a sensor with no MAC and no internal address asserting nothing but that shared public value. It is now carried as the `ext_ip` attribute, which is what `cybereason/` and `kandji/` do with the equivalent field. Note the selector documentation's wording — these are *last observed* values recorded by the cloud, not live reads.
- **A sensor that has enrolled but not yet checked in has no address and no MAC at all.** `network_interface` returns nothing usable in that case, and the asset is imported with no interface, correlating on its hostname alone.

### Pagination

**The sensor list is paged with a continuation token**, and the walk follows it. The response carries `continuation_token` alongside `sensors`, and the next request sends that value back as a query parameter of the same name. The walk ends when the token comes back absent, `null`, or empty — all three are falsy and all three mean the same thing.

The contract is not currently documented on a live vendor reference page (`docs.limacharlie.io/apidocs/get-sensor-list` returns 404 and the old readme.io reference redirects to the docs root), so it is taken from the two official SDKs, which agree:

- `refractionPOINT/python-limacharlie`, `Organization.list_sensors()` — loops setting `qp["continuation_token"]` and breaks on `if not continuation_token`.
- `refractionPOINT/go-limacharlie`, `sensor.go` — the page struct is `{"continuation_token": string, "sensors": …}`.

The list was previously fetched **once**, with the response read a single time and no loop, so an organization larger than one page imported only whatever the first response happened to carry, silently. The `paged` scenario is the regression test: three pages, each route matching on the token the previous page returned, with the sensors from pages 2 and 3 asserted by id.

Two implementation notes:

- **`is_compressed` is deliberately not sent.** With it, LimaCharlie replaces the `sensors` array with a base64-encoded gzip blob (this is what the Go SDK does); without it the array arrives as plain JSON. The `paged` scenario asserts the parameter never appears on a request.
- **A repeated continuation token ends the walk.** A server that echoed one forever would spin, and a task that never finishes is worse than a truncated import.

There is no documented default or maximum page size — `limit` exists as a parameter, but the vendor sources say only that leaving it unset "defers to the backend default", so the script does not set one.

## Future

This integration calls exactly two endpoints: the token exchange and `GET /v1/sensors/{oid}`. LimaCharlie's API is considerably larger, and the items below name capabilities rather than quoting routes that were not exercised — confirm each against LimaCharlie's reference before building on it.

- **Detections as an event feed.** LimaCharlie's detection and event retention surface returns detections carrying the `sid` this integration already uses as the asset identity, so the join back to a runZero asset is direct. These are behavioral detections rather than CVEs and belong in a time-windowed feed with a high-water mark, not in `Vulnerability` records — modelling them as vulnerabilities would put uncorrelatable identifiers in a field runZero's vulnerability reporting expects to hold CVEs.
- **Outbound: push runZero classification as sensor tags — the most valuable direction here.** LimaCharlie sensors carry tags, and its Detection & Response rules select on them. That means a runZero query — every asset on a regulated segment, everything runZero classifies as a domain controller, everything missing an expected agent — can become a tag that immediately changes which detection rules apply. Very few EDR platforms let an external inventory drive detection scope this directly. Note the permission consequence: this needs `sensor.tag`, which the credential guidance above explicitly tells you *not* to grant for the inbound direction, so an outbound integration wants a separate key.
- **Outbound: runZero asset lists as a lookup for D&R rules.** LimaCharlie's configuration store holds lookup resources that rules can join against. Pushing a runZero-derived list — unmanaged devices, assets on a sensitive subnet — would let detection logic reference runZero's view of the network rather than a hand-maintained list.
- **Sensor tasking and isolation are reachable and deliberately out of scope.** The API can task a sensor to run commands and can isolate it from the network. Both are natural responses to a runZero finding and both are wrong to attach to a scheduled sync: an isolation rule that misfires takes a fleet offline. The credential guidance above (no `sensor.task`) exists to make that impossible from this integration's key.
- **Agent coverage-gap reporting.** LimaCharlie knows which machines carry a sensor; runZero discovers the ones that do not. The sensor record's own fields — already imported as custom attributes by the catch-all loop — additionally identify sensors that have stopped reporting, separating "no agent" from "silent agent". This is a reporting exercise rather than new integration work.
- **What this API does not offer.** A sensor record carries no installed-software inventory, no open-port list, and no CVE feed, so `Software`, `Service`, and CVE-bearing `Vulnerability` records cannot be produced from it. LimaCharlie's telemetry contains process and network events that could in principle be shaped into services, but those describe observed activity over a retention window rather than current listening state — the same caveat that applies to `cybereason/`'s connection pass.

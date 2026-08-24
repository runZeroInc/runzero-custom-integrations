# Custom Integration: Unraid

Imports an Unraid server — hardware, OS, disks, array state — and the Docker
containers that hold **an address of their own on the network**.

Unraid sits at the centre of a very large number of homelabs and small offices,
and it is usually running a dozen services that active scanning sees only as
open ports on one host. This integration puts the server in runZero with its
real hardware detail, and separates out the containers that are genuinely
independent devices on the LAN.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Unraid web interface.

## Unraid requirements

- **Unraid 7.2 or newer**, where the GraphQL API is built into the OS. On 7.0–7.1 the same API is available through the Unraid Connect plugin.
- The **`unraid-api` service running**. It normally is; see [When the API is down](#when-the-api-is-down) for why its absence is unusually hard to notice.
- Nothing needs to be enabled for a runZero integration beyond the API service itself. In particular the **GraphQL sandbox does not need to be on** — `unraid-api developer --sandbox true` only unblocks `GET /graphql` for interactive browsing, and this integration uses `POST`. Introspection is likewise blocked by default and is not used.

### Creating the API key

On the Unraid server:

```bash
unraid-api apikey --create --name runzero -r VIEWER --json
```

`VIEWER` is documented as "Read-only access to all resources" and is the right
role here. The command prints `{"key":"...","name":"runzero","id":"..."}`; the
`key` value is what runZero needs.

If you would rather grant individual permissions than a role, these are the ones
this integration uses:

```bash
unraid-api apikey --create --name runzero \
  -p INFO:READ_ANY,DOCKER:READ_ANY,VMS:READ_ANY,ARRAY:READ_ANY,DISK:READ_ANY,VARS:READ_ANY --json
```

| Permission | What it unlocks here |
|---|---|
| `INFO:READ_ANY` | **Required.** System info *and* the network interfaces — `networkInterfaces` is gated on `INFO`, not `NETWORK` |
| `DOCKER:READ_ANY` | Container inventory |
| `VMS:READ_ANY` | VM inventory (recorded on the server asset) |
| `ARRAY:READ_ANY`, `DISK:READ_ANY` | Array state, capacity, disk models and serials |
| `VARS:READ_ANY` | Flash GUID, licence tier, server name and comment |

Only `INFO:READ_ANY` is required. A key missing any of the others still works —
see [Partial results are normal](#partial-results-are-normal).

Confirm the credential from the Explorer host:

```bash
curl -s http://tower.local/graphql \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <key>' \
  -d '{"query":"{ info { machineId os { hostname release } } }"}'
```

The key goes in **`x-api-key`**. A bearer token is *not* accepted — the API
registers only a header strategy, a session cookie strategy, and a local session
strategy, and there is no JWT strategy at all.

### Transport

- The API process itself listens on a **unix socket** (`/var/run/unraid-api.sock`), not a TCP port. You reach it through the same nginx that serves the WebGUI, at `/graphql`, on whatever port and scheme the WebGUI uses.
- Unraid's defaults are **plain HTTP on port 80**, with HTTPS on 443 only once SSL is turned on. When it is, the certificate is normally **self-signed**, so set the TLS options accordingly rather than assuming validation will pass.
- The nginx `location /graphql` block is `allow all` — there is no source-address restriction to configure.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Unraid").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Unraid URL** (`url`): base URL of the web interface, for example `http://tower.local`. The API is resolved as `<url>/graphql`.
   - **API key** (`api_key`).
   - **Collect Docker containers** (`collect_containers`): optional, default enabled.
   - **Import container published ports as services** (`container_services`): optional, default enabled.
   - **Include stopped containers** (`include_stopped_containers`): optional, default **disabled**.
   - **Include containers on the default Docker bridge** (`include_nat_containers`): optional, default **disabled** — read [Which containers become assets](#which-containers-become-assets) before turning this on.
   - **Collect virtual machines** (`collect_vms`) / **Collect array and disk detail** (`collect_storage`): optional, both default enabled.
   - **Maximum containers** (`max_containers`): optional, default 500.
   - **TLS options** (`tls_*`): set these if the WebGUI is on HTTPS with a self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Unraid.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:unraid`.
- Split the two asset kinds with `tag:unraid-server` and `tag:unraid-container`.
- Find containers by stack with `tag:compose-project:homelab`, or find containers due an update with `unraid_update_available:true`.
- Find the server by disk serial with `unraid_storage_disk_serials:VGH12345`, or by chassis serial with `tag:serial:S123456789`.

## Running it from the command line

```bash
runzero script --filename unraid/unraid.star \
  --kwargs url=http://tower.local \
  --kwargs api_key=<key> \
  --kwargs collect_vms=false \
  --kwargs max_containers=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/unraid-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename unraid/unraid.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=http://tower.local,api_key=<key>'
```

**One CLI caveat:** `--kwargs` passes a value through verbatim, commas included,
until the value contains a *second* `=` -- at which point it is parsed as CSV,
so a value containing a comma *and* an `=` is silently torn into extra
parameters. Unraid API keys are restricted to `[A-Za-z0-9-_]` so they are safe,
but the URL is not if it carries a query string.

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, with different match behavior.

### The server

- Target entity: the Unraid machine.
- Source ID field: **`info.machineId`**.
- Final runZero ID: `unraid:machine:8f2a1c4e9b7d43a6bd0e5f1c2a3b4c5d`. No host scope is needed, and deliberately so — the machine id is unique to the machine, so the same server polled by IP in one task and by DNS name in another produces **one** asset rather than two.
- Match behavior: `"no-mac-break no-ip-break no-name-break"`. The id drives merges, and a changed address, MAC, or hostname does not disqualify a merge against the existing asset.
- **Why `machineId` and not `vars.flashGuid`.** The flash GUID is arguably the more meaningful identifier — Unraid boots from the USB stick and the licence is bound to its GUID, so it survives an OS reinstall. It was rejected anyway, because it comes from a *different* resolver with a *different* permission (`VARS:READ_ANY`). A key granted `INFO` but not `VARS` would silently produce a different id than a key granted both, and **a changed foreign id from one custom integration always forks the asset** — `no-id-break` does not prevent this; a separate unconditional gate refuses any merge that would place two different foreign ids from the same integration on one asset. `machineId` comes from the same `info` resolver that everything else here needs, so it cannot disappear independently of the rest of the collection. The flash GUID is recorded as `unraid_vars_flashGuid` and is the better thing to search on; it is simply not the key.
- Missing-ID behavior: if `machineId` is absent the id falls back to `unraid:<configured-host>:server` and the match behavior flips to `no-id-match no-id-break`, because a host-derived id is an *address* and addresses are recycled. The run logs that it took this branch. Nothing is invented and `new_uuid()` is not used anywhere in this script.
- The factory hostname `Tower` is treated as a placeholder and not imported, for the same reason `localhost` is not: on the host-derived branch there is no stable id, so merging falls back to MAC, IP, and hostname, and a name shared by every unconfigured Unraid would merge unrelated servers.
- Verdict: **authoritative vendor identifier.**

### Containers

- Target entity: one Docker container that has its own presence on the network.
- Source ID field: the **container name** (`names[0]`, leading slash stripped).
- **Why not the container id.** Unraid recreates a container on every image update, and Docker mints a new 64-character id each time. Keying on it would produce a brand-new asset on every update and abandon the old one. The name is what Unraid's Docker manager keeps stable, because it comes from the template. The id is still recorded as `unraid_container_id` — with its `PrefixedID` server prefix (`1:`) stripped, since that prefix is not part of the Docker identifier.
- Final runZero ID: `unraid:<server-host>:container:<name>`. Scoped on the configured host rather than on `machineId`, so that a key without `INFO` permission — or any other reason `machineId` is missing — cannot change every container id at once.
- Match behavior: `no-id-match no-id-break`. A container name is unique only within one Docker host, and `plex` on two servers is two different things. Correlation runs on the container's MAC and address, which is what actually identifies it.
- Missing-ID behavior: a container with no name falls back to its stripped id; one with neither is not emitted.
- Verdict: **derived / non-authoritative.**

### Which containers become assets

Only containers that hold **an address of their own**. Three groups are
deliberately excluded, and each exclusion is recorded on the server asset in
`unraid_docker_containers_without_own_address` so nothing disappears silently:

| Excluded | Why |
|---|---|
| `networkMode: host` (and `none`, `container:*`) | The container shares the server's network stack. It has no MAC, no address, and no hostname, so an asset for it could never merge with anything and would be a permanent orphan — exactly what the `has_correlator` invariant exists to prevent. |
| `networkMode: bridge` — Docker's default NAT bridge | These get `172.17.0.0/16`, which is the **same range on every Docker host on earth**. Two containers on two different servers would both claim `172.17.0.4`, and runZero's IP-based merging is site-scoped, so within one site they would merge into a single asset. They are also unreachable from the network, so they are not devices in any useful sense. Set `include_nat_containers` if you want them anyway. |
| Stopped containers | No live address. Set `include_stopped_containers` to import them when Docker still reports one. |

What is left is the macvlan and `br0` case — a container with a real LAN address
and its own MAC, which genuinely is another device on the network and which
active scanning will find independently. Those merge correctly.

Note one consequence for MACs: Docker generates container MACs in the
`02:42:...` space, which sets the locally administered bit. The foreign id
keeps the MAC losslessly, while the emitted `NetworkInterface` carries the
LAA-cleared form, because `net.network_interface` clears that bit to help
cross-source matching. The `happy` fixture asserts both halves so a refactor
cannot quietly route the id through `normalize_mac`.

### Virtual machines are not assets

Unraid's schema exposes **exactly four fields** for a guest: `id`, `name`,
`state`, and a deprecated `uuid`. There is no NIC list, no MAC, no IP address,
and no libvirt XML — the VM service holds a live libvirt connection but only
ever calls `getInfo()` and lifecycle methods, and `getXMLDesc()` is not surfaced
through GraphQL at all.

An asset built from a UUID and a display name like `Windows 11` carries no MAC,
no address, and no usable hostname. It could never merge with the machine
runZero actually scans, so it would sit in the inventory forever as a duplicate
of a host that is already there under its real identity. The VM inventory is
therefore recorded on the server asset (`unraid_vm_guests`,
`unraid_vm_guest_count`) rather than emitted. See [Future](#future).

## Notes

### What is imported

| Query | Gated by | What it gives |
|---|---|---|
| `info` | always | machineId, OS, system, baseboard, CPU, versions, network interfaces |
| `vars` + `metrics` | always | Flash GUID, licence tier, server name, timezone, memory totals |
| `array` + `disks` | `collect_storage` | Array state and capacity, per-disk model, serial, and health |
| `docker { containers }` | `collect_containers` | Container inventory, network settings, published ports, labels |
| `vms { domains }` | `collect_vms` | VM names and states, recorded on the server |

`Service` objects are produced for a container's published ports.
No `Software` or `Vulnerability` records are emitted: Unraid's API inventories
no installed packages on the host beyond a handful of daemon versions, and no
vulnerability data at all.

### The collection is several small queries, on purpose

It would be one round trip to ask for everything in a single document, and the
research notes for this integration suggested exactly that. It is not done here,
because GraphQL validates the **whole document** before executing any of it: a
single field that a given server's schema does not have fails the entire query
and returns no data at all. Splitting the collection means an Unraid release
that renamed one `array` field costs the array data and nothing else. Five small
POSTs is a negligible cost for that.

The published documentation is a live example of why this matters — it still
shows a root `dockerContainers` query, which does not exist in the schema. The
field names used here come from the generated SDL in the `unraid/api` source
tree, not from the docs.

The container query goes one step further, because `unraid-api` releases add
and remove `DockerContainer` fields quickly and one unknown field would
otherwise version-gate the whole container import to zero. It is tiered: the
full field set is tried first, and when the server's schema rejects it with a
`Cannot query field` validation error, the same collection is retried with the
core fields the asset is actually built from. A container imported through the
core tier simply lacks the enrichment attributes (`template_path`,
`auto_start`, labels, and the like). The `schema-drift` fixture locks this
behavior.

### Partial results are normal

Unraid's exception filter sends **HTTP 200 for GraphQL errors**, and a key that
can read one resource but not another gets both in one response: populated
`data` for what it may see, plus an `errors` entry for what it may not.
Discarding the whole response on any error — the reflex an all-or-nothing HTTP
client encourages — would throw away a perfectly good server asset because the
key lacked `VMS:READ_ANY`.

So partial data is ingested, and every refused resource is named in the log:

```
unraid: vars and metrics returned no data: Forbidden resource
unraid: array and disks returned partial data: Forbidden resource
```

### When the API is down

This is the failure most worth knowing about, because nothing about it looks
like a failure. Stock Unraid's `rc.nginx` intercepts the upstream 502 from the
API's unix socket and answers `/graphql` with **HTTP 200** and a hand-written
body:

```json
{"errors":[{"error":{"name":"InternalError","message":"Graphql is offline."}}]}
```

Note the shape: the message is at `errors[0].error.message`, **not** at
`errors[0].message`, so it is not standard GraphQL and an integration that reads
only `.message` finds no error at all. There is no 404 and no connection
refusal to notice either, because the nginx location block exists whether or not
the backend is running. This integration detects that body specifically and says
what to do:

```
unraid: the Unraid API service is not running. nginx answers /graphql with
HTTP 200 and 'Graphql is offline.' when the backend socket is down. Start it on
the server with 'unraid-api start' and check 'unraid-api status'.
```

### Fields deliberately not used

- **`networkInterfaces[].gateway`** — the resolver hardcodes it to the literal string `"unknown"`. Importing it would put that word in an inventory.
- **`virtual`** as an interface filter — Unraid's primary interface is normally `br0`, a bridge, which reports `virtual: true`. Filtering on it would discard the server's real address. The API's own `primaryNetwork` resolver prefers `br0` over `eth0` for the same reason. Loopback is dropped using the `internal` flag instead, and container and VPN adapters by name.
- **`os.uptime`** as a duration — the schema documents it as a **"Boot time ISO string"**. It is a timestamp, and it becomes `firstSeenTS` after being validated and clamped to now, because `time.parse_time` aborts the whole script on unparseable input and the platform rejects the **entire asset record** on a future timestamp.

### Units

Two unit mismatches in the same response are worth knowing before comparing
numbers: `ArrayDisk.size` is in **kilobytes** while `Disk.size` is in **bytes**,
and `array.capacity.kilobytes.*` are `String!` rather than numbers. All of these
are preserved verbatim as attributes rather than converted.

### Verification status

Verified against local fixtures and against the **generated GraphQL schema** in
the `unraid/api` source tree (`api/generated-schema.graphql`, release 4.37.1),
not against a live Unraid server. Every field used here was checked to resolve
against that SDL, and the `networkSettings` contents were taken from the
dockerode `ContainerInfo` type that the Docker resolver passes through
unmodified. Unraid does not containerize — it is a licensed OS distribution that
boots from USB — so no container was run for this integration.

Two things a live server would settle: the exact wire shape of an
*authentication* failure (the guard throws an `UnauthorizedException` whose
rendering in the Apollo context could not be determined from static reading, so
both an HTTP 401 and a body-level error are handled), and whether a macvlan
container's `IPAMConfig.IPv4Address` ever differs from its
`Networks[].IPAddress` in practice.

## Future

- **VM network identity.** The single biggest gap. `vms { domains }` gives a UUID, a name, and a state, and nothing that can correlate to a real machine. libvirt has the NIC list and Unraid's service holds a live connection to it; if a future schema exposes `getXMLDesc()` or a `vnics { mac }` field, VMs become first-class assets immediately and this integration should emit them.
- **`vars.flashGuid` as a second correlator.** It is recorded but not used for identity, for the permission reason above. If the schema ever moved it under `info`, it would be the better key.
- **Installed plugins.** Unraid's plugin list is real installed software on the host and would map cleanly to `Software` objects. It is not in the queries used here.
- **Shares as services.** SMB and NFS exports are listening services on the server that runZero would otherwise have to fingerprint from the outside.
- **The `metrics` subscription surface.** Only the memory totals are used today; CPU and network utilization exist and would make the server asset a better operational record, though neither is asset data.
- **Unraid Connect.** When the plugin is installed it adds `network { accessUrls { ... } }`, which enumerates every URL the server answers on — including its remote-access hostname. That is genuinely useful reachability data, but it is plugin-provided, so it would need to be probed rather than assumed.
- **UPS and USB peripherals.** `info.devices.usb` lists attached devices; a network UPS in particular is an asset in its own right elsewhere in an inventory.

## API documentation

- [Unraid API docs](https://docs.unraid.net/API/) and [How to use the API](https://docs.unraid.net/API/how-to-use-the-api/) — auth, the endpoint, and example queries. **Note:** the how-to still shows a root `dockerContainers` query that does not exist in the current schema; prefer the SDL below.
- [CLI reference](https://docs.unraid.net/API/cli/) — `unraid-api apikey`, `start`, `stop`, `status`, `logs`, `developer`.
- **Schema of record:** [`unraid/api`](https://github.com/unraid/api), file `api/generated-schema.graphql`. This is a code-first NestJS schema, so the generated SDL is authoritative and the docs are not. The `x-api-key` header name is fixed in `api/src/unraid-api/auth/header.strategy.ts`; the role and permission enums, the resolver `@UsePermissions` decorators, and the `PrefixedID` scalar are all defined in that tree.
- Container fields pass straight through from [dockerode's `ContainerInfo`](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/dockerode/index.d.ts), which is the shape of `networkSettings`; the underlying contract is the [Docker Engine API](https://docs.docker.com/reference/api/engine/).

# Custom Integration: Portainer / Docker Engine

Imports the **Docker hosts** a Portainer server manages, every **Swarm node**
those hosts belong to, and the small subset of **containers** that actually hold
an address on the physical network.

The interesting decision here is what this integration refuses to import. A
container's default address is `172.17.0.2` on the default bridge — the same
address on every Docker host on earth — and its default MAC is *derived from*
that address, so `172.17.0.2` is always `02:42:ac:11:00:02`. Importing those
would correlate one site's Redis onto another site's Postgres. So the Docker
host is always an asset, a Swarm node is always an asset because a swarm node is
a machine whose real address the API publishes, and a container becomes an asset
only when it is attached to a **macvlan** or **ipvlan** network and therefore
really is a separate device on the LAN. Everything else a container knows is
attached to the host that runs it: published ports become services on the host,
because `-p 8080:80` means the *host* answers on 8080. This mirrors the shipped
[`kubernetes/`](../kubernetes/) integration, which emits Nodes and routable
Services and keeps cluster-CIDR ClusterIPs off every interface for the same
reason.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Portainer server's HTTPS port — `9443` on a default container install, or whatever port the reverse proxy in front of it uses. In `docker` mode the Explorer instead needs the Docker Engine API socket, normally TCP `2376` with TLS.
- Portainer is very commonly behind its own self-signed certificate, so `OPTIONS_TLS` is exposed. Nothing is skipped by default.

## Portainer requirements

- **Portainer CE 2.x or newer.** Access tokens sent as `X-API-Key` are the documented API credential, and the vendor's own example is `GET <portainer url>/api/endpoints/1/docker/containers/json` with that header — the exact call this integration makes.
- **An administrator's access token.** This is the load-bearing requirement and it is explained below.
- Nothing has to be enabled first. The API is always on, it needs no licence, and no feature flag gates the Docker proxy.

### Community Edition versus Business Edition

Everything this integration touches exists in **CE**. The granular roles —
Environment Administrator, Operator, Helpdesk, Read-Only User, Namespace
Operator — are Business Edition only, because *"Role-Based Access Control is
only available in Portainer Business Edition"*. That matters in an unexpected
direction: CE has **no read-only role to create**, so the choice is between an
administrator and a standard user whose view is silently filtered two ways.

- `GET /api/endpoints` runs its result through `security.FilterEndpoints()`, which returns only the environments that user is authorized for. Environments they were never granted are simply absent from the array; nothing errors.
- The Docker proxy applies **resource controls** to the container list. `/containers/json` is handled by `rewriteOperationWithLabelFiltering` → `applyAccessControlOnResourceList`, which drops containers the user does not own. `/networks` goes through `restrictedResourceOperation` and is filtered the same way.

The second is the nastier of the pair, because the network list is what tells
this integration which Docker networks are `macvlan` or `ipvlan` — a filtered
network list makes a genuinely routable container look non-routable, and it is
skipped. `/info` has no restriction handler at all, and `/nodes` restricts only
*modifications* to administrators, so both read fine.

Net effect: a standard user's token authenticates, returns HTTP 200 on every
call, and quietly imports a subset of your estate. Use an administrator's token
unless you specifically want a partial view. (There is an **open, unconfirmed**
issue, [#12952](https://github.com/portainer/portainer/issues/12952) against
2.33.4 BE, arguing the API leaks container metadata the UI hides. If accurate, a
non-admin token sees *more* than the above predicts — but not more reliably, so
the recommendation is unchanged.)

### Creating the credential in Portainer

1. Log in to Portainer as the user the token should act as. For a full estate,
   that means an **administrator**.
2. Click your **username in the top right**, then **My account**.
3. Scroll to the **Access tokens** section and click **Add access token**.
   Portainer requires you to **re-enter your password** to create one.
4. Give it a description (`runZero`, for example) and create it. **Copy the
   token immediately** — Portainer shows it exactly once and there is no way to
   retrieve it afterwards. Whether a CE access token can be given an expiry was
   not established from the documentation available; treat it as long-lived and
   rotate it on your own schedule.
5. Confirm the token from the Explorer host before configuring anything in
   runZero. The first call proves the token; the second proves the Docker proxy
   is reachable for a specific environment:

   ```bash
   curl -s -H 'X-API-Key: ptr_AbCdEf0123456789ExampleTokenValue=' \
     'https://portainer.example.com:9443/api/endpoints?start=1&limit=1&excludeSnapshots=true'

   curl -s -H 'X-API-Key: ptr_AbCdEf0123456789ExampleTokenValue=' \
     'https://portainer.example.com:9443/api/endpoints/1/docker/info'
   ```

   The first answers a bare JSON **array**, not an envelope. If it answers `[]`
   with a 200, the token is valid and the user can see no environments — which
   is the standard-user case above, not a connectivity problem.

To use a dedicated account rather than an existing administrator, create it at
**Users → Add a new user** with the **Administrator** toggle on, then mint the
token from *that* user's **My account** page. The docs place user management
under the administration area; the exact top-level grouping has moved between
2.x releases. A token carries exactly the access its owner has in the UI, so it
is only ever as privileged as the account behind it.

### The `docker` mode alternative

Setting `mode` to `docker` skips Portainer entirely and talks to one Docker
Engine API socket; `api_key` is unused. **Do not expose a Docker socket over
plain TCP to get this** — an unauthenticated Docker API is root on the host. Use
the daemon's mutual-TLS port (conventionally `2376`) and supply the client
certificate through the shared TLS options (`tls_client_cert`, `tls_client_key`,
`tls_ca_cert`). One task collects one daemon in this mode, so it does not scale
the way Portainer mode does; it exists for estates that run Docker without
Portainer.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Portainer").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Connection mode** (`mode`): `portainer` (the default) or `docker`.
   - **Base URL** (`url`): the Portainer server URL, e.g. `https://portainer.example.com:9443`; in `docker` mode, the Engine API URL, normally `https://dockerhost.example.com:2376`.
   - **Portainer API key** (`api_key`): the token from step 3 above. Required in `portainer` mode, unused in `docker` mode.
   - **Limit to environment IDs** (`environment_ids`): optional, comma-separated Portainer environment IDs. Blank collects every Docker environment.
   - **Import containers as assets** (`import_containers`): optional, default `routable-only`. Also `all` and `none`.
   - **Additional routable network names** (`routable_networks`): optional, comma-separated Docker network names to treat as routable beyond `macvlan` and `ipvlan`.
   - **Import published ports as services** (`import_published_ports`): optional, default enabled.
   - **Include stopped containers** (`include_stopped_containers`): optional, default enabled — this sends `all=1` on the container listing.
   - **Maximum environments to collect** (`max_environments`): optional, default 200.
   - **Portainer page size** (`page_size`): optional, default 100.
   - **TLS options** (`tls_*`): set these for Portainer's self-signed certificate, or for the Docker daemon's client certificate in `docker` mode.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Container estates churn faster than hardware inventories, so hourly is reasonable where a nightly run would do for most sources.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Portainer.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:portainer`.
- Split the asset kinds with `tag:docker-host`, `tag:docker-swarm-node`, and `tag:docker-container`. Hosts running an active swarm also carry `tag:docker-swarm`.
- Containers carry their state as a tag — `tag:docker-running`, `tag:docker-exited`, `tag:docker-paused` — and the ones that earned a real LAN address carry `tag:docker-routable`.
- Host facts are `docker.` attributes: `docker.server_version`, `docker.storage_driver`, `docker.containers_running`, `docker.swarm_state`, `docker.container_images`, `docker.compose_projects`. Portainer's own view of the environment is under `portainer.`: `portainer.endpoint_name`, `portainer.endpoint_type`, `portainer.endpoint_status`, `portainer.group_id`, `portainer.tag_ids`.
- Container facts are also `docker.`: `docker.image`, `docker.compose_project`, `docker.compose_service`, `docker.networks`, `docker.health`, `docker.labels`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename portainer/portainer.star \
  --kwargs url=https://portainer.example.com:9443 \
  --kwargs mode=portainer \
  --kwargs api_key=ptr_AbCdEf0123456789ExampleTokenValue= \
  --kwargs import_containers=routable-only \
  --kwargs max_environments=5 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/portainer-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; without it the assets are parsed and discarded.
Capping `max_environments` on a first run keeps a smoke test from walking a
200-environment estate one `/info`, `/containers/json`, and `/networks` call at
a time.

**One CLI caveat, and neither list parameter trips it.** `--kwargs` passes a
value through verbatim, commas included, as long as the pair contains a single
`=` — so `environment_ids` and `routable_networks` can both be given as full
comma-separated lists from the command line. What breaks is a value carrying a
*second* `=` **as well as** a comma: that pair is re-read as CSV, so the value is
cut off at the comma and the remainder becomes a parameter the integration never
declared, with no error. Portainer API keys often end in `=`, as the one above
does, which is harmless on its own — it is the combination with a comma that
bites. Wrap such an argument in double quotes to keep it a single field:
`--kwargs '"api_key=ptr_AbCdEf=,more"'`.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename portainer/portainer.star --validate
```

`python3 tests/run.py portainer` exercises the fixture scenarios in
`portainer/tests/fixtures/` — a single-environment collection, `start`/`limit`
paging over `/api/endpoints`, and a Swarm manager — against the real scanner.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://portainer.example.com:9443,api_key=ptr_AbCdEf0123456789ExampleTokenValue='
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Every id is scoped on the **hostname of the configured URL**, taken with
`url_parse`. Two Portainer servers, or two Docker daemons, are two namespaces.

Three kinds of asset are emitted as three declared asset types — `host`,
`swarm-node`, and `container` — selected per record with
`ImportAsset(assetType=...)`, and each type's merge policy is declared under
that key in `CONFIG["assetTypeBehavior"]`.

`type-break` is left ON (the default), and for containers it is load-bearing.
A container is the one type here with `no-id-break`, so its merges are decided
entirely by MAC, IP, and hostname — and in the common case it has no address at
all, since only macvlan and ipvlan attachments are imported, which leaves the
hostname deciding alone. That hostname is a compose service name or a `--name`
argument: values operators reuse freely, and which routinely collide with a real
machine's name, including the Docker host's own for a host-networked container
that sets `hostname:`. The break is what keeps a workload from folding into the
machine that runs it.

`host` and `swarm-node` both keep `id-break`, so they already refuse to merge
with each other on the foreign-id path; leaving `type-break` on says the same
thing a second way. That pair genuinely can be one machine — a swarm node added
to Portainer as its own environment is reported twice, once by daemon ID and
once by node ID — and it forks today. Relaxing `type-break` would not repair
that fork, because two foreign ids from one custom integration cannot sit on one
asset regardless of the break flags.

### Docker hosts

- Target entity: one Docker **daemon** — the machine running the engine, whether Portainer reached it locally, through an agent, or through an edge agent.
- Source ID field: **`ID`** from `GET /info`.
- Documentation evidence: the Engine API's `SystemInfo` schema documents `ID` as the unique identifier of the daemon, and it is the value Docker itself uses to identify an engine to a swarm and to a registry. It is minted once and persisted by the engine.
- Uniqueness scope: globally unique in practice, but scoped here on the Portainer hostname anyway, so two Portainer servers managing the same daemon do not silently share an asset across two integrations pointed at different URLs.
- Cardinality: exactly one per **daemon**, not per environment. Portainer can hold two environments that front the same Docker socket — a host registered once as a local entry and again through the agent, or simply adopted twice — and both `/info` calls return the same `ID`. Since every id below is scoped on that `ID`, collecting both emitted duplicate foreign ids for the host and for every container on it. The second environment is therefore **skipped whole**, with `INFO: environment <n> (<name>) reports daemon <id>, already collected from environment <m>`. The environment that appears first in `/api/endpoints` wins, and its `portainer.endpoint_*` attributes are the ones recorded. The alternative — folding the environment id into the identity — was rejected: it would trade one collision for two permanent assets describing one machine, and two foreign ids from a single integration can never merge onto each other. See the `duplicate-daemon` scenario.
- Stability: survives rename, re-address, restart, and Docker upgrade. It changes when the engine's data root is wiped and recreated.
- Reuse behavior: not recycled — it is generated, not allocated from a sequence.
- Presence: required. An environment whose `/info` returns no `ID` is **skipped** with `WARN: skipping environment <n>: /info returned no daemon ID`, because without it there is nothing durable to key on.
- Final runZero ID: `docker:<portainer-hostname>:host:<daemon-id>` — for example `docker:portainer.example.com:host:bea7c305-c44d-475b-8c73-6f4215a5c947`.
- Missing-ID behavior: skip, as above. No id is invented and `new_uuid()` is never used.
- Asset type: **`host`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**. Docker supplies at most one address for a host and no MAC at all, so at first contact — before any id match exists — a differing MAC, address, or name must not disqualify a merge with the machine runZero already scans. Once the foreign id has matched, break flags no longer participate.
- Verdict: **scoped authoritative.** A genuine, stable, non-address vendor identifier, and one of the few in this repository allowed to drive merges.

### Swarm nodes

- Target entity: one row of `GET /nodes` — a machine that has joined the swarm.
- Source ID field: **`ID`**, the 25-character swarm node id.
- Documentation evidence: it is the node object's own `ID` and the path parameter every per-node route takes (`/nodes/{id}`).
- Uniqueness scope: one swarm cluster; scoped on the Portainer hostname here.
- Cardinality: one per node. A three-node swarm queried through its manager yields three assets — **including the manager itself**, which is also emitted as a Docker host from `/info`. Those are two different views of one machine and merge on hostname and address.
- Stability: assigned when the node joins and kept until it leaves. `docker swarm leave` and rejoin mints a new one.
- Presence: required. A node row with no `ID` is skipped with `WARN: skipping swarm node with no ID`.
- Final runZero ID: `docker:<portainer-hostname>:swarm-node:<node-id>` — for example `docker:portainer.example.com:swarm-node:24ifsmvkjbyhksix2ldy4o4bx`.
- Missing-ID behavior: skip. A node with neither a hostname nor a parseable `Status.Addr` is also skipped, because it would have nothing to correlate on.
- Asset type: **`swarm-node`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**, for the same reason as the host: `Status.Addr` is the single address Docker publishes and there is no MAC.
- Verdict: **scoped authoritative.**

### Containers

- Target entity: one container from `GET /containers/json`, emitted **only** when it holds a routable address (default), or for every container when `import_containers` is `all`.
- Source ID field: **none that is usable.** Docker's 64-hex container `Id` is minted fresh on every recreate — `docker compose up` after an image bump produces a new one for the same service — so it is recorded as `docker.container_id` and deliberately kept out of the identity.
- What is used instead: this script's own composite of the Compose labels, `com.docker.compose.project` / `com.docker.compose.service` / `com.docker.compose.container-number`, joined as `project/service/number`. When those labels are absent — a bare `docker run` — the container **name** is used.
- Uniqueness scope: one daemon. The daemon ID is part of the id, so `hqstack/web/1` on two hosts is two assets.
- Cardinality: one per container. A Compose replica set produces one per replica, because the container number is in the key.
- Stability: deterministic across recreates, redeploys, and image bumps, which is the whole point of preferring the labels to the `Id`. It changes if the Compose project or service is renamed.
- Presence: a container with neither a name nor Compose labels is skipped with `WARN: skipping container with no name and no compose labels`. A container that survives that but has no routable address and no usable hostname is also skipped.
- Final runZero ID: `docker:<portainer-hostname>:<daemon-id>:container:<key>` — for example `docker:portainer.example.com:bea7c305-c44d-475b-8c73-6f4215a5c947:container:hqstack/web/1`, or `...:container:homeassistant` for an unlabelled one.
- Missing-ID behavior: skip, as above. Nothing is invented.
- Asset type: **`container`**.
- Match behavior: **`no-id-match no-id-break`**. The id is this script's construction, not a vendor identifier, so it must neither find nor block a merge. Correlation is left entirely to the macvlan address, the MAC, and the name — which is safe precisely because a container only becomes an asset when it has those.
- Verdict: **synthesized key, deliberately inert.**

The MAC on a macvlan container is emitted on the interface but never in the id.
`net.normalize_mac` clears the locally administered bit, and **every**
Docker-generated MAC sets it — `02:42:c6:33:64:2a` normalizes to
`00:42:c6:33:64:2a` — so two distinct containers can normalize to one value.
That is correct for an interface, because the platform normalizes a scanned MAC
the same way and the two still match, and wrong for identity.

## Notes

### What is imported

| Request | Gated by | What it gives |
|---|---|---|
| `GET /api/endpoints?start=&limit=&excludeSnapshots=true` | `portainer` mode | The environment list, paged |
| `GET .../docker/info` | always | The host asset: daemon ID, OS, kernel, CPU, memory, storage driver, swarm state |
| `GET .../docker/containers/json[?all=1]` | `import_containers` ≠ `none` **or** `import_published_ports` | Containers, their networks, and their published ports |
| `GET .../docker/networks` | containers are being imported | The network → driver map that decides routability |
| `GET .../docker/nodes` | `Swarm.LocalNodeState` is `active` | One asset per swarm node |

In `portainer` mode each Docker path is prefixed with
`/api/endpoints/{id}/docker`; in `docker` mode it is sent straight to the base
URL. Paths are sent **unversioned** — no `/v1.45` prefix. Portainer routes on
the literal `/docker/` segment and strips any `/vX.Y` before applying its RBAC,
and Docker negotiates the version itself when none is given, whereas pinning one
either 400s on a newer daemon that dropped it or is refused as too new.

Only `ImportAsset` and `Service` records are produced. Docker knows nothing
about installed packages or vulnerabilities, so no `Software` or `Vulnerability`
records are emitted; the image name is the closest thing available and it lands
as `docker.image` and as the service `product`.

### Published ports become services on the host

`-p 8080:80` makes the **host** listen on 8080. A port entry with no
`PublicPort` is not published at all and produces nothing. A published port
bound to `0.0.0.0` or `::` names no interface, so the host's own addresses are
used instead; with no host address either, the service is dropped rather than
bound to a wildcard, because a `Service` with no address is not something the
platform accepts. Services are bounded at 99 per asset — past that the platform
rejects the record outright — and the truncation is logged as `INFO: environment
<n> published more than 99 ports`.

### Which container addresses count

Bridge and overlay addresses are refused unconditionally: a default bridge
address is `172.17.0.x` everywhere, a user-defined bridge allocates from the
same per-host pool, and an overlay address comes from a default pool every swarm
cluster shares. Only `macvlan` and `ipvlan` attachments are routable, because
those really do put the container on the LAN segment with its own address and,
for macvlan, its own MAC. `routable_networks` names additional networks for
drivers this list does not cover. Every network the container is attached to is
recorded either way as `docker.networks` in `name=driver` form, so you can see
what was rejected and why.

Link-local addresses are filtered here rather than left to the platform. The
runtime drops loopback, multicast, and unspecified addresses itself but
deliberately **keeps** link-local, and an estate of hosts that failed DHCP would
otherwise all correlate to each other through `169.254/16` and `fe80::/10`.

### Environment paging, and why the loop stops on a short page

`GET /api/endpoints` answers a bare JSON array and reports the filtered total in
the **`X-Total-Count`** response header, which `get_json` does not surface. So
the walk pages on `start`/`limit` and terminates on a page shorter than the page
size. `start` is **1-based**: the handler decrements it, so `start=1` and
`start=0` both mean the first record. `excludeSnapshots=true` is sent because a
Portainer snapshot embeds an entire container and image inventory per
environment — a large payload this integration does not read.

Non-Docker environments are filtered on `Type`, 1-based in Portainer's own
`EndpointType`: 1 local Docker, 2 Docker agent, and 4 Docker edge agent are
collected; 3 Azure and 5/6/7 Kubernetes are skipped with an `INFO` line naming
the type, because those describe a different object model that the shipped
[`kubernetes/`](../kubernetes/) integration already covers.

If the listing fails **after** at least one page has been read, the run keeps
what it has and warns. If the first page fails, it errors out — an empty import
that looks like success is worse than a failure.

### Swarm mode changes what Docker will tell you about other machines

Outside swarm mode, `/info` carries **no address for the daemon at all**. That
is why a host's addresses are assembled from, in order of trustworthiness, the
swarm advertise address the node published about itself (`Swarm.NodeAddr`), then
a literal IP that Portainer recorded for the environment in `URL` or
`PublicURL`. A hostname written there is never resolved: it may point at a proxy,
and attaching a proxy's address to a Docker host is worse than attaching none.

Swarm mode is the one place the Docker API hands out routable addresses for
machines **other than** the one being queried — `GET /nodes` returns every
node's `Status.Addr`. So `/nodes` is requested whenever `Swarm.LocalNodeState`
is `active`, and each row becomes its own asset with its role, availability,
reachability, engine version, and node labels. But `/nodes` is a
cluster-management call, and a **worker** answers it `503 This node is not a
swarm manager` while still reporting `LocalNodeState: active` — so an
environment pointed at a worker produces one `INFO: no swarm node list for
environment <n>` line and the host asset alone. Handled, not fatal, and the
reason a swarm's node inventory only appears through a manager.

### Type coercion

Docker mixes integers and strings for the same field across daemon versions and
across the Portainer proxy, so every numeric read accepts either and falls back
rather than aborting. `/info` reports `Labels` as an array of `k=v` strings while
a container's `Labels` is a map; both are kept as written, so an unusual value is
never silently mangled.

### Verification status

Verified against the local fixture scenarios and against vendor documentation
and vendor source — not against a live Portainer server or Docker daemon.

- The container, `/info`, `/networks`, and `/nodes` response shapes in the fixtures follow the schemas in [`moby/moby` `api/swagger.yaml`](https://github.com/moby/moby/blob/master/api/swagger.yaml).
- The environment fields follow the JSON tags on `portainer.Endpoint` in `api/portainer.go`, and the paging contract (`start` decremented, `X-Total-Count`, bare array, `security.FilterEndpoints`) comes from `api/http/handler/endpoints/endpoint_list.go`.
- The non-admin filtering claims come from `api/http/proxy/factory/docker/transport.go` and `containers.go`, read directly.
- **Not verified:** the `docker` mode path against a real mutual-TLS daemon socket, and the exact Portainer version in which `excludeSnapshots` was introduced. The parameter is accepted by the current handler; an older 2.x server that does not know it will ignore an unknown query parameter rather than fail, but that was not confirmed against an old build.
- **Stated with less confidence than the rest:** that CE has exactly two roles. What the vendor documents outright is that *"Role-Based Access Control is only available in Portainer Business Edition"* and that the granular roles are BE features; the specific "administrator and standard user, and nothing else" phrasing comes from vendor-adjacent comparison material rather than the roles reference page, which does not label its list by edition. Nothing in this integration depends on the count — only on the fact that CE offers no read-only role.
- **Edge Agent environments (Type 4)** are collected because they are Docker-family, and the Edge Agent Standard is documented for both editions, but one field on its configuration page is called out as Business Edition only. No Edge environment was exercised, by fixture or otherwise.

## Future

- **Image inventory as `Software`.** `GET /images/json` gives every image on the host with its repo tags, digest, and size. Attaching those to the host asset would answer "which hosts still run `log4j`-era images" without a scan. The cost is one more call per environment and a decision about whether an image is meaningfully "software installed on" the host.
- **Volume and bind-mount exposure.** A container's `Mounts` array names the host paths it can write. A container bind-mounting `/var/run/docker.sock` is effectively root on the host, and flagging that as an attribute or tag would be a genuinely useful security signal. It is available in the container list already, at zero extra requests.
- **Swarm services rather than containers.** `GET /services` and `GET /tasks` describe the desired state of a swarm workload and its placement, which is a more stable object than the container that happens to be running now. That is the right model for a swarm estate, and a poor fit for the standalone daemons that make up most installs.
- **Portainer environment groups and tags as runZero sites.** `portainer.group_id` and `portainer.tag_ids` are imported as raw ids today. Resolving them through `GET /endpoint_groups` and `GET /tags` would turn them into names, and group-to-site mapping is the obvious follow-on.
- **Kubernetes environments.** Types 5, 6, and 7 are skipped rather than handled. Routing them to the existing [`kubernetes/`](../kubernetes/) integration through Portainer's `/api/endpoints/{id}/kubernetes/` proxy would let one credential cover a mixed estate, at the cost of a second object model in one script.
- **`X-Total-Count` for exact paging.** The environment walk stops on a short page because `get_json` does not expose response headers. Dropping that one call to raw `http.get` would let it read the header — at the cost of the retry budget, which raw HTTP does not accept.

## API documentation

- Accessing the Portainer API — https://docs.portainer.io/api/access. Source for the **My account → Access tokens → Add access token** path, the `X-API-Key` header, the one-time display of the token value, and the statement that a token carries the same access as its owner's UI session.
- API usage examples — https://docs.portainer.io/api/examples. Source for the exact call shape `GET <portainer url>/api/endpoints/1/docker/containers/json` with `X-API-Key`.
- Roles — https://docs.portainer.io/admin/user/roles. Source for the role list and for which roles are Business Edition only.
- Docker roles and permissions — https://docs.portainer.io/advanced/docker-roles-and-permissions. Source for what a standard user can read and for ownership-based filtering of resource lists.
- Access control — https://docs.portainer.io/advanced/access-control. Source for the Administrators / Restricted / Public resource-ownership model that does the filtering.
- Users — https://docs.portainer.io/admin/user/users and https://docs.portainer.io/admin/user/add. Source for the user-creation path and the **Administrator** toggle.
- Environment management — https://docs.portainer.io/admin/environments. Source for the "environment" terminology, which the UI adopted in 2.10 while the API kept `/api/endpoints`.
- Docker Engine API — https://docs.docker.com/reference/api/engine/, with the authoritative schemas in [`moby/moby` `api/swagger.yaml`](https://github.com/moby/moby/blob/master/api/swagger.yaml). Source for `SystemInfo.ID`, the container list, the network object's `Driver`, and the `Node` schema.
- Portainer source, read for behavior the docs do not publish: [`api/http/handler/endpoints/endpoint_list.go`](https://github.com/portainer/portainer/blob/develop/api/http/handler/endpoints/endpoint_list.go) (paging and `security.FilterEndpoints`), [`api/http/proxy/factory/docker/transport.go`](https://github.com/portainer/portainer/blob/develop/api/http/proxy/factory/docker/transport.go) (which Docker paths are administrator-only), and [`api/http/proxy/factory/docker/containers.go`](https://github.com/portainer/portainer/blob/develop/api/http/proxy/factory/docker/containers.go) (`applyAccessControlOnResourceList`).
- Portainer issue [#12952](https://github.com/portainer/portainer/issues/12952), open and unconfirmed, on API-versus-UI filtering of the container list.

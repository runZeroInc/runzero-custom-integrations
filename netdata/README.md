# Custom Integration: Netdata

Imports the nodes a [Netdata](https://www.netdata.cloud/) Agent knows about. Pointed at a
**Parent**, one request returns every child streaming to it; pointed at a standalone agent it
returns that agent's own host and nothing else.

**Read [Asset identity](#asset-identity) before deploying this.** Netdata is a metrics agent, not
an inventory system. It publishes a stable machine GUID, a hostname, and — with one extra request
per node — the OS, kernel, architecture, virtualization, and container runtime. It publishes **no
IP address and no MAC address for any node**, so every asset this integration emits correlates on
hostname alone.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations)
- An Explorer with network reach to the Netdata Agent, normally on TCP 19999

## Netdata requirements

- Netdata Agent **v1.40 or later** for `/api/v2/nodes`; **v2.0 or later** for `/api/v3/nodes`.
  The default `api_version` of `auto` tries v3 first and falls back to v2, so both are supported
  without configuration.
- The agent's HTTP API reachable from the Explorer. By default an agent listens on `0.0.0.0:19999`
  and serves its API without authentication.
- Optionally, a **bearer token**, if the agent has bearer protection enabled.

### Enabling API access

Netdata's dashboard and API are served by the same listener, and access is controlled in
`netdata.conf` rather than by a credential. Two settings matter:

```ini
[web]
    bind to = 0.0.0.0:19999
    # The Explorer's address, or a network it sits in, must be permitted here.
    # The default is "localhost *" on some packaged installs.
    allow dashboard from = localhost 10.0.0.0/8 192.0.2.10
```

Edit with `sudo /etc/netdata/edit-config netdata.conf`, then
`sudo systemctl restart netdata`. Confirm from the Explorer host:

```sh
curl -s 'http://netdata-parent.example.com:19999/api/v3/nodes' | head -c 400
```

An HTTP 403 means `allow dashboard from` does not include the caller. An empty reply on
`/api/v3/nodes` with a working `/api/v2/nodes` means the agent predates Netdata v2, which is
handled automatically.

### Creating a bearer token (only if bearer protection is enabled)

Most self-hosted agents serve the API unauthenticated and need no token — leave **Bearer token**
blank. If your agent has bearer protection turned on, mint a token on the agent host:

```sh
curl -s 'http://127.0.0.1:19999/api/v3/bearer_get_token'
```

Netdata restricts token issuance to callers it already trusts, so this must be run on the agent
itself. Paste the returned token into the **Bearer token** field.

### Pointing at a Parent

This integration is worth scheduling only against a
[Parent](https://learn.netdata.cloud/docs/netdata-parents/). Children configured to stream to a
Parent appear in that Parent's `/api/v3/nodes` output with `hops` of 1 or more, and their own
system detail is served by the Parent under `/host/<node name>/api/v1/info`. Confirm the fleet is
visible before scheduling:

```sh
curl -s 'http://netdata-parent.example.com:19999/api/v3/nodes' \
  | python3 -c 'import json,sys; [print(n["nm"], n.get("hops"), n.get("state")) for n in json.load(sys.stdin)["nodes"]]'
```

## Steps

### Netdata configuration

1. Confirm the agent version: `netdata -v`, or `curl -s http://<agent>:19999/api/v1/info | head -c 200`.
2. Permit the Explorer in `allow dashboard from` and restart the agent (see above).
3. If bearer protection is enabled, obtain a token on the agent host (see above).
4. Prefer a Parent over individual agents, so one task covers the fleet.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Netdata").
   - Toggle `Enable custom integration script` and paste in the contents of `netdata.star`.
   - Click `Validate` to ensure it has valid syntax, then `Save`.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Netdata Agent URL** (`url`): base URL of the agent or Parent, e.g.
     `https://netdata-parent.example.com:19999`. Required; nothing is hardcoded.
   - **Bearer token** (`api_token`): optional; only when bearer protection is enabled.
   - **API version** (`api_version`): optional; `auto` (default), `v3`, or `v2`.
   - **Collect per-node system detail** (`collect_node_details`): optional; default enabled.
   - **Maximum nodes to enrich** (`max_detail_nodes`): optional; default 500.
   - **Import stale and offline nodes** (`include_unreachable_nodes`): optional; default enabled.
   - **Attach the configured address to the local agent** (`attach_agent_address`): optional;
     default disabled. See [Asset identity](#asset-identity).
   - **Disable TLS validation** (`tls_disable_validation`): optional; only when the agent presents
     a self-signed certificate and the network path is trusted.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above.
   - Select an Explorer that can reach the agent.
   - Set the schedule and `Save`.

### Testing from the command line

The runZero CLI runs the script directly, which is the fastest way to confirm connectivity and see
what would be imported. `--validate` checks CONFIG and HTTP wiring against a local dummy server and
makes no request to your agent:

```sh
runzero script --filename netdata/netdata.star --validate
```

To run it against a real agent, pass each CONFIG parameter as a `--kwargs` pair and an output
directory. `-v` prints the script's own log lines:

```sh
runzero script \
  --filename netdata/netdata.star \
  --kwargs url=https://netdata-parent.example.com:19999 \
  --kwargs collect_node_details=true \
  --kwargs max_detail_nodes=200 \
  --output /tmp/netdata-run \
  --overwrite \
  -v
```

Add `--kwargs api_token=<token>` only if bearer protection is enabled, and
`--kwargs tls_disable_validation=true` only for a self-signed certificate on a trusted path.
`--kwargs` takes one `key=value` per flag; a value containing a comma **and** an `=` is corrupted
by the flag parser, so no parameter here is designed to need one.

### Running it as a scan

The same script can be attached to a scan task rather than an ingest task, so that collection runs
on the same schedule and Explorer as a subnet scan:

```sh
runzero scan --custom-integration-id <integration-id> <targets>
```

Use `runzero scan --help` for the flags your build supports. In the Console this is the
`custom-integration-id` shown on the integration's page after `Save`; the script itself is
unchanged, and the assets it reports merge exactly as they do from an ingest task.

### What's next?

- The task runs like any other ingestion task on the [tasks](https://console.runzero.com/tasks) page.
- Search for assets from this integration with `custom_integration:netdata`.
- Assets carry a `netdata.*` attribute set: machine GUID, agent version, hops, streaming state, OS
  and kernel detail, virtualization and container runtime, and every Netdata host label.
- Nodes are tagged `netdata` plus `netdata-agent-host` (the agent queried) or `netdata-child`, and
  a node that is not currently reachable also carries `netdata-stale` or `netdata-offline`.

## Asset identity

- **Target entity:** a machine that runs, or once ran, a Netdata Agent — either the agent being
  queried or a child streaming to it. It is a monitoring-agent registration, not a hardware record.
- **Source ID field:** `nodes[].mg`, the Netdata **machine GUID**.
- **Documentation evidence:** Netdata's own OpenAPI document types `mg` as "The machine guid of the
  node." Netdata's Node Identities page states the machine GUID is "a UUID that uniquely identifies
  this specific node", is generated once on first start, is written to
  `/var/lib/netdata/registry/netdata.public.unique.id`, and "remains permanent — never changing
  throughout the node's lifecycle." It is additionally mirrored into status files for crash
  recovery.
- **Uniqueness scope:** globally, in principle — it is a UUID minted per install. The agent
  hostname is nevertheless prepended, so two Parents polled into one runZero organization cannot
  collide, and so the id records which Parent reported the node.
- **Cardinality:** one node per machine GUID, therefore one asset per GUID. A Parent and a child
  both report the child, but only one of them is polled by a given task; polling both produces the
  same id from both, which merges rather than duplicates.
- **Stability:** the id survives a hostname change, an IP change, an OS upgrade, an agent upgrade,
  a reboot, a crash, and a re-claim to Netdata Cloud. It does **not** survive deleting
  `/var/lib/netdata/registry/` and every status file, which regenerates the GUID — practically, a
  reinstall that discards the state directory, or a container recreated without a persistent volume
  on `/var/lib/netdata`.
- **Reuse behavior:** no. A regenerated GUID is a fresh UUID; it is never handed to another machine.
- **Presence:** `mg` is a documented property of every node entry, and is absent only when the
  response is served by Netdata Cloud rather than by an agent. Values are screened against the UUID
  shape before use; anything else is skipped and counted.
- **Final runZero ID:** `netdata:<agent-host>:<machine-guid>` — for example
  `netdata:netdata-parent.example.com:5c9a1f2e-6b7d-4c88-9a10-2f3b4c5d6e70`. The agent host is the
  hostname from the configured URL, with scheme and port dropped so that reaching the same agent on
  a different port does not re-identify everything it reports.
- **Missing-ID behavior:** skip. The node is logged by its GUID or by the field that was unusable,
  never by the record body, and no id is invented. `new_uuid()` is not used anywhere in the script.
- **Match behavior (set once in `CONFIG`):** `no-mac-break no-ip-break no-name-break`. The GUID is a genuine stable vendor
  id, so it drives merges; but Netdata supplies no address to corroborate it, so a differing MAC, IP,
  or name must not disqualify a merge against an asset runZero already knows by other means.
- **Verdict:** **authoritative for the identifier, thin for the record.** The GUID is as stable as
  any identifier in this repository. What hangs off it is not: hostname, OS, kernel, architecture,
  virtualization, container runtime, and labels. That is real enrichment for a host runZero already
  scans, and real discovery of a host it does not reach — but it is hostname-correlated discovery,
  which is weaker than MAC or IP correlation, and a fleet of hosts with duplicate or generic
  hostnames will merge badly. Judge it against your naming discipline.

### Notes

- **What is imported:** one asset per entry in `GET /api/v3/nodes` (or `/api/v2/nodes`). Each
  asset carries the machine GUID, the Netdata Cloud node id when the node is claimed, the node
  name as its hostname, the agent version, the hop count, the streaming state, and the per-node
  status block (`code`, `msg`).
- **Per-node system detail** (**Collect per-node system detail**, on by default) adds one request
  per node. For the agent being queried that is `GET /api/v1/info`; for every child it is
  `GET /host/<node name>/api/v1/info`, which is how a Parent serves a child's own info. This
  supplies `os` and `osVersion` plus `os_id`, `os_id_like`, `kernel_name`, `kernel_version`,
  `architecture`, `virtualization`, `virt_detection`, `container`, `container_detection`,
  `is_k8s_node`, and the full host-label set. **Maximum nodes to enrich** caps the call count; nodes
  past the cap are still imported, without OS fields, and the number skipped is logged.
- **Host labels** are split by Netdata's own convention: labels beginning with `_` are set by the
  agent and land under `netdata.label_auto.*` (`os_name`, `architecture`, `virtualization`,
  `container`, `install_type`, and on cloud instances `cloud_provider_type`, `cloud_instance_type`,
  `cloud_instance_region`); operator-assigned labels land under `netdata.label.*`. Keeping them
  apart means a site's own `environment` label is never confused with an agent-derived one.
- **No addresses.** This is the integration's central limitation and it is not a parsing gap:
  `/api/vN/nodes`, `/api/v1/info`, and `/api/v3/stream_path` carry no IP address and no MAC address
  for any node. Netdata's network charts are keyed on interface *names*, not addresses. **Attach
  the configured address to the local agent** is the single opt-in exception: when enabled *and*
  the URL was written with a literal IP, that address is placed on the node with `hops` of 0 — the
  machine the agent runs on. It is off by default and deliberately refuses to resolve a hostname,
  because a name may point at a reverse proxy or a load balancer, and attaching a proxy's address
  to a monitored host is worse than attaching none.
- **Stale and offline nodes.** A Parent remembers children that have stopped streaming, and reports
  them with `state` of `stale` or `offline`. They are imported by default and tagged, because a
  host that has gone quiet is worth knowing about; **Import stale and offline nodes** turns them off.
- **Placeholder hostnames are skipped, not imported.** A node whose name is `localhost`,
  `unknown`, `(none)`, `netdata`, or a bare IP literal carries no usable identity — runZero rejects
  such a value as a hostname, and an asset with no other correlator would merge with every other
  such node. Those nodes are skipped and counted rather than emitted as unmergeable orphans.
- **Node names are validated before URL interpolation.** A name containing `/`, `?`, `#`, `\`, or a
  space cannot be safely placed in a `/host/<name>/api/v1/info` path, so the detail call is skipped
  for that node and logged; the node is still imported from the listing.
- **Streaming and memory:** each asset is reported as it is built through `report_asset()`, so a
  Parent with a large fleet never holds the whole inventory at once.
- **Pagination:** none. `/api/vN/nodes` returns the whole node list in one body and Netdata offers
  no cursor for it. The endpoint accepts `cardinality` to cap the count and `scope_nodes` to filter
  by name pattern; neither is used, because truncating an inventory silently is worse than a large
  response, and the body is small — a node entry is a handful of short fields.
- **Rate limiting:** Netdata publishes none for the agent API. `get_json` retries transient statuses
  three times by default with exponential backoff and honors `Retry-After`; nothing is hand-rolled.
- **No software, services, or vulnerabilities.** Netdata's collectors observe processes and sockets
  as *metrics* — a count of established connections, a per-process CPU series — not as an inventory
  of listening services with ports and versions. Nothing in the API maps onto `Service` or
  `Software` without inventing detail, so none is emitted.
- **Unverified assumptions:** this integration was built against Netdata's published OpenAPI
  document (`src/web/api/netdata-swagger.yaml`) and validated against local fixtures, not a live
  Parent. `/api/v3/info` is documented as returning a multi-node `agents[]` array with `machine_guid`,
  `hostname`, and OS fields, which would replace the N+1 detail loop with one request; its response
  is typed in the spec only as a bare object, so that shape is unconfirmed and the per-node
  `/api/v1/info` path — which is stable across every Netdata release and typed in the spec — is used
  instead.

## Future

- **Replace the N+1 detail loop with `/api/v3/info`.** If that endpoint really does return one
  entry per node with `machine_guid`, `hostname`, `os_name`, `architecture`, `virtualization`, and
  `host_labels`, a fleet of 500 nodes drops from 501 requests to 2. This needs one look at a live
  Netdata v2 Parent to confirm the response shape, and is the single highest-value follow-up here.
- **Netdata Cloud as an alternative source.** `https://app.netdata.cloud/api/v2/spaces/{space}/...`
  with an `Authorization: Bearer <token>` covers every node in a Space across every Parent, which
  suits an estate with several Parents. It is a different base URL, a different auth model, and a
  different response shape, so it belongs in its own integration rather than as a mode of this one.
- **Alerts as asset context.** `/api/v2/alerts` and `/api/v1/alarms` carry node identity alongside
  each alert. These are operational conditions rather than vulnerabilities, so they do not map onto
  `Vulnerability`; the useful shape would be a small set of custom attributes recording how many
  alerts a node is currently raising and at what severity, which would let a search surface
  monitored hosts that are unhealthy.
- **Node functions for real hardware detail.** Netdata exposes per-node "functions" — including
  `streaming`, which describes the parent/child link — through `/api/v3/function`. If any function
  reports the child's connection address, it would give this integration the IP correlation it
  currently lacks and would materially raise its value. Worth probing on a live Parent.
- **Kubernetes context.** `is_k8s_node` and the `_k8s_*` host labels are imported as attributes
  today. Correlating them against the shipped [`kubernetes/`](../kubernetes/) integration's node
  assets would let one confirm the other, without either needing new endpoints.

## API documentation

- Netdata Agent REST API index: https://learn.netdata.cloud/api
- REST API overview (agent vs. cloud): https://learn.netdata.cloud/docs/developer-and-contributor-corner/rest-api
- OpenAPI document — the source for every field, path, and deprecation used here:
  https://github.com/netdata/netdata/blob/master/src/web/api/netdata-swagger.yaml
- Node identities (machine GUID stability, on-disk location, node id, claim id):
  https://learn.netdata.cloud/docs/netdata-agent/node-identities
- Parent/child streaming: https://learn.netdata.cloud/docs/netdata-parents/
- Parent-child configuration reference: https://learn.netdata.cloud/docs/netdata-parents/parent-child-configuration-reference
- Host labels: https://learn.netdata.cloud/docs/netdata-agent/configuration/organize-systems-metrics-and-alerts
- Source: https://github.com/netdata/netdata

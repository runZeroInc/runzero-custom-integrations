# Custom Integration: Trend Micro Vision One

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Trend Micro Vision One requirements

- A Trend Vision One API key issued to a user role that can view the Endpoint Inventory. The key is a long-lived bearer token; no OAuth exchange is involved.
- The regional API domain for your tenant. An API key only works against the region it was issued in.

## Steps

### Trend Micro Vision One configuration

1. In the Trend Vision One console, go to **Administration > API Keys** and create a new API key.
2. Assign it a role whose **Endpoint Security > Endpoint Inventory** permission includes at least **View**. No response or task permissions are required — this integration only reads.
3. Copy the key value when it is displayed; it cannot be retrieved again.
4. Identify your regional API domain (**Administration > Console Settings**, or the [regional domains list](https://automation.trendmicro.com/xdr/Guides/Regional-domains/)). It is one of `https://api.xdr.trendmicro.com` (United States), `https://api.au.xdr.trendmicro.com`, `https://api.eu.xdr.trendmicro.com`, `https://api.in.xdr.trendmicro.com`, `https://api.sg.xdr.trendmicro.com`, `https://api.mea.xdr.trendmicro.com`, `https://api.uk.xdr.trendmicro.com`, `https://api.usgov.xdr.trendmicro.com`, or `https://api.xdr.trendmicro.co.jp` (Japan — note this region uses a `.co.jp` domain rather than a regional subdomain).

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Trend Micro Vision One").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Vision One API host** (`api_host`): the regional API domain your tenant is provisioned in.
   - **API key** (`api_token`): the Vision One API key created above.
   - **Inventory filter** (`inventory_filter`): optional; a Vision One filter expression sent as the `TMV1-Filter` header, for example `osPlatform eq 'windows'` or `not (eppAgentStatus eq 'off')`. Leave blank to import every endpoint.
   - **Import Trend agent products as software** (`import_software`): optional; default on. See the note on software below.
   - **Fetch MAC addresses** (`fetch_interfaces`): optional; default off. Costs one extra request per endpoint.
   - **MAC address lookup limit** (`interface_limit`): optional; default 1000. `0` removes the cap.
   - **Page size** (`page_size`): optional; default 100.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter. Note that this integration has no `url` parameter — the base URL is the
`api_host` enum value, and it must be the domain your tenant was provisioned in:

```bash
runzero script --filename trend-vision-one/trend-vision-one.star \
  --kwargs api_host=https://api.eu.xdr.trendmicro.com \
  --kwargs api_token=eyJhbGciOiJFUzI1NiJ9.ExampleFakeVisionOneApiKey.0123456789abcdef \
  --kwargs page_size=50 \
  --kwargs import_software=true \
  --kwargs fetch_interfaces=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./trend-vision-one-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. Leave `fetch_interfaces` off for a first run: it costs one extra request per
endpoint, so enabling it turns a smoke test against a large tenant into thousands of
calls. If you do enable it, cap `interface_limit`.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside an `inventory_filter` reaches the `TMV1-Filter` header intact. Only a
value that *also* contains an `=` flips the flag into comma-separated parsing, and then
the value is cut at the first comma — the remainder either becomes a fabricated second
parameter or aborts the run with `must be formatted as key=value`. Vision One's filter
syntax spells equality as the `eq` operator rather than `=`, so a filter does not
normally hit that combination. Filters still need quoting for the *shell*, because they
contain spaces and parentheses:

```bash
  --kwargs "inventory_filter=osPlatform eq 'windows' and eppAgentStatus eq 'on'"
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename trend-vision-one/trend-vision-one.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Vision One accepts the key, that the key belongs to the
region named in `api_host`, or that any endpoint is parsed. The fixture scenarios are
what exercise the parsing:

```bash
python3 tests/run.py trend-vision-one
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat trend-vision-one/trend-vision-one.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_host=https://api.eu.xdr.trendmicro.com,api_token=eyJhbGciOiJFUzI1NiJ9.ExampleFakeVisionOneApiKey.0123456789abcdef' \
  --output ./trend-vision-one-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string — genuinely, and with no single-`=` exemption. Here a
comma in *any* value splits it, so an `inventory_filter` containing a comma cannot be
passed this way at all even though `script --kwargs` accepts it. Prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with endpoint data pulled from Trend Micro Vision One.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:trend-vision-one`.

## Asset identity

- Target entity: an endpoint — a physical machine, virtual machine, or server — carrying a Trend Vision One endpoint protection agent or XDR sensor.
- Source ID field: `agentGuid`
- Documentation evidence: Trend documents `agentGuid` as "The ID of the endpoint on the Trend Vision One platform" in the filter reference for `GET /v3.0/endpointSecurity/endpoints` (reproduced verbatim in Trend's own `trendmicro/vision-one-mcp-server`, `internal/v1mcp/tooldescriptions/descriptions.go`). Trend's Python SDK `pytmv1` uses the same value as the path parameter for `GET /v3.0/endpointSecurity/endpoints/{agentGuid}`, so it is the platform's addressable handle for the endpoint and not a per-response row key.
- Uniqueness scope: the Vision One tenant reachable with the configured API key. Values are UUIDs minted by the platform, so they are unique by construction rather than by tenant partitioning; the regional API host is carried in the runZero ID as a deployment boundary, since an API key is valid in exactly one region and the same estate is never served by two regions.
- Cardinality: one inventory row per endpoint. The optional per-endpoint profile call returns the same `agentGuid` and is merged into the same asset, so it does not create a second identity.
- Stability: survives rename, reboot, IP/MAC change, policy change, and agent version upgrade — none of those are inputs to the value, and the run below was verified against a fixture that renamed the host and replaced its address while keeping `agentGuid`.
- Reuse behavior: **not confirmed.** Trend does not publish whether an uninstall/reinstall of the agent re-registers under the existing `agentGuid` or mints a new one, and no reachable documentation, SDK comment, or sample states it either way. The field name says "agent", which suggests it tracks the agent installation rather than the machine, but that reading could not be verified. If your estate shows duplicate assets after mass agent redeployments, `matchBehavior` cannot fix it and the duplicates have to be reconciled in runZero. An earlier revision of this document recommended `"no-id-break no-ip-break"` here; that advice was wrong. `no-id-break` only disables `MatchBreakByForeignID`, while a separate and unconditional gate — `ForeignIDSetsHaveMergeConflict`, reached from `Asset.CanMergeWithDevice` — refuses any merge that would put two different foreign IDs from the same custom integration on one asset. That gate never consults `matchBehavior`, because `SourceAllowsConflictingForeignIDs` returns false for custom integrations. A re-registered agent therefore always produces a second asset regardless of the tokens set here.
- Presence: present on every inventory row in practice, but modeled as optional by Trend's own SDK, so it is checked.
- Final runZero ID: `trend-vision-one:<regional-api-host>:<agentGuid>`
- Missing-ID behavior: the record is skipped and a line naming only the endpoint name is logged. No fallback identity is invented.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. `agentGuid` is authoritative and drives matching, but every other signal in this payload is weak or absent: the inventory listing carries **no MAC address at all** unless the optional adapter pass is enabled, `ipAddresses` are DHCP leases on roaming laptops, and `endpointName` follows a rename. Leaving those break rules on would let ordinary network churn fork one endpoint into two assets. `id-break` is deliberately left on, subject to the unresolved reinstall question above.
- Verdict: scoped authoritative.

### Notes

- **What is imported:** assets, and optionally software. Endpoints come from `GET /v3.0/endpointSecurity/endpoints`. This is the current path; older Trend integrations and the `TMV1-Query`-based "Search" API used `GET /v3.0/eiqs/endpoints`, which is a different resource with a different response shape (value-wrapped fields, and MAC addresses inline). Both still exist — `pytmv1` exposes them as `GET_ENDPOINT_DATA` (`/eiqs/endpoints`) and `GET_ENDPOINT_LIST` (`/endpointSecurity/endpoints`) — and this integration uses the `endpointSecurity` one because it is the surface Trend's own current tooling targets and it carries the agent/sensor health fields.
- **No vulnerabilities and no services.** Vision One's endpoint inventory contains no CVE list and no listening-port data, so neither object type is built.
- **Software is not a general software inventory.** With `import_software` on, one `Software` record is created per product name reported under `eppAgent.productNames` and `edrSensor.productNames`, versioned by that component's `version` — that is, the Trend endpoint protection agent and the Trend XDR sensor themselves (e.g. "Trend Micro Apex One" 14.0.12658). Vision One reports nothing about other software on the host. The pattern, engine, and component versions the agents also report are security-content updates rather than installed products, so they stay on the asset as custom attributes (`trend_vision_one_epp_agent_component_version` and friends) instead of being dressed up as software. No `cpe23` is set: Trend publishes no CPE for these products, and `Software.cpe23` only accepts the CPE 2.2 `cpe:/a:` binding, so a hand-built string would fail validation.
- **MAC addresses require an extra request per endpoint.** The inventory listing returns `ipAddresses` but no MAC. MACs live in the `interfaces[]` array of `GET /v3.0/endpointSecurity/endpoints/{agentGuid}`, which is one request per endpoint. `fetch_interfaces` is off by default for that reason; turn it on (and raise or clear `interface_limit`) when the added merge accuracy is worth the request count. With it on, interfaces are built per adapter so each MAC is paired with its own addresses. A detail lookup that fails is logged and skipped, and the endpoint is still imported from the listing data.
- **`lastUsedIp` is never placed on a network interface.** It is the address the endpoint most recently connected from, which for an agent checking in through a Service Gateway, a proxy, or a NAT gateway is a shared egress address. Attaching it would invite unrelated endpoints to merge onto one asset. It is kept as the `trend_vision_one_last_used_ip` attribute instead.
- **Loopback, unspecified, and link-local addresses are filtered** out of every address list (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`) before interfaces are built, because an agent that reports only `127.0.0.1` would otherwise merge the whole estate onto one asset. The unfiltered list is retained as `trend_vision_one_ip_addresses`.
- **Pagination** is cursor-based: each page carries `nextLink`, an absolute URL that already contains the paging cursor in its query string. It is followed with no `params` argument at all, because passing `params=` would replace that query string and silently restart pagination at the first page. Page size is requested through `top` on the first call only. A `nextLink` that points at a host other than the configured regional API host is not followed, and the truncation is logged.
- **Filtering** uses the `TMV1-Filter` request header rather than a query parameter, and the header is repeated on every page including those reached through `nextLink`.
- **Rate limiting:** Vision One enforces per-API request quotas that vary by endpoint and license tier, and answers `429` with `Retry-After`. The shared HTTP helper retries `408/425/429/5xx` with exponential backoff and honors `Retry-After`; the backoff multiplier is widened here so a long adapter pass does not exhaust its retry budget racing the quota window.
- **Unverified assumptions**, stated plainly:
  - Whether an agent reinstall preserves `agentGuid` (see Asset identity above).
  - The maximum accepted `top` value. Trend's published reference for this endpoint was not reachable without a tenant login; `pytmv1` defaults to 100, which is the default used here, and the parameter is capped at 1000. Because the real cap is unverified, a `400` on the first page with an operator-raised `page_size` falls back once to `top=100` with a logged explanation rather than ending the run with zero assets.
  - The detail response's `interfaces[]` shape (the only MAC source). When adapter lookups succeed but none of them yields an `interfaces[]` list, the run logs that the schema may differ rather than silently importing no MACs.
  - The exact regional domain list is taken from Trend's published regional domains guide and from the region mapping in `trendmicro/vision-one-mcp-server`; both agree, including the `.co.jp` Japan domain.
- This integration was validated against local fixtures, not a live Trend Micro Vision One tenant.

## Future

- **Endpoint response actions as an outbound integration.** `POST /v3.0/response/endpoints/isolate` and `/v3.0/response/endpoints/restore` accept a list of endpoints keyed by `agentGuid` or `endpointName`, and `/v3.0/response/endpoints/collectFile`, `/runScript`, and `/terminateProcess` round out the set. An outbound integration could isolate assets matching a runZero query. **Isolation is disruptive**: it cuts the endpoint off from the network except for its managing Trend server, so it should never be wired to a broad query, and any implementation needs an explicit confirmation step and a matching restore path. These calls are non-idempotent task submissions and must be issued with `retries=0`.
- **Task status polling.** `GET /v3.0/response/tasks/{id}` and `GET /v3.0/endpointSecurity/tasks` report the state of submitted actions, which any outbound integration would need in order to report success rather than just acceptance.
- **Workbench alert ingestion as an event feed.** `GET /v3.0/workbench/alerts` returns alerts with a severity, a score, an investigation status, and an `impactScope.entities[]` array whose host entities carry `guid`, `name`, and `ips` — enough to attach detections to the same assets this integration imports. `GET /v3.0/workbench/alerts/{id}` adds matched rules and indicators. The alerts list is time-windowed and cursor-paginated the same way, so an incremental feed is straightforward.
- **Observed Attack Techniques.** `GET /v3.0/oat/detections` returns per-technique detections with MITRE tactic and technique IDs, a risk level, and an `endpoint` block containing `agentGuid` and `ips`. This is a higher-volume surface than Workbench alerts and is better suited to a filtered enrichment pass (for example, importing only high and critical risk levels as asset attributes or tags) than to wholesale ingestion. `POST /v3.0/oat/dataPipelines` additionally registers a package-based delivery pipeline for bulk export.
- **EDR coverage-gap reporting.** The inventory listing already distinguishes an endpoint with only an EPP agent from one that also runs the XDR sensor, and the `availableActions` filter enumerates the exact gap states Trend recognizes — `unmanaged`, `sensorDisabled`, `sensorUpdateRequired`, and the per-product `*MaintenanceRecommended` values. A second scheduled task running this same script with `inventory_filter` set to one of those states would tag precisely the endpoints missing detection and response coverage, which combined with runZero's own discovery makes the "device runZero sees but Trend does not manage" set directly queryable.
- **Endpoint activity search.** `GET /v3.0/search/endpointActivities` exposes per-event telemetry including source and destination addresses and ports. It is an event search rather than an inventory, and the retention window is short, so it is a poor fit for asset import — noted here only because it is the surface that would otherwise look like a source of service data.

## API documentation

- Regional API domains: https://automation.trendmicro.com/xdr/Guides/Regional-domains/
- Trend Vision One API reference (tenant login required): https://automation.trendmicro.com/xdr/api-v3
- Endpoint inventory paths, request headers, and region mapping, from Trend's official MCP server: https://github.com/trendmicro/vision-one-mcp-server — `internal/v1client/endpoint.go`, `internal/v1client/v1client.go`, `internal/v1mcp/tooldescriptions/descriptions.go`
- Endpoint response models, pagination shape (`items` / `nextLink`), and the `eiqs` vs `endpointSecurity` path split, from Trend's official Python SDK: https://github.com/trendmicro/tm-v1-pytv1 — `src/pytmv1/model/enum.py`, `src/pytmv1/model/common.py`, `src/pytmv1/model/response.py`, `src/pytmv1/api/endpoint.py`
- Legacy `/v3.0/eiqs/endpoints` field list, as consumed by the Cortex XSOAR content pack: https://github.com/demisto/content/tree/master/Packs/TrendMicroVisionOne

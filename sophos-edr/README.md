# Custom Integration: Sophos EDR

Imports computer and server endpoints from Sophos Central (Intercept X / EDR)
using the [Endpoint API](https://developer.sophos.com/docs/endpoint-v1/1/overview),
including health, protection, isolation, encryption, cloud, and ownership
metadata.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- A [Custom Integration Script Secret](https://console.runzero.com/credentials) credential configured with your Sophos API credential client ID and client secret.

## Sophos requirements

- A Sophos Central **API credential** (service principal). A Super Admin can
  create one under **Global Settings → API Credentials** in
  [Sophos Central Admin](https://central.sophos.com/manage). See
  [Getting Started as a Tenant](https://developer.sophos.com/getting-started-tenant).
- The read-only **Service Principal ReadOnly** role is sufficient; this
  integration only calls `GET` endpoints.
- Tenant credentials work with no extra configuration. For **partner** or
  **organization** service principals, also set the `tenant_id` and
  `data_region_url` parameters for the tenant you want to import.

## Parameters

| Key | Required | Description |
| --- | --- | --- |
| `client_id` | yes | Sophos Central API credential client ID |
| `client_secret` | yes | Sophos Central API credential client secret |
| `tenant_id` | no | Target tenant ID. Only needed for partner/organization credentials; discovered via `/whoami/v1` for tenant credentials |
| `data_region_url` | no | Regional API host, e.g. `https://api-us03.central.sophos.com`. Only needed with an explicit `tenant_id` |
| `endpoint_types` | no | Filter to `computer` and/or `server`; blank imports all |
| `last_seen_days` | no | Only import endpoints seen within the last N days (`lastSeenAfter=-P<N>D`); 0 imports all |

## How it works

1. Exchanges the client ID/secret for a JWT at
   `https://id.sophos.com/api/v2/oauth2/token` (client credentials,
   `scope=token`, 1 hour lifetime). The token is refreshed automatically if a
   page request returns 401 mid-run.
2. Calls `https://api.central.sophos.com/whoami/v1` to discover the tenant ID
   and regional data host, unless both are provided as parameters.
3. Pages through `GET {dataRegion}/endpoint/v1/endpoints?view=full` with
   `pageSize=100` (documented maximum) and the `X-Tenant-ID` header, following
   key-based pagination: fetch continues with `pageFromKey=<pages.nextKey>`
   until `nextKey` is absent.
4. Streams each page to runZero with `report_assets`, so large inventories are
   never held in memory.

Rate limiting (HTTP 429) and transient server errors are retried automatically
with exponential backoff, honoring `Retry-After`.

## Asset identity

- Target entity: Sophos Central managed endpoints (computers and servers
  running the Sophos agent).
- Source ID field: `id`
- Documentation evidence:
  [GET /endpoints/{endpointId}](https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/%7BendpointId%7D/get)
  — `id (required) string (uuid) "Unique ID for the endpoint."`
- Uniqueness scope: Sophos Central tenant (UUIDs are globally unique in
  practice; the tenant ID is included in the namespace regardless).
- Cardinality: one `items[]` row per endpoint in `GET /endpoints`; child data
  (products, volumes, agent services) is nested in the same row and imported
  as software and custom attributes, never as separate assets.
- Stability: the ID persists across polls, renames, IP/MAC changes, OS and
  agent updates. A full agent reinstall registers a new endpoint ID; Sophos
  flags suspected duplicates via the `cloned` field, which is imported.
- Reuse behavior: UUIDs; not documented as recycled.
- Presence: required field in the documented response schema.
- Final runZero ID: `sophos:<tenant-id>:<endpoint-id>`
- Missing-ID behavior: skip the record with a log line (no fallback ID).
- Match behavior: `no-mac-break no-ip-break no-name-break` — the vendor ID is
  authoritative, so normal network churn must not fragment the asset.
- Verdict: scoped authoritative foreign ID.

## Imported data

| Sophos field | runZero field |
| --- | --- |
| `id` (+ tenant ID) | `ImportAsset.id` (`sophos:<tenant>:<id>`) |
| `hostname` | `hostnames` |
| `os.name` | `os` |
| `os.majorVersion`/`minorVersion`/`build` | `osVersion` (dotted) |
| `type` / `os.isServer` | `deviceType` (`Server` when applicable) |
| `ipv4Addresses`, `ipv6Addresses`, `macAddresses` | `networkInterfaces` (all IPs on the first MAC; additional MACs as extra interfaces — the API does not correlate IPs to MACs) |
| `assignedProducts[]` (code, version, status) | `software` (vendor `Sophos`) |
| `health.*`, `tamperProtection*`, `lockdown.*`, `isolation.*`, `encryption.volumes`, `cloud.*`, `group`/`groupHierarchy`, `associatedPerson.*`, `serialNumber`, `online`, `cloned`, `lastSeenAt`, `lastOsUpdateAt`, `lastAgentUpdateAt`, `tags` | `customAttributes` |

Not imported: `packages` / `deviceSoftware` (available agent package choices,
not asset state).

Note: per the Sophos docs, only Mac endpoints currently report `serialNumber`.

## Steps

### Sophos configuration

1. Sign in to [Sophos Central Admin](https://central.sophos.com/manage) as a Super Admin.
2. Go to **Global Settings → API Credentials** and add a new credential
   (ReadOnly role recommended).
3. Record the client ID and client secret.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select **Custom Integration Script Secrets**.
   - Enter the Sophos client ID and client secret.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a descriptive name (e.g. `sophos-edr`), paste the script, click
     **Validate**, then **Save**.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above, pick an
     Explorer, set the schedule, and **Save**.

## Validation

Local validation with the `runzero` CLI:

```bash
runzero script --filename sophos-edr/sophos-edr.star --validate
runzero script --filename sophos-edr/sophos-edr.star \
  --kwargs client_id=<CLIENT_ID> --kwargs client_secret=<CLIENT_SECRET>
```

Verified with a local fixture: stable IDs across repeated runs, distinct IDs
for distinct endpoints, records without `id` skipped, pagination followed to
the final page, and 401 mid-run token refresh.

## Documentation references

- Authentication and whoami: <https://developer.sophos.com/getting-started-tenant>
- Endpoint API overview: <https://developer.sophos.com/docs/endpoint-v1/1/overview>
- List endpoints (pagination, filters, views): <https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/get>
- Endpoint object schema: <https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/%7BendpointId%7D/get>

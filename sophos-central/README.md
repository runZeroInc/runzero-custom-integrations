# Custom Integration: Sophos Central

Sophos Central is the cloud console for Sophos endpoint protection, Intercept X,
and XDR. This integration imports the managed endpoint inventory into runZero
through the Sophos Central Endpoint API, discovering the tenant's data region
automatically and, for partner and organization credentials, walking every
managed tenant.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Sophos Central requirements

- A Sophos Central API credential (tenant-level) or service principal
  (partner/organization-level) with a client ID and client secret. Read access to
  the Endpoint API is enough; the integration never writes.
- The right role is **Service Principal Read-Only**. Sophos offers Service Principal
  Super Admin, Management, Forensics, Read-Only, Active Directory Sync, and Firewall at
  the tenant level, and the first four at the enterprise level. Read-Only is the correct
  least-privilege choice for this integration.
- **The administrator creating the credential must hold Super Admin.** A lesser admin
  cannot create API credentials at all, which is a separate question from what role the
  credential itself gets.
- Network egress from the Explorer to `https://id.sophos.com`,
  `https://api.central.sophos.com`, and the regional data-region hosts
  (`https://api-us01.central.sophos.com`, `api-eu01`, `api-eu02`, `api-ca01`,
  `api-au01`, `api-jp01`, `api-br01`, `api-in01`, and the rest). The regional
  host is discovered at run time, so allow the whole
  `*.central.sophos.com` set rather than one host.
- Awareness of the API rate limits: 100 requests per minute (bursting to 300)
  and 200,000 per day, applied per credential, per account, and per source IP
  across **all** Sophos APIs.

## Steps

### Sophos Central configuration

1. Sign in to Sophos Central as a **Super Admin**.
   - **Tenant credentials:** at `https://central.sophos.com/manage`, go to
     **Global Settings > Access Control > API Credentials**, click
     **Add Credential**, give it a name and description, and assign the
     **Service Principal Read-Only** role.
   - **Partner credentials:** in Sophos Central Partner, go to
     **Settings & Policies > API Credentials**.
   - **Organization credentials:** in Sophos Central Enterprise, go to
     **Settings & Policies > API Credentials**.
2. Record the **Client ID** and **Client Secret**. The secret is shown only once.
3. Confirm access by requesting a token from
   `https://id.sophos.com/api/v2/oauth2/token` with
   `grant_type=client_credentials&scope=token` and calling
   `https://api.central.sophos.com/whoami/v1` with the returned bearer token.
   The `idType` field in that response tells you which kind of credential you
   have.
4. For partner or organization credentials, note the tenant IDs you want to
   import if you do not want every managed tenant.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Sophos Central").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Sophos Central API URL** (`url`): the common API URL, normally `https://api.central.sophos.com`. The per-tenant data region host is discovered from it.
   - **Sophos ID authentication URL** (`auth_url`): optional; the OAuth2 token service, default `https://id.sophos.com`.
   - **Tenant IDs** (`tenant_ids`): optional; comma-separated tenant IDs to import. Only used with partner or organization credentials; leave blank to import every managed tenant.
   - **API credential client ID** (`client_id`): the client ID of the API credential or service principal.
   - **API credential client secret** (`client_secret`): the matching client secret.
   - **Page size** (`page_size`): optional; default 100, maximum 500. See the note on `pages.maxSize` below.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a credential, find out what kind of credential it actually is, and see
what the endpoint inventory returns before scheduling anything. `--kwargs` is
repeated once per parameter:

```bash
runzero script --filename sophos-central/sophos-central.star \
  --kwargs url=https://api.central.sophos.com \
  --kwargs client_id=a1b2c3d4-e5f6-4071-89ab-cdef01234567 \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --kwargs page_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./sophos-central-run
```

`auth_url` defaults to `https://id.sophos.com` and rarely needs setting.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**Run it verbose the first time and read the `whoami` result.** A tenant
credential imports one tenant; a partner or organization credential enumerates
every managed tenant and will happily walk hundreds of them, one full endpoint
listing each, against a 100-request-per-minute budget. Which one you hold is
not obvious from the client ID — it is the `idType` field in the `whoami`
response, and it decides whether this command finishes in seconds or in a very
long time.

**`tenant_ids` passes from the command line as a whole list.** `--kwargs` hands
the value to the script verbatim, commas included, as long as the pair contains a
single `=` — and a tenant ID is a UUID, so a comma-separated list arrives intact:

```bash
runzero script --filename sophos-central/sophos-central.star \
  --kwargs url=https://api.central.sophos.com \
  --kwargs client_id=a1b2c3d4-e5f6-4071-89ab-cdef01234567 \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --kwargs tenant_ids=11111111-2222-3333-4444-555555555555,66666666-7777-8888-9999-aaaabbbbcccc \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./sophos-two-tenants --overwrite
```

The flag does have a sharp edge, but it is a different one. A value carrying a
*second* `=` **as well as** a comma is re-read as CSV: the value is cut off at the
comma and the remainder becomes a parameter the integration never declared —
silently, with no error. The client secret is the opaque value here that could be
that shape. Wrap it in double quotes to keep it a single field
(`--kwargs '"client_secret=a=b,c"'`), doubling any double quote inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename sophos-central/sophos-central.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Sophos ID issues a token,
and it does not exercise the data-region discovery — the redirect from the
common API host to a regional `api-xx01.central.sophos.com` host is the part
most likely to be blocked by an egress policy, and validation will never
reveal that.

The fixture under `sophos-central/tests/fixtures/` exercises the tenant
discovery path offline:

```bash
python3 tests/run.py sophos-central
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat sophos-central/sophos-central.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.central.sophos.com,client_id=a1b2c3d4-e5f6-4071-89ab-cdef01234567,client_secret=<secret>' \
  --output ./sophos-central-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is genuinely stricter than `script
--kwargs`: it is one comma-separated string, so no value passed through it may
contain a comma at all, and a multi-tenant `tenant_ids` list cannot be expressed
this way — the commas that separate tenant IDs are the same commas that separate
parameters. Use `script --kwargs` or the console credential form for that.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Sophos Central.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:sophos-central`.

## Asset identity

- Target entity: a physical or virtual computing endpoint (workstation, laptop,
  or server) running a Sophos Central managed agent.
- Source ID field: `items[].id`
- Documentation evidence:
  https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/get — the
  endpoint object declares `id` as a required `string (uuid)`, "ID of the
  endpoint". The same value is the path parameter of
  `GET /endpoint/v1/endpoints/{endpointId}` and the member of the `ids` array
  accepted by `POST /endpoint/v1/endpoints/isolation`, so it is the API's own
  permanent handle for the endpoint rather than a row or event key. Every
  endpoint object also carries `tenant.id`, and the tenant-scoping contract is
  stated at https://developer.sophos.com/intro: tenant-scoped routes require an
  `X-Tenant-ID` header, and one regional `apiHost` serves many tenants.
- Uniqueness scope: tenant. The UUID is unique inside one Sophos Central tenant.
  It is **not** safe to treat as globally unique in this integration's context,
  because a partner or organization credential walks many tenants against the
  same data-region hostnames in a single run.
- Cardinality: one `/endpoint/v1/endpoints` item per endpoint. There are no
  child rows: the addresses, MACs, health service details, assigned products,
  group hierarchy, and encryption volumes are all nested inside the single
  endpoint object, so nothing is many-to-one.
- Stability: the UUID is assigned when the agent registers and survives rename,
  IP/MAC change, OS upgrade, agent upgrade, group move, and re-scan. It is
  replaced when the agent is uninstalled and reinstalled, or when the endpoint is
  deleted from Central and re-enrolled — that is a genuinely new registration in
  Sophos's model, and the previous asset simply stops being updated. The API also
  exposes a `cloned` boolean for endpoints Sophos believes were imaged from
  another endpoint; it is imported as a custom attribute so a duplicate-looking
  pair can be identified.
- Reuse behavior: not documented. As a v4 UUID the practical reuse risk is nil,
  and Sophos publishes no ID-recycling behavior for deleted endpoints.
- Presence: required. `id` is marked required in the 200 schema and is the one
  field returned even by the `basic` view and by partial `fields=` responses
  ("`id` is always returned"). A record that still arrives without one is
  skipped rather than given an invented ID.
- Final runZero ID: `sophos-central:<tenant-id>:<endpoint-id>`. The tenant ID is
  the authoritative one for the poll — the `whoami` response's own `id` for
  tenant credentials, or the tenant record's `id` from `/partner/v1/tenants` or
  `/organization/v1/tenants` — not the hostname and not the data region host,
  because the data region host is shared across tenants and the hostname is
  neither unique nor stable.
- Missing-ID behavior: skip. The record is logged as
  `skipping endpoint with no id: hostname=<hostname>` and dropped. No random or
  synthesized ID is ever generated.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The endpoint UUID
  stays authoritative for matching, but this is an EDR-managed laptop population
  where the reported MAC, IP, and hostname churn constantly — wireless roaming,
  VPN adapters, MAC randomization, DHCP, and rename. Those dimensions must not
  disqualify a merge with an asset runZero already discovered by scan.
- Verdict: scoped authoritative.

### Notes

- **Assets** come from `GET {apiHost}/endpoint/v1/endpoints?view=full`, streamed
  to runZero one page at a time. `hostname` becomes the hostname;
  `os.name` (falling back to `os.platform`) becomes the OS and
  `os.majorVersion`/`minorVersion`/`build` are joined into the OS version;
  `lastSeenAt` becomes `lastSeenTS`. There is no first-seen field in this API, so
  `firstSeenTS` is left unset. A `lastSeenAt` that arrives with no zone designator
  is read as UTC, so the value is **clamped to the current time** before assignment:
  runZero rejects an asset whose last-seen time is in the future and the error fails
  the entire record, so a source reporting local time east of UTC would otherwise
  have every asset dropped. The clamp skews last-seen toward the present instead of
  losing the asset.
- **`view=full` is mandatory, not an optimization.** Sophos documents the
  default view as `summary` and `basic` as "only ID, type, tenant and hostname
  fields". Only `full` returns the addresses, MACs, health detail, assigned
  products, group, encryption, isolation, and tags this import maps.
- **The three-step authentication and region discovery.** (1) `POST
  https://id.sophos.com/api/v2/oauth2/token` with
  `grant_type=client_credentials`, the client ID and secret, and the literal
  `scope=token`, form-encoded. (2) `GET
  https://api.central.sophos.com/whoami/v1` with that bearer token, which
  returns `id`, `idType` (`tenant`, `partner`, or `organization`), and
  `apiHosts`. (3) Every data call goes to the region-specific host with both
  `Authorization: Bearer <token>` and `X-Tenant-ID: <tenant id>`. Calling the
  common host for endpoint data does not work, and skipping `whoami` means not
  knowing which regional host to call.
- **Partner and organization credentials enumerate tenants; they are not
  rejected.** For those credential types `whoami` returns no
  `apiHosts.dataRegion`, because there isn't one — the credential spans regions.
  The integration then pages `GET {apiHosts.global}/partner/v1/tenants` (header
  `X-Partner-ID`) or `GET {apiHosts.global}/organization/v1/tenants` (header
  `X-Organization-ID`) with `page`, `pageSize`, and `pageTotal=true`, and imports
  each tenant against that tenant's own `apiHost`. Set **Tenant IDs**
  (`tenant_ids`) to restrict the run to specific tenants; a requested tenant the
  credential does not manage is logged by ID. A tenant whose record carries no
  `apiHost` is skipped and logged, because there is nowhere to read its data
  from. The field is ignored, with a log line, for tenant-level credentials.
- **Two different pagination models in one product.** The endpoint inventory is
  cursor paginated: `pages.nextKey` is fed back as `pageFromKey`, and the
  documented termination condition is `nextKey` being absent ("This field won't
  present if there are no more pages to fetch"). `nextKey` is an opaque key, not
  a URL, so the query parameters are rebuilt on every request and the cursor
  cannot be lost. The tenant lists are offset paginated with `page`/`pageSize`,
  where `pages.total` is the number of **pages** (a real response shows 17 items
  at size 2 reported as `total: 9`), so the loop trusts `pages.total` when
  `pageTotal=true` is honored and falls back to a short page otherwise.
- **The maximum page size is genuinely ambiguous in Sophos's own material**, so
  the script adapts instead of guessing. The route reference states no numeric
  ceiling; the docs examples show `"maxSize": 100`; a captured real response from
  this endpoint shows `"maxSize": 500`; the reference XSOAR client says the
  maximum is 100. The default here is a conservative **100**, and every response
  publishes `pages.maxSize`, which the script uses to lower the requested page
  size automatically when the API reports a smaller ceiling. Raise **Page size**
  to 500 on a tenant where you have confirmed the larger value works.
- **Loopback and link-local addresses are filtered out of the interfaces.** The
  agent regularly reports `127.0.0.1`, `169.254.0.0/16`, `::1`, and `fe80::/10`
  — the vendor's own published sample response has an endpoint whose entire
  `ipv6Addresses` array is `fe80::` addresses. Letting those reach a
  NetworkInterface would give every such host the same address and invite runZero
  to merge unrelated machines. `127.0.0.0/8`, `0.0.0.0`, `169.254.0.0/16`, `::1`,
  `::`, and `fe80::/10` are dropped, and the complete unfiltered lists are kept
  as the `sophos_central_ipv4_addresses`, `sophos_central_ipv6_addresses`, and
  `sophos_central_mac_addresses` custom attributes.
- **Interfaces are built without inventing a MAC-to-address binding.** Sophos
  returns `macAddresses`, `ipv4Addresses`, and `ipv6Addresses` as three
  independent parallel arrays with no documented correlation between them.
  Pairing the first MAC with all the addresses would assert a relationship the
  API never states, so the usable addresses go on one interface of their own and
  each MAC gets an interface carrying only itself.
- **Virtual adapter MACs are imported as-is, and can collide across hosts.**
  Sophos reports every adapter the agent sees, including fixed-address virtual
  ones — VMware host-only/NAT adapters (`00:50:56:C0:00:01`, `00:50:56:C0:00:08`)
  and VirtualBox host-only adapters (`0A:00:27:00:00:xx`) use the same MAC on
  every machine that has them installed. Those MACs are present in the vendor's
  own published sample response. Because each imported asset carries a distinct
  foreign ID and the default `id-break` behavior is left on, two Sophos endpoints
  sharing such a MAC will not merge into each other; a collision with a
  runZero-scanned asset remains possible, and the raw list is retained as a
  custom attribute so it can be audited.
- **`deviceType` is mapped only where Sophos actually says something.** `type`
  has three documented values — `computer`, `server`, and `securityVm` (which
  Sophos notes is "no longer used"). `server` maps to `Server` and `securityVm`
  to `Virtual Machine`; an endpoint with `os.isServer` true also maps to
  `Server`. **`computer` is deliberately left unmapped**, because Sophos does not
  distinguish a laptop from a desktop and asserting either one would be wrong
  about half the fleet and would compete with runZero's own hardware
  fingerprinting. The raw value is always kept as the `sophos_central_type`
  custom attribute.
- **Tags** applied are `sophos-central`, `health:<overall>`, `group:<group
  name>`, `serial:<serial number>`, `isolated` when the endpoint is isolated,
  `tamper-protection:disabled` when tamper protection is explicitly off, and each
  of the tenant's own endpoint tags (Sophos caps these at 15 per endpoint and
  supplies a rendered `key:value` `displayString`).
- **Custom attributes** are prefixed `sophos_central_` and cover health
  (`overall`, `threats`, `services`, plus the names of any Sophos component
  service that is not running and the total service count), tamper protection
  (enabled and supported), assigned products (both the bare code list and
  `code=version/status` triples), group ID/name and the top-down group hierarchy
  path, the associated person (ID, name, and login), serial number, isolation
  status, lockdown status, encryption overall status, cloud provider and instance
  ID, `online`, `cloned`, and the OS platform/build/isServer detail.
- **No software inventory and no vulnerabilities are imported, because the API
  has neither.** The Endpoint API's 121 routes contain no installed-application
  inventory and no vulnerability or CVE route, and none of the 23 published
  Sophos Central APIs is a software-inventory or vulnerability API. The
  `/endpoint/v1/software/*` routes, `settings/device-software`, and the endpoint
  object's `packages`/`deviceSoftware` fields all describe **Sophos's own agent
  installer packages**, not third-party software. `assignedProducts[]` is
  likewise the Sophos component set (`coreAgent`, `interceptX`, `xdr`,
  `endpointProtection`, `deviceEncryption`, `mtr`, `ztna`); it is imported as
  custom attributes rather than synthesized into `Software` objects, so runZero's
  software inventory is not populated with the security agent's own parts. No
  `Software`, `Service`, or `Vulnerability` objects are produced.
- **No per-endpoint detail call is made.** `GET /endpoint/v1/endpoints/{id}`
  exists, but its 200 schema is field-for-field identical to a list item under
  `view=full`, so an N+1 pass would spend one request per endpoint against a
  100-requests-per-minute budget and return nothing new.
- Rate limiting: Sophos documents 10 requests/second (recommended), 100
  requests/minute (enforced, bursting to 300), 1,000/hour (recommended), and
  200,000/day (enforced), applied per credential, per account, and per source IP
  across all its APIs, and answers with 429. It documents **no `Retry-After`
  header** and prescribes exponential backoff with full jitter instead. Requests
  go through `get_json`/`post_json`, which retry transient statuses (408, 425,
  429, 500, 502, 503, 504) and transport errors by default; `retry_backoff` is
  raised to 2.0 seconds so a large partner estate does not burn its minute budget
  retrying tightly on the first tenant.
- Failure isolation: a failed page aborts only the tenant it belongs to. A
  partner run continues to the next tenant, and whatever was already streamed is
  kept.
- Unverified assumptions: (1) The numeric maximum `pageSize` for
  `/endpoint/v1/endpoints` is not stated normatively anywhere; the script reads
  `pages.maxSize` at run time instead of trusting either published number.
  (2) The real API returns at least one field that is not in the published
  schema (`lockdown.updateStatus` appears in captured responses), so the schema
  is treated as a floor; unknown fields are simply ignored. (3) Older captured
  responses show `os.isServer` and `tamperProtectionEnabled` as the strings
  `"True"`/`"False"` where the schema says boolean, so both spellings are parsed
  defensively. (4) Reuse of a deleted endpoint UUID is not documented.
  (5) `pages.items` on the endpoints route is described ambiguously ("the total
  number of items on all the pages"); it is not used, because pagination
  terminates on the absence of `nextKey`.
- This integration was validated against local fixtures, not a live Sophos
  Central tenant.

## Future

- **Outbound: endpoint isolation and scan-now — powerful, and explicitly
  disruptive.** `POST /endpoint/v1/endpoints/isolation` takes
  `{"enabled": true, "comment": "...", "ids": [...]}` with 1 to 50 endpoint IDs
  and a comment of at most 400 characters, returning `202 Accepted`;
  `PATCH /endpoint/v1/endpoints/{endpointId}/isolation` does one endpoint.
  `POST /endpoint/v1/endpoints/{endpointId}/scans` with an empty `{}` body
  returns `201` and `{"id", "status": "requested", "requestedAt"}`. Because this
  integration already stores each endpoint's UUID as
  `sophos_central_endpoint_id`, a runZero query result maps directly onto the
  `ids` array. **Isolation cuts an endpoint off the network and scan-now imposes
  real load on a user's machine, so neither belongs in a scheduled sync.** These
  are one-shot, human-approved response actions: an outbound integration would
  have to be triggered deliberately against an explicitly reviewed asset list,
  never on a timer, and Sophos itself warns to "wait for a period of time between
  turning endpoint isolation on and off using this API".
- **Alert and event ingestion.** `GET /common/v1/alerts` returns `id`,
  `category` (33 values), `product`, `severity` (`high`/`medium`/`low`),
  `raisedAt`, `groupKey`, `managedAgent{id, type}`, and `person{id}`, cursor
  paginated the same way as the endpoint inventory and filterable by `from`/`to`.
  `GET /siem/v1/events` — the shape the vendor's own
  `sophos/Sophos-Central-SIEM-Integration` client consumes — is a different
  animal: snake_case `{"has_more", "items", "next_cursor"}`, a `limit` between
  200 and 1000, a `from_date` given as a Unix timestamp, and a **hard 24-hour
  retention window**, so it must be polled at least daily or events are lost.
  `managedAgent.id` and `endpoint_id` are the same endpoint UUID this integration
  uses as its asset ID, so either feed keys straight onto the imported assets.
  Neither is imported here, because an alert is an event about a device, not a
  property of it.
- **Health status as a runZero policy signal.** `health.overall`,
  `health.threats.status`, `health.services.status`, the per-service
  running/stopped detail, `tamperProtectionEnabled`, and `lockdown.status` are
  already imported as attributes and `health:` tags, which makes queries like
  "assets where Sophos reports bad health and tamper protection is off"
  expressible today. The natural extension is the reverse direction: a policy
  integration that watches those attributes and raises a runZero finding, rather
  than leaving them as searchable metadata. The `healthStatus`,
  `tamperProtectionEnabled`, and `lockdownStatus` query filters on the endpoints
  route would let such a job pull only the endpoints in a bad state instead of
  the whole inventory.
- **EDR coverage-gap reporting.** This is the strongest case for the vendor
  pair. Comparing the runZero inventory against the Sophos inventory identifies
  hosts runZero has discovered that carry no Sophos agent at all, and Sophos
  endpoints runZero has never seen on the network. Because `assignedProducts[]`
  is imported, the same comparison extends to partial coverage — an endpoint with
  `coreAgent` and `endpointProtection` but no `interceptX` or `xdr` is licensed
  but not on EDR, and one without `mtr` is not under managed detection and
  response. The `lastSeenAt`, `online`, and `lastAgentUpdateAt` fields separate a
  genuinely unprotected host from one whose agent has simply not checked in.
- **Installed software, if it is ever needed, requires a different API.** The
  only routes to third-party application inventory are the Live Discover API
  (`/live-discover/v1/queries`, "Run osquery against endpoints connected to
  Sophos Central" — osquery's `programs`, `apps`, and `rpm_packages` tables would
  supply it) and the XDR Query API against the Sophos Data Lake. Both are async
  job models rather than inventory reads, Live Discover only reaches **online**
  endpoints and carries its own per-tenant limit of 10 query runs per minute and
  500 per day, and XDR queries need XDR licensing. That is a genuinely different
  integration shape from this one, not an extra endpoint call.

## API documentation

- Getting started, authentication, headers, regional host table, pagination model, and rate limits: https://developer.sophos.com/intro
- Tenant-credential walkthrough (token request and whoami example): https://developer.sophos.com/getting-started-tenant
- Who am I (identity, `idType` values, `apiHosts`): https://developer.sophos.com/docs/whoami-v1/1/routes/get
- Endpoint list (identity, `view`, filters, `pageFromKey`/`nextKey`, full object schema): https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/get
- Single endpoint (identical schema, used to justify skipping the N+1): https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/%7BendpointId%7D/get
- Partner tenant list (`X-Partner-ID`, `page`/`pageSize`/`pageTotal`, `apiHost`): https://developer.sophos.com/docs/partner-v1/1/routes/tenants/get
- Organization tenant list (`X-Organization-ID`): https://developer.sophos.com/docs/organization-v1/1/routes/tenants/get
- Endpoint isolation: https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/isolation/post
- Scan now: https://developer.sophos.com/docs/endpoint-v1/1/routes/endpoints/%7BendpointId%7D/scans/post
- Common alerts: https://developer.sophos.com/docs/common-v1/1/routes/alerts/get
- SIEM events (24-hour window, `has_more`/`next_cursor`): https://developer.sophos.com/docs/siem-v1/1/routes/events/get
- Full API catalog (used to confirm no software-inventory or vulnerability API exists): https://developer.sophos.com/apis
- Vendor reference client for the region/tenant discovery flow: https://github.com/sophos/Sophos-Central-SIEM-Integration (`api_client.py`)

# Custom Integration: Cortex XDR

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach your Cortex XDR API host over HTTPS.

## Cortex XDR requirements

- An **API Key** and its **API Key ID**, created with the **Standard** security level.
- Your tenant's **API FQDN**.

## Steps

### Cortex XDR configuration

1. **Create the API key.** In Cortex XDR go to **Settings → Configurations → Integrations →
   API Keys** and select **+ New Key**. Cortex XSIAM uses the same path. We could not
   establish the equivalent path in the newer unified Cortex console, so if your console
   does not match, check Palo Alto's documentation for your specific product rather than
   hunting for this menu.

2. **Choose Security Level: Standard.** This is the setting that decides whether the
   integration works at all.

   - **Standard** sends the key as-is in the `Authorization` header. This is what the script
     does, and it is what you need.
   - **Advanced** does not send the key. It sends a SHA-256 digest of the key concatenated
     with a nonce and a timestamp, along with `x-xdr-nonce` and `x-xdr-timestamp` headers.
     Palo Alto notes that "cURL does not support this but it is suitable with scripts", and
     requires it for the Cortex XSOAR integration. **This script does not implement it.** An
     Advanced key will fail to authenticate here.

   Palo Alto publishes no warning that Standard is insecure or discouraged, so treat this as
   a compatibility choice rather than a security trade-off you are being cautioned against.

3. **Copy both values before closing the dialog.** Palo Alto's own wording: "You will not be
   able to view the API Key again after you complete this step. Ensure that you copy it
   before closing the notification."

   You need two separate things. The **API Key** goes in the `Authorization` header. The
   **API Key ID** is a distinct value — "your unique token used to authenticate the API
   Key" — and travels in `x-xdr-auth-id`. Both appear in the API Keys table; the ID is
   copyable from the row.

4. **Assign a role to the key.** The key creation dialog offers predefined or custom roles.
   The predefined roles are **Account Admin**, **Instance Administrator**, **Investigator**,
   **Responder**, **Privileged Responder**, and **Viewer**. Palo Alto describes Viewer as
   able to "View the majority of the features for this instance and can edit reports".

   **We could not establish which role is the least-privileged one that permits
   `endpoints/get_endpoint`.** Palo Alto publishes no per-endpoint permission table for the
   XDR public API and the `get_endpoint` reference page carries no required-permissions
   line; the documentation only states that a key without sufficient RBAC gets HTTP 403.
   Start with Viewer, confirm with the call in step 6, and escalate only if it returns 403.

   One trap to avoid: there is an RBAC permission literally named **"Public API"**. It
   governs viewing and managing API keys *in the console* — "View the list of existing API
   keys" — and does **not** control what an API key is allowed to call. Do not grant it
   expecting it to authorize this integration.

5. **Get your API FQDN.** On the same **Settings → Configurations → Integrations → API
   Keys** page, click **Copy API URL**. Use that rather than deriving it by hand — Palo Alto
   documents retrieval, not a derivation algorithm.

   If you do need to work it out: a tenant at
   `mycompany.xdr.us.paloaltonetworks.com` has an API host of
   `api-mycompany.xdr.us.paloaltonetworks.com`, i.e. the tenant FQDN with `api-` prefixed.
   Region codes are two-letter country or region codes — `us`, `ca`, `br`, `eu`, `uk`,
   `de`, `it`, `es`, `ch`, `pl`, `il`, `sa`, `za`, `qt`, `fa`, `au`, `jp`, `sg`, `in`, `id`,
   `kr`, `tw`, `dl`. There is **no `apac` region code**; JPAC is a grouping label Palo Alto
   uses in prose, not a subdomain.

   Give runZero the **origin only** — `https://api-mycompany.xdr.us.paloaltonetworks.com`.
   The script appends `/public_api/v1/` itself, so a URL that already ends in that path will
   produce a doubled path and 404.

6. **Confirm both values** from the Explorer host before configuring anything in runZero.
   Note that `Authorization` carries the raw key with no `Bearer` prefix:

   ```bash
   curl -s -X POST \
     'https://api-mycompany.xdr.us.paloaltonetworks.com/public_api/v1/endpoints/get_endpoint' \
     -H 'x-xdr-auth-id: 7' \
     -H 'Authorization: exampleFakeCortexApiKey0123456789abcdefghijklmnop' \
     -H 'Content-Type: application/json' \
     -d '{"request_data":{"search_from":0,"search_to":1}}' | jq '.reply.total_count'
   ```

   A count means the key, the ID, the role, and the host are all right. A 403 means the role
   is insufficient.

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter endpoint data.
    - Customize attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - **Cortex XDR base URL** (`url`): the API origin, e.g.
      `https://api-mycompany.xdr.us.paloaltonetworks.com`. No path.
    - **API key ID** (`api_key_id`): the ID from the API Keys table, sent as `x-xdr-auth-id`.
    - **API key** (`api_key`): the Standard key itself.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "cortex-xdr").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what an
integration would import before scheduling it — and the fastest way to find out you were
issued an Advanced key. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename cortex-xdr/cortex-xdr.star \
  --kwargs url=https://api-mycompany.xdr.us.paloaltonetworks.com \
  --kwargs api_key_id=7 \
  --kwargs api_key=exampleFakeCortexApiKey0123456789abcdefghijklmnop \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cortex-xdr-run
```

`--output` writes the assets the run produced, and it requires `--custom-integration-id` —
the scanner rejects the run with `custom integration ID required for output` without one.
Any well-formed UUID works for a local run; use the real one from the console when you want
the output to match a scheduled task. The scanner also refuses to write into a directory
that already exists, so add `--overwrite` when re-running into the same path. Add
`--verbose` for the request-by-request log, or omit `--output` to see only the log lines.

`API call failed:` followed by `status 401` is a rejected key, and the most common cause is
an **Advanced** key rather than a wrong one. `status 403` is a key whose role does not
permit `endpoints/get_endpoint`. `Error retrieving endpoints` means the response arrived but
carried no `reply` object.

Cortex XDR limits every tenant to **10 API requests per second across all endpoints**, and
`endpoints/get_endpoint` caps a page at 100 — "The maximum result set size is 100." The
script already requests exactly 100 per page and advances `search_from` and `search_to`
together, so a large tenant means many sequential requests. Palo Alto also reserves the
right to limit excessive usage under a Fair Usage Policy.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma —
the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. A Cortex API key is opaque; if one arrives with both
characters, wrap the whole argument in a second pair of quotes:
`--kwargs '"api_key=ab=cd,ef"'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename cortex-xdr/cortex-xdr.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server, so
it proves the script initializes, declares its parameters correctly, and issues a request.
It does not prove Cortex accepts the key, that the key is Standard rather than Advanced, or
that any endpoint is parsed. The fixture scenarios are what exercise the parsing:

```bash
python3 tests/run.py cortex-xdr
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat cortex-xdr/cortex-xdr.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api-mycompany.xdr.us.paloaltonetworks.com,api_key_id=7,api_key=exampleFakeCortexApiKey0123456789abcdefghijklmnop' \
  --output ./cortex-xdr-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for a
script with a different entry point. Note that `--custom-integration-script-kwargs` takes
one comma-separated string — genuinely, and with no single-`=` exemption. Here a comma in
*any* value splits it. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated with **endpoint data from Cortex XDR**.
- The script captures details like **agent status, policies, OS version, compliance, and IPs**.
- Search for these assets in runZero using `custom_integration:cortex-xdr`.

### Notes

- The script **retrieves all endpoints** using pagination, 100 per request — the documented
  maximum — advancing `search_from` and `search_to` by 100 each round and stopping when a
  short page comes back.
- Endpoints are identified by `agent_id`, falling back to `endpoint_id`. An endpoint
  carrying neither is skipped with a log line rather than importing an asset with no stable
  identity.
- All attributes from Cortex XDR are stored in `customAttributes`.
- The task **can be scheduled** to sync endpoint data regularly.
- Only the **first** entry of the endpoint's `mac_address` list becomes a network interface, so a multi-homed endpoint contributes one MAC. The `ip` and `ipv6` lists are merged and all of their addresses are used.
- `first_seen` and `last_seen` are normalized from epoch milliseconds to seconds and stored as custom attributes, but they are **not** assigned to the asset's `firstSeenTS` / `lastSeenTS` fields, so runZero's own first- and last-seen values are unaffected by this import.

## Asset identity

- Target entity: an **endpoint running a Cortex XDR agent** — one row per agent installation in the tenant, covering workstations, servers, and mobile endpoints alike.
- Source ID field: `agent_id`, falling back to `endpoint_id`.
- Documentation evidence: **the preference order here is inverted relative to the field Palo Alto documents.** `endpoint_id` is the identifier the `endpoints/get_endpoint` reply publishes and the value every per-endpoint operation is addressed by — isolation, scanning, and policy lookups all take an endpoint id list. `agent_id` is **not part of the documented `get_endpoint` response**; it appears in other Cortex surfaces. Reading it first is harmless on a tenant that does not return it (the fallback then supplies the documented value), but on a tenant that returns both it decides identity with the undocumented field. This is recorded as a finding rather than corrected, because this pass does not modify scripts.
- Uniqueness scope: the tenant, which is the API FQDN the credential points at. The value is used bare with no tenant prefix, so two tenants imported through one custom integration share an id space — mitigated in practice by `endpoint_id` being a UUID.
- Cardinality: one source row per agent installation.
- Stability: the id is assigned when the agent installs and survives rename, DHCP address change, reboot, OS upgrade, and agent content updates — it is the handle Cortex's own per-endpoint operations use between calls. It does **not** survive an agent uninstall and reinstall, which enrolls a new endpoint record.
- Reuse behavior: not documented. `endpoint_id` is a UUID, so reassignment to a different endpoint is implausible on shape alone; nothing published confirms it.
- Presence: expected on every endpoint. An endpoint carrying neither field is skipped with `cortex-xdr: skipping endpoint with no agent_id/endpoint_id: name=<endpoint_name>` rather than being imported with a synthesized identity.
- Final runZero ID: the raw Cortex value as a string.
- Missing-ID behavior: skip and log, after the fallback has been tried.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: Cortex issues a persistent per-agent identifier and this integration uses it directly, which is what holds a roaming laptop on one asset while its address and hostname churn.
- Verdict: **scoped authoritative** for an agent installation within one tenant; derived for the physical machine, because a reinstall mints a new id.

On the reinstall case: the outcome is a second runZero asset, and **no `matchBehavior` flag prevents it.** runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`, so relaxing `id-break` would not recover the merge. Conversely, once the id matches, nothing fragments the asset — a foreign-id match is never vetoed by a conflicting MAC, IP, or hostname.

`endpoint_type` is used for the device *type* rather than for identity, with the documented `AGENT_TYPE_` prefix stripped before the lookup so a tenant returning the bare token maps the same way. `WORKSTATION` maps to Desktop because Cortex does not separate a desktop from a laptop; `AGENT_TYPE_UNKNOWN` and anything unrecognised leave the type unset rather than displacing what runZero fingerprints from the hardware.

## Future

- **XQL is the whole datalake, and it is the largest unexploited surface here.** `POST /public_api/v1/xql/start_xql_query` followed by `xql/get_query_results` runs arbitrary XQL over everything Cortex collects. With the Host Insights add-on that includes the per-host application inventory — which is exactly the `Software` records this integration cannot produce today, because `endpoints/get_endpoint` publishes no package list — and the vulnerability data that would produce `Vulnerability` records. It is an asynchronous start-poll-page pattern rather than a single request, so it is a different collector shape from the paging loop used here, and it is gated on the tenant licensing Host Insights.
- **`endpoints/get_endpoints` for a cheap coverage check.** The concise list form returns far less per endpoint than `get_endpoint`, which makes it the right call for a periodic "which agents exist and are they alive" sync when the full record is not needed — relevant given the tenant-wide ceiling of 10 requests per second and a documented maximum page of 100.
- **Incident and alert ingestion as an event feed.** `incidents/get_incidents`, `incidents/get_incident_extra_data`, and the alert retrieval endpoints return detections carrying the endpoint id this integration already uses as the asset identity, so the join back to a runZero asset is direct. These are behavioral detections rather than CVEs and belong in a time-windowed feed with a high-water mark, not in `Vulnerability` records.
- **Outbound: push runZero context onto Cortex endpoints as tags.** Cortex exposes endpoint tag assignment and removal, addressed by endpoint id. A runZero query — assets on a regulated segment, assets runZero classifies as OT, assets missing an expected agent — could be pushed as a Cortex tag, letting Cortex policy and investigation scoping act on runZero's view of the network. This is the most useful non-destructive outbound direction, because it changes what Cortex operators see without changing what the agent does.
- **Isolation and script execution are reachable and deliberately out of scope.** `endpoints/isolate` and `endpoints/unisolate` cut an endpoint off the network, and the script-execution endpoints run code on it. Both are natural responses to a runZero finding and both are wrong to attach to a scheduled sync: an automated rule that misfires isolates a fleet. They would need per-device operator approval, a dry-run mode, and an audit trail.
- **Agent coverage-gap reporting.** Cortex knows which machines carry an agent and, through `operational_status`, `agent_status`, `last_seen`, and `endpoint_version`, which of those have gone quiet or are running an outdated build. Diffing that against runZero's own discovery separates machines with no agent at all from machines whose agent has stopped reporting. Every field needed is already imported as a custom attribute, so this half is a reporting exercise rather than new integration work.
- **The rate limit shapes everything above.** Ten requests per second tenant-wide, shared with every other consumer of the API, and a Fair Usage Policy on top of it. Any addition that issues a request per endpoint rather than per page will be the thing that exhausts that budget, which is an argument for XQL — one query returning many rows — over per-endpoint enrichment calls.

## API documentation

- Manage API keys (Cortex XDR 5.x): https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/onboard-cortex-xdr/deployment-steps/manage-api-keys
- Create a new API key: https://cortex-docs.paloaltonetworks.com/xdr-5-api/create-a-new-api-key
- Make your first API call, with the Standard and Advanced header samples: https://cortex-docs.paloaltonetworks.com/xdr-5-api/make-your-first-api-call
- Get your FQDN, including the **Copy API URL** button: https://cortex-docs.paloaltonetworks.com/xdr-5-api/get-your-fqdn
- Regional egress resources, for the region codes: https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/onboard-cortex-xdr/deployment-steps/activate-cortex-xdr/enable-access-to-required-panw-resources/regional-egress-resources
- Predefined roles: https://cortex-docs.paloaltonetworks.com/gateway-guide/roles-management/predefined-roles-in-cortex-gateway.md

Note that `docs-cortex.paloaltonetworks.com` URLs now redirect to `cortex-docs.paloaltonetworks.com`.

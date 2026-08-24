# Custom Integration: Illumio Core

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Illumio Core requirements

- An Illumio Core Policy Compute Engine (PCE) reachable from the Explorer on its API port, which is `8443` on a standard on-premises deployment and `443` on Illumio's SaaS PCEs.
- A PCE API key. The key is issued as an **Authentication Username** (for example `api_1a2b3c4d5e6f7890`) and a **Secret**, which this integration sends as HTTP Basic credentials.
- The API key must belong to a user with a read-capable role in the target organization. The **Global Read Only** role is sufficient: the integration only issues `GET` requests against `workloads` and `labels`.
- The numeric organization ID. On a single-tenant on-premises PCE this is almost always `1`; it appears in the console URL after `/orgs/`.
- If the PCE uses a private certificate authority, supply the CA certificate through the integration's TLS options rather than disabling validation.

## Steps

### Illumio Core configuration

1. Log in to the PCE web console as a user who can manage API keys.
2. Go to **Access** > **API Keys** (on newer releases, your profile menu > **My API Keys**), then click **Add**.
3. Give the key a name and description and click **Save**.
4. Copy the **Authentication Username** and the **Secret**. The secret is shown once and cannot be retrieved afterwards; download the credentials file if the console offers one.
5. Note the PCE hostname and API port from the console URL, and the organization ID that follows `/orgs/` in that URL.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Illumio Core").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **PCE URL** (`url`): base URL of the Policy Compute Engine including the API port, for example `https://pce.example.com:8443`. The `/api/v2/` path is appended automatically.
   - **Organization ID** (`org_id`): the numeric PCE organization ID, usually `1`.
   - **API key username** (`api_key_id`): the Authentication Username issued with the API key.
   - **API key secret** (`api_secret`): the secret issued alongside it.
   - **Import listening services** (`import_services`): optional; fetch each workload individually to collect its open service ports (default: true). See the note on cost below.
   - **Service enrichment limit** (`service_detail_limit`): optional; maximum number of workloads to fetch individually for services (default: 1000, `0` removes the cap).
   - **Only import managed workloads** (`managed_only`): optional; restrict the import to workloads that report through a VEN (default: false).
   - **Asynchronous collection timeout (seconds)** (`async_timeout_seconds`): optional; how long to wait for an offline collection job on estates larger than 500 workloads (default: 600).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename illumio-core/illumio-core.star \
  --kwargs url=https://pce.example.com:8443 \
  --kwargs org_id=1 \
  --kwargs api_key_id=api_1a2b3c4d5e6f7890 \
  --kwargs api_secret=4c1e9b7a3f0d82165e4b9c7a0d3f6182b5e8c4a7 \
  --kwargs import_services=true \
  --kwargs service_detail_limit=25 \
  --kwargs managed_only=true \
  --output ./illumio-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

**Cap `service_detail_limit` on a first run.** Illumio does not return services on a
collection request — getting a collection of workloads returns none of the services running
on them, and only a single-workload `GET` returns them — so `import_services` costs **one
extra request per workload**. On a 10,000-workload PCE that is 10,000 requests against a
500-per-minute rate limit, roughly 20 minutes of wall clock. `service_detail_limit=25`
turns a smoke test back into seconds; workloads past the limit are still imported, without
services, and the skipped count is logged.

**Past 500 workloads the run switches to the asynchronous path.** A synchronous collection
`GET` returns at most 500 objects, so when the first call comes back at exactly 500 the
same collection is re-issued with `Prefer: respond-async`, the job is polled at the interval
the PCE asks for, and the result is downloaded as a data file. On a large PCE the log will
sit quietly during that poll; `async_timeout_seconds` (default 600) bounds it. If any step
of that path fails the integration imports the 500 workloads it already has and logs a loud
warning saying an unknown number are missing — it never truncates silently, so read the log
before trusting a count.

To check the `CONFIG` block and the HTTP and TLS wiring without a live PCE:

```bash
runzero script --filename illumio-core/illumio-core.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove the PCE accepts the API key or that any workload is parsed.

The full asynchronous collection flow, including a failed job, is exercised by the fixture
suite:

```bash
python3 tests/run.py illumio-core
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat illumio-core/illumio-core.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://pce.example.com:8443,org_id=1,api_key_id=api_1a2b3c4d5e6f7890,api_secret=<secret>' \
  --output ./illumio-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a secret
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Illumio Core.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:illumio-core`.

## Asset identity

- Target entity: an Illumio *workload* — a server, virtual machine, or cloud instance the PCE knows about, either managed by a VEN or created by hand as an unmanaged record.
- Source ID field: `href`
- Documentation evidence: "When you get either a single or a collection of workloads in an organization, the URI of the workload is returned in the form of an HREF path" (Illumio Core REST API, Workload Operations). The value has the form `/orgs/{org_id}/workloads/{uuid}` and is the resource identifier the PCE itself uses for every per-workload operation (`GET`/`PUT`/`DELETE [api_version][org_href]/workloads/{uuid}`), for policy references, and as the `outputs_key_field` of Illumio's own Cortex XSOAR content pack.
- Uniqueness scope: one PCE. The path already embeds the organization, so a workload href is unique across every org on one PCE.
- Cardinality: exactly one row per workload in `GET /api/v2/orgs/{org_id}/workloads`. There is no many-to-one relationship to collapse — services and labels are nested inside the workload record, not separate rows.
- Stability: the href is assigned when the workload record is created and is never rewritten. It survives rename, re-addressing, interface changes, VEN upgrade, reboot, moving between labels, enforcement-mode changes, and unpairing-to-unmanaged. It does **not** survive deleting and re-creating the record, or unpairing a VEN with the "remove the workload" option, which is a genuine delete.
- Reuse behavior: the trailing component is a UUID, so reassignment after deletion is implausible. This is inference from the value format, not an explicit vendor contract.
- Presence: always present on every workload object the PCE returns. Any record arriving without it is skipped.
- Final runZero ID: `illumio-core:<pce-hostname>:<href>` — for example `illumio-core:pce.example.com:/orgs/1/workloads/aaaa-1111-...`.
- Missing-ID behavior: skip the record and log only its `hostname`; no identifier is ever synthesized and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`
- Verdict: authoritative, scoped to one PCE.

The href already carries the org, so a second organization on the same PCE cannot collide. The PCE hostname is nevertheless prepended, because two separate PCEs — a production and a test appliance, or two regional SaaS tenants — both start numbering at `/orgs/1/` and would otherwise mint identical ids for unrelated workloads. The hostname is known from configuration before any record is parsed, so it can never go missing mid-import. It is taken from the URL's host only, not host-and-port, so changing the API port does not renumber the estate.

`matchBehavior` keeps the href as the merge signal while stopping network churn from fragmenting a workload. The three break flags are relaxed deliberately, and for different reasons:

- **`no-mac-break` is a formality.** Illumio publishes no MAC address anywhere in the workload model — not on the workload, not on `interfaces[]`, not on the VEN. `MatchBreakByMACs` only fires when *both* sides have MACs, so with none on this side the flag can never change an outcome. It is set for symmetry with the rest of the library and to make the absence explicit rather than accidental.
- **`no-ip-break` is load-bearing.** `MatchBreakByIPs` disqualifies a merge when the two address sets do not *overlap at all*. Illumio reports the addresses the VEN read from the host's own interface table, which for a cloud workload is the private VPC address; runZero may only ever have observed that same machine at an elastic IP, a load-balancer address, or through a NAT gateway. Those sets have zero overlap, so leaving the break on would reject exactly the first-contact merges this integration exists to make, and every cloud workload would arrive as a duplicate asset.
- **`no-name-break` is the general loosening.** Custom-integration hostnames land in the trusted-name set, so a trusted-name mismatch would break a merge. Illumio's `hostname` is the OS hostname the VEN read locally, which routinely disagrees with the DNS or certificate name runZero learned by scanning — `ip-10-0-1-5` versus `api.example.com` is the normal case in an autoscaled estate, not the exception.

The cost of relaxing these is that a first-contact merge found by one identifier is no longer vetoed by the others. That trade is acceptable here because Illumio's identifiers describe the workload's own view of itself rather than something observed about a peer, and because a second poll re-matches on the authoritative href regardless. Note that no break flag would have helped if the href were not one-per-workload: `MatchByForeignID` never consults the MAC, IP, or hostname break helpers at all, so foreign-ID quality has to be solved at the identifier.

### Notes

- Assets come from `GET /api/v2/orgs/{org_id}/workloads`. Imported fields are `hostname` and `name`, the interface addresses, `os_id` and `os_detail`, `created_at`, the VEN's `last_heartbeat_on` (falling back to `updated_at`), `online`, `managed`, `enforcement_mode`, `visibility_level`, `data_center`, `public_ip`, the VEN/agent metadata, and the workload's labels.
- **Services are real and first-class.** `services.open_service_ports[]` is the workload's own set of listening sockets as observed by the VEN — not remote peers seen in flow data — so each entry becomes a runZero `Service`. `port` maps to the port, `process_name` (or `win_service_name` on Windows) to the product, and `package`, `user`, and the raw bind address to service custom attributes.
- `open_service_ports[].protocol` is an **IANA protocol number, not a name** — `6` for TCP and `17` for UDP, verified against Illumio's own published fixture data. It is converted before being assigned to `Service.transport`. `132` is mapped to `sctp`; entries on a protocol with no port concept (ICMP `1`, IPv6-ICMP `58`) are counted in the `illumio_core_service_ports_unmapped` attribute rather than invented into a service.
- A service that binds the wildcard address (`0.0.0.0` or `::`) is re-pointed at the workload's primary imported address, because `Service.address` is required and a service pinned to the unspecified address would be meaningless. A workload with no importable address gets no services, and the count is recorded.
- **Services are not returned by collection requests.** Illumio documents this explicitly: getting a collection of workloads returns none of the services running on them, because a PCE with thousands of workloads each running dozens of services could not expand them all; getting one workload returns all of that workload's services. So `import_services` costs **one extra request per workload**. `service_detail_limit` caps that pass (default 1000); workloads past the limit are still imported, without services, and the skipped count is logged. Turn `import_services` off to import inventory only.
- **No software and no CVEs are imported, and none are faked.** The PCE does not inventory installed packages, so there is nothing to build a `Software` record from. For vulnerabilities it publishes only a *summary* — `vulnerabilities_summary.num_vulnerabilities` plus the aggregate `vulnerability_score`, `vulnerability_exposure_score`, and `vulnerable_port_exposure` — never the individual findings, their CVE identifiers, or their affected ports. A count is not a finding, so no `Vulnerability` objects are synthesized from it; the numbers are carried verbatim as `illumio_core_num_vulnerabilities` and friends. Those fields only appear at all on PCEs licensed for the Vulnerability Map with vulnerability data loaded, and are absent otherwise.
- **Illumio has no MAC address at all**, in any object. Every merge into an already-scanned asset therefore rests on hostname or IP, which is why the `matchBehavior` reasoning above matters more here than for a source that can fall back to a hardware address. In practice this means a first poll against a greenfield runZero instance may create workload assets that a later scan merges into, rather than enriching scanned assets immediately.
- **Interface address handling.** `interfaces[].address` values are imported, because they are the addresses the VEN read from the workload's own interface table and genuinely belong to that machine. Four classes are filtered out before a `NetworkInterface` is built, and the unfiltered list is preserved as `illumio_core_interfaces` with the exclusions listed in `illumio_core_interfaces_excluded`:
  - loopback, unspecified, and link-local addresses (`127.0.0.0/8`, `::1`, `0.0.0.0`, `169.254.0.0/16`, `fe80::/10`) — an agent-based source that reports `127.0.0.1` as a host's only address would otherwise give every such host the same IP and let runZero merge the entire estate onto one asset;
  - interfaces Illumio flags with `"loopback": true`;
  - interfaces named in the workload's own `ignored_interface_names`, which is Illumio's declaration that the address is not the workload's network identity;
  - interfaces whose name matches a container, hypervisor, or overlay bridge (`docker*`, `br-*`, `veth*`, `virbr*`, `cni*`, `flannel*`, `cali*`, `tunl*`, `vxlan*`, `weave*`, `antrea-*`, `cbr*`, `vnet*`, and similar). The default Docker bridge assigns `172.17.0.1` to *every* Docker host, so importing it would hand thousands of unrelated workloads an identical address to merge on. This last filter is a name heuristic, not a documented Illumio contract; it is the one deliberately opinionated choice in the mapping.
- **`public_ip` is deliberately not attached to a network interface.** It is the NAT egress address the PCE observed the workload connecting from, shared by every workload behind one gateway. It is kept as the `illumio_core_public_ip` custom attribute.
- Labels become runZero tags in `key:value` form (`role:Web`, `env:Production`, `app:HRM`, `loc:US`). A workload's `labels[]` may arrive either expanded or as bare `href` references depending on the PCE release, and the expanded representation is not portable across releases, so the organization's label catalog is fetched once from `GET /api/v2/orgs/{org_id}/labels` and used to resolve references. An organization with more than 500 labels hits the collection cap on that call, and the catalog is then re-fetched as an asynchronous GET collection — the same escape hatch the workload collection uses. Only if that asynchronous fetch fails do the affected labels import as references, and the shortfall is logged.
- `deviceType` is deliberately left unset. Illumio does not publish a device type, and while a Core workload is nearly always a server, guessing would override runZero's own fingerprinting for the cases where it is not.
- `os` is derived from the leading token of `os_id` through a fixed platform table (`ubuntu-x86_64-xenial` becomes `Ubuntu Linux`). `osVersion` is set only when the release token is numeric, because it is a version on the RPM-family platforms (`centos-x86_64-7.9`) and a codename elsewhere (`xenial`). The full `os_id` and `os_detail` survive verbatim as attributes.
- **Pagination model — this is the important one.** The workloads collection has no offset, page, or cursor parameter. A synchronous `GET` returns at most **500 objects**, and Illumio documents the asynchronous GET collection as the only supported way past that. This integration implements it: a synchronous collection is tried first, and when it comes back at exactly 500 objects the same collection is re-issued with `Prefer: respond-async`, the job href from the `Location` response header is polled at the interval the `Retry-After` header asks for until the job reports `done` (or `completed`), and the result is downloaded from the `result.href` data file. `max_results` is deliberately omitted on the asynchronous request, because that parameter is what caps a collection and the point of the offline job is to return the estate uncapped.
- If the asynchronous path fails at any step — a missing `Location` header, a failed job, a poll timeout, a download error — the integration imports the 500 workloads it already has and logs a **loud warning** naming the failure and stating plainly that an unknown number of workloads are missing. It never truncates silently.
- The asynchronous trigger is the one request that has to use the raw HTTP builtin rather than `get_json`, because `get_json` does not expose response headers and `Location` is the only handle on the job. Raw requests take **no retry budget**, so that single call gets one attempt. It is only issued after a synchronous collection has already succeeded, so the PCE is known to be reachable at that point, but a transport failure on that one request will abort the run rather than degrade. Every other request in the integration goes through `get_json` and gets the default three retries with exponential backoff, honoring `Retry-After`.
- The asynchronous result is one downloadable file holding the whole estate, so it is streamed record by record with `jsonstream` rather than decoded whole — a large PCE's datafile decoded in one piece could exhaust the script's memory ceiling. Each asset is built and reported in turn, so only one raw record and one `ImportAsset` object exist at a time. If the datafile turns out to be missing rows the synchronous snapshot already returned, those rows are imported from the snapshot and the shortfall is logged.
- **Rate limiting.** The PCE allows 500 requests per minute per API key. With `import_services` enabled the integration makes roughly one request per workload, so a 10,000-workload estate takes about 20 minutes of wall clock at the limit; 429 responses are retried with backoff. Lower `service_detail_limit` or disable `import_services` on very large estates.
- Timestamps are parsed defensively. Every component is hand-validated before `parse_time`, because an unparseable layout or a timestamp with no timezone aborts the whole script and cannot be caught. Parsed values are then clamped to *now*: a first- or last-seen time in the future fails validation for the **entire asset record**, not just the field, so an unclamped clock skew on the PCE would silently drop assets. The raw `created_at` and `updated_at` strings are kept as attributes.
- Workloads flagged `deleted: true` are skipped and counted. The PCE does not return them unless `include_deleted` is requested, which this integration never does; the check is defensive.
- Unverified assumption: the asynchronous collection is assumed to return the same workload representation as the synchronous one, and therefore to omit `services` in the same way. Every estate over 500 workloads consequently depends on the per-workload pass for services, exactly as smaller ones do.
- Unverified assumption: workload hrefs are assumed never to be recycled after a workload is deleted, as noted in the identity record.
- Unverified assumption: the PCE is assumed to return `status: "done"` for a workload collection job. Illumio's own client accepts both `done` and `completed`, so both are handled.
- This integration was validated against local fixtures, not a live Illumio Core PCE. The fixture PCE reproduces HTTP Basic authentication, the 500-object synchronous cap, the full `Prefer: respond-async` / `Location` / `Retry-After` / job-poll / data-file flow, a failing job, a job response with no `Location` header, 401 and 429 responses, an empty organization, and malformed records — but no request has been made to a real PCE.

## Future

- **Push runZero-discovered assets into the PCE as unmanaged workloads (outbound).** This is the strongest outbound story any segmentation vendor has, and it closes a real blind spot. Illumio can only write policy about things the PCE knows about; anything without a VEN is invisible to it unless someone creates a record by hand. runZero's whole job is finding the things nobody enrolled — the OT controller, the appliance, the forgotten VM, the contractor's device. `POST /api/v2/orgs/{org_id}/workloads` creates a single unmanaged workload from a name, hostname, `interfaces[]`, and `labels[]`, and `workloads/bulk_create` does up to 1,000 per call. Crucially, the workload schema carries `external_data_set` and `external_data_reference`, a pair Illumio documents as a unique composite key identifying "the original data source of the resource" and "a unique identifier within that data source" — so an outbound script can stamp `external_data_set: "runzero"` and the runZero asset ID, then use `GET /api/v2/orgs/{org_id}/workloads?external_data_set=runzero&external_data_reference=<id>` to find the record again on the next run and `workloads/bulk_update` to reconcile it, instead of duplicating it. runZero's asset type, OS, site, and tags map naturally onto Illumio's role/app/env/loc label dimensions via `GET`/`POST /api/v2/orgs/{org_id}/labels`. The result is that an Illumio operator can write and enforce boundary policy about the unmanaged estate without ever hand-entering it.
- **Traffic-flow enrichment (inbound).** `POST /api/v2/orgs/{org_id}/traffic_flows/async_queries` runs an Explorer query as an offline job over a time range and returns observed flows with source and destination workload, port, protocol, and policy decision. Because the same asynchronous job machinery this integration already implements drives it, a companion script could attach "who actually talks to this asset, on which ports, and would policy allow it" to runZero assets. That is genuinely new information: it is *observed* connectivity rather than reachability inferred from scanning. It is kept out of this integration deliberately — flow data is a different volume class and a different refresh cadence from inventory, and remote peers seen in flow records are emphatically **not** the local asset's own services.
- **Event ingestion.** `GET /api/v2/orgs/{org_id}/events` returns PCE audit and system events (`timestamp`, `event_type`, `severity`, `status`, and the affected resource href) with `timestamp[gte]`/`timestamp[lte]` filters. A scheduled script carrying a high-water mark between runs could attach VEN pairing and unpairing, enforcement-mode changes, tampering, and policy-provisioning events to the originating workload asset, giving runZero a segmentation change log alongside its inventory.
- **Segmentation coverage-gap reporting.** Because Illumio's own inventory is authoritative for "does this host have a VEN and what mode is it in", diffing it against runZero's discovery separates three populations: workloads Illumio manages that runZero has never observed on a network, hosts runZero discovers that Illumio has no record of at all, and workloads Illumio knows but has left in `visibility_only` rather than `full` enforcement. The `managed`, `enforcement_mode`, `visibility_level`, and `online` fields this integration already imports carry everything needed to build that report inside runZero as a saved query, with no additional API work.
- **Vulnerability detail is not available and cannot be added.** The PCE stores vulnerability data only as aggregate scores per workload and per port. There is no endpoint that returns the individual findings behind `num_vulnerabilities` for a workload, so no future version of this integration can emit real `Vulnerability` objects from Illumio Core. That data has to come from the scanner that fed Illumio in the first place.

## API documentation

- REST API URIs and org-scoped path structure (`https://<pce>:8443/api/v2/orgs/{org_id}/...`): <https://product-docs-repo.illumio.com/Tech-Docs/Core/25.1/REST-APIs/out/en/overview-of-the-illumio-rest-api/rest-api-uris.html>
- HTTP requests and responses (Basic authentication, `Accept: application/json`, the `X-Total-Count` and `X-Matched-Count` response headers): <https://product-docs-repo.illumio.com/Tech-Docs/Core/24.5/REST-APIs/out/en/overview-of-the-illumio-rest-api/http-requests-and-responses.html>
- REST API limits (the 500-object synchronous GET collection cap, the 500 requests/minute rate limit, `max_results`, and the direction to use an asynchronous GET collection past 500): <https://product-docs-repo.illumio.com/Tech-Docs/Core/25.2/REST-APIs/out/en/rest-apis-25-2-10/overview-of-the-illumio-rest-api/rest-api-limits.html>
- Async job operations (`Prefer: respond-async`, the `Location` and `Retry-After` headers, `GET /api/v2/orgs/{org_id}/jobs/{href}`, job statuses, and downloading the result from `GET /api/v2/orgs/{org_id}/datafiles/{href}`): <https://product-docs-repo.illumio.com/Tech-Docs/Core/25.4/REST-APIs/out/en/rest-apis-25-4/asynchronous-get-collections/async-job-operations.html>
- Workload operations (the collection and single-workload URIs, the query parameter list, the workload object properties, and `services.open_service_ports`): <https://product-docs-repo.illumio.com/Tech-Docs/Core/22.5/REST-APIs/out/en/core-22-5-rest-api-developer-guide/workloads-apis/workload-operations.html>
- Getting workloads, used to verify that a collection response omits services while a single-workload response includes them, and that the workload URI is returned as an href: <https://docs.illumio.com/asp/20.1/Content/Guides/rest-api/workloads/getting-workloads.htm>
- Workload bulk operations, used for the outbound section (`bulk_create`/`bulk_update`, the 1,000-item limit, `external_data_set` and `external_data_reference` as a unique composite key): <https://docs.illumio.com/asp/19.3/Content/Guides/rest-api/workloads/workload-bulk-operations.htm>
- Illumio's own Python client, used as the reference implementation of the asynchronous collection poll-and-download loop: <https://illumio-py.readthedocs.io/en/latest/user/advanced.html>

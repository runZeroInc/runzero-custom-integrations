# Custom Integration: Kenna Security

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Kenna Security requirements

- A Kenna Security (Cisco Vulnerability Management) account with API access.
- A Kenna API key. The key inherits the permissions of the role it was created under, so it must be able to read assets and vulnerabilities.
- **Use the `Read Only` system role.** Kenna's three system roles are Administrator, Write/Normal User, and Read Only, and Read Only is sufficient here — this integration never writes. Two Kenna constraints shape how you get there: **an API key can only be attached to a system role, not a custom user role**, and **an administrator cannot grant API access to another administrator**. So the credential is a dedicated user created with the Read Only role, whom an administrator then grants API access before the key is generated.
- The key value **can be copied only once**, immediately after generation. Kenna documents no expiry.
- The API host must match your UI host — Kenna states the API base URL takes the same form as the interface URL. Kenna deliberately does **not** publish a list of regional hostnames; their documentation tells you to ask your administrator or account team if you are unsure. Read the value off the Settings then API Keys page rather than guessing at a regional pattern.

## Steps

### Kenna Security configuration

1. Create the user the integration will act as, with the **Read Only** system role. An API key cannot be attached to a custom user role, and an administrator cannot grant API access to another administrator, so a dedicated non-admin user is the only route to a least-privilege key.
2. As an administrator, grant that user API access from **Settings** then **API Keys** then **All Keys**. The same page offers Grant Access, Revoke Access, and Reset API Key per user.
3. Sign in as that user, open **Settings** then **API Keys**, choose **My Key**, and click **Generate New Key**. Copy it immediately; Kenna shows the value only once.
4. Note the hostname of your instance, shown on that same page. Kenna serves regional instances from their own hostnames and the API base URL takes the same form as the UI URL. `https://api.kennasecurity.com` is the default. Kenna does not publish the regional hostnames, so read yours from the console rather than assuming a pattern.
5. Confirm the key works: `curl -H "X-Risk-Token: <token>" https://api.kennasecurity.com/assets/search?per_page=1`. HTTPS is mandatory; a plain HTTP request fails rather than redirecting.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Kenna Security").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Kenna API URL** (`url`): base URL of the Kenna API. Defaults to `https://api.kennasecurity.com`; use your regional hostname if the UI subdomain differs.
   - **API token** (`api_token`): the Kenna API key, sent as the `X-Risk-Token` header.
   - **Import vulnerabilities** (`include_vulnerabilities`): optional; fetch vulnerabilities for each page of assets and attach them to the matching asset (default: enabled).
   - **Asset status** (`asset_status`): optional; one of `active`, `inactive`, or `all` (default: `active`).
   - **Minimum asset risk meter score** (`min_risk_meter_score`): optional; only import assets scoring at or above this value on Kenna's 0-1000 asset scale (default: 0, meaning all assets).
   - **Import non-network assets** (`include_non_network_assets`): optional; import assets whose primary locator is a URL, file, database, or application (default: disabled).
   - **Page size** (`page_size`): optional; records requested per page, 1-5000 (default: 500).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token and see what a real instance returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename kenna/kenna.star \
  --kwargs url=https://api.kennasecurity.com \
  --kwargs api_token=7f3a91c4e0b84d26a5c8f1e7d09b3a42 \
  --kwargs asset_status=active \
  --kwargs include_vulnerabilities=false \
  --kwargs page_size=100 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./kenna-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

Turn `include_vulnerabilities` off for the first run. It adds a vulnerability
fetch for every page of assets, and on a large instance that is most of the
wall-clock time; confirm the asset side looks right before paying for it.

**`page_size` is not just a tuning knob here.** Kenna serves at most **20 pages
per search**, so the reachable inventory is `20 × page_size` and nothing beyond
it — at the default 500 that is a hard ceiling of 10,000 assets, silently
reached with no error. If your instance holds more than that, raise `page_size`
toward its 5000 maximum, and use `min_risk_meter_score` to make the selection
deliberate rather than arbitrary:

```bash
runzero script --filename kenna/kenna.star \
  --kwargs url=https://api.kennasecurity.com \
  --kwargs api_token=7f3a91c4e0b84d26a5c8f1e7d09b3a42 \
  --kwargs page_size=5000 \
  --kwargs min_risk_meter_score=300 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./kenna-highrisk --overwrite
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename kenna/kenna.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Kenna accepts the
`X-Risk-Token`, or that any asset is parsed.

The fixtures under `kenna/tests/fixtures/` exercise the parsing offline,
including the paging and vulnerability cases:

```bash
python3 tests/run.py kenna
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat kenna/kenna.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.kennasecurity.com,api_token=<token>,asset_status=active' \
  --output ./kenna-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way; prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Kenna Security.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:kenna`.

## Asset identity

- Target entity: a host tracked in a Kenna tenant. Kenna is an aggregator, so the underlying entity is whatever an upstream connector reported — a physical device, VM, cloud instance, or container host.
- Source ID field: `id` on `GET /assets/search`
- Documentation evidence: the asset schema on [Search Assets](https://apidocs.kennasecurity.com/reference/search-assets) types `id` as a non-nullable integer, and the whole API addresses an asset by it: `GET /assets/{id}`, `GET /assets/{id}/vulnerabilities`, `PUT /assets/{id}`, `PUT /assets/{id}/tags`. `GET /vulnerabilities/search` returns `asset_id` on every finding and accepts `asset[id][]` as a filter, described as "Search for vulnerabilities related to the specified asset IDs" — the API uses this value as the join key between the two object types, which is exactly what this integration does with it.
- Uniqueness scope: tenant. `id` is a tenant-local integer.
- Cardinality: one row per asset. Kenna deduplicates the feeds from its connectors into a single asset record, which is the entire point of the product; multiple upstream scanners reporting the same machine produce one Kenna asset carrying several `connectors` entries on its findings.
- Stability: preserved across connector runs. Kenna's own deduplication is what keeps a machine on one `id` when a connector re-reports it. Whether re-addressing a host causes Kenna to fork it into a second asset depends on the tenant's locator configuration and is not documented; this is called out as unverified below.
- Reuse behavior: undocumented. The ids are sequential integers, and nothing in the API reference describes deletion semantics.
- Presence: present on every asset row. The schema marks `id` non-nullable, and every response example in the vendor documentation carries it.
- Final runZero ID: `kenna:<api-host>:<id>` — for example `kenna:api.kennasecurity.com:21741`. The scheme is stripped from the configured URL so switching between `http` and `https` does not re-identify existing assets.
- Missing-ID behavior: skip the record, logging only its `locator`. No composite fallback and no `new_uuid()`. Records that are not objects at all are skipped and counted.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
- Verdict: scoped authoritative.

Two decisions in that record need justifying, because Kenna is not a scanner and the usual reasoning does not transfer.

**Why the break flags are suppressed, unlike the peer `frontline-vm` integration.** Frontline keeps runZero's default match behavior because every Frontline host row carries a MAC, an IP, and a hostname that its own scanner observed on that scan — contemporaneous evidence that *should* be allowed to disqualify a wrong merge. Kenna's identifiers are the opposite: they are second-hand, copied from whichever connector last fed the asset in, and they are frequently null. Kenna's own documented `assets/search` response example has `hostname`, `fqdn`, `netbios`, and `mac_address` all null with only `ip_address` populated, and its published sample for that field is `127.0.0.1`. An identifier that may be months stale or absent must not be allowed to veto a merge against the asset runZero discovered directly, so `no-mac-break no-ip-break no-name-break` is set. The `id` still drives matching, which is what keeps repeated polls from duplicating.

**Why assets with no correlator are dropped rather than imported.** This is the risk that matters for an aggregator. Kenna's assets are, by construction, mostly machines runZero already knows from the original scanner. When a Kenna record carries a MAC, a hostname, or a routable address, the import lands on that existing asset and adds Kenna's risk scoring to it — the outcome we want. When it carries none of those, runZero has no signal to merge on, and the record becomes a standalone asset that will sit beside the real one forever, holding nothing but a Kenna id and a risk score. That is a permanent duplicate manufactured by the import itself. The integration therefore requires every record to carry at least one usable correlator after the loopback filter, and skips the rest with a logged count. The same rule normally accompanies `no-id-match no-id-break`; it is applied here despite the authoritative id because the aggregator relationship, not the id quality, is what creates the duplication risk.

`no-id-match no-id-break` was considered as the alternative — treat Kenna purely as enrichment and never let it assert identity. It was rejected because the Kenna `id` is the single strong thing this source has. Without it, poll-to-poll stability would rest entirely on Kenna's sparse, frequently-null MAC/IP/hostname, and every DHCP move on an IP-only asset would strand the previous record. Keeping id matching while suppressing the break flags gets the stability without letting stale identifiers do damage.

### Notes

- **What is imported.** Assets come from `GET /assets/search`. `hostname`, `fqdn`, and `netbios` become hostnames (de-duplicated case-insensitively, nulls skipped); `ip_address`, `ipv6`, and `mac_address` become a single network interface via `network_interface()`; `operating_system` and `os_version` become `os`/`osVersion`; `created_at` becomes `firstSeenTS` and `last_seen_time` becomes `lastSeenTS`; Kenna's `tags` are carried through alongside a `kenna` tag. `risk_meter_score`, `asset_groups` (names), `owner`, `status`, `priority`, `external_id`, `primary_locator`, `locator`, `notes`, `vulnerabilities_count`, `inactive_at`, and the raw reported addresses become custom attributes under the `kenna` prefix.
- **Vulnerabilities are the point of this integration.** They come from `GET /vulnerabilities/search`: `cve_id` becomes `cve` (see below), `cve_description` or `description` becomes the description, `solution` becomes the solution, `cvss_v2`/`cvss_v3` `score` and `temporal_score` become the four CVSS fields, `risk_meter_score` becomes `riskScore`/`riskRank`, `cve_published_at` becomes `publishedTS`, `first_found_on` becomes `firstDetectedTS`, and `last_seen_time` becomes `lastDetectedTS`. `status`, `threat`, `scanner_score`, `priority`, `top_priority`, `due_date`, `closed_at`, `fix_id`, `identifiers`, `platform_types`, and the observed ports are custom attributes. The endpoint documents that "By default, only open vulnerabilities with active assets are returned", so no status filter is sent and closed findings are not imported.
- **The `connectors` array on each finding is preserved as `kenna_connector_names`, `kenna_connector_vendors`, and `kenna_connector_definitions`.** For an aggregator this is the most valuable provenance available: it tells you which upstream scanner actually saw the finding, which is what lets you decide whether Kenna is telling you something runZero's other sources already know.
- **Pagination is `page` plus `per_page`, terminated on `meta.pages`.** Every Kenna search response is `{<objects>: [...], meta: {page, pages, total_count}}`. The integration requests `page=N&per_page=<page_size>` and stops when `page >= meta.pages`, falling back to a short-page check for any response that omits `meta`. **Kenna caps every search endpoint at 20 pages**, whatever the page size (`/assets/search` allows up to 50,000 per page, `/vulnerabilities/search` up to 5,000; one page size drives both here, so 5,000 is the ceiling). A tenant with more than `20 x page_size` assets will be truncated, and the integration says so explicitly in the task log rather than silently stopping — raise the page size or set a minimum risk meter score to bring the set inside the cap. This is worth stating plainly because the Cortex XSOAR reference client implements no pagination at all: it fires one un-paged GET and slices the result to a client-side `limit`, so it silently returns at most one default page.
- **Vulnerabilities are fetched per page of assets, not as one flat walk.** After each asset page, the integration issues `GET /vulnerabilities/search?asset[id][]=...` for the ids on that page, in batches of 100, and indexes the results by `asset_id`. This is deliberate. Walking the flat vulnerability list once would hit the same 20-page ceiling globally — at most 100,000 findings for an entire tenant — whereas partitioning by asset applies the ceiling per batch, where it is unreachable. It also bounds memory to one page of assets. The alternative, `GET /assets/{id}/vulnerabilities`, was rejected: it costs one request per asset and its documentation includes no pagination table at all, so there is no way to know when its response is complete.
- **The `asset[id][]` query string is built by hand, not passed as `params`.** `get_json` builds its query from a dict, and a Starlark dict cannot hold the repeated `asset[id][]` key that Kenna's array filter needs. The query is assembled directly onto the URL with percent-encoded brackets — the same encoding the vendor's own Python reference client sends — and `params` is then omitted entirely, because passing it would replace the query rather than merge into it.
- **Loopback and link-local addresses are filtered before they reach a network interface.** This is not cosmetic for this source. Kenna's own documented `assets/search` response example carries `"ip_address": "127.0.0.1"`, because the asset in that example is a URL-locator web application with no host address at all. An aggregator whose connectors cannot resolve a real address will report loopback for every asset it feeds in, and if that reached a `NetworkInterface`, every such host would share one address and runZero could merge an entire estate onto a single asset. `127.0.0.0/8`, `0.0.0.0`, `169.254.0.0/16`, `::1`, `::`, and `fe80::/10` are removed, and the raw reported values are kept as `kenna_reported_ip_address`, `kenna_reported_ipv6`, and `kenna_reported_mac_address` so nothing is lost.
- **`primary_locator` is used as a gate, not just an attribute.** Kenna documents it as "The primary locator used for an asset. This should be one of the following values: ip_address, hostname, database, url, mac_address, netbios, fqdn, file, or application" — that is, Kenna's own statement of which field identifies the asset. Four of those values (`url`, `file`, `database`, `application`) describe something that is not a network host: a web application, a code file, a database schema. Importing them as runZero assets would populate the inventory with non-devices, so they are skipped by default and the **Import non-network assets** parameter turns that off. `primary_locator` is also carried through as a custom attribute so an operator can see how Kenna identified any given record. Note that enabling the parameter only relaxes the locator gate; a URL-locator asset with no address still has no correlator and is still skipped.
- **`Service` objects are emitted from `network_ports`, conditionally.** The schema is well specified — `protocol`, `port_number`, `name`, `product`, `version`, `state` — and Kenna clearly indexes it, because `/vulnerabilities/search` exposes `asset[service_ports][]`, `asset[service_names][]`, `asset[service_products][]`, and `asset[service_protocols][]` as filters. So it is mapped when present. Three gates apply: the asset must have a routable address (`Service.address` is required and there is no honest placeholder for it), `protocol` must lower-case to `tcp` or `udp`, and `state`, when set, must be `running` or `open`. Kenna's own sample response has `network_ports: []` on every asset, so expect this to be empty in many tenants — it depends entirely on whether an upstream connector supplies port data. Both response shapes are handled: the schema documents an array, but the `search-assets` example shows a single bare object.
- **No `Software` objects.** Kenna's asset record has no installed-software inventory. `network_ports[].product`/`version` describe a listening service, which is mapped onto `Service`, not `Software`, and no CPE field exists anywhere on either object.
- **Vulnerability service fields are set only when Kenna reports exactly one port.** `scanner_vulnerabilities[].port` is nullable and often null, and the top-level `port` array can hold several values — the POODLE example in the vendor documentation carries ports 443 and 5003 on a single finding. Picking one of several would be arbitrary, so `serviceAddress`/`servicePort` are set only when exactly one distinct port is present and the asset has a routable address. `serviceTransport` is set only when the asset's own `network_ports` list names a transport for that port, because `scanner_vulnerabilities` carries a port number and nothing else. All observed ports are kept as `kenna_ports` regardless.
- **CVE identifiers are format-checked, not trusted.** `cve_id` is nullable and, on findings with no CVE, carries scanner-supplied text instead — the vendor's own unit-test fixture has `"cve_id": "Kenna"`. The value is upper-cased and matched against `^CVE-[0-9]{4}-[0-9]{4,19}$` before assignment; anything else is dropped and the finding falls back to its first `identifiers` entry for a name. Upper-casing is not optional: `Vulnerability.cve` is validated against that pattern *before* the type normalizes case, so a lower-case `cve-2024-11111` out of vendor text fails the whole record.
- **Severity and risk use two different scales, deliberately.** `severityRank`/`severityScore` come from `cvss_v3.score`, falling back to `cvss_v2.score` and then to Kenna's own `severity` integer, banded on the published CVSS v3 qualitative scale (9.0+ Critical, 7.0+ High, 4.0+ Medium, above 0 Low). `riskRank`/`riskScore` come from the vulnerability's `risk_meter_score`, which Kenna documents on a 0-100 scale coloured in thirds — 0-33 green, 34-66 amber, 67-100 red — so the rank stops at 3 (High) and never claims Critical, a band Kenna's scale does not define. **`scanner_score` is deliberately not scored.** The dossier for this build suggested mapping it to severity, but it is the upstream scanner's own grade, its range is undocumented, and it is not comparable across connectors: the vendor's response example shows `scanner_score: 3` on a finding whose CVSS v2 and v3 base scores are both 7.5. Averaging Nessus and Qualys grades onto one axis would produce a number that means nothing, so it is recorded as `kenna_scanner_score` and left out of the scoring.
- **Note the two different risk meter scales.** A vulnerability's `risk_meter_score` runs 0-100; an *asset's* `risk_meter_score` runs 0-1000. The **Minimum asset risk meter score** parameter is on the 0-1000 scale.
- **`exploitable` is set from evidence, not prediction.** `easily_exploitable`, `malware_exploitable`, and `active_internet_breach` each assert that exploit code or in-the-wild activity exists, and any of them sets the flag. `remote_code_execution` describes impact rather than exploit availability and `predicted_exploitable` is a forecast, so neither contributes; both are kept as custom attributes.
- **Timestamps are format-checked before parsing.** Kenna emits both `2020-03-04T01:30:36Z` and `2020-02-23T14:46:46.000Z` on timestamp fields, but `inactive_at` is a bare `2020-10-31` with no time and no zone. `parse_time` returns an uncatchable Go error on a value with no timezone and kills the run, so only full RFC 3339 values are parsed; anything else stays verbatim as a custom attribute.
- **Rate limiting.** Kenna publishes no rate limit in its API reference. `get_json` retries 408, 425, 429, and 5xx with exponential backoff and honors `Retry-After`, three times by default; this integration keeps that count and widens the backoff factor to 2.0 seconds. Verified against a fixture that returns 429 with `Retry-After: 1` on the first two requests.
- **Memory.** Asset pages are streamed with `report_asset`, and each page's vulnerabilities are fetched, attached, and released before the next page is requested, so nothing larger than one page is ever resident. Services and vulnerabilities are each capped at 99 per asset, the platform's child-collection limit.
- Unverified assumptions, stated plainly: that a Kenna asset `id` survives the host being re-addressed by an upstream connector; that Kenna never recycles a deleted asset id; that Kenna's `severity` integer shares the 0-10 axis used for the CVSS fallback banding (the API reference gives it no documented range); that `state: "running"` and `state: "open"` are the only values on `network_ports` that mean a listening service; and that the `X-Risk-Token` header and asset schema are identical on regional instances, which is implied by the documentation's statement that the API host matches the UI subdomain but is not stated for the schema. The tenant scope in the asset id is the API hostname, which distinguishes regional instances but **not two Kenna tenants served from the same host** — import each Kenna tenant into its own runZero organization.
- This integration was validated against local fixtures, not a live Kenna tenant.

## Future

**Kenna's risk scoring is a prioritization signal runZero has no native equivalent for.** runZero knows what exists and what is exposed; it does not know that a given CVE is being exploited in the wild this week. `risk_meter_score`, `top_priority`, `active_internet_breach`, `easily_exploitable`, and `malware_exploitable` all arrive with this import already, which means a runZero query can rank an asset by exploitation likelihood rather than by CVSS. The natural extension is `GET /fixes/search`, which returns Kenna's remediation groupings — one `fix` object bundles the vulnerabilities a single patch resolves, with `vuln_count`, `max_vuln_score`, and the affected `assets[]` — so runZero could answer "which single change removes the most risk from this subnet", which neither product answers alone today.

**Connector-run status is a data-freshness signal worth importing.** `GET /connectors` returns each connector with `name`, `host`, and `running`, and `GET /connectors/{id}/connector_runs` returns per-run `start_time`, `end_time`, `success`, `processed_assets_count`, and the created/updated/closed vulnerability counts. That is enough to answer a question this import raises on its own: when Kenna says an asset has no findings, is that because it is clean, or because the connector that covers it has not completed a run in three weeks? A small internal integration polling those two endpoints and surfacing the last successful run per connector would make every Kenna-sourced attribute in runZero self-dating. It cannot be folded into this inbound script, which has no asset to hang tenant-level metadata on.

**Asset tagging write-back is the obvious outbound integration.** `PUT /assets/{id}/tags` accepts a tag or array of tags on an asset, and the API reference documents the matching `DELETE` for removal. runZero knows things Kenna does not — device type, which subnet an asset really lives on, whether it is internet-facing, whether it is an OT device that must never be actively scanned — and pushing those into Kenna as tags makes them available to Kenna's own risk meters, which can be scoped by tag. The join is the `id` this integration already stores as `kenna_asset_id`, so an outbound script has the handle it needs with no extra lookup. `PUT /assets/{id}` (notes, inactive) is available on the same object if a deactivation workflow is ever wanted.

**The honest strategic note: the higher-value direction is probably runZero feeding Kenna, not the reverse.** Everything Kenna knows about an asset it learned from some other scanner. What it does *not* know about is the asset no scanner has ever been pointed at — which is precisely runZero's contribution. Kenna supports this directly: the Data Importer accepts a KDI JSON document describing assets and vulnerabilities, uploaded with `POST /connectors/{id}/data_file` as `multipart/form-data`, with an optional `run=true` to trigger the connector immediately (verified in the [Upload Data File](https://apidocs.kennasecurity.com/reference/upload-data-file) reference; the connector id comes from `GET /connectors`, and the documentation warns not to set `Content-Type: application/json` on the request or it returns 400). An outbound integration that pushed runZero's discovered inventory into Kenna as a generic connector would close Kenna's coverage gap rather than re-importing its own aggregate, and would make runZero the source of truth for what exists while Kenna stays the source of truth for what is dangerous. That build is more involved than this one — it needs the KDI document schema, which is documented in Kenna's Data Importer material rather than in the endpoint reference — so it is flagged here rather than assumed to be simple.

**Alert and event ingestion is not available.** The API reference exposes no webhook, subscription, or event-stream endpoint. The closest thing is `GET /audit_logs/`, which returns a gzipped JSON-lines file of changes for a date range — a batch export over past events, not a push channel — so any near-real-time behavior on the runZero side would have to be built by polling on the task schedule.

## API documentation

- API authentication (the `X-Risk-Token` header, key generation, regional hostnames): https://apidocs.kennasecurity.com/reference/api-authentication
- Pagination model (`page`, `per_page`, the `meta` object, per-endpoint limits): https://apidocs.kennasecurity.com/reference/pagination
- Search Assets — asset schema, `primary_locator` values, `network_ports` shape, 20-page / 50,000-per-page limits: https://apidocs.kennasecurity.com/reference/search-assets
- Search Vulnerabilities — vulnerability schema, `asset[id][]` filter, `scanner_vulnerabilities`, CVSS blocks, open-by-default behavior, 20-page / 5,000-per-page limits: https://apidocs.kennasecurity.com/reference/search-vulnerabilities
- Show Asset Vulnerabilities (the per-asset alternative, rejected for having no documented pagination): https://apidocs.kennasecurity.com/reference/show-asset-vulnerabilities
- Tag an Asset (`PUT /assets/{id}/tags`, for the outbound direction): https://apidocs.kennasecurity.com/reference/tag-an-asset
- List Connectors and List Connector Runs (for the freshness signal): https://apidocs.kennasecurity.com/reference/list-connectors and https://apidocs.kennasecurity.com/reference/list-connector-runs
- Upload Data File (`POST /connectors/{id}/data_file`, the Data Importer path): https://apidocs.kennasecurity.com/reference/upload-data-file
- Search Fixes (remediation groupings): https://apidocs.kennasecurity.com/reference/search-fixes
- Risk and vulnerability score ranges (0-100 vulnerability score in thirds, 0-1000 asset risk score): https://help.kennasecurity.com/hc/en-us/articles/4402070116116-Understanding-Vulnerability-Asset-and-Risk-Meter-Scoring
- Cortex XSOAR KennaV2 reference client, used to corroborate the endpoints and header and as the counter-example for pagination: https://github.com/demisto/content/blob/master/Packs/Kenna/Integrations/KennaV2/KennaV2.py

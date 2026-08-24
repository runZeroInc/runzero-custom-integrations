# Custom Integration: Cyberwatch

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Cyberwatch master scanner, which is normally an internal appliance.

## Cyberwatch requirements

- A Cyberwatch master scanner with a valid license.
- An API access key and API secret key generated from **Profile > API Keys**. The pair is used as HTTP Basic credentials: access key as the username, secret key as the password.
- **The owning user must hold the Administrator role.** Cyberwatch states this without qualification: using the API, regardless of the route queried, requires keys belonging to a user with the Administrator role. There is no read-only *user* that can drive this integration, so the usual least-privilege advice does not apply here.
- Least privilege is available at the **key** level instead. A key is issued at one of three access levels — *Agent installation*, *Read only*, or *Full* — and Cyberwatch says outright that Read only suffices for retrieving data. *Agent installation* is the default for a new key and will make every request fail.
- A 403 therefore has two distinct causes that look identical: a non-administrator account, or an administrator's key issued at the *Agent installation* level. Check both.

## Steps

### Cyberwatch configuration

1. Log in to the Cyberwatch master scanner with an Administrator account. The role field on the account must read *Administrator*; a lower role cannot use the API at all.
2. Open **Profile > API Keys**, choose **See my API keys**, and add a new key pair at the **Read only** access level. Record the **API access key** and the **API secret key**; the secret key is shown once. Cyberwatch also offers a **Create > Export** option that downloads the pair as an `api.conf` file.
3. Confirm API access from the Explorer host: `curl -u '<access_key>:<secret_key>' https://<scanner>/api/v3/ping`. A working key returns a JSON body identifying the user.
4. Your instance hosts its own API reference. Open the Cyberwatch UI and click the `</>` button in the top right corner to reach the Swagger documentation for the exact version you are running, including a downloadable `swagger.yaml`. The public documentation lives at `docs.cyberwatch.com` (the older `docs.cyberwatch.fr` now redirects there).

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Cyberwatch").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Cyberwatch master scanner URL** (`url`): base URL of the master scanner, for example `https://192.168.0.1`.
   - **API access key** (`api_access_key`): the access key half of the Cyberwatch API key pair.
   - **API secret key** (`api_secret_key`): the secret key half of the Cyberwatch API key pair.
   - **Import software, services, and CVEs** (`include_details`): optional; fetch the two per-asset detail endpoints (default: enabled).
   - **Detail enrichment limit** (`detail_limit`): optional; maximum number of assets to enrich with detail (default: 1000, `0` removes the cap).
   - **Asset category filter** (`category`): optional; restrict the import to one Cyberwatch category, for example `industrial_device`.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a key pair and see what the scanner returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename cyberwatch/cyberwatch.star \
  --kwargs url=https://cyberwatch.example.com \
  --kwargs api_access_key=7f3a91c4e0b84d26 \
  --kwargs api_secret_key=a5c8f1e7d09b3a42b6d40f9ac1e47f01 \
  --kwargs include_details=true \
  --kwargs detail_limit=10 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cyberwatch-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

Keep `detail_limit` low for a smoke test. `include_details` costs **two extra
requests per asset**, so on a few thousand assets the difference between a
ten-second run and a very long one is entirely this parameter.

A Cyberwatch appliance normally presents an internal or self-signed
certificate. If the run fails on TLS rather than on authentication, set the
`tls_` options rather than reaching for the URL — for example
`--kwargs tls_ca_cert=/etc/ssl/certs/internal-ca.pem`.

To restrict a test run to one category:

```bash
runzero script --filename cyberwatch/cyberwatch.star \
  --kwargs url=https://cyberwatch.example.com \
  --kwargs api_access_key=7f3a91c4e0b84d26 \
  --kwargs api_secret_key=a5c8f1e7d09b3a42b6d40f9ac1e47f01 \
  --kwargs category=industrial_device \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./cyberwatch-ot --overwrite
```

`category` takes a single value, so this is safe either way, but the `--kwargs`
rule is worth knowing: the value reaches the script verbatim, commas included, as
long as the pair contains a single `=`. Only a value carrying a *second* `=` as
well as a comma is re-read as CSV — cut off at the comma, with the remainder
becoming a second, fabricated parameter rather than an error. Wrap such an
argument in double quotes to keep it a single field, `--kwargs '"key=a=b,c=d"'`,
doubling any double quote inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename cyberwatch/cyberwatch.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Cyberwatch accepts the key
pair, that the key is at the right access level, or that any asset is parsed.

The fixtures under `cyberwatch/tests/fixtures/` exercise the parsing offline,
including the malformed-CVE and detail-cap cases:

```bash
python3 tests/run.py cyberwatch
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat cyberwatch/cyberwatch.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://cyberwatch.example.com,api_access_key=7f3a91c4e0b84d26,api_secret_key=<secret>' \
  --output ./cyberwatch-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so no value containing a comma at all can be passed
this way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Cyberwatch.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:cyberwatch`.
- OT assets can be isolated with the runZero search `tag:ot` or `cyberwatch_category:industrial_device`.

## Asset identity

- Target entity: a Cyberwatch "server" — one scanned host, which may be a physical machine, a virtual machine, a hypervisor, a container image, a cloud instance, a network device, or an industrial device.
- Source ID field: `id`, the integer primary key returned by `/api/v3/vulnerabilities/servers`, `/api/v3/assets/servers`, and `/api/v3/compliance/assets`.
- Documentation evidence: every per-asset route in the Cyberwatch API is addressed as `/api/v3/<namespace>/servers/{id}` — `vulnerabilities`, `assets`, `compliance`, the declarative-data route `/api/v3/vulnerabilities/servers/{id}/info`, and the SBOM route `/api/v3/servers/{id}/export` — so the same integer addresses the same host across every view. The vendor-maintained Cortex XSOAR client (`Packs/Cyberwatch/Integrations/Cyberwatch`, authored by Framatome) builds its "full asset" by merging `/api/v3/vulnerabilities/servers/{id}` and `/api/v3/assets/servers/{id}` on that identity alone, and declares `outputs_key_field: id`.
- Uniqueness scope: the master scanner appliance. Cyberwatch ships as an on-prem, single-tenant appliance, so `id` is a database key that is unique within one scanner and carries no meaning across two of them.
- Cardinality: one source row per asset per namespace. The vulnerability view, the sysadmin view, and the compliance view each return one row for the same asset under the same `id`, so several rows collapse to one runZero asset rather than several.
- Stability: the id survives rename, reboot, IP change, OS upgrade, agent upgrade, connector re-scan, and ordinary inventory refresh. It is replaced only when the asset is deleted from Cyberwatch and re-registered, or when the same physical host is registered a second time through a different connector under a different hostname (which produces two Cyberwatch assets, not one).
- Reuse behavior: not documented by the vendor. Cyberwatch is a Rails application and the id is a sequential primary key, which in practice is not recycled after a delete. This is an assumption, not a documented contract, and it is the weakest link in this record.
- Presence: required. Present on every list and detail response in every namespace observed.
- Final runZero ID: `cyberwatch:<scanner-hostname>:<id>` — for example `cyberwatch:cw.corp.example:1226`. The scanner hostname is derived from the configured `url`, which is what makes two appliances that both number their first asset `1` produce distinct runZero ids.
- Missing-ID behavior: skip the record and print `cyberwatch: skipping server with no id: hostname=<hostname>`. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
- Verdict: scoped authoritative.

The match behavior deserves its justification. The Cyberwatch API publishes **no MAC address anywhere** — not on the list endpoints, not on the detail endpoints, not in `metadata`. IP addresses arrive only through the untyped `addresses[]` array, which is frequently just `["127.0.0.1"]` or just the hostname for an agent-scanned host, and which this integration filters down to routable addresses only. So the asset id is the one strong signal, MAC is permanently absent, and IP and hostname are sparse and can change between polls without the asset changing. `no-mac-break no-ip-break no-name-break` keeps the id driving merges while stopping an absent MAC or a changed IP from disqualifying a merge against an asset runZero already discovered on the network.

### Notes

- **What is imported.** Assets come from `GET /api/v3/vulnerabilities/servers`, which is the richer of the two list views (the sysadmin list at `/api/v3/assets/servers` returns only `id`, `hostname`, `last_communication`, `category`, and `description`). With detail enrichment enabled, each asset costs two more requests:
  - `GET /api/v3/vulnerabilities/servers/{id}` supplies `addresses[]`, `cve_announcements[]` (→ **Vulnerabilities**), `security_issues[]`, and `updates[]`.
  - `GET /api/v3/assets/servers/{id}` supplies `packages[]` (→ **Software**), `ports[]` and `services[]` (→ **Services**), `metadata[]`, and `connector`.

  This is the only integration in this repository that populates all four runZero object types.
- **Field mapping.** `hostname` and the non-IP elements of `addresses[]` become hostnames; `os.name` becomes the OS; `category` becomes the device type; `created_at` becomes `firstSeenTS` and `last_communication` becomes `lastSeenTS`. `os.arch`, `os.eol`, `environment`, `groups`, `compliance_repositories`, `connector`, and every `metadata` key/value pair become custom attributes under the `cyberwatch_` prefix. Groups and security issue identifiers also become tags, and `industrial_device` assets are tagged `ot` and `industrial-device` so OT inventory can be searched directly.
- **`addresses[]` is untyped and mixes hostnames with IPs** — `["WIN-GNVEC8UIKUD", "127.0.0.1"]` is a real sample. Each element is sniffed with `ip_address()`; IPs go to the network interface and everything else goes to hostnames. Loopback, unspecified, and link-local addresses are dropped from the network interface, because a Cyberwatch agent commonly reports `127.0.0.1` as the asset's only address and importing that would merge the entire estate onto one runZero asset. The raw array is preserved verbatim in the `cyberwatch_addresses` attribute.
- **No MAC addresses.** The API does not expose one, so none is imported and none is fabricated.
- **Detail enrichment is an N+1 and is capped.** Two extra requests per asset means a 10,000-asset scanner costs about 20,000 requests. `detail_limit` caps the number of assets that get enriched (default 1000). Assets past the cap are still imported with their full list-view data, just without software, services, and CVEs, and they carry `cyberwatch_detail_enriched=false`. When the cap trips the run prints exactly what was skipped, for example `cyberwatch: detail limit of 1000 reached; software, services, and CVEs were not imported for 412 of 1412 assets`. Nothing is truncated silently. Set `detail_limit=0` to remove the cap or `include_details=false` to skip detail entirely.
- **Pagination.** Cyberwatch pages with `page` (1-based, default 1) and `per_page` (**default 30**; the maximum is not documented anywhere the vendor publishes). It reports the result count in the `x-total`, `x-per-page`, and `x-page` response headers and also emits a `Link` header with `rel="next"`. `get_json` does not expose response headers, so neither of those is readable here; this integration uses the alternative rule instead. It requests `per_page=500` and stops on the first page that returns fewer records than the **first page actually returned**, or on the first empty page. Learning the page size from the response rather than trusting the requested `per_page` matters precisely because the maximum is undocumented: if an appliance silently caps `per_page` at 100, comparing against the requested 500 would stop after one page and silently import a fraction of the estate. The cost of this approach is one extra request per run when the record count divides evenly by the page size.
- **Rate limiting.** Cyberwatch does not document a rate limit. The shared HTTP helper retries 408/425/429/500/502/503/504 with exponential backoff and honors `Retry-After`. `retries` defaults to 3, which is what this integration uses.
- **Vulnerabilities.** Each entry in `cve_announcements[]` becomes a Vulnerability. `cve_code` populates `cve` and `name`; `epss`, `prioritized`, `ignored`, and `detected_at` become custom attributes; `published` becomes `publishedTS` and `detected_at` becomes `firstDetectedTS`. The asset's `analyzed_at` becomes `lastDetectedTS`, since that is when Cyberwatch last confirmed the finding was still present.
  - `score` drives `severityScore` and `severityRank` rather than `cvss3BaseScore`. The per-asset announcement carries a single merged `score` with no CVSS version attached; only the CVE catalog endpoint splits it into `score_v2` and `score_v3`. Writing an unlabelled score into a v3-specific field would be a guess, and would be wrong for older CVEs that only have v2 data.
  - `environmental_score` drives `riskScore` and `riskRank`. Cyberwatch computes it by adjusting the CVSS environmental metrics with the asset's declared confidentiality, integrity, and availability requirements, which is precisely runZero's notion of risk: severity placed in context. When it is absent the base score is used for both.
  - Ranks use the standard CVSS bands (`<0.1` info, `<4.0` low, `<7.0` medium, `<9.0` high, otherwise critical).
  - `updates[]` is indexed by the CVE codes each update fixes, so every finding carries a `solution` such as `Update libnettle6 from 3.4.1-1 to 3.4.1-1+deb10u1`, plus a `cyberwatch_patch_available` attribute. Updates flagged `patchable: false` say so in the solution text.
  - Announcements with a `fixed_at` date or `active: false` are **not** imported: they are remediated, and importing them would show closed findings as open in runZero. The count is preserved as `cyberwatch_cve_fixed_count`. Announcements Cyberwatch has `ignored` are imported and flagged, so a runZero user can see what has been suppressed upstream.
  - **No service fields are set on a Vulnerability.** Cyberwatch cannot associate a CVE with a port, so `serviceAddress`, `servicePort`, and `serviceTransport` are deliberately left unset.
- **Software.** Each entry in `packages[]` becomes a Software record with `product`, `vendor`, and `version`. The `type` field distinguishes `Packages::Deb`, `Packages::WinApp`, and `Packages::Kb`. A Windows KB is a patch rather than an application, but it is still real installed-state inventory and there is nowhere else in the runZero model to record it, so KB entries are emitted as Software and sorted **behind** the applications. That way the 99-child cap is filled with real applications first and KBs only take whatever room is left, instead of a Windows host's several hundred KBs pushing every application out.
  - Other observed `type` values are `Packages::Nvd` (an application declared by CPE) and, per the Elasticsearch export schema, an RPM variant. The list is not exhaustive, so anything that is not a KB is treated as an application.
  - `paths` is **not** mapped to `installedFrom`. On Debian assets it carries the dpkg selection state (`["ii"]`), not a filesystem path, so it is recorded as `cyberwatch_package_paths` instead.
  - `Software.cpe23` is never set. **Cyberwatch publishes no CPE on the output side at all** — not in the asset detail response, not in the Elasticsearch export schema (`package_vendor`, `package_product`, `package_version`, `package_type`, `package_eol`, and no CPE column). A package's identity is the `(vendor, product, version, type)` tuple, where `vendor` and `product` are CPE-derived tokens rather than CPE strings. CPE appears only on the *declarative input* side, where Cyberwatch's own documentation mixes the 2.2 URI binding (`cpe:/a:elastic:kibana:7.0.0`) and 2.3 formatted strings (`cpe:2.3:a:redhat:keycloak:...`) inconsistently. Since `Software.cpe23` is validated against `^cpe:/a:.*` — the CPE 2.2 URI binding, application class only — a synthesized or 2.3-formatted value would fail validation and drop the whole Software record, so none is constructed.
- **Services come from `ports[]`, not from `services[]`.** This is the one mapping worth reading carefully, because the two Cyberwatch fields are not what their names suggest.
  - `ports[]` holds network sockets: `{"port": 443, "protocol": "TCP", "package": {...}}`. Each becomes a runZero **Service**. `protocol` is lower-cased into `transport`; when `package` is populated it is the full package object that owns the socket, so its `product` and `version` enrich the Service — a listener on 443 owned by `docker-ce 5:19.03.12` is imported with that product and version attached.
  - `services[]` holds **operating system service units**: `{"name": "systemd-time-wait-sync", "status": "disabled", "updated_at": "..."}`. There is no port and no protocol on a service, and the two arrays are independent — a service cannot be joined to a port. They are therefore **not** imported as Service objects, which require an address, port, and transport. They are recorded as `cyberwatch_services` (a list of `name:status` pairs) and `cyberwatch_service_count` instead.
  - An element in either array that names no transport is recorded as `tcp` and flagged with `cyberwatch_transport_source=assumed`. Ports outside 1-65535 and duplicate port/transport pairs are dropped.
  - **The remaining assumption:** this shape is documented in Cyberwatch's own API v3 reference and corroborated by the Elasticsearch export schema (`computers_ports` has `port_number` / `port_protocol` / `port_product`; `computers_services` has only `service_name` / `service_status` / `service_updated_at`, with no port column) and by the declarative input grammar (`TCP:22|openssh` versus `SERVICE:ssh|enabled`). But every JSON sample that could be obtained had `"services": []`, so a non-empty `services[]` response has not been seen firsthand. As insurance against schema drift, a `services[]` element that unexpectedly *does* carry a usable port is still turned into a Service. If a future release changes the shape, that path will catch it rather than dropping the data.
- `ports[]` and `services[]` are only populated for assets Cyberwatch scans over the network; agent-scanned hosts report both as empty, which is why the vendor's own published example shows them empty.
- Assets are streamed to runZero one page at a time with `report_asset`, so the full inventory is never held in memory at once.
- This integration was validated against local fixtures, not a live Cyberwatch appliance.

## Future

- **Outbound asset feed via `POST /api/v2/cbw_scans/scripts`.** This is Cyberwatch's declarative (air-gap) data upload: a client posts a `{"output": "<text blob>"}` body describing a host, and Cyberwatch ingests it as a scan result. The blob grammar is fully documented and includes exactly the fields runZero is best at producing — `HOSTNAME`, `IP`, `OS_NAME`, `OS_VERSION`, `ARCH`, `TCP:<port>[|<product>]`, `UDP:<port>`, `SERVICE:<name>|<status>`, `PACKAGE:<name>|<version>`, `NVD_APPLICATION:<cpe>`, `FIRMWARE`, `HARDWARE`, and `META:<key>|<value>`. An outbound runZero integration could push runZero's own asset inventory into Cyberwatch for vulnerability analysis, which is the strongest pairing of the two products for air-gapped OT networks, where runZero's passive and unauthenticated discovery reaches segments no Cyberwatch agent or authenticated connector can. This requires a **Full** access-level API key, unlike everything else described here. The corresponding read side, `GET /api/v3/vulnerabilities/servers/{id}/info`, returns that same blob as **plain text** rather than JSON and only for declaratively scanned assets, so it is useless for inventory import and is deliberately not called by this integration.
- **SBOM export via `GET /api/v3/servers/{id}/export?format=CycloneDX` (or `SPDX`).** Cyberwatch will render an asset's package inventory as a standard SBOM document. That is a richer and more portable software record than the `packages[]` array this integration reads, and it would be the natural basis for an SBOM-oriented import if runZero grows a place to put one.
- **Compliance import via `GET /api/v3/compliance/servers` and `/api/v3/compliance/servers/{id}`.** These return per-asset CIS and ANSSI rule results — `compliance_rules_count`, `compliance_rules_failed_count`, `compliance_rules_succeed_count`, and the repositories in scope. Rule pass/fail is a data class runZero does not model today; the counts could land as custom attributes immediately, and individual failed rules could be imported as Vulnerabilities with a `compliance` category if that framing is acceptable. Note that the vendor's own XSOAR client calls the list route `/api/v3/compliance/assets` while the API reference documents `/api/v3/compliance/servers`; which one the current release serves needs checking against a live instance.
- **Security issues via `GET /api/v3/vulnerabilities/security_issues` and `/{id}`.** These are manually recorded findings — pentest results, `Obsolete-Os`, custom `sid` values — with a `level` (`level_critical` … `level_info`), a title, a description, and the list of affected servers. The detail endpoint returns `servers[]`, so a single pass over the security issue list would attach these to assets as Vulnerabilities without an N+1, which is a better trade than the per-asset `security_issues[]` this integration currently reduces to tags. The same route ambiguity applies here: the API reference documents `/api/v3/vulnerabilities/security_issues` and the vendor's XSOAR client calls `/api/v3/security_issues`.
- **CVE enrichment via `GET /api/v3/vulnerabilities/cve_announcements/{cve_code}`.** The catalog record carries the description, `score_v2` and `score_v3` split out separately, `epss`, `exploit_code_maturity`, `exploitable`, CWE, CAPEC, ATT&CK references, and vendor security announcements. Fetching it per distinct CVE with a cache would let the integration set `cvss2BaseScore` and `cvss3BaseScore` correctly instead of the version-agnostic `severityScore` used today, and would populate finding descriptions. The cost is one request per distinct CVE across the estate, which is why it is not done inline.
- **Scan-coverage-gap reporting.** Cyberwatch records `last_communication`, `analyzed_at`, and `connector` per asset. Comparing runZero's own discovered inventory against the Cyberwatch asset list would identify hosts runZero sees that Cyberwatch has never scanned, and Cyberwatch assets that have gone quiet. This needs no new Cyberwatch endpoint; it is a reporting layer over what this integration already imports.
- **Alert and event ingestion is not possible.** The Cyberwatch API publishes no webhook, event stream, or alert endpoint. Change detection would have to be built by polling `analyzed_at` and diffing, which is a scheduled import rather than an event integration.

## API documentation

- Documentation portal — https://docs.cyberwatch.com/help/en/ (the older `docs.cyberwatch.fr` now redirects here). Used for authentication, key access levels, and the declarative grammar.
- Authentication and key generation — https://docs.cyberwatch.com/help/en/API_documentation/API_use/ ("These API keys can be generated from the Cyberwatch GUI, in Profile > API Keys tab, for each user") and https://docs.cyberwatch.com/help/en/API_documentation/curl_snippets/ (`--user 'access_key:secret_key'`, confirming HTTP Basic with the access key as username).
- **Object schema, pagination, and the endpoint set** — the complete Cyberwatch API v3 reference, which has been removed from the live site in favour of per-instance Swagger, is preserved at https://web.archive.org/web/20230201101446id_/https://docs.cyberwatch.fr/api/fr/. This is the source for the `page` / `per_page` contract (`per_page` default 30, `page` default 1), the `x-total` / `x-per-page` / `x-page` / `Link` response headers, and the `ports[]` (`{port, protocol, package}`) and `services[]` (`{name, status, updated_at}`) element shapes on `GET /api/v3/assets/servers/{id}`.
- Elasticsearch export schema — https://docs.cyberwatch.com/help/en/reports/es_indexes/. Independent corroboration of the ports/services split (`computers_ports` carries `port_number`, `port_protocol`, `port_product`; `computers_services` carries only `service_name`, `service_status`, `service_updated_at`) and of the absence of any CPE column on packages.
- Declarative data grammar — https://docs.cyberwatch.com/help/en/configurations/declarative_syntax/. The basis for the outbound feed described under Future, and a third confirmation that ports and services are distinct concepts (`TCP:22|openssh` versus `SERVICE:ssh|enabled`).
- Vendor-maintained Cortex XSOAR integration, published by Framatome — https://github.com/demisto/content/tree/master/Packs/Cyberwatch/Integrations/Cyberwatch. Source for the identity contract (`outputs_key_field: id`, and the merge of `/vulnerabilities/servers/{id}` with `/assets/servers/{id}`), the `category` filter enum (`no_category`, `server`, `desktop`, `hypervisor`, `network_device`, `network_target_or_website`, `docker_image`, `industrial_device`, `cloud`, `mobile`), and the JSON response fixtures this integration was tested against.
- Cyberwatch API client libraries — https://github.com/Cyberwatch (`cyberwatch_api`, `cyberwatch_api_toolbox`). Both are hand-written wrappers with no generated models; their recorded HTTP fixtures were used to confirm the pagination response headers. No public OpenAPI or Swagger document exists — the Swagger is served only from a running instance.

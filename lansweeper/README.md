# Custom Integration: Lansweeper

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Lansweeper requirements

- A Lansweeper Sites account with at least one site containing scanned assets.
- A personal application created under Developer Tools, authorized against every site you want to import.
- The application identity code issued when that application is authorized.
- Nothing beyond the default read access is required for assets and installed software. Vulnerability data is **not** imported by this integration; it would additionally require a Pro or Enterprise plan and the **View vulnerabilities** permission.

## Steps

### Lansweeper configuration

1. Sign in to [Lansweeper Sites](https://app.lansweeper.com/) and open **Developer Tools**.
2. Create a **Personal Application**.
3. Click **Authorize** and select the sites the application may read.
4. Copy the **Application identity code** shown after authorization. This is the only credential the integration needs.
5. Note the site IDs from the same screen if you intend to import only a subset of your sites.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Lansweeper").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Lansweeper API URL** (`url`): optional; defaults to `https://api.lansweeper.com`.
   - **Site IDs** (`site_ids`): optional; comma-separated site IDs. Leave blank to import every authorized site.
   - **Application identity code** (`application_identity_code`): the identity code from Developer Tools.
   - **Import installed software** (`import_software`): optional; defaults to enabled.
   - **Assets per page** (`page_size`): optional; defaults to 200, maximum 500.
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
runzero script --filename lansweeper/lansweeper.star \
  --kwargs url=https://api.lansweeper.com \
  --kwargs application_identity_code=b4f19c2e7a305d8641bce09f27a3d5108e6b4c92 \
  --kwargs site_ids=6f0d4a2b-91c7-4e58-b3a0-72d1e9f4c580 \
  --kwargs import_software=false \
  --kwargs page_size=25 \
  --output ./lansweeper-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`url` is optional and defaults to `https://api.lansweeper.com`. Leave `site_ids` out
entirely to import every site the identity code is authorized for.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

`site_ids` is a comma-separated list, and it survives `--kwargs` intact: the flag only
CSV-splits a value when the whole argument contains a second `=`, which a list of site IDs
does not. Quote the argument in your shell and `site_ids=<id1>,<id2>` is passed through as
written. The same is not true of `scan --custom-integration-script-kwargs` below.

Turn `import_software` off for a first run. It adds five element paths to the GraphQL query
and attaches a software list to every asset, which is what pushes a response page towards
the 4 MB cap; drop `page_size` further if pages are rejected.

To check the `CONFIG` block and the HTTP and TLS wiring without touching the real API:

```bash
runzero script --filename lansweeper/lansweeper.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Lansweeper accepts the identity code or that any asset is
parsed.

The recorded GraphQL shapes, including an error envelope, are exercised by the fixture
suite:

```bash
python3 tests/run.py lansweeper
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat lansweeper/lansweeper.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.lansweeper.com,application_identity_code=<code>' \
  --output ./lansweeper-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. This flag takes one
comma-separated string, so a multi-site `site_ids` value genuinely cannot be passed through
it — name a single site, configure the list on the console credential, or use
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Lansweeper.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:lansweeper`.

## Asset identity

- Target entity: a Lansweeper asset — the scanned device (workstation, server, VM, network device, printer) as tracked in the inventory of one Lansweeper site.
- Source ID field: `data.site.assetResources.items[].key`
- Documentation evidence: `assetResources` is rooted at `site(id: "<siteId>")`, so every result set is scoped to one site ([getting data guide](https://developer.lansweeper.com/docs/data-api/guides/getting-data)). `key` is the handle the rest of the API uses to address an asset: the per-asset software query takes it as `softwares(key: "...")` ([softwares reference](https://developer.lansweeper.com/docs/data-api/reference/softwares)), the vulnerabilities query joins back through `assetKeys` ([vulnerabilities guide](https://developer.lansweeper.com/docs/data-api/guides/vulnerabilities)), and `deleteAssets(keys: [...])` deletes by it ([actions guide](https://developer.lansweeper.com/docs/data-api/guides/actions)). The Cortex XSOAR Lansweeper pack likewise renames `key` to `assetId` and stores the owning `siteId` alongside it.
- Uniqueness scope: site. The key is only meaningful inside the site it was returned from, so the site ID is part of the runZero ID.
- Cardinality: one `items[]` entry per asset per site. Installed software arrives as a nested `softwares` list on the same row rather than as separate rows, so software never fans an asset out into duplicates.
- Stability: the key is assigned by Lansweeper's inventory, not derived from network state, so it survives rename, reboot, DHCP lease change, NIC replacement, and OS upgrade. Deleting an asset and letting a later scan rediscover it produces a new key — Lansweeper's own documentation warns that a deleted asset reappears on the next scan unless it is added to Scan Exclusions.
- Reuse behavior: not documented. Lansweeper does not state whether a deleted asset's key can be reissued to a different asset. Keys observed in practice are opaque, high-entropy values, which makes reuse unlikely but unproven.
- Presence: present on every `assetResources` item observed in vendor documentation examples and in the XSOAR pack's recorded responses. The integration does not assume it: an item with a blank or missing `key` is skipped.
- Final runZero ID: `lansweeper:<siteId>:<key>`
- Missing-ID behavior: skip the record and log `lansweeper: skipping asset with no key: name=<name>`. No ID is synthesized and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The site-scoped key drives merging; Lansweeper reports only a single primary MAC and a single primary IP per asset, and both churn under DHCP and NIC changes, so neither should be able to disqualify a merge.
- Verdict: scoped authoritative.

### Notes

- **Imported objects.** Assets from `site(id:).assetResources`, plus `Software` objects built from the nested `softwares` list on each asset. Services and vulnerabilities are not imported.
- **Endpoints.** Everything goes through a single endpoint, `POST https://api.lansweeper.com/api/v2/graphql`. `authorizedSites` enumerates the sites the identity code can read; one `assetResources` query is then issued per site. Authentication is the static header `Authorization: Token <application identity code>`.
- **Asset fields.** `assetBasicInfo.name`, `.fqdn`, and `assetCustom.dnsName` are collected and de-duplicated into `hostnames`. `.mac` and `.ipAddress` build the network interface via `network_interface()`. `.domain` maps to `domain`, `.type` to `deviceType`, `assetCustom.manufacturer`/`.model` to `manufacturer`/`model`, and `operatingSystem.caption` to `os`. `.firstSeen`/`.lastSeen` become `firstSeenTS`/`lastSeenTS`. Everything else — user, location, department, state, SKU, serial number, firmware version, OS product type, site ID/name, and the asset's Lansweeper URL — lands in custom attributes prefixed `lansweeper_`. Serial number, state, and site name are also emitted as tags.
- **`firmwareVersion` is not mapped to `osVersion`.** Lansweeper reports it as the hardware/BIOS revision (e.g. `A11` on a Dell OptiPlex), so pairing it with `operatingSystem.caption` would produce a contradictory OS/version pair. It is kept as `lansweeper_firmware_version`.
- **Pagination.** Verified against the vendor documentation. `AssetsPaginationInputValidated` has exactly three fields — `cursor` (`ID`), `limit` (`Int`), and `page` (`AssetsPage`, one of `FIRST`, `PREV`, `NEXT`, `LAST`) — and the [getting data guide](https://developer.lansweeper.com/docs/data-api/guides/getting-data) shows the variable sent whole as `{"pagination": {"limit": 3, "page": "FIRST"}}`. It must be passed as a single object; splitting `limit` into its own GraphQL variable returns HTTP 400. This integration sends `{"limit": N, "page": "FIRST"}` for the opening request and `{"limit": N, "page": "NEXT", "cursor": <previous response's pagination.next>}` for each subsequent page, looping until `pagination.next` is null.
- **The `total` field is only requested on the first page.** Lansweeper's [restrictions page](https://developer.lansweeper.com/docs/data-api/get-started/restrictions) states that selecting `total` requires `FIRST` and cannot be combined with `PREV`, `NEXT`, or `LAST`, so the integration builds two query documents per site and drops `total` from the paging document.
- **The terminal pagination condition is the one unverified element.** The documentation describes what `next` means but never states in prose what it contains on the last page. `next == null` is used here because that is what Lansweeper's own published code does — the official [MCP server](https://github.com/Lansweeper-public/MCP-server-lansweeper) types `next` as `string | null` and treats null as done, and a Lansweeper staff Python sample loops `while ...['pagination']['next'] != None`. A short page is deliberately *not* treated as the end, because silently truncating an inventory is worse than one extra request; a repeated cursor and a hard page bound stop the loop if `next` ever fails to clear.
- **Page size.** 500 is the effective maximum — Lansweeper's own MCP server enforces `limit ≤ 500` and its staff samples hardcode 500 — but no official sentence states a maximum, so treat 500 as observed rather than contractual. The default here is 200 because a response page is capped at 4 MB and attaching the `softwares` list to every asset inflates pages considerably; lower it further if pages are rejected.
- **Documented API limits.** 150 requests per minute (exceeding it restarts the cooldown), 30 element paths per request, 100 filter conditions, 2,000 synchronous requests per hour, 4 MB per response page. This integration requests 23 element paths for assets and 28 with software enabled, staying under the 30-path cap.
- **Rate limiting.** `post_json` retries `408/425/429/500/502/503/504` with exponential backoff and honors `Retry-After`, making up to three additional attempts by default. Nothing is hand-rolled.
- **CPE handling.** `Software.cpe23` in runZero only accepts the CPE 2.2 application URI binding (`cpe:/a:...`) and rejects the entire import otherwise. Lansweeper does not document which binding `softwares.cpe` emits, so a value that does not match is preserved as a `lansweeper_cpe` custom attribute on the `Software` object instead of being passed through.
- **Software is optional.** Set **Import installed software** to off to drop the five `softwares.*` paths from the query. This reduces response size and path count at the cost of losing the software inventory.
- **Multi-site.** Every authorized site is imported by default. Because the asset key is site-scoped, the same device present in two sites is imported as two distinct runZero assets and merged downstream on hostname/MAC/IP.
- This integration was validated against local fixtures, not a live Lansweeper tenant.

## Future

- **Outbound push-back is genuinely supported — the Data API is not read-only.** [`addAsset`](https://developer.lansweeper.com/docs/data-api/reference/addasset) creates an asset in a site and explicitly notes that "any field specified during asset creation will be protected from being overwritten by the discovery systems", which makes runZero-discovered assets a durable source of truth for fields Lansweeper's own scanners cannot reach. `editAsset`/`editAssets` update existing assets, and `createCustomField` plus `editAssets` would let runZero write attributes such as its own asset ID, risk rank, or service fingerprint back onto Lansweeper records. There is no `assetImport` or `installAssetCustomField` mutation — those are the equivalents. Note the input shape is inconsistent: some `AddAssetInput` fields are bare scalars (`barCode`, `branchOffice`) while others are wrapped objects (`name: {value: ...}`), and the wrapper is what marks a field discovery-protected.
- **Coverage-gap reporting between two overlapping discovery tools.** This is the most valuable pairing available here. Lansweeper and runZero are direct analogs — both sweep the network and build an asset inventory — so the interesting artifact is not the union but the difference. An outbound integration could pull the runZero inventory, diff it against `assetResources` on hostname/MAC/IP, and report three buckets: assets runZero sees that Lansweeper's credentialed scanners missed (usually unmanaged, embedded, or OT devices), assets Lansweeper has that runZero has not scanned (usually a scope or Explorer placement gap), and assets both see but disagree about (OS, owner, or last-seen drift). The gap list is the output customers actually act on. `exportFilteredAssets`/`cancelExport` provide an asynchronous bulk export path better suited to a full-inventory diff than paging `assetResources`, and `createScanningTask` and `scanNow` would let runZero ask Lansweeper to re-scan the subnets where it found assets Lansweeper does not have.
- **Vulnerability import.** The schema supports it and it was deliberately left out of this first version. `site(id:).vulnerabilities(pagination:, filters:)` returns a typed `SiteVulnerability` list — `cve`, `severity`, `baseScore`, `riskScore`, `attackVector`, `attackComplexity`, `weaknessEnumeration` (CWE), `references`, `publishedOn`/`updatedOn`, `patchable`, `isActive`, a `cause` object (`vendor`, `affectedProduct`, `category`), and an `exploitability` object carrying CISA KEV, EPSS, NVD, MSRC, and Vulncheck signals plus `exploitedInTheWild` — which maps cleanly onto runZero's `Vulnerability` type. It joins back to assets through `assetKeys`. Three things make it a separate piece of work: it requires a Pro or Enterprise plan and the **View vulnerabilities** permission, so it must degrade gracefully when either is absent; the argument is named `pagination` rather than `assetPagination` despite reusing the same input type; and its cursors are offset-based, with the [vulnerabilities guide](https://developer.lansweeper.com/docs/data-api/guides/vulnerabilities) stating outright that "both `current` and `next` values in the response will always match", so `next == null` is *not* a valid stop condition there — paging must run against `total` instead. `kbPatches(cve:)` would additionally supply Microsoft KB patch IDs for remediation guidance.
- **Deeper software inventory.** Beyond the five paths imported here, `softwares.*` also exposes `architecture`, `edition`, `language`, `marketVersion`, `shortVersion`, `installType`, `operatingSystem`, `category`, `unspsc`, and `status`, which map to `targetHardware`, `softwareEdition`, `language`, and related `Software` fields. The 30-path cap is what prevents pulling them all alongside the asset fields; a second pass using the site-wide `softwareListWithCursor` query (which uses a different `softwarePagination` shape with `cursor: [{fieldName, fieldValue}]` and a lowercase `page: next`) would lift that constraint. `assetsWithSoftware` and `assetsWithoutSoftware` would also support license-compliance and missing-agent reporting.
- **Event ingestion.** `createWebhook`/`editWebhook`/`deleteWebhook` exist, and vulnerability INSERT/DELETE webhook events are documented. A near-real-time trigger could replace or supplement the scheduled poll, which matters given the 150 request/minute ceiling on large estates.

## API documentation

- Getting data, `assetResources`, field selectors, and the pagination variable: https://developer.lansweeper.com/docs/data-api/guides/getting-data
- Cursor semantics and the worked pagination example: https://developer.lansweeper.com/docs/data-api/get-started/example-query
- Type reference (`AssetsPaginationInputValidated`, `AssetsPage`, `Software`, `SiteVulnerability`): https://developer.lansweeper.com/docs/data-api/reference/types
- Rate limits, path caps, response size cap, and the `total`/`FIRST` restriction: https://developer.lansweeper.com/docs/data-api/get-started/restrictions
- Per-asset software query: https://developer.lansweeper.com/docs/data-api/reference/softwares
- Software request patterns: https://developer.lansweeper.com/docs/data-api/guides/request-software
- Vulnerabilities: https://developer.lansweeper.com/docs/data-api/guides/vulnerabilities
- Asset creation mutation: https://developer.lansweeper.com/docs/data-api/reference/addasset
- Scan and delete actions: https://developer.lansweeper.com/docs/data-api/guides/actions
- Lansweeper's official MCP server, used to corroborate the pagination and software field paths: https://github.com/Lansweeper-public/MCP-server-lansweeper

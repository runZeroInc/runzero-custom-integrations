# Custom Integration: Tenable OT Security

Tenable OT Security (formerly Tenable.ot, originally Indegy, and rebranded again as
Tenable OT Exposure on the developer portal) is an OT/ICS asset inventory and
exposure product delivered as an on-premise console appliance. This integration
imports that inventory into runZero through the console's GraphQL API, including
the plugin findings and Windows hotfixes the console records against each asset.

Note that this is a **different product from the native runZero Tenable
integrations**. Those cover Tenable Vulnerability Management, Nessus, and
Security Center; Tenable OT Security is not among them, which is why it is a
custom integration.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Tenable OT Security requirements

- A reachable Tenable OT Security console (the Enterprise Manager or a standalone
  console). There is no shared SaaS hostname; the address is per-customer.
- An API key generated on that console. The key inherits the permissions of the
  user who created it, so create it as a user with read access to assets and
  plugins.
- Network egress from the Explorer to the console over HTTPS. These appliances
  commonly present a certificate that is not signed by a public CA; if so, set
  the standard `tls_disable_validation` option on the credential rather than
  disabling validation somewhere else.

## Steps

### Tenable OT Security configuration

1. In the OT Security console, open **Local Settings > System Configuration > API Keys**
   and click **Generate Key**.
2. Record the key. Tenable documents that "The API key and API secret are shown only
   once", so it cannot be retrieved later.
3. Choose an expiration. **The maximum expiration period is 365 days**, so the key
   is not permanent and this credential will need rotating before it lapses.
4. An API *secret* is issued alongside the key. Every observed client (Tenable's own
   pyTenable, Elastic's shipping integration, and the GraphiQL playground documentation)
   authenticates with the **key alone**, so this integration only asks for the key.
5. Confirm access. The header is `X-APIKeys` with a `key=` prefix and **no bearer
   scheme**:

   ```bash
   curl -sk https://ot.example.com/graphql \
     -H 'X-APIKeys: key=<api-key>' \
     -H 'Content-Type: application/json' \
     -d '{"query":"query { assets(first: 2) { nodes { id name type } pageInfo { hasNextPage endCursor } } }"}'
   ```

   The console also serves an interactive GraphiQL playground, which is the fastest
   way to confirm which fields your release publishes before scheduling anything.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Tenable OT Security").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OT Security console URL** (`url`): the console base URL, for example `https://ot.example.com`. The `/graphql` path is appended automatically.
   - **API key** (`api_key`): the key generated above. Sent as `X-APIKeys: key=<value>`.
   - **Assets per page** (`page_size`): optional; default 200, maximum 1000. This is the GraphQL `first` argument. pyTenable uses 200 and Elastic uses 1000.
   - **Lookback window (days)** (`lookback_days`): optional; default 0, which imports the whole inventory. A positive value imports only assets created or updated within that window.
   - **Include hidden assets** (`include_hidden`): optional; default false. Hidden assets are ones an operator suppressed in the console.
   - **Import plugin findings** (`import_vulnerabilities`): optional; default true.
   - **Import OS hotfixes as software** (`import_software`): optional; default true.
   - **Import open ports as services** (`import_services`): optional; default false. Adds `openPorts` to the interface selection, which is the deepest part of the document, three connections down from the asset, so it is opt-in.
   - **Disable TLS validation** (`tls_disable_validation`): set this if the console presents a self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a key and see what a console returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename tenable-ot-security/tenable-ot-security.star \
  --kwargs url=https://ot.example.com \
  --kwargs api_key=0123456789abcdef0123456789abcdef \
  --kwargs page_size=200 \
  --kwargs lookback_days=0 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./tenable-ot-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run; the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

For a fast smoke test on a large console, narrow the pull rather than the page:

```bash
runzero script --filename tenable-ot-security/tenable-ot-security.star \
  --kwargs url=https://ot.example.com \
  --kwargs api_key=0123456789abcdef0123456789abcdef \
  --kwargs lookback_days=7 \
  --kwargs import_vulnerabilities=false \
  --kwargs import_software=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

The three import toggles are worth knowing about on a busy console: each adds a
nested selection to the same GraphQL document, so the console does materially
more work per page with them on. Turning them off does not change the asset
count, only the depth of what is attached. Every nested connection the document
selects carries a server-side `first:` bound matching the client-side cap, so an
asset with thousands of plugin hits is truncated by the console rather than
transferred in full and then discarded.

To check the `CONFIG` block and the HTTP and TLS wiring without a live console:

```bash
runzero script --filename tenable-ot-security/tenable-ot-security.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the console accepts the key, that the
GraphQL document validates against your release, or that any asset is parsed.

The fixtures under `tenable-ot-security/tests/fixtures/` exercise the parsing
offline, including the cursor walk, the malformed-record case, the rate-limit
case, the identity regression lock, the `PluginDetails` selection, the
never-seen asset, the combined `And` filter, DNS-name hostnames, and open ports:

```bash
python3 tests/run.py tenable-ot-security
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat tenable-ot-security/tenable-ot-security.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://ot.example.com,api_key=<key>,lookback_days=0' \
  --output ./tenable-ot-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so no value containing a comma at all can be passed
this way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Tenable OT Security.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:tenable-ot-security`.

## Asset identity

- Target entity: physical OT and IT assets observed by an OT Security console: controllers, HMIs, RTUs, engineering stations, servers, and network devices.
- Source ID field: `assets.nodes[].id`
- Documentation evidence: https://docs.tenable.com/OT-security/api/asset.doc.html declares `id` as type `ID!` (non-null) with the description "Asset ID". The observed values are UUIDs: Elastic's shipping `tenable_ot_security` package carries `"id": "c2fb6b1e-f015-49b4-a247-6576fc648a6e"` in its pipeline test fixture, and its docker fixture carries `"id": "00b1e0a5-31ce-4b30-9af7-a6e1aa4616b8"`. Note one documentation inconsistency: pyTenable's `assets.asset()` type-hints `asset_id: int`, which contradicts both the schema and every observed value. The schema and the samples are authoritative.
- Uniqueness scope: console-global. A single console covers all of its sensors, and `segments` is a per-asset attribute rather than a partition of the id space. Whether ids stay unique across consoles aggregated by an Enterprise Manager could not be verified from public documentation, so the console is treated as the identity scope regardless.
- Cardinality: one `assets` node per asset. Plugin findings and OS hotfixes are many-to-one children of the same node and are attached to the asset rather than emitted as separate assets. Revisions are modelled by the vendor as `revisions { nodes { ordinal isBase } }` hanging off the asset, so a re-observed asset accumulates revisions rather than spawning rows.
- Stability: survives rename, readdress, and reclassification. `ips`/`macs` are multi-valued `StringConnection!` fields hanging off the asset, `directIps`/`directMacs` are separate again, and `assetByEndpoint(ip: String, mac: String)` exists as a **separate lookup**, which is the structural proof that IP and MAC are secondary indexes rather than the key. `name` is an ordinary `String!` and the customer-editable `customField1..10` are distinct fields from it.
- Reuse behavior: not documented either way, and marked unverified. Reuse is nonetheless very unlikely: the values are UUIDs rather than a sequence, and `deletedAssets(since: Time)` exists specifically so consumers can retire ids that have gone away.
- Presence: always. `ID!` is non-null in the schema, and it is the field pyTenable sorts on by default (`{"field": "id", "direction": "DescNullLast"}`).
- Final runZero ID: `tenable-ot-security:<console hostname>:<asset id>`
- Missing-ID behavior: skip. A node with a null, empty, or non-scalar `id` is logged as `skipping asset with no id: name=<name>`, counted, and dropped. No random or synthesized id is ever generated.
- Match behavior (set once in `CONFIG`): `no-name-break`. Id matching stays **on**, because the id is a genuine one-per-asset opaque key by every test above. Only name breaking is relaxed: the console names most assets synthetically (`OT Device #966`, `PLC #14`) and operators rename them freely, so a name disagreement carries no evidence and must not veto a first-contact merge. `mac-break` and `ip-break` are deliberately **kept on**. `ips`/`macs` aggregate every address the console associates with an asset, including addresses inherited from sibling backplane modules and the address of a gateway an asset is reached through, so a conflicting address here is genuine evidence against a merge and is often the only signal separating two members of one chassis.
- Verdict: **scoped authoritative.** The id identifies the asset, not one of its addresses or observations, and is unique within one console, which is why the console hostname is part of the runZero id.

### Notes

- **Assets** come from a single `POST /graphql` with the published `assets(first:, after:, filter:, sort:)` query. The DNS names on the asset's interfaces become the hostnames, with `name` behind them and always kept as `tenable_ot_security_name`; `directNetworkInterfaces` becomes the network interfaces; `vendor` becomes the manufacturer; `model` becomes the model; `type` becomes the device type; `os` (or `osDetails.name`) becomes the OS and `osDetails.version` the OS version; `firstSeen` becomes `firstSeenTS` and `lastSeen` becomes `lastSeenTS`.
- **`lastSeen` is the only sighting, and it is nullable.** The schema is explicit about the other two: `lastHit` is "Latest date of last plugin hit or plugin status change" and `lastUpdate` is "Asset's details last update time". Neither means anybody observed the device: a plugin set re-evaluated overnight, or a criticality an operator edited, touches the record without a sighting. Because `lastSeen` is nullable while `lastUpdate` is `Time!` and therefore always present, a fallback chain would fire on precisely the assets the console says were never seen and stamp every one of them as freshly seen, which makes a decommissioned asset look live in runZero forever. So there is no fallback: an asset with no `lastSeen` gets no `lastSeenTS`, and both other fields are kept as attributes.
- **The console's own asset names are usually not hostnames, so DNS names are used instead.** Synthetic names like `OT Device #966` contain characters that cannot appear in a DNS name, so `clean_hostnames` refuses them along with placeholders and bare IP addresses. The real hostname source is `dnsNames`, which the schema publishes on both `NetworkInterface` and `IpDetails` and which pyTenable selects from both; both are read, and the console name is kept as the fallback behind them. A real name such as `DeviceNet_L81` or `ENG-STATION-04` is still imported. The raw value is always available as a custom attribute either way.
- **`deviceType` carries the console's `type` value verbatim** (`Plc`, `Hmi`, `Rtu`, `EngineeringStation`, `OtDevice`, `Server`). `trustType` is deliberately not set, so runZero's own fingerprinting still wins where it has evidence. `superType` and `category` are kept as attributes.
- **Interfaces come from `directNetworkInterfaces`, which pairs each MAC with its own addresses.** The flat `directIps`/`directMacs` lists cannot express that pairing, so with two MACs and three addresses they can only hang every address on the first MAC. They remain the fallback for the minimal document and for a console that returns an empty interface connection, preferring `directIps`/`directMacs` and falling back to `ips`/`macs` when the direct list is empty, which is not hypothetical: a recorded sample carries `directMacs: []` with the real MAC only in `macs`. In that fallback each remaining MAC becomes an address-less interface rather than being dropped. The **direct** connection is used deliberately: `NetworkInterface` carries `directAsset`, so the associated `networkInterfaces` connection includes interfaces belonging to a sibling backplane module or to a fronting gateway, the same over-association `directIps` exists to avoid. Loopback, unspecified, and link-local addresses are filtered with `routable_ips`; an APIPA address a device invents when DHCP fails identifies nothing and would correlate unrelated hosts.
- **Vulnerabilities come from the `plugins` connection nested inside the same asset query.** The documented join key is `Asset.id` on both sides, and the vendor exposes the relationship in both directions: `plugins { nodes { ... } }` under an asset, and a top-level `plugins` query whose nodes carry `affectedAssets { nodes { id } }`. Nesting is used because it joins on `Asset.id` implicitly and avoids a second pagination loop. `severity` drives the severity and risk ranks, `vprScore` becomes the risk score when present, and `details.description` becomes the description with the operator `comment` behind it. Up to 99 findings are attached per asset, and the connection is sorted `{field: severity, direction: DescNullLast}` server-side and again client-side on severity then CVSS, so the cap keeps the findings worth keeping rather than whichever ones the console listed first.
- **CVEs, CVSS, and remediation text come from `Plugin.details`.** `Plugin` publishes `cvss3Score: Float` and `details: PluginDetails!` (non-null), and `PluginDetails` publishes `cves`, `cpes`, `description`, `solution`, `cvssV3BaseScore` and `cvssBaseScore`; pyTenable's `PLUGINS_DETAILS_QUERY` selects the same block. `severityScore` is the first real base score of `cvss3Score`, `cvssV3BaseScore`, `cvssBaseScore`; only a plugin publishing none of them falls back to a severity-derived stand-in, and `tenable_ot_security_plugin_max_cvss` on the asset reports the highest **published** score so the two are never confused. The CVE is the first entry of `details.cves` that is publishable, with a plugin whose entire name *is* a CVE kept as the fallback. `Vulnerability.cve` is validated against `^CVE-[0-9]{4}-[0-9]{4,19}$` and is not upper-cased by the platform, and a malformed value fails the whole record rather than the field, so every candidate is upper-cased and regex-checked before it is assigned. **A finding with no CVE is still imported.** Most OT plugins are configuration and protocol checks that have none, and dropping them would hide the findings the product exists to report. Because a vulnerability's own fields are not searchable from the asset, the CVEs are also rolled up into `tenable_ot_security_plugin_cves`.
- **Software is Windows hotfixes only.** `osDetails.hotFixes` is the only installed-software inventory in the asset schema; there is no general package list. Each hotfix becomes a `Software` record keyed on its own name, with `installDate` as the install timestamp. Up to 99 per asset.
- **Services are open ports, and they are opt-in.** The path is `Asset.directNetworkInterfaces` -> `NetworkInterface.ips` -> `IpDetails.openPorts` -> `IPOpenPorts.ports` -> `OpenPorts { port scanTime source name description }`. Because the ports hang off one `IpDetails` rather than off the asset, every service lands on the address the console actually saw it on. `OpenPorts` publishes no transport, so `tcp` is assumed and the assumption is recorded as `tenable_ot_security_transport_source: assumed` rather than presented as reported fact; the protocol name and description, the discovery source, and the scan time are kept as attributes. Ports outside 1-65535 are dropped, a port repeated on one address is deduplicated, and a port on a non-routable address never becomes a service. Up to 99 per asset. This is off by default because it is the deepest selection in the document.
- **The Go zero time is treated as "never".** Optional `Time` fields arrive as `0001-01-01T00:00:00Z` rather than `null` (`runStatusTime` does this on almost every asset), so every timestamp is rejected unless it parses to a positive Unix time. Without that guard a year-1 first-seen date would be stamped on the estate. All parsing goes through `parse_ts`, which also clamps a future value to now rather than aborting the run.
- Pagination: Relay-style forward cursors. `first` requests the page size, the previous response's `pageInfo.endCursor` is passed as `after`, and the walk **terminates when `pageInfo.hasNextPage` is false**, the explicit condition in Elastic's CEL program (`"want_more": body.data.assets.pageInfo.hasNextPage`). A missing or repeated cursor also ends the walk, so a console that reported `hasNextPage` forever could not spin. pyTenable's own iterator uses the weaker variant of reading only `endCursor`; the `hasNextPage` form is preferred here.
- Filtering: with no lookback, the request carries pyTenable's default `{"op": "Equal", "field": "hidden", "values": "false"}`. With a lookback, it carries Elastic's `Or` over `lastUpdate` and `firstSeen`. With both, the two are combined into a single `And` wrapping the hidden equality and that `Or`. `ExprOp` publishes `And` alongside `Or`, and `AssetExpressionsParams` documents `expressions: [AssetExpressionsParams!]` as "List of expressions, Must be applied when using [And/Or] operators", so both filters stay server-side rather than the console assembling and transferring every suppressed asset in the window for the script to discard on arrival. Hidden assets are still dropped client-side as a guard, which is why `hidden` is always selected. Sorting is always `{"field": "id", "direction": "DescNullLast"}`, pyTenable's default: sorting on the immutable id keeps a cursor walk stable while assets are being updated underneath it.
- Rate limiting: Tenable publishes no rate limit for this API, and the appliance is on-premise so the Vulnerability Management limits do not govern it. The schema does expose `slowCount` and `countTimeout` on `assets`, which implies the console self-protects against expensive counts; neither is requested here, and no total is asked for. Requests use the shared HTTP helper's default retry budget, which absorbs 408/425/429 and 5xx with exponential backoff and honors `Retry-After`.
- **Classification tags drop the "not set" sentinels.** `PurdueLevel` is `{ UnknownLevel Level0..Level4 }` and `Criticality` is `{ NoneCriticality LowCriticality MediumCriticality HighCriticality }`. `UnknownLevel` and `NoneCriticality` say only that nobody has classified the asset, so tagging them would give every unclassified asset on the console the same tag and narrow nothing, so they are filtered out exactly as `runStatus: Unknown` already was. The raw values stay as attributes.
- **Unverified assumptions, all handled defensively.** (1) The extended field selection (`vendor`, `model`, `serial`, `family`, `location`, `slot`, `firmwareVersion`, `os`, `description`, `backplane`, `osDetails`, `customField1..10`, `directNetworkInterfaces`, and `plugins`) comes from pyTenable's `ASSETS_QUERY` rather than from a captured console response. GraphQL validates the whole document, so a release that does not publish one of those fields would reject the entire query and return nothing. The script therefore falls back **once** to the narrower field set Elastic's shipping integration uses, which is the one selection confirmed against a real console, and logs that it did so. If you see `the console rejected the extended field selection` in the task log, the hardware detail on that console is coming from a smaller field set than this integration would prefer; the GraphiQL playground will say which field is missing. (2) `risk.totalRisk` arrives as a **string**, not a number, so it is preserved verbatim as an attribute rather than coerced. (3) Whether an asset merge in the console rewrites or retires an id could not be verified. (4) Whether ids remain unique across consoles aggregated by an Enterprise Manager could not be verified; the console hostname is part of the runZero id either way.
- Severity mapping: the enum **is** published (`enum PluginSeverity { Info Low Medium High Critical }`) and is matched case-insensitively with a trailing `Severity` stripped, which also covers the suffixed spelling the sibling `Criticality` enum uses (`MediumCriticality`). An unrecognized value ranks 0 rather than failing the record.
- This integration was validated against local fixtures built from Elastic's real redacted samples, not against a live Tenable OT Security console.

## Future

- **Reconciling deletions.** `deletedAssets(since: Time)` is documented as "Assets that were deleted from the system" and is exactly the signal a console-side merge or decommission produces. Custom integrations import rather than retire, but a companion outbound or internal script could mark the matching runZero assets, which is the cleanest available answer to the unverified merge behavior above.
- **Lookup rather than full inventory.** `asset(id: ID!)` and `assetByEndpoint(ip: String, mac: String)` fetch a single asset. An enrichment-style integration could resolve addresses runZero already found on an OT segment without pulling the whole console, which matters on a large site where the full walk is expensive.
- **Hidden-asset reporting.** `hiddenAssets` is a separate top-level query. Today this integration reaches hidden assets through the `include_hidden` toggle on the main query; importing them as a labelled population with its own `assetType` would let an operator see suppressed-in-Tenable assets as a distinct category in runZero.
- **Segment and Purdue-level coverage analysis.** `segments` already lands as tags and attributes, and the segment nodes carry `vlan` and `subnet`. Comparing runZero's own view of those subnets against the console's would identify OT segments where one product has visibility and the other does not, attributed to a named segment and Purdue level.
- **Exploitability from `PluginDetails`.** The block already selected carries more than this integration uses: `exploitAvailable`, `exploitedByMalware`, `exploitCodeMaturity`, `cisaKnownExploitedDates`, `vulnPubDate`, `stigSeverity`, and the `cvssV3Vector`. Those are what separate a theoretically severe finding from one being exploited on an OT network today, and they cost nothing extra to fetch; the question is only which of them belong on a runZero `Vulnerability` and which are noise.
- **Plugin-first ingest.** The top-level `plugins` query returns nodes carrying `affectedAssets { nodes { id name } }`. For a console where most assets carry no findings, walking plugins and joining back on `Asset.id` would move much less data than selecting `plugins` on every asset: the same join key, taken from the other end.

## API documentation

- OT Security integrations overview (the single `/graphql` endpoint): https://developer.tenable.com/docs/ot-integrations
- Generating an API key (365-day maximum expiry, shown once, inherits the creating user's role): https://developer.tenable.com/docs/ot-generate-an-api-key
- GraphiQL playground and the `X-APIKeys` header block: https://developer.tenable.com/docs/ot-graphiql-playground
- Query reference (`assets`, `asset`, `assetByEndpoint`, `hiddenAssets`, `deletedAssets`): https://docs.tenable.com/OT-security/api/query.doc.html
- Asset object reference (`id: ID!`, `ips`, `macs`, `directIps`, `directMacs`, `directNetworkInterfaces`, `lastSeen`/`lastHit`/`lastUpdate`, `criticality`, `risk`, `segments`, `revisions`): https://docs.tenable.com/OT-security/api/asset.doc.html
- Plugin object reference (`cvss3Score: Float`, `details: PluginDetails!`): https://docs.tenable.com/OT-security/api/plugin.doc.html
- PluginDetails object reference (`cves`, `cpes`, `description`, `solution`, `cvssV3BaseScore`, `cvssBaseScore`, `vulnPubDate`, `exploitAvailable`, `cisaKnownExploitedDates`): https://docs.tenable.com/OT-security/api/plugindetails.doc.html
- Severity enum (`Info Low Medium High Critical`): https://docs.tenable.com/OT-security/api/pluginseverity.doc.html
- Classification enums: https://docs.tenable.com/OT-security/api/purduelevel.doc.html and https://docs.tenable.com/OT-security/api/criticality.doc.html
- Interface, address, and open-port objects (`NetworkInterface.dnsNames`/`ips`, `IpDetails.ip`/`dnsNames`/`openPorts`, `IPOpenPorts.ports`, `OpenPorts.port`/`scanTime`/`source`/`name`/`description`): https://docs.tenable.com/OT-security/api/networkinterface.doc.html, https://docs.tenable.com/OT-security/api/ipdetails.doc.html, https://docs.tenable.com/OT-security/api/ipopenports.doc.html, https://docs.tenable.com/OT-security/api/openports.doc.html
- Filter expression reference (`ExprOp` including `And`/`Or`, and `AssetExpressionsParams.expressions`): https://docs.tenable.com/OT-security/api/exprop.doc.html and https://docs.tenable.com/OT-security/api/assetexpressionsparams.doc.html
- Sort reference (`PluginField` including `severity` and `cvss3Score`, `SortDirection`): https://docs.tenable.com/OT-security/api/pluginfield.doc.html and https://docs.tenable.com/OT-security/api/sortdirection.doc.html
- pyTenable's OT session and queries (the `X-APIKeys` header, `ASSETS_QUERY`, `PLUGINS_QUERY`, the default filter and sort): https://github.com/tenable/pyTenable/blob/master/tenable/ot/graphql/query.py
- Elastic's shipping `tenable_ot_security` package (the production query, the `hasNextPage` termination condition, the incremental filter, and the redacted sample responses these fixtures are built from): https://github.com/elastic/integrations/tree/main/packages/tenable_ot_security

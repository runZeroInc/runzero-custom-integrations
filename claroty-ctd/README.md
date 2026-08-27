# Custom Integration: Claroty CTD

Claroty Continuous Threat Detection (CTD) is the on-premise OT/ICS monitoring
appliance that builds a passive asset inventory from industrial network traffic.
The Enterprise Management Console (EMC) aggregates many CTD appliances into one
console. This integration imports that inventory into runZero through the
appliance's `/ranger/` REST API.

This is **not** Claroty xDome (the Medigate-derived cloud product). xDome is a
different API on a different host and needs its own integration.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the CTD or EMC appliance. These are internal
  appliances, so the integration normally runs from an on-premise Explorer rather
  than a hosted scanner.

## Claroty CTD requirements

- A CTD appliance, or preferably an **EMC**. Claroty's own guidance to integrators
  is to point at the EMC rather than at each CTD, because the EMC returns the union
  across every site it aggregates while a single CTD returns only its own site.
- A CTD or EMC user account with the **Visibility** and **Risk and Vulnerabilities**
  RBAC permissions. Those two are what Qualys documents as the minimum for reading
  the asset and vulnerability tables; an account without the second one can still
  import assets but will fail the vulnerability walk.
- The appliance's base URL. Modern deployments answer plain HTTPS on 443. Older
  ones answer on **5000**, so include the port when that applies
  (`https://ctd.example.com:5000`).
- **These appliances normally present a self-signed certificate.** Every published
  client for this API disables certificate validation by default. Set the
  **Disable TLS validation** option on the credential (`tls_disable_validation`)
  unless the appliance has been given a certificate the Explorer trusts.

## Steps

### Claroty CTD configuration

1. In the CTD or EMC console, create (or pick) a user account for runZero and give
   it the **Visibility** and **Risk and Vulnerabilities** permissions. No API key
   or token has to be minted: the integration logs in with the username and
   password and the appliance returns a JWT.
2. Confirm the account can reach the API. Note the header on the second call:
   Claroty takes the **raw token with no `Bearer` prefix**, which is unusual and is
   the single most common way to get this API wrong:

   ```bash
   TOKEN=$(curl -sk -X POST https://ctd.example.com/auth/authenticate \
     -H 'Content-Type: application/json' \
     -d '{"username":"runzero","password":"<password>"}' | jq -r .token)

   curl -sk -H "Authorization: $TOKEN" \
     'https://ctd.example.com/ranger/assets?page=1&per_page=5&ghost__exact=false'
   ```

   A successful response is the envelope
   `{"count_filtered": N, "count_in_page": N, "count_total": N, "objects": [...]}`.
3. If the login returns a 200 whose body contains `"password_expired": true`, the
   account's password has to be rotated in the console before the API returns any
   data at all. The integration detects that case and says so rather than reporting
   an opaque authentication failure.
4. The appliance hosts its own Swagger reference at `https://<host>/ranger/apidocs`
   (the "API Explorer"). Access to it is gated on a separate API Explorer
   permission, and it is the authoritative reference for this API; there is no
   public one.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Claroty CTD").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Claroty CTD or EMC URL** (`url`): the appliance base URL, for example
     `https://ctd.example.com`. Include the port if it is not 443.
   - **Username** (`username`): the CTD or EMC account.
   - **Password** (`password`): that account's password.
   - **Import CVE findings** (`include_vulnerabilities`): optional; default on.
     Turn it off to skip the extra walk of the vulnerability join table.
   - **Lookback window (days)** (`last_updated_days`): optional; default 0, meaning
     import the whole inventory. A positive value sends `last_updated__gt` and
     imports only records the appliance changed inside that window. Note the
     interaction with `children[]` described under **Notes**: an incremental run
     does not refresh a backplane card whose own record did not change, so keep a
     periodic full run scheduled alongside it.
   - **Disable TLS validation** (`tls_disable_validation`): usually required, see above.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm an account and see what the appliance returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename claroty-ctd/claroty-ctd.star \
  --kwargs url=https://ctd.example.com \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs include_vulnerabilities=true \
  --kwargs last_updated_days=0 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./claroty-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run (the scanner refuses an existing `--output` directory
otherwise). Add `--verbose` for the request-by-request log. Omit `--output` to see
only the log lines.

For a fast smoke test against a large EMC, set a short lookback so the walk only
covers recently changed records:

```bash
runzero script --filename claroty-ctd/claroty-ctd.star \
  --kwargs url=https://emc.example.com \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs last_updated_days=1 \
  --kwargs include_vulnerabilities=false \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./claroty-recent --overwrite
```

`--kwargs` hands the value to the script verbatim, commas included, as long as the
pair contains a single `=`. Only a value carrying a *second* `=` as well as a
comma is re-read as CSV: it is cut off at the comma, with the remainder becoming a
second, fabricated parameter rather than rejected. A password is opaque, so wrap
it in double quotes if it is that shape: `--kwargs '"password=a=b,c"'`, doubling
any double quote inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live appliance:

```bash
runzero script --filename claroty-ctd/claroty-ctd.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the appliance accepts the account or that
any asset is parsed.

The fixtures under `claroty-ctd/tests/fixtures/` exercise the parsing offline,
including the paging, re-authentication, rate-limit, malformed-record, and
identity-stability cases:

```bash
python3 tests/run.py claroty-ctd
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat claroty-ctd/claroty-ctd.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://ctd.example.com,username=runzero,password=<password>' \
  --output ./claroty-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so no value containing a comma at all can be passed
this way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Claroty CTD.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:claroty-ctd`.

## Asset identity

- Target entity: physical and virtual OT, IoT, and IT devices observed on the
  industrial network by CTD, including PLC backplane cards that exist only as a
  slot address on a chassis.
- Source ID field: `objects[].resource_id`
- Documentation evidence: Claroty's own vendor-facing integration contract (the
  XSOAR pack's `Claroty.yml`) documents the output field as *"The asset RID
  (AssetID-SiteID)"*, and the single-asset route is `GET /ranger/assets/{resource_id}`,
  so it is the API's own addressable key. Ivanti's connector guide independently
  describes the resource ID as formatted "asset-id-instance". The construction is
  confirmed against recorded responses: an asset with `"id": 15, "site_id": 1` has
  `"resource_id": "15-1"`, and `resource_id == "<id>-<site_id>"` held for all ten
  raw asset objects in Elastic's recorded corpus.
- Uniqueness scope: unique within one CTD or EMC deployment, across every site
  that deployment aggregates. **It is not globally unique.** Two separate customer
  deployments both contain a `resource_id` of `15-1`, so the appliance is the scope
  that has to be namespaced.
- Cardinality: one top-level `objects[]` row per asset. Child assets appear inside
  a parent's `children[]` array *as well as* being returned as their own top-level
  row, so the walk deliberately never recurses into `children[]`; see Notes.
  Vulnerability matches are many-to-one children keyed on the asset and are
  attached to the asset rather than emitted as separate assets.
- Stability: survives rename, reboot, VLAN change, and IP or MAC change. Nothing
  address-derived or name-derived feeds into the value. The direct evidence for the
  readdress case is the `old_ips` field: CTD appends a previously observed address
  to the *same* record rather than forking a new one. `first_seen` persists
  separately from `last_seen`, which only makes sense if records survive
  observation gaps.
- Reuse behavior: **not documented, assumed possible.** `id` is a small monotonic
  integer, which is the signature of a database sequence, and nothing published
  says whether CTD reassigns an id after an asset is deleted. `first_seen` is
  imported as a custom attribute so a recycled id can at least be detected after
  the fact; see the open assumptions in Notes.
- Presence: present and well-formed on 100% of the recorded asset objects, and the
  reference XSOAR client force-appends `resource_id` to every projection, treating
  it as mandatory. One caveat is handled in code: because `fields` is a server-side
  projection, `resource_id` is only guaranteed present when `fields` is not sent,
  which is why this integration never sends it.
- Final runZero ID: `claroty-ctd:<appliance-hostname>:<resource_id>`, for example
  `claroty-ctd:emc.example.com:68-1`. The namespace is the **hostname alone with
  any port stripped**, taken from the configured URL. A port is a deployment detail
  and moving the appliance behind a reverse proxy would otherwise re-key every asset
  in the estate.
- Missing-ID behavior: skip. A row with no `resource_id` is logged as
  `skipping asset with no resource_id: id=<id>` and dropped. The bare numeric `id`
  is **not** used as a fallback, because it is site-scoped and every site has an
  asset `id` of 1. No random or synthesized ID is ever generated.
- Match behavior (set once in `CONFIG`): `no-name-break`. Default ID matching is kept,
  because `resource_id` is a database primary key with a genuine one-to-one
  relationship to the asset. `name-break` is relaxed: CTD learns names passively from
  OT protocol traffic, so the label it holds for a host routinely disagrees with the
  FQDN an authoritative scan of the same box recorded. That disagreement lands on
  *first contact*, the only moment a break flag acts, where it would fork one device
  into two assets that can never be reconciled. **`mac-break` and `ip-break` are
  deliberately kept on.** An EMC aggregates many sites whose private address plans
  overlap (that overlap is exactly why `resource_id` embeds `site_id`), and OT hosts
  reached through a router or a serial gateway present the gateway's MAC rather than
  their own. Those two breaks are the only thing separating such devices before the
  foreign id has matched. This matches the conclusion `forescout-eyeinspect` reached
  for the same class of source.
- Verdict: **scoped authoritative.** The value is a stable, one-per-asset vendor
  primary key that is unique within one deployment and is namespaced on the
  appliance host to make it unique across deployments.

### Notes

- **Assets** come from `GET /ranger/assets`, paged with `page` and `per_page` (500 per
  page) and streamed to runZero one record at a time. `hostname`, `display_name`, and
  `name` are offered as hostnames but all three are screened, which rejects both the
  address strings CTD falls back to when it never learned a real name (`10.1.34.32`,
  `10.1.30.1:Card 2 \ Addr 255`) and the DNS-shaped names shared across many assets
  (`SCADA-SERVER`, `Windows7`). `ipv4`/`ipv6` and `mac` become the network interfaces;
  `vendor` becomes the manufacturer; `model` the model; `os` the OS and
  `os_build`/`os_revision` the OS version; `asset_type__` the device type with its
  leading `e` stripped (`ePLC` becomes `PLC`), falling back to the published 0-86
  `asset_type` integer table when a response projects the integer without its paired
  label; `domain_workgroup` the domain; `first_seen` and `last_seen` become
  `firstSeenTS` and `lastSeenTS`.
- **`children[]` is never walked**, which is the single most important decision in this
  integration. A CTD asset can carry a `children` array holding *complete nested asset
  objects* (a chassis lists its backplane cards) and each of those children is **also
  returned as its own top-level row** in `objects[]`, so recursing would import every
  card twice. Only `children[].resource_id` is kept, as the
  `claroty_ctd_children_resource_ids` relationship attribute. The `happy` fixture is
  the regression lock: `68-1` carries `33-1` as a full nested child while `33-1` is
  also a top-level row, and the run must emit four assets rather than five.
- **A lookback window and `children[]` interact.** Not recursing into `children[]` is
  only lossless while the walk sees every row, which is true of a full run and not of
  an incremental one. With **Lookback window (days)** set, a chassis whose record
  changed inside the window arrives, but a backplane card whose own record did not
  change is excluded from the top-level query and, because the walk never recurses, is
  not refreshed on this run. It is not lost: it stays at the state the last full run
  left it in, and the parent's `claroty_ctd_children_resource_ids` still names it.
  Schedule a periodic lookback-free run alongside the incremental one, which is worth
  doing anyway, since a quiet OT segment and a broken credential look identical through
  a lookback window.
- **The `fields` projection is never sent.** Its delimiter is the literal
  three-character sequence `,;$` rather than a comma, and omitting the parameter
  entirely both avoids that trap and guarantees `resource_id` is on every row. This
  is what Elastic's shipping CTD integration does.
- **Ghosts and pseudo-assets are excluded.** The asset query sends
  `ghost__exact=false`; a ghost is a placeholder CTD invents for an address it inferred
  but never confirmed, and it can shadow the real asset. Rows whose `special_hint` is
  not 0 (broadcast, multicast, out of scope, external) are dropped client-side, as is
  any ghost the server-side filter let through, so a build that ignores the filter
  cannot leak pseudo-assets into the inventory. `valid__exact` and `approved__exact`
  are **deliberately not applied**, even though the reference clients default to them:
  on a deployment that does not use the approval workflow they would silently drop most
  of the inventory. `valid`, `approved`, and `ghost` are imported as attributes so an
  operator can filter on them in runZero instead.
- **Vulnerabilities** come from `GET /ranger/asset-vulnerabilities` with
  `relevance__exact=1`, which restricts the walk to *confirmed* CVE matches rather than
  the vendor/model-inferred "potentially relevant" ones. The whole join table is walked
  once and indexed by asset rather than one request per asset. `cve_id` becomes the
  CVE, `description` the description, `detection_date` the first-detected timestamp,
  and `actively_exploited` sets `exploitable`. Up to 99 findings are attached per
  asset. Set `include_vulnerabilities` to false to skip the walk entirely.
- **`cvss_v3_score` and `epss_score` are objects, not scalars.** Both are documented as
  `{value, label}` / `{value}`, and reading them as numbers is the obvious way to get
  zero severity on every finding. The score drives `cvss3BaseScore` and the
  severity/risk ranks; the CVSS band label is the fallback when no numeric value is
  present. A build that sends a bare number for either is still parsed, which the
  `malformed` fixture covers.
- **`Vulnerability.cve` is validated by the platform and a malformed value fails the
  whole record**, so `cve_id` is upper-cased and checked against
  `^CVE-[0-9]{4}-[0-9]{4,19}$` before it is assigned. A value that misses the shape
  is carried as the finding's name and as the `claroty_ctd_cve_id` attribute instead.
- **No services are produced.** CTD publishes a `protocol` list naming the protocols
  it observed (`CIP`, `ENIP`, `PCCC`, `TCP`) but never the ports they ran on, so
  there is no shape from which a `Service` could honestly be built. The protocol
  names are imported as `protocol:` tags and as an attribute. The `Open Ports`
  insight name is likewise a flag, not a port list.
- **One Software record per asset**, carrying the firmware. `model` becomes the
  product, `vendor` the vendor, and `firmware` the version; nothing is emitted when
  CTD determined none of the three, which is normal for passively observed IT
  endpoints. `cpe23` is deliberately unset: CTD publishes no CPE, and
  `Software.cpe23` only accepts the CPE 2.2 `cpe:/a:` binding.
- **Address-less assets are imported on purpose.** A PLC backplane card is addressed
  by slot (`address: ["10.1.30.1:Card 2 \ Addr 255"]`) and has no IPv4 and no MAC. Such
  an asset can never merge with anything runZero discovers, but it reconciles against
  itself poll to poll on its foreign id and carries vendor, model, firmware, serial,
  and PLC project detail nothing else in an estate can supply. The `happy` and `paged`
  fixtures skip the `has_correlator` invariant for that one record and say why.
- **OT context is imported as both tags and attributes**: `class:OT`/`IT`/`IoT`,
  `type:PLC`, `purdue-level:1.5` (fractional Purdue levels are valid),
  `zone:<virtual zone>`, `criticality:High`, `risk:Critical`, `site:<site name>`,
  `protocol:<name>`, and `insight:<insight name>`. Tags are capped at 40 per asset.
  `plc_slots` (per-card vendor, product, order number, firmware, serial),
  `project_parsed` (the parsed PLC project), `custom_informations`, and
  `custom_attributes` are flattened into `claroty_ctd_`-prefixed attributes, since
  none of them survives a plain list join.
- **`class_type` is a string in responses and an integer in filters.** Responses
  carry `"OT"`/`"IT"`/`"IoT"`, while `class_type__exact` takes 0/1/2. Both are
  accepted. The same asymmetry applies to `asset_type`, `criticality`, `risk_level`,
  and `special_hint`, which each ship a paired `__`-suffixed label; the label is
  preferred and a local integer table is the fallback. `asset_type` matters most,
  because it drives `deviceType` and its table runs 0-86: a projection that returns the
  integer without `asset_type__` would otherwise leave every asset untyped. The table
  stores labels already stripped of their `e` prefix, so the integer path and the label
  path produce the same value.
- Pagination: `page` (1-based) and `per_page`, over the
  `{count_total, count_filtered, count_in_page, objects}` envelope, in three tiers.
  **A full page always earns another request**, whatever the counts say, because
  trusting a count over a visibly full page is the one mistake that truncates an import
  silently. **On a short page the count decides, and the count used is
  `count_filtered`**: every request carries a filter and `count_total` is the total
  *before* filters, so bounding on it over-runs the filtered set. `count_total` is the
  fallback when the filtered count is absent. **With neither count usable a short page
  ends the walk.** Keeping a count in play protects against an appliance that clamps
  `per_page`, where every page could legitimately come back short and stopping on that
  alone would end the import after one page without an error. An empty `objects` array
  ends the walk unconditionally. The `filtered-count` fixture is the regression lock,
  with `count_total: 500` against `count_filtered: 2`.
- Authentication: `POST /auth/authenticate` with `{username, password}` returns a
  JWT in `token`, sent back as `Authorization: <token>` with **no `Bearer` prefix**.
  A 401 mid-run is treated as an aged-out session rather than a bad credential: the
  integration authenticates again and retries the failed request exactly once. The
  HTTP options are rebuilt around the new token rather than mutated, because
  `get_http_options` snapshots the header map. A 200 carrying
  `"password_expired": true` is reported as an expired password.
- Rate limiting: requests are issued with `retries=3`, so the shared HTTP helper
  absorbs 429 and 5xx responses with exponential backoff and honors `Retry-After`.
  No rate limit is documented for this API and no reviewed client handles one, but
  the appliance is customer-owned hardware whose CPU is the real constraint, so a
  429 or 503 under load has to be survivable rather than fatal.
- **This integration was validated against local fixtures, not a live Claroty
  appliance.** No public vendor API reference could be reached: the Swagger spec lives
  on the appliance at `/ranger/apidocs` and the Web API User Guide is behind Claroty's
  support portal, so the contract implemented here is reconstructed from
  Claroty-authored scripts and four independent shipping third-party clients. The
  following are **explicit assumptions that a live appliance should confirm**:
  1. **Token lifetime is unknown.** Only the facts that tokens expire and that 401
     is the signal are confirmed. Handled defensively by re-authenticating once on
     a 401 and retrying.
  2. **Rate limits are unknown and undocumented.** Assumed absent or generous
     because this is a single-tenant on-premise appliance. Handled defensively with
     the standard retry budget.
  3. **Multi-site behaviour is structurally certain but never empirically
     observed.** Every reachable fixture and script uses `site_id: 1`. The argument
     that `resource_id` is unique across the sites an EMC aggregates rests on the
     documented `AssetID-SiteID` construction rather than on an observed cross-site
     response. This is the single most valuable thing to confirm against a real EMC.
  4. **ID recycling after deletion is unknown.** Assumed possible; `first_seen` is
     imported so a recycled id can be spotted.
  5. **The `per_page` server maximum is unknown.** 500 is used because it is what
     Claroty's own scripts and Elastic's integration send; the observed range across
     five clients is 10 to 5000. A lower server-side clamp cannot truncate the import,
     for the reason given under Pagination above.
  6. **The `asset_id` column on `/ranger/asset-vulnerabilities` is ambiguous.** One
     Claroty-adjacent client passes the `"<id>-<site_id>"` form and another describes
     it as the plain numeric id, so every row is canonicalised to the resource-id form
     at index time using the row's own `site_id`. Matching both spellings at lookup
     would over-join on an EMC, crediting asset 30 at site 1 with the findings of
     asset 30 at site 2. A row carrying neither a site nor a compound id is claimed by
     the first matching asset and removed from the index, so it joins at most once.
  7. **`GET /ranger/assets/{resource_id}/risks` was never sampled.** It is
     documented by one third-party connector only, and may be a cleaner per-asset
     vulnerability call than the join table.

## Future

- **Site enumeration and training-mode reporting.** `GET /ranger/sites?format=site_list_slim`
  returns the site list, and each site carries a `training_mode` boolean; when true the
  appliance is still learning and its behavioural detection is inactive. Importing the
  site table would make the site name attribute a real scope and surface which sites
  are not yet detecting anything.
- **Alerts as an event feed.** `GET /ranger/alerts` returns policy and protocol alerts
  with an `actionable_assets[]` array that embeds a copy of each affected asset,
  already keyed on `resource_id`. That is an event stream rather than a property of a
  device, which is why it is not imported here. `POST /ranger/ranger_api/resolve_alerts`
  exists, so an outbound integration could resolve Claroty alerts from runZero.
- **Insights as findings.** `insight_names` is already imported as tags, and
  `GET /ranger/insights` plus `GET /ranger/insights/{insight_name}` expand each one
  into the assets that hit it. Several of the 33 known insight names (`End Of Life
  Assets`, `Unsupported OS`, `SMBv1 Negotiate`) are genuine findings that could become
  non-CVE `Vulnerability` records rather than tags.
- **Baselines.** `GET /ranger/baselines` returns CTD's learned communication baseline.
  Paired with runZero's own topology it would identify flows CTD considers normal,
  which is closer to a relationship import than an inventory one.
- **Topology enrichment.** `GET /ranger/networks`, `/ranger/subnets`, and
  `/ranger/virtual_zones` publish the definitions behind the `network_id`,
  `subnet_id`, and `virtual_zone_id` values already imported as attributes. Resolving
  them would turn those ids into names without a per-asset lookup.
- **Appliance health as an asset.** `GET /ranger/license`, `/ranger/system_health`, and
  `/ranger/current_version` describe the CTD appliance itself, which is a device
  runZero would otherwise only see from the outside.

## API documentation

There is **no public vendor API reference for CTD**. The authoritative one is the
Swagger API Explorer served by the appliance itself, and the vendor guide is behind
Claroty's support portal. The contract implemented here was reconstructed from the
sources below.

- On-appliance Swagger reference (the authority): `https://<host>/ranger/apidocs`
- Claroty, "Product Feature Spotlight: API Explorer" (confirms the Explorer exists on
  both CTD and EMC and supports per-site and global calls): https://claroty.com/blog/product-feature-spotlight-api-explorer
- Elastic's shipping Claroty CTD integration (the closest thing to a published
  polling contract, and the source for the `Authorization: <raw token>` header, the
  `last_updated__gt` cursor, and the `count_total` pagination logic):
  https://www.elastic.co/docs/reference/integrations/claroty_ctd
- Elastic's asset field inventory, including the nested `children`, `plc_slots`, and
  `project_parsed` groups: https://github.com/elastic/integrations/blob/main/packages/claroty_ctd/data_stream/asset/fields/fields.yml
- Cortex XSOAR Claroty pack (the source for the auth flow, the `,;$` fields
  delimiter, the `{field}__{lookup}` filter grammar, and the recorded response
  fixtures that confirm the envelope and `resource_id`):
  https://github.com/demisto/content/tree/master/Packs/Claroty/Integrations/Claroty
- FortiSOAR Claroty connector, the most complete public endpoint table
  (`/ranger/assets/{resource_id}`, `/ranger/assets/{resource_id}/risks`,
  `/ranger/insights`, `/ranger/events`): https://docs.fortinet.com/document/fortisoar/1.1.0/claroty/590/claroty-v1-1-0
- Qualys Claroty connector documentation (the RBAC requirement and `/ranger/apidocs`):
  https://docs.qualys.com/en/conn/latest/integrations/claroty.htm
- Ivanti Claroty CTD connector guide (independently describes the resource ID format
  and confirms IPv4/IPv6 are returned as lists): https://help.ivanti.com/iv/help/en_US/RS/vNow/Claroty-CTD-Connector-Guide.htm
- Vectra Claroty context integration (the guidance to integrate against EMC rather
  than each CTD): https://docs.fusion.vectra.ai/enrich-traffic-with-context/configure-context-integrations/claroty-context

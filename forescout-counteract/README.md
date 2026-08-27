# Custom Integration: Forescout CounterACT

Forescout CounterACT (marketed as **eyeSight** in the Forescout Continuum platform) is the
agentless network access control and device-profiling product. It runs on an Enterprise Manager
that fronts one or more Appliances, learns endpoints from the network infrastructure, and
classifies them with its own profiling engine. This integration talks to the **Web API plugin**
on the Enterprise Manager.

> **Not the same product as `forescout-eyeinspect`.** eyeInspect (formerly SilentDefense) is
> Forescout's passive OT/ICS deep-packet-inspection product: separate sensors, a separate
> Command Center, a separate `/api/v1/` REST API with HTTP Basic authentication, and an
> inventory of industrial hosts with Purdue levels and protocol alerts. CounterACT/eyeSight is
> the IT+OT NAC and classification product: an Enterprise Manager, an `/api/` Web API secured
> with a short-lived JWT, and an inventory of every endpoint on the corporate network. Most
> customers who own both should run both integrations; they cover different estates and neither
> is a superset of the other.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Forescout Enterprise Manager over HTTPS.

## Forescout CounterACT requirements

- A Forescout Enterprise Manager or standalone Appliance reachable over HTTPS.
- The **Open Integration Module** installed and enabled, with the **Web API** submodule enabled
  (`Tools > Options > Modules > Open Integration Module`). The Web API is a read-only module.
- A Web API user account, which is a separate credential from a console operator account.
- The Explorer's IP address added to the Web API **Client IPs** allow list. Requests from any
  other address are rejected, which surfaces as a 403 rather than a 401.

## Steps

### Forescout CounterACT configuration

1. In the CounterACT console, select `Tools > Options > Modules` and confirm the **Open
   Integration Module** and its **Web API** submodule are installed and enabled.
2. Select `Tools > Options > Web API > User Settings` and click `Add` to create a username and
   password for the integration.
3. Select `Client IPs` next to `User Settings` and add the address of the Explorer that will run
   this integration. Click `Apply`.
4. Confirm access from the Explorer host, for example
   `curl -k -d "username=<user>&password=<pass>" https://<enterprise-manager>/api/login`. A
   successful call returns a bare JWT as the response body.
5. If the Enterprise Manager uses a private certificate authority, either add the CA to the
   integration's TLS options or disable TLS validation on the credential.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Forescout CounterACT").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Enterprise Manager URL** (`url`): base URL of the Enterprise Manager, for example `https://enterprise-manager.example.com`.
   - **Web API username** (`username`): the Web API user created above.
   - **Web API password** (`password`): password for that user.
   - **Policy or rule IDs** (`match_rule_ids`): optional; comma-separated Forescout policy or sub-rule IDs. Only hosts selected by all of them are imported.
   - **Host property filter** (`host_filter`): optional; a host field filter in the Web API's own `field=value&field=value` format, for example `online=true`.
   - **Import classification, services, and software** (`include_details`): optional; default enabled. Requests host properties alongside each endpoint.
   - **Endpoints per page** (`page_size`): optional; default `1000`. Endpoints returned per paginated request. The Web API accepts 50 to 5000.
   - **Only import endpoints updated in the last N days** (`since_days`): optional; default `0` (the whole estate). Sends the paginated walk a `sinceTime`, so the Enterprise Manager answers only with endpoints updated since then.
   - **Detail enrichment limit (legacy path only)** (`detail_limit`): optional; default `1000`. Caps the one-request-per-host enrichment used only on a Web API plugin too old for the paginated endpoint. `0` removes the cap.
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
runzero script --filename forescout-counteract/forescout-counteract.star \
  --kwargs url=https://enterprise-manager.example.com \
  --kwargs username=runzero-webapi \
  --kwargs password='ExampleFakePassw0rd' \
  --kwargs host_filter='online=true' \
  --kwargs include_details=true \
  --kwargs page_size=500 \
  --kwargs since_days=7 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./forescout-counteract-run
```

Run this from the Explorer host, or from a host whose address you added to the Web API
**Client IPs** allow list -- the allow list is enforced per source address, so a
command-line run from a laptop is rejected with a 403 even when the credential is
correct.

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. Setting `since_days` on a first run keeps a smoke test to whatever the Enterprise
Manager has touched recently rather than the whole estate.

**One CLI caveat:** `--kwargs` takes the value verbatim as long as the whole argument
holds a single `=`, so `--kwargs match_rule_ids=101,102` arrives intact as `101,102`. A
value that *also* contains an `=` flips the flag into comma-separated parsing: the value
is cut at the first comma and the remainder either becomes a fabricated second parameter
or aborts the run with `must be formatted as key=value`. That is reachable through
`host_filter`, whose conditions are `key=value` pairs, and through a password. Wrap the
whole argument in a second pair of quotes when a value needs both characters:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

`host_filter` separates its conditions with `&` rather than a comma, so a plain filter
survives unquoted parsing -- but it still needs shell quoting, or the `&` backgrounds the
command.

To check the `CONFIG` block and the HTTP and TLS wiring without a live Enterprise
Manager:

```bash
runzero script --filename forescout-counteract/forescout-counteract.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove the Web API accepts the credential, that the Explorer's
address is on the Client IPs list, or that any host is parsed. The fixture scenarios are
what exercise the parsing:

```bash
python3 tests/run.py forescout-counteract
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat forescout-counteract/forescout-counteract.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://enterprise-manager.example.com,username=runzero-webapi,password=ExampleFakePassw0rd' \
  --output ./forescout-counteract-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so neither `match_rule_ids` nor a password containing
a comma can be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Forescout CounterACT.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:forescout-counteract`.

## Asset identity

- Target entity: a host object in the CounterACT host database, which is an endpoint the
  Enterprise Manager is tracking on the network.
- Source ID field: `hosts[].hostId` from `GET /api/hosts`, and `hosts[].id` from
  `POST /api/hosts/discovery`. **These are the same value and are normalised to one canonical
  form**, so the id an endpoint produces does not depend on which endpoint answered -- see
  "One id, two endpoints" below.
- Documentation evidence: the vendor guide is public. *eyeExtend Web API Plugin*
  v1.5.16/v1.5.17 is published at
  <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/>, and every claim in this
  section is quoted from it. The contract is corroborated by two
  independently written, shipped clients -- the Cortex XSOAR `Forescout` content pack and the
  Splunk SOAR `forescoutcounteract` connector -- and by a recorded live response published in
  the Netskope Cloud Exchange `forescout_ztre` plugin README.
  **The decisive evidence is what the samples show about the id.** The guide's own
  `GET /api/hosts` example pairs `"hostId": 170525084` with `"ip": "10.42.1.156"` -- exactly
  that address packed into a 32-bit integer -- and the same holds for its second row, for the
  recorded live response (`167838209` / `10.1.2.1`), and for all nine rows of the XSOAR pack's
  `forescout-get-hosts` output. The CounterACT object id is therefore an *encoding of the
  endpoint's address*, not an opaque, device-scoped object key.
- Uniqueness scope: one Enterprise Manager. The value is only as unique as the address space it
  encodes, so two Enterprise Managers covering overlapping RFC 1918 ranges will both mint
  `3232235820` for their own `192.168.1.44`. The scope is baked into the runZero id.
- Cardinality: one index row per host object. Because the id is address-derived, one physical
  device that is re-addressed becomes a *different* host object with a *different* id, and the
  same device can therefore appear under several ids over time.
- Stability: the id survives rename, re-profiling, reboot, agent install, and policy changes --   everything except a change of IPv4 address, which replaces it outright.
- Reuse behavior: reuse is not merely possible, it is guaranteed. When a DHCP lease moves, the
  next endpoint to hold the address is described by the same `hostId`. This is the property that
  disqualifies the id from driving merges.
- Presence: present on every sample row in both vendor clients. `mac` is frequently `null` and
  is sometimes the placeholder `000000000000`; `ip` is the only field the index always carries.
  Rows without a `hostId` are skipped.
- Final runZero ID: `forescout-counteract:<enterprise-manager-host>:<hostId>`, where the scope is
  the hostname parsed from the configured URL.
- Missing-ID behavior: skip the row with a log line naming only its IP. A host whose row carries
  an id but no routable IP, no usable MAC, and no hostname is also skipped, because with
  `no-id-match` such a record gives runZero nothing to correlate on.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. The default and the
  `no-mac-break no-ip-break no-name-break` preset were both considered and rejected. Letting an
  address-derived id drive matching would be actively harmful in two directions: a device that
  changes IP would fragment into a new runZero asset on every move, and -- worse -- a recycled
  address would assert that two unrelated devices are the same asset. Ignoring the id and
  merging on MAC, IP, and hostname is the correct model for this source, and it happens to be
  the right one on the merits as well: CounterACT's contribution to runZero is its classification
  of endpoints runZero already discovers, not a separate authoritative inventory. The id is still
  emitted, namespaced and deterministic, so re-polling the same object updates the same record.
- Verdict: derived / non-authoritative.

**One id, two endpoints.** The two walks name the host key differently, and the guide's sample
for the paginated endpoint cannot be read literally: it types `hosts[].id` with an `{EM.IP}`
placeholder, in a block that also prints two `"id"` keys inside one object. Since the integer
and the address are the same value, the key is canonicalised rather than trusted -- an all-digit
value passes through unchanged, a dotted-quad is packed into the integer the host index would
have returned, and anything else is screened and passed through identically on both paths.
**The foreign id is therefore byte-identical whichever walk produced it**, which is what keeps
an existing deployment from re-keying every asset when it moves onto the paginated endpoint or
falls back off it. The `id-stability-discovery` and `id-stability-legacy` fixtures serve the
same endpoint through both Web API endpoints and assert the same id literal; if that stops
being true, exactly one of them fails.

**What could not be confirmed.** No source publishes a host CounterACT tracks by MAC only (seen
at layer 2 but never addressed) or an IPv6-only host, so it is unknown whether those receive a
non-address-derived id from a different sequence. That does not change the decision:
`no-id-match no-id-break` is correct for a weak id and merely redundant for a strong one. It is
also why a non-numeric, non-address key is passed through rather than dropped.

### Notes

- **Assets come from `POST /api/hosts/discovery`**, the paginated endpoint the guide documents as
  "Retrieve Paginated Hosts and Other Properties". Properties are selected *inline*, in a JSON
  request body of the form `{"fields": [...]}`, and come back attached to each endpoint in the
  same response, so an estate costs one request per page rather than one per endpoint --   101 requests for a 100,000-endpoint Enterprise Manager against 100,001 for the legacy path.
  Paging is by `page` and `nodeId`, and the walk ends when a response carries no
  `metadata.next_link`. `match_rule_ids` and `host_filter` push selection server-side on the
  legacy path, and `since_days` does the equivalent on the paginated one.
- **Falling back degrades rather than fails, and which path ran is always logged.** A Web API
  plugin predating the paginated endpoint answers 404 (the guide's error table also shows this
  API answering 500 for conditions that are really request errors), so any failure of the
  *first* paginated request falls back to `GET /api/hosts` plus per-host properties. A failure
  *after* the first page does not: the endpoints already reported would simply be fetched again,
  and restarting a partial walk on the slower path against a 20-request-per-minute limit costs
  more than it recovers, so the partial result is kept and the failure logged with the page it
  stopped on. A paginated walk prints `imported N assets from the paginated endpoint over M
  request(s)`; a fallback prints `the paginated endpoint is unavailable (...)` first, or an
  operator cannot tell a slow legacy import from a fast paginated one.
- **`detail_limit` is consulted only by the legacy path.** It caps the per-host N+1, which
  happens only when the walk has fallen back, so it is labelled "legacy path only" rather
  than removed -- removing a declared parameter changes the credential form for every
  existing deployment. The paginated path selects properties inline and has nothing to cap.
  The `detail-cap` fixture pins the legacy behaviour.
- **A detail-disabled run is still useful.** The paginated response yields an id, IP, and MAC per
  endpoint even with an empty `fields` list, and those are precisely what runZero correlates on,
  so an unenriched run still tags every known endpoint and confirms NAC coverage.
- **Host properties are discovered, not hardcoded.** `GET /api/hostfields` enumerates every
  property the deployment exposes, and every installed plugin contributes its own, so no two
  deployments have the same property set. The index is fetched once at startup and intersected
  with what this integration can map, so the field list contains only advertised names. If
  `/api/hostfields` fails or names nothing mappable, properties are skipped rather than
  requested blindly.
- **The field list is capped at 50, and that cap is a protocol limit.** The guide states users
  can enter "up to 50 different fields" in the paginated request body, and a deployment can
  advertise several hundred properties, so the request is assembled in priority tiers -- identity
  first (hostnames, MACs, ports, domain), then freshness, then the discovered software and CVE
  properties, then classification, then everything else. Appending in list order would let the
  cap fall on whatever sorted last, taking the software and vulnerability properties -- the whole
  reason to enrich -- with it. A property that did not fit is also not read back, so the builders
  never walk a name that was never requested.
- **`hostname_calculated` leads the hostname list, and that matters more than it sounds.** The one
  recorded property document from a live deployment contains *none* of `hostname`, `nbthost`,
  `dhcp_hostname`, `linux_hostname`, or `mac_hostname`. What it carries is `hostname_calculated`
  (the name eyeSight resolved from whichever source won) and `otsm_details_host_name` (forwarded
  from eyeInspect), so a deployment shaped like that imports no hostname at all from the
  plugin-specific names. `segment_name_calculated` and `segment_path_calculated` are carried as
  custom attributes: a segment name is how an operator recognises where in a plant an OT endpoint
  sits.
- **A classification of "Unknown" is not imported as a classification.** The live document
  returns `os_classification` as `Unknown`, and writing that to `os` states something the
  classification engine explicitly did not conclude. `unknown`, `unclassified`, `n/a`, `none`,
  `-`, and `other` are treated as absent for OS, function, vendor, model, and manufacturer.
- **Classification is mapped as the product's primary output**, because profiling is what
  CounterACT is for:
  - `prim_classification` (Function) -> `deviceType`, and a `function:` tag. The value is a
    classification-tree path such as `Computer/Windows Machine/Desktop`, so the leaf segment is
    taken as the most specific answer and mapped onto runZero's device type vocabulary. A leaf
    with no mapping is passed through verbatim, so a deployment with a custom classification tree
    still gets a device type.
  - `os_classification` (Operating System) -> `os`, again taking the leaf of the tree path. No
    attempt is made to split an `osVersion` out of it.
  - `vendor_classification` (Vendor and Model) -> `manufacturer` from the root segment and `model`
    from the leaf, plus a `vendor-model:` tag. **Assumption:** the property is a tree path whose
    first level is the vendor and whose leaf is the model, which is what its label states. A
    deployment returning it flat, with no `/`, yields the manufacturer and no model, so a flat
    value cannot produce a wrong split.
  - `manufacturer_classification` / `model_classification` and eyeInspect's
    `otsm_details_manufacturer` / `otsm_details_model` are the fallbacks when the tree path is
    flat or absent -- the OT pair is often the only place a model like `Wireless I/O Card` is
    stated.
  - `mac_vendor_string` (NIC Vendor) is the last fallback manufacturer when there is no vendor
    classification at all.
  - `cl_type` becomes a `classified-by:` tag, so a search can separate endpoints classified by a
    policy from ones inferred from a DHCP fingerprint.
  - `online`, `onsite`, and `manage_agent` become the bare tags `online`, `onsite`, and
    `secureconnector`. Every asset also carries the constant `forescout-counteract` and `nac`
    tags, matching the way `forescout-eyeinspect` tags its hosts `ot`.
  - The remaining classification and state properties (`cl_rule`, `dhcp_class`, `dhcp_os`,
    `user_def_fp`, `fingerprint`, `matched_fingerprints`, `agent_version`, `switch_port_name`,
    and the rest) are preserved as `forescout_counteract_`-prefixed custom attributes.
- **Services** are built only from `openports`, which is the one property typed `port` in the
  vendor's field list. Its element shape is not published, so ints, `"445/tcp"`, `"137 (UDP)"`,
  and `{"port": ..., "protocol": ...}` dicts are all accepted; an entry that names no transport
  is recorded as `tcp` and flagged `forescout_counteract_transport_source=assumed`, matching the
  honesty flag `forescout-eyeinspect` uses. Port ranges such as `"10-20"` and out-of-range values
  are skipped rather than guessed at.
- **The `nmap_def_fp5`/`nmap_def_fp7` properties are deliberately not turned into services.**
  Their names suggest port data, but the vendor documents them as "Nmap-OS Fingerprint": OS
  fingerprint strings with no port in them. Synthesizing ports from a classification label would
  invent scan data runZero never observed, so they stay custom attributes. The same applies to
  `samba_open_ports`, a boolean-style indicator that NetBIOS ports are open, not a port list.
- **Software** comes from installed-application properties discovered by name from
  `/api/hostfields` (anything matching `application`, `installed_program`, `installed_software`,
  or `packages`), capped at eight. In practice these exist only for hosts CounterACT manages
  through SecureConnector or a remote inspection credential; an unmanaged endpoint yields none.
  The guide's composite example for Applications Installed names its sub-fields
  `app_name`, `app_version`, and `app_user`, so those are read first; other dict spellings
  (`name`/`product`, `version`, `vendor`) and plain strings are also accepted. **Assumption:**
  for a plain string, a trailing whitespace-delimited token starting with a digit is treated as
  the version (`"Notepad++ 8.6.4"` -> product `Notepad++`, version `8.6.4`); the original string
  is kept verbatim in `forescout_counteract_software_raw` so nothing is lost if the split is
  wrong. CounterACT publishes no CPE, so `Software.cpe23` is left unset rather than synthesized.
- **Vulnerabilities are opportunistic and deployment-dependent, and they are scored.** CounterACT
  itself is not a vulnerability scanner; CVE data exists only when a vulnerability assessment
  plugin or an eyeExtend connector has been installed and has written its findings into host
  properties. There is no fixed property name for this, so any property whose name contains `cve`
  or `vulnerab` is requested (capped at eight).

  These properties are *composite* -- the guide's term for a property whose value is a record with
  named sub-fields -- and the live document shows both of the ones a Forescout OT deployment
  produces carrying real scores. `otsm_details_cves` (forwarded from eyeInspect) writes
  `cve_id`, `cvss_score`, `cvss_temporal_score`, `title`, `icsa_id`, `matching_confidence`,
  `cvss_remediation_level`, and `suppressed`; `cysiv_risk_cve_list` (the risk plugin) writes the
  same facts under `cysiv_cve_`-prefixed names plus an exploitability level and percentile and a
  CISA KEV flag. All of it is read structurally, so a finding arrives with a base score, a
  temporal score where one is published, a title, a published date, and a derived rank.

  **The CVSS revision is inferred per record, because the records do not name one.** v2 scores
  the three impacts as `NONE`/`PARTIAL`/`COMPLETE` and carries Access Vector, Access Complexity,
  and Authentication sub-scores; v3 scores them as `NONE`/`LOW`/`HIGH`. The live document carries
  both forms inside one property, which is why this is decided per record, not per deployment.

  A property whose shape is not recognised still has its identifiers scraped out by pattern.
  Identifiers are upper-cased and matched against the anchored `^CVE-[0-9]{4}-[0-9]{4,19}$` form
  *before* being set, because `Vulnerability.cve` is validated and is not upper-cased for you --   a value that would fail rejects the whole record. A CVE the deployment has marked `suppressed`
  is skipped and counted, rather than re-raising a finding the operator closed.
- **Authentication is a JWT returned in the response body.** `POST /api/login` takes
  `username` and `password` as a form-encoded body and answers with the bare token as
  `text/plain` -- not JSON, and not a response header -- confirmed against both vendor clients.
  The token is then sent as `Authorization: <token>` with **no `Bearer` prefix**, again matching
  both. Because the body is not JSON, the login call uses the raw `http.post` builtin;
  `post_json` would try to decode a bare JWT as a document. The response is checked for the
  three-segment JWT shape before it is installed, so an HTML error page or a captive-portal
  redirect is never stored as a credential, and the token is never printed. Because `retries`
  is a parameter of `get_json`/`post_json` only and the raw builtins reject it, the login
  retries a 408/425/429/5xx or a missing response up to three more times by hand, each attempt
  logged, so one transient 503 at the first login does not end the run. Every other request
  goes through the JSON helpers and gets their built-in retry and backoff.
- **Token lifetime is short and is handled in both directions.** The default JWT validity is
  five minutes, which any walk of a real estate outlives -- at 20 requests per minute even a
  hundred-page run takes five minutes on its own. The token is refreshed proactively once it is
  four minutes old, and if the Enterprise Manager rejects it anyway the request is retried once
  after re-authenticating, on both walks (which re-authenticate through different functions and
  so have separate fixture coverage). A 401 on a *fresh* token, or a 403 from the Client IPs
  allow list, is a real authentication failure: it is reported and stops the run. A host whose
  detail call fails for any other reason is logged and treated as unenriched.
- **Pagination.** The paginated endpoint takes `page`, `pageSize` (the guide: "users can request
  from 50-5,000 endpoints"), `sinceTime`, and `nodeId`, and returns
  `{"metadata": {"next_link": ...}, "hosts": [...]}`. The walk starts at `nodeId=0` and follows
  `next_link` through all appliances as the guide recommends, so `GET /api/nodes/` is never
  needed. `pager()` guards it against `CONFIG["maxPages"]` (1000 -- a million endpoints at the
  default page size, and roughly what 20 requests per minute can move inside a task's wall clock).

  **`next_link` is read for its parameters, not dialled.** Only `page` and `nodeId` are taken
  from it and the request is rebuilt against the configured Enterprise Manager URL, because on
  a multi-appliance deployment `next_link` names the appliance holding the next node -- an
  address the Explorer may have no route to, no credential for, and no TLS trust in. Rebuilding
  also keeps the operator's own `pageSize` and `sinceTime` on every page rather than only the
  first. A `next_link` repeating a page and node already visited ends the walk cleanly: the
  documented terminator is the *absence* of a link, so an Enterprise Manager that keeps serving
  one would otherwise spin until `pager()` raised, reporting a finished import as incomplete
  after a thousand wasted requests.

  By contrast the legacy `GET /api/hosts` has no pagination at all: no offset, limit, page, or
  cursor, and the guide warns the response "may truncate" when an internal timeout is exceeded --   itself a good reason to prefer the paginated endpoint. Legacy assets are still built and
  streamed in chunks of 100 so the `ImportAsset` set never accumulates.
- **Incremental sync.** `sinceTime` is documented as "respond only with endpoints that have been
  updated after the provided UNIX timestamp", defaulting to 0. It is exposed as `since_days`, a
  window in days, because an epoch is not a thing an operator types; the epoch is computed from
  it at run time. `since_days=0` leaves the parameter off the request entirely. Note this is a
  filter on the source side only -- runZero is not told that an endpoint was excluded, so an
  incremental run updates what changed and leaves everything else at its previous state.
- **Rate limiting is documented and is not handled by hand.** The guide: "the transaction is
  limited to 20 requests per minute. Excess requests will generate a 429 error", and "the
  transaction allows one request at a time, per node ID". The JSON helpers already retry
  408/425/429/5xx with exponential backoff, honouring `Retry-After`. Lower `page_size` only if a
  large Enterprise Manager truncates a page; raising it is how to stay inside the limit.
- **ETag / `If-None-Match` is deliberately not implemented.** The guide documents it and the
  Netskope connector uses it against `/api/hosts`, so it is genuinely available. It is left out
  because it cannot be done safely here: `get_json`/`post_json` do not expose response headers,
  so reading an `ETag` means dropping to the raw builtins and hand-rolling the JSON decode,
  status handling, and `Retry-After` backoff the helpers provide. A 304 also carries no body, so
  a partial implementation that mistook one for an empty page would silently import nothing and
  look like a successful run. `since_days` achieves the same reduction with no such failure mode.
- **Loopback and placeholder addresses are filtered** out of network interfaces
  (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`), as is the all-zero MAC
  `000000000000` that appears in the vendor's own sample output, and the literal `"undefined"`
  the guide documents `ip` and `mac` as returning when the endpoint has neither. Each would
  otherwise be a shared merge signal capable of collapsing an entire estate onto one asset. The
  raw values are preserved as `forescout_counteract_index_ip`/`_index_mac`, and where the
  response carries no address at all, `ipv4_calculated` and `access_ip` are read as a fallback.
- **MACs are collected from every property that carries one** -- `macs`, `mac`, `mac_calculated`,
  and eyeInspect's `otsm_details_host_mac_addresses` -- because which of them a deployment
  publishes varies, and the live document carries three of the four.
- **Duplicate endpoints are collapsed.** The same host key appearing twice in one run is imported
  once, which on the legacy path also avoids spending a second detail request on it. The
  de-duplication is on the canonical key, so it holds across both walks.
- **`lastSeenTS` comes from the value wrapper's own timestamp first.** The guide states that
  every property value is returned wrapped as `{"timestamp": ..., "value": ...}` and that "the
  timestamp field indicates how recently the value was updated in eyeSight". That makes it a
  freshness signal that exists on *every* deployment, independent of which plugins are
  installed, which is why it leads. The preference order is

  1. the wrapper timestamp on a liveness property (`online`, `engine_seen_packet`) -- the property
     carries no date of its own, but the wrapper says when eyeSight last decided whether the
     endpoint was up, which is exactly last-seen;
  2. an explicitly date-typed property, where a plugin publishes one (`otsm_details_last_seen`,
     then `last_nbt_report_time`, then `ipv4_report_time`);
  3. the newest wrapper timestamp anywhere in the document, as an upper bound on when eyeSight
     last learned anything about the endpoint.

  Which one won is recorded in `forescout_counteract_last_seen_source`. A wrapper timestamp of
  `0` is discarded rather than read as 1970: the live document stamps every `in-group` value `0`,
  meaning never. `ipv4_report_time` is tried *last* among the date properties despite its name,
  because the live document returns it as `{"value": "true"}` -- a boolean -- while
  `last_nbt_report_time` alongside it carries a real epoch.

  **On serialization:** Appendix 1 types a Date property as "NUMBER type with Epoch Time in
  seconds, or DATE, DATETIME, TIMESTAMP". Seconds is the only numeric form documented and no
  deployment has been observed emitting milliseconds, but the millisecond width check is kept
  defensively: `parse_ts` returns `None` for an unqualified 13-digit value, so a deployment that
  did serialize them would get no timestamps at all. Two "never" sentinels are also rejected
  explicitly, because `parse_ts` does **not** return `None` for either -- an ISO year-1 value
  (Go's zero time) parses to `unix=-62135596800` and any `1970-01-01` value to `unix=0`, and
  epoch 0 even survives a plain truth test. The raw values are preserved as custom attributes.

  **`firstSeenTS` is set only where a real one exists.** CounterACT publishes no
  first-discovery property of its own, but a deployment running the OT module forwards
  eyeInspect's `otsm_details_first_seen` (epoch seconds). That is the only genuine first-seen
  this API offers. Deriving one from a report time would be wrong, and is not done.
- `GET /api/policies` is fetched by neither this integration nor any asset mapping; policies are
  configuration objects rather than assets. It is only relevant as the place to look up the IDs
  for the `match_rule_ids` parameter.
- This integration was validated against local fixtures, not a live Forescout CounterACT
  deployment.

## Future

- **Outbound: push runZero classification into CounterACT through the DEX API.** The natural
  inverse of this integration. CounterACT's **Data Exchange (DEX)** module accepts *external*
  host properties: `POST /fsapi/niCore/Hosts` with an `FSAPI` XML transaction writes into
  properties an administrator has pre-created under `Tools > Options > Data Exchange (DEX)`.
  Writing runZero's device type, OS, or risk score there makes it a first-class condition in
  CounterACT policy, so NAC enforcement can act on what runZero discovered;
  `POST /fsapi/niCore/Lists` does the same for Forescout Lists. Three constraints: DEX is a
  **different API** with its own `{user}@{account}` credential, so this one cannot be reused;
  the target properties and lists must exist in the console first; and the host key is an IP
  address, so the push inherits the address-keyed identity model discussed above.
- **Outbound: policy actions as a disruptive control surface.** A CounterACT policy can act --   VLAN reassignment, switch port block, ACL application, endpoint isolation -- and a
  runZero-driven policy would reach those indirectly, by writing a DEX property a policy is
  configured to act on, keeping the enforcement decision inside the customer's own auditable
  policy. A mistaken push still takes endpoints off the network, so it needs a confirmation
  model, a dry-run mode, and a scoped saved query, not a scheduled sync.
- **`GET /api/hostfields` as a self-describing schema.** The deployment enumerates its own
  property catalogue with a `name`, `label`, `description`, and `type`, so new mappings could be
  driven from the type rather than a hardcoded name list -- every `ip`-typed property into
  network interfaces, every `port`-typed one into services -- picking up properties from plugins
  that did not exist when the integration was written. The same index would let the credential
  form offer a live pick-list, which matters because the 50-field ceiling makes *which*
  properties are requested a real decision.
- **Per-appliance walks through `GET /api/nodes/`.** The guide's "one request at a time, per
  node ID" means a multi-appliance Enterprise Manager could be walked node by node with more
  concurrency than the single `next_link` chain gives. This integration already reads and
  re-sends the `nodeId`; what it does not do is fan out. Only worth building against a
  deployment large enough to measure it on, and it stays inside the same 20-per-minute budget.
- **NAC coverage-gap reporting.** Diffing runZero's inventory against `GET /api/hosts` in both
  directions is directly actionable: assets runZero sees that CounterACT has no host object for
  are segments the NAC cannot see, a policy enforcement gap rather than a data gap; in reverse,
  CounterACT hosts runZero never reaches are segments the Explorer cannot scan. Layering
  `matchRuleId` turns the same report into per-policy coverage, and `GET /api/policies` supplies
  the names to label it.
- **Alert or event ingestion is not available on this API.** The Web API exposes hosts, host
  fields, and policies, and nothing event-shaped: no admission-event, policy-violation, or
  action-history endpoint, and no webhook. An event-driven pairing would have to be built on DEX
  writes and CounterACT-side policy rather than a runZero-side poller.

## API documentation

- **The primary source is the vendor's own *eyeExtend Web API Plugin* guide**, which is public at
  <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/>. The topics this integration
  is built from:
  - Retrieve Paginated Hosts and Other Properties --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/retrieve-pag.htm>
    (`POST /api/hosts/discovery`, the `page`/`pageSize`/`sinceTime`/`nodeId` parameters, the
    `{"fields": [...]}` body and its 50-field limit, the `metadata.next_link` response shape, and
    the 20-requests-per-minute limit).
  - Retrieve a List of Active Endpoints --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/endpoints.htm>
    (`GET /api/hosts`, `matchRuleId`, the filter syntax, and the `hostId`/`ip`/`mac` response
    whose example pins the packed-IPv4 identity analysis above).
  - Retrieve Specified Host Property Values --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/web-service-retrieve.htm>
    (`GET /api/hosts/{obj_ID}?fields=`, and the value-wrapper shapes with the statement that
    `timestamp` indicates how recently the value was updated).
  - Retrieve an Index of Host Properties --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/retrieve-indexs.htm>
    (`GET /api/hostfields` and its `name`/`label`/`description`/`type` records).
  - Retrieve Node IDs --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/retrieve-node-IDs.htm>
    (`GET /api/nodes/`; documented, not needed, not called).
  - Using Entity Tags --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/using-entity-tags-followup-requests.htm>
    (the ETag/`If-None-Match`/304 model, deliberately not implemented -- see the Notes).
  - Appendix 1: Property and Data Types --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/appendix-1.htm>
    (the Date type as "NUMBER type with Epoch Time in seconds, or DATE, DATETIME, TIMESTAMP",
    and the single-value / list / composite property model).
  - Service Interaction Considerations --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/service-interaction-considerations.htm>
    (the warning that a list response "may truncate" when internal timeouts are exceeded).
  - Web Service Error Responses --     <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/eyeextend-web-api-plugin/error-responses.htm>.

  A PDF of the whole guide is at
  <https://docs.forescout.com/eyeextend/eyeextend-web-api-plugin/Resources/PDFs/web-api-1-5-16-h.pdf>.
- A recorded live response -- the property document that showed `hostname_calculated` and
  `otsm_details_host_name` are the only hostnames a real OT deployment carries, and that
  `otsm_details_cves` and `cysiv_risk_cve_list` carry structured CVSS -- is published in the
  Netskope Cloud Exchange Forescout plugin README,
  <https://github.com/netskopeoss/ta_cloud_exchange_plugins/blob/main/forescout_ztre/docs/README.md>.
- The CounterACT administration guide, covering the console-side configuration (modules, Web API
  user settings, DEX accounts, properties, lists) but not the REST contract:
  <https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf>.
- Module prerequisites, Web API user creation, the Client IPs allow list, and the DEX account and
  property model: <https://xsoar.pan.dev/docs/reference/integrations/forescout>.
- The login contract, which the guide describes only in prose -- `POST /api/login` returning a
  bare JWT in the response body rather than as JSON or a header, the raw `Authorization: <token>`
  header with **no `Bearer` prefix**, and the five-minute token validity -- plus the DEX endpoints
  discussed under Future, were read from two independently written, shipped clients:
  - <https://github.com/demisto/content/tree/master/Packs/Forescout/Integrations/Forescout>
    (request construction, the JWT validity constant, the host field type enum, and the sample
    responses the identity analysis above is based on).
  - <https://github.com/splunk-soar-connectors/forescoutcounteract> (the endpoint list, and an
    independent confirmation that the login token is the response body).
- Product overview for CounterACT/eyeSight: <https://www.forescout.com/platform/eyesight/>

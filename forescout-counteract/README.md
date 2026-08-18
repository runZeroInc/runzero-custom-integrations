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
   - **Import classification, services, and software** (`include_details`): optional; default enabled. Fetches the per-host property document.
   - **Detail enrichment limit** (`detail_limit`): optional; default `1000`. Maximum number of hosts to enrich with properties. `0` removes the cap.
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
  --kwargs detail_limit=25 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./forescout-counteract-run
```

Run this from the Explorer host, or from a host whose address you added to the Web API
**Client IPs** allow list — the allow list is enforced per source address, so a
command-line run from a laptop is rejected with a 403 even when the credential is
correct.

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. Capping `detail_limit` on a first run keeps a smoke test from issuing a per-host
property request for every endpoint the Enterprise Manager knows about.

**One CLI caveat, and it is narrower than it looks:** `--kwargs` takes the value verbatim
as long as the whole argument holds a single `=`, so the comma-separated `match_rule_ids`
list passes through fine — `--kwargs match_rule_ids=101,102` arrives as the string
`101,102`. What breaks is a value that *also* contains an `=`, which flips the flag into
comma-separated parsing: the value is cut at the first comma and the remainder either
becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. That combination is reachable here through
`host_filter`, whose conditions are `key=value` pairs, and through a password. Wrap the
whole argument in a second pair of quotes when a value needs both characters:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

`host_filter` separates its conditions with `&` rather than a comma, so a plain filter
survives unquoted parsing — but it still has to be quoted for the *shell*, which would
otherwise read the `&` as a request to background the command.

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
- Source ID field: `hosts[].hostId` from `GET /api/hosts`. The same value is returned as
  `host.id` by `GET /api/hosts/{obj_id}`.
- Documentation evidence: the Web API plugin guide is distributed through the Forescout support
  portal (`docs.forescout.com`) and is gated, so it could not be read. The contract used here
  comes from two independently written, shipped clients for this API — the Cortex XSOAR
  `Forescout` content pack and the Splunk SOAR `forescoutcounteract` connector — plus the sample
  responses published in the XSOAR pack's README.
  **The decisive evidence is what those samples show about the id.** In the vendor pack's own
  `forescout-get-hosts` output, every one of the nine host rows carries a `hostId` that is
  exactly its IPv4 address packed into a 32-bit integer: `192.168.1.44` → `3232235820`,
  `192.168.1.1` → `3232235777`, `192.168.1.17` → `3232235793`, `192.168.1.212` → `3232235988`.
  The relationship holds for all nine with no exceptions. The CounterACT object id is therefore
  an *encoding of the endpoint's address*, not an opaque, device-scoped object key.
- Uniqueness scope: one Enterprise Manager. The value is only as unique as the address space it
  encodes, so two Enterprise Managers covering overlapping RFC 1918 ranges will both mint
  `3232235820` for their own `192.168.1.44`. The scope is baked into the runZero id.
- Cardinality: one index row per host object. Because the id is address-derived, one physical
  device that is re-addressed becomes a *different* host object with a *different* id, and the
  same device can therefore appear under several ids over time.
- Stability: the id survives rename, re-profiling, reboot, agent install, and policy changes —
  everything except a change of IPv4 address, which replaces it outright.
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
  changes IP would fragment into a new runZero asset on every move, and — worse — a recycled
  address would assert that two unrelated devices are the same asset. Ignoring the id and
  merging on MAC, IP, and hostname is the correct model for this source, and it happens to be
  the right one on the merits as well: CounterACT's contribution to runZero is its classification
  of endpoints runZero already discovers, not a separate authoritative inventory. The id is still
  emitted, namespaced and deterministic, so re-polling the same object updates the same record.
- Verdict: derived / non-authoritative.

**What could not be confirmed.** The IP-to-id relationship was verified against nine IPv4 hosts.
Neither vendor client publishes a sample of a host CounterACT tracks by MAC only (an endpoint it
has seen at layer 2 but never assigned an address) or of an IPv6-only host, so it is unknown
whether those receive a non-address-derived id from a different sequence. That uncertainty does
not change the decision: `no-id-match no-id-break` is safe either way, since it is correct for a
weak id and merely redundant for a strong one.

### Notes

- **Assets** come from `GET /api/hosts`, which returns the full host index. The index is
  deliberately thin: the vendor's own clients read only `hostId`, `ip`, and `mac` from it, and
  that is all it returns. Everything else requires a per-host call.
- **The N+1 is the central cost of this integration, and it is capped.** `GET /api/hosts/{id}`
  returns the properties for exactly one host, so a full enrichment of a 100,000-endpoint
  Enterprise Manager would be 100,000 requests. Enrichment is therefore bounded by
  `detail_limit` (default `1000`); hosts past the cap are still imported from the index with
  their IP and MAC, and the run prints exactly how many were left unenriched. Three further
  controls exist for a large deployment: `include_details` turns per-host fetching off entirely,
  and `match_rule_ids` and `host_filter` push the selection server-side so the index itself comes
  back smaller. Scoping with `match_rule_ids` against a policy that already selects the endpoints
  you care about is the recommended way to run this at scale.
- **A detail-disabled run is still useful.** The index alone yields an IP and a MAC per host,
  which are precisely the fields runZero correlates on, so an unenriched run still tags every
  known endpoint and confirms NAC coverage. It costs two requests for the whole estate.
- **Host properties are discovered, not hardcoded.** `GET /api/hostfields` enumerates every
  property the deployment exposes, and every plugin installed on the Enterprise Manager
  contributes its own, so no two deployments have the same property set. The integration fetches
  that index once at startup and intersects it with the properties it knows how to map; the
  `fields=` list sent with each per-host request contains only names the deployment has
  advertised. If `/api/hostfields` fails or names nothing mappable, per-host fetching is skipped
  entirely rather than spending one request per host on a query that cannot return anything.
- **Classification is mapped as the product's primary output**, because profiling is what
  CounterACT is for:
  - `prim_classification` (Function) → `deviceType`, and a `function:` tag. The value is a
    classification-tree path such as `Computer/Windows Machine/Desktop`, so the leaf segment is
    taken as the most specific answer and mapped onto runZero's device type vocabulary. A leaf
    with no mapping is passed through verbatim, so a deployment with a custom classification tree
    still gets a device type.
  - `os_classification` (Operating System) → `os`, again taking the leaf of the tree path. No
    attempt is made to split an `osVersion` out of it.
  - `vendor_classification` (Vendor and Model) → `manufacturer` from the root segment and `model`
    from the leaf, plus a `vendor-model:` tag. **Assumption:** this property is treated as a
    tree path whose first level is the vendor and whose leaf is the model, which is what its
    label states. When the deployment returns it as a flat string with no `/`, the whole value
    becomes the manufacturer and no model is set, so a flat value cannot produce a wrong split.
  - `mac_vendor_string` (NIC Vendor) is the fallback manufacturer when there is no vendor
    classification at all.
  - `cl_type` becomes a `classified-by:` tag, so a search can separate endpoints classified by a
    policy from ones inferred from a DHCP fingerprint.
  - `online`, `onsite`, and `manage_agent` become the bare tags `online`, `onsite`, and
    `secureconnector`. Every asset also carries the constant `forescout-counteract` and `nac`
    tags, matching the way `forescout-eyeinspect` tags its hosts `ot`.
  - The remaining classification and state properties — `cl_rule`, `dhcp_class`, `dhcp_os`,
    `user_def_fp`, `fingerprint`, `matched_fingerprints`, `agent_version`, `switch_port_name`,
    and the rest — are preserved as `forescout_counteract_`-prefixed custom attributes.
- **Services** are built only from `openports`, which is the one property typed `port` in the
  vendor's field list. Its element shape is not published, so ints, `"445/tcp"`, `"137 (UDP)"`,
  and `{"port": ..., "protocol": ...}` dicts are all accepted; an entry that names no transport
  is recorded as `tcp` and flagged `forescout_counteract_transport_source=assumed`, matching the
  honesty flag `forescout-eyeinspect` uses. Port ranges such as `"10-20"` and out-of-range values
  are skipped rather than guessed at.
- **The `nmap_def_fp5`/`nmap_def_fp7` properties are deliberately not turned into services.**
  Their names suggest port data, but the vendor documents them as "Nmap-OS Fingerprint" — they
  are operating-system fingerprint strings produced by an Nmap-based classification probe, with
  no port in them. Synthesizing ports from a classification label would invent scan data runZero
  never observed, so they are recorded as custom attributes only. The same applies to
  `samba_open_ports`, which is a boolean-style indicator that NetBIOS ports are open, not a port
  list.
- **Software** comes from installed-application properties discovered by name from
  `/api/hostfields` (anything matching `application`, `installed_program`, `installed_software`,
  or `packages`), capped at eight properties. In practice these exist only for hosts CounterACT
  manages through SecureConnector or a remote inspection credential; an unmanaged endpoint yields
  none. Element shapes are undocumented, so dicts (`name`/`product`, `version`, `vendor`) and
  plain strings are both accepted. **Assumption:** for a plain string, a trailing whitespace-
  delimited token that starts with a digit is treated as the version (`"Notepad++ 8.6.4"` →
  product `Notepad++`, version `8.6.4`); the original string is kept verbatim in
  `forescout_counteract_software_raw` so nothing is lost if the split is wrong. CounterACT
  publishes no CPE for an application, so `Software.cpe23` is deliberately left unset rather than
  synthesized.
- **Vulnerabilities are opportunistic and deployment-dependent.** CounterACT itself is not a
  vulnerability scanner; CVE data exists only when a vulnerability assessment plugin or an
  eyeExtend connector has been installed and has written its findings into host properties. There
  is no fixed property name for this, so any property whose name contains `cve` or `vulnerab` is
  requested (capped at eight) and CVE identifiers are extracted from its values by pattern.
  Identifiers are upper-cased before use, because `Vulnerability.cve` is validated against a
  strict upper-case pattern and a lower-case value would fail the whole record; anything that
  still does not match is dropped. No CVSS score, severity, publication date, or remediation is
  available from this source, so the findings carry a CVE, a category, and the property they came
  from — and no invented severity or risk rank.
- **Authentication is a JWT returned in the response body.** `POST /api/login` takes
  `username` and `password` as a form-encoded body and answers with the bare token as
  `text/plain` — not JSON, and not a response header. That is confirmed against both vendor
  clients (`WEB_AUTH = response.text` in the XSOAR pack, `token = response.text` in the Splunk
  SOAR connector). The token is then sent as `Authorization: <token>` with **no `Bearer` prefix**,
  again matching both clients. Because the body is not JSON, the login call has to use the raw
  `http.post` builtin: `post_json` would try to decode a bare JWT as a document. The response is
  checked for the three-segment JWT shape before it is installed, so an HTML error page or a
  captive-portal redirect is never stored and used as a credential. The token is never printed.
- **The login request has no retry budget**, because `retries` is a parameter of
  `get_json`/`post_json` only and the raw builtins reject it. A transient failure or a TLS
  problem on the login call aborts the run with the transport error rather than being retried,
  which is visible in the task log. Every other request in this integration goes through
  `get_json` and gets the built-in retry and backoff behavior.
- **Token lifetime is short and is handled in both directions.** The Web API's default JWT
  validity is five minutes, which a run that enriches a thousand hosts will certainly outlive.
  The token is refreshed proactively once it is four minutes old, and if the Enterprise Manager
  rejects it anyway the request is retried once after re-authenticating. A single host whose
  detail call fails for any other reason is logged and treated as unenriched rather than ending
  the run.
- **Pagination: there is none.** `GET /api/hosts` publishes no offset, limit, page, or cursor
  parameter — neither vendor client passes one — and answers with the whole index in a single
  response. The request therefore cannot be split, and on a very large Enterprise Manager that
  one response can be large. Assets are still built and streamed to runZero in chunks of 100 with
  `report_asset`, so the `ImportAsset` set never accumulates, and `match_rule_ids` /
  `host_filter` are the supported way to make the index itself smaller.
- **Loopback and placeholder addresses are filtered** out of network interfaces
  (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`), as is the all-zero MAC
  `000000000000` that appears in the vendor's own sample output for hosts CounterACT has never
  resolved a MAC for. Both would otherwise be shared merge signals capable of collapsing an
  entire estate onto one asset. The raw index values are preserved as
  `forescout_counteract_index_ip` and `forescout_counteract_index_mac`.
- **Duplicate index rows are collapsed.** The same `hostId` appearing twice in one index response
  is imported once, which also avoids spending a second detail request on it.
- **No timestamps are mapped.** CounterACT exposes date-typed properties such as
  `ipv4_report_time` and `last_nbt_report_time`, but their serialization is not published by
  either vendor client, and `parse_time` aborts the whole script on a format it cannot parse.
  They are preserved verbatim as custom attributes instead, so `firstSeenTS` and `lastSeenTS` are
  left unset rather than risking the run on a guess.
- Rate limiting is not documented for this API. `get_json` retries 408/425/429 and 5xx with
  exponential backoff and honors `Retry-After`, three additional attempts by default.
  Authentication failures (401 on a fresh token, or 403 from the Client IPs allow list) are
  reported and stop the run rather than being retried indefinitely.
- `GET /api/policies` is fetched by neither this integration nor any asset mapping; policies are
  configuration objects rather than assets. It is only relevant as the place to look up the IDs
  for the `match_rule_ids` parameter.
- This integration was validated against local fixtures, not a live Forescout CounterACT
  deployment.

## Future

- **Outbound: push runZero classification into CounterACT through the DEX API.** This is the
  strongest pairing available with this vendor, and it is the natural inverse of this
  integration. CounterACT's **Data Exchange (DEX)** module accepts *external* host properties:
  `POST /fsapi/niCore/Hosts` with an `FSAPI` XML transaction (`<HOST_KEY NAME="ip" VALUE="..."/>`
  plus `<PROPERTY>`/`<TABLE_PROPERTY>` elements) writes values into properties an administrator
  has pre-created under `Tools > Options > Data Exchange (DEX) > CounterACT Web Console >
  Properties`. Writing runZero's device type, operating system, hardware fingerprint, or a
  risk/exposure score into such a property makes it a first-class condition in CounterACT policy,
  so NAC enforcement can act on what runZero discovered — quarantine anything runZero classifies
  as an unmanaged OT device on a corporate VLAN, or admit only endpoints runZero has fingerprinted
  recently. `POST /fsapi/niCore/Lists` does the same for Forescout Lists, which is the right shape
  for pushing a runZero saved query as a membership list. Three constraints matter: **DEX is a
  different API from the Web API used here**, with its own `{user}@{account}` credential pair and
  its own account configuration, so an outbound integration needs a second credential rather than
  reusing this one; the target properties and lists must exist in the console first and be
  associated with the DEX account; and the host key is an IP address (`CREATE_NEW_HOST=false`
  keeps the push from inventing host objects), which means the push inherits the same
  address-keyed identity model discussed above and should be driven from runZero assets that
  currently hold an address.
- **Outbound: policy actions as a disruptive control surface.** Beyond writing properties,
  CounterACT's value is that a policy can act — VLAN reassignment, switch port block, ACL
  application, endpoint isolation, HTTP notification to the user. A runZero-driven policy would
  reach those actions indirectly, by writing a DEX property that a CounterACT policy is
  configured to act on. That indirection is a feature rather than a limitation: it keeps the
  enforcement decision inside the customer's NAC policy where it is auditable. It is still a
  genuinely disruptive surface — a mistaken push can take endpoints off the network — so it needs
  a confirmation model, a dry-run mode, and a scoped saved query, not a scheduled sync.
- **`GET /api/hostfields` as a self-describing schema.** Because the deployment enumerates its
  own property catalogue, with a `name`, `label`, `description`, and `type`
  (`string`, `boolean`, `ip`, `ipv6`, `port`, `service`, `date`, `integer`, `composite`,
  `tree_path`, `session`, `appliance`, `change`, `list_change`), expanding this integration is
  unusually cheap: new mappings can be driven from the type rather than from a hardcoded name
  list. A future version could map every `ip`/`ipv6`-typed property into network interfaces, every
  `port`-typed property into services, and every `date`-typed property into timestamps once the
  date serialization is confirmed, and would then pick up properties from plugins that did not
  exist when the integration was written. The same index would let the credential form offer the
  operator a live pick-list of properties to import.
- **NAC coverage-gap reporting.** Diffing runZero's inventory against `GET /api/hosts` in both
  directions is directly actionable for a NAC program: assets runZero sees that CounterACT has no
  host object for are endpoints on segments the NAC has no visibility into, which is a policy
  enforcement gap rather than a data gap. In reverse, CounterACT hosts runZero never reaches
  identify segments the Explorer cannot scan. Layering `matchRuleId` on the query turns the same
  report into per-policy coverage — how many endpoints a compliance policy actually selects
  versus how many exist — and `GET /api/policies` supplies the policy and rule names needed to
  label it.
- **Alert or event ingestion is not available on this API.** The Web API exposes hosts, host
  fields, and policies, and nothing event-shaped: there is no admission-event, policy-violation,
  or action-history endpoint to poll, and no webhook. CounterACT does emit syslog and can be
  configured to send events to a SIEM, but that is outside this API surface. An event-driven
  pairing would have to be built on DEX writes and CounterACT-side policy rather than on a
  runZero-side poller.

## API documentation

- The Forescout Web API plugin guide and the CounterACT administration guide are distributed
  through the Forescout documentation portal at <https://docs.forescout.com/>. The Web API plugin
  guide is gated behind a customer login and could not be read; the CounterACT administration
  guide is public, for example
  <https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf>,
  and covers the console-side configuration (modules, Web API user settings, DEX accounts,
  properties, and lists) that this integration depends on but not the REST contract.
- Module prerequisites, Web API user creation, the Client IPs allow list, and the DEX account and
  property model: the public setup instructions in the Cortex XSOAR `Forescout` content pack,
  <https://xsoar.pan.dev/docs/reference/integrations/forescout>.
- The API contract actually used — `POST /api/login` returning a JWT in the response body, the
  raw `Authorization: <token>` header, `GET /api/hosts` returning `{"hosts": [{hostId, ip, mac}]}`,
  `GET /api/hosts/{obj_id}?fields=` returning `{"host": {id, ip, mac, fields: {name: {value}}}}`,
  `GET /api/hostfields` returning `{"hostFields": [{name, label, description, type}]}`, and the
  DEX endpoints `POST /fsapi/niCore/Hosts` and `POST /fsapi/niCore/Lists` — was read from two
  independently written, shipped clients:
  - <https://github.com/demisto/content/tree/master/Packs/Forescout/Integrations/Forescout>
    (`Forescout.py` for the request construction and the five-minute JWT validity constant,
    `Forescout.yml` for the host field type enum, and the pack `README.md` for the sample
    `forescout-get-hosts`, `forescout-get-host-fields`, and `forescout-get-host` responses that
    the identity analysis above is based on).
  - <https://github.com/splunk-soar-connectors/forescoutcounteract> (`forescoutcounteract_consts.py`
    for the endpoint list and `forescoutcounteract_connector.py` for an independent confirmation
    that the login token is the response body).
- Product overview for CounterACT/eyeSight: <https://www.forescout.com/platform/eyesight/>

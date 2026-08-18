# Custom Integration: BMC Helix Discovery

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## BMC Helix Discovery requirements

- A BMC Discovery appliance or Helix Discovery tenant reachable from the Explorer over HTTPS.
- A BMC Discovery user that holds the **api-access** permission, in addition to the normal permissions needed to read the datastore. Without `api-access` every REST call returns `403`.
- A permanent API token generated for that user.

## Steps

### BMC Helix Discovery configuration

1. In the **Administration** page, open the **Security** section and click the **Users** icon, then click **Add** at the bottom of the Users page. In the **Template** field choose **API Access** — BMC's own guidance is that *"if writing a script or program to make unattended calls against the REST API, it is recommended that a new local BMC Discovery user of type API Access is created just for this purpose."* Choosing that template automatically selects the **api-access** and **never-deactivate** check boxes.
2. Confirm the user's group membership. `api-access` is a **group**, not a standalone permission toggle, and it is required to make *any* request to the REST, CSV or XML APIs — BMC's own troubleshooting guidance is that if every endpoint returns 403, the user probably lacks it.

   Note that `api-access` on its own is **not read-only**: BMC describes that group as users who *"can read and write to some of the model and control some of reasoning."* For a genuinely read-only integration account, add the **readonly** group alongside it. BMC does not document that pairing explicitly, so treat `api-access` + `readonly` as a recommendation rather than a vendor-blessed configuration, and confirm with a real run. Users need the same permissions they would need to perform the equivalent action in the UI.
3. With that user selected, choose **Generate API Token** from the **Action** list and copy the token from the dialog. Tokens generated this way **do not expire**, which is what makes them suitable for a scheduled task — but they also **cannot be revoked**. BMC is explicit: to invalidate a token you must delete the user. Plan the account accordingly rather than expecting a rotate button.
4. Determine which REST API versions your appliance actually publishes, rather than guessing from the release number. `GET https://<appliance>/api/about` returns the list, and **that endpoint performs no authentication check**, so you can call it before you have a token:

   ```bash
   curl -s https://discovery.example.com/api/about
   ```

   It answers with an `api_versions` array — a 23.3 appliance lists `1.0` through `1.10`, on-premises 24.x reaches `v1.12`, and BMC Helix Discovery (SaaS) supports up to `v1.18`. Higher versions stay backwards compatible, so the `api_version` default of `v1.3` works against any modern appliance; set it higher only if you need a newer endpoint. The appliance also hosts a Swagger UI at `https://<appliance>/swagger-ui`, linked from the **Help** menu on every page, and the machine-readable spec at `/api/v<version>/openapi.json`.
5. Confirm the token from the Explorer host. **The `B` in `Bearer` must be upper case** — older BMC Discovery releases accepted a lower-case `bearer` and current ones do not, which makes this a silent breakage on upgrade:

   ```bash
   curl -i -X GET -H 'Authorization: Bearer <your_token>' \
     https://discovery.example.com/api/v1.3/discovery
   ```

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "BMC Helix Discovery").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **BMC Discovery appliance URL** (`url`): base URL of the appliance, for example `https://discovery.example.com`. Do not include the `/api/...` path; the script appends it.
   - **REST API version** (`api_version`): optional; the version segment of the API path (default: `v1.3`).
   - **Host filter** (`host_filter`): optional; a BMC Query Language condition appended to the host search as a `WHERE` clause, for example `os_class = 'UNIX'`. Leave blank to import every host.
   - **API token** (`api_token`): the API token generated above.
   - **Import software and listening ports** (`include_details`): optional; fetch per-host detail (default: enabled).
   - **Detail enrichment limit** (`detail_limit`): optional; maximum number of hosts to enrich with software and listening ports (default: 500; 0 removes the cap).
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
runzero script --filename bmc-discovery/bmc-discovery.star \
  --kwargs url=https://discovery.example.com \
  --kwargs api_token=YmV4YW1wbGVmYWtldG9rZW4wMTIzNDU2Nzg5YWJjZGVm \
  --kwargs api_version=v1.3 \
  --kwargs include_details=true \
  --kwargs detail_limit=25 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./bmc-discovery-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. Capping `detail_limit` on a first run keeps a smoke test from issuing a
per-host detail search against every host in the datastore.

**One CLI caveat, and it is narrower than it looks:** `--kwargs` takes the value verbatim
as long as the whole argument holds a single `=`, so a comma on its own is harmless —
`--kwargs "host_filter=os_class IN ('UNIX', 'Windows')"` arrives intact. What breaks is a
value that *also* contains an `=`, which flips the flag into comma-separated parsing: the
value is cut at the first comma and the remainder either becomes a fabricated second
parameter or aborts the run with `must be formatted as key=value`. A TQL condition hits
that combination easily, because `=` is its equality operator. Wrap the whole argument in
a second pair of quotes when a filter needs both characters:

```bash
  --kwargs "\"host_filter=os_class = 4, name matches 'web'\""
```

Use escaped double quotes for the inner pair as shown. Wrapping in single quotes instead
looks equivalent but is not — the shell closes and reopens the string at each `'`, so any
quotes inside the filter are stripped before the scanner sees them.

To check the `CONFIG` block and the HTTP and TLS wiring without a live appliance:

```bash
runzero script --filename bmc-discovery/bmc-discovery.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove the appliance accepts the token or that any `Host` node is
parsed. The fixture scenarios are what exercise the parsing:

```bash
python3 tests/run.py bmc-discovery
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat bmc-discovery/bmc-discovery.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://discovery.example.com,api_token=YmV4YW1wbGVmYWtldG9rZW4wMTIzNDU2Nzg5YWJjZGVm' \
  --output ./bmc-discovery-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string — genuinely, and with no single-`=` exemption. Here a
comma in *any* value splits it, so a `host_filter` with a comma in it cannot be passed
this way at all. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from BMC Helix Discovery.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:bmc-discovery`.

## Asset identity

- Target entity: a physical or virtual computer system. BMC's `Host` node represents "any physical or virtual computer system in your organization", one node per host.
- Source ID field: `key` on the `Host` node, requested explicitly in the search's `SHOW` clause.
- Documentation evidence: the [Host node reference](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Developing/Node-lifecycle/Inferred-nodes/Host-node/) documents `key : string` as the "Globally unique key", created when the node is first generated from a combination of attribute values, and states that "the key itself will not be changed" even if those attributes change later. [How nodes are identified](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Developing/Node-lifecycle/How-nodes-are-identified/) is explicit that the node id is the wrong choice here: it is "a unique datastore identifier for that node in the datastore", "not guaranteed to remain stable over time", and "not persisted on destruction and creation of a new node which represents the corresponding real-world entity", closing with "if you need to identify a node uniquely over time in order to effect an integration with any external system, we strongly recommend that you use the key attribute of the node, rather than the node ID".
- Uniqueness scope: BMC calls the key globally unique, and because it is derived from discovered properties two appliances scanning the same host should derive the same key. That is not something this integration can verify, so the id is still namespaced by appliance host — see the note on collisions below.
- Cardinality: one `Host` node per host, so one source row per asset. Software instances and listening ports are child rows reached by traversal and never become assets of their own.
- Stability: the key survives attribute churn and survives the destruction and recreation of the node. A host that BMC re-identifies through its `EndpointIdentity` chain (a rebuild, a re-image) is a genuinely new entity to BMC and gets a new key; runZero then merges it with the existing asset on MAC, IP, or hostname like any first contact.
- Reuse behavior: BMC does not document key reuse. Because the key is derived from the identity of the real-world entity rather than allocated from a counter, reuse would mean two hosts BMC considers identical.
- Presence: `key` is created with the node and should always be present. If it is absent the script falls back to `node:<#id>` and logs once that it has done so, because importing a host under a less stable id is better than dropping it. A host with neither is skipped, logging only the slug and the hostname.
- Final runZero ID: `bmc-discovery:<appliance-host>:<key>`, for example `bmc-discovery:discovery.example.com:OWQ1YWY4MjItSE9TVC13ZWIx`.
- Missing-ID behavior: fall back to `bmc-discovery:<appliance-host>:node:<#id>`, then skip.
- Match behavior (set once in `CONFIG`): `no-ip-break`. Reasoning below.
- Verdict: authoritative.

### Why the id is namespaced even though BMC calls the key global

The namespace is asymmetric insurance. If the key really is stable across appliances, namespacing costs a duplicate asset the first time two appliances report the same host — and that duplicate immediately merges on MAC, IP, or hostname, because a second custom-integration record for a host runZero already knows is exactly the first-contact path those signals exist for. If the key is only unique within one datastore, *not* namespacing would fold two unrelated hosts into one asset, and nothing could undo it: `MatchByForeignID` consults only the foreign-id collision check, not the MAC, IP, or hostname break helpers, so a foreign-id match cannot be vetoed by conflicting network data. A recoverable duplicate is a much cheaper mistake than an unrecoverable merge.

### Why `no-ip-break` and nothing else

All eight match dimensions are on by default. `<dim>-match` decides whether a dimension can *find* a merge candidate; `<dim>-break` decides whether a disagreement on that dimension *disqualifies* one. Only the break flags are relaxed here, and only one of them:

- **id-match / id-break stay on.** The key is a strong, documented, stable identity, so it should drive merges and a conflicting BMC key on an existing asset should disqualify one.
- **mac-break stays on.** BMC signs in to the host under credentials and reads its real interface table, so the MAC set is high quality and reasonably complete. A break only fires when both sides have MACs and *none* of them overlap, which for a credentialed source really does mean a different device. BMC also reports the whole table, including virtual and container interfaces, so a genuine match nearly always overlaps somewhere.
- **name-break stays on.** BMC reads the OS hostname off the host itself, and runZero enrols custom-integration hostnames in the trusted-name set, so `MatchBreakByTrustedHostname` applies to this source. That is a signal worth keeping: the platform's hostname comparison already treats `WEB1` and `WEB1.corp.example.com` as agreeing, so the common short-name-versus-FQDN mismatch does not cause a spurious break. The script does its part by never emitting a placeholder name — `local_fqdn` is literally `localhost` on a large share of UNIX hosts, and BMC sometimes names an unidentified host after its address, so placeholders, bare IPs, and anything not shaped like a hostname are dropped before they reach `hostnames`.
- **ip-break is turned off.** Addresses are the one signal that goes stale between runs. BMC discovery is scheduled, often weekly; runZero scans on its own cadence. A host that DHCP moved since BMC last saw it presents a stale address set that does not overlap the current one, and that disagreement would veto an otherwise correct MAC or hostname match and create a first-contact duplicate. IP disagreement is the weakest of the three signals here and the most likely to be an artifact of scan timing rather than a real difference.

None of this affects merges that happen through the id itself, which are the common case after the first import. The break flags only bite on first contact against an asset runZero discovered on its own.

### Notes

- **What is imported.** Assets come from `POST /api/<version>/data/search?format=object` with `SEARCH Host ... SHOW <attributes>`. Software comes from a traversal of `Host:HostedSoftware:RunningSoftware:SoftwareInstance` per host. Services come from a traversal to `DiscoveredListeningPort`, backed up by the `listening_ports` attribute of each software instance.
- **No vulnerabilities, plainly.** BMC Discovery does not record CVEs or any other vulnerability finding in its datastore, and there is no vulnerability node kind to query. CVE data for BMC-managed estates lives in BMC Helix Vulnerability Management / Automation Console, a separate product that consumes Discovery's asset data. This integration therefore imports no `Vulnerability` objects at all, and it does not synthesize any.
- **No CPEs.** `SoftwareInstance` publishes no CPE, so `Software.cpe23` is deliberately left unset rather than constructed from the product name.
- **Services are real listening sockets.** `DiscoveredListeningPort` records a socket the host itself reported as listening, not the remote end of an observed connection, which is what makes this a genuine `Service` source. Two caveats. First, these nodes are raw discovery data hanging off the `DiscoveryAccess` that observed them rather than off the `Host`, so reaching them from a host takes a four-hop traversal (`Host` to `HostInfo` to `DiscoveryAccess` to `NetworkConnectionList` to the port) and the result includes the ports seen by *every* retained discovery run of that host, not only the most recent. Sockets are deduplicated by address, port, and transport, which collapses the repeats. Second, that traversal path and the `local_port` / `protocol` / `local_ip_addr` attribute names are the least verifiable part of this integration — see the unverified list below. If the traversal fails three times in a row it is dropped for the rest of the run, logged once, and every host still gets services from `SoftwareInstance.listening_ports`, which costs no extra request because those rows are already fetched for the software import. Ports from that fallback carry no protocol, so they are recorded as `tcp` and flagged `bmc_discovery_transport_source = assumed`.
- **Loopback and link-local are filtered.** BMC reports a host's whole interface table, so `127.0.0.1`, `::1`, `0.0.0.0`, and `fe80::/10` are always present. They are removed before any network interface is built, because a source that gives every host the same address can merge an entire estate onto one asset. The raw lists survive verbatim as `bmc_discovery_all_ip_addrs`, `bmc_discovery_all_mac_addrs`, and `bmc_discovery_all_dns_names`. A host whose only address is loopback is imported with no network interface and no services.
- **Pagination.** Each response is a *list* of per-kind envelopes, each with its own `results`, `results_id`, and `next_offset`. The next request is rebuilt against the configured URL with `offset` and `results_id` in the query string rather than following the absolute `next` link, because that link names the appliance by its own hostname and may not be reachable the way the Explorer reaches it. `offset` is never sent without `results_id`; the appliance rejects that. Paging stops when no envelope reports a `next_offset` greater than the current one, so an appliance that ignores the cursor cannot produce an infinite loop. If more than one envelope reports its own cursor, only the first is followed and the run logs that it did so; the searches this integration issues each name a single kind, so that should not arise.
- **Page sizes.** Hosts are fetched 200 rows at a time; the documented default is 100 and no maximum is published. Per-host detail traversals fetch a single page of up to 500 rows, which is well past the 99-child cap an asset can carry anyway.
- **Cost of detail.** Enrichment costs up to two extra searches per host. `detail_limit` caps how many hosts are enriched (default 500); hosts past the cap are still imported without software or services, and the run logs how many were skipped. Set `include_details` to false to import inventory only.
- **Rate limiting and retries.** BMC does not document a rate limit on `/data/search`. The shared HTTP helper retries `408`, `425`, `429`, and `5xx` with exponential backoff and honors `Retry-After`; three retries is the platform default and this integration does not override it.
- **Timestamps.** `last_seen` is taken from the Host `last_update_success` attribute, "the time at which a scan was last successfully associated with this Host". BMC stores a date as a count of 100-nanosecond ticks, and it is not documented whether the REST layer serializes it as that number or as a text stamp, so both are handled and anything else is left alone. Every parsed timestamp is clamped to now, because a timestamp in the future fails validation for the whole asset record rather than for the field — an appliance clock running ahead would otherwise drop assets silently. The raw value is always kept as `bmc_discovery_last_update_success`.
- **Schema drift.** The `SHOW` clause names roughly fifty Host attributes. If an older appliance rejects the search, it is retried once with a core attribute set of the twenty names needed to build an identifiable asset, and the downgrade is logged.
- **Unverified without a live appliance.** The `DiscoveredListeningPort` traversal path and its attribute names (`local_port`, `protocol`, `local_ip_addr`, `state`) — BMC publishes no attribute reference for that node, and the path here is the reverse of the one BMC's own reporting queries walk; whether the `key` attribute is returned for a `Host` when named explicitly in `SHOW` (it is documented but is not returned by `SHOW *`); whether two appliances derive the same key for the same host; the serialization of a `date` attribute under `format=object`; and the maximum accepted `limit`. Each of these degrades rather than fails: a rejected search falls back, a failing traversal falls back, an unrecognized timestamp is skipped, and a missing key falls back to the node id.
- This integration was validated against local fixtures, not a live BMC Helix Discovery appliance.

## Future

- **Outbound: create and drive discovery runs.** `POST /api/<version>/discovery/runs` starts a snapshot run from a body of `{scan_kind, scope, ranges, label, scan_level}` and returns a run `uuid`; `GET /discovery/runs/{uuid}` polls it to `finished`, and `PATCH /discovery/runs/{uuid}` with `{"cancelled": true}` stops it. An outbound integration could push runZero's own discovered subnets, or the addresses of assets runZero has seen and BMC has not, straight into a BMC scan — closing the loop rather than only reading from it.
- **Coverage-gap reporting.** The same endpoint family answers "what did BMC try and fail to reach". `GET /discovery/runs/{uuid}/results` returns the run summary and `GET /discovery/runs/{uuid}/results/{type}` returns the per-endpoint outcomes by category (`Success`, `Dropped`, and the other result kinds), paginated with the same `limit` / `offset` / `results_id` cursor as `/data/search`. Importing the failures as assets, or as attributes on assets runZero already holds, would surface exactly the hosts BMC cannot credential — the blind spots in a CMDB that otherwise looks complete. The `age_count` attribute already imported here is the datastore-side version of the same signal: it goes negative once a host stops answering and counts down to removal.
- **Alert and event ingestion.** BMC exposes `POST /api/<version>/events` for pushing an event *into* Discovery, which makes it an outbound target for runZero findings rather than an inbound source. There is no documented endpoint for subscribing to or polling BMC-generated alerts, so an inbound event feed is not something this API supports today; saying otherwise would be inventing it.
- **Lookup and enrichment.** `POST /data/search` is a general query endpoint, so a lookup-style integration could answer per-asset questions on demand instead of sweeping the estate: `SEARCH Host WHERE __all_ip_addrs LIKE '<ip>'` or `__all_dns_names LIKE '<name>'` resolves a single address to BMC's view of the host, its business and IT owners (`#OwnedItem:Ownership:ITOwner:Person.name`), and its location (`#ElementInLocation:Location:Location:Location.name`) — ownership and siting data runZero cannot discover on the wire. `GET /api/<version>/taxonomy/<kind>` returns the live attribute schema for a node kind, which would let a future version of this integration discover the appliance's real attribute set instead of shipping a fixed `SHOW` clause and a fallback.
- **Dependency topology.** `GET /api/<version>/topology` returns the modelled relationships between elements. BMC's distinguishing asset is not its inventory but its dependency map — which software instance talks to which, and which business service they add up to. Importing `BusinessApplicationInstance` and `TechnicalService` memberships as tags or attributes would let runZero answer "what breaks if this host goes away", which no network scan can determine.
- **Token lifecycle.** `POST /api/token` exchanges a username and password for a one-hour bearer token. This integration uses a permanent token instead, which is simpler and is what BMC recommends for scripted access, but an installation that forbids permanent tokens could authenticate that way.

## API documentation

- [Endpoints in the REST API](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Integrating/Using-the-REST-APIs/Endpoints-in-the-REST-API/) — endpoint families and the `/api/v<major>.<minor>/` path convention.
- [Authentication and permissions in the REST API](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/DISCO242/Integrating/Using-the-REST-APIs/Authentication-and-permissions-in-the-REST-API/) — bearer tokens, the `api-access` permission, and permanent versus expiring tokens.
- [General principles for using the REST APIs](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Integrating/Using-the-REST-APIs/General-principles-for-using-the-REST-APIs/) — the per-kind result envelope, `format=object`, and the `limit` / `offset` / `results_id` / `next` pagination contract.
- [Using the Query Language](https://docs.bmc.com/xwiki/bin/view/IT-Operations-Management/Discovery/BMC-Helix-Discovery/DAAS/Using/Using-the-Search-and-Reporting-service/Using-the-Query-Language/) and [Traversals](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Using/Using-the-Search-and-Reporting-service/Using-the-Query-Language/Traversals/) — `SEARCH ... WHERE ... TRAVERSE ... SHOW` and the `fromRole:Relationship:toRole:toKind` traversal quadruple.
- [How nodes are identified](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Developing/Node-lifecycle/How-nodes-are-identified/) — node id versus key, and the recommendation to use the key for external integrations.
- [Host node](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Developing/Node-lifecycle/Inferred-nodes/Host-node/) — the Host attribute reference, including `key`, `last_update_success`, `age_count`, and the `__all_*` search attributes.
- [Software Instance node](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Developing/Node-lifecycle/Inferred-nodes/Software-Instance-node/) — `publisher`, `product`, `version`, `product_version`, `edition`, `install_root`, and `listening_ports`.
- [Using the REST APIs](https://docs.helixops.ai/bin/IT-Operations-Management/Discovery/BMC-Discovery/BMC-Helix-Discovery-25-2-On-Premises/Integrating/Using-the-REST-APIs/) — index for the pages above.

# Custom Integration: PuppetDB

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## PuppetDB requirements

- PuppetDB 6 or later, open source or the copy bundled with Puppet Enterprise, reachable
  from the Explorer on its query API.
- **A credential.** PuppetDB canonically authenticates clients with a **client certificate**
  issued by the Puppet CA, and that is the only mechanism open-source PuppetDB has. Puppet
  Enterprise additionally accepts an **RBAC token** in the `X-Authentication` header. Supply
  one or the other:
  - **Client certificate** — set the integration's TLS options `client_cert` and
    `client_key` to a PEM certificate/key pair whose Subject CN appears in PuppetDB's
    `certificate-whitelist` file (configured as `certificate-whitelist` in the `[puppetdb]`
    section of `jetty.ini`). A certificate signed by the Puppet CA that is *not* listed is
    rejected with 403 once a whitelist exists. Also set the TLS option `ca_cert` to the
    Puppet CA certificate (`/etc/puppetlabs/puppet/ssl/certs/ca.pem`), because PuppetDB's
    certificate is issued by that CA and not by a public one.
  - **Puppet Enterprise RBAC token** — generate one with `puppet-access login` or from the
    PE console, and give the associated user a role with the *view node data from PuppetDB*
    permission. Tokens expire; a token minted with a short lifetime will start failing with
    401 between runs.
- Neither credential is strictly mandatory. PuppetDB's **port 8080** listener is cleartext
  and unauthenticated, and it is bound to `localhost` by default precisely because anything
  that can reach it can read the whole estate. If a site has deliberately widened that bind
  address, this integration will import from it with no credential at all; it logs a line
  saying so and issues the request either way rather than refusing.
- **Port 8081** is the TLS listener and is the one to use. `https://puppetdb.example.com:8081`.
- Read access is all that is needed. The integration only issues `GET` requests against
  `/pdb/query/v4` and never touches the command API.

## Steps

### PuppetDB configuration

1. Decide which credential to use. On open-source PuppetDB it must be a client certificate.

2. **For a client certificate**, the simplest source is an existing Puppet agent's own
   certificate, or a certificate minted for this purpose:

   ```
   puppetserver ca generate --certname runzero-puppetdb
   ```

   That writes `/etc/puppetlabs/puppet/ssl/certs/runzero-puppetdb.pem` and
   `/etc/puppetlabs/puppet/ssl/private_keys/runzero-puppetdb.pem`. Add the certname to
   PuppetDB's whitelist file and restart PuppetDB:

   ```
   echo runzero-puppetdb >> /etc/puppetlabs/puppetdb/certificate-whitelist
   systemctl restart puppetdb
   ```

   Keep the CA certificate at hand as well — it goes into the integration's `ca_cert` TLS
   option.

3. **For a Puppet Enterprise RBAC token**, create or pick a user, assign it a role holding
   the *view node data from PuppetDB* permission, and generate a token:

   ```
   puppet-access login --lifetime 1y
   ```

   The token is written to `~/.puppetlabs/token`. Copy its contents.

4. Confirm the credential works before configuring runZero:

   ```
   curl --cert cert.pem --key key.pem --cacert ca.pem \
     'https://puppetdb.example.com:8081/pdb/query/v4/nodes?limit=1'
   ```

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "PuppetDB").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **PuppetDB URL** (`url`): base URL of the PuppetDB query API, for example `https://puppetdb.example.com:8081`. The `/pdb/query/v4` path is appended automatically.
   - **X-Authentication token** (`auth_token`): optional; a Puppet Enterprise RBAC token. Leave blank when using a client certificate.
   - **Puppet environment** (`environment`): optional; restrict the import to one Puppet environment, for example `production`.
   - **Import deactivated and expired nodes** (`include_inactive`): optional; also import nodes PuppetDB has retired (default: false).
   - **Import package inventory** (`include_packages`): optional; fetch installed packages from the Puppet Enterprise package inventory (default: false).
   - **Additional fact names** (`extra_facts`): optional; comma-separated top-level Facter fact names to import alongside the built-in set, for example `role,datacenter`.
   - **Nodes per page** (`page_size`): optional; nodes requested per page (default: 500).
   - **Fact rows per page** (`fact_page_size`): optional; fact rows requested per page (default: 2000).
   - **Maximum fact rows to index** (`max_fact_rows`): optional; cap on the (node, fact) rows the whole-estate fact pre-index holds in memory (default: 0, uncapped). On a very large estate the index can otherwise approach the sandbox's memory limit before the first node is reported; nodes past the cap still import, without fact enrichment.
   - **Client certificate (PEM)** (`tls_client_cert`) and **Client key (PEM)** (`tls_client_key`): the mutual-TLS credential. These come from the shared TLS option set; the form requires the key whenever a certificate is supplied.
   - **CA certificate (PEM)** (`tls_ca_cert`): the Puppet CA certificate, so the Explorer trusts PuppetDB's own certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter. With a Puppet Enterprise RBAC token:

```bash
runzero script --filename puppetdb/puppetdb.star \
  --kwargs url=https://puppetdb.example.com:8081 \
  --kwargs auth_token=9d41f7b0c286ae53f19d47c0b3e825a6 \
  --kwargs environment=production \
  --kwargs extra_facts=role,datacenter \
  --kwargs include_packages=false \
  --kwargs page_size=50 \
  --kwargs tls_ca_cert=/etc/puppetlabs/puppet/ssl/certs/ca.pem \
  --output ./puppetdb-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

With a client certificate instead, drop `auth_token` and supply the mutual-TLS pair:

```bash
runzero script --filename puppetdb/puppetdb.star \
  --kwargs url=https://puppetdb.example.com:8081 \
  --kwargs tls_client_cert=/etc/puppetlabs/puppet/ssl/certs/runzero-puppetdb.pem \
  --kwargs tls_client_key=/etc/puppetlabs/puppet/ssl/private_keys/runzero-puppetdb.pem \
  --kwargs tls_ca_cert=/etc/puppetlabs/puppet/ssl/certs/ca.pem \
  --output ./puppetdb-run --overwrite \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`tls_ca_cert` matters in both cases: PuppetDB's own certificate is issued by the Puppet CA,
which the Explorer host does not trust by default.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. `--overwrite` re-runs into a directory that already exists. Omit `--output` to see
only the log lines, and add `--verbose` for the request-by-request log.

`extra_facts` is a comma-separated list, and it survives `--kwargs` intact: the flag only
CSV-splits a value when the whole argument contains a second `=`, which a list of fact names
does not. `extra_facts=role,datacenter` is passed through as written. The same is not true
of `scan --custom-integration-script-kwargs` below.

Leave `include_packages` off for a first run. The package inventory is a Puppet Enterprise
feature and is by far the largest thing PuppetDB will hand back.

To check the `CONFIG` block and the HTTP and TLS wiring without a live PuppetDB:

```bash
runzero script --filename puppetdb/puppetdb.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove PuppetDB accepts the certificate or token, or that any node is
parsed.

The recorded query shapes, including paging and the package inventory, are exercised by the
fixture suite:

```bash
python3 tests/run.py puppetdb
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat puppetdb/puppetdb.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://puppetdb.example.com:8081,auth_token=<token>,environment=production' \
  --output ./puppetdb-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. This flag takes one
comma-separated string, so a multi-fact `extra_facts` value genuinely cannot be passed
through it — name a single fact, configure the list on the console credential, or use
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from PuppetDB.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:puppetdb`.

## Asset identity

- Target entity: a machine under Puppet management — a physical server, a VM, a container,
  or a network device managed through a Puppet proxy. One Puppet agent, one asset.
- Source ID field: `certname` on the node record returned by `GET /pdb/query/v4/nodes`.
- Documentation evidence: `certname` is the **Subject CN of the node's Puppet SSL
  certificate**, which is how the node authenticates to the Puppet Server, and it is
  PuppetDB's primary key throughout the schema. Every entity in the data model joins back
  to it: `certname-relations` in PuppetDB's `query_eng/engine.clj` lists `factsets`,
  `reports`, `package-inventory`, `inventory`, `catalogs`, `nodes`, `facts`,
  `fact_contents`, `events`, `edges`, and `resources`, and the join column for every one of
  them is `certname`. The single-node route is
  [`/pdb/query/v4/nodes/<NODE>`](https://help.puppet.com/pdb/current/topics/nodes.htm),
  documented as behaving "exactly like a call to `/pdb/query/v4/nodes` with a query string
  of `["=", "certname", "<NODE>"]`". This is unusually strong for this class of source:
  most inventory systems key on a surrogate integer, whereas PuppetDB's key *is* the
  cryptographic identity the node uses to authenticate.
- Uniqueness scope: one PuppetDB instance, and in practice one Puppet CA. The Puppet Server
  refuses to issue a second certificate for a certname that already has one, so certnames
  are unique by construction within a Puppet infrastructure.
- Cardinality: one node row per asset. Facts, packages, catalogs, and reports are child
  rows keyed on the same certname and are folded into that asset rather than becoming
  assets of their own. The facts endpoint returns one row per `(certname, fact name)` pair
  and the package endpoint one row per `(certname, package)` pair; both are grouped by
  certname before an asset is built.
- Stability: survives reboot, re-addressing, rename, OS upgrade, and fact re-upload — none
  of those touch the certificate. It is replaced only when the node's certificate is revoked
  and reissued under a different certname, which is a deliberate administrative act.
- Reuse behavior: a certname **is** reused, and this is the honest caveat. Rebuilding a
  machine, clearing its certificate with `puppetserver ca clean`, and reprovisioning it
  under the same certname produces a new certificate for the same identity — and in nearly
  every case that genuinely is the same asset: same hardware, same rack, same role, same
  DNS name. Treating it as the same runZero asset is the right answer. The failure mode is
  the narrow one where a certname is retired and later assigned to unrelated hardware; a
  site that recycles certnames that way would see the old machine's serial number and
  hardware carried forward. That is far less likely than the equivalent hazard with a
  hostname, because a certname is chosen at provisioning time and pinned by a certificate
  rather than handed out by DHCP.
- Presence: always present and never empty. It is the field the API routes on, it is
  `NOT NULL` in the schema, and it cannot be blank because it comes from a certificate
  Subject. A record arriving without one is malformed.
- Final runZero ID: `puppetdb:<puppetdb-host>:<certname>`, for example
  `puppetdb:puppetdb.example.com:web01.corp.example.com`. The host comes from the configured
  URL, so two PuppetDB installations imported into one runZero account cannot collide even
  though both may hold a node called `web01.corp.example.com`.
- Missing-ID behavior: the record is skipped and one line is logged. No identity is
  synthesized, no fact is substituted, and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The id is authoritative, so it
  should drive the merge, but every other signal on the record moves underneath it: a node
  re-addressed by DHCP reports a new `networking.ip`, a rebuilt node reports new MACs, and
  a renamed node reports a new `networking.hostname` and `networking.fqdn` while keeping its
  certname. None of that churn should disqualify a merge against the existing asset. The
  converse also matters — a node whose certificate *was* reissued under a new certname
  arrives with a new id and must still merge onto its existing runZero asset by MAC or
  hostname, which these flags permit.
- Verdict: scoped authoritative — authoritative within one Puppet infrastructure,
  namespaced by the PuppetDB host.

### Why not the FQDN

`certname` **defaults** to the node's FQDN, and on most estates the two are identical — but
they are not the same thing and the difference is load-bearing. `certname` is settable
per-node in `puppet.conf`, and sites routinely set it to something stable and
location-independent (`web01-prod`, a serial number, a UUID) exactly so that renaming or
re-homing a machine does not orphan its Puppet certificate. Keying on the FQDN would
therefore key on a value that can change without the node's identity changing at all, and
would also fuse a decommissioned machine with an unrelated one that inherited its DNS name.
`networking.fqdn` and `networking.hostname` are still imported — as **hostnames**, so
runZero can merge on them — but not as the identity.

### Notes

- **What is imported.** Assets from `GET /pdb/query/v4/nodes`. Facter facts from one paged
  pass over `GET /pdb/query/v4/facts`. Network interfaces from the `networking` fact.
  Installed packages, behind `include_packages`, from
  `GET /pdb/query/v4/package-inventory`. Every mapped field is also kept verbatim as a
  `puppetdb_*` custom attribute.
- **The N+1 was avoided, and this was the central design decision.**
  `GET /pdb/query/v4/facts` answers for **every** node at once — one row per
  `(certname, fact name, value)` — so no per-node fact request is needed. The query sent is
  the AST form `["in", "name", ["array", ["networking", "os", "dmi", …]]]`, which is
  documented as the way to filter a field against a list of literals. PQL's
  `facts[certname,name,value] { name in [...] }` compiles to exactly this and would work
  equally well, but PQL is accepted only on the root `/pdb/query/v4` endpoint while AST
  works on the entity endpoints, so AST was used.
- **Fact pages straddle node boundaries, and that is the trap.** PuppetDB pages the facts
  endpoint by individual **fact row**, not by node, so a node with 40 mapped facts will
  routinely have its fact set split across two pages. Treating each page as a complete fact
  set for the nodes it names would silently drop facts from every node on a page boundary —
  which is a data-loss bug that gets *rarer* as the page size grows, so it survives casual
  testing. Pages are merged into a single map keyed by certname instead, which also makes
  the endpoint's ordering irrelevant. This was verified rather than assumed: the same
  fixture estate read at `fact_page_size=1` (52 separate requests, every node straddling)
  and at `fact_page_size=25000` (one request) produced byte-identical assets, custom
  attributes included.
- **Paging.** `limit`, `offset`, and `order_by` are the shared PuppetDB paging parameters;
  responses are **bare JSON arrays** with no envelope, so paging advances until a short or
  empty page arrives. `order_by` is not optional in practice: PuppetDB documents that
  "the order in which results are returned by PuppetDB is not guaranteed to be consistent
  unless you specify a value for `order_by`", and an unordered result set paged by offset
  can skip and repeat rows. Nodes are ordered by `certname`, facts by `certname` then
  `name`, packages by `certname` then `package_name`. `include_total` is not requested; the
  short-page test is cheaper than the count query it would cost.
- **Deactivated and expired nodes are excluded by default, and the mechanism is worth
  recording.** The `/nodes` and `/facts` routes do not simply filter — PuppetDB's HTTP layer
  *rewrites* the query, adding `["=", "node_state", "active"]` unless the submitted query
  already names a node state (`restrict-query-to-active-nodes` in
  `src/puppetlabs/puppetdb/http/query.clj`). So the default pass sends no state predicate at
  all and gets active nodes. `include_inactive` adds a **second** pass sending
  `["=", "node_state", "inactive"]`, which selects exactly the deactivated and expired ones;
  they arrive tagged `deactivated` or `expired` with the retirement timestamp in
  `puppetdb_deactivated` / `puppetdb_expired`. The third value, `"any"`, was deliberately not
  used: PuppetDB *elides* that predicate entirely rather than expanding it
  (`"any" ::elide` in `query_eng/engine.clj`), and a query that can reduce to nothing is a
  shape not worth depending on for the main walk. It is used in one place only — the package
  query, which is a compound `and` where a sibling clause always survives elision.
- **Interfaces come from `networking.interfaces`, one runZero interface per device.** That
  fact is a hash keyed by device name, and each device carries its `mac` plus `bindings[]`
  for IPv4 and `bindings6[]` for IPv6, each binding a hash of `address`, `netmask`, and
  `network`. Both binding arrays are read, not just the single `ip`/`ip6` convenience keys,
  so a NIC with several addresses keeps all of them. Devices reporting the same MAC — a bond
  and its slaves, a VLAN device and its parent — are folded into one interface carrying all
  of their addresses, with the device names recorded joined by `+` in
  `puppetdb_interface_identifiers` (for example `bond0+bond0.55+eno1+eno2`). The node's
  top-level `networking.mac` / `networking.ip` are added last and only if the per-interface
  facts did not already account for them, so a node with only legacy flat facts still gets
  one interface.
- **Loopback is filtered, and this is a merge-safety issue rather than a cosmetic one.**
  Facter reports `127.0.0.1` and `::1` on the `lo` device of literally every node. If those
  reached a NetworkInterface, every node in the estate would share an address and runZero
  could merge the whole estate onto one asset. `lo`/`lo0`/`loopback` are dropped by device
  name, and `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, and `fe80::/10` are
  removed from every address list. An all-zero MAC is treated as absent. A node whose only
  address is loopback — a container, or a host that has not brought up a real NIC — is
  imported with **no** network interface at all; its raw values remain in `puppetdb_fact_ip`
  and `puppetdb_fact_mac`. This case is covered by a fixture.
- **Both structured and legacy fact names are requested.** Facter 4 emits structured facts
  and PuppetDB stores each one whole, so `networking` arrives as a single row whose value is
  the entire nested hash. The flat legacy names (`operatingsystem`, `serialnumber`,
  `ipaddress`, `macaddress`, …) are requested alongside them, because a Puppet agent still
  ships those and a node inventoried by an older or non-Facter fact source may report only
  those. Every mapping tries the structured path first and falls back to the flat name; a
  node with legacy facts only still gets its OS, serial, manufacturer, model, and one
  interface.
- **Timestamps, and why they are clamped.** PuppetDB serializes these as ISO-8601 with an
  explicit `Z`, but the shape is validated with a regex before `parse_time` sees it, because
  a value without an offset aborts the whole script and cannot be caught.
  `lastSeenTS` is the most recent of `report_timestamp`, `facts_timestamp`, and
  `catalog_timestamp` — all three are agent check-ins, and PuppetDB guarantees at least one
  is non-null. Each is **clamped to the start of the run before being assigned**: a
  timestamp in the future fails validation of the entire ImportAsset, not just that field,
  so a node with a fast clock — or a PuppetDB server with one — would otherwise be dropped
  from the import silently. The raw values are always kept as
  `puppetdb_report_timestamp`, `puppetdb_facts_timestamp`, and
  `puppetdb_catalog_timestamp`, so a clamped value is still visible.
  `firstSeenTS` is deliberately **not** set: PuppetDB records no creation time for a node,
  and backfilling it from a check-in time would make first-seen move on every poll.
- **No software by default, and no services or vulnerabilities at all.** Facter reports no
  package inventory — this is worth saying plainly rather than working around, because the
  temptation is to synthesize software from facts like `puppetversion` and produce an
  inventory that looks real and is not. PuppetDB likewise has no listening-port data of any
  kind and no vulnerability object; nothing is invented for either. The one genuine source
  of installed software is `GET /pdb/query/v4/package-inventory`, which returns `certname`,
  `package_name`, `version`, and `provider`. Package collection is a **Puppet Enterprise**
  feature and is off even there until `package_inventory` is enabled, so `include_packages`
  defaults to false and an open-source PuppetDB answers the query with an error that switches
  the feature off for the rest of the run rather than failing it. `cpe23` is never set:
  PuppetDB publishes no CPE, and `Software.cpe23` accepts only the CPE 2.2 `cpe:/a:`
  application binding, so a synthesized value would fail validation.
- **Packages are fetched per node page, not per node and not per estate.** The
  package-inventory endpoint covers the whole installation, so an unfiltered walk would read
  every package on every node — easily millions of rows. Instead the query is restricted to
  the certnames on the node page currently being built, in batches of 25, keeping both the
  encoded query string well inside Jetty's default request header limit and the response
  bounded. Packages past the per-asset cap of 99 are discarded as they arrive rather than
  accumulated and thrown away later.
- **Site-specific facts are not guessed at.** A `packages` custom fact exists on some
  estates, but it is not a Facter core fact and its shape is not standardized, so it is not
  mapped onto `Software`. Name it in `extra_facts` and it will be imported as a custom
  attribute verbatim.
- **Rate limiting.** PuppetDB publishes no rate limit and returns no `X-RateLimit` headers.
  Transient statuses (408, 425, 429, 500, 502, 503, 504) and transport errors are retried
  with exponential backoff by the shared HTTP helper, which honors `Retry-After`. Verified
  against a fixture that returns 429 for two of every three requests.
- **Degradation.** A failure of the fact walk logs one line and the run continues, importing
  nodes without facts. A failure of the package query switches packages off for the rest of
  the run. Only a failure of the node list itself ends the run. A response body that is not
  valid JSON is surfaced as an error by the HTTP helper rather than aborting the script,
  because the script never calls `json_decode` on a response itself.
- **Unverified assumptions.** The `X-Authentication` header is documented for Puppet
  Enterprise services generally and is what `pypuppetdb` sends, but it was not exercised
  against a real PE instance — only against a fixture that asserts the header arrives.
  Likewise, `package-inventory`'s response shape was read from PuppetDB's own
  `package-inventory-query` projection in `query_eng/engine.clj` (`certname`, `package_name`,
  `version`, `provider`) rather than observed on a PE server, since package collection is
  not available in the open-source build. The behavior of a ~45-name `in`/`array` fact filter
  against a large production fact table has not been measured; if that query is ever
  rejected, the run degrades to importing nodes without facts rather than failing.
- **This integration was validated against local fixtures, not a live PuppetDB.** The
  fixture server implements PuppetDB's actual paging and query-rewriting semantics —
  bare-array responses, row-counted paging, the implicit active-node restriction, and
  `in`/`array` filtering — and the Facter fact shapes were taken from real `facter --json`
  output rather than from the documentation alone.

## Future

- **Resources and catalogs as configuration-state enrichment.** This is the most valuable
  thing PuppetDB holds that this import does not touch.
  `GET /pdb/query/v4/resources` returns every resource in every node's catalog — each
  `package`, `service`, `file`, `user`, and `firewall` rule Puppet manages, with its title,
  parameters, and the class and manifest line that declared it. That is a statement of what
  *should* be true of a node, which is a fundamentally different signal from what runZero
  observes on the wire, and the gap between them is where the interesting findings live: a
  node whose catalog declares `service { 'sshd': ensure => stopped }` while runZero sees 22
  open, or a host with a `firewall` resource permitting a port that no scan can reach
  because something upstream is blocking it. A query as narrow as
  `["and", ["=", "type", "Service"], ["=", ["parameter", "ensure"], "running"]]` would give
  every service Puppet intends to be running, per node, in one paged call. The reason this
  is future work rather than a toggle here is that it does not fit `Software` or `Service`:
  a catalog resource is an *intent*, and importing it as an observation would misrepresent
  it. It wants either a dedicated attribute namespace or a runZero object type that models
  declared-versus-observed.
- **Report status as a configuration-drift signal.** `latest_report_status` and
  `latest_report_corrective_change` are already imported as attributes, but the richer data
  is at `GET /pdb/query/v4/reports` and `GET /pdb/query/v4/events`, which give the individual
  resource events of each run: what changed, what failed, what was corrected, and whether the
  run was `noop`. A node whose Puppet runs have been failing for a week is a node whose
  configuration is drifting and whose patches are not landing — and it is invisible to
  scanning, because a drifting host looks identical to a healthy one from outside. A future
  revision could turn `latest_report_status = failed`, or a node that stopped reporting
  entirely while still answering scans, into a first-class runZero signal. The
  `["=", "latest_report_status", "failed"]` filter makes this cheap to compute.
- **PQL as an on-demand query surface.** Everything above assumes a scheduled bulk import,
  but PuppetDB's real strength is ad-hoc querying, and PQL exists specifically so that
  queries can be written by humans:
  `inventory[certname] { facts.os.name = "RedHat" and facts.os.release.major = "8" }` is a
  complete question about the estate. A lookup-style integration — take a runZero asset,
  ask PuppetDB what it knows about it, show the answer inline — would fit that far better
  than a nightly import, and the `/pdb/query/v4/inventory` endpoint is built for it: it
  returns one row per node with every fact as a single hash and supports dot-notation on
  `facts` and `trusted`. It was not used for the bulk import here precisely because it
  returns *every* fact, which is the wrong trade for a scheduled full-estate walk and the
  right one for a single-node lookup.
- **Puppet-coverage-gap reporting.** The inverse of this import is the report a platform
  team actually acts on. Because every imported asset is stamped
  `custom_integration:puppetdb`, the gap is already expressible as a runZero search: a
  server on a managed subnet that PuppetDB has never heard of has no configuration
  management, no enforced baseline, and no audit trail. The data imported here already
  splits the population three ways — nodes Puppet manages and that report facts, nodes
  PuppetDB knows about but that have gone quiet (`report_timestamp` stale, or deactivated
  and expired, which is why `include_inactive` exists), and hosts runZero sees that PuppetDB
  does not. The third group is the one that matters, and the second is the one that gets
  missed, because a node that silently stopped reporting looks fine in Puppet's own console
  until somebody goes looking.
- **Outbound is not a fit, and it is worth saying so.** PuppetDB has a command API
  (`POST /pdb/cmd/v1`) that accepts `replace_facts`, `replace_catalog`, `store_report`, and
  `deactivate_node`. It would be technically possible to push runZero's view of the estate
  in as fact sets. It should not be done. PuppetDB is a *derived* store: its contents are
  supposed to be the output of Puppet agent runs, and writing synthetic facts into it would
  corrupt the exported-resource collection and the ENC data that Puppet Server itself reads
  back out, potentially changing what gets provisioned onto real machines. The one command
  with a defensible use case is `deactivate_node`, and even that belongs to Puppet's own
  lifecycle tooling rather than to a scanner.
- **Incremental import.** The nodes endpoint supports inequality operators on timestamps, so
  `[">", "facts_timestamp", "<last run>"]` would fetch only nodes that have checked in since
  the previous poll — a large saving on a big estate. The `environment` parameter already
  allows manual partitioning today; making the time filter automatic would require the
  integration to persist the previous run's timestamp, which the custom integration
  framework does not currently offer.

## API documentation

- PuppetDB query API overview and query structure (endpoints, the `query` parameter, the two
  query languages): https://help.puppet.com/pdb/current/topics/query.htm
- Nodes endpoint — response fields, and the statement that deactivated and expired nodes are
  excluded: https://help.puppet.com/pdb/current/topics/nodes.htm
- Facts endpoint — `certname`/`name`/`value`/`environment` rows, structured facts returned as
  nested JSON: https://help.puppet.com/pdb/current/topics/facts.htm
- Inventory endpoint — the one-row-per-node alternative discussed under Future:
  https://help.puppet.com/pdb/current/topics/inventory.htm
- Paging — `limit`, `offset`, `order_by`, `include_total`, and the warning that ordering is
  not guaranteed without `order_by`: https://help.puppet.com/pdb/current/topics/paging.htm
- AST query language — `extract`, `from`, `and`/`or`/`=`, and
  `["in", <field>, ["array", [...]]]`: https://help.puppet.com/pdb/current/topics/ast.htm
- PQL — literal lists and the `in` operator, and the note that PQL is accepted only on the
  root endpoint: https://help.puppet.com/pdb/current/topics/pql.htm
- Facter core facts — the `networking`, `os`, `dmi`, `processors`, and `memory` structures
  this integration maps: https://help.puppet.com/core/current/Content/PuppetCore/Markdown/core_facts.htm
- Puppet Enterprise token-based authentication and the `X-Authentication` header:
  https://help.puppet.com/pe/2025.5/topics/rbac_token_auth_intro.htm
- `voxpupuli/pypuppetdb` — an independent client whose paging parameters (`limit`, `offset`,
  `order_by` as a JSON string, `include_total`, the `X-Records` header) corroborate the
  paging model used here: https://github.com/voxpupuli/pypuppetdb
- The node-state rewriting, the `node_state` values (`active`/`inactive`/`any`), and the
  `package-inventory` projection were read from the PuppetDB source, which is the
  authoritative contract where the documentation is silent:
  `src/puppetlabs/puppetdb/http/query.clj` (`restrict-query-to-active-nodes`,
  `is-active-node-criteria?`) and `src/puppetlabs/puppetdb/query_eng/engine.clj`
  (`package-inventory-query`, `certname-relations`, `remove-elided-nodes`) —
  https://github.com/puppetlabs/puppetdb

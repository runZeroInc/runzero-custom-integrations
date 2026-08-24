# Custom Integration: JumpCloud

JumpCloud is a cloud directory and a device management platform in one product, and that
combination is what makes it worth importing. Most endpoint sources can tell runZero what a
device is; JumpCloud can also tell it **who is bound to that device, and why** — directly, or
through a group whose membership would have to change to revoke the access. That
identity-to-device edge is a first-class object in JumpCloud's graph, and it is the thing this
integration exists to carry into runZero.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the JumpCloud console host over HTTPS (`https://console.jumpcloud.com`, or the EU/India regional host).

## JumpCloud requirements

- A JumpCloud **API key**, generated from the admin profile menu. Keys are issued per administrator
  and inherit that administrator's permissions, so use an account with a read-only or read-only-plus-billing
  role rather than a full administrator.
- Newer keys carry a `jca_` prefix and have a configurable expiry (30–365 days, or never). A key with an
  expiry needs rotating on that cadence or the task will start failing with `401`.
- For a **multi-tenant (MSP) administrator**, the organization ObjectID of the tenant to import.
  JumpCloud requires the `x-org-id` header on every request from a multi-tenant admin and returns `401`
  without it. Single-tenant administrators must **not** send it — JumpCloud returns `403` when the header
  is supplied on a route that does not accept it, which is why this integration only sends it when you
  fill the field in.
- Importing installed software or MAC addresses additionally requires a plan that includes
  **System Insights**, and System Insights must be enabled for the organization and for the individual devices.

## Steps

### JumpCloud configuration

1. Sign in to the [JumpCloud Admin Portal](https://console.jumpcloud.com) as an administrator with a
   read-only role.
2. Click the account initials in the top right, choose **My API Key**, and generate or copy the key.
3. Multi-tenant administrators: list the organizations reachable by that key with
   `curl -H 'x-api-key: <key>' https://console.jumpcloud.com/api/organizations/` and note the `_id` of
   the organization to import.
4. Optional, for software and MAC addresses: go to **Settings > Features** and enable **System Insights**,
   then enable it on the devices you care about under **Device Management > Devices > Insights**.
5. Confirm access with `curl -H 'x-api-key: <key>' 'https://console.jumpcloud.com/api/systems?limit=1'`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "JumpCloud").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **JumpCloud console URL** (`url`): optional; defaults to `https://console.jumpcloud.com`. Use
     `https://console.eu.jumpcloud.com` or `https://console.in.jumpcloud.com` for the EU and India regions.
   - **Organization ID** (`org_id`): optional; the organization ObjectID, sent as `x-org-id`. Required for
     multi-tenant administrators, and must be left blank for single-tenant administrators.
   - **API key** (`api_key`): the JumpCloud API key, sent as `x-api-key`.
   - **Import bound users** (`include_bound_users`): optional; default **on**. Resolves the directory users
     bound to each system. Costs one request per system plus one pass over the user directory.
   - **Import installed software** (`include_software`): optional; default off. Requires System Insights.
   - **Import MAC addresses** (`include_mac_addresses`): optional; default off. Requires System Insights.
   - **Per-system detail limit** (`detail_system_limit`): optional; default 1000. Caps how many systems are
     queried for bound users, software, and MAC addresses.
   - **Page size** (`page_size`): optional; default 100, which is also JumpCloud's documented maximum.
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
runzero script --filename jumpcloud/jumpcloud.star \
  --kwargs url=https://console.jumpcloud.com \
  --kwargs api_key=jca_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r \
  --kwargs include_bound_users=true \
  --kwargs include_software=false \
  --kwargs include_mac_addresses=false \
  --kwargs detail_system_limit=25 \
  --kwargs page_size=100 \
  --output ./jumpcloud-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`url` is optional and defaults to `https://console.jumpcloud.com`; set it to
`https://console.eu.jumpcloud.com` or `https://console.in.jumpcloud.com` for those regions.

**Do not pass `org_id` unless you are a multi-tenant administrator.** JumpCloud returns
`401` to a multi-tenant admin that omits the `x-org-id` header and `403` to a single-tenant
admin that sends it, so the parameter is left out of the example above deliberately. Add
`--kwargs org_id=<objectid>` only if your account administers more than one organization.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Cap `detail_system_limit` on a first run. Bound users, software, and MAC addresses are each
a per-system request on top of the system list, so the limit is what keeps a smoke test from
walking the whole directory. `include_software` and `include_mac_addresses` additionally
need System Insights enabled on the individual devices; with it off they simply return
nothing rather than failing.

To check the `CONFIG` block and the HTTP and TLS wiring without touching a real tenant:

```bash
runzero script --filename jumpcloud/jumpcloud.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove JumpCloud accepts the key or that any system is parsed.

The recorded API shapes, including paging with the per-system detail cap and a System
Insights response, are exercised by the fixture suite:

```bash
python3 tests/run.py jumpcloud
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat jumpcloud/jumpcloud.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://console.jumpcloud.com,api_key=<key>' \
  --output ./jumpcloud-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from JumpCloud.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:jumpcloud`.

## Asset identity

- Target entity: a physical or virtual host running the JumpCloud agent — laptop, desktop, or server.
- Source ID field: `_id` on each element of the `results` array returned by `GET /api/systems`.
- Documentation evidence: the v1 OpenAPI document (`https://docs.jumpcloud.com/api/1.0/index.yaml`) defines
  the `systemslist` response as `{results: [system], totalCount: integer}` and the `system` schema's first
  property as `_id`. It is the resource key every other JumpCloud endpoint addresses a system by:
  `GET /api/systems/{id}`, `GET /api/v2/systems/{system_id}/users`,
  `GET /api/v2/systems/{system_id}/associations`, and the `system_id` column that every System Insights row
  carries as a required, non-nullable string. It is a Mongo-style 24-character ObjectID.
- Uniqueness scope: the organization. A JumpCloud API key belongs to an administrator, and a multi-tenant
  administrator can address several organizations with the same key by varying the `x-org-id` header; the
  ObjectID space is not shared between them. The regional consoles (US, EU, India) are separate systems
  with separate data residency and are a second, coarser boundary.
- Cardinality: one row per enrolled system per poll. Bound users, installed applications, and adapter
  details are child records joined onto the system, not separate assets. `GET /api/v2/systems/{id}/users`
  returns many rows for one system, and every System Insights row carries the `system_id` it belongs to.
- Stability: survives rename, `displayName` edit, DHCP address change, adapter replacement, reboot, OS
  upgrade, agent upgrade, group membership change, and moving between system groups. It does **not**
  survive uninstalling and reinstalling the agent, or re-imaging the host — JumpCloud treats that as a new
  device enrollment and mints a new ObjectID. `serialNumber` is the hardware-stable value.
- Reuse behavior: not documented. Values are ObjectIDs, which embed a timestamp and a per-process counter,
  so reassignment after a device is deleted is implausible. Treated as non-reusable; this is the one
  identity property taken on inference rather than an explicit contract.
- Presence: present on every record observed and used as the primary key by every sibling endpoint, but it
  is not marked `required` in the published `system` schema, so records arriving without it are skipped
  rather than assigned a synthesized ID.
- Final runZero ID: `jumpcloud:<org-id-or-console-host>:<_id>` — for example
  `jumpcloud:5e0000000000000000000abc:6a0000000000000000000001`, or
  `jumpcloud:console.jumpcloud.com:6a0000000000000000000001` when no organization ID is configured.
- Missing-ID behavior: skip the record and log `skipping system with no _id: hostname=<hostname>`. No
  identifier is invented, and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
- Verdict: **scoped authoritative**.

The namespace is taken from configuration, not from the record. The `system` object does carry an
`organization` field, but the same reasoning the Absolute integration used applies here: a value known
from configuration before any record is parsed can never go missing mid-import, whereas a per-record field
can. When an organization ID is configured it *is* the real uniqueness boundary and is used directly. When
it is not — the single-tenant case, where JumpCloud forbids sending the header at all — the regional
console host is the next real boundary, and it is stable for the life of the tenant. `organization` is
preserved as the `jumpcloud_organization` custom attribute either way, so the record's own view is never
lost.

One consequence is worth stating plainly: **switching a working task from a blank organization ID to a
populated one re-identifies the whole estate**, because the namespace changes. Multi-tenant administrators
should set the field before the first run. Single-tenant administrators should leave it blank permanently.

`matchBehavior` keeps `_id` as the merge signal while stopping network churn from fragmenting a device.
The reasoning is specific to what JumpCloud actually reports. This is an agent-based source, largely
covering roaming laptops: `networkInterfaces` holds whatever addresses the host had at its last check-in,
which for a laptop is routinely a coffee-shop or home DHCP lease; `displayName` is operator-editable;
and — most importantly — **the system inventory publishes no MAC address at all** unless System Insights is
licensed and enabled. A device that reports no MAC on Monday and a MAC on Tuesday, because an administrator
turned System Insights on, must not fragment into two assets. Allowing a MAC/IP/name mismatch to
*disqualify* a merge would be exactly wrong. The serial number is emitted both as a `serial:` tag and as
the `jumpcloud_serial_number` custom attribute so operators have a hardware-stable pivot for reconciling
records after an agent reinstall, which is the one event that does mint a new `_id`.

`deviceType`, `model`, `osFamily`-derived form factors, and similar guesses are deliberately **not** set.
JumpCloud reports `hwVendor` (mapped to `manufacturer`) but nothing that separates a laptop from a desktop,
and leaving those fields unset lets runZero's own fingerprinting decide rather than overwriting it.

### Notes

- **Two API generations, and the split is load-bearing.** The system inventory only exists on **v1**
  (`GET /api/systems`). Every relationship in the directory graph only exists on **v2**
  (`GET /api/v2/...`). Both live on the same host and take the same `x-api-key` header. This integration
  uses v1 for `GET /api/systems` and `GET /api/systemusers`, and v2 for
  `GET /api/v2/systems/{id}/users`, `GET /api/v2/systeminsights/apps`,
  `GET /api/v2/systeminsights/programs`, and `GET /api/v2/systeminsights/interface_details`.
- **The bound-user path.** `GET /api/v2/systems/{system_id}/users` is the endpoint used, and it is the
  correct one. The v2 specification describes it as returning "all Users bound to a System, **either
  directly or indirectly** essentially traversing the JumpCloud Graph for your Organization". The nearby
  `GET /api/v2/systems/{system_id}/associations?targets=user` returns only the **direct** associations and
  would silently miss every user who reaches a device through a user group, which is how most JumpCloud
  estates are actually administered. `GET /api/v2/systems/{system_id}/memberof` returns system groups, not
  users. The v1 endpoint `GET /api/systems/{id}/systemusers` still appears in JumpCloud's generated Python
  SDK, but it is **absent from the current v1 specification** and is documented there as being for
  "users still using JumpCloud Tags", a deprecated model; it is not used.
- **Bound users need one request per system.** The graph endpoint returns user ObjectIDs and paths, not
  usernames, and no bulk system-to-users endpoint exists. Rather than resolving each ID with its own
  request, the script walks `GET /api/systemusers` once and builds an ObjectID-to-username map, then joins
  locally. Cost is therefore one pass over the directory plus one request per system. The per-system walk
  stops after 50 bound users; when that cap is hit with rows still unread, `jumpcloud_bound_user_count`
  reports a floor (`50+`) and `jumpcloud_bound_users_truncated` is set, so a host bound to a whole
  directory is not mistaken for one with exactly 50 users.
- **Direct versus group-derived bindings are distinguished.** Each returned element carries a `paths` array
  which "enumerates each path from this System to the corresponding User". A path consisting of a single
  connection is a direct system-to-user binding; a longer path arrives through a group. The script splits
  bound users into `jumpcloud_bound_users_direct` and `jumpcloud_bound_users_via_group` on that basis, so
  an operator can see not just who can log in but which grouping would have to change to revoke it. The
  length-one interpretation is inferred from the documented meaning of `paths`, not stated as such in the
  specification.
- **Sudo rights are read from `compiledAttributes`.** The v2 schema names the compiled per-object graph
  attributes `compiledAttributes`; the endpoint's own prose calls it `attributes`. Both spellings are read
  and neither is required, so `jumpcloud_bound_users_with_sudo` is populated when the field is present and
  silently empty when it is not.
- **Local accounts are kept separate from graph bindings.** The system record includes `userMetrics`
  (`userName`, `admin`, `managed`, `suspended`) and `primarySystemUser`, which arrive inline and cost no
  extra request. These describe accounts as the *device* sees them, including unmanaged local accounts,
  rather than as the directory binds them, so they land in their own attributes
  (`jumpcloud_local_users`, `jumpcloud_local_admin_users`, `jumpcloud_local_unmanaged_users`,
  `jumpcloud_primary_user`) and are never merged into the bound-user attributes. See the unverified
  assumptions below.
- **Pagination is offset based, not page based**, and the sort is pinned. Every v1 list endpoint takes
  `limit` (documented "Limited to 100") and `skip` (offset), and answers with
  `{"results": [...], "totalCount": N}` — not a bare array. The v2 graph and System Insights endpoints take
  the same `limit`/`skip` pair but answer with a **bare JSON array** and no total, so those loops stop when
  a page returns fewer records than requested. Every `skip`-paginated v1 call also sends `sort=_id`, because
  JumpCloud's own API guidance is that paging on `skip` over the default ordering can return a record twice
  and miss another. For a device inventory a silently dropped system is the worst possible failure.
- **The two generations disagree on filter syntax.** v1 filter operators are dollar-prefixed (`$eq`); the v2
  System Insights collections take bare operators (`eq`). Only the v2 form is used here, as
  `filter=system_id:eq:<id>`.
- **System Insights is checked before it is called.** Every system record carries
  `systemInsights.state` (`enabled`, `disabled`, or `deferred`). When software or MAC import is enabled, the
  script reads that field first and skips the request entirely for any system that is not `enabled`,
  reporting the count at the end. That turns the common "licensed but not enabled everywhere" case into
  zero wasted requests.
- **MAC addresses come from System Insights, or not at all.** The v1 `system` object publishes no MAC, and
  its `networkInterfaces[]` entries carry only `{name, address, family, internal}`.
  `GET /api/v2/systeminsights/interface_details` does publish `mac` alongside `interface`, so with
  **Import MAC addresses** enabled the script joins those MACs onto the matching adapter **by adapter name**.
  MACs are only attached to adapters that already carry a usable address: System Insights also enumerates
  loopback, tunnel, and hypervisor adapters, and turning those into MAC-only interfaces would hand runZero
  a pile of identical VMware and Hyper-V MACs to merge unrelated hosts on. All-zero MACs are dropped.
- **Network interfaces are regrouped by adapter.** JumpCloud emits one `networkInterfaces` entry per adapter
  *per address family*, so a dual-stack `en0` appears twice. Entries are regrouped on the adapter name so
  that adapter becomes one interface rather than two.
- **Loopback and link-local addresses are dropped.** Entries flagged `internal: true` are loopback by
  definition and are excluded, as are `127.0.0.0/8`, `::1`, `0.0.0.0`, `169.254.0.0/16`, and `fe80::/10`.
  An agent that reports only a loopback address would otherwise merge every such host onto one runZero
  asset. The unfiltered list is preserved as `jumpcloud_network_addresses`, and a host whose only address
  is loopback is still imported — identified by its `_id`, with no network interface at all.
- **`remoteIP` is deliberately not attached to an interface.** It is the NAT egress address the agent was
  last seen from, shared by every device behind one gateway. It is kept as `jumpcloud_remote_ip`.
- **Hostnames are filtered.** `hostname` is reported by the host itself and used directly. `displayName`
  defaults to the hostname but administrators routinely rewrite it into a human label
  (`Jane's MacBook Pro`), so it is only promoted to a hostname when it is still hostname shaped. The raw
  value is always kept as `jumpcloud_display_name`.
- **Software.** With `include_software` enabled, macOS systems are read from
  `GET /api/v2/systeminsights/apps` and Windows systems from `GET /api/v2/systeminsights/programs`, both
  filtered server-side on `system_id`. The specification is explicit that apps covers macOS and programs
  covers Windows; **Linux systems populate neither**, so no software request is made for them. macOS maps
  `bundle_name` to product (the sibling `name` carries a `.app` suffix), `bundle_short_version` to version,
  and `path` to `installedFrom`. Windows maps `name`, `version`, `publisher` to vendor, and
  `install_location`. Neither table publishes a CPE, so `Software.cpe23` is left unset rather than
  synthesized. Windows `install_date` is a bare `YYYYMMDD` string, not a timestamp, so it is kept verbatim
  as a software custom attribute rather than parsed.
- **No vulnerabilities, no ports, no services.** JumpCloud is a directory and device management platform,
  not a scanner. It publishes no CVE data and no port or listening-service inventory, so this integration
  imports no `Vulnerability` and no `Service` records. Nothing is synthesized to fill the gap.
- **Timestamps.** `created` becomes `firstSeenTS` and `lastContact` becomes `lastSeenTS`, assigned after
  construction because the `ImportAsset` constructor rejects `lastSeenTS`. Both are RFC 3339 with a `Z`
  designator and optionally milliseconds (`2013-10-16T19:30:55.611Z`), and `lastContact` is documented
  nullable. Values that carry no zone designator would abort `parse_time` outright, so anything without one
  is normalized before parsing and anything unrecognized is kept verbatim as a custom attribute instead. Since that
  normalization reads a zone-less value as UTC, both timestamps are **clamped to the current time** before
  assignment: runZero rejects an asset whose first- or last-seen time is in the future and the error fails the
  entire record, so a source reporting local time east of UTC would otherwise have every asset dropped. The clamp
  skews first-seen and last-seen toward the present instead of losing the asset.
  The System Insights `collection_time` is a *different* format with no zone at all
  (`2019-06-03T19:41:30`) and is never parsed — it is stored as a software custom attribute as-is.
- **Rate limiting.** JumpCloud documents `429 Rate limit exceeded` and advises "apply sufficient backoff;
  retry with a considerably less frequent request rate", but **publishes no numeric limit** and documents
  no `Retry-After` or `X-RateLimit-*` header. The shared HTTP helper retries transient failures — including
  429 — up to three times with exponential backoff by default, honoring `Retry-After` when the server does
  send it, so no explicit opt-in is needed. Because bound-user resolution costs one request per system, a
  large estate is the thing most likely to discover JumpCloud's real limit; `detail_system_limit` exists to
  bound that, and both System Insights options are off by default.
- **Unverified assumption: `userMetrics` semantics.** The v1 specification declares the field and its
  sub-fields but gives them no descriptions. The presence of a `managed` boolean strongly implies these are
  local OS accounts observed on the device, some of which are not JumpCloud-managed — which is why they are
  imported under `local_*` attributes and kept strictly apart from the graph bindings. If they turn out to
  mean something narrower, the `local_*` attributes are wrong but the `bound_*` attributes, which come from
  the graph endpoint, are unaffected.
- **Unverified assumption: System Insights failure mode when unlicensed.** The v2 specification declares
  only a `200` response for both software endpoints and for `interface_details`, so what an unlicensed
  organization receives is undocumented. The script treats *any* error from those endpoints as "no data",
  logs it once rather than once per system, and continues — so an unlicensed tenant that enables the option
  by mistake still gets a complete asset import.
- **Unverified assumption: ObjectID reuse.** Covered in the identity record above.
- **Known runner limitation during validation.** The 429 fixture case was verified with an explicitly
  passed `retries=3` rather than the platform default, because the locally built test runner predates the
  change that made `retries` default to `3`. The current platform source sets `defaultJSONRetries = 3`, so
  the shipped script relies on the default and does not set `retries` itself; the retry path itself was
  exercised end to end and does recover from two consecutive 429s.
- This integration was validated against local fixtures, not a live JumpCloud tenant.

## Future

- **JumpCloud as an outbound target.** JumpCloud exposes full CRUD on systems and groups, so runZero
  context could be pushed back into the directory. The safe, non-destructive shape is
  `PUT /api/systems/{id}`, whose `systemput` body accepts `displayName`, `tags`, and `attributes` (a list
  of key/value pairs) — writing the runZero asset URL, discovered criticality, or observed service exposure
  into `attributes` would let JumpCloud admins see runZero's view without leaving their console, and would
  do so without touching any field the agent itself owns. Note the body does **not** accept a free-text
  `description`, so `attributes` is the only real vehicle.
  `POST /api/v2/systemgroups/{group_id}/members`
  could likewise drive membership from a runZero query, for instance putting every system runZero has seen
  exposing RDP into a "needs review" group.
  **Anything that changes device policy is a different risk class and should not be automated from a
  scheduled sync.** System groups in JumpCloud carry policies, and adding a system to the wrong group can
  push a configuration change — FileVault enforcement, an SSHD rewrite via `/api/systems/updateAuthConf`,
  a password policy — to a live fleet. The built-in command endpoints
  (`POST /api/systems/{system_id}/command/builtin/{erase,lock,restart,shutdown}`) are outright destructive;
  `erase` is irreversible. Those belong behind explicit, per-device, human-confirmed action, never an
  unattended task.
- **System Insights as a much deeper enrichment surface.** This integration touches three of roughly thirty
  System Insights tables. `system_info` (hardware vendor, model, CPU, memory, board serial) would fill in
  `model` and hardware detail the v1 system object cannot supply; `os_version` gives an authoritative build;
  `patches` (Windows) and `disk_encryption` give patch and encryption posture; `usb_devices` gives peripheral
  inventory; `logged_in_users` gives live session data; `browser_plugins`, `chrome_extensions`,
  `firefox_addons`, and `safari_extensions` give a browser-extension inventory that is genuinely hard to get
  any other way. All of them use the same `filter=system_id:eq:<id>` join and the same pagination, and the
  `limit` ceiling on the System Insights collections is **10000** rather than 100 — so a bulk pull with
  client-side grouping, rather than the per-system calls used here, would be the right shape for a
  wide enrichment pass.
- **The directory side, as identity context runZero does not otherwise get.** `GET /api/systemusers`,
  `GET /api/v2/usergroups`, and the SSO application endpoints (`GET /api/v2/applications`, and
  `GET /api/v2/applications/{id}/users`) describe who exists, what they belong to, and which SaaS
  applications they can reach. runZero has no other source for that. Combined with the device bindings this
  integration already imports, it would support questions no network scanner can answer alone: which
  applications are reachable by the owner of a device that is failing a policy, or which suspended accounts
  still hold a binding to a live host. `GET /api/v2/directories` and `GET /api/v2/ldapservers` would extend
  the same picture to federated sources.
- **Agent coverage-gap reporting.** This is the highest-value follow-on and needs no new endpoint. Once
  JumpCloud inventory is in runZero, a saved query for hosts runZero has discovered on the network that
  carry no `custom_integration:jumpcloud` source is a direct list of unmanaged devices. The inverse is
  equally useful and uses fields already imported: systems with `jumpcloud_active` false or a stale
  `lastSeenTS` are devices JumpCloud believes it manages but that nothing has seen — decommissioned
  hardware still holding a directory binding. No directory can produce either list from its own data,
  because a device it never enrolled is a device it cannot see.
- **Event ingestion is possible but is a separate integration.** JumpCloud publishes a Directory Insights
  API — `POST /events` on `https://api.jumpcloud.com/insights/directory/v1` (with `api.eu.` and `api.in.`
  regional variants) — covering directory, system, SAML, RADIUS, LDAP, and MDM events over a requested time
  window, alongside `/events/count`, `/events/distinct`, and `/events/interval`. It is a genuine pull API,
  unlike a webhook-only feed, so a scheduled integration carrying a high-water mark between runs could
  attach device authentications and Full Disk Encryption key updates to the originating system. It is out
  of scope here because it is a third API generation on a **different host** from the console API, with its
  own POST-body query model, its own pagination, and its own retention limits.

## API documentation

- JumpCloud v1 API reference and OpenAPI document (authentication, `x-org-id` multi-tenant header rules, `limit`/`skip` pagination, the `systemslist` envelope, and the full `system` schema used for the field mapping and the identity decision): <https://docs.jumpcloud.com/api/1.0/index.html> and <https://docs.jumpcloud.com/api/1.0/index.yaml>
- JumpCloud v2 API reference and OpenAPI document (the graph traversal endpoints, `GraphObjectWithPaths`, and the System Insights collections with their distinct filter syntax and 10000 `limit` ceiling): <https://docs.jumpcloud.com/api/2.0/index.html> and <https://docs.jumpcloud.com/api/2.0/index.yaml>
- Best practices for the JumpCloud API (response codes including 429, backoff guidance, and the recommendation to pin `sort=_id` when paginating with `skip`): <https://jumpcloud.com/support/best-practices-jumpcloud-api>
- JumpCloud API keys — issuance, `jca_` prefix, expiry, and per-administrator scoping: <https://jumpcloud.com/support/jumpcloud-apis>
- System Insights — licensing, org-level and per-device enablement, the 60-minute collection interval, and 90-day retention: <https://jumpcloud.com/support/system-insights>
- Manage associations of a system (the v2 association model that superseded the deprecated v1 tag-based binding endpoint): <https://docs.jumpcloud.com/2.0/systems/manage-associations-of-a-system>
- JumpCloud Directory Insights OpenAPI document, cited in the Future section for the event-ingestion host and endpoints: <https://docs.jumpcloud.com/api/insights/directory/1.0/index.yaml>
- `TheJumpCloud/jcapi-python` generated SDK, used for endpoint naming and cross-checking; note its model docs are stale relative to the published specification and omit `serialNumber`, `osVersionDetail`, `mdm`, and `userMetrics` among others: <https://github.com/TheJumpCloud/jcapi-python>

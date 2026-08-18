# Custom Integration: OpenNMS Horizon

Imports monitored **nodes** from OpenNMS Horizon, with their IP interfaces,
their SNMP interfaces and the MAC addresses attached to them, their monitored
service names, and their **asset records** — the 50-plus-field inventory OpenNMS
keeps beside every node, of which the 20 fields describing the device rather
than the poller are imported: manufacturer, model, serial number, operating
system, department, building, room, rack, circuit id, and the rest.

The thing that makes OpenNMS unusually cheap to read is a modelling decision
nobody advertises: an IP interface record **inlines the entire SNMP interface
object** rather than referring to it by id. So a single estate-wide call to
`/api/v2/ipinterfaces` returns every address in the estate already paired with
the physical address of the port it is configured on, with no join and no
per-node request. This integration reads a whole OpenNMS install in four
requests plus paging, not one request per node — which matters, because OpenNMS
is the NMS that survives in service provider and large-enterprise networks,
where the estate is thousands of nodes and a naive N+1 walk is the difference
between a task that finishes and a task that times out.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the OpenNMS web UI. Horizon listens on **TCP 8980** by default (`org.opennms.netmgt.jetty.port = 8980`) and serves the application under the **`/opennms`** context path, so the ReST base is `http://opennms.example.com:8980/opennms/rest/`.
- OpenNMS is self-hosted, frequently behind an internal CA or a self-signed certificate, so `OPTIONS_TLS` is exposed. Nothing is skipped by default.

## OpenNMS Horizon requirements

- **HTTP Basic authentication**, and a user whose security roles permit reading the ReST API. The vendor is explicit that the server does not challenge you first: *"By default, you will not receive a challenge, so you must configure your REST client library to send basic authentication proactively."* This integration sends the `Authorization` header on the very first request for exactly that reason.
- **Horizon 20.1 or newer** for the fast path. The `/opennms/api/v2` tree arrived in 20.1 and is still described by OpenNMS as *"a new experimental ReST API … This API is still subject to change."* Against an older or otherwise unavailable v2 tree the integration falls back to one `/rest/nodes/{id}/ipinterfaces` request per node — correct, but far slower, and capped.
- The `Accept: application/json` header. OpenNMS answers XML otherwise: *"To receive JSON-encoded responses, you must send the `Accept: application/json` header with the request."* The integration always sends it.
- Nothing has to be enabled first. The ReST API is part of the web application and is on by default; there is no module to switch on and no licence tier involved.

### Creating the credential in OpenNMS

1. Sign in to the OpenNMS web UI as `admin` (or another account holding **ROLE_ADMIN**).
2. Click **Administration → Configure OpenNMS** in the side menu. Under **OpenNMS System**, click **Configure Users, Groups and On-Call Roles**. On the Users and Groups page, click **Configure Users**.
3. Click **Add New User**. Specify a user ID and password, confirm the password, and click **OK**. Use a dedicated account — `runzero-ro` rather than a shared human login — so the reads are attributable and the credential can be revoked on its own.
4. Give the account a role that can read the API. Find the user, click **Modify** beside their name, select the role from the **Available Roles** list, and click **Add**, then **Finish**. Log out and back in for the change to take effect.

   The role names are literal strings and the choice is narrower than it looks. OpenNMS's own Spring Security configuration authorizes `GET /rest/**` and `GET /api/v2/**` to exactly `ROLE_REST, ROLE_ADMIN, ROLE_MOBILE, ROLE_USER`. So:

   - **`ROLE_USER`** — *"Default permissions of a new created user to interact with the Web User Interface."* Sufficient for everything this integration reads, and the least privileged option that works.
   - **`ROLE_REST`** — *"Allow users interact with the whole ReST API."* Also sufficient, and the more honest label for an API account.
   - **`ROLE_ADMIN`** — *"Permissions to create, read, update and delete in the Web User Interface and the ReST API."* Far more than this integration needs; do not use it.
   - **`ROLE_READONLY`** — *"Limited to just read information…no possibility to change Alarm states."* **This one is a trap.** Despite the name it is not a ReST role at all: it appears in the security configuration only as a *negative* clause (`… and !hasRole('ROLE_READONLY')`) on alarm-modifying calls, and never in a rule that grants access to `/rest/**` or `/api/v2/**`. A user holding only `ROLE_READONLY` will be rejected on every call this integration makes.

   Assigning nothing usable produces the classic failure: the login form accepts the account, the API refuses every request, and the task imports nothing.

5. Confirm the credential from the Explorer host before configuring anything in runZero. This is the exact first request the integration makes:

   ```bash
   curl -s -u 'runzero-ro:not-a-real-password' \
     -H 'Accept: application/json' \
     'https://opennms.example.com:8980/opennms/rest/nodes?limit=1&offset=0'
   ```

   A working credential returns a JSON envelope with `count`, `totalCount`, `offset`, and a `node` array. Confirm the v2 tree separately, because its availability is what decides whether the run is fast or slow:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -u 'runzero-ro:not-a-real-password' \
     -H 'Accept: application/json' \
     'https://opennms.example.com:8980/opennms/api/v2/ipinterfaces?limit=1&offset=0'
   ```

   `200` means the fast path is available. **`204` also means it is available** — that is how a v2 endpoint reports an empty result set, and the integration reads it as "no more records" rather than as an error. `404` means the v2 tree is not there and the per-node fallback will be used.

**Two things could not be established from the documentation available; confirm
them on your own version rather than trusting them here.** The admin menu labels
have drifted — current documentation gives **Administration → Configure OpenNMS**
in the side menu, older Horizon releases reached the same page through a gear
icon at the top right, and some releases also expose a newer
**User Management → Manage Users** entry. And OpenNMS does not document which
HTTP status it returns when a user authenticates but holds no authorized role;
Spring Security conventionally answers `403` there and `401` for bad
credentials, and this integration prints an explicit authentication message for
**both**, so either way the log names the problem. No published rate limit for
the ReST API was found, so none is assumed.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "OpenNMS Horizon").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OpenNMS URL** (`url`): the base URL including the port, e.g. `https://opennms.example.com:8980`. Required; OpenNMS is self-hosted so there is no default host.
   - **Username** (`username`): the account from step 3 above. Required.
   - **Password** (`password`): that account's password. Required.
   - **Application context path** (`context_path`): default `/opennms`. Change this only when a reverse proxy rewrites the path away.
   - **Collect interfaces** (`collect_interfaces`): default enabled. This is where all addressing comes from; turning it off leaves nodes with names only.
   - **Collect SNMP-only interfaces** (`collect_snmp_interfaces`): default enabled. Adds MAC addresses for ports with no IP bound. Requires the v2 tree and is ignored on the fallback path.
   - **Record monitored services** (`collect_services`): default enabled. Records each node's service names as a custom attribute.
   - **Per-node request limit** (`detail_limit`): default `1000`, `0` removes the cap. Only consulted on the fallback path.
   - **Records per page** (`page_size`): default `200`, minimum 1, maximum 10000.
   - **TLS options** (`tls_*`) and **HTTP options** (`http_*`): set these if OpenNMS is behind an internal certificate or a proxy.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Node inventory and asset records change slowly, so daily is usually plenty.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from OpenNMS.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:opennms-horizon`.
- Every node carries the tag `opennms`. Node categories become `tag:category:<name>`, the monitoring location becomes `tag:location:<name>`, the provisioning requisition becomes `tag:requisition:<foreignSource>`, the asset record serial becomes `tag:serial:<value>`, and the node type becomes `tag:type:active`.
- Every field lands as a custom attribute under the `opennms_` prefix: `opennms_node_id`, `opennms_label_source`, `opennms_sys_object_id`, `opennms_monitored_services`, `opennms_services_down`, `opennms_primary_interface_address`, and the whole asset record as `opennms_asset_*` (for example `opennms_asset_rack:R12` or `opennms_asset_serial_number:FCW2345X0AB`).

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename opennms-horizon/opennms-horizon.star \
  --kwargs url=https://opennms.example.com:8980 \
  --kwargs username=runzero-ro \
  --kwargs password=not-a-real-password \
  --kwargs page_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/opennms-horizon-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; without it the assets are parsed and discarded.

**One CLI caveat:** `--kwargs` re-reads a pair as CSV once the value contains a
second `=`, so a value containing both `=` and `,` is torn into an extra
parameter the integration never declared. The only free-text value here is
`password`. A password containing a comma alone passes through verbatim and is
fine; one containing a comma *and* an `=` has to be wrapped in double quotes so
it stays a single field (`--kwargs '"password=a=b,c"'`), or configured through
the console credential form rather than passed on the command line.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename opennms-horizon/opennms-horizon.star --validate
```

`python3 tests/run.py opennms-horizon` exercises the fixture scenarios in
`opennms-horizon/tests/fixtures/` — a full four-endpoint collection, a
multi-page walk, an empty server, and a response full of wrong types — against
the real scanner.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://opennms.example.com:8980,username=runzero-ro,password=not-a-real-password'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: one OpenNMS **node** — the thing OpenNMS provisions, polls, and hangs interfaces, services, and an asset record off. A node is a device, not an interface.
- Source ID field: **`id`** on the node record, the primary key of the `node` table.
- Documentation evidence: every sub-resource route in the API is keyed on it — `/rest/nodes/{id}`, `/rest/nodes/{id}/ipinterfaces`, `/rest/nodes/{id}/snmpinterfaces`, `/rest/nodes/{id}/assetRecord`, `/rest/nodes/{id}/hardwareInventory` — and every IP interface and SNMP interface record carries it back as `nodeId`. It is present on every node row.
- Uniqueness scope: **one OpenNMS install**. It is a per-install database sequence with no meaning outside that server, so the id is namespaced on the hostname taken from the configured URL.
- Cardinality: exactly one row per node in the node walk.
- Stability: survives a rename, an address change, an interface being added or removed, a re-scan, and a change of requisition. It changes only if the node is deleted and re-provisioned.
- Reuse behavior: not documented by the vendor. It comes from a database sequence and is not recycled in practice, but that is an inference from the schema rather than a published contract.
- Presence: required, and present on every row observed.
- Final runZero ID: `opennms:<opennms-hostname>:<node id>` — for example `opennms:opennms.example.com:1`.
- Missing-ID behavior: the record is skipped and `opennms: skipping node with no id: label=<label>` is printed, with a total at the end of the run. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**.
- Verdict: **scoped authoritative.** A genuine, stable, non-address vendor identifier that is allowed to drive merges.

The match behavior earns its justification. An OpenNMS node is frequently known
by exactly one of the three correlators: a switch discovered by SNMP has MACs
and no useful hostname, a node provisioned by hand has a label and no MAC at
all, and a node whose reverse DNS never resolved has an address and nothing
else. Letting an absent MAC or a changed address disqualify a merge against an
asset runZero already found would be wrong in all three cases, so the id matches
and breaks while the weaker signals match without breaking.

## Notes

### What is imported

Four requests, plus one more per additional page of each collection:

```
GET /opennms/api/v2/ipinterfaces?limit=200&offset=0     -> "ipInterface"
GET /opennms/api/v2/snmpinterfaces?limit=200&offset=0   -> "snmpInterface"
GET /opennms/rest/ifservices?limit=200&offset=0         -> "monitored-service"
GET /opennms/rest/nodes?limit=200&offset=0              -> "node"
```

| runZero | OpenNMS |
|---|---|
| `id` | node `id` |
| `hostnames` | node `label` (only when `labelSource` is not `A`), `sysName`, and each IP interface `hostName` |
| `networkInterfaces` | `ipInterface.ipAddress` grouped by `ifIndex`, with `snmpInterface.physAddr` as the MAC |
| `os` | `assetRecord.operatingSystem`, falling back to `sysDescription` |
| `manufacturer` / `model` | `assetRecord.manufacturer` (or `vendor`) / `assetRecord.modelNumber` |
| `deviceType` | `assetRecord.category` and `sysDescription`, mapped only where unambiguous |
| `firstSeenTS` / `lastSeenTS` | `createTime` / `lastCapsdPoll` |
| `tags` | categories, location, requisition, serial, node type |
| `customAttributes` | the node record, the whole asset record, and the monitored service names |

No `Service` records are emitted, and no `Software` or `Vulnerability` records.
The reason for the first is specific rather than lazy: an **OpenNMS monitored
service carries no port number anywhere in the data model**. The port a poller
connects to lives in `poller-configuration.xml`, keyed by service name, not on
the service record — so `ICMP`, `SNMP`, and `HTTPS` arrive as bare names.
Inventing `443` for `HTTPS` would be a guess written into runZero's data, so the
names are recorded as `opennms_monitored_services` and the currently-failing
ones as `opennms_services_down` instead.

`deviceType` is mapped with the same caution: only from `sysDescription` strings
that name a class of device unambiguously — `cisco ios`, `fortigate`,
`vmware esxi`, `jetdirect`, and about a dozen more — after first checking the
asset record's own `category`, which an operator set deliberately. Everything
else is left unset so runZero's own fingerprinting decides.

### Two global calls instead of one request per node

`/api/v2/ipinterfaces` and `/api/v2/snmpinterfaces` return the whole estate's
interfaces in one paged walk, indexed in memory by `nodeId` before the node walk
starts. Because the IP interface record inlines its SNMP interface, that one
index already carries both the addresses and their MAC addresses. The SNMP-only
walk exists to cover the other half — switch ports that have a MAC and no IP
bound — and **drops every interface with no physical address as it reads it**,
because on a 48-port access switch those are the overwhelming majority and none
of them tells runZero anything.

If `/api/v2/ipinterfaces` fails, the run prints `the v2 interface collection is
unavailable; falling back to one request per node` and switches to
`/rest/nodes/{id}/ipinterfaces`. That path is capped by `detail_limit` (default
1000) and reports how many nodes were imported without interfaces. The v2 tree
is the fast path but the experimental one; v1 is stable but has no estate-wide
interface collection at all, which is exactly why both are here.

### Pagination is driven by the page, not by the envelope

Both trees page with `limit` and `offset`, and both return `count`, `totalCount`,
and `offset` in the envelope. **None of those three is read.** The walk requests
pages until one comes back shorter than the limit it asked for, because on the
v2 side `totalCount` is computed by a second, separate count query after the
limit and offset are stripped — it describes the matching set rather than the
page in hand, and bounding a loop with it couples the walk to a number the
server computed for a different question.

A limit is always sent, never omitted: both API versions default to
**`DEFAULT_LIMIT = 10`**, so an integration trusting the server's default would
import ten nodes and stop.

The two versions also disagree about how to say "empty", and both answers are
handled. A v2 endpoint returns **`204 No Content` with no body at all**, which
decodes to nothing rather than to an envelope; a v1 endpoint returns `200` with
a populated envelope whose collection key may be absent or an empty array. All
three end a walk, and none is an error.

### Timestamps are epoch milliseconds, and the future is clamped

Every timestamp in the JSON representation — `createTime`, `lastCapsdPoll`,
`lastModifiedDate` — is a bare integer of epoch **milliseconds**, which is
Jackson's default rendering of `java.util.Date`. The ISO 8601 strings that
appear throughout the OpenNMS documentation are the **XML** representation and
never reach a JSON client. A value that is not a run of digits is discarded
rather than guessed at.

`lastCapsdPoll` is clamped to now when it is in the future. This is not
theoretical tidiness: the platform rejects an **entire asset** whose timestamp
is after now, so a node whose last poll was recorded a few seconds ahead of the
Explorer's clock would otherwise be dropped in full rather than losing one field.

### The same id is a string here and a number there

OpenNMS types its identifiers inconsistently, and the inconsistency is between
two records that have to be joined: a node's own `id` is the JSON **string**
`"1"`, while the `nodeId` on every interface referring to that node is the
**number** `1`. Every value used as a join key is therefore normalized to text
before it is compared. The same applies to `ifIndex` and `ifType`, which are
numbers on a well-behaved server and have been observed as strings.

### Addresses and names that are not

- **`labelSource` decides whether the node label is a hostname.** OpenNMS records how it chose the label: `H` hostname, `S` sysName, `N` netbios, `U` user-defined, and `A` **address**. When it is `A` the label *is* the IP address, and importing it as a hostname would put a placeholder into runZero's name field, so it is refused.
- **An interface `hostName` is the reverse-DNS name when one resolved and a copy of the IP address when it did not**, so anything that parses as an address is refused as a name.
- **`localhost` is refused as well.** OpenNMS monitors the loopback of its own server as a matter of course, and the reverse-DNS name of `127.0.0.1` is `localhost` almost everywhere — a name that would otherwise be offered as a merge signal by every OpenNMS node carrying a loopback interface.
- **Loopback, unspecified, and link-local addresses never reach an interface.** `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/32`, `::1/128`, `::/128`, and `fe80::/10` are dropped. Loopback would be filtered by the platform anyway; APIPA would not, and two hosts that both failed DHCP are not the same host.
- **A physical address of twelve zeroes is discarded.** OpenNMS stores a MAC as twelve bare hex characters with no separators and inconsistent case — the provisioner lower-cases what it normalizes from an ASCII SNMP response while a raw six-byte response is stored as-is — so nothing is reformatted before normalization, which accepts either.

### Interfaces are grouped by ifIndex, and duplicates are pooled

Addresses are grouped by the SNMP `ifIndex` that ties them to a physical port.
Ports reporting the **same MAC** — a LAG and its members, a VLAN interface and
its parent — are one endpoint as far as runZero is concerned, so their addresses
are pooled onto one interface instead of being emitted several times. Interface
types describing a software construct rather than a port are dropped outright:
`24` softwareLoopback, `53` propVirtual, `131` tunnel, `150` mplsTunnel. An
address OpenNMS never correlated to an SNMP interface has no `ifIndex` at all,
and those are pooled onto a single address-only interface rather than scattered
across invented ones.

### Deleted nodes never arrive

OpenNMS soft-deletes a node by setting its type to `D`. The v1 `/rest/nodes`
resource adds `Restrictions.ne("type", "D")` whenever no explicit `type`
parameter is supplied, so a decommissioned node is filtered out by the server
before this integration sees it. The `type` mapping is still applied
defensively, which is why `tag:type:active` appears on every node and
`tag:type:deleted` is possible but should never be observed.

### Verification status

Verified against the four fixture scenarios in `opennms-horizon/tests/fixtures/`
run under the real scanner, and against OpenNMS documentation and OpenNMS source.
The fixture payloads are built from the shape of real OpenNMS ReST captures —
the server's own `v1/nodes.json` and `v1/ifservices.json` test resources, which
`NodeRestServiceIT` and `IfServicesRestServiceIT` compare live responses against
— with every value replaced by a synthetic one. Envelope keys and field names
come from the JAXB-annotated model classes (`OnmsNodeList`, `OnmsIpInterfaceList`,
`OnmsSnmpInterfaceList`, `OnmsNode`, `OnmsIpInterface`, `OnmsSnmpInterface`,
`OnmsAssetRecord`); the `DEFAULT_LIMIT = 10`, the `204` on an empty v2 result,
and the deleted-node filter come from the ReST resource classes themselves.

**Not verified against a live OpenNMS server.** Three specific claims are the
weakest: the exact admin menu labels, which have drifted between Horizon
releases; the HTTP status returned when a valid user holds no authorized role;
and the report — in this repository's own research notes, not in vendor
documentation — that a single-element collection is sometimes serialized as an
object rather than a one-element array. No capture reproducing that last case
was found, and current OpenNMS emits an array for a one-element list, but a
server that did return an object would have that collection read as empty rather
than as one record.

## Future

- **Hardware inventory.** `/rest/nodes/{id}/hardwareInventory` returns the `OnmsHwEntity` tree — ENTITY-MIB physical entities with model, serial, firmware, and software revision per chassis, module, and transceiver. Genuine component-level inventory, and the single best remaining source here. It costs a request per node, so it would want its own opt-in parameter and its own cap.
- **Monitored services as real services.** The names are already imported; turning them into `Service` records needs the port, which lives in `poller-configuration.xml` — readable over the ReST configuration endpoints by an admin-role account, not by a read-only one. A name-to-port table shipped with the integration would be a guess; reading the server's own configuration would be correct but raises the privilege required.
- **Outages and availability.** `/api/v2/outages` supports FIQL and reports current and historical outages per service. "Down for six days" is a strong signal that an asset is decommissioned rather than missing.
- **FIQL server-side filtering.** The v2 endpoints accept `_s=`, for example `_s=node.foreignSource==Servers`, so a large estate could be narrowed to one requisition or one category at the server rather than in the Explorer. This wants a parameter and a decision about what happens when the expression is wrong, since a bad FIQL string is answered with an error rather than an empty set.
- **Multi-location awareness.** Node `location` is already a tag; with OpenNMS Minions it is a real topology fact worth mapping onto runZero sites rather than a label. `/rest/requisitions` would supply the provisioning intent behind it.

## API documentation

- ReST API overview — https://docs.opennms.com/horizon/latest/development/rest/rest-api.html. Source for the `http://opennmsserver:8980/opennms/rest/` base URL, the HTTP Basic requirement and the "you will not receive a challenge" wording, the `Accept: application/json` requirement, and the `limit`/`offset` parameters.
- Nodes ReST API — https://docs.opennms.com/horizon/latest/development/rest/nodes.html. The `/rest/nodes` walk, the `/rest/nodes/{id}/ipinterfaces` and `/snmpinterfaces` sub-resources used by the fallback path, and the default limit of 10.
- IP Interfaces ReST API — https://docs.opennms.com/horizon/latest/development/rest/ipinterfaces.html. Establishes `/api/v2/ipinterfaces` as read-only and documents `_s`, `orderBy`, `limit`, and `offset`.
- SNMP Interfaces ReST API — https://docs.opennms.com/horizon/latest/development/rest/snmpinterfaces.html. Same for `/api/v2/snmpinterfaces`, including the vendor's own `curl -u admin:admin "http://localhost:8980/opennms/api/v2/snmpinterfaces?..."` example confirming the port and context path.
- Assign User Permissions — https://docs.opennms.com/horizon/latest/operation/deep-dive/user-management/security-roles.html. The role assignment flow, the **Available Roles** list, and the note that roles apply after signing out and back in.
- Administrators Guide, security roles table — https://vault.opennms.com/docs/opennms/releases/26.1.1/guide-admin/guide-admin.html. The verbatim descriptions of `ROLE_USER`, `ROLE_REST`, `ROLE_ADMIN`, `ROLE_READONLY`, and the rest, and the `users.xml` location.
- `applicationContext-spring-security.xml` — https://github.com/OpenNMS/opennms/blob/develop/opennms-webapp/src/main/webapp/WEB-INF/applicationContext-spring-security.xml. The authoritative statement that `GET /rest/**` and `GET /api/v2/**` require `ROLE_REST, ROLE_ADMIN, ROLE_MOBILE, ROLE_USER`, and that `ROLE_READONLY` appears only as a negative clause.
- Horizon 21.1.0 release notes — https://vault.opennms.com/docs/opennms/releases/21.1.0/releasenotes/. "A new experimental ReST API (`/opennms/api/v2`) has been enabled… This API is still subject to change", new in 20.1.
- Securing Jetty with HTTPS — https://docs.opennms.com/horizon/30/operation/admin/https/https-server.html. `org.opennms.netmgt.jetty.port = 8980`, the `https-port` properties, and the warning that enabling HTTPS does not disable the plain-HTTP listener.
- `pyonms` — https://github.com/mattsmithnc/pyonms. An independent Python client whose DAO base confirms the `/rest/` and `/api/v2/` split and HTTP Basic authentication.

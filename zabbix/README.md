# Custom Integration: Zabbix

Imports monitored hosts from Zabbix, with their interfaces, their **host
inventory** — a 70-field structured record covering serial numbers, hardware
model, OS, location, contacts, and asset tags — their tags, and their host
groups.

The inventory is the point. Zabbix is usually thought of as up/down telemetry,
but a site that populates inventory (by hand or automatically from discovery
items) is running a CMDB most people forget they have.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Zabbix **frontend** — the web UI, not the server daemon on port 10051.

## Zabbix requirements

- **Zabbix 6.4 or newer.** API tokens sent as `Authorization: Bearer` were introduced in 6.4 (`ZBXNEXT-8051`, "Authorization method changed from auth parameter to Authorization header"). This integration only implements that path; it does not implement the legacy `user.login` session handshake. Against an older server it reads `apiinfo.version`, tells you plainly that every call is about to fail, and does not silently produce an empty import.
- An **API token**, and a user role that can read the hosts you want.
- Zabbix ships behind whatever TLS the site configured, which for an internal frontend is frequently a self-signed or internal-CA certificate, so `OPTIONS_TLS` is exposed. Nothing is skipped by default.

### Creating the credential in Zabbix

1. Log in to the Zabbix frontend as a Super admin.
2. Create the user the integration will act as, under **Users → Users → Create user**. A dedicated user is better than reusing an admin.
   - On the **Permissions** tab give it the **User** role (not Super admin). Read-only is sufficient; this integration never writes.
   - Grant it **Read** on the host groups you want imported. Zabbix permissions are per host group, so a user with no group permissions authenticates fine and then returns an empty host list — which is the single most common cause of "the integration runs but imports nothing".
3. Go to **Users → API tokens → Create API token**.
   - **Name**: something identifiable, e.g. `runZero`.
   - **User**: the user from step 2.
   - **Set expiration date and time**: clear this checkbox for a non-expiring token, or set a date and remember to rotate it.
   - Press **Add**. The token value is shown **once**, on the confirmation screen, with a copy button. There is no way to retrieve it later.
4. Confirm the token from the Explorer host. Note the `Content-Type` — Zabbix checks it *before* any JSON-RPC handling and answers a bare `412 Precondition Failed` with an empty body if it does not recognise the value:

   ```bash
   curl -s --request POST \
     --url 'https://zabbix.example.com/zabbix/api_jsonrpc.php' \
     --header 'Content-Type: application/json-rpc' \
     --header 'Authorization: Bearer <token>' \
     --data '{"jsonrpc":"2.0","method":"host.get","params":{"output":["hostid","host"],"limit":1},"id":1}'
   ```

### Finding the right URL

The API path is **not fixed**. Package installs serve the frontend under
`/zabbix`, so the endpoint is `https://host/zabbix/api_jsonrpc.php`. The
official container images serve it at the root, so it is
`https://host/api_jsonrpc.php`. A reverse proxy can put it anywhere.

Configure the **frontend base URL** and this integration appends
`/api_jsonrpc.php`; if you paste the full endpoint URL it is used as-is. Both
of these are correct:

```
https://zabbix.example.com/zabbix
https://zabbix.example.com/zabbix/api_jsonrpc.php
```

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Zabbix").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Zabbix frontend URL** (`url`): see above.
   - **API token** (`api_token`): the token from step 3.
   - **Host group filter** (`host_groups`): optional, comma-separated group names.
   - **Include disabled hosts** (`include_disabled`): optional, default disabled.
   - **Import interfaces as services** (`include_services`): optional, default enabled.
   - **Import inventory software fields** (`include_software`): optional, default enabled.
   - **Host groups per request** (`group_chunk`): optional, default 20.
   - **Maximum hosts** (`max_hosts`): optional, default 20000, `0` removes the cap.
   - **TLS options** (`tls_*`): set these if the frontend uses an internal certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Zabbix inventory changes slowly, so daily is usually plenty.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Zabbix.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:zabbix`.
- Zabbix host groups and host tags both become runZero tags, so `tag:group:Linux servers` and `tag:env:prod` work directly.
- LLD-created hosts carry `tag:zabbix-discovered`; hosts in maintenance carry `tag:zabbix-maintenance`.
- Any of the 70 inventory fields can be searched as `zabbix_inventory_<field>`, for example `zabbix_inventory_site_rack:R12` or `zabbix_inventory_deployment_status:Production`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename zabbix/zabbix.star \
  --kwargs url=https://zabbix.example.com/zabbix \
  --kwargs api_token=b72c1ae5f0d94c1f9e3a6d8b7c4f2a10e5d3b9c8a7f6e4d2c1b0a9f8e7d6c5b4 \
  --kwargs max_hosts=25 \
  --kwargs group_chunk=5 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/zabbix-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; without it the assets are parsed and discarded.
Capping `max_hosts` on a first run keeps a smoke test from turning into a full
collection of a 20,000-host server.

**One CLI caveat, and `host_groups` survives it.** `--kwargs` passes a value
through verbatim, commas included, as long as the pair contains a single `=`, so
a comma-separated `host_groups` filter can be given on the command line as
written. What breaks is a value carrying a *second* `=` **as well as** a comma:
that pair is re-read as CSV, so the value is cut off at the comma and the
remainder becomes a parameter the integration never declared, with no error. A
Zabbix API token cannot be that shape, but a group name holding both characters
could. Wrap such an argument in double quotes to keep it a single field:
`--kwargs '"host_groups=a=b,c"'`.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename zabbix/zabbix.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://zabbix.example.com/zabbix,api_token=...'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: one Zabbix **host** — a monitored device, which may be a server, a network device, a hypervisor, an appliance, or anything else with an interface Zabbix can poll.
- Source ID field: **`hostid`**, the primary key of the `hosts` table.
- Documentation evidence: `hostid` is the id property of the host object and the parameter every per-host API route takes — `host.get` `hostids`, `host.update`, `hostinterface.get` `hostids`, `item.get` `hostids`, `trigger.get` `hostids`. It is returned on every host row of every method observed, always as a JSON string.
- Uniqueness scope: **one Zabbix server**. It is a database sequence, so two servers both numbering a host `10084` mean two different hosts. The id is therefore scoped on the frontend hostname taken from the configured URL.
- Cardinality: exactly one row per host per response. A host that belongs to several host groups is returned once per group chunk this integration requests, so those repeats are collapsed on `hostid` before anything is emitted — otherwise the same host would be imported several times and the `unique_ids` invariant would fire.
- Stability: survives rename of both the technical name (`host`) and the visible name (`name`), IP change, interface add/remove, template change, host group change, disable and re-enable, and inventory edits. It changes only if the host is deleted from Zabbix and re-created — which for a host created by low-level discovery can happen on its own, when the LLD rule stops matching for longer than the "keep lost resources" period.
- Reuse behavior: not documented by the vendor. `hostid` comes from a database sequence and is not recycled in practice, but that is an inference from the implementation rather than a published contract, and it is the weakest link in this record.
- Presence: required. Present on every host row of every method.
- Final runZero ID: `zabbix:<frontend-hostname>:<hostid>` — for example `zabbix:zabbix.example.com:10084`.
- Missing-ID behavior: skip the record and print `zabbix: skipping host with no hostid: host=<host>`. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**.
- Verdict: **scoped authoritative.** This is the one integration among its siblings with a genuine, stable, non-address vendor identifier, and the only one whose id is allowed to drive merges.

The match behavior earns its justification separately. Zabbix publishes **at
most two MAC addresses per host**, and only as the free-text inventory fields
`macaddress_a` and `macaddress_b` — there is no MAC anywhere on an interface
object. A host is also very commonly addressed by DNS name with `useip: 0` and
an empty `ip`, so it may carry no address at all. The `hostid` is the one strong
signal; MAC is usually absent and address and name are sparse and mutable.
Letting an absent MAC or a changed address disqualify a merge against an asset
runZero already discovered on the network would be exactly wrong.

## Notes

### What is imported

One `host.get` call per host-group chunk, with everything selected in a single
round trip:

```jsonc
{"jsonrpc":"2.0","method":"host.get","id":3,"params":{
  "output":["hostid","host","name","status","description","flags",
            "maintenance_status","active_available","inventory_mode"],
  "selectInterfaces":["interfaceid","ip","dns","port","type","main",
                      "useip","available","error"],
  "selectInventory":"extend",
  "selectTags":"extend",
  "selectHostGroups":["groupid","name"],
  "groupids":["1","2"],
  "filter":{"status":"0"}
}}
```

Plus `apiinfo.version` once (unauthenticated) and `hostgroup.get` once.

| runZero | Zabbix |
|---|---|
| `id` | `hostid` |
| `hostnames` | `host`, `name`, `inventory.name`, `inventory.alias`, and every interface `dns` |
| `networkInterfaces` | `interfaces[].ip`, with `inventory.macaddress_a` and `macaddress_b` |
| `os` / `osVersion` | `inventory.os` (or `os_short`) / `inventory.os_full` |
| `manufacturer` / `model` | `inventory.vendor` / `inventory.model` |
| `deviceType` | `inventory.type`, mapped where it maps cleanly |
| `services` | one per interface — see below |
| `software` | `inventory.software` and `software_app_a`..`software_app_e` |
| `tags` | host groups, host tags, and the disabled / discovered / maintenance states |
| `customAttributes` | all 70 inventory fields plus the host state fields |

No `Vulnerability` records are emitted. Zabbix is a monitoring system, not a
vulnerability scanner; its problems and triggers are alert state, not findings
against a CVE.

**Interfaces become Services.** A Zabbix interface is the address and port
Zabbix polls, which means it is a listening service on the host: type 1 is the
Zabbix agent on TCP (usually 10050), type 2 is SNMP on UDP (161), type 3 is IPMI
on UDP (623), type 4 is JMX on TCP. An interface with `useip: 0` carries an
empty `ip` and produces no service, because a `Service` needs an address and
guessing one would be wrong. A port that is a `{$MACRO}` reference — which only
the server can resolve — also produces no service.

**Inventory software fields become Software.** These are free-text fields, not a
package-manager listing, so the value is taken verbatim as the product name and
no version is parsed out of it. `Software.cpe23` is never set: it is validated
against the CPE 2.2 URI binding `^cpe:/a:` and a synthesized value would fail
validation and drop the whole record. Turn this off with `include_software` if
your site does not populate the fields usefully.

### Everything is a string

Zabbix states it outright: *"the Zabbix API always returns values as strings or
arrays only"*. `hostid`, `status`, `flags`, `port`, `type`, `main`, `useip`, and
`available` all arrive as JSON strings, and this integration compares them as
strings throughout rather than assuming a number will ever appear. A
verification against a real 22-host production dump found every single value in
the file to be typed `str`.

### The two array-versus-object traps

Both of these come from PHP rendering an empty array where an object is
expected, and both abort a script that subscripts without a type check:

- **`inventory` is `[]` when the host has inventory disabled**, and an object when it is enabled. Inventory disabled is the shipped default and the common real-world state — in that production dump, 21 of 22 hosts had `inventory_mode: "-1"`. Every host record here goes through a helper that returns an empty dict unless the value really is one, and `zabbix_inventory_present` records which it was.
- **`interfaces[].details` is `[]` on an agent, IPMI, or JMX interface** and an object on an SNMP one — the vendor's own `hostinterface.get` example shows both shapes in a single response. This integration does not request `details`, partly because it holds the SNMP community string, so the trap is documented rather than handled.

### Pagination: there is none

This is the design constraint that shaped the whole integration. The Zabbix API
has **no offset and no cursor**. The complete common-`get` parameter set is
`countOutput`, `editable`, `excludeSearch`, `filter`, `limit`, `output`,
`preservekeys`, `search`, `searchByAny`, `searchWildcardsEnabled`, `sortfield`,
`sortorder`, and `startSearch`, and `host.get` adds none of its own.
`startSearch` is not a cursor — it makes `search` anchor its `LIKE` at the start
of the string. There is no `hostid > N` operator: `filter` is exact-match only,
and `search` is documented to work on `string` and `text` properties, which
`hostid` (type `ID`) is not. The major client libraries — `pyzabbix` and the
official `zabbix_utils` — implement no paging at all.

So responses are bounded by **host group** instead. A Zabbix host cannot be
created without at least one group (`host.create` fails with `No groups for host`),
so walking the groups covers every host, and `group_chunk` controls how many
groups are asked for at once. A host in several groups comes back in several
chunks and is collapsed on `hostid`.

On top of that, the single `host.get` call is issued with raw `http.post` and
walked with `jsonstream.iter_array(body, path="result")`, so a large chunk is
streamed element by element rather than decoded into one enormous Starlark
value, and each asset is reported as it is built. Dropping to
raw `http.post` costs the retry budget — it accepts no `retries` kwarg — so that
one call gets a single attempt while `apiinfo.version` and `hostgroup.get` keep
the default three. `iter_array` **aborts the script** when its path is missing,
so the response body is checked for a `result` member before it is streamed and
decoded normally when it is not there; an error envelope is small.

If `hostgroup.get` fails outright, the run falls back to a single unfiltered
`host.get` rather than importing nothing. An empty *filtered* group list is
treated as "nothing selected" and does **not** fall back, because silently
importing an entire server when the operator asked for one group would be worse
than importing nothing.

### Errors arrive inside a 200

Zabbix reports failures in a JSON-RPC error envelope with an HTTP 200, so
checking status codes alone reports success while importing nothing. Every call
here inspects the envelope. Two codes matter and they are not
interchangeable:

- `-32602 "Invalid params."` with data `Not authorized.` or `Session terminated, re-login, please.` — a **bad or expired token**.
- `-32500 "Application error."` with data `No permissions to referred object or it does not exist!` — a **valid token whose user lacks permission** on the object.

Treating `-32602` as the only auth signal misses the far more common
misconfiguration, which is a token whose user has no host group permissions.

### `apiinfo.version` is called without credentials

Zabbix exempts `apiinfo.version`, `user.login`, and `user.checkauthentication`
from authentication and treats **sending credentials to them as an error**:
`The "apiinfo.version" method must be called without authorization header.` So
that one call is made with a separate options dict carrying no `Authorization`
header at all, which the fixture suite asserts directly.

### No timestamps are set

`host.get` publishes no last-seen or first-seen time for a host, and the
inventory `date_hw_*` fields are hardware lifecycle dates rather than
observations — `date_hw_expiry` and `date_hw_decomm` are routinely in the
**future**. A future timestamp makes the platform reject the **entire asset
record**, not just the field, so none of these is mapped to `firstSeenTS` or
`lastSeenTS`. They are kept verbatim as `zabbix_inventory_date_hw_*`
attributes.

### Discrepancies with the research notes

- **`selectGroups` versus `selectHostGroups`.** `selectHostGroups` arrived in 6.2 and `selectGroups` was removed in 7.2. Since Bearer auth already requires 6.4, `selectHostGroups` is the only correct spelling here. It returns its data under the lowercase key `hostgroups`.
- **`flags: 4`** is worded by the vendor as "a host converted from a prototype" — that is, created by low-level discovery — rather than "discovered host". Same thing, but the wording matters when reading the docs.
- **Passing `auth` alongside a Bearer header is not an error before 7.2.** In 6.4 and 7.0 the header simply wins and `auth` is ignored with a deprecation notice. In 7.2 `auth` was removed from the validator, so sending it produces `-32600 "Invalid request."`. This integration never sends it.
- **`output: extend` returns fields absent from the documented host object table** — `templateid`, `custom_interfaces`, `uuid`, `vendor_name`, `vendor_version` all appear in real output. This integration requests an explicit output list rather than `extend`, so it is unaffected, but decode permissively if you extend it.

### Verification status

Verified against local fixtures and against vendor documentation plus the Zabbix
frontend PHP source, not against a live server. The fixture host rows follow a
real production `host.get` dump from a Zabbix 7.x server; the interface and
inventory shapes follow the vendor's own `host.get` and `hostinterface.get`
examples. The `inventory: []` behavior is established from vendor source
(`CHost::addRelatedObjects()` → `CRelationMap::mapOne()`, which leaves an
unmatched empty array that `json_encode` renders as `[]`) and from Zabbix ticket
ZBX-12943; no public live capture of that case was found, so it is the one claim
here resting on code reading rather than a copied payload.

## Future

- **Problem state as tags or findings.** `problem.get` returns current problems with `severity`, `name`, `clock`, `acknowledged`, and `suppressed`, and `trigger.get` returns trigger state with `priority` and `value`. Attaching "this host has 3 unacknowledged disaster-severity problems" as attributes would let a runZero user see monitoring health beside inventory. Whether individual problems should become `Vulnerability` records with a non-CVE category is a product question, not a technical one.
- **`item.get` for last values.** Sites that do not populate host inventory often still have discovery items collecting serial numbers, chassis IDs, and installed software into item values. Reading the last value of a configured set of item keys would recover inventory-grade data from those sites. The cost is a second large call and a key list the operator has to supply.
- **`service.get` for business services.** Zabbix's service tree models business-level dependencies over hosts. That maps to runZero's ownership and criticality thinking better than anything currently imported.
- **Software from `item.get` on `system.sw.packages`.** The Zabbix agent template collects a full package list on Linux. That is a genuine software inventory, and much better than the free-text inventory fields used today, but it arrives as one large text value per host and needs parsing per package manager.
- **Legacy `user.login` for pre-6.4 servers.** A parameter selecting the session handshake would extend support back to 5.0, at the cost of managing a session token and calling `user.logout`. Deliberately not built speculatively: 6.4 is old enough that the token path covers most estates.
- **`hostinterface.get` for SNMP details.** The `details` object on an SNMP interface carries the SNMP version and bulk setting, which are useful device facts. It also carries the community string, which is a credential, so this needs a deliberate decision about what to import rather than a blanket pull.
- **Proxy awareness.** `monitored_by`, `proxyid`, and `assigned_proxyid` say which Zabbix proxy polls a host, which is a good proxy (in both senses) for network location and would map onto runZero sites.

## API documentation

- API reference — https://www.zabbix.com/documentation/current/en/manual/api. Source for the endpoint, the `Content-Type` requirement, the Bearer header, and the error envelope.
- `host.get` — https://www.zabbix.com/documentation/current/en/manual/api/reference/host/get. The `select*` parameters and the common-get parameter set that proves there is no offset.
- Host object — https://www.zabbix.com/documentation/current/en/manual/api/reference/host/object. `status`, `flags`, `maintenance_status`, `active_available`, `inventory_mode`.
- `hostinterface.get` — https://www.zabbix.com/documentation/current/en/manual/api/reference/hostinterface/get. The full interface shape, and the one published example showing `details` as both an array and an object.
- Host inventory fields — https://www.zabbix.com/documentation/current/en/manual/config/hosts/inventory. The 70-field list, inventory ids 1–70.
- API tokens — https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/users/api_tokens.
- 6.4 API changes (`ZBXNEXT-8051`, the Bearer switch) — https://www.zabbix.com/documentation/6.4/en/manual/api/changes.
- Reference commentary, including "the Zabbix API always returns values as strings or arrays only" — https://www.zabbix.com/documentation/current/en/manual/api/reference_commentary.
- Zabbix ticket ZBX-12943, "Disabled (-1): inventory returns as empty array" — https://support.zabbix.com/browse/ZBX-12943.
- Client libraries read for the pagination question — [`lukecyca/pyzabbix`](https://github.com/lukecyca/pyzabbix) and the official [`zabbix/python-zabbix-utils`](https://github.com/zabbix/python-zabbix-utils). Neither implements paging of any kind.

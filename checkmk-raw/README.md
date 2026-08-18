# Custom Integration: Checkmk Raw Edition

Imports monitored hosts from a Checkmk site, with their live monitoring state,
their configuration, and — the reason this integration is worth having — their
**HW/SW inventory**: MAC addresses, serial numbers, manufacturer and model, OS
version and kernel, BIOS, CPU and memory, and the full installed-package list.

The inventory is the point. Checkmk is usually thought of as up/down and
threshold telemetry, but a site running the `mk_inventory` agent plugin is
holding a hardware and software asset register that nobody thinks to call one.
This integration reads it in the **same request** as the monitoring state,
because Checkmk exposes the whole inventory tree as a Livestatus column rather
than as a per-host endpoint — so a thousand-host site costs one request, not a
thousand and one.

Raw Edition is named in the title because Raw is the free edition and the one
most likely to be sitting unintegrated. Nothing here is Raw-specific: the same
script works against the commercial editions, which serve the same endpoints.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Checkmk **web server** — the Apache that fronts the site, on 80 or 443. Not the Livestatus socket on 6557, and not the agent port 6556.

## Checkmk requirements

- **Checkmk 2.1 or newer** for the REST API in the shape this integration uses. The `mk_inventory` Livestatus column, which is where every hardware fact comes from, requires **2.2.0p21, 2.3.0b1, or 2.1.0p39 or later** — before those patch levels the column exists but the REST endpoint does not decode it. Turn `collect_inventory` off against an older site.
- An **automation user** and its **automation secret**. This is not a normal password: Checkmk distinguishes interactive users from machine accounts, and only a machine account authenticates cleanly against the REST API without a login session.
- The **site name**, which is a mandatory path segment of every API URL and is the single most common first-attempt failure.
- Checkmk sites are frequently fronted by an internal-CA or self-signed certificate, so `OPTIONS_TLS` is exposed. Nothing is skipped by default.

### Creating the credential in Checkmk

1. Log in to the Checkmk site's web interface as an administrator.
2. Go to **Setup → Users → Users** and add a user. Checkmk's own wording is that
   you find automation users *"just like other users, under Setup > Users >
   Users"*.
   - Give it a recognisable name, for example `runzero`.
   - **Do not set a normal password.** Choose the **"Automation secret for
     machine accounts"** option instead. Checkmk describes this option as meant
     for accounts that access Checkmk over HTTP/HTTPS and authenticate through
     the URL, which is exactly what this integration does. The UI can generate
     the secret for you.
   - Copy the secret. Unlike a password it can be re-read from the user's
     settings later, but treat it as a credential either way.
3. Give the user a role under **Setup → Users → Roles and permissions**.
   Checkmk's guidance is to copy a predefined role as a template, name the copy,
   and assign that to the user. This integration only reads, so a read-only
   derivative of the `user` role is enough in principle.

   **What could not be established:** Checkmk documents that *"to use all
   endpoints of the REST API, you need an automation user with fairly extensive
   permissions"* and recommends the `admin` role, but it does not publish the
   specific permission that gates the two endpoints used here
   (`host_config` collection and the `host` monitoring collection). The
   `host_config` list endpoint's own source marks `wato.see_all_folders` as an
   **optional** permission, which means a user without it gets a *filtered*
   list rather than an error. Start with a copy of `admin` if you want it to
   work on the first try, then narrow it and re-check the imported host count.
   A user whose role cannot see every folder authenticates fine and quietly
   imports a subset — which is the failure mode to watch for, not a 403.

4. Confirm the credential from the Explorer host before configuring anything in
   runZero. Note the **two space-separated values** inside the Bearer token —
   this is not base64 Basic auth and not a single opaque token:

   ```bash
   curl -s \
     --header 'Accept: application/json' \
     --header 'Authorization: Bearer runzero YOURAUTOMATIONSECRET' \
     'https://checkmk.example.com/mysite/check_mk/api/1.0/domain-types/host_config/collections/all?effective_attributes=true'
   ```

   If that returns HTML rather than JSON, the site name in the path is wrong.
   If it returns 401, the user is not an automation user or the secret is stale.

### Enabling the HW/SW inventory

Everything interesting — MACs, serials, model, packages — comes from the
inventory, and the inventory only exists if the agent is collecting it. The
plugin is **not** enabled by default.

- Install the `mk_inventory` agent plugin on the hosts you care about. In the
  commercial editions this is done with the Agent Bakery; **the Agent Bakery is
  not in Raw Edition**, so on Raw you install the plugin manually. Checkmk
  publishes the plugin under **Setup → Agents** in the Community (Raw) edition,
  and under **Setup → Agents → Windows, Linux, Solaris, AIX → Related page** in
  the commercial editions.
- On Linux and Unix the plugin's cadence is configured in
  `/etc/check_mk/mk_inventory.cfg`.
- The inventory is *not* a commercial feature. Raw collects, stores, and serves
  it; only the baking of the agent package is commercial.

A host with no inventory still imports — it simply arrives with its monitored
address, its name, and its monitoring state, and this integration counts and
logs how many such hosts it saw.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Checkmk").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Checkmk URL** (`url`): the base URL of the server, *without* the site name — for example `https://checkmk.example.com`.
   - **Site name** (`site`): the site, for example `mysite`. One credential reads one site.
   - **Automation user** (`username`): the user from step 2 above.
   - **Automation secret** (`password`): that user's automation secret.
   - **Collect HW/SW inventory** (`collect_inventory`): optional, default enabled.
   - **Import installed software** (`collect_software`): optional, default enabled. No effect when the inventory is not collected.
   - **Livestatus filter** (`query`): optional JSON filter expression, applied server-side. Blank reads every host.
   - **Assets per batch** (`batch_size`): optional, default 200.
   - **TLS options** (`tls_*`): set these if the site uses an internal certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Inventory changes slowly, so daily is usually plenty.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Checkmk.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:checkmk`.
- Checkmk host groups, host labels, and the folder become runZero tags, so `tag:group:linux`, `tag:folder:/servers`, and `tag:cmk/os_family:linux` all work directly.
- Every host also carries `tag:site:<site>` and `tag:state:up|down|unreachable`, and a host with a serial carries `tag:serial:<serial>`.
- Inventory facts are searchable under the `checkmk_` prefix — `checkmk_system_serial:FIXT1234`, `checkmk_os_kernel_version:5.15.0-105-generic`, `checkmk_bios_version:2.15.1`, `checkmk_cpu_model:...`.

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
credential and see what a real site returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename checkmk-raw/checkmk-raw.star \
  --kwargs url=https://checkmk.example.com \
  --kwargs site=mysite \
  --kwargs username=runzero \
  --kwargs password=A1B2C3D4E5F6G7H8I9J0 \
  --kwargs collect_software=false \
  --kwargs batch_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/checkmk-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; `--overwrite` lets you re-run into the same
directory. Turning `collect_software` off on a first run keeps the response
small while you confirm the credential.

**One CLI caveat, and it is narrower than it looks.** `--kwargs` passes the value
through verbatim, commas included, as long as the pair contains a single `=`. A
`query` such as `{"op": "~", "left": "name", "right": "^prod-"}` therefore
arrives exactly as written, so a JSON filter can go on the command line as-is.
What does break is a value carrying a *second* `=` **as well as** a comma: that
pair is re-read as CSV, so the value is cut off at the comma and the remainder
becomes a parameter the integration never declared — silently, with no error. A
Livestatus filter built on the `=` operator has that shape, and so does a
password containing both characters. Wrap such an argument in double quotes to
keep it a single field — `--kwargs '"password=a=b,c"'`, doubling any double
quote already inside the value — or set it through the console credential form.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real site:

```bash
runzero script --filename checkmk-raw/checkmk-raw.star --validate
```

The fixture scenarios in `checkmk-raw/tests/fixtures/` exercise the parsing
against scripted responses, which `--validate` cannot do — its dummy server
answers every collection empty, so no row is ever parsed:

```bash
python3 tests/run.py checkmk-raw
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://checkmk.example.com,site=mysite,username=runzero,password=...'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: one Checkmk **host** — anything Checkmk monitors, which may be a server, a network device, an appliance, a cluster, or a piece of infrastructure that only answers SNMP.
- Source ID field: the **host name**, which is the object id on both endpoints.
- Documentation evidence: the host name is the primary key throughout. It is the `id` of the `host_config` domain object (`serialize_host` passes `identifier=host.id()`), the `id` of the monitoring domain object (`_host_object` passes `identifier=host_name`), the `name` Livestatus column, and the path parameter of every per-host route. Checkmk publishes no numeric surrogate for a host.
- Uniqueness scope: **one site**. Host names are unique within a site and routinely reused between sites — a test site and a production site both monitoring `web01` is the normal arrangement, not an edge case.
- Cardinality: exactly one row per host per collection. A host appears once in the configuration collection and at most once in the monitoring collection.
- Stability: survives address change, folder move, tag and label edits, going down, and being taken out of monitoring. It does **not** survive a rename — Checkmk treats renaming a host as a first-class operation, and the renamed host is a new identity here.
- Reuse behavior: fully reusable, and deliberately so. Delete `web01` and create `web01` again and it is the same id. That is usually right: an operator who recreates a host under the same name means the same host.
- Presence: required. A host cannot exist without a name.
- Final runZero ID: `checkmk:<server-hostname>:<site>:<host-name>` — for example `checkmk:checkmk.example.com:mysite:web01.example.com`. The server hostname comes from the configured URL and the site from the `site` parameter, so both halves of the scope are operator-supplied and stable.
- Missing-ID behavior: skip the record and print `checkmk: skipping a monitored host with no name`, then report the count at the end. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**.
- Verdict: **scoped authoritative.** The host name is a real vendor identifier, and with the server and site prepended it is safe to drive merges.

The match behavior earns a note. Checkmk's host name is frequently *not* a
resolvable hostname — sites name hosts by asset tag, by rack position, or by a
naming scheme that has nothing to do with DNS. The address Checkmk polls is
whatever an operator typed or whatever DNS resolved at configuration time, and
a host with no inventory carries no MAC at all. So the id is the one strong
signal and the correlators are sparse and mutable; letting an absent MAC or a
changed address disqualify a merge against an asset runZero already discovered
on the network would be exactly wrong.

The **alias** is treated with suspicion for the same reason. Checkmk's alias is
free text, and `"Web server, rack 4"` is as common as a second FQDN, so it only
becomes a hostname when it actually looks like a DNS name. This matters more
than it sounds: `serialize_host` sets the configuration object's `title` to
`host.alias() or host.name()`, so a host with an alias is *titled* by its
description. That is why this integration reads the `id` and never the `title`.

## Notes

### What is imported

Exactly two requests, regardless of estate size:

```
GET /{site}/check_mk/api/1.0/domain-types/host_config/collections/all?effective_attributes=true
GET /{site}/check_mk/api/1.0/domain-types/host/collections/all?columns=name&columns=address&...&columns=mk_inventory
```

| runZero | Checkmk |
|---|---|
| `id` | the host name |
| `hostnames` | the host name, plus the alias when it is DNS-shaped |
| `networkInterfaces` | `hardware.nwadapter`, `networking.interfaces` and `networking.addresses` from the inventory, plus the monitored and configured addresses |
| `os` / `osVersion` | `software.os.name` / `software.os.version` |
| `manufacturer` / `model` | `hardware.system.manufacturer` / `hardware.system.product` |
| `deviceType` | `hardware.system.type`, `description`, or `product`, where it maps cleanly |
| `software` | `software.packages`, up to 99 per host |
| `tags` | host groups, labels, folder, monitoring state, serial, and the site |
| `customAttributes` | the system, OS, CPU, memory, BIOS and firmware inventory nodes, plus every monitoring column and every host tag |

No `Vulnerability` records are emitted. Checkmk is a monitoring system; its
service states are alert state, not findings against a CVE. No `Service`
records are emitted either — a Checkmk *service* is a check ("CPU load",
"Filesystem /"), not a listening port, and importing those as services would
be a category error.

### Two endpoints, two different truths

The configuration collection and the monitoring collection are not two views of
one thing, and both are read because each carries something the other does not:

- **Configuration** carries the folder a host lives in, its host tags, and the
  address an operator *typed*. It is requested with `effective_attributes=true`,
  which merges in everything inherited from parent folders — an address or a
  tag set at folder level lives nowhere else. That parameter is not free:
  without it the field is `null`, and the parser falls back to the plain
  `attributes`.
- **Monitoring** carries the address Checkmk actually *polls*, the state, the
  labels the agent discovered, and the inventory tree.

Both addresses are kept, monitored first, because that is the address traffic
went to.

A host present in the configuration and absent from monitoring is a host that
was added in the Setup but whose changes were never activated. Those hosts are
real — somebody recorded an address for them — so they are imported from the
configuration alone rather than dropped, and the count is logged.

### The inventory tree has two spellings

Checkmk serializes an inventory tree as nested objects with three reserved keys:
attributes for scalar pairs, table for row data, and nodes for children. The
on-disk form — which is what the `mk_inventory` Livestatus column carries —
**capitalizes** them: `Attributes`, `Pairs`, `Table`, `KeyColumns`, `Rows`,
`Nodes`. The inventory REST endpoint added in 2.5 emits the identical structure
in lower snake case. This integration reads both casings at every level, so one
parser covers either route into the data.

The tree is walked by explicit dotted paths (`hardware.system`,
`software.packages`, `networking.addresses`) rather than by recursing blindly,
so a vendor-specific subtree that appears on one host cannot change what gets
imported. Empty branches are omitted entirely rather than serialized as empty
objects, so a missing key is the normal case and not an error.

### Two interface tables that disagree

Addressing arrives from two inventory tables with different coverage, so both
are read and joined:

- `hardware.nwadapter` is what the **Windows** agent reports, and pairs a MAC
  with its addresses directly.
- `networking.interfaces` is what the **SNMP and Linux** checks report; it
  carries the MAC as `phys_address` but not the address, which then has to be
  joined from `networking.addresses` by device name.

Devices reporting the same MAC — a bond and its slaves, a VLAN device and its
parent — are one endpoint as far as runZero is concerned and are pooled onto
one interface. The host's own monitored address is added last, and only when no
interface already accounts for it, so a host with no inventory at all still gets
one interface built from the address Checkmk polls.

An all-zero MAC, a loopback address, and an APIPA `169.254/16` address are all
screened out. The last one matters most: the platform's own address filter
deliberately **keeps** link-local, so an integration that fails to screen it
would correlate every DHCP-failed host in an estate onto one asset.

### There is no pagination

Checkmk's collections are not paginated. One request answers with every host on
the site, and with the inventory column that response carries a full hardware
and software tree per host — which is the largest payload this integration ever
handles, tens of megabytes on a large install.

Two consequences shaped the code. First, the response is **streamed**: the raw
body is walked with `jsonstream.iter_array(body, path="value")` so only one
entry is live at a time, rather than decoding the whole document into Starlark
values at several times the wire size. Assets are flushed to runZero every
`batch_size` records, so peak memory is one batch rather than the whole estate.
Dropping to the raw `http.get` builtin to obtain the body as text costs the
retry budget — it accepts no `retries` kwarg — so each of the two calls gets a
single attempt.

Second, `iter_array` **aborts the entire script** when its path is missing, and
Starlark has no exceptions to catch that with. An error page, an HTML login
redirect, or a `{"value": null}` body would all end the run silently. So the
body is checked for a real `"value": [` before the iterator is ever built, and a
response that fails that check is reported as a readable error instead.

The only way to bound the response is the server-side `query` parameter, which
is why it is exposed. It takes a Livestatus filter expression as JSON, for
example `{"op": "~", "left": "tag_names", "right": "windows"}` or
`{"op": "!=", "left": "state", "right": "0"}`.

### `columns` is a repeated parameter

The monitoring query needs about twenty columns, and Checkmk expects them as
`columns=name&columns=address&columns=alias&...` — a repeated key. A Starlark
dict holds no duplicate keys, so a `params=` dict cannot express this and the
query string is assembled by hand instead. Without any `columns` at all,
Checkmk returns only the host name, and the integration would import an estate
of empty assets.

### Timestamps arrive in two shapes

The configuration API serializes ISO 8601 with an offset; the Livestatus columns
are an integer epoch, where `0` means "never checked" rather than 1970. Both are
handled, and a **future** value is clamped to now — the platform rejects the
*entire asset record* when a timestamp is ahead of now, not just the field, so
clock skew between the Checkmk server and the Explorer would otherwise silently
import nothing. `parse_time` aborts the script on anything it cannot read, so
the shape is regex-checked before the call.

### Forward compatibility: the GET form is deprecated

Checkmk **werk #17003** deprecates the `GET` form of
`/domain-types/host/collections/all` and replaces it with a `POST` to the same
collection href, carrying the former query parameters in the request body. The
stated reason is the maximum size of query parameters, which this integration
brushes against precisely because it sends twenty `columns` values. The werk
says the `GET` form is **removed in Checkmk 2.5**.

This integration currently uses `GET`. It works on 2.1 through 2.4 and will stop
working on 2.5. Moving to `POST` is the single most important piece of
outstanding work here, and is listed under Future below.

### Verification status

Verified against local fixtures and against Checkmk's own source, not against a
live site. Specifically:

- The collection and domain-object envelopes are taken from
  `cmk/gui/openapi/restful_objects/constructors.py`
  (`collection_object`, `domain_object`), so the `domainType` / `links` /
  `members` / `extensions` shape in the fixtures is the real one.
- The configuration `extensions` shape — `folder`, `attributes`,
  `effective_attributes`, `is_cluster`, `is_offline`, `cluster_nodes` — is from
  `host_config.serialize_host`, which is also where the `title = alias or name`
  behavior is established.
- The monitoring `extensions` shape is from `host._host_object`, which passes
  the raw Livestatus column dict straight through; the column names and types
  are from `cmk/utils/livestatus_helpers/tables/hosts.py` (`groups` is a list,
  `labels` and `tags` are dicts, `state` is an int).
- The inventory tree's reserved keys are from the `SDRawTree` TypedDict in
  `cmk/utils/structured_data.py`, and every inventory key name used
  (`macaddress`, `phys_address`, `ipv4_address`, `total_ram_usable`,
  `kernel_version`, `service_pack`, `package_type`, `expresscode`,
  `device_number`, `max_speed`) is confirmed against the display hints in
  `cmk/gui/views/inventory/_display_hints.py`.
- The deprecation claim is from werk #17003 and from the `deprecated_urls`
  annotation in `cmk/gui/openapi/endpoints/host/__init__.py`.

**Not verified:** no live Checkmk server was polled, so the exact wire bytes of
a real `mk_inventory` column have not been compared against the fixtures. A
`checkmk/check-mk-raw:2.3.0p49` container *was* stood up to try, and was
abandoned: the site was created but its web server never accepted a connection,
and the run was called off rather than spend the whole budget debugging a
container. It would not have settled the important question anyway — a bare
Checkmk container has no agent reporting to it, so its `mk_inventory` column
would have been empty, which is precisely the part of the fixture that most
needs a real capture. Treat the inventory tree in these fixtures as
source-derived rather than observed. The specific permission required by each
endpoint is also unverified — see the honest note under "Creating the
credential" above.

## Future

- **Move the monitoring query to `POST`.** Werk #17003 removes the `GET` form in 2.5. The body form takes the same `columns` and `query` parameters as JSON, and removes the query-length ceiling that the twenty-column request is already flirting with. This needs a version probe, because the `POST` form does not exist on 2.1.
- **Use the 2.5 inventory REST endpoint where available.** 2.5 exposes the inventory tree through its own endpoint in lower-snake-case form. The parser here already reads both casings, so the work is endpoint selection and a version gate, not parsing.
- **Import Checkmk services as evidence, not as `Service` records.** A Checkmk service is a check, not a port — but "Filesystem /", "Interface 1", and "Postfix Queue" collectively describe what a host *does*, and the `num_services_crit` counters already imported are a poor substitute. `/domain-types/service/collections/all` would give the detail at the cost of a second large response.
- **Cluster topology.** `is_cluster` and `cluster_nodes` are imported as attributes today, but the node relationship is not modelled. A Checkmk cluster is an abstraction over real hosts that runZero already knows about, and linking them would be more useful than recording a boolean.
- **Per-site multi-tenancy.** One credential reads one site. A Checkmk distributed setup with a central site and several remotes would need one credential per site today; reading the site list and walking it would need the central site's own configuration API and a decision about how to scope ids across sites.
- **`software.applications` subtrees.** The inventory tree carries far more than packages — Docker containers, Oracle instances, MSSQL databases, Kubernetes nodes — each with its own schema. Any of these would be a genuine asset-adjacent inventory, and each needs its own mapping decision.
- **A `folder` to runZero site mapping.** Checkmk folders are how sites express physical and organisational structure. That maps onto runZero sites better than a tag does.

## API documentation

- Checkmk REST API introduction — https://docs.checkmk.com/latest/en/rest_api.html. Source for the `{PROTO}://{HOST}/{SITE}/check_mk/api/{VERSION}` URL structure, the `Authorization: Bearer {USERNAME} {PASSWORD}` header, and the "fairly extensive permissions" statement.
- Users, roles and permissions — https://docs.checkmk.com/latest/en/wato_user.html. Source for **Setup → Users → Users**, the "Automation secret for machine accounts" option, and **Setup → Users → Roles and permissions**.
- The HW/SW inventory — https://docs.checkmk.com/latest/en/inventory.html. Source for the `mk_inventory` agent plugin, its manual installation on Raw, `/etc/check_mk/mk_inventory.cfg`, and the Agent Bakery being commercial-only.
- Monitoring agents — https://docs.checkmk.com/latest/en/wato_monitoringagents.html. Source for where the plugin is published in each edition.
- Livestatus references, including the filter operators the `query` parameter accepts — https://docs.checkmk.com/latest/en/livestatus_references.html.
- Werk #17003, "Show hosts for specific condition: deprecate GET in favour of POST" — https://checkmk.com/werk/17003. Source for the 2.5 removal.
- Checkmk source read for the response shapes: `constructors.py`, `host_config.py`, `host/__init__.py`, `structured_data.py`, `hosts.py` (Livestatus table), and `_display_hints.py` — https://github.com/Checkmk/checkmk.

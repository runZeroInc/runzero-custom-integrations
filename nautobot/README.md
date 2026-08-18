# Custom Integration: Nautobot

Imports DCIM **devices** and **virtual machines** from a Nautobot 2.x instance,
each with its interfaces, MAC addresses, and IP addresses, plus the platform,
software version, manufacturer, model, location hierarchy, tenant, rack position,
and every user-defined custom field on the record.

Nautobot is a source of truth: it records what the network is *supposed* to
contain, where runZero records what is actually answering. Merging the two is the
whole point — a Nautobot device that never merges with a scanned asset is either
decommissioned hardware nobody deleted or a host runZero has not reached yet, and
both are worth knowing. The identity story is unusually good, too: Nautobot
replaced NetBox's integer primary keys with **UUIDs**, minted once and never
rewritten, so this is one of the few integrations here whose foreign id is
allowed to drive merges rather than being deliberately inert.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Nautobot web application over HTTPS — the same URL operators open the UI with. Nautobot serves its REST API from `/api/` on the web front end rather than from a separate listener, so there is no second port to open. The port that front end runs on is site-specific (Nautobot's own deployment guide puts uWSGI behind nginx), so this integration has no default URL and requires one.

## Nautobot requirements

- **Nautobot 2.0 or newer.** This is established from the API surface the script calls, not assumed. It requests `?depth=1`, which replaced `?brief` in 2.0 — "Support for `?brief` REST API query parameter and `Nested*Serializers` have been removed in Nautobot v2.X. They are replaced by the new `?depth` query parameter." It reads `role` and `location`, the 2.0 names for what 1.x called `device_role` and `site`. It expects a UUID primary key. And it filters interfaces with `device=<uuid>` rather than `device_id=<uuid>`, because 2.0 announced that "PK-based filters suffixed by `_id` will no longer be supported in v2.0" and that the plain filter accepts "both names and UUID primary keys as inputs".
- **Nautobot 2.2 or newer** to populate `osVersion`: the `SoftwareVersion` model and the `Device.software_version` foreign key arrived in 2.2. On 2.0 and 2.1 the field is absent and the asset imports without a version.
- A **Nautobot API token** belonging to a user with view permission on the objects below.
- Object permissions covering every model the run reads. Nautobot's permission names follow Django's `app_label.action_modelname` form:

  | Permission | Needed for |
  |---|---|
  | `dcim.view_device` | the device collection |
  | `dcim.view_interface` | device interfaces, which is where MACs come from |
  | `dcim.view_manufacturer` | the manufacturer lookup table |
  | `virtualization.view_virtualmachine` | the virtual machine collection |
  | `virtualization.view_vminterface` | virtual machine interfaces |
  | `ipam.view_ipaddress` | IP addresses, which arrive nested on interfaces |

  The last two are easy to miss: the parameter descriptions inside `CONFIG` name
  only four models, but the script calls six collections. Grant all six.
  **Whether `ipam.view_ipaddress` is genuinely enforced on the `ip_addresses`
  nested at `depth=1` was not established** — Nautobot filters querysets and a
  nested serializer is not a queryset — but it is cheap and obviously correct to
  grant.

### Creating the credential in Nautobot

1. Sign in to Nautobot as the user the integration will act as, click that
   **username in the upper right**, and choose **Profile**.
2. In the left sidebar under User Profile, choose **API Tokens**, then
   **+ Add a token**.
3. Leave the **Key** field blank and Nautobot generates one for you — "a 160-bit
   key represented as 40 hexadecimal characters". You may also paste your own.
4. **Clear the "Write enabled" checkbox.** Deselecting it "will restrict API
   requests made with the token to read operations (e.g. GET) only", which is
   exactly what this integration needs and nothing more. It never writes.
5. Set an **Expires** date if your policy demands rotation, or leave it empty for
   a token that does not expire. An expired token fails closed with a 403.
6. Grant the object permissions listed above. Permissions are administered
   through Nautobot's admin interface at `/admin/`, where Users, Groups, and
   Object Permissions live; assigning them to a **group** and putting the token's
   user in it is easier to audit than six direct grants. **The precise menu
   labels inside `/admin/` were not established from the documentation** — the
   permissions guide describes the model and the naming convention but does not
   walk the UI — so confirm the layout against your own release.
7. Confirm the token from the Explorer host before configuring anything in
   runZero:

   ```bash
   curl -s -H 'Authorization: Token 0123456789abcdef0123456789abcdef01234567' \
     -H 'Accept: application/json; version=2.4' \
     'https://nautobot.example.com/api/dcim/devices/?limit=1&depth=1'
   ```

   Note the scheme: it is `Token <key>`, **not** `Bearer <key>`. A Bearer header
   is accepted by the framework and then resolved as an anonymous user.

Two failure modes look nothing alike, and it is worth knowing which you have. A
user with **no** `dcim.view_device` permission gets a flat refusal — "Nautobot
will return a 403 (forbidden) HTTP response". A user who *has* the permission but
whose grant carries **constraints** matching nothing gets a well-formed `200`
with `"count": 0`, because constraints work by "filtering the database query
generated by a user's request to restrict the set of objects returned". The
second case is what produces "the integration runs but imports nothing"; this
integration logs `nautobot: no assets retrieved` rather than failing, because
from the client side it is indistinguishable from an empty Nautobot.

**Whether an administrator can mint a token for a separate service account was
not established from the documentation.** A token is described as "a unique
identifier mapped to a Nautobot user account", and the docs discuss restricting a
user's ability to create their *own* tokens without saying whether a superuser
can create one for somebody else. The reliable approach is to create a dedicated
read-only user, sign in as it once, and mint the token from its own profile page.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Nautobot").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Nautobot URL** (`url`): base URL of the Nautobot server, for example `https://nautobot.example.com`. The `/api` paths are appended automatically. Nautobot is self-hosted, so there is no default.
   - **API token** (`api_token`): the 40-character key from step 3 above.
   - **REST API version** (`api_version`): optional; a version to pin, sent as `Accept: application/json; version=<value>`. Leave blank to accept the server's default, which is its own current version.
   - **Import DCIM devices** (`import_devices`): optional, default enabled.
   - **Import virtual machines** (`import_virtual_machines`): optional, default enabled.
   - **Collect interfaces** (`collect_interfaces`): optional, default enabled. This is where MAC addresses and non-primary IP addresses come from.
   - **Device filter** (`device_filter`): optional; a URL query fragment in Nautobot's own filter syntax, for example `status=active` or `location=DM01&location=DM02`. Values must already be URL-encoded. Blank imports every device the token can see.
   - **Virtual machine filter** (`virtual_machine_filter`): optional; the same, applied to virtual machines.
   - **Records per page** (`page_size`): optional, default 100, minimum 1, maximum 1000. Nautobot caps this at its own `MAX_PAGE_SIZE` setting, which defaults to 1000.
   - **TLS options** (`tls_*`) and **HTTP options** (`http_*`): set these if Nautobot is behind an internal certificate or a proxy.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. A source of truth changes on human timescales, so daily is usually plenty.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Nautobot.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:nautobot`.
- Split the two asset kinds with `tag:device` and `tag:virtual-machine`. Those tags are emitted verbatim and are deliberately generic, so pair them with `custom_integration:nautobot` rather than using them alone.
- Nautobot's own object tags arrive prefixed: a Nautobot tag named `pci` becomes `tag:tag:pci`. Status, role, location, tenant, and platform each become a tag too, so `tag:status:Active`, `tag:role:Access Switch`, and `tag:location:AMS01` all work, as does `tag:serial:FDO12345678`.
- Every imported field is searchable under the `nautobot_` prefix — `nautobot_rack:R12`, `nautobot_tenant:Retail`, `nautobot_location_path`, `nautobot_platform_network_driver`. User-defined custom fields land under `nautobot_custom_field_<name>`, so a Nautobot custom field named `support_contract` is `nautobot_custom_field_support_contract:SC-99213`.

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
token and see what a real instance returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename nautobot/nautobot.star \
  --kwargs url=https://nautobot.example.com \
  --kwargs api_token=0123456789abcdef0123456789abcdef01234567 \
  --kwargs api_version=2.4 \
  --kwargs page_size=25 \
  --kwargs import_virtual_machines=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/nautobot-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory. Turning the
virtual machine pass off and dropping `page_size` keeps a first look at a large
estate from becoming a full collection.

**One CLI caveat, and `&` keeps most filters clear of it.** `--kwargs` passes a
value through verbatim, commas included, as long as the pair contains a single
`=` — a comma on its own is harmless. What breaks is a value carrying a *second*
`=` **as well as** a comma: that pair is re-read as CSV, so the value is cut off
at the comma and the remainder becomes a parameter the integration never
declared. Every useful `device_filter` and `virtual_machine_filter` value
contains a second `=`, which puts this integration one comma away from that
edge — but Nautobot's separator for a repeated filter is `&`, not a comma, so
both `device_filter=status=active` and
`device_filter=status=active&status=staged` arrive exactly as written. Only a
filter carrying a literal comma *inside* a value needs care: wrap the whole
argument in double quotes so it stays a single field,
`--kwargs '"device_filter=a=b,c"'`, doubling any double quote inside it. The
console credential form takes any of these as written.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real instance:

```bash
runzero script --filename nautobot/nautobot.star --validate
```

`python3 tests/run.py nautobot` exercises the fixture scenarios in
`nautobot/tests/fixtures/` against the real scanner — the happy path, an empty
instance, malformed rows, two-page pagination, and a 429 from a proxy.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://nautobot.example.com,api_token=0123456789abcdef0123456789abcdef01234567'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, built the same way and sharing one match behavior.

### Devices

- Target entity: one row of Nautobot's `dcim.Device` table — a piece of hardware, racked or not.
- Source ID field: **`id`**, the record's primary key.
- Documentation evidence: Nautobot 2.0 removed slug fields in favour of UUID primary keys, to the point that object URLs changed shape — the release notes show `https://nautobot/dcim/locations/building-01` becoming `https://nautobot/dcim/locations/e41f381a-a53b-485a-886f-9d36859b47a1`. Every per-object REST route is addressed by that UUID, and it is returned on every row at every `depth`.
- Uniqueness scope: one Nautobot installation. A UUID is unique by construction, but two installations are two different estates, so the id is namespaced on the hostname taken from the configured URL. The class is namespaced too, because `dcim.Device` and `virtualization.VirtualMachine` are separate tables whose UUIDs could in principle collide.
- Cardinality: exactly one asset per device row. Pagination returns each row once, so no fold is needed.
- Stability: survives rename, address change, interface add and remove, re-racking, role and status change, moving to another location or tenant, and a platform or software version change. It is a database key, not an observation. It changes only if the device is deleted and re-created.
- Reuse behavior: a UUID4 is not recycled. This is the strongest reuse story of any integration in this repository, and it is why the id is allowed to match.
- Presence: required. The script still refuses anything that is not shaped like a UUID — `UUID_RE` is checked before the record is used — because a value in `id` that is not a UUID means the response is not what this integration expects.
- Final runZero ID: `nautobot:<nautobot-hostname>:device:<uuid>`, for example `nautobot:nautobot.example.com:device:89b2ac3b-1853-4eeb-9ea6-6a081999bd3c`.
- Missing-ID behavior: the record is skipped with `nautobot: skipping device with no usable id: name=<name>`, and a total is printed at the end of the pass. No id is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`** — the literal string `CONFIG` declares. The platform records it expanded, as `id-match id-break mac-match no-mac-break ip-match no-ip-break name-match no-name-break`. The id matches and breaks; a disagreeing MAC, address, or name does not disqualify a merge. That asymmetry is right for a source of truth: Nautobot's addressing is hand-maintained and therefore routinely stale, while its UUID is machine-assigned and cannot drift.
- Verdict: **scoped authoritative.**

### Virtual machines

- Target entity: one row of `virtualization.VirtualMachine`. In Nautobot these are first-class objects with their own interfaces and IP addresses, not children of a device.
- Everything above applies unchanged, except that the class segment is `virtual_machine`, giving `nautobot:<nautobot-hostname>:virtual_machine:<uuid>`, and `deviceType` is set to `Virtual Machine` outright rather than derived from the role.
- Match behavior: the same **`no-mac-break no-ip-break no-name-break`** — one CONFIG-level declaration covers every record this integration emits.
- Verdict: **scoped authoritative.**

## Notes

### What is imported

| Endpoint | Gated by | What it gives |
|---|---|---|
| `GET /api/dcim/manufacturers/` | always | The manufacturer UUID-to-name table, read once per run |
| `GET /api/dcim/devices/` | `import_devices` | The device rows, at `depth=1` |
| `GET /api/dcim/interfaces/` | `collect_interfaces` | Per-interface MACs and IPs, one request per page of devices |
| `GET /api/virtualization/virtual-machines/` | `import_virtual_machines` | The VM rows, at `depth=1` |
| `GET /api/virtualization/interfaces/` | `collect_interfaces` | VM interface MACs and IPs |

Note the last path. `VMInterface` is registered under `interfaces`, not
`vm-interfaces`, so the collection is at `/api/virtualization/interfaces/`.

| runZero | Nautobot |
|---|---|
| `id` | `id` (UUID), namespaced by host and object class |
| `hostnames` | `name` |
| `networkInterfaces` | interface `mac_address` and `ip_addresses`, plus `primary_ip4` and `primary_ip6` |
| `manufacturer` | `device_type.manufacturer.name`, joined from the manufacturer table |
| `model` | `device_type.model` |
| `os` / `osVersion` | `platform.name` / `software_version.version` |
| `deviceType` | `role.name`, mapped through a conservative table; `Virtual Machine` for VMs |
| `firstSeenTS` / `lastSeenTS` | `created` / `last_updated` |
| `tags` | Nautobot tags, plus status, role, location, tenant, platform, and serial |
| `customAttributes` | everything else, under `nautobot_`, including all custom fields |

Only `ImportAsset` objects are produced. Nautobot records intended state: it
inventories no listening services, no installed packages, and no vulnerabilities,
so no `Service`, `Software`, or `Vulnerability` records are emitted. The serial
number is carried as `nautobot_serial` and as a `serial:` tag rather than as an
`ImportAsset` field, because the constructor has no serial parameter.

### Pagination, and why the `next` link is not followed

Nautobot uses the standard Django REST Framework envelope — `count`, `next`,
`previous`, `results` — with `limit` and `offset` as the query parameters, a
default page size from `PAGINATE_COUNT` (50 out of the box) and a hard ceiling
from `MAX_PAGE_SIZE` (1000 out of the box).

The `next` field is an **absolute URL**, and this integration deliberately does
not request it verbatim. Nautobot builds that URL from the `Host` header of the
incoming request, so an install behind a reverse proxy can hand back a hostname
the Explorer cannot resolve or a scheme it should not use. Only the *query
string* is taken from `next` and re-issued against the configured base URL, which
keeps the server's own cursor authoritative — offsets are never recomputed
client-side — without trusting the server's idea of its own address. The `paged`
fixture proves exactly this by returning a `next` pointing at a hostname that
does not exist. A `maxPages` (CONFIG) guard stops a server that answers with a `next`
link forever.

### `depth=1`, and the one relation it does not expand

`?depth=1` expands a device's direct relations into full nested objects; at
`depth=0` a related field is only `{id, object_type, url}`. Both shapes are read,
because the related-object reader tries `name`, `model`, `display`, `label`, and
`value` in turn.

The gap is that depth applies one level. Objects nested *inside* an expanded
object fall back to depth 0, so at `depth=1` a device's `device_type` is a full
object but `device_type.manufacturer` is a bare triple with no name in it.
Raising the request to `depth=2` would expand every other relation as well and
multiply the response size to recover one string. So the **manufacturer table is
read once per run** — a few dozen rows on even a large install — and joined
locally, with `platform.manufacturer` as a last resort.

`SoftwareVersion` needs its own special case: it names its field **`version`**,
not `name`, so the generic reader would fall through to `display`, which prefixes
the platform. **That the field is named `version` was not confirmed from the
vendor's model documentation** — the 2.2 release notes announce the model and the
`Device.software_version` foreign key without listing its fields — so the generic
reader stays as a fallback and a wrong guess degrades to the display string
rather than losing the value.

### Interfaces are fetched per page, not per device

The obvious implementation is one interface request per device, which is an N+1.
Nautobot's interface filters accept a **repeated key** — `?device=<uuid>&device=<uuid>`
— so one request covers a whole page of parents. Ids go in batches of 25 rather
than all 100 at once, because repeating a UUID 100 times builds a query string
around 4 KB and some reverse proxies in front of Nautobot truncate that.

The query string is assembled by hand rather than through the runtime's `params=`
kwarg, because a Starlark dict cannot hold a duplicate key and so can never
express a repeated filter — and because `params=` replaces an existing query
rather than merging with it, which would wipe the cursor. The filter key is
`device`, not `device_id`, because 2.0 stopped supporting `_id`-suffixed filters
and made the plain filter accept a UUID or a name. **The script's comment
additionally claims `device_id` was removed outright in Nautobot 3.x; that was
not confirmed from the 3.0 release notes**, which do not mention filter removals
at all. Either way `device` works on both.

If an interface request fails — a 400 from a filter a particular release does not
recognise is the realistic case — interfaces are abandoned for the rest of that
pass and the parents are still imported with their primary addresses. The virtual
machine pass resets the flag and retries, because the two endpoints have separate
filtersets and one can be unavailable without the other.

### Which interfaces become endpoints, and which addresses are refused

Interfaces whose `type` is `virtual`, `bridge`, `lag`, `lte`, or `other` describe
a logical construct rather than a network adapter and share the MAC of a real
interface underneath them, so emitting them would add a duplicate endpoint rather
than a second one. They are skipped — but their **addresses are kept**, pooled,
and attached to the first physical interface, because an address configured on a
bridge is still a real address. The same pooling handles the device's primary IP,
which Nautobot does not attribute to any interface unless that interface listed
it. A device with no physical interface gets one address-only interface rather
than nothing, so an IPAM-only record still has something to merge on.

`Interface.type` is one of the few genuine choice fields left in the 2.x API and
arrives as `{"value": "virtual", "label": "Virtual"}`. `VMInterface` has no
`type` at all, which is why an absent type is treated as physical rather than
skipped. A disabled interface is skipped outright, and interfaces sharing a MAC
are merged with their addresses unioned.

Nautobot records are hand-maintained, so a placeholder is a realistic data-entry
outcome. Loopback, unspecified, and link-local addresses never reach an interface
— importing a placeholder loopback would merge every device carrying it onto a
single asset — and the all-zero MAC is dropped for the same reason. Nautobot
writes addresses with a mask everywhere except the `host` field, so `192.0.2.1/24`
has its prefix length stripped first, and the interface-to-address relation is
many-to-many in 2.x, so each of an interface's addresses is read.

### Timestamps, device types, and rate limits

`created` becomes `firstSeenTS` and `last_updated` becomes `lastSeenTS`, both
through a guard. `parse_time` **aborts the entire script** on a string it cannot
read, so the shape is matched against a regex first. Parsed values are then
**clamped to now**, because the platform rejects the *entire* `ImportAsset`
carrying a future timestamp — not just the field — so clock skew between Nautobot
and the Explorer would otherwise drop assets silently. The `malformed` fixture
proves this with a device reported as last updated in 2099. `lastSeenTS` is
assigned after construction, because the constructor rejects it as a parameter.

Roles are free text, so only the conventional names appearing in Nautobot's own
example data and documentation are mapped to a `deviceType`. Anything else is
left unset for runZero's fingerprinting to decide: a wrong device type is worse
than none.

Nautobot ships no rate limiter, but installs routinely sit behind nginx, Traefik,
or a WAF that does. Nothing here retries by hand — `get_json` already retries
transient statuses three times with exponential backoff and honours
`Retry-After` — and the `rate-limit` fixture serves a 429 once and counts
attempts to prove the retry actually happens.

### Verification status

Verified against the fixture scenarios in `nautobot/tests/fixtures/` and against
Nautobot's published documentation and source. It has **not** been run against a
live Nautobot instance.

The fixture response shapes follow a `depth=1` capture from `demo.nautobot.com`,
with synthetic UUIDs and RFC 5737 addressing substituted. The
`/api/virtualization/interfaces/` path is confirmed from Nautobot's own
`nautobot/virtualization/api/urls.py`. The `?depth` replacement of `?brief`, the
removal of `_id` filters, the Site-to-Location and DeviceRole-to-Role renames,
and UUID primary keys come from the 2.0 release notes; `SoftwareVersion` from the
2.2 release notes.

Not verified: the field name inside `SoftwareVersion`; the claim that `device_id`
was removed in 3.x; the `/admin/` menu path for assigning object permissions;
whether an administrator can mint a token for another user; and whether
`ipam.view_ipaddress` is enforced on nested `ip_addresses` at `depth=1`.

## Future

- **GraphQL for the main collection.** Nautobot's GraphQL support at `POST /api/graphql/` is first-class, and one query could return devices with nested interfaces, IPs, platform, manufacturer, and location in a single round trip — removing the manufacturer join, the per-page interface request, and the `depth` awkwardness at once. The cost is that a GraphQL query is not paginated the same way, so the whole estate arrives in one response and would need streaming rather than paging.
- **`ipam/ip-addresses/` as a first-class collection.** Addresses arrive nested on interfaces today, so an address recorded in IPAM but assigned to no interface is invisible. Walking `/api/ipam/ip-addresses/` would catch those, and Nautobot's IPAM is frequently more complete than its DCIM. The cost is one more paged collection and a decision about whether an unattached address deserves an asset of its own.
- **Cables and interface connections.** `/api/dcim/cables/` and the `connected_endpoint` relation give the same switchport-to-device adjacency the Netdisco integration produces, except recorded as intent rather than observed. Comparing the two is exactly the gap a source of truth exists to expose.
- **Config contexts.** `/api/dcim/devices/<uuid>/config-context/` returns the merged config context — the data Golden Config and Nornir actually consume. It is arbitrary JSON of arbitrary size, so it needs a cap and an explicit opt-in, but for sites running Golden Config it is the richest per-device data Nautobot holds.
- **Inventory items and modules.** `/api/dcim/inventory-items/` and the 2.3 module model carry line cards, transceivers, and their serial numbers — real hardware with real part numbers, which would sharpen model and manufacturer on chassis devices.
- **Dynamic groups as a filter.** Nautobot 2.x dynamic groups are saved filtersets with a stable UUID. Accepting a group id instead of a raw query fragment would let an operator define the import scope in Nautobot's own UI, where it can be reviewed, rather than in a runZero credential field.

## API documentation

- REST API overview — https://docs.nautobot.com/projects/core/en/stable/user-guide/platform-functionality/rest-api/overview/. Source for pagination (`limit`/`offset`, the `count`/`next`/`previous`/`results` envelope, `PAGINATE_COUNT`, `MAX_PAGE_SIZE`), for the `?depth` parameter and what depth 0 and 1 return, and for the `Accept: application/json; version=X.Y` versioning header.
- REST API authentication — https://docs.nautobot.com/projects/core/en/stable/user-guide/platform-functionality/rest-api/authentication/. Source for the `Authorization: Token $TOKEN` scheme.
- Token model — https://docs.nautobot.com/projects/core/en/stable/user-guide/platform-functionality/users/token/. Source for the Profile → API Tokens UI path, the 40-hexadecimal-character key, the "write enabled" flag, and expiration.
- Object permissions — https://docs.nautobot.com/projects/core/en/stable/user-guide/administration/guides/permissions/. Source for `app_label.action_modelname` naming, for the 403 on a missing base permission, and for constraints filtering the queryset rather than refusing the request.
- Nautobot 2.0 release notes — https://docs.nautobot.com/projects/core/en/stable/release-notes/version-2.0/. Source for `?brief` → `?depth`, the removal of `_id` filters, Site → Location, DeviceRole → Role, and UUID primary keys.
- Nautobot 2.2 release notes — https://docs.nautobot.com/projects/core/en/stable/release-notes/version-2.2/. Source for `SoftwareVersion`, `SoftwareImageFile`, and `Device.software_version`.
- Interface model — https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/interface/. Source for the single optional MAC address, the `enabled` flag, the type field, and the many-to-many relation to IP addresses.
- Virtualization API routes — https://github.com/nautobot/nautobot/blob/develop/nautobot/virtualization/api/urls.py. Proves `VMInterfaceViewSet` is registered under `interfaces`, giving `/api/virtualization/interfaces/`.
- Every instance also serves its own interactive OpenAPI browser at `/api/docs/` and a GraphiQL console at `/graphql/`, which is the fastest way to confirm what a particular release supports.
- Public demo — https://demo.nautobot.com/.

# Custom Integration: TrueNAS

Imports a TrueNAS system over the v2.0 REST API: the appliance itself with its
interfaces, chassis identity, pools and disks; its applications as installed
software and published ports as services; and each virtual machine as its own
asset carrying the MACs of its virtual NICs.

A TrueNAS box is one of the few integration targets runZero can already find on
its own — it has an address, it answers on 443, and a network scan will
fingerprint it. So the honest question is what this adds over a scan, and the
answer is four things a scan cannot see: the **chassis serial and model**, the
**pool and disk inventory** including per-disk models and serials, the
**application and VM inventory**, and **addresses on networks the Explorer
cannot reach** — a storage or replication VLAN that exists only between the NAS
and its clients shows up here and nowhere else.

The virtual machines are the other reason. A TrueNAS host running six guests is
six devices that runZero would otherwise have to discover one at a time, and
this gives it their MACs directly.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the TrueNAS **web interface**, over **HTTPS**. Plain HTTP is not merely discouraged here: TrueNAS *automatically revokes* any user-linked API key presented over an insecure transport, so a misconfigured URL does not fail the run, it destroys the credential.

## TrueNAS requirements

- **TrueNAS SCALE 24.04 or later**, or TrueNAS CORE 13, is what this integration is written against. The parsing is tolerant of both, but see the version notes below — the API this integration uses is on its way out.
- An **API key**, sent as `Authorization: Bearer <key>`.
- TrueNAS ships a **self-signed certificate** by default, which is why `OPTIONS_TLS` is exposed. Nothing is skipped by default; set `tls_disable_validation` or supply the CA if the appliance still has its factory certificate.

### The REST API is deprecated, and that matters here

This is the most important thing to know before configuring anything.

- The TrueNAS REST API is **deprecated in 25.04 (Fangtooth)**. TrueNAS's own release notes say *"The TrueNAS REST API is deprecated in TrueNAS 25.04. Full removal of the REST API is planned for a future release."*
- The replacement is a versioned **JSON-RPC 2.0 over WebSocket** API.
- On 25.x this integration still works, but every poll authenticates against a deprecated interface, and TrueNAS raises a **daily "Deprecated REST API usage" alert** naming the client's address. That alert will be the Explorer. The script detects a 25.x release from `system/info` and warns about this in its own log, so the alert is not a surprise.
- On a release where `/api/v2.0` no longer answers at all, the run stops after the first request and says so explicitly rather than reporting an empty import.

Read the Future section before deploying this against a 25.x or later fleet.

### Creating the credential in TrueNAS

1. Log in to the TrueNAS web interface.
2. Click the **account icon in the top-right toolbar** and choose **My API
   Keys**. This opens the User API Keys screen.
3. Click **Add**, give the key a recognisable name such as `runzero`, and
   optionally set an expiry date. Keys are revocable and can be configured to
   expire on a preset date.
4. Copy the key. TrueNAS *"displays the key string only once, in the API Key
   confirmation dialog, immediately after creation."* There is no way to
   retrieve it later.
5. Confirm it from the Explorer host:

   ```bash
   curl -sk \
     --header 'Accept: application/json' \
     --header 'Authorization: Bearer 1-ExampleFakeApiKeyValue0123456789abcdef' \
     'https://truenas.example.com/api/v2.0/system/info'
   ```

**On privileges, and this is the part to get right.** A user-linked API key
carries the associated user's access level — TrueNAS describes them as allowing
*"password-equivalent access to the TrueNAS middleware"*, and warns that *"a
compromised API key results in access to the TrueNAS API as the associated
user."* They are also **not** subject to the user's two-factor configuration.
The recommended pattern in TrueNAS's own migration guidance is therefore to
create a dedicated **service account**, define its access rights, generate a
user-linked key for it, and give that key to the client — rather than issuing a
key against an admin login.

**What could not be established:** TrueNAS does not publish a per-endpoint
privilege matrix, so there is no documented answer to "which minimum role can
read `system/info`, `interface`, `pool`, `disk`, `app`, and `vm`". This
integration reads only, and every endpoint it touches is a `query`-style read,
but whether a non-privileged service account can reach all six was not
confirmed from documentation. Start with an account that works, then narrow it
and re-check that all six endpoints still answer — the script logs each one that
does not, so a narrowed account produces a readable partial result rather than a
silent one.

**On where the key lives.** The path above is the one TrueNAS documents. There
is also a per-user route through **Credentials → Users**, editing a user and
managing that user's API keys, which is how the user-linked key model is
administered in 25.04 and later; the script's own parameter description names
that route. Both reach the same object. Older releases (24.10 and earlier) had a
single non-user-linked keyring reached from the top bar; on upgrade those legacy
keys migrate to the `root`, `admin`, or `truenas_admin` account depending on how
the server is configured, and any legacy key created through the API with a
white-listed method allow-list is **revoked** by the upgrade.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "TrueNAS").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **TrueNAS URL** (`url`): the base URL of the web interface, for example `https://truenas.example.com`. The `/api/v2.0/` path is appended automatically.
   - **API key** (`api_key`): the key from step 4.
   - **Collect virtual machines** (`collect_vms`): optional, default enabled.
   - **Collect applications** (`collect_apps`): optional, default enabled.
   - **Collect pools and disks** (`collect_storage`): optional, default enabled.
   - **Page size** (`page_size`): optional, default 100.
   - **Maximum records per collection** (`max_records`): optional, default 5000, `0` removes the cap.
   - **TLS options** (`tls_*`): set these if the appliance still has its factory self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. A NAS inventory changes slowly, so daily is plenty — and on 25.x, each run costs a deprecation alert, so do not poll it hourly.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from TrueNAS.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:truenas`.
- The appliance carries `tag:truenas` and `tag:nas`; each guest carries `tag:truenas` and `tag:truenas-vm`, so `tag:truenas-vm` is the whole guest estate.
- Appliance facts are searchable under the `truenas_` prefix — `truenas_system_serial`, `truenas_pools`, `truenas_pool_status`, `truenas_disk_models`, `truenas_disk_serials`, `truenas_apps`, `truenas_cpu_model`, `truenas_version`.
- Guest facts use the same prefix — `truenas_vm_state:RUNNING`, `truenas_vm_uuid`, `truenas_vm_memory_mib`, `truenas_appliance` (which NAS it lives on).

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
key and see what a real appliance returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename truenas/truenas.star \
  --kwargs url=https://truenas.example.com \
  --kwargs api_key=1-ExampleFakeApiKeyValue0123456789abcdef0123456789abcdef01 \
  --kwargs collect_vms=true \
  --kwargs collect_apps=false \
  --kwargs page_size=25 \
  --kwargs max_records=100 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/truenas-run --overwrite
```

`--output` writes the serialized assets to a directory so you can inspect
exactly what would be imported; `--overwrite` lets you re-run into the same
directory. Capping `max_records` on a first run keeps a shelf full of disks from
turning a smoke test into a full collection.

No parameter here takes a comma-bearing value, so the usual `--kwargs`
comma-splitting caveat does not apply to this integration.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real appliance:

```bash
runzero script --filename truenas/truenas.star --validate
```

Be aware of what that does **not** prove. The validator's dummy server answers
`system/info` with a shape the script rejects, so the run stops at the first
request and the remaining seven endpoints — and all of the parsing — are never
reached. `--validate` reporting success here means the CONFIG parses and one
HTTP request was made, nothing more. The fixture scenarios are what exercise the
parsing:

```bash
python3 tests/run.py truenas
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://truenas.example.com,api_key=1-Example...'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two kinds of asset are emitted and they are keyed on completely different
principles, so they are described separately.

They are emitted as two declared asset types — `system` and `vm` — selected per
record with `ImportAsset(assetType=...)`, and each type's merge policy is
declared under that key in `CONFIG["assetTypeBehavior"]`.

`type-break` is left ON (the default), so a `system` and a `vm` never merge with
each other. A guest is not its host, and the two populations carry disjoint
hardware: the system asset's interfaces come from the NAS's own NICs, a VM's
from its virtual NICs. Keeping the break on is what stops a bridged guest
answering on the management segment, or a VM named after the NAS, from folding
the storage system into one of the machines it happens to be running.

### The TrueNAS system

- Target entity: the appliance itself.
- Source ID field: **none.** This is the honest statement and it drives everything else here.
- Documentation evidence: TrueNAS publishes no identifier for the *system* that survives a reinstall. `system_serial` is copied from SMBIOS, and on a self-built NAS — which is most of them — it reads `To be filled by O.E.M.`, `Default string`, or `System Serial Number`, values that appear on thousands of unrelated machines. The middleware's own ids (`pool.id`, `disk.identifier`, `vm.id`) are per-object, not per-system.
- Uniqueness scope: the **hostname in the configured URL**, taken from the credential. The scheme and port are dropped, so reaching the same appliance on a different port does not change the identity of its assets.
- Cardinality: exactly one per run.
- Stability: stable for a fixed credential. It is **not** stable across a change to the configured URL — pointing the credential at `192.0.2.10` instead of `truenas.example.com` produces a different id and therefore, potentially, a second asset. This is the weakest link in the record and it is a property of the design, not a bug: with no vendor identifier to key on, the operator-supplied URL is the only stable thing available.
- Reuse behavior: not applicable — nothing is issued, so nothing is recycled.
- Presence: always.
- Final runZero ID: `truenas:<hostname-from-url>:system` — for example `truenas:truenas.example.com:system`.
- Missing-ID behavior: the run aborts before any asset is emitted if the hostname cannot be parsed out of the configured URL, printing `truenas: could not determine the host from the configured URL`. No id is invented and `new_uuid()` is never used.
- Asset type: **`system`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**.
- Verdict: **weak scope, strong correlators.** The id is a convenience key, not an authority. What actually merges this asset with the one runZero scanned on the network is the interface MACs, the addresses, and the hostname — so none of those may disqualify a merge, which is exactly what the match behavior says. Note that the id *does* drive a merge when it matches (`id-match id-break`), which is fine: two runs against the same URL are the same appliance.

The serial is imported when it is real and dropped when it is an SMBIOS
placeholder, which is the right call — importing `Default string` as a serial
number would make it a false correlator across every white-box NAS in the
estate.

### Virtual machines

- Target entity: one guest defined on the appliance.
- Source ID field: **`id`**, the middleware's own row id for the VM, an integer.
- Documentation evidence: `id: int` is a declared field of `VMEntry` in the middleware's API model, and it is the path parameter of every per-VM route.
- Uniqueness scope: **one appliance**. It is a per-system counter, so it is namespaced on the NAS.
- Cardinality: one row per guest.
- Stability: stable for the life of the VM. It survives rename, reconfiguration, and start/stop.
- Reuse behavior: **recycled.** A deleted VM's id can be handed to a new one by the middleware's own counter. This is why the id is not allowed to drive a merge — see the match behavior below.
- Presence: required, but a malformed row can carry a null id; that row is skipped with `truenas: skipping VM with no id: name=<name>`.
- Final runZero ID: `truenas:<hostname-from-url>:vm:<id>` — for example `truenas:truenas.example.com:vm:1`.
- Missing-ID behavior: skip the record and log it. A VM that has *neither* a MAC *nor* a DNS-shaped name is also skipped, with `truenas: skipping VM <id> with no MAC and no usable name`, because such an asset would have no correlator at all and could never merge with anything.
- Asset type: **`vm`**.
- Match behavior: **`no-id-match no-id-break`** — the id is explicitly *not* used for matching, in either direction. Merging is left entirely to the MAC and the name.
- Verdict: **local key, deliberately non-authoritative.** This is the right choice given id reuse: an id that can be reassigned must never merge two assets together, and this one cannot.

`uuid` is present on modern SCALE releases and would be a better key, but it is
absent on CORE and null on older rows, so it is recorded as an attribute rather
than used. That is a defensible trade and it is worth revisiting once CORE is
out of scope — see Future.

**A guest's name is not a hostname unless it looks like one.** A VM's name is an
operator-chosen label; `Windows 11 Desktop` is as valid to TrueNAS as
`ubuntu-server`. Importing free text as a hostname would invite runZero to
correlate two unrelated guests on two unrelated appliances that happen to share
a label, so only DNS-shaped names become hostnames, and a guest with neither a
MAC nor a DNS-shaped name is skipped rather than imported uncorrelatable.

### Applications are not assets

An application on TrueNAS runs in the host's network namespace or behind a
published host port. It has no address, no MAC, and no hostname of its own.
Emitting one as a device would either create an asset with no correlator or give
a second asset the NAS's address — and the second is worse, because it merges a
container with its host. So applications are imported as what they are:
**software** installed on the NAS, and **services** listening on it, with the
published host port and the NAS's own address.

## Notes

### What is imported

Up to eight requests per run, in this order:

```
GET /api/v2.0/system/info
GET /api/v2.0/network/configuration
GET /api/v2.0/interface
GET /api/v2.0/pool?limit=&offset=
GET /api/v2.0/disk?limit=&offset=
GET /api/v2.0/app?limit=&offset=            (falls back to /chart/release)
GET /api/v2.0/vm?limit=&offset=
GET /api/v2.0/vm/device?limit=&offset=      (only when needed — see below)
```

| runZero | TrueNAS |
|---|---|
| appliance `id` | the hostname from the configured URL |
| `hostnames` / `domain` | `network/configuration` `hostname` and `domain`, falling back to `system/info` `hostname` |
| `networkInterfaces` | `interface` — `state.link_address` for the MAC, `state.aliases` and the top-level `aliases` for addresses |
| `manufacturer` / `model` | `system_manufacturer` / `system_product` |
| `osVersion` | `version`, with the brand prefix stripped |
| `software` | `app` — one per application |
| `services` | `app` `active_workloads.used_ports[].host_ports[].host_port` |
| appliance attributes | CPU, memory, timezone, uptime, licence, pools, pool status, disk count, disk models, disk serials |
| VM `id` | `vm` `id` |
| VM `networkInterfaces` | the `NIC` devices' `mac` |

### Pagination has no envelope

TrueNAS collection endpoints take the documented `limit` and `offset` query
parameters and return a **bare JSON array** — no total, no cursor, no wrapper.
So a short page is the only end-of-collection signal available, and that is what
the walk uses. `max_records` exists because a system with a few hundred disks
would otherwise be read in full before anything is emitted; reaching it logs
`truenas: record cap of <n> reached for <path>`.

`system/info`, `network/configuration`, and `interface` are singletons or small
enough not to need paging and are fetched whole.

### Every endpoint is allowed to fail

A failing endpoint is reported and returns `None`, and the run continues. This
is deliberate rather than lax: the same script has to work across CORE, four
generations of SCALE, and systems where the operator has narrowed the service
account. An appliance with no VM support, no application catalog, or no pools is
a normal outcome, not an error.

The one exception is `system/info`. If that does not answer, the run stops
rather than emitting an appliance asset with no facts on it, and prints the
three most likely causes — wrong URL, wrong key, or a release that no longer
serves `/api/v2.0` at all.

### The application catalog moved twice

`/app` is the Docker-based catalog on SCALE 24.04 and later. It replaced the
Kubernetes-era catalog at `/chart/release`, which was removed in 24.10. This
integration tries `/app` first and falls back to `/chart/release` only when the
first genuinely fails — an empty `/app` is an answer, not a failure, so it does
not trigger the fallback and does not spend the extra request. Both failing on
CORE is expected and is logged as such rather than as an error.

### The VM device list moved onto the VM

Current releases embed the device list on each VM row, so the NIC MACs are
already in the `/vm` response. The separate `/vm/device` endpoint is requested
**only** when no NIC turned up inline across the whole VM list, which is the
signal that this release keeps devices separately. On a modern appliance that
eighth request never happens.

The NIC discriminator also moved: it used to be a top-level `dtype` on the
device row and is now `attributes.dtype`. Both are read.

### MACs are canonicalized, not normalized

`normalize_mac` is deliberately **not** used on VM MACs. It clears the locally
administered bit, and every MAC TrueNAS generates for a virtual NIC sets that
bit — two guests could otherwise collide on one normalized value. Instead the
MAC is lower-cased and colon-formatted by hand, and a multicast address (an odd
first octet), an all-zero, and an all-ff MAC are each rejected outright.

### Addresses that identify nothing

Loopback, unspecified, broadcast, and link-local `169.254/16` and `fe80::/10`
are all screened before an address reaches an interface. Link-local is the one
that matters: the platform's own address filter deliberately **keeps** it, so an
appliance that has fallen back to APIPA would otherwise correlate with every
other DHCP-failed host in the estate.

Interfaces belonging to container and guest plumbing — `lo`, `docker*`, `veth*`,
`vnet*`, `kube-*`, `cni*`, `flannel*`, `cali*`, `tun*`, `tap*`, `wg*`, `zt*`,
`virbr*`, `ix-*` — are dropped by name. **Bridges are deliberately not
filtered**: a TrueNAS host that runs VMs usually carries its own address on
`br0`, so filtering `br` would discard the only address the system has.

### Defects found and fixed while writing the fixtures

Three real bugs were found by building the fixtures, and all three are fixed in
the script as shipped. They are recorded here because two of them are worth
knowing about generally:

1. **Starlark strings are not iterable.** `_major()` walked a version string
   with `for character in head`, which aborts the entire run with
   `string value is not iterable` — Starlark is not Python here. Because
   `_major()` is called immediately after the first request, the integration
   aborted on **every** real run. `--validate` could not catch it: the
   validator's dummy server answers `system/info` with a shape the script
   rejects, so the run returns before reaching the crash. Fixed by walking
   `head.elems()`, which is the repo's existing idiom.
2. The same bare-string iteration existed in `_dns_name()`.
3. `build_vm_asset()` called `_hostname()` where it meant `_dns_name()`, so the
   guard that stops an operator's free-text VM label from becoming a hostname
   was never actually applied — `_dns_name()` was dead code. Fixed, and the
   `happy` and `malformed` fixtures both assert that a VM named
   `Windows 11 Desktop` with no NIC is skipped.

### Verification status

Verified against local fixtures and against the TrueNAS middleware's own API
models, not against a live appliance. Every response shape in the fixtures is
taken from the pydantic models in `truenas/middleware`:

- `system.info` keys from `middlewared/plugins/system/info.py`.
- `InterfaceEntry` and `InterfaceEntryState` — including `link_address`,
  `permanent_link_address`, and the `aliases` list with its `type`/`address`/
  `netmask`/`broadcast` members — from `middlewared/api/v25_10_0/interface.py`.
- `NetworkConfigurationEntry` from `middlewared/api/v25_10_2/network_configuration.py`.
- `PoolEntry` and `DiskEntry` from `middlewared/api/v25_10_2/{pool,disk}.py`.
- `AppEntry`, `AppActiveWorkloads`, `UsedPorts`, and `HostPorts` from
  `middlewared/api/v25_04_0/app.py`.
- `VMEntry`, `VMStatus`, `VMDeviceEntry`, and `VMNICDevice` from
  `middlewared/api/v25_04_2/{vm,vm_device}.py`.

**Not verified:** no live appliance was polled. TrueNAS does not containerize in
any way that would produce a useful capture — it is an appliance OS, not a
service — so no container was attempted. The credential-privilege question noted
above is unresolved, and the exact UI path for API key creation is documented
from TrueNAS's own docs for the current release only; older releases differ, and
the README says which.

## Future

- **Move to the JSON-RPC 2.0 WebSocket API.** This is the important one. The REST API is deprecated as of 25.04 and slated for removal, and the WebSocket API is where TrueNAS is going. It is a larger change than an endpoint swap — a persistent connection, a login call, and a request/response correlation model — and it needs a version probe so one script can serve both. Until then, this integration has a shelf life.
- **Use `uuid` as the VM identity once CORE is out of scope.** A UUID does not get recycled the way a row id does, which would let the VM id drive merges instead of being explicitly excluded from them. The blocker is that `uuid` is absent on CORE and null on older SCALE rows.
- **Read guest addresses, not just MACs.** A running VM's addresses are visible to the host through the bridge's forwarding table and, for some guest agents, through the middleware. Today a guest arrives with a MAC and no address, which merges correctly but tells an operator less than it could.
- **`virt.instance.query` for LXC containers.** Recent releases added an incus-based virtualization layer alongside the libvirt VMs. Those instances are guests too, and they are not in `/vm`.
- **Pool and dataset topology as attributes rather than a summary.** Today pools become a name list and a status list. The `topology` member of `PoolEntry` describes vdevs, their members, and their redundancy, which is genuinely useful for a storage inventory and is one more field away.
- **SMART and enclosure data.** `DiskEntry` carries `enclosure` (number and slot), and the middleware exposes SMART attributes separately. Slot-level placement is what turns a disk serial into something an operator can act on.
- **Certificate inventory.** TrueNAS manages its own certificates and CAs, and those are assets in their own right for an estate tracking expiry.

## API documentation

- TrueNAS API reference index — https://www.truenas.com/docs/scale/api/. The versioned reference for the endpoints used here.
- Managing API Keys / User API Keys Screen — https://www.truenas.com/docs/scale/toptoolbar/settings/apikeysscreen/. Source for the account icon → **My API Keys** → **Add** path, "displays the key string only once", "password-equivalent access to the TrueNAS middleware", the 2FA exemption, and the automatic revocation of a key sent over plain HTTP.
- 25.04 (Fangtooth) version notes — https://www.truenas.com/docs/scale/25.04/gettingstarted/scalereleasenotes/. Source for "The TrueNAS REST API is deprecated in TrueNAS 25.04. Full removal of the REST API is planned for a future release.", the JSON-RPC 2.0 over WebSocket replacement, user-linked API keys, and the legacy key migration and revocation rules.
- `truenas/middleware` source — https://github.com/truenas/middleware. The authority for every response shape; the specific model files are listed under Verification status.

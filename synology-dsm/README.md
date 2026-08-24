# Custom Integration: Synology DSM

Imports a Synology NAS **and the devices it knows about** — Virtual Machine
Manager guests, Surveillance Station cameras, the machines Active Backup for
Business protects, and DHCP leases where the NAS is the DHCP server.

The NAS itself is easy. The reason this integration is worth having is the
second half: a Synology in a small office is frequently also the camera NVR, the
backup server, and the hypervisor, and each of those roles makes it the only
system that knows a particular set of devices exists.

**Read [What actually yields other devices](#what-actually-yields-other-devices)
before deploying.** Every one of those sources depends on an add-on package, and
a bare DSM with no packages produces exactly one asset.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to DSM, normally on port 5001.

## Synology requirements

- **DSM 6 or DSM 7.** Both are supported and the differences are handled by discovery rather than by configuration — see [Nothing is hardcoded](#nothing-is-hardcoded).
- **An administrator account.** This is not a preference, it is a constraint of the platform, and it is worth being blunt about it.

### Why administrator is required

DSM gates its APIs with a per-API `allowUser` list, and the split falls badly
for an inventory tool:

| API | Administrator required? | What it gives |
|---|---|---|
| `SYNO.DSM.Info` | **No** — a normal user can read it | Model, serial, DSM version, RAM, temperature, uptime |
| **`SYNO.DSM.Network`** | **Yes** | **The NAS's own MAC addresses and IPs** |
| `SYNO.Core.System` | **Yes** | CPU, firmware date, attached USB devices |
| `SYNO.Core.Network.DHCPServer.*` | **Yes** | DHCP leases |
| `SYNO.SurveillanceStation.Camera` | No, but needs the Surveillance Station application privilege | Cameras |

`SYNO.DSM.Network` is the **only** API that exposes the NAS's own MACs, and it
is administrator-gated. A non-administrator account therefore yields a record
with a serial number and nothing runZero can correlate on — no MAC, no address
beyond the one you connected to, and a hostname only if you addressed the NAS by
name. This integration does not pretend otherwise: it emits nothing in that case
and says which API needs the rights. The `non-admin` fixture scenario pins that
behavior deliberately.

### Creating the credential

1. In DSM, go to **Control Panel → User & Group → User → Create**.
2. Create a user, for example `runzero`, and add it to the **`administrators`** group.
3. Harden it, because API data access survives all of this:
   - **Deny access to every shared folder.**
   - **Deny access to every application** except Surveillance Station, and grant that only if you want cameras imported.
   - Set a long random password.
4. **Do not enable 2FA on this account.** A one-time code expires in seconds and cannot be supplied by a scheduled task. The `otp_code` parameter exists only for a one-off manual run.
5. If DSM's auto-block is on, add the Explorer's address to **Control Panel → Security → Account → Auto Block → Allow List**, so a burst of runs cannot lock the account out.

Confirm the credential from the Explorer host:

```bash
# 1. what this DSM publishes
curl -sk 'https://nas.example.com:5001/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all'

# 2. sign in
curl -sk -X POST 'https://nas.example.com:5001/webapi/entry.cgi' \
  -d 'api=SYNO.API.Auth&version=6&method=login&account=runzero&passwd=<secret>&session=runzero&format=sid&enable_syno_token=yes'
```

A success returns `{"data":{"sid":"...","synotoken":"..."},"success":true}`. A
failure returns HTTP **200** with `{"success":false,"error":{"code":400}}` — the
status code says nothing, the body is the only signal.

### Transport

DSM listens on **5000 (HTTP)** and **5001 (HTTPS)** by default, with a
self-signed certificate on 5001. Include the port in the URL. Set the TLS
options accordingly rather than assuming validation will pass.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Synology DSM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **DSM URL** (`url`): including the port, for example `https://nas.example.com:5001`.
   - **Username** (`username`) and **Password** (`password`).
   - **One-time password** (`otp_code`): leave blank; see above.
   - **Collect Virtual Machine Manager guests** (`collect_vms`) / **Collect Surveillance Station cameras** (`collect_cameras`) / **Collect Active Backup for Business devices** (`collect_backup_devices`) / **Collect DHCP leases** (`collect_dhcp_leases`): optional, all default enabled and all skipped automatically when the package is absent.
   - **DHCP interfaces** (`dhcp_interfaces`): optional, default `bond0,eth0,ovs_eth0,eth1`.
   - **Maximum assets** (`max_assets`): optional, default 5000.
   - **TLS options** (`tls_*`): set these for DSM's self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Select the Explorer you would like the Custom Integration to run from.
   - **Run it from one Explorer, on a schedule that does not overlap.** DSM's concurrent-session allowance is small; see [Sessions](#sessions).
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Synology DSM.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:synology-dsm`.
- Split the asset kinds with `tag:synology-nas`, `tag:synology-vm`, `tag:synology-camera`, `tag:synology-backup-device`, and `tag:synology-dhcp-lease`.
- Find the NAS by serial with `tag:serial:2140PDN123456`.
- Find machines whose backup agent has gone quiet with `synology_agent_status:offline`.

## Running it from the command line

```bash
runzero script --filename synology-dsm/synology-dsm.star \
  --kwargs url=https://nas.example.com:5001 \
  --kwargs username=runzero \
  --kwargs password='correct horse battery staple' \
  --kwargs tls_disable_validation=true \
  --kwargs collect_cameras=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/synology-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real NAS:

```bash
runzero script --filename synology-dsm/synology-dsm.star --validate
```

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://nas.example.com:5001,username=runzero,password=...'
```

**One CLI caveat, and `dhcp_interfaces` is not caught by it.** `--kwargs` passes
a value through verbatim, commas included, as long as the pair contains a single
`=`, so the default `bond0,eth0,ovs_eth0,eth1` and any list like it can be given
on the command line as written. What breaks is a value carrying a *second* `=`
**as well as** a comma: that pair is re-read as CSV, so the value is cut off at
the comma and the remainder becomes a parameter the integration never declared.
A password is the value here that could be that shape — set it through the
console credential form, or wrap the argument in double quotes so it stays a
single field (`--kwargs '"password=a=b,c"'`).

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Five asset kinds. Two carry a real vendor identifier and drive merges; three are
records *about* machines that other systems own, and are deliberately inert.

### The NAS — authoritative

- Source ID field: **`serial`** from `SYNO.DSM.Info`, the serial on the chassis. It is unique to the hardware and survives a DSM reinstall, a re-address, and a rename.
- Final runZero ID: `synology:serial:2140PDN123456`. No host scope, deliberately — the serial is globally unique, so the same NAS polled by IP in one task and by DNS name in another produces **one** asset.
- Match behavior: `"no-mac-break no-ip-break no-name-break"`.
- Missing-ID behavior: falls back to `synology:<configured-host>:nas` with `no-id-match no-id-break`, and logs that it did — a host-derived id is an *address*, and addresses are recycled. `SYNO.DSM.Info` is readable without administrator rights, so in practice the serial is present whenever anything else is.
- The factory hostname `DiskStation` is treated as a placeholder and not imported, for the same reason `localhost` is not: on the fallback branch there is no stable id, so merging falls back to MAC, IP, and hostname, and a name every unconfigured unit shares would merge unrelated NASes.
- Verdict: **authoritative vendor identifier.**

### VMM guests — authoritative

- Source ID field: **`guest_id`**, a VMM-assigned UUID. It is stable across a rename, a migration between hosts, and a DSM upgrade.
- Final runZero ID: `synology:vm:49dee62c-8ea2-465b-9dff-815025f91bba`. Unscoped, because a UUID does not need it.
- Match behavior: `"no-mac-break no-ip-break no-name-break"`.
- **A guest is only emitted when it has at least one virtual NIC MAC.** VMM reports no IP address for a guest at all, so the MAC is the only correlator there is; a guest without one could never merge with the machine runZero scans and would sit in the inventory forever as a duplicate. Those are counted and logged, not invented.
- This depends entirely on using the **right API**. `SYNO.Virtualization.API.Guest` is the official, documented one and is the only one that returns `vnics`. The similarly named `SYNO.Virtualization.Guest` is the internal UI API: it has no `vnics` at all, and its `ip` field is an empty string in practice. Integrations built on the internal API never surface guest MACs, which is why this one calls the documented one with `additional=["vnics"]`.
- Verdict: **authoritative vendor identifier.**

### Cameras — derived

- Source ID field: the Surveillance Station **camera `id`**, a small per-install integer (`1`, `2`, `3`).
- Final runZero ID: `synology:<nas-host>:camera:1`. Scoped, because camera `1` exists on every Surveillance Station on earth.
- Match behavior: `no-id-match no-id-break`. The index is **reused** when a camera is deleted and another added, so letting it drive a merge would eventually merge a new camera onto a retired one's asset — and **nothing could veto it**, because the platform's foreign-id match path consults only a site check and a collision helper whose allowlist does not include custom integrations, so the MAC, IP, and name break flags are never consulted once an id matches.
- Correlation runs on the address. **Surveillance Station reports no MAC for a camera anywhere in the response**, so the address in `host` is all there is — and `host` may hold an IP, a hostname, or a DDNS name, so both forms are handled. A camera with neither is skipped and counted.
- The camera's display name is imported as a hostname **only when it is shaped like one**. A free-text label such as `Front Door` is an operator annotation, not a machine name — a value with a space or any other character that cannot appear in a DNS name is kept in the `synology_camera_name` attribute and stays off the hostname list, where it would be a weak merge key.
- `vendor` and `model` are only imported when they are not the literal placeholders `User` and `Define`, which is what Surveillance Station stores for a manually added generic camera.
- Verdict: **derived / non-authoritative.**

### Active Backup devices — derived

- Source ID field: **`device_uuid`**, falling back to `id-<device_id>` when the uuid is empty. The two live in separate id namespaces so a uuid can never collide with a numeric id, and `device_id: 0` is treated as Active Backup's unset sentinel rather than a real id — taking it literally would key every unregistered row on `0` and collapse them into one asset.
- Final runZero ID: `synology:<nas-host>:backup-device:<uuid>`.
- Match behavior: `no-id-match no-id-break`. The uuid identifies an **agent registration**, not a machine: reinstalling the agent mints a new one, and the same physical laptop would fork. These are records about machines runZero will discover properly by itself, so correlation belongs on the address and hostname, which every imported record carries.
- The same device appears once per task it belongs to; duplicates are folded before anything is emitted.
- Verdict: **derived / non-authoritative.**

### DHCP leases — derived

- Source ID field: the **MAC**, the only identifier a lease has.
- Final runZero ID: `synology:<nas-host>:lease:<mac>`.
- Match behavior: `no-id-match no-id-break`, for the reason a MAC always demands it — MACs move with a NIC, are spoofed, and are randomized per network by modern clients.
- The MAC is canonicalized **losslessly** — lower-cased, separators stripped, re-joined with colons. `net.normalize_mac` and `net.network_interface` are deliberately not used for this, because they clear the locally administered bit, and every randomized client MAC sets it. The emitted `NetworkInterface` still goes through `network_interface`, which is correct there.
- Multicast MACs and the all-zeros MAC are skipped, and **the NAS's own MACs are excluded** so the NAS does not also appear as one of its own DHCP clients.
- Verdict: **derived / non-authoritative.**

The `no_mac_in_id` fixture invariant is skipped for this integration, with the
reason recorded in each scenario. It exists to catch a MAC used as an id
*without* these safeguards.

## Notes

### Nothing is hardcoded

Every run begins with `SYNO.API.Info`, and the catalog it returns drives
everything after it. That is not politeness, it is a requirement:

- **The CGI differs by DSM version.** `SYNO.API.Auth` is served from `auth.cgi` on DSM 6 and `entry.cgi` on DSM 7. Hardcoding either produces an error 102 on exactly the installs hardest to debug remotely.
- **Version ranges differ per API.** `SYNO.DSM.Info` and `SYNO.DSM.Network` are **version 2 only** — asking for version 1 or 3 fails with error 104. Preferred versions are clamped into each API's advertised range.
- **Optional packages are detected, not assumed.** A NAS without Surveillance Station is never asked about cameras; the collection is skipped with a message naming the API that is absent. The `non-admin` scenario proves that no request is made for any of the four optional collections when the catalog does not list them.
- **The DHCP API was renamed.** DSM 6 has the DHCP server built in as `SYNO.Core.Network.DHCPServer.ClientList`; DSM 7 moves it to a separate package and clients report `SYNO.Network.DHCPServer.ClientList`. Both spellings are probed.

`SYNO.SurveillanceStation.Camera` is the one place a version is deliberately
held *below* the advertised maximum: v8 and v9 restructure the response, so it
is capped at 7.

### Login and CSRF

The login is a **POST with a form-encoded body**, not a GET, so the password
never enters a URL that DSM or an intervening proxy might log. `format=sid` asks
for the session id in the JSON body rather than as a cookie, which keeps the
flow explicit and needs no cookie jar.

`enable_syno_token=yes` is **always** sent. A DSM with *"Improve protection
against cross-site request forgery attacks"* enabled refuses subsequent calls
without the returned `SynoToken`, and asking for it costs nothing on a DSM that
does not need it. When one comes back it is sent as `X-SYNO-TOKEN` on every
later request.

One implementation detail that is easy to get wrong: the HTTP options are
rebuilt per request rather than cached once, because `get_http_options` snapshots
the header map into the Go layer and the token does not exist until after login.
Caching the options up front would silently drop the CSRF header on exactly the
hardened DSMs that need it.

### Sessions

DSM allows few concurrent sessions and a session lingers well past a collection
run, so this integration ends with an explicit `logout`. A scheduled task that
never logged out would eventually lock itself out of its own account.

Error codes `106` (session timeout), `107` (interrupted by duplicate login), and
`119` (invalid session) mid-run trigger **one re-login**: the script
re-authenticates with the stored username and password (deliberately without
the OTP, which is single-use and long expired by then) and retries the failed
request with the new session id, so a duplicated login from another tool costs
one round trip instead of every remaining collection. If the retry fails too,
the collection is reported as a session problem naming the concurrent-session
limit, rather than as an empty result — the usual cause is a second tool
signing in as the same account — and no further re-login is attempted that run.

Two more codes worth knowing: `105` means the account is not an administrator
and is reported as such, and `150` means the request arrived from a different
address than the login did, which bites when an Explorer egresses through more
than one address.

### What actually yields other devices

Be realistic about this before deploying. **A bare DSM with no add-on packages
produces exactly one asset — the NAS.** Everything else needs a package:

| Source | Package | Yields | Quality |
|---|---|---|---|
| VMM guests | Virtual Machine Manager | MAC only, no IP | Good — a MAC merges cleanly |
| Backup devices | Active Backup for Business | IP, hostname, OS name | **Best described**, no MAC |
| Cameras | Surveillance Station (+ licenses) | IP or hostname, vendor, model, firmware | Good, no MAC |
| DHCP leases | DHCP Server (built in on DSM 6) | MAC, IP, hostname | Best shape, rarely present |

Two caveats worth stating to whoever asks for this integration:

- **Surveillance Station licensing bounds what you see.** A NAS ships with 2 free device licenses (4 on NVR models); beyond that, licence packs must be bought. Expect two cameras unless the customer paid for more.
- **Most Synology units are DHCP clients, not servers.** The lease collection commonly finds nothing, and says so rather than erroring.

### SRM is a different product

Synology Router Manager has `SYNO.Core.Network.NSM.Device`, which enumerates
every client connected to the router — precisely the data this integration would
most like to have. **It does not exist on DSM.** It is absent from real DSM 6 and
DSM 7 API catalogs and from a full DSM 7.x API definition dump, and appears only
in libraries written for SRM routers. This integration does not request it and
does not promise it. An SRM integration would be separate work; see
[Future](#future).

### Verification status

Verified against local fixtures, Synology's official developer PDFs, and two
community clients whose test fixtures are real captures. **Synology does not
containerize** — DSM is a licensed OS distribution tied to Synology hardware —
so no container was run for this integration, and no live NAS was available.

Confirmed from official documentation: the `SYNO.API.Info` contract, the login
parameters and version guidance, the `format`/`enable_syno_token` semantics, the
common and authentication error tables, the default ports, and the VMM guest
shape including `vnics[].mac`. Confirmed from real captures published by
community clients: the `SYNO.DSM.Info`, `SYNO.Core.System`, `SYNO.DSM.Network`,
Surveillance Station camera, and Active Backup task response shapes, and the
DSM 6 versus DSM 7 catalog differences. Administrator gating was confirmed from
a DSM 7.x API definition dump that exposes each API's `allowUser` list.

**Two things are explicitly unverified and are handled defensively rather than
assumed:**

- **The DHCP lease record schema.** Synology documents none, and no public capture exists. DSM's own UI confirms the *columns* are MAC, IP, hostname, lease expiry, and reservation status, so the data is there — but the JSON keys are unknown. Every lease field is therefore read through a list of candidate spellings (`mac`/`mac_address`/`hwaddr`/…​), and the collection wrapper is likewise probed across `clients`/`leases`/`items`/`data`/`list`. A response whose list lives under a key none of the candidates name is no longer a silent zero: the script logs the keys it actually received, so a schema drift is visible in the task log. The lease expiry is preserved verbatim as a string and **never** converted into a timestamp, because whether it is an epoch, a duration, or a formatted date is not established, and a value misread into the future would make the platform reject the whole record.
- **The Active Backup device nesting.** `data.tasks[].devices[]` is reconstructed from community captures. The script also accepts a top-level `data.devices[]` list, and when a non-empty response yields no device row under either shape it logs the response keys rather than quietly reporting zero backup devices.
- **POST with a form-encoded body is convention, not specification.** Synology's guides show only GET templates and never name a content type. Every community client posts form bodies against real hardware, so it is well proven in practice, but it is undocumented.

A live NAS would settle both, and the lease schema is the single most valuable
thing to confirm.

## Future

- **Confirm the DHCP lease schema against a live NAS.** The candidate-key approach works but is a hedge; one capture would replace it with certainty.
- **Synology Router Manager.** SRM's `SYNO.Core.Network.NSM.Device` returns every connected client with MAC, IP, and hostname — the single richest device source in the Synology ecosystem. It is a different product with a different API surface and deserves its own integration rather than being bolted onto this one.
- **`SYNO.Entry.Request` compound calls.** DSM can batch several API calls into one round trip. It would cut this integration to two or three requests, but it is entirely undocumented and carries a nasty trap: the outer `success` stays `true` even when a sub-request fails, so `has_fail` and each `result[i].success` must be checked independently. Worth doing with a live NAS to test against, not before.
- **`SYNO.Core.CurrentConnection`.** Lists active SMB/AFP/FTP sessions, which implies client addresses, and is readable by a non-administrator. It is a point-in-time snapshot of *active* sessions, so it is volatile and sparse — but it is the only device source on this list that does not need a package, which makes it the natural answer for a bare DSM.
- **Surveillance Station camera MACs.** The camera list has none. `SYNO.SurveillanceStation.Camera.Search` or the per-camera detail endpoints may expose more; if a MAC is reachable anywhere, cameras become far better assets.
- **Services on the NAS.** DSM knows which of its own services are enabled and on which ports — a natural `Service` list, and useful exposure data for a device that often has more listening than its owner realises.
- **Installed packages as software.** `SYNO.Core.Package` would map to `Software` objects. It is administrator-gated, which this integration already requires.
- **iSCSI initiators.** `SYNO.Core.ISCSI.Host` exists on stock DSM 7 and may carry initiator IQNs and addresses. Unverified and niche, but it is another source of hosts that are not the NAS.

## API documentation

- [DSM Login Web API Guide](https://kb.synology.com/en-global/DG/DSM_Login_Web_API_Guide/) — the authoritative source for `SYNO.API.Info`, the login parameters, `format`, `enable_syno_token`/`SynoToken`, and the authentication error table.
- [Developer guides index](https://kb.synology.com/en-global/DSM/help/DSM/Tutorial/api) — the other official PDFs.
- **Virtual Machine Manager API Guide** (Synology PDF) — the `SYNO.Virtualization.API.Guest` `list` contract, the `additional` parameter, the `vnics` array, and the `status` and `vnic.model` enumerations. This is the document that distinguishes the official Guest API from the internal one.
- File Station and Calendar API Guides (Synology PDFs) — the common error code table, the `requestFormat` rule, and the only official mention of `SYNO.Entry.Request` compound mode.
- [`N4S4/synology-api`](https://github.com/N4S4/synology-api) — the best single source for the undocumented `SYNO.Core.*` surface, including the DHCP client list and the login flow as it is actually performed.
- [`mib1185/py-synologydsm-api`](https://github.com/mib1185/py-synologydsm-api) — its test fixtures are real DSM 6 and DSM 7 captures, which is where the `SYNO.DSM.Info`, `SYNO.DSM.Network`, and catalog shapes here come from.
- [`aerialls/synology-srm`](https://github.com/aerialls/synology-srm) — the SRM-only APIs, cited here so it is clear what DSM does **not** have.

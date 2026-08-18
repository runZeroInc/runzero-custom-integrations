# Custom Integration: Workspace ONE UEM

runZero already ships integrations for Jamf, Kandji, Mosyle, and Microsoft Intune. Omnissa
Workspace ONE UEM — the platform formerly sold as VMware Workspace ONE UEM, and before that
as AirWatch — is the notable remaining gap in that MDM lineup. This integration closes it, so
that the mobile and endpoint estate an organization manages through Workspace ONE lands in
runZero alongside everything else, and so that runZero can be asked the question no MDM can
answer on its own: which devices on the network are *not* enrolled.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Workspace ONE UEM REST API endpoint (`https://asXXX.awmdm.com` for SaaS tenants, or the on-premises API server).

## Workspace ONE UEM requirements

- REST API access enabled under **Settings > System > Advanced > API > REST API**.
- The tenant's **API Key**, shown on that same page. It is sent as the `aw-tenant-code` header.
- An administrator account with a **read-only** role (or a custom role carrying read access). Both the
  account credentials *and* the API key are required: the API rejects a request that carries only one of them.

## Steps

### Workspace ONE UEM configuration

1. Go to **Settings > System > Advanced > API > REST API**, enable REST API access, and copy the **API Key**
   and the **REST API URL**.
2. Go to **Accounts > Administrators > List View**, click **ADD**, and create an administrator whose role is
   `Read Only` (or a custom role with read access). API access requires a role with read permission.
3. Confirm access with a request to `https://<your-api-url>/api/mdm/devices/search`, sending the
   `aw-tenant-code` header and HTTP Basic credentials.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Workspace ONE UEM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Workspace ONE UEM API URL** (`url`): the REST API URL for the tenant, e.g. `https://as1687.awmdm.com`.
   - **API username** (`username`): the read-only administrator account.
   - **API password** (`password`): that account's password, sent as HTTP Basic auth.
   - **API key (tenant code)** (`api_key`): the REST API key, sent as the `aw-tenant-code` header.
   - **Organization group ID** (`organization_group_id`): optional; numeric organization group ID to limit the
     search to. Defaults to the API user's own organization group.
   - **Import pending OS updates** (`include_os_updates`): optional; default off. Adds one request per device.
   - **Import installed applications** (`include_software`): optional; default off. Adds at least one request per device.
   - **Per-device detail limit** (`detail_device_limit`): optional; default 250. Caps how many devices are queried
     for OS updates and applications.
   - **Device page size** (`page_size`): optional; default 500.
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
runzero script --filename workspace-one-uem/workspace-one-uem.star \
  --kwargs url=https://as1687.awmdm.com \
  --kwargs username=runzero-readonly \
  --kwargs password=NotTheRealPassword1 \
  --kwargs api_key=c8Fq2LmXe4TnZb91RvWk7Ys3 \
  --kwargs organization_group_id=570 \
  --kwargs include_os_updates=false \
  --kwargs include_software=false \
  --kwargs detail_device_limit=25 \
  --kwargs page_size=100 \
  --output ./workspace-one-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

**Both credentials are required, and they are two separate things.** `username` and
`password` are the administrator account, sent as HTTP Basic auth; `api_key` is the tenant's
REST API key from **Settings > System > Advanced > API > REST API**, sent as the
`aw-tenant-code` header. The API rejects a request carrying only one of them, so a run that
fails to authenticate with a password you know is right is almost always a missing or wrong
`api_key`, and vice versa.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Leave `include_os_updates` and `include_software` off for a first run and keep
`detail_device_limit` small. Each adds at least one request per device on top of the device
search, so on a large tenant they dominate the run time.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename workspace-one-uem/workspace-one-uem.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Workspace ONE accepts the credentials or that any device is
parsed.

The recorded API shapes, including an authentication failure and the per-device detail cap,
are exercised by the fixture suite:

```bash
python3 tests/run.py workspace-one-uem
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat workspace-one-uem/workspace-one-uem.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://as1687.awmdm.com,username=runzero-readonly,password=<password>,api_key=<tenant-code>' \
  --output ./workspace-one-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password or
tenant code containing a comma cannot be passed this way; prefer `script --kwargs` for
ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Workspace ONE UEM.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:workspace-one-uem`.

## Asset identity

- Target entity: an enrolled physical device (phone, tablet, laptop, desktop, or rugged device) under Workspace ONE UEM management.
- Source ID field: `Uuid` on each element of the `Devices` array returned by `GET /api/mdm/devices/search`.
- Documentation evidence: the device search endpoint is documented in the per-tenant Swagger help at
  `https://<host>.awmdm.com/api/help/#!/apis/10003?!%2FDevicesV2%2FDevicesV2_SearchAsync` and its response
  contract is published in the Cortex XSOAR pack's context-output table
  (`VMwareWorkspaceONEUEM.Device.Uuid`, "The UUID of the device"), which also documents the sibling
  `Id.Value` numeric device ID and the `Udid` hardware identifier. The UUID is the key the v2/v4 device
  endpoints (`GET /api/mdm/devices/{uuid}`, `GET /api/mdm/devices/{uuid}/osupdate`,
  `GET /api/mdm/devices/{uuid}/apps/search`) are addressed by, which is what makes it the join key here.
- Uniqueness scope: tenant. The UUID is generated by the tenant's own console, so it is not safe to treat as
  globally unique across two Workspace ONE environments.
- Cardinality: one row per enrolled device per poll. The search endpoint returns device records, not
  events, sessions, or app installations; installed applications and pending OS updates are attached to the
  device rather than emitted as separate assets.
- Stability: the UUID survives rename, reboot, IP/MAC change, OS upgrade, ownership change, and organization-group
  moves. It does **not** survive re-enrollment. Workspace ONE requires the device record to be deleted before a
  device is re-enrolled (for example after a wipe or an environment migration), and the re-enrolled device is a
  new record with a new `Id` and a new `Uuid`. `SerialNumber` and `Udid` are the hardware-stable values.
- Reuse behavior: no evidence that a deleted device's UUID is ever reassigned; UUIDs are minted per enrollment.
- Presence: present on every record in the observed search responses, but the field is not marked required in any
  published contract, so records without it are skipped rather than assigned a synthesized ID.
- Final runZero ID: `workspace-one-uem:<tenant-host>:<device-uuid>`. The tenant host is the API hostname with the
  scheme stripped, so switching the configured URL between `http` and `https` does not re-identify the estate. The
  UUID is lower-cased because the search endpoint and the device-detail endpoint disagree on casing for the same
  device.
- Missing-ID behavior: skip the record and log `skipping device with no Uuid: id=<numeric id>`. No UUID is invented,
  and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
- Verdict: **scoped authoritative**.

The match-behavior choice follows directly from the re-enrollment finding. Because a wipe-and-re-enroll mints a new
UUID, the same physical laptop will eventually arrive under a second Workspace ONE ID, and the only thing that can
reunite it with the asset runZero already holds is its MAC, hostname, or serial. Allowing a MAC/IP/name mismatch to
*disqualify* a merge would be exactly wrong here — MDM-reported network identifiers are sparse and volatile, and a
re-enrolled device frequently has a new name. The serial number is therefore also emitted both as a `serial:` tag and
as the `workspace_one_serial_number` custom attribute, so operators have a hardware-stable pivot for reconciling
duplicate records after a re-enrollment event.

### Notes

- **What is imported.** Assets from `GET /api/mdm/devices/search`. With `include_software` enabled, `Software`
  records from `GET /api/mdm/devices/{uuid}/apps/search`. With `include_os_updates` enabled, patch-level custom
  attributes (`workspace_one_os_update_pending_count`, `_critical_count`, `_restart_required`, `_pending`,
  `_latest`) from `GET /api/mdm/devices/{uuid}/osupdate`. No services or vulnerabilities are imported; the API
  exposes neither for a managed device.
- **Both credentials are required.** Every request carries HTTP Basic auth *and* the `aw-tenant-code` header. A
  request with valid Basic credentials but a wrong or missing API key returns 403, not 401; the script logs a
  distinct hint for each.
- **The API version is chosen per endpoint, not per tenant.** Workspace ONE UEM selects a response schema from the
  `Accept` header. The device search and OS update endpoints are called with `application/json;version=2` and return
  the PascalCase `Devices`/`Total` envelope. The per-device application search is a version 1 endpoint and returns
  the lower-case `app_items`/`TotalResults` envelope, so it is called with `application/json;version=1`. Sending a
  single global `Accept` version to all three would be wrong.
- **Pagination.** `page` is zero-based and `pagesize` caps at 500 for the device search. The script stops when a page
  returns no devices or when `(page + 1) * pagesize >= Total`. It pins `orderby=deviceid&sortorder=ASC` explicitly,
  because paging over the endpoint's default ordering can return a device twice or skip one when the inventory
  changes mid-walk. Application pages use the same model against `TotalResults`.
- **Rate limiting.** Workspace ONE UEM enforces a per-tenant request budget and reports it on every response through
  `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`, returning 429 once the budget is spent. The
  shared HTTP helper does **not** retry by default, so the script opts in explicitly (3 retries, 2s backoff factor,
  60s ceiling) and lets the helper honor `Retry-After`. Enabling per-device detail multiplies request count by the
  device count, which is the reason both detail options are off by default and capped by `detail_device_limit`.
- **Empty responses.** A search with no matches, and an application search for a device with no inventory, answer
  204 with an empty body, which decodes to `None`. Every call site coalesces to an empty dict.
- **Timestamps.** The API emits some timestamps with no zone designator (`2021-06-28T04:35:20.150`), which
  `parse_time` rejects outright, and writes an `0001-01-01T00:00:00.000` sentinel instead of null for events that
  never happened. Both are normalized before parsing. `LastSeen` becomes `lastSeenTS` and `LastEnrolledOn` becomes
  `firstSeenTS`; the raw strings are kept as custom attributes. Because a zone-less value is read as UTC, both are
  **clamped to the current time** before assignment: runZero rejects an asset whose first- or last-seen time is in
  the future and the error fails the entire record, so a tenant reporting local time east of UTC would otherwise
  have **every asset dropped**. The clamp skews first-seen and last-seen toward the present instead of losing the
  asset, and the raw strings preserve the original values either way.
- **Hostnames are filtered.** `HostName` and `LocalHostName` are device-reported and used directly.
  `DeviceFriendlyName` and `DeviceReportedName` are operator-facing labels that routinely contain spaces and
  possessives (`user123's Laptop`, `jdoe MacBook Pro macOS 14`), so they are only promoted to hostnames when they are
  actually hostname-shaped. Both raw values are always kept as custom attributes. This is a deliberate deviation
  from a naive `DeviceFriendlyName -> hostnames` mapping, which would inject unmergeable junk names into runZero.
- **Loopback and link-local addresses are dropped.** `DeviceNetworkInfo` entries reporting `127.0.0.0/8`, `::1`,
  `0.0.0.0`, `169.254.0.0/16`, or `fe80::/10` are excluded from network interfaces, because an agent that reports
  only a loopback address would otherwise merge every such host onto one runZero asset. The unfiltered list is kept
  as `workspace_one_ip_addresses`.
- **Many MDM devices report no IP at all**, and that is expected. A device with only a `MacAddress` still produces a
  valid MAC-only network interface. A device with neither is still imported and identified by its UUID.
- **Device type is mapped conservatively.** `Model` is checked first because it is the only field that separates an
  iPad from an iPhone or a MacBook from an iMac (`ipad`/`tablet` -> Tablet, `iphone`/`ipod` -> Mobile, `book` ->
  Laptop). `Platform` then supplies the fallback: the handheld platforms (`Apple`/`AppleIos`/`Android`/
  `WindowsPhone`/`BlackBerry`) map to Mobile, and `AppleOsX` maps to Desktop once MacBooks have been claimed.
  Windows and Chrome OS platforms are deliberately left **unset** — the platform string cannot distinguish a laptop
  from a desktop, and an unset value lets runZero's own fingerprinting decide rather than overwriting it with a guess.
- **OS name and version.** `OperatingSystem` is usually a bare version (`10.0.18363`) with the product name living in
  `Platform`, but some platforms prefix it (`iOS 17.4`). The script splits at the first digit and falls back to a
  platform-derived name (`WinRT` -> Windows, `AppleOsX` -> macOS, `Apple` -> iOS, and so on).
- **Enrollment and compliance become tags** (`enrollment:Enrolled`, `compliance:NonCompliant`, `ownership:corporate`,
  `platform:AppleOsX`, `serial:<serial>`, plus `compromised` when `CompromisedStatus` is true) so they are directly
  searchable for triage in runZero.
- **Software carries no CPE.** The application search publishes no CPE string, so `Software.cpe23` is left unset
  rather than synthesized. `bundle_id` and `assigned_version` are attached as software custom attributes.
- **Known API limitation (vendor-documented).** The OS update endpoint returns an empty response for Windows devices
  even when updates are visible in the console UI. Windows devices will therefore show
  `workspace_one_os_update_pending_count: 0` regardless of their real patch state.
- **Unverified assumptions.** The `apps/search` response field names (`name`, `installed_version`,
  `assigned_version`, `bundle_id`) and envelope (`app_items`, `TotalResults`) were taken from three independent
  client implementations rather than from the vendor's own published schema, which is only served from a
  per-tenant Swagger endpoint that requires a live tenant. The device search response shape and every device field
  mapped here are backed by the vendor-facing Cortex XSOAR pack contract and its recorded responses. The
  observation that re-enrollment mints a new UUID is inferred from the documented requirement to delete the device
  record before re-enrolling, plus third-party clients that de-duplicate search results on `SerialNumber`; it is not
  stated in that form in vendor documentation.
- This integration was validated against local fixtures, not a live Workspace ONE UEM tenant.

## Future

- **Device actions as an outbound integration.** The MDM API exposes device commands via
  `POST /api/mdm/devices/{id}/commands` (v1) and `POST /api/mdm/devices/{uuid}/commands/DeviceWipe` (v2), covering
  lock, enterprise wipe, full device wipe, and clear passcode. **These are destructive and irreversible.** A wipe
  issued from a scheduled sync against stale or mismatched inventory would destroy user devices, so this should
  never be built as a recurring task. If it is built at all, it belongs behind an explicit, human-confirmed,
  single-device action — not an inbound-style poll.
- **Compliance and enrollment status as a runZero policy signal.** `ComplianceStatus`, `EnrollmentStatus`, and
  `CompromisedStatus` already land as tags. `GET /api/mdm/devices/{uuid}/compliance` returns the per-policy detail
  behind that verdict (policy name, policy detail, last and next compliance check, action taken), which would let
  runZero surface *why* a device is non-compliant rather than only that it is.
- **App inventory for software-license reconciliation.** `GET /api/mam/apps/search` enumerates managed applications
  tenant-wide, and `GET /api/mam/apps/{uuid}/devices` returns the devices each is installed on. Walking the
  catalog once and inverting it is far cheaper than the per-device `apps/search` walk this integration uses, and it
  would let runZero reconcile purchased seats against observed installs. It is a poor fit for the current design
  only because it covers managed apps, not the unmanaged applications a device reports.
- **MDM coverage-gap reporting.** This is the highest-value follow-on and needs no new endpoint. Once Workspace ONE
  inventory is in runZero, a saved query for mobile and endpoint assets that runZero has seen on the network but
  that carry no `custom_integration:workspace-one-uem` source is a direct list of unmanaged devices. Unmanaged
  mobile is exactly the gap runZero exists to surface, and no MDM can produce this list from its own data, because
  a device it has never enrolled is a device it cannot see.
- **Event ingestion is not supported as a pull.** Workspace ONE UEM has no polling event or alert feed comparable to
  a SIEM query API; it pushes events outward through its own Event Notification (webhook) configuration. Ingesting
  those would require runZero to expose a receiver, which is outside what a scheduled inbound integration can do.

## API documentation

- [Workspace ONE UEM APIs — Omnissa Developer Portal](https://developer.omnissa.com/workspace-one-uem-apis/) — API families (MDM v1–v4, MAM v1–v2, System v1–v2) and versioning model.
- [REST API for Workspace ONE UEM — Omnissa Docs](https://docs.omnissa.com/bundle/SystemSettingsVSaaS/page/RestAPIforWorkspaceONEUEM.html) — enabling REST API access and obtaining the API key.
- Per-tenant Swagger help at `https://<host>.awmdm.com/api/help/#` — the authoritative schema for `DevicesV2_SearchAsync`, `DevicesV2_GetOSUpdatesByUUIDAsync`, and the device application search. It is only reachable from a live tenant.
- [Cortex XSOAR VMware Workspace ONE UEM pack](https://github.com/demisto/content/blob/master/Packs/VMwareWorkspaceONEUEM/Integrations/VMwareWorkspaceONEUEM/README.md) — device search and device-get context-output contracts (field names, types, and descriptions), authentication model, and the documented Windows OS-update limitation.
- [Zentral Workspace ONE API client](https://github.com/zentralopensource/zentral/blob/main/ee/zentral/contrib/wsone/api_client.py) — pagination contract (`Devices`/`Total`, `app_items`/`TotalResults`), per-endpoint `Accept` versioning, and the `X-RateLimit-*` headers.
- [Oomnitza Workspace ONE device-software connector](https://github.com/Oomnitza/oomnitza-connector/blob/master/connectors/workspaceone_devicesoftware.py) — `apps/search` field names (`name`, `installed_version`, `bundle_id`) and the 204-on-empty behavior.
- [GLPI AirWatch plugin REST client](https://github.com/pluginsGLPI/airwatch/blob/master/inc/rest.class.php) — independent confirmation of the `/mdm/devices/{id}/apps` device-application endpoint.
- [Device Enrollment — Omnissa Docs](https://docs.omnissa.com/bundle/WorkspaceONE-UEM-Managing-DevicesVSaaS/page/HowDoYouEnrollDevicesInUEM.html) — enrollment lifecycle and the requirement to delete a device record before re-enrolling.

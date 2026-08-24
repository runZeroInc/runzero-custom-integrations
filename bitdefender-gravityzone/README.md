# Custom Integration: Bitdefender GravityZone

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Bitdefender GravityZone requirements

- A GravityZone Control Center account whose role can see the Network inventory, and an API key generated for that account with the **Network API** enabled. Enabling the **Companies API** as well is recommended but not required — see the note on the parent node below.
- The Control Center Access URL that issued the key. A key is valid only against the console instance it was created on.

## Steps

### Bitdefender GravityZone configuration

The account generating the key needs the **Manage Networks**, **Manage Users**, **Manage Company**, and **View and analyze data** rights. Bitdefender documents no read-only variant of an API key — **which APIs the key may call is the only scoping mechanism**, so ticking the smallest set of boxes is the whole of least privilege here.

1. Sign in to the GravityZone Control Center, click your username in the upper-right corner, and choose **My Account**.
2. Find the **Control Center API** section and copy the **Access URL**. That is the value to give runZero. Take it from the console rather than guessing — a key issued on one cloud instance does not work on another, and there is no way to probe for the right one.
3. In the **API keys** section, click **Add**, type a description, and select the APIs to enable. Tick **Network** — it is the API carrying `getNetworkInventoryItems` and `getManagedEndpointDetails`, so nothing works without it. Tick **Companies** as well if you can; it carries `getCompanyDetails`, which lets the integration name the company it is importing and pin the walk to it explicitly. Without it the integration falls back to the API key's own default company, which is the same set of endpoints in the common single-company case. Leave every other API unticked — Accounts, General, Incidents, Investigation, Integrations, Licensing, Maintenance windows, Packages, PHASR, Policies, Push, Quarantine, and Reports are all unused by this integration.
4. Click **Generate** and copy the key value when it is shown. Control Center displays it once and cannot show it again.
5. Confirm the key from the Explorer host. Two things trip people up here, and both are visible in this one command:

   ```bash
   curl -s -u '<apiKey>:' \
     --url 'https://cloud.gravityzone.bitdefender.com/api/v1.1/jsonrpc/network' \
     --header 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","method":"getNetworkInventoryItems","params":{"page":1,"perPage":1},"id":"runzero"}'
   ```

   - The API key is the HTTP Basic **username** and the password is **empty** — the trailing colon in `-u '<apiKey>:'` is what makes that so. Written out, the header is `Authorization: Basic base64("<apiKey>:")`. Bitdefender states it directly: "the API key is set as username, and password is set as an empty string." Putting the key in the password position authenticates as nobody and fails.
   - **Most failures still return HTTP 200.** GravityZone is JSON-RPC, so it reports errors in an `error` object inside a 200 response body — Bitdefender's own status table says 200 covers "requests that have failed due to server errors". Read the body, not the status line: `-32001` is an authorization failure and `-32602` means the parameters were rejected.
   - **Four failures are the exception and do arrive as HTTP status codes**: `401` (bad or missing key), `403` (that API not enabled on the key), `405` (anything other than POST), and `429` (rate limited, carrying `Retry-After` and JSON-RPC code `-32003`). So a `403` here is the specific, useful signal that the key exists but the **Network** API box was not ticked.

The cloud console hostnames, from Bitdefender's per-instance communication-ports articles, are:

| Instance | Console / API host |
| --- | --- |
| Cloud Instance 1 (EU) | `cloudgz.gravityzone.bitdefender.com` |
| Cloud Instance 2 (US) | `cloud.gravityzone.bitdefender.com` |
| Cloud Instance 3 (APAC) | `cloudap.gravityzone.bitdefender.com` |
| OVH Roubaix (FR) | `cloudrbx.ovh.gravityzone.bitdefender.com` |
| SysEleven Hamburg (DE) | `cloudham.s11.gravityzone.bitdefender.com` |
| DTS IT AG Herford (DE) | `cloudher.dts.gravityzone.bitdefender.com` |

An on-premises GravityZone appliance uses its own hostname with the same URL shape. Two traps worth knowing:

- **`gravityzone.bitdefender.com` is not a console.** It is a GeoDNS login entry point that routes to whichever instance is nearest, so it is a fine bookmark and a bad API base. Do not configure it.
- **The short hosts on the partner-instance pages are not API hosts.** The RBX, SysEleven, and DTS articles also list `cloudrbx.`/`cloudham.`/`cloudher.gravityzone.bitdefender.com` for the agent Setup Downloader. Those fail TLS validation with a certificate subject mismatch. Use the long form in the table.

Enter the host without a path: the script adds `/api/<version>/jsonrpc/<service>` itself.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Bitdefender GravityZone").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **GravityZone Control Center URL** (`url`): the Access URL from My Account, without a path.
   - **API key** (`api_key`): the API key created above. It is sent as the HTTP Basic username with an empty password, which is what Control Center expects.
   - **Parent company or group ID** (`parent_id`): optional; a network inventory node to import from. Leave blank to import everything under the company the key belongs to. Set it to a company ID on a partner console, or to a group ID to import one branch of the tree.
   - **Include endpoints without a Bitdefender agent** (`include_unmanaged`): optional; default off. See the note on coverage gaps below.
   - **Fetch per-endpoint details** (`fetch_details`): optional; default off. Costs one extra request per endpoint.
   - **Per-endpoint detail limit** (`detail_limit`): optional; default 1000. `0` removes the cap.
   - **Page size** (`page_size`): optional; default 100, maximum 1000.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with endpoint data pulled from Bitdefender GravityZone.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:bitdefender-gravityzone`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm an
API key and see what a real Control Center returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename bitdefender-gravityzone/bitdefender-gravityzone.star \
  --kwargs url=https://cloud.gravityzone.bitdefender.com \
  --kwargs api_key=3f1a8c92d7e64b05a1c8f37e92b4d6a0 \
  --kwargs page_size=10 \
  --kwargs fetch_details=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/gravityzone-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Leave `fetch_details` off for a first run: it is one extra request per endpoint,
and everything needed to prove the credential works arrives on the inventory
listing alone. Turn it on, with `detail_limit` set low, once the listing looks
right. `get_bool` accepts `true/false`, `1/0`, `yes/no`, and `on/off`.

Remember that this API answers a failed call with **HTTP 200 and an `error`
object**. The script inspects the envelope and names the JSON-RPC code, so an
authorization failure shows up in the log as `-32001` rather than as a transport
error. A run that reports zero endpoints and no error is usually a `parent_id`
pointing at the wrong node, not a bad key.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real console:

```bash
runzero script --filename bitdefender-gravityzone/bitdefender-gravityzone.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real
endpoint row, so it tells you nothing about field mapping.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://cloud.gravityzone.bitdefender.com,api_key=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a console:

```bash
python3 tests/run.py bitdefender-gravityzone
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: an endpoint in the GravityZone network inventory — a physical computer, a virtual machine, or an EC2 instance, normally one carrying the Bitdefender Endpoint Security Tools (BEST) agent.
- Source ID field: `id` on each `getNetworkInventoryItems` result item.
- Documentation evidence: the same value is the `endpointId` parameter of `getManagedEndpointDetails` and the target of every endpoint-addressed method across the Network, Incidents, and Investigation services (`createIsolateEndpointTask`, `createRestoreEndpointFromIsolationTask`, `killProcess`, `startCommandExecutionOnEndpoint`, `moveEndpoints`, `setEndpointLabel`, `deleteEndpoint`, `assignPolicy`). It is the handle GravityZone itself uses to address an endpoint, not a per-response row key.
- Uniqueness scope: the Control Center database. Values are MongoDB `ObjectId`s — this is inferred rather than stated, but the inference is tight: decoding the embedded creation timestamp of Bitdefender's own documented example `6979caeecc68e2d8440569f3` yields `2026-01-28T08:38:06Z`, which is character-for-character the `createdAt` documented on that same record. A second documented id, `64b7625d3c11463ef77e5d6d`, decodes to 100 seconds after that record's `lastSuccessfulScan.date`. The value is therefore minted when the inventory row is created and is unique by construction inside one console, not by tenant partitioning.
- Cardinality: one inventory row per endpoint. The optional `getManagedEndpointDetails` call returns the same `id` and is merged into the same asset, so it never creates a second identity.
- Stability: survives rename, reboot, IP change, MAC change, policy change, group move, and agent version upgrade. Bitdefender treats hardware identity as something that changes *underneath* a stable record — `hwid-change` ("Hardware ID Change") is a first-class push event type — which is direct evidence the record outlives hardware churn. Verified here against a fixture that renamed the host and replaced its address and MAC while keeping the same `id`, which produced the same runZero ID.
- Reuse behavior: **not documented.** Bitdefender does not say whether a removed endpoint's `id` can be reassigned. The `ObjectId` structure makes reuse implausible, but that is an inference from the value's shape, not a contract.
- Presence: present on every observed inventory row. It is still checked, because a row without it cannot be addressed by any method and has no identity worth inventing.
- Final runZero ID: `bitdefender-gravityzone:<console-host>:<companyId>:<id>`. The console host is the deployment boundary — a key works against exactly one instance, and an on-premises appliance and a cloud tenant never share an id space. `companyId` is included because one cloud Control Center serves many tenants and a partner-level key can walk several companies in a single run, so the host alone does not make the value tenant-unique. When a row carries no `companyId` the literal `unknown` fills that position, so the ID shape stays fixed.
- Missing-ID behavior: the record is skipped and a line naming only the endpoint name is logged. No fallback identity is invented, and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-ip-break no-name-break`. Reasoning below.
- Verdict: **scoped authoritative for the inventory record** — stable, unique, and addressable — with the record-versus-machine caveat spelled out next. It is not a machine identity, and this integration does not pretend otherwise.

### Does this ID track the machine or the agent installation?

It tracks **the inventory record**, which is created when an endpoint first registers. That is the honest answer, and Bitdefender's own troubleshooting documentation is what settles it. On preparing a Windows system with BEST for duplication:

> the unique ID used by GravityZone for endpoint identification cannot be reset by any cloning solution. If you create a clone without resetting the ID, the machine will have duplicate entries in the GravityZone inventory.

Three things follow. First, BEST stores a locally generated agent ID, so the record is anchored to an *installation* on disk rather than to hardware. Second, that ID survives disk imaging, which is why Bitdefender ships a separate **Bitdefender Endpoint Security Patch for Sysprep** to reset it. Third, and most usefully, Bitdefender is explicit that the failure mode is *duplicate entries* — one machine acquiring several inventory rows.

Several documented behaviors churn the ID the same way:

- **Deleted endpoints that come back are treated as new.** Bitdefender's guidance on deleting entities says returning endpoints "are identified as new endpoints and are licensed again." That is licensing and inventory language, and it stops short of saying a new `id` is minted — but it is hard to read any other way.
- **Tenant-configurable auto-cleanup deletes offline machines.** Control Center can remove endpoints that have been offline for a configured window (1–730 days, or 1–23 hours; off by default). A laptop that comes back from a long leave can therefore be deleted and re-registered without anyone touching it.
- **Cloning without the Sysprep patch duplicates.** As quoted above.
- **Hyper-V dynamic MAC regeneration** is separately called out by Bitdefender as a cause of duplicate entries.

Bitdefender's own answer to this is **Golden Images**, a feature whose stated purpose is to "avoid duplicates of cloned endpoints." It is opt-in, requires the endpoints to be Active Directory joined, and requires an administrator to mark each source image by hand.

**What could not be verified:** whether an ordinary uninstall-and-reinstall of BEST on an unchanged machine reuses the previous record. Bitdefender does not publish where the agent ID is stored on disk, the Sysprep patch is a closed binary, and a community thread asking this exact question went unanswered by Bitdefender staff. The MSP licensing FAQ says GravityZone "detects that the endpoint was reinstalled and it will not be billed twice," which proves some reconciliation exists but is scoped to billing and says nothing about the inventory `id`.

### The consequence in runZero, and why no `matchBehavior` token fixes it

When one machine acquires a second GravityZone `id`, the new record arrives with a new foreign ID and tries to merge onto the existing runZero asset by MAC or hostname. **That merge is refused, and it cannot be permitted by any `matchBehavior` setting.** This is worth stating precisely, because the obvious remedy does not work:

- `no-id-break` disables `MatchBreakByForeignID`, which is the per-batch match-break that custom integrations are wired to.
- It has no effect on `Asset.CanMergeWithDevice`, the final gate before a device is applied to an asset. For any match that is not itself a foreign-ID match, that gate calls `ForeignIDSetsHaveMergeConflict`, and `SourceAllowsConflictingForeignIDs` returns **false** for custom integrations. Two differing foreign IDs from the same custom integration on one asset is a conflict, full stop.
- `ForeignIDSetsHaveMergeConflict` never consults `matchBehavior`. The eight `matchBehavior` tokens do not reach it.

So a churned ID produces a second runZero asset, and the fix has to be applied where the churn happens:

1. **Prevent the churn.** Use the Bitdefender Endpoint Security Patch for Sysprep before sealing a Windows image, or enable Golden Images. Review the offline-machine cleanup window in Control Center — a short window on an estate with travelling laptops will churn IDs on its own.
2. **Clean up after it.** Merge the duplicate assets in runZero. The old GravityZone ID stays on the asset as `bitdefender_gravityzone_endpoint_id` history, which is how you recognise the pair.

The mirror-image risk — several machines sharing one inventory record, which *would* be unfixable in runZero because a foreign-ID match is never vetoed by a conflicting MAC, IP, or hostname — is not what Bitdefender documents. The documented clone outcome is duplicate rows, not shared ones. It is called out here because the shared agent ID makes it theoretically reachable, and the symptom is unmistakable: one GravityZone-sourced asset whose hostname and address change on every task run. If you see that, fix the golden image; runZero cannot.

**One note for anyone hardening this further:** `ssid` (Bitdefender's key for the **Active Directory security identifier**, not a wireless network name) and `macs` are the only two server-side filter keys `getNetworkInventoryItems` documents for endpoint lookup, both usable "regardless of their protection status," and Golden Images requires AD membership. That is a strong hint that the AD SID is the cross-installation key Bitdefender itself relies on. It is imported as `bitdefender_gravityzone_ad_sid` but is **not** used in the asset ID: it is empty in both of Bitdefender's documented examples and meaningless on workgroup, macOS, Linux, and EC2 endpoints, so an ID built on it would be unstable in exactly the estates that need it most.

### Why `no-ip-break no-name-break`, and why the other two stay on

- **`no-ip-break`.** `details.ip` is a single primary address. On a laptop it is a DHCP lease, and on a VPN-connected host it is the tunnel address. runZero's IP break helper vetoes a merge when two address sets have no overlap at all, so one stale or tunnel-side address blocks an otherwise good MAC or hostname merge at first contact with an already-scanned asset. This is the weakest signal in the payload.
- **`no-name-break`.** `name` is the machine name as the agent last reported it, so it lags a rename until the endpoint next checks in — which on an offline laptop can be weeks — and on Linux and macOS endpoints it routinely differs from the DNS name runZero discovers. The break helper already forgives short-name-versus-FQDN, but it cannot forgive a name that is simply out of date. Both `name` and `details.fqdn` are still submitted as hostnames, so this loosens vetoing without giving up matching. This is a real general loosening, taken deliberately rather than copied from a preset.
- **`mac-break` stays ON.** This is a deliberate divergence from the Sophos Central and Trend Vision One integrations, which turn it off, and the reason is that this API is better: `getNetworkInventoryItems` returns the endpoint's complete `macs[]` array inline with no extra request. runZero's MAC break helper fires only when two MAC sets have *no* overlap, so a complete set makes that test meaningful rather than an artifact of a truncated list. This is also why the `macs[0]`-only mapping in the Cortex XSOAR pack is not copied: submitting one arbitrary MAC would make the break helper fire on the wrong adapter, turning a good check into a source of false breaks.
- **`id-break` stays ON.** As established above, turning it off would not rescue the ID-churn case, because a separate gate outside the `matchBehavior` system blocks that merge regardless. Since it buys nothing there, there is no reason to give up the signal it does provide during candidate matching.

### Notes

- **What is imported: assets only.** Endpoints come from `getNetworkInventoryItems` on `POST {url}/api/v1.1/jsonrpc/network`, optionally enriched by `getManagedEndpointDetails` on `POST {url}/api/v1.0/jsonrpc/network`. Note the version difference: `v1.1` is granted per-method on the network service and covers only `getEndpointsList`, `getNetworkInventoryItems`, `createReconfigureClientTask`, and `getTaskStatus`. `getManagedEndpointDetails` exists on `v1.0` only, and calling it on `v1.1` would fail.
- **No software, no services, and no vulnerabilities.** This API returns none of them. The Network inventory reports the machine, its addresses, its operating system string, and the state of Bitdefender's own protection modules — there is no installed-software list, no listening-port data, and no CVE list anywhere in it. Nothing of those kinds is invented. The BEST agent's own `productVersion` and `engineVersion` are recorded as custom attributes rather than dressed up as a `Software` record, because a single security agent is not a software inventory and presenting it as one would make software searches in runZero misleading. GravityZone does produce application-vulnerability data through Risk Management and Patch Management, but not on this API surface; see Future.
- **This is JSON-RPC 2.0, not REST.** Every call is a `POST` to a versioned service path with the method name in the body, and **a failed call normally comes back as HTTP 200 with an `error` object in the payload** — Bitdefender's own documentation notes that 200 covers "requests that have failed due to server errors (e.g. a required parameter is not passed)". The HTTP helper reports success for those, so every response is checked for `error` before `result` is read, and the documented codes (`-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32000` server, `-32001` authorization, `-32002` not found, `-32003` too many requests) are named in the log. Only the `code` and `message` are logged; the `data` member can echo request parameters back and is deliberately not logged. Batch requests and JSON-RPC notifications are not supported by the API, and only `POST` is accepted.
- **All methods used here are reads**, so the HTTP helper's default retry budget is safe — a repeated call cannot create or change anything.
- **Authentication** is HTTP Basic with the API key as the username and an **empty password**, i.e. `Authorization: Basic base64("<apiKey>:")`. Bitdefender states it directly: "the API key is set as username, and password is set as an empty string." There is no bearer token and no OAuth exchange. The wording is identical in the 2017 on-premises API guide, so it has been stable for years.
- **The parent node is resolved first, but not required.** `getNetworkInventoryItems` documents `parentId` as defaulting to the company the API key belongs to. When `parent_id` is left blank the script still calls `getCompanyDetails` on `POST {url}/api/v1.0/jsonrpc/companies` first, because knowing the company makes the run self-describing in the logs and pins the walk explicitly. If that call fails — most likely because the key does not have the Companies API enabled — the failure is logged and the walk proceeds with `parentId` omitted, which the API resolves to the same company. Setting `parent_id` skips the lookup entirely and is how you point a partner-level key at one specific company or one group.
- **Pagination** is `page` / `perPage`. `perPage` accepts 1–1000 on `v1.1` (the API's own default is 30; `v1.0` caps the same method at 100). The stop condition is version-dependent and this is a live trap: **`v1.1` returns `pagesCount` and `total` on the first page only**, and supplies `hasMoreRecords` on every page instead. Reading `pagesCount` off page two would find nothing. The walk therefore prefers `hasMoreRecords`, falls back to the `pagesCount` captured from page one, and falls back again to stopping on an empty or short page, so it terminates correctly against either version and is bounded regardless.
- **Loopback, unspecified, and link-local addresses are filtered** out of `details.ip` (`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, `fe80::/10`) before any interface is built, because an agent that reports `127.0.0.1` as a host's only address would otherwise give every such host the same address and merge the estate onto one asset. The raw value is always kept as `bitdefender_gravityzone_ip`.
- **Every MAC is imported, not just the first.** `details.macs[]` is an array and each entry becomes an interface. GravityZone does not say which address belongs to which adapter, so the single reported address is attached to the first interface and the remaining MACs stand alone. MACs are normalized by runZero's interface helper, which also clears the locally-administered bit so randomized and hypervisor-assigned addresses match across sources; because that transformation is lossy, no MAC is ever used in or as the asset ID.
- **Timestamps: naive values are UTC, and both formats appear in one response.** `lastSeen` and `agent.lastUpdate` arrive with no zone (`2025-12-16T21:46:16`), while `lastSuccessfulScan.date` carries an explicit offset (`2023-07-19T04:09:29+00:00`). Both shapes are handled. That the naive values are UTC is not documented, but it is established by the same ObjectId evidence used above: a documented record's `createdAt` of `2026-01-28T08:38:06` matches its own id's embedded UTC creation timestamp exactly. Parsed values are still clamped to the current time before being assigned, because runZero rejects an entire asset record whose first- or last-seen time is in the future — a silent way to lose an estate if a console ever disagrees. The unmodified string is always kept as `bitdefender_gravityzone_last_seen`. Values that do not match the expected shape, and the `0001-01-01T00:00:00` "never" sentinel, are discarded rather than parsed, because an unparseable timestamp aborts the whole script.
- **`lastSeen` and the last logged-in users require the per-endpoint call.** The inventory listing has no check-in time, no `state`, no `operatingSystem`, and no user list. Those live in `getManagedEndpointDetails`, which is one request per endpoint. `fetch_details` is off by default for that reason; turn it on and raise or clear `detail_limit` when the extra data is worth the request count. Endpoints past the limit are still imported from the listing alone and the number skipped is logged. A detail lookup that fails is logged and skipped, and the endpoint is still imported.
- **The protection-module map does not require the per-endpoint call.** `modules`, `productOutdated`, `riskScore`, and `lastSuccessfulScan` are documented on the inventory listing as well as on the detail response, so the listing is preferred and the detail only fills gaps. This matters: the EDR coverage picture below is available at no extra request cost.
- **Unmanaged endpoints.** By default the walk filters to endpoints managed by BEST (`filters.security.management.managedWithBest`). Turning on `include_unmanaged` drops that filter entirely rather than guessing at an inverse flag, so the walk returns everything GravityZone knows about under the node — including machines its own network discovery or its AD/vCenter/EC2 integrations have found but that carry no agent. Bitdefender defines these plainly as "detected endpoints on which the security agent has not been installed yet." They carry much less detail, often no MAC and no operating system, and are tagged `management:unmanaged`.
- **Non-endpoint inventory nodes are skipped and counted.** The tree also holds companies, folders, groups, and container nodes. Each item's `type` names which it is (`5` computer, `6` virtual machine, `7` EC2 instance are the endpoint types; `1`–`4` and `14`–`16` are structural), so `type` is the discriminator, with the presence of a `details` object as a fallback for a response that omits it. The count is printed at the end of the run so the skip is never silent.
- **`machineType` is recorded but no `deviceType` is claimed.** `1` computer / `2` virtual machine / `3` EC2 instance / `0` other does not distinguish a desktop from a server, so it is exposed as `bitdefender_gravityzone_machine_type_name` and nothing is asserted about the asset's device type.
- **Rate limiting:** GravityZone answers a throttled request with **HTTP 429**, a `Retry-After` header, and JSON-RPC error `-32003`. Because that one arrives as an HTTP status rather than a 200, the shared HTTP helper retries it with exponential backoff and honors `Retry-After` without any special handling here. **Do not hardcode a rate:** Bitdefender's documentation contradicts itself three ways — the prose says "a specific number of requests per second per API key" without a number, the HTTP status table says more than 10 per second, and the sample error body says 100 per 60 seconds — and the current docs add that limits "are set per API key and may vary by method and subscription tier."
- **Unverified assumptions**, stated plainly:
  - Whether an ordinary BEST reinstall on an unchanged machine preserves the endpoint `id` (see above). This is the one that matters most, and it is genuinely undocumented rather than merely hard to find.
  - Whether a deleted endpoint's `id` can be reassigned.
  - The Access URL for Cloud Instance 3, RBX, SysEleven, and DTS. Bitdefender's API code samples hardcode `https://cloud.gravityzone.bitdefender.com/api` and `https://cloudgz.…/api`, which confirms the host-plus-`/api` shape for Instances 1 and 2 directly; the other four are the console hosts from Bitdefender's own instance articles, assumed to follow the same shape. This is exactly why the URL is an operator-entered parameter and not a picklist.
  - The reference timezone for zone-less timestamps is UTC by strong inference (see above), not by documentation.
- This integration was validated against local fixtures, not a live Bitdefender GravityZone console.

## Future

- **Endpoint response actions as an outbound integration.** `createIsolateEndpointTask` and `createRestoreEndpointFromIsolationTask` on the Incidents service, plus `killProcess`, `startCommandExecutionOnEndpoint`, `createMemoryDumpTask`, `collectInvestigationPackage`, and `createSubmitToSandboxAnalyzerTask`, are all keyed by the same endpoint `id` this integration already imports, so an outbound integration needs no extra identity mapping. **Isolation is disruptive** — it cuts the endpoint off from everything but its managing GravityZone server — so it must never be wired to a broad query, and any implementation needs an explicit confirmation step and a matching restore path. These are non-idempotent task submissions and must be issued with `retries=0`, unlike every call this integration makes.
- **Task status polling.** `getTaskStatus` (network, `v1.1`) returns the state of a submitted task including subtasks, and `getScanTasksList` and `deleteTask` round out the set. Any outbound integration needs these in order to report that an action completed rather than merely that it was accepted.
- **Incident ingestion as an event feed.** `getIncidentsList`, `getIncident`, and `getIncidentsByIds` are **`v1.2`-only** on the incidents service, paginated with `page`/`perPage` against `pagesCount` the same way the inventory is. Incidents carry the endpoint they occurred on, so detections could be attached as tags or attributes to the assets this integration already imports, and `changeIncidentStatus` and `updateIncidentNote` allow write-back from runZero. `addToBlocklist` / `getBlocklistItems` / `removeFromBlocklist` and `startYaraScan` sit on the same service.
- **Push event notifications instead of polling.** The Push service (`setPushEventSettings`, `getPushEventSettings`, `sendTestPushEvent`, `getPushEventStats`, `resetPushEventStats`) makes GravityZone deliver events to an HTTP listener rather than being polled, across 29 documented event types. Four are directly relevant to inventory freshness — `install`, `uninstall`, `registration`, and **`hwid-change`** — and `endpoint-moved-in` / `endpoint-moved-out` track group membership. `hwid-change` is the interesting one for the identity question above, since it is GravityZone telling you a record's hardware identity shifted; some tenants need Bitdefender support to enable it. This is the right shape for near-real-time enrichment but needs a listener runZero does not currently provide, so it is a design note rather than a script that could be written today.
- **EDR coverage-gap reporting — the strongest thing this API enables.** GravityZone knows both which machines carry an agent and which it has merely discovered, and it distinguishes an endpoint running only antimalware from one running the EDR sensor. That is exactly the "what does my EDR not see" question, and three-quarters of it works today:
  - Run a second scheduled task with `include_unmanaged` on. Unmanaged machines arrive tagged `management:unmanaged`, so `custom_integration:bitdefender-gravityzone AND tag:management:unmanaged` lists the endpoints GravityZone can see but is not protecting. `getEndpointsList` offers the same distinction more directly through its `isManaged` parameter — unset returns both managed and unmanaged, `True` returns only managed — but it needs a `/computers` or `/virtualmachines` path suffix and, for Active Directory endpoints, Bitdefender's own documentation points back at `getNetworkInventoryItems`, which is why this integration uses the latter.
  - The `modules` map is imported without any extra request, so `tag:module:no-edr-sensor` lists endpoints protected by antimalware alone, and `tag:agent:outdated` / `tag:agent:signature-outdated` list agents that are installed but stale. Those are coverage gaps that an "is the agent installed?" check would score as green.
  - Compare against runZero's own discovery. Assets runZero found that carry no `bitdefender-gravityzone` source at all are the machines GravityZone does not know about — the gap that is invisible from inside the GravityZone console, and the one an agent-based tool structurally cannot report on itself.
- **Installation packages as a remediation path.** `getPackagesList` and `getInstallationLinks` on the Packages service return deployment links for the BEST agent. A workflow that identifies an unprotected asset in runZero and hands an operator the correct installer link for that company would close the loop on the coverage-gap report above. This is a lookup, not a push: the API distributes packages, it does not install them.
- **Group and policy management as an outbound integration.** `getCustomGroupsList`, `createCustomGroup`, `moveEndpoints`, `setEndpointLabel`, and `assignPolicy` would let runZero query results drive GravityZone group membership and policy assignment — for example, moving every asset in a runZero-defined segment into a group carrying a stricter policy. Note that `deleteEndpoint` is a **two-phase soft delete**: the first call moves the endpoint to the Deleted folder and generates an uninstall task, and the docs require calling it twice with the same ID to remove it permanently. There is no `removeEndpoint`. Any automation touching it should be treated as destructive.
- **Quarantine as an enrichment source.** `getQuarantineItemsList` (services `computers` and `exchange`, filterable by `fileSha256`) with `createRemoveQuarantineItemTask` and `createEmptyQuarantineTask` would attach per-endpoint quarantine counts to assets. It is a per-endpoint list rather than an inventory, so it suits a filtered enrichment pass rather than wholesale ingestion.
- **Not available from this API:** installed-software inventory, listening services, and CVE findings. GravityZone's Risk Management and Patch Management modules do produce application-vulnerability and missing-patch data, but it is surfaced through the reporting subsystem — create a report, poll it, download it, parse it — rather than through a queryable inventory method. That is a fundamentally different integration shape and it is licensed separately, so it is called out here as a possibility rather than folded into this script.
- **On-premises consoles are a smaller surface.** An on-premises GravityZone uses the same `https://<host>/api/v1.0/jsonrpc/<service>` shape but exposes no companies, incidents, integrations, push, licensing, or investigation services, and documents no `v1.1` at all. It adds a `sandbox` service, and `getContainers` exists only there. Anything built from the list above should check the target console before assuming a method exists.

## API documentation

- Public API overview, authentication, and error codes: https://www.bitdefender.com/business/support/en/77209-125277-public-api.html
- Network API methods, including `getNetworkInventoryItems` and `getManagedEndpointDetails`: https://www.bitdefender.com/business/support/en/77209-128476-network.html
- API usage examples (the source of the confirmed `https://<console-host>/api` base for the EU and US instances): https://www.bitdefender.com/business/support/en/77209-141188-api-usage-examples.html
- Push API event types: https://www.bitdefender.com/business/support/en/77209-135324-event-types.html
- Communication ports per cloud instance, the source of the console hostname table: https://www.bitdefender.com/business/support/en/77209-376337-gravityzone-communication-ports.html
- Preparing a Windows system with BEST for duplication — the endpoint-identity and cloning contract quoted under Asset identity: https://www.bitdefender.com/business/support/en/77209-87466-troubleshooting.html
- Deleting entities, on endpoints that reconnect after removal: https://www.bitdefender.com/business/support/en/77211-1200701-deleting-entities.html
- Offline-machine cleanup configuration: https://www.bitdefender.com/business/support/en/77209-155208-configuration.html
- Checking the endpoints status, on the managed/unmanaged distinction: https://www.bitdefender.com/business/support/en/77209-155142-checking-the-endpoints-status.html
- On-premises Public API, for the reduced service set: https://www.bitdefender.com/business/support/en/77212-125277-public-api.html
- Transport shape and recorded API fixtures, as implemented by Palo Alto's Cortex XSOAR content pack: https://github.com/demisto/content/tree/master/Packs/GravityZone/Integrations/GravityZone — `GravityZone.py` and `test_data/`

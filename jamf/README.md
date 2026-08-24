# Custom Integration: JAMF

Imports computers and mobile devices from Jamf Pro, using the modern Jamf Pro
API with an API Client (OAuth client credentials) rather than a user account.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Jamf Pro server over HTTPS.

## JAMF requirements

- Jamf Pro new enough to have **API Roles and Clients**. Client credentials are
  the modern replacement for the Classic API's Basic authentication; older
  releases that only offer a username and password cannot be used with this
  script, which authenticates exclusively with a client ID and secret.
- An **API Role** carrying read privileges on the objects you want, and an
  **API Client** that role is assigned to.
- Your Jamf Pro base URL. For Jamf Cloud it is
  `https://<yourcompany>.jamfcloud.com`; for a self-hosted server it is whatever
  hostname (and context path) that server is published at. Give the base URL
  only — the script appends `/api/...` itself.

### Creating the credential in Jamf Pro

The role comes first, because a client cannot be created without one to assign.

1. In Jamf Pro, go to **Settings > System > API Roles and Clients**. That page
   has two tabs, **API Roles** and **API Clients**.
2. On the **API Roles** tab, create a role — name it something identifiable, such
   as `runZero read-only` — and give it the privileges this integration actually
   needs:
   - **Read Computers** — required. Jamf's reference for
     `GET /v1/computers-inventory` names this privilege directly, and the same
     privilege covers the per-device `computers-inventory-detail` lookups.
   - **Read Mobile Devices** — required only if you want iOS and iPadOS devices.
     It covers `/v2/mobile-devices/detail`.

   That is the whole list. In particular, **do not grant "Read Computer
   Inventory Collection Settings"** — despite the name it has nothing to do with
   reading inventory. It governs `/v2/computer-inventory-collection-settings`,
   which is the *preferences* object controlling what Jamf collects from
   managed Macs. Granting it widens the credential without helping this
   integration at all. (Earlier revisions of this README listed a privilege
   called "Read Computer Inventory Collection", which does not exist under that
   name.)
3. On the **API Clients** tab, create a client, assign the role you just made,
   and enable it.
4. Generate the **client secret**. It is displayed once. Record it along with the
   **client ID**.

**One operational trap worth knowing before you go looking for it.** Jamf
documents that *"Adding or removing an API Role from an existing API Client
requires that the client secret be rotated for the changes to take effect."* So
if you assign a second role later — say you add mobile devices after starting
with computers — the change appears saved in the UI and does nothing until you
rotate the secret and update the runZero credential. Editing the privileges
*inside* a role you have already assigned is different: that takes effect
immediately, with no rotation.

### Confirming the credential

```bash
curl -s -X POST 'https://yourcompany.jamfcloud.com/api/v1/oauth/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=1a2b3c4d-5e6f-7788-99aa-bbccddeeff00' \
  -d 'client_secret=ExampleFakeClientSecret0123456789abcdefghij'
```

A success returns `access_token`, `token_type: "Bearer"`, and `expires_in`.

**A note on that path.** Jamf's own documentation is inconsistent here: the API
reference documents the token endpoint as `/api/v1/oauth/token`, while Jamf's
blog and several Jamf-authored posts use `/api/oauth/token`. Both appear to work
against a live server, and `/api/oauth/token` looks to be an undocumented alias.
`jamf.star` currently calls `/api/oauth/token`; the documented path is
`/api/v1/oauth/token`, which is what the curl above uses and what to prefer if
you adapt this script. If a future Jamf release retires the alias, that line in
the script is where it will break.

Token lifetime is configurable per API Client through its **Access Token
Lifetime** setting, so there is no single correct number to quote — read
`expires_in` from the response rather than assuming one. Client-credentials
tokens have no keep-alive endpoint (unlike the older basic-auth token flow), so
they must be re-requested; the script re-authenticates every 100 requests and
again on a 401 or 403, retrying the rejected request once with the new token.
Jamf Pro answers an expired or failed authentication with 401; 403 usually
means a missing privilege, but a fresh token settles which.

## Steps

### JAMF configuration

1. Create the API Role and API Client as described above, and record the client
   ID and client secret.
2. Note your Jamf Pro base URL, e.g. `https://yourcompany.jamfcloud.com`.
3. Confirm the token request above succeeds from the Explorer host.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - **Activity window (days)** (`activity_days`, default `60`) sets the
      lookback. The script filters computers on `general.lastContactTime` and
      mobile devices on `lastInventoryUpdateDate`, so a device that has not
      checked in within that window is **not imported**. Raise it for stale
      records, lower it if you only care about active devices, or set it to `0`
      to remove the filter entirely.
    - **Import computers** (`import_computers`) and **Import mobile devices**
      (`import_mobile`) (both default true) turn each device class on or off.
      Disable `import_mobile` if you did not grant **Read Mobile Devices**,
      otherwise every mobile request returns 403.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Jamf base URL** (`url`): e.g. `https://yourcompany.jamfcloud.com`.
    - **API client ID** (`client_id`): the API Client's ID.
    - **API client secret** (`client_secret`): the secret generated for that client.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "JAMF").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename jamf/jamf.star \
  --kwargs url=https://yourcompany.jamfcloud.com \
  --kwargs client_id=1a2b3c4d-5e6f-7788-99aa-bbccddeeff00 \
  --kwargs client_secret=ExampleFakeClientSecret0123456789abcdefghij \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./jamf-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. There is no parameter that caps the run, so the size of a first run is set by
the `activity_days` parameter — lower it temporarily for a smoke test against a large
fleet (add `--kwargs activity_days=7` to the command above).

A 403 on the computer endpoints means the role is missing **Read Computers**; a 403 on
the mobile endpoints alone means it is missing **Read Mobile Devices**. If you granted
both and still see 403, check whether the role was assigned after the client secret was
generated — that combination needs the secret rotated before it takes effect.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma
— the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. A Jamf client secret is opaque; if one arrives with an
`=` and a comma in it, wrap the whole argument in a second pair of quotes:
`--kwargs '"client_secret=ab=cd,ef"'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename jamf/jamf.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Jamf accepts the client credentials, that the role carries
the right privileges, or that any device is parsed. The fixture scenarios are what
exercise the parsing:

```bash
python3 tests/run.py jamf
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat jamf/jamf.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://yourcompany.jamfcloud.com,client_id=1a2b3c4d-5e6f-7788-99aa-bbccddeeff00,client_secret=ExampleFakeClientSecret0123456789abcdefghij' \
  --output ./jamf-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so a secret containing a comma cannot be passed this
way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:JAMF`.

## Asset identity

- Target entity: an **Apple device enrolled in Jamf Pro** — a Mac from `GET /v1/computers-inventory`, or an iPhone, iPad, or Apple TV from `GET /v2/mobile-devices/detail`. Both paths produce assets in the same id space.
- Source ID field: `udid`, falling back to `mobileDeviceId`.
- Documentation evidence: `udid` is Apple's hardware Unique Device Identifier, and Jamf publishes it at the top level of both the computer inventory record and the mobile device record. It is not a Jamf-assigned key at all — which is exactly what makes it the strongest identity in this set of integrations. Jamf's own numeric `id` is used only to address the per-device detail lookups; it is deliberately not the asset identity.
- Uniqueness scope: **global, not tenant-scoped.** A UDID identifies a piece of Apple hardware regardless of which Jamf Pro server manages it. Two Jamf tenants importing the same device through one custom integration would correctly converge on one asset rather than colliding — the opposite of the usual situation, and worth knowing if you migrate between servers.
- Cardinality: one source row per device per path. Computers and mobile devices never share a UDID, so the two passes cannot collide.
- Stability: **survives everything Jamf can do to the device.** Rename, address change, OS upgrade, wipe, un-enrollment and re-enrollment, and a move to a different Jamf server all preserve it, because it is a property of the hardware rather than of the management record. This is the case the governing rule's "persistent ID" clause was written for.
- **The one failure mode is cloning.** A virtual macOS instance created from a template, or any device whose hardware identifiers were duplicated rather than regenerated, carries the same UDID as its source. Because `matchBehavior` is left at the default, those records merge onto one runZero asset, and a foreign-id match cannot be vetoed by a conflicting MAC or hostname — so no flag prevents it. On a fleet of physical Apple hardware this does not arise; on a Mac virtualization farm it can.
- Reuse behavior: not reassignable. The value belongs to the hardware.
- Presence: expected on every record. A record with neither field is skipped with `Asset ID not found:` (computers) or `Mobile asset ID not found:` (mobile). Note that on the computer path the `mobileDeviceId` fallback can never fire — that field does not exist on a computer record — so in practice a computer with no `udid` is simply skipped.
- Final runZero ID: the raw UDID, e.g. `00008103-000A4D2E3C82001E`.
- Missing-ID behavior: skip and log the whole record.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct, and better supported here than anywhere else in this set: because the id is hardware-derived rather than enrollment-derived, the usual "an agent reinstall forks the asset" caveat does not apply.
- Verdict: **authoritative.** The only qualification is the cloning case above.

Two data-quality notes about what accompanies the identity:

- **Each MAC gets its own network interface, but only the first carries the addresses.** Jamf reports addresses at the device level (`general.lastIpAddress` and friends) and MACs at the hardware level (`macAddress`, `altMacAddress`, `wifiMacAddress`), and publishes nothing tying either to the other. `asset_networks` puts the address list on the **first** MAC — Jamf's own ordering, primary NIC first — and emits the remaining MACs as address-less interfaces, so every MAC still reaches runZero for correlation without any of them claiming an address it was never reported with. This previously called `asset_networks` once per MAC with the identical address list each time, so a Mac with a Thunderbolt dock asserted its one address on both adapters.
- **Only private addresses are imported.** `asset_ips` filters `lastIpAddress`, `ipAddress`, and `lastReportedIp` against `PRIVATE_NETWORKS`, so a remote Mac reporting only its ISP-assigned public address contributes no address at all. That is deliberate: importing a shared NAT egress address would correlate every home-working laptop onto one asset. The list is `10/8`, `172.16/12`, `192.168/16`, **`100.64/10`** (RFC 6598 carrier-grade NAT — the range every Apple device on a mobile carrier reports from), and **`fc00::/7`** (RFC 4193 IPv6 unique local addresses), evaluated with `net.ip_in_network`. The last two were absent from the earlier hand-rolled prefix check, which meant CGNAT clients and **every IPv6 address of any kind** were discarded along with genuine public addresses.

## Future

- **Ask for inventory sections instead of making a second request per device — this replaces the whole N+1 and unlocks most of the items below.** `GET /v1/computers-inventory` accepts a `section` parameter naming which parts of the record to return (`GENERAL`, `HARDWARE`, `OPERATING_SYSTEM`, `APPLICATIONS`, `SECURITY`, `DISK_ENCRYPTION`, `SOFTWARE_UPDATES`, and others). This integration requests no sections and then issues `GET /v1/computers-inventory-detail/{id}` once per computer to recover them, and does the same again for every mobile device. Requesting the sections on the list call would cut the request count from *one per device* to *one per page* — and would make the enrichment below free rather than expensive.
- **Installed applications as `Software` records.** The `APPLICATIONS` section is the per-device application inventory, and this integration currently emits **no `Software` records at all**; `applications` and `packageReceipts` are explicitly excluded from the attribute flattening. For a Mac fleet this is the single most useful thing Jamf knows that runZero cannot see from the network.
- **Security posture as tags rather than flattened text.** The `SECURITY` and `DISK_ENCRYPTION` sections carry FileVault state, System Integrity Protection, Gatekeeper, the firewall, secure-boot level, and XProtect version. Some of that is already reaching custom attributes through the catch-all flattening, as keys like `diskEncryption.bootPartitionEncryptionDetails...`. Modelled as tags it would make "every Mac on this segment without FileVault" a one-line runZero query.
- **Pending software updates as findings.** The `SOFTWARE_UPDATES` section reports available updates per device. Where an Apple update names CVEs those map onto real `Vulnerability` records — unlike behavioral detections, these would be recognised by runZero's CVE-based reporting.
- **A shorter activity window is the obvious cheap incremental sync.** The lookback is now the `activity_days` CONFIG parameter (default 60, `0` disables it), applied as a Jamf filter on `general.lastContactTime` (computers) and `lastInventoryUpdateDate` (mobile). A scheduled task with a window barely longer than its interval imports only what changed.
- **Outbound: push runZero context into Jamf as an extension attribute.** Jamf scopes policies and configuration profiles by Smart Group, and Smart Groups can be built on extension attributes. Writing a runZero-derived value onto a computer record — the segment it was found on, whether runZero classifies it as a server, whether it is missing an expected agent — would let Jamf act on runZero's view of the network directly, rather than an administrator re-deriving the same set by hand. This integration already reads extension attributes (both device-level and user-level) and imports them as `ext_attr_*` custom attributes, so the shape is familiar; the write is the new part.
- **MDM commands are reachable and deliberately out of scope.** The same credential class can issue device lock, wipe, and profile-removal commands. A wipe is unrecoverable, so nothing about an inventory sync justifies going near them; if an outbound integration is ever built, these need per-device confirmation and an audit trail rather than a policy rule.
- **Enrollment coverage-gap reporting.** Jamf knows every enrolled Apple device; runZero discovers the ones on the network. Apple hardware runZero fingerprints that has no Jamf record is unmanaged, which for a Mac fleet is the whole point of asking. In the other direction, `general.lastContactTime` is already imported and identifies enrolled devices that have stopped checking in — a device that is managed on paper and absent in practice.

- Jamf Pro API reference — https://developer.jamf.com/jamf-pro/reference/
- `GET /v1/computers-inventory` (privilege: Read Computers) — https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory
- `GET /v2/mobile-devices` (privilege: Read Mobile Devices) — https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices
- Client credentials and the secret-rotation rule — https://developer.jamf.com/jamf-pro/docs/client-credentials
- Privileges reference, including the distinct "Read Computer Inventory Collection Settings" — https://developer.jamf.com/jamf-pro/docs/privileges-and-deprecations

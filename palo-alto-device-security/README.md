# Custom Integration: Palo Alto Networks Device Security

Palo Alto Networks Device Security (formerly IoT Security, and originally Zingbox)
is the IoT/OT/medical device inventory and vulnerability product delivered through
Strata Cloud Manager. This integration imports that inventory into runZero through
the IoT public API.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Palo Alto Networks Device Security requirements

- A Device Security (IoT Security) subscription activated in Strata Cloud Manager.
- A Strata Cloud Manager service account with a client ID and client secret, granted
  a role that can read the IoT inventory and vulnerability data.
- **The role is where the vendor documentation contradicts itself, so pick deliberately.**
  Palo Alto's IoT public API setup instructions tell you to assign **All Apps & Services**
  with the **Superuser** role. Separately, the Device Security user-roles page states that
  Device Security supports exactly two Strata Cloud Manager roles: Superuser and
  **View-only Administrator**. View-only Administrator is obviously the least-privilege
  read role, but we could not verify that a *service account* holding it is accepted by
  the IoT public API — every documented API recipe uses Superuser. Try View-only
  Administrator first and fall back to Superuser if the token is refused; do not assume
  the tightening works untested.
- The Tenant Service Group (TSG) ID of the tenant to import. The token request is
  scoped to exactly one TSG, so one credential imports one tenant.
- Network egress from the Explorer to `https://auth.apps.paloaltonetworks.com` and
  `https://api.strata.paloaltonetworks.com`.

## Steps

### Palo Alto Networks Device Security configuration

1. In Strata Cloud Manager, open **Settings > Identity & Access > Access Management**,
   click **Add Identity**, and set the Identity Type to **Service Account**. Record the
   **client ID** and **client secret**; the secret is shown only once. Service accounts
   are created here (or through Common Services), not in the Customer Support Portal.
2. Assign the service account a role — see the note above on Superuser versus View-only
   Administrator.
3. Record the **TSG ID** of the tenant. It is the value used as the token scope
   (`tsg_id:<TSG ID>`). The simplest place to read it is the service account's own display
   name, which has the form `<name>@<tsg_id>.iam.panserviceaccount`; it is also shown on
   the Identity & Access page beside the tenant name.
4. Confirm access. Note that the client ID and secret go in **HTTP Basic**, not in the
   form body — only `grant_type` and `scope` are posted:

   ```bash
   curl -s -X POST https://auth.apps.paloaltonetworks.com/oauth2/access_token \
     -u '<client-id>:<client-secret>' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'grant_type=client_credentials&scope=tsg_id:<tsg-id>'
   ```

   Then call the inventory with the returned bearer token:

   ```bash
   curl -s -H "Authorization: Bearer <access-token>" \
     'https://api.strata.paloaltonetworks.com/iot/pub/v1/device/list?detail=true&pagelength=10'
   ```

   Access tokens are short-lived — Palo Alto documents a 15-minute lifetime — so expect
   to re-request one while testing. The device list endpoint is rate-limited to 60
   requests per minute.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Palo Alto Networks Device Security").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Device Security API URL** (`url`): the IoT public API base URL, normally `https://api.strata.paloaltonetworks.com`.
   - **Strata Cloud Manager auth URL** (`auth_url`): optional; the OAuth2 token service, default `https://auth.apps.paloaltonetworks.com`.
   - **Tenant Service Group ID** (`tsg_id`): the TSG ID used as the token scope and as the runZero asset ID namespace.
   - **Service account client ID** (`client_id`): the Strata Cloud Manager service account client ID.
   - **Service account client secret** (`client_secret`): the matching client secret.
   - **Lookback window (days)** (`lookback_days`): optional; default 30. **Set this to 0 to import the whole inventory** — see the note below.
   - **User-Agent** (`http_user_agent`): optional; set it if the API rejects the default agent — see the note below.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a service account and see what the IoT inventory returns before
scheduling anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename palo-alto-device-security/palo-alto-device-security.star \
  --kwargs url=https://api.strata.paloaltonetworks.com \
  --kwargs tsg_id=1234567890 \
  --kwargs client_id=runzero@1234567890.iam.panserviceaccount.com \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --kwargs lookback_days=7 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./palo-alto-run
```

`auth_url` defaults to `https://auth.apps.paloaltonetworks.com` and rarely
needs setting.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**`lookback_days` is the parameter that decides what "empty" means here.** It
defaults to 30, so a device that has not been seen in the last 30 days is not
returned at all — and a quiet OT segment can look like a broken credential for
exactly that reason. A short window like the `7` above makes a smoke test fast;
`0` removes the time filter and imports the whole inventory:

```bash
runzero script --filename palo-alto-device-security/palo-alto-device-security.star \
  --kwargs url=https://api.strata.paloaltonetworks.com \
  --kwargs tsg_id=1234567890 \
  --kwargs client_id=runzero@1234567890.iam.panserviceaccount.com \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --kwargs lookback_days=0 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./palo-alto-full --overwrite
```

`tsg_id` is both the token scope and the runZero asset ID namespace, so getting
it wrong does not produce an authentication error — it produces a successful
token for a tenant you did not mean to read, or an empty one. One credential
imports one TSG.

If the API rejects requests in a way that does not look like an authentication
failure, set the User-Agent through the standard HTTP option:
`--kwargs http_user_agent='runzero-integration'`.

`--kwargs` hands the value to the script verbatim, commas included, as long as
the pair contains a single `=`. Only a value carrying a *second* `=` as well as a
comma is re-read as CSV — cut off at the comma, with the remainder becoming a
second, fabricated parameter rather than rejected. Nothing in this parameter set
is normally that shape, but a client secret is opaque; wrap it in double quotes
if it is, `--kwargs '"client_secret=a=b,c"'`, doubling any double quote inside
it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename palo-alto-device-security/palo-alto-device-security.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove the token service accepts
the service account, that the TSG scope resolves, or that any device is parsed.

The fixtures under `palo-alto-device-security/tests/fixtures/` exercise the
parsing offline, including the paging, malformed-record, and rate-limit cases:

```bash
python3 tests/run.py palo-alto-device-security
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat palo-alto-device-security/palo-alto-device-security.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.strata.paloaltonetworks.com,tsg_id=1234567890,client_id=runzero@1234567890.iam.panserviceaccount.com,client_secret=<secret>' \
  --output ./palo-alto-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so no value containing a comma at all can be passed
this way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Palo Alto Networks Device Security.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:palo-alto-device-security`.

## Asset identity

- Target entity: physical IoT, OT, IoMT, and IT endpoints observed on the network by Device Security.
- Source ID field: `devices[].deviceid`
- Documentation evidence: https://pan.dev/iot/api/device-inventory-v-2/ — `deviceid` is "The device ID, which IoT Security uses to identify and track a device (always included)". The vulnerability schema (https://pan.dev/iot/api/vulnerability-list/) states the same value more explicitly: "The MAC address or IP address of the device", and the `groupby` parameter description confirms it is the device key ("`groupby=vulnerability&deviceid=<id>` (the device's MAC address, or its IP for static-IP devices)").
- Uniqueness scope: tenant. `deviceid` is unique inside one Tenant Service Group; the OAuth token is scoped to a single `tsg_id`, so a poll never mixes tenants.
- Cardinality: one `/device/list` row per device. Vulnerability instances are many-to-one children keyed by the same `deviceid` and are attached to the asset rather than emitted as separate assets.
- Stability: the value is the device's MAC address for normal devices, so it survives rename, reboot, IP change, VLAN change, and profile reclassification. For static-IP-only devices the value is the IP address, so a readdress of such a device produces a new `deviceid`.
- Reuse behavior: not documented, and it differs between the two cases. In the MAC case, reuse would require the same hardware address reappearing in the tenant, which runZero would legitimately treat as the same device. In the **static-IP case the identifier is recycled routinely**: an address released by one device and assigned to another produces the *same* `deviceid` for a genuinely different machine. This is the decisive fact for match behavior below.
- Presence: always present. The v2 inventory schema marks `deviceid` as "always included" regardless of the `projection` parameter.
- Final runZero ID: `palo-alto-device-security:<tsg_id>:<deviceid>`
- Missing-ID behavior: skip. A record with no `deviceid` is logged as `skipping device with no deviceid: hostname=<hostname>` and dropped. No random or synthesized ID is ever generated.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. `deviceid` is an **address-derived** identifier, not an opaque device key, so it must not drive matching. A foreign-ID match in runZero is never disqualified by a conflicting MAC, IP, or hostname — that check exists only on the MAC, IP, and hostname match paths — so if a static IP were reassigned to a different device, the recycled `deviceid` would merge that device into the original asset and no break flag could veto it. Turning off id matching removes that failure mode entirely and correlates on the MAC, IP, and hostname the record already carries. `aruba-clearpass` (MAC as id) and `forescout-counteract` (address-derived id) reach the same conclusion for the same identifier class. The id is still emitted so each record keeps a stable key.
- Verdict: **derived, non-authoritative.** The value identifies an address, not a device, and the two coincide only for as long as the address assignment does.

### Notes

- **Assets** come from `GET /iot/pub/v2/device/list`, paged with `offset` and
  `pagelength` (500 per page) and streamed to runZero one page at a time.
  `hostname` becomes the hostname; `ip_address`/`ip` plus `mac_address`/`MAC`
  become the network interface; `vendor` becomes the manufacturer; `model`
  becomes the model; `osGroup`/`os_group`/`os` becomes the OS and `os_ver`
  becomes the OS version; `first_seen_date` and `last_activity` become
  `firstSeenTS` and `lastSeenTS`.
- **`deviceType` is mapped from `category`, not `profile`.** `category` is the
  coarse device class the runZero device type expects ("Infusion System",
  "Camera", "PLC", "Network Equipment"). `profile` is the make/model-specific
  classification ("Sigma Spectrum Infusion System"), which would produce
  thousands of one-off device types; it is kept as a custom attribute and as a
  `profile:` tag instead.
- **Vulnerabilities** come from `GET /iot/pub/v1/vulnerability/list` with
  `type=vulnerability&status=Confirmed&groupby=device`. With `groupby=device` the
  API returns "one item per device ID, each with a single vulnerability", so the
  findings are indexed by `deviceid` first and then attached to the matching
  asset. `vulnerability_name` becomes the vulnerability name, and also the `cve`
  when it matches `CVE-YYYY-NNNN`; `remediate_instruction` becomes the solution;
  `detected_date` becomes `firstDetectedTS`; `risk_level` drives the severity and
  risk ranks. Up to 99 findings are attached per asset.
- **No port data exists in this API**, so `serviceAddress`, `servicePort`, and
  `serviceTransport` are deliberately left unset on every Vulnerability.
- Devices that appear only in the vulnerability response and never in the
  inventory response are still reported, built from the device fields the
  vulnerability instance itself carries (`name`, `ip`, `vendor`, `model`, `os`,
  `sn`, `display_profile_category`). This keeps findings from being silently
  dropped when the inventory time filter excludes an inactive device.
- **The lookback window silently truncates a full inventory pull if you leave it
  at the default.** `lookback_days` maps to the API `stime` parameter, which for
  `/device/list` is "the time when a device was last active". The default of 30
  days matches the reference XSOAR client, which hard-codes `now - 2592000`, but
  it means devices that have been quiet for longer than the window are simply not
  returned. **For a complete inventory import, set `lookback_days` to 0**, which
  omits `stime` entirely from both requests.
- **The API rejects some default user agents.** The reference XSOAR client
  forcibly sets `User-Agent: /` on every request for this reason. runZero sends
  its own default agent; if requests fail with a client error that the
  credentials do not explain, set the **User-Agent** (`http_user_agent`) field on
  the credential — `/` is the value the vendor's own client uses. The script
  never sets a User-Agent itself, so this field is always honored.
- **No software inventory and no service/port data are available from this API.**
  Device Security classifies devices from network behavior; it does not report
  installed packages or listening ports, so no `Software` or `Service` objects are
  produced. Runtime detail such as switch name/IP/port, access point name/IP,
  SSID, wired/wireless, VLAN, subnet, DHCP, site, location, department, asset tag,
  serial number, risk score, risk level, and confidence score is mapped to custom
  attributes prefixed `panw_device_security_`, plus `site:`, `profile:`, and
  `risk:` tags. Tenant-defined attributes (the `attr` block, the
  `customAttributes` list, and `allTags` values) are carried through as well.
- Pagination: both endpoints use `offset` + `pagelength`. The documented maximum
  and default `pagelength` is 1000 for alerts, devices, and vulnerabilities; the
  vendor recommends a smaller page for alerts and vulnerabilities. This
  integration uses 500 for devices and 100 for vulnerabilities.
- Rate limiting: both endpoints are documented at 60 requests per minute. Requests
  are issued with `retries=3` so the shared HTTP helper absorbs 429 and 5xx
  responses with exponential backoff and honors `Retry-After`.
- **Documentation discrepancy.** The authentication page
  (https://pan.dev/iot/api/iot-public-api-new/) shows its worked example against
  `/iot/pub/v1/device/list`, while the dedicated inventory reference
  (https://pan.dev/iot/api/device-inventory-v-2/) documents
  `GET /iot/pub/v2/device/list` and notes it is "Only available to customers with
  SCM access. This api is not supported for IoT Standalone Portal customers". The
  reference XSOAR client agrees with the v2 reference — it rewrites its `/v1` base
  URL to `/v2` for the device list only. Since this integration authenticates
  through Strata Cloud Manager, it uses v2 for `/device/list` and v1 for
  `/vulnerability/list`. Tenants still on the IoT Standalone Portal need the v1
  device list instead.
- **Alternative auth mode for older tenants (not shipped).** Tenants that were
  never migrated to Strata Cloud Manager still run the IoT Standalone Portal
  generation, which is a different base URL and a different credential entirely:
  `https://<tenant>.iot.paloaltonetworks.com/pub/v4.0/<route>`, authenticated with
  `X-Key-Id` and `X-Access-Key` headers instead of a bearer token, and requiring
  `customerid=<tenant>` on every query string. That generation has no `/v2`
  device list. Palo Alto Networks documents it as DEPRECATED, so this repository
  ships one integration for the current Strata Cloud Manager path rather than two.
  If a tenant needs the legacy path, the changes are: replace the token exchange
  with the two static headers, add `customerid` to every request, and move
  `/device/list` back to `/pub/v4.0/device/list`.
- Unverified assumptions: (1) With no `projection` parameter the v2 inventory is
  documented to return "every field from `device/attributes`", but the published
  schema only guarantees `deviceid`, `site_name`, and `attr`, and the response
  example is explicitly partial. Field spellings therefore vary between tenant
  generations, so the script reads several documented spellings for MAC, IP, and
  OS and copies a broad list of attribute names verbatim; fields a given tenant
  does not return are simply absent. (2) `risk_score` on a vulnerability instance
  is a 0-100 device risk score, not a CVSS score, so it is preserved as a custom
  attribute and the Vulnerability severity/risk scores are derived from
  `risk_level` instead. (3) Reuse of a deleted `deviceid` is not documented.
- This integration was validated against local fixtures, not a live Palo Alto
  Networks Device Security tenant.

## Future

- **Outbound: resolve findings from runZero.** `PUT /iot/pub/v1/vulnerability/update`
  ("Mark one or more instances of a vulnerability as resolved") accepts
  `{"action": "mitigate", "full_name": ..., "reason": ..., "ticketIdList": [...]}`,
  and `PUT /iot/pub/v1/alert/update?id=<alert id>` accepts
  `{"resolved": "yes", "reason": ..., "reason_type": [...]}`. Because this
  integration already stores each finding's `zb_ticketid` as a custom attribute,
  an outbound integration could close Device Security tickets when runZero
  confirms a device was patched, decommissioned, or is no longer reachable.
- **Alert ingestion as an event feed.** `GET /iot/pub/v1/alert/list` returns policy
  alerts with `date`, `zb_ticketid`, `deviceid`, `siteName`, `trafficDirection`,
  and `resolved`, and supports `stime`/`sortfield=date`/`sortdirection` for
  incremental pulls. That shape suits an event or activity feed keyed to the same
  asset identity rather than an inventory import, which is why alerts are not
  imported here — a policy alert is not a property of a device.
- **Lookup and enrichment for runZero-discovered IPs.** `GET /iot/pub/v1/device/ip?ip=<ip>`
  returns the full device record for a single address, and
  `GET /iot/pub/v1/device?deviceid=<id>` does the same by device ID. A lookup-style
  integration could enrich addresses runZero found on a segment without pulling the
  whole tenant, which matters on rate-limited tenants (60 requests per minute).
  `GET /iot/pub/v2/device/search` covers the same need for multi-interface devices.
- **IoT coverage-gap reporting.** Comparing the runZero inventory against the
  Device Security inventory identifies devices runZero sees that Device Security
  does not (segments with no PAN-OS visibility) and vice versa. The `site_name`,
  `siteid`, and `subnet` fields already imported here, together with
  `GET /iot/pub/v1/network/segment` and the site definition endpoints, would let a
  reporting integration attribute each gap to a specific site or segment.
- **Pushing runZero data back into the device record.** `PUT /iot/pub/v1/device/bulkUpdate`
  and its `updateSource=` variants exist for third-party enrichment, and
  `POST /iot/pub/v1/tag` adds manual tags to devices. The documented update sources
  are a fixed list of specific vendor integrations (Cisco WLC, Aruba WLC, SNMP,
  SCCM, CrowdStrike, cellular, Infoblox), so there is no generic "arbitrary
  scanner" source; a runZero writeback would most likely have to use the tag and
  custom-attribute endpoints rather than the bulk device update.

## API documentation

- IoT API index: https://pan.dev/iot/api/
- Authentication (OAuth2 client credentials, Basic pre-auth, `scope=tsg_id:<TSG ID>`): https://pan.dev/iot/api/iot-public-api-new/
- Device inventory v2 (identity, `projection`, `stime`, `offset`, `pagelength`, rate limit): https://pan.dev/iot/api/device-inventory-v-2/
- Device inventory v1 (IoT Standalone Portal tenants): https://pan.dev/iot/api/device-inventory/
- Device attributes (the field names `projection` accepts): https://pan.dev/iot/api/device-attributes/
- Vulnerability list (`groupby`, `status`, `stime`, response schema): https://pan.dev/iot/api/vulnerability-list/
- Resolve vulnerability instances: https://pan.dev/iot/api/vulnerability-resolve/
- Alert list: https://pan.dev/iot/api/alert-list/
- Resolve a security alert: https://pan.dev/iot/api/alert-resolve/
- Device details per IP address: https://pan.dev/iot/api/device-detail-ip/
- Device details per MAC address: https://pan.dev/iot/api/device-detail/
- Deprecated IoT Standalone Portal authentication (`X-Key-Id` / `X-Access-Key`): https://pan.dev/iot/api/iot-public-api-headers/
- OpenAPI source for the above: https://github.com/PaloAltoNetworks/pan.dev/tree/master/openapi-specs/iot

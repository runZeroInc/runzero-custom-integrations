# Custom Integration: Device42

## runZero requirements

- A runZero **superuser** account to access [Custom Integrations](https://console.runzero.com/custom-integrations).
- An Explorer that can reach the Device42 appliance over HTTPS.

## Device42 requirements

- Access to the Device42 REST API at the `/api/1.0/devices/all/` endpoint.
- Either:
  - A valid Device42 **username and password**, or
  - A valid **Bearer token**.

## Preparing the API credentials

Device42 supports **Basic** or **Bearer** authentication. Its own API reference states that
the REST APIs "enforce the role-based security that is created with the Device42 app" —
there is no separate API permission model, so whatever the account can read in the UI is
what the integration imports.

You must configure both fields in your runZero credential:

- `auth_scheme`: must be either `basic` or `bearer`.
- `credential`:
  - For `basic`: a base64-encoded string of `username:password`.
  - For `bearer`: your raw API token.

### Example for Basic Authentication

```bash
echo -n 'myuser:mypassword' | base64
```

Use the output as your `credential`. Set `auth_scheme` to `basic`.

Note that the script sends this value straight through as `Authorization: Basic <credential>`.
It does **not** encode it for you, so paste the base64 output, not the raw `user:password`.

### Example for Bearer Authentication

Set `auth_scheme` to `bearer`, and `credential` to your API token string.

**Read this before choosing bearer.** Device42 bearer tokens are minted per API Client and
are short-lived by design — the API Client's `token_ttl` field is documented as "token time
to live in **seconds**", and the vendor's own examples show values of 10 and 60. Device42
states plainly that "Bearer tokens are time limited, and, once expired, cannot be used
again." A token pasted into a runZero credential is a static value, so unless you raise
`token_ttl` on the API Client to cover the interval between scheduled runs, the task will
authenticate once and then fail. **Basic is the appropriate choice for a scheduled
integration.** Bearer is workable for a one-off command-line run where you mint a token
immediately beforehand:

```bash
curl -sk -u '<client key>:<client secret key>' \
  -X POST 'https://device42.example.com/tauth/1.0/token/'
```

The response carries `token`, `expires`, and `ttl`. The API Client's `resource_owner` must
be a Device42 **non-staff** user, and the token inherits that user's permissions.

## Steps

### Device42 configuration

1. Create a dedicated read-only account for the integration. In the Device42 UI go to
   **Tools → Admins & Permissions → Administrators**. Device42's deployment guidance is
   explicit that "when creating dedicated users for API access, limit their actions to
   read-only if that is all that is required."

2. Take away UI access, and keep API access. Device42 has **no separate "enable API
   access" checkbox** — every user can call the API. The documented way to make an
   API-only account is the inverse: "If you want a user to have access via the API, but
   not via the UI - deselect **'Staff Status'** for that user from UI Tools → Admins &
   Permissions → Administrators."

3. Grant read access through an admin group. Uncheck **Superuser Status** on the account,
   then assign it to a group under **Tools → Admins & Permissions → Admin Groups** that
   carries read permission on Devices, using the **Permissions** box on the
   Administrators record.

   The exact name of a suitable group is **not something we could establish from Device42's
   documentation** — the role-based-access page describes only administrator-created custom
   groups and names no built-in read-only group. Check what exists on your own appliance
   rather than looking for a specific label.

4. **Turn on API paging, or this integration will not page.** This is the single most
   important prerequisite and it is off by default. Go to **Tools → Settings → Global
   Settings**, click **Edit** at the top right, and in the **API** section near the bottom
   check **Enforce API GET Limits**, then set **API GET Limit**. Device42's own guidance:
   "A good limit to start with is 500 or 1000." The vendor documents that "offset is used
   for paging - that is, the offset is only applied when the total number of objects
   returned exceeds the limit that is returned." With the setting off, `limit` and `offset`
   are ignored, one request returns the entire inventory, and the script's paging loop is
   working against an API that is not honouring it. The script requests 1000 per page, so
   set the API GET Limit to at least that.

5. Note the base URL. Device42 is a self-hosted virtual appliance, so this is
   `https://<your-appliance-host>` with **no path suffix** — the script appends
   `/api/1.0/devices/all/` itself. The Device42 **Appliance Manager** is a different
   service on ports 4343/4242; do not point the integration at it.

6. Plan for the certificate. A Device42 appliance ships with a certificate no public trust
   store contains — the vendor notes you get a "Your Connection is not private" warning
   "because you are accessing a local server that does not have a signed security
   certificate." Either install a properly signed certificate on the appliance, or supply
   the appliance CA as `tls_ca_cert` on the runZero credential. Disabling validation with
   `tls_disable_validation` is a last resort.

7. Confirm the credential and the endpoint from the Explorer host before configuring
   anything in runZero:

   ```bash
   curl -sk -H "Authorization: Basic $(echo -n 'myuser:mypassword' | base64)" \
     'https://device42.example.com/api/1.0/devices/all/?limit=2&offset=0' | jq .
   ```

   A `total_count` and a device array means the account, the permissions, and the endpoint
   are all right.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Device42 API URL** (`url`): your appliance, for example `https://device42.example.com`.
     **Required, with no default.** Device42 is customer-hosted, so nothing but your own
     appliance is a correct answer. The one endpoint the vendor publishes,
     `https://swaggerdemo.device42.com`, is its public Swagger sandbox: it holds Device42's
     demo records rather than yours, its guest credentials are published in the vendor's API
     spec, and its database resets every 30 minutes. Shipping it as a default meant a
     credential left blank imported that sandbox into your inventory as real assets, so
     there is no default now and a blank value fails validation instead.
   - **Auth scheme** (`auth_scheme`): `basic` or `bearer`.
   - **Credential** (`credential`): base64-encoded `username:password` for basic, or the raw
     API token for bearer.
   - **TLS options** (`tls_*`): set `tls_ca_cert` to the appliance CA exported above.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g. `device42`).
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
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
runzero script --filename device42/device42.star \
  --kwargs url=https://device42.example.com \
  --kwargs auth_scheme=basic \
  --kwargs credential=ZXhhbXBsZWZha2V1c2VyOkV4YW1wbGVGYWtlUGFzc3cwcmQ= \
  --kwargs tls_ca_cert=/etc/runzero/device42-ca.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./device42-run
```

`--output` writes the assets the run produced, and it requires
`--custom-integration-id` — the scanner rejects the run with `custom integration ID
required for output` without one. Any well-formed UUID works for a local run; use the real
one from the console when you want the output to match a scheduled task. The scanner also
refuses to write into a directory that already exists, so add `--overwrite` when re-running
into the same path. Add `--verbose` for the request-by-request log, or omit `--output` to
see only the log lines.

Read the result rather than just the exit status. `Device42 API logical error:` in the log
is the appliance answering with a non-zero `code` — an authentication or permission
problem, not a connectivity one. Getting the full inventory back in a single page when you
expected several is the **Enforce API GET Limits** setting being off.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma —
the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. That matters here: **base64 is padded with `=`**, so a
`credential` for basic auth very often ends in one or two of them. A padded value with no
comma is still fine, but if one ever carries both characters, wrap the whole argument in a
second pair of quotes: `--kwargs '"credential=YWJjZA==,ZQ=="'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live appliance:

```bash
runzero script --filename device42/device42.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Device42 accepts the credential, that the account can read
devices, or that any device is parsed. The fixture scenario is what exercises the parsing:

```bash
python3 tests/run.py device42
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat device42/device42.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://device42.example.com,auth_scheme=basic,credential=ZXhhbXBsZWZha2V1c2VyOkV4YW1wbGVGYWtlUGFzc3cwcmQ=' \
  --output ./device42-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for a
script with a different entry point. Note that `--custom-integration-script-kwargs` takes
one comma-separated string — genuinely, and with no single-`=` exemption. Here a comma in
*any* value splits it. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Device42.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:device42`.

### Notes

- Your Device42 instance must be reachable from the runZero Explorer.
- API pagination is handled automatically using `limit` and `offset`, 1000 devices per
  request — but only if **Enforce API GET Limits** is on. See step 4 above.
- Assets will be enriched with all available fields (except IP/MAC/name) in `customAttributes`.
- `/api/1.0/devices/all/` is current, not deprecated. Device42's OpenAPI spec describes it
  as "Get all devices with detailed output (added in v6.3.4)" and carries no deprecation
  flag, while marking roughly twenty other operations deprecated explicitly. `/api/2.0/devices/`
  is a thinner endpoint, not a drop-in replacement for this one.
- **If a run reports no devices while the same request in `curl` clearly returns some,
  check the case of the array key.** This script reads `Devices`. Device42's published
  OpenAPI spec is internally inconsistent on this point: the `devicesAll` schema backing
  `/api/1.0/devices/all/` declares the array as lowercase `devices`, while the sibling
  device-list endpoints declare it as `Devices`. We have not been able to settle which one
  a live appliance actually returns for this path.
- Device42 documents no request-rate limit for the REST API. The "API GET Limit" setting is
  a page-size cap, not a rate cap — the two are unrelated.
- **Device42's `type` is mapped, not passed through.** It used to reach `deviceType`
  verbatim, falling back to `device_sub_type` and then `virtual_subtype`. Device42's `type`
  names *how a device is realized* — physical, virtual, blade, cluster, other, unknown — not
  what chassis it is, and the platform does not discard a value it does not recognise: it
  misses the exact-match list in `IdentifyTypeFromCustomIntegration`, then
  `normalize.DeviceType()` title-cases it and returns it, so "physical" and "virtual" became
  device types in their own right and displaced the chassis runZero fingerprints from
  `hw_model` and `manufacturer`.

  `device_type()` now consults `device_sub_type` first — it is the more specific field, and a
  customer who named a sub-type `Switch` or `Firewall` has said exactly what runZero wants —
  and honours it only when it already spells a member of runZero's exact-match list. `blade`
  maps to `Server`, since a Device42 blade is a blade server. Everything else, including
  `virtual` and `cluster`, leaves `deviceType` **unset**: runZero has no member for either, and
  a Device42 cluster is a logical grouping rather than a device at all. All three raw fields
  are kept as custom attributes, so nothing is lost by not typing on them.
- **Tags are imported.** `build_assets` used to guard the tag loop with
  `if type(raw_tags) == list:`, comparing a *string* (`type()` returns `"list"`) against the
  `list` builtin, so the condition was never true and no asset ever carried a tag. It now uses
  the correct `type(x) == "list"` form, as the rest of the file does.

## Asset identity

- Target entity: a **device record in the Device42 CMDB** — anything the appliance tracks as a device, which includes physical hardware, virtual machines, clusters, and network gear alike.
- Source ID field: a four-step fallback chain — `id`, then `uuid`, then `device_id`, then `serial_no`.
- Documentation evidence: Device42's published OpenAPI spec describes the device record for this path with `device_id` as the numeric primary key and `uuid` as a separate UUID column. **A bare `id` key — the field this chain reads first — is not what the spec names for `/api/1.0/devices/all/`,** so which of the four is actually in force depends on what your appliance version returns. This is the same spec inconsistency already noted above for the `Devices` / `devices` array key; the two problems have the same root cause and the same resolution, which is to check a real response.
- Uniqueness scope: one Device42 appliance. The value is used bare with no appliance prefix, so two appliances imported through the same custom integration share an id space.
- Cardinality: one source row per device record.
- Stability: `device_id` and `uuid` are CMDB primary keys and are stable for the life of the record — that is what a CMDB is for. A record deleted and re-created is a new device with a new id, which is a data-entry event rather than an infrastructure one.
- **The `serial_no` tail of the chain is the identity hazard, and it is a real one.** A serial number is not a unique identifier in practice: it is blank on many virtual and whitebox devices, and where it is populated it is frequently a placeholder such as `To be filled by O.E.M.` or `System Serial Number` shared by every machine from one board vendor. Any two records that fall through to that step with the same placeholder compose the *same* foreign id and merge into one runZero asset. Because `matchBehavior` is left at the default, the foreign id is used to find merge candidates — and once found, that match cannot be vetoed by a conflicting MAC, hostname, or address. No flag prevents this; only removing the step, or qualifying it, would.
- **The chain also mixes id spaces.** A numeric primary key, a UUID, and a serial number can all be foreign ids within a single import, and a record that gains or loses one of the earlier fields between runs silently moves from one id space to another — which forks the asset, because runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset.
- Reuse behavior: not documented. A monotonic `device_id` makes recycling after deletion conceivable; a `uuid` makes it implausible; a `serial_no` guarantees collisions as described above.
- Presence: a record with none of the four is skipped with `device42: skipping device with no stable id: name=<name>`.
- Final runZero ID: whichever field the chain reached, as a string.
- Missing-ID behavior: skip and log.
- Match behavior: **not set** — the platform default, all match and break dimensions on.
- Verdict: **authoritative where the chain lands on `device_id` or `uuid`; not authoritative where it falls through to `serial_no`.** The default setting is right for the first case and wrong for the second, and there is no way to express both with one flag set — which is the argument for narrowing the chain rather than for changing `matchBehavior`.

## Future

Device42 is a CMDB, so it holds substantially more than the device list this integration reads, and it is one of the few sources in this repository where the *outbound* direction is more valuable than the inbound one. Endpoint paths below come from Device42's published API surface; confirm them against your own appliance version before building on them, given the spec inconsistencies already noted.

- **Outbound: feed the CMDB from runZero's discovery — this is the point of pairing these two products.** A CMDB's chronic failure mode is that it only knows what somebody entered into it, while runZero's entire job is finding what nobody entered. Device42 accepts device creation and update through its device endpoints and IP records through its IPAM endpoints, so runZero-discovered assets that have no CMDB record could be created as devices, and runZero's observed addresses could populate IPAM. That closes the loop that makes a CMDB trustworthy. It is also a write into a system of record, so it needs a dry-run mode, a clear rule for what qualifies as "new", and an owner for the reconciliation — otherwise it fills the CMDB with duplicates of records that already exist under a different name.
- **IPAM: subnets, VLANs, and the IP inventory.** Device42's IPAM holds subnet and VLAN definitions and per-address records. Those are directly useful to runZero in two ways: as **scan scope** (a subnet inventory is a ready-made target list, and one that includes segments runZero has never been pointed at), and as a reconciliation source (addresses Device42 believes are assigned that runZero finds unused, and vice versa). Neither is available from the device endpoint this integration reads today.
- **Software inventory.** Device42 tracks software separately from devices, which is what would produce `Software` records — this integration currently emits none, because `/api/1.0/devices/all/` carries no package list.
- **Lifecycle and ownership data, which is the CMDB's unique contribution.** Purchase records, warranty and support-contract dates, and parts inventory are things no scanner can ever discover: they are commercial facts, not network facts. Importing them as custom attributes would let a runZero search answer "which of the assets on this segment are out of warranty" — a question runZero cannot answer from its own data at all, and a genuinely better use of a CMDB than re-importing hostnames it already knows.
- **Business application and service mapping.** Device42's application and service-instance records describe which business service depends on which host. Attached to runZero assets, that turns an inventory question into an impact question — "what breaks if this host is taken off the network" — which is the most valuable thing a CMDB knows and the hardest for any other tool to reconstruct.
- **Rack, room, and building records for physical location.** Location is another fact discovery cannot infer. Imported as custom attributes it makes "every asset in this data hall" a searchable runZero query.
- **DOQL for anything the REST endpoints do not expose.** Device42 publishes a query interface over the underlying CMDB schema, which is the escape hatch when a needed join has no dedicated endpoint — for example correlating devices to purchases to business applications in one pass rather than in three. It is also the most version-sensitive surface here, since it exposes the schema directly.
- **Coverage-gap reporting in both directions.** Devices in Device42 that runZero has never observed are either decommissioned records nobody cleaned up or hosts on segments no Explorer reaches — both worth knowing, and distinguishable by whether the address is live. Assets runZero discovers with no CMDB record are the shadow IT case, and they are the input to the outbound push described above.

To find assets imported by this integration:

```
custom_integration:device42
```

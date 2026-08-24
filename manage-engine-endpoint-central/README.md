# Custom Integration: Endpoint Central

## runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Endpoint Central server over HTTP or HTTPS.

## Endpoint Central Requirements

- **An on-premises Endpoint Central server.** This integration sends the token as a bare
  `Authorization` header value, which is the on-prem format. Endpoint Central **Cloud**
  expects `Authorization: Zoho-oauthtoken <access_token>` instead and will reject a bare
  token — see the note under Endpoint Central Configuration below.
- The server's base URL, including its port.
- An Endpoint Central auth token for an account that can read the Inventory module.

The script targets API version **1.4**, which is hardcoded. ManageEngine's own Getting
Started page states "1.4 ie current API Version" for both on-prem and cloud, and no higher
version exists. Note that the sibling product **Endpoint Central MSP is on 1.3**, so this
script does not work against an MSP installation.

## Steps

### Endpoint Central Configuration

1. **Create a least-privilege account.** In the current role matrix, the narrowest built-in
   role with read access to Inventory is **Guest**, which is read-only across the product.
   Two roles that sound like they would work do not: **Technician** and **Auditor** are both
   listed as **No Access** to Inventory. If Guest is broader than you want, create a custom
   role under **Admin → General Settings → User Administration → Add Role** and grant
   Inventory read only.

   One thing to check empirically: Guest also has **No Access** to Scope Of Management. If
   any field you expect turns up empty, that is the likely cause.

2. **Note the base URL and port.** An on-prem Endpoint Central server defaults to **8020 for
   HTTP** and **8383 for HTTPS**, both configurable at install time — so the URL is
   typically `https://ec.example.com:8383`. The script appends
   `/api/1.4/inventory/scancomputers` itself, so give it the origin only.

3. **Get an auth token.** Post to the authentication endpoint with a **base64-encoded**
   password:

   ```bash
   curl -s -X POST 'https://ec.example.com:8383/api/1.4/desktop/authentication' \
     -H 'Content-Type: application/json' \
     -d '{"username":"runzero","password":"'"$(echo -n 'ExampleFakePassw0rd' | base64)"'","auth_type":"local_authentication"}'
   ```

   For an Active Directory account use `"auth_type":"ad_authentication"` and add
   `"domainName":"<domain>"`.

   The token is nested deeper than you might expect — read it from
   `message_response.authentication.auth_data.auth_token`, not from a top-level field. The
   same response returns a `user_permissions` object with `read`/`write`/`admin` arrays,
   which is a quick way to confirm the account got the rights you intended.

   If two-factor authentication is enabled, this first call returns
   `two_factor_data.unique_userID` instead of a token, and you complete the exchange against
   `/api/1.4/desktop/authentication/otpValidate`.

   **We could not establish how long an on-prem auth token remains valid.** ManageEngine's
   on-prem API documentation does not state an expiry, and the "1 hour" figure that
   circulates widely is the *cloud* OAuth access-token lifetime, which does not apply here.
   Treat token rotation as something to observe on your own installation rather than
   something to schedule against a documented number.

4. **On the "API key generation" console page.** Endpoint Central does have a persistent
   API key feature at **Admin → Integrations → API key generation** (older builds:
   **Admin → Global Settings → API Key Generation**), generated per logged-on user, who must
   hold Administrator privilege, and invalidating the previous key each time it is
   regenerated. **We could not verify that this key is accepted for `/api/1.4/inventory/`
   requests** — ManageEngine documents it only for ServiceDesk Plus and other ME-product
   integrations. Use the `desktop/authentication` token above unless you have confirmed
   otherwise on your own server.

5. **Test your credentials** before configuring anything in runZero. Note the header is the
   raw token with **no `Bearer` prefix**:

   ```bash
   curl -s -X GET 'https://ec.example.com:8383/api/1.4/inventory/scancomputers?pagelimit=1&page=1' \
     -H 'Authorization: B42550F3-006D-48EB-8011-F6C7D6323EE7' \
     -H 'Accept: application/json'
   ```

   A 200 with `message_response.scancomputers` populated means the token and the role are
   both right.

### runZero Configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter device data.
    - Adjust the custom attributes as needed for your specific use case.

2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Endpoint Central URL** (`url`): the server origin including port, for example
      `https://ec.example.com:8383`.
    - **API auth token (on-prem)** (`oauth_token`): the on-prem `auth_token` from step 3,
      sent verbatim as the `Authorization` header. Despite the parameter key -- kept as
      `oauth_token` so existing credentials continue to work -- it is not an OAuth bearer
      token and must not be prefixed with `Bearer` or `Zoho-oauthtoken`.
    - **TLS options** (`tls_*`): an on-prem server usually presents a certificate no public
      trust store contains; set `tls_ca_cert` rather than disabling validation.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "endpoint-central").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.

4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what an
integration would import before scheduling it. Note that the script file here is
`manage-engine-endpoint-central.star`, not a name matching the directory. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename manage-engine-endpoint-central/manage-engine-endpoint-central.star \
  --kwargs url=https://ec.example.com:8383 \
  --kwargs oauth_token=B42550F3-006D-48EB-8011-F6C7D6323EE7 \
  --kwargs tls_ca_cert=/etc/runzero/ec-ca.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./endpoint-central-run
```

`--output` writes the assets the run produced, and it requires `--custom-integration-id` —
the scanner rejects the run with `custom integration ID required for output` without one.
Any well-formed UUID works for a local run; use the real one from the console when you want
the output to match a scheduled task. The scanner also refuses to write into a directory
that already exists, so add `--overwrite` when re-running into the same path. Add
`--verbose` for the request-by-request log, or omit `--output` to see only the log lines.

Read the result rather than just the exit status. `Scan API error:` in the log is the server
rejecting the request — most often an expired token, or a bare token sent to a Cloud tenant
that wanted `Zoho-oauthtoken`. A clean run that reports `No devices returned` usually means
the account's role has No Access to Inventory rather than that the inventory is empty.

The script requests `pagelimit=1000`, which is exactly ManageEngine's documented ceiling:
"Maximum 1000 objects are displayed per page." Paging starts at `page=1`.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma —
the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. An Endpoint Central auth token is a hyphenated hex GUID,
so it carries neither character.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename manage-engine-endpoint-central/manage-engine-endpoint-central.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server, so
it proves the script initializes, declares its parameters correctly, and issues a request.
It does not prove Endpoint Central accepts the token, that the account can read Inventory,
or that any computer is parsed. The fixture scenario is what exercises the parsing:

```bash
python3 tests/run.py manage-engine-endpoint-central
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat manage-engine-endpoint-central/manage-engine-endpoint-central.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://ec.example.com:8383,oauth_token=B42550F3-006D-48EB-8011-F6C7D6323EE7' \
  --output ./endpoint-central-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for a
script with a different entry point. Note that `--custom-integration-script-kwargs` takes
one comma-separated string — genuinely, and with no single-`=` exemption. Here a comma in
*any* value splits it. Prefer `script --kwargs` for ad-hoc runs.

### What's Next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from the custom integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:endpoint-central`.

### Notes

- **What is imported.** One asset per row of `GET /api/1.4/inventory/scancomputers`, read
  from `message_response.scancomputers`. The response also carries `total`, `limit`, and
  `page` inside `message_response`.
- **On-prem only, in practice.** The cloud edition serves the same `/api/1.4/` path from
  eight regional hosts (`https://endpointcentral.manageengine.` plus `com`, `eu`, `in`,
  `com.au`, `cn`, `jp`, `ca`, `uk`), but requires the `Zoho-oauthtoken` header and a full
  OAuth exchange, which this script does not perform.
- **No documented rate limit** for on-prem `/api/1.4/` endpoints. The throttles ManageEngine
  publishes for the cloud edition apply to OAuth token issuance, not to read throughput.
- **An interface is attached only when something usable was built.** `build_network_interfaces`
  goes through `net.network_interface`, which answers `None` when neither the addresses nor the
  MAC survive parsing, and returns an empty list in that case. A computer whose row carries
  neither `ip_address` nor `mac_address` — an agent that has enrolled but not yet completed an
  inventory scan — therefore imports with no interface rather than an empty one, and correlates
  on its `resource_name`. This previously returned a one-element list unconditionally.
- **A malformed MAC no longer ends the run.** Endpoint Central writes the literal string
  `unknown` into `mac_address` on a not-yet-inventoried row. That used to reach
  `NetworkInterface(macAddress=...)` verbatim, and the runtime rejects it — `asset Network
  Interface MAC address "unknown" is invalid` — which, with no exceptions in Starlark, killed the
  whole page: every asset already parsed was lost and none were exported. `network_interface`
  drops an unparseable MAC and keeps whatever address is beside it. It also strips a `:port` or
  `%zone` suffix, so an `ip_address` field of `10.91.1.22:445` now contributes `10.91.1.22`
  instead of being discarded.

## Asset identity

- Target entity: a **computer in the Endpoint Central inventory** — one row per scanned system on the server this credential points at.
- Source ID field: `resource_id`, falling back to `id`.
- Documentation evidence: `resource_id` is Endpoint Central's internal resource identifier for a managed computer, and it is the value ManageEngine's other inventory endpoints accept when scoping a query to one machine. **The exact fallback semantics could not be verified** — whether a `scancomputers` row ever carries a bare `id` instead is not something the published documentation settles, so the second step of the chain is defensive rather than evidence-based.
- Uniqueness scope: **one Endpoint Central server.** The value is used bare with no server prefix, so two servers imported through one custom integration share an id space — and because these are sequential internal identifiers rather than UUIDs, two servers will genuinely reuse the same numbers for different machines. One credential and one custom integration per server.
- Cardinality: one source row per scanned computer.
- Stability: stable while the inventory record exists. Removing a computer from Endpoint Central and re-adding it — a re-imaged machine, or one whose agent was uninstalled and reinstalled — creates a new record with a new `resource_id`.
- Reuse behavior: not documented. A sequential internal identifier makes recycling after deletion conceivable, and unlike a UUID nothing about its shape argues against it.
- Presence: a row with neither field is skipped with `endpoint-central: skipping device with no resource_id/id: name=<resource_name>`.
- Final runZero ID: the raw value as a string.
- Missing-ID behavior: skip and log, after the fallback has been tried.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: this is a persistent per-machine identifier issued by the server and used directly, which is what keeps a laptop on one asset while its address changes.
- Verdict: **scoped authoritative** for an inventory record on one server; derived for the machine, because a re-registration mints a new id. On that path the result is a second runZero asset and **no `matchBehavior` flag prevents it** — runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`.

Correlation rests on the single `ip_address` and `mac_address` values on the row, plus `resource_name` as the hostname. The address field is split on commas before parsing, so a server that returns several addresses in one field is handled, but only one MAC is available — a multi-homed machine contributes one adapter. Every other field on the row is carried through into custom attributes untouched, truncated to 1023 characters.

## Future

Endpoint Central's `/api/1.4/` surface is considerably larger than the one endpoint this integration reads, and it is unusually well suited to runZero because it is a patch-management product rather than an EDR — it knows about software and updates, not just about devices. Confirm the routes below against your own server's API reference before building on them; the on-prem documentation is versioned with the build.

- **Software inventory as `Software` records — the largest gap.** Endpoint Central maintains a per-computer software inventory, and this integration emits **no `Software` records at all** today. For a Windows estate that inventory is the main thing the product knows which runZero cannot observe from the network, and it is the join key for everything below.
- **Missing patches as real `Vulnerability` records.** This is the item worth doing first after software. Endpoint Central's patch module reports which updates each machine is missing, with severity, and vendor patch metadata routinely names the CVEs a patch addresses. Unlike the behavioral detections that most EDR integrations in this repository surface, those genuinely *are* CVEs, so they populate `Vulnerability.cve` and runZero's own vulnerability reporting recognises them. Very few sources in this repository can produce that.
- **Prohibited-software and license data.** Endpoint Central tracks software an organization has banned and license entitlements against installed copies. Attached to runZero assets, "every machine on this segment running prohibited software" becomes a network-scoped question rather than an inventory-scoped one.
- **Scope of Management, which is where the coverage gap actually lives.** `scancomputers` returns machines that have been scanned — that is, managed ones. Endpoint Central's scope-of-management view also knows about machines it has *discovered* but does not manage. Importing that set separately, and tagging it as unmanaged, gives a three-way diff: managed and scanned, known but unmanaged, and discovered by runZero and unknown to Endpoint Central entirely. The third set is the one a deployment team acts on.
- **Mobile device management.** Endpoint Central's MDM module covers phones and tablets under the same server. Those are assets, they have MACs and addresses, and they are invisible to the computer inventory this integration reads.
- **Detailed hardware inventory.** Serial number, manufacturer, model, memory, and disk detail are available per computer and would populate the asset's `manufacturer`, `model`, and serial rather than leaving runZero to fingerprint them — useful precisely because Endpoint Central sees hosts that are powered off or off-segment when a scan runs.
- **Outbound is possible and should be approached carefully.** The same API can deploy patches and run remote actions. Driving patch deployment from a runZero query is a real workflow, and it is also a way to reboot a fleet by accident: it needs per-machine confirmation, a dry-run mode, and an audit trail rather than a scheduled task. The reversible and genuinely useful subset is Endpoint Central's custom fields on a computer record, which would let runZero's classification appear where administrators already work.
- **Cloud tenants are out of reach without an OAuth exchange.** The cloud edition serves the same `/api/1.4/` paths from eight regional hosts but requires the `Zoho-oauthtoken` header and a full OAuth flow, which this script does not perform. Supporting it is a self-contained change — an authorization-code or refresh-token grant plus a header switch — and it would roughly double the set of installations this integration can reach.

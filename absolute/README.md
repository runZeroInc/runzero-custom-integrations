# Custom Integration: Absolute Secure Endpoint

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Absolute Secure Endpoint requirements

- An Absolute API token created with the **Generate Token** option, which issues a token ID and a secret key. This integration signs requests with HS256 (symmetric) and does **not** support the ES256 (asymmetric, uploaded public key) token type.
- The token requires the `View` permission for **Device reports** and **Device Fields**. Importing installed software additionally requires the `View` permission for **Software reports**. Geolocation attributes require the `View` and `Address-level view` permissions for **Geolocation**; without them Absolute simply omits `geoData` and the rest of the import still succeeds.
- The token must not be expired. Absolute defaults new tokens to 90 days and allows a maximum of one year, so the credential needs rotating on that cadence.
- If the token restricts access by **Approved IP Address**, the public egress address of the Explorer running the task must be on that list.
- Absolute APIs accept TLS 1.2 connections only.

## Steps

### Absolute Secure Endpoint configuration

1. Log in to the Secure Endpoint Console as a user with the `Manage` permission for **API credentials**.
2. On the navigation bar, click **Settings** > **API management**, then click **Create API token**.
3. Give the token a title, select **Generate Token**, and set an expiration date.
4. Adjust the token permissions down to the minimum listed above, then click **Save**.
5. Copy the **Token ID** and the **Secret key** from the Token Key Details section, or click **Download Token**. The secret key cannot be retrieved after the dialog is closed.
6. Note which console URL you sign in to, so you can pick the matching API host below:

   | Console URL | API host |
   | --- | --- |
   | Console URL | API host | Region |
   | --- | --- | --- |
   | `https://cc.absolute.com` | `https://api.absolute.com` | CA1, Montreal |
   | `https://cc.us.absolute.com` | `https://api.us.absolute.com` | US1, Oregon |
   | `https://cc.eu2.absolute.com` | `https://api.eu2.absolute.com` | EU2, Frankfurt |
   | `https://cc.uk1.absolute.com` | `https://api.uk1.absolute.com` | UK1, London |
   | `https://cc.in1.absolute.com` | `https://api.in1.absolute.com` | IN1, Mumbai |
   | `https://cc.fr1.absolutegov.com` | `https://api.fr1.absolutegov.com` | FR1, US FedRAMP |

   **UK1 is absent from Absolute's own API reference and is nonetheless real.**
   The console-to-API mapping published in their OpenAPI strings document names
   the other five and omits this one, which is why it was missing from the
   `api_host` enum here. It is a production region: Absolute's sub-processor
   page lists a UK data center on AWS in London, `api.uk1.absolute.com` presents
   a dedicated certificate for `uk1.absolute.com` rather than a wildcard, and it
   answers `401` to an unauthenticated `/v3` request exactly as the documented
   hosts do. It is now selectable.

   Two names that look plausible and are **not** usable: `api.ca1.absolute.com`
   resolves but serves a certificate for `api.absolute.com` with no matching
   SAN, so every TLS client fails on it — the Canadian data center's API host is
   the unprefixed `api.absolute.com`. And `api.us1.absolute.com` does not exist;
   the region code is US1 but the hostname carries no digit.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Absolute Secure Endpoint").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Absolute API host** (`api_host`): the regional API endpoint that matches your Secure Endpoint Console address.
   - **API token ID** (`token_id`): the token ID from Settings > API management.
   - **API secret key** (`secret_key`): the secret key issued alongside the token ID.
   - **Import installed software** (`import_software`): optional; make a second pass over the software report and attach applications to each device (default: false).
   - **Only import active agents** (`active_only`): optional; restrict the import to devices whose agent status is Active (default: false).
   - **Page size** (`page_size`): optional; records requested per page, capped at 500 by the device report (default: 500).
   - **Maximum pages to retrieve** (`max_pages`): optional; safety ceiling on the paging walk (default: 20000, which is ten million records at the maximum page size). Raise it if a run fails with `pagination limit reached`. Left unset, the ceiling scales with `page_size` so a smaller page still reaches the same ten-million-record target.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token and see what a real account returns before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename absolute/absolute.star \
  --kwargs api_host=https://api.eu2.absolute.com \
  --kwargs token_id=6f2a91c4-e0b8-4d26-a5c8-f1e7d09b3a42 \
  --kwargs secret_key=Zm9vYmFyc2VjcmV0a2V5ZXhhbXBsZTEyMzQ1Njc4OTA= \
  --kwargs active_only=true \
  --kwargs page_size=50 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./absolute-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

Lowering `page_size` on a first run keeps a smoke test small. Leave
`import_software` off until the device pass looks right: it is a second full
pass over the account, and on a large fleet that is the expensive half of the
run.

The most common first-run failure is not the credential but the token's
permissions. A token without `View` on **Device reports** authenticates
correctly and then returns nothing, which looks identical to an empty account
in the log.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename absolute/absolute.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Absolute accepts the token
pair, that the JWS signature is well formed against a real host, or that any
device is parsed.

The fixtures under `absolute/tests/fixtures/` exercise the parsing offline:

```bash
python3 tests/run.py absolute
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat absolute/absolute.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_host=https://api.eu2.absolute.com,token_id=6f2a91c4-e0b8-4d26-a5c8-f1e7d09b3a42,secret_key=<secret>' \
  --output ./absolute-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
secret key containing a comma cannot be passed this way; prefer
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Absolute Secure Endpoint.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:absolute`.

## Asset identity

- Target entity: a physical endpoint (laptop, desktop, or tablet) carrying the Absolute Secure Endpoint agent, frequently persisted in the device firmware.
- Source ID field: `deviceUid`
- Documentation evidence: the published v3 OpenAPI document defines `deviceUid` as "The system-defined unique identifier of the device" (`shared.response.payload.deviceUid` in `https://api.absolute.com/api-doc/strings.json`). It is the resource key Absolute itself uses for per-device endpoints such as `GET/PUT /v3/configurations/customfields/devices/{deviceUid}`, and it is the documented default sort and join key of the software report (`deviceUid:asc,appId:asc`).
- Uniqueness scope: the regional Absolute cloud. Values are GUIDs, and every device row also carries the `accountUid` that owns it; an API token can only ever read its own account.
- Cardinality: one row per device in `GET /v3/reporting/devices`. `GET /v3/reporting/applications-advanced` emits many rows per device, all carrying the same `deviceUid`, which is what the software pass groups on.
- Stability: survives rename, DHCP address change, NIC replacement, reboot, OS upgrade, and agent upgrade. Absolute's firmware persistence is specifically designed so that a reimage or disk replacement reinstalls the agent and keeps reporting under the same device record.
- Reuse behavior: not documented. Values are GUIDs, so reassignment is implausible, and unenrolled devices are marked with `unenrollmentDateTimeUtc` rather than being recycled. Treated as non-reusable; this is the one identity property taken on inference rather than an explicit contract.
- Presence: always returned when `deviceUid` is requested in `select`, which this integration always does. Any record arriving without it is skipped.
- Final runZero ID: `absolute:<api-hostname>:<deviceUid>` — for example `absolute:api.eu2.absolute.com:56be8d1f-2eb8-4e9b-bbd6-1aab032abcde`.
- Missing-ID behavior: skip the record and log only its `esn`; no identifier is ever synthesized.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`
- Verdict: authoritative, scoped to the regional cloud.

The namespace is the configured regional API hostname rather than `accountUid`, because it is known from configuration before any record is parsed and therefore can never go missing mid-import. The six regional clouds are separate systems with separate data residency, so the hostname is the real uniqueness boundary; `accountUid` is preserved as a custom attribute.

`matchBehavior` keeps `deviceUid` as the merge signal while preventing network churn from fragmenting a device. This fleet is mostly roaming laptops: `localIp` is a last-known DHCP address that changes with every network, hostnames are renameable, and `networkAdapters` is empty for devices that have not checked in recently or whose token lacks the permission to see it.

### Notes

- Assets come from `GET /v3/reporting/devices`. Imported fields include hostnames (`deviceName`, `fullSystemName`), `domain`, OS name and version, manufacturer, model, device type, first and last check-in times, and network interfaces built from `networkAdapters` (MAC, IPv4, IPv6) falling back to `localIp`.
- Installed software is optional and comes from `GET /v3/reporting/applications-advanced`, mapping `appName` to product, `appVersion` to version, `appPublisher` to vendor, and `installPath`/`installDateTimeUtc` to the installed-from and installed-at fields. Rows are joined to devices on `deviceUid`. It is off by default because it is a second full pass over the account.
- The software pass requests the documented default sort (`deviceUid:asc,appId:asc`) explicitly and groups consecutive rows per device, carrying a partial group across page boundaries. Each device's applications are emitted once, as an enrichment record sharing the device's asset ID, so memory stays bounded to a single device rather than the whole account.
- With `active_only=true`, the device report is filtered by `agentStatus=A` but the software report has no such filter. The software pass therefore drops the groups whose device was not imported by the device walk, logging `skipped software for N devices excluded by active_only` -- otherwise inactive agents would import as orphan assets carrying only an id and a software list.
- `publicIp` is deliberately **not** attached to a network interface. It is the NAT egress address shared by every device behind one gateway, and adding it as an interface address would invite unrelated laptops to merge together. It is kept as the `absolute_public_ip` custom attribute instead.
- Absolute publishes no CPE for applications, so `Software.cpe23` is left unset rather than being populated with a guessed value.
- Authentication is JSON Web Signature request signing, not a bearer token. Each call builds a JOSE header carrying `kid`, `method`, `content-type`, `uri`, `query-string`, and `issuedAt` (epoch milliseconds), signs `{"data": {}}` with HS256 using the secret key, and POSTs the compact JWS as a `text/plain` body to `<host>/jws/validate`. The real method, path, and query string never appear in the request URL.
- Query-string values are percent-encoded with `%20` for spaces, matching Absolute's documented canonical form (`select=esn%2CdeviceName%2CagentStatus&sortBy=esn%3Adesc`). The opaque `nextPage` cursor is appended verbatim, because Absolute warns that modifying the query parameter in any way breaks pagination.
- Pagination follows `metadata.pagination.nextPage` until it is empty. The device report caps `pageSize` at 500 (default 10); the software report allows up to 10000 (default 100) but is held to the same configured page size. A cursor that does not advance stops the walk on the first repeat and logs `paging stopped after N pages (API returned the same cursor twice ...)` rather than re-fetching page one. The `max_pages` ceiling behind it is enforced by the platform's `pager()` guard, which fails the run with `pagination limit reached: "devices" ran N pages ...` rather than truncating silently -- the assets streamed before the stop survive. Absolute's envelope reports no row total, so the cursor-stall line says `total not reported` rather than inventing a denominator.
- Absolute enforces 20 requests per second per account across all endpoints. Transient failures (including 429) are retried three times with exponential backoff starting at two seconds, honoring `Retry-After` via the shared HTTP helper.
- Only symmetric (HS256) generated tokens are supported. Absolute also offers asymmetric ES256 tokens backed by an uploaded EC public key; those would need a private-key credential field and ES256 signing, which this script does not implement.
- Unverified assumption: the `jwt` module stamps a standard `"typ": "JWT"` parameter into the JOSE header, which Absolute's own examples omit. This is believed harmless because the Cortex XSOAR Absolute integration signs with PyJWT, which also emits `typ` by default, and runs against the production API. It has not been confirmed against a live tenant.
- Unverified assumption: `networkAdapters.ipV4Address` and `ipV6Address` are typed as single strings but documented as "the IPv4/IPv6 addresses" for the adapter, so values are split on commas, semicolons, and spaces before being handed to the network-interface helper. Whether Absolute ever returns more than one address per field has not been observed.
- Unverified assumption: `deviceUid` values are never recycled after a device is deleted, as noted in the identity record above.
- This integration was validated against local fixtures, not a live Absolute Secure Endpoint tenant. The fixture server decodes each JWS, verifies the HS256 signature against the shared secret, and rejects any request whose JOSE header claims are malformed, so the signing path is exercised end to end — but no request has been made to a real Absolute API host.

## Future

- **Custom field write-back (outbound).** `GET/PUT /v3/configurations/customfields/devices/{deviceUid}` reads and writes the user-defined device fields, and `GET /v3/configurations/customfields/definitions` lists the field definitions available on the account. Because this integration already resolves every asset to its `deviceUid`, an outbound script could push runZero context — asset criticality, owning site, discovered service exposure, or the runZero asset URL — back into Absolute so console operators and Reach scripts can act on it. This is non-destructive, idempotent, and the natural companion to the inbound import.
- **Security event ingestion.** `GET /v3/reporting/siem-events` returns account events over a `fromDateTimeUtc`/`toDateTimeUtc` window with its own `pageSize`/`nextPage` pagination (Absolute's own collector uses a 1000-record page). A scheduled integration could carry a high-water mark between runs and attach events to the originating device, giving runZero visibility into freeze actions, unenrollments, and agent tampering.
- **Endpoint coverage-gap reporting.** Absolute's firmware persistence makes it unusually authoritative for the question "does this laptop still exist?" — the agent survives reimaging and reports even from off-network devices. Diffing the Absolute inventory against runZero's own discovery separates two very different populations: devices Absolute still sees but runZero has not observed on any network (checked out, remote, or dormant), and devices runZero discovers that Absolute has never enrolled (agent coverage gaps). `GET /v3/reporting/devices/compliance` and the `agentStatus`, `lastConnectedDateTimeUtc`, and `unenrollmentDateTimeUtc` fields already carry everything needed to build that report.
- **Device actions are intentionally out of scope.** `/v3/actions/requests/freeze`, `/v3/actions/requests/unenroll`, `/v3/actions/requests/wipe`, and `/v3/actions/file-delete` exist and are reachable with the same signing scheme, but they are destructive: freezing a device locks the user out, and wipe and unenroll are irreversible. They would need a much tighter confirmation model than a scheduled sync — explicit per-device operator approval, a dry-run mode, and an audit trail — and should not be driven by an unattended integration. This script never calls them.

## API documentation

- Absolute Public API v3 reference (authentication, JWS construction, sorting, selecting, filtering, pagination, rate limits): <https://api.absolute.com/api-doc/doc.html>
- Machine-readable OpenAPI document backing that reference, used to verify endpoint paths, the `select` field lists, and response schemas: <https://api.absolute.com/api-doc/spec/openapi.json>
- Field descriptions referenced by the OpenAPI document, used to verify the `deviceUid` identity contract: <https://api.absolute.com/api-doc/strings.json>
- Working with Absolute APIs (token creation, permissions, expiry, regional hosts, OData filtering): <https://help.absolute.com/corporate/html5/ja-jp/Content/PDFs/EN/abt-api-working-with-absolute.pdf>
- OData query option reference, which Absolute's filtering syntax derives from: <https://www.odata.org/documentation>

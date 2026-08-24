# Custom Integration: Fleet (osquery)

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- Network access from the selected Explorer to the Fleet server.

## Fleet requirements

- A Fleet server (self-hosted or Fleet Cloud) reachable from the Explorer.
- A Fleet API-only user with at least the **Observer** role, or **Observer+** if you want software inventory. Global observers see every host; a team observer sees only that team's hosts.
- Software inventory requires `features.enable_software_inventory` to be on in the Fleet configuration (it is on by default).
- Listening services are optional and require an additional query to be configured on the Fleet server first. See the services step below.

## Steps

### Fleet configuration

1. Create an API-only user. With `fleetctl`:
   ```
   fleetctl user create --name "runZero" --email runzero@example.com --password '<password>' --global-role observer --api-only
   ```
   Or call [`POST /api/v1/fleet/users/api_only`](https://fleetdm.com/docs/rest-api/rest-api#create-api-only-user) as an admin. On success `fleetctl` prints `Success! The API token for your new user is: <token>` — **shown once**.

   `--global-role observer` is also the default when the flag is omitted, so the
   least-privilege user is what you get by default. The full role set is
   Observer, Observer+, Technician, Maintainer, Admin, and GitOps; Observer+,
   Technician, and GitOps are Fleet Premium only. A **global** Observer sees
   every host, while a team-scoped one sees only that team's hosts.
2. Retrieve the API token for that user, either from the create output above, from `fleetctl login`, or by calling [`POST /api/v1/fleet/login`](https://fleetdm.com/docs/rest-api/rest-api#log-in) with the user's email and password. Login is not available for SSO or MFA users; those retrieve a token from the UI at `/profile` via **Get API token**.
3. Decide how to authenticate:
   - Supply the **API token**. This is the normal choice. **An API-only user's token does not expire** — Fleet made these long-lived in 4.11.0, and the server's [`session_duration`](https://fleetdm.com/docs/configuration/fleet-server-configuration#session-duration) setting (default 5 days) governs *regular* user sessions, not API-only tokens. There is nothing to raise and nothing to rotate on a schedule.
   - Or supply the **email and password** and leave the API token blank, and the integration logs in to mint a fresh token on every run. This is the fallback for a token you cannot retrieve, and it costs one extra request per run.

   > The `api_token` parameter's built-in description still says tokens expire
   > after `session_duration` and advises using email and password for longer
   > schedules. That advice predates Fleet 4.11.0 and no longer applies to
   > API-only users. Prefer the token.
4. Optional, only if you want listening services. Add an additional query that reads the `listening_ports` osquery table, then note the name you gave it:
   ```
   curl -X PATCH https://fleet.example.com/api/v1/fleet/config \
     -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
     -d '{"features":{"enable_host_users":true,"enable_software_inventory":true,
          "additional_queries":{"listening_ports":
            "SELECT pid, port, protocol, family, address, path FROM listening_ports"}}}'
   ```
   Fleet runs additional queries alongside its own detail queries and stores the rows on each host under `additional.<query name>`. Hosts report the new data on their next detail refresh (hourly by default), or immediately if you call `POST /api/v1/fleet/hosts/:id/refetch`.

   The name you choose here is what goes in the `listening_ports_query`
   parameter. Fleet does **not** return additional-query results on the host list
   unless they are asked for by name — `GET /hosts` omits the `additional` object
   entirely when `additional_info_filters` is not set — which is exactly why this
   is a named parameter rather than a boolean. The integration passes the name
   through for you; the consequence to remember is that the name must match the
   key in `additional_queries` exactly, and a mismatch produces no services and no
   error.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Fleet (osquery)").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Fleet server URL** (`url`): base URL of the Fleet server, for example `https://fleet.example.com`. The `/api/v1/fleet/` path is appended automatically.
   - **Fleet user email** (`email`): optional; email of the API-only user. Only needed when no API token is supplied.
   - **API token** (`api_token`): the API token for the API-only user. Supply this or a password.
   - **Fleet user password** (`password`): optional; the API-only user's password, used to mint a token at the start of each run when no API token is supplied.
   - **Import software inventory** (`include_software`): optional; request `populate_software` on the host list (default: true).
   - **Import CVE findings** (`include_vulnerabilities`): optional; map the CVEs Fleet matched against installed software (default: false).
   - **Import label and team membership** (`include_labels`): optional; request `populate_labels` (default: true).
   - **Import policy results** (`include_policies`): optional; request `populate_policies` (default: true).
   - **Listening ports additional query name** (`listening_ports_query`): optional; the name of the Fleet additional query configured above. Leave blank to skip services.
   - **Fetch per-host detail** (`include_host_detail`): optional; one extra request per host for disk encryption and MDM detail (default: false).
   - **Per-host detail limit** (`detail_limit`): optional; cap on how many hosts are enriched with per-host detail (default: 500, 0 removes the cap).
   - **Hosts per page** (`page_size`): optional; hosts requested per page (default: 100).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Fleet.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:fleet-osquery`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real Fleet server returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename fleet-osquery/fleet-osquery.star \
  --kwargs url=https://fleet.example.com \
  --kwargs api_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ZmFrZQ.c2lnbmF0dXJl \
  --kwargs page_size=25 \
  --kwargs include_software=false \
  --kwargs include_policies=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/fleet-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

`api_token` and `password` are alternatives — the `CONFIG` block requires at
least one of them. To exercise the login path instead of a pre-minted token,
supply the email and password and leave the token out:

```bash
runzero script --filename fleet-osquery/fleet-osquery.star \
  --kwargs url=https://fleet.example.com \
  --kwargs email=runzero@example.com \
  --kwargs password=hunter2-not-a-real-password \
  --kwargs page_size=25
```

Turning `include_software` off for a first run is worth doing: Fleet documents
`populate_software` as expensive, and it is the parameter most likely to make a
smoke test time out on a large estate. `get_bool` accepts `true/false`, `1/0`,
`yes/no`, and `on/off`.

**One `--kwargs` caveat, for the password specifically.** A comma in a value is
harmless on its own — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks is a value
carrying **both** an `=` and a comma: the flag parses an argument containing a
second `=` as a CSV record, so `password=a=b,c=d` yields `password=a=b` plus a
fabricated `c=d`. Wrap the whole argument in double quotes to pass such a value
as one field — `--kwargs '"password=a=b,c=d"'` — and double any quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename fleet-osquery/fleet-osquery.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real host
row, so it tells you nothing about field mapping.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://fleet.example.com,api_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma. `listening_ports_query` is the one to watch: it
is the *name* of a Fleet additional query, so keep the name comma-free. The SQL
itself lives on the Fleet server and never travels through this flag.

The recorded fixtures run without a Fleet server:

```bash
python3 tests/run.py fleet-osquery
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: the physical machine, VM, or mobile device running an osquery or fleetd agent, as tracked by one row of Fleet's `hosts` table.
- Source ID field: `hosts[].id`
- Documentation evidence: [Get host](https://fleetdm.com/docs/rest-api/rest-api#get-host) documents `id` as the required path parameter that addresses a single host, and every host list and detail response carries it. Fleet's schema declares it `` `id` int unsigned NOT NULL AUTO_INCREMENT ... PRIMARY KEY (`id`) `` ([`server/datastore/mysql/schema.sql`](https://github.com/fleetdm/fleet/blob/main/server/datastore/mysql/schema.sql)).
- Uniqueness scope: one Fleet server. The value is a per-server auto-increment, so it must be namespaced by the server before it is used across tenants.
- Cardinality: one `hosts` row per agent installation. Fleet enforces this with `UNIQUE KEY idx_osquery_host_id (osquery_host_id)`, so a machine that keeps its osquery host identifier keeps its `id` across check-ins, detail refreshes, and agent upgrades.
- Stability: survives rename, reboot, IP/MAC change, OS upgrade, osquery/fleetd upgrade, team reassignment, and MDM enrollment changes. It is replaced only when the host row itself is deleted (manual delete, batch delete, or host expiry) and the agent later re-enrolls, or when the machine is re-imaged and reports a new osquery host identifier.
- Reuse behavior: no. `id` is a MySQL `AUTO_INCREMENT` column, which does not hand a deleted row's value to a different host.
- Presence: always present, on both list and detail responses. Records without it are not expected and are skipped rather than invented.
- Final runZero ID: `fleet-osquery:<fleet-server-host>:<hosts[].id>`
- Missing-ID behavior: skip the record and print the hostname only.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. Fleet publishes exactly one address (`primary_ip`) and one MAC (`primary_mac`) per host, both re-derived from osquery on every detail refresh, so a laptop moving between networks changes both between polls. The Fleet id stays authoritative for merging while that churn is prevented from disqualifying a merge against an existing runZero asset.
- Verdict: scoped authoritative.

### Why `id` and not `uuid`

`uuid` is the more tempting choice because it tracks the machine rather than the server row, but it is not safe as a foreign id here:

- Fleet indexes it non-uniquely — `` KEY `idx_hosts_uuid` (`uuid`) `` — and declares it `NOT NULL DEFAULT ''`. Fleet therefore permits several hosts to share one `uuid`, and permits it to be empty. Cloned VMs and golden-image VDI pools routinely report an identical hardware UUID, and using it as the foreign id would silently collapse those distinct machines onto a single runZero asset.
- The API documentation adds a second failure mode: "For iOS, iPadOS, and Android hosts with `mdm.enrollment_status` set to 'On (personal)', `hardware_serial` and `uuid` represent a temporary enrollment ID" ([Get host](https://fleetdm.com/docs/rest-api/rest-api#get-host)). For those hosts `uuid` is neither hardware-derived nor stable.

The trade is deliberate. Keying on `id` means a host that is deleted from Fleet and re-enrolls arrives as a new foreign id; runZero then merges it back onto the existing asset on hostname, MAC, or IP, which is the ordinary recoverable case. Keying on `uuid` would mean two real machines silently becoming one asset, which is neither visible nor recoverable. `uuid` is imported as the `fleet_uuid` custom attribute so it stays searchable.

### Notes

- Assets come from `GET /api/v1/fleet/hosts`, paged with `page` (numbered from **zero**) and `per_page`, ordered by `id` ascending. The response envelope is `{"hosts": [...]}` and carries no total or cursor, so paging stops on the first short or empty page. Each asset is streamed with `report_asset` as it is built, so the full inventory is never held in memory.
- Software, policies, labels, and listening-port rows are all requested on that same host-list call via `populate_software`, `populate_policies`, `populate_labels`, and `additional_info_filters`. There is no per-host request for any of them, so the common configuration issues exactly one request per page.
- Software comes from `hosts[].software[]`: `name` to `product`, `version` to `version`, first `installed_paths` entry to `installedFrom`, and `source`, `bundle_identifier`, `last_opened_at`, and the CPE to custom attributes. This is the flat, one-row-per-version shape. The separate `GET /api/v1/fleet/hosts/:id/software` endpoint returns a different, title-grouped shape with nested `installed_versions[]` and is deliberately not used.
- Fleet's `generated_cpe` is the CPE 2.3 formatted string (`cpe:2.3:a:gnu:glibc:2.12:*:*:*:*:*:*:*`). runZero validates `Software.cpe23` against `^cpe:/a:.*`, the CPE 2.2 URI binding, which the 2.3 form does not match. The prefix is therefore checked at runtime: only a genuine `cpe:/a:` value is assigned to `cpe23`, and everything else is kept as the `fleet_cpe` custom attribute. The 2.3 string still yields a real vendor token, which is used for `Software.vendor` — Fleet exposes no other vendor for an installed package.
- Vulnerabilities come from `hosts[].software[].vulnerabilities[]` and are opt-in. `cve` is upper-cased and then checked against `^CVE-[0-9]{4}-[0-9]{4,19}$`; anything that still does not match is dropped rather than failing the whole record. `cvss_score` is recorded as `cvss3BaseScore` because Fleet documents its own `min_cvss_score` filter against the "CVSS version 3.x base score". `cisa_known_exploit` becomes `exploitable`, and `resolved_in_version` becomes the solution text. Fleet does not associate a CVE with a port, so no service fields are set on a finding.
- CVSS scores, EPSS probabilities, exploit flags, CVE descriptions, and publication dates are **Fleet Premium only**. On Fleet Free each finding still carries its CVE and details link, so findings import with no score and severity rank 0. That is a tier limitation, not a failure.
- Findings are bucketed by severity before the 99-per-asset child cap is applied, so the most severe survive when a host has more than 99 CVEs.
- Services are opt-in and require the `listening_ports` additional query described above. `listening_ports.protocol` is the IANA IP protocol number, not a name, so it is mapped through 6/17/132. A wildcard bind (`0.0.0.0`, `::`) is rewritten to the host's `primary_ip`; a loopback bind, a unix socket (port 0), and an unmapped protocol are dropped.
- Per-host detail (`GET /api/v1/fleet/hosts/:id?exclude_software=true`) is off by default because it is one request per host. It adds `disk_encryption_enabled`, the full `mdm` object including profile and disk-encryption status, `orbit_version`, and `scripts_enabled`. When enabled it is capped by `detail_limit`, and the number of hosts skipped past the cap is printed at the end of the run.
- Loopback, unspecified, and link-local addresses are filtered out before any network interface is built, and an all-zero MAC is dropped. `public_ip` is **never** used as an interface address: it is the NAT egress address that every host behind one office router shares. It is kept as the `fleet_public_ip` custom attribute.
- Only user-created (`label_type: "regular"`) labels become `label:` tags. Fleet's builtin labels — "All Hosts", "macOS", "All Linux" — are membership bookkeeping and would appear on every asset, so they are recorded in the `fleet_labels` attribute instead.
- `os_version` is a single combined string that Fleet assembles itself. Non-Windows hosts get `"<name> <version>"` ("macOS 15.2", "Ubuntu 22.04.5 LTS"), so the split is made at the first dotted numeric token. Windows hosts get `"<name> <display version> <build>"` ("Windows Server 2022 Datacenter 21H2 10.0.20348.2402"), and Fleet's own host filters document the OS name as everything except the trailing build number, so the last token is taken as the version there.
- Transient failures (408/425/429/500/502/503/504) are retried with exponential backoff by the shared HTTP helper, which honors Fleet's `retry-after` header on the rate-limited login endpoint. The login call narrows retries to 429 and 503 so a retried login cannot mint duplicate sessions.
- Fleet is self-hosted, so servers of many ages are in the field. If a server rejects the request as invalid (400/404/422), the page is retried once with the older boolean `populate_software=true` form so software import survives, and only a second rejection drops the optional `populate_*` and `additional_info_filters` parameters entirely; the run then continues with basic inventory. A 401/403 or a transient status is reported instead, never silently downgraded.
- Fleet Premium calls a team a "fleet" in current releases and returns both `team_name` and `fleet_name`; both spellings are read, and the value becomes a `team:` tag. `GET /api/v1/fleet/teams` returns **402 Payment Required** on Fleet Free, which is why team names are read off the host record rather than from the teams endpoint.
- Local OS user accounts (`populate_users`) and end-user email addresses (`device_mapping`) are deliberately not requested. They are personal data and add nothing to asset identification.
- Unverified assumptions, stated plainly:
  - Policy result mapping was exercised against fixtures only. The live server used for validation had no policies defined, so `populate_policies=true` was accepted but returned an empty list; the shape of a populated `policies[]` entry is taken from the API documentation.
  - CVE mapping was exercised against fixtures only. The live server had no vulnerability database downloaded, so every `generated_cpe` was empty and no CVE was matched. Premium-only fields (CVSS, EPSS, CISA exploit flag) could not be observed at all.
  - MDM, disk encryption, and Windows OS-version splitting were exercised against fixtures only; the live host was a Linux VM with no MDM.
- This integration was validated against **a live Fleet 4.90.1 server with a real enrolled osqueryd 5.17.0 host**, in addition to local fixtures. The live run confirmed the `{"hosts": [...]}` envelope, zero-based paging, that `populate_software` / `populate_labels` / `additional_info_filters` work on the host list endpoint, the `additional.<query name>` row shape, and end-to-end import of 102 deb packages and 11 listening services onto one asset.

## Future

- **Live queries as on-demand enrichment.** `POST /api/v1/fleet/hosts/:id/query` and `POST /api/v1/fleet/hosts/identifier/:identifier/query` run arbitrary osquery SQL against one host and return rows synchronously, which makes every osquery table reachable from runZero: `certificates`, `chrome_extensions`, `usb_devices`, `docker_containers`, `windows_security_products`, `disk_encryption`. `POST /api/v1/fleet/reports/:id/run` does the same for a saved report across many hosts. This suits a lookup-style integration triggered against a single asset far better than a scheduled import: the call only works while the host is online, and it times out after `FLEET_LIVE_QUERY_REST_PERIOD` (25 seconds by default), so it cannot be fanned out across a large estate. Fleet's scheduled `additional_queries` mechanism, which this integration already uses for listening ports, is the bulk equivalent and could carry any other table the same way.
- **Policy and compliance state as a runZero signal.** `GET /api/v1/fleet/global/policies` and `GET /api/v1/fleet/hosts?policy_id=&policy_response=failing` enumerate Fleet's compliance checks and the hosts failing them. This integration already imports per-host pass/fail counts; a dedicated integration could import each policy as a first-class finding with its query text and resolution steps, which is closer to how an auditor reads them. `GET /api/v1/fleet/policies/count` and the `critical` flag would let runZero rank them.
- **MDM commands as an outbound surface.** `POST /api/v1/fleet/commands/run` enqueues a raw Apple or Windows MDM command against a list of host UUIDs, and `POST /api/v1/fleet/scripts/run` runs a saved script on a host. A runZero outbound integration could use these to act on discovery results — reinstall a missing agent, collect a certificate inventory, force a detail refetch. **Anything destructive must stay out of scope or behind an explicit confirmation parameter:** `POST /api/v1/fleet/hosts/:id/wipe` erases the device, `POST /api/v1/fleet/hosts/:id/lock` locks a user out of it, and `DELETE /api/v1/fleet/hosts/:id` removes the host record. None of those should ever be reachable from an automated runZero task.
- **Agent coverage gap reporting.** This is the strongest outbound case, and it runs in the opposite direction from this integration. runZero discovers assets by scanning the network, including assets that have no agent at all; Fleet only knows about hosts that enrolled. Comparing the two sets — runZero assets with no matching `fleet-osquery` foreign id — produces the list of machines missing osquery coverage, which is exactly the blind spot a Fleet operator cannot see from inside Fleet. `GET /api/v1/fleet/hosts/count` and `GET /api/v1/fleet/hosts?query=<serial|hostname|ipv4>` (documented as searching `hostname`, `hardware_serial`, `uuid`, and `ipv4`) are enough to confirm a candidate is genuinely absent before reporting it as a gap.
- **Activity feed as event ingestion.** `GET /api/v1/fleet/activities` is Fleet's audit log — host enrollment and deletion, team changes, MDM turned on or off, scripts run, software installed. It is paged and ordered by any column of the `activities` table, so it supports incremental polling and would let runZero react to enrollment churn rather than rediscovering it on the next full import.
- **Software installation as remediation.** `POST /api/v1/fleet/hosts/:id/software/:software_title_id/install` and the Fleet-maintained apps catalog (`GET /api/v1/fleet/software/fleet_maintained_apps`) can push a package to a host. A runZero workflow that finds an outdated or vulnerable version could hand the upgrade to Fleet rather than to a separate patch tool. Both endpoints are Fleet Premium only, so this would have to degrade cleanly on Fleet Free.
- **What the API does not support.** There is no webhook or push subscription for host inventory changes, so any freshness beyond the poll interval has to come from polling `activities`. There is also no bulk endpoint that returns listening ports, certificates, or any other arbitrary osquery table across all hosts in one call — that data is only reachable per host through live queries, or in bulk through `additional_queries`, which requires a server-side configuration change and is limited to what the operator configured in advance.

## API documentation

- Fleet REST API reference: https://fleetdm.com/docs/rest-api/rest-api
- Source of the same reference, used for exact field names: https://github.com/fleetdm/fleet/blob/main/docs/REST%20API/rest-api.md
- List hosts, including `populate_software`, `populate_policies`, `populate_labels`, and `additional_info_filters`: https://fleetdm.com/docs/rest-api/rest-api#list-hosts
- Get host, including the personal-enrollment caveat on `uuid` and `hardware_serial`: https://fleetdm.com/docs/rest-api/rest-api#get-host
- About host timestamps (`created_at`, `seen_time`, `detail_updated_at`): https://fleetdm.com/docs/rest-api/rest-api#about-host-timestamps
- Log in and API token retrieval: https://fleetdm.com/docs/rest-api/rest-api#log-in
- Create API-only user: https://fleetdm.com/docs/rest-api/rest-api#create-api-only-user
- Update configuration, for `features.additional_queries`: https://fleetdm.com/docs/rest-api/rest-api#update-configuration
- Session duration and token expiry: https://fleetdm.com/docs/configuration/fleet-server-configuration#session-duration
- Hosts table schema, for the identity decision: https://github.com/fleetdm/fleet/blob/main/server/datastore/mysql/schema.sql
- OS version ingestion, for the `os_version` string format: https://github.com/fleetdm/fleet/blob/main/server/service/osquery_utils/queries.go
- osquery `listening_ports` schema: https://fleetdm.com/tables/listening_ports
- osquery table schema reference: https://osquery.io/schema/

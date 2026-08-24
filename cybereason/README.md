# Custom Integration: Cybereason

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cybereason requirements

- A Cybereason console user account with a role that grants read access to **System** > **Sensors**. The Analyst L1 role is enough for the sensor inventory; the optional connection enrichment additionally needs access to **Investigation**.
- The account must not have two-factor authentication enabled. Cybereason authenticates API clients with the same HTML form login the console uses, and that form has no second-factor step an unattended script can complete.
- The tenant URL including its port, for example `https://acme.cybereason.net:443`. Some on-premises deployments publish the console on 8443 instead.
- Network reachability from the Explorer to the console. Cybereason SaaS tenants may restrict API access to allow-listed source addresses, in which case the Explorer's public egress address has to be on that list.

## Steps

### Cybereason configuration

1. Sign in to the Cybereason console as a user who can manage users (**System** > **Users**).
2. Create a dedicated service account, or choose an existing account, and give it a role with read access to **System** > **Sensors**. Add **Investigation** access only if you plan to enable connection enrichment.
3. Confirm that two-factor authentication is **not** enabled for that account.
4. Note the console URL and port exactly as you browse to it. That is the value the integration needs.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Cybereason").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Cybereason URL** (`url`): the console base URL including the port, for example `https://acme.cybereason.net:443`.
   - **Username** (`username`): the console user, normally an email address.
   - **Password** (`password`): the password for that user.
   - **Import inbound network connections as services** (`import_connections`): optional; run one investigation graph query per sensor and record the ports the endpoint accepted connections on (default: false).
   - **Connection enrichment limit** (`connection_limit`): optional; maximum sensors to query for connections. Sensors past the limit are still imported, without services. 0 removes the cap (default: 500).
   - **Sensors per page** (`page_size`): optional; sensor records requested per call (default: 200).
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
runzero script --filename cybereason/cybereason.star \
  --kwargs url=https://acme.cybereason.net:443 \
  --kwargs username=runzero-svc@example.com \
  --kwargs password=NotTheRealPassword1 \
  --kwargs import_connections=false \
  --kwargs page_size=50 \
  --output ./cybereason-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

**A bad password does not fail at login.** Cybereason authenticates with the same HTML form
login the console uses, and that form answers with a redirect and a `JSESSIONID` cookie
whether or not the credentials were accepted. A command-line run with a wrong password will
therefore log a successful-looking login and then fail on the first data call, reported as
`authentication rejected, check the username and password`. Read past the login line before
concluding the credential is good. The session itself is treated as good for 28000 seconds
and is refreshed proactively five minutes before that, so a long import does not need
babysitting.

Leave `import_connections` off for a first run. It issues one investigation-graph query per
sensor, which is by far the most expensive thing the integration does; `connection_limit`
caps it once you do turn it on.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename cybereason/cybereason.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Cybereason accepts the credential or that any sensor is parsed.

The recorded API shapes — including the redirect-based login, a mid-run session expiry, and
the connection-graph response — are exercised by the fixture suite:

```bash
python3 tests/run.py cybereason
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat cybereason/cybereason.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://acme.cybereason.net:443,username=runzero-svc@example.com,password=<password>' \
  --output ./cybereason-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Cybereason.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:cybereason`.

## Asset identity

- Target entity: an endpoint carrying a Cybereason sensor — a workstation, laptop, or server enrolled in the tenant.
- Source ID field: `sensorId`
- Documentation evidence: Cybereason's API reference is published only behind the Cybereason Nest customer portal and is not publicly readable, so the contract used here is the Cortex XSOAR Cybereason integration (`Packs/Cybereason/Integrations/Cybereason/Cybereason.py`) together with its captured API responses. That client uses `sensorId` as the `outputs_key_field` for every machine-details result, and reads it out of `POST /rest/sensors/query` exactly as this integration does. A captured response shows the value in full: `5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F`.
- Uniqueness scope: the tenant. The captured value is a composite of a server-side registration identifier and the sensor's `pylumId`, so it is already qualified within the tenant, but nothing guarantees it against a second tenant.
- Cardinality: one row per sensor in `POST /rest/sensors/query`. The optional connection query returns many graph elements per machine; they are folded into services on the one asset rather than becoming assets of their own.
- Stability: survives rename, DHCP address change, reboot, OS upgrade, and sensor upgrade. It does **not** survive a sensor uninstall and reinstall, which registers a new sensor and therefore a new `pylumId` and a new `sensorId`. The leading component is a server-side identifier, so a tenant migration or a rebalance across servers in a multi-server collective would also change it.
- Reuse behavior: not documented. The value embeds a per-registration identifier, so reassignment to a different endpoint is implausible, but this is inference rather than a published contract.
- Presence: returned on every sensor in every captured response. Any record arriving without it is skipped.
- Final runZero ID: `cybereason:<tenant-hostname>:<sensorId>` — for example `cybereason:acme.cybereason.net:5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F`.
- Missing-ID behavior: skip the record and log only its opaque graph `guid`; no identifier is ever synthesized.
- Match behavior (set once in `CONFIG`): `no-ip-break`
- Verdict: scoped authoritative — authoritative for a sensor installation within one tenant, not for the physical machine across a reinstall.

The namespace is the configured tenant hostname rather than the per-record `serverId`, because it is known from configuration before any record is parsed and therefore can never go missing mid-import. `serverId`, `serverName`, `siteId`, and `collectiveUuid` are preserved as custom attributes so a multi-server collective stays visible.

`guid` and `pylumId` were both considered and are kept as custom attributes rather than used as the identity. `guid` is the investigation graph's element id and is the right join key for malops, processes, and connections, but a captured response shows it is itself server-scoped: two different machines on one server carry `-1826875736.1198775089551518743` and `-1845090846.1198775089551518743`, sharing the trailing component, and a machine on a different server carries a different trailing component. `pylumId` is the most portable of the three, but it is not the key of the endpoint being imported and it embeds the machine name captured at install time. `sensorId` is the identifier `POST /rest/sensors/query` is keyed on and the one every `/rest/sensors/*` operation accepts, so it is the field whose contract is clearest.

### Why `matchBehavior` is `no-ip-break` and not the usual preset

**Cybereason publishes no MAC address field on a sensor record.** `POST /rest/sensors/query` returns no MAC field in any captured response. A MAC is recovered from `pylumId` where the record's layout can be re-confirmed (see Notes), but it is derived rather than published and is not available on every record, so correlation still rests principally on hostname and a single internal IP address. That changes the calculus for every flag:

- **`no-ip-break` is on.** `internalIpAddress` is one last-known address on a fleet that is mostly roaming endpoints. A stale DHCP address is not evidence of a different machine, and letting it veto a merge would fragment assets on every poll.
- **`no-mac-break` is deliberately not listed**, so a MAC mismatch still breaks a merge. The MAC this source contributes is derived from an undocumented `pylumId` format rather than published as a field, and it is an install-time value that a NIC replacement leaves stale. If either the derivation or the value is ever wrong, the right outcome is a separate asset that an operator can see and reconcile, not a confident merge onto the wrong machine.
- **`name-break` is deliberately left on**, which is where this integration departs from `absolute/`. Absolute can afford `no-name-break` because `deviceUid` is firmware-persistent and provably one row per physical device; there is no failure mode that hands one id to many machines. Cybereason's `sensorId` embeds a `pylumId` assigned when the sensor was installed, so a golden image built with the sensor already installed clones one `pylumId` — and therefore one `sensorId` — onto every machine deployed from it. With no MAC available, the hostname is the *only* remaining structural signal that would notice that, and a collapsed fleet (many real machines silently folded onto one asset) is far worse than the duplicate an occasional rename would produce.
- **`id-break` is left on**, which is where this integration departs from `cisco-secure-endpoint/`. Cisco relaxes `id-break` because it documents `connector_guid` changing on a connector reinstall, and it can afford to because it supplies MACs and hostnames as fallback merge signals. Here, relaxing `id-break` on top of an already-relaxed `ip-break` would leave the hostname alone deciding merges for a reinstalled sensor. The consequence is stated plainly below.

**Known behavior on sensor reinstall:** uninstalling and reinstalling the Cybereason sensor on an unchanged machine produces a new `sensorId` and therefore a new runZero foreign id. Because `id-break` is left on, the new record will not merge onto the existing asset and a second asset appears. This is a deliberate trade: it is visible and correctable, whereas the alternative risks merging genuinely different machines that a duplicated golden-image id or a stale hostname made look alike. If your estate has no golden images carrying a pre-installed sensor, adding `no-id-break` to `matchBehavior` is a reasonable local change.

### Notes

- Assets come from `POST /rest/sensors/query`, paged with a plain `{"filters": [], "limit": N, "offset": N}` body. The response envelope carries `sensors`, `totalResults`, and `hasMoreResults`; paging stops on `hasMoreResults: false`, on a short page, or on an empty page. A tenant that ignored the offset and repeated the same first record would be caught by a repeated-leading-id check rather than looping. Cybereason defaults to a limit of 50 when none is sent; the maximum it accepts is not documented and 200 is used by default.
- Imported fields: hostnames (`machineName` and `fqdn`, de-duplicated case-insensitively), `domain` derived from `fqdn` when it is genuinely qualified, one network interface built from `internalIpAddress` and, where it can be recovered, the MAC derived from `pylumId`, `os` and `osVersion` from `osType` and `osVersionType`, `model` from `deviceModel`, `deviceType` from `deviceType`, first-seen from `firstSeenTime`, and last-seen from `lastPylumUpdateTimestampMs` falling back to `lastPylumInfoMsgUpdateTime`.
- Tags: `cybereason`, plus `site:`, `group:`, `policy:`, `status:`, and `serial:` values, `isolated` for an isolated sensor, `outdated-sensor` for one flagged as out of date, and a `tag:` entry per `customTags` value. Roughly fifty sensor fields are carried through as `cybereason_*` custom attributes.
- **`externalIpAddress` is deliberately not attached to a network interface.** It is the NAT egress address shared by every endpoint behind one office gateway, and importing it as an interface address would invite unrelated laptops to merge onto a single asset. `serverIp` and `privateServerIp` are excluded for a different reason: they are addresses of the *Cybereason server* the sensor reports to, not of the endpoint, so every sensor on one server would otherwise claim the same address. All three are kept as custom attributes.
- Loopback, unspecified, and link-local addresses (`127.0.0.0/8`, `::1`, `0.0.0.0`, `169.254.0.0/16`, `fe80::/10`) are filtered out of `internalIpAddress` before an interface is built, for the same estate-merging reason. A sensor whose only address is one of those is imported with no network interface at all.
- `fqdn` is frequently the short name repeated rather than a qualified name — that is what the captured response shows — so the two name fields collapse to a single hostname more often than not, and `domain` is only set when `fqdn` actually contains a dot.
- **Timestamps are epoch milliseconds** and Cybereason writes `0` for "never". They are converted and then **clamped to the current time**: runZero rejects an `ImportAsset` whose first- or last-seen time is in the future by failing the whole record, so an unclamped value from a clock-skewed tenant would silently drop assets rather than drop a field. The raw millisecond values are kept as custom attributes.
- `osVersionType` is a release family (`Windows_10`, `Windows_Server_2019`, `macOS_13`), not a build number. It becomes the `os` value with underscores turned into spaces, and `osVersion` is only set when what remains after trimming the platform name is numeric — so `Windows_10` yields an `osVersion` of `10` while `Windows_Server_2019` yields none rather than the nonsense string `Server 2019`. Cybereason publishes no OS build number.
- `deviceType` is `null` on every sensor in the only captured response available, so its value set is unverified. Only spellings whose meaning is unambiguous are mapped to a runZero device type; anything else leaves `deviceType` unset and survives as `cybereason_device_type`, rather than being guessed into a type that runZero search would then treat as authoritative.
- **There is no installed-software inventory and there are no CVE vulnerabilities in this API.** Cybereason is a behavioral EDR: it reports Malops (malicious operation detections), not a package list and not a CVE feed. No `Software` or `Vulnerability` records are produced. The sensor's own component versions (`version`, `avDbVersion`, `consoleVersion`) are agent metadata and are recorded as custom attributes rather than dressed up as installed software.
- Services are **off by default** and are only emitted under a narrow condition. When `import_connections` is enabled, one `POST /rest/visualsearch/query/simple` graph query is issued per sensor, requesting `Connection` elements joined to the machine through the `ownerMachine` connection feature. A Cybereason `Connection` describes a conversation, not a listening socket, and `serverAddress`/`serverPort` name the server side of it — which for an outbound connection is the *remote peer*. Recording those would attach other hosts' ports to this asset. A `Service` is therefore only produced when `direction` is `INCOMING` **and** `serverAddress` matches this endpoint's own reported address; every other element is counted and discarded, and the counts are logged.
- Cybereason publishes no transport protocol on a connection, so services are recorded as `tcp` with the custom attribute `cybereason_transport_source: assumed`. A UDP listener such as NetBIOS will be reported as tcp. This is the main accuracy limitation of the connection pass.
- The connection pass is one request per sensor (N+1) and is capped by `connection_limit`. Sensors past the cap are imported normally, without services, and the number skipped is logged. A failed graph query for one sensor is logged and treated as no connections rather than ending the run.
- **Authentication is a form login, not a token, and the redirect handling matters.** `POST /login.html` with `Content-Type: application/x-www-form-urlencoded` and a `username`/`password` body answers with a redirect, and the `JSESSIONID` cookie is set on that redirect rather than on a final body. The runZero HTTP client follows redirects and carries no cookie jar, so reading `Set-Cookie` off the raw response returns the **unauthenticated** cookie that the login page sets on the last hop — this was confirmed empirically against a fixture, not assumed. The login therefore runs on a `requests.Session`, which has a real cookie jar, follows the chain with the cookie attached, and ends up holding the authenticated session. Every later call replays it as a plain `Cookie: JSESSIONID=<id>` header on `post_json`.
- Sessions are refreshed proactively at 28000 seconds minus a five-minute margin, matching the lifetime Cybereason's own clients assume, and a mid-run expiry is retried once after a fresh login. The expiry is detected differently from Cybereason's reference client: that client sniffs whether a successful response's *final URL* contains "login", but the runZero response object exposes no final URL. Instead, an expired session is recognized by what it actually produces — the login page returned with a `200` and an HTML body, which surfaces as a JSON decode failure on a 200 — together with `401` and `403`. This is more robust than the URL sniff and is exercised by a fixture case.
- A wrong password still yields a `JSESSIONID`, because the form login answers with a redirect whether or not the credentials were accepted. Bad credentials therefore only surface on the first data call, where they are reported as `authentication rejected, check the username and password` rather than as the raw decode error.
- **The login request cannot carry the full TLS configuration.** A `requests.Session` accepts only `insecure_skip_verify`, so the `Disable TLS validation` option is honored on the login hop but a custom CA certificate, a client certificate, or a certificate thumbprint pin configured on the integration is **not** applied to it. Those options are applied to every subsequent data request. A tenant behind a private CA will need `Disable TLS validation`, or the login will fail. The login also gets a single attempt with no retry budget, because retries are a feature of `get_json`/`post_json` and are not available on a session request; a transient failure at login aborts the run cleanly and the next scheduled task retries it.
- Data requests use the built-in retry budget (four attempts with exponential backoff, honoring `Retry-After`), so a rate-limited or briefly unavailable tenant recovers on its own. Cybereason does not publish a request-rate limit.
- **A MAC address is recovered from `pylumId`.** Cybereason publishes no MAC field, but `pylumId` is built as `PYLUMCLIENT_<realm>_<machine name>_<twelve hex digits>` and the trailing token is the endpoint's MAC. Two independent captured values support this and neither is a coincidence of shape: `PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F` yields `08:00:27:3a:dc:2f`, whose OUI `08:00:27` is VirtualBox's — matching the virtual machine the fixture was captured from — and `PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5` yields `12:3c:c9:9c:a7:e5`, which has the locally administered bit set, exactly as AWS assigns EC2 interfaces, on a record whose hostname `EC2AMAZ-4CTUN1V` is an EC2 Windows instance.

  Because the format is undocumented, the token is not trusted on shape alone. The field layout is re-confirmed against each record before the MAC is read: the component immediately before the token must be that machine's own name (`machineName` or the leading label of `fqdn`, compared case-insensitively). The captured record pairs `..._DESKTOP-VG9KE2U_0800273ADC2F` with a `machineName` of `desktop-vg9ke2u`, which is what makes the check meaningful. A `pylumId` variant this integration does not understand therefore fails the layout check and contributes no MAC, rather than yielding a plausible-looking wrong one — a wrongly derived MAC merges unrelated assets, which is far worse than no MAC at all. The token must then be twelve hexadecimal digits forming a unicast, non-zero address; multicast and all-zero tokens are rejected.

  Locally administered addresses are **kept**, which is the reason the AWS example above imports a MAC at all. Rejecting them — for instance by requiring a registered vendor OUI — would discard the MAC for every cloud-hosted endpoint and for anything using randomized addressing, since those have no vendor by definition.

  One consequence to expect when reading the results: runZero's `network_interface` deliberately clears the locally administered bit so that MACs match across sources, so the EC2 address above is stored as `10:3c:c9:9c:a7:e5` rather than `12:3c:c9:9c:a7:e5`. Every source is treated the same way, so correlation is unaffected, but the stored value differs by one bit from what the AWS console shows. The recovered address is therefore also kept verbatim as the `cybereason_pylum_mac` custom attribute, and `pylumId` itself is retained in full.

  This remains an **install-time** MAC: it is captured when the sensor registers, so a NIC replacement or a change of primary adapter leaves it stale, and on a multi-homed machine it names only one adapter. `mac-break` is left on partly for this reason — see Asset identity.
- Unverified assumption: the maximum `limit` accepted by `POST /rest/sensors/query` is undocumented. The default of 200 is well above Cybereason's own default of 50 and below the configurable ceiling of 1000.
- Unverified assumption: `customTags` is `null` on every sensor in the captured response, so whether Cybereason publishes a list or a delimited string is unconfirmed. Both shapes are handled.
- Unverified assumption: the `deviceType` value set, as described above.
- Unverified assumption: `sensorId` values are never reassigned to a different endpoint after a sensor is deleted.
- This integration was validated against local fixtures, not a live Cybereason tenant. The fixture server reproduces the redirect-based form login with an unauthenticated decoy cookie on the login page, multi-page sensor paging, a mid-run session expiry, `401`, `429`, malformed records, loopback-only and link-local-only endpoints, future timestamps, and the connection graph response shape — but no request has been made to a real Cybereason console.

## Future

- **Malop and detection ingestion as an event feed.** `POST /rest/crimes/unified` and `POST /rest/mmng/v2/malops` return Malops — Cybereason's malicious operation detections — and `/rest/detection/inbox` and `/rest/detection/details` return the newer detection inbox. A captured Malop carries `guid`, `malopDetectionType`, `severity`, `priority`, `status`, `creationTime`, and an `affectedMachines`/`machines` list whose entries hold the machine `guid` this integration already stores as a custom attribute, so the join back to a runZero asset is straightforward. These are **behavioral detections, not CVEs**: a Malop says "this host ran something that looks like credential theft", not "this host has an unpatched library". They belong in an alert or event feed keyed to a time window with a high-water mark between runs, not in `Vulnerability` records, and modelling them as vulnerabilities would put uncorrelatable identifiers into a field that runZero's vulnerability reporting expects to hold CVEs.
- **Endpoint isolation as an outbound integration — flagged as disruptive.** `POST /rest/monitor/global/commands/isolate` and `/rest/monitor/global/commands/un-isolate` take a `pylumId` and cut the endpoint off from the network. This is reachable with the same session and would be a natural response to a runZero finding, but it is **not suitable for a scheduled sync**: isolating a machine locks its user out of everything, and an automated rule that misfires takes out a fleet. It would need explicit per-device operator approval, a dry-run mode, and an audit trail before it could be considered. `/rest/sensors/action/archive` and the remediation endpoints (`/rest/remediate`) carry the same warning.
- **The investigation graph as a general enrichment surface.** `POST /rest/visualsearch/query/simple` is a query language over the whole sensor telemetry graph, not just connections: `requestedType` also accepts `Process`, `File`, `User`, `Domain`, and `MachineRuntime`, each joined to a machine through a connection feature the same way this integration joins connections through `ownerMachine`. That would allow running-process inventories, file-hash reporting, and logged-on-user attribution. The caveat is structural and does not go away: the query is per-machine, so every one of these is an N+1 pass over the fleet, and the graph reflects *observed activity over a retention window* rather than current state. Any such pass needs the same opt-in, cap, and skip-count treatment the connection pass has here.
- **Confirming the `pylumId` MAC derivation against a live tenant.** The derivation described in Notes is supported by two captured samples and guarded by a per-record layout check, but it has not been exercised against a real tenant. The work worth doing is a sweep across platforms — Windows, macOS, Linux — and across machines with multiple NICs, a `pylumId` from a sensor installed before a NIC replacement, and a non-`INTEGRATION` realm, comparing each recovered address against the MAC runZero observes on the wire. That would establish which adapter Cybereason captures on a multi-homed host and how often the install-time value goes stale, and would show whether any `pylumId` variant exists whose layout check silently suppresses a MAC that could have been recovered.
- **EDR coverage-gap reporting.** Cybereason knows which endpoints carry a sensor and, through `status`, `disconnectionTime`, and `staleTimeMS`, which of those have stopped reporting. Diffing that against runZero's own discovery separates two populations that matter operationally: machines runZero sees on the network that Cybereason has never enrolled (agent coverage gaps), and machines Cybereason still lists whose sensor has gone stale (silent-agent gaps). Every field needed is already imported as a custom attribute, so this is a reporting exercise rather than a new integration.
- **No software or vulnerability import is possible.** Stated here rather than left as an open possibility: this API exposes neither an installed-package inventory nor a CVE feed, so no amount of additional endpoint work would produce `Software` or `Vulnerability` records from Cybereason.

## API documentation

- Cybereason's own API reference is published only behind the [Cybereason Nest customer portal](https://nest.cybereason.com/) and requires a customer login, so it could not be used to write this integration. Everything below stands in for it.
- Cortex XSOAR Cybereason integration client, used as the primary contract for the form login, the session lifetime, sensor paging, and the connection graph query: <https://github.com/demisto/content/blob/master/Packs/Cybereason/Integrations/Cybereason/Cybereason.py>
- Captured API responses shipped with that pack, used to verify the sensor response envelope (`sensors`, `totalResults`, `hasMoreResults`), the sensor field set, the `sensorId`/`guid`/`pylumId` formats, and the investigation graph result shape (`data.resultIdToElementDataMap`, `simpleValues`): <https://github.com/demisto/content/tree/master/Packs/Cybereason/Integrations/Cybereason/test_data>
- Command and output reference for the same pack, used to confirm the `direction` values (`OUTGOING`/`INCOMING`) and the connection field names: <https://github.com/demisto/content/blob/master/Packs/Cybereason/Integrations/Cybereason/README.md>

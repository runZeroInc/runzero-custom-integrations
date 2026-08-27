# Custom Integration: Microsoft Defender for IoT

Microsoft Defender for IoT (formerly CyberX) discovers and classifies OT and ICS
devices by passively monitoring industrial network traffic from an on-premises
**OT network sensor**. This integration imports one sensor's device inventory,
its open ports, and its vulnerability report into runZero.

**This integration talks to a single OT sensor, and that shapes everything
below.** Microsoft retired the on-premises management console (unsupported and
undownloadable after January 1, 2025, with sensor versions released after that
date refusing to connect to it), which removed the only endpoint that returned
a cross-site, consolidated inventory. What remains, and what Microsoft
explicitly endorses for third-party integration, is the per-sensor API. Three
consequences follow, and none of them are optional:

- **One credential and one base URL per OT sensor.** An operator with six
  sensors configures six credentials and six tasks of this integration.
- **Cross-sensor duplication is expected, not exceptional.** Microsoft's
  consolidation of "devices found in the same zone with similar characteristics"
  happened in the console layer, which no longer exists. Talking to sensors
  directly returns the unconsolidated view, so a device two sensors both observe
  arrives twice, once per sensor, with a different device id each time.
  De-duplicating it is runZero's job, done by MAC, IP, and hostname correlation
  (see [Asset identity](#asset-identity)), but the estate you get is the union
  of every sensor's view, not a pre-merged inventory.
- **There is no cloud alternative to fall back on.** The Azure ARM surfaces
  that appear under a "Defender for IoT" search (`Microsoft.Security` IoT
  Security Solution, Device Security Groups) are the legacy Azure IoT Hub
  security APIs, not the OT device inventory. No public cloud REST device
  inventory API for Defender for IoT OT was found.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the OT sensor's management interface on
  443/tcp. Sensors normally sit on a management VLAN reachable from the OT
  environment rather than from the corporate network, so place the Explorer
  accordingly.

## Microsoft Defender for IoT requirements

- A Defender for IoT **OT network sensor** appliance, virtual or physical,
  already onboarded and classifying devices.
- An **access token** generated on that sensor. Tokens are per-sensor: a token
  from sensor A cannot read sensor B.
- Network egress from the Explorer to the sensor's address on 443/tcp.
- **Certificate handling.** Sensors ship with a self-signed certificate, which
  is why every example in Microsoft's documentation passes `curl -k`. Either
  install a trusted certificate on the sensor, or set the **Disable TLS
  validation** (`tls_disable_validation`) option on the credential. Prefer the
  first; the second trusts whatever answers on that address.
- Nothing in Azure is required. The sensor API is served by the appliance
  itself and works on an air-gapped sensor, which Microsoft confirms is
  unaffected by the management console retirement.

## Steps

### Microsoft Defender for IoT configuration

1. Sign in to the OT sensor's web console as an **Admin** user.
2. Open **System Settings > Integrations > Access Tokens** and select
   **Generate token**.
3. Give the token a description that names runZero, then copy it. Microsoft's
   documentation is explicit that "the access token appears. Copy it, because
   it won't be displayed again." No expiry is documented, so the token is
   effectively indefinite and revocation is manual: delete it on this page
   when the integration is retired.
4. Confirm the token works against both endpoints this integration reads. The
   header carries the token **verbatim, with no `Bearer` prefix**:

   ```bash
   curl -k -H "Authorization: 1234b734a9244d54ab8d40aedddcabcd" \
     https://<sensor-address>/api/v1/devices/
   curl -k -H "Authorization: 1234b734a9244d54ab8d40aedddcabcd" \
     https://<sensor-address>/api/v1/reports/vulnerabilities/devices
   ```

5. The **Access Tokens** page shows a **Used** timestamp per token. `N/A` in
   that column means the sensor has never seen the token used, which is the
   quickest way to tell a credential problem from a connectivity one after a
   task fails.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Microsoft Defender for IoT, Plant 1 sensor").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **OT sensor URL** (`url`): the base URL of one sensor, for example `https://10.10.0.5`.
   - **Sensor access token** (`access_token`): the token generated above.
   - **Device authorization filter** (`authorized_filter`): optional; `all` (default), `authorized`, or `unauthorized`. `all` omits the documented `authorized` query parameter and imports everything.
   - **Import the vulnerability report** (`include_vulnerabilities`): optional; default on. See the note on the join below before leaving it on.
   - **Disable TLS validation** (`tls_disable_validation`): set this if the sensor still presents its self-signed certificate.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.
4. **Repeat steps 2 and 3 for every other OT sensor.** One credential and one
   task per sensor. The same script serves all of them; only the URL and token
   differ.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a token and see what a sensor actually returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename microsoft-defender-for-iot/microsoft-defender-for-iot.star \
  --kwargs url=https://10.10.0.5 \
  --kwargs access_token=1234b734a9244d54ab8d40aedddcabcd \
  --kwargs authorized_filter=all \
  --kwargs include_vulnerabilities=true \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./defender-for-iot-run
```

`--output` writes the assets the run produced, `--overwrite` replaces a
directory from a previous run (the scanner refuses an existing one otherwise),
and `--verbose` adds the request-by-request log.

The run makes **exactly two requests**: one to `/api/v1/devices/` and one to
`/api/v1/reports/vulnerabilities/devices`, or one request when
`include_vulnerabilities=false`. Neither endpoint pages, so there is nothing to
tune and no partial-import mode; a slow run is a slow sensor.

To check the `CONFIG` block and the HTTP and TLS wiring without a live sensor:

```bash
runzero script --filename microsoft-defender-for-iot/microsoft-defender-for-iot.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove the sensor accepts the
token, or that any device is parsed. The fixtures under
`microsoft-defender-for-iot/tests/fixtures/` exercise the parsing offline,
covering the IP-or-name vulnerability join, the malformed record cases, the
rate-limit case, and the identity-stability regression:

```bash
python3 tests/run.py microsoft-defender-for-iot
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat microsoft-defender-for-iot/microsoft-defender-for-iot.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://10.10.0.5,access_token=1234b734a9244d54ab8d40aedddcabcd' \
  --output ./defender-for-iot-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page and `--custom-integration-entry-function-name` defaults to `main`.
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it
takes one comma-separated string, so no value containing a comma can be passed
that way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from the OT sensor.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:microsoft-defender-for-iot`.
- With several sensors configured, a device two sensors both observe merges into
  one runZero asset on its MAC, IP, or hostname. Search
  `custom_attribute:microsoft_defender_for_iot_sensor` to see which sensor, or
  sensors, contributed to an asset.

## Asset identity

- Target entity: a physical OT/ICS/IT device observed on the monitored network by one Defender for IoT OT sensor.
- Source ID field: `id` on each element of the `GET /api/v1/devices/` array.
- Documentation evidence: https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/api/sensor-inventory-apis. The inventory field table documents `id` as "Numeric. Defines the device ID", **Not nullable**, and the endpoint as returning "a list of all devices detected by this sensor". The documented format is a small sequential integer, not a UUID: the sibling `connections` sample carries `"firstDeviceId": 171, "secondDeviceId": 22`, and the documented path examples read `/api/v1/devices/2/connections`.
- Uniqueness scope: **one sensor**. Device `2` on sensor A and device `2` on sensor B are unrelated devices. With the on-premises management console retired there is no vendor-side global identifier left, so the sensor must be part of the key.
- Cardinality: one array element per device per sensor. Within a sensor there is no evidence of duplicate rows. **Across sensors, duplicates are routine and expected.** Microsoft's own consolidation of similar devices happened in the console layer that no longer exists, so a device on a boundary between two monitored segments appears once per sensor with a different `id` each time.
- Stability: **could not verify.** Microsoft documents the field's type and nullability and nothing else. Whether the id survives a rename in the sensor UI is undocumented; whether it survives an IP or MAC change is undocumented. There is reason for doubt in both directions: `ipAddresses` and `macAddresses` are arrays on the device object, which suggests the device is the identity and addresses are attributes, but the presence of `hasDynamicAddress` and the fact that the CVE routes key on IP both hint that the address does more identity work internally than the schema implies.
- Reuse behavior: **could not verify, and this is the decisive unknown.** A per-sensor autoincrement is exactly the shape of identifier that gets reused after a database reset, and a sensor re-image would almost certainly restart numbering from 1. Nothing in the documentation says otherwise.
- Presence: always present. The field table marks `id` **Not nullable** on the list response. The vulnerability report response does **not** carry it at all; see the note on the join below.
- Final runZero ID: `microsoft-defender-for-iot:<sensor-hostname>:<id>`, for example `microsoft-defender-for-iot:sensor-plant1.example.com:42`. The scope is the hostname from the configured URL **with the port stripped**: a sensor reached on a non-default port is the same sensor, and a port in the namespace would re-key the entire site the day the sensor moved.
- Missing-ID behavior: skip. A record with no `id` is logged as `skipping a device record with no documented id` and dropped; an array element that is not an object is logged as `skipping an inventory entry that is not a device object`. No random or synthesized id is ever generated. Skip logging is capped at the first ten records and then tallied, so a large site produces a count rather than thousands of lines.
- Match behavior (set once in `CONFIG`): `no-id-match no-id-break`. **A foreign-ID match cannot be vetoed.** Once the foreign id matches, runZero never consults the break helpers (`no-mac-break`, `no-ip-break`, and `no-name-break` exist only on the MAC, IP, and hostname match paths), so a recycled or re-numbered sensor id would pull a completely unrelated device into an existing asset and no flag could disqualify the merge. With recyclability unverified and a sequential per-sensor counter as the identifier, delegating correlation to MAC, IP, and hostname is the only safe option. `palo-alto-device-security`, `aruba-clearpass`, and `forescout-counteract` reach the same conclusion for the same class of identifier. The id is still emitted so every record keeps a stable, namespaced key.
- Verdict: **scoped, non-authoritative.** The value identifies a row in one sensor's device table, and only that sensor's lifecycle keeps it pointing at the same physical device.
- **What follows from the MAC doing the correlating.** With id matching off, two inventory rows that share a MAC merge into one runZero asset. A sensor produces that shape routinely: a device behind a serial-to-Ethernet gateway or a NAT, or one host seen on two segments and not yet deduplicated by the sensor. The script does not try to resolve it: both rows are reported with their own sensor ids, nothing is dropped, and each id stays visible on the merged asset through the `device_id` attribute. Guessing which row to discard would be worse, because the script cannot tell a genuine duplicate from a gateway. `tests/fixtures/duplicate-mac.json` pins that behavior.

### Notes

- **Every emitted record must carry a MAC, an IP, or a hostname.** Because the
  id does not drive matching, a record with none of the three has no
  correlation signal at all and would land as an orphan asset that can never
  merge with anything. Such records are skipped, logged as
  `skipping device <id> with no MAC, IP, or usable hostname to correlate on`,
  and counted. This is common on a passive OT sensor: a device seen only as a
  serial-bus endpoint behind a gateway can have neither address.
- **Sensor-assigned device names are deliberately not imported as hostnames.**
  Defender for IoT labels a passively discovered device `PLC #14`, `IED #10`,
  or `OT Device #966`. Those are display labels built from a per-sensor type
  counter, not DNS names: they resolve nowhere, and the counter behind them
  restarts per sensor, so `PLC #14` on two sensors names two unrelated
  devices. `clean_hostname` rejects them because `#` and space cannot appear in
  a DNS name, which is the right outcome. Names the sensor genuinely learned
  from traffic still import normally. Every device name, generated or learned,
  is preserved as the `microsoft_defender_for_iot_device_name` custom
  attribute, and the raw label is what the vulnerability join falls back to.
- **The vulnerability join is on IP or name, and it is lossy.** This is a
  property of the API, not a shortcut: `GET /api/v1/reports/vulnerabilities/devices`
  returns `name` and `ipAddresses` and **no device id at all**, and the sibling
  CVE route puts an address, not an id, in the path
  (`/api/v1/devices/<ipAddress>/cves`). The integration indexes every report
  entry under each of its routable addresses and under its lower-cased name,
  then claims an entry for a device by address first and by name second, at most
  once. What that loses:
  - A device whose address changed between the two requests, or whose address
    is a DHCP lease (the inventory publishes `hasDynamicAddress` precisely to
    say it might be), can join to the wrong device or to none.
  - On a network with NAT or address reuse across monitored segments, two
    devices can present the same address and the first one processed claims the
    findings. Two devices sharing a sensor-generated label join by name
    unpredictably; the claim-once rule bounds the damage to one of them rather
    than duplicating findings onto both.
  - Each asset records which key actually matched as
    `microsoft_defender_for_iot_vulnerability_join`, so a suspicious result can
    be traced. Turn **Import the vulnerability report** off if the approximation
    is not acceptable for a site; the device inventory is unaffected.
- **Report entries that join nothing are still reported**, as their own asset
  tagged `vulnerability-report-only` and keyed
  `microsoft-defender-for-iot:<sensor>:report:<address>:<name-slug>`. Microsoft
  documents the report as a strict subset of the inventory ("devices that are
  found to have no vulnerabilities are not included in the result response"), so
  an unclaimed entry is a failed join rather than a device the inventory does
  not know about. Reporting it keeps the findings that would otherwise be
  dropped silently, and because id matching is off, runZero correlates it back
  onto the inventory asset by IP or hostname.
- **Assets** come from `GET /api/v1/devices/`. `name` becomes the hostname when
  it survives the check above; `ipAddresses` and `macAddresses` become the
  network interfaces; `vendor` becomes the manufacturer; `operatingSystem`
  becomes the OS; `type` becomes the device type (normalized, see below) and a
  verbatim `type:` tag;
  `firmware[].model` becomes the model and `firmware[].serial` a custom
  attribute. `authorized`, `engineeringStation`, `scanner`, and
  `hasDynamicAddress` become custom attributes, and the first three also become
  `unauthorized`, `engineering-station`, and `scanner` tags when set.
- **Software** is one record per `firmware[]` module, the richest part of the
  sensor schema: it names the `model`, `serial`, and `firmwareVersion` of each
  module in a chassis along with its physical `rack` and `slot`. Modules
  carrying none of model, serial, or firmware version are skipped rather than
  emitted as empty rows. `cpe23` is deliberately unset: the sensor publishes no
  CPE, and `Software.cpe23` accepts only the CPE 2.2 `cpe:/a:` binding.
- **Services** come from the vulnerability report's `vulnerabilities.openedPorts[]`,
  bound to the device's first routable address; an address-less device gets no
  services rather than services on a placeholder address. The entry's
  `protocol` ("SMP Over IP", "HTTP") is kept as a service custom attribute
  rather than a protocol name, which expects a lower-case token. A port whose
  `transport` is missing or unrecognized is recorded as `tcp` and flagged
  `transport_source=assumed`.
- **Vulnerabilities** come from `vulnerabilities.cves[]` on the report:
  `{id, score, description}`. The id is upper-cased and checked against
  `^CVE-[0-9]{4}-[0-9]{4,19}$` before it is set as the CVE, because
  `Vulnerability.cve` is not upper-cased for the script and a malformed value
  fails the whole record. Advisory identifiers that are not shaped like a CVE
  (`ICSA-21-159-01`) are kept as the finding name with no `cve` set rather than
  dropped. `score` drives the severity and risk ranks; it is deliberately **not**
  asserted as a CVSS v2 or v3 base score, because the report publishes no CVSS
  version alongside it. Up to 99 findings are attached per asset.
- **Plain-text passwords are never imported.** The report's
  `vulnerabilities.plainTextPasswords[]` carries live credentials recovered from
  monitored traffic. Everything about each finding *except* the credential is
  imported: `plaintext_password_count`, `plaintext_password_protocols`, and
  `plaintext_password_strengths`, Microsoft's own `Very weak` / `Weak` /
  `Medium` / `Strong` rating, which says how bad the finding is while disclosing
  nothing. `tests/fixtures/vulnerabilities.json` puts a distinctive sentinel in
  the `password` field and asserts that no attribute carries it.
- **`weakAuthentication[]` names are imported, not just counted.** Microsoft
  types the field as a JSON array of strings naming the applications detected
  using weak authentication, so the names land in
  `weak_authentication_applications` exactly as `antiViruses` does, alongside
  `weak_authentication_count`. Both this and the plain-text password finding
  also add a tag (`weak-authentication`, `plaintext-passwords`) so they are
  searchable without reading attributes.
- **`remoteAccess[]` is imported in full.** `remote_access_ports`,
  `remote_access_transports`, `remote_access_clients` (the address that reached
  the device), and `remote_access_software` (the tool it used). None of it
  becomes a `Service`, because the report does not say the port is still
  listening.
- **`deviceType` is normalized where the mapping is unambiguous.** Microsoft's
  `type` is display text from a sensor vocabulary that mixes runZero's own
  spellings (`PLC`, `HMI`, `Server`) with sensor-specific ones
  (`Industrial Packaging System`, `Wifi Pineapple`, `Slot`, `RTU`, `IED`). Those
  fold onto the nearest runZero type (`Industrial Control` for the OT gear,
  `WAP`, `NAS`, `Desktop`, `IP Camera`, `Server` for the rest), and `Unknown`
  folds to nothing rather than being imported as a type. Anything unmapped
  passes through verbatim, because a sensor's own classification of an OT device
  carries more information than a guess. The raw spelling always survives as the
  `type:` tag and the `microsoft_defender_for_iot_device_type` attribute.
- **The report's `operatingSystem` block is not trusted as an OS name.**
  Microsoft's own published sample response puts a vendor string in it
  (`"name": "ABB Switzerland Ltd, Power Systems", "type": "abb"`), so only
  `version` is used, and only when the inventory did not supply an OS version.
  `name`, `type`, and `latestVersion` are recorded as custom attributes. More
  generally the report only fills gaps: a manufacturer, model, or OS version
  the inventory already supplied is never overwritten.
- **No timestamps are imported.** The documented device schema has no
  first-seen or last-seen field, so neither `firstSeenTS` nor `lastSeenTS` is
  set and runZero stamps the import itself. The `connections` endpoint does
  carry epoch-millisecond `lastSeen` and `discovered` values, but that is a
  different dataset; see [Future](#future).
- **There is no pagination, and none is invented.** The inventory endpoint
  documents exactly one query parameter (`authorized`) and no `limit`,
  `offset`, `page`, or cursor; the vulnerability report documents none at all.
  The script therefore contains no pagination loop and declares no `maxPages`
  ceiling, because there would be nothing for `pager()` to bound. A busy sensor
  returns its entire inventory in one unbounded response with no incremental
  filter to reduce it. Assets are streamed with `report_asset` as each record is
  converted, so only one asset is in flight at a time, but the response body
  itself is buffered, and memory and timeout behaviour on a very large site is
  unverified.
- **Rate limits are unverified.** Microsoft publishes none for the sensor API.
  Requests are issued with `retries=3`, so the shared HTTP helper absorbs 429
  and 5xx responses with exponential backoff and honors `Retry-After`.
- **Unverified assumptions, in one place.** (1) Device `id` stability and
  recycling, per the Asset identity record above. (2) `protocols` is typed in
  the field table as a single Object of `{id, name, ipAddresses}`, which cannot
  describe a device that speaks several protocols; the script accepts both an
  object and an array. (3) The `authorized` and `scanner` rows in Microsoft's
  field table carry copy-paste errors: both are described as "Defines whether
  the device is defined as an engineering station or not", and `scanner`'s value
  list reads "Device is authorized / Device is not authorized". The field
  *names* are reliable, the prose for those two is not, so both are imported
  under their own names without reinterpretation. (4) Memory and timeout
  behaviour of the unpaginated inventory response, per the pagination note.
- **Device response shapes came from the field table, not from a recorded
  response.** Microsoft publishes a real sample response for the vulnerability
  report endpoint, used verbatim as the first entry in
  `tests/fixtures/vulnerabilities.json` apart from a trimmed CVE description,
  but publishes **no sample response for `/api/v1/devices/` itself**. The device
  field names used here are exactly the ones in the documented field table, but
  the nesting and the element shapes of `protocols` and `firmware` are inferred
  from that table rather than observed. This integration was validated against
  those fixtures, not a live sensor.

## Future

- **Confirm the identity questions against a live sensor.** Three experiments
  would settle whether the id can be promoted to an authoritative key: rename a
  device in the sensor UI and re-poll; move a device to a new IP and MAC and
  re-poll; delete a device, let the sensor rediscover a different one, and see
  whether the number is reused. Only if the id proves stable and non-recycled
  should the `matchBehavior` here be revisited, because a wrong answer merges
  unrelated OT assets and nothing can veto it.
- **Device connections as an adjacency dataset.** `GET /api/v1/devices/connections`
  and `GET /api/v1/devices/<id>/connections` are the one adjacent dataset that
  **does** key on the device id (`firstDeviceId` / `secondDeviceId`), and they
  carry `ports`, `protocols[].commands`, and epoch-millisecond `lastSeen` and
  `discovered`. That is the raw material for OT communication mapping and
  Purdue-level inference, and it also supports `discoveredBefore`,
  `discoveredAfter`, and `lastActiveInMinutes`, the only incremental filter in
  this API.
- **The dedicated CVE routes.** `GET /api/v1/devices/cves` returns every known
  CVE sorted by descending score with `cveId`, `ipAddress`, `score`,
  `attackVector`, and `description` (optional `top`, default 100), and
  `GET /api/v1/devices/<ipAddress>/cves` does the same for one address. They
  add `attackVector`, which the report endpoint does not carry, at the cost of
  a second IP-keyed join or one request per device. The report endpoint was
  chosen here because it returns the open ports and the security findings in
  the same response.
- **Streaming the inventory response.** `jsonstream.iter_array` can walk a
  large JSON array without materializing the document, the natural answer to
  the unbounded inventory response. It needs the raw body, so it would mean
  dropping to `http.get` and losing `get_json`'s automatic 429/5xx retry, worth
  doing only if a real sensor proves the buffered response is a problem.
- **Sensor health as an asset in its own right.** The sensor API exposes
  appliance health and version information, which would let runZero track the
  sensors themselves, useful precisely because there is no longer a management
  console watching them.
- **Alerts as an event feed.** The sensor exposes alerts with their own
  lifecycle. A policy alert is not a property of a device, so it suits an event
  feed keyed to the same asset identity rather than an inventory import, which
  is why alerts are not imported here.

## API documentation

- Defender for IoT API reference index, including the `Authorization` header contract ("add an HTTP header titled **Authorization** to your request, and set its value to the token that you generated"): https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/references-work-with-defender-for-iot-apis
- Sensor inventory APIs (`/api/v1/devices/`, the device field table, the `authorized` parameter, `connections`, and the CVE routes): https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/api/sensor-inventory-apis
- On-premises management console retirement, and the direction to use the sensor APIs to send data to third-party systems: https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/ot-deploy/on-premises-management-console-retirement
- The vulnerability report endpoint (`/api/v1/reports/vulnerabilities/devices`) and its published sample response are documented in the sensor API reference set linked from the index above.

# Custom Integration: Carbon Black

> **Breaking configuration change.** This integration now requires an **API ID**
> (`api_id`) parameter that did not exist before. Carbon Black documents its auth
> header as `X-Auth-Token: <API Secret Key>/<API ID>`, and the script previously
> sent the Org Key in the API ID's place — a value Carbon Black cannot match to
> any key, so no request could authenticate. An existing credential will fail
> validation until `api_id` is filled in; the value is on **Settings > API
> Access**, in the **Actions** menu of the API key you already created, and needs
> no new key.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Carbon Black requirements

- An API key created with a **Custom** access level. The older `API`, `LIVE_RESPONSE`, and `SIEM` access levels are deprecated; build a custom access level instead and grant it only what this integration reads.
- The custom access level needs read (`READ`) permission on **Device** (`device`) for the device inventory, and on **Vulnerability Assessment** (`vulnerabilityAssessment`) if you want the vulnerability enrichment. The integration issues only `POST ... /_scroll` and `.../_search` reads; no write permission is needed.
- Both halves of the API key: the **API Secret Key** and the **API ID**. Carbon Black authenticates with the two joined as `X-Auth-Token: <API Secret Key>/<API ID>`, so one without the other is not a usable credential.
- The **Org Key** for the organization whose devices you want. It appears in the request path on every call, and *only* there — it is not part of the auth header, and supplying it as the API ID is what the earlier revision of this script got wrong.
- The regional API hostname. Carbon Black Cloud is a multi-region service and the hostname is not the same for every tenant.

## Steps

### Carbon Black configuration

1. Sign in to the Carbon Black Cloud console and go to **Settings > API Access**.
2. Open the **Access Levels** tab and click **Add Access Level**. Give it a name, then grant **Read** on the `device` category, and on `vulnerabilityAssessment` if you want vulnerabilities imported. Save it.
3. Open the **API Keys** tab and click **Add API Key**.
   - Give it a name, for example `runzero`.
   - Set **Access Level type** to **Custom** and choose the access level created in step 2.
   - Save. The console then shows the **API ID** and the **API Secret Key**. Record both — this integration needs both. The secret is shown only at creation time; the API ID can be read back later from the key's **Actions** menu on the **API Keys** tab.
4. Find the **Org Key** on **Settings > General**, or at the top of **Settings > API Access**. Copy the value without any surrounding `<>` or `{}` brackets. It is a third, separate value — not the API ID.
5. Determine your regional hostname. Carbon Black publishes the full list on the
   [authentication reference](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#hostname); the common ones are:

   | Environment | Hostname |
   |---|---|
   | Prod 01 | `https://dashboard.confer.net` |
   | Prod 02 | `https://defense.conferdeploy.net` |
   | Prod 05 | `https://defense-prod05.conferdeploy.net` |
   | Prod 06 (EU) | `https://defense-eu.conferdeploy.net` |
   | Prod NRT (Tokyo) | `https://defense-prodnrt.conferdeploy.net` |
   | Prod SYD (Sydney) | `https://defense-prodsyd.conferdeploy.net` |

   The hostname shown in your browser's address bar when you are signed in to the console is the right one.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API queries as needed to filter asset data.
    - Adjust which attributes are included in runZero.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Carbon Black base URL** (`url`): **required.** The regional hostname from step 5, for example `https://defense.conferdeploy.net`. There is no default — Carbon Black Cloud is multi-region and no single hostname would be right for every tenant.
    - **Organization key** (`organization_key`): **required.** The Org Key from step 4. This scopes the request path; it is never sent as a header.
    - **API ID** (`api_id`): **required.** The API ID from step 3. This is the second half of the `X-Auth-Token` header, and it is *not* the Org Key.
    - **API secret key** (`api_key`): **required**, stored as a secret. The API Secret Key from step 3.
    - TLS and HTTP options arrive through the shared includes.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "carbonblack").
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
runzero script --filename carbon-black/carbon-black.star \
  --kwargs url=https://defense.conferdeploy.net \
  --kwargs organization_key=A1B2C3D4 \
  --kwargs api_id=ABCD123456 \
  --kwargs api_key=QWERTYUIOPASDFGHJKLZXCVB \
  --output ./carbon-black-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

The device scroll pulls the whole organization in pages of 1000 and then makes one
vulnerability request per device, so a first run against a large tenant is not quick. Watch
the log rather than waiting on `--output` if you only want to confirm the credential works.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename carbon-black/carbon-black.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Carbon Black accepts the key or that any device is parsed.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py carbon-black
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat carbon-black/carbon-black.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://defense.conferdeploy.net,organization_key=A1B2C3D4,api_id=ABCD123456,api_key=<secret>' \
  --output ./carbon-black-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from Carbon Black.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:carbonblack`.

## Asset identity

- Target entity: a **device carrying a Carbon Black Cloud sensor** — one row per sensor registration in the organization, covering endpoints, workloads, VDI instances, and cloud compute instances alike.
- Source ID field: `id`, from `POST /appservices/v6/orgs/{org_key}/devices/_scroll`.
- Documentation evidence: Carbon Black's own API addresses a device by this value. The vulnerability enrichment this integration performs interpolates it straight into the vendor's per-device path — `/vulnerability/assessment/api/v1/orgs/{org_key}/devices/{id}/vulnerabilities/_search` — so `id` is the key the platform itself uses to name a device across two different services, not merely a field on the device record.
- Uniqueness scope: the organization named by `organization_key`, which appears in the path of every request. The composed runZero id does **not** carry the org key, so importing two Carbon Black organizations through one custom integration puts both in a single id space.
- Cardinality: one source row per device. Vulnerability rows are many-to-one and attach to the device rather than becoming assets.
- Stability: the id survives rename, address change, reboot, policy change, and sensor upgrade — it is the identifier the vulnerability service is addressed by between calls. What it does **not** survive is a sensor re-registration: an uninstall and reinstall, or a re-imaged machine, enrolls as a new device record with a new id. This is the ordinary cause of duplicate device records in Carbon Black Cloud, but **no vendor statement confirming it could be cited**, so treat it as expected rather than documented.
- Reuse behavior: not documented. The value is a monotonic integer rather than a UUID, so recycling cannot be excluded on shape alone.
- Presence: present on every device row. The script still checks explicitly, because `.get`'s default does not catch a key that is present with a null value — an earlier revision turned every such row into the single foreign id `"None"`, collapsing them onto one asset and issuing `POST .../devices/None/vulnerabilities/_search`. A row whose `id` is null or empty is now skipped with `carbon-black: skipping device with no id`.
- Final runZero ID: the raw Carbon Black device id as a string, e.g. `4839201`.
- Missing-ID behavior: skip and log. Rows that are not JSON objects at all are skipped separately with `carbon-black: skipping non-object device row`.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: Carbon Black issues a persistent per-device identifier and this integration uses it directly, which is what keeps a roaming laptop on one asset while its DHCP address and hostname churn.
- Verdict: **scoped authoritative** for a sensor registration within one organization; derived for the physical machine, because a re-registration mints a new id.

On the re-registration case specifically: the result is a second runZero asset, and **no `matchBehavior` flag prevents it**. runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check never consults `matchBehavior` — so relaxing `id-break` would not recover the merge. The duplicate has to be reconciled in runZero. In the opposite direction, once the id *does* match, nothing fragments the asset: a foreign-id match is never disqualified by a conflicting MAC, IP, or hostname.

`deployment_type` is imported as a device *type* rather than as identity — `WORKLOAD`, `AWS`, `AZURE`, and `GCP` map to Server and `VDI` to Desktop, while `ENDPOINT` is deliberately left unmapped because it covers desktops and laptops without separating them and translating it would displace the chassis runZero fingerprints for itself.

### Notes

- **Three values, three distinct roles.** Carbon Black documents the header as `X-Auth-Token: <API Secret Key>/<API ID>`, secret first; the Org Key is a separate value that appears only in the request path (`/appservices/v6/orgs/<org_key>/devices/_scroll`). The script now sends exactly that, with `api_id` supplying the second component. Until this fix it built the header as `<api_key>/<organization_key>` — the Org Key standing in for an API ID that `CONFIG` did not even declare — which Carbon Black cannot match to any key, so a correct credential still returned `401`. If you see a `401` now, it is the key or the access level rather than the header shape; check that the secret and the API ID belong to the same key and that neither has been pasted into the other's field.
- The integration automatically retrieves **all device attributes** available in Carbon Black Cloud.
- Data such as **sensor version, status, policy, network details, and security attributes** are included in `customAttributes`.
- Use the **runZero search queries** to filter assets by key attributes.
- Vulnerabilities are fetched **one request per device**, paged 100 at a time with no cap (`MAX_VULNS` is `None`), and sorted by `risk_meter_score`. On a large tenant this dominates the run. There is no credential parameter to turn it off; the constant at the top of the script is the switch.
- A vulnerability whose `risk_meter_score` or `severity` is present but null is handled rather than fatal — `.get`'s default only applies to an absent key, and `float(None)` would abort the whole script.

## Future

- **Fetch vulnerabilities once for the organization instead of once per device.** The Vulnerability Assessment service exposes an organization-scoped search alongside the per-device path this integration uses, which would replace N requests with a paged walk and make the enrichment affordable on a large tenant. That is the single highest-value change available here, and it is a request-shape change rather than new data.
- **`POST /appservices/v6/orgs/{org_key}/devices/_search` instead of `_scroll`.** The search form accepts a `criteria` block — including `last_contact_time` windows and status filters — which would give this integration the incremental mode it currently lacks. Today every run is a full inventory walk with `"criteria": {}`, so there is no way to sync only what changed.
- **Alert ingestion as an event feed.** Carbon Black's Alerts API returns detections with severity, device id, and timestamps, and the device id is exactly the value this integration already uses as the asset identity, so the join back to a runZero asset is direct. These are behavioral detections rather than CVEs and belong in a time-windowed feed with a high-water mark, not in `Vulnerability` records — modelling them as vulnerabilities would put uncorrelatable identifiers in a field runZero's vulnerability reporting expects to hold CVEs.
- **USB Device Control is the genuinely novel one.** Carbon Black's Device Control service inventories removable media observed on endpoints — vendor, product, serial number, and which endpoint it was attached to. That is asset data runZero cannot obtain any other way, since a USB device is never on the network to be scanned. It would want its own record shape rather than being folded into the host asset.
- **Outbound: device actions driven by runZero policy.** The device actions endpoint can quarantine a device, change its policy, or toggle sensor bypass. A runZero query — every asset missing an expected agent, everything on a segment that should not have internet access — could drive policy assignment. Quarantine and sensor uninstall are genuinely destructive and would need per-device confirmation and an audit trail; policy *assignment* is the reversible subset and the sensible place to start.
- **Live Response is reachable and deliberately out of scope.** The same credential class can open a Live Response session and read files, registry keys, and process lists from an endpoint. It is a remote-shell equivalent, it is heavily audited for good reason, and nothing about an inventory sync justifies it.
- **EDR coverage-gap reporting.** Carbon Black knows which machines carry a sensor and, through `status`, `last_contact_time`, and `sensor_version`, which of those have gone quiet or are running an outdated build. Diffing that against runZero's own discovery separates machines with no sensor at all from machines whose sensor has stopped reporting. Every field needed is already imported as a custom attribute, so this is a reporting exercise rather than new integration work.

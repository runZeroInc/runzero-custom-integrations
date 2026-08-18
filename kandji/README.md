# Custom Integration: Kandji

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Kandji requirements

- A Kandji tenant and an admin account that can create API tokens.
- Your tenant-specific **API URL**, including the `/api/v1` path.
- A **Kandji API Token** with read permission on the device endpoints.

> **Kandji is now Iru.** The API documentation has moved to
> [api-docs.iru.com](https://api-docs.iru.com/) — `api-docs.kandji.io` issues a
> permanent redirect there — and the docs are titled "Iru Endpoint Management
> API". **The API hostnames have not changed** and remain under `*.api.kandji.io`.
> Kandji's own documentation notes that many URLs and references will continue to
> say Kandji for some time, so expect both names while the migration settles.

### Creating the API token

1. Log in to Kandji and go to **Settings > Access**.
2. Click **Add API Token**.
3. Give it a **Name** and **Description**, then click **Create**.
4. The token is shown in a modal **once** — use the visibility toggle or **Copy Token** to capture it. "You will not be able to see the token details again."
5. Click **Next**, then **Configure** to set the token's API permissions (or **Skip** and set them later from the token's **Permissions** tab).

**Permissions.** Kandji stores token permissions as **endpoint path plus HTTP
method** pairs rather than as named scopes. Kandji publishes no reference list of
permission names, so no scope string is quoted here. Grant the read permissions
this integration actually uses, both under **Device Information**:

- `GET /api/v1/devices` — the device list.
- `GET /api/v1/devices/{device_id}/details` — per-device detail, which this integration fetches for every device.

Grant nothing under **Device Actions**; that section holds the write operations,
and this integration never writes.

> **Provision the token under an account that will outlive its creator.** Kandji
> states plainly: "if you remove an admin user from the Kandji Web App after
> they've created an API Token, the API Token will also be removed." A token
> created by a departing administrator disappears with them, and the task starts
> failing with no change on the runZero side.

### Finding your API URL

**The tenant-specific API URL is only shown after you create your first token.**
That ordering catches people out — there is nothing to copy until a token exists.
Once one does, the URL appears in **Settings > Access**.

There are two regional shapes, and they differ by more than the subdomain:

| Region | API URL |
|---|---|
| US | `https://<subdomain>.api.kandji.io/api/v1` |
| EU | `https://<subdomain>.api.eu.kandji.io/api/v1` |

Configure the **whole URL including the `/api/v1` path** — the script uses the
value verbatim and appends `/devices` to it, so a URL without `/api/v1` produces
404s on every request.

### Rate limit

Kandji enforces **10,000 requests per hour** per tenant. That matters here
because this integration is an N+1 fetch: one paged request per 300 devices for
the list, plus **one detail request per device**. A 5,000-device tenant therefore
costs roughly 5,017 requests per run, which fits, and a tenant approaching 10,000
devices does not. Schedule accordingly, and do not run several Kandji tasks
against one tenant in the same hour.

### runZero configuration

1. (OPTIONAL) Make any necessary changes to the script to align with your environment.
    - Modify API queries as needed to filter asset data.
    - Adjust which attributes are included in runZero.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Kandji API URL** (`url`): your tenant-specific API URL **including the `/api/v1` path**, for example `https://acme.api.kandji.io/api/v1` (US) or `https://acme.api.eu.kandji.io/api/v1` (EU).
    - **API token** (`api_token`): the token created above.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "kandji").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from Kandji.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:kandji`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real tenant returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair — this integration has only two:

```bash
runzero script --filename kandji/kandji.star \
  --kwargs url=https://acme.api.kandji.io/api/v1 \
  --kwargs api_token=11111111-2222-3333-4444-555555555555 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/kandji-run --overwrite
```

For an EU tenant the URL carries the extra `.eu` label:
`--kwargs url=https://acme.api.eu.kandji.io/api/v1`.

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

**There is no limit parameter, and this run is not cheap.** The script pages the
device list 300 at a time and then issues **one detail request per device**,
against a 10,000-requests-per-hour tenant budget. A command-line run on a large
tenant consumes the same budget the scheduled task will, so avoid running it
repeatedly in one hour while iterating.

The two failure modes worth recognising:

- **404 on every request** — the `url` is missing its `/api/v1` path. The script
  appends `/devices` to the value verbatim and does not add the API version
  itself.
- **403 on the detail requests but not the list** — the token has
  `GET /api/v1/devices` but not `GET /api/v1/devices/{device_id}/details`.
  Because permissions are granted per endpoint path and method, this is a common
  half-configured state, and it produces assets with much less detail rather than
  an outright failure.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real tenant:

```bash
runzero script --filename kandji/kandji.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real device.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://acme.api.kandji.io/api/v1,api_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py kandji
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: an **Apple device enrolled in Kandji** — a Mac, iPhone, iPad, Apple TV, or Vision device under this tenant's management.
- Source ID field: `device_id`, from `GET /devices`.
- Documentation evidence: Kandji's own API addresses a device by this value. This integration interpolates it directly into `GET /devices/{device_id}/details` for every record, so it is demonstrably the resource key rather than an incidental field on the list response.
- Uniqueness scope: **the tenant, within one region.** The US and EU deployments are separate — they differ by hostname, not merely by routing — so an id is only meaningful against the host it came from. The value is used bare with no tenant prefix.
- Cardinality: one source row per enrolled device; the detail lookup returns more fields for the same device rather than new records.
- Stability: the id belongs to the Kandji device record and survives rename, address change, OS upgrade, and blueprint reassignment. Un-enrolling a device and re-enrolling it creates a new record with a new id.
- Reuse behavior: not documented. The value is a UUID, so reassignment to a different device is implausible on shape alone.
- Presence: read with `device.get("device_id", "")` and **not explicitly checked**. A record with no `device_id` therefore reaches the detail request as `GET /devices//details`, which fails, and the device is dropped by the `if not details: continue` guard — the right outcome, but reached by accident and at the cost of a wasted request against a rate-limited budget. Every other integration in this repository skips and logs before spending the request.
- Final runZero ID: the raw Kandji device id, e.g. `11111111-2222-3333-4444-555555555555`.
- Missing-ID behavior: none explicitly; see above.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: this is a persistent per-device identifier issued by the platform and used directly.
- Verdict: **scoped authoritative** for an enrolled device within one regional tenant; derived for the hardware, because a re-enrollment mints a new id.

**Worth contrasting with `jamf/`, which covers the same estate.** Jamf's integration keys on the Apple hardware `udid`, which is global and survives un-enrollment; this one keys on Kandji's own record id, which does not. The practical difference shows up when a Mac is migrated between MDMs or re-enrolled: the Jamf asset persists, the Kandji asset forks. Kandji publishes the hardware serial number — it is imported as the `serial_number` custom attribute — but it is not used as identity and is not a correlation dimension, so it is available for a manual reconciliation and nothing more.

On correlation: the hostname is `network.local_hostname` and a single MAC comes from `network.mac_address`, both from the detail response. **`public_ip` is deliberately excluded** from the network interface — it is the egress address of whatever gateway the device is behind, so every device in one office reports the same one, and pairing it with each device's own MAC would correlate the whole fleet onto a single address. It is kept as a custom attribute instead. A device whose detail request fails contributes no addresses at all and correlates on nothing, since the hostname comes from the same response.

### Notes

- The integration automatically retrieves **all devices** available in Kandji.
- Data such as **serial number and OS model** are included in `customAttributes`.
- Use the **runZero search queries** to filter assets by key attributes.
- The device family (`platform`) supplies the device type for phones, tablets, and Apple TVs; a Mac is resolved from its marketing model name instead, because `mac` covers laptops and desktops alike. A model that names no chassis leaves the type unset rather than displacing what runZero fingerprints for itself. `vision` is deliberately unmapped — runZero has no device type for a headset.

## Future

- **Kandji Prism is the answer to the N+1, and it changes what this integration can afford to do.** Prism exposes fleet-wide tables — device information, applications, FileVault state, installed profiles, local users, certificates, kernel extensions, launch agents and daemons, Gatekeeper and XProtect status — as bulk queries rather than per-device lookups. This integration currently spends one request per device to recover network and hardware detail, which is what makes it cost roughly one request per device against a 10,000-per-hour tenant budget. Moving to Prism would collapse that to a handful of paged requests *and* supply several of the enrichments below for free. It is the single highest-value change available here.
- **Installed applications as `Software` records.** Kandji reports the application inventory per device, and Prism exposes it fleet-wide. This integration emits **no `Software` records at all** today. For a Mac fleet that is the main thing an MDM knows which runZero cannot observe from the network.
- **Compliance and security posture as tags.** FileVault, Gatekeeper, XProtect, system extensions, and activation lock are all reachable, and Kandji's library-item status per device says whether the device is actually converged on its blueprint or drifting. Modelled as tags that makes "every Mac on this segment out of compliance with its blueprint" a runZero query — a question neither product answers alone in that form.
- **Vulnerability data, if the tenant is entitled to it.** Kandji has added vulnerability management to its platform, which would produce CVE-bearing `Vulnerability` records that runZero's own vulnerability reporting recognises — unlike posture assertions, which do not map onto CVEs. Confirm entitlement and the exact routes against <https://api-docs.iru.com/> before designing around it.
- **Server-side filtering for an incremental sync.** The device list accepts filter parameters, so a scheduled task could fetch only devices that have checked in since the last run rather than walking the whole fleet. Combined with the rate-limit arithmetic above, this is what makes a frequent schedule viable on a large tenant.
- **Blueprints as grouping data.** A Kandji blueprint is the management policy a device is assigned to, and it is a meaningful grouping — imported as a tag it would let runZero searches align with how the Mac fleet is actually administered.
- **Outbound: push runZero context into Kandji.** Device records carry an asset tag and user assignment, and blueprints scope policy. A runZero query could drive the asset tag so that Kandji administrators see runZero's classification where they already work. Device actions — lock, erase, reinstall the agent — are also reachable and are deliberately out of scope: an erase is unrecoverable, and the token guidance above (grant nothing under **Device Actions**) exists precisely to make that impossible.
- **Enrollment coverage-gap reporting.** Apple hardware runZero fingerprints on the network with no Kandji record is unmanaged — for a Mac fleet, exactly the question worth asking. In the other direction, Kandji's last-check-in data identifies enrolled devices that have stopped reporting: managed on paper, absent in practice.

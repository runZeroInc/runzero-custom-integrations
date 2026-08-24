# Custom Integration: NinjaOne

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with outbound HTTPS access to your NinjaOne instance.

## NinjaOne requirements

- API client ID and secret with appropriate permissions.
- NinjaOne API URL (e.g. `https://us2.ninjarmm.com`).
- **A NinjaOne system administrator to create the client app.** NinjaOne states that only system administrators may configure OAuth tokens for the API; a technician account cannot do this step.
- The `monitoring` scope. NinjaOne describes it as granting read-only access to monitoring data and organization structure, which is exactly what this integration needs — it reads `/v2/devices-detailed` and nothing else. The `management` and `control` scopes are not required and should not be granted.

### Finding your instance URL

NinjaOne runs several regional instances and yours is simply the host you log
in to. There is no lookup and no per-tenant subdomain:

| Host | Region |
| --- | --- |
| `https://app.ninjarmm.com` | US |
| `https://us2.ninjarmm.com` | US (second instance) |
| `https://eu.ninjarmm.com` | Europe |
| `https://ca.ninjarmm.com` | Canada |
| `https://oc.ninjarmm.com` | Oceania |

Use the same host in `api_url` that appears in your browser's address bar when
you are signed in to NinjaOne. Both the OAuth token endpoint and the device API
are served from it.

## Steps

### NinjaOne configuration

1. Sign in to NinjaOne as a **system administrator**.
2. Navigate to **Administration > Apps > API**, open the **Client app IDs** tab, and click **Add client app**.
3. Configure the app:
   - **Application Platform**: `API Services (machine-to-machine)`. This is the option that produces a client secret; the interactive platforms do not.
   - **Allowed Grant Types**: `Client Credentials`. Do not select Authorization Code — this integration has no user to redirect and no browser.
   - **Redirect URIs**: leave blank. Client Credentials never redirects.
   - **Scopes**: `monitoring` only.
   - Give it a name that identifies it later, e.g. `runZero`.
4. Save the app and record the **Client ID** and **Client Secret**. NinjaOne's public documentation does not state whether the secret can be retrieved later, so treat it as shown once and copy it now.
5. Note down the API URL — the instance host from the table above, with no trailing path.
6. Confirm the credential from the Explorer host before configuring anything in runZero:

   ```bash
   curl -s -X POST 'https://us2.ninjarmm.com/ws/oauth/token' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'grant_type=client_credentials' \
     -d 'client_id=<client_id>' \
     -d 'client_secret=<client_secret>' \
     -d 'scope=monitoring'
   ```

   A working credential returns a JSON object containing `access_token`. An
   `{"error":"invalid_client"}` response means the pair is wrong; a 404 means the
   instance host is wrong.

   Note that the token path is not published in NinjaOne's public documentation
   (their full API reference sits behind a login). `/ws/oauth/token` is what this
   integration uses and it is confirmed to work on every regional instance;
   `/oauth/token` routes to the same handler.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter inventory data.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **NinjaOne API URL** (`api_url`): your NinjaOne instance URL, for example `https://us2.ninjarmm.com`. There are five instances and no per-tenant subdomain; any instance but your own answers 404. The value is read with `get_url_base()`, so a URL copied from the console with a path or fragment attached is trimmed to scheme and host automatically.
    - **OAuth client ID** (`client_id`): your NinjaOne client ID.
    - **OAuth client secret** (`client_secret`): your NinjaOne client secret.
    - **Maximum pages to retrieve** (`max_pages`, optional, default `20000`): safety ceiling on the paging walk. The default is the repo-wide ten-million-record target divided by the 500-device page NinjaOne serves, so it does not truncate any real inventory. Raise it only if a run logs `page limit of 20000 hit (integration safety limit, ...)`; that line is the only signal that an import was cut short.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "ninjaone").
    - Upload an image file for the NinjaOne icon.
        - Download [NinjaOne logos and icons](https://www.ninjaone.com/wp-content/uploads/2024/10/NinjaOne-Logos-and-Favicons.zip)
        - Resize selected icon to be 256px by 256px
        - Upload resized icon file
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a client app and see what the device inventory returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename ninjaone/ninjaone.star \
  --kwargs api_url=https://us2.ninjarmm.com \
  --kwargs client_id=a1b2c3d4e5f6071829ab \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./ninjaone-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

There is no page size and no filter here, so the whole device inventory comes
back from `/v2/devices-detailed`. `max_pages` is the one lever on run size: set
it low (`--kwargs max_pages=2`) to sample the first pages of a large tenant
before scheduling anything.

The walk pages with the `after` keyset cursor and ends on a short or empty page.
Two things can cut it short, and both say so in the log:

- `ninjaone: paging stopped after N pages (API returned the same cursor twice, ...)` — the server answered with the same last row id twice, meaning it ignored `after` or replayed a cached response. Raising `max_pages` will not help; the walk was not making progress.
- `ninjaone: page limit of N hit (integration safety limit, ...) - raise the max_pages parameter to import the rest` — a genuinely larger inventory than the ceiling allows.

The three failure modes are cleanly separable, which makes this quick to
diagnose:

- **Wrong `api_url`** — the token request 404s. You cannot guess the instance; it is the host you sign in to.
- **Wrong `client_id` / `client_secret`** — the token request returns `invalid_client`, and the script prints `failed to retrieve bearer token`.
- **Missing `monitoring` scope** — the token is issued but the device call is refused. This is the one that looks like a working credential.

`--kwargs` takes its value verbatim as long as the whole argument holds a single
`=`, so a comma inside a value is passed through intact — `--kwargs 'x=a,b'`
arrives as `a,b`. What breaks is a value carrying **both** a second `=` and a
comma: the flag then parses the argument as a CSV record, so
`--kwargs 'x=a=b,c=d'` yields `x=a=b` plus a fabricated parameter `c="d"`. A
client secret is opaque and could hold both; wrap the whole argument in a second
pair of quotes if it does — `--kwargs '"client_secret=a=b,c=d"'` — or configure
it through the console credential form.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename ninjaone/ninjaone.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove NinjaOne issues a token,
that the `monitoring` scope was granted, or that any device is parsed.

The fixtures under `ninjaone/tests/fixtures/` exercise the parsing offline,
including the empty and paged cases:

```bash
python3 tests/run.py ninjaone
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat ninjaone/ninjaone.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_url=https://us2.ninjarmm.com,client_id=a1b2c3d4e5f6071829ab,client_secret=<secret>' \
  --output ./ninjaone-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way; prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ninjaone`.

## Asset identity

- Target entity: a device with the NinjaOne agent installed, as returned by `GET /v2/devices-detailed`. NinjaOne is an RMM, so the population is the managed estate of whichever organizations the credential can see — in an MSP tenant that is every client organization at once.
- Source ID field: `id` on the device record. A record without it is skipped with `ninjaone: skipping device with no id: systemName=<name>`.
- Documentation evidence: NinjaOne's full API reference sits behind a login, so the contract here rests on the API's own shape rather than on a published document. `id` is the value every device-scoped route is addressed by — `/v2/device/{id}`, and the `/v2/device/{id}/...` sub-resources for software, disks, and volumes — which is the strongest available statement that it is the primary key for a device. The integration also preserves it as the `id` custom attribute, so the join key stays visible on the asset for anyone building the outbound direction later.
- Uniqueness scope: the NinjaOne tenant. `id` is a per-tenant auto-increment integer, not a UUID: a small NinjaOne instance numbers its devices from 1, so `1` means something different in every tenant. The script uses it **unprefixed and unscoped** — `id=str(id)` — even though `api_url` is required and identifies the regional instance. Two NinjaOne tenants imported into one runZero organization would collide, and the collision would be silent and systematic rather than occasional, because both tenants number from the same low integers. Scoping the id on the instance host, the way `snipe-it` does for the same reason, would close this.
- Cardinality: one row per managed device. `devices-detailed` is the deduplicated inventory view, not an event feed, so a device polled a thousand times is still one row.
- Stability: survives rename, address change, reinstall of the OS, and moves between organizations inside the tenant. Deleting a device from NinjaOne and re-deploying the agent mints a new id — the record is gone, not renumbered.
- Reuse behavior: not documented. Auto-increment integers are not normally recycled, but NinjaOne publishes no statement and the integration should not be read as relying on one.
- Presence: present on every device row observed. The guard exists for defensive reasons rather than because the field is known to be optional.
- Final runZero ID: the decimal device id as a string, unprefixed.
- Missing-ID behavior: skip the record, logging its `systemName`.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within one tenant; the tenant boundary is enforced by the credential rather than by the id, which is the weakness recorded above.

### Why the default is kept

The device id is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it. The usual companion preset `no-mac-break no-ip-break no-name-break` is not applied, and that is the right call for this source rather than an oversight: the record carries an `ipAddresses` list, a `macAddresses` list, and **four separate name fields** — `displayName`, `systemName`, `dnsName`, and `netbiosName` — all of which the mapping passes through as hostnames. This is contemporaneous agent-reported data about a live machine, not drifting inventory metadata, and it is exactly the material that should be allowed to merge a NinjaOne record onto an asset runZero already discovered. Suppressing the break flags would discard the richest correlation signal of any source in this library while protecting against churn that cannot happen — once the device id matches, no MAC, address, or name disagreement can fragment the asset, because those checks live only on the MAC, IP, and name match paths.

Two details of that mapping are worth knowing because they affect what gets matched:

- **`displayName` is an operator-editable label**, not a machine name. It is the friendly name shown in the NinjaOne console and is routinely set to a person or a location. It is passed as a hostname alongside the three real ones, so a device can contribute a hostname that no name service would ever resolve.
- **Devices with no address get no synthetic one.** An earlier shape assigned a placeholder address to address-less devices; because a placeholder is identical on every host, IP matching would have pulled every one of them onto the same asset. Those devices now correlate on MAC and hostname only, which is correct and is why some records legitimately arrive with no network interface.

### A defect worth noting

`build_assets()` contains `dns_name = item.get('')` — a read of the empty-string key, which is always absent and always yields `None`. The variable is never used; the hostname list reads `item.get('dnsName', '')` inline and is unaffected. `display_name` and `system_name` are assigned on the adjacent lines and are likewise unused. Nothing is broken by this, but the empty-key read looks like a typo for `dnsName` and should be removed rather than left to be mistaken for a working field reference.

## Future

- **Per-device software inventory.** `GET /v2/device/{id}/software` returns installed products per device, and the device id this integration already imports is the join key. That is the single most valuable addition: it populates runZero `Software` records for the whole managed fleet from an agent that reads the installed-products list directly, rather than inferring it from a network banner. The cost model is the obvious constraint — one request per device — so it belongs behind a parameter the way `include_alerts` does in comparable integrations here.
- **Patch state as findings.** NinjaOne tracks OS and third-party patch compliance per device and exposes it through the device sub-resources and the queries endpoints. Pending and failed patches are directly expressible as runZero findings on assets this integration already creates, and unlike scanner-derived findings they come with a remediation path the customer already owns.
- **The `/v2/queries/...` family as a bulk alternative to per-device calls.** NinjaOne exposes tenant-wide query endpoints for software, OS patches, volumes, and antivirus status that return rows for *all* devices with a cursor, rather than one device at a time. For any enrichment added here that is the shape to prefer — it turns an N-request-per-run enrichment into a paged sweep, which is the difference between a feasible and an infeasible feature on a large MSP tenant.
- **Alerts as an event feed.** `GET /v2/alerts` returns active alerts across the tenant with device references, which is the right shape for a poller: alerts carry a device id, so they attach to the assets this integration already creates without any correlation guesswork. This is the closest thing NinjaOne offers to an event stream — there is no webhook or push mechanism in the API surface this integration has seen.
- **Outbound: runZero discovery as NinjaOne device groups or custom fields.** NinjaOne supports custom fields on devices, written through the device API, and policies and views can be scoped by them. Pushing a runZero verdict — exposure, unexpected open service, site, criticality — into a NinjaOne custom field would let the RMM's own automation act on runZero's discovery. The device id is again the join key, and it is already imported, so the join is free. Note the real constraint: this writes to live device records that drive automation policies, so it needs a much tighter confirmation model than a scheduled read, and NinjaOne's script-execution endpoints are emphatically **not** the right surface for it.
- **Agent coverage-gap reporting needs no new endpoint.** runZero discovers devices with no agent; NinjaOne knows only devices that have one. In-scope runZero assets carrying no `custom_integration:ninjaone` source are RMM deployment gaps. The `lastContact`-style fields on the device record additionally separate "never enrolled" from "enrolled and stopped reporting", which are different problems with different owners.
- **MSP organization structure is available and unused.** `GET /v2/organizations` and `GET /v2/locations` describe the client organizations and sites a device belongs to. Importing the organization name as a tag or custom attribute would let an MSP filter runZero by client, which is the first question an MSP asks of any inventory. It is one extra request per run, not per device, and the device record already carries the organization reference needed to join it.

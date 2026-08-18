# Custom Integration: ExtremeCloud IQ

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## ExtremeCloud IQ requirements

- An ExtremeCloud IQ administrator account that is **local to the VIQ** you want to import. The integration signs in with `POST /login` and the token it receives is scoped to the VIQ the account belongs to.
- The account must be able to read devices (`GET /devices`). A read-only administrator role is enough; the integration issues no writes.
- The base API URL is `https://api.extremecloudiq.com`. This is the API host, which is not the same as the `extremecloudiq.com` web console you sign in to as a human.
- Two-factor authentication cannot be used. The `/login` endpoint takes a username and password only, and there is no second-factor step an unattended script can complete.

## Steps

### ExtremeCloud IQ configuration

1. Sign in to ExtremeCloud IQ as an administrator of the VIQ you want to import.
2. Create or choose a dedicated account for the integration, under the user administration section, with a role that can read devices. Note the exact username — it is normally an email address.
3. **If the account is an external or partner administrator**, API access is off by default and a local administrator has to enable it for that user; a token obtained by an external user otherwise only grants access to its own home instance, not the VIQ you are pointing at. Prefer a local account for this integration and avoid the problem entirely.
4. Confirm the credential works, and that the account lands on the right VIQ:

   ```bash
   curl -s -X POST https://api.extremecloudiq.com/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"runzero@example.com","password":"<password>"}'
   ```

   The response carries an `access_token` in JWT form. It is a bearer token valid for 24 hours (86400 seconds); the integration logs in once per task and does not need to refresh it.

5. The interactive API browser at `https://api.extremecloudiq.com/` lists every route and can issue test calls with that token if you want to confirm `GET /devices` returns what you expect.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - You may modify the script to filter inventory by site, device type, or other parameters.
    - All discovered assets will be enriched with additional metadata using `customAttributes`.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Username** (`username`): **required.** Your ExtremeCloud IQ username, normally an email address.
    - **Password** (`password`): **required**, stored as a secret.
    - **Extreme CloudIQ API URL** (`url`): optional, defaults to `https://api.extremecloudiq.com`. Override only for a regional or self-hosted deployment.
    - **TLS options** (`tls_*`): only `tls_disable_validation` reaches this integration — see the note under Asset identity below.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "ExtremeCloudIQ").
    - Toggle `Enable custom integration script` and paste in the finalized script.
    - Click `Validate` to ensure the script syntax is correct.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to run on your desired frequency.
    - Select a hosted Explorer that can execute the integration.
    - Click `Save` to schedule and start the task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename extreme-cloud-iq/extreme-cloud-iq.star \
  --kwargs url=https://api.extremecloudiq.com \
  --kwargs username=runzero@example.com \
  --kwargs password=NotTheRealPassword1 \
  --output ./extreme-cloud-iq-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`url` is optional and defaults to `https://api.extremecloudiq.com`, so `username` and
`password` are the only parameters a real run needs.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

If the log shows `Access token not found in response.`, the `/login` call did not return an
`access_token`. That is a credential problem, or an external-administrator account that has
not been granted API access, rather than a problem with the device query.

To check the `CONFIG` block and the HTTP and TLS wiring without touching the real API:

```bash
runzero script --filename extreme-cloud-iq/extreme-cloud-iq.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove ExtremeCloud IQ accepts the credential or that any device is
parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat extreme-cloud-iq/extreme-cloud-iq.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.extremecloudiq.com,username=runzero@example.com,password=<password>' \
  --output ./extreme-cloud-iq-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- The integration task will appear on the [Tasks page](https://console.runzero.com/tasks) and begin execution.
- The task will update existing assets in your runZero inventory or create new assets based on the data retrieved from ExtremeCloud IQ.
- You can search for enriched assets using the query: `custom_integration:ExtremeCloudIQ`.

## Asset identity

- Target entity: a **device managed by the VIQ** — an access point, a switch, or a router that has been onboarded into the ExtremeCloud IQ instance the credential belongs to. Note that this is the *infrastructure*, not the clients connected to it.
- Source ID field: `id`, falling back to `serial_number`.
- Documentation evidence: `id` is the device identifier in Extreme's published OpenAPI specification for CloudIQ and the key every per-device route is addressed by. `device_function`, the field used for the device type, comes from the same specification's `XiqDeviceFunction` enum, and every documented value is mapped except the two bare VPN-gateway forms — those name a role without naming a chassis, so they are left for runZero to fingerprint.
- Uniqueness scope: **the VIQ.** The `/login` token is scoped to the VIQ the account belongs to, so one credential sees exactly one instance. The value is used bare with no VIQ prefix, so two VIQs imported through the same custom integration would share an id space.
- Cardinality: one source row per managed device.
- Stability: the id is assigned when the device is onboarded and survives reboot, rename, address change, and firmware upgrade. Removing a device from the VIQ and re-onboarding it mints a new id.
- **The `serial_number` fallback mixes two id spaces.** A device that reports an `id` on one run and not on the next moves from the numeric id space to the serial space, which forks the asset — runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`. The collision risk is lower than it would be with a generic serial field, because an Extreme serial is vendor-assigned and unique to the hardware; the id-space switch is the real exposure.
- Reuse behavior: not documented. The primary value is a monotonic integer, so recycling after deletion cannot be excluded on shape alone.
- Presence: expected on every device. A record with neither field is skipped with `Skipping device with no id or serial number.`
- Final runZero ID: the raw value as a string.
- Missing-ID behavior: skip and log, after the fallback has been tried.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: CloudIQ issues a persistent per-device identifier and this integration uses it directly. It matters more here than for a roaming endpoint, because network infrastructure is exactly the class of device whose management address changes without the device changing.
- Verdict: **scoped authoritative** for a device onboarded in one VIQ.

Two operational notes that follow from how the requests are made rather than from the identity itself:

- **This integration authenticates and fetches over a `requests.Session`, which accepts only `insecure_skip_verify`.** The consequence is that of the shared TLS options on the credential, **only `tls_disable_validation` is honored** — a custom CA certificate, a client certificate, or a pinned thumbprint will not be applied to any request this integration makes. The shared HTTP retry budget does not apply either, so a rate-limited or briefly unavailable API is not retried; the run ends and the next scheduled task tries again.
- **Unmanaged devices are imported by default.** `SKIP_UNMANAGED` is `False` at the top of the script, so the `device_admin_state != "MANAGED"` check never fires. Set it to `True` to restrict the import to managed devices only.

## Future

- **Connected clients are the largest gap, and they are the reason to integrate a wireless platform at all.** CloudIQ knows every client associated to every access point — MAC address, IP address, hostname, operating system, username, and which AP and SSID it is on. Those are endpoints, many of which never appear in any other inventory: personal devices, contractor laptops, and the whole population of wireless-only IoT. This integration imports none of them; it imports the APs and switches themselves. Adding the active-client resource would turn it from a network-gear inventory into a genuine endpoint discovery source, complete with the MAC addresses that make correlation work. Confirm the exact route against the interactive API browser at `https://api.extremecloudiq.com/` before building on it.
- **Location hierarchy for physical placement.** CloudIQ models buildings and floors and places devices on them. Imported as custom attributes that makes "every asset in this building" a runZero search, and it is information no scan can infer — a physical fact rather than a network one. For wireless clients it is better still, since the AP a client is associated to locates the *client* to a floor.
- **Alarms and events as a change feed.** CloudIQ raises alarms for device state changes, and a time-windowed poll over them would show when a switch went offline or an AP was replaced, rather than only the current state a scheduled inventory sync captures. That is a different collector shape — a high-water mark over events, not a full walk.
- **Firmware version as vulnerability input.** The device record carries the running software version, which is already imported as a custom attribute by the catch-all field loop. CloudIQ itself publishes no CVE data, so vulnerabilities cannot be produced from this API directly — but the version is the join key against Extreme's published security advisories, which is how "every AP running an advisory-affected build" would become answerable. Stated plainly: **this API cannot produce `Vulnerability` records on its own.**
- **Outbound: push runZero context onto CloudIQ devices.** Device records support tagging and location assignment, so a runZero query could drive how devices are grouped and located in CloudIQ. This is the low-risk outbound direction; anything that reconfigures a network policy or reboots a device is not, and should not be attached to a scheduled task.
- **Infrastructure coverage-gap reporting.** Switches and APs that CloudIQ manages but runZero has never scanned are usually on management VLANs no Explorer reaches — worth knowing, because that is also where the management interfaces live. The reverse diff finds Extreme hardware on the network that was never onboarded into the VIQ, which is either a rogue device or an unmanaged one; both matter.
- **The catch-all attribute loop is doing a lot of quiet work.** Every field on the device record that is not already mapped is copied into custom attributes, with nested objects flattened. That makes the import resilient to CloudIQ adding fields, but it also means the attribute set is whatever the API happened to return rather than a curated list, and `view=full` returns a great deal. Deciding which of those fields deserve to be tags or first-class asset properties is the cheapest available improvement to how this data reads in runZero.

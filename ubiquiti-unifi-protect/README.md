# Custom Integration: Ubiquiti UniFi Protect

Cameras, doorbells, sensors, floodlights, chimes, viewports, and the NVR itself — a large class of unmanaged IoT hardware that active scanning characterises poorly.

This is the **Protect** application. The UniFi **Network** controller is covered separately by [`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/), and the two are complementary rather than overlapping: see *Asset identity* for why running both is worth more than running either.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the UniFi OS console over HTTPS.

## UniFi Protect requirements

- **UniFi Protect 5.3 or later.** The official Integration API landed in 5.3; older consoles have no such path and answer `404`.
- **Protect 7.1 or later is strongly recommended.** The API has only ever been added to, never trimmed, but the earlier releases are materially thinner:
  - Protect 6.x publishes no `type` (the model name) and no `guid` on any device.
  - Protect before 7.1 publishes **no MAC on the NVR record**, which leaves the console with no hardware identity at all. This integration skips it there rather than inventing one.
  - The `speakers`, `sirens`, `relays`, `fobs`, `bridges`, `link-stations`, and `alarm-hubs` collections are 7.x-only, which is why they sit behind a toggle that is off by default.
- A **UniFi OS API key**. Created in the local console UI: **Settings → Control Plane → Integrations → Create API Key**. You must be signed in as an administrator to create one.
- Network reachability to the console on 443.

### The API key is the same one the Network integration uses

The key is minted at the **console** level, not per application, so a single key authenticates both `/proxy/network/integration/v1/...` and `/proxy/protect/integration/v1/...`. If you already configured [`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/) against this console, reuse that credential.

### Confirm access before configuring runZero

```bash
curl -sk -H 'X-API-KEY: <api-key>' \
     'https://<console>/proxy/protect/integration/v1/meta/info'
# -> {"applicationVersion":"7.2.105"}
```

- `404` means Protect is older than 5.3, or Protect is not installed/running on this console. The response cannot distinguish the two.
- `401`/`403` means the key is wrong, revoked, or was created on a different console.

## Steps

### UniFi OS configuration

1. Sign in to the console's local web UI as an administrator.
2. Go to **Settings → Control Plane → Integrations**.
3. Click **Create API Key**, name it (e.g. `runzero`), and copy the value. It is shown once.
4. Verify it with the `curl` above from the Explorer host.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "UniFi Protect").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **UniFi console URL** (`url`): base URL of the console, e.g. `https://192.0.2.1`. The `/proxy/protect/integration/v1` path is appended automatically.
   - **UniFi API key** (`api_key`): the key created above.
   - **Collect cameras** (`collect_cameras`): optional; default enabled.
   - **Collect the NVR** (`collect_nvr`): optional; default enabled.
   - **Collect sensors** (`collect_sensors`): optional; default enabled.
   - **Collect lights, chimes, and viewers** (`collect_accessories`): optional; default enabled.
   - **Collect speakers, sirens, relays, fobs, bridges, link stations, and alarm hubs** (`collect_extended`): optional; default **disabled** — these paths 404 on Protect 6.x.
   - **Include disconnected devices** (`include_disconnected`): optional; default enabled.
   - **Maximum devices** (`max_devices`): optional; default 5000, 0 removes the cap.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the CLI

```bash
runzero script --filename ubiquiti-unifi-protect/ubiquiti-unifi-protect.star \
  --kwargs url=https://192.0.2.1 \
  --kwargs api_key='<api-key>' \
  --kwargs collect_cameras=true \
  --kwargs collect_nvr=true \
  --kwargs collect_sensors=true \
  --kwargs collect_accessories=true \
  --kwargs collect_extended=false \
  --kwargs max_devices=1000 \
  --kwargs tls_disable_validation=true
```

Wiring check only, without touching a console:

```bash
runzero script --filename ubiquiti-unifi-protect/ubiquiti-unifi-protect.star --validate
```

Two notes on the CLI:

- **`--kwargs` cannot carry a value containing both `=` and `,`.** The flag parser reads such a pair as CSV and invents a parameter from the remainder. UniFi API keys are alphanumeric, so this does not bite here, but it is worth knowing before pasting an arbitrary secret.
- **`scan` is a different command and is not what runs this.** `runzero scan` performs active network discovery against a target list and never loads a custom integration script. An active scan of the camera VLAN is a genuinely useful *companion* to this integration — it is how the cameras acquire IP addresses and open-service data, which Protect does not publish (see below) — but it is a separate operation, not a way to run this script.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with Protect model, state, and capability data.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ubiquiti-unifi-protect`.

## Asset identity

- Target entity: one **adopted Protect device** — a camera, doorbell, sensor, light, chime, viewport, or the NVR itself.
- Source ID field: `id`, published on every device type and declared required.
- What that id actually is: a **MongoDB ObjectId**, minted when Protect first creates the device document. Both examples in the official specification are 24 lowercase hex characters whose leading four bytes decode to sane creation timestamps, and Protect embeds MongoDB. The specification calls the field "The primary key of camera" — a *document* identity.
- Uniqueness scope: one console. The console hostname is part of the runZero id, and so is the `modelKey`, so a camera and a sensor that somehow shared an ObjectId could not collide.
- Cardinality: one document per physical device.
- Stability: stable for the life of an adoption. It survives renaming, firmware upgrades, moving the camera to a different port, and changing every setting on it.
- Reuse behavior: **no.** An ObjectId is minted per document and never reissued.
- Presence: `id` is required on every device type in every API version, so it is always present. A record arriving without one is skipped and logged with its `modelKey` and nothing else.
- Final runZero ID: `ubiquiti-unifi-protect:<console-host>:<modelKey>:<id>` — for example `ubiquiti-unifi-protect:192.0.2.1:camera:672094f900e26303e800062a`.
- Missing-ID behavior: skip. `new_uuid()` is not used anywhere in this script.
- Match behavior (set once in `CONFIG`): **`no-mac-break no-ip-break no-name-break`**. The id is one-per-physical-device and is therefore a legitimate foreign id that may drive merging; the break flags stop a disagreeing MAC or name from disqualifying a merge at first contact.
- Known limitation: **removing and re-adopting a device mints a new ObjectId**, which forks the asset. This is inference rather than a confirmed observation — Protect creates the document at discovery, and the ObjectId embeds a creation timestamp precisely because it is per-document — but the mechanism is clear. It is also unavoidable rather than a tuning mistake: the platform refuses, unconditionally and without consulting `matchBehavior`, to place two different foreign ids from the same custom integration on one asset. Reconcile such a fork in runZero.
- Verdict: **authoritative for adopted Protect hardware**, and *only* for adopted hardware — the Integration API has no pending/unadopted-device endpoint, so a camera powered on but not yet adopted is invisible here.

### Why the MAC is not the id

The MAC would survive re-adoption, and two mature Protect clients key on it. It is deliberately not used, for two reasons. `normalize_mac` clears the locally administered bit, so a MAC is the wrong shape for an identity in this repo generally. More to the point, **it is not necessary**: correlation on MAC happens through the network interface regardless of what the id is. Putting the ObjectId in the id and the MAC on the interface gets both properties — a stable foreign id *and* MAC-based merging — without spending the id on an address.

### This integration produces no IP addresses, and that is the point

The Protect Integration API publishes **no address of any kind** — no `host`, no `connectionHost`, no `ipAddress`, on any device type including the NVR. Nor does it publish firmware version, adoption state, uptime, or a last-seen time. Those fields exist only on Protect's internal, undocumented bootstrap API, which requires session auth and rejects the API key this integration uses.

Every asset from this integration therefore correlates on **MAC and name alone**. That is a limitation, but it is also exactly why running this alongside [`ubiquiti-unifi-network/`](../ubiquiti-unifi-network/) is worth more than running either: Protect cameras are PoE devices, so the Network controller sees them as clients *with* an IP and a switchport, and this integration supplies the model, capabilities, and state that Network does not know. Same MAC, one asset, both halves.

## Notes

- **What is imported.** One asset per device, carrying `id`, `guid`, `mac`, `name`, `type` (the model name, e.g. `UVC G4 Doorbell`), `modelKey` (the class), and `state`. Per class: cameras add HDR/mic/speaker/video-mode capability flags and smart-detect types; sensors add mount type, battery percentage and low flag, signal quality and strength, and the capability set; lights add on/dark state and the paired camera; chimes add paired camera ids; viewers add the stream limit; bridges add SoC platform and client counts; the NVR adds arm status.
- **`/nvrs` returns a single object despite the plural path.** Every other collection returns a bare array. Both shapes are handled.
- **There is no pagination anywhere in this API.** No endpoint declares a `limit`, `offset`, `page`, or `filter` parameter; responses are bare arrays. The paging loop from the Network integration must not be ported here — it would trip on the first call, because the response is a list rather than the `{data, totalCount, offset, limit}` envelope Network uses. Collections are streamed with `report_asset` per class.
- **Timestamps are epoch milliseconds as bare numbers**, not the RFC 3339 strings the Network API uses. They are floored to seconds before conversion because `from_timestamp` requires an int and rejects a float, and clamped to now because a future timestamp makes the platform reject the **entire asset record** rather than the field. Several Protect fields are legitimately in the future — `armMode.willBeArmedAt` is a *scheduled* arm time and `lcdMessage.resetAt` is when a doorbell message will be *removed* — so the clamp is not theoretical.
- **`name` is nullable on every device type.** An unnamed camera arrives as `{"name": null}`. It is filtered before reaching `hostnames`; such a device is carried by its MAC alone, and one with neither MAC nor name is skipped and logged.
- **`featureFlags` is the only genuinely optional field** in the device set — every other field is declared required, though many are also nullable. `type` and `guid` should be treated as absent regardless, because Protect 6.x does not publish them.
- **`sensor.batteryStatus` is deprecated** in favour of `wirelessConnectionState.batteryStatus`. The nested one is read.
- **A 404 is ambiguous and is reported as such.** The path is absent on Protect older than 5.3 *and* when Protect is not installed or has crashed. The integration stops at the `/meta/info` preflight rather than issuing a dozen more doomed requests, and deliberately does **not** fall back to the unofficial bootstrap endpoint.
- Request volume is 2–14: one `/meta/info` preflight, one `/nvrs`, and one per enabled collection. The preflight validates the key, proves reachability, and reads the version in a single call.
- Rate limiting: Protect advertises roughly 10 requests/second per API key via a draft `RateLimit-Policy` header. A full sweep is well under that. The shared HTTP helper retries transient statuses three times with exponential backoff and honors `Retry-After`.
- Consoles ship self-signed certificates. `OPTIONS_TLS` is exposed for that; it never defaults to insecure.
- **Verification status:** UniFi Protect runs only on UniFi OS hardware and has no container image, so **this integration was not exercised against a live console.** Field names, types, nullability, required-ness, response shapes, and the version differences above were taken from the official machine-readable OpenAPI specifications for Protect 7.2.105 and 6.2.83 at `developer.ui.com`, cross-checked against the `uilibs/uiprotect` and `hjdhjd/unifi-protect` reference clients. The fixture scenarios encode those shapes; they are a faithful hypothesis, not a capture. A live run against a real console is the outstanding validation step.

## Future

- **The 7.x device classes deserve promotion once 6.x is rare.** `collect_extended` is off by default only because those paths 404 on Protect 6.x. When the installed base has moved on, they should default on like the rest.
- **Users and access records.** `/v1/users` and `/v1/ulp-users` are already in the API. They describe people rather than devices, so they fail this repository's scope rule as assets, but they would enrich the console asset with an administrator inventory.
- **Event subscription.** `/v1/subscribe/devices` and `/v1/subscribe/events` are WebSocket endpoints, and there is no WebSocket module on this platform, so they are unreachable today. They are the only route to adoption and disconnection events as they happen rather than at poll time.
- **Liveviews and arm profiles as grouping metadata.** `/v1/liveviews` and `/v1/arm-profiles` describe how an operator has grouped cameras — usually by physical area. That maps onto runZero sites and tags better than anything currently imported.
- **Correlating with UniFi Network automatically.** Today the two integrations converge on the same asset by MAC, which works but is implicit. Emitting the Protect `id` as an attribute on the Network-side client record, or vice versa, would make the relationship explicit and queryable.
- **The internal bootstrap API is where the missing data lives** — IP address, firmware version, uptime, adoption state, `nvrMac`, and the uplink device are all on `/proxy/protect/api/bootstrap`. It is undocumented, requires session rather than API-key auth, and Ubiquiti may change it without notice. Building on it would roughly double the field set at the cost of a second credential and a standing compatibility risk. Worth revisiting only if Ubiquiti documents it or adds the fields to the Integration API.

## API documentation

- Protect Integration API reference and machine-readable specification: https://developer.ui.com/protect/
- Getting started with the official UniFi API (API key creation): https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API
- Announcement of the Integration API in Protect 5.3: https://github.com/uilibs/uiprotect/discussions/442
- Reference client, Python: https://github.com/uilibs/uiprotect
- Reference client, TypeScript (documents the internal bootstrap API's field set): https://github.com/hjdhjd/unifi-protect

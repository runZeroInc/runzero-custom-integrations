# Custom Integration: Ivanti Neurons - device inventory

Retrieve devices from Ivanti Neurons API "People and Devices" API endpoint (https://<hostname>/api/apigatewaydataservices/v1/devices) to enrich asset inventory in runZero.

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
``` 

Note that the script for this integration is `ivanti_neurons/ivanti_neurons.star`, not
`ivanti_neurons/ivanti_neurons.star`.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero
- An Explorer with outbound HTTPS access to your Neurons landscape host

##  Ivanti Neurons requirements

- An Ivanti Neurons tenant with the **People and Devices** module licensed. Ivanti lists a Neurons licence key per module as a requirement for API access, and the People and Device Inventory API carries a paid listing on Ivanti's developer portal. We could not establish the exact SKU name from public documentation — if the token call succeeds but `/devices` is refused, licensing is the thing to check with your Ivanti account team.
- An **App Registration** of type **Custom App**, which issues the three values this integration needs plus the URL they belong to.
- No role or scope needs choosing. Ivanti documents the platform default for these JWTs as a read-only scope, with GET endpoints authorized under that standard role; elevated scopes exist only for non-GET operations and for specific Patch Group registration types, neither of which applies here. There is no permission picker on a Custom App registration.

All four integration parameters come from the App Registration panel:

| Parameter | Where it comes from |
| --- | --- |
| `url` | The host part of the **Neurons Auth Url** |
| `tenant_id` | The GUID path segment of the same Auth Url |
| `client_id` | **Client ID** shown on the registration panel |
| `client_secret` | **Client secret** shown on the registration panel |

### Finding your landscape host

Neurons has **no per-tenant subdomain**. It serves a small set of fixed
regional "landscape" hosts, and yours is determined by where your tenant was
provisioned — not by anything you choose. Ivanti documents the hostname as a
pattern, `<landscape-code>***-sfc.ivanticloud.com`, with these codes:

| Code | Region |
| --- | --- |
| `nvu` | AMER |
| `fru` | EU |
| `uku` | EMEA / UK |
| `mlu` | APAC |
| `tku` | JPN |
| `ttu` | CAN |

In practice the production landscapes read `nvuprd-sfc.ivanticloud.com`,
`fruprd-sfc.ivanticloud.com`, and so on. Because Ivanti publishes a wildcard
rather than a fixed list, **do not assume the `prd` segment** — take the host
verbatim from your own Auth Url. Ivanti also documents a shortcut: the first
three letters of the hostname you log in to are your landscape code.

## Ivanti Neurons API Docs

- [Ivanti Neurons API](https://help.ivanti.com/ht/help/en_US/CLOUD/api/Shared-Content/welcome.htm)
- [Ivanti Product API Hub](https://www.ivanti.com/support/api)
- [Neurons APIs hostname (landscape table)](https://help.ivanti.com/ht/help/en_US/CLOUD/api/Shared-Content/hostname.htm)
- [People and Devices — authentication](https://help.ivanti.com/ht/help/en_US/CLOUD/api/PeopleDevices/peopledevices-authenication.htm)
- [People and Devices — devices endpoint](https://help.ivanti.com/ht/help/en_US/CLOUD/api/PeopleDevices/neuronsplatformDevices.htm)
- [App Registrations](https://help.ivanti.com/ht/help/en_US/CLOUD/vNow/app-registrations.htm)

## Steps

### Ivanti Neurons configuration

**Create a new app registration in the Neurons Console:**
1. In Ivanti Neurons, navigate to Admin > App Registrations.
2. Select New registration to open the New app registration panel.
3. From the drop-down, select Custom App.
4. Click Continue.
5. In the Custom App panel, optionally enter a Description for the registration e.g. "runZero integration"
6. Click Register to generate the authentication settings.
7. In the Complete this registration panel, the authentication settings, required to complete the registration, are provided:
   - *Neurons Auth URL* - the host part of this URL is the value for `url` when creating the Custom Integration credentials in the runZero console (see below).
   - *Client ID* - Copy the Client ID to the value for `client_id` when creating the Custom Integration credentials in the runZero console (see below).
   - *Client secret* - Copy the Client secret to the value for `client_secret` when creating the Custom Integration credentials in the runZero console (see below)

***Warning***: Ivanti states plainly that the registration settings will not display again once this panel is closed. Copy all three values, and the Auth Url, before clicking Finish.

8. Finish and close.
9. **Split the Auth Url into `url` and `tenant_id`.** The Auth Url has the form
   `https://<landscape-host>/<tenant-id>/connect/token`. For example, given:

   ```
   https://nvuprd-sfc.ivanticloud.com/a2db38ca-9594-4f09-a9da-47f446a9980f/connect/token
   ```

   the two values are:

   - `url` = `https://nvuprd-sfc.ivanticloud.com`
   - `tenant_id` = `a2db38ca-9594-4f09-a9da-47f446a9980f`

   Note that this integration does **not** call the `/connect/token` path in
   that URL. The Auth Url is where you read the host and tenant from; see the
   next section for what is actually requested.

10. Confirm the credential from the Explorer host before configuring anything in
    runZero:

    ```bash
    curl -s "https://nvuprd-sfc.ivanticloud.com/api/apigatewaydataservices/v1/token" \
      -H "X-TenantId: a2db38ca-9594-4f09-a9da-47f446a9980f" \
      -H "X-ClientId: <client_id>" \
      -H "X-ClientSecret: <client_secret>"
    ```

    A working credential returns a JSON object containing `access_token`.

[How to authenticate to Neurons API](https://help.ivanti.com/ht/help/en_US/CLOUD/api/Shared-Content/authenticate_api.htm)

### A note on the token call

The People and Device Inventory API's token request is unusual, and it is easy
to get wrong by reading the wrong Ivanti page. It is a **`GET`**, to
`/api/apigatewaydataservices/v1/token`, carrying the credentials in
**headers** — `X-ClientId`, `X-ClientSecret`, and `X-TenantId` — not a `POST`
with a form body.

Other Neurons APIs, such as App Distribution, use the conventional
`POST https://<host>/<tenantId>/connect/token` with
`grant_type=client_credentials` form-encoded in the body. That is the shape the
Auth Url points at, and it is **not** what this integration uses. Do not
conflate the two when troubleshooting.

Ivanti's documented response schema for the token call lists only
`access_token`; a token lifetime is mentioned in prose but not specified, so
this integration does not attempt to pre-emptively refresh.

The script reads that field and sends its value as the bearer token. A response
that is not a JSON object, or one that carries no `access_token` — the shape a
rejected client pair produces on an endpoint that reports failure in the body
rather than the status line — ends the run with a logged reason and no device
request.

### Pagination and the 5-minute scroll window

The devices endpoint pages with an OData `@odata.nextLink` that carries a
`$scrollID`, and Ivanti documents that **a scrollID expires 5 minutes after it
is issued**. Ivanti also notes that a response typically carries only 10 to 20
objects, and there is no page-size parameter to raise.

Together those two facts set the real constraint on this integration: a large
device inventory means a great many small requests, each of which must be
issued within five minutes of the previous response, with no way to resume a
walk that stalls. A slow link, an aggressive proxy, or a rate limit between the
Explorer and Ivanti will surface as a truncated import rather than an error.

The walk follows Ivanti's own instruction — keep calling the next link until the
response is empty — so it ends when `@odata.nextLink` is absent or the page
carries no rows. `@odata.count` is used only as an upper bound, to stop a
landscape that keeps handing out next links; it no longer bounds the walk
directly, which is what used to drop the final page. Whatever arrived before a
stall is imported rather than discarded.

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - **Ivanti Neurons URL** (`url`): the landscape host from the Auth Url, for example `https://nvuprd-sfc.ivanticloud.com`.
    - **Tenant ID** (`tenant_id`): the GUID path segment of the Auth Url.
    - **OAuth client ID** (`client_id`): the Client ID from the app registration.
    - **OAuth client secret** (`client_secret`): the Client secret from the app registration.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon 
    - Toggle `Enable custom integration script` to input your finalized script
    - Click `Validate` to ensure it has valid syntax
    - Click `Save` to create the Custom Integration 
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created in steps 2 and 3
    - Update the task schedule to recur at the desired timeframes
    - Select the Explorer you'd like the Custom Integration to run from
    - Click `Save` to kick off the first task 

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm an app registration and see what the device inventory returns before
scheduling anything. Note the script filename — this directory does not follow
the usual `<slug>/<slug>.star` convention:

```bash
runzero script --filename ivanti_neurons/ivanti_neurons.star \
  --kwargs url=https://nvuprd-sfc.ivanticloud.com \
  --kwargs tenant_id=a2db38ca-9594-4f09-a9da-47f446a9980f \
  --kwargs client_id=AppReg_customClientType_a1b2c3d4e5f60718 \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Njc4OTA \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./ivanti-neurons-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**Run this one verbose.** There are no tuning parameters — no page size, no
cap, no filter — so the only way to see the scroll walk described above is the
request log. With 10 to 20 devices per response and a five-minute scrollID
window, `--verbose` is how you find out whether the walk is completing or
quietly stopping partway.

The four parameters divide cleanly by failure mode:

- Wrong `url` — connection or 404. The landscape host is fixed; you cannot guess it.
- Wrong `tenant_id` — the token call fails even though the client pair is correct, because the tenant is a header on that request, not a path segment.
- Wrong `client_id` / `client_secret` — the script prints `authentication failed` with the status and a snippet of the body, or `authentication response carried no access_token` if the landscape reports the rejection with a 200. Either way the run stops before `/devices` is called.
- All four correct but no devices — licensing, or a genuinely empty tenant.

`--kwargs` takes the value verbatim as long as the whole argument holds a single
`=`, so a comma inside a value is passed through intact. Only a value that
*also* contains an `=` flips the flag into comma-separated parsing, and then the
value is cut at the first comma — the remainder either becomes a fabricated
second parameter or aborts the run with `must be formatted as key=value`.
Nothing in this parameter set normally contains either character, but a client
secret is opaque; if one arrives with both, wrap the whole argument in a second
pair of quotes: `--kwargs '"client_secret=ab=cd,ef"'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename ivanti_neurons/ivanti_neurons.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Ivanti issues a token, and
it does not exercise the `$scrollID` walk at all — which is the part of this
integration most likely to misbehave against a real tenant.

The fixtures under `ivanti_neurons/tests/fixtures/` cover the token exchange,
the scroll walk, and the degraded envelopes offline — `paged` walks three pages
and checks the last one is not dropped, `scroll-ends-early` stops on an absent
next link, `degraded-envelope` survives a page with no `@odata.count` and an
error document with no `value`, `token-rejected` stops before `/devices`, and
`missing-network` imports devices that report no adapter:

```bash
python3 tests/run.py ivanti_neurons
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat ivanti_neurons/ivanti_neurons.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://nvuprd-sfc.ivanticloud.com,tenant_id=a2db38ca-9594-4f09-a9da-47f446a9980f,client_id=AppReg_customClientType_a1b2c3d4e5f60718,client_secret=<secret>' \
  --output ./ivanti-neurons-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way; prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration 
- The task will update the existing assets with the data pulled from the Custom Integration source 
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:ivanti-neurons`

## Asset identity

- Target entity: a **device record in the Neurons People and Devices inventory** — an endpoint Neurons knows about through its discovery and agent estate.
- Source ID field: `DiscoveryId`, falling back to `DeviceID`.
- Documentation evidence: **which of the two Ivanti treats as primary could not be established.** Both are published on the device object and both are imported as custom attributes (`discoveryId` and `deviceId`), but Ivanti's People and Device Inventory documentation does not describe either one's lifecycle, and the narrative material that might is not publicly retrievable. The names are suggestive — a discovery id would be minted by the discovery pipeline, a device id by the device record — but nothing here rests on that reading, and the preference order in the code is not backed by a vendor statement.
- Uniqueness scope: the tenant, which is supplied as the `X-TenantId` header on the token call. The value is used bare with no tenant prefix.
- Cardinality: one source row per device record. Because Neurons aggregates several discovery sources, a device seen by two of them may or may not collapse to one record inside Neurons; that reconciliation happens on Ivanti's side and is invisible from here.
- Stability: **not established.** Neither field's behavior across a re-discovery, an agent reinstall, or a hardware refresh is documented publicly.
- Reuse behavior: not documented.
- Presence: a record with neither field is skipped with `ivanti-neurons: skipping asset with no DiscoveryId/DeviceID: name=<DeviceName>`.
- Final runZero ID: the raw value as a string.
- Missing-ID behavior: skip and log, after the fallback has been tried.
- **The fallback mixes two id spaces.** A record that reports a `DiscoveryId` on one run and only a `DeviceID` on the next moves between them, which forks the asset — runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`, so no flag recovers the merge.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Defensible under the governing rule *if* `DiscoveryId` is persistent, which is precisely what could not be verified. Recorded as a gap rather than presented as a decision.
- Verdict: **scoped authoritative if `DiscoveryId` is stable; unverified.**

**Correlation here rests on IP address and hostname only, because no MAC is imported.** The network interface is built as `network_interface(ips=address_list, mac=None)` — the MAC argument is passed as `None` unconditionally, and no MAC field is read from the device record anywhere in the script. Addresses come from `Network.TCPIP`, whose values are collected with `list(tcpip.values())`. For a fleet of DHCP endpoints that is a weak basis for merging, and it is the most consequential limitation of this integration as it stands.

### Fixed defects

Four run-aborting behaviors have been corrected. They are recorded here because
each changes what a run does on a real tenant, and because Starlark has no
exception handling — every one of them killed `main()` outright and lost every
device already collected, rather than degrading to a partial import.

- **The bearer token was the whole response document.** `get_token` returned `response.body` and `get_assets` sent it as `Authorization: Bearer <body>`, but the token call answers with **a JSON object containing `access_token`**, as this README's own verification step states. The `access_token` field is now extracted and sent on its own; a response that is not an object, or has no such field, stops the run before `/devices` instead of sending a malformed credential. **This was almost certainly why the device call failed against a live tenant.**
- **A response without `@odata.count` ended the run.** `total_assets = data.get('@odata.count')` yields `None` when the key is absent, and the loop condition then evaluated `None - 1`. The count is now adopted only when it really is a number, and the walk no longer depends on it.
- **A response without a `value` key ended the run.** `assets = data['value']` was direct key access, so an error document aborted the script. The shape is now checked; an envelope with no rows array ends the walk with `ivanti-neurons: response carried no value array` and keeps everything already collected.
- **The scroll walk had no termination guard.** When `@odata.nextLink` was absent the URL became `None` and the next iteration requested it. An absent next link now ends the walk, which is Ivanti's documented stopping condition.

A fifth, quieter defect went with them: the walk was bounded by
`len(assets_all) < @odata.count - 1`, which stopped one record short of the
tenant's own reported total and silently dropped the final page. The bound is
now `>= @odata.count` and serves only as a backstop against a landscape that
keeps handing out next links.

## Future

- **Import the MAC addresses.** This is the highest-value change available and it needs no new endpoint: the People and Devices record carries adapter detail alongside the `Network.TCPIP` addresses this integration already reads, and a MAC is what would let these assets merge reliably with everything else in runZero. Correlating a DHCP fleet on address and hostname alone is the weakest form of correlation available.
- **Software inventory is the module's headline capability and none of it is imported.** Neurons People and Device Inventory is, among other things, a software-asset-management product: it tracks installed applications and their versions per device. Those are `Software` records, and they are the main reason to integrate an inventory platform rather than an EDR. The device endpoint this integration calls returns the device shell only.
- **Patch state as findings.** Ivanti Neurons for Patch Management knows which updates each device is missing. Where an update names CVEs, those map onto runZero `Vulnerability` records — and unlike behavioral detections these genuinely are CVEs, so runZero's vulnerability reporting would recognise them. This is a separate module with separate licensing, so confirm entitlement before designing around it.
- **The `$scrollID` walk needs to be made resumable, or replaced.** Ten to twenty objects per response, no page-size parameter, and a five-minute expiry per scroll id together mean a large tenant is thousands of small sequential requests that cannot be resumed if one stalls. If the API exposes any filter — a modified-since window in particular — an incremental sync would sidestep the problem entirely rather than making the full walk more robust. That is the change to investigate first.
- **People, not just devices.** The module is *People and Devices*, and the people half carries device-to-owner assignment. Attributing an asset to a person is something runZero cannot derive from the network, and it is what turns an inventory entry into something actionable.
- **Outbound: push runZero discoveries into Neurons.** An inventory platform's blind spot is anything without an agent or a discovery connector reaching it, which is exactly what runZero finds. Whether the People and Devices API accepts writes **could not be established** from public documentation — the platform default for these JWTs is documented as read-only, with elevated scopes existing for non-GET operations, which implies a write surface exists somewhere but not that this module exposes one.
- **Coverage-gap reporting works today.** Devices Neurons knows about that runZero has never seen, and assets runZero discovers with no Neurons record, are both computable from what is already imported. The second set is the more interesting one: it is the population an inventory-driven security programme believes does not exist.

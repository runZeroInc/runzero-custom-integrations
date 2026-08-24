# Custom Integration: Netskope

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Netskope requirements

- A **REST API v2** token. The v1 tokens are a different, tenant-wide credential and are not what this integration uses.
- The token must have the endpoint `/api/v2/events/datasearch/clientstatus` added to it with **Read** privilege. A v2 token carries an explicit list of endpoint paths; a token that authenticates fine but was never granted this path returns an authorization error rather than data, which is the most common reason the task runs and imports nothing.
- Your tenant URL, of the form `https://<tenant>.goskope.com`. This is the hostname you sign in to the Netskope UI with. The `/api/v2/...` path is appended by the integration, so configure the host only.
- If your tenant enforces IP allowlisting for REST API access, the Explorer's egress address has to be on that list.

## Steps

### Netskope configuration

1. Sign in to the Netskope UI as an administrator and go to **Settings > Tools > REST API v2**.
2. Click **New Token**.
   - Give it a name, for example `runzero`.
   - Set the token expiration. An expiring token has to be rotated on that cadence or the task starts failing.
   - Click **Add Endpoint** and add `/api/v2/events/datasearch/clientstatus`, then set its privilege to **Read** (which grants `GET`). Read and write would additionally grant `POST`, `PUT`, `PATCH`, and `DELETE`, and is not needed here.
3. Save. The token value is displayed **once**, on the confirmation page, with a **Copy Token** button. There is no way to retrieve it afterwards.
4. Note your tenant URL, for example `https://acme.goskope.com`.
5. Confirm the token from the Explorer host. The documented v2 header is `Netskope-Api-Token`; some tenants also accept it as a bearer token, so the integration sends both forms with the same value and either one authenticates:

   ```bash
   curl -s -H 'Netskope-Api-Token: <token>' \
     'https://acme.goskope.com/api/v2/events/datasearch/clientstatus?limit=1'
   ```

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify the NETSKOPE_API_GROUPBYS attribute, if appropriate. By default this script groups by nsdeviceuid to avoid duplicate records. Modifying this variable could alter what attributes are available.
    - Modify the NETSKOPE_API_ATTRIBUTES array. These are the attributes that runZero will ingest. It is passed to Netskope as part of the API call.
    - Modify datapoints uploaded to runZero as needed. If you modify the NETSKOPE_API_ATTRIBUTES, you will also need to update `ImportAssets` so that the asset is included in the import. 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Netskope tenant URL** (`url`): your tenant hostname, e.g. `https://acme.goskope.com`.
    - **API token** (`api_token`): the REST API v2 token from the steps above.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "netskope").
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
runzero script --filename netskope/netskope.star \
  --kwargs url=https://acme.goskope.com \
  --kwargs api_token=3f8c1a95b27de640c5931ae7024fb8d6 \
  --output ./netskope-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

If the run completes but reports nothing, check the token's endpoint list before anything
else. A v2 token that has not had `/api/v2/events/datasearch/clientstatus` added to it with
Read privilege authenticates successfully and then returns no usable data — which looks
identical to an estate with no clients.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename netskope/netskope.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Netskope accepts the token or that any client record is parsed.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py netskope
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat netskope/netskope.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://acme.goskope.com,api_token=<token>' \
  --output ./netskope-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:netskope`.

## Asset identity

- Target entity: a device running the Netskope Client (the steering agent). This is not Netskope's whole view of the world — it is the endpoints that have the client installed and have reported a status event. Unmanaged devices reaching cloud apps through a Netskope proxy without the client never appear.
- Source ID field: `_id.nsdeviceuid`, falling back to `device_id`. A record carrying neither is skipped with `netskope: skipping record with no nsdeviceuid/device_id`.
- Documentation evidence: the shape of `_id` is not an accident of the response — it is a consequence of the request. The script sends `groupbys=nsdeviceuid` to `GET /api/v2/events/datasearch/clientstatus`, and the endpoint answers an aggregated query by returning the grouping key inside an `_id` object. `nsdeviceuid` is therefore the field this integration explicitly asked the API to collapse the event stream onto, which is a stronger statement about identity than reading a field off a record would be: it is the key Netskope itself uses to reduce many client-status events to one device.
- Uniqueness scope: the tenant. `ns_tenant_id` is present on every record and is captured as a custom attribute, but it is **not** used to scope the foreign id — the id is the bare `nsdeviceuid`. One credential addresses one tenant, so this only matters for an account importing two Netskope tenants into one runZero organization; there, two devices could in principle collide on a shared id. Scoping the id on `ns_tenant_id` or on the configured tenant hostname would close that, and every other integration in this library that faces the same choice does so.
- Cardinality: one asset per device, guaranteed by the `groupbys`. Without it the endpoint is an event stream and one device would produce one record per status change — which is the reason the parameter exists and the reason the note under **runZero configuration** warns against editing it casually.
- Stability: `nsdeviceuid` is Netskope's own device identifier and survives rename, address change, and reconnection. Client reinstall is the case to watch: nothing public states whether a fresh enrollment reuses the previous `nsdeviceuid`, and the record carries a `deleted` flag (imported as a custom attribute) that implies removal is a state a record enters rather than a row that vanishes. Assume a reinstall can mint a new value; the consequence is a second runZero asset, not a collision.
- Reuse behavior: not documented.
- Presence: the fallback to `device_id` exists because `_id` is not always well-formed — note the `or {}` guard, which is there because a record can arrive with `_id` present and null. `device_id` is also imported as a custom attribute in its own right, so a record that fell back is identifiable after the fact by comparing the two.
- Final runZero ID: the raw `nsdeviceuid` (or `device_id`), unprefixed and unscoped.
- Missing-ID behavior: skip the record and log. No fallback id is synthesized.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: scoped authoritative, with the scope enforced by the credential rather than by the id.

### Why the default is correct, and why `mac-break` matters more here than usual

`nsdeviceuid` is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it. The usual companion preset `no-mac-break no-ip-break no-name-break` would be a mistake in this specific case, and the reason is a property of the payload rather than a general principle.

The `clientstatus` record carries **MAC addresses and no IP at all**. That is not a gap in the mapping — the event genuinely has no address field, which is why the script builds interfaces from `mac_addresses` alone and why a hardcoded `127.0.0.1` was removed from this code path. So the MAC is the *only* network identifier this source contributes, and it is the only way a Netskope record can find the asset runZero already discovered by scanning. Relaxing `mac-break` would remove the guard on the single correlation signal the source has, in exchange for protecting against churn that cannot occur — a foreign-ID match is never disqualified by a conflicting MAC, because that check exists only on the MAC match path. `ip-break` and `ip-match` are inert here for the same reason: there is no address to match on.

The related consequence worth stating plainly: a device whose MAC addresses Netskope cannot read, or which reports only virtual adapters, arrives with **no network interface and no address**, and correlates on hostname alone.

## Future

- **The rest of the `datasearch` event families.** `clientstatus` is one of several; `GET /api/v2/events/datasearch/{eventtype}` also serves `alert`, `page`, `application`, `audit`, `infrastructure`, and `network`, all with the same `fields`/`groupbys`/`offset`/`limit` contract this integration already implements. `alert` is the interesting one for runZero: Netskope alerts are per-device policy and threat events, and grouping them by `nsdeviceuid` would attach them to the assets this integration already creates, as findings rather than as attributes. `application` would answer "which cloud services does this device actually reach", which is inventory data no scanner can produce.
- **Private Access as a network-visibility source.** Netskope's ZTNA side knows which private applications a device is entitled to and connects to. Publishers and private apps are managed through the v2 API (`/api/v2/steering/apps/private` and the publisher endpoints), and importing the private-app definitions would give runZero a list of internal services that are being reached through the tunnel — including ones in segments no Explorer sits in. That is a genuinely additive coverage story rather than an enrichment of existing assets.
- **Outbound: runZero asset lists as Netskope steering or policy scope.** This is the direction with the most leverage and the one that needs the most care. The v2 API exposes URL lists and file-hash lists (`/api/v2/policy/urllist`, and the corresponding update-and-deploy calls) which policies reference by name, so a runZero query could maintain a Netskope list rather than an operator maintaining it by hand. The honest limitation: those list types are URL- and hash-shaped, not device-shaped. Netskope's device-scoped policy targeting is driven by device classification and by user/group membership from the directory, neither of which is a list a third party writes into. So runZero *can* feed Netskope policy, but through the destination side rather than by pushing an asset list — and any such integration edits live inline-policy inputs, which needs a far tighter confirmation model than a scheduled read.
- **Device classification as a runZero attribute, and as a gap report.** `device_classification_status` is already imported as `userInfoDeviceClassificationStatus`. It is Netskope's verdict on whether an endpoint is managed, and diffing it against runZero's own inventory is directly actionable: runZero assets with no `custom_integration:netskope` source are devices with no Netskope Client at all, and imported assets whose classification is *not* managed are devices with the client but failing the managed test. Those are two different remediation queues and the data to separate them is already in the import.
- **Incremental collection instead of a full sweep.** Every run pages the entire client population in 20,000-record pages with no time bound. The `datasearch` endpoints accept `timeperiod` and `starttime`/`endtime` parameters, so a bounded window would cut the request cost on a large tenant substantially. The reason it is not done today is that a windowed query returns only devices that changed status inside it, which silently stops refreshing quiet devices — so this is a trade, not a free improvement, and it belongs behind a parameter.
- **v1 iterator endpoints are deliberately not used.** Netskope's v1 API exposes an event iterator with a server-side cursor that is well suited to incremental collection, but v1 tokens are a different, tenant-wide credential with far broader access than the endpoint-scoped v2 token this integration requires. That trade — a better paging model for a much weaker credential — is not worth making.

# Custom Integration: Nexthink

## runZero requirements

- Superuser access to the runZero Custom Integrations configuration
- Access to create credentials and ingest tasks in runZero

## Nexthink requirements

- A Nexthink Infinity tenant, and an administrator account that can create API credentials.
- An **OAuth client credential** (Client ID and Client Secret) with the **NQL API** permission.
- A **saved NQL API query**, created before the integration is run. The export API accepts only a query ID — it will not take raw NQL — so this is a hard prerequisite, not a convenience.
- Your instance name and region, which together form the two hostnames the integration needs.

### Finding the two hostnames

Nexthink splits authentication and data onto different hosts, and both are
required parameters:

```
auth_url   https://<instance>-login.<region>.nexthink.cloud
api_url    https://<instance>.api.<region>.nexthink.cloud
```

`<instance>` is the subdomain of your tenant URL — `acme` in
`acme.api.us.nexthink.cloud`. `<region>` is one of **`us`** (United States),
**`eu`** (European Union), **`pac`** (Asia-Pacific), or **`meta`** (Middle East,
Turkey, and Africa). Nexthink's documentation says only "replace instance by the
name of the instance" and describes no discovery page for it, so take it from the
URL you use to reach the product.

### Creating the API credential

1. In the Nexthink web interface, open **Administration → API credentials** (under **Account Management** in the left navigation).
2. Click **New OAuth client credentials**.
3. Give it a name and description, then tick the permissions it needs. These are **checkboxes on the credential**, not OAuth scope strings — the available set is NQL API, Campaigns API, Workflows API, Enrichment API, Remote Actions API, Data management, Spark API, and Hypervisor API. For this integration tick **NQL API only**.
4. Click **Save and generate credentials**. The Client ID and Client Secret are displayed **once**; there is no way to retrieve the secret afterwards.

The OAuth scope is a separate thing and is not a per-API selector.
`service:integration` is the only scope string Nexthink defines, and the
integration sends it as a constant. The `scope` parameter exists so it can be
overridden if that ever changes; leave it at its default.

### Creating the saved NQL query

Your own user account needs the **Manage all NQL API queries** permission
(granted in the Administration section of the user profile) before this menu
appears.

1. Open **Administration → NQL API queries** (under **Content Management**).
2. Click **New NQL API query**.
3. Set the **Query ID**. It must match `^#[a-z0-9_]{2,255}$` — a leading `#`, then lowercase letters, digits, and underscores. `#runzero_integration` is valid and is this integration's default.
4. **The Query ID cannot be changed after creation.** Getting it wrong means creating a second query and deleting the first, so decide the name before you save.
5. Write a query returning the fields listed below, then save it.

## What this integration imports

The script imports assets from Nexthink using NQL export workflow and maps:

- `id` from `device.uid`
- `hostnames` from `device.name`
- `os` from `device.operating_system.name`
- `osVersion` derived from `device.operating_system.build`
- `networkInterfaces` from `device.collector.local_ip`
- `deviceType` from `device.hardware.type`, which Nexthink documents as the
  device form factor. `laptop` and `desktop` map to runZero's **Laptop** and
  **Desktop**; the third documented value, `virtual`, says the device is a
  hypervisor guest rather than naming a chassis, so it is left unmapped and
  runZero's own fingerprinting decides. A query that does not select this field
  simply produces no device type.
- `customAttributes`:
  - `nexthink.first_seen`
  - `nexthink.last_seen`
  - `nexthink.hardware.manufacturer`
  - `nexthink.hardware.model`
  - `nexthink.hardware.type`
  - `nexthink.hardware.chassis_serial_number`
  - `nexthink.operating_system.build`
  - `nexthink.collector.local_ip`

## Steps

### 1. Configure Nexthink

1. Create the OAuth client credential with the **NQL API** permission, as described under [Creating the API credential](#creating-the-api-credential) above.
2. Create the saved NQL API query, as described under [Creating the saved NQL query](#creating-the-saved-nql-query) above, and note its `#`-prefixed Query ID.
3. Ensure your NQL query returns these fields:
   - `device.uid`
   - `device.name`
   - `device.operating_system.name`
   - `device.operating_system.build`
   - `device.collector.local_ip`
   - `device.hardware.manufacturer`
   - `device.hardware.model`
   - `device.hardware.type`
   - `device.hardware.chassis_serial_number`
   - `device.first_seen`
   - `device.last_seen`

### 2. Configure runZero credential

1. In runZero, create a credential of type **Custom Integration Script Secrets**.
2. The script embeds its `CONFIG` block, so the credential form is generated from it. Fill in:
   - **Nexthink authentication URL** (`auth_url`): `https://<instance>-login.<region>.nexthink.cloud`
   - **Nexthink API URL** (`api_url`): `https://<instance>.api.<region>.nexthink.cloud`
   - **Client ID** (`client_id`): the Client ID from the OAuth credential
   - **Client secret** (`client_secret`): the Client Secret from the OAuth credential
   - **NQL query ID** (`query_id`): optional; your saved query ID, defaults to `#runzero_integration`
   - **OAuth scope** (`scope`): optional; defaults to `service:integration`. Leave it alone.
   - **Export poll timeout (seconds)** (`poll_timeout`): optional; defaults to `300`. How long to wait for the asynchronous export to complete before giving up. Raise it if a large estate's export logs `NQL export did not complete in time`.

### 3. Configure runZero custom integration

1. Create a new custom integration in runZero.
2. Paste the script from [nexthink/nexthink.star](nexthink/nexthink.star).
3. Validate and save.

### 4. Create an ingest task

1. Create a custom ingest task.
2. Select the credential and custom integration.
3. Select an explorer.
4. Save and run.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and a query ID against a real tenant. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename nexthink/nexthink.star \
  --kwargs auth_url=https://acme-login.us.nexthink.cloud \
  --kwargs api_url=https://acme.api.us.nexthink.cloud \
  --kwargs client_id=0oa4f9k2mQwErTyUi7x8 \
  --kwargs client_secret=Xq7-fake-secret-not-a-real-credential-9Zt \
  --kwargs query_id=#runzero_integration \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/nexthink-run --overwrite
```

Note the `#` in `query_id`: most shells treat `#` as a comment character only at
the start of a word, so `query_id=#runzero_integration` is safe unquoted, but
quoting the whole pair (`--kwargs 'query_id=#runzero_integration'`) is the
habit worth having.

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

This integration is asynchronous, and watching a command-line run is the clearest
way to see where it gets stuck. It performs four steps in order:

1. `POST <auth_url>/oauth2/default/v1/token` — Basic auth with the client ID and
   secret, with `grant_type=client_credentials` and `scope=service:integration`
   in the form-encoded body.
2. `POST <api_url>/api/v1/nql/export` with a JSON body of
   `{"queryId": "<query_id>"}` — returns an `exportId`.
3. `GET <api_url>/api/v1/nql/status/<exportId>` — polled until `status` reaches
   `COMPLETED`, for up to `poll_timeout` seconds (default 300; raise it for a
   large estate whose export takes longer). The other states are `SUBMITTED`,
   `IN_PROGRESS`, and `ERROR`.
4. A download of `resultsFileUrl`, which is a pre-signed URL. **No `Authorization`
   header is sent to it** — adding one makes the storage backend reject the
   request with `Only one auth mechanism allowed`.

A failure at step 1 is the credential. A failure at step 2 with a 4xx is almost
always the `query_id`: the export API matches it exactly, and a query ID that
does not exist is not distinguishable from one you lack permission to run.

There are no paging or limit parameters, because the export workflow returns the
whole result set. That is the point of using it — the `execute` endpoint caps at
1,000 rows and this one does not — so a first run reads everything the saved
query selects. If you want a small first run, save a narrower query.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real tenant:

```bash
runzero script --filename nexthink/nexthink.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never completes a token
exchange, never starts an export, and never parses a real row.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'auth_url=https://acme-login.us.nexthink.cloud,api_url=https://acme.api.us.nexthink.cloud,client_id=...,client_secret=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py nexthink
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a device running the Nexthink Collector. Nexthink is a digital-employee-experience platform, so the population is the managed endpoint estate — laptops, desktops, and virtual desktops with the agent — and nothing else. Servers, network gear, and unmanaged devices are outside it by construction.
- Source ID field: `device.uid`, read from the NQL export result row. A row without it is skipped with a bare `continue`.
- Documentation evidence: `device.uid` is Nexthink's documented device identifier in the NQL data model — it is the field the `device` table is keyed on and the one every other NQL table joins to a device with. It is not derived from anything the Collector observes on the network, which is what separates it from `device.name` and from the hardware serial.
- Uniqueness scope: the Nexthink instance. The value is used verbatim: no vendor prefix, no scoping on `api_url`, and nothing derived from the tenant. Two Nexthink instances imported into one runZero organization would share a namespace. That is a narrower risk than usual here, because `api_url` encodes the instance (`https://<instance>.api.<region>.nexthink.cloud`) and is already a required parameter — the material to scope the id exists and simply is not used.
- Cardinality: one row per device, and this is a property of the saved query rather than of the API. **An NQL query that aggregates, joins to a per-event table, or selects a time series can return many rows per device**, and the script does not deduplicate — it builds one `ImportAsset` per row. Several rows sharing a `device.uid` produce several `ImportAsset` objects with the same foreign id, which the platform then merges onto one asset, last-write-wins on every field. The import will not break, but attribute values become arbitrary. Keep the saved query one row per device.
- Stability: `device.uid` survives rename, address change, OS upgrade, and hardware refresh of individual components. A Collector reinstall on a rebuilt machine is the case Nexthink does not publish a guarantee for; assume it can mint a new uid, which produces a second asset rather than a collision.
- Reuse behavior: not documented.
- Presence: guaranteed only if the saved query selects it. This is the one identity property here that is under the **operator's** control rather than the vendor's, and it is why `device.uid` heads the required-field list under **Configure Nexthink** above. A query that omits it imports nothing at all, silently — every row fails the `if not asset_id` test and the run reports zero assets with no error.
- Final runZero ID: the raw `device.uid`, unprefixed.
- Missing-ID behavior: skip the row. There is no log line, so a query missing the field is indistinguishable in the task log from a query that matched no devices. The `No rows returned from Nexthink export workflow` message under **Troubleshooting** covers the empty-export case, not this one.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within the instance, conditional on the saved query selecting the field.

### Why the default is kept, and the one field that argues for relaxing it

`device.uid` is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it.

The argument for the usual `no-mac-break no-ip-break no-name-break` preset would rest on `device.collector.local_ip`, and it is weaker than it first looks. That field is a **single** address — the script parses exactly one value out of it, normalizing an IPv4-mapped IPv6 form (`::ffff:10.0.0.5`) along the way — and it is the address the Collector last reported locally. On a laptop that is a DHCP lease from wherever the user happened to be, so it drifts constantly. But the drift argues for relaxing `ip-break` only if a drifting address could fragment an asset, and it cannot: once `device.uid` has matched, no address disagreement can disqualify the merge, because that check exists only on the IP match path. The flags govern first contact, where a contemporaneous local address is exactly the signal that should be allowed to find the asset runZero scanned.

The asymmetry worth recording is that **no MAC address is imported at all.** Nexthink exposes MAC data in its NQL model, but neither the field list this integration requires nor the mapping consumes it, so correlation on first contact rests on one address and a hostname. Adding a MAC field to the saved query and to the mapping would be the single highest-value change to this integration's merge behavior — more valuable than any `matchBehavior` adjustment.

## Future

- **MAC addresses and a fuller network picture.** As above: the NQL device model exposes network adapter data that this integration does not select, and a MAC is the strongest first-contact signal a managed-endpoint source can offer runZero. This is a change to the required-fields list and the mapping, not new API surface — the export workflow returns whatever the saved query selects.
- **Installed software as an SBOM source.** Nexthink's NQL model includes installed packages and executables per device, and the export endpoint has no row cap, so a query joining `device` to the package table would populate runZero `Software` records for the whole managed fleet. The constraint to design around is the one-row-per-device rule recorded under **Asset identity**: a software join is inherently many rows per device, so it needs a second export and a local group-by rather than a widened single query.
- **Binary and vulnerability data as findings.** Nexthink tracks executables and their versions per device, and its Vulnerability/Software Metering content maps those to known CVEs. Exporting that join would give runZero `Vulnerability` objects on managed endpoints from a source that sees the actual installed binary rather than a network banner — complementary to, not overlapping with, a scanner-derived finding.
- **Remote actions as outbound push-back — the genuinely novel direction.** Nexthink exposes a remote-action API (`POST /api/v1/act/execute`) that runs a published remote action against a set of devices. runZero routinely establishes things Nexthink cannot see for itself: that a device is exposed on a segment it should not be, that it answers on an unexpected port, that it is the only unmanaged neighbour on a subnet. Feeding a runZero query into a Nexthink remote action would let that discovery drive a scripted response on the endpoint. Two constraints before anyone starts: the action must already be published in Nexthink, and the API addresses devices by their Nexthink identifiers — so the outbound direction needs the `device.uid` this integration already imports as its join key, which is a good argument for keeping the attribute even after the id itself is scoped.
- **Campaigns as a human-in-the-loop channel.** Nexthink can prompt the end user directly through its campaign feature. A runZero finding that needs user action rather than an administrator — an unauthorized device sharing a connection, a personal access point — could be routed to the person actually sitting at the machine. This is a real capability with no equivalent in any other integration in this library.
- **The `execute` endpoint is deliberately not used, and should stay that way.** `POST /api/v1/nql/execute` is synchronous and simpler, and it caps at 1,000 rows — silently, which is exactly the failure recorded under **Troubleshooting**. The export workflow's extra three steps buy an uncapped result set, and any future collector added here should use the same pattern rather than reaching for the simpler call.
- **Coverage-gap reporting needs no new endpoint.** Nexthink knows only devices with the Collector installed. runZero assets classified as workstations that carry no `custom_integration:nexthink` source are Collector deployment gaps, and `nexthink.last_seen` — already imported — identifies devices that have the Collector but stopped reporting.
- **Alert and event ingestion has no path here.** The NQL API is a query interface with no push mechanism, no webhook, and no server-side cursor. Anything resembling a live feed would be re-running the export on a short schedule, and the export workflow's submit-poll-download cycle makes that expensive. This is a scheduled-inventory integration by the API's nature, not by choice.

## Validation checklist

- Task succeeds without authentication errors.
- Export starts and reaches `COMPLETED`.
- Assets in runZero show `custom_integration:nexthink`.
- Imported assets include expected hostnames, OS, and custom attributes.

## Troubleshooting

- `No rows returned from Nexthink export workflow`:
  - Verify query fields and data availability in Nexthink.
  - Verify `query_id` matches a saved Nexthink query.
- `Failed to download export results ... Only one auth mechanism allowed`:
  - Ensure no `Authorization` header is sent to `resultsFileUrl`.
- Exactly 1,000 rows imported:
  - This script already uses export workflow to avoid execute endpoint limits.

## Preparing a pull request

1. Ensure these files exist:
   - [nexthink/nexthink.star](nexthink/nexthink.star)
   - [nexthink/README.md](nexthink/README.md)
2. Verify your branch is `nexthink` and only intended files changed.
3. Run a quick manual validation in runZero with test credentials.
4. Commit with a clear message, for example:
   - `Add Nexthink inbound custom integration with export workflow`
5. Open a PR including:
   - Summary of mapping
   - Validation notes/screenshots
   - Any known limitations

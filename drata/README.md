# Custom Integration: Drata

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Drata requirements

- A Drata **API key** with read access to assets.
- The public API host, `https://public-api.drata.com`.

An API key is scoped to **one workspace** — a key created in one workspace cannot
query another — so an organization with several Drata workspaces needs one
credential and one task per workspace.

Drata does not document which user role can reach the API key screen, nor
whether public API access is gated behind a plan tier or add-on. If the menu
described below is not present for your user, that is the likely cause and it is
a question for Drata support rather than something to work around.

## Steps

### Drata configuration

1. In Drata, select your account in the **bottom-left** side navigation, then go to **Settings > API Keys**.
2. Click **Create API Key** and fill in:
   - **Name** — this **cannot be changed once the key is active**, so pick something durable like `runZero`.
   - **Expiration date** — the choices are 12 months, Never, or Custom, and the default is **12 months**. A key that expires silently stops the task, so either choose Never or diary the renewal.
   - **Allowed IP Addresses** — optional, and worth using. Restrict the key to the egress address of the Explorer that will run the task.
3. Choose the access level. Drata offers **Custom**, **All read**, and **All read and write**.
   - Use **Custom** and grant only asset read access. This integration issues `GET` requests and nothing else.
   - **All read** also works but is documented as covering all current *and future* read permissions, so it silently widens over time.
   - Never use **All read and write**. The assets collection exposes create, update, and delete, and this integration needs none of them.

   Drata's documentation names only these three tiers and does not publish the
   individual scope strings, so the exact permission to tick under **Custom**
   cannot be quoted here — look for the asset read permission. Scopes remain
   editable after creation as long as the key is unexpired and unrevoked, so
   starting narrow is low-risk.
4. Copy the key. The full value is shown **once**.
5. Test it:

   ```bash
   curl -s -H 'Authorization: Bearer <api key>' \
     'https://public-api.drata.com/public/assets?limit=1'
   ```

Drata enforces a rate limit of **500 requests per minute per unique source IP**.
This integration pages 50 assets at a time, so that ceiling is not a practical
constraint for a single task.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter assets (e.g., by `assetClassType` or `employmentStatus`).
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Drata API URL** (`url`): optional; defaults to `https://public-api.drata.com`. Drata publishes no regional API hostnames, so leave this alone unless you have been told otherwise.
    - **API token** (`api_token`): the Drata API key created above. Sent as `Authorization: Bearer`.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "drata").
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
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:drata`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a key
and see what a real workspace returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair — this integration has only two, and one has a working
default:

```bash
runzero script --filename drata/drata.star \
  --kwargs api_token=drt_9f4c2b8e15a7d0364e8bcf27a91d5e03 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/drata-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Two things to expect from that run:

- **The result set is filtered in the script, not by a parameter.** Every request
  carries `assetClassType=HARDWARE&employmentStatus=CURRENT_EMPLOYEE`, so what
  you get is hardware assigned to current employees — not everything Drata calls
  an asset. Drata's asset inventory also covers policies, personnel, and cloud
  infrastructure, none of which is imported. To widen it, edit the `filter`
  string in `main()`.
- **Drata publishes no IP address for an asset.** Assets correlate on hostname,
  MAC, and serial. If a local run produces assets with no network interface at
  all, that is expected for records whose device block is absent, not a mapping
  failure.

There are no paging or limit parameters — the script walks all pages at 50
records each until Drata reports no next page.

This integration was recently found not to have worked at all and has since been
repaired, so treat the output of a first run as something to read carefully
rather than something to trust. Compare a handful of assets against the Drata UI
before scheduling it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching Drata:

```bash
runzero script --filename drata/drata.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real asset.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://public-api.drata.com,api_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a Drata workspace:

```bash
python3 tests/run.py drata
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a **record in Drata's asset register** — specifically an entry of class `HARDWARE` belonging to a current employee, because that filter is hard-coded into the request. It is a compliance record *about* a device rather than the device itself, and the difference shows up throughout: the record is created when somebody (or a connector) registers the asset in Drata, not when the machine appears on the network.
- Source ID field: `id`, from the `data[]` array of `GET /public/assets`.
- Documentation evidence: `id` is the record key Drata's own asset endpoints are addressed by. No stronger vendor statement about its lifecycle is quoted here, because Drata's public API reference does not describe one.
- Uniqueness scope: **the workspace**, and this is unusually well established for once — an API key is scoped to a single Drata workspace and cannot query another, so one credential can only ever see one id space. An organization with several workspaces needs one credential and one task per workspace, and because the id is used bare with no workspace prefix, those tasks should not share a custom integration if the id spaces might overlap.
- Cardinality: one source row per asset record. A device registered twice in Drata — by a connector and by hand, say — is two records with two ids, and Drata is where that has to be reconciled.
- Stability: stable for the life of the register entry. Removing an asset from Drata and re-adding it creates a new record with a new id; the `removedAt` and `deletedAt` fields on the record show that removal is a state Drata tracks rather than a hard delete, which suggests re-adding is genuinely a new row.
- Reuse behavior: not documented.
- Presence: expected. A record without one is skipped with `drata: skipping asset with no id: name=<name>`.
- Final runZero ID: the raw Drata asset id as a string.
- Missing-ID behavior: skip and log.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Defensible under the governing rule: the id is a persistent record key rather than something derived from an address or a scan, so matching on it is what keeps the record attached to one runZero asset.
- Verdict: **authoritative for a Drata register entry within one workspace; derived for the machine**, because the register entry and the machine are not the same object and Drata's own duplicates are invisible from here.

Two things about correlation are worth reading carefully, because they differ from every agent-based source in this repository:

- **Drata publishes no IP address at all.** Correlation therefore rests on the MAC addresses from the record's `device.macAddress` field and on the hostname. An earlier revision of this script placed a synthetic `127.0.0.1` on the network interface, which — because loopback is identical on every host — pulled every Drata asset onto the same existing runZero asset and merged unrelated machines. Nothing of the sort is done now: a record with no MAC gets no network interface, and correlates on its name alone.
- **The hostname is Drata's asset `name`, which is a label rather than a name in the DNS sense.** For hardware synced from a device connector it is usually the real machine name; for a hand-entered asset it can be anything an administrator typed. Custom integration hostnames are enrolled in runZero's trusted-name set, so a label like `<owner>'s laptop` participates in both matching and breaking. If Drata assets are merging oddly, the `name` values in the register are the first place to look.
- **The serial number is imported as the `device.serialNumber` custom attribute only.** It is not used as identity and it is not a correlation dimension, so it is available for a search or a manual reconciliation but it does not merge anything by itself.

### Compliance-check handling

Six check types are mapped by name (`AGENT_INSTALLED`, `PASSWORD_MANAGER`, `HDD_ENCRYPTION`, `ANTIVIRUS`, `AUTO_UPDATES`, `LOCK_SCREEN`). Any type Drata introduces beyond those is logged — `drata: unrecognized compliance check: <type>` — and the record still imports with the checks it does recognize. An earlier revision aborted the whole run here: its `else` branch concatenated a string with `type`, the Starlark **builtin** rather than the variable holding the check's type, and Starlark has no exception handling, so the first unrecognized check took the entire import down. The loop also screens its input now — a present-but-null `complianceChecks` value and a non-object entry inside the list are both skipped rather than aborting the run.

## Future

- **Widen the hard-coded filter, or make it a parameter.** Every request carries `assetClassType=HARDWARE&employmentStatus=CURRENT_EMPLOYEE`. Drata's register also covers software, cloud infrastructure, physical assets, documents, and policies — and hardware belonging to *former* employees, which is exactly the population a security team most wants to find, since an unreturned laptop is both a compliance finding and a live credential risk. Exposing the filter as a credential parameter is a small change with a large effect on what this integration can answer.
- **Compliance-check results as first-class findings.** The script already parses six per-device checks — agent installed, password manager, disk encryption, antivirus, auto-updates, lock screen — with a status, a last-checked time, and an expiry, and then flattens all of it into forty-odd flat custom attributes with names like `device.complianceCheckDiskEncryptionStatus`. That is posture data being stored as text. Modelled properly it would be tags (so `has:device.complianceCheckDiskEncryptionStatus` searches become `tag:disk-encryption-failing`) or findings, and either would make "every laptop on this segment without disk encryption" a one-line runZero query. This is the highest-value change available and it needs no new endpoint.
- **Personnel and ownership.** The record's `owner` object is already imported (id, email, name, roles), which is most of the way to attributing an asset to a person. Drata's personnel resource holds the rest of the employment context — start and end dates, offboarding status — which is what turns "this laptop belongs to a former employee" into something a scheduled task can surface.
- **Outbound: register runZero discoveries in Drata — the direction that matters for an audit.** A compliance asset register is only as good as its completeness, and completeness is precisely what a discovery tool establishes and a register cannot. Drata's assets collection supports create and update (which is why this README tells you never to grant **All read and write** for the inbound direction), so runZero-discovered hardware with no register entry could be pushed in, or at minimum reported as a gap. Note the credential consequence: an outbound integration needs a *separate*, write-scoped key rather than widening this one.
- **Register-versus-reality gap reporting, which is this integration's real value.** Two diffs, both directly meaningful to an auditor. Assets runZero discovers on the network with no Drata record are **unregistered hardware** — an inventory control failure. Drata records for hardware runZero has never seen are either genuinely off-network or **stale register entries**, which is the failure that quietly inflates a compliance scope. The data for both is already imported today, so this is a reporting exercise rather than new integration work.
- **What this API does not offer.** Drata is a compliance platform, not a scanner: there is no open-port data, no installed-package inventory, and no CVE feed on an asset record, so `Service`, `Software`, and CVE-bearing `Vulnerability` records are out of reach from this source regardless of how much more of the API is consumed. The compliance checks described above are the nearest equivalent, and they are posture assertions rather than vulnerabilities.

# Custom Integration: Scan Passive Assets

This custom integration finds assets discovered only by passive sources, creates targeted scans from the last-seen agent, waits for those scans to finish, and can optionally delete the passive assets the completed scans superseded.

This is an **internal** integration (`"type": "internal"`), not an inbound
importer. It has no third-party product behind it: everything it touches is
runZero's own API. It imports nothing and always returns an empty asset list, so
a successful run reports **zero assets** on the tasks page. That is the expected
outcome, not a failure — the work it did shows up as newly queued scan tasks.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- A runZero **Organization API key** for the organization that owns the target site.
- An Explorer that can reach the console over HTTPS.

### Creating the Organization API key

1. Sign in to the runZero console as a **superuser**.
2. Go to the [Account settings page](https://console.runzero.com/account) and
   create an **Organization API key**. Pick the organization that owns the site
   you want scans created in — this key is scoped to one organization, and a key
   from a different organization authenticates fine and then fails on the site.
3. Copy the value; it is shown once.

There is no read-only variant to recommend here. This script does three things
with that key, and two of them write:

| Call | Endpoint | Effect |
|---|---|---|
| Export passive assets | `GET /api/v1.0/export/org/assets.json` | read |
| Create a scan per Explorer | `PUT /api/v1.0/org/sites/<site_id>/scan` | **creates scan tasks** |
| Poll each scan task | `GET /api/v1.0/org/tasks/<task_id>` | read |
| Bulk delete (optional) | `POST /api/v1.0/org/assets/bulk/delete` | **deletes assets** |

An Organization API key carries full read and write access to its organization,
which is more than this script needs, and runZero publishes no narrower token
type. Scope it by rotating it rather than by restricting it.

### Finding the Site ID

Open the site in the console — the UUID in the address bar is the site ID.
Alternatively, list them with the same key you just created:

```bash
curl -s -H "Authorization: Bearer $RUNZERO_ORG_TOKEN" \
  https://console.runzero.com/api/v1.0/org/sites
```

## Scan Passive Assets requirements

Some things are set on the credential and two are still script globals:

- **Site ID** (`site_id`) — a credential parameter. Earlier revisions of this
  script used a `SITE_ID` global; it no longer exists.
- **Seconds to wait for each scan to finish** (`scan_wait_seconds`) — a credential
  parameter, default `1800`. The delete only removes assets whose scan actually
  completed, so this is how long the run is willing to sit and wait for that.
  A scan still running when the wait expires keeps its assets and the next run
  queues another scan for them. **Set it to `0` to make cleanup a separate step**:
  the scans are queued, each task is checked once, and anything not already
  finished is left alone.
- **Seconds between scan status checks** (`scan_poll_seconds`) — a credential
  parameter, default `15`.
- `ALLOW_LIST` — a script global near the top of
  `runzero-scan-passive-assets/runzero-scan-passive-assets.star`. It ships as
  `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]` — all three RFC1918
  ranges. Narrow it if part of that space is not yours to scan.
- **Delete passive assets after their scan completes** (`delete_assets`) — a
  credential parameter, and it ships **off**. The delete-after-scan design has
  an unresolved merge question: the active scan of the same IP in the same site
  may merge onto the very passive asset being tracked (IP-match is the platform
  default for a record whose only correlator is that IP), in which case the
  delete would erase the freshly scanned asset. Leave it off to queue the scans
  and keep every passive record; turn it on only after confirming in your
  environment that scanned results land on a separate asset.

## Steps

### Script configuration

1. Open `runzero-scan-passive-assets/runzero-scan-passive-assets.star`.
2. (Optional) Narrow `ALLOW_LIST` near the top of the file if part of the RFC1918 space is not yours to scan. Deletion is controlled by the `delete_assets` credential parameter and is off by default.
3. (Optional) Adjust the search filter in the export request if you want to include more than `source:sample source_count:1`.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **runZero URL** (`url`): defaults to `https://console.runzero.com`. Set it to your own console base URL if you are self-hosted.
   - **Target site ID** (`site_id`): the site UUID scans should be created in.
   - **runZero org API token** (`org_api_token`): the Organization API key created above.
   - **Seconds to wait for each scan to finish** (`scan_wait_seconds`): optional, defaults to `1800`. `0` queues the scans and leaves the cleanup for another day.
   - **Seconds between scan status checks** (`scan_poll_seconds`): optional, defaults to `15`.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon (e.g., `scan-passive-assets`).
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you'd like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly. For this integration that is
more than a convenience: it is the only way to watch which addresses pass the
allow list before anything is scanned or deleted. Leave `delete_assets` unset
(it defaults to off). `--kwargs` is repeated once per parameter:

```bash
runzero script --filename runzero-scan-passive-assets/runzero-scan-passive-assets.star \
  --kwargs url=https://console.runzero.com \
  --kwargs site_id=1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --kwargs org_api_token=CT4f0e1d2c3b4a59687766554433221100ffeeddccbbaa9988 \
  --kwargs scan_wait_seconds=0 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./scan-passive-assets-run
```

`scan_wait_seconds=0` is there so an ad-hoc run does not sit for half an hour
waiting on scans; leave it off to see the whole cycle.

The script prints `Evaluating IP: <addr>` for every address it considers,
`Scan created for agent <id> as task <id>` for each scan it queues, and one line
per scan as it finishes, so `--verbose` is rarely needed — the useful log is on
stdout already. `--output` writes the returned
asset list, which for this script is always empty; the directory being empty is
correct. The scanner refuses to write into a directory that already exists, so
add `--overwrite` when re-running into the same path.

**This command has side effects on your account.** Unlike every inbound
integration in this repository, a command-line run here is not a dry run: it
creates real scan tasks in the target site, and with `delete_assets=true` it
deletes assets. There is no flag that makes it read-only.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma
— the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. Nothing here carries both: `site_id` is a UUID and an
Organization API key is hex.

To check the `CONFIG` block and the HTTP and TLS wiring without touching your
console:

```bash
runzero script --filename runzero-scan-passive-assets/runzero-scan-passive-assets.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the token is valid, that the site ID
exists, or that any asset matched. The fixture scenarios are what exercise the
grouping, the allow list, the scan-completion wait, and the delete:

```bash
python3 tests/run.py runzero-scan-passive-assets
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat runzero-scan-passive-assets/runzero-scan-passive-assets.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://console.runzero.com,site_id=1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b,org_api_token=CT4f0e1d2c3b4a59687766554433221100ffeeddccbbaa9988' \
  --output ./scan-passive-assets-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main` and only
needs setting for a script with a different entry point. Note that
`--custom-integration-script-kwargs` takes one comma-separated string; prefer
`script --kwargs` for ad-hoc runs.

### What's next?

- The task exports passive assets matching the search filter and groups allowed IPv4 addresses by `last_agent_id`.
- The script creates one scan per agent with the matching targets.
- It then polls each scan task until it completes or `scan_wait_seconds` expires. A run therefore lasts as long as the scans it queued, up to that bound.
- If `delete_assets` is enabled on the credential, the passive assets belonging to a *completed* scan are removed. Everything else is kept.
- You can review task activity on the [tasks](https://console.runzero.com/tasks) page.

## Asset identity

**This integration reports no assets, so it has no asset identity.** `CONFIG` declares
`"type": "internal"`, `main` never constructs an `ImportAsset`, never calls `report_assets`,
and returns a bare `[]`. There is no `id=` to derive an identity from and no `matchBehavior`
to document.

What it does instead is act on runZero's own inventory through runZero's own API:

1. `GET /api/v1.0/export/org/assets.json?search=source:sample+source_count:1&fields=id,addresses,last_agent_id` — finds assets whose **only** source is passive traffic sampling.
2. Filters their IPv4 addresses against `ALLOW_LIST` and groups the survivors by `last_agent_id`, the Explorer that last saw each one.
3. `PUT /api/v1.0/org/sites/<site_id>/scan` — queues one scan per Explorer, targeting that Explorer's addresses.
4. `POST /api/v1.0/org/assets/bulk/delete` — when `delete_assets` is on, removes the passive assets it just queued scans for.

The identity that matters here is runZero's own, and it appears twice in ways worth
understanding:

- **`asset["id"]` is the runZero asset UUID**, and it is used for exactly one thing: the bulk-delete payload. It is never re-imported, so it never participates in merging.
- **The scan targets are bare IPv4 addresses**, not asset references. The Explorer scans an address and whatever answers becomes an asset by runZero's normal active-discovery identity rules — which is the entire point. The passive record is deleted precisely so the actively-discovered asset that replaces it starts clean rather than merging onto a thin, sampling-derived one.

That sequencing is what makes `delete_assets` matter rather than being cosmetic, and it is why
the delete waits. **The scan must have finished before its assets are deleted.** Earlier
revisions fired the bulk delete the moment the scans were *queued*, which is the one order that
cannot be right: the passive record is the only evidence the host exists, the scan meant to
replace it had not run, and a device that had gone offline, an address the Explorer could not
reach, or a scan that errored took the asset with it. Now each `PUT .../scan` response's task id
is polled at `GET /api/v1.0/org/tasks/<id>` until it reports a completed status, and only the
assets belonging to an Explorer whose scan reached `processed` (or `completed`) are deleted:

- A task that ends in `error`, `canceled`, `stopped`, or `removed` **keeps** its assets.
- A task still running when `scan_wait_seconds` expires **keeps** its assets; the next run
  finds them again and queues another scan.
- The wait is per Explorer, which is why asset ids are grouped by Explorer rather than pooled:
  one Explorer's scan failing must not spend another Explorer's assets.

`processed` is the status runZero's cruncher sets once a scan's results have been ingested, so
it is the point at which the active asset really has superseded the passive one.

Even so, `delete_assets` ships off — and should stay off until you have seen a full cycle
complete on your own estate *and* confirmed the scanned results land on a separate asset
rather than merging onto the passive record (see the Future note below).

### Notes

- Only IPv4 addresses are considered; IPv6 addresses are skipped. `is_ip_allowed()` returns `False` for anything that is not version 4, so an IPv6-only passive asset is never scanned and — because it also never enters `asset_ids` — never deleted either.
- The allow list applies before scans are created, so verify `ALLOW_LIST` matches your internal ranges.
- `delete_assets` defaults to off, which is the right setting for initial testing and stays right until the merge question below is settled for your environment.
- The `search` filter is a script constant, not a parameter. `source:sample source_count:1` is deliberately narrow: `source_count:1` is what restricts it to assets that *nothing else* has ever seen, and dropping it would sweep in assets that active scanning already knows about.
- Scan parameters are hardcoded in `scan_payload` — rate 1000, 3 passes, screenshots on, tagged `type=AUTOMATED`. They are not credential fields, so tuning them for a slow or fragile segment means editing the script.
- An asset with no `last_agent_id` is skipped entirely. There is no Explorer to attribute the scan to, so it can neither be scanned nor deleted.

## Future

- **Promote the remaining script globals to `CONFIG` parameters.** `scan_wait_seconds`, `scan_poll_seconds`, and `delete_assets` are parameters now; `ALLOW_LIST` (which now covers all three RFC1918 ranges) and the export search still require editing and re-saving the script. A `list`-typed parameter would finish the job.
- **Hand the wait back to the scheduler.** The delete now waits for the scans in-process, which is correct but costs a task slot for as long as the scans take (bounded by `scan_wait_seconds`). The cheaper shape is to queue the scans on one run and delete on a *later* one, which needs run-to-run state that a custom integration does not have — a `hidden` flag or a tag written onto the passive assets would approximate it, and it is also what would let the wait be removed entirely rather than merely bounded.
- **Deleting an asset the scan may have merged into — the reason `delete_assets` ships off.** The delete is by asset UUID and it fires after the scan has been ingested, so if the active scan merged into the same runZero asset rather than creating a new one, the delete removes the freshly scanned asset. Whether it merges depends on the platform's normal matching (address, MAC, name) against a record that has only an address, and it was not established here — which is why deletion is now opt-in rather than the default. A check that the asset's source count grew before deleting it would settle the question properly and would let the default flip back on.
- **Scan by asset rather than by address.** Targets are currently a newline-joined list of IPv4 strings. runZero's scan API also accepts hostnames and CIDR ranges, so a passive asset known only by a name, or one whose addresses are IPv6, could be scanned instead of skipped. Extending `is_ip_allowed()` to handle IPv6 prefixes is the prerequisite, and it is a small change — the current implementation converts dotted quads to integers by hand precisely because it only ever handles v4.
- **Use scan templates instead of an inline payload.** runZero supports scan templates, and `/api/v1.0/org/sites/<site_id>/scan` can reference one rather than carrying eighteen hardcoded tuning values. That would let an operator manage scan behavior in the console, where the rest of their scan configuration already lives, and would remove the block of magic numbers from the script.
- **Other "assets only one source has seen" workflows.** The export search is the interesting, generalizable part. `source:sample source_count:1` finds passively-observed-only assets, but the same three-step shape — export a query, group by Explorer, queue a scan — would serve any coverage gap expressible as a runZero search: assets last seen more than N days ago, assets in a site with no recent scan, assets discovered by an integration that active scanning has never confirmed. Parameterizing the search turns this from one workflow into a general scan-orchestration primitive.
- **There is no narrower credential, and that will not change soon.** An Organization API key carries full read and write access to its organization; runZero publishes no scoped token type that would grant "create scans" without also granting "delete assets". Until one exists, the mitigation is rotation and a dedicated key, not restriction — which is what the table under **runZero requirements** says and is worth repeating here.

# Custom Integration: Task Sync

## Overview

This integration script is designed to sync tasks between a runZero SaaS instance and a self-hosted runZero console. It retrieves tasks from a SaaS instance, downloads their data, and uploads them to a self-hosted site. Optionally, it can hide the tasks in the SaaS instance after a successful sync.

## Requirements

### runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

### API Requirements

Both credentials are **runZero** tokens. There is no third-party product to configure — the
source and the destination are two runZero consoles.

- **Source organization ID** (`src_org_id`) — the organization whose tasks are read.
- **Source API token** (`src_api_token`) — an **Organization API token** (`OT`) for that
  organization. This has to be an organization token, not an export token: the sync reads
  `/api/v1.0/org/tasks`, downloads `/api/v1.0/org/tasks/{id}/data`, and — when
  `hide_tasks_on_sync` is enabled — posts to `/api/v1.0/org/tasks/{id}/hide`. An export
  token (`ET`) reaches only the `/api/v1.0/export` paths and cannot do any of that.
- **Destination organization ID** (`dst_org_id`) and **destination site ID**
  (`dst_site_id`) — where the task data is imported. The site ID is required; the source
  side does not take one, because tasks are selected by search filter rather than by site.
- **Destination API token** (`dst_api_token`) — an Organization API token for the
  destination organization, with write access. The upload is a `PUT` to
  `/api/v1.0/org/sites/{site_id}/import`, so a read-only token is not sufficient.
- Network reachability from the Explorer running the task to **both** consoles.

## Configuration Steps

1. **Obtain Required IDs and Tokens**

   For each console — the source and the destination — do the following:

   - Go to **Organizations** and click the organization. Its ID is shown on the
     organization's information page, and also appears as the `_oid` query parameter in the
     console URL while that organization is selected.
   - Click **Edit organization** and generate a token in the **organization API tokens**
     section. Organization tokens begin with `OT`; export tokens begin with `ET` and will
     not work here.
   - On the destination console only, open **Sites**, click the target site, and note its
     ID from the site page URL.

   Record: source organization ID and token, destination organization ID, destination site
   ID, and destination token.

2. **Decide which tasks to sync**

   `src_task_search_filter` selects them, using the same search syntax as the tasks page.
   The shipped default is `name:="test"`, which is a placeholder — it matches tasks named
   exactly `test` and is almost certainly not what you want. Set it to something that
   matches the tasks you actually intend to move before the first run.

3. **Create the Credential for the Custom Integration**
   - Go to [runZero Credentials](https://console.runzero.com/credentials).
   - Select `Custom Integration Script Secrets`.
   - **Source runZero URL** (`src_url`): optional; defaults to `https://console.runzero.com`.
   - **Source org ID** (`src_org_id`): the organization to read tasks from.
   - **Source task search filter** (`src_task_search_filter`): optional; which tasks to sync.
   - **Destination runZero URL** (`dst_url`): optional; defaults to `https://console.runzero.com`. Set it to your self-hosted console.
   - **Destination org ID** (`dst_org_id`): the organization to import into.
   - **Destination site ID** (`dst_site_id`): the site to import into.
   - **Hide source tasks after sync** (`hide_tasks_on_sync`): optional; default off.
   - **Source API token** (`src_api_token`): the `OT` token for the source organization.
   - **Destination API token** (`dst_api_token`): the `OT` token for the destination organization.
   - TLS and HTTP options are separate for each side, prefixed `src_tls_` / `dst_tls_` and `src_http_` / `dst_http_`, so a self-hosted console with a private certificate can be configured without loosening anything on the other end.

4. **Create the Custom Integration**
   - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Task Sync").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.

5. **Create the Custom Integration Task**
   - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in the previous steps.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you'd like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

## Optional Settings

- To automatically hide tasks in the source instance after a successful sync, enable **Hide source tasks after sync** (`hide_tasks_on_sync`) on the credential. This was previously a `HIDE_TASKS_ON_SYNC` constant in the script; it is now a credential field and the script does not need editing.

## Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to confirm
both consoles are reachable and both tokens work before scheduling it. `--kwargs` is
repeated once per parameter. Note that this integration's script is `runzero-task-sync.star`:

```bash
runzero script --filename runzero-task-sync/runzero-task-sync.star \
  --kwargs src_url=https://console.runzero.com \
  --kwargs src_org_id=8c1f0a34-5b62-4d97-a0e3-71f4b8c26d95 \
  --kwargs src_task_search_filter=name:=nightly-scan \
  --kwargs dst_url=https://runzero.internal.example.com \
  --kwargs dst_org_id=2e7b91c6-4a08-4f35-9d1c-06b3ea75f482 \
  --kwargs dst_site_id=b5390c74-2ad1-4e86-83f9-c410d7e29a6b \
  --kwargs hide_tasks_on_sync=false \
  --kwargs src_api_token=OT1a2b3c4d5e6f708192a3b4c5d6e7f809 \
  --kwargs dst_api_token=OT9f8e7d6c5b4a30291817f6e5d4c3b2a1 \
  --kwargs dst_tls_disable_validation=true
```

**`--output` is not useful here.** This integration reports no assets back to the console it
runs from — it moves task data from one instance to another — so an export directory would
be written empty. Read the log instead: it prints `Got <n> task(s) to sync`, then
`Pulling task with ID ...` and `Uploading task with ID ...` for each one. Add `--verbose`
for the request-by-request detail.

**The default search filter cannot be passed on the command line as written.** `--kwargs`
CSV-parses any argument containing a second `=` sign, and the shipped default
`name:="test"` contains both a second `=` and bare double quotes, which fails with
`parse error on line 1, column 30: bare " in non-quoted-field`. Two ways around it:

- Use an unquoted filter — `--kwargs src_task_search_filter=name:=nightly-scan` — which
  works because a value with no double quotes survives CSV parsing.
- Or wrap the *entire* argument as one CSV field and double the inner quotes:

  ```bash
  --kwargs '"src_task_search_filter=name:=""test"""'
  ```

  which arrives at the script as `name:="test"`.

The console credential form has no such limitation; this only affects ad-hoc CLI runs.

To check the `CONFIG` block and the HTTP and TLS wiring without touching either console:

```bash
runzero script --filename runzero-task-sync/runzero-task-sync.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes and declares its parameters correctly. It does not
prove either token is valid or that any task can be moved.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat runzero-task-sync/runzero-task-sync.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'src_org_id=<src-org>,dst_url=https://runzero.internal.example.com,dst_org_id=<dst-org>,dst_site_id=<dst-site>,src_api_token=<OT-token>,dst_api_token=<OT-token>'
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. This flag takes one
comma-separated string, so a search filter containing a comma cannot be passed through it
at all; configure that field on the console credential.

## Asset identity

**This integration reports no assets, so it has no asset identity.** `main` never constructs
an `ImportAsset`, never calls `report_assets`, and returns `None`. There is no `id=` to derive
an identity from and no `matchBehavior` to document.

It is worth being precise about what it does instead, because "sync tasks" understates it:
the payload it moves is **scan data**, not task metadata. Per task, in order:

1. `GET <src_url>/api/v1.0/org/tasks?_oid=<src_org_id>&search=<filter>` — selects tasks.
2. `GET <src_url>/api/v1.0/org/tasks/<task_id>/data?_oid=<src_org_id>` — downloads that task's raw scan result. The `_oid` matters: with an account-level token, a `/data` call without it resolves against the token's default org and 404s every task.
3. `PUT <dst_url>/api/v1.0/org/sites/<dst_site_id>/import?_oid=<dst_org_id>` — replays it into the destination console through the same import path a real Explorer uses.
4. `POST <src_url>/api/v1.0/org/tasks/<task_id>/hide?_oid=<src_org_id>` — optional, only when `hide_tasks_on_sync` is set. A hide that fails is logged, because a silent hide failure re-syncs the same task every run.

So asset identity **is** decided — just on the destination console, by runZero's own scan
ingestion, exactly as it would be for a scan the destination ran itself. The records in the
uploaded file carry the same fingerprints, MACs, addresses, and hostnames the source Explorer
observed, and the destination merges them by its normal rules. Nothing in this script
constructs, rewrites, or namespaces an identity, and that is deliberate: re-keying the data
would break precisely the merge behavior that makes the replay useful.

Two consequences follow, and both are easy to be surprised by:

- **Assets appear in the destination under the destination's own site**, the one named by `dst_site_id`, regardless of which site they were scanned into on the source. There is no site mapping; every synced task lands in the same destination site.
- **Re-syncing a task re-imports it.** The import endpoint is not idempotent in the sense of "skip if already present" — it merges the data again. That is harmless for assets, which merge onto themselves, but it does move first-seen and last-seen timestamps around. `hide_tasks_on_sync` exists to stop a task being picked up twice by the same search filter; without it, the filter itself has to exclude what has already moved.

**A note on the `CONFIG` type.** This script declares `"type": "internal"`. It used to declare
`"inbound"`, which did not describe what it does: an `inbound` integration is one whose `main`
yields `ImportAsset` values for the platform to merge, and this one reports no assets at all —
everything it writes goes to a *different* console over that console's own API. The two
comparable scripts in this repository, `runzero-scan-passive-assets` and
`runzero-vulnerability-workflow`, declare `"internal"` for the same shape, and this now
matches them.

## Future

- **Site mapping instead of a single destination site.** `dst_site_id` is one value, so every task from every source site collapses into one destination site. The source task record returned by `/api/v1.0/org/tasks` carries its own `site_id`, and the destination's `/api/v1.0/org/sites` lists the available targets, so a mapping — by name, or by an explicit table — is buildable from data both ends already expose. On any estate with more than one site this is the difference between a usable mirror and a pile.
- **Incremental selection without `hide_tasks_on_sync`.** Today the only way to avoid re-syncing is to hide the source task, which mutates the source console and is off by default for good reason. The task list is queryable with the same search syntax as the tasks page, so a filter bounded on completion time would select only new work — but a custom integration has no run-to-run state to hold the previous high-water mark, so the window has to be derived from the task schedule. That is the same constraint every incremental design in this library runs into, and it is the main thing blocking a cleaner selection model.
- **Sync more than scan tasks.** `/api/v1.0/org/tasks` returns every task type, and the search filter does not distinguish them. Integration and sampling tasks carry data in the same `/data` shape, so they would replay through the same import path — but whether replaying a non-scan task into a foreign console produces sensible results has not been established, and the shipped default filter (`name:="test"`) does not constrain the type. A `type:` clause in the filter is the safe habit until it has been.
- **Bidirectional sync is not supported and would need care.** The script is one-way by construction: it holds a source token and a destination token and never reads from the destination. A reverse path is mechanically symmetric — the same three endpoints exist on both ends — but two consoles syncing to each other would replay each other's imports indefinitely unless something marks provenance. runZero's import path carries no "already synced from elsewhere" marker, so a bidirectional design needs a tagging convention invented for it.
- **Failure handling is per-task and silent in aggregate.** Each of the three calls prints on failure and `sync_task` returns `False`, but the loop continues and the task still reports success overall. A run in which every upload failed is indistinguishable from a clean one without reading the log. A count of successes and failures in the final log line — and a non-empty failure list ending the run non-zero — would be a small change with a large effect on operability.
- **The gzip detection is a heuristic worth eventually removing.** The download endpoint redirects to object storage and presigns the *uncompressed* object whenever the gzipped one is absent, so the script sniffs the first byte for `{` and only decompresses when it is not one. That is correct today and is documented in the script's own comment, including the platform-side TODO it works around. It is still a content-type decision being made from a payload byte, and it should be revisited once the platform's own migration to gzip is complete.
- **There is no third-party API here, so there is no vendor surface to extend.** Everything above is bounded by runZero's own API. That also means there is no alert or event feed to ingest and no outbound push-back to design — the two ends of this integration are both runZero, and the only question is which of runZero's endpoints it should be using.

## Troubleshooting

- **Task Sync Failures**: Ensure that both the SaaS and self-hosted tokens are valid and have the necessary permissions.
- **Data Transfer Issues**: Confirm that the self-hosted console is reachable from the machine running this script.
- **Network Timeouts**: Increase the timeout in the `sync_task()` function if syncing large tasks.

---

## License

This integration is provided under the MIT License. See the LICENSE file for more details.

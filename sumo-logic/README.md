# Custom Integration: Sumo Logic

**This is an outbound integration.** It does not import anything into runZero. It reads
your runZero asset inventory through the export API and posts it into a Sumo Logic HTTP
source, one JSON object per line, in batches of 500. Everything below is about setting up
the *destination* and a read-only token for the *source*; there is no third-party device
credential to create.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An **export token** for the organization whose assets you want to send. Export tokens begin with `ET` and are read-only: they can reach only the `/api/v1.0/export` endpoints and nothing else, which is exactly the access this integration needs. An organization API token (`OT`) also works but grants far more than necessary.
  - Generate one from **Organizations**, click the organization, choose **Edit organization**, and use the button in the **export tokens** section. Regenerating the token invalidates the old one.
- The integration reads `/api/v1.0/export/org/assets.json` with the search `alive:t`, set as the `SEARCH` constant in the script.

## Sumo Logic requirements

- An **HTTP Logs and Metrics Source** on a hosted collector. Its unique upload URL is the destination.
  - Format: `https://<endpoint>.collection.sumologic.com/receiver/v1/http/<unique-code>`. The `<endpoint>` part is your Sumo deployment (`endpoint1`, `endpoint2`, `collectors.eu`, and so on) — the URL Sumo generates for the source is authoritative, so copy it rather than assembling it.
- The URL is itself the credential. Anything holding it can write to that source, so treat it as a secret.

## Steps

### Sumo Logic configuration

1. In Sumo Logic, go to **Manage Data > Collection > Collection**.
2. Find a **Hosted Collector** to attach the source to, or click **Add Collector** and create one.
3. Click **Add Source** next to that collector and choose **HTTP Logs & Metrics**.
4. Name the source (for example `runzero-assets`), set a source category you can query on such as `runzero/assets`, and save.
5. Sumo displays the **HTTP Source Address**. Copy it in full — this is the `dst_url` value. You can regenerate it later from the source's settings if it leaks.
6. Confirm the endpoint accepts a post from the Explorer host:

   ```bash
   curl -s -X POST -d '{"test":"runzero"}' \
     'https://endpoint4.collection.sumologic.com/receiver/v1/http/<unique-code>'
   ```

   A successful upload answers `200`. The record then shows up in a search on the source category you set.

> Earlier versions of this integration required editing a `<UPDATE_ME>` placeholder in the script. The destination is now the `dst_url` credential field and the script does not need editing for it.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify the `SEARCH` variable to adjust the query used to filter assets in runZero.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **runZero source URL** (`src_url`): the console to export from, e.g. `https://console.runzero.com`, or your self-hosted console.
    - **Sumo HTTP endpoint** (`dst_url`): the HTTP Source Address copied above.
    - **runZero export token** (`runzero_export_token`): the `ET` export token for the source organization.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "sumo-logic-export").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to confirm
both ends are wired up before scheduling it. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename sumo-logic/sumo-logic.star \
  --kwargs src_url=https://console.runzero.com \
  --kwargs runzero_export_token=ET1a2b3c4d5e6f708192a3b4c5d6e7f809 \
  --kwargs dst_url=https://endpoint4.collection.sumologic.com/receiver/v1/http/ZaVnC4dhaV1F8yTn0pQ7rXbK
```

**`--output` is not useful here.** This integration is outbound: it reports no assets to
runZero, so an export directory would be written empty. Read the log instead — it prints
`Got <n> assets` after the export call and `Sending <n> assets to Sumo Logic` before the
upload, which together tell you which half failed. Add `--verbose` for the
request-by-request detail.

The two ends fail differently and it is worth knowing which you are looking at:

- `runZero export failed: ...` means the export token or `src_url` is wrong. Export tokens
  are organization-scoped, so a token from the wrong organization authenticates and returns
  nothing.
- `runZero did not return any assets` means the token worked but the `SEARCH` constant
  (`alive:t`) matched nothing in that organization.
- `Sumo Logic rejected a batch of ... with status ...` is the Sumo endpoint, not runZero:
  the source address, the collector code, the batch size, or a rate limit. The status and
  the response body are both in the line, and the task itself fails.

To check the `CONFIG` block and the HTTP and TLS wiring without touching either end:

```bash
runzero script --filename sumo-logic/sumo-logic.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove the export token is valid or that Sumo accepted anything.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat sumo-logic/sumo-logic.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'src_url=https://console.runzero.com,runzero_export_token=<ET-token>,dst_url=https://endpoint4.collection.sumologic.com/receiver/v1/http/<unique-code>'
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will retrieve asset data from runZero and upload it to your configured Sumo Logic HTTP Source.
- Asset data in Sumo Logic will be updated with each successful task execution.

## Asset identity

**This integration reports no assets, so it has no asset identity.** `CONFIG` declares
`"type": "outbound"`, `main` never constructs an `ImportAsset`, never calls `report_assets`,
and returns nothing. There is no `id=` to derive an identity from and no `matchBehavior` to
document, because nothing is ever imported.

What it does instead is a one-way copy:

1. `GET <src_url>/api/v1.0/export/org/assets.json?search=alive%3At` — reads the runZero asset inventory for one organization, filtered by the `SEARCH` constant in the script.
2. `POST <dst_url>` — writes those records to a Sumo Logic HTTP source as newline-delimited JSON, in batches of 500.

The records posted to Sumo are runZero's own export objects, verbatim — they are not
transformed, re-keyed, or reduced. **runZero's asset UUID is what identifies a record on the
Sumo side**, and it is carried in the export payload rather than constructed here. That is the
field to key a Sumo lookup or join on, and it is stable for the life of the asset in runZero.

Two consequences of the shape are worth stating plainly, because neither is obvious from a
successful task:

- **A successful run reports zero assets on the tasks page.** That is the expected outcome, not a failure. The evidence of work is the `Got <n> assets`, `Sending <n> assets to Sumo Logic`, and `Uploaded <n> of <n> assets to Sumo Logic` log lines — and, since a refused upload now fails the task, a green task means every batch was accepted.
- **Sumo is an append-only log destination, so this is not a sync.** Every run posts the full current inventory as fresh log records; nothing is updated in place and nothing is deleted. An asset removed from runZero simply stops appearing in new batches, and Sumo retains everything already sent for whatever its retention policy allows. Queries on the Sumo side therefore need to select the most recent record per asset UUID rather than assuming one record per asset.

### Notes

- Ensure the `SEARCH` variable in the script is customized to meet your asset filtering needs (e.g., `alive:t` to include only live assets). It is a script global, not a credential parameter, so changing it means editing the script.
- You can monitor the ingestion of data in Sumo Logic through the configured HTTP Source logs.
- Use Sumo Logic’s query tools to analyze and visualize the runZero asset data.
- The export is a single request with a 600-second timeout and no paging, so the whole
  inventory is held in memory at once before the first batch is posted. On a very large
  organization, narrow `SEARCH` rather than raising the timeout.
- **A rejected upload fails the task.** Every batch's status is checked — an HTTP source
  answers `200` and the status code is the only acknowledgement it gives. A batch Sumo
  refuses (a bad source address, a revoked collector, a payload over the source's size
  limit, a 429 under load) is logged as
  `Sumo Logic rejected a batch of <n> assets with status <code>` together with the response
  body, and the remaining batches are still sent, because they are independent uploads and
  abandoning them would turn one refused batch into a lost estate. The run then ends with
  `Uploaded <sent> of <total> assets to Sumo Logic` and, if anything was refused, fails the
  task with `Sumo Logic did not accept <n> of <total> assets`. That last part matters
  because this integration emits no assets: the task's own outcome is the only place an
  operator can see that the receiver has a hole in it. Earlier revisions assigned the
  `http_post` result to a variable they never read, so a refused batch produced no error, no
  log line, and a green task.

## Future

The two sides of this integration have very different futures, because runZero's export API
is broad and a Sumo HTTP source is deliberately narrow.

- **Send more than assets.** The export API serves several collections under the same `ET` token and the same shape: `/api/v1.0/export/org/services.json`, `/api/v1.0/export/org/software.json`, `/api/v1.0/export/org/vulnerabilities.json`, `/api/v1.0/export/org/wireless.json`, and `/api/v1.0/export/org/sites.json`. Vulnerabilities are the obvious next one — a SIEM that already holds runZero's findings can correlate them against detections it saw on the same host — and services would let Sumo answer "what is listening where" without a second data source. Each is one more call and one more batch loop; no new credential is needed, because the export token already reaches all of them.
- **A search parameter instead of a script constant.** `SEARCH` is compiled in, so filtering the export means editing the script and re-saving the integration. Promoting it to a `CONFIG` parameter would let one script serve several tasks with different scopes — a per-site export, a critical-assets-only export — which is the normal way this is configured everywhere else in this library. Note the interaction with the command line recorded above: a search filter containing both an `=` and a comma cannot be passed through `--kwargs` without extra quoting, which is one reason it was left as a constant.
- **Incremental export instead of a full sweep.** Every run posts the entire inventory. runZero's export search syntax supports time-bounded queries, so a task could send only assets seen or changed since the last run and cut the volume — and therefore the Sumo ingest cost — by orders of magnitude on a stable estate. The blocker is that a custom integration has no run-to-run state store, so the window would have to be derived from the task schedule rather than from a stored cursor.
- **Sumo cannot push anything back, and this is a hard limit.** An HTTP Logs and Metrics source is write-only by construction: it accepts a POST and returns `200`. There is no read path, no query, and no acknowledgement beyond the status code. Anything bidirectional would have to use Sumo's **management API** instead (`https://api.<deployment>.sumologic.com/api/v1/`), which is a completely different credential — an access ID and key rather than a source URL — and a different integration. With it, a `POST /api/v1/search/jobs` search job could pull Sumo detections back into runZero as findings, or `/api/v1/collectors` could be read to report which hosts have a Sumo collector installed and which do not. Neither is reachable from the source URL this integration holds.
- **Coverage-gap reporting would need that management API.** "Which runZero assets have no Sumo collector" is exactly the kind of question this pairing should answer, and it is currently unanswerable in this direction: the data flows out of runZero and nothing flows back. Building it means the management-API credential above, reading `/api/v1/collectors`, and importing the result as an inbound integration — a separate script, not an extension of this one.
- **Batching is fixed at 500 records and is not tuned to Sumo's limits.** Sumo documents a per-request size limit on HTTP sources rather than a record count, so a runZero organization with unusually large asset records can exceed it while one with small records wastes requests. A size-aware batcher, or simply a configurable batch size, would be a small and worthwhile change. An oversized batch is at least visible now that the response status is checked — it is logged and it fails the task — but the fix for it is still to send less in one request.

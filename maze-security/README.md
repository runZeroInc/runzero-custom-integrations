# Custom Integration: Maze

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Maze requirements

- A Maze API key with access to the Investigations API. The key is sent as the `X-API-Key` header on every request.
- Read access is all that is needed. The integration issues one call, `POST /v1/investigations/search`, and never writes.
- The API host is `https://api.mazehq.com`, which is the default and only needs setting if your tenant is served elsewhere.

## Steps

### Maze configuration

1. Obtain an **API key** from the Maze platform.

   Maze does not publish its API documentation publicly, and the exact place a key is
   issued in the product could not be confirmed from vendor documentation. Ask your Maze
   representative or Maze support for a key scoped to the Investigations API rather than
   following a menu path from this document.

2. Confirm the key works from the Explorer host before configuring runZero. The integration
   sends the key as `X-API-Key` and posts a search body bounded by an absolute cutoff
   timestamp, which it computes from `days_back`:

   ```bash
   curl -s -X POST https://api.mazehq.com/v1/investigations/search \
     -H 'X-API-Key: <key>' \
     -H 'Content-Type: application/json' \
     -d '{"limit":100,"updated_from":"2026-07-17T00:00:00Z"}'
   ```

   A successful response carries the investigations under a `data` array and a
   `next_cursor` field, which the integration replays as `cursor` to page through the rest.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Maze").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Maze API URL** (`url`): optional; defaults to `https://api.mazehq.com`. Override only for a regional or self-hosted deployment.
   - **Maze API key** (`api_key`): your Maze API key with access to the Investigations API.
   - **Lookback window (days)** (`days_back`): optional; how far back to fetch updated investigations (default: 30, minimum 1).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename maze-security/maze-security.star \
  --kwargs url=https://api.mazehq.com \
  --kwargs api_key=mz_7c4e1b93a0d5628f4b17e3c095da8261 \
  --kwargs days_back=7 \
  --output ./maze-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`url` is optional and defaults to `https://api.mazehq.com`, so `api_key` is the only
parameter a real run needs.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Lower `days_back` for a first run. Investigations are grouped by asset across every page
before anything is reported, so a wide lookback means the whole result set is walked before
the first asset appears.

To check the `CONFIG` block and the HTTP and TLS wiring without touching the real API:

```bash
runzero script --filename maze-security/maze-security.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Maze accepts the key or that any investigation is parsed.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py maze-security
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat maze-security/maze-security.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.mazehq.com,api_key=<key>' \
  --output ./maze-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with vulnerability investigation data pulled from Maze.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:maze`.

## Asset identity

Maze is a vulnerability-investigation product, not an asset inventory. It has no asset endpoint and no asset object — the only thing `POST /v1/investigations/search` returns is investigations, each of which is one CVE against one thing. The asset side of this import is therefore **reconstructed** from fields inside the investigation, and everything below follows from that.

- Target entity: whatever the upstream scanner that fed Maze called an asset. Maze aggregates findings from other scanners, so the entity is defined by that scanner, not by Maze.
- Source ID field: there is no single one. Only two fields in the payload name an asset, and the script tries them in order:
  1. `related_scanner_findings[].asset_name` — used when the investigation carries related findings that name one. This is a **name**, not an identifier.
  2. `parse_asset_id(scanner_finding_hash)` — the third `::`-delimited segment of `scanner_finding_hash`, whose documented layout is `scanner::CVE::asset_id`. A related finding with no `asset_name` of its own falls back to this.
- Documentation evidence: **none available.** Maze publishes no API reference; the `scanner::CVE::asset_id` layout is asserted by a comment in the script and by the fixtures, not by a vendor document. This is the weakest evidence base of any integration in this library, and everything below should be read as inference from the code rather than as a contract.
- Uniqueness scope: none. The value is used verbatim with no vendor prefix, no tenant scope, and no scoping on the configured API host. A bare scanner asset name such as `web-01` becomes the foreign id as-is. Under `no-id-match` (below) that value no longer drives matching, so it is a label rather than a key.
- Cardinality: many investigations collapse onto one asset — that is the whole point of the grouping pass in `group_investigations()`. One device can still be *named* two ways within a single run, because an investigation whose related findings carry an `asset_name` groups under that while one without groups under the hash segment, and those two strings need not agree. `no-id-break` is what keeps that from forking the asset — see below.
- Stability: only as stable as the upstream scanner's asset label. A rename in the source scanner produces a differently-named record; because the id does not drive matching, the two still converge if the hostname or an address agrees.
- Reuse behavior: unknown and unknowable from the code. Scanner asset names are recycled freely in practice.
- Presence: an investigation that names no asset at all is **skipped**, not given a synthesized id. See the fix below.
- Final runZero ID: the raw value from whichever path matched. No prefix is applied.
- Missing-ID behavior: skipped and logged — `maze: skipping investigation with no asset name or asset segment: id=… scanner_finding_hash=…` — with a per-run count in the closing summary. Reached when `scanner_finding_hash` has fewer than three `::` segments (or is absent) *and* no related finding names an asset.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`.**
- Verdict: **derived, and correlated as derived data.** There is no vendor-assigned identifier behind these assets, so the id is carried for reference and merging is done on hostname and address.

### Why `no-id-match no-id-break`, and what changed

The rule this library follows is that a source with a persistent remote id matches on the foreign id, and a source with only scan-derived data and no stable id sets `no-id-match no-id-break` and correlates on hostname, MAC, and IP instead. Maze is squarely the second case: there is no Maze-assigned asset identifier anywhere in the payload, only names that some upstream scanner chose.

The script used to leave the platform default on, which mattered because of `id-break` rather than `id-match`. With `id-break` on, the platform disqualifies a merge candidate whose foreign id disagrees, so a device that Maze names `web-01` on one investigation and `web-01.corp.example.com` on another forks into two runZero assets that can never converge — the hostname match that would have joined them is vetoed by the id disagreement. Turning both flags off removes the veto and lets the two records converge on hostname and address, which is the only evidence Maze actually supplies.

Two paths also minted **one asset per finding** instead of one per device, and both are now removed:

- **`parse_asset_id()` returned the entire hash when it had fewer than three `::` segments.** The hash embeds the CVE, so a two-segment hash such as `tenable::CVE-2024-1234` became the asset id — and every CVE on that host produced a different one. It now returns `""`, which means "this value names no asset".
- **The fallback to `investigation.id`.** An investigation is one CVE on one asset by definition, so this guaranteed one asset per finding for any record that reached it. It is gone; there is no third source of asset identity to fall back to, so the record is skipped and logged the way every other integration here skips a record with no id.

**These are breaking changes for an existing deployment**, in two ways:

- Any asset whose foreign id came from one of the two removed paths — a whole `scanner_finding_hash`, or a bare `investigation.id` — is no longer imported. Those assets go stale in runZero and should be retired. They were one-per-finding artifacts, not devices, so there is nothing to migrate them onto.
- Assets on the surviving paths keep their foreign ids exactly, but their merge policy changes. Existing Maze assets are not re-keyed; they simply stop being found by foreign id and start being found by hostname. Where Maze had previously forked one device into two assets under two spellings of its name, the two can now merge.

`tests/run.py maze-security` covers all of this: `identity-convergence` is the regression test, asserting that four investigations naming one host through both id spaces collapse to a single asset, that the two-segment-hash and no-hash records are skipped by id, and that the resolved `_match.behavior` is exactly `no-id-match no-id-break …`.

### Notes

- The integration fetches investigations updated within the last 30 days by default. Change the **Lookback window (days)** credential field (`days_back`) to adjust this.
- Each investigation is mapped to a **Vulnerability** on the corresponding asset, including CVE, CVSS scores, exploitability verdict, and root cause analysis.
- When `related_scanner_findings` data is available, additional metadata (cloud platform, region, scanner type, account ID) is included as custom attributes.
- Assets are grouped from paginated investigations (the grouping spans pages, so it cannot stream per record); each finished asset is then streamed to runZero via `report_asset`.
- Transient API errors (429/5xx) are retried automatically with backoff by the shared HTTP helper. An auth failure (401) is not retried: the page error is printed and the run ends with zero assets.
- `days_back` is converted to an absolute `updated_from` timestamp before the first request, so every page of a run shares one cutoff and a long run cannot drift.
- The paging loop is bounded by `CONFIG["maxPages"]` (5,000 pages of 1,000 investigations). A server that keeps answering `has_more` forever raises there, so an incomplete import is reported as an error rather than truncated silently.
- `cve_id` is screened against the `CVE-YYYY-NNNN` shape before it reaches the `cve` field. A non-CVE code (a vendor advisory id, a scanner's own key) still imports as a finding, keeping the raw value as the vulnerability name and the `maze_cve_id` attribute.

## Future

Maze publishes no API reference, so unlike most entries in this library the section below cannot cite an endpoint list. What follows is bounded by what the one endpoint this integration calls actually exposes, plus what the product is documented to do; where an endpoint would be needed and its existence is unknown, that is said rather than guessed.

- **Asset-oriented ingestion, if Maze has an asset endpoint.** This is the single change that would most improve the integration, and it is blocked on information rather than on effort. Every identity weakness recorded above exists because assets are reconstructed from `scanner_finding_hash` and `related_scanner_findings[].asset_name`. A Maze-assigned asset id — anything stable enough to key on — would replace the whole three-path fallback chain with a normal foreign-ID import. `related_scanner_findings[]` already carries `asset_id`, `asset_type`, `cloud_platform`, `region`, `account_id`, and `scanner`, which is the shape of an asset record; the integration stores `asset_id` as the `maze_asset_full_id` attribute today precisely because there is no documented endpoint to resolve it against. Ask Maze whether `asset_id` is addressable before building anything else here.
- **Incremental polling instead of a lookback window.** The search body accepts `updated_from` and returns `next_cursor`/`has_more`, which is already an incremental-feed shape. Persisting the highest `updated_at` seen and passing it as the next run's `updated_from` would replace `days_back` and remove the re-grouping of the same 30 days on every run. The blocker is that a runZero custom integration has no run-to-run state store, so this needs either a platform-side cursor or a very short `days_back` and acceptance that a missed run loses data.
- **Exploitability as a runZero-side filter rather than an attribute.** Maze's distinguishing output is the `exploitability` verdict with its `exploitability_reason`, plus `vulnerability_root_cause_analysis` — evidence that a CVE is or is not actually reachable on a given host. Today all of it lands on the finding as attributes and the `exploitable` flag. A variant that imported only `exploitability == "exploitable"` investigations would produce a much smaller, much higher-signal finding set, and needs no new endpoint: `POST /v1/investigations/search` already takes a filter body, though which filter keys it accepts beyond `limit`, `updated_from`, and `cursor` is not documented.
- **Outbound push-back is not supported.** Nothing in the observed API accepts a write, and the integration issues exactly one call, which is a search. There is no documented endpoint for creating an investigation, attaching a comment, or marking a finding, so runZero could not currently feed its own discovery — unmanaged hosts, unscanned segments — back into Maze. If Maze exposes a write API it is not one this integration has seen.
- **Coverage-gap reporting works today and needs no new endpoint.** Maze only knows about hosts some upstream scanner already reported to it, and runZero discovers hosts no scanner was ever pointed at. The difference is a runZero-side query for in-scope assets carrying no `custom_integration:maze` source. The `maze_scanner` attribute makes it sharper: it attributes each covered asset to the scanner that found it, so the gap can be reported per scanner rather than as a single total. This is the one item here with no unknowns in it.
- **Alert or event ingestion has no path.** There is no webhook, no event stream, and no push mechanism in anything this integration touches. Near-real-time behavior would have to be polling `POST /v1/investigations/search` on a short `updated_from` window, which is what the scheduled task already does.

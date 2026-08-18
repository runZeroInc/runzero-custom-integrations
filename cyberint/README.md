# Custom Integration: Cyberint

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cyberint requirements

- Access to the Cyberint Argos platform. **Cyberint is now part of Check Point**, and the product is branded **External Risk Management (ERM)**, sometimes written "Cyberint/ERM". Documentation appears under both names.
- An **API token** generated from the ERM portal, and the portal hostname it belongs to.

> **Two different Check Point credentials exist, and only one of them works
> here.** The **Infinity Portal API key** (created under **Settings > API Keys >
> New** in the Check Point portal) is a separate credential for a separate API.
> This integration needs the **ERM portal API token** described below, which is
> sent as a cookie rather than as a bearer token.

### Generating the API token

1. Log in to the ERM portal.
2. From the left navigation panel, click the **Profile icon > User Settings**.
3. Find **Generate API Token** and click **Generate API Token**.
4. Choose **Copy Token to Clipboard** or **Download Token to File**. **This is a one-time token** — the portal will not show it again.

On an older Cyberint UI revision the same action lives behind the profile button
at the top right → **USER SETTINGS** → the three-dot menu at the top right →
**Generate API Token**.

The token is scoped to the user who generated it and inherits whatever that user
can see. Cyberint publishes no role, scope, or permission name for API access, so
there is no least-privilege role to request by name — control the blast radius by
choosing which user generates the token.

### Finding the tenant hostname

The classic form is `https://<company>.cyberint.io`, and that is what the `url`
parameter's placeholder shows. Since the Check Point acquisition, newer ERM
tenants may be served from an ERM subdomain instead. **Take the hostname from the
URL you actually log in to** rather than assuming `.cyberint.io`. The script
appends `/alert/api/v1/alerts` itself, so configure a scheme and host only.

## Steps

### Cyberint configuration

1. Generate the API token as described above, and note the portal hostname.
2. Confirm the token works from the Explorer host. Note that it is sent as a
   **cookie**, not as an `Authorization` header — this is the vendor's own
   documented approach, matching Cyberint's QRadar workflow and Palo Alto's XSOAR
   pack:

   ```bash
   curl -s -X POST \
     --url 'https://mycompany.cyberint.io/alert/api/v1/alerts' \
     --header 'Cookie: access_token=<token>' \
     --header 'Accept: application/json' \
     --header 'Content-Type: application/json' \
     --data '{}'
   ```

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter data.
    - Customize attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - **Cyberint base URL** (`url`): the portal hostname, for example `https://mycompany.cyberint.io`.
    - **Access token (cookie)** (`access_token`): the one-time API token generated above.
    - **TLS options** (`tls_*`): only needed if the portal is reached through an inspecting proxy.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "Cyberint").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

## What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated with data from Cyberint.
- The script captures details about leaked credentials, domains, and other threat intelligence data.
- Search for these assets in runZero using `custom_integration:cyberint`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real tenant returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair — this integration has only two:

```bash
runzero script --filename cyberint/cyberint.star \
  --kwargs url=https://mycompany.cyberint.io \
  --kwargs access_token=b9f2a41c7d3e48a6b05c19e7f4d82a3c \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/cyberint-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

What you get back is not a device inventory. The script reads **alerts** and
emits one asset per **domain** named in an alert's `related_assets`, carrying the
alerts as `Vulnerability` records. So an empty result usually means the alerts
returned name no domain-type related assets, not that authentication failed —
worth checking against the raw API response before assuming the credential is
bad.

The script pages `POST /alert/api/v1/alerts` with a 1-based `page` and
`size: 100` in the request body, walking until the running count reaches the
`total` the response reports. See **Pagination** below. There is no credential
field for the page size; 100 is the vendor maximum.

If the run fails, the token is the first thing to check, and the failure mode is
distinctive: because the token travels as a **cookie** rather than an
`Authorization` header, a missing or expired token typically produces a redirect
to a login page or an empty alert list rather than a clean `401`.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real tenant:

```bash
runzero script --filename cyberint/cyberint.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real alert.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://mycompany.cyberint.io,access_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py cyberint
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a **domain name mentioned in a Cyberint alert**, not a device. The script walks each alert's `related_assets` array and keeps only entries whose `type` is `domain`; every other related-asset type is discarded, and an alert naming no domain contributes nothing at all.
- Source ID field: **none — Cyberint publishes no asset identifier on this path.** The alert itself has an `id` (used as the `Vulnerability` id), but a related asset carries only `type` and `name`. The script therefore composes an identity from the name: `domain.replace(".", "-")`, so `www.example.com` becomes `www-example-com`.
- Uniqueness scope: the tenant, implicitly — the composed value contains no tenant identifier, and a domain name is globally meaningful anyway, so two tenants importing the same domain would land on the same asset. For most estates that is arguably correct rather than a defect.
- Cardinality: one asset per distinct domain, with every alert naming that domain folded onto it as a vulnerability. Many alerts collapse to one asset by design.
- Stability: **deterministic and therefore stable** — the same domain always produces the same id, across runs and across tenants. This is the one property the composed id genuinely has.
- **Uniqueness is not guaranteed, and this is the finding worth acting on.** Replacing dots with dashes is not a reversible transform: `foo.example.com` and the entirely separate domain `foo-example.com` both compose to `foo-example-com`. Because `matchBehavior` is left at the default, the foreign id *is* used to find merge candidates, so two unrelated domains that collide this way merge into a single runZero asset carrying both sets of findings. The hostname on each record is the raw domain, so the collision is visible after the fact, but nothing prevents it. Nothing forces the substitution either — a runZero foreign id may contain dots — so using the domain verbatim would remove the hazard entirely.
- Reuse behavior: a domain that changes ownership carries its findings across to the new owner, because the identity is the name and nothing else. Inherent to identifying an entity by its domain name rather than by a vendor key.
- Presence: a related asset with no `name` is skipped (`if not domain: continue`). Alerts with no `id` are skipped earlier with `cyberint: skipping alert with no id`.
- Final runZero ID: the dash-substituted domain, e.g. `www-example-com`.
- Missing-ID behavior: skip the related asset; the alert is still processed for any other domain it names.
- Match behavior: **not set** — the platform default, all match and break dimensions on.
- Verdict: **derived, and defensible only because the composed value is deterministic.** Under the governing rule a deterministic name-derived id may reasonably drive matching; the caveat is the non-injective transform above, which means the id is not strictly one-per-entity. Where an id is not one-per-entity, no `matchBehavior` flag helps — a foreign-id match is never vetoed by a conflicting hostname or address — so the fix belongs in how the id is composed, not in the flags.

## Notes

- The script retrieves data from the Cyberint Argos API (`POST /alert/api/v1/alerts`).
- Authentication is by **cookie** — `Cookie: access_token=<token>` — not by bearer token. This is the vendor's documented approach, and it is why the credential field is named `access_token` rather than `api_key`.
- Assets are **domains**, derived from the `related_assets` array on each alert. Alerts become `Vulnerability` records attached to those domains. Alerts that name no domain contribute nothing.
- The task can be scheduled to sync data regularly.
- **The alert request is paged.** See the section below.

## Pagination

`POST /alert/api/v1/alerts` pages on a **1-based `page` and a `size`, both top-level fields of the request body**, and answers with `total` — the number of matching alerts across *all* pages — alongside `alerts`. There is no cursor and no `pagination` wrapper object. The script requests `size: 100` and keeps incrementing `page` until the running count reaches `total`, or a page comes back empty.

Cyberint publishes no public API reference: `cyberint.com`'s API documentation page is a gated marketing resource and the live Swagger sits behind tenant authentication. The contract above is therefore taken from four independent implementations that agree exactly, two of them authored by Cyberint itself:

- `github.com/CyberInt/servicenow-integration` — its `fetchAlerts(page)` posts `{page, size, filters}` with `size = 100`, and its loop decrements the returned `total` by `100 * page` until it is exhausted. This is also where the terminator this script uses comes from.
- `github.com/CyberInt/qradar-universal-cloud-rest-api`, `cyberint-argos/cyberint-workflow.xml` — posts `{"page": 1, "size": …, "filters": {…}}` literally.
- Check Point's Splunk SOAR app (`splunk-soar-connectors/cyberintalerts`) and the Cortex XSOAR pack (`demisto/content`, `Packs/Cyberint`) — both read the count as `total`, and both cap `size` at 100 (XSOAR also rejects a `size` below 10 client-side).

Two things about the previous behavior are worth recording:

- **The request was a single `POST` with an empty `{}` body.** Whatever one response happened to carry was the entire import, and every alert past it was invisible. With the vendor default page size of 10, that is a very small ceiling.
- **The `total_assets` field it decoded does not exist.** No such key appears in this response in any of the four implementations above, nor in FortiSOAR's published output schema for the endpoint; the only count is `total`. The variable would have held `0` on every real run, which is presumably why nothing ever noticed it was unused. The one `total_*` key that does exist anywhere nearby is `alert_data.total_credentials`, which is per-alert payload on a credential-leak alert, not a response-level count.

The `paged` scenario is the regression test: three pages matched on the page number in the POST body, with the domains that exist only on pages 2 and 3 asserted by id.

## Future

- **Filter the alert request.** Now that the body carries paging it can carry `filters` too — a `created_date` window, a status set, a severity floor — which is what would give the integration the incremental mode it lacks. A date-windowed poll is the only way to keep a scheduled task's cost proportional to what changed rather than to the whole alert history. Note that with no cursor, every page must repeat an identical `filters` block or the result set is inconsistent across pages.
- **Import the other `related_assets` types, especially `ip`.** Today only `type == "domain"` produces an asset, so a Cyberint alert about a specific address is discarded. Importing IP-type related assets would let these findings attach to the runZero asset that already holds that address, by IP correlation, instead of creating a name-only asset that may never merge with anything. That is the single change that would most improve how this data lands in runZero, and it needs no new endpoint — the entries are already in the response being parsed.
- **Read the attack-surface inventory rather than scraping names out of alerts.** Cyberint's external attack-surface module maintains its own inventory of an organization's discovered domains, addresses, certificates, and cloud footprint, which is a genuine asset list with vendor-issued records rather than names extracted from alert bodies. That is where a stable per-asset identifier would come from, and it would let this integration import assets that currently have no alerts against them at all. **The endpoint path could not be verified** and is deliberately not guessed at here — confirm it against your own tenant's API reference before building on it.
- **Alert detail and evidence.** Individual alerts can be retrieved by reference id, with analysis reports and attachments alongside them. The current import keeps `title`, `description`, `recommendation`, and `severity`; the detail form is where the supporting evidence lives, which is what an analyst needs when triaging a finding surfaced in runZero.
- **Outbound: close the loop on alert status.** The alerts API supports updating an alert's status, so an alert that runZero data shows to be irrelevant — a domain that resolves to an address runZero knows is decommissioned, for example — could be acknowledged or closed automatically. This writes into an analyst workflow, so it needs to be opt-in and narrowly scoped rather than attached to a scheduled sync.
- **External-exposure gap reporting.** Cyberint looks at an organization from the outside; runZero looks from the inside. Domains Cyberint has alerts against that resolve to addresses runZero has never scanned are external footprint nobody is monitoring internally — the most actionable form of the diff. The reverse direction is less interesting here, because runZero's internal assets are mostly not things an external risk service would ever see.
- **What this API does not offer.** These are threat-intelligence and external-risk findings, not host telemetry: there is no software inventory, no port data, and no hardware detail anywhere in the alert model, so `Software` and `Service` records are out of reach no matter how much more of the API is consumed. The findings imported as `Vulnerability` records also carry no CVE identifiers — they are leaked-credential, phishing-domain, and exposure alerts — so runZero's CVE-based vulnerability reporting will not recognise them.

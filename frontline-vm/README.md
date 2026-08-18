# Custom Integration: Frontline VM

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Frontline VM requirements

- A Fortra VM (Frontline.Cloud) account.
- A Frontline API token. **The token is equivalent to the user's password** — Fortra says so directly — and inherits that user's permissions, so create it on a dedicated account rather than on a named administrator.
- A token is valid **only in the region its account belongs to**. There is no global endpoint.

Fortra's default roles, managed under **Account > Users** (or **Roles**), are
**Account admin**, **Limited User**, **Read Only User**, **Reports User**, and
**User**. **Read Only User** — "for users who only need view access to the Fortra
VM environment" — is the least-privilege choice for an integration account, since
this integration only reads. Fortra does not document a separate API-access
permission toggle, and does not state whether a Read Only User can create its own
token; if it cannot, have an administrator create the token for that account.

## Steps

### Frontline VM configuration

1. Sign in to Fortra VM.
2. From the navigation menu, select **Account > My Profile**.
3. On the **API Tokens** tab, select **+ Create new token**.
4. In the **Add New Token** dialog, enter a name (e.g. `runZero`) and select **OK**.
5. Below the token name, select **Click to show key** to reveal the API key, and copy it.
6. Confirm the token works. The header format is `Authorization: Token <token>`:

   ```bash
   curl -s -H 'Authorization: Token <token>' https://vm.frontline.cloud/api/session/
   ```

#### Finding the right base URL

`https://vm.frontline.cloud` is the default in this integration, and it is not
correct for every account. Fortra publishes a **router endpoint** that returns the
base URL for each product in your region, and its documentation says the base URL
"may periodically change" and should be re-checked at the start of each session:

```bash
curl -s -H 'Authorization: Token <token>' https://api.frontline.cloud/api/router/
```

The response is a JSON object keyed by product. Take the `url` under `vm` — for
example `https://vm.us.frontline.cloud/api/` — and configure its **scheme and
host only** (`https://vm.us.frontline.cloud`), dropping the `/api/` path. If your
account is on a regional host, leaving the parameter at its default will fail to
authenticate no matter how good the token is.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Frontline VM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Frontline VM URL** (`url`): base URL of the Frontline.Cloud instance. Defaults to `https://vm.frontline.cloud`. Take the real value from the router endpoint described above — regional accounts are served from hosts such as `https://vm.us.frontline.cloud`, and the default will not authenticate against them.
   - **API token** (`api_token`): the Frontline API token, sent as the `Authorization: Token` header.
   - **Import vulnerabilities** (`include_vulnerabilities`): optional; fetch active-view vulnerabilities and attach them to the matching hosts (default: enabled).
   - **Minimum vulnerability severity** (`min_vuln_severity`): optional; one of `critical`, `high`, `medium`, `low`, `trivial`, `info`. Leave unset to import every severity.
   - **Maximum days since scan** (`max_days_since_scan`): optional; only import hosts whose active-view record was created within this many days (default: 0, meaning all hosts).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Frontline VM.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:frontline-vm`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
token and see what a real tenant returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename frontline-vm/frontline-vm.star \
  --kwargs url=https://vm.frontline.cloud \
  --kwargs api_token=4d19b8f0c73a41e6ba25d8f0197c3e5b \
  --kwargs include_vulnerabilities=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/frontline-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

There is no page-size parameter to cap a first run — pagination is a Django REST
Framework cursor and the integration follows it to the end. The two parameters
that do bound the work are `include_vulnerabilities`, which skips the second full
walk, and `max_days_since_scan`, which narrows the host set:

```bash
runzero script --filename frontline-vm/frontline-vm.star \
  --kwargs url=https://vm.frontline.cloud \
  --kwargs api_token=4d19b8f0c73a41e6ba25d8f0197c3e5b \
  --kwargs max_days_since_scan=7 \
  --kwargs min_vuln_severity=high
```

`min_vuln_severity` takes one of `critical`, `high`, `medium`, `low`, `trivial`,
`info`, and means "at or above" on Frontline's DDI scale. `get_bool` accepts
`true/false`, `1/0`, `yes/no`, and `on/off`.

One thing to watch when you check the output of that run: Fortra's filter
documentation lists the accepted values **capitalized** (`Critical`, `High`,
`Medium`, `Low`, `Trivial`, `Info`), while this integration sends the lowercase
form from its own `CONFIG` enum. Frontline **silently ignores a filter it does
not recognize** rather than returning an error, so if the filter is
case-sensitive the symptom is not a failure — it is every severity being
imported as though no filter had been set. Count the severities in the output of
a local run before trusting the filter in production.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real tenant:

```bash
runzero script --filename frontline-vm/frontline-vm.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real host
row, so it tells you nothing about field mapping — including nothing about
whether the positional-index filter encoding described in the Notes is reaching
Frontline correctly.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://vm.frontline.cloud,api_token=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py frontline-vm
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a scanned network host — physical device, VM, or appliance — as tracked in the Frontline active view.
- Source ID field: `id` on `GET /api/scanresults/active/hosts/`
- Documentation evidence: Fortra does not publish an open API reference for Frontline.Cloud. The contract used here is the Fortra-authored Cortex XSOAR client, `Packs/Digital_Defense_FrontlineVM/Integrations/Digital_Defense_FrontlineVM/Digital_Defense_FrontlineVM.py`. It treats `id` as the canonical host handle in two independent places: `get_asset_output()` reads `host.get("id")` as the record's `ID`, and `get_host_id_from_ip_address()` resolves an IP to a host `id` purely so it can address the child collection `/api/scanresults/active/hosts/<id>/vulnerabilities/`. The API itself therefore uses this value to scope a host's findings.
- Uniqueness scope: tenant. `id` is an account-local integer, so it is only unique within one Frontline.Cloud instance.
- Cardinality: one row per host. The endpoint serves the *active view*, Frontline's deduplicated rolling inventory, so a host scanned many times is one row rather than one row per scan. This is why the integration reads the active view rather than `/api/scans/`.
- Stability: preserved across rescans for as long as the host remains in the active view. Fortra does not document whether re-addressing a host produces a new active-view row; this is called out as unverified below.
- Reuse behavior: undocumented. The ids are sequential integers and nothing in the reference client suggests recycling, but Fortra publishes no deletion semantics.
- Presence: present on every host row. The reference client dereferences `host.get("id", None)` on every record without a guard.
- Final runZero ID: `frontline-vm:<frontline-host>:<id>` — for example `frontline-vm:vm.frontline.cloud:1001`. The scheme is stripped from the configured URL so switching between `http` and `https` does not re-identify existing assets.
- Missing-ID behavior: skip the record and log only its IP address. No composite fallback and no `new_uuid()`.
- Match behavior: default (`id-match id-break mac-match mac-break ip-match ip-break name-match name-break`).
- Verdict: scoped authoritative.

The `matchBehavior` choice deserves a note, because the usual reflex for a source with a stable foreign id is the `no-mac-break no-ip-break no-name-break` preset. That preset exists to stop *stale or absent* network identifiers from disqualifying an id-based merge, and that is not this source's failure mode. Frontline is an active network scanner: every host row carries a scanner-observed IP, and most carry a MAC, a hostname, and a DNS name as well. Those identifiers are contemporaneous scan evidence, not drifting inventory metadata, so they should be allowed to participate in matching — that participation is precisely how a Frontline host gets merged onto the asset runZero already discovered. Suppressing the break flags here would discard the strongest correlation signal the source has. The default is therefore kept, and the stable `id` prevents duplication across polls.

### Notes

- **What is imported.** Assets come from `GET /api/scanresults/active/hosts/`: `hostname` and `dns_name` become hostnames (de-duplicated case-insensitively), `ip_address` and `mac_address` become a single network interface via the `network_interface()` helper, `os` becomes the asset OS, and `date_created` becomes `firstSeenTS`. Vulnerabilities come from `GET /api/scanresults/active/vulnerabilities/`: `title` becomes the name, `severities.ddi` maps to `severityRank`/`riskRank`, and `active_view_date_created` becomes `firstDetectedTS`.
- **No software or services are imported.** Neither endpoint exposes an installed-software inventory or an open-port list.
- **`os_type` is a custom attribute, not `deviceType`.** Frontline's `os_type` is an operating-system family (`Windows`, `Linux`, and similar), which is a different axis from runZero's device-type taxonomy (`Server`, `Desktop`, `Printer`). Mapping one onto the other would assert a classification the source never made, so `os_type` is carried as `frontline_vm_os_type` and runZero's own device-type fingerprinting is left to decide.
- **Severity counts are imported.** `active_view_vulnerability_severity_counts.weighted.ddi.counts` is flattened into `frontline_vm_vuln_counts_critical`, `frontline_vm_vuln_counts_high`, and so on. These are useful for triage even when `include_vulnerabilities` is disabled. Only `critical` is confirmed by the reference client; the remaining keys are passed through as-is, so whatever Frontline returns is what appears.
- **All custom attributes use the `frontline_vm` prefix with an `_` separator**, which also flattens the nested count structure with underscores.
- **Vulnerabilities are joined to hosts on IP address, falling back to hostname.** The active-view vulnerability record carries `hostname` and `ip_address` but **no host id** — an id join is not available. The evidence is the reference client itself: to scope findings to one host it cannot filter the flat list, and instead switches to the `/api/scanresults/active/hosts/<id>/vulnerabilities/` sub-resource, and it needs `get_host_id_from_ip_address()` to get there. That sub-resource would be one request per host, so this integration fetches the flat list once and joins locally. Each finding is indexed under its IP when it has one and under its lowercased hostname otherwise — never both, because indexing under both would attach a finding to every host sharing a hostname. Consequences worth knowing: two Frontline hosts sharing an IP will both receive that IP's findings, and a host whose address changed between the host scan and the vulnerability scan will show no findings until the next scan. Findings with neither an IP nor a hostname cannot be joined and are dropped with a logged count.
- **CVE identifiers are recovered by pattern, not by field.** Frontline exposes no CVE field on the vulnerability record. The integration scans the `title` and then the `data` blob for the exact `CVE-YYYY-NNNN` format and uses the first match; nothing else is inferred from the free-form text. The match is upper-cased before assignment because `Vulnerability.cve` is validated against `^CVE-[0-9]{4}-[0-9]{4,19}$` *before* the type normalizes case, so a lower-case `cve-2024-11111` in the source text fails the whole record otherwise.
- **No `Service` objects and no Vulnerability service fields.** The dossier for this build asked whether the free-form `data` blob reliably carries a port or protocol. It does not: the reference client never parses `data`, it passes the value straight through as an incident `details` string and as the `vuln-info` context field, and the integration YAML documents it only as "Information related to the vulnerability". There is one undocumented `vuln.get("port")` read in the client's incident path, but it appears in no documented output, no table header, and no other code path, so it is not evidence of a reliable port. Rather than tie findings to a socket on that basis, `serviceAddress`/`servicePort`/`serviceTransport` are left unset and the raw `data` value is preserved as `frontline_vm_data` custom attributes (flattened if Frontline returns an object). If a live tenant confirms a consistent top-level `port`, that is the field to wire up — not `data`.
- **Severity has no numeric score.** Frontline grades on its own qualitative DDI scale, so the same 0-4 rank drives both `severityRank` and `riskRank`, and `severityScore`/`riskScore`/CVSS fields are left unset rather than fabricated. The mapping is `critical=4, high=3, medium=2, low=1, trivial=0, info=0`; an unrecognized value falls back to 0.
- **Pagination is a Django REST Framework cursor.** Every list response is `{count, next, results[]}` where `next` is an absolute URL. The integration follows `next` verbatim until it is falsy and never constructs a page URL. There is a subtlety here worth recording: passing `params` to `get_json` *replaces* the URL's query string rather than merging into it, so passing even an empty `params={}` alongside a cursor URL silently strips the cursor and restarts pagination at page one — an infinite loop. The `_get_page()` helper omits `params` entirely once the first page has been fetched. No page-size parameter is exposed, because the page size is not documented and the cursor makes it unnecessary.
- **Filter parameters use positional-index encoding.** Frontline requires each filter key to be prefixed with its ordinal position — `_0_lte_vuln_severity_ddi=high`, `_1_...` — and **silently ignores** any filter that is not, without returning an error. All filters are built through `_index_filters()`, which reproduces the `parse_params()` behavior in the reference client. Anyone adding a filter must route it through that function. The two filters currently exposed are `min_vuln_severity` → `lte_vuln_severity_ddi` and `max_days_since_scan` → `gte_host_date_created`; both were verified on the wire against a local fixture. Note the `lte` in the severity filter is not a typo: on the DDI scale a lower value is more severe, so "less than or equal to `high`" selects `critical` and `high`. This matches the reference client's own "minimum severity" semantics.
- **Rate limiting.** Fortra publishes no rate limit for the Frontline API. `get_json` handles transient statuses (408, 425, 429, 5xx) with exponential backoff and honors `Retry-After`, retrying three times by default. Requests here keep that count and widen the backoff factor to 2.0 seconds.
- **Memory.** Host pages are streamed with `report_asset` so the full inventory is never resident. The vulnerability index is built first and held in memory as finished `Vulnerability` objects; findings per host are capped at 99, the platform's child-collection limit.
- Unverified assumptions, stated plainly: that active-view host `id` survives a host being re-addressed; that Frontline never recycles a deleted host id; that the severity-count keys beyond `critical` are named `high`/`medium`/`low`/`trivial`/`info`; and that `date_created` on a host row means first entry into the active view rather than the most recent scan. The date-filter semantics come from the reference client, which treats `gte_host_date_created` as "days since scan".
- This integration was validated against local fixtures, not a live Frontline.Cloud tenant.

## Future

**Scan orchestration as an outbound integration — the highest-value pairing.** `/api/scans/` is not read-only: the reference client issues `POST /api/scans/` with a full scan payload, so runZero could trigger a Frontline scan against assets it discovered that Frontline has never scanned. This closes a real gap, because a vulnerability scanner only knows what it has been pointed at. Building it means reproducing the payload the client assembles: `GET /api/networkprofiles/?_0_eq_networkprofile_internal=True` to enumerate internal network profiles, `GET /api/scanners/<id>/` to confirm a scanner in that profile is `online`, `GET /api/networkprofiles/<id>/rules/` to find the profile whose `ip_address_range` brackets the target, `GET /api/scans/policies` to validate the scan policy name, and optionally `GET /api/session/` plus `GET /api/businessgroups/` when the account has business groups enabled. Two friction points are worth flagging before anyone starts: the `adhoc_targets[].ip_address_range` object wants `low_ip_number`/`high_ip_number` as 32-bit integers alongside the dotted-quad strings, and Starlark has no `inet_aton` equivalent, so the conversion has to be written by hand from the octets; and the profile lookup is a nested walk that can cost several requests per scan request.

**Vulnerability-only enrichment mode.** A variant that imports findings without creating assets — pulling only `/api/scanresults/active/vulnerabilities/` and correlating on IP and hostname with `matchBehavior="no-id-match no-id-break"` — would suit customers who want Frontline risk data on their existing runZero inventory without Frontline's host records becoming assets in their own right. The endpoint already carries everything needed for this; the only reason it is not the default is that the host endpoint's identity data is much stronger.

**Scan-coverage-gap reporting.** Answering "which runZero assets have never appeared in a Frontline scan" needs no new Frontline endpoint — the active-view host list this integration already imports is the coverage set, so the gap is a runZero-side query against assets lacking the `frontline-vm` custom integration source. Turning that answer into action is what the outbound scan integration above is for. Adding `GET /api/scans/` as a metadata import would enrich it further with scan names, policies, and schedules, so a gap could be attributed to a specific missing scan rather than just reported as absent.

**Alert and event ingestion.** Frontline exposes no webhook or event-stream endpoint in the reference client. New-finding detection there is implemented by polling `/api/scanresults/active/vulnerabilities/` with a `gte_vuln_date_created` filter and comparing `active_view_date_created` against the previous run. Any near-real-time behavior on the runZero side would have to be built the same way, on the task schedule.

## API documentation

Fortra does not publish an open API reference for Frontline.Cloud; API details are available to account holders through the in-product documentation. The contract implemented here was derived from the Fortra-authored Cortex XSOAR integration, which is the public source of record for these endpoints:

- Client implementation (authentication, pagination, filter encoding, object schema, identity, scan creation): https://github.com/demisto/content/blob/master/Packs/Digital_Defense_FrontlineVM/Integrations/Digital_Defense_FrontlineVM/Digital_Defense_FrontlineVM.py
- Command and output schema (documented vulnerability and host fields): https://github.com/demisto/content/blob/master/Packs/Digital_Defense_FrontlineVM/Integrations/Digital_Defense_FrontlineVM/Digital_Defense_FrontlineVM.yml
- Pack overview: https://github.com/demisto/content/tree/master/Packs/Digital_Defense_FrontlineVM
- Fortra Frontline VM product page: https://www.fortra.com/products/frontline-vulnerability-manager
- Django REST Framework pagination (the `{count, next, results}` envelope Frontline returns): https://www.django-rest-framework.org/api-guide/pagination/

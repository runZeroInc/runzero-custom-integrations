# Custom Integration: Akamai Guardicore Centra

Imports assets from the Guardicore Centra management console. Centra
concurrently exposes a v3 and a v4 API, and this directory ships **two**
scripts — pick one:

| Script | Reads assets from | Also does |
| --- | --- | --- |
| `centra-v4-api.star` | `/api/v4.0/assets` for both `on` and `off` status | Resolves label GUIDs to `key: value` strings via `/api/v4.0/labels/{guid}`, with a cache shared across pages |
| `centra-v3-api.star` | `/api/v4.0/assets` for `on`, `/api/v3.0/assets` for `off` | Nothing extra |

A large portion of the data overlaps. **Use `centra-v4-api.star` unless you have
a specific reason not to** — it is the one that resolves labels into readable
values. Review both if you are unsure which fits your use case.

Both scripts authenticate identically and take the same three parameters, so
switching between them is a script swap, not a credential change.

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
```

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Centra management console over HTTPS.

## Guardicore Centra requirements

- The URL of the Centra management console, e.g. `https://centra.example.com`.
  Supply the base URL only — the scripts append `/api/v3.0/...` and
  `/api/v4.0/...` themselves. This used to be a `CENTRA_BASE_URL` global inside
  the script; it is now the `url` credential parameter, and the global no longer
  exists.
- A Centra **username and password**. Both scripts exchange them for a JWT at
  `POST /api/v3.0/authenticate` and send it as `Authorization: Bearer <token>`
  on every subsequent call. There is no API-key or client-credentials option;
  the credential is an ordinary Centra account.
- That account needs read access to the asset inventory, and — for
  `centra-v4-api.star` — to labels.

### Creating the credential in Centra

Create a dedicated, read-only Centra user for this integration rather than
reusing an operator login, and record its username and password.

**Akamai does not publish the Centra API reference.** The administration guide
is behind a customer login, so nothing below is quoted from it. The steps that
follow come from Akamai's own [Unified Log Streamer credentials
guide](https://github.com/akamai/uls/blob/main/docs/AKAMAI_API_CREDENTIALS.md),
which is Akamai-authored and public, and describes exactly this
username-and-password flow against the same API:

1. Go to **Administration**.
2. Select **Users** in the left navigation tree.
3. Click **Create User**.
4. Enter a username and a password, and select a permission scheme.
5. Save.
6. **Log out and log back in as the new user, and complete the
   password-change-on-first-login flow.**

Step 6 is not optional and is the single most common way this integration is
misconfigured. A brand-new Centra user is created in a must-change-password
state; until a human logs in and clears it, the account cannot authenticate and
the integration returns `authentication failed`. Do this *before* you create the
runZero credential, and make sure the password you finally set is the one you
put in runZero.

**On the permission scheme — Akamai's own document contradicts itself here.** It
tells you to create a *"read only (= GUEST role)"* user, and then instructs you
to select **"Support"** as the permission scheme. Those are different schemes.
`GUEST` is the named read-only role; `Support` and `Administrator` also appear as
selectable schemes. We could not obtain the authoritative list, so the honest
guidance is: pick the most restrictive scheme that passes the asset check below,
starting with the read-only one, and escalate only if the check fails.

Two more things worth knowing before you create the account, because both cause
failures that look like something else:

- **Multi-factor authentication probably breaks this.** The script performs a
  single-shot username-and-password POST and reads `access_token` out of the
  response. Guardicore's own published Python client has no two-factor handling
  of any kind, which suggests an MFA-enrolled account cannot complete this flow
  — though Akamai does not document that outright, so treat it as a likely cause
  rather than a certainty. The symptom is `invalid authentication data`:
  authentication was answered, but the response carried no `access_token`.
- **Password rotation policy applies to this account too.** A Centra password
  policy that expires the password will stop the scheduled task at the next
  expiry, with an authentication failure rather than a warning.

**Authentication failures come back as `403`, not `401`.** Guardicore's client
treats 403 as the authentication-error status, so do not read a 403 here as "the
account exists but lacks permission" without checking the credential first.

Confirm the credential from the Explorer host before configuring anything:

```bash
curl -s -X POST 'https://centra.example.com/api/v3.0/authenticate' \
  -H 'Content-Type: application/json' \
  -d '{"username":"runzero","password":"ExampleFakePassw0rd"}'
```

A success returns a JSON body containing `access_token`. Then check the account
can actually read assets:

```bash
curl -s -H 'Authorization: Bearer <access_token>' \
  'https://centra.example.com/api/v4.0/assets?status=on&max_results=1'
```

## Guardicore Centra API Docs

- Requires a customer account. Akamai does not publish the Centra API reference publicly.

## Steps

### Guardicore Centra configuration

1. Select the script to use — `centra-v4-api.star` in almost all cases. See the table at the top of this file.
2. Determine the Centra console URL. It goes in the `url` credential field; do not edit the script.
3. Create the read-only Centra user described above, complete its first-login password change, and note its username and password.

### runZero configuration

1. (OPTIONAL) - make any necessary changes to the script to align with your environment.
    - Both scripts import assets with status `on` and `off`, in that order. Assets with status `Deleted` are never requested; Centra retains those records indefinitely.
    - To import only powered-on assets, remove the `'off'` entry from the status loop in `stream_assets` — in `centra-v4-api.star` that is the `for status in ('on', 'off'):` tuple, and in `centra-v3-api.star` it is the second entry of the `status_urls` list. Both carry a comment marking the spot.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - **Centra URL** (`url`): base URL of the management console, e.g. `https://centra.example.com`
    - **Username** (`username`): the Centra account
    - **Password** (`password`): that account's password
    - **Maximum pages to retrieve** (`max_pages`): optional; safety ceiling on the paging walk (default: 10000, which is ten million assets per status at 1000 per page). Raise it if a run logs `page limit of ... hit (integration safety limit`.
    - TLS options arrive through the shared include; set them if the console uses an internal certificate authority.
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

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter. **Note the filename** — this directory ships two scripts and the example
targets `centra-v4-api.star`, the recommended one:

```bash
runzero script --filename akamai-guardicore-centra/centra-v4-api.star \
  --kwargs url=https://centra.example.com \
  --kwargs username=runzero \
  --kwargs password='ExampleFakePassw0rd' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./centra-run
```

To try the other script, change only the filename — the parameters are identical:

```bash
runzero script --filename akamai-guardicore-centra/centra-v3-api.star \
  --kwargs url=https://centra.example.com \
  --kwargs username=runzero \
  --kwargs password='ExampleFakePassw0rd' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./centra-v3-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path —
which matters here, because comparing the two scripts means two runs. Add `--verbose`
for the request-by-request log, or omit `--output` to see only the log lines. Both scripts page
1000 assets at a time through the full `on` and `off` inventory, so a first run against a
large Centra is a full collection. Two guards bound that walk. The primary one is a
page-signature check: a page whose length and end ids match the previous page means the
appliance ignored `start_at`, and the walk stops on the first repeat with `paging stopped
after N pages (API returned the same page twice ...)`. Behind it, `max_pages` is a
backstop that logs `page limit of N hit (integration safety limit, ...) - raise the
max_pages parameter to import the rest`. Both lines report what fraction of Centra's own
`total_count` the run actually retrieved.

`authentication failed` in the log is a rejected credential; `invalid authentication
data` means Centra answered but the response carried no `access_token`, which is what
an MFA challenge looks like from here.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a password is passed through intact. Only a value that *also* contains an
`=` flips the flag into comma-separated parsing, and then the value is cut at the first
comma — the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. A Centra password containing both characters needs a
second pair of quotes around the whole argument:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live console:

```bash
runzero script --filename akamai-guardicore-centra/centra-v4-api.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Centra accepts the credential or that any asset is parsed.
The fixture scenarios are what exercise the parsing — the happy path, a degraded
response, and the label cache:

```bash
python3 tests/run.py akamai-guardicore-centra
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat akamai-guardicore-centra/centra-v4-api.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://centra.example.com,username=runzero,password=ExampleFakePassw0rd' \
  --output ./centra-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so a password containing a comma cannot be passed this
way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration 
- The task will update the existing assets with the data pulled from the Custom Integration source 
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:<INSERT_NAME_HERE>`

**!NOTE!** Centra agent IDs are known to change frequently as the agent ID is determined by several factors such as:
- hostname (minus FQDN)
- BIOS UUID
- product_serial file
- Vendor
- Network interface names and associated hardware addresses (loopbacks, virtual bonding, vlan, excluded interfaces are not considered)
-- Commonly NIC configuration changes are responsible for agent ID changing

## Asset identity

- Target entity: an **asset** in the Centra management console — normally an agent-managed VM or host, but the collection also carries orchestration-derived records (the `orchestration_metadata.f5_device_hostname` / `vs_name` fields describe an F5 virtual server rather than a machine).
- Source ID field: `objects[].id`, with a fallback chain. `centra-v4-api.star` reads `id` or `bios_uuid` or `instance_id`; `centra-v3-api.star` reads `id` or `bios_uuid` or `guest_agent_details.hardware.hw_uuid`. A record carrying none of them is skipped with a log line naming only its `name`.
- **The two scripts' fallback chains diverge at the third element**, so a record with no `id` and no `bios_uuid` receives a different foreign id depending on which script is running, and swapping scripts re-points exactly those assets. Where `id` is present — the normal case — both scripts agree, which is what makes the swap described at the top of this file safe in practice.
- Documentation evidence: **none available.** Akamai does not publish the Centra API reference, so no vendor statement about `id` could be read. What is established from the code alone: `id` is the field both scripts read first; the agent carries its *own* separate identifier at `agent.id`, which is imported as the `agent.Id` custom attribute and is **not** used as the asset identity; and label lookups are addressed by a different GUID space entirely (`GET /api/v4.0/labels/{guid}`).
- Uniqueness scope: one Centra management console. The value is used bare — neither script prefixes it with the console hostname — so two consoles imported through the same custom integration share a single id space. The record's own `mssp_tenant_name` field shows one console can serve several tenants, which means `id` must already separate them inside the console.
- Cardinality: one source row per asset record, fetched twice over — once with `status=on` and once with `status=off`. A machine that changes power state between the two passes can legitimately appear in both; it carries the same `id` in each, so it converges on one asset.
- Stability: **not established, and this is the open question for this integration.** The note directly above records that Centra *agent* IDs are derived from hostname, BIOS UUID, product serial, vendor, and NIC hardware addresses, and that NIC configuration changes are the common cause of one changing. That note describes `agent.id`, which is not what is used here — but Akamai publishes nothing that ties the asset `id` to, or separates it from, that derivation, so it cannot be claimed as immune. Treat a churning foreign id as possible until it has been observed over several polls on a real console.
- Reuse behavior: unknown. Nothing public describes what happens to an `id` after an asset is deleted from Centra.
- Presence: assumed present on every record; the skip path exists because it could not be confirmed.
- Final runZero ID: the raw Centra value, e.g. `9d8f4b2c-1e3a-4c5d-8f70-2a1b3c4d5e6f`.
- Missing-ID behavior: skip and log, after both fallbacks have been tried.
- Match behavior: **not set** — the platform default, which leaves all eight match and break dimensions on, so the foreign id is used both to find merge candidates and to disqualify them.
- Verdict: **scoped authoritative if `id` is stable; unverified.** Under the governing rule this default is the right call *provided* the id persists, and the wrong one if it behaves like the agent id described above. It is recorded here as a known gap rather than papered over, because the two outcomes are very different in practice.

  If the id does churn, the failure mode is a duplicate, not a corrupted asset: a record arriving with a new foreign id will not merge onto the existing runZero asset even though the hostname and MAC still match, because runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`. No `no-*-break` flag prevents it. The duplicate has to be reconciled in runZero. Conversely, once an id *does* match, nothing fragments the asset — a foreign-id match is never vetoed by a conflicting MAC, IP, or hostname.

## Future

The scripts here read four endpoints in total: `POST /api/v3.0/authenticate`, `GET /api/v4.0/assets`, `GET /api/v3.0/assets`, and `GET /api/v4.0/labels/{guid}`. Everything below is what the same credential could reach beyond them. **Akamai does not publish the Centra API reference**, so endpoint paths named here are inferred from the versioned `/api/vN.0/<resource>` shape the four confirmed endpoints follow and from Akamai's public tooling — verify each against your own console before building on it.

- **Incident ingestion as an event feed.** Centra's incident store is what Akamai's own [Unified Log Streamer](https://github.com/akamai/uls) exists to stream — the same product, the same username-and-password credential this integration already uses. Centra incidents cover network scans, reveal/deception hits, and policy violations, all of which name the asset that triggered them and are therefore joinable to what this integration already imports. This is the single highest-value addition available and the one with the best public evidence behind it, because ULS is Akamai-authored, public, and does exactly this against this API. It belongs in a time-windowed event feed with a high-water mark, not in the inventory sync: incidents are behavioral detections, not CVEs, and they have no stable mapping onto runZero `Vulnerability` records.
- **Flow-based coverage-gap reporting — the thing Guardicore is uniquely good at.** Centra's whole reason for existing is east-west flow visibility: it records which asset talked to which, on what port. Diffing that against runZero's own inventory answers a question neither product answers alone — *which peers does Centra observe in flows that no Centra agent is installed on, and that runZero has also never scanned?* Those are the genuinely unmanaged hosts. The reverse diff is just as useful: assets runZero discovers that carry no Centra agent are segmentation blind spots, and the agent state needed to identify them (`agent.Id`, `agent.Version`, `agent.LastSeenTS`, `status`) is **already imported as custom attributes today**, so that half is a reporting exercise with no new API work at all.
- **Outbound: runZero inventory as Centra labels.** Centra's segmentation policy is written entirely against labels — `key: value` pairs — which is why `centra-v4-api.star` resolves them through `GET /api/v4.0/labels/{guid}` and imports them as `key=value` tags. The write direction is the natural outbound integration: push a runZero query result (every asset runZero classifies as a domain controller, everything on a PCI subnet, everything missing an EDR agent) into Centra as a label, and Centra's segmentation rules pick it up without an operator re-deriving the same set by hand. This is a genuinely additive direction — runZero sees unmanaged hosts Centra's agents cannot — but it writes into the input of a policy engine that can block traffic, so it needs a dry-run mode and an explicit confirmation step, not a scheduled sync.
- **Agent lifecycle management is reachable and should be left alone.** The same credential can reach agent administration, including upgrade and uninstall operations. Nothing about a runZero import justifies exercising those: uninstalling a Guardicore agent removes enforcement from a production host. Named here only so it is a recorded decision rather than an oversight.
- **What this API does not offer.** There is no installed-software inventory and no CVE feed in the asset records this integration reads — `os_info` carries a kernel version and nothing more — so no amount of additional endpoint work produces `Software` or `Vulnerability` records from the asset resource. Centra also publishes no per-asset open-port list, so no `Service` records either. Vulnerability data for these hosts has to come from a scanner, which is what runZero itself or one of the VM integrations in this repository is for.

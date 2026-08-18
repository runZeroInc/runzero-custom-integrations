# Custom Integration: Automox

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach `https://console.automox.com` over HTTPS.

## Automox requirements

- An **Organization API key** for a user that can read devices and software.
- The API base URL, which is `https://console.automox.com`. The script appends `/api`
  itself.

Two host notes worth getting right up front. `api.automox.com` is **not** the REST API — it
is an agent-communication endpoint that appears on Automox's firewall allowlist, and
pointing this integration at it will not work. And Automox's OpenAPI specification declares
exactly one server, so there are **no regional API hosts**; EU and AU customers use
`https://console.automox.com` like everyone else.

Automox's old developer portal at `developer.automox.com` is dead and redirects. The
current, machine-readable reference is the Console API spec linked from
`https://console.automox.com/api/docs`.

## Steps

### Automox configuration

1. **Create the account the key will belong to, with the narrowest role that works.**
   Automox API keys carry no permissions of their own: "API keys inherit the same
   permissions that the user has." There is no per-key scoping — the only options at
   creation time are a name and an optional expiration date.

   The least-privileged built-in role is **Read Only**, described as "Users with this role
   can read all content within a organization." Its grants include **Devices: Read**,
   **Package: Read**, and **Organization: Read**, which is exactly what this integration's
   three calls need. A custom role limited to those three plus **Personal API Keys: Manage**
   would be tighter still.

   One thing Automox does not reconcile in its own documentation: the key-management page
   lists a prerequisite of Full Administrator (or a custom role with Organization: Read and
   Manage), while also stating that adding an organization API key *for yourself* requires
   only Personal API Key: Manage — which Read Only has. **We could not establish whether a
   bare Read Only user can self-serve a key.** If it turns out they cannot, have an
   administrator mint the key while the key still belongs to the Read Only user.

2. **Create the Organization API key.** In the Automox console, open the **Settings** menu —
   the **three vertical dots (⋮) in the upper right** — and choose **Secrets & Keys**. That
   lands on the Secrets Management page; the **Organization API Keys** table is further down
   and may need scrolling. Select **Add**, enter a unique name, optionally set an expiration
   date, and select **Create**.

   Older Automox pages, including one of their own developer docs, call this menu item
   **Keys**. The current label is **Secrets & Keys**. A separate **Keys** page does still
   exist for *global* keys, under Setup & Configuration in the Global View — that is a
   different thing.

   An Organization API key is hard-scoped: it "never grants access to other organizations,
   even if the user has roles elsewhere." A user may hold at most **10** organization API
   keys.

3. **Find your Organization ID** if you intend to pin the integration to one organization.
   Automox renamed *Zones* to *Organizations*, not the other way round, so current
   documentation and the API both say organization. Three ways to get the numeric ID:

   - Switch to the organization in the console and read the value after `?o=` in the URL,
     e.g. `https://console.automox.com/dashboard?o=1234`.
   - Organization selector (upper right) → **Manage Orgs and Users** → **Setup and
     Configuration** → the **Organization ID** column of the Organizations table.
   - `GET /api/orgs`, which returns an `id` for each organization.

4. **Confirm the key from the Explorer host** before configuring anything in runZero:

   ```bash
   curl -s -H 'Authorization: Bearer <api token>' \
     'https://console.automox.com/api/orgs' | jq '.[] | {id, name}'

   curl -s -H 'Authorization: Bearer <api token>' \
     'https://console.automox.com/api/servers?o=1234&page=0&limit=1&include_details=1' | jq .
   ```

   `Authorization: Bearer` is the only documented scheme; the `?api_key=` query parameter
   that appears in older material is not in the current specification.

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter device data.
    - Customize data attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - **Automox API URL** (`url`): optional; defaults to `https://console.automox.com`.
      Override only for a deployment that genuinely differs.
    - **Automox API token** (`api_token`): the Organization API key created above.
    - **Organization hint** (`organization_hint`): optional — but read the note below on
      what it actually does before setting it.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "automox").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

#### What `organization_hint` really does

The parameter takes "an Automox organization ID or name", and both forms now work.

- A **numeric organization ID** is used as-is: no `/api/orgs` call is made, the ID scopes the
  software lookup, and it is passed as the `o` parameter on the device query. This is the
  cheapest and most explicit form.
- An organization **name** is looked up against `/api/orgs` and matched
  case-insensitively. On a match the resolved ID is used exactly as a numeric one would be,
  and the resolution is logged: `automox: organization_hint '<name>' resolved to org id <id>`.
- A name that **matches nothing** is reported rather than swallowed:
  `automox: organization_hint '<name>' matched no organization by id or name; using '<other>'
  and leaving the device listing unscoped`. This used to be silent — the name was ignored, the
  software lookup fell through to the first organization in the list, and the device query was
  issued unscoped, so an operator who mistyped the name got a *different* organization's
  inventory and a successful-looking run. If you see this line, the value is wrong.
- **Left blank**, the software lookup uses the first organization `/api/orgs` returns and the
  device query is issued with no `o` parameter, so devices come from whatever organization the
  key defaults to. That is fine on a single-organization account and is why the unhinted
  behavior was left as it was.

If `/api/servers` answers 404 for the scoped organization — a key that cannot see it — the
listing is retried unscoped, and that fallback is now logged too.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what an
integration would import before scheduling it. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename automox/automox.star \
  --kwargs url=https://console.automox.com \
  --kwargs api_token=exampleFakeAutomoxApiToken0123456789abcdef \
  --kwargs organization_hint=1234 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./automox-run
```

`--output` writes the assets the run produced, and it requires `--custom-integration-id` —
the scanner rejects the run with `custom integration ID required for output` without one.
Any well-formed UUID works for a local run; use the real one from the console when you want
the output to match a scheduled task. The scanner also refuses to write into a directory
that already exists, so add `--overwrite` when re-running into the same path. Add
`--verbose` for the request-by-request log, or omit `--output` to see only the log lines.

**Mind the rate limit on repeated command-line runs.** The device endpoint is far more
tightly limited than the rest of the API: Automox documents `/servers` as "rate limited to
<30 requests per minute", and "rate limited clients will receive a 429 for 1 minute" —
against a general ceiling of 100 authenticated requests per second everywhere else. The
script pages 500 devices at a time, so a large account can approach that on its own without
you re-running it in a loop. Responses carry `x-ratelimit-limit`, `x-ratelimit-remaining`,
`x-ratelimit-reset`, and `retry-after`.

`Failed to fetch devices from Automox:` in the log ends the run and names the underlying
error. A run that reports nothing at all, on an account with devices, is usually the
organization mismatch described above rather than a credential problem.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma —
the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. An Automox API token is opaque; if one arrives with both
characters, wrap the whole argument in a second pair of quotes:
`--kwargs '"api_token=ab=cd,ef"'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live console:

```bash
runzero script --filename automox/automox.star --validate
```

**Expect this one to report failure, and expect that to be fine.** Validation answers from a
local dummy server whose canned response contains no organizations, so `choose_org_id` hits
its own guard and the run ends with:

```
automox/automox.star: script returned an error after 1 validation HTTP request(s):
fail: No organizations returned from Automox; cannot determine org_id.
```

That message means the script compiled, declared its parameters, issued a request, parsed
the reply, and correctly refused to continue without an organization — which is the whole
of what validation can establish here. It does not prove Automox accepts the token, that the
user's role can read devices, or that any device is parsed. The fixture scenarios are what
exercise the parsing — including the organization-hint path and the rate-limit response:

```bash
python3 tests/run.py automox
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat automox/automox.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://console.automox.com,api_token=exampleFakeAutomoxApiToken0123456789abcdef,organization_hint=1234' \
  --output ./automox-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for a
script with a different entry point. Note that `--custom-integration-script-kwargs` takes
one comma-separated string — genuinely, and with no single-`=` exemption. Here a comma in
*any* value splits it. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- The task will kick off on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated based on **Automox device inventory**.
- The script captures details like **OS version, agent status, compliance, and IPs**.
- Search for these assets in runZero using `custom_integration:automox`.

## Asset identity

- Target entity: a **device with an Automox agent installed** — the unit Automox patches, one row per agent enrollment.
- Source ID field: `id`, from `GET /api/servers`.
- Documentation evidence, derivable from this integration's own code: the software pass fetches `GET /api/orgs/{orgID}/packages` and indexes every package row by its `server_id`, and the device pass then looks its software up with `sw_by_server.get(str(device_id))`. Automox's own package records are therefore keyed on the same value this integration uses as the asset identity, which is the strongest available evidence that `id` is the device primary key rather than an incidental field.
- Uniqueness scope: the Automox account. The value is used bare, with no organization or account prefix, so two Automox accounts imported through one custom integration would share an id space. Because an Organization API key "never grants access to other organizations", one credential cannot straddle organizations, which limits the exposure in practice.
- Cardinality: one source row per device. Package rows are many-to-one and collapse onto the device through `server_id`, so they never create assets of their own.
- Stability: **partially established.** The id survives rename, address change, reboot, and OS patching — it is the key Automox's own package join depends on across calls. What could **not** be determined is whether an agent uninstall and reinstall on unchanged hardware re-uses the existing device record or enrolls a new one. Automox publishes no statement either way, so assume a reinstall can mint a new id.
- Reuse behavior: not documented. The value is a monotonic integer rather than a UUID, so recycling after deletion cannot be ruled out on shape alone; nothing observed suggests it happens.
- Presence: expected on every device row. `build_device_asset` still checks, and skips with `automox: skipping device with no id: name=<name>` when it is missing or empty, because `.get`'s default does not catch an explicit null.
- Final runZero ID: the raw Automox device id as a string, e.g. `4821993`.
- Missing-ID behavior: skip the record and log its name. No identifier is synthesized.
- Match behavior: **not set** — the platform default, all match and break dimensions on. This is the correct choice under the governing rule: Automox issues a persistent per-device identifier and this integration uses it directly, so matching on the foreign id is what keeps a roaming laptop on one asset as its address and hostname change.
- Verdict: **scoped authoritative** for an agent enrollment within one Automox account; derived for the physical machine, to the extent that a reinstall may mint a new id.

Two consequences worth stating plainly:

- **If a reinstall does mint a new id, the result is a duplicate asset, and no `matchBehavior` flag prevents it.** runZero refuses any merge that would place two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`. Relaxing `id-break` would not help. The duplicate has to be reconciled in runZero.
- **The `organization_hint` mismatch described above shows up as missing software, not as wrong software.** When the software list is fetched from one organization and the device list comes from another, the two are joined on `server_id`, so the ids simply fail to match and the devices import with no software attached. A silently empty software list on an otherwise healthy import is the symptom to look for.

One flag to be aware of when reading the imported records: the asset is built with `trust_os=True` and `trust_os_version=True`, so Automox's `os_family`/`os_name`/`os_version` values are asserted over what runZero fingerprints for itself. That is defensible — the values come from an agent running on the host, which is better evidence than a network fingerprint.

`trust_device_type=True` used to be set alongside them and has been removed. **This integration assigns no `deviceType` at all**, and the flag could never have had an effect: `IdentifyTypeFromCustomIntegration` skips a candidate whose type is empty *before* it reads the trust flag, so the flag was discarded unread. It looked like a deliberate decision to override runZero's fingerprint while overriding nothing. There is also no type to set — `/api/servers` reports OS and hardware detail but nothing naming a chassis or a role — so runZero fingerprinting the type from the manufacturer and model is the right outcome rather than a guess from the OS family.

### Notes

- The script **automatically retrieves all devices**, including paginated results. It pages
  `/api/servers` 500 at a time starting at `page=0`, which is what the API expects — paging
  is zero-indexed here, and `limit` accepts 1 to 500.
- The script always sends `include_details=1`. This matters: since Automox's "Fast By
  Default" change, `/api/servers` returns a minimal payload unless detail is requested
  explicitly, and without it there would be no OS or hardware information to import.
- Software inventory comes from `/api/orgs/{orgID}/packages` and is indexed by device before
  the device pages are walked.
- If `/api/servers` answers `404` while an `o` parameter is set, the script retries once
  without it and restarts paging from the beginning.
- All attributes from Automox are stored in `customAttributes`.
- The task **can be scheduled** to sync device inventory at regular intervals.

## Future

- **Missing patches as `Vulnerability` records — the largest gap, and it needs no new endpoint.** `GET /api/orgs/{orgID}/packages` is already fetched on every run, and each package row already carries `cves`, `cve_score`, `severity`, `agent_severity`, `installed`, `requires_reboot`, and `patch_classification_category_id`. Today every one of those is flattened into a `Software` custom attribute, which means the CVE identifiers Automox publishes are imported as opaque text rather than as findings. A row with `installed: false` and a populated `cves` list *is* a missing patch with named CVEs — precisely a runZero `Vulnerability`, with `severity`/`cve_score` driving the rank. Splitting the package list into installed software (as now) and pending patches (as vulnerabilities) is the single highest-value change available here, and every field it needs is already in hand.
- **Device grouping as an outbound surface.** Automox scopes patch policy by server group, and the Console API exposes group management alongside the device resource. The natural push is to drive that scope from runZero: everything runZero classifies as a domain controller into one group, everything on a regulated subnet into another, so patch windows follow runZero's inventory instead of an operator re-deriving the same set by hand. Verify the exact group and device-update paths against the Console API spec at <https://console.automox.com/api/docs> before building — the specification is the only current reference, and the endpoint names are not quoted here because they were not exercised by this integration.
- **Patch execution is reachable and deliberately out of scope.** The same key can queue actions against a device — patch now, reboot — because an Organization API key inherits its user's permissions and there is no per-key scoping to prevent it. That makes an accidental fleet-wide reboot a real possibility rather than a theoretical one, and it is why the credential guidance above pushes so hard toward the **Read Only** role. Any future outbound work here needs explicit per-device confirmation and a dry-run mode; it is not something to attach to a scheduled sync.
- **Agent coverage-gap reporting.** Automox only knows about machines that enrolled an agent; runZero discovers the ones that did not. Diffing the two separates unpatched-and-unmanaged hosts from merely-unpatched ones, and the fields needed to also spot *stale* agents — `agent_version` and `status.agent_status` — are already imported as custom attributes today, so that half is a reporting exercise with no new API work.
- **The activity and event log as a change feed.** Automox records device and policy activity separately from the device inventory this integration reads. A time-windowed poller over it would show *when* a device stopped reporting or a patch policy failed, rather than only the current state a scheduled inventory sync captures. This is a different integration shape — a high-water mark over events, not a full inventory walk — and it would run against the same rate-limit ceiling noted above.
- **Rate limiting is the binding constraint on anything added here.** `/servers` is documented as fewer than 30 requests per minute against a general ceiling of 100 per second, and this integration already spends its budget on 500-device pages plus a full package walk. Any addition that issues a request per device (rather than per page) will hit the limit on a large account, so per-device enrichment should be considered only where the data cannot be obtained from an organization-wide list endpoint.

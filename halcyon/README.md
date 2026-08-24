# Custom Integration: Halcyon

This directory was previously spelled `halcyon`. It has been corrected to match the
vendor's own spelling, so any saved query or bookmark using the old spelling needs
updating. The integration's `CONFIG` id was already `runzero-halcyon`, so existing
credentials and configured integrations are unaffected.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Halcyon API over HTTPS.

## Halcyon requirements

- Access to the Halcyon API from the runZero Explorer:
  - `https://api.halcyon.ai` for default (US) tenants.
  - **`https://api.eu.halcyon.ai` for EU-region tenants.** This is a separate deployment
    serving the same API, not an alias. Set the `url` parameter accordingly — the shipped
    default points at the US host, and an EU tenant will not authenticate against it.
- A Halcyon console user account whose username and password the integration can use.
- That account needs the **ReadOnly** role or higher.

### What Halcyon publishes, and what it does not

Halcyon serves a machine-readable API reference, unauthenticated, at
**https://api.halcyon.ai/docs** (the EU host serves its own copy at
`https://api.eu.halcyon.ai/docs`). That is the source for everything asserted below about
endpoints and roles.

Halcyon's narrative customer documentation portal at `docs.halcyon.ai` is **gated behind
Halcyon SSO**, so several setup details cannot be established from public sources. Where
that is the case this README says so rather than guessing. In particular, **we could not
establish the console menu path for creating a user or assigning it a role** — ask your
Halcyon representative, or use the API directly.

You may find third-party guidance claiming you should "go to Settings → API Access and
generate an API key". **Disregard it.** Halcyon's API reference declares exactly one
security scheme — HTTP bearer with a JWT — and there is no endpoint anywhere in it for
minting an API key or personal access token. Username and password are the only way in.

## Authentication behavior

- The script posts the username and password to `/identity/auth/login` and takes the
  `accessToken` from the response.
- If a later call returns `401 Unauthorized`, the script **logs in again** with the same
  username and password and retries the call once. It does not use the `refreshToken` that
  the login response also returns.
- **Halcyon does not publish the access token's lifetime.** There is no `expiresIn` field on
  the login response and no TTL stated in the API reference. The re-login-on-401 behavior
  above is what makes a long run survive expiry, which is why username/password is the mode
  to use for a scheduled task.

## Data imported into runZero

- Asset ID
- Hostname
- Operating system
- IPv4 and IPv6 addresses
- MAC address
- Custom attributes:
  - `agentVersion`
  - `heartbeat`
  - `policyGroupOwner`
  - `registeredDate`
  - `createdDate`
  - `lastHeartbeatDate`
  - `lastUpdatedDate`

## Steps

### Halcyon configuration

1. Work out which host your tenant lives on. Default tenants use `https://api.halcyon.ai`;
   EU-region tenants use `https://api.eu.halcyon.ai`. The console is at
   `https://console.halcyon.ai` (`console.eu.halcyon.ai` for EU). Both API hosts answer an
   unauthenticated health check, which is a quick reachability test from the Explorer host:

   ```bash
   curl -s https://api.halcyon.ai/healthcheck
   ```

2. Use a dedicated account rather than a person's login, and give it the **ReadOnly**
   role. Halcyon's API reference annotates both endpoints this integration calls —
   `POST /v2/assets/search` and `GET /v2/assets/{assetId}` — as `RBAC: [ReadOnly]`, and
   `ReadOnly` is the lowest role annotation used anywhere in the API. The full set of roles
   is `ReadOnly`, `User`, `PowerUser`, `Admin`, and `TenantAdmin`.

   You may see third-party integration guides asking for an Admin account. That is broader
   than this integration needs.

   **We could not verify the console path for creating the user or setting its role.** The
   API equivalents are `POST /identity/tenants/{tenantId}/users` and
   `PUT /identity/tenants/{tenantId}/users/{userId}/role`. New users go through an email
   invite flow.

3. Consider MFA and SSO before you pick the account. Halcyon supports per-user OTP
   enrollment and per-tenant SAML/OIDC single sign-on, and the `login` endpoint documents no
   MFA-challenge response — it returns 200, 400, 401, or 500 and nothing else. **We could
   not verify whether an MFA-enrolled or SSO-only account can complete a password login
   against the API.** The safe assumption is that the integration's account should be
   neither, but confirm that with Halcyon rather than treating it as settled.

4. Confirm the credential from the Explorer host before configuring anything in runZero:

   ```bash
   TOKEN=$(curl -s -X POST 'https://api.halcyon.ai/identity/auth/login' \
            -H 'Content-Type: application/json' \
            -d '{"username":"runzero@example.com","password":"ExampleFakePassw0rd"}' \
          | jq -r .accessToken)

   curl -s -X POST 'https://api.halcyon.ai/v2/assets/search' \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"filters":[],"pagination":{"page":1,"pageSize":10}}' | jq '.pagination'
   ```

   A `pagination` block with a non-zero `totalItems` means the account, the role, and the
   host are all right.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Halcyon API URL** (`url`): `https://api.halcyon.ai`, or `https://api.eu.halcyon.ai`
     for an EU tenant.
   - **Username** (`username`): the Halcyon console username for the ReadOnly account.
   - **Password** (`password`): that account's password.
   - **Search page size** (`page_size`): optional; assets per search page (default 10).
     Raise it to reduce request volume on a large tenant.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration, such as `halcyon`.
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in the earlier steps.
   - Update the task schedule to recur at the desired interval.
   - Select the Explorer you want the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what an
integration would import before scheduling it. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename halcyon/halcyon.star \
  --kwargs url=https://api.halcyon.ai \
  --kwargs username=runzero@example.com \
  --kwargs password='ExampleFakePassw0rd' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./halcyon-run
```

`--output` writes the assets the run produced, and it requires `--custom-integration-id` —
the scanner rejects the run with `custom integration ID required for output` without one.
Any well-formed UUID works for a local run; use the real one from the console when you want
the output to match a scheduled task. The scanner also refuses to write into a directory
that already exists, so add `--overwrite` when re-running into the same path. Add
`--verbose` for the request-by-request log, or omit `--output` to see only the log lines.

Expect a command-line run against a large tenant to take a while. The script pages the
search endpoint `page_size` assets at a time (default 10) and then issues **one additional
detail request per asset**, so a ten-thousand-asset tenant at the default page size is
roughly a thousand search calls plus ten thousand detail calls. Raise `page_size` to cut
the search half of that; the detail pass is not capped. Page progress is reported to the
task log as the walk advances, and the page walk itself is bounded by the `maxPages`
value in `CONFIG`.

`Halcyon login failed:` in the log is a rejected credential or the wrong regional host.
`Failed to fetch detailed info for asset <id>:` is a per-asset detail failure — the run
continues and imports that asset without its addresses rather than aborting.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
password containing a comma is passed through intact. Only a password that *also* contains
an `=` flips the flag into comma-separated parsing, and then the value is cut at the first
comma — the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. Wrap the whole argument in a second pair of quotes when a
password needs both characters:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename halcyon/halcyon.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server, so
it proves the script initializes, declares its parameters correctly, and issues a request.
It does not prove Halcyon accepts the credential, that the account holds `ReadOnly`, or that
any asset is parsed. The fixture scenarios are what exercise the parsing — including the
401-then-re-login path:

```bash
python3 tests/run.py halcyon
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat halcyon/halcyon.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.halcyon.ai,username=runzero@example.com,password=ExampleFakePassw0rd' \
  --output ./halcyon-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for a
script with a different entry point. Note that `--custom-integration-script-kwargs` takes
one comma-separated string — genuinely, and with no single-`=` exemption. Here a comma in
*any* value splits it, so a password containing one cannot be passed this way at all.
Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will create new assets or update existing assets in runZero based on merge criteria such as hostname, MAC address, and IP address.
- Asset search pagination and per-asset detail lookups are handled automatically by the script.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:halcyon`.

## Notes

- Username/password is the mode to use. The script re-authenticates on a `401`, which is
  what lets a long import survive an access token expiring mid-run.
- The script contains a fallback path that treats `password` as an already-minted bearer
  token when `username` is left empty. **It is not reachable through the console**, because
  `username` is a required field on the credential form, and there is in any case no way to
  obtain a standing bearer token from Halcyon — the API mints no API keys. Treat that path
  as vestigial.
- Assets are paged off the response's own `pagination` block (`currentPage` and
  `totalPages`) rather than by counting rows.
- **Rate limits are essentially unpublished.** Halcyon's API reference declares a `429`
  response on only two operations, neither of which this integration calls, and states no
  numeric limit anywhere. That is not a guarantee that none is enforced. The shared HTTP
  helper retries transient failures with backoff and honours `Retry-After`.
- This integration has not been run against a live Halcyon tenant. It was validated against
  local fixtures.

## Asset identity

- Target entity: an **endpoint carrying a Halcyon agent** — one row per registered asset in the tenant.
- Source ID field: `id`, from the `items[]` array of `POST /v2/assets/search`.
- Documentation evidence: Halcyon's own API addresses an asset by this value. This integration interpolates it straight into the detail path `GET /v2/assets/{id}` on every record, so `id` is demonstrably the resource key rather than an incidental field on the search result.
- Uniqueness scope: **the tenant within one region.** The US and EU hosts are separate deployments serving the same API, not aliases, so an id is only meaningful against the host it came from. The value is used bare with no tenant or region prefix, which matters for an organization importing both regions through the same custom integration.
- Cardinality: one source row per asset. The detail lookup returns additional fields for the same asset rather than new records.
- Stability: not published. Halcyon's API reference documents the shape of an asset but says nothing about the lifecycle of its `id`, and the narrative documentation that might is behind SSO. What can be established is that the id survives between the search call and the detail call within a run, and that it is the handle the platform uses. **Whether an agent uninstall and reinstall re-uses the existing asset record or creates a new one could not be determined** — assume the latter, as with every other agent-based source in this repository.
- Reuse behavior: not documented.
- Presence: expected on every search result. A record without one is skipped, and the skip is logged with the record's name (`halcyon: skipping asset with no id: name=...`), so a tenant returning malformed records produces a visibly short import rather than a quiet one.
- Final runZero ID: the raw Halcyon asset id as a string.
- Missing-ID behavior: skip, with a log line naming the record.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule: this is a per-agent identifier issued by the platform and used directly, not something derived from an address or a scan.
- Verdict: **scoped authoritative** for an agent registration within one regional tenant; the stability caveat above is the one unverified property.

**One operational consequence deserves emphasis, because it changes how these assets merge.** Every address and MAC comes from the per-asset detail call, not from the search result — `ipAddresses` and `macAddresses` are read from `detail_data` only. When a detail request fails, the script logs `Failed to fetch detailed info for asset <id>` and imports the asset anyway, with **no network interface at all**, leaving it to correlate on its hostname alone. On a tenant where detail lookups fail intermittently, the same endpoint can therefore merge correctly on one run and sit as a name-only asset on the next. Watch for those log lines before concluding that correlation is behaving oddly.

## Future

Halcyon serves an unauthenticated, machine-readable API reference at
<https://api.halcyon.ai/docs> (and the EU host serves its own copy). That makes it unusually
easy to establish what else is reachable, so this section deliberately does **not** guess at
route names it has not read — the items below name capabilities to look for and the changes
that are derivable from this integration's own code.

- **Raise the default page size.** `pageSize` is now the `page_size` parameter, but its
  default stays at **10** because no larger value has been verified against a live tenant.
  Combined with the per-asset detail call, a ten-thousand-asset tenant at the default costs
  roughly a thousand search requests plus ten thousand detail requests. Nothing in the API
  reference requires a page that small; once a few hundred is verified live, raising the
  default would cut the search half of that by an order of magnitude at no cost in
  correctness.
- **Use the `filters` array that is already being sent empty.** The search body carries
  `"filters": []` on every request. A server-side filter — a last-seen window, an agent
  status — is what would turn this from a full inventory walk into an incremental sync, and
  it is the only way to make the per-asset detail pass affordable on a large tenant.
- **Ask whether the search result can carry the addresses directly.** The entire N+1 detail
  pass exists to obtain `ipAddresses` and `macAddresses`. If the search endpoint can be asked
  to return them — through a field selection, a view parameter, or simply because it already
  does on some tenants — the detail call disappears and with it the failure mode described
  above.
- **Use the `refreshToken` the login response already returns.** The script ignores it and
  re-sends the username and password on every `401`. Refreshing instead would mean the
  password crosses the network once per run rather than once per token expiry, which matters
  more here than usual because there is no API-key alternative to fall back on.
- **Ransomware-specific state is the reason to integrate Halcyon at all, and none of it is
  imported.** Halcyon is an anti-ransomware platform: protection status, policy assignment,
  resilience or key-capture state, and detection events are what it knows that nothing else
  in an inventory does. The current import takes hostname, OS, addresses, agent version, and
  heartbeat — the generic part. Read the published reference for the endpoints covering
  protection state and detections; surfacing "which endpoints are actually protected" as a
  runZero attribute or tag is far more valuable than another copy of the hostname.
- **Agent coverage-gap reporting.** Halcyon only knows about endpoints that enrolled an
  agent; runZero discovers the ones that did not. The fields needed to also spot *stale*
  agents — `agentVersion`, `heartbeat`, and `lastHeartbeatDate` — are already imported as
  custom attributes, so that half is a reporting exercise rather than new integration work.
- **What this API does not offer.** The asset record carries no installed-software inventory,
  no open-port data, and no CVE feed, so `Software`, `Service`, and CVE-bearing
  `Vulnerability` records cannot be produced from it. Halcyon is a behavioral protection
  product, not a scanner or a patch-management tool.

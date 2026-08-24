# Custom Integration: CyberArk EPM

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with HTTPS reachability to the EPM SaaS dispatcher
  (`https://login.epm.cyberark.com` by default) and to the tenant's manager
  host that the logon response names.

## CyberArk EPM requirements

- An EPM SaaS tenant.
- An EPM user with API access to the sets you want to import. The endpoints
  API additionally requires the role permission **View-only access to the
  Endpoints section**.
- The user must be able to authenticate with username and password at the EPM
  logon endpoint. **SAML-only users cannot use this integration** — EPM's
  `SAML/Logon` endpoint takes an IdP-minted assertion that a scheduled task
  cannot produce.
- Consider raising **Administration > Account Configuration > Timeout for
  inactive session**, which governs how long the API session token lives.

## Steps

### CyberArk EPM configuration

1. Create (or reuse) an EPM user for runZero with view-only access to the
   relevant sets and to the Endpoints section.
2. Confirm the logon works:

   ```bash
   curl -s https://login.epm.cyberark.com/EPM/API/Auth/EPM/Logon \
     -H 'Content-Type: application/json' \
     -d '{"Username":"<user>","Password":"<pass>","ApplicationID":"runZero"}'
   ```

   The response carries `ManagerURL` (the tenant's data host) and
   `EPMAuthenticationResult` (the session token).

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "CyberArk EPM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **EPM dispatcher URL** (`url`): optional; default `https://login.epm.cyberark.com`. Regional tenants may use a different dispatcher.
   - **Username** (`username`) / **Password** (`password`): the EPM API user.
   - **Application ID** (`application_id`): optional; free-form caller name recorded by EPM (default `runZero`).
   - **Set name** (`set_name`): optional; import only the named set.
   - **Fetch per-endpoint details** (`include_details`): optional; enrich each
     endpoint with OS version and build, MAC addresses and per-adapter IPs,
     vendor/model/serial, and the DNS FQDN. One extra API call per endpoint
     (default: off).
   - **Detail call cap** (`detail_limit`): optional; maximum detail calls per
     run (default 500). Endpoints past the cap import without detail and the
     skip is logged.
   - **Page size** (`page_size`): optional; endpoints per page, API max 1000.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with EPM agent data and create new assets where nothing matches.
- You can search for assets from this custom integration with the runZero search `custom_integration:cyberark-epm`.

## Running it from the command line

```bash
runzero script --filename cyberark-epm/cyberark-epm.star \
  --kwargs username=runzero-api@example.com \
  --kwargs password=not-a-real-password \
  --kwargs set_name="Default Set" \
  --kwargs include_details=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/epm-run --overwrite
```

To check only the CONFIG block and HTTP/TLS wiring without a tenant:

```bash
runzero script --filename cyberark-epm/cyberark-epm.star --validate
```

The recorded fixtures run without a tenant:

```bash
python3 tests/run.py cyberark-epm
```

## Asset identity

- Target entity: an endpoint computer running the EPM agent.
- Source ID field: the agent id GUID — `legacyId` from the endpoints API when
  present (it equals `AgentId` from the deprecated computers API), otherwise
  the endpoint `id`. Preferring `legacyId` keeps the foreign id identical
  whichever API generation a tenant is served by.
- Uniqueness scope: one tenant. Ids are prefixed with the tenant's manager
  host (from the logon response), which is stable per tenant, rather than the
  shared regional dispatcher.
- Stability: the GUID is minted at agent install and survives renames,
  re-addressing, and set moves. **An agent reinstall mints a new id and always
  forks the asset**; that is reconciled in runZero, not with flags.
- Final runZero ID: `cyberark-epm:<manager-host>:<agent-guid>`.
- Missing-ID behavior: skip and log. No id is invented.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
  EPM endpoints are largely laptops whose names and addresses drift; none of
  that may veto an id merge.
- Verdict: **authoritative** for machines under EPM management.

### Notes

- Authentication: `POST /EPM/API/Auth/EPM/Logon` at the dispatcher returns the
  tenant `ManagerURL` and a session token; every data call goes to the manager
  host with the documented header `Authorization: basic <token>` — the token
  is passed verbatim, it is not an HTTP Basic credential. Session lifetime is
  the tenant's inactive-session timeout.
- Endpoint listing: `POST {manager}/EPM/API/Sets/{id}/Endpoints/search` with
  `offset`/`limit` in the query string (limit max 1000) and the filter in the
  body. An empty body is tried first; a tenant that rejects it gets the
  documented platform filter (`platform IN "Windows", "MacOS", "Linux"`) on
  retry, which is logged because endpoints reporting an unknown platform could
  be missed that way.
- Legacy fallback: a tenant where the endpoints API answers 404/405 is walked
  with the deprecated `GET Sets/{id}/Computers` API instead (PascalCase
  fields, no IP address, limit below 5000). The reshaped fields map onto the
  same asset builder, and ids stay identical because both APIs expose the same
  agent GUID.
- What is imported per endpoint: name (as hostname), platform (as OS),
  `platformType` mapped to device type (Desktop/Laptop/Server), the reported
  IP, the agent version (also emitted as a `Software` entry), connection
  status, logged-in user, threat-protection and upgrade status, and install /
  last-connected times (`installTime` becomes `firstSeenTS`, `lastConnected`
  becomes `lastSeenTS`).
- Detail enrichment (off by default): one `POST Endpoints/{id}/search` per
  endpoint adds OS version and build, per-adapter MACs and IPs (loopback and
  link-local filtered), vendor, model, serial number, domain, and the DNS
  FQDN. The API budget is **1000 calls per 5 minutes, 5 per second, and
  300,000 results per 24 hours**, which is why the cap exists; 429s are
  retried with backoff by the shared HTTP helper.
- Rate limits on the listing APIs are the same 1000 calls / 5 minutes; at one
  call per 1000 endpoints the walk is far below them.
- Unverified assumptions: validated against recorded fixtures, not a live
  tenant. The empty-search-body acceptance and the exact 400 behavior on
  filterless searches vary by tenant version; both paths are handled.

## Future

- **CyberArk PAM (PVWA) accounts as enrichment.** PAM Self-Hosted has no
  endpoint-inventory API, but `GET /PasswordVault/API/Accounts` exposes
  `address` and `platformId` per managed account; joined onto existing assets
  it would mark which machines hold vaulted credentials. That is an
  enrichment-shaped integration (`no-id-match no-id-break`) and a separate
  script.
- **Policy and event data.** EPM's aggregated events and policy audit APIs
  could enrich endpoints with least-privilege posture, at meaningful API
  budget cost.
- **SAML authentication** for tenants that disable password logon, once
  scheduled tasks can mint assertions.

## API documentation

- EPM authentication (Logon, dispatcher, ManagerURL): https://docs.cyberark.com/epm/latest/en/content/webservices/serverauthentication.htm
- Web services introduction (versioning, paging rule, rate limits): https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm
- Get sets list: https://docs.cyberark.com/epm/latest/en/content/webservices/getsetslist.htm
- Get endpoints (search API): https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/get-endpoints.htm
- Get endpoint details (inventory): https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/get-endpoint-details.htm
- Get computers (deprecated, the fallback path): https://docs.cyberark.com/epm/latest/en/content/webservices/getcomputers.htm
- PVWA Get accounts (future enrichment): https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccounts.htm

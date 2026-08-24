# Custom Integration: SAP LeanIX

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with HTTPS reachability to the LeanIX workspace instance (`https://<subdomain>.leanix.net`).

## SAP LeanIX requirements

- A **Technical User API token**, created under **Administration > Technical
  Users**. The token is shown once at creation and carries an admin-set expiry
  date; the Viewer role is sufficient for this integration, which only reads.
- The workspace base URL. There is no global LeanIX API host — the token
  exchange and the GraphQL API both live on the customer's own instance
  (`acme.leanix.net`, `us.leanix.net`, `eu.leanix.net`, ...), so copy the host
  from the workspace address bar.

## Steps

### LeanIX configuration

1. In the workspace, open **Administration > Technical Users** and create a
   technical user with the **Viewer** permission role.
2. Copy the API token when it is displayed — it is shown only once.
3. Confirm the token works:

   ```bash
   curl -u "apitoken:<API_TOKEN>" \
     --request POST "https://<subdomain>.leanix.net/services/mtm/v1/oauth2/token" \
     --data grant_type=client_credentials
   ```

   The response carries `access_token`; that bearer token is what the
   integration mints for itself on every run.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "SAP LeanIX").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Workspace URL** (`url`): e.g. `https://acme.leanix.net`.
   - **API token** (`api_token`): the technical user token.
   - **Fact sheet types** (`fact_sheet_types`): optional; comma-separated type
     names, default `ITComponent`. Useful additions: `Application`,
     `TechnicalStack`, `System`, `Provider`. Type names are workspace-specific
     (the meta model is configurable); an unknown type simply matches nothing.
   - **Page size** (`page_size`): optional; fact sheets per GraphQL page (default 500, max 1000).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- Fact sheets whose names are FQDN-shaped will merge onto matching assets; everything else imports as standalone inventory records.
- You can search for assets from this custom integration with the runZero search `custom_integration:leanix`.

## Running it from the command line

```bash
runzero script --filename leanix/leanix.star \
  --kwargs url=https://acme.leanix.net \
  --kwargs api_token=not-a-real-token \
  --kwargs fact_sheet_types=ITComponent,System \
  --kwargs page_size=100 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/leanix-run --overwrite
```

To check only the CONFIG block and HTTP/TLS wiring without a real workspace:

```bash
runzero script --filename leanix/leanix.star --validate
```

The recorded fixtures run without a workspace:

```bash
python3 tests/run.py leanix
```

## Asset identity

- Target entity: a LeanIX fact sheet — by default an **IT Component**, which
  LeanIX defines as a *non-instance-level* technology (e.g. "PostgreSQL 14",
  "AWS EC2"). The optional `System` type is the instance level (a server or VM)
  and is worth adding on workspaces that use it.
- Source ID field: the fact sheet `id`, a UUID that survives renames and every
  attribute edit.
- Uniqueness scope: one workspace. The workspace host is prefixed so two
  workspaces imported into one runZero organization cannot collide.
- Final runZero ID: `leanix:<workspace-host>:<factsheet-uuid>`.
- Missing-ID behavior: skip and log. No id is invented.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`.
  The UUID drives merging; the rare hostname-shaped names must not veto it.
- Verdict: **authoritative for the fact sheet, logical for the estate.**
  LeanIX is an enterprise-architecture inventory: most records carry no
  addressing, no MAC, and no hostname, so most imported assets stand alone as
  inventory entries rather than merging with scanned assets. That is the
  point — they represent the technologies and systems the EA team says exist,
  which runZero can then be checked against.

### Notes

- What is imported: one asset per fact sheet of the configured types, carrying
  the name, display name, type, description, status, last-update time,
  lifecycle phase, and the workspace's own tags (as runZero tags, capped at
  25). Each asset is labeled with `assetType` = its fact sheet type
  (lowercased), so populations can be told apart in the inventory.
- **Hostnames are imported only from FQDN-shaped names.** A name that survives
  hostname validation *and contains a dot* (e.g. `erp-db01.corp.example.com`)
  is imported as a hostname and participates in runZero's name matching.
  Product-style names ("PostgreSQL 14") are never imported as hostnames, so
  they cannot mis-merge assets.
- Authentication: the API token is exchanged at
  `POST /services/mtm/v1/oauth2/token` with HTTP Basic `apitoken:<token>` and
  `grant_type=client_credentials` — built by hand rather than with the shared
  OAuth helper, which would put the credentials in the form body instead of
  the Basic header LeanIX documents. The bearer token lives 3600 seconds; the
  walk re-authenticates once and retries the same cursor if it expires
  mid-run.
- GraphQL: `POST /services/pathfinder/v1/graphql`, paging `allFactSheets` with
  relay cursors (`first`/`after`, `pageInfo.hasNextPage`/`endCursor`). Cursors
  are forward-only, and the read is not snapshot-isolated. Archived fact
  sheets are excluded by default by the API.
- Meta-model tolerance: the standard query asks for `status`, `updatedAt`, and
  `lifecycle { asString }`. A workspace whose meta model was customized away
  from one of these fails the whole GraphQL query, so on the first error the
  walk retries the same cursor with a minimal universal field set instead of
  importing nothing.
- Rate limits: 1800 requests/min per user on the Pathfinder API; at one
  request per page this integration is far below it. 429s are retried with
  backoff by the shared HTTP helper.
- Unverified assumptions: validated against recorded fixtures, not a live
  workspace; the default `ITComponent` type name matches meta model v3 and v4
  default workspaces, but a renamed meta model needs the actual type names in
  **Fact sheet types**.

## Future

- **Relations.** `relToChild` / `relToParent` and the typed relations
  (`relITComponentToApplication`, ...) would let IT components carry which
  applications run on them, and `System` fact sheets name their IT components.
- **Subscriptions as ownership.** Fact sheet subscriptions
  (`subscriptions { edges { node { user { email } roles } } }`) map cleanly
  onto runZero's ownership attributes.
- **Outbound: report scanned reality back into LeanIX.** The GraphQL API
  supports mutations; the natural write-back is annotating fact sheets with
  whether runZero actually observes the technology, or creating `System` fact
  sheets for servers LeanIX does not model.
- **Self-Built Software Discovery API.** LeanIX's discovery surface
  (`/services/technology-discovery/v1`) accepts SBOM-shaped inputs; a runZero
  export could feed it.

## API documentation

- Authentication (Basic `apitoken:<token>` exchange): https://help.sap.com/docs/leanix/ea/authentication-to-sap-leanix-services
- GraphQL API and endpoint path: https://help.sap.com/docs/leanix/ea/graphql-api
- Pagination in GraphQL (relay cursors, 1000/page recommendation): https://help.sap.com/docs/leanix/ea/pagination-in-graphql
- Retrieving and filtering fact sheets (facet filters, `FactSheetTypes`): https://help.sap.com/docs/leanix/ea/filtering-fact-sheets
- Meta model (fact sheet types, ITComponent definition): https://help.sap.com/docs/leanix/ea/meta-model
- Technical users and API tokens: https://help.sap.com/docs/leanix/ea/technical-users
- Rate limiting: https://help.sap.com/docs/leanix/ea/rate-limiting
- LeanIX's own example scripts (auth flow confirmation): https://github.com/leanix-public/scripts

# Custom Integration: Quest KACE SMA

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the KACE Systems Management Appliance over HTTPS.

## Quest KACE SMA requirements

- A KACE SMA user account with the **Administrator** or **Read-only administrator** role. A Standard user can call every query route, but the appliance only returns the records that belong to that user, so the import would be incomplete.
- The account must not have two-factor authentication enabled. The appliance requires a second `POST /ams/shared/api/security/verify_2factor` call with a code from an authenticator app, which an unattended task cannot supply; without it every later request fails with `401 User not fully authenticated`.
- On a multi-organization appliance, one credential and one task per organization: a session is bound to a single organization and queries only return that organization's records.

## Steps

### Quest KACE SMA configuration

1. Create (or choose) a service account in the Administration Console under **Settings > Users**, and assign it the Read-only administrator role.
2. Note the organization name the account should log into (**Settings > Organizations**, `Default` on a single-organization appliance).
3. Confirm API access from the Explorer, for example with `POST https://<appliance>/ams/shared/api/security/login` and then `GET https://<appliance>/api/inventory/machines?paging=limit 1`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Quest KACE SMA").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **KACE SMA URL** (`url`): base URL of the appliance, for example `https://kace.example.com`.
   - **Organization name** (`organization`): optional; the organization to log into on a multi-organization appliance, for example `Default`. Leave blank to use the account's default organization.
   - **Username** (`username`): the KACE SMA service account.
   - **Password** (`password`): the password for that account.
   - **Import installed software** (`import_software`): optional; request the software sub-entity for every machine (default: enabled).
   - **Enrich from the asset CMDB** (`import_assets`): optional; attach the matching `/api/asset/assets` record to each machine (default: enabled).
   - **Records per page** (`page_size`): optional; records requested per API call (default: 100).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Quest KACE SMA.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:quest-kace`.

## Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm an
account and see what a real appliance returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename quest-kace/quest-kace.star \
  --kwargs url=https://kace.example.com \
  --kwargs organization=Default \
  --kwargs username=runzero-ro \
  --kwargs password=hunter2-not-a-real-password \
  --kwargs page_size=25 \
  --kwargs import_software=false \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/kace-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Two behaviors of this appliance are worth understanding before you read the
output of that run:

- **The MAC address and serial number only arrive because of `shaping`.** Every
  machine query is issued with `shaping=machine all`, and with
  `shaping=machine all,software all` when `import_software` is on. Without the
  `all` level KACE returns a thin machine record — id, name, and little else —
  and the assets come out with no MAC and no serial, which is to say with almost
  nothing runZero can correlate on. The value is built inside the script and is
  not a parameter, so there is nothing to set here; it matters because it
  explains what you are looking at, and because anyone editing the query needs to
  keep it.
- **The organization in the asset ID comes from a login cookie, not from what you
  typed.** The appliance states the session's organization in the
  `KACE_LAST_ORG_SECURE` cookie it sets at login, and that value — lowercased —
  is what lands in `quest-kace:<appliance>:<org>:<machine id>`. The
  `organization` parameter is only the request; the cookie is the answer, and the
  configured name is used solely as a fallback when the appliance sets no cookie.
  So if a run against a multi-organization appliance produces IDs naming an
  organization you did not expect, the account logged into its default
  organization rather than the one you asked for, and every asset in that run is
  scoped accordingly.

Leave `import_software` off for a first run: it adds the full installed-software
list to every machine and makes each page considerably larger. `get_bool` accepts
`true/false`, `1/0`, `yes/no`, and `on/off`. KACE appliances commonly present a
self-signed certificate, which is why `tls_disable_validation` appears above;
drop it if yours presents a certificate the Explorer trusts.

If the run fails at login, check the account's two-factor setting before anything
else — the appliance answers `401 User not fully authenticated` for a 2FA-enabled
account, and no unattended run can satisfy the second factor.

**One `--kwargs` caveat, for the password specifically.** A comma in a value is
harmless on its own — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks is a value
carrying **both** an `=` and a comma: the flag parses an argument containing a
second `=` as a CSV record, so `password=a=b,c=d` yields `password=a=b` plus a
fabricated `c=d`. Wrap the whole argument in double quotes to pass such a value
as one field — `--kwargs '"password=a=b,c=d"'` — and double any quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real appliance:

```bash
runzero script --filename quest-kace/quest-kace.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never completes a real login
and never parses a real machine row, so it tells you nothing about the
organization scoping described above.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://kace.example.com,username=runzero-ro,password=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma — which for this integration means an organization
name containing a comma has to be configured through the console credential form.

The recorded fixtures run without an appliance:

```bash
python3 tests/run.py quest-kace
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: a device in the KACE inventory — a physical machine, virtual machine, or agentless device that the appliance has inventoried.
- Source ID field: `Id` on the `Machine` entity returned by `GET /api/inventory/machines`.
- Documentation evidence: the [KACE SMA 15.0 API Reference Guide](https://support-public.cfm.quest.com/80844_KACE_SMA_15.0_API_Reference_en-US.pdf) defines the `Machine` entity with an `Id` integer and routes every per-device operation through it (`GET /api/inventory/machines/{id}/`, `PUT /api/inventory/machines/{id}/`, `POST /api/inventory/machines/{id}/force/`). The guide also states that "if the appliance is configured for multiple organizations, querying is limited to the currently selected organization for the requesting user", and that the organization is selected at login (`organizationName` in the `ApiCredentials` body) or switched with `POST /ams/shared/api/security/organization/switch`.
- Uniqueness scope: one organization on one appliance. The id is a per-organization database row id, so machine 1 exists in every organization of every appliance and describes a different device in each.
- Cardinality: one row per device. The software titles, CMDB asset record, tickets, processes, and services are sub-entities of that row, never additional rows.
- Stability: the id survives rename, IP and MAC change, agent upgrade, OS upgrade, and ordinary inventory refresh. It is replaced when the device is deleted from inventory and re-inventoried, which is the same event that produces a new KUID.
- Reuse behavior: ids are auto-increment row ids. Quest does not document recycling, and no observed release reissues a deleted id, but this is not a contractual guarantee.
- Presence: required. It is present at every shaping level, including `LIMITED`, which the guide defines as "ID and name".
- Final runZero ID: `quest-kace:<appliance-host>:<organization>:<Id>` — for example `quest-kace:kace.example.com:default:1`. The appliance host comes from the configured URL; the organization comes from the `KACE_LAST_ORG_SECURE` cookie the appliance sets at login, lower-cased, falling back to the configured **Organization name** and then to `default`.
- Missing-ID behavior: skipped with `quest-kace: skipping machine with no id: name=<name>`. No id is invented and no random value is used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The id is authoritative, but KACE stores exactly one primary MAC and one primary IP per device, and both change with DHCP leases, docking stations, and VPN adapters; hostnames are renamed in place. Network churn must not disqualify a merge against an existing runZero asset.
- Verdict: scoped authoritative.

### Notes

- **What is imported.** Devices from `GET /api/inventory/machines`, and their installed software as `Software` records from the `software` sub-entity of the same response. Hostname, domain, IPv4/IPv6, MAC, manufacturer (`Cs_Manufacturer`), model (`Cs_Model`), OS name and version, chassis type, serial numbers, agent version, logged-in user, KUID, and the six inventory custom fields are imported. Every mapped field is also kept verbatim as a `quest_kace_*` custom attribute.
- **Shaping is not optional.** The appliance's default `STANDARD` shaping level returns none of the fields that make this integration worth running: no MAC, no serial numbers, no manufacturer or model, and no software. The script always requests `shaping=machine all` and, when software import is enabled, `shaping=machine all,software all`. The grammar is `<entity> <LIMITED|STANDARD|EXTENDED|ALL>`, comma-separated, per the API guide's Shaping section.
- **Pagination.** `paging=offset <n> limit <m>`, documented in the API guide's Paging section; the appliance returns 50 records when no paging is requested. The script pages until a short or empty page arrives, and additionally stops if the appliance serves the same leading record id twice, so an appliance that ignores `paging` cannot loop forever. `use_count=false` is sent because the count costs the appliance a second query and the field it lands in is not part of the published response schema.
- **Query encoding.** The KACE query language is built out of spaces (`paging=offset 0 limit 100`). The query string is encoded once and appended to the URL with `%20` for spaces, matching the appliance's own documented examples, rather than passed as request parameters.
- **Authentication.** `POST /ams/shared/api/security/login` with `{"userName", "password", "organizationName"}`. The response sets five cookies (`KACE_LAST_USER_SECURE`, `KACE_LAST_ORG_SECURE`, `kboxid`, `x-dell-auth-jwt`, `KACE_CSRF_TOKEN`) which are reassembled into a `Cookie` header and replayed on every later request, along with a version header and, when the appliance issues one, the CSRF token. Any additional cookie the appliance sets is replayed too.
- **API generations.** Releases before 12.1 issue the CSRF token in the `x-dell-csrf-token` response header (and mirror it in the `KACE_CSRF_TOKEN` cookie) and require it back on every request. From 12.1 the appliance "no longer returns nor requires the x-kace-csrf-token header" and only needs a version header. The script sends both `x-dell-api-version` and `x-kace-api-version`, and echoes the CSRF token under both spellings only when it received one, so a single script covers both generations. The token is read from the response header first and from the cookie second.
- **Session expiry.** A `401` on a collection request triggers one re-login and one retry of that page. Repeated failures end the run with a message.
- **Rate limiting.** KACE publishes no rate limit. Transient statuses (408/425/429/5xx) are retried three times with exponential backoff by the shared HTTP helper, honoring `Retry-After`. The login is a raw POST and is not retried, because the helper that implements retries does not expose response headers and the session cookies are only available there.
- **Timestamps.** `Created` becomes `firstSeenTS`. `Last_sync` becomes `lastSeenTS`, falling back to `Last_inventory` and then `Modified`: `Last_sync` is the last agent check-in and is the closest thing the appliance records to an observation of the device, while `Modified` also moves when an administrator edits the record and would overstate presence. KACE serializes timestamps as `YYYY-MM-DD HH:MM:SS` with no zone and uses `0000-00-00 00:00:00` for "never"; the sentinel is discarded and the remaining values are **assumed to be UTC**. This is the one mapping that could not be settled from the documentation.

  Every parsed timestamp is **clamped to the current time** before it is assigned, including the software `installedAt` below. runZero rejects an asset whose first- or last-seen time is in the future, and rejects a software record whose install time is — which fails the asset carrying it — and the error fails the entire record. On an appliance east of UTC (most of Europe and Asia) every timestamp would otherwise read as future-dated and **every asset would be dropped**. With the clamp, a non-UTC appliance skews first-seen and last-seen toward the present instead of losing the asset. The unmodified strings are always kept as the `quest_kace_created`, `quest_kace_last_sync`, `quest_kace_last_inventory`, and `quest_kace_modified` custom attributes, so the appliance's own values survive the import either way.
- **Loopback filtering.** `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, and `fe80::/10` are removed before a network interface is built, because an agent with no usable NIC reports `127.0.0.1` as the device's only address and importing that would merge the whole estate onto one asset. The raw values stay in the `quest_kace_ip` and `quest_kace_ipv6` custom attributes.
- **Software.** `Display_Name` (or `Name`) becomes `product`, `Display_Version` (or `Version`) becomes `version`, `Publisher` becomes `vendor`, and `Install_Date` becomes `installedAt`, clamped to the current time for the reason given under Timestamps. `cpe23` is deliberately never set: KACE publishes no CPE for an inventoried title, and `Software.cpe23` only accepts the CPE 2.2 `cpe:/a:` application binding. Titles are capped at 99 per asset.
- **No services.** KACE inventories operating system service units and running processes (`/api/inventory/machines/{id}` sub-entities) but records no listening port or transport for them, so no `Service` objects are emitted rather than inventing ports.
- **Asset CMDB.** `GET /api/asset/assets` is read first and indexed by `mapped_id`, the inventory machine each CMDB record points at, and the matching record is attached to the machine as `quest_kace_asset_*` custom attributes plus an `asset-type:<name>` tag. Records whose `asset_type_name` is not `Device` (License, Location, Software, Cost Center) are skipped, as are records with no `mapped_id`: they describe no device and have nothing to merge onto. **`mapped_id` as the join key is inferred from response samples, not from the API guide**, which documents the column without stating what it references; the appliance's own `Device` asset type is the only one that populates it. If two CMDB records claim the same machine, the first wins and the rest are counted in a log line. Disable **Enrich from the asset CMDB** to skip this pass entirely.
- **Field name casing.** The appliance is not consistent about the casing of its own field names. The API guide documents the inventory `Machine` entity as `Cs_Manufacturer` / `Bios_Serial_Number`, live 10.x appliances answer with `Os_name` / `Last_inventory`, the asset API spells the same columns `cs_manufacturer`, and at least one field (`Ram Total`) is separated by a space. The script folds every response key to `lower_snake_case` before mapping, so all spellings are handled. Note also that the Cortex XSOAR pack for this product converts keys to CamelCase before displaying them, so its documented field names (`OSName`, `BiosIdentificationCode`) are not what the API returns.
- **Multi-organization appliances.** A session sees exactly one organization. To import several, create one credential and one task per organization, each with its own **Organization name**. Because the organization is part of every asset id, changing that setting for an existing task creates a second set of assets; the id is taken from the appliance's own `KACE_LAST_ORG_SECURE` cookie precisely so that leaving the field blank and later filling it in with the same organization does not renumber anything.
- This integration was validated against local fixtures, not a live Quest KACE SMA appliance. The shaping and paging grammar comes from the API Reference Guide; neither is exercised by the Cortex XSOAR pack, which fetches every record in one unshaped request and truncates client-side.

## Future

- **Service desk ticket creation (outbound).** `POST /api/service_desk/tickets` is documented and creates a ticket from a body of `{"Tickets": [{"hd_queue_id": .., "title": .., "summary": .., "machine": .., "asset": ..}]}`, returning the new ticket ids; `POST /api/service_desk/tickets/{id}` updates one and `DELETE` removes it. A queue's writable fields are discoverable with `GET /api/service_desk/queues/{id}/fields`. That makes an outbound integration practical: file a KACE ticket from a runZero finding (an unmanaged device on a managed subnet, an end-of-life OS, a newly exposed service) with the `machine` field set to the KACE machine id already stored on the asset, so the ticket lands on the right device record.
- **Ticket ingestion (alert/event).** `GET /api/service_desk/tickets?filtering=created gt <timestamp>` with a `hd_ticket all` shaping is the poll the XSOAR pack uses for incidents. The same query could attach open hardware and software tickets to the asset they name, giving an operational view of which devices are currently in a break/fix state.
- **Richer CMDB enrichment.** This version only copies the scalar columns of the mapped `Device` asset. `GET /api/asset/assets?shaping=asset all` also exposes the asset custom fields an organization defines (`field_100xx`), and the `Location` and `Cost Center` asset types carry the ownership hierarchy that the device records only reference by id. Resolving those references would give real location, department, and cost-center attribution rather than raw ids.
- **Software license reconciliation.** KACE tracks license assets and installed-title counts separately from the inventory. Joining `GET /api/asset/assets?filtering=asset_type_name eq License` to the software already imported here would let runZero report installations with no entitlement, and entitlements with no installation, across the estate rather than per appliance.
- **Endpoint-management coverage gaps.** The inverse of this import is the more valuable report: every runZero asset that is *not* in the KACE inventory is a device with no agent, no patching, and no inventory. Because the import stamps `custom_integration:quest-kace` on everything KACE knows about, the gap is already expressible as a runZero search once the integration has run; a future version could publish the gap back as a KACE ticket per subnet using the outbound route above.
- **Not supported.** The API has no webhook, subscription, or event-stream route, so every one of these remains a poll. There is also no bulk lookup by MAC or serial: `filtering=mac eq <value>` works per request, which makes on-demand enrichment of a single runZero asset possible but a full reconciliation still a paged crawl.

## API documentation

- [KACE SMA 15.0 API Reference Guide (PDF)](https://support-public.cfm.quest.com/80844_KACE_SMA_15.0_API_Reference_en-US.pdf) — authentication and organization selection, headers, filtering, sorting, paging, shaping, counts, and the `Machine`, `Software`, `machine`, `software`, and `Organization` entity definitions.
- [KACE SMA API Reference Guide — About the API](https://support.quest.com/technical-documents/kace-systems-management-appliance/14.0%20common%20documents/api-reference-guide/6) — the same reference in HTML, including the 12.1 note that the appliance no longer returns or requires the CSRF header.
- [KACE SMA API Reference Guide — Shaping](https://support.quest.com/technical-documents/kace-systems-management-appliance/13.0%20common%20documents/api-reference-guide/about-the-kace-systems-management-appliance-api/shaping) — the shaping levels and the `machines?shaping=machine all,software limited` example.
- [Cortex XSOAR QuestKace pack](https://github.com/demisto/content/tree/master/Packs/QuestKace/Integrations/QuestKace) — the reference client for the cookie and CSRF login flow, and the source of the observed 10.0.290 response samples. It is published as beta, performs no paging, and requests no shaping, so its field list was treated as a sample rather than a contract.

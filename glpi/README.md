# Custom Integration: GLPI

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## GLPI requirements

- The REST API enabled in **Setup > General > API**. The toggle is worded slightly differently across GLPI versions and translations — the vendor FAQ writes it as "enable API Rest" — but there is only one such option on that tab.
- An **API client** with an application token, allowed from the Explorer's IP address.
- A GLPI user with read access to the item types you want to import (`Computer`, and
  optionally `NetworkEquipment` and `Printer`), plus `Software`, `Item_OperatingSystem`,
  and `NetworkPort`. GLPI ships a built-in **Read-only** profile, which is sufficient; the
  integration never writes. Rights are checkboxes rather than named permission strings —
  the one that matters is **Administration > Profiles > (profile) > Assets > Computer >
  Read**. GLPI does not deduce permissions, so each item type has to be ticked
  individually.
- This integration uses the legacy REST API at `/apirest.php`. That endpoint still exists
  in GLPI 11, where it is preserved as a route rather than a file, alongside the newer
  high-level API at `/api.php/v2/`. The vendor describes the legacy API as soft-deprecated
  with no removal planned.
- Either a personal **API token** on that user (`Enable login with external token`) or
  a username and password (`Enable login with credentials`).

## Steps

### GLPI configuration

1. Go to **Setup > General > API** and set `Enable Rest API` to Yes. Note the
   **API base URL** shown on that page; it is your GLPI URL with `/apirest.php` appended.
2. Still on that page, enable `Enable login with external token` (for a user API token)
   or `Enable login with credentials` (for a username and password).
3. Add an **API client**, set its IPv4 range to cover the runZero Explorer, and copy the
   generated **application token**. GLPI shows the token only when the client is saved.
4. Open the GLPI user that the integration will run as, and in **Settings** regenerate
   and copy its **API token**.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "GLPI").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **GLPI URL** (`url`): base URL of the GLPI instance, including any subdirectory, for example `https://itsm.example.com/glpi`. The `/apirest.php` path is appended automatically.
   - **Username** (`username`): optional; GLPI username, for password login.
   - **Application token** (`app_token`): the App-Token of the GLPI API client. Required whenever the matching API client defines one.
   - **User API token** (`user_token`): optional; the personal API token of a GLPI user. Preferred over username and password.
   - **Password** (`password`): optional; used only together with the username.
   - **Import installed software** (`include_software`): optional; fetch the per-computer software inventory (default: true).
   - **Software enrichment limit** (`detail_limit`): optional; maximum number of computers to enrich with software (default: 1000, 0 removes the cap).
   - **Import network equipment and printers** (`include_network_devices`): optional; also import the `NetworkEquipment` and `Printer` item types (default: false).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm the token pair and see what a real GLPI returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename glpi/glpi.star \
  --kwargs url=https://itsm.example.com/glpi \
  --kwargs app_token=AbCdEf0123456789AbCdEf0123456789AbCdEf01 \
  --kwargs user_token=Zy9XwV8UtS7RqP6OnM5LkJ4IhG3FeD2CbA1zYx0w \
  --kwargs include_software=true \
  --kwargs detail_limit=10 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./glpi-run
```

Note that this example passes **no** `username` and **no** `password`. GLPI has
two mutually exclusive login modes and the parameters reflect that:

- **User token** — set `user_token`, leave `username` and `password` empty. This
  is the preferred mode, and the one shown above.
- **Password** — set `username` and `password`, leave `user_token` empty.

`app_token` is separate from both and is nearly always required: it identifies
the API client, and GLPI refuses to open a session when the matching client
defines an application token and the request does not carry it. Sending a
`user_token` *and* a `username`/`password` pair is not a documented
combination; pick one.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

Keep `detail_limit` low while testing. `include_software` is one extra request
per computer, which on a large GLPI is the whole cost of the run. To check the
network-equipment and printer path as well:

```bash
runzero script --filename glpi/glpi.star \
  --kwargs url=https://itsm.example.com/glpi \
  --kwargs app_token=AbCdEf0123456789AbCdEf0123456789AbCdEf01 \
  --kwargs user_token=Zy9XwV8UtS7RqP6OnM5LkJ4IhG3FeD2CbA1zYx0w \
  --kwargs include_network_devices=true \
  --kwargs include_software=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./glpi-netdev --overwrite
```

Two failure modes look like authentication problems and are not. The **API
client's IPv4 range** must cover whatever host is making the request — running
from your laptop when the client is scoped to the Explorer's address fails at
`initSession`, and the script surfaces that as `ERROR_NOT_ALLOWED_IP` rather
than a bad-credential message. And the API itself must be enabled in
**Setup > General > API**; with it off, `/apirest.php` answers but refuses every
session.

`--kwargs` hands the value to the script verbatim, commas included, as long as
the pair contains a single `=`. It is a value carrying a *second* `=` as well as
a comma that gets re-read as CSV: cut off at the comma, with the remainder
becoming a second, fabricated parameter rather than rejected. No GLPI token is
that shape, but a password could be — wrap it in double quotes so it stays a
single field, `--kwargs '"password=a=b,c"'`, doubling any double quote inside it,
or configure it through the console credential form.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename glpi/glpi.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove GLPI opens a session, that
the profile can read `Computer`, or that any item is parsed.

The fixtures under `glpi/tests/fixtures/` exercise the parsing offline,
including the detail-cap and item-type identity cases:

```bash
python3 tests/run.py glpi
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat glpi/glpi.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://itsm.example.com/glpi,app_token=<app-token>,user_token=<user-token>' \
  --output ./glpi-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is stricter than `script --kwargs`: it takes
one comma-separated string, so no value containing a comma at all can be passed
this way. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from GLPI.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:glpi`.

## Asset identity

- Target entity: a physical or virtual inventory item held in GLPI — a computer, and
  optionally a piece of network equipment or a printer.
- Source ID field: `id` on the item record returned by `GET /apirest.php/Computer`
  (likewise `/NetworkEquipment` and `/Printer`).
- Documentation evidence: `apirest.md` documents `GET /:itemtype/:id` as "Return the
  instance fields of itemtype identified by id", making `id` the addressable primary key
  of an item. Confirmed directly against a GLPI 10.0.26 server: `glpi_computers` declares
  `id int unsigned NOT NULL AUTO_INCREMENT, PRIMARY KEY (id)` with `entities_id` as an
  ordinary indexed column, so the id is allocated once per instance and is not
  partitioned by entity.
- Uniqueness scope: one GLPI instance, per item type. The same integer is reused across
  item types (`Computer` 1 and `Printer` 1 both exist), so the item type is part of the
  key. GLPI's multi-entity model does **not** widen the scope: entities partition
  visibility, not the id sequence, and moving an item between entities keeps its id.
- Cardinality: one row per asset. Network ports, software installations, and the
  operating system are separate child rows that are folded into the same asset rather
  than becoming assets of their own.
- Stability: survives rename, reboot, IP and MAC change, re-inventory, entity move, and
  agent upgrade. GLPI's native inventory matches an incoming agent report to an existing
  item by serial, UUID, MAC, or `deviceid` and updates that row in place.
- Reuse behavior: `id` comes from a MySQL `AUTO_INCREMENT` column, which does not reissue
  values for deleted rows while the table exists. GLPI also soft-deletes by default
  (`is_deleted`), so a purge is required before a row leaves the table at all. A restore
  of the database from a dump taken before an item existed could in principle reissue the
  value; this is the same exposure every self-hosted autoincrement id carries.
- Presence: always present on both list and single-item responses. It is the field the
  API routes on.
- Final runZero ID: `glpi:<glpi-host>:<ItemType>:<id>`, for example
  `glpi:itsm.example.com:Computer:2481`. The host comes from the configured URL, so two
  GLPI instances imported into one runZero account cannot collide.
- Missing-ID behavior: the record is skipped and one line is logged with the item name
  only. No identity is synthesized and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The GLPI id is authoritative,
  but GLPI records are routinely renamed by hand, and an item created manually or by a
  discovery job can carry stale addressing or none at all, so network churn must not
  disqualify a merge.
- Verdict: scoped authoritative — authoritative within one GLPI instance and one item
  type, namespaced by the instance host.

### Notes

- **What is imported.** Assets from `GET /Computer`, and behind the
  `include_network_devices` option from `GET /NetworkEquipment` and `GET /Printer`.
  Network interfaces come from the `with_networkports=true` expansion on those same
  collection responses. Software comes from `GET /Computer/{id}?with_softwares=true`.
  Operating systems come from one paged pass over `GET /Item_OperatingSystem`. Software
  publishers come from one paged pass over `GET /Software`.
- **Session lifecycle.** Authentication is two-part. The App-Token identifies the GLPI
  API client and the user token or Basic credential identifies the user; both are sent to
  `GET /apirest.php/initSession`, which returns a `session_token`. That token is sent as
  the `Session-Token` header on every subsequent request and released with
  `GET /apirest.php/killSession` when the run ends, including when the run ended in an
  error. If GLPI invalidates the token mid-run (`ERROR_SESSION_TOKEN`, e.g. a short PHP
  session lifetime on a large estate), the session is re-opened once and the failed
  request retried, so the tail of the inventory is not lost. Verified end to end against
  GLPI 10.0.26: after `killSession` the next request returns 401.
- **The App-Token is conditionally required.** `apirest.md` lists it as optional, and it
  genuinely is when the API client matching the Explorer's IP address has an empty token.
  As soon as that client defines a token, omitting it fails with
  `ERROR_APP_TOKEN_PARAMETERS_MISSING`. It is therefore modelled as an optional secret,
  and should be filled in for any normal deployment.
- **Pagination.** GLPI pages with a `range=<start>-<end>` query parameter — confirmed as a
  query parameter, not only the `Range` header — and answers with 206 plus
  `Content-Range: 0-199/258` and `Accept-Range: Computer 1000`. Because `get_json` does
  not expose response headers, paging instead advances by the number of rows returned and
  stops on the first short or empty page. The page size is 200 for item collections and
  500 for the two side tables, both well under the advertised server maximum of 1000.
- **A range past the end is an error, not an empty page.** A request whose first index is
  greater than the total count returns `400 ERROR_RANGE_EXCEED_TOTAL` rather than `[]`.
  Fixed-size paging cannot produce that on its own, but items deleted between two pages
  can, so that specific error is treated as a clean end of data instead of a failure.
- **Dropdowns must be expanded.** `manufacturers_id`, `computermodels_id`,
  `locations_id`, `entities_id` and friends are foreign keys to GLPI dropdown tables and
  serialize as bare integers by default; importing them unexpanded would produce
  meaningless numbers. Every item request sets `expand_dropdowns=true`, which replaces
  them with their names. An unset dropdown stays the integer `0`, which is treated as
  "none" rather than as a value.
- **`expand_dropdowns` cannot be used on `Item_OperatingSystem`.** It would rewrite that
  table's `items_id` from the numeric item id to the item's *name* and destroy the join
  key. The documented `add_keys_names[]` parameter is used instead: it keeps the numeric
  ids and adds a parallel `_keys_names` object with the resolved names. GLPI 10 keeps no
  `operatingsystems_id` column on `Computer` at all, so this relation is the only source
  of OS and OS version.
- **Software publishers need a second source.** The `with_softwares` expansion names the
  product and version but never the publisher, so the `Software` catalog is fetched once
  and indexed by product name to fill in `Software.vendor`. GLPI publishes no CPE for an
  installation, so `Software.cpe23` is deliberately left unset rather than synthesized.
- **GLPI HTML-encodes stored text.** Values round-trip out of the API with entities in
  place of punctuation — a location reads `HQ &#62; Floor 2` rather than `HQ > Floor 2`.
  Text fields are decoded before they become hostnames, tags, or custom attributes.
- **Timestamps carry no timezone.** GLPI serializes SQL `DATETIME` as
  `2026-08-15 08:44:01`, with a space and no offset, which `parse_time` rejects with an
  error that would abort the whole script. Each value is validated field by field and a
  `Z` is appended before parsing. GLPI stores these in the timezone configured on the
  server and the API publishes no offset, so **they are read as UTC**.
  `date_creation` becomes `firstSeenTS`; `last_inventory_update` becomes
  `lastSeenTS`, falling back to `date_mod` when the item was never agent-inventoried.
  Both are **clamped to the current time** before they are assigned. runZero rejects an
  asset whose first- or last-seen time is in the future and the error fails the entire
  record, so on a server east of UTC — most of Europe and Asia — every timestamp would
  otherwise read as future-dated and **every asset would be dropped**. With the clamp, a
  non-UTC server skews first-seen and last-seen toward the present instead of losing the
  asset. The unmodified strings are always kept as the `glpi_date_creation`,
  `glpi_date_mod`, and `glpi_last_inventory_update` custom attributes, so the vendor's
  own values survive the import either way.
- **Loopback is filtered.** GLPI models the `lo` interface as a `NetworkPortLocal` port,
  which is skipped outright, and loopback, unspecified, and link-local addresses are
  removed from every port's address list before interfaces are built. A host whose only
  address is `127.0.0.1` is imported with no network interface rather than sharing an
  address with every other such host.
- **One interface per port.** GLPI keys the `_networkports` expansion by port class
  (`NetworkPortEthernet`, `NetworkPortWifi`, `NetworkPortAggregate`, `NetworkPortAlias`,
  `NetworkPortDialup`, `NetworkPortLocal`, `NetworkPortFiberchannel`) and hangs each
  port's addresses off `NetworkName.IPAddress[].name`. Every port with a MAC or a routable
  address becomes its own runZero network interface, so a multi-homed host keeps its
  per-NIC addressing. Port classes not in that list are still imported, so a future GLPI
  release cannot silently drop interfaces.
- **N+1 cost.** Only the software inventory costs a request per computer, because
  `with_softwares` is honored on the single-item endpoint only. It is capped by
  `detail_limit` (default 1000) and can be turned off entirely with `include_software`.
  Computers past the limit are still imported, without software, and the number skipped is
  printed. Network ports cost nothing extra: `with_networkports` is honored on the
  collection endpoint, which was verified against a live server.
- **Templates and deleted items are excluded.** Item templates (`is_template`) are
  blueprints rather than inventory and are skipped; `is_deleted=false` is requested so
  soft-deleted items are not imported.
- **No services and no vulnerabilities.** GLPI models neither. It has no port or listener
  inventory — `NetworkPort` describes a physical or logical interface, not a listening
  socket — and no vulnerability object of any kind. Nothing is synthesized for either, so
  assets from this integration carry no `Service` or `Vulnerability` records.
- **Monitors and phones are not imported.** GLPI's `Monitor` records carry good EDID
  serial numbers, but a monitor has no network identity at all, so importing one produces
  an asset with a name and a serial that runZero can never merge or scan. The same applies
  to most `Phone` records. Both are better modelled as attributes of the computer they are
  connected to, which is future work — see below.
- **Rate limiting.** GLPI publishes no rate limit and returns no `X-RateLimit` headers.
  Transient failures (408, 425, 429, 5xx) are retried with exponential backoff by the
  shared HTTP helper, which honors `Retry-After`.
- This integration was validated against a live GLPI 10.0.26 server running locally in
  Docker, seeded through GLPI's native agent-inventory endpoint, and additionally against
  local fixtures for the pagination, authentication, rate-limit, and malformed-record
  cases. It has not been run against a large production tenant or against GLPI 11.

## Future

- **Outbound: push runZero assets into GLPI.** GLPI exposes a full CRUD REST API —
  `POST /apirest.php/Computer` with `{"input": {...}}` creates an item and returns its
  new id, `PUT /apirest.php/Computer` updates one, and both accept arrays for bulk
  operations. This is the strongest pairing available for GLPI: runZero finds assets that
  never check in with an agent (OT gear, appliances, contractor laptops, anything
  unmanaged) and GLPI is the ITAM system of record that has no way to see them. A
  companion outbound integration could create or update `Computer` and `NetworkEquipment`
  records from runZero inventory, keyed on serial number or MAC. The risk deserves stating
  plainly: GLPI is a system of record with an audit trail, financial data, and contracts
  attached to its items, so an outbound integration should create items in a dedicated
  entity, set `is_dynamic` honestly, never purge, and never overwrite a manually
  maintained field. A dry-run mode that reports what it would create is close to mandatory.
- **Ticket creation from runZero findings.** `POST /apirest.php/Ticket` creates an ITIL
  ticket, `POST /apirest.php/ITILFollowup` adds a comment, and
  `POST /apirest.php/Document_Item` attaches evidence. An outbound integration could open
  a GLPI ticket for each newly discovered unmanaged asset or each runZero policy
  violation, and link it to the GLPI item with `POST /apirest.php/Item_Ticket` so the
  ticket appears on the asset's own page. The `Ticket` search API
  (`GET /apirest.php/search/Ticket`) would let a subsequent run avoid duplicate tickets.
- **More inventory item types.** GLPI stores far more than computers: `Monitor` (with EDID
  serial numbers from the agent), `Peripheral`, `Phone`, `Rack`, `Enclosure`, `PDU`,
  `Cluster`, and `Unmanaged`. The connection tables `Computer_Item` and `Asset_PeripheralAsset`
  tie monitors and peripherals to the computer they are attached to, so a future revision
  could fold monitor and peripheral serials into the *computer's* custom attributes rather
  than importing them as unmergeable standalone assets. `Unmanaged` is especially
  interesting: it is GLPI's own bucket for devices its network discovery saw but could not
  identify, which is precisely the population runZero is best at resolving.
- **Deep hardware inventory.** The `with_devices=true` expansion returns
  `Item_DeviceMotherboard`, `Item_DeviceProcessor`, `Item_DeviceMemory`,
  `Item_DeviceHardDrive`, `Item_DeviceNetworkCard`, `Item_DeviceFirmware`, and more —
  per-slot memory modules, per-drive serials, BIOS versions. `with_disks=true` adds
  filesystems with free and total size and encryption status. None of this maps onto a
  runZero type today, but all of it would make rich custom attributes, and the firmware
  and BIOS versions in particular would support fleet-wide firmware-currency queries.
- **Incremental import.** The search API supports a `date_mod` criterion
  (`GET /apirest.php/search/Computer` with `criteria[0][field]=19&criteria[0][searchtype]=morethan`),
  which would let a scheduled task fetch only items changed since the last run instead of
  walking the whole inventory. The search API returns search-option numbers rather than
  field names, so it needs a `listSearchOptions` call to map them, which is why the plain
  item endpoints are used here.
- **Financial and contract reconciliation.** `with_infocoms=true` and
  `with_contracts=true` return purchase date, warranty expiry, supplier, budget, and
  contract linkage. Importing those as attributes would let runZero answer "which assets
  on my network are out of warranty" or "which discovered assets appear on no contract" —
  and, read the other way, "which GLPI items have not been seen on the network in 90
  days", which is the reconciliation ITAM teams actually want.

## API documentation

- GLPI REST API reference (authentication, session lifecycle, pagination, item and
  relation endpoints): https://github.com/glpi-project/glpi/blob/10.0/bugfixes/apirest.md
- `initSession` / `killSession`, App-Token and user_token semantics:
  https://github.com/glpi-project/glpi/blob/10.0/bugfixes/apirest.md#init-session
- `GET /:itemtype` range pagination, `Content-Range` and `Accept-Range`:
  https://github.com/glpi-project/glpi/blob/10.0/bugfixes/apirest.md#get-all-items
- `GET /:itemtype/:id` expansion parameters (`expand_dropdowns`, `get_hateoas`,
  `add_keys_names`, `with_networkports`, `with_softwares`, `with_disks`, `with_devices`,
  `with_infocoms`): https://github.com/glpi-project/glpi/blob/10.0/bugfixes/apirest.md#get-an-item
- GLPI Agent inventory schema, the source vocabulary for the inventoried fields:
  https://github.com/glpi-project/glpi-agent

# Custom Integration: phpIPAM

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the phpIPAM web application **over HTTPS**. See the TLS note below — this is not optional for phpIPAM.

## phpIPAM requirements

- phpIPAM 1.4 or later. Developed and captured against **phpIPAM 1.8.1**.
- **The API must be served over TLS.** phpIPAM refuses every API request that does not arrive over HTTPS, in *every* security mode, with `503 {"message":"SSL connection is required for API"}`. This is enforced in `api/index.php` and is the single most common setup failure. A plain-HTTP URL will authenticate zero times and import zero assets.
- The API server must be switched on globally: **Administration → phpIPAM settings → API → Enabled**. When it is off, every request answers `503 {"message":"API server disabled"}`.
- An **API application** (Administration → API → Create API key) with:
  - **App ID** — a short identifier such as `runzero`. It is a path segment on every request, so it is a required parameter here.
  - **App security** — `SSL with User token`. That is the mode this integration implements.
  - **App permissions** — `Read` is sufficient. The integration issues only `GET` requests plus the one `POST` that exchanges credentials for a token.
- A phpIPAM **user account** for the integration. Token authentication runs as that user, so the user's section permissions decide what the integration can see. Give it read permission on the sections you want imported.

### Why `Read` and not `Read/Write`

`Read/Write/Admin` (`app_permissions = 3`) additionally unlocks `/user/all/` and `/user/admins/`, which return the phpIPAM user table. This integration never calls them, and granting the extra level only widens what a leaked token reaches.

## Steps

### phpIPAM configuration

1. Enable the API server: **Administration → phpIPAM settings → API**, set *API* to *Enabled*, and save.
2. Create the API application: **Administration → API → Create API key**.
   - *App ID*: `runzero`
   - *App security*: `SSL with User token`
   - *App permissions*: `Read`
3. Create or choose a phpIPAM user for the integration and grant it read permission on the sections to import (**Administration → Users**, then **Administration → Sections** for per-section rights).
4. Confirm access from the Explorer host. Note that both calls must use `https://`:

   ```bash
   # 1. exchange credentials for a token
   curl -s -X POST -u 'runzero-user:<password>' \
        'https://ipam.example.com/api/runzero/user/'
   # -> {"code":200,"success":true,"data":{"token":"...","expires":"..."}}

   # 2. use the token
   curl -s -H 'token: <token>' 'https://ipam.example.com/api/runzero/subnets/'
   ```

   If step 1 answers `{"code":503,...,"message":"SSL connection is required for API"}`, the URL is not HTTPS or TLS is terminated somewhere phpIPAM cannot see. If it answers `{"code":503,...,"message":"API server disabled"}`, step 1 of this section was skipped.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "phpIPAM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **phpIPAM URL** (`url`): base URL of the web application, e.g. `https://ipam.example.com`. Include any path prefix phpIPAM is mounted under (`https://host/phpipam`) — the path is used verbatim.
   - **API app ID** (`app_id`): the App ID created above, e.g. `runzero`.
   - **Username** (`username`): phpIPAM user for the integration.
   - **Password** (`password`): that user's password.
   - **Import IPAM addresses** (`import_addresses`): optional; import one asset per managed address (default: enabled).
   - **Import registered devices** (`import_devices`): optional; import the operator-maintained device inventory (default: enabled).
   - **Sections** (`sections`): optional; comma-separated section names or IDs. Blank imports every readable section.
   - **Address tags** (`address_tags`): optional; comma-separated tag names or IDs, e.g. `Used,Reserved`. Blank imports every tag.
   - **Skip addresses with no hostname or MAC** (`require_identity`): optional; default enabled. See *Asset identity*.
   - **Maximum subnets** (`max_subnets`): optional; default 5000, 0 removes the cap.
   - **Maximum addresses** (`max_addresses`): optional; default 100000, 0 removes the cap.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the CLI

The Explorer ships the same runtime, so a task can be rehearsed locally before it is scheduled. `runzero script` takes one `--kwargs` pair per parameter:

```bash
runzero script --filename phpipam/phpipam.star \
  --kwargs url=https://ipam.example.com \
  --kwargs app_id=runzero \
  --kwargs username=runzero-user \
  --kwargs password='<password>' \
  --kwargs import_addresses=true \
  --kwargs import_devices=true \
  --kwargs address_tags=Used \
  --kwargs max_addresses=5000 \
  --kwargs tls_disable_validation=true
```

To check only that the CONFIG block and HTTP/TLS wiring are sound, without touching a real phpIPAM:

```bash
runzero script --filename phpipam/phpipam.star --validate
```

Two notes on the CLI:

- **Commas in a `--kwargs` value are fragile, which matters for `sections` and `address_tags`.** Both accept a comma-separated list, and both are fine in the console credential form. On the command line the flag parser treats a value containing `=` as CSV, splits it on the comma, and invents a second parameter from the remainder — so a password of that shape is corrupted silently. The repository's fixture harness refuses any comma-bearing kwarg outright for this reason. If a multi-term filter does not behave as expected from the CLI, set it in the console instead, or pass a single term as in the example above.
- **`scan` is a different command and is not what runs this.** `runzero scan` performs active network discovery against a target list; it never loads a custom integration script. Inbound integrations run either through `runzero script` as above or, in production, as a scheduled Custom Integration task on an Explorer. Nothing here needs `scan`.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with IPAM ownership, naming, VLAN, and location data from phpIPAM.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:phpipam`.

## Asset identity

phpIPAM publishes two different kinds of record, and they do not deserve the same treatment. They are imported with **different foreign id shapes and different match behavior**, which is the central design decision here.

They are emitted as two declared asset types — `address` and `device` — selected per record with `ImportAsset(assetType=...)`, and each type's merge policy is declared under that key in `CONFIG["assetTypeBehavior"]`.

`type-break` is left ON (the default), so an `address` and a `device` never merge with each other. An address row is a reservation whose occupant changes — see the reuse-behavior note below — while a device row is a hand-registered switch, router, or firewall. Letting a recycled reservation merge into a registered device would carry a decommissioned host's identity onto a switch, which is the same hazard `no-id-match` was chosen to avoid, one step removed. The known cost is that a router whose management IP is *also* documented as an address produces two assets; that is visible and reconcilable in runZero, whereas a wrong merge is silent.

### Addresses (`/subnets/{id}/addresses/`)

- Target entity: an **IP address reservation** under phpIPAM management. It is not a device record.
- Source ID field: `ipaddresses.id`, a MySQL `AUTO_INCREMENT` surrogate primary key, published as `id`.
- Uniqueness scope: one phpIPAM instance. The phpIPAM hostname is part of the runZero id so two instances polled into one organization cannot collide.
- Cardinality: one row per address per subnet — **not** one row per device. A device holding three addresses produces three assets.
- Stability: the id survives edits to the hostname, MAC, owner, description, tag, and location. It does **not** survive deleting and re-creating the address entry.
- Reuse behavior: **yes, and this is decisive.** The row describes an address, not the thing currently at that address. When a workstation is decommissioned and the address is handed to a printer, an operator edits the same row — same `id`, different device. Nothing in phpIPAM marks that transition.
- Presence: `id` is a primary key and is returned on every row. Rows arriving without one are skipped and logged by id only.
- Final runZero ID: `phpipam:<phpipam-host>:address:<id>` — for example `phpipam:ipam.example.com:address:101`.
- Missing-ID behavior: skip, logging the slug and the subnet id only — never the row, because an IPAM `description`, `note`, or `owner` routinely carries a person's name or a ticket reference. `new_uuid()` is not used anywhere in this script.
- Asset type: **`address`**.
- Match behavior: **`no-id-match no-id-break`**. The id is deterministic and stable, which is what makes repeated polls converge instead of duplicating, but it must not *drive* a merge. Because the underlying row is recycled between devices, a foreign-id match would eventually pull a decommissioned workstation and a new printer onto one asset — and a foreign-id match, once made, cannot be vetoed by any break flag. Correlation therefore falls back to MAC, IP, and hostname.
- Verdict: **derived / non-authoritative.** Treat address import as enrichment that layers IPAM ownership, naming, VLAN, section, and switchport context onto assets runZero already knows about.

### Registered devices (`/devices/`)

- Target entity: a **network device an operator registered** in phpIPAM — a switch, router, or firewall — from the `devices` table. This is a device inventory, not an address table.
- Source ID field: `devices.id`, again an `AUTO_INCREMENT` surrogate key, published as `id`.
- Cardinality: one row per physical device.
- Stability: survives hostname, address, type, rack, and location edits.
- Reuse behavior: **no.** A `devices` row is not recycled between chassis the way an address row is; retiring a device means deleting its row, and registering a replacement creates a new one.
- Final runZero ID: `phpipam:<phpipam-host>:device:<id>` — for example `phpipam:ipam.example.com:device:50`.
- Asset type: **`device`**.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**. The id is one-per-physical-device, so it is a legitimate foreign id and is allowed to drive merging; the break flags keep a disagreeing MAC, address, or name from disqualifying a first-contact merge.
- Known limitation: deleting and re-registering a device mints a new `id` and therefore **forks the asset**. That is unavoidable rather than a tuning mistake — the platform refuses, unconditionally and without consulting `matchBehavior`, to place two different foreign ids from the same custom integration on one asset. Reconcile such a fork in runZero.
- Verdict: **authoritative for what it covers**, which is only the devices an operator bothered to register. phpIPAM does not discover devices; this table is hand-maintained.

### Why `require_identity` defaults to on

An IPAM is mostly empty space. A row carrying an address and nothing else — no hostname, no MAC — says only "this address is spoken for", which is a statement about the address rather than about any device. Imported anyway, it merges onto whatever happens to hold that IP today and contributes a description written for a human. Such rows are skipped by default; turn the parameter off to import them, and expect noise.

## Notes

- **What is imported.** One asset per address row (address, hostname, MAC, owner, description, note, tag, gateway flag, switchport, subnet CIDR, VLAN number and name, section, location, customer), and one asset per registered device (hostname, address, type, description, sections, rack position, location, SNMP *version* and *port*).
- **SNMP credentials are dropped, deliberately.** `GET /devices/` runs a bare `SELECT * FROM devices` and phpIPAM does not redact the credential columns, so the response contains `snmp_community`, `snmp_v3_auth_pass`, and `snmp_v3_priv_pass` **in cleartext**. Verified against phpIPAM 1.8.1. This script removes `snmp_community`, `snmp_v3_auth_pass`, `snmp_v3_priv_pass`, and `snmp_v3_ctx_engine_id` from every device row before any attribute mapping, so they cannot reach runZero; `phpipam/tests/fixtures/happy.json` asserts their absence. `snmp_version` and `snmp_port` are kept because they describe the device rather than authenticate to it. This mirrors the `netdisco` integration's exclusion of `snmp_comm`.
- **Three fields are renamed on the wire**, which is easy to trip over when reading the schema rather than a response: `ipaddresses.ip_addr` (stored as a decimal string) is published as `ip` in dotted form; `ipaddresses.state` is published as `tag`; and `ipaddresses.switch` is published as `deviceId`.
- **An empty collection is HTTP 404, not an empty array.** `No devices configured`, `No addresses found`, and `No custom fields defined` are all 404s. Every fetch here treats a 404 as "empty" rather than as a failure; `tests/fixtures/empty.json` covers a completely fresh install.
- **There is no pagination anywhere in the phpIPAM API.** `/addresses/all/` executes an unbounded `SELECT *` over the whole `ipaddresses` table and returns every row in a single body, which on a production IPAM is hundreds of thousands of rows. This integration therefore **never calls `/addresses/all/`**; it enumerates subnets and walks addresses one subnet at a time, streaming each subnet's assets with `report_asset` so memory stays bounded by the largest single subnet. The subnet walk also supplies the CIDR, VLAN, and section context each address is reported with.
- **Timestamps are local time with no zone.** `lastSeen` and `editDate` are MySQL `DATETIME`/`TIMESTAMP` columns written in the database server's local time and returned as `2026-08-15 09:12:00`. Read as UTC on a server east of Greenwich they land in the future, and the platform rejects the **entire asset record** on a future timestamp rather than just the field. Every parsed value is therefore clamped to now, and the raw string is preserved as `phpipam_last_seen_raw` / `phpipam_edit_date_raw`. `1970-01-01 00:00:01` is phpIPAM's "never seen" column default and is discarded rather than imported as an epoch sighting.
- **`location` arrives in three different shapes.** On an address it is an integer id; on a subnet it is a nested object when set and an **empty list** when unset — not `null`, not `{}`. The type is checked before any subscript.
- Request volume is `6 + subnets` — one login, four reference-table reads, one device read, and one read per non-folder subnet. Folder subnets are skipped because they hold no addresses.
- Reference tables (`/sections/`, `/tools/tags/`, `/tools/locations/`, `/tools/device_types/`, `/vlans/`) are read once per run and only decorate assets, so each degrades to an empty map rather than failing the run.
- `deviceType` is set only from phpIPAM's own device type table, resolved by name at runtime because that table is user-editable. Unrecognised types leave `deviceType` unset rather than guessing.
- Self-signed certificates are common on self-hosted phpIPAM. `OPTIONS_TLS` is exposed for that; it never defaults to insecure.
- Rate limiting: phpIPAM publishes no documented rate limit. The shared HTTP helper retries transient statuses three times with exponential backoff and honors `Retry-After`.
- **Verification status:** every response body in `tests/fixtures/happy.json` was captured verbatim from a real phpIPAM 1.8.1 container (`phpipam/phpipam-www:v1.8.1` with `mariadb:11.4.4`) seeded with synthetic data. The 404-as-empty behavior, the cleartext SNMP columns, the field renames, the TLS requirement, and the absence of pagination were all observed on that instance rather than inferred from documentation.

## Future

- **`ssl_code` (static app code) authentication.** phpIPAM's `ssl_code` security mode replaces the login round trip with a fixed `app_code`, which suits an unattended collector. It is deliberately not implemented here because it could not be exercised against a live instance during development, and shipping an unverified auth path is worse than shipping one. `crypt` mode is the only mode that works without TLS, at the cost of encrypting each request with a shared key.
- **IPAM reconciliation.** The most valuable thing these two datasets can do together needs no new endpoint. Addresses runZero observes that phpIPAM has no row for are unmanaged space — shadow IT, or a subnet nobody registered. The inverse, rows tagged `Used` that runZero has never seen, are stale IPAM entries. `/subnets/{id}/usage/` already returns phpIPAM's own free/used arithmetic per subnet and would make the comparison cheap.
- **Outbound write-back.** phpIPAM's API supports `POST /addresses/` and `PATCH /addresses/{id}/`, so runZero could register addresses it discovers or correct a stale hostname. This should default to off and start by annotating `description` or a custom field rather than creating rows: in most deployments phpIPAM is the system of record and a bad write is a operational problem, not just inventory noise.
- **Subnets as runZero subnet metadata.** The subnet walk already reads CIDR, VLAN, section, description, and location for every subnet. Those map cleanly onto runZero sites and subnet annotations, and `masterSubnetId` supplies the supernet hierarchy above them.
- **`/l2domains/` and switchport correlation.** `ipaddresses.deviceId` and `port` already record which registered device and interface an address was seen on, and are imported as attributes. Joined with `/l2domains/` and the device inventory this approaches the layer-2 location data the `netdisco` integration produces, for sites that maintain it by hand.
- **Custom fields.** phpIPAM lets an administrator add arbitrary columns to `ipaddresses` and `devices`, returned nested under `custom_fields` when the API app has *nest custom fields* enabled. They are imported verbatim when present; `/addresses/custom_fields/` would let the integration discover and label them.

## API documentation

- API documentation index: https://phpipam.net/api/api_documentation/
- Interactive Swagger specification: https://phpipam.net/api-documentation/
- Source, including `api/index.php` (the TLS gate and app-security modes) and `api/controllers/`: https://github.com/phpipam/phpipam
- Database schema (`db/SCHEMA.sql`), authoritative for column names and defaults: https://github.com/phpipam/phpipam/blob/master/db/SCHEMA.sql
- Official container images: https://github.com/phpipam-docker/phpipam-docker

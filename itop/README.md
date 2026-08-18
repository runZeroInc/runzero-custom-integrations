# Custom Integration: iTop

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the iTop web server over HTTP or HTTPS.

## iTop requirements

- An iTop user holding the **REST Services User** profile. This is the requirement people
  most often miss: iTop's documentation states plainly that "Users with Administrator
  profile won't have access to REST without this additional profile."
- Read permission on the CI classes to be imported, **and bulk read permission on the
  same classes**. `core/get` checks both, and answers a user with read but not bulk read
  with `"The current user does not have enough permissions for exporting data of class X"`.
- iTop 2.6.1 or later for pagination. The `limit` and `page` parameters of `core/get`
  arrived with REST API version 1.4; an older instance ignores them and returns
  everything at once.
- iTop 3.1 or later with the `authent-token` module if a token is used instead of a
  password.

## Steps

### iTop configuration

1. Create the account the integration will use. In iTop go to
   **Administration → User Accounts → New**, create a local user, and on the
   **Profiles** tab grant it:
   - **REST Services User** — mandatory; without it every call returns code 1.
   - A read-only data profile such as **Configuration Manager** or **Service Desk Agent**
     covering the CI classes you intend to import. The integration only ever issues
     `core/get`; it never writes.

2. Confirm the credential and the permission from the Explorer host. iTop's REST endpoint
   is a single URL that takes `version` and `json_data` as form fields:

   ```bash
   curl -s -X POST 'https://itop.example.com/webservices/rest.php' \
     -u 'runzero:<password>' \
     -d 'version=1.4' \
     --data-urlencode 'json_data={"operation":"core/get","class":"Server","key":"SELECT Server","output_fields":"id,name,serialnumber,managementip","limit":5,"page":1}'
   ```

   A healthy response is `{"objects":{"Server::1":{...}},"code":0,"message":"Found: 5"}`.
   `"code":1` is an authorization failure — check the REST Services User profile first.
   `"objects":null` means the query matched nothing.

3. **HTTP Basic works out of the box; `auth_user` and `auth_pwd` do not.** iTop's wiki
   shows both, but the two body fields belong to iTop's `url` login type, and the shipped
   default for `allowed_login_types` is `form|external|basic|token`
   (`DEFAULT_ALLOWED_LOGIN_TYPES` in `core/config.class.inc.php`) — `url` is absent. This
   integration therefore sends the credential in an `Authorization` header. If your
   instance has had `basic` removed from `allowed_login_types`, add it back in
   `conf/production/config-itop.php`.

4. Optional, iTop 3.1 and later: create a token instead of using a password. Under the
   user's own **Personal tokens**, or **Administration → Application tokens**, create a
   token scoped to REST. It is sent in the `Auth-Token` header. A token can be revoked on
   its own and does not expose the account password.

5. Decide which classes to import and confirm the field names resolve on your data model.
   `output_fields` naming an attribute a class does not define is an error, not an
   omission, so an instance with a customized data model should be checked with the curl
   command above before scheduling the task.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "iTop").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **iTop URL** (`url`): base URL of the instance, including any subdirectory, for example `https://itsm.example.com/itop`. The `/webservices/rest.php` path is appended automatically.
   - **Username** (`username`): the iTop user holding the REST Services User profile. Leave blank when a token is supplied.
   - **Password** (`password`): that user's password.
   - **Authentication token** (`auth_token`): optional; application or personal token, sent as `Auth-Token`. Preferred over a password.
   - **CI classes** (`classes`): optional; comma-separated classes to import (default: `Server,VirtualMachine,NetworkDevice,PC`).
   - **OQL filter** (`oql_filter`): optional; appended to every query as a `WHERE` clause, for example `status != 'obsolete'`.
   - **REST API version** (`api_version`): optional; value sent as `version` (default: `1.4`).
   - **Page size** (`page_size`): optional; objects per `core/get` (default: 200).
   - **Import network interfaces** (`include_interfaces`): optional; read `PhysicalInterface` and `LogicalInterface` and attach each to its CI (default: true).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename itop/itop.star \
  --kwargs url=https://itsm.example.com/itop \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs classes=PhysicalDevice \
  --kwargs page_size=200 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./itop-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a directory
from a previous run. Add `--verbose` for the request-by-request log. Omit `--output` to
see only the log lines.

Note that `--kwargs` splits a single flag's value on commas, so a multi-class list such
as `classes=Server,VirtualMachine` cannot be passed on the command line — it arrives as
`classes=Server` plus a parameter named `VirtualMachine` that the script never declared.
For a command-line run, name one class at a time, or query the abstract parent
(`classes=PhysicalDevice`) which collects every subclass in a single query anyway. The
console's credential form has no such limitation.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename itop/itop.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove iTop accepts the credential or that any CI is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat itop/itop.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://itsm.example.com/itop,username=runzero,password=<password>' \
  --output ./itop-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. This flag takes one
comma-separated string and has the same limitation described above.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with CMDB data pulled from iTop.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:itop`.

## Asset identity

- Target entity: an iTop configuration item — a `Server`, `VirtualMachine`,
  `NetworkDevice`, `PC`, or any other `FunctionalCI` subclass the operator selects.
- Source ID field: the object's `key`, which is iTop's primary key for the object, taken
  from the per-object `key` field of the `core/get` response and falling back to
  `fields.id`.
- Documentation evidence: the REST/JSON reference shows every `core/get` response keying
  its `objects` map on `<Class>::<id>` and repeating the same value in each entry's `key`
  field, and documents `key` as accepting "an object ID" directly. iTop's own
  implementation builds that map key as `get_class($oObject).'::'.$oObject->GetKey()`
  (`core/restservices.class.inc.php`), so both halves come from the object itself.
- Uniqueness scope: one iTop instance. iTop allocates ids from a MySQL `AUTO_INCREMENT`
  column on the **root** of each class hierarchy, so an id is unique across every
  `FunctionalCI` subclass at once — a `Server` and a `VirtualMachine` cannot share one.
  The instance hostname is part of the runZero id so two iTop instances cannot collide.
- Cardinality: one row per asset. `PhysicalInterface` and `LogicalInterface` rows are
  separate objects in iTop that are folded into the CI that owns them rather than
  becoming assets.
- Stability: survives rename, address change, interface changes, status transitions,
  moving between organizations and locations, and re-import from a data collector. iTop's
  synchronization engine matches an incoming row to an existing object by its
  reconciliation key and updates that object in place.
- Reuse behavior: no, in normal operation. MySQL `AUTO_INCREMENT` does not reissue values
  for deleted rows while the table exists. Restoring the database from a dump taken before
  an object existed could in principle reissue one; that is the same exposure every
  self-hosted auto-increment id carries.
- Presence: always. It is the field iTop's REST layer keys its response on.
- Final runZero ID: `itop:<itop-host>:<Class>:<id>`, for example
  `itop:itsm.example.com:Server:11`. The class is the **concrete** class iTop reported
  for the object, never the class that was queried, so switching a task from
  `classes=Server` to `classes=PhysicalDevice` does not re-key a single asset.
- Missing-ID behavior: the record is skipped and one line is logged carrying the class
  and the object's name only. No identity is synthesized and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The iTop id is authoritative,
  but a CMDB record is maintained by hand and by importers, so it is routinely renamed
  and routinely carries a stale `managementip` or none at all. Network churn must not
  disqualify a merge against the asset runZero already has.
- Verdict: **scoped authoritative** — authoritative within one iTop instance, namespaced
  by the instance hostname.

### Notes

- **What is imported.** One asset per CI from `core/get` on each selected class, carrying
  the name, description, organization, business criticity, status, serial number, asset
  number, location, brand and model, operating system family and version, CPU and RAM,
  rack and enclosure, warranty and purchase dates, and the class-specific attributes
  (`networkdevicetype_name` and `iosversion_name` for network devices,
  `virtualhost_name` for virtual machines, `type` for PCs, `phonenumber` and `imei` for
  telephony CIs). Network interfaces come from `PhysicalInterface` and
  `LogicalInterface`.
- **Interfaces are read as classes, not as link sets.** `ConnectableCI` exposes a
  `physicalinterface_list` link set and `VirtualMachine` a `logicalinterface_list`, and
  asking for either in `output_fields` would return them inline. iTop's own documentation
  warns against exactly that: "Try to avoid `*_list` fields in the `output_fields`" —
  a link set pulls the full contents of every linked object and can exhaust the PHP
  memory limit on a large CMDB. Instead each interface class is read once, up front, with
  an explicit field list, and indexed by the external key that names its owner
  (`connectableci_id` for physical, `virtualmachine_id` for logical). Because iTop
  allocates ids from the root of the hierarchy, one map keyed on the owner id serves both
  without a collision.
- **`managementip` is not on every class.** It is defined on `DatacenterDevice`, which is
  the parent of `Server` and `NetworkDevice`, and separately on `VirtualMachine`. A `PC`
  or a `Printer` is a `ConnectableCI` and has no such attribute at all — their addressing
  comes only from `PhysicalInterface`. When a management address is present it becomes an
  interface of its own only if no modelled interface already carries it, so a
  well-populated CMDB does not gain a duplicate.
- **Field names differ from the obvious guesses.** The organization is
  `organization_name`, not `org_name`; both `org_id` and `organization_name` exist and
  only the latter resolves to a readable value. `status` lives on `PhysicalDevice` and on
  `VirtualDevice` but not on their shared parent `FunctionalCI`, so it cannot be requested
  from an abstract query above that level. Requesting an attribute a class does not define
  is an error rather than an omission, which is why each class has an explicit field list
  and an unlisted class falls back to the `FunctionalCI` attributes that every CI has.
- **An abstract class collects every subclass in one query.** `classes=PhysicalDevice`
  returns Servers, PCs, Printers, Tablets, and phones in a single `core/get`, and iTop
  instantiates each row as its concrete leaf class and reports that class per object. That
  is usually the better query: fewer round trips, and no risk of missing a subclass
  somebody added. The concrete class is what ends up in the foreign id.
- **Requests are form posts, not JSON posts.** `version` and `json_data` are ordinary
  `application/x-www-form-urlencoded` fields — this is what iTop's own curl examples
  send — while the credential travels in an `Authorization` or `Auth-Token` header. The
  documented `auth_user` and `auth_pwd` body fields are deliberately not used, because
  they belong to iTop's `url` login type which is absent from the shipped
  `allowed_login_types` default.
- **Pagination needs version 1.4.** iTop's source comments the version history inline:
  *"1.4 - iTop 2.5.2, 2.6.1, 2.7.0, Verb 'core/get': added pagination parameters limit and
  page"*. The wiki's worked examples still show `version=1.3`, which is why the version is
  a parameter and defaults to `1.4`. An instance that ignores `limit` and `page` returns
  the whole result set on every request, which would otherwise be an infinite loop rather
  than an error — each page looks full, so the loop asks for the next one forever. The run
  detects a page that produced no new objects, logs that the server appears to ignore the
  parameters, and stops.
- **The HTTP status is not the error signal.** iTop answers an authorization failure with
  HTTP 200 and `{"code":1,"message":"..."}`. A run that trusted the status code would
  report an empty CMDB. Every response's own `code` is checked against iTop's documented
  table (1 UNAUTHORIZED, 2 MISSING_VERSION, 3 MISSING_JSON, 4 INVALID_JSON, 10
  UNSUPPORTED_VERSION, 11 UNKNOWN_OPERATION, 100 INTERNAL_ERROR), and per-object codes
  inside the `objects` map are checked too.
- **An empty result is `null`, not `{}`.** A query that matched nothing returns
  `"objects": null`, which is the loop's termination condition alongside a short page.
- **Timestamps carry no timezone and are clamped.** iTop serializes `AttributeDate` as
  `2024-03-11` and `AttributeDateTime` as `2024-03-11 08:21:38`, with no offset in either
  case, and `parse_time` rejects both with an error that would abort the whole script.
  Each is validated field by field before a `Z` is appended, and read as UTC because the
  API publishes no offset. `move2production` becomes `firstSeenTS`, clamped to the current
  time — runZero rejects an asset whose first-seen time is in the future and drops the
  **entire record**, so a CI with a planned go-live date would otherwise be lost
  silently. `lastSeenTS` is deliberately **not** set: a CMDB row records what should
  exist, not when it was last observed, and filling last-seen from the date somebody last
  edited the record would misrepresent a documentation change as an observation.
- **A CI with nothing to correlate on is skipped.** An iTop record with no interface, no
  management address, and a name that is a human label rather than a hostname — "Unnamed
  rack unit" — cannot merge with anything runZero discovers. It is dropped with a log
  line naming the class and id.
- **`deviceType` comes from the class, not from a guess.** `Server` → Server,
  `NetworkDevice` → Network Device, `VirtualMachine` → Virtual Machine, `Hypervisor` →
  Hypervisor, `Printer` → Printer, and `PC` → Laptop or Desktop from its own two-valued
  `type` enumeration.
- **No services and no vulnerabilities.** iTop models neither. Its `SoftwareInstance`
  class records that an application is installed on a CI, which is closer to software
  inventory than to a listening port, and nothing in the base data model describes an open
  socket. Nothing is synthesized for either.
- **Rate limiting.** iTop publishes no rate limit and returns no rate-limit headers.
  Transient failures are retried with exponential backoff by the shared HTTP helper,
  which honours `Retry-After`. `core/get` is a read, so retrying it is safe.
- This integration was validated against local fixtures built from the response shapes in
  iTop's REST/JSON documentation and the attribute names in the shipped
  `itop-config-mgmt`, `itop-endusers-devices`, and `itop-virtualization-mgmt` data model
  XML. It has **not** been run against a live iTop instance, and an instance with a
  customized data model may define or rename attributes this integration requests.

## Future

- **`SoftwareInstance` as software inventory.** iTop's `SoftwareInstance` class links a
  `Software` object to the CI it runs on, with `softwarelicence_id` and patch levels
  through `lnkSoftwareInstanceToSoftwarePatch`. One extra paged read keyed on
  `functionalci_id` would populate runZero `Software` records, and the `Patch` and
  `OSPatch` classes would give patch-currency data that nothing else in this integration
  reaches. `Software.cpe23` would have to stay unset — iTop publishes no CPE — which
  limits vulnerability correlation but not inventory value.
- **Subnets and VLANs as network context.** `Subnet` (with `ip`, `ip_mask`, `vlans_list`)
  and `VLAN` are first-class classes, and `lnkPhysicalInterfaceToVLAN` ties an interface
  to the VLANs it carries. Importing those would let runZero map discovered addresses onto
  the subnets the CMDB believes exist — and, read the other way, surface address space in
  use that the CMDB has never heard of, which is one of the most valuable things these
  two datasets can say together.
- **Contacts, teams, and application solutions as ownership.** `lnkContactToFunctionalCI`
  and `applicationsolution_list` answer "who owns this and what does it serve", which is
  the question that actually gets asked when runZero finds something unexpected. These are
  link sets, so they need the same read-the-link-class-directly treatment the interfaces
  get here.
- **Incremental import.** OQL supports filtering on any attribute, so a scheduled task
  could fetch only objects changed since the last run. What blocks it is that iTop's
  change timestamps live on the `CMDBChangeOp` history objects rather than on the CI, so
  this needs either a join through the change log or a customization that surfaces a
  modification date on the CI itself.
- **Outbound: create and update CIs from runZero discovery.** The same endpoint supports
  `core/create`, `core/update`, and `core/apply_stimulus`, so runZero could file the
  assets a CMDB has no way to see — unmanaged devices, OT gear, contractor equipment —
  directly into iTop. This is the strongest pairing available here and also the one that
  needs the most care: iTop is a system of record with change history, contracts, and
  ticket linkage attached to its objects. Such an integration should write into a
  dedicated organization, reconcile on serial number or MAC, never delete, never overwrite
  a manually maintained field, and ship with a dry-run mode. iTop's own **Data
  Synchronization** feature (synchro data sources) is the more idiomatic target: it is
  built for exactly this, keeps imported objects visibly distinct from hand-maintained
  ones, and handles the reconciliation rules itself.
- **Ticket creation from runZero findings.** `core/create` on `UserRequest` or `Incident`
  would open an iTop ticket for a newly discovered unmanaged asset, and
  `lnkFunctionalCIToTicket` would attach it to the CI so it appears on the object's own
  page.

## API documentation

- REST/JSON services reference (endpoint, authentication, `json_data`, `core/get`,
  `output_fields`, `limit` and `page`, the error code table):
  https://www.itophub.io/wiki/page?id=latest%3Aadvancedtopics%3Arest_json
- Authentication by token (`Auth-Token` header, application and personal tokens):
  https://www.itophub.io/wiki/page?id=extensions%3Aauthent-token
- Data model documentation (class hierarchy and attribute names):
  https://www.itophub.io/wiki/page?id=latest:datamodel:start
- Shipped data model XML, the source of every field name used here —
  `FunctionalCI`, `PhysicalDevice`, `ConnectableCI`, `DatacenterDevice`, `Server`,
  `NetworkDevice`, `IPInterface`, `PhysicalInterface`:
  https://github.com/Combodo/iTop/blob/develop/datamodels/2.x/itop-config-mgmt/datamodel.itop-config-mgmt.xml
- `PC`, `Printer`, `Tablet`, and the telephony classes:
  https://github.com/Combodo/iTop/blob/develop/datamodels/2.x/itop-endusers-devices/datamodel.itop-endusers-devices.xml
- `VirtualMachine`, `Hypervisor`, `Farm`, `LogicalInterface`:
  https://github.com/Combodo/iTop/blob/develop/datamodels/2.x/itop-virtualization-mgmt/datamodel.itop-virtualization-mgmt.xml
- REST implementation, including the supported version list and the `<Class>::<id>` key
  construction: https://github.com/Combodo/iTop/blob/develop/core/restservices.class.inc.php
- `allowed_login_types` and its shipped default:
  https://github.com/Combodo/iTop/blob/develop/core/config.class.inc.php

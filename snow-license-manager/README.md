# Custom Integration: Snow License Manager

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  Snow License Manager requirements

- **Snow License Manager instance URL** (`url`) — the base URL of your SLM web server, for example `https://slm.example.com`. The Web API lives under `/api` on that same host, and the integration appends the path itself, so configure the host only.
- **Customer ID** (`customer_id`) — the numeric customer whose computers you want. On Enterprise Edition this is always `1`. On SPE (multi-customer) editions there are several, and which ones you can see depends on the rights of the API user.
- **Username** (`username`) and **password** (`password`) — an SLM user account holding the built-in **API Users** role. The Web API authenticates with HTTP Basic, which is why the connection must be HTTPS.
- The integration only reads. No write permission is required.

> These four values are runZero credential fields. Earlier versions of this integration hard-coded the URL and customer ID in the script as `SNOW_BASE_URL` and `SNOW_CUSTOMER_ID`; they are now `CONFIG` parameters and the script does not need editing.

## Snow License Manager API Docs

- Snow License Manager Web API — <https://docs.flexera.com/snow-license-manager/web-api/>

## Steps

### Snow License Manager configuration

1. Create the API account. In **Snow Management and Configuration Center** (not the SLM web UI), create or choose a user and assign it the built-in **API Users** role.
   - An account holding the API Users role **cannot sign in to the Snow License Manager web interface**. This is expected; make it a dedicated service account rather than an existing person's login.
   - Record the username and password. These become the `username` and `password` credential fields in runZero.
2. Determine the instance URL. The Web API is your SLM URL with `/api` appended — if the SLM URL is `https://slm.example.com`, the API is at `https://slm.example.com/api`. Configure the base URL (`https://slm.example.com`) in runZero, not the `/api` path.
3. Find the Customer ID:
   - **Enterprise Edition**: it is always `1`.
   - **SPE editions**: browse `https://<slm-url>/api` and follow the **Customers** link, or request `https://<slm-url>/api/customers/` directly, and note the `Id` of the customer you want. Only the customers the API user has rights to are listed.

   ```bash
   curl -s -u '<username>:<password>' https://slm.example.com/api/customers/
   ```

   To import from more than one customer, create one credential and one task per customer ID.

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - **Snow License Manager URL** (`url`): the SLM base URL, e.g. `https://slm.example.com`. The `/api` path is appended automatically.
    - **Customer ID** (`customer_id`): the numeric customer to import; `1` on Enterprise Edition.
    - **Username** (`username`): the SLM account holding the API Users role.
    - **Password** (`password`): that account's password, sent as HTTP Basic auth.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon 
    - Toggle `Enable custom integration script` to input your finalized script
    - Click `Validate` to ensure it has valide syntax
    - Click `Save` to create the Custom Integration 
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created in steps 2 and 3
    - Update the task schedule to recur at the desired timeframes
    - Select the Explorer you'd like the Custom Integration to run from
    - Click `Save` to kick off the first task 

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter. Note that this integration's script is `snow-license-manager.star`, not `snow-license-manager.star`:

```bash
runzero script --filename snow-license-manager/snow-license-manager.star \
  --kwargs url=https://slm.example.com \
  --kwargs customer_id=1 \
  --kwargs username=runzero-api \
  --kwargs password=NotTheRealPassword1 \
  --output ./snow-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

If the run authenticates but returns nothing, check the customer ID before the credential.
An API user with no rights to the customer you named produces an empty result rather than
an error.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename snow-license-manager/snow-license-manager.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Snow accepts the credential or that any computer is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat snow-license-manager/snow-license-manager.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://slm.example.com,customer_id=1,username=runzero-api,password=<password>' \
  --output ./snow-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration 
- The task will update the existing assets with the data pulled from the Custom Integration source 
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:snow-license-manager`. The slug is the script's `CONFIG` id with the `runzero-` prefix removed; if it returns nothing, check the name you gave the integration in the console.

## Asset identity

- Target entity: a **computer** record in Snow License Manager, from `GET /api/customers/{customer_id}/computers`. Snow is a software asset management platform, so the population is machines its inventory agent (or a connector) has reported — the estate Snow is licensing, not everything on the network.
- Source ID field: `Body.Id`, falling back to `Body.BiosSerialNumber`. A record with neither is skipped and logged with its `Name`.
- Documentation evidence: `Id` is the value every computer sub-resource is addressed by in the Web API — this integration itself relies on that, building `GET /api/customers/{customer_id}/computers/{Id}/applications` from it to fetch each machine's software. An identifier the API uses to scope a child collection is the API's own statement about what identifies the parent. Every Web API response wraps the record in a `Body` object alongside its `Meta`, which is why the mapping reads `entry.get('Body', {})` before anything else.
- Uniqueness scope: **one customer within one SLM instance — and the id does not say so, which is the weakness here.** `customer_id` is a required parameter precisely because Snow's computer ids are numbered per customer, and on an SPE (multi-customer) edition several customers exist side by side in one installation. The id is nevertheless used bare: `asset_id = str(raw_id)`. Two consequences follow:
  - Importing two Snow customers into one runZero organization — which the setup notes explicitly describe as "one credential and one task per customer ID" — puts both customers' computers into a single foreign-ID namespace, where low integers collide systematically.
  - Two separate SLM installations collide the same way.

  Both are avoidable: `customer_id` and the URL hostname are already in hand, and scoping the id on them the way `snipe-it` does would close it. This is the single change most worth making to this integration.
- Cardinality: one asset per computer record. Applications are fetched per computer and attached as `Software`, so a machine with two hundred packages is still one asset.
- Stability: `Id` is stable for the life of the record. Snow's own inventory dedup decides whether a rebuilt machine is the same computer or a new one, and that is a Snow-side configuration question rather than something this integration can influence — expect a re-imaged host to be a new record on some installations and the same one on others.
- Reuse behavior: not documented.
- Presence: `Id` is present on every computer record. The `BiosSerialNumber` fallback is defensive, and it changes the shape of the identity when it fires — a numeric id becomes a serial string. A record that reports an `Id` on one run and only a serial on the next would change identity; no such behavior has been observed.
- Final runZero ID: the raw `Id` (or `BiosSerialNumber`) as a string, unprefixed and unscoped.
- Missing-ID behavior: skip the record with `snow: skipping computer with no Id/BiosSerialNumber: name=<name>`.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within one customer of one installation; the boundary is enforced by the credential and the task, not by the id.

### Why the default `matchBehavior` is right

The Snow computer id is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it.

The usual companion preset `no-mac-break no-ip-break no-name-break` would be a poor fit for this source, and the reason is the shape of `Hardware.NetworkAdapters`. Snow's inventory agent reports the machine's adapters with both `MacAddress` and `IpAddress`, and the mapping builds one `NetworkInterface` per adapter — splitting `IpAddress` on `;` because a multi-homed adapter reports several addresses in one field. That is first-party agent data about a real machine's real hardware, not drifting inventory metadata, and it is exactly what should be allowed to merge a Snow record onto an asset runZero already scanned. Suppressing the break flags would discard the strongest correlation signal this source has while protecting against churn that cannot occur — a foreign-ID match is never disqualified by a conflicting MAC, address, or name.

One thing to know about the adapter list: it is **not filtered**. Every adapter Snow reports becomes an interface, including virtual, VPN, and hypervisor adapters, whose addresses are frequently identical across hosts. `mac-break` staying on is what limits the damage when a shared virtual MAC is about to pull two machines together, which is a second reason not to relax it.

### Notes

- **Software costs one request per computer.** `get_apps()` calls `GET /api/customers/{customer_id}/computers/{Id}/applications` for every machine, paged. On a large estate that dominates the run time, and there is no parameter to turn it off — disabling software import means editing the script.
- **There is no third request tier, and there deliberately is not one.** A `get_app_details()` helper wrapping `GET /api/customers/{customer_id}/applications/{app_id}` used to sit in the script with its call site in `build_app()` commented out. It has been removed. It could not have run as written — the call site passed one argument to a five-parameter function, inside a function that holds no base URL, customer id or credentials to pass it — and its cost is not one request per computer but one per **computer-application pair**, since the same application is installed on hundreds of machines. What it would have added over the per-computer row is licensing state, and the whole catalog carries that in a single request (see the applications-catalog item below). The `happy` fixture asserts `requests_absent` on that path, so the tier cannot come back unnoticed.
- **Timestamps are parsed with `parse_ts`**, which reads Snow's zone-less values as UTC and never raises — a date-only or already-offset value on one record becomes its raw string attribute instead of aborting the whole import (`parse_time` with a `Z` appended, which this script used to do on six fields, raised on exactly those shapes).
- **A computers-list row without a `Hardware` block triggers one per-computer detail read** (`GET /api/customers/{customer_id}/computers/{Id}`) as a fallback. Whether the real SLM list returns full rows or summary rows is unconfirmed against a live install; a server whose list rows carry `Hardware` never pays the extra call.
- **`DisplayAdapters` and `Monitors` are flattened into indexed attributes** (`displayAdapter.0.*`, `monitor.0.*`), handling both the list and single-object shapes Snow returns depending on count.
- **`deviceType` is set only when Snow says something positive.** `IsServer` maps to `Server` and `IsPortable` to `Laptop`; a machine that is neither is left unmapped rather than assumed to be a desktop, because Snow sets `IsVirtual` independently of both and an invented `deviceType` overrides runZero's own fingerprinting.
- This integration was validated against local fixtures, not a live Snow License Manager installation.

## Future

- **The `applications` catalog as a licensing view.** `GET /api/customers/{customer_id}/applications` lists the applications Snow knows about, with manufacturer, family, and — the point of the product — licensing and compliance state. This integration reaches applications only through the per-computer collection, so it sees what is installed and never what is licensed. Importing the catalog and joining on `Id` would let runZero answer "which installed software is unlicensed or over-deployed", which is a question no scanner can answer and which Snow exists to answer.
- **`GET /api/customers/{customer_id}/applications/{id}` for per-application detail.** It carries the fuller metadata — version, edition, licensing model — that the per-computer list omits. The helper that once wrapped it has been removed (see above), and anything that reinstates it needs a run-scoped cache keyed on application id, because the same application appears on hundreds of computers and would otherwise be fetched hundreds of times. The whole-catalog read in the item above is the cheaper route to the same fields and should be tried first.
- **Users and organizational structure.** The Web API exposes users and the organizational hierarchy alongside computers, and Snow tracks which user a computer is assigned to. That is ownership attribution runZero's own discovery cannot produce. It is personal data, so it belongs behind a parameter rather than being imported unconditionally.
- **Datacenter and virtualization inventory.** Snow tracks hosts and clusters separately from client computers for licensing purposes — core counts and virtualization relationships are what server licensing is calculated from. Those records describe physical infrastructure that runZero scans anyway, so importing them would let the two views merge rather than sit apart.
- **Server-side filtering and a page-size parameter.** The computers endpoint is paged with the standard Web API `Meta` envelope, and this integration reads every page of every run with no filter and no configurable page size. A first run against a large SPE customer therefore reads everything, and there is no way to bound it from the credential. Both are small changes and both would help most on exactly the installations where the run is slowest.
- **Outbound push-back is not available.** The Snow License Manager Web API is documented as a read interface; there is no documented endpoint for creating or updating a computer record, and the API Users role is a read role. Snow's write-side integrations go through its Inventory and connector machinery rather than through this API, so runZero could not currently file a discovered-but-uninventoried machine into Snow. If that is wanted, the route to investigate is Snow Inventory's connector import format, not the Web API.
- **Coverage-gap reporting needs no new endpoint and is the strongest pairing here.** Snow only knows machines its inventory agent reports. runZero discovers machines regardless. In-scope runZero assets carrying no `custom_integration:snow-license-manager` source are Snow Inventory deployment gaps — and on a software asset management estate those are not just monitoring gaps, they are unlicensed-software risk, because software on a machine Snow cannot see is software nobody is counting.
- **There is no event or alert feed.** The Web API is a resource interface with no webhook, no event stream, and no change cursor on the computers collection. Anything near-real-time would be re-paging the collection, which — given the per-computer applications call — is the most expensive thing this integration does.
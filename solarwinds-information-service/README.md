# Custom Integration: SolarWinds Orion - SolarWinds Information Service (SWIS) 

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  SolarWinds SWIS requirements

**SWIS instance URL** — the hostname or IP of the SolarWinds Platform (Orion) server plus the SWIS REST port, for example `https://my.solarwinds.instance:17774`. This is the `url` credential parameter; it defaults to `https://localhost:17774`. It is read with `get_url_base()`, so give a scheme, host, and port only — the script appends `/SolarWinds/InformationService/v3/Json/Query` itself.

**username** and **password** — a SolarWinds Platform Web Console account, configured in the Credentials section of runZero. These are not API keys; SWIS authenticates with HTTP Basic against a normal console account.

**A SWQL query** — this integration ships with an **empty query** and imports nothing until you supply one. See the configuration steps below. This is the most common reason a correctly configured task returns zero assets.

### Which port

The SWIS REST endpoint moved, and which port answers depends on the version:

| SolarWinds Platform version | SWIS REST port |
|---|---|
| before 2023.1 | 17778 |
| 2023.1 through 2024.1 | 17774 or 17778 (17778 deprecated in 2023.1) |
| 2024.2 and later | **17774 only** — 17778 no longer listens |

### Which account

SWIS has no dedicated API role. Access is governed by the ordinary Web Console
account settings, and there is nothing to enable to turn the API on — the
endpoint listens by default.

- An **Orion individual account** (one that exists only in the SolarWinds database) is the simplest choice for an integration. Windows/AD and SAML accounts also work.
- New accounts are created with minimal rights and no account limitations, so a freshly created account is already effectively read-only. Leave the `Allow …` toggles off: **Allow Administrator Rights**, **Allow Node Management Rights**, **Allow Report Management Rights**, **Allow Alert Management Rights**, and the various "Allow Account to Disable / Clear / Unmanage" settings. This integration only reads.
- Watch **account limitations** specifically. They restrict which objects the account can see, and they apply to SWIS queries too — an account with a limitation silently returns a subset of your estate rather than an error. If the import is missing nodes you expect, check this before debugging the query.

The exact Settings menu path to account management varies by version and was not
verified for this document; look for Manage Accounts in the SolarWinds Platform
administration settings.

### Certificates

SWIS presents an **intentionally self-signed certificate** whose subject is
`CN=SolarWinds-Orion` rather than the server's FQDN, so both chain and hostname
validation fail by default. Either install a trusted certificate on the server
(the certificate SWIS presents is selected with the
`CertificateNameForSafeguardCommunicationOnSwisRestEndpoint` setting) or set the
`tls_` options on the runZero credential accordingly.

## SolarWinds SWIS API Docs

- [SWIS Cortex.Orion.Node Schema Reference](https://solarwinds.github.io/OrionSDK/schema/Cortex.Orion.Node.html)

- [Orion SDK SWIS Docs](https://github.com/solarwinds/OrionSDK/wiki/About-SWIS)

## Steps

### Solarwinds configuration

1. Determine the proper SolarWinds URL and port, using the version table above. The URL is a credential parameter (`url`), not a constant in the script — there is nothing to edit in the source to set it.
2. Create or choose the Web Console account the integration will use, and confirm it carries no account limitations that would hide part of your estate.
3. Confirm the endpoint answers from the Explorer host before configuring anything in runZero:

   ```bash
   curl -sk -u '<user>:<password>' \
     --get 'https://my.solarwinds.instance:17774/SolarWinds/InformationService/v3/Json/Query' \
     --data-urlencode 'query=SELECT TOP 1 NodeID, Caption FROM Orion.Nodes'
   ```

   A JSON object with a `results` array means the port, the account, and SWQL
   are all working. `-k` is used here because of the self-signed certificate
   described above; decide deliberately whether to keep skipping validation in
   the runZero credential.

### runZero configuration

1. (Make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
     >- Determine the proper SWQL query needed to return the data set to import to runZero
     >- Add this query to the integration script in the 'params' variable within the 'get_assets' function.
    - Modify attribute mapping based on the data returned by the SWQL query as needed
        >- The integration script outlines some common example attributes that could be brought in from Solarwinds but the attributes that are actually retrieved will be determined by the SWQL query passed in the API call params
        >- Modify the asset attributes and custom attributes to match the data provided by the SWQL query following the pattern outlined in the script
        >- For a list of "core" attributes that runZero maps, reference the Custom SDK documentation [here](https://runzeroinc.github.io/runzero-sdk-py/autoapi/runzero/types/_data_models_gen/index.html#runzero.types._data_models_gen.ImportAsset). All other attributes provided by Solarwinds should be mapped within 'Custom Attributes'
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type **Custom Integration Script Secrets**
    - **SWIS URL** (`url`) is optional and defaults to `https://localhost:17774`. Set it to the SolarWinds server the Explorer should reach — the default is only correct if the Explorer runs on the SolarWinds server itself.
    - Both **username** and **password** are required
    - **username** corresponds to the username to access Solarwinds
    - **password** corresponds to the password to access Solarwinds
    - **TLS options** (`tls_*`): set these to deal with the self-signed SWIS certificate described above
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name (e.g. solarwinds) and Icon 
    - Toggle **Enable custom integration script** to input your finalized script
    - Click **Validate** to ensure it has valide syntax
    - Click **Save** to create the Custom Integration 
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created in steps 2 and 3
    - Update the task schedule to recur at the desired timeframes
    - Select the Explorer you'd like the Custom Integration to run from
    - Click **Save** to start the task 


### Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to iterate on a
SWQL query — and because this integration ships with an empty query, iterating on
one is most of the work. Each `CONFIG` parameter is a `--kwargs key=value` pair:

```bash
runzero script --filename solarwinds-information-service/solarwinds-information-service.star \
  --kwargs url=https://my.solarwinds.instance:17774 \
  --kwargs username=runzero-ro \
  --kwargs password=hunter2-not-a-real-password \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/swis-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

**Expect this to import nothing on a first run.** The `query` value in
`get_assets()` ships empty, so the script asks SolarWinds for nothing and prints
`no assets`. That is the shipped state, not a failure. Edit the query in
`solarwinds-information-service/solarwinds-information-service.star` — the commented-out example above the
`params` line is a working starting point — then re-run. Because there is no
query parameter on the credential, the edit-and-re-run loop is the only way to
develop one, which is exactly what the command line is good for.

`tls_disable_validation=true` appears above because SWIS presents a self-signed
`CN=SolarWinds-Orion` certificate that will not validate against the hostname you
connect to. Drop it once a trusted certificate is installed.

There is no paging parameter. Bound a first run inside the SWQL itself with
`SELECT TOP 25 …` rather than trying to cap it from the command line.

**One `--kwargs` caveat, for the password specifically.** A comma in a value is
harmless on its own — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks is a value
carrying **both** an `=` and a comma: the flag parses an argument containing a
second `=` as a CSV record, so `password=a=b,c=d` yields `password=a=b` plus a
fabricated `c=d`. Wrap the whole argument in double quotes to pass such a value
as one field — `--kwargs '"password=a=b,c=d"'` — and double any quote inside it.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real server:

```bash
runzero script --filename solarwinds-information-service/solarwinds-information-service.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it does not run your SWQL and
tells you nothing about whether the query is valid or the account can see the
nodes it selects.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://my.solarwinds.instance:17774,username=runzero-ro,password=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma. A SWQL query would be torn apart by that rule
several times over, which is one more reason the query lives in the script rather
than in a parameter.

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

### What's next?

- You will see the task initialize on the [tasks](https://console.runzero.com/tasks) page like other integration tasks
- The task will update the existing assets with the data pulled from the Custom Integration source
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, IP, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:solarwinds-information-service`. The slug is the script's `CONFIG` id with the `runzero-` prefix removed; if it returns nothing, check the name you gave the integration in the console.

## Asset identity

**Read this before writing your SWQL query — the query decides the identity.** Unlike every
other integration in this library, the field this one keys on is not fixed by the script. It
is whatever your query happens to select, and getting that wrong produces a silent, systematic
identity failure rather than an error.

- Target entity: a **node** in SolarWinds Orion — a device Orion polls, which may be a server, a switch, a router, a firewall, a UPS, or anything else with an address Orion monitors.
- Source ID field: `NodeId`, falling back to `Fqdn`, then to `IpAddress`. A row with none of the three is skipped and logged.
- Documentation evidence: `NodeID` is the primary key of `Orion.Nodes` and the value every other Orion entity joins a node with — `Orion.NodesCustomProperties`, `Orion.NPM.Interfaces`, `Orion.Volumes`, and the rest all carry a `NodeID` foreign key. The [Cortex.Orion.Node schema reference](https://solarwinds.github.io/OrionSDK/schema/Cortex.Orion.Node.html) documents it as the node key, and SWIS URIs for a node are built from it. It is the right field, and it is not the one you will get by accident.
- Uniqueness scope: one Orion installation, and the id now says which one. `NodeID` is a small per-installation auto-increment integer that every Orion numbers from 1, so a bare id collided systematically on low integers as soon as two Orion servers were imported into one runZero organization. The id is therefore namespaced on the host from the configured SWIS URL — `swis:<swis-host>:node:<id>` — which is the only thing distinguishing two installations that this API exposes.
- Cardinality: one asset per node **if the query returns one row per node**. A SWQL query that joins to interfaces, volumes, or any other child entity returns one row per child, and the script builds one `ImportAsset` per row — several rows sharing a `NodeId` produce several assets with the same foreign id, which the platform merges last-write-wins. Nothing errors; the attributes simply become arbitrary. Keep the query on `Orion.Nodes` and pull child data with a separate pass if you need it.
- Stability: `NodeID` is stable for the life of the node record and survives rename, re-addressing, and re-polling. It does not survive deleting and re-adding the node, which is a routine way Orion estates are corrected.
- Reuse behavior: not documented. Orion's node ids are sequential integers and a restored database can certainly re-issue them.
- Presence: **entirely under your control, and this is the trap.** The two fallbacks fire when the SWQL query does not select `NodeID`:
  - A query selecting `Fqdn` but not `NodeID` silently keys every asset on its **hostname**. That works until a device is renamed, at which point it becomes a new asset.
  - A query selecting neither keys on **`IpAddress`**, which is far worse — a DHCP device changes identity whenever its lease changes, and two nodes that have ever shared an address merge into one.

  Neither case logs anything. The run succeeds, the asset count looks right, and the identity is wrong. Select `NodeID` in every query, whether or not you map it to anything.
- Final runZero ID: `swis:<swis-host>:node:<NodeId>`, falling back to the `Fqdn` or `IpAddress` in the same slot when the query returned no `NodeId`.
- Missing-ID behavior: the row is skipped and tallied, and the run prints one `swis: skipped N nodes with no NodeId/Fqdn/IpAddress` line at the end rather than a line per row — a query selecting the wrong columns would otherwise log once per node in the estate.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within one Orion installation **when the query selects `NodeID`**; hostname- or address-derived and not authoritative otherwise.

> **Upgrading from a build that emitted the bare id:** earlier versions used the
> raw `NodeId` (`101`) with no scope. Assets created by those runs carry the old
> foreign id and will not merge with the scoped one, so the first run after
> upgrading creates a second asset per node. Reconcile them in runZero — no
> `matchBehavior` setting can merge them, because two foreign ids from one
> custom integration are never placed on a single asset.

### Why the default `matchBehavior` is right, and where the data is thin

When the query is written correctly, `NodeID` is a persistent vendor-assigned identifier and the governing rule points at foreign-ID matching, which is what the code does.

The usual companion preset `no-mac-break no-ip-break no-name-break` would be wrong here for a straightforward reason: **this source contributes no MAC address at all.** `network_interface(ips=[addresses], mac=None)` is the only interface built, from the node's single `IpAddress`. So the correlation signals are one address and one FQDN, and both are contemporaneous polling data about a device Orion is actively monitoring — not stale inventory metadata. Relaxing the break flags would remove the guards on the only two signals available while protecting against churn that cannot occur, since a foreign-ID match is never disqualified by a conflicting address or name.

`ip-break` staying on matters more than usual here precisely *because* the identity can silently degrade to an address. If a query without `NodeID` ever keys two nodes on the same address, the break flags are the only thing standing between that and a merge of unrelated devices.

Two mapping details worth knowing:

- **`IpAddress` is wrapped in a list before parsing** — `network_interface(ips=[addresses], ...)` — so a node reporting several addresses in one field yields one address, not several. Orion's `Orion.Nodes.IPAddress` is a single primary address by design; secondary addresses live on `Orion.NodeIPAddresses`, which this integration does not read.
- **`OsVersion` is mapped to `os`, not to `osVersion`.** On Orion that field carries a descriptive string rather than a bare version number, so it reads better as the OS; nothing is mapped to `osVersion` at all.

## Future

The ceiling here is unusually high, because SWIS is a general query interface over Orion's whole schema rather than a fixed set of endpoints. Almost everything below is a SWQL change rather than new API surface.

- ~~A `query` credential parameter.~~ **Done.** The SWQL used to be a script constant that shipped **empty**, so a correctly configured task returned zero assets and every deployment began by editing and re-saving the script. It is now a `textarea` parameter defaulting to a query that selects the columns this integration maps, so one saved script can serve several tasks with different scopes. The CLI caveat still holds — a SWQL query cannot be passed through `--custom-integration-script-kwargs` and needs careful quoting through `--kwargs` — but that was always an argument about the CLI rather than the console credential form.
- **Interfaces as their own data.** `Orion.NPM.Interfaces` carries per-interface names, speeds, types, admin/oper status, **and MAC addresses** — the field this integration currently has none of. A second query joined on `NodeID` would give every node its real hardware addresses, which would do more for merge quality than any other change available. It is the natural companion to the one-row-per-node rule above: a separate pass, grouped locally, rather than a widened single query.
- **Node custom properties as runZero attributes.** `Orion.NodesCustomProperties` is where Orion estates keep owner, location, environment, criticality, and change-window data. It joins on `NodeID` and is usually the richest business context an Orion installation holds. Mapping it into custom attributes would carry that structure into runZero for free.
- **Volumes, hardware health, and installed software.** `Orion.Volumes` gives disks and capacity; `Orion.HardwareHealth.HardwareItem` gives sensor-level hardware status where Orion polls it; the SAM (Server & Application Monitor) entities expose application and component state. All join on `NodeID`, and the last is close to a software inventory for the servers Orion watches.
- **Alerts as findings.** `Orion.AlertActive` and `Orion.AlertHistory` are queryable through the same endpoint and reference the node they fired against. Active alerts are directly expressible as runZero findings on assets this integration already creates, with no correlation guesswork — the join key is already in hand.
- **`Orion.Discovery` results as a coverage source.** Orion runs its own network discovery, and its results describe devices Orion found but is **not** currently monitoring. That is a genuinely additive population: devices that neither runZero nor Orion's polled inventory would otherwise surface. The `DiscoveryProfileId` this integration already imports as a custom attribute is the thread to pull.
- **Outbound: runZero discovery as Orion nodes.** SWIS is not read-only. The Orion SDK exposes `Create`, `Update`, `Delete`, and `Invoke` verbs over the same endpoint (`/SolarWinds/InformationService/v3/Json/Create/Orion.Nodes`, and `Invoke/Orion.Nodes/Unmanage` among others), so runZero could file a discovered-but-unmonitored device into Orion for polling, or write a runZero verdict into a node custom property where an Orion operator would see it. Two constraints, both serious: the account this integration asks for is deliberately read-only, and adding nodes to Orion has licensing consequences, since Orion licenses are counted by monitored element. This is a real capability that should stay behind an explicit, narrow, confirmed workflow.
- **Coverage-gap reporting needs no new query.** Orion monitors what somebody added to it. runZero discovers what is there. In-scope runZero assets carrying no `custom_integration:solarwinds-information-service` source are monitoring gaps — devices nobody is watching — and that is one of the more directly actionable reports this pairing can produce. The reverse is also useful: Orion nodes whose `Status` says down that runZero has recently seen alive are polling or credential failures rather than outages.
- **There is no event feed, and paging has to be done in SWQL.** SWIS has no webhook, no server-side cursor, and no change token; the endpoint answers a query and returns `results`. Bounding a run means `SELECT TOP n` or a `WHERE` clause in the query itself, which is also the only way to page a very large estate — there is no paging parameter on the credential and adding one would mean rewriting the operator's query, which the script deliberately does not do.
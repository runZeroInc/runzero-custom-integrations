# Custom Integration: Trellix ePolicy Orchestrator

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the ePO console port (8443 by default). ePO is an on-premises application, so the Explorer must be inside the network that serves it.

## Trellix ePolicy Orchestrator requirements

- **ePO On-prem.** Trellix's Web API Scripting Reference is titled and scoped for ePolicy Orchestrator On-prem, and the ePO SaaS product guide documents no Web API section at all — its only API chapter covers events, and SaaS exposes no customer-controlled console port. We could not find an explicit vendor sentence saying SaaS lacks `/remote/`, so state it the way the evidence supports it: the `/remote/` interface is documented for On-prem only.
- An ePO user account and password. The remote command interface authenticates with HTTP Basic. There is no API token object in ePO — the credential is an ordinary user account.
- A permission set granting read access to the System Tree. The integration only issues `system.find`, `system.findGroups`, and `epogroup.findSystems`, all of which are read-only. Trellix states that Web API commands follow the same role-based permissions the console enforces, so there is no separate "may call the API" permission to grant.
- **The one non-obvious permission: `system.find` needs a tag right.** Trellix documents that non-administrator users hit authorization errors running `System.Find` unless the permission set's **Systems** category has **Tag use > Apply, exclude, and clear tags** enabled, and notes this became required after ePO On-prem 5.10.x Service Pack 1 Update 6. That forces a write-shaped permission into an otherwise read-only role. If you are unwilling to grant it, use `collection_mode=system-tree`, which does not call `system.find`.
- `epogroup.findSystems` is **not** in Trellix's published key-commands table. It is real and discoverable at run time through `core.help`, but treat it as undocumented rather than contractual.
- ePO consoles ship with a self-signed certificate on port 8443. Enable `disable_validation` in the integration's TLS options if the certificate is not trusted by the Explorer, or install a trusted certificate on the console.

## Steps

### Trellix ePolicy Orchestrator configuration

1. In the ePO console, open **Menu > User Management > Permission Sets** and create a permission set with **System Tree access** and **Systems: view "System Tree" tab** enabled. The built-in **Global Reviewer** set is the closest stock fit — Trellix describes it as view access globally across functionality, products, and the System Tree — and can be used instead of a custom set.
2. If you intend to use the default `search` collection mode, also edit the **Systems** category of that permission set and tick **Tag use > Apply, exclude, and clear tags**. Without it, `system.find` returns an authorization error for any non-administrator. Users must log out and back in for the change to take effect.
3. Open **User Management > Users**, create (or select) the account the integration will use, and assign it the permission set from step 1.
4. Confirm the remote command interface answers for that account by requesting `https://<epo-host>:8443/remote/core.help?:output=json` with the same credentials. A working response begins with the line `OK:`. That same call lists every command the account may run, which is the way to confirm `epogroup.findSystems` is available on your build.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Trellix ePolicy Orchestrator").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **ePolicy Orchestrator URL** (`url`): base URL of the ePO console, for example `https://epo.example.com:8443`.
   - **Username** (`username`): the ePO account from the steps above.
   - **Password** (`password`): the password for that account.
   - **Collection mode** (`collection_mode`): optional; `search` (default) issues one `system.find` call, `system-tree` walks each System Tree group separately.
   - **Search text** (`search_text`): optional; substring filter for `search` mode. Leave blank to import every system.
   - **Import unmanaged systems** (`include_unmanaged`): optional; import System Tree entries that have no ePO agent (default: true).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm an ePO account and see what the System Tree returns before scheduling
anything. Run it from a host inside the network that serves the console.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename trellix-epo/trellix-epo.star \
  --kwargs url=https://epo.example.com:8443 \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs collection_mode=search \
  --kwargs include_unmanaged=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./trellix-epo-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**The two collection modes fail differently, which is the point of having
both.** `search` issues a single `system.find` and returns the whole estate in
one response — fast, and fine up to a few thousand systems. On a large estate
that one response gets very large; switch to `system-tree`, which walks each
group with `epogroup.findSystems` and keeps every response small:

```bash
runzero script --filename trellix-epo/trellix-epo.star \
  --kwargs url=https://epo.example.com:8443 \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs collection_mode=system-tree \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./trellix-epo-tree --overwrite
```

To keep a first run small without changing modes, use `search_text` — it is the
same substring filter `system.find` takes in the console:

```bash
  --kwargs search_text=LAPTOP
```

`search_text` is ignored in `system-tree` mode, so combining the two silently
does nothing rather than erroring.

Since ePO ships a self-signed certificate on 8443, a first run that fails on
TLS rather than on authentication needs the CA or the TLS options, not a
different URL. Add `--kwargs tls_ca_cert=/path/to/epo-ca.pem`.

`--kwargs` hands the value to the script verbatim, commas included, as long as
the pair contains a single `=` — an ePO password with a comma in it goes through
fine. It is a password carrying a *second* `=` as well as a comma that gets
re-read as CSV: cut off at the comma, with the remainder becoming a second,
fabricated parameter rather than rejected. Wrap that one in double quotes so it
stays a single field, `--kwargs '"password=a=b,c"'`, doubling any double quote
inside it.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename trellix-epo/trellix-epo.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove ePO accepts the account,
that the permission set exposes the System Tree, or that any system is parsed.
In particular it never sees ePO's `OK:`-prefixed response envelope, which is
not JSON until that prefix is stripped.

The fixtures under `trellix-epo/tests/fixtures/` exercise the parsing offline,
including the error-envelope, System Tree, and unmanaged-excluded cases:

```bash
python3 tests/run.py trellix-epo
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat trellix-epo/trellix-epo.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://epo.example.com:8443,username=runzero,password=<password>' \
  --output ./trellix-epo-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is the stricter flag: it takes one
comma-separated string, so a password containing a comma cannot be passed this
way at all. Prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Trellix ePolicy Orchestrator.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:trellix-epo`.

## Asset identity

- Target entity: a physical or virtual computer registered in the ePO System Tree.
- Source ID field: `EPOComputerProperties.ParentID`, the System Tree leaf node that owns the computer properties row.
- Documentation evidence: `EPOComputerProperties` is a child table of `EPOLeafNode`, joined as `EPOLeafNode.AutoID = EPOComputerProperties.ParentID`; `AutoID` is the leaf node's SQL Server identity column. Both vendor response samples shipped with the XSOAR `epo` pack agree: in `epo_find_systems_command.txt` every one of the six systems returned for a single group carries a distinct `ParentID` (7, 8, 9, 15, 16, 17) while `EPOBranchNode.AutoID` is 2 for all of them, because that column identifies the *group*, not the system.
- Uniqueness scope: one ePO server, i.e. one ePO database. Leaf node ids restart per installation, so the ePO hostname is part of the runZero id.
- Cardinality: one row per system. `system.find` and `epogroup.findSystems` both return one `EPOComputerProperties` row per System Tree entry; neither returns per-interface, per-event, or per-product child rows.
- Stability: survives rename, DHCP lease change, NIC replacement, agent upgrade, agent reinstall, and a move between System Tree groups, because all of those update columns on an existing leaf node rather than creating one. It is replaced only when the System Tree entry itself is deleted and re-created.
- Reuse behavior: `AutoID` is a monotonic SQL Server identity column, so a deleted node's id is not handed to a later system.
- Presence: present on every row in both vendor samples, including entries with no agent installed.
- Final runZero ID: `trellix-epo:<epo-hostname>:<ParentID>`
- Missing-ID behavior: skip the record with a message naming only `ComputerName`. No id is synthesized.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. ePO reports the addresses its agent last saw rather than addresses observed on the wire, and many System Tree entries carry no MAC or IP at all, so network churn must not disqualify a merge against an authoritative id.
- Verdict: scoped authoritative.

### Why not `AgentGUID`

`EPOLeafNode.AgentGUID` is the obvious candidate and it is *not* used, for two reasons found in the vendor's own sample data:

1. **It is frequently null.** In `epo_find_systems_command.txt`, five of the six systems returned have `"EPOLeafNode.AgentGUID": null`, because a System Tree entry exists from the moment ePO learns about a machine (Active Directory sync, rogue system detection, manual add) and only gains a GUID once an agent checks in. Any GUID-based scheme needs a fallback for the majority of rows in that sample.
2. **A mixed scheme changes ids.** If the GUID were used when present and a fallback otherwise, then installing an agent on a previously unmanaged system would change that system's runZero id and split it into two assets — precisely the failure the identity gate exists to prevent. Reinstalling an agent mints a new GUID for the same machine, which has the same effect. This second point is asserted from ePO's documented duplicate-GUID behavior and could **not** be confirmed against a live appliance.

The leaf node id has neither problem, so `AgentGUID` is imported as the custom attribute `trellix_epo_agent_guid` instead, where it remains available for search and correlation without driving identity.

### Notes

- Assets come from `system.find` (search mode) or `system.findGroups` followed by one `epogroup.findSystems` call per group (system-tree mode). `system.findGroups` is also called in search mode purely to translate each system's group id into a readable `groupPath`; if that call fails the import continues without the group tag and no asset id changes.
- Imported fields: `ComputerName` and `IPHostName` become hostnames; `DomainName` becomes the domain; `IPV4x`, `IPAddress`, `IPV6`, and `NetAddress` become one network interface; `OSType` becomes the OS; `OSVersion`, `OSBuildNum`, and `OSServicePackVer` are composed into the OS version; `OSPlatform` becomes the device type; `EPOLeafNode.Tags` is split into runZero tags alongside `trellix-epo`, `managed:<bool>`, and `group:<path>`; `EPOLeafNode.LastUpdate` becomes `lastSeenTS`. The remaining columns, including `AgentGUID`, `UserProperty1` through `UserProperty4`, CPU, memory, and disk figures, become `trellix_epo_*` custom attributes.
- **There is no pagination.** Both commands return the entire result set in one response and accept no offset, limit, or cursor argument. Search mode therefore necessarily holds one response body in memory — but the rows are streamed off it with `jsonstream` and each asset goes to `report_asset` as it is built, so the decoded estate never exists as one value. System-tree mode additionally breaks the response itself up by group; prefer it on very large estates. `epogroup.findSystems` returns only the direct members of a group, so walking every group returned by `system.findGroups` covers the tree exactly once.
- **Responses are not plain JSON.** Every reply is prefixed with a status line — `OK:\r\n` before the document, or `Error <code>:\r\n` before a plain-text message. The script uses raw `http.get` and strips that prefix before decoding, because `get_json` cannot parse the body. A payload that is not a JSON array (ePO answers `true`, a bare string, or an empty body for some commands) is reported as an error rather than handed to the row iterator, since a malformed document aborts the script and Starlark has no exception handling.
- **`IPV4x` is not a dotted quad.** It is the address biased by 2^31 and stored as a signed 32-bit integer so that it sorts correctly in SQL Server, which is why 10.0.0.0/8 arrives negative and 192.168.0.0/16 arrives positive. The address is recovered by adding 2147483648 back and splitting the result into four octets — the same conversion ePO's own SQL consumers use. Verified in both directions against the vendor sample: `1084752230` decodes to `192.168.1.102` and `-1979711487` decodes to `10.0.0.1`. A column of exactly 0 is treated as unset rather than decoded to `128.0.0.0`, and `-2147483648` (0.0.0.0) is dropped.
- **`NetAddress` is the MAC as unpunctuated hex**, e.g. `000C29B1EE8E`. `network_interface()` normalizes that form directly, so no separators are inserted by hand; colon-punctuated values from other ePO versions are accepted equally.
- **The transport carries its own bounded retry.** Stripping the status prefix requires the raw `http.get` builtin, which rejects a `retries` argument outright (`get: unexpected keyword argument "retries"`), so the backoff machinery `get_json` exposes cannot be used here — instead each command is retried by hand: up to three attempts with a short backoff, repeated only on a missing response or a transient status (408/425/429/5xx). Every remote command here is a read, so repeating one is safe, and without the retry a transient 502 on `system.find` produced a green zero-asset run. A persistent failure is still reported as a failed command. In system-tree mode a failed group is logged and the walk continues, so one bad group does not abandon the rest of the tree.
- Manufacturer, model, and serial number are **not** imported. They are not present in the default `EPOComputerProperties` view — `CPUSerialNum` is a CPU field that both vendor samples return as the literal string `N/A`, not a chassis serial. ePO's other literal placeholders (`N/A`, `(none)`, `<null>`) are treated as empty rather than imported as values.
- Software inventory is **not** imported; see `## Future` for what was established and what is missing.
- **Do not use the `Trellix_ePO` XSOAR pack as a reference.** It contains only XSIAM parsing and modeling rules for syslog and has no API client at all (its directory holds `ModelingRules`, `ParsingRules`, and release notes, and no `Integrations` directory). The working client is the separate `epo` pack, at `Packs/epo/Integrations/epoV2/epoV2.py`.
- This integration was validated against local fixtures built from the vendor client's own recorded responses, not a live Trellix ePO appliance. Two things could not be confirmed without one: that the console accepts the literal `:output=json` parameter written into the query string (the script sends the colon unencoded, matching every documented ePO client, rather than relying on the console to decode `%3Aoutput`), and the agent-reinstall GUID behavior described above.

## Future

- **`core.executeQuery` as a general enrichment surface.** Every ePO table is queryable through `core.executeQuery` with `target`, `select`, `where`, `order`, `group`, and `joinTables` arguments in SQUID s-expression syntax, for example `select=(select EPOEvents.AutoID EPOEvents.DetectedUTC)`. That makes threat events (`EPOProductEvents`), product properties, and compliance state reachable without any new endpoint. This is the most valuable unexploited surface in the API.
- **Software inventory.** There is no dedicated command for installed software; it is reachable only through `core.executeQuery`. What the available evidence establishes is that `EPOProductEvents` declares a foreign key `ProductCode -> EPOSoftwareView.ProductCode` and a join to `EPOLeafNode` on `AgentGUID`, so `EPOSoftwareView` is the product catalog and per-system product state lives in the `EPOProdPropsView_<PRODUCTCODE>` views. What it does **not** establish is the SQUID target name for those views, their column names, or how a per-system product row joins back to a leaf node — `core.listTables` output was available for exactly one table (`EPOProductEvents`), and the `EPOProdPropsView_*` views are named per product, so the set differs per deployment. Rather than ship a guessed query behind a flag that would fail on every real console, software is left out. The correct next step is to run `core.listTables` against a live ePO, capture the `EPOProdPropsView_*` entries and their `relatedTables`/`foreignKeys` blocks, and build the query from that. Note also that ePO's product properties describe managed Trellix products and their DAT/engine versions, not a general installed-software inventory like an OS package list.
- **Tag write-back as an outbound integration.** `system.applyTag` and `system.clearTag` both exist and take `names` and `tagName` arguments — confirmed in the vendor client, which calls them at `Packs/epo/Integrations/epoV2/epoV2.py` in `apply_tag` and `clear_tag`, with `system.findTag` available to enumerate valid tag names first. An outbound integration could push runZero classifications (device type, ownership, criticality, exposure) onto ePO systems as tags, where they become usable as ePO System Tree sorting criteria and policy assignment targets. `system.move` and `system.wakeupAgent` exist as well, so triggering an agent check-in on a newly discovered asset is possible, though both are state-changing and would need care.
- **Endpoint protection coverage-gap reporting.** ePO is the management plane for the EPP agent, which makes the *absence* of an ePO record the interesting signal. Because this integration imports unmanaged System Tree entries as well as managed ones and tags every asset `managed:true` or `managed:false`, a runZero query for assets that have no `custom_integration:trellix-epo` source, or that carry the `managed:false` tag, is a direct list of machines with no working endpoint protection. This is the strongest pairing between the two products and needs no further API work.
- **`core.help` and `core.listTables` as a live API catalog.** ePO describes itself at runtime: `core.help` lists every remote command with its arguments, and `core.listTables` returns each table's columns, types, related tables, and foreign keys. Any future expansion can be built by reading the target console rather than by finding documentation, and a future integration could even validate that the commands it needs exist before it uses them.
- **Alert and event ingestion.** `EPOProductEvents` carries `DetectedUTC`, `ReceivedUTC`, `TVDSeverity`, `HostName`, and `AgentGUID`, and joins to `EPOLeafNode` on `AgentGUID`. Threat detections could be attached to the matching asset. They are events rather than durable findings, so they do not map cleanly onto `Vulnerability`; a time-bounded query feeding custom attributes or tags would fit better.

## API documentation

- Trellix ePO Web API documentation is served by the appliance itself rather than published at a stable public URL: `https://<epo-host>:8443/remote/core.help?:output=json` lists every command, and `core.listTables` describes every queryable table.
- Vendor API client used as the contract for authentication, the `OK:` response envelope, command names, and arguments: `Packs/epo/Integrations/epoV2/epoV2.py` in the [Cortex XSOAR content repository](https://github.com/demisto/content/blob/master/Packs/epo/Integrations/epoV2/epoV2.py).
- Recorded vendor responses used as fixtures for the response schema and identity analysis: `Packs/epo/Integrations/epoV2/test_data/epo_find_system_command.txt`, `epo_find_systems_command.txt`, and `epo_get_system_tree_groups.txt` in the same repository.
- `IPV4x` bias conversion, cross-checked against a third-party consumer of the ePO database: [HASecuritySolutions/Logstash `mcafee.sql`](https://github.com/HASecuritySolutions/Logstash/blob/master/mcafee.sql), which converts the column as `EPOComputerProperties.IPV4x + 2147483648` before splitting it into octets.

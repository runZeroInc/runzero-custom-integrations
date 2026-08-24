# Custom Integration: Microsoft WSUS

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the WSUS server over WinRM (TCP 5985, or 5986 for HTTPS).

## WSUS requirements

- A WSUS server (Windows Server 2012 or later, WSUS 6.x+). The integration runs a
  collection script **on the WSUS server itself** over WinRM, because the WSUS
  administration API has no remote HTTP interface: the `ApiRemoting30` SOAP
  endpoint speaks .NET-remoting payloads that only the Microsoft client
  assemblies can produce, and the default SUSDB lives in the Windows Internal
  Database, which is reachable only through a local named pipe.
- WinRM enabled on the WSUS server (`winrm quickconfig`, or the
  `WinRM Service` GPO). NTLM authentication is used by default; Basic is
  supported for lab setups.
- An account that is a member of the **WSUS Administrators** local group (or
  local Administrators) on the WSUS server, with remote management rights.

## Steps

### WSUS configuration

1. Enable WinRM on the WSUS server if it is not already:

   ```powershell
   winrm quickconfig
   ```

2. Create (or reuse) an account for runZero and add it to the **WSUS
   Administrators** local group on the WSUS server.
3. Confirm the account can run the WSUS API locally:

   ```powershell
   [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')
   [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer().GetStatus()
   ```

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Microsoft WSUS").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **WSUS server host** (`host`): hostname or IP of the WSUS server (the WinRM target).
   - **Username** (`username`): `DOMAIN\user`, `user@domain`, or a local account.
   - **Password** (`password`): password for that account.
   - **WinRM over HTTPS** (`winrm_https`): optional; connect on 5986 with TLS (default: off).
   - **WinRM port** (`winrm_port`): optional; 0 picks 5985/5986 by transport.
   - **WinRM authentication** (`winrm_auth`): `ntlm` (default) or `basic`.
   - **Skip TLS verification** (`winrm_insecure`) / **PEM CA bundle** (`winrm_ca_cert`): TLS options for HTTPS listeners.
   - **WSUS administration port** (`wsus_port`) / **WSUS uses SSL** (`wsus_ssl`): only needed for an SSL-only WSUS (8531).
   - **Include downstream computers** (`include_downstream`): include rollup rows from downstream servers in a WSUS hierarchy (default: on).
   - **Computer name filter** (`name_includes`): optional substring filter on the full domain name.
   - **Import missing updates as vulnerabilities** (`import_missing_updates`): default on.
   - **Security classifications only** (`security_only`): restrict vulnerabilities to Security Updates and Critical Updates (default: on).
   - **Missing updates per computer** (`max_updates_per_computer`): cap, default 99.
   - **Computers per WinRM call** (`page_size`): default 100.
   - **WinRM call timeout** (`timeout`): seconds per remote invocation, default 300, max 600.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer that can reach the WSUS server over WinRM.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with WSUS inventory and missing-update data, and create new assets where nothing matches.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:wsus`.

## Running it from the command line

```bash
runzero script --filename wsus/wsus.star \
  --kwargs host=wsus01.corp.example.com \
  --kwargs 'username=CORP\runzero-svc' \
  --kwargs password=not-a-real-password \
  --kwargs page_size=25 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/wsus-run --overwrite
```

To check only that the `CONFIG` block parses and the script compiles (this
integration uses `validationMode: "compile"` because it speaks WinRM rather
than HTTP):

```bash
runzero script --filename wsus/wsus.star --validate
```

There are no fixture tests for this integration: the fixture harness serves
HTTP, and driving the WinRM protocol (SOAP shell lifecycle plus NTLM) would be
a mock of the transport rather than of WSUS. Validate against a real WSUS
server with a small `page_size` first.

## Asset identity

- Target entity: a WSUS computer target — a Windows client or server registered with this WSUS hierarchy.
- Source ID field: `IComputerTarget.Id` (`ComputerTargetId`), the GUID WSUS derives from the client's SusClientId at registration.
- Uniqueness scope: one WSUS hierarchy. Downstream-server rollup rows carry the same id space as the upstream. The configured server host is prefixed so two hierarchies imported into one runZero organization cannot collide.
- Stability: survives renames, re-addressing, OS upgrades, and group moves. An OS reinstall (or a `SusClientId` reset) mints a new id and forks the asset.
- Known pathology: **cloned machine images that share a SusClientId** collapse to one row inside WSUS itself — WSUS shows one computer flip-flopping between names. This integration imports what WSUS holds; fix the clones with the documented `SusClientId` reset procedure.
- Final runZero ID: `wsus:<server-host>:<ComputerTargetId>` — for example `wsus:wsus01.corp.example.com:5f2ab...`.
- Missing-ID behavior: skip and log. No id is invented.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The id is authoritative; the addressing WSUS holds is self-reported and drifts, so it must not veto a merge. No MAC is ever emitted.
- Verdict: **authoritative** for machines under WSUS management.

### Notes

- What is imported: one asset per computer target with FQDN, self-reported IP
  (`IPAddress.None`/broadcast filtered out), `OSDescription` as the OS,
  `OSInfo.Version` as the OS version, architecture, make/model/BIOS, the
  Windows Update Agent version (also emitted as a `Software` entry), the
  last-sync and last-reported times (`lastReportedStatusTime` becomes
  `lastSeenTS`), and the per-computer update summary counts.
- Missing updates: each update in installation state `NotInstalled` or
  `Failed` (declined updates excluded) becomes a `Vulnerability` carrying the
  title, KB articles, security bulletins, classification, and installation
  state. `MsrcSeverity` maps to severity rank: Critical=4, Important=3,
  Moderate=2, Low=1; non-security updates carry no invented severity. WSUS
  stores KB and bulletin ids, **not CVEs**, so no CVE field is emitted.
- Transport: the collection script is delivered on **stdin** to a short
  `powershell -Command "Invoke-Expression ([Console]::In.ReadToEnd())"`
  launcher, because the WinRM command line is capped at roughly 8K characters
  and `-EncodedCommand` inflates a script ~2.7x.
- Output framing: the remote script prints NDJSON, one line per computer, each
  line terminated with a `\t//rz` marker. WinRM output is capped at 16 MiB per
  stream and truncated silently, so only marker-complete lines are decoded;
  on truncation the walk resumes after the last complete record with a halved
  page size. Computers are collected in `Sort-Object Id` order so offsets are
  stable across calls.
- The per-computer missing-update query is one database round trip per
  computer on the WSUS side. On a large estate, lower `page_size` to keep each
  WinRM call inside the 600-second ceiling, or disable
  `import_missing_updates` for a fast inventory-only run.
- Timestamps rendered as `0001-01-01...` (never reported) are dropped before
  they can poison `firstSeen`/`lastSeen`.

## Future

- **SUSDB SQL path.** For estates where per-computer API calls are too slow,
  the `PUBLIC_VIEWS` schema (`vComputerTarget`, `vUpdate`,
  `vUpdateInstallationInfoBasic`) can produce the same join in one set-based
  query via `runzero.sql` — but only when WSUS runs on full SQL Server, since
  the default Windows Internal Database is local-pipe-only.
- **KB-to-CVE mapping.** WSUS carries KB ids and MSRC severities but no CVEs.
  Joining the MSRC CSAF/CVRF feed would turn each missing KB into its CVE list.
- **Target groups as tags.** `GetComputerTargetGroups()` per computer would
  import WSUS group membership; skipped for now because it is another
  round trip per computer.

## API documentation

- WSUS administration API (`AdminProxy`, `IUpdateServer`): https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa354254(v=vs.85)
- `IComputerTarget` properties: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa354292(v=vs.85)
- `IUpdateSummary` counts: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms752735(v=vs.85)
- `IUpdate` properties (KB articles, MSRC severity): https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms752741(v=vs.85)
- `UpdateInstallationStates` enumeration: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa354552(v=vs.85)
- SUSDB public views (for the SQL future path): https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb410149(v=vs.85)
- WSUS ports and deployment: https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/plan/plan-your-wsus-deployment

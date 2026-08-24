# Custom Integration: Windows WMI

Imports Windows asset information into runZero by querying `Win32_OperatingSystem`,
`Win32_ComputerSystem`, `Win32_SystemEnclosure`, `Win32_NetworkAdapterConfiguration`,
`Win32_Service`, and `Win32_Product` from a **single** Windows host.

This is not an HTTP API integration. There is no token, no base URL, and no tenant: the
Explorer opens a WinRM or DCE/RPC session to one host and runs six WQL queries. The credential
is a Windows account.

The integration is **one host per run**. To cover many hosts, create one credential and one
task per target, or extend the script to loop.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the target on the transport's port — 5986 or 5985 for WinRM, TCP 135 (plus the dynamic RPC range) for `wmi-tcp`, or TCP 445 for `wmi-smb`.

## Windows requirements

- A Windows account permitted to query WMI on the target. It does **not** need to be a Domain Admin: `Remote Enable` and `Enable Account` on the `root/cimv2` namespace, plus membership of the local **Distributed COM Users** group (and, for WinRM, **Remote Management Users**), is the least-privilege shape.
- The relevant service running and reachable:
  - **WinRM** — `winrm quickconfig` sets up the listener. Default ports are **5985** for HTTP and **5986** for HTTPS.
  - **DCE/RPC WMI** — the RPC endpoint mapper on TCP 135 and the dynamic port range behind it, or named pipes over TCP 445 with `transport=wmi-smb`.

### Choosing a transport

| `transport` | Protocol | Default port | When to use it |
|---|---|---|---|
| `winrm-https` (default) | SOAP over HTTPS | 5986 | The right default. Encrypted, firewall-friendly, one port. |
| `winrm-http` | SOAP over HTTP | 5985 | Only on a trusted network. With `winrm_auth=ntlm` the payload is still NTLM-sealed; with `basic` the credential is effectively in the clear. |
| `wmi-tcp` | DCOM / MS-WMI over `ncacn_ip_tcp` | 135 + dynamic | Hosts with no WinRM listener. Needs the dynamic RPC range open, which firewalls rarely allow. |
| `wmi-smb` | DCOM / MS-WMI over `ncacn_np` | 445 | Same as above but tunnelled through SMB, so only one port is needed. |

**`winrm_auth=basic` is only safe over HTTPS with a trusted CA.** NTLM is the default and is
the right choice in almost every case.

**`winrm_insecure` skips TLS verification** and is labelled *NOT for production* in the
credential form for a reason — it disables the check that the certificate belongs to the host
you think you are talking to, on a connection carrying an administrative credential. Supply
`winrm_ca_cert` instead.

## Steps

### Windows configuration

1. Create or choose the account. A dedicated service account is better than reusing an operator's credentials, and it should not be a Domain Admin.
2. Grant it WMI access: in **wmimgmt.msc**, open the security properties of `Root\CIMV2` and grant **Enable Account** and **Remote Enable**. Add the account to **Distributed COM Users**, and to **Remote Management Users** if you are using WinRM.
3. Enable and confirm the transport:

   ```powershell
   winrm quickconfig
   winrm enumerate winrm/config/listener
   ```

4. Confirm the account can query WMI from the Explorer's position before configuring anything in runZero.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Windows WMI").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.

     | key | type | required | description |
     | --- | --- | --- | --- |
     | `host` | string | **yes** | Hostname or IP of the Windows target |
     | `username` | string | **yes** | `DOMAIN\user`, `user@domain`, or a local account name |
     | `password` | secret | **yes** | Account password |
     | `transport` | enum | no | `winrm-https` (default), `winrm-http`, `wmi-tcp`, `wmi-smb` |
     | `winrm_port` | int | no | Overrides the 5985/5986 default. `0`, the default, means "use the protocol default". WinRM transports only. |
     | `winrm_insecure` | bool | no | Skip TLS verification. Default `False`. **Not for production.** |
     | `winrm_ca_cert` | textarea | no | PEM-encoded CA chain for the target |
     | `winrm_auth` | enum | no | `ntlm` (default) or `basic` |
     | `wmi_namespace` | string | no | Defaults to `//./root/cimv2` |
     | `timeout` | int | no | Per-operation timeout in seconds; default `60`, range 1–600 |

   - `wmi_namespace` is written in the DCE/RPC spelling (`//./root/cimv2`). On a WinRM transport the script converts it to the `root/cimv2` form Get-CimInstance expects — the `//./` (or `//<host>/`) prefix and any leading slash are removed — so one value works for all four transports; do not enter two different spellings.
   - `winrm_port`, `winrm_insecure`, `winrm_ca_cert`, and `winrm_auth` are read **only** when `transport` starts with `winrm-`. On `wmi-tcp` or `wmi-smb` they are ignored, silently.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer that can reach the host.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to find out
whether the transport and the account work before scheduling anything. `--kwargs` is repeated
once per parameter:

```bash
runzero script --filename windows-wmi/windows-wmi.star \
  --kwargs host=win-srv-01.example.com \
  --kwargs 'username=ACME\svc-runzero' \
  --kwargs password='ExampleFakePassw0rd!' \
  --kwargs transport=winrm-https \
  --kwargs winrm_auth=ntlm \
  --kwargs timeout=60 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./windows-wmi-run
```

Quote the username: an unquoted `ACME\svc-runzero` loses its backslash to the shell, and the
account then authenticates — or fails to — as a bare `svc-runzero` with no domain. `user@domain`
avoids the problem entirely.

`--output` writes the asset the run produced. The scanner refuses to write into a directory
that already exists, so add `--overwrite` when re-running into the same path. Add `--verbose`
for a fuller log, or omit `--output` to see only the log lines.

Read `wmi.serviceCount` and the software list in the output before trusting a run. A host that
authenticates but returns no rows for `Win32_Product` is usually a WMI permission problem on
that class rather than a connection problem — and note that **querying `Win32_Product` triggers
a Windows Installer consistency check on every installed MSI**, which is slow and writes an
event log entry per product. That is a property of the class, not of this script, and it is the
usual reason a run takes minutes rather than seconds.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
password containing a comma is passed through intact — `--kwargs 'password=a,b'` arrives as
`a,b`. Only a password that *also* contains a second `=` flips the flag into comma-separated
parsing, and then the value is cut at the first comma and the remainder either becomes a
fabricated parameter or aborts the run with `must be formatted as key=value`. Both characters
are legal in a Windows password, so wrap the whole argument in a second pair of quotes when
one needs them:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

`winrm_ca_cert` is a `textarea` holding a PEM chain, which is multi-line. It cannot be passed
through `--kwargs` at all; configure it on the console credential, or use `winrm_insecure` for
a throwaway command-line test only.

To check the script compiles and its `CONFIG` block is well-formed:

```bash
runzero script --filename windows-wmi/windows-wmi.star --validate
```

This integration declares `"validationMode": "compile"`, so validation stops at compilation and
the `CONFIG` block. There is no HTTP wiring for the validator's dummy server to exercise — the
module speaks WinRM or DCE/RPC — so `--validate` proves nothing at all about whether the host is
reachable, whether authentication succeeds, or whether any WMI class returns a row. Only a real
run against a real host tells you that. There are no fixture scenarios for this integration.

The same script also runs under the `scan` command, which is what the platform itself invokes
for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat windows-wmi/windows-wmi.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'host=win-srv-01.example.com,username=svc-runzero@example.com,password=ExampleFakePassw0rd!,transport=winrm-https' \
  --output ./windows-wmi-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is a different flag with a stricter rule: it takes **one**
comma-separated `key=value` string, so no value passed through it may contain a comma at all.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- One asset is reported per target host, carrying its OS, device type, network interfaces, and installed software.
- The task will update an existing asset when one meets merge criteria (hostname, MAC, etc), and create one otherwise.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:windows-wmi`.

## Asset identity

- Target entity: the **one Windows host this credential points at**. There is no discovery step and no enumeration — `host` is a required parameter, the script opens one session, and exactly one asset is reported.
- Source ID field: `Win32_OperatingSystem.CSName`, falling back to `Win32_ComputerSystem.Name`, falling back to the **configured `host` string**.
- Documentation evidence: `CSName` and `Name` are both the computer's **NetBIOS name** — the value `hostname` returns on Windows, capped at 15 characters, upper-cased by convention. Microsoft documents both as the name of the computer system. They are a *name*, not an identifier, and Windows exposes a genuine identifier a few classes away: `Win32_ComputerSystemProduct.UUID` is the SMBIOS system UUID, which is stable across rename and reinstall. It is not queried.
- Uniqueness scope: **none whatsoever**, and this is the notable weakness. The id is a bare NetBIOS name with no domain, no prefix, and nothing derived from the target. `Win32_ComputerSystem.Domain` **is** collected — it becomes the `wmi.domain` custom attribute — so the material to qualify the name into `DOMAIN\NAME` is in hand and is not used.

  The collision this invites is not hypothetical. NetBIOS names are unique within a domain and nowhere else, and the Windows estate is full of names that repeat across domains and workgroups by default: `WIN-XXXXXXXX` from an unconfigured install, `DESKTOP-XXXXXXX` from a consumer image, and every deliberate naming convention that restarts per site. Two such hosts in different domains produce **one runZero asset**, silently merged.
- Cardinality: one asset per run, always.
- Stability: **not stable in either direction.**
  - Renaming a Windows host changes `CSName`, which mints a new runZero asset and strands the old one. Rename is a routine operation.
  - The **fallback is the real hazard**. If `Win32_OperatingSystem` and `Win32_ComputerSystem` both return no rows — a WMI permission problem on those classes, a partial failure, a namespace typo — the id silently becomes the configured `host` string instead. So a host imported as `WINSRV01` on one run can be imported as `10.0.0.5` or `win-srv-01.example.com` on the next, creating a duplicate. Nothing in the task log distinguishes the two cases, because both produce a successful run with one asset.
- Reuse behavior: fully reusable. A rebuilt machine given the same computer name inherits the previous one's runZero asset, history included.
- Presence: `CSName` is present whenever `Win32_OperatingSystem` returns a row, which is the normal case. The two fallbacks exist because it is not guaranteed.
- Final runZero ID: the bare computer name, e.g. `WINSRV01` — or the configured host string when both classes came back empty.
- Missing-ID behavior: not reachable. `host` is required, so the chain always terminates in a value.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: **not authoritative.** The identifier is a non-unique, mutable name with a silent fallback to a configuration string.

### Where the code and the identity rule disagree

The governing rule says a persistent remote id matches on the foreign id, and data with no
stable id sets `no-id-match no-id-break` and correlates on hostname, MAC, and IP. A bare
NetBIOS name is not a persistent remote id — it is precisely the kind of value the second
branch of the rule is written about — so by the rule this source should either key on something
durable or not key on an id at all. The code keeps `id-match` on.

The practical damage is limited by a coincidence: **the id and the hostname are the same
string**, because `cs_name` is appended to `hostnames` as well as used as `id`. So foreign-ID
matching behaves much like hostname matching, which is what the rule would have asked for
anyway. That is why this is recorded as a documented mismatch rather than a defect — but it
also means the foreign id is buying nothing that hostname matching was not already providing,
while adding the cross-domain collision described above.

The honest fix is not to flip a flag but to build a real id, and the material is one WQL query
away: `SELECT UUID FROM Win32_ComputerSystemProduct` returns the SMBIOS system UUID, which
survives rename and reinstall and is genuinely unique. Failing that, qualifying the name with
`Win32_ComputerSystem.Domain` — already collected — would at least make the namespace explicit.

### Why the break flags are right regardless

Whatever happens to the id, the default flags are correct here, and the argument is strong.
This integration collects **first-party hardware data read directly off the host**:
`Win32_NetworkAdapterConfiguration` gives MAC addresses and IPv4/IPv6 addresses per adapter,
filtered server-side to `IPEnabled=true`. That is the best correlation evidence a source can
offer, and it is exactly what should be allowed to merge this record onto the asset runZero
already scanned.

Keeping `mac-break` on matters more than usual *because* of the collision above: when two hosts
sharing a NetBIOS name are about to be merged, a disagreeing MAC is the only thing that can
stop it. Reaching for the `no-mac-break no-ip-break no-name-break` preset here would remove the
last guard on a known, likely failure.

One caveat on the adapter list: it is **not filtered by adapter type**, only by `IPEnabled`. So
virtual, VPN, hypervisor, and container adapters are imported alongside real hardware, and
their addresses are frequently identical across hosts — a hypervisor's virtual switch address
is shared with every guest. That is a second, independent reason to keep `mac-break` on, and a
good argument for adding a name-based virtual-adapter filter of the kind `uptycs` uses.

### Notes

- **Six WQL queries per run**, all against the same session, then the session is closed. There is no paging and no per-object follow-up.
- **On WinRM transports each query is independently tolerant.** Every query is issued through `run_powershell` inside a PowerShell `try/catch`, so a class that fails — the classic case is `Win32_Product` blowing the 60-second timeout on a package-heavy host — prints one line, contributes an empty collection, and the asset is still reported with whatever the other five queries returned. On the `wmi-tcp`/`wmi-smb` transports there is no PowerShell layer to catch a failure in: `query()` raises straight through and Starlark has no exception handling, so a single failed class still aborts that transport. Prefer a WinRM transport where degradation matters; on DCE/RPC, `Win32_Product` is at least capped server-side to fetch no more rows than the child limit allows.
- **`Win32_Product` is expensive.** Querying it makes Windows Installer validate every installed MSI package and log an event per product. It is the standard way to enumerate MSI-installed software over WMI and it is also the slowest thing this integration does. It also **only sees MSI-installed software** — anything installed by another mechanism does not appear. The software list is capped at 99 entries — the platform's per-asset child limit — with the overflow counted in the log.
- **Services are counted, not imported.** `Win32_Service` is queried for `Name`, `DisplayName`, `State`, `StartMode`, and `PathName`, and the only thing that reaches the asset is `wmi.serviceCount`. Every other field is discarded. No runZero `Service` objects are emitted — which is correct, since a Windows service is not a listening socket, but it does mean five of the six selected columns are collected and thrown away.
- **Device type comes from SMBIOS, with a deliberate refusal to guess.** `Win32_SystemEnclosure.ChassisTypes` is mapped first; only values that name a form factor become `Desktop`, `Laptop`, `Tablet`, or `Server`. Anything else — including `Other` and `Unknown`, which is what most hypervisor guests report — falls through to `Win32_ComputerSystem.PCSystemType`, which is coarser (it cannot see a tablet and folds every portable into `Mobile`). If neither names a form factor the device type is left **unset** so runZero's own fingerprinting decides, and the raw value is kept as `wmi.chassisType` so you can see why.
- **Numeric CIM values are normalized before lookup.** `ChassisTypes` and `PCSystemType` are `uint16` in CIM, but they arrive through PowerShell's `ConvertTo-Json` and then a Go-to-Starlark conversion, so the same value can present as an int, a float, or a string depending on transport. `_smbios_key()` strips a trailing `.0` so a host whose type decoded as `9.0` is not silently missed.
- **Empty custom attributes are dropped** before the asset is built, so a host that reports no model or no domain simply has no such attribute rather than an empty one.
- **The credential is privileged discovery configuration.** This module executes on the selected Explorer and can reach internal addresses, and it authenticates with an account that can read WMI. Scope both the Explorer and the account to the intended host.

## Future

- **`Win32_ComputerSystemProduct.UUID` as the asset id.** One additional WQL query, and it replaces the weakest identity in this integration with a genuinely stable one. This is the highest-value change available and it is small.
- **Real services from listening sockets.** `Win32_Service` is already queried and discarded down to a count. The more useful data is `MSFT_NetTCPConnection` (or `netstat`-equivalent WMI classes) joined to the owning process, which would give runZero actual `Service` objects with ports — from the host's own view, including services bound to interfaces a scan cannot reach.
- **Software beyond MSI.** `Win32_Product` misses everything not installed by Windows Installer, which on a modern desktop is most of it. The registry uninstall keys (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and the WOW6432Node mirror) are the complete list, and are reachable through `StdRegProv` over the same WMI session — and without triggering the installer consistency check that makes `Win32_Product` slow.
- **Patch level as findings.** `Win32_QuickFixEngineering` returns installed hotfixes with their KB ids. Combined with a build number — already collected as `Win32_OperatingSystem.BuildNumber` — that is enough to say whether a host is missing a specific patch, which is a finding rather than an attribute.
- **Local accounts and groups.** `Win32_UserAccount` and `Win32_Group` expose local accounts, including whether they are disabled and whether the password expires. Local administrator sprawl is a classic finding that nothing on the network can see.
- **Disk encryption and secure boot.** `Win32_EncryptableVolume` in `root/cimv2/Security/MicrosoftVolumeEncryption` reports BitLocker protection status per volume. Note this needs a **different namespace** — which is exactly what the `wmi_namespace` parameter is for, though a single run currently uses one namespace for all six queries, so collecting it would mean a second session or a per-query namespace.
- **A target list instead of one host.** `host` is a single required string, so an estate of a hundred Windows servers needs a hundred credentials and a hundred tasks. A list-typed parameter, or targets resolved from a runZero query, would make this schedulable across a fleet — and it is the change that would most change what this integration is for. Note the interaction with identity: whatever id scheme is used must be per-host, which is another argument for the SMBIOS UUID above.
- **Outbound push-back is possible and should be approached with great care.** WMI is not read-only: `Win32_Process.Create` and the service-control methods can start processes and change service state on the target. That is remote code execution, and a discovery integration should not hold a credential that can do it. If runZero data ever needs to reach a Windows host, the right channel is a management platform the customer already operates — an RMM, Intune, SCCM — not this credential.
- **There is no event feed.** WMI does support event subscriptions (`__InstanceCreationEvent` and friends), but a runZero custom integration is a scheduled task with a bounded run, not a long-lived subscriber, so this is not a shape the platform can host. This integration is a poll by design.
- **Coverage-gap reporting runs the other way here.** Because this integration targets one host at a time, it cannot tell you which Windows machines you missed. The useful pairing is a runZero-side query: assets runZero fingerprints as Windows that carry no `custom_integration:windows-wmi` source are hosts nobody has collected inventory from.

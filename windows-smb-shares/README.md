# Windows SMB shares

Inbound integration that authenticates to a Windows host over SMB2/3
using NTLMv2, lists all advertised shares, and counts the entries in
each share that the supplied account can access.

This is not an HTTP API integration. There is no token, no base URL and no
tenant: the Explorer opens an SMB session to one host on TCP 445 and speaks
SMB2/3 to it. The credential is a Windows account — local or domain. Each
credential targets exactly **one** host; there is no discovery step and no host
list, so an estate of many servers means one credential and one task per server.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the target host on TCP 445. This integration does
  not fall back to the legacy NetBIOS session service on TCP 139.

## Windows requirements

- A Windows host with the **Server** service running and file sharing enabled.
  A host with no shares advertised returns an empty list, which imports an
  asset with `smb.share_count` of `0` rather than failing.
- An account that can establish an SMB session to that host. Anonymous and null
  sessions are not usable here — the script always authenticates.

### What the account actually needs

Two distinct things happen, with different privilege requirements:

**Enumerating the share list.** Microsoft documents the requirement per
information level of the `NetShareEnum` call behind it: for non-interactive
users, *"No special group membership is required for level 0 or level 1
calls"* — those are the levels that return share names and comments. Levels 2,
502 and 503, which additionally return security descriptors and connection
counts, require Administrator, Power User, Print Operator or Server Operator
membership (on Windows Server 2022, Administrator, Access Control Assistance
Operators or Server Operator). This integration reports share **names**, so an
ordinary authenticated domain user is normally enough to produce the share list.

**Listing the root of each share.** That is ordinary file access: the account
needs both share-level and NTFS read permission on the share root. Shares it
cannot open contribute a `share.<name>` attribute but no entry list.

**`ADMIN$` is the exception, and it is deliberate.** Shares whose name ends in
`$` are skipped — except `ADMIN$`, which this integration does try to open.
`ADMIN$` maps to the Windows directory and is restricted to local
Administrators, so a least-privilege account cannot read it. Decide which you
want before you configure the credential:

- A **plain domain user** enumerates the share list and reads the shares it has
  been granted, and contributes nothing from `ADMIN$`. This is the
  least-privilege posture and the one to prefer.
- A **local Administrator** additionally reads `ADMIN$`. That is a very large
  grant to hand an integration for a directory listing of `C:\Windows`, and it
  is rarely worth it.

If the host has `RestrictNullSessAccess` or the `RestrictAnonymous` family of
settings hardened, that affects anonymous access only and does not change any of
the above — this integration never attempts an anonymous session.

## Authentication

Provide **either** a password **or** an NTLM hash (hex-encoded). NTLM
hashes let operators run the integration without exposing the
plaintext password. Supplying neither stops the run with
`either password or nt_hash is required` before any connection is attempted.

If the username includes a backslash (e.g. `ACME\svc-runzero`) the
domain is parsed automatically; otherwise pass `domain` explicitly. For a
**local** account on the target, either leave `domain` blank or set it to the
host's own computer name — do not set it to your Active Directory domain, which
sends the authentication to a domain controller that has never heard of the
account.

Because authentication is NTLMv2, a host or domain policy that has disabled NTLM
outright (`Network security: Restrict NTLM`) rejects the session no matter how
the credential is configured. This integration does not speak Kerberos.

## Steps

### Windows configuration

1. Create or choose the account. A dedicated service account is better than
   reusing an operator's credentials, and it should not be a Domain Admin.
2. Grant it read access to the shares you want inventoried, at both the share
   permission and the NTFS permission layer. Share-level `Read` with no NTFS
   read still produces an empty listing.
3. Confirm TCP 445 is reachable from the Explorer, allowing for the Windows
   Firewall's **File and Printer Sharing (SMB-In)** rule and its scope.
4. Decide whether you want `ADMIN$` covered, per the section above.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Windows SMB shares").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Target host** (`host`): the one host this credential targets.
   - **SMB port** (`port`): optional; default `445`.
   - **Username** (`username`): may include `DOMAIN\user`.
   - **Password** (`password`): optional if `nt_hash` is set.
   - **NTLM hash (hex)** (`nt_hash`): optional alternative to the password.
   - **Domain (optional)** (`domain`): only needed when the username has no `DOMAIN\` prefix.
   - **Connection timeout (seconds)** (`timeout`): optional; default `30`.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer that can reach the host on TCP 445.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename windows-smb-shares/windows-smb-shares.star \
  --kwargs host=fileserver01.example.com \
  --kwargs port=445 \
  --kwargs 'username=ACME\svc-runzero' \
  --kwargs password='ExampleFakePassw0rd!' \
  --kwargs timeout=30 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./windows-smb-shares-run
```

Quote the username: an unquoted `ACME\svc-runzero` loses its backslash to the shell,
and the account then authenticates — or fails to — as a bare `svc-runzero` with no
domain. To authenticate with a hash instead of a password, swap the password line for
`--kwargs nt_hash=31d6cfe0d16ae931b73c59d7e0c089c0`.

`--output` writes the asset the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for a fuller log, or omit `--output` to see only the log lines. Compare
`smb.share_count` against `smb.accessible_share_count` in the output: a large gap means
the account authenticated fine but has read permission almost nowhere, which is a
permissions problem rather than a credential problem.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a password containing a comma is passed through intact. Only a password that *also*
contains an `=` flips the flag into comma-separated parsing, and then the value is cut at
the first comma — the remainder either becomes a fabricated second parameter or aborts
the run with `must be formatted as key=value`. Both characters are legal in a Windows
password, so wrap the whole argument in a second pair of quotes when one needs them:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

To check the script compiles and its `CONFIG` block is well-formed:

```bash
runzero script --filename windows-smb-shares/windows-smb-shares.star --validate
```

This integration declares `"validationMode": "compile"`, so validation stops at
compilation and the CONFIG block. There is no HTTP wiring for the validator's dummy
server to exercise — the module speaks SMB — so `--validate` proves nothing at all
about whether the host is reachable, whether NTLM authentication succeeds, or whether
any share is listed. Only a real run against a real host tells you that. There are no
fixture scenarios for this integration.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat windows-smb-shares/windows-smb-shares.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'host=fileserver01.example.com,username=svc-runzero,domain=ACME,password=ExampleFakePassw0rd!' \
  --output ./windows-smb-shares-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so a password containing a comma cannot be passed
this way; prefer `script --kwargs` for ad-hoc runs. Splitting the username into separate
`username` and `domain` values, as above, avoids fighting the backslash entirely.

## Output

A single asset is reported per target host, identified as `smb://<host>:<port>`,
with custom attributes:

- `smb.target` — `host:port`
- `smb.share_count` — total advertised share count
- `smb.accessible_share_count` — shares whose root we listed
  successfully
- `share.<name>` — `listed` flag per advertised share
- `share.<name>.entries` — first 20 top-level entries (when readable)

Admin shares ending in `$` (other than `ADMIN$`) are not enumerated by
default to avoid scanning user home directories.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The asset merges with anything runZero already knows at that hostname; it carries no MAC or IP of its own.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:windows-smb-shares`.

## Asset identity

- Target entity: the **one Windows host this credential points at**. There is no discovery step and no enumeration — `host` is a required parameter, the script opens one SMB session to it, and exactly one asset is reported. One credential and one task per host.
- Source ID field: **none.** The id is `smb://<host>:<port>`, synthesized entirely from configuration. Nothing read over the wire contributes to it.
- Documentation evidence: not applicable. SMB does expose host identity — the NetBIOS computer name and the domain arrive in the session setup, and `Win32_ComputerSystemProduct.UUID` is available to a WMI caller — but `runzero.smb` surfaces none of it to the script, and the mapping does not attempt to read it. The identity here is a URI naming a socket, not a statement about a machine.
- Uniqueness scope: the `host:port` string as configured. Two credentials naming the same machine differently — one by IP, one by FQDN, one by short name — produce **three different foreign ids and three assets**, all describing one server. That is the failure mode to design around, and the only defense is a convention: pick one addressing form and use it for every credential.
- Cardinality: one asset per run, always.
- Stability: perfectly stable while the credential is unchanged, and **re-identifying the moment it changes**. Re-pointing a credential from `10.0.0.5` to `fileserver01.example.com` mints a new asset and strands the old one, even though the target machine never moved. This is the same property `pfsense` has in its fallback case, and it is the whole story here rather than a fallback.

  There is a subtler version of the same problem: `port` is part of the id. Changing the credential from the default `445` to an explicit `445` is harmless, but any real port change re-identifies the asset.
- Reuse behavior: fully reusable, and this is the case worth naming. Point the credential at a **different machine on the same address** — a rebuilt file server, a DHCP address that moved, a DNS name re-pointed — and the new machine inherits the old one's runZero asset, its history, and its share attributes. Nothing detects it.
- Presence: always present; `host` is required and validated before the session opens.
- Final runZero ID: `smb://<host>:<port>`, for example `smb://fileserver01.example.com:445`.
- Missing-ID behavior: not reachable.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: **configuration-derived, not authoritative.** This identity names what you pointed at, not what answered.

### How this squares with the identity rule, and why the default is nevertheless right

The governing rule has no branch that fits cleanly. There is no persistent remote id to match on, so the rule's first branch does not apply. But this is also not ephemeral scan-derived data with churning identifiers — the id is perfectly deterministic run to run, which is the property `no-id-match no-id-break` exists to work around. Setting that preset here would be actively worse: it would discard the one thing that reliably links this run to the previous one, and leave correlation to a single hostname string.

So the default is the right setting, and the reason is what the asset actually carries:

- **`hostnames=[host]`** — the configured target string, asserted as a hostname. When `host` is an FQDN or a short name this is a real hostname and it is the primary merge path onto the asset runZero already scanned. When `host` is an IP address, a literal address is being asserted as a name, which is not useful and is not harmful.
- **No network interfaces, no MAC, and no IP.** `runzero.smb` gives the script no addressing information, and the mapping does not resolve the host. So an IP-addressed credential contributes nothing on the IP match path at all — the address is in the id and in the hostname field, and nowhere runZero would match on it.
- **`os="Windows"`** is hardcoded, which is safe: the target answered on SMB with NTLM.

The practical consequence: **use an FQDN or a hostname, not an IP, in the `host` parameter.** It is the difference between this asset merging onto the file server runZero already knows about and sitting beside it as a duplicate. That advice matters more here than the `matchBehavior` discussion does.

### Notes

- **Every advertised share becomes an attribute; only some are listed.** `share.<name>` is written for every share `list_shares()` returns. Shares ending in `$` other than `ADMIN$` are then skipped before the mount, so `share.C$` exists as a `listed` flag with no `share.C$.entries` beside it. That is deliberate — home-directory shares are `$`-suffixed and enumerating them would walk user data.
- **`smb.share_count` versus `smb.accessible_share_count` is the diagnostic that matters.** The first is what the server advertised; the second is how many the account could actually open. A large gap is an NTFS-permission problem, not an authentication problem, and nothing else in the output distinguishes the two.
- **Only the first 20 top-level entries per share are recorded**, joined into one attribute value. This is a fingerprint of what a share holds, not an inventory of it.
- **A refused share depends on the runtime, and today it still loses the run.** The script checks `mount()` and `list()` for `None` and records a refused share as `share.<name> = "denied"` before carrying on. That check only does anything on a runtime where those calls *return* something on a refusal. Starlark has no exception handling, so on every currently released Explorer a refused tree connect is a Go error and it aborts the whole script: the scanner logs `failed to call main function: mount: permission denied` and exports **zero** assets — not the share, the run, including every share that *was* readable. Reproduced against real Samba (`tests/docker/`) both ways: a scanner built before the runtime change emits 0 assets on that stack, one built after reports `finance` as `denied` and reports the host. Nothing in the script can close this gap on its own — you cannot learn that a share will be refused without attempting the mount, and the attempt is what aborts — so until the change ships, **a single unreadable non-`$` share on a host means that host does not import at all**. If a host imports on some runs and not others, this is the first thing to suspect, and the workaround is an account entitled to every advertised share, or a target that has none it is refused.
- **The credential is privileged discovery configuration.** This module executes on the selected Explorer and can reach internal addresses, and it authenticates with a domain account. Scope both the Explorer and the account to the intended host.

## Future

- **Read host identity from the SMB session.** The single most valuable change, and it fixes the identity weakness above rather than working around it. An SMB session setup response carries the server's NetBIOS name and its domain, and the negotiate exchange carries the dialect and signing state. If `runzero.smb` exposed the session's server name, the id could become `smb:<domain>\<computername>` — a real machine identity that survives re-addressing — with the configured `host` kept as an attribute. This needs a helper-module change, not a script change, which is why it is a future item rather than a fix.
- **SMB signing, encryption, and dialect as findings.** The negotiated dialect and whether signing is required are exactly the sort of thing a security team wants inventoried across a file-server estate — SMBv1 still enabled, signing not required — and the session already knows all of it. This would turn the integration from a share inventory into a posture check with almost no additional protocol work.
- **Share ACLs rather than a reachability flag.** Today a share is `listed` or it is not, which conflates "no share permission" with "no NTFS permission" with "the account is fine and the share is empty". Reading the share's security descriptor would say *who* can reach it, and the classic finding — a share readable by `Everyone` or by `Authenticated Users` — is not derivable from anything currently collected.
- **Deeper or targeted enumeration behind a parameter.** Only the first 20 top-level entries of each share are recorded. A depth parameter, or a pattern to look for, would let this answer questions like "which shares contain a `web.config`" or "which contain files matching a backup naming convention". This wants to stay off by default: walking a file server is expensive and is the kind of thing that shows up in someone's DLP alerts.
- **A target list instead of one host.** `host` is a single required string, so an estate of fifty file servers needs fifty credentials and fifty tasks. A list-typed parameter, or a runZero query resolved to targets, would make this schedulable across a fleet. Note the interaction with identity: whatever id scheme is used has to stay per-host, so the `smb://` URI would become per-target rather than per-credential.
- **Named-pipe and RPC enumeration over the same session.** SMB is the transport for a great deal more than file shares — `srvsvc`, `wkssvc`, `svcctl`, and the rest are reachable over named pipes on the same connection, and they expose sessions, logged-on users, local groups, and services. `runzero.smb` does not currently surface named pipes to a script; if it did, one authenticated SMB session could produce most of what the `windows-wmi` integration collects, without WinRM.
- **There is no push, no event feed, and no outbound direction.** SMB is a client-initiated file protocol. There is no notification mechanism a runZero integration could subscribe to, and writing to a share is not something a discovery integration should do. This integration is a scheduled poll by the protocol's nature, not by choice.
- **Coverage-gap reporting is possible but inverted here.** Because this integration is pointed at one host at a time, it cannot tell you which file servers you missed. The useful pairing runs the other way: runZero's own scanning finds hosts answering on TCP 445, and any of those with no `custom_integration:windows-smb-shares` source is a file server nobody has inventoried the shares of. That is a runZero-side query and it needs nothing new here.
- Search for everything this integration touched with `custom_integration:windows-smb-shares`.

## Proxmox VE Custom Integration for runZero

This custom integration discovers Proxmox VE cluster nodes, QEMU VMs and LXC containers, and imports them into runZero as assets—complete with hostnames, management IPs, in-guest IPs, MAC addresses, device metadata, and custom attributes. A global `DEBUG` flag controls verbose logging.

---

## Features

* **Cluster Nodes**

  * Discovers all nodes via `/nodes`
  * Captures management IP, CPU/memory/disk stats, uptime, status

* **QEMU VM Discovery**

  * Enumerates VMs via `/nodes/{node}/qemu`
  * Fetches live in-guest interfaces (MAC + IP) via the QEMU Guest Agent
  * Falls back to parsing VM config for MACs and to `/status/current` for IPs

* **LXC Container Discovery**

  * Enumerates containers via `/nodes/{node}/lxc`
  * Parses container config for MACs and `/status/current` for IPs

* **Insecure TLS**

  * The credential's `tls_disable_validation` option allows connections to endpoints without valid TLS certificates. The `INSECURE_ALLOWED` global in the script is only the fallback used when that option is not set on the credential.

* **Debug Logging**

  * Global `DEBUG = True|False` toggles all `print("DEBUG: …")` statements

---

## Prerequisites

### 1. Proxmox VE API Token

Create a dedicated user first rather than using `root@pam`. In the Proxmox web
UI:

1. **Datacenter → Permissions → Users → Add**. Create e.g. `runzero@pve` in the
   `pve` realm. A `pve`-realm user needs no operating-system account on the
   nodes.
2. **Datacenter → Permissions → API Tokens → Add**. Pick the user and give the
   token an ID such as `runzero`. The full token ID is the composite
   `USER@REALM!TOKENID` — here `runzero@pve!runzero`. Copy the secret; it is a
   UUID and is displayed **once**.
3. **Datacenter → Permissions → Add → API Token Permission**. Grant the token
   itself a role on path `/` with **Propagate** checked.

Step 3 is not optional, and skipping it is the most common way this integration
ends up importing nothing. Proxmox documents that **privilege separation is the
default for newly created tokens**: a separated token starts with *no*
permissions of its own, and its effective rights are the intersection of the
user's rights and the token's own ACL entries. An empty intersection is empty no
matter how privileged the user is. Either add the token's own ACL entry, or
clear **Privilege Separation** on the token so it inherits the user's rights.
(Even unseparated, a token can never exceed its user's permissions.)

#### Required Privileges

This integration reads cluster nodes, QEMU VMs, and LXC containers, and asks the
QEMU guest agent for in-guest addresses and OS information. Those are the only
things it touches — it makes no storage, pool, or SDN calls. The privileges it
actually needs, at path `/` with **Propagate**:

| What the script reads | API path | Privilege |
| --- | --- | --- |
| Cluster name, node list, node status | `/cluster/status`, `/cluster/config/nodes`, `/cluster/resources?type=node` | `Sys.Audit` |
| QEMU VM list and config | `/nodes/{node}/qemu`, `/nodes/{node}/qemu/{vmid}/config` | `VM.Audit` |
| LXC container list, config, interfaces | `/nodes/{node}/lxc`, `/nodes/{node}/lxc/{vmid}/config`, `/nodes/{node}/lxc/{vmid}/interfaces` | `VM.Audit` |
| In-guest interfaces and OS info | `/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`, `/agent/get-osinfo` | `VM.GuestAgent.Audit` |

Two corrections to guidance you may have seen elsewhere, including in earlier
revisions of this file:

- **There is no `PVEVM.Audit` privilege.** Containers and VMs are both covered by
  `VM.Audit`. `PVEVMAdmin` and `PVEVMUser` are *roles*, not privileges.
- **There is no `/lxc` ACL path.** Proxmox's object paths are `/`,
  `/nodes/{node}`, `/vms`, `/vms/{vmid}`, `/storage/{storeid}`,
  `/pool/{poolname}`, and the `/access/...` paths. Containers live under
  `/vms/{vmid}` alongside VMs.

The built-in **`PVEAuditor`** role is the convenient answer for the first three
rows — Proxmox describes it as read-only access, and it covers the `*.Audit`
privileges. **We were not able to confirm from Proxmox's documentation whether
`PVEAuditor` includes the guest-agent read privilege**, and we believe it does
not. If you assign `PVEAuditor` and find that VMs import with their configured
MAC addresses but no in-guest IP addresses and no guest OS information, that
missing privilege is why; add a role that also carries `VM.GuestAgent.Audit`.

On the guest-agent privilege name: `VM.GuestAgent.Audit` is what current
Proxmox documents. Older releases gated the same calls behind `VM.Monitor`. If
your version's permission dialog offers no `VM.GuestAgent.*` entries, use
`VM.Monitor` instead.

Guest-agent data also requires the QEMU Guest Agent to be **installed and
running inside the VM**, and the VM's `Options → QEMU Guest Agent` setting to be
enabled. No privilege recovers in-guest IPs from a VM that is not running the
agent; the script falls back to parsing MACs out of the VM config.

### 2. runZero Console

1. **Credentials** → **Add Credential** → **Custom Integration Script Secrets**

   * **Proxmox base URL** (`base_url`): including the port, e.g. `https://pve.example.com:8006`
   * **API token ID** (`api_token_id`): the composite ID, e.g. `runzero@pve!runzero`
   * **API token secret** (`api_token_secret`): the UUID shown when the token was created
   * TLS options arrive through the shared include. A stock Proxmox install
     presents a self-signed certificate, so either set `tls_ca_cert` to the
     cluster's CA or set `tls_disable_validation`.

2. **Integrations** → **Custom Integrations** → **Add Script**

   * Paste the Starlark code
   * Save and attach to a custom integration task

The script sends the credential as `Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID`,
which is the format Proxmox documents. The default API port is **8006**, and it
must be in `base_url` — Proxmox does not serve the API on 443.

---

## Configuration

| Field           | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `base_url`      | Proxmox API URL (including port), e.g. `https://pve.local:8006` |
| `api_token_id`     | Your API token ID, e.g. `runzero@pve!runzero`                |
| `api_token_secret` | UUID secret of your API token                                |

**Legacy JSON form.** For backwards compatibility, `api_token_secret` may
instead be a single-line JSON string carrying all three values, which the script
unpacks when the value starts with `{`:

```json
{"base_url":"https://your.proxmox.server:8006","api_token_id":"root@pam!monitoring","api_token_secret":"123e4567-e89b-12d3-a456-426614174000"}
```

Prefer the three separate credential fields for new deployments; the JSON form
exists to keep older credentials working.

---

## Script globals

Two globals near the top of `proxmox.star` are worth knowing about. Neither is a credential
parameter, so changing either means editing the script:

```python
DEBUG = False             # per-request "DEBUG: …" prints
INSECURE_ALLOWED = False  # fallback only, when tls_disable_validation is unset
```

`INSECURE_ALLOWED` is genuinely only a fallback: `tls_disable_validation` on the credential
takes precedence whenever it is set, so the supported way to deal with a self-signed
certificate is the credential option, not this global.

Assets are streamed to runZero with `report_assets` and `main` returns `None`; the parameters
arrive as three separate kwargs, with the JSON-stuffed `api_token_secret` recognized only as a
back-compat path.

---

## Running the Integration

1. **Associate** the custom script with a discovery job.
2. **Select** the credential with your Proxmox API token values.
3. **Run** the scan.
4. **Review** discovered assets—nodes, VMs, and containers with IPs and MACs—in runZero.
5. **Find them** with the runZero search `custom_integration:proxmox`. The slug is the script's `CONFIG` id (`runzero-proxmox`) with the `runzero-` prefix removed, not the display name you type. The task itself appears on the [tasks](https://console.runzero.com/tasks) page like any other integration.

---

## Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it — and the fastest way to find out that
a privilege-separated token has no ACL entry of its own. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename proxmox/proxmox.star \
  --kwargs base_url=https://pve.example.com:8006 \
  --kwargs 'api_token_id=runzero@pve!runzero' \
  --kwargs api_token_secret=123e4567-e89b-12d3-a456-426614174000 \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./proxmox-run
```

Quote `api_token_id`: it contains a `!`, which some shells expand as history
substitution. Single quotes are the safe form.

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. This script also has its own `DEBUG` global near the top of `proxmox.star`; set
it to `True` for its per-request `DEBUG:` prints.

Read the result rather than just the exit status. Nodes present but no VMs means the
token is missing `VM.Audit`. VMs present with MACs but no in-guest IP addresses and no
guest OS means the token is missing the guest-agent privilege, or the guest agent is not
running in those VMs. Nothing at all usually means privilege separation, not a bad
secret.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma
— the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. Nothing here carries an `=`: a token secret is a UUID
and `api_token_id` is `user@realm!tokenid`. The legacy JSON-stuffed form of
`api_token_secret` is full of commas but contains no `=`, so it survives on the command
line as one argument, quoted for the shell:

```bash
  --kwargs 'api_token_secret={"base_url":"https://pve.example.com:8006","api_token_id":"runzero@pve!runzero","api_token_secret":"123e4567-e89b-12d3-a456-426614174000"}'
```

The three separate parameters shown above are still the clearer form.

To check the `CONFIG` block and the HTTP and TLS wiring without a live cluster:

```bash
runzero script --filename proxmox/proxmox.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Proxmox accepts the token, that the token's ACL grants
anything, or that any VM is parsed. The fixture scenarios are what exercise the parsing:

```bash
python3 tests/run.py proxmox
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat proxmox/proxmox.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'base_url=https://pve.example.com:8006,api_token_id=runzero@pve!runzero,api_token_secret=123e4567-e89b-12d3-a456-426614174000' \
  --output ./proxmox-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so the legacy JSON secret cannot be passed this way
either; prefer `script --kwargs` for ad-hoc runs.

---

## Asset identity

This integration emits **three kinds of asset** from one run — hypervisor nodes, QEMU VMs, and
LXC containers — and all three share one scoping decision, which is where the risk is.

### The shared scope: `cluster_name`

Every id begins with `cluster_name`, read from `GET /cluster/status` by finding the entry whose
`type` is `cluster` and taking its `name`. **When no such entry exists, `cluster_name` falls
back to the literal string `proxmox`.**

That fallback fires on every **standalone Proxmox host**, because a host that has never been
joined to a cluster reports only a `node` entry from `/cluster/status`, never a `cluster` one.
It is not an edge case: single-host Proxmox is the common deployment.

The consequence is a systematic collision. Two standalone Proxmox hosts imported into one
runZero organization both scope their ids under `proxmox`, and Proxmox numbers VMIDs from 100
on every host independently — so `proxmox-vm-100` on host A and `proxmox-vm-100` on host B are
the same foreign id for two unrelated machines, and runZero merges them. Nodes collide the same
way if the two hosts share a node name, which for a default install (`pve`) they usually do.

If you run more than one standalone host, scope them apart before scheduling this: either join
them into a cluster, or give each its own runZero organization. There is no credential
parameter that overrides the scope.

### Hypervisor nodes

- Target entity: a physical Proxmox VE host running the hypervisor.
- Source ID field: the `node` name from `GET /cluster/resources?type=node`, scoped by cluster name.
- Documentation evidence: the node name is Proxmox's cluster-wide handle for a host — it is what every `/nodes/{node}/...` path is addressed by, what `/cluster/config/nodes` keys its Corosync ring addresses on, and what the cluster's own quorum membership is expressed in. There is no node UUID in the v2 API surface this integration reads.
- Uniqueness scope: the cluster. Proxmox enforces node-name uniqueness within a cluster, which is what makes this usable at all.
- Cardinality: one asset per host.
- Stability: stable while the host keeps its name. Renaming a Proxmox node is a disruptive operation that is not routine, so this is stronger than a hostname-derived id usually is — but it is still a name, not an identifier, and a rename mints a new asset.
- Reuse behavior: fully reusable. Remove a node and add a replacement under the same name and it inherits the old asset.
- Presence: a record with no `node` key is skipped with `continue`.
- Final runZero ID: `<cluster_name>-node-<node_name>`, for example `pve-cluster-node-pve01`.
- Missing-ID behavior: skip the record, silently.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within a named cluster; **not** authoritative on a standalone host, for the reason above.

### QEMU VMs

- Target entity: a guest virtual machine.
- Source ID field: `vmid` from `GET /nodes/{node}/qemu`, scoped by cluster name.
- Documentation evidence: Proxmox allocates VMIDs from a single **cluster-wide** pool — a VMID is unique across the whole cluster, not per node, which is precisely why a VM can live-migrate between nodes without renumbering. That property is what the id design rests on.
- Uniqueness scope: the cluster.
- Cardinality: one asset per guest, regardless of how many virtual NICs it has.
- Stability: **survives live migration and HA failover**, which is the important case and the one the script comments call out explicitly. The node name is deliberately kept out of the id and recorded as a custom attribute instead: including it would change the id every time a guest moved, minting a duplicate on every migration and stranding the previous asset. Migration is routine and often automatic on a Proxmox cluster, so this is not a hypothetical.
- Reuse behavior: **VMIDs are recycled, and this is the real weakness.** Proxmox frees a VMID when the guest is destroyed and offers the lowest free number to the next create, so destroying VM 101 and creating a new one immediately hands the new guest the old identity — and runZero merges the new machine onto the destroyed one's asset. There is no property on the VM record that would disambiguate this; Proxmox exposes no per-guest UUID through the endpoints this integration reads. Treat a rebuilt-from-scratch estate as the case to watch.
- Presence: `vmid` is present on every guest record.
- Final runZero ID: `<cluster_name>-vm-<vmid>`.
- Missing-ID behavior: not guarded. A record with no `vmid` would produce an id ending in `-vm-None`.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within a named cluster, subject to VMID recycling.

### LXC containers

Identical to QEMU VMs in every respect — same cluster-wide VMID pool, same recycling behavior,
same deliberate omission of the node name — except that the id reads
`<cluster_name>-ct-<vmid>` and the OS comes from the container's `ostype` rather than from a
guest agent. The `-vm-` and `-ct-` infixes are what keep a VM and a container that happen to
hold the same VMID apart; Proxmox draws both from one pool, so without the infix they would
collide.

### Why the default `matchBehavior` is kept for all three

The governing rule points at foreign-ID matching for a source with a stable remote id, and
these ids are stable in the sense that matters — they survive migration, reboot, rename of the
guest, and address change. The code follows the rule.

The usual companion preset `no-mac-break no-ip-break no-name-break` is not applied, and for
this source that is the better call, because each of the three asset kinds contributes network
data that should be allowed to find an existing runZero asset:

- **Nodes** contribute the Corosync `ring0_addr` management address from `/cluster/config/nodes` and the node name as a hostname. Both are static configuration rather than drifting metadata. No MAC is available for a node from this API at all, so the interface is address-only.
- **VMs** contribute the virtual MAC parsed out of the guest config, plus in-guest addresses from the QEMU guest agent when it is running. The MAC is the strong signal: Proxmox assigns it at NIC creation and it survives migration, rename, and power cycling.
- **Containers** contribute the same from their config and `/status/current`.

Relaxing the break flags would remove those guards on the one path where they do anything —
first contact, before any id has matched — while protecting against churn that cannot occur,
since a foreign-ID match is never disqualified by a conflicting MAC, address, or name. Given
that both VM and container ids are recyclable, keeping the breaks on is also the remaining
safety net when a recycled VMID is about to pull a new guest onto an old asset.

One asymmetry to note: **VMs are imported with an empty `hostnames` list.** The Proxmox `name`
on a QEMU guest is an administrative label rather than the guest's own hostname, so it is
deliberately not asserted as a name. Containers do get a hostname, because an LXC container's
config carries a real `hostname` field.

## Future

- **The rest of `/cluster/resources`.** One call already returns storage, pools, and SDN objects alongside nodes and guests, so widening the existing `type=node` request is close to free. Storage is the interesting one: a Ceph pool, an NFS export, or an iSCSI target is a real network service on a real address, and importing them as services would describe infrastructure that no guest-level scan reaches.
- **Full node NIC detail.** `GET /nodes/{node}/status/network` (and `/nodes/{node}/network`) returns every physical NIC, bridge, bond, and VLAN on a host with its addresses — including MACs, which the node asset currently has none of. That single gap is why a node correlates on one management address and a name today, and closing it would make hypervisor hosts merge onto scanned assets far more reliably than any `matchBehavior` change could.
- **Proxmox tags and pool membership as runZero tags.** Guests carry a `tags` field and belong to pools; both are how a Proxmox operator expresses environment, owner, and criticality. Mapping them onto runZero tags would carry that structure across for free — the tag data is already in the guest record this integration reads.
- **Guest-agent enrichment beyond addresses.** The integration already calls `/agent/network-get-interfaces` and `/agent/get-osinfo`. The same privilege covers `/agent/get-host-name`, which would give VMs the real in-guest hostname they currently lack, and the file-system and user endpoints. This is the cheapest large improvement available: one extra call per running VM, against an endpoint the token is already authorized for.
- **Backup and replication state as posture data.** `GET /cluster/backup` and the per-guest backup and replication status endpoints report which guests are protected and when they were last backed up. "Which VMs have never been backed up" is a question an inventory should be able to answer and currently cannot.
- **Certificate and subscription status.** `GET /nodes/{node}/certificates/info` lists the certificates the node serves, with expiry. Infrastructure certificate expiry is a routine blind spot and nothing else in a runZero estate reports it.
- **Outbound: runZero data as Proxmox guest tags or notes.** Proxmox accepts writes to a guest's `tags` and `description` through `PUT /nodes/{node}/qemu/{vmid}/config`, so a runZero verdict — exposed service, missing agent, unexpected segment — could be written onto the guest where a Proxmox operator would actually see it. Two constraints: this needs `VM.Config.Options` rather than the read-only privileges this integration asks for, which is a materially broader grant, and it writes live guest configuration, so it needs a much tighter confirmation model than a scheduled read.
- **Alert and event ingestion has a partial path.** Proxmox has no webhook or push mechanism, but `GET /cluster/tasks` and `GET /nodes/{node}/tasks` return the task log — creates, destroys, migrations, backups — with timestamps, which is enough for an incremental poller keyed on a start time. That is the closest thing available to an event feed, and it is the right place to look for the guest-destroy events that would otherwise silently recycle a VMID.
- **Coverage-gap reporting needs no new endpoint.** Every VM and container is imported with its configured MAC, so runZero assets discovered on the network that carry no `custom_integration:proxmox` source and no other virtualization source are machines outside the hypervisor's view. The reverse is also useful: guests imported here that no Explorer has ever scanned are workloads on internal-only bridges with no monitoring reaching them.

---

## Support

For help, contact your runZero administrator or see the [runZero docs](https://docs.runzero.com).

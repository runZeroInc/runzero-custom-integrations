## Scale API v1 Custom Integration for runZero

This custom integration imports **virtual machines** from a Scale Computing HyperCore (HC3) cluster into runZero, enriched with network-device details (MACs, IPs, VLANs), OS info, memory and CPU, state, console settings, boot order, snapshot and replication metadata, and custom attributes.

> **It imports one kind of asset: VMs**, each typed `Virtual Machine`. `GET /rest/v1/Cluster` is called, but only to read the cluster's UUID and name, which become custom attributes on every VM — the cluster does not become an asset of its own, and neither does any physical node. The `CONFIG` description used to say "Imports VMs and nodes from Scale Computing HC3 clusters", which was wrong: no node endpoint is called. It now says what the script does. See [Future](#future) for what adding nodes would involve.

---

## What it reads

| Call | Purpose |
|---|---|
| `GET /rest/v1/Cluster` | cluster UUID and name, taken from the **first** record, for the `clusterId` and `clusterName` attributes |
| `GET /rest/v1/VirDomain` | the VM list — one asset per record |
| `GET /rest/v1/VirDomainNetDevice` | all network devices in one call, grouped locally by `virDomainUUID` |

Every asset carries `deviceType: Virtual Machine`. It is not inferred: `/rest/v1/VirDomain`
is the only source of records here and an HC3 VirDomain *is* a guest VM, so the type comes
from the resource rather than from a name or an OS string. It is the same value
`nutanix-prism`, `truenas`, and `synology-dsm` emit for a hypervisor guest, so one runZero
search covers virtual machines from all of them.

Per VM the mapping keeps **UUID**, **name** (as the hostname), **operatingSystem**,
**description**, **state**, **desiredDisposition**, **console** (type, IP, port, keymap),
**boot devices**, **UI state**, **snapshot UUIDs**, **snapshot serial**, **replication UUIDs**,
**source VM UUID**, **memory** in bytes, **CPU count**, **tags**, and **created/modified**
timestamps. Interfaces carry the **MAC address** and **IPv4 addresses**; VLAN and the
connected flag are logged but not currently mapped onto the interface.

Three calls total, regardless of estate size — there is no per-VM request and no paging.

### Two script globals

```python
INSECURE_ALLOWED = False   # fallback only; tls_disable_validation on the credential wins
DEBUG = True               # verbose debug_print() output — ships ON
```

`DEBUG` ships as `True`, which is useful for a first run and worth turning off before
scheduling a production task. `INSECURE_ALLOWED` is only the fallback used when
`tls_disable_validation` is not set on the credential; the credential option is the supported
route.

---

## Prerequisites

### 1. Scale API v1 Credentials

HyperCore has **no API token concept**. The credential is an ordinary local
cluster user account, sent as HTTP Basic authentication. You need one with read
access to:

* **Cluster** (`/rest/v1/Cluster`)
* **VirDomain** (`/rest/v1/VirDomain`)
* **VirDomainNetDevice** (`/rest/v1/VirDomainNetDevice`)

These paths are **case-sensitive**.

**Use the `Read` role.** HyperCore's role set is `Backup`, `VM Delete`,
`Cluster Settings`, `Cluster Shutdown`, `VM Power Controls`, `Read`,
`VM Create/Edit`, and `Admin` — enumerated in Scale Computing's own Ansible
collection. `Read` alone covers everything this integration does, and nothing
here ever writes, powers a VM on or off, or changes cluster settings. Do not
use `Admin`.

**On creating that user:** Scale Computing's HC3 user guide sits behind their
login-walled customer portal, and we were **not able to verify the exact menu
path** for creating a user and assigning a role. Rather than print a path that
may be wrong: create the account through the HyperCore web interface's user
management, assign it the `Read` role, and confirm with the check below. Note
that the vendor calls the management interface the **Control Panel**, and its
**Support** tab links to the HyperCore API documentation for the version you are
actually running. Each cluster also serves its own Swagger reference at
`/rest/v1/docs/`.

**Confirm the account before going near runZero:**

```bash
curl -sk -u '<username>:<password>' https://scale.example.com/rest/v1/Cluster | head -c 400
```

`-k` is there because HyperCore clusters present a certificate that is not
trusted by default; Scale's own example scripts either supply a chain explicitly
or disable verification. Prefer installing a trusted certificate, or point
`tls_ca_cert` at the cluster's CA, over disabling validation in production.

Make note of:

| Field           | Description                                    |
| --------------- | ---------------------------------------------- |
| `base_url`      | Scale API endpoint, e.g. `https://scale.local` |
| `username`      | Your Scale username                            |
| `password`      | Your Scale password                            |

**A note on API versions.** `/rest/v1` is current and is **not** deprecated —
Scale Computing's official Ansible collection targets the HyperCore v1 API and
is tested against recent cluster releases. If you have seen a "v2" Scale API, it
belongs to a different product: SC//Fleet Manager, a cloud service at
`https://api.scalecomputing.com/api/v2`. There is no HyperCore v2 REST API.

### 2. runZero Console

1. **Credentials** → **Add Credential** → **Custom Integration Script Secrets**

  * **base_url**: the cluster URL, e.g. `https://scale.example.com`
  * **username**: your Scale username
  * **password**: your Scale password

2. **Integrations** → **Custom Integrations** → **Add Script**

   * Paste the Starlark code
   * Save and tie it to an integration task

---

## Configuration

The integration declares three parameters, and the credential form in the
console is generated from them:

| Field           | Description                                                   |
| --------------- | ------------------------------------------------------------- |
| `base_url`      | Scale API URL (no trailing slash), e.g. `https://scale.local` |
| `username`      | Scale username                                                |
| `password`      | Scale password                                                |

Standard `tls_*` and `http_*` options are also available; `tls_ca_cert` and
`tls_disable_validation` are the ones that matter for a cluster with an
untrusted certificate.

**Legacy credential format.** For back-compatibility, **password** may instead
be a single-line JSON string carrying all three values. It is used only when the
password begins with `{`, and the named parameters win over anything inside it:

```json
{"base_url":"https://scale.api.server","username":"scale_user","password":"s3cr3tP@ssw0rd"}
```

New deployments should use the named parameters.

---

## Running the Integration

1. **Associate** this custom script with an integration task in runZero.
2. **Select** the credential you created.
3. **Run** the task.
4. **Review** the discovered VMs — with network, OS, and metadata — in your runZero inventory. Assets are streamed with `report_assets` and `main` returns `None`, so the task reports its count in the log rather than returning a list.
5. **Find them** with the runZero search `custom_integration:scale-computing`. The slug is the script's `CONFIG` id (`runzero-scale-computing`) with the `runzero-` prefix removed, not the display name you type. The task itself appears on the [tasks](https://console.runzero.com/tasks) page like any other integration.

### From the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a cluster account and see what HyperCore returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename scale-computing/scale-computing.star \
  --kwargs base_url=https://scale.example.com \
  --kwargs username=runzero \
  --kwargs password='Ch4nge-Me!2026' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./scale-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Omit `--output` to see only the log lines.

**This script is chatty by default.** `DEBUG = True` is set at the top of
`scale-computing.star`, so a command-line run already prints its URLs, status
codes, and session headers without `--verbose`. That is useful here and worth
turning off before scheduling a production task.

Because HyperCore's certificate is untrusted by default, a first run commonly
fails on TLS rather than on the credential. Supply the CA rather than reaching
for the URL:

```bash
runzero script --filename scale-computing/scale-computing.star \
  --kwargs base_url=https://scale.example.com \
  --kwargs username=runzero \
  --kwargs password='Ch4nge-Me!2026' \
  --kwargs tls_ca_cert=/etc/ssl/certs/scale-cluster-ca.pem \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./scale-tls --overwrite
```

`--kwargs` takes the value verbatim as long as the whole argument holds a single
`=`, so a comma inside a value is passed through intact — `--kwargs 'x=a,b'`
arrives as `a,b`, and a cluster password containing a comma is fine. What breaks
is a value carrying **both** a second `=` and a comma: the flag then parses the
argument as a CSV record, so `--kwargs 'x=a=b,c=d'` yields `x=a=b` plus a
fabricated parameter `c="d"`. Two consequences here — **the legacy JSON-in-password
format cannot be passed at all**, because JSON carries both characters several
times over, and a password holding both needs the whole argument wrapped in a
second pair of quotes:

```bash
  --kwargs '"password=Ch4nge=Me,2026"'
```

Use the named parameters on the command line and keep the JSON form for existing
console credentials.

To check the `CONFIG` block and the HTTP and TLS wiring without a live cluster:

```bash
runzero script --filename scale-computing/scale-computing.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the cluster accepts the account, that
the account holds the `Read` role, or that any VM is parsed.

The fixtures under `scale-computing/tests/fixtures/` exercise the parsing
offline, including the degraded-cluster and cluster-name cases:

```bash
python3 tests/run.py scale-computing
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat scale-computing/scale-computing.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'base_url=https://scale.example.com,username=runzero,password=<password>' \
  --output ./scale-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is a different flag with a stricter rule: it
takes **one** comma-separated `key=value` string, so no value passed through it
may contain a comma at all — neither the JSON form nor a comma-bearing password.

---

## Asset identity

- Target entity: a guest virtual machine on a HyperCore cluster, from `GET /rest/v1/VirDomain`. Nothing else becomes an asset.
- Source ID field: `uuid` on the VM record, used verbatim.
- Documentation evidence: `uuid` is HyperCore's own handle for a guest — it is what `VirDomainNetDevice` records point back at through their `virDomainUUID` field, which is the join this integration performs to attach interfaces to VMs, and it is what a VM's own `sourceVirDomainUUID` and `snapUUIDs` reference. The API is self-consistent about it: everything guest-scoped in the v1 schema keys on this value. Each cluster also serves its own Swagger reference at `/rest/v1/docs/`, which is the authoritative source for the version you are running.
- Uniqueness scope: **unscoped, and this is the notable weakness.** The cluster UUID is fetched on every run and stored as the `clusterId` custom attribute, but it is **not** used to namespace the id — `id = vid` is the bare VM UUID. The material to scope it is right there and is simply not applied. In practice the risk is low, because these are UUIDs rather than sequential integers, so two clusters colliding by accident is not a realistic concern. The reason to scope it anyway is the same reason `nutanix-prism` and `proxmox` do: it makes the namespace explicit rather than resting on the value's format, and it survives a vendor deciding UUIDs are per-cluster.
- Cardinality: one asset per VM, regardless of how many virtual NICs it has. Network devices are fetched in one flat call and grouped locally by `virDomainUUID`, so a VM with four interfaces is one record with four interfaces, not four records.
- Stability: survives rename, power cycling, address change, and migration between nodes in the cluster. A **clone** gets a new UUID, which is correct — a clone is a different VM. A restore-from-snapshot in place keeps the UUID; a restore-as-new-VM does not, which is why `sourceVirDomainUUID` is preserved as an attribute.
- Reuse behavior: not documented, and not a practical concern for a UUID.
- Presence: guarded. A record arriving without a `uuid` is skipped and logged as `scale-computing: skipping VM with no uuid: name=<name>`. This check was missing, and its absence was not merely untidy: `vid` reached `ImportAsset(id=None)`, which the runtime rejects with `id must be a string`, and with no exceptions in Starlark that ended the **whole run** — every VM already built was discarded and none were reported. One malformed record cost the entire import.
- Final runZero ID: the raw VM UUID.
- Missing-ID behavior: none — see above.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative, on the strength of the UUID rather than of any scoping the script performs.

### Why the default `matchBehavior` is kept

The VM UUID is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it.

The usual companion preset `no-mac-break no-ip-break no-name-break` is not applied, and that is the right call here because of what the network data actually is. `VirDomainNetDevice` returns the **virtual MAC HyperCore assigned at NIC creation**, not something observed on a wire — it is stable across migration, rename, and power cycling, and it is the single strongest signal this source contributes for finding the asset runZero already scanned. Relaxing `mac-break` would remove the guard on exactly that path while protecting against churn that cannot occur, since a foreign-ID match is never disqualified by a conflicting MAC.

Two properties of the mapping are worth knowing because they bear on merging:

- **`ipv4Addresses` come from the hypervisor's view of the guest, so they are absent for a powered-off VM** and for any guest whose addressing HyperCore does not observe. An address-less record correlates on MAC and name only, which is normal rather than a fault.
- **The VM `name` is asserted as a hostname.** On HyperCore that is the administrative label an operator typed, not the guest OS's own hostname, and the two routinely differ. `name-break` staying on means a genuine disagreement can veto a first-contact merge — which is the conservative choice, and the one to revisit if VMs are observed failing to merge onto scanned assets they should match.

### Notes

- **The cluster lookup takes the first record and stops.** `/rest/v1/Cluster` is scoped to the appliance being queried, so it describes that cluster and its first record is the right one. An earlier revision built a map keyed by cluster UUID and looked it up with the VM's `nodeUUID` — a *node* UUID — so the lookup never matched and `clusterName` was never populated. That is fixed; the comment in the script records it.
- **`nodeUUID` is preserved as a custom attribute and deliberately kept out of the id**, for the same reason `proxmox` keeps the node name out of a guest id: a VM that moves between nodes must not change identity.
- **VLAN and the connected flag are read and logged but not mapped.** `debug_print` shows them per interface; neither reaches the asset. They would be reasonable custom attributes.
- The whole run is three requests with no paging, so a very large cluster returns everything in one response per endpoint. `report_assets` streams the finished list, but the raw VM and network-device responses are held in memory together while they are being joined.
- This integration was validated against local fixtures, not a live HyperCore cluster.

## Future

- **Physical nodes as assets — the gap the `CONFIG` description already claims.** `GET /rest/v1/Node` returns the cluster's physical hosts with their UUIDs, LAN and backplane addresses, and hardware detail. These are real servers on the network that runZero will discover by scanning anyway, and importing them would let the hypervisor's own view merge onto the scanned asset instead of sitting beside it. The identity design is straightforward — node UUID, scoped by cluster UUID — and it is the single most valuable addition here.
- **Block devices and storage.** `GET /rest/v1/VirDomainBlockDevice` gives per-VM disks, sizes, and backing storage, and `GET /rest/v1/VirtualDisk` covers the storage pool side. Useful as attributes, and the disk inventory is one of the few things a network scan can never infer.
- **Snapshots and replication as posture data.** The VM record already carries `snapUUIDs`, `snapshotSerialNumber`, and `replicationUUIDs`, and this integration preserves all three as attributes without resolving them. `GET /rest/v1/VirDomainSnapshot` and the replication endpoints would turn "this VM has three snapshot UUIDs" into "this VM was last snapshotted on a date", which is the form a "which workloads are unprotected" report needs.
- **Cluster and node health.** HyperCore exposes cluster condition and per-node status, which would make the difference between a VM that is genuinely absent and one that is on a node that is down. Right now a degraded node looks the same as a deleted VM: the record simply stops appearing.
- **Outbound: runZero data as HyperCore VM tags.** The VM record carries a `tags` field, and the v1 API accepts a `PATCH` to `/rest/v1/VirDomain/{uuid}`. A runZero verdict — exposed service, unexpected segment, missing agent — could be written onto the guest where a HyperCore operator would see it. Two constraints: this needs the `VM Create/Edit` role rather than the `Read` role this integration asks for, which is a materially broader grant on a hypervisor, and it writes live guest configuration, so it needs a much tighter confirmation model than a scheduled read.
- **VM power control is available and should stay off the table.** The API and the `VM Power Controls` role make it possible for an integration to stop a VM. That is a genuinely destructive capability on production workloads, and no discovery integration should hold a credential that carries it.
- **There is no event or alert feed.** The v1 API is a REST resource interface with no webhook, no event stream, and no change cursor. HyperCore does expose an alert/task history through the Control Panel, but nothing in the v1 surface this integration touches offers a pollable cursor, so anything resembling live behavior would be re-reading the three endpoints on a short schedule — which, at three requests per run, is at least cheap.
- **SC//Fleet Manager is a different product and a different integration.** The v2 API at `https://api.scalecomputing.com/api/v2` belongs to Scale's cloud fleet service, not to HyperCore. It would give a multi-cluster view without an Explorer inside each cluster's network, which is a real advantage for a distributed edge estate — but it is a separate credential, a separate API, and a separate script. It is not a version bump of this one.

---

## Support

For assistance, reach out to your runZero administrator or consult the [runZero documentation](https://docs.runzero.com).

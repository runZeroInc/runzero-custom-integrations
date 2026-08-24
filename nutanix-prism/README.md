# Custom Integration: Nutanix Prism

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Nutanix Prism requirements

- A Prism Element local user, or a mapped directory user, with the **Viewer** role. This integration only issues `GET` requests, so no higher role is needed.
- The Prism Element URL including its port, for example `https://prism.example.com:9440`. Prism Element publishes the v2.0 API on port 9440.
- Network reachability from the Explorer to Prism Element. Point the integration at the **cluster virtual IP** rather than at an individual Controller VM address, so the import keeps working when a single CVM is down for maintenance.
- This integration talks to **Prism Element** (the per-cluster interface). Prism Central is a different product with a different API version and is not supported here; run one integration per cluster.

## Steps

### Nutanix Prism configuration

1. Sign in to Prism Element as an administrator.
2. Open the gear menu and choose **Local User Management** (or **Role Mapping** for a directory account).
3. Create a dedicated service account and assign it the **Viewer** role.
4. Note the Prism Element URL and port exactly as you browse to it, preferring the cluster virtual IP.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Nutanix Prism").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Prism Element URL** (`url`): the Prism Element base URL including the port, for example `https://prism.example.com:9440`.
   - **Username** (`username`): the Prism Element user with the Viewer role.
   - **Password** (`password`): the password for that user.
   - **Import guest VMs** (`import_vms`): optional; import the cluster's guest VMs in addition to the hypervisor nodes (default: true).
   - **Records per page** (`page_size`): optional; records requested per call (default: 250).
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
runzero script --filename nutanix-prism/nutanix-prism.star \
  --kwargs url=https://prism.example.com:9440 \
  --kwargs username=runzero-viewer \
  --kwargs password=NotTheRealPassword1 \
  --kwargs import_vms=true \
  --kwargs page_size=50 \
  --kwargs tls_disable_validation=true \
  --output ./nutanix-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

Point `url` at the **cluster virtual IP**, not at a single Controller VM, so the run keeps
working while a CVM is down for maintenance. Prism Element serves the v2.0 API on port 9440.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

Prism Element ships with a self-signed certificate, so a command-line run usually needs
`tls_disable_validation=true` or `tls_ca_cert=/path/to/ca.pem`. Set `import_vms=false` to
confirm the hypervisor node import on its own before adding the guest VMs — the two produce
different assets with different identity and different match behavior, and it is easier to
read the output one kind at a time.

To check the `CONFIG` block and the HTTP and TLS wiring without a live cluster:

```bash
runzero script --filename nutanix-prism/nutanix-prism.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Prism accepts the credential or that any node or VM is parsed.

The recorded API shapes, including the before/after migration identity cases, are exercised
by the fixture suite:

```bash
python3 tests/run.py nutanix-prism
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat nutanix-prism/nutanix-prism.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://prism.example.com:9440,username=runzero-viewer,password=<password>' \
  --output ./nutanix-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a password
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Nutanix Prism.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:nutanix-prism`.

## Asset identity

This integration emits **two different kinds of asset** from one run, and they get separate identity and separate match behavior.

They are emitted as two declared asset types — `host` and `vm` — selected per record with `ImportAsset(assetType=...)`. Only `vm` has an entry in `CONFIG["assetTypeBehavior"]`; `host` deliberately has none, and there is no integration-wide `matchBehavior` either, so a node resolves to the platform default with all eight flags on. That is a decision, not an omission — see *Why hosts and guests get different `matchBehavior`* below.

`type-break` is left ON (the default), so a `host` and a `vm` never merge with each other. It is the same argument one level up: the Controller VM is a guest on the very node it manages and sits on the same management segment, so `vm` and `host` records are the pair most likely to reach each other on a shared address. A guest must never absorb its hypervisor.

### Hypervisor nodes

- Target entity: a physical Nutanix node — the server running the AHV hypervisor.
- Source ID field: `uuid` on each entity of `GET /hosts`.
- Documentation evidence: the [Prism Element v2.0 API reference](https://www.nutanix.dev/api_reference/apis/prism_v2.html) declares `GET /hosts` as returning `EntityCollection_get.dto.appliance.configuration.NodeDTO_`, whose `uuid` is the node key. The same value appears as `node_uuid` on the host NIC DTO and inside `cluster.rackable_units[].node_uuids`, so it is the identifier the rest of the schema joins on.
- Uniqueness scope: generated as a UUID and used as the cluster-wide node key. It is namespaced by cluster here anyway, because global uniqueness is not a published guarantee.
- Cardinality: exactly one row per physical node.
- Stability: survives reboot, rename, and address changes. A Foundation re-image or a cluster remove/re-add should be assumed to mint a new value; Nutanix publishes no statement either way.
- Reuse behavior: not documented. UUID-shaped and per-node, so reassignment is implausible but unverified.
- Presence: present on every host entity observed. A record without it is skipped.
- Final runZero ID: `nutanix:<cluster-uuid>:host:<host-uuid>`
- Missing-ID behavior: skip the record, logging only the node name.
- Asset type: **`host`**, with no `assetTypeBehavior` entry.
- Match behavior: default — all eight flags left on.
- Verdict: authoritative within the cluster.

### Guest VMs

- Target entity: a guest virtual machine running on the cluster.
- Source ID field: `uuid` on each entity of `GET /vms`.
- Documentation evidence: the same reference declares `VmConfigDTO` with `uuid` and `host_uuid` as **separate** fields. That separation is the contract that matters here: the VM's identity is defined independently of the node it currently runs on. Nutanix also documents the AHV VM UUID as immutable — unlike ESXi, it cannot be edited.
- Uniqueness scope: the cluster. Namespaced by cluster uuid.
- Cardinality: one row per VM. A VM with several virtual NICs is still one row and becomes one asset with several interfaces.
- Stability: **survives live migration between nodes**, power cycling, rename, and re-addressing. A clone gets a new UUID, which is correct — a clone is a different VM. A cross-cluster DR failover or a restore-as-clone may mint a new UUID; see Notes.
- Reuse behavior: not documented.
- Presence: present on every VM entity observed. A record without it is skipped.
- Final runZero ID: `nutanix:<cluster-uuid>:vm:<vm-uuid>`
- Missing-ID behavior: skip the record, logging only the VM name.
- Asset type: **`vm`**.
- Match behavior: `no-ip-break no-name-break`
- Verdict: authoritative within the cluster.

### Why the id is namespaced by cluster uuid and not by hostname

Prism Element answers on the cluster virtual IP **and** on every Controller VM address in the cluster. The configured hostname is therefore not a name for the cluster — the same cluster reached through a different CVM address would produce a different namespace and mint a duplicate copy of the entire estate. The cluster `uuid` from `GET /cluster` is the only scope that survives that, so the integration fetches it first and **aborts the run if it cannot be obtained**. Guest records carry no cluster field of their own, so there is nothing to fall back to, and importing VMs under a guessed namespace is worse than importing nothing.

`GET /cluster` returns a single object rather than a collection, and its display name field is `name` — there is no `cluster_name` field. `uuid` is preferred over `cluster_uuid`, and `id` is deliberately unused because on v2.0 it carries the composite `<cluster-uuid>::<entity-id>` form.

### Why a guest's id never contains its host

`host_uuid` is recorded as the `nutanix_host_uuid` custom attribute but is **absent from the asset id by design**. Live migration is a routine, frequently automatic event on a Nutanix cluster, and an id built from the current node would change every time a VM moved — minting a second asset for the same guest on every migration and leaving the old one to go stale. This case is covered by a dedicated fixture test in which a VM changes node, name, and address between polls and must keep one id.

### Why hosts and guests get different `matchBehavior`

The two settings were decided separately, because the evidence differs.

The starting point is that for a custom integration a foreign-ID match cannot be vetoed. `MatchByForeignID` consults only a site check and `MatchBreakForeignIDCollision`, and that helper carries the comment *"Does not support custom integrations"* — it only fires for a hardcoded list of built-in sources. So no break flag protects an id that is not one-per-device, and the break flags matter only on the other path: **first contact**, where this record merges into an asset runZero already discovered by scanning, on MAC, IP, or hostname.

**Hypervisor nodes keep every break flag on.** There is no churn here to defend against. `hypervisor_address` is a static management address rather than a DHCP lease, and `name` is the cluster-assigned `NTNX-<block>-<position>` label that AHV also reports as its own hostname, so the two signals this record contributes are stable and agree with what a scan sees. Leaving the breaks on preserves their protection exactly where it is most valuable: a node shares its subnet with its own Controller VM and its BMC (see below), and if this record were ever about to merge onto one of those instead, a disagreeing hostname or MAC *should* be allowed to stop it. Relaxing the flags would buy nothing and disable that.

**Guest VMs use `no-ip-break no-name-break`, and deliberately keep `mac-break` on.**

- `no-ip-break` — a guest address is a lease the hypervisor learned. It is absent entirely for a powered-off guest, absent for any guest whose addressing AHV does not manage, and stale between polls. A disagreeing address is not evidence of a different machine, and vetoing on it would fragment the guest away from the asset runZero scanned.
- `no-name-break` — the `name` on a VM record is the **Prism administrative label**, not the guest operating system's hostname. An operator renames it freely and it routinely differs from what the guest actually reports on the network. A name disagreement here is expected rather than suspicious, and vetoing on it would block precisely the merge that makes this import worth doing. This is the general loosening the flag is meant for: custom-integration hostnames sit in the trusted-name set, so the label would otherwise be weighed as though it were authoritative.
- `mac-break` stays **on**. The virtual MAC is the one strong, stable signal a guest record carries — Nutanix assigns it at NIC creation and it survives migration, rename, and power cycling — and it is how this record should find the scanned asset in the first place. A genuine MAC disagreement does mean a different machine. Keeping this single break is what makes relaxing the other two safe rather than reckless.

### Notes

- **What is imported:** hypervisor nodes from `GET /hosts` and guest VMs from `GET /vms`, with the cluster identity taken from `GET /cluster`. All three are under `{url}/PrismGateway/services/rest/v2.0` and authenticate with HTTP Basic.
- **There is no software inventory, no service or port inventory, and no CVE data in this API.** Stated plainly because it is a common expectation of a hypervisor source: the v2.0 schema contains no installed-package list, no listening-port list, and no vulnerability feed. No `Software`, `Service`, or `Vulnerability` records are produced. The only version-shaped data available is metadata — `hypervisor_full_name`, `bios_version`, and the cluster `version` — and it is kept as custom attributes rather than dressed up as installed software.
- **The two listings page with different conventions, and mixing them up silently returns page one forever.** `GET /hosts` uses `count` (page size) and `page` (1-based). `GET /vms` uses `offset` and `length`. They also differ on filter parameter names (`filter_criteria` versus `filter`). Both are always sent as complete pairs. Paging stops on an empty page or a short page.
- **`include_vm_nic_config=true` is what makes guest NICs exist.** Without it `GET /vms` returns every VM with no `vm_nics` array at all — no MAC and no address — which makes the guest assets nearly uncorrelatable. This is the single most important parameter in the integration.
- Each entry in `vm_nics` becomes its own network interface, so a multi-homed guest keeps its addresses attached to the correct MAC. `mac_address` is the MAC; addresses are read from `ip_address` (singular) and `ip_addresses` (list), both of which the schema declares.
- **`requested_ip_address` is deliberately not imported.** It is the address requested of AHV IPAM, not one the hypervisor observed, so it can name an address the guest never actually took.
- **A guest with a MAC and no address is normal, not an error.** Address information is only available where AHV itself manages or learns the assignment; a guest on an external DHCP server or a static address may report no IP even while running, and a powered-off guest reports none by definition. Such guests are imported with a MAC-only interface.
- **Node addresses: only two of the several in the record belong to the node.** `hypervisor_address` (the AHV host's management address) and `backplane_ip` (its address on a segmented backplane network) are attached as interfaces. Everything else that looks like an address is kept as a custom attribute and never attached, because a Nutanix node is really **three separately scannable machines sharing one chassis**:
  - `service_vmexternal_ip`, `service_vmnat_ip`, and `controller_vm_backplane_ip` belong to the **Controller VM**, a real guest with its own operating system, hostname, and MAC that runZero discovers as its own asset. A captured host record shows the split directly: `hypervisor_address` `192.168.20.51` alongside `service_vmexternal_ip` `192.168.20.52`. Nutanix requires CVMs and hypervisor hosts to share a subnet, which is exactly why the two addresses are adjacent and exactly why claiming one for the other is so easy to get wrong.
  - `ipmi_address` is the node's **BMC**. It is the same piece of hardware in the sense that it is bolted to the same motherboard, but it is a separate network endpoint with its own MAC, its own firmware, and its own service surface, and runZero fingerprints BMCs as their own assets. Attaching it here would merge the BMC into the hypervisor.
  - `management_server_name` and `hypervisor_key` repeat the hypervisor address on AHV but name the **vCenter server** on an ESXi-backed cluster, so neither is safe to treat as an address of this node.

  All of these are preserved as `nutanix_*` attributes, and the ones deliberately withheld are additionally collected into `nutanix_addresses_not_imported` so an operator can see the decision rather than wonder about a missing address.
- **Nodes have no MAC address in this import.** `GET /hosts` publishes only `host_nic_ids`, not MACs. Physical NIC MACs are reachable, but only through a per-node `GET /hosts/{uuid}/host_nics` call; that N+1 pass is described under Future rather than done here. Node assets therefore correlate on IP and hostname alone.
- Loopback, unspecified, and link-local addresses (`127.0.0.0/8`, `::1`, `0.0.0.0`, `169.254.0.0/16`, `fe80::/10`) are filtered out of every address list before an interface is built, for both asset kinds. A node or guest whose only address is one of those is imported with no network interface at all rather than sharing a meaningless address with every other such record. A fixture case covers a loopback-only node.
- **`boot_time_in_usecs` is MICROseconds, not the milliseconds most APIs use.** Reading it with the wrong divisor places every node tens of thousands of years in the future, and runZero fails an entire `ImportAsset` whose timestamps are in the future rather than dropping the field — so that mistake would silently import nothing. The value is converted from microseconds and then clamped to the current time, and the normalized result is stored as `nutanix_boot_time_normalized` with the raw value retained alongside it.
- **First-seen and last-seen are handled conservatively.** This API publishes no discovery timestamp for either asset kind; boot time is the only time available and it is not a "seen" time — using it would push first-seen forward on every reboot. `lastSeenTS` is set to the time of the run, which is what this source can honestly attest to, and `firstSeenTS` is left unset.
- **`serial` is not always a hardware serial.** On Community Edition it has been observed carrying the same UUID as the node's `uuid`, because a virtualized node has no real chassis serial. It is imported as an attribute only and is never used for identity. `block_serial` and `block_model` describe the chassis and are imported as attributes and as the asset `model`.
- `os` and `osVersion` on a node come from `hypervisor_full_name` (for example `Nutanix 20190916.321`) combined with the `hypervisor_type` enum, where `kKvm` is AHV. The version is only split off when the trailing token actually begins with a digit; otherwise the whole string is kept as the OS name rather than guessed apart.
- **`os` is deliberately not set on guest VMs.** `guest_os`, `guest_driver_version`, and `tools_running_status` are carried through as custom attributes, but they are only populated when Nutanix Guest Tools is installed and their value format is not published, so mapping them into `os` would put an unreliable string into a field runZero search treats as authoritative.
- Transient failures are retried by the shared HTTP helper with exponential backoff, which honors `Retry-After`. Nutanix does not publish a request-rate limit for the v2.0 API. An authentication failure is reported as a credential problem rather than as a raw status.
- Unverified assumption: **whether `GET /hosts` truly rejects `page` when `count` is absent.** This was asserted in the source material used to scope the work, but no Nutanix documentation confirms it, and the schema marks both parameters optional with no declared defaults. The integration always sends the pair, which makes the question moot.
- Unverified assumption: **the maximum `length` accepted by `GET /vms`.** The v2.0 schema declares no default, minimum, or maximum. The frequently cited limit of 500 is a **v3** constraint and should not be assumed to apply here, so the default of 250 is deliberately conservative.
- Unverified assumption: whether a host `uuid` survives a Foundation re-image or a cluster remove/re-add. Both are treated as identity-changing events in the record above, which is the conservative reading.
- Unverified assumption: whether a VM `uuid` survives a cross-cluster DR failover. A restore-as-clone demonstrably mints a new UUID. Because clusters are separate namespaces here anyway, a VM that moves between clusters will appear as a new asset regardless; `mac-break` remaining on means the MAC still governs whether it merges with what runZero scanned.
- Unverified assumption: `backplane_ip` is the hypervisor's backplane address rather than the CVM's. The schema pairs it with a distinct `controller_vm_backplane_ip`, which is strong evidence, but it was not confirmed against a live segmented cluster. Backplane networks are isolated storage VLANs an Explorer will rarely reach, so the practical exposure is small.
- This integration was validated against local fixtures, not a live Nutanix cluster. The fixture server reproduces both paging conventions across multiple pages, an empty cluster, a `401`, a `429` that recovers, a failed cluster lookup, malformed records of both kinds, records with no `uuid`, a loopback-only node, a future boot time, a powered-off guest with an IPAM request address, a multi-NIC dual-stack guest, two clusters serving identical local UUIDs, and a guest that migrates between nodes while being renamed and re-addressed — but no request has been made to a real Prism Element.

## Future

- **Node MAC addresses and switch topology, from `GET /hosts/{uuid}/host_nics`.** This is the most valuable near-term addition. The host NIC DTO carries `mac_address`, `ipv4_addresses`, `ipv6_addresses`, `name`, `link_speed_in_kbps`, and `status`, which would give node assets the MAC they currently lack and make them correlate far more strongly. The same response also carries LLDP/CDP neighbour data — `switch_mac_address`, `switch_management_ip`, `switch_port_id`, `switch_vlan_id`, `switch_vendor_info` — which is genuine network topology: it says which physical switch port each node is plugged into. `GET /hosts/{uuid}/virtual_nics` adds the host's virtual interfaces and their `vlan_id`. The cost is one request per node, which is a small N, so this is a much cheaper N+1 than a per-guest pass would be.
- **The Controller VM as its own asset.** Every node record already contains the CVM's addresses, which this integration deliberately declines to attach to the node. Emitting the CVM as a third asset kind — `nutanix:<cluster-uuid>:cvm:<service_vmid>` — would model the cluster as it actually is, and would give runZero an owner for the addresses currently parked in attributes. The identity question needs care: `service_vmid` is the composite `<cluster-uuid>::<n>` and is only unique within a cluster, and it should be expected to change on a node remove and re-add.
- **Alert and event ingestion as a feed, not as vulnerabilities.** `GET /alerts` and `GET /events` both return `AlertDTO`, with `start_time_in_usecs`/`end_time_in_usecs` windowing and `count`/`page` paging, plus narrower `/hosts/{uuid}/alerts` and `/hosts/{uuid}/events` variants. The join back to an imported asset is direct: `affected_entities` is an array of self-contained `{uuid, id, entity_type, entity_name}` objects, and `node_uuid` and `cluster_uuid` are carried as well. Prefer `affected_entities` over the parallel `entity_uuids`/`entity_types` arrays, which have to be correlated by position. These are **hardware and operational alerts** — a failing disk, a degraded node, a full container — not CVEs, so they belong in an event feed with a high-water mark between runs rather than in `Vulnerability` records. Note there is no `/vms/alerts`; VM-scoped alerts come from filtering `/alerts` by `entity_type` and `entity_ids`.
- **Virtualization coverage-gap reporting.** This is the strongest reporting story a hypervisor source enables, and every field it needs is already imported. A Nutanix cluster knows its complete guest inventory — including guests that are powered off, and guests whose MAC runZero has never observed on the wire. Diffing that against runZero's own discovery separates several populations that matter operationally: guests Nutanix lists that runZero has never seen on the network (unmanaged or dormant VMs, and VMs on segments no Explorer reaches), guests runZero scans that no hypervisor claims (candidates for shadow infrastructure or for a hypervisor this integration is not pointed at), and nodes whose `num_vms` disagrees with the number of guests actually correlated. Because `power_state` and `host_uuid` are imported as attributes, "which powered-on VMs has runZero never seen" is a search rather than new integration work.
- **Cluster and storage inventory as context.** `GET /clusters`, `GET /storage_containers`, `GET /disks`, and `GET /protection_domains` describe the cluster's storage and replication topology. These are not assets in runZero's sense — a storage container is not a device — so the sensible use is enriching the node and cluster attributes already imported, for example recording which protection domain a guest belongs to so DR posture is visible next to the asset.
- **No outbound integration is proposed, and that is a deliberate recommendation rather than an API limitation.** The v2.0 API is perfectly capable of writes: `POST /vms/{uuid}/set_power_state` changes a guest's power state, and there are endpoints for migration and for VM lifecycle. None of them is appropriate to drive from a scheduled inventory sync. Powering off or migrating a production guest in response to a discovery finding is disruptive and hard to undo, and it would need explicit per-VM operator approval, a dry-run mode, and an audit trail before it could be considered.

## API documentation

- Prism Element v2.0 API reference, used for the endpoint list, the `{entities, metadata, error_info}` envelope, the paging parameters on both listings, the `VMNicSpecDTO` NIC field names, the `NodeDTO` host fields, and the `ClusterDTO` identity fields: <https://www.nutanix.dev/api_reference/apis/prism_v2.html>
- Setting up a first v2.0 request, used for the base path and authentication model: <https://www.nutanix.dev/2019/08/22/get-all-the-things-setting-up-your-first-nutanix-rest-api-v2-0-request/>
- Captured `GET /hosts` entity, used to confirm that `hypervisor_address` and `service_vmexternal_ip` are genuinely different addresses on one node and that `serial` can carry a UUID on Community Edition: <https://gist.github.com/gowatana/0554cee0f0ebea33d3ab30bda60615e7>
- Captured v2.0 pagination response, used to confirm that `page` and `start_index` are 1-based and which metadata keys are actually populated on `GET /hosts`: <https://next.nutanix.com/how-it-works-22/how-to-handle-pagination-in-rest-api-v2-41035>
- VM NIC address availability, used for the finding that addresses are only reported where AHV manages or learns them: <https://next.nutanix.com/api-31/vms-uuid-nics-missing-ip-when-requested-18141>
- CVM IP reconfiguration guidance, used to confirm that Controller VMs and hypervisor hosts are separate machines required to share a subnet: <https://portal.nutanix.com/page/documents/details?targetId=Advanced-Admin-AOS%3Aip-cvm-ip-address-reconfigure-t.html>
- AHV VM UUID immutability: <https://next.nutanix.com/ahv-virtualization-27/is-it-possible-to-change-vm-uuid-44135>
- Cloned VMs receiving new UUIDs: <https://next.nutanix.com/installation-configuration-23/cloned-vm-and-source-vm-power-on-43026>
- The 500-record `length` limit being a v3 constraint rather than a v2.0 one: <https://www.nutanix.dev/2019/06/13/the-five-hundred-500-vms-via-v3-api/>
- Cortex XSOAR Nutanix Hypervisor integration, used as the initial scoping contract for the base path, Basic auth, and the two paging vocabularies. Note that it does not pass `include_vm_nic_config`, which is why VMs come back from it with no NICs: <https://github.com/demisto/content/blob/master/Packs/NutanixHypervisor/Integrations/NutanixHypervisor/NutanixHypervisor.py>

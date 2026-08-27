# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-nutanix-prism",
    "name": "Nutanix Prism",
    "type": "inbound",
    "description": "Imports hypervisor nodes and guest VMs from a Nutanix Prism Element cluster.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Guests get a different setting from nodes, on their own evidence.
    # 
    # no-ip-break: a guest address is a DHCP lease the hypervisor learned,
    # it is absent entirely while the guest is powered off, and it goes
    # stale between polls. A disagreeing address is not evidence of a
    # different machine, and letting it veto a merge fragments the guest
    # from the asset runZero scanned on the network.
    # no-name-break: the name here is the Prism administrative label for the
    # VM, not the guest's own hostname. An operator renames it freely and
    # it routinely differs from what the guest reports, so a name
    # disagreement is expected rather than suspicious -- and vetoing on it
    # would block exactly the merge that makes this import useful.
    # mac-break is deliberately left ON. The virtual MAC is the one strong,
    # stable correlation signal a guest record carries, it is what should
    # find the scanned asset in the first place, and a genuine MAC
    # disagreement does mean a different machine. Keeping this one break
    # is what makes relaxing the other two safe.
    "matchBehavior": "no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Prism Element URL",
            "type": "url",
            "required": True,
            "placeholder": "https://prism.example.com:9440",
            "description": "Base URL of the Prism Element interface, including the port. Prism Element listens on 9440. Point this at the cluster virtual IP rather than at an individual Controller VM so the integration keeps working when a CVM is down.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Prism Element user. A role of Viewer is sufficient; this integration only issues GET requests.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the Prism Element user.",
        },
        {
            "key": "import_vms",
            "label": "Import guest VMs",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the cluster's guest VMs as assets in addition to the hypervisor nodes. Turn this off to import only the physical nodes.",
        },
        {
            "key": "page_size",
            "label": "Records per page",
            "type": "int",
            "required": False,
            "default": 250,
            "min": 1,
            "max": 1000,
            "description": "Records requested per call. Applies to both the hosts and the VMs listing, which page with different parameters but accept the same sizes.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'routable_ip')
load('http', 'get_json', 'basic')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'from_timestamp')

VENDOR = "nutanix"
# to_custom_attributes joins the prefix to each key with the separator, so the
# separator has to be passed too or every attribute is named nutanix.<key>.
ATTR_PREFIX = "nutanix"
ATTR_SEPARATOR = "_"

API_BASE = "/PrismGateway/services/rest/v2.0"
CLUSTER_PATH = "/cluster"
HOSTS_PATH = "/hosts"
VMS_PATH = "/vms"

DEFAULT_PAGE_SIZE = 250
MAX_PAGE_SIZE = 1000
MAX_INTERFACES = 99

DIGITS = "0123456789"

# Microseconds since the epoch. Nutanix reports boot time in microseconds, not
# the milliseconds most APIs use, so the wrong divisor puts every host tens of
# thousands of years in the future.
USECS_PER_SECOND = 1000000

# hypervisor_type is a small enum. kKvm is AHV; the other two appear on
# clusters where Nutanix provides storage under a third-party hypervisor.
HYPERVISOR_TYPES = {
    "kKvm": "Nutanix AHV",
    "kVMware": "VMware ESXi",
    "kHyperv": "Microsoft Hyper-V",
}

# Host fields copied verbatim onto every node asset. This deliberately includes
# the Controller VM and IPMI addresses that are NOT attached as interfaces, so
# an operator can still see them.
HOST_ATTRS = [
    "bios_version", "block_model", "block_serial", "boot_time",
    "boot_time_in_usecs", "cluster_uuid", "controller_vm_backplane_ip",
    "cpu_frequency_in_hz", "cpu_model", "default_vhd_container_uuid",
    "failover_cluster_fqdn", "failover_cluster_node_state", "host_maintenance_mode",
    "host_nic_ids", "host_type", "hypervisor_address", "hypervisor_full_name",
    "hypervisor_key", "hypervisor_state", "hypervisor_type", "hypervisor_username",
    "ipmi_address", "ipmi_username", "is_degraded", "is_hardware_virtualized",
    "is_secure_booted", "management_server_name", "memory_capacity_in_bytes",
    "metadata_store_status", "monitored", "name", "num_cpu_cores",
    "num_cpu_sockets", "num_cpu_threads", "num_vms", "oplog_disk_pct",
    "oplog_disk_size", "position", "power_state", "rdma_backplane_ips",
    "reboot_pending", "serial", "service_vmexternal_ip", "service_vmid",
    "service_vmnat_ip", "service_vmnat_port", "state", "uuid", "vzone_name",
]

# VM fields copied verbatim onto every guest asset. guest_os and the Nutanix
# Guest Tools fields are carried through but are deliberately not mapped to the
# asset's os field: they are only populated when NGT is installed, and the
# value format is not published, so guessing at it would put an unreliable
# string into a field runZero search treats as authoritative.
VM_ATTRS = [
    "allow_live_migrate", "description", "gpus_assigned", "guest_driver_version",
    "guest_os", "ha_priority", "host_uuid", "machine_type", "memory_mb", "name",
    "num_cores_per_vcpu", "num_vcpus", "power_state", "timezone",
    "tools_running_status", "uuid", "vm_logical_timestamp",
]

def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    if value == None:
        return ""
    if type(value) == "list":
        return ",".join([_clean(item) for item in value if item != None])
    if type(value) == "dict":
        return ""
    return str(value).strip()

def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is neither."""
    if type(value) == "int":
        return value
    if type(value) == "float":
        return int(value)
    text = _clean(value)
    if not text or len(text) > 19:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)
def _routable_ips(values):
    """Filter a list of candidate addresses down to routable, de-duplicated ones."""
    kept = []
    seen = {}
    for value in values:
        canonical = routable_ip(value)
        if not canonical or canonical in seen:
            continue
        seen[canonical] = True
        kept.append(canonical)
    return kept

def _boot_time(record, ceiling):
    """Return the node's boot time as a normalized string, or "".

    boot_time_in_usecs is MICROseconds since the epoch, which is the trap in
    this field: reading it as seconds or milliseconds places the value tens of
    thousands of years ahead. The result is clamped to the current time because
    runZero fails an entire ImportAsset whose timestamps are in the future, and
    a cluster with a skewed clock should cost a field rather than an asset.
    """
    usecs = _to_int(record.get("boot_time_in_usecs"))
    if usecs <= 0:
        return ""
    parsed = from_timestamp(usecs // USECS_PER_SECOND)
    if parsed.unix > ceiling.unix:
        parsed = ceiling
    return parsed.format("2006-01-02T15:04:05Z07:00")

def _pick(record, names):
    """Return the first non-empty value among several candidate field names."""
    for name in names:
        value = _clean(record.get(name))
        if value:
            return value
    return ""

def _attrs(record, names, extra):
    """Collect the documented fields plus computed extras into one flat dict."""
    attrs = {}
    for name in names:
        if name in record:
            attrs[name] = record.get(name)
    for key in extra:
        attrs[key] = extra[key]
    return attrs

def split_hypervisor(record):
    """Split hypervisor_full_name into an OS name and a version.

    The field reads "Nutanix 20190916.321" on AHV. Only a trailing token that
    actually looks like a version is taken as one; anything else is left whole
    as the OS name rather than guessed apart.
    """
    hv_type = _clean(record.get("hypervisor_type"))
    full = _clean(record.get("hypervisor_full_name"))
    named = HYPERVISOR_TYPES.get(hv_type, "")
    if not full:
        return named, ""

    parts = full.split(" ")
    tail = parts[-1] if len(parts) > 1 else ""
    if tail and tail[0] in DIGITS:
        head = " ".join(parts[:-1])
        return named or head, tail
    return named or full, ""

def build_host_asset(ctx, record):
    """Build one ImportAsset for a physical Nutanix node, or None to skip it."""
    if type(record) != "dict":
        print("nutanix-prism: skipping a host entry that is not an object")
        return None

    uuid = _clean(record.get("uuid"))
    if not uuid:
        print("nutanix-prism: skipping host with no uuid: name=" + _clean(record.get("name")))
        return None

    # Only the node's own interfaces. hypervisor_address is the AHV host's
    # management address and backplane_ip is its address on a segmented
    # backplane network when network segmentation is enabled.
    #
    # Everything else in the record that looks like an address is deliberately
    # left off and kept as a custom attribute instead:
    #   service_vmexternal_ip / service_vmnat_ip / controller_vm_backplane_ip
    #     belong to the Controller VM, which is a separate guest with its own
    #     OS, hostname, and MAC. runZero scans it as its own asset, so claiming
    #     its address here would merge the CVM into the hypervisor.
    #   ipmi_address is the node's BMC. It is the same piece of hardware but a
    #     separate network endpoint with its own MAC and firmware, and runZero
    #     fingerprints BMCs as their own assets, so claiming it here would merge
    #     the BMC into the hypervisor.
    #   management_server_name and hypervisor_key repeat an address that is
    #     already covered, or name a third-party management server.
    ips = _routable_ips([record.get("hypervisor_address"), record.get("backplane_ip")])
    nic = network_interface(ips=ips) if ips else None
    netifs = [nic] if nic else []

    os_name, os_version = split_hypervisor(record)
    boot_time = _boot_time(record, ctx["now"])

    tags = [VENDOR, "hypervisor", "cluster:" + ctx["cluster_name"]]
    state = _clean(record.get("state"))
    if state:
        tags.append("state:" + state)

    attrs = _attrs(record, HOST_ATTRS, {
        "asset_kind": "host",
        "cluster_name": ctx["cluster_name"],
        "cluster_scope_uuid": ctx["cluster_uuid"],
        "boot_time_normalized": boot_time,
        # Recorded so it is obvious which addresses were seen but deliberately
        # not attached to an interface.
        "addresses_not_imported": ",".join([
            _clean(record.get("ipmi_address")),
            _clean(record.get("service_vmexternal_ip")),
            _clean(record.get("service_vmnat_ip")),
            _clean(record.get("controller_vm_backplane_ip")),
        ]),
    })

    asset = ImportAsset(
        id="{}:{}:host:{}".format(VENDOR, ctx["cluster_uuid"], uuid),
        hostnames=[_clean(record.get("name"))],
        networkInterfaces=netifs,
        os=os_name,
        osVersion=os_version,
        manufacturer="Nutanix",
        model=_pick(record, ["block_model"]),
        deviceType="Hypervisor",
        tags=tags,
        # matchBehavior is deliberately left at the default, with all eight
        # flags on. The node's uuid is one row per physical node, its
        # hypervisor_address is a static management address rather than a DHCP
        # lease, and its name is the cluster-assigned NTNX-<block>-<position>
        # label that AHV also reports as its own hostname, so there is no churn
        # here for a relaxed break flag to defend against. Leaving the breaks on
        # keeps their protection on the first-contact path, where this record
        # merges into an already-scanned asset by IP or hostname and where the
        # neighbours it could be confused with -- the Controller VM and the BMC
        # sharing this node -- are exactly the things a disagreeing MAC or
        # hostname should be allowed to veto.
        assetType="host",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )
    asset.lastSeenTS = ctx["now"]
    return asset

def build_host_assets(ctx, records):
    """Build node assets for one page of hosts, skipping unusable rows."""
    assets = []
    for record in records:
        asset = build_host_asset(ctx, record)
        if asset:
            assets.append(asset)
    return assets

def build_vm_interfaces(record):
    """Build one network interface per virtual NIC.

    The MAC is the durable half of a guest's identity here: Nutanix assigns it
    when the NIC is created and it survives migration, rename, and power
    cycling. The addresses are learned by the hypervisor, so a powered-off or
    quiet guest contributes a MAC and no address at all.
    """
    nics = record.get("vm_nics")
    if type(nics) != "list":
        return []

    netifs = []
    for entry in nics:
        if type(entry) != "dict":
            continue
        mac = _pick(entry, ["mac_address", "macAddress"])

        # ip_address is the singular observed address and ip_addresses is the
        # list form; both are declared on the NIC schema and either may be
        # populated. requested_ip_address is deliberately NOT read: it is the
        # address asked of AHV IPAM, not one the hypervisor observed, so it can
        # name an address the guest never took.
        candidates = []
        listed = entry.get("ip_addresses")
        if type(listed) == "list":
            candidates.extend(listed)
        value = _clean(entry.get("ip_address"))
        if value:
            candidates.append(value)
        ips = _routable_ips(candidates)

        if not mac and not ips:
            continue
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)
    return netifs[:MAX_INTERFACES]

def build_vm_asset(ctx, record):
    """Build one ImportAsset for a guest VM, or None to skip it."""
    if type(record) != "dict":
        print("nutanix-prism: skipping a VM entry that is not an object")
        return None

    uuid = _clean(record.get("uuid"))
    if not uuid:
        print("nutanix-prism: skipping VM with no uuid: name=" + _clean(record.get("name")))
        return None

    netifs = build_vm_interfaces(record)

    tags = [VENDOR, "vm", "cluster:" + ctx["cluster_name"]]
    power = _clean(record.get("power_state"))
    if power:
        tags.append("power:" + power)

    # host_uuid is recorded as an attribute so an operator can see where a guest
    # is running, but it is deliberately absent from the asset id -- see below.
    attrs = _attrs(record, VM_ATTRS, {
        "asset_kind": "vm",
        "cluster_name": ctx["cluster_name"],
        "cluster_scope_uuid": ctx["cluster_uuid"],
        "host_name": ctx["host_names"].get(_clean(record.get("host_uuid")), ""),
        "nic_count": len(netifs),
    })

    asset = ImportAsset(
        # The id is namespaced by cluster and carries a "vm" infix so a guest
        # can never collide with a node, and it contains NO reference to the
        # host the guest currently runs on. A live migration moves host_uuid and
        # must not mint a second asset.
        id="{}:{}:vm:{}".format(VENDOR, ctx["cluster_uuid"], uuid),
        hostnames=[_clean(record.get("name"))],
        networkInterfaces=netifs,
        manufacturer="Nutanix",
        deviceType="Virtual Machine",
        tags=tags,
        assetType="vm",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )
    asset.lastSeenTS = ctx["now"]
    return asset

def build_vm_assets(ctx, records):
    """Build guest assets for one page of VMs, skipping unusable rows."""
    assets = []
    for record in records:
        asset = build_vm_asset(ctx, record)
        if asset:
            assets.append(asset)
    return assets

def _entities(data):
    """Return the entity list out of a Prism paged envelope, or None."""
    if type(data) != "dict":
        return None
    entities = data.get("entities")
    if type(entities) != "list":
        return None
    return entities

def _total(data):
    """Return the entity total a Prism envelope advertises, or -1."""
    if type(data) != "dict":
        return -1
    metadata = data.get("metadata")
    if type(metadata) != "dict":
        return -1
    for name in ["grand_total_entities", "total_entities"]:
        total = _to_int(metadata.get(name))
        if total >= 0:
            return total
    return -1

def _auth_failure(err):
    """Report whether an error string is Prism rejecting the credential."""
    return err.startswith("status 401") or err.startswith("status 403")

def fetch_cluster(ctx):
    """Fetch the cluster record and record its uuid as the identity namespace.

    This has to succeed. Prism Element answers on the cluster virtual IP and on
    every Controller VM address, so the configured hostname is not a stable
    name for the cluster -- pointing the integration at a different CVM in the
    same cluster would mint a second copy of the whole estate under a different
    namespace. The cluster uuid is the only scope that survives that, and guest
    records carry no cluster field of their own, so there is nothing to fall
    back to.
    """
    data, err = get_json(ctx["base_url"] + API_BASE + CLUSTER_PATH, **ctx["http_options"])
    if err:
        # The cluster uuid scopes every asset id, so there is nothing to fall
        # back to and no partial run worth reporting.
        if _auth_failure(err):
            fail("nutanix-prism: authentication rejected, check the username and password: {}".format(err))
        fail("nutanix-prism: failed to fetch the cluster record: {}".format(err))
    data = data or {}
    if type(data) != "dict":
        print("nutanix-prism: unexpected cluster response shape")
        return False

    cluster_uuid = _pick(data, ["uuid", "cluster_uuid"])
    if not cluster_uuid:
        print("nutanix-prism: the cluster record carries no uuid, cannot namespace asset ids")
        return False

    ctx["cluster_uuid"] = cluster_uuid
    # The cluster's display name is "name"; there is no "cluster_name" field.
    ctx["cluster_name"] = _clean(data.get("name")) or cluster_uuid
    print("nutanix-prism: cluster {} ({}) running {}".format(
        ctx["cluster_name"], cluster_uuid, _clean(data.get("version"))))
    return True

def fetch_and_report_hosts(ctx):
    """Fetch and stream nodes one page at a time.

    The hosts listing pages with count and page, both 1-based, which is a
    different vocabulary from the VMs listing. They are always sent as a pair:
    neither carries a documented default, so a page number without a page size
    has no defined meaning. Whether Prism actually rejects that combination is
    unverified, and sending both makes the question moot.
    """
    reported = 0
    total = -1
    prev_signature = None
    _pager1 = pager("nutanix-prism-1")
    while _pager1.next():
        page = _pager1.page
        data, err = get_json(ctx["base_url"] + API_BASE + HOSTS_PATH,
                             params={"count": ctx["page_size"], "page": page},
                             **ctx["http_options"])
        if err:
            if _auth_failure(err):
                print("nutanix-prism: authentication rejected while fetching hosts:", err)
            else:
                print("nutanix-prism: failed to fetch hosts on page {}: {}".format(page, err))
            return reported
        data = data or {}
        entities = _entities(data)
        if entities == None:
            print("nutanix-prism: stopping hosts, no entity list on page", page)
            return reported
        if not entities:
            break

        # A Prism build that honors `count` but ignores `page` answers every
        # request with the same first page, and the loop's other exits (a
        # short or empty page) never fire. Stop on the first replay, BEFORE
        # reporting, so the page is not imported twice.
        first = entities[0] if type(entities[0]) == "dict" else {}
        signature = (len(entities), _clean(first.get("uuid")))
        if signature == prev_signature:
            print("nutanix-prism: hosts listing repeated page {}; stopping to avoid re-importing".format(page))
            break
        prev_signature = signature

        if total < 0:
            total = _total(data)
            if total > 0:
                print("nutanix-prism: {} hosts reported by the cluster".format(total))

        # Remember each node's name so a guest can record the node it runs on
        # without that name ever reaching the guest's identity.
        for record in entities:
            if type(record) == "dict":
                uuid = _clean(record.get("uuid"))
                if uuid:
                    ctx["host_names"][uuid] = _clean(record.get("name"))

        reported += report_assets(build_host_assets(ctx, entities))
        if len(entities) < ctx["page_size"]:
            break

    print("nutanix-prism: reported {} hypervisor nodes".format(reported))
    return reported

def fetch_and_report_vms(ctx):
    """Fetch and stream guests one page at a time.

    The VMs listing pages with offset and length -- a different convention from
    the hosts listing, which uses count and page. include_vm_nic_config is what
    makes Prism return the vm_nics array; without it every guest comes back with
    no MAC and no address at all.
    """
    reported = 0
    offset = 0
    total = -1
    _pager2 = pager("nutanix-prism-2")
    while _pager2.next():
        data, err = get_json(ctx["base_url"] + API_BASE + VMS_PATH,
                             params={"offset": offset, "length": ctx["page_size"],
                                     "include_vm_nic_config": "true"},
                             **ctx["http_options"])
        if err:
            if _auth_failure(err):
                print("nutanix-prism: authentication rejected while fetching VMs:", err)
            else:
                print("nutanix-prism: failed to fetch VMs at offset {}: {}".format(offset, err))
            return reported
        data = data or {}
        entities = _entities(data)
        if entities == None:
            print("nutanix-prism: stopping VMs, no entity list at offset", offset)
            return reported
        if not entities:
            break

        if total < 0:
            total = _total(data)
            if total > 0:
                print("nutanix-prism: {} VMs reported by the cluster".format(total))

        reported += report_assets(build_vm_assets(ctx, entities))
        if len(entities) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    print("nutanix-prism: reported {} guest VMs".format(reported))
    return reported

def main(**kwargs):
    require(kwargs, "url", "username", "password")
    base_url = get_url_base(kwargs)
    if not base_url:
        fail("nutanix-prism: could not determine the Prism Element URL")

    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    ctx = {
        "base_url": base_url,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
            "Authorization": basic(get_string(kwargs, "username"),
                                   get_string(kwargs, "password")),
        }),
        "now": now(),
        "page_size": page_size,
        "cluster_uuid": "",
        "cluster_name": "",
        "host_names": {},
    }

    if not fetch_cluster(ctx):
        return None

    reported = fetch_and_report_hosts(ctx)
    if get_bool(kwargs, "import_vms", default=True):
        reported += fetch_and_report_vms(ctx)

    if not reported:
        print("nutanix-prism: no assets retrieved")
    return None

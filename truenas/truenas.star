# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-truenas",
    "name": "TrueNAS",
    "type": "inbound",
    "description": "Imports the TrueNAS system, its virtual machines, and its applications over the v2.0 REST API. The REST API is deprecated in 25.04 and removed in TrueNAS 26, where this integration cannot collect anything; see the README.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # A 'vm' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'vm': "no-id-match no-id-break",
    },
    # Backstop for the pager() guard on collection paging; the max_records cap
    # is the working bound, this exists so a server that ignores limit/offset
    # cannot spin a run forever.
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "TrueNAS URL",
            "type": "url",
            "required": True,
            "placeholder": "https://truenas.example.com",
            "description": "Base URL of the TrueNAS web interface. The /api/v2.0/ path is appended automatically.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "TrueNAS API key, created under Credentials > Local Users > API Keys (25.04 and later) or the top bar API Keys dialog (24.10 and earlier). Sent as a bearer token.",
        },
        {
            "key": "collect_vms",
            "label": "Collect virtual machines",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import each VM as its own asset, with the MAC of every virtual NIC attached to it.",
        },
        {
            "key": "collect_apps",
            "label": "Collect applications",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import applications as software and published ports as services on the TrueNAS asset. Apps share the host's network stack, so they are not imported as separate devices.",
        },
        {
            "key": "collect_storage",
            "label": "Collect pools and disks",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Summarize pools and physical disks onto the TrueNAS asset, including disk models and serials.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Records requested per page from collection endpoints, sent as the documented limit query parameter.",
        },
        {
            "key": "max_records",
            "label": "Maximum records per collection",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on the number of rows read from any one collection endpoint. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "Service", "ServiceProtocolData", "Software", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", "get_json", "bearer", "url_parse")
load("kwargs", "get_url_base", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_text', 'dicts')
VENDOR = "truenas"
ATTR_PREFIX = "truenas"
ATTR_SEPARATOR = "_"

API_BASE = "/api/v2.0"

# The platform caps each child collection at 99 per asset and rejects the record
# above it.
CHILD_CAP = 99

HEXDIGITS = "0123456789abcdef"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-", "truenas.local"]

# Interface names that belong to container and guest plumbing rather than to the
# NAS. Bridges are deliberately absent: a TrueNAS host that runs VMs usually
# carries its own address on br0, so filtering "br" would discard the only
# address the system has.
VIRTUAL_INTERFACE_PREFIXES = [
    "lo", "docker", "veth", "vnet", "kube-", "cni", "flannel", "cali",
    "tun", "tap", "wg", "zt", "virbr", "ix-",
]

# system_serial is copied from SMBIOS, and a self-built NAS - which is most of
# them - reports one of these placeholders rather than a serial.
PLACEHOLDER_SERIALS = [
    "to be filled by o.e.m.", "system serial number", "default string",
    "0123456789", "none", "n/a", "na", "not specified", "not applicable",
    "unknown", "chassis serial number", "0", "123456789",
]
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    normalize_mac is not used because it clears the locally administered bit,
    and every MAC TrueNAS generates for a virtual NIC sets that bit - two guests
    would otherwise be able to collide on one normalized value.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    if int(text[0:2], 16) % 2 == 1:
        return ""
    if text == "000000000000" or text == "ffffffffffff":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    """Return a usable hostname, or "" for a placeholder or a bare address."""
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text

def _dns_name(value):
    """Return a value only when it is shaped like a DNS name.

    A VM's name is an operator-chosen label - "Windows 11 Desktop" is as valid
    to TrueNAS as "ubuntu-server" - and importing free text as a hostname would
    invite runZero to correlate two unrelated guests that happen to share it.
    """
    text = _hostname(value)
    if not text:
        return ""
    if text.startswith(".") or text.startswith("-") or text.endswith("-"):
        return ""
    # Starlark strings are not iterable; elems() is the only way to walk one.
    for character in text.elems():
        if character in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-.":
            continue
        return ""
    return text

def _serial(value):
    """Return a chassis serial worth recording, or "" for an SMBIOS placeholder."""
    text = as_text(value, join=",").strip()
    if not text or text.lower() in PLACEHOLDER_SERIALS:
        return ""
    return text

def _is_virtual_interface(name):
    """Report whether an interface name belongs to container or guest plumbing."""
    lowered = as_text(name, join=",").strip().lower()
    if not lowered:
        return True
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix):
            rest = lowered[len(prefix):]
            if not rest:
                return True
            if rest[0] in "0123456789-_.":
                return True
    return False

def _appliance_host(base_url):
    """Return the TrueNAS hostname from the configured URL, which scopes every
    imported id. The scheme and port are dropped so that reaching the same
    system on a different port does not change the identity of its assets."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]

def _version(raw):
    """Normalize the version reported by system/info.

    25.04 and later report the short form, "25.10.6". Earlier SCALE releases and
    CORE report the branded train name, "TrueNAS-SCALE-24.04.2.2" or
    "TrueNAS-13.0-U6.1", so a known brand prefix is stripped and anything else is
    returned whole rather than guessed at.
    """
    text = as_text(raw, join=",").strip()
    if not text:
        return ""
    for prefix in ["TrueNAS-SCALE-", "TrueNAS-CORE-", "TrueNAS-", "FreeNAS-"]:
        if text.startswith(prefix):
            return text[len(prefix):]
    return text

def _major(version):
    """Return the leading major version as an int, or 0 when it is not numeric."""
    head = as_text(version, join=",").split(".")[0].split("-")[0].strip()
    if not head:
        return 0
    # Starlark strings are not iterable; elems() is the only way to walk one.
    for character in head.elems():
        if character not in "0123456789":
            return 0
    return int(head)

def fetch(ctx, path, params):
    """Call one TrueNAS endpoint. Failures are reported and returned as None so
    an endpoint missing on this release cannot end the run."""
    url = ctx["base_url"] + API_BASE + path
    if params:
        data, err = get_json(url, params=params, **ctx["http_options"])
    else:
        data, err = get_json(url, **ctx["http_options"])
    if err:
        print("truenas: {} failed: {}".format(path, err))
        return None
    return data

def fetch_collection(ctx, path):
    """Read a whole collection endpoint through its documented limit and offset
    query parameters, stopping at the configured record cap.

    TrueNAS returns a bare JSON array and no total, so a short page is the only
    end-of-collection signal. The cap exists because a system with thousands of
    disks would otherwise be read in full before anything is emitted.

    The loop is guarded by pager(): a server that ignores limit/offset and
    keeps answering full pages raises with the collection's label rather than
    ending silently at an arbitrary bound.
    """
    page_size = ctx["page_size"]
    limit = ctx["max_records"]
    rows = []
    p = pager("collection " + path)
    while p.next():
        offset = len(rows)
        if limit and offset >= limit:
            print("truenas: record cap of {} reached for {}".format(limit, path))
            break
        want = page_size
        if limit and offset + want > limit:
            want = limit - offset
        data = fetch(ctx, path, {"limit": want, "offset": offset})
        if data == None:
            if not rows:
                return None
            break
        if type(data) != "list":
            print("truenas: {} returned {} where a list was expected".format(path, type(data)))
            if not rows:
                return None
            break
        page = dicts(data)
        rows.extend(page)
        if len(data) < want:
            break
    return rows

def collect_interfaces(ctx):
    """Return the NAS's own interfaces as (NetworkInterface list, names, macs).

    interface.query reports each interface as {id, name, type, state}, with the
    live addresses under state.aliases as {type: INET|INET6|LINK, address,
    netmask}. The LINK alias repeats state.link_address, which is the MAC.
    """
    rows = fetch(ctx, "/interface", None)
    if type(rows) != "list":
        return [], [], []

    netifs = []
    names = []
    macs = []
    for entry in dicts(rows):
        name = as_text(entry.get("name"), join=",") or as_text(entry.get("id"), join=",")
        if _is_virtual_interface(name):
            continue
        state = entry.get("state")
        mac = ""
        ips = []
        aliases = []
        if type(state) == "dict":
            mac = _mac_key(state.get("link_address")) or _mac_key(state.get("permanent_link_address"))
            aliases = dicts(state.get("aliases"))
        # A configured-but-not-yet-applied interface carries its addresses only
        # in the top-level aliases array, so both are read.
        aliases = aliases + dicts(entry.get("aliases"))
        for alias in aliases:
            kind = as_text(alias.get("type"), join=",").upper()
            if kind == "LINK":
                if not mac:
                    mac = _mac_key(alias.get("address"))
                continue
            routable = routable_ip(alias.get("address"))
            if routable and routable not in ips:
                ips.append(routable)
        if not mac and not ips:
            continue
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)
            names.append(name)
            if mac and mac not in macs:
                macs.append(mac)
    return netifs, names, macs

def build_app_children(ctx, address):
    """Turn the application list into software and services for the NAS asset.

    An application on TrueNAS runs in the host's network namespace or behind a
    published host port; it has no address, no MAC, and no hostname of its own.
    Emitting one as a device would either create an asset with no correlator or
    give a second asset the NAS's address, so applications are imported as what
    they are: software installed on the NAS, and listening ports on it.
    """
    rows = fetch_collection(ctx, "/app")
    if rows == None:
        # /app is the Docker-based app catalog on SCALE 24.04 and later. The
        # Kubernetes-era catalog it replaced lived at chart/release and was
        # removed in 24.10, so it is tried only as a fallback. CORE has neither,
        # and both failing there is a normal outcome rather than an error.
        rows = fetch_collection(ctx, "/chart/release")
    if rows == None:
        print("truenas: no application catalog endpoint answered; this is expected on TrueNAS CORE")
        return [], [], []

    software = []
    services = []
    names = []
    for entry in rows:
        name = as_text(entry.get("name"), join=",") or as_text(entry.get("id"), join=",")
        if not name:
            continue
        names.append(name)
        version = as_text(entry.get("human_version"), join=",") or as_text(entry.get("version"), join=",")
        metadata = entry.get("metadata")
        vendor = ""
        if type(metadata) == "dict":
            vendor = as_text(metadata.get("title"), join=",") or as_text(metadata.get("train"), join=",")
        if len(software) < CHILD_CAP:
            software.append(Software(
                id="{}:{}:app:{}".format(VENDOR, ctx["scope"], name),
                product=name,
                version=version,
                vendor=vendor,
                customAttributes=to_custom_attributes({
                    "state": entry.get("state") or entry.get("status"),
                    "upgrade_available": entry.get("upgrade_available"),
                    "custom_app": entry.get("custom_app"),
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            ))

        if not address:
            continue
        workloads = entry.get("active_workloads")
        if type(workloads) != "dict":
            continue
        for port in dicts(workloads.get("used_ports")):
            transport = as_text(port.get("protocol"), join=",").lower() or "tcp"
            for host_port in dicts(port.get("host_ports")):
                number = host_port.get("host_port")
                if type(number) != "int" or number < 1 or number > 65535:
                    continue
                if len(services) >= CHILD_CAP:
                    break
                services.append(Service(
                    address=address,
                    port=number,
                    transport=transport,
                    product=name,
                    version=version,
                    protocolData=[ServiceProtocolData(name="truenas-app", attributes={
                        "app": name,
                        "container_port": as_text(port.get("container_port"), join=","),
                    })],
                ))
    return software, services, names

def collect_storage(ctx):
    """Summarize pools and disks onto the NAS asset.

    A disk is not a device runZero can scan, so the disks are folded into
    attributes rather than emitted. Serials and models are the part worth
    keeping: they are what tie a chassis to a purchase record.
    """
    attrs = {}
    pools = fetch_collection(ctx, "/pool")
    if pools != None:
        names = []
        statuses = []
        for entry in pools:
            name = as_text(entry.get("name"), join=",")
            if not name:
                continue
            names.append(name)
            statuses.append("{}={}".format(name, as_text(entry.get("status"), join=",")))
        attrs["pools"] = names
        attrs["pool_status"] = statuses
        attrs["pool_count"] = len(names)

    disks = fetch_collection(ctx, "/disk")
    if disks != None:
        models = []
        serials = []
        for entry in disks:
            model = as_text(entry.get("model"), join=",").strip()
            if model and model not in models:
                models.append(model)
            serial = _serial(entry.get("serial"))
            if serial and serial not in serials:
                serials.append(serial)
        attrs["disk_count"] = len(disks)
        attrs["disk_models"] = models
        attrs["disk_serials"] = serials
    return attrs

def build_system_asset(ctx, info, network):
    """Build the asset for the TrueNAS system itself."""
    netifs, interface_names, macs = collect_interfaces(ctx)

    address = ""
    for nic in netifs:
        for candidate in nic.ipv4Addresses:
            if candidate:
                address = str(candidate)
                break
        if address:
            break

    fqdn = ""
    domain = ""
    if type(network) == "dict":
        fqdn = as_text(network.get("hostname"), join=",").strip()
        domain = as_text(network.get("domain"), join=",").strip()
    if not fqdn and type(info) == "dict":
        fqdn = as_text(info.get("hostname"), join=",").strip()

    hostname = _hostname(fqdn)
    if hostname and "." in hostname:
        short = hostname.split(".")[0]
        if not domain:
            domain = hostname[len(short) + 1:]
        hostname = short

    version = ""
    attrs = {"appliance": ctx["scope"]}
    if type(info) == "dict":
        version = _version(info.get("version"))
        attrs["version"] = info.get("version")
        attrs["system_product"] = info.get("system_product")
        attrs["system_manufacturer"] = info.get("system_manufacturer")
        attrs["cpu_model"] = info.get("model")
        attrs["cores"] = info.get("cores")
        attrs["physical_cores"] = info.get("physical_cores")
        attrs["physmem"] = info.get("physmem")
        attrs["ecc_memory"] = info.get("ecc_memory")
        attrs["timezone"] = info.get("timezone")
        attrs["uptime_seconds"] = info.get("uptime_seconds")
        attrs["license"] = "present" if info.get("license") else "absent"
    attrs["interfaces"] = interface_names
    attrs["interface_count"] = len(interface_names)

    serial = ""
    if type(info) == "dict":
        serial = _serial(info.get("system_serial"))
        if serial:
            attrs["system_serial"] = serial

    if ctx["collect_storage"]:
        for key, value in collect_storage(ctx).items():
            attrs[key] = value

    software = []
    services = []
    if ctx["collect_apps"]:
        software, services, app_names = build_app_children(ctx, address)
        attrs["apps"] = app_names
        attrs["app_count"] = len(app_names)

    params = {
        # TrueNAS publishes no identifier for the system that survives a
        # reinstall: system_serial is SMBIOS data and is a placeholder on most
        # self-built systems, and the middleware's own ids are per-object. The
        # host in the configured URL is therefore the scope, and it is stable
        # for a fixed credential. The interface MACs, the addresses, and the
        # hostname are what let this merge with an asset runZero scanned, so
        # none of them may disqualify that merge.
        "id": "{}:{}:system".format(VENDOR, ctx["scope"]),
        "hostnames": [hostname] if hostname else [],
        "domain": domain,
        "networkInterfaces": netifs,
        "os": "TrueNAS",
        "deviceType": "Storage",
        "manufacturer": as_text(info.get("system_manufacturer"), join=",") if type(info) == "dict" else "",
        "model": as_text(info.get("system_product"), join=",") if type(info) == "dict" else "",
        "tags": [VENDOR, "nas"],
        "assetType": "system",
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if version:
        params["osVersion"] = version
    if software:
        params["software"] = software[:CHILD_CAP]
    if services:
        params["services"] = services[:CHILD_CAP]
    return ImportAsset(**params), macs

def _nic_mac(device):
    """Return the MAC of a VM device row when it is a NIC, else "".

    A device is {id, vm, order, attributes}. The discriminator moved: it used to
    be a top-level dtype key and is now attributes.dtype, so both are read.
    """
    if type(device) != "dict":
        return ""
    attributes = device.get("attributes")
    if type(attributes) != "dict":
        return ""
    dtype = as_text(device.get("dtype"), join=",") or as_text(attributes.get("dtype"), join=",")
    if dtype.upper() != "NIC":
        return ""
    return _mac_key(attributes.get("mac"))

def _vm_device_macs(ctx):
    """Index virtual NIC MACs by the VM they are attached to.

    Only called when the inline devices array on the VM rows yielded nothing,
    because current releases embed the device list on the VM itself and the
    extra request would be wasted.
    """
    index = {}
    rows = fetch_collection(ctx, "/vm/device")
    if rows == None:
        return index
    for entry in rows:
        mac = _nic_mac(entry)
        if not mac:
            continue
        owner = as_text(entry.get("vm"), join=",")
        if not owner:
            continue
        if owner not in index:
            index[owner] = []
        if mac not in index[owner]:
            index[owner].append(mac)
    return index

def _vm_inline_macs(entry):
    """Return the NIC MACs embedded on one VM row."""
    macs = []
    for device in dicts(entry.get("devices")):
        mac = _nic_mac(device)
        if mac and mac not in macs:
            macs.append(mac)
    return macs

def build_vm_asset(ctx, entry, macs):
    """Convert one VM row into a runZero asset, or None when it has no id."""
    vm_id = as_text(entry.get("id"), join=",").strip()
    name = as_text(entry.get("name"), join=",").strip()
    if not vm_id:
        print("truenas: skipping VM with no id: name={}".format(name))
        return None

    netifs = []
    for mac in macs:
        nic = network_interface(mac=mac, ips=[])
        if nic:
            netifs.append(nic)

    hostname = _dns_name(name)
    if not netifs and not hostname:
        print("truenas: skipping VM {} with no MAC and no usable name".format(vm_id))
        return None

    status = entry.get("status")
    state = ""
    if type(status) == "dict":
        state = as_text(status.get("state"), join=",")

    attrs = {
        "appliance": ctx["scope"],
        "vm_id": vm_id,
        "vm_name": name,
        "vm_uuid": entry.get("uuid"),
        "vm_state": state,
        "vm_autostart": entry.get("autostart"),
        "vm_vcpus": entry.get("vcpus"),
        "vm_cores": entry.get("cores"),
        "vm_threads": entry.get("threads"),
        "vm_memory_mib": entry.get("memory"),
        "vm_bootloader": entry.get("bootloader"),
        "vm_description": entry.get("description"),
        "vm_macs": macs,
    }

    return ImportAsset(
        # The middleware's own row id is the only identifier present on every
        # release; uuid was added later and is absent on CORE, so it is recorded
        # as an attribute rather than used as the key. The id is namespaced on
        # the NAS because it is a per-system counter.
        id="{}:{}:vm:{}".format(VENDOR, ctx["scope"], vm_id),
        hostnames=[hostname] if hostname else [],
        networkInterfaces=netifs,
        deviceType="Virtual Machine",
        tags=[VENDOR, "truenas-vm"],
        # The row id is stable for the life of the VM but means nothing outside
        # this NAS, and a deleted VM's id can be handed to a new one by the
        # middleware's own counter. Merging is left to the MAC and the name.
        assetType="vm",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )

def report_vms(ctx):
    """Stream VM assets to runZero in bounded batches."""
    rows = fetch_collection(ctx, "/vm")
    if rows == None:
        print("truenas: the VM endpoint did not answer; this release may not support VMs")
        return 0, 0

    # Current releases embed the device list on each VM. Only when no NIC turned
    # up inline is the separate device endpoint worth a request.
    inline = {}
    found_any = False
    for entry in rows:
        macs = _vm_inline_macs(entry)
        if macs:
            found_any = True
        inline[as_text(entry.get("id"), join=",").strip()] = macs
    device_macs = {}
    if rows and not found_any:
        device_macs = _vm_device_macs(ctx)

    reported = 0
    skipped = 0
    for entry in rows:
        vm_id = as_text(entry.get("id"), join=",").strip()
        macs = list(inline.get(vm_id, []))
        for mac in device_macs.get(vm_id, []):
            if mac not in macs:
                macs.append(mac)
        asset = build_vm_asset(ctx, entry, macs)
        if asset == None:
            skipped += 1
            continue
        report_asset(asset)
        reported += 1
    return reported, skipped

def main(**kwargs):
    base_url = get_url_base(kwargs)
    scope = _appliance_host(base_url)
    if not scope:
        print("truenas: could not determine the host from the configured URL")
        return None

    max_records = get_int(kwargs, "max_records", default=5000)
    if max_records < 0:
        max_records = 0

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Authorization": bearer(get_string(kwargs, "api_key")),
            "Accept": "application/json",
        }),
        "page_size": get_int(kwargs, "page_size", default=100),
        "max_records": max_records,
        "collect_apps": get_bool(kwargs, "collect_apps", default=True),
        "collect_storage": get_bool(kwargs, "collect_storage", default=True),
    }

    info = fetch(ctx, "/system/info", None)
    if info == None:
        # The REST API was deprecated in 25.04 and removed outright in TrueNAS
        # 26, where every /api/v2.0 path 404s. That is the most likely cause of
        # a total failure here, so it is named rather than left to guesswork.
        print("truenas: /api/v2.0/system/info did not answer.")
        print("truenas: check the URL and the API key, and confirm the release still serves the REST API")
        print("truenas: - the REST API was removed in TrueNAS 26 in favour of JSON-RPC 2.0 over WebSocket")
        return None
    if type(info) != "dict":
        print("truenas: /api/v2.0/system/info returned an unexpected shape; aborting")
        return None

    release = _major(_version(info.get("version")))
    if release >= 26:
        print("truenas: release {} reports a REST API that TrueNAS documents as removed;".format(release))
        print("truenas: results may be incomplete")
    elif release >= 25:
        print("truenas: the REST API is deprecated on TrueNAS {} and each poll authenticates,".format(release))
        print("truenas: which raises a daily 'Deprecated REST API usage' alert naming the Explorer's address")

    network = fetch(ctx, "/network/configuration", None)

    system, _macs = build_system_asset(ctx, info, network)
    report_assets(system)
    print("truenas: reported the system asset for {}".format(scope))

    if get_bool(kwargs, "collect_vms", default=True):
        reported, skipped = report_vms(ctx)
        print("truenas: reported {} virtual machines".format(reported))
        if skipped:
            print("truenas: {} VM rows were skipped for want of an id or a correlator".format(skipped))
    return None

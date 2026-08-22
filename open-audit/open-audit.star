# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-open-audit",
    "name": "Open-AudIT Community",
    "type": "inbound",
    "description": "Imports audited devices, their addresses, network adapters, and installed software from an Open-AudIT Community server.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "maxPages": 10001,
    "params": [
        {
            "key": "url",
            "label": "Open-AudIT server URL",
            "type": "url",
            "required": True,
            "placeholder": "https://openaudit.example.com",
            "description": "Base URL of the Open-AudIT web server, without the application path. Open-AudIT ships behind Apache on port 80/443 and is commonly reached over HTTP on a management network.",
        },
        {
            "key": "app_path",
            "label": "Application path",
            "type": "string",
            "required": False,
            "default": "/open-audit",
            "placeholder": "/open-audit",
            "description": "Path segment the Open-AudIT application is served under, before /index.php. The default installer uses /open-audit on both Linux and Windows. Set to a single / when the application is served from the web root.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Open-AudIT user with read permission on the devices collection.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the Open-AudIT user. Exchanged for a ci_session cookie at /index.php/logon and never sent again.",
        },
        {
            "key": "org_id",
            "label": "Organisation ID",
            "type": "string",
            "required": False,
            "description": "Import only devices belonging to this Open-AudIT organisation id. Leave blank to import every organisation the user can see.",
        },
        {
            "key": "include_retired",
            "label": "Include retired devices",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import devices whose status is deleted, lost, or retired. Off by default, because Open-AudIT keeps those rows so their history survives, not because the device is still on the network.",
        },
        {
            "key": "collect_interfaces",
            "label": "Collect addresses and adapters",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read each device's ip and network sub-tables for every address and MAC it holds. This is one extra request per device, so it is bounded by the detail cap below. With this off, only the single primary address on the device row is imported and no MAC is available.",
        },
        {
            "key": "collect_software",
            "label": "Collect installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Also read each device's software sub-table. Adds no requests when addresses are already being collected, but makes each response substantially larger.",
        },
        {
            "key": "max_detail_devices",
            "label": "Detail request cap",
            "type": "int",
            "required": False,
            "default": 2000,
            "min": 0,
            "max": 100000,
            "description": "Stop issuing per-device detail requests after this many devices. Devices past the cap are still imported from the collection response; only their extra addresses, MACs, and software are missing.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 10000,
            "description": "Number of devices requested per collection page.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'ip_address', 'ip_in_network', 'routable_ip')
load('http', 'get_json', 'url_encode', 'url_parse')
load('kwargs', 'get_string', 'get_http_options', 'get_bool', 'get_int')
load('requests', 'Session')
load('time', 'now', 'parse_time', 'parse_ts')

load('coerce', 'as_text', 'dicts')
VENDOR = "open-audit"
MANUFACTURER = "FirstWave"

DEFAULT_APP_PATH = "/open-audit"
DEFAULT_PAGE_SIZE = 500
DEFAULT_MAX_DETAIL = 2000

LOGON_PATH = "/index.php/logon"
DEVICES_PATH = "/index.php/devices"

# CodeIgniter's session cookie. Open-AudIT does not rename it, and the
# application has no bearer-token mode: /index.php/logon answers with
# Set-Cookie and every later call is authenticated by that cookie alone.
SESSION_COOKIE = "ci_session"

# Columns requested from the devices collection. Open-AudIT drops any property
# that is not a column on the target install rather than erroring, so naming a
# field a 4.x server does not have is safe. This is the server's own documented
# default list plus the hardware and lifecycle fields runZero can use.
DEVICE_PROPERTIES = ",".join([
    "devices.id", "devices.uuid", "devices.name", "devices.ip",
    "devices.hostname", "devices.dns_hostname", "devices.domain",
    "devices.dns_domain", "devices.fqdn", "devices.dns_fqdn",
    "devices.description", "devices.type", "devices.class",
    "devices.os_group", "devices.os_family", "devices.os_name",
    "devices.os_version", "devices.os_display_version", "devices.os_arch",
    "devices.kernel_version", "devices.manufacturer", "devices.model",
    "devices.serial", "devices.service_tag", "devices.form_factor",
    "devices.status", "devices.environment", "devices.function",
    "devices.org_id", "devices.location_id", "devices.memory_count",
    "devices.processor_count", "devices.uptime", "devices.asset_number",
    "devices.vm_vendor", "devices.vm_server_name", "devices.cluster_name",
    "devices.snmp_oid", "devices.sysDescr", "devices.sysObjectID",
    "devices.sysContact", "devices.sysName", "devices.sysLocation",
    "devices.snmp_enterprise_name", "devices.first_seen", "devices.last_seen",
    "devices.last_seen_by", "devices.instance_provider", "devices.instance_ident",
])

# Sub-tables joined onto a device by the read endpoint's include parameter.
# Every one of these is a real table with a device_id foreign key.
INCLUDE_INTERFACES = ["ip", "network"]
INCLUDE_SOFTWARE = ["software"]

# Statuses Open-AudIT itself treats as "not on the network any more".
RETIRED_STATUSES = ["deleted", "lost", "retired"]

# Open-AudIT's device type vocabulary is its own; only the entries that name a
# runZero device class outright are translated. Anything else is passed through
# title-cased so an operator still sees the vendor's own word for it.
DEVICE_TYPES = {
    "computer": "",
    "unknown": "",
    "unclassified": "",
    "general purpose": "",
    "access point": "Wireless Access Point",
    "wap": "Wireless Access Point",
    "wireless router": "Wireless Router",
    "router": "Router",
    "broadband router": "Router",
    "switch": "Switch",
    "hub": "Hub",
    "bridge": "Bridge",
    "firewall": "Firewall",
    "load balancer": "Load Balancer",
    "proxy": "Proxy Server",
    "proxy server": "Proxy Server",
    "printer": "Printer",
    "network printer": "Printer",
    "print server": "Print Server",
    "scanner": "Scanner",
    "network scanner": "Scanner",
    "ip phone": "IP Phone",
    "voip phone": "IP Phone",
    "voip gateway": "VoIP Gateway",
    "voip adapter": "VoIP Adapter",
    "pbx": "PBX",
    "phone": "Phone",
    "cell phone": "Mobile Device",
    "smart phone": "Mobile Device",
    "android": "Mobile Device",
    "iphone": "Mobile Device",
    "ipod": "Mobile Device",
    "ipad": "Tablet",
    "tablet": "Tablet",
    "pda": "Mobile Device",
    "security camera": "IP Camera",
    "webcam": "IP Camera",
    "nas": "Storage",
    "san": "Storage",
    "storage misc": "Storage",
    "tape library": "Storage",
    "ups": "UPS",
    "pdu": "Power Device",
    "power device": "Power Device",
    "kvm": "KVM",
    "blade chassis": "Blade Enclosure",
    "chassis": "Blade Enclosure",
    "gateway": "Gateway",
    "network device": "Network Device",
    "network ids": "IDS/IPS",
    "environment monitor": "Environment Control",
    "building management": "Building Automation",
    "access control": "Access Control",
    "iot sensor": "Sensor",
    "ot sensor": "Sensor",
    "sensor": "Sensor",
    "game console": "Game Console",
    "media device": "Media Device",
    "monitor": "Monitor",
    "projector": "Projector",
    "point of sale": "Point of Sale",
    "time clock": "Time Clock",
    "video conference": "Video Conferencing",
    "terminal server": "Terminal Server",
    "remote management": "Management Controller",
    "remote access controller": "Management Controller",
    "management console": "Management Controller",
    "cable modem": "Modem",
    "dsl modem": "Modem",
    "adsl modem": "Modem",
    "mobile modem": "Modem",
}

# The device row's own class column is a second, coarser signal used when type
# says nothing useful.
DEVICE_CLASSES = {
    "server": "Server",
    "virtual server": "Virtual Machine",
    "virtual desktop": "Virtual Machine",
    "hypervisor": "Hypervisor",
    "desktop": "Desktop",
    "workstation": "Desktop",
    "laptop": "Laptop",
    "tablet": "Tablet",
}

# Adapters that are a software construct rather than a physical port. Their
# MACs belong to a hypervisor, a VPN client, or a container runtime, and
# attaching them to the host merges unrelated assets together.
VIRTUAL_ADAPTER_HINTS = [
    "vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "vmnet", "docker",
    "wan miniport", "wi-fi direct virtual", "loopback", "tap-windows",
    "tap adapter", "openvpn", "wintun", "tailscale", "zerotier",
    "virtual ethernet", "virtual adapter", "pppoe", "6to4 adapter",
    "teredo", "isatap", "bluetooth device (personal area network)",
]

# SMBIOS strings that mean the manufacturer never filled the field in. They
# appear on thousands of unrelated machines, so they must never become a serial
# number, a model, or a merge signal.
PLACEHOLDER_VALUES = [
    "", "0", "none", "n/a", "na", "null", "unknown", "not specified",
    "not available", "to be filled by o.e.m.", "to be filled by oem",
    "system serial number", "default string", "system manufacturer",
    "system product name", "chassis manufacture", "no asset tag",
    "oem", "invalid", "empty", "xxxxxxx", "123456789", "0123456789",
]

# Hostnames that name no host.
PLACEHOLDER_HOSTNAMES = ["localhost", "localhost.localdomain", "unknown", "none"]

MAX_CHILDREN = 99
MAX_HOSTNAMES = 99
MAX_TAG_LENGTH = 64

# Open-AudIT stores every datetime as a MySQL DATETIME with no offset, and
# 2000-01-01 00:00:00 is the schema default that means "never".
NEVER_TIMESTAMP = "2000-01-01 00:00:00"
def _meaningful(value):
    """Return a hardware identity string, or "" for the SMBIOS placeholders."""
    text = as_text(value)
    if text.lower() in PLACEHOLDER_VALUES:
        return ""
    return text
def _server_host(url):
    """Return the Open-AudIT hostname, which scopes every imported id."""
    parsed = url_parse(url)
    return parsed.hostname if parsed else ""


def _app_base(base_url, app_path):
    """Return the application base, e.g. https://oa.example.com/open-audit."""
    path = as_text(app_path)
    if not path:
        path = DEFAULT_APP_PATH
    if not path.startswith("/"):
        path = "/" + path
    while path.endswith("/"):
        path = path[:-1]
    return base_url + path


DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def _days_in_month(year, month):
    """Return the real length of a month, so an impossible date never reaches
    parse_time, which aborts the entire script on one."""
    if month == 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        return 29
    return DAYS_IN_MONTH[month - 1]
def _is_virtual_adapter(row):
    """Decide whether a network row describes a software adapter."""
    for key in ["description", "name", "alias", "model"]:
        lowered = as_text(row.get(key)).lower()
        if not lowered:
            continue
        for hint in VIRTUAL_ADAPTER_HINTS:
            if hint in lowered:
                return True
    return False


def _hostname(value):
    """Return a usable hostname, dropping placeholders and bare addresses."""
    text = as_text(value)
    if not text or text.lower() in PLACEHOLDER_HOSTNAMES:
        return ""
    # A bare address imported as a hostname is a false merge signal, and
    # Open-AudIT falls back to the address for a host that never resolved.
    if ip_address(text) != None:
        return ""
    return text


def _device_type(record):
    """Translate the Open-AudIT type, then class, into a runZero device type."""
    oa_type = as_text(record.get("type")).lower()
    mapped = DEVICE_TYPES.get(oa_type)
    if mapped:
        return mapped
    if mapped == None and oa_type:
        # A type Open-AudIT knows but this table does not is still better than
        # nothing; the empty-string entries above are the ones deliberately
        # suppressed because they classify nothing.
        return oa_type.title()
    return DEVICE_CLASSES.get(as_text(record.get("class")).lower(), "")


def _hostnames(record):
    """Return the device's names, most specific first, de-duplicated."""
    names = []
    seen = {}
    for key in ["fqdn", "dns_fqdn", "name", "hostname", "dns_hostname", "sysName"]:
        candidate = _hostname(record.get(key))
        if not candidate:
            continue
        if seen.get(candidate.lower(), False):
            continue
        seen[candidate.lower()] = True
        names.append(candidate)
    return names[:MAX_HOSTNAMES]


def collect_interfaces(record, included):
    """Build the network interfaces for one device.

    Open-AudIT keeps addresses in the ip table and adapters in the network
    table, joined to each other by net_index rather than by a shared key, so
    the adapters are indexed first and each address is attached to the adapter
    that owns its index. An address whose index names no adapter still becomes
    an interface, because the address is the part runZero can merge on.
    """
    adapters = {}
    virtual_indexes = {}
    virtual = []
    for row in dicts(included.get("network")):
        index = as_text(row.get("net_index"))
        if _is_virtual_adapter(row):
            name = as_text(row.get("description")) or as_text(row.get("name"))
            if name and name not in virtual:
                virtual.append(name)
            if index:
                virtual_indexes[index] = True
            continue
        if index:
            adapters[index] = row

    # Addresses grouped by the adapter index they were bound to. A device with
    # no ip rows at all still gets its single primary address from the device
    # row, which is the only address a discovery-only record ever carries.
    grouped = {}
    order = []
    for row in dicts(included.get("ip")):
        address = routable_ip(row.get("ip"))
        if not address:
            continue
        index = as_text(row.get("net_index"))
        # An address bound to an adapter that was filtered as virtual is
        # dropped with it: the address belongs to the hypervisor's software
        # switch or the container bridge, not to this host.
        if index and virtual_indexes.get(index, False):
            continue
        if index not in grouped:
            grouped[index] = []
            order.append(index)
        if address not in grouped[index]:
            grouped[index].append(address)

    primary = routable_ip(record.get("ip"))
    if primary:
        placed = False
        for index in order:
            if primary in grouped[index]:
                placed = True
        if not placed:
            if "" not in grouped:
                grouped[""] = []
                order.append("")
            grouped[""].append(primary)

    netifs = []
    macs = []
    for index in order:
        mac = ""
        adapter = adapters.get(index)
        if adapter:
            mac = as_text(adapter.get("mac"))
        if not mac:
            for row in dicts(included.get("ip")):
                if as_text(row.get("net_index")) == index:
                    mac = as_text(row.get("mac"))
        # network_interface returns None when neither the MAC nor any address
        # parses, and networkInterfaces=[None] aborts the entire run.
        nic = network_interface(mac=mac, ips=grouped[index])
        if nic:
            netifs.append(nic)
            if mac:
                macs.append(mac)

    # An adapter with a MAC but no address is still worth importing: a MAC is
    # runZero's strongest merge signal and a switch port only ever sees that.
    for index in adapters:
        if index in grouped:
            continue
        mac = as_text(adapters[index].get("mac"))
        if not mac:
            continue
        nic = network_interface(mac=mac, ips=[])
        if nic:
            netifs.append(nic)
            macs.append(mac)

    return netifs[:MAX_CHILDREN], macs, virtual


def collect_software(included, scope, device_id, address):
    """Build Software objects from the device's software sub-table.

    Open-AudIT keeps one row per installed package and re-inserts a row on
    every audit, so the same product and version routinely appears more than
    once; the pair is the natural key and duplicates collapse onto it.
    """
    entries = []
    seen = {}
    for row in dicts(included.get("software")):
        product = as_text(row.get("name"))
        if not product:
            continue
        version = as_text(row.get("version"))
        key = "{}:{}".format(product, version)
        if seen.get(key.lower(), False):
            continue
        seen[key.lower()] = True
        args = {
            "id": "{}:{}:{}:software:{}".format(VENDOR, scope, device_id, key),
            "product": product,
        }
        if version:
            args["version"] = version
        publisher = as_text(row.get("publisher"))
        if publisher:
            args["vendor"] = publisher
        # serviceAddress is optional but must parse as an address when set, so
        # it carries the device's own primary address rather than a stand-in.
        if address:
            args["serviceAddress"] = address
        entries.append(Software(**args))
        if len(entries) >= MAX_CHILDREN:
            break
    return entries


def _tags(record, virtual_adapters):
    """Return the search tags for one device."""
    tags = [VENDOR]
    for key in ["type", "class", "status", "environment"]:
        value = as_text(record.get(key)).lower()
        if value and value not in ["unknown", "unclassified"]:
            tags.append("{}:{}".format(key, value[:MAX_TAG_LENGTH]))
    if as_text(record.get("status")).lower() in RETIRED_STATUSES:
        tags.append("open-audit-retired")
    if virtual_adapters:
        tags.append("open-audit-virtual-adapters")
    return tags


def build_asset(record, included, scope, ceiling):
    """Build one ImportAsset from a devices row and its optional sub-tables."""
    device_id = as_text(record.get("id"))
    netifs, macs, virtual = collect_interfaces(record, included)
    software = collect_software(included, scope, device_id, routable_ip(record.get("ip")))

    attrs = {
        "device_id": device_id,
        "uuid": as_text(record.get("uuid")),
        "name": as_text(record.get("name")),
        "type": as_text(record.get("type")),
        "class": as_text(record.get("class")),
        "function": as_text(record.get("function")),
        "status": as_text(record.get("status")),
        "environment": as_text(record.get("environment")),
        "description": as_text(record.get("description")),
        "domain": as_text(record.get("domain")),
        "dns_domain": as_text(record.get("dns_domain")),
        "os_group": as_text(record.get("os_group")),
        "os_family": as_text(record.get("os_family")),
        "os_name": as_text(record.get("os_name")),
        "os_version": as_text(record.get("os_version")),
        "os_display_version": as_text(record.get("os_display_version")),
        "os_arch": as_text(record.get("os_arch")),
        "kernel_version": as_text(record.get("kernel_version")),
        "form_factor": as_text(record.get("form_factor")),
        "serial": _meaningful(record.get("serial")),
        "service_tag": _meaningful(record.get("service_tag")),
        "asset_number": as_text(record.get("asset_number")),
        "memory_count": as_text(record.get("memory_count")),
        "processor_count": as_text(record.get("processor_count")),
        "uptime": as_text(record.get("uptime")),
        "org_id": as_text(record.get("org_id")),
        "org_name": as_text(record.get("orgs.name")),
        "location_id": as_text(record.get("location_id")),
        "location_name": as_text(record.get("locations.name")),
        "vm_vendor": as_text(record.get("vm_vendor")),
        "vm_server_name": as_text(record.get("vm_server_name")),
        "cluster_name": as_text(record.get("cluster_name")),
        "instance_provider": as_text(record.get("instance_provider")),
        "instance_ident": as_text(record.get("instance_ident")),
        "snmp_oid": as_text(record.get("snmp_oid")),
        "snmp_enterprise_name": as_text(record.get("snmp_enterprise_name")),
        "sys_descr": as_text(record.get("sysDescr"))[:1024],
        "sys_object_id": as_text(record.get("sysObjectID")),
        "sys_contact": as_text(record.get("sysContact")),
        "sys_location": as_text(record.get("sysLocation")),
        "sys_name": as_text(record.get("sysName")),
        "last_seen_by": as_text(record.get("last_seen_by")),
        # The unmodified vendor strings are kept alongside the clamped
        # timestamps, so an operator can still see what the server said.
        "first_seen": as_text(record.get("first_seen")),
        "last_seen": as_text(record.get("last_seen")),
        "mac_addresses": ", ".join(macs),
        "software_count": str(len(software)),
        "virtual_adapters": ", ".join(virtual),
    }

    args = {
        # The devices.id primary key is Open-AudIT's own identity for the
        # device and survives every re-audit, rename, and re-address, so it
        # drives merging; MAC, IP, and hostname churn must not disqualify it.
        "id": "{}:{}:{}".format(VENDOR, scope, device_id),
        "hostnames": _hostnames(record),
        "networkInterfaces": netifs,
        "tags": _tags(record, virtual),
        "customAttributes": to_custom_attributes(attrs, prefix=VENDOR.replace("-", "_"),
                                                 separator="_"),
    }

    if software:
        args["software"] = software

    device_type = _device_type(record)
    if device_type:
        args["deviceType"] = device_type

    manufacturer = _meaningful(record.get("manufacturer"))
    if manufacturer:
        args["manufacturer"] = manufacturer
    model = _meaningful(record.get("model"))
    if model:
        args["model"] = model

    os_name = as_text(record.get("os_name"))
    if os_name:
        args["os"] = os_name
    os_version = as_text(record.get("os_version"))
    if os_version:
        args["osVersion"] = os_version

    first_seen = parse_ts(record.get("first_seen"), ceiling)
    if first_seen:
        args["firstSeenTS"] = first_seen

    asset = ImportAsset(**args)
    last_seen = parse_ts(record.get("last_seen"), ceiling)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def login(ctx):
    """Exchange the username and password for a ci_session cookie.

    Open-AudIT has no bearer-token mode. /index.php/logon sets a CodeIgniter
    session cookie, and every later request is authenticated by that cookie
    alone. The login runs on a requests.Session because that is the only
    transport here with a cookie jar: the raw HTTP client follows redirects and
    keeps no jar, so reading Set-Cookie off the response would capture whatever
    the final hop set rather than the authenticated session. The cookie is then
    replayed as a plain header on the data calls, which keeps the configured
    proxy, timeout, custom CA, and retry budget in play for the calls that
    move the actual inventory.
    """
    session = Session(insecure_skip_verify=ctx["insecure"])
    headers = dict(ctx["base_options"].get("headers", {}))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    # Without an Accept of application/json the logon controller answers HTML
    # and redirects on both success and failure, which makes the two outcomes
    # indistinguishable from here.
    headers["Accept"] = "application/json"
    body = url_encode({"username": ctx["username"], "password": ctx["password"]})
    resp = session.post(ctx["base"] + LOGON_PATH, headers=headers, body=bytes(body))
    if resp == None:
        print("open-audit: no response from {}".format(LOGON_PATH))
        return False
    if resp.status_code == 401:
        print("open-audit: logon rejected the username or password")
        return False
    if resp.status_code >= 400:
        print("open-audit: logon failed with status {}".format(resp.status_code))
        return False

    token = ""
    cookies = session.cookies.get(ctx["base_url"])
    for cookie in cookies if type(cookies) == "list" else []:
        if cookie.name == SESSION_COOKIE:
            token = cookie.value
    if not token:
        print("open-audit: logon set no {} cookie; check that {} is the application path".format(
            SESSION_COOKIE, ctx["app_path"]))
        return False

    headers = dict(ctx["base_options"].get("headers", {}))
    headers["Accept"] = "application/json"
    headers["Cookie"] = "{}={}".format(SESSION_COOKIE, token)
    options = dict(ctx["base_options"])
    options["headers"] = headers
    ctx["http_options"] = options
    return True


def _auth_failure(err):
    """Report whether a request error means the session is no longer valid.

    An expired Open-AudIT session does not answer 401 on a data path. The
    session filter redirects to /index.php/logon, the client follows it, and
    the login page comes back as a 200 carrying HTML. That surfaces here as a
    JSON decode failure on a 200, which is the only signal available, because
    the response struct exposes no final URL to inspect.
    """
    if err.startswith("status 401") or err.startswith("status 403"):
        return True
    return err.startswith("status 200") and "invalid JSON" in err


def _get(ctx, url, params):
    """Issue one authenticated GET, logging in again once if the session died."""
    for attempt in range(2):
        options = dict(ctx["http_options"])
        options["params"] = params
        data, err = get_json(url, **options)
        if not err:
            return data, None
        if _auth_failure(err) and attempt == 0:
            print("open-audit: session rejected, logging in again")
            if not login(ctx):
                return None, err
            continue
        return None, err
    return None, "request failed"


def _envelope_rows(data):
    """Return the data array of an Open-AudIT response envelope.

    Every collection and read answers {"meta": {...}, "included": ..., "data":
    [{"id": n, "type": "devices", "attributes": {...}}]}. A read of an id that
    does not exist answers the same envelope with an empty data array.
    """
    if type(data) != "dict":
        return []
    rows = data.get("data")
    if type(rows) != "list":
        return []
    return rows


def _attributes(row):
    """Return the attributes object of one data item, or None."""
    if type(row) != "dict":
        return None
    attributes = row.get("attributes")
    if type(attributes) != "dict":
        return None
    return attributes


def _included(data):
    """Return the included sub-tables of a read response.

    The field is a PHP array, so it serialises to [] when no sub-table matched
    and to an object keyed by table name when one did. Subscripting the list
    form would abort the run.
    """
    if type(data) != "dict":
        return {}
    included = data.get("included")
    if type(included) != "dict":
        return {}
    return included


def fetch_detail(ctx, device_id):
    """Read one device with its sub-tables, returning the included block."""
    url = "{}{}/{}".format(ctx["base"], DEVICES_PATH, device_id)
    params = {"format": "json", "include": ",".join(ctx["includes"])}
    data, err = _get(ctx, url, params)
    if err:
        print("open-audit: failed to read device {}: {}".format(device_id, err))
        return {}
    return _included(data)


def fetch_and_report(ctx):
    """Page the devices collection, streaming each page as it is parsed."""
    url = ctx["base"] + DEVICES_PATH
    offset = 0
    reported = 0
    skipped = 0
    detailed = 0
    capped = 0
    ceiling = now()

    _pager = pager("open-audit")

    while _pager.next():
        params = {
            "format": "json",
            "properties": DEVICE_PROPERTIES,
            "limit": str(ctx["page_size"]),
            "offset": str(offset),
            # A stable sort is what makes limit/offset paging correct; without
            # it MySQL may return the same row on two pages and omit another.
            "sort": "devices.id",
        }
        if ctx["org_id"]:
            params["devices.org_id"] = ctx["org_id"]
        if not ctx["include_retired"]:
            # Open-AudIT reads the operator off the front of the value, so
            # notin(...) is how a set exclusion is expressed.
            params["devices.status"] = "notin(" + ",".join(RETIRED_STATUSES) + ")"

        data, err = _get(ctx, url, params)
        if err:
            print("open-audit: failed to list devices at offset {}: {}".format(offset, err))
            if _auth_failure(err):
                print("open-audit: check that the user has read permission on the devices collection")
            return reported, skipped, detailed, capped

        rows = _envelope_rows(data)
        if not rows:
            break

        assets = []
        for row in rows:
            record = _attributes(row)
            if record == None:
                skipped += 1
                continue
            device_id = as_text(record.get("id"))
            if not device_id:
                device_id = as_text(row.get("id"))
            if not device_id or device_id == "0":
                skipped += 1
                print("open-audit: skipping a devices row with no id at offset {}".format(offset))
                continue
            record["id"] = device_id

            included = {}
            if ctx["includes"]:
                if detailed < ctx["max_detail"]:
                    included = fetch_detail(ctx, device_id)
                    detailed += 1
                else:
                    capped += 1
            assets.append(build_asset(record, included, ctx["scope"], ceiling))

        if assets:
            reported += report_assets(assets)
        print("open-audit: reported {} devices (offset {})".format(reported, offset))

        if len(rows) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    return reported, skipped, detailed, capped


def main(**kwargs):
    base_url = get_string(kwargs, "url", default="").strip()
    while base_url.endswith("/"):
        base_url = base_url[:-1]
    if not base_url:
        print("open-audit: no Open-AudIT server URL was configured")
        return None

    scope = _server_host(base_url)
    if not scope:
        print("open-audit: could not determine the server host from the configured URL")
        return None

    app_path = get_string(kwargs, "app_path", default=DEFAULT_APP_PATH)
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    max_detail = get_int(kwargs, "max_detail_devices", default=DEFAULT_MAX_DETAIL)
    if max_detail < 0:
        max_detail = DEFAULT_MAX_DETAIL

    includes = []
    if get_bool(kwargs, "collect_interfaces", default=True):
        includes = includes + INCLUDE_INTERFACES
    if get_bool(kwargs, "collect_software", default=False):
        includes = includes + INCLUDE_SOFTWARE

    base_options = get_http_options(kwargs, headers={"Accept": "application/json"})
    ctx = {
        "base_url": base_url,
        "app_path": app_path,
        "base": _app_base(base_url, app_path),
        "scope": scope,
        "username": get_string(kwargs, "username", default=""),
        "password": get_string(kwargs, "password", default=""),
        "org_id": get_string(kwargs, "org_id", default="").strip(),
        "include_retired": get_bool(kwargs, "include_retired", default=False),
        "includes": includes,
        "max_detail": max_detail,
        "page_size": page_size,
        "base_options": base_options,
        "http_options": base_options,
        "insecure": base_options.get("tls", {}).get("insecure", False) == True,
    }

    if not login(ctx):
        return None

    reported, skipped, detailed, capped = fetch_and_report(ctx)
    if not reported:
        print("open-audit: no assets retrieved")
    if skipped:
        print("open-audit: skipped {} rows with no usable device id".format(skipped))
    if capped:
        print("open-audit: detail cap of {} reached, {} devices imported without addresses".format(
            max_detail, capped))
    print("open-audit: imported {} devices, {} with detail".format(reported, detailed))
    return None

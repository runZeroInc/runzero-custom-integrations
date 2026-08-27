# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-zabbix",
    "name": "Zabbix",
    "type": "inbound",
    "description": "Imports monitored hosts from Zabbix, with their interfaces, their 70-field host inventory, their tags, and their host groups.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Zabbix publishes at most two MACs and only as free-text inventory
    # fields, and a host is very often addressed by DNS with no IP at all,
    # so an absent MAC or a changed address must never disqualify a merge
    # against an asset runZero already discovered.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Zabbix frontend URL",
            "type": "url",
            "required": True,
            "placeholder": "https://zabbix.example.com",
            "description": "Base URL of the Zabbix frontend. /api_jsonrpc.php is appended unless the URL already names it. Package installs usually need https://host/zabbix.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Zabbix API token, created under Users > API tokens. Sent as an Authorization: Bearer header, which requires Zabbix 6.4 or newer.",
        },
        {
            "key": "host_groups",
            "label": "Host group filter",
            "type": "string",
            "required": False,
            "description": "Comma-separated host group names to import. Leave blank to import every group.",
        },
        {
            "key": "include_disabled",
            "label": "Include disabled hosts",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import hosts Zabbix has stopped monitoring (status 1).",
        },
        {
            "key": "include_services",
            "label": "Import interfaces as services",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Emit each Zabbix interface as a listening service on its address and port.",
        },
        {
            "key": "include_software",
            "label": "Import inventory software fields",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Emit the inventory software and software_app_a..e fields as Software records. These are free-text fields, so their quality depends on how the site populates them.",
        },
        {
            "key": "group_chunk",
            "label": "Host groups per request",
            "type": "int",
            "required": False,
            "default": 20,
            "min": 1,
            "max": 500,
            "description": "How many host groups to ask for in one host.get call. The Zabbix API has no offset parameter, so this is what bounds the size of a single response.",
        },
        {
            "key": "max_hosts",
            "label": "Maximum hosts",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 0,
            "description": "Cap on the number of hosts imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "Service", "Software", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", http_post="post", "post_json", "bearer", "url_parse")
load("json", json_decode="decode")
load("jsonstream", "iter_array")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "zabbix"
ATTR_PREFIX = "zabbix"
ATTR_SEPARATOR = "_"

API_PATH = "/api_jsonrpc.php"
MAX_CHILDREN = 99

HEXDIGITS = "0123456789abcdef"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-"]

# Zabbix interface types. The port each one polls is a genuine listening
# service on the host, which is why they are worth emitting.
INTERFACE_TYPES = {
    "1": ("agent", "Zabbix agent", "tcp"),
    "2": ("snmp", "SNMP", "udp"),
    "3": ("ipmi", "IPMI", "udp"),
    "4": ("jmx", "JMX", "tcp"),
}

INTERFACE_AVAILABLE = {"0": "unknown", "1": "available", "2": "unavailable"}

# inventory.type is a free-text field, so only values that map cleanly are
# promoted; anything else survives as the zabbix_inventory_type attribute.
DEVICE_TYPES = {
    "server": "Server",
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "printer": "Printer",
    "workstation": "Desktop",
    "desktop": "Desktop",
    "laptop": "Laptop",
    "storage": "Storage",
    "ups": "UPS",
    "pdu": "Power Distribution Unit",
    "hypervisor": "Hypervisor",
    "virtual machine": "Virtual Machine",
    "access point": "Wireless Access Point",
    "camera": "IP Camera",
    "phone": "IP Phone",
}

# The complete Zabbix host inventory field set: 70 fields, inventory ids 1-70.
INVENTORY_FIELDS = [
    "type", "type_full", "name", "alias", "os", "os_full", "os_short",
    "serialno_a", "serialno_b", "tag", "asset_tag", "macaddress_a",
    "macaddress_b", "hardware", "hardware_full", "software", "software_full",
    "software_app_a", "software_app_b", "software_app_c", "software_app_d",
    "software_app_e", "contact", "location", "location_lat", "location_lon",
    "notes", "chassis", "model", "hw_arch", "vendor", "contract_number",
    "installer_name", "deployment_status", "url_a", "url_b", "url_c",
    "host_networks", "host_netmask", "host_router", "oob_ip", "oob_netmask",
    "oob_router", "date_hw_purchase", "date_hw_install", "date_hw_expiry",
    "date_hw_decomm", "site_address_a", "site_address_b", "site_address_c",
    "site_city", "site_state", "site_country", "site_zip", "site_rack",
    "site_notes", "poc_1_name", "poc_1_email", "poc_1_phone_a",
    "poc_1_phone_b", "poc_1_cell", "poc_1_screen", "poc_1_notes",
    "poc_2_name", "poc_2_email", "poc_2_phone_a", "poc_2_phone_b",
    "poc_2_cell", "poc_2_screen", "poc_2_notes",
]

SOFTWARE_FIELDS = ["software", "software_app_a", "software_app_b",
                   "software_app_c", "software_app_d", "software_app_e"]
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    Zabbix inventory macaddress_a and macaddress_b are FREE TEXT fields that a
    site fills by hand or from a discovery item, so they hold anything at all.
    Validating the shape here is what stops a note or a serial number reaching
    a NetworkInterface.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    if text == "000000000000" or text == "ffffffffffff":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text

def _to_port(value):
    """Zabbix returns every scalar as a string, including the interface port,
    and a port may also be a {$MACRO} reference that cannot be resolved here."""
    text = as_text(value, join=",").strip()
    if not text:
        return -1
    for index in range(len(text)):
        if text[index] not in "0123456789":
            return -1
    port = int(text)
    if port < 1 or port > 65535:
        return -1
    return port

def _inventory(record):
    """Return a host's inventory as a dict.

    selectInventory answers with an OBJECT when the host has inventory enabled
    and an empty ARRAY when it does not - PHP's json_encode renders the
    unmatched empty array that CRelationMap::mapOne() leaves behind as [], not
    {}. Inventory disabled is the shipped default, so this is the common path,
    not an edge case, and subscripting it without a type check would abort.
    """
    inventory = record.get("inventory")
    if type(inventory) == "dict":
        return inventory
    return {}

def _endpoint(url):
    """Return the JSON-RPC endpoint for a configured frontend URL.

    The path is not fixed across installs: packages serve the frontend under
    /zabbix, the official container images serve it at the root, and a reverse
    proxy can put it anywhere. So the URL is treated as the frontend base and
    the RPC file is appended unless it is already named.
    """
    text = as_text(url, join=",").strip().rstrip("/")
    if not text:
        return ""
    if text.endswith(API_PATH):
        return text
    if text.endswith("api_jsonrpc.php"):
        return text
    return text + API_PATH

def _scope(url):
    parsed = url_parse(url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return as_text(url, join=",").split("://")[-1].split("/")[0].split(":")[0]

def _rpc_error(payload):
    """Render a JSON-RPC error object as one readable line."""
    if type(payload) != "dict":
        return "unexpected response shape"
    error = payload.get("error")
    if type(error) != "dict":
        return ""
    return "{} {} {}".format(
        as_text(error.get("code"), join=","), as_text(error.get("message"), join=","), as_text(error.get("data"), join=",")).strip()

def call(ctx, method, params, authenticated):
    """Make one JSON-RPC call and return its result, or None on failure.

    Two things about the envelope matter. The `id` member is optional in the
    validator but omitting it makes the request a JSON-RPC NOTIFICATION, to
    which Zabbix answers with an empty body - so it is always sent. And the
    Content-Type is checked before any JSON-RPC handling: anything other than
    application/json-rpc, application/json, or application/jsonrequest is
    answered with a bare 412 and no body at all.
    """
    ctx["seq"] += 1
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": ctx["seq"]}
    options = ctx["http_options"] if authenticated else ctx["anon_options"]
    data, err = post_json(ctx["endpoint"], json=body, **options)
    if err:
        print("zabbix: {} failed: {}".format(method, err))
        return None
    if type(data) != "dict":
        print("zabbix: {} returned an unexpected body".format(method))
        return None
    message = _rpc_error(data)
    if message:
        print("zabbix: {} returned an error: {}".format(method, message))
        return None
    return data.get("result")

def check_version(ctx):
    """Read apiinfo.version, which must be called WITHOUT credentials.

    Zabbix exempts apiinfo.version from authentication and treats sending
    credentials to it as an error, so this call deliberately uses an options
    dict with no Authorization header.
    """
    version = call(ctx, "apiinfo.version", {}, False)
    if version == None:
        print("zabbix: could not read apiinfo.version; continuing anyway")
        return ""
    text = as_text(version, join=",").strip()
    parts = text.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        major = int(parts[0])
        minor = int(parts[1])
        if major < 6 or (major == 6 and minor < 4):
            print("zabbix: this server reports {}. Bearer token authentication was added in 6.4, ".format(text) +
                  "so every call is about to fail. Upgrade Zabbix, or add the legacy user.login handshake.")
    print("zabbix: server API version {}".format(text))
    return text

def fetch_group_ids(ctx, wanted):
    """Enumerate host group ids, optionally filtered to named groups.

    Groups are how this integration bounds a response. The Zabbix API has no
    offset or cursor of any kind - the complete common-get parameter set is
    countOutput, editable, excludeSearch, filter, limit, output, preservekeys,
    search, searchByAny, searchWildcardsEnabled, sortfield, sortorder, and
    startSearch, and startSearch only anchors a LIKE. Since a Zabbix host
    cannot exist without at least one group, walking the groups covers every
    host while keeping each response a bounded size.
    """
    params = {"output": ["groupid", "name"]}
    if wanted:
        params["filter"] = {"name": wanted}
    result = call(ctx, "hostgroup.get", params, True)
    if type(result) != "list":
        return None
    groups = {}
    for row in dicts(result):
        groupid = as_text(row.get("groupid"), join=",").strip()
        if groupid:
            groups[groupid] = as_text(row.get("name"), join=",").strip()
    if wanted:
        missing = [name for name in wanted if name not in groups.values()]
        if missing:
            print("zabbix: these host groups were not found and are being skipped: {}".format(",".join(missing)))
    return groups

def host_get_params(ctx, groupids):
    """Build the one host.get call this integration makes per group chunk."""
    params = {
        "output": ["hostid", "host", "name", "status", "description", "flags",
                   "maintenance_status", "active_available", "inventory_mode"],
        "selectInterfaces": ["interfaceid", "ip", "dns", "port", "type", "main",
                             "useip", "available", "error"],
        "selectInventory": "extend",
        "selectTags": "extend",
        # selectHostGroups replaced selectGroups in 6.2 and selectGroups was
        # removed in 7.2. This integration requires 6.4 for Bearer auth, so the
        # new spelling is the only one that can be correct here.
        "selectHostGroups": ["groupid", "name"],
    }
    if groupids:
        params["groupids"] = groupids
    if not ctx["include_disabled"]:
        params["filter"] = {"status": "0"}
    return params

def stream_hosts(ctx, groupids):
    """POST one host.get and yield its hosts without decoding the whole result.

    host.get has no server-side paging, so a large estate with
    selectInventory:"extend" produces one very large response. Raw http.post
    plus jsonstream.iter_array walks the result array element by element rather
    than materializing the entire decoded document, which is the difference
    between one page of dicts and all of them.

    The cost of dropping to raw http.post is that it accepts no retries kwarg
    and returns the body rather than a decoded value, so the JSON-RPC envelope
    has to be inspected by hand. iter_array ABORTS the script when its path is
    absent, so the body is checked for a result member before it is streamed
    and is decoded normally when it is not there - an error envelope is small.
    """
    ctx["seq"] += 1
    body = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": host_get_params(ctx, groupids),
        "id": ctx["seq"],
    }
    resp = http_post(ctx["endpoint"], json=body, **ctx["raw_options"])
    if resp == None:
        print("zabbix: host.get produced no response")
        return []
    if resp.status_code < 200 or resp.status_code > 299:
        if resp.status_code == 412:
            fail("zabbix: host.get was refused with 412 before any JSON-RPC handling, " +
                 "which means the Content-Type was rejected")
        fail("zabbix: host.get failed with status {}".format(resp.status_code))

    text = as_text(resp.body, join=",")
    head = text[:400]
    if '"result"' not in head:
        if head.strip().startswith("{"):
            decoded = json_decode(text)
            message = _rpc_error(decoded)
            if message:
                fail("zabbix: host.get returned an error: {}".format(message))
        fail("zabbix: host.get returned a body with no result member")
    return iter_array(text, path="result")

def build_interfaces(record, inventory):
    """Return (netifs, services_source, addresses, dns_names) for one host.

    A Zabbix interface carries an address and a port but never a MAC; the only
    MACs in the whole API are the free-text inventory fields macaddress_a and
    macaddress_b, and nothing says which interface either belongs to. So the
    primary MAC is attached to the address set and the secondary MAC is emitted
    as an interface of its own with no address, which is what the data actually
    supports.
    """
    addresses = []
    dns_names = []
    endpoints = []
    for entry in dicts(record.get("interfaces")):
        ip = routable_ip(entry.get("ip"))
        if ip:
            addresses.append(ip)
        name = _hostname(entry.get("dns"))
        if name:
            dns_names.append(name)
        endpoints.append((entry, ip))

    addresses = dedupe(addresses)
    dns_names = dedupe(dns_names)

    mac_a = _mac_key(inventory.get("macaddress_a"))
    mac_b = _mac_key(inventory.get("macaddress_b"))

    netifs = []
    primary = network_interface(mac=mac_a, ips=addresses)
    if primary:
        netifs.append(primary)
    if mac_b and mac_b != mac_a:
        secondary = network_interface(mac=mac_b)
        if secondary:
            netifs.append(secondary)
    return netifs, endpoints, addresses, dns_names

def build_services(ctx, hostid, endpoints):
    """Turn each Zabbix interface into the service it polls.

    An interface configured with useip=0 is addressed by DNS and carries an
    empty ip, and a Service needs an address, so those are skipped rather than
    bound to a guessed address. A port may also be a {$MACRO} reference that
    only the server can resolve, which _to_port rejects.
    """
    services = []
    seen = []
    for entry, ip in endpoints:
        if not ip:
            continue
        port = _to_port(entry.get("port"))
        if port < 0:
            continue
        kind, product, transport = INTERFACE_TYPES.get(
            as_text(entry.get("type"), join=",").strip(), ("other", "", "tcp"))
        key = "{}/{}/{}".format(ip, port, transport)
        if key in seen:
            continue
        seen.append(key)
        params = {
            "address": ip,
            "port": port,
            "transport": transport,
            "customAttributes": to_custom_attributes({
                "interface_id": entry.get("interfaceid"),
                "interface_kind": kind,
                "interface_main": entry.get("main"),
                "interface_use_ip": entry.get("useip"),
                "interface_available": INTERFACE_AVAILABLE.get(
                    as_text(entry.get("available"), join=",").strip(), as_text(entry.get("available"), join=",")),
                "interface_error": entry.get("error"),
                "hostid": hostid,
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        if product:
            params["product"] = product
        services.append(Service(**params))
    return services

def build_software(ctx, hostid, address, inventory):
    """Emit the inventory software fields as Software records.

    These are free-text inventory fields, not a package manager listing, so no
    version is parsed out of them and no CPE is synthesized: Software.cpe23 is
    validated against the CPE 2.2 URI binding ^cpe:/a: and a guessed value
    would fail the whole record.
    """
    software = []
    for field in SOFTWARE_FIELDS:
        product = as_text(inventory.get(field), join=",").strip()
        if not product:
            continue
        software.append(Software(**{
            "id": "{}:{}:{}:software:{}".format(VENDOR, ctx["scope"], hostid, field),
            "product": product[:255],
            "serviceAddress": address,
            "customAttributes": to_custom_attributes({
                "inventory_field": field,
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }))
    return software

def build_asset(ctx, record):
    """Convert one Zabbix host into a runZero asset."""
    hostid = as_text(record.get("hostid"), join=",").strip()
    inventory = _inventory(record)

    netifs, endpoints, addresses, dns_names = build_interfaces(record, inventory)
    address = addresses[0] if addresses else ""

    hostnames = dedupe([
        _hostname(record.get("host")),
        _hostname(record.get("name")),
        _hostname(inventory.get("name")),
        _hostname(inventory.get("alias")),
    ] + dns_names)

    groups = []
    for group in dicts(record.get("hostgroups")):
        name = as_text(group.get("name"), join=",").strip()
        if name:
            groups.append(name)

    tags = [VENDOR]
    for group in groups:
        tags.append("group:" + group)
    for entry in dicts(record.get("tags")):
        key = as_text(entry.get("tag"), join=",").strip()
        if not key:
            continue
        value = as_text(entry.get("value"), join=",").strip()
        tags.append("{}:{}".format(key, value) if value else key)
    if as_text(record.get("status"), join=",").strip() == "1":
        tags.append("zabbix-disabled")
    if as_text(record.get("flags"), join=",").strip() == "4":
        tags.append("zabbix-discovered")
    if as_text(record.get("maintenance_status"), join=",").strip() == "1":
        tags.append("zabbix-maintenance")
    # ImportAsset has no serial field, so the inventory serials become tags.
    for serial in dedupe([inventory.get("serialno_a"), inventory.get("serialno_b")]):
        tags.append("serial:" + serial)

    attrs = {
        "hostid": hostid,
        "server": ctx["scope"],
        "technical_name": record.get("host"),
        "visible_name": record.get("name"),
        "description": record.get("description"),
        "status": "disabled" if as_text(record.get("status"), join=",").strip() == "1" else "monitored",
        "flags": record.get("flags"),
        "maintenance_status": record.get("maintenance_status"),
        "active_available": INTERFACE_AVAILABLE.get(
            as_text(record.get("active_available"), join=",").strip(), as_text(record.get("active_available"), join=",")),
        "inventory_mode": record.get("inventory_mode"),
        "inventory_present": "true" if inventory else "false",
        "host_groups": groups,
        "interface_count": len(endpoints),
        "addresses": addresses,
    }
    for field in INVENTORY_FIELDS:
        value = inventory.get(field)
        if value != None and as_text(value, join=",").strip():
            attrs["inventory_" + field] = value

    if not hostnames and not netifs:
        # Nothing to correlate on: no usable name, no address, no MAC. Such an
        # asset can never merge with anything runZero discovers, so it is
        # skipped rather than imported as an orphan.
        ctx["no_identity"] += 1
        if ctx["no_identity"] == 1:
            ctx["no_identity_first"] = hostid
        return None

    services = build_services(ctx, hostid, endpoints) if ctx["include_services"] else []
    software = build_software(ctx, hostid, address, inventory) if (
        ctx["include_software"] and address) else []

    params = {
        # hostid is the primary key of the Zabbix hosts table and every
        # per-host API route is addressed by it. It survives rename, IP change,
        # template change, and re-monitoring, so it is allowed to drive merges.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], hostid),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "services": services[:MAX_CHILDREN],
        "software": software[:MAX_CHILDREN],    }

    os_name = as_text(inventory.get("os"), join=",").strip() or as_text(inventory.get("os_short"), join=",").strip()
    if os_name:
        params["os"] = os_name
    os_full = as_text(inventory.get("os_full"), join=",").strip()
    if os_full and os_full != os_name:
        params["osVersion"] = os_full
    vendor = as_text(inventory.get("vendor"), join=",").strip()
    if vendor:
        params["manufacturer"] = vendor
    model = as_text(inventory.get("model"), join=",").strip()
    if model:
        params["model"] = model
    device_type = DEVICE_TYPES.get(as_text(inventory.get("type"), join=",").strip().lower(), "")
    if device_type:
        params["deviceType"] = device_type

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    # No timestamp is set on purpose. host.get publishes no last-seen or
    # first-seen time, and the inventory date_hw_* fields are hardware lifecycle
    # dates rather than observations - date_hw_expiry and date_hw_decomm are
    # routinely in the FUTURE, and a future timestamp makes the platform reject
    # the entire asset record, not just the field. They are kept as attributes.
    return ImportAsset(**params)

def collect(ctx, groupids):
    """Stream one host.get chunk and report the assets it produces."""
    seen = 0
    for record in stream_hosts(ctx, groupids):
        if type(record) != "dict":
            continue
        hostid = as_text(record.get("hostid"), join=",").strip()
        if not hostid:
            ctx["no_hostid"] += 1
            if ctx["no_hostid"] == 1:
                ctx["no_hostid_first"] = as_text(record.get("host"), join=",")
            continue
        if hostid in ctx["seen"]:
            continue
        ctx["seen"][hostid] = True
        # host.get is already asked to filter on status, but the filter is
        # server-side and a proxied or older frontend can ignore it, so the
        # decision is re-made here rather than trusted.
        if not ctx["include_disabled"] and as_text(record.get("status"), join=",").strip() == "1":
            continue
        if ctx["max_hosts"] and ctx["reported"] >= ctx["max_hosts"]:
            ctx["skipped"] += 1
            continue
        asset = build_asset(ctx, record)
        if asset == None:
            continue
        report_asset(asset)
        ctx["reported"] += 1
        seen += 1
    return seen

def main(**kwargs):
    url = get_string(kwargs, "url")
    endpoint = _endpoint(url)
    scope = _scope(url)
    if not endpoint or not scope:
        fail("zabbix: could not build the API endpoint from the configured URL")

    headers = {
        # Zabbix checks this before any JSON-RPC handling and answers a bare
        # 412 with no body when it does not recognise the value.
        "Content-Type": "application/json-rpc",
        "Accept": "application/json",
    }
    anon_options = get_http_options(kwargs, headers=dict(headers))
    headers["Authorization"] = bearer(get_string(kwargs, "api_token"))
    http_options = get_http_options(kwargs, headers=dict(headers))
    # Raw http.post rejects a retries kwarg entirely, so the streamed call gets
    # one attempt. Everything else keeps the default three.
    raw_options = get_http_options(kwargs, headers=dict(headers))
    raw_options.pop("retries", None)

    max_hosts = get_int(kwargs, "max_hosts", default=20000)
    group_chunk = get_int(kwargs, "group_chunk", default=20)
    wanted = []
    for entry in as_text(get_string(kwargs, "host_groups", default=""), join=",").split(","):
        value = entry.strip()
        if value:
            wanted.append(value)

    ctx = {
        "endpoint": endpoint,
        "scope": scope,
        "http_options": http_options,
        "anon_options": anon_options,
        "raw_options": raw_options,
        "seq": 0,
        "seen": {},
        "reported": 0,
        "skipped": 0,
        # Drops are counted by cause, with one example kept for diagnosis, so a
        # misconfigured server costs two summary lines rather than one line per
        # host across the whole estate.
        "no_hostid": 0,
        "no_hostid_first": "",
        "no_identity": 0,
        "no_identity_first": "",
        "include_disabled": get_bool(kwargs, "include_disabled", default=False),
        "include_services": get_bool(kwargs, "include_services", default=True),
        "include_software": get_bool(kwargs, "include_software", default=True),
        "max_hosts": max_hosts if max_hosts > 0 else 0,
    }

    check_version(ctx)

    groups = fetch_group_ids(ctx, wanted)
    if groups == None:
        print("zabbix: host groups could not be listed; falling back to a single unfiltered host.get")
        collect(ctx, None)
    elif not groups:
        print("zabbix: no host groups matched")
    else:
        groupids = sorted(groups.keys())
        print("zabbix: walking {} host groups in chunks of {}".format(len(groupids), group_chunk))
        for start in range(0, len(groupids), group_chunk):
            chunk = groupids[start:start + group_chunk]
            collect(ctx, chunk)
            if ctx["max_hosts"] and ctx["reported"] >= ctx["max_hosts"]:
                break

    print("zabbix: reported {} hosts".format(ctx["reported"]))
    if ctx["no_hostid"]:
        print("zabbix: skipped {} hosts with no hostid (first host: {})".format(
            ctx["no_hostid"], ctx["no_hostid_first"]))
    if ctx["no_identity"]:
        print("zabbix: skipped {} hosts with no usable hostname, address, or MAC (first hostid: {})".format(
            ctx["no_identity"], ctx["no_identity_first"]))
    if ctx["skipped"]:
        print("zabbix: host limit of {} reached; {} further hosts were not imported".format(
            ctx["max_hosts"], ctx["skipped"]))
    if not ctx["reported"]:
        print("zabbix: no assets retrieved")
    return None

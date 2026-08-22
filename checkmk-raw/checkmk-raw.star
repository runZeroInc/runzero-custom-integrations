# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-checkmk-raw",
    "name": "Checkmk Raw Edition",
    "type": "inbound",
    "description": "Imports monitored hosts, their live status, and their HW/SW inventory - MACs, serial numbers, hardware, OS, and installed packages - from a Checkmk Raw Edition site.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Checkmk URL",
            "type": "url",
            "required": True,
            "placeholder": "https://checkmk.example.com",
            "description": "Base URL of the Checkmk server, without the site name. Checkmk is self-hosted, so there is no default.",
        },
        {
            "key": "site",
            "label": "Site name",
            "type": "string",
            "required": True,
            "placeholder": "mysite",
            "description": "The Checkmk site name. It is the first path segment of every API URL, as in https://checkmk.example.com/mysite/check_mk/api/1.0/. One credential reads one site.",
        },
        {
            "key": "username",
            "label": "Automation user",
            "type": "string",
            "required": True,
            "placeholder": "automation",
            "description": "The Checkmk user the integration authenticates as. This must be a user with an automation secret, not a password.",
        },
        {
            "key": "password",
            "label": "Automation secret",
            "type": "secret",
            "required": True,
            "description": "That user's automation secret. Checkmk sends it as 'Authorization: Bearer <user> <secret>', with a space between the two, which is unusual and is handled by the script.",
        },
        {
            "key": "collect_inventory",
            "label": "Collect HW/SW inventory",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Ask for the mk_inventory column on the monitoring query. This is where MAC addresses, serial numbers, manufacturer, model, OS version, and installed software come from, so it is on by default. It costs no extra requests, but it makes the single monitoring response much larger. Requires Checkmk 2.2.0p21, 2.3.0b1, or 2.1.0p39 or later.",
        },
        {
            "key": "collect_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the software.packages table from the inventory tree as Software records, up to 99 per host. Has no effect when the inventory is not collected.",
        },
        {
            "key": "query",
            "label": "Livestatus filter",
            "type": "string",
            "required": False,
            "placeholder": "{\"op\": \"~\", \"left\": \"name\", \"right\": \"^prod-\"}",
            "description": "Optional Livestatus filter expression, as JSON, applied server-side to the monitoring query, for example {\"op\": \"~\", \"left\": \"tag_names\", \"right\": \"windows\"}. This is the only way to limit the response size, because the Checkmk collections are not paginated. Leave blank to read every host.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', http_get='get', 'url_parse', 'url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_time', 'from_timestamp', 'now', 'parse_ts')
load('re', re_match='match', re_search='search')
load('jsonstream', 'iter_array')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "checkmk"
ATTR_PREFIX = "checkmk"
ATTR_SEPARATOR = "_"

# The version segment is the literal string "1.0". Checkmk 2.2 through 2.4
# accept anything there and discard it, but 2.5 validates it, so the documented
# value is the only one that works everywhere.
API_PATH = "/check_mk/api/1.0"
HOST_CONFIG_PATH = "/domain-types/host_config/collections/all"
HOST_STATUS_PATH = "/domain-types/host/collections/all"

MAX_CHILDREN = 99

# Livestatus columns asked for on the monitoring query. Requesting columns
# explicitly matters twice over: without them Checkmk returns only the host
# name, and mk_inventory - the whole HW/SW inventory tree, already decoded from
# its on-disk repr into JSON by the endpoint itself - is the column that removes
# what would otherwise be a request per host.
STATUS_COLUMNS = [
    "name",
    "address",
    "alias",
    "state",
    "state_type",
    "hard_state",
    "has_been_checked",
    "last_check",
    "last_state_change",
    "last_time_up",
    "check_command",
    "filename",
    "groups",
    "labels",
    "tags",
    "num_services",
    "num_services_ok",
    "num_services_crit",
    "num_services_warn",
    "num_services_unknown",
]
INVENTORY_COLUMN = "mk_inventory"

# The guard that makes streaming safe. jsonstream.iter_array raises - and a
# raise aborts the entire script, because Starlark has no exceptions - when the
# body is not JSON or the path does not hold an array. An error page, a login
# redirect, or {"value": null} would all end the run, so the body is checked for
# a real array at the path before the iterator is built.
VALUE_ARRAY_RE = r'"value"\s*:\s*\['

# A DNS label sequence. Used to decide whether a Checkmk alias is a second name
# for the host or a human-readable description that must not become a hostname.
HOSTNAME_RE = r"^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$"

EMPTY_MAC = "00:00:00:00:00:00"

# Checkmk's Livestatus host state, which is not the same numbering as a service
# state.
HOST_STATES = {"0": "up", "1": "down", "2": "unreachable"}

# Inventory paths, as Checkmk's HW/SW inventory display hints name them. The
# tree is walked by these dotted paths rather than by recursing blindly, so an
# unexpected vendor-specific subtree cannot change what is imported. There are
# exactly three top-level nodes: hardware, networking, and software.
INV_SYSTEM = "hardware.system"
INV_CPU = "hardware.cpu"
INV_MEMORY = "hardware.memory"
INV_BIOS = "software.bios"
INV_FIRMWARE = "hardware.firmware"
INV_OS = "software.os"
INV_PACKAGES = "software.packages"
INV_NWADAPTER = "hardware.nwadapter"
INV_INTERFACES = "networking.interfaces"
INV_ADDRESSES = "networking.addresses"

# Chassis and system descriptions Checkmk records, lower-cased, mapped to a
# runZero device type. Anything unrecognized is left for runZero's own
# fingerprinting to decide.
DEVICE_TYPES = {
    "desktop": "Desktop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "portable": "Laptop",
    "tablet": "Tablet",
    "server": "Server",
    "rack mount chassis": "Server",
    "main server chassis": "Server",
    "blade": "Server",
    "blade enclosure": "Server",
    "virtual machine": "Virtual Machine",
}
def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable."""
    mac = normalize_mac(as_text(value, join=",").strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac


def _hostname_like(value):
    """Report whether a string is usable as a hostname.

    Checkmk's alias is free text, so it is often a description rather than a
    second name. A bare IP address is also refused: importing one as a hostname
    is a documented data-quality defect, not a synonym."""
    text = as_text(value, join=",").strip()
    if not text or len(text) > 253:
        return False
    if ip_address(text) != None:
        return False
    return re_match(HOSTNAME_RE, text) != None


def api_url(ctx, path):
    """Build an absolute API URL. The site name is a mandatory path segment on
    every Checkmk endpoint, which is the single most common first-attempt
    failure against this API."""
    return "{}/{}{}{}".format(ctx["base_url"], ctx["site"], API_PATH, path)


def stream_values(ctx, url, label):
    """Stream the entries of a Checkmk collection response without decoding the
    whole document.

    Checkmk does not paginate its collections: one request answers with every
    host on the site, which on a large install is tens of megabytes. Decoding
    that into Starlark values costs several times the wire size, so the raw body
    is streamed instead and only one entry is live at a time.

    Returns (iterator, err). The raw http builtin is used rather than get_json
    because the body is needed as text; it accepts no retries kwarg and so gets
    one attempt per call."""
    resp = http_get(url, **ctx["http_options"])
    if resp == None:
        return None, "no response"
    if resp.status_code != 200:
        return None, "status {}: {}".format(resp.status_code, as_text(resp.body, join=",")[:200])
    body = resp.body
    text = as_text(body, join=",")
    if not re_search(VALUE_ARRAY_RE, text):
        # iter_array aborts the entire script when the path is absent, so an
        # error page, an HTML login redirect, or a null value node has to be
        # caught here rather than by the iterator.
        return None, "{} response carried no value array: {}".format(label, text[:200])
    return iter_array(body, path="value"), None


def fetch_config(ctx):
    """Index every configured host's WATO attributes in one request.

    This is the configuration collection, which is a different endpoint from
    the monitoring query and carries different fields: the folder a host lives
    in, its host tags, and the address an operator typed, rather than the
    address Checkmk resolved and polls. It is read into a map because it is the
    smaller of the two responses - a configuration entry is a handful of
    attributes, while a monitoring row can carry an entire inventory tree.

    Failure is not fatal: the run continues with monitoring data only."""
    index = {}
    url = api_url(ctx, HOST_CONFIG_PATH) + "?effective_attributes=true"
    stream, err = stream_values(ctx, url, "host configuration")
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("checkmk: authentication to the Checkmk site failed:", err)
            ctx["auth_failed"] = True
        else:
            print("checkmk: failed to read the host configuration, continuing without it:", err)
        return index
    for entry in stream:
        record = as_dict(entry)
        # The host name is the object id. It is deliberately not read from
        # title, which Checkmk sets to the alias when one exists, so a host with
        # an alias would otherwise be indexed under a description.
        name = as_text(record.get("id"), join=",").strip()
        if not name:
            continue
        extensions = as_dict(record.get("extensions"))
        # effective_attributes merges in everything inherited from parent
        # folders, which is where an address or a host tag set at folder level
        # lives. It is null unless the query parameter asked for it.
        attributes = as_dict(extensions.get("effective_attributes"))
        if not attributes:
            attributes = as_dict(extensions.get("attributes"))
        attributes = dict(attributes)
        for key in ["folder", "is_cluster", "is_offline", "cluster_nodes"]:
            if key in extensions and key not in attributes:
                attributes[key] = extensions[key]
        index[name] = attributes
    print("checkmk: read configuration for {} hosts".format(len(index)))
    return index


def status_url(ctx):
    """Build the monitoring query URL.

    columns is a repeated parameter, which a params= dict cannot express
    because a Starlark dict holds no duplicate keys, so the query is assembled
    here instead. The Livestatus filter, when one is configured, is a JSON
    document passed as a single URL-encoded value."""
    parts = []
    columns = list(STATUS_COLUMNS)
    if ctx["inventory"]:
        columns.append(INVENTORY_COLUMN)
    for column in columns:
        parts.append("columns=" + column)
    if ctx["query"]:
        parts.append(url_encode({"query": ctx["query"]}))
    return api_url(ctx, HOST_STATUS_PATH) + "?" + "&".join(parts)


def _branch(node, capital, lower):
    """Read one of an inventory node's three reserved keys under either casing.

    Checkmk serializes the same tree two ways. The on-disk form, which is what
    the mk_inventory Livestatus column carries, capitalizes them - Attributes,
    Pairs, Table, KeyColumns, Rows, Nodes. The inventory REST endpoint added in
    2.5 emits the identical structure in lower snake case. Reading both means
    one parser covers every route into this data."""
    value = node.get(capital)
    if type(value) == "dict":
        return value
    value = node.get(lower)
    if type(value) == "dict":
        return value
    return {}


def inv_node(tree, path):
    """Resolve a dotted inventory path to its node.

    Checkmk serializes an inventory tree as nested objects with three reserved
    keys - attributes for scalar pairs, table for row data, and nodes for
    children - so a path like hardware.nwadapter is walked through the nodes
    key at each level rather than by plain subscripting. Empty branches are
    omitted entirely rather than serialized as empty objects, so a missing key
    is the normal case and not an error."""
    node = as_dict(tree)
    for part in path.split("."):
        children = _branch(node, "Nodes", "nodes")
        if part not in children:
            return {}
        node = as_dict(children[part])
    return node


def inv_pairs(tree, path):
    """Return the scalar attributes at an inventory path."""
    node = inv_node(tree, path)
    return _branch(_branch(node, "Attributes", "attributes"), "Pairs", "pairs")


def inv_rows(tree, path):
    """Return the table rows at an inventory path."""
    table = _branch(inv_node(tree, path), "Table", "table")
    rows = table.get("Rows")
    if type(rows) != "list":
        rows = table.get("rows")
    return dicts(rows)


def inventory_interfaces(tree):
    """Build interface entries from the inventory tree.

    Two tables carry addressing and they disagree in coverage, so both are read.
    hardware.nwadapter is what the Windows agent reports and pairs a MAC with
    its addresses directly. networking.interfaces is what the SNMP and Linux
    checks report and carries the MAC but not the address, which then has to be
    joined from networking.addresses by device name."""
    entries = {}
    for row in inv_rows(tree, INV_NWADAPTER):
        name = as_text(row.get("name"), join=",").strip() or as_text(row.get("index"), join=",").strip()
        mac = _clean_mac(row.get("macaddress"))
        ips = []
        for key in ["ipv4_address", "ipv6_address", "address"]:
            for value in as_text(row.get(key), join=",").split(","):
                routable = routable_ip(value)
                if routable and routable not in ips:
                    ips.append(routable)
        if not name and not mac:
            continue
        key = name or mac
        entry = entries.setdefault(key, {"mac": "", "ips": []})
        if mac:
            entry["mac"] = mac
        for ip in ips:
            if ip not in entry["ips"]:
                entry["ips"].append(ip)

    for row in inv_rows(tree, INV_INTERFACES):
        name = as_text(row.get("description"), join=",").strip() or as_text(row.get("alias"), join=",").strip() or as_text(row.get("index"), join=",").strip()
        mac = _clean_mac(row.get("phys_address") or row.get("macaddress"))
        if not name and not mac:
            continue
        key = name or mac
        entry = entries.setdefault(key, {"mac": "", "ips": []})
        if mac and not entry["mac"]:
            entry["mac"] = mac

    for row in inv_rows(tree, INV_ADDRESSES):
        name = as_text(row.get("device"), join=",").strip()
        routable = routable_ip(row.get("address"))
        if not routable:
            continue
        entry = entries.setdefault(name or routable, {"mac": "", "ips": []})
        if routable not in entry["ips"]:
            entry["ips"].append(routable)
    return entries


def build_interfaces(entries, host_ips):
    """Reduce the inventory's per-device entries to runZero network interfaces.

    Devices that report the same MAC - a bond and its slaves, a VLAN device and
    its parent - are one endpoint as far as runZero is concerned and are pooled
    onto one interface. The host's own monitored address is added last, and only
    when no interface already accounts for it, so a host with no inventory at
    all still gets one interface."""
    merged = []
    seen_macs = {}
    for name in sorted(entries):
        entry = entries[name]
        mac = entry["mac"]
        if not mac and not entry["ips"]:
            continue
        if mac and mac in seen_macs:
            target = merged[seen_macs[mac]]
            for ip in entry["ips"]:
                if ip not in target["ips"]:
                    target["ips"].append(ip)
            continue
        if mac:
            seen_macs[mac] = len(merged)
        merged.append({"mac": mac, "ips": list(entry["ips"])})

    remaining = []
    for ip in host_ips:
        placed = False
        for entry in merged:
            if ip in entry["ips"]:
                placed = True
        if not placed and ip not in remaining:
            remaining.append(ip)
    if remaining:
        if merged:
            for ip in remaining:
                merged[0]["ips"].append(ip)
        else:
            merged.append({"mac": "", "ips": remaining})

    netifs = []
    for entry in merged:
        nic = network_interface(mac=entry["mac"], ips=entry["ips"])
        # network_interface returns None when nothing usable survived, and a
        # list holding None aborts the run.
        if nic:
            netifs.append(nic)
    return netifs


def build_software(ctx, hostname, address, tree):
    """Convert the inventory's package table into Software records.

    Checkmk publishes no CPE for an installed package, so cpe23 is left unset
    rather than synthesized: Software.cpe23 only accepts the CPE 2.2 cpe:/a:
    application binding, and a guessed one would be worse than none."""
    software = []
    if not ctx["software"]:
        return software
    seen = []
    for row in inv_rows(tree, INV_PACKAGES):
        product = as_text(row.get("name"), join=",").strip()
        if not product:
            continue
        version = as_text(row.get("version"), join=",").strip()
        key = product + "\x00" + version
        if key in seen:
            continue
        seen.append(key)
        params = {
            "id": "{}:{}:{}:package:{}".format(VENDOR, ctx["scope"], hostname, key)[:255],
            "product": product[:255],
            "serviceAddress": address or "127.0.0.1",
        }
        if version:
            params["version"] = version[:255]
        vendor = as_text(row.get("vendor"), join=",").strip()
        if vendor:
            params["vendor"] = vendor[:255]
        arch = as_text(row.get("arch"), join=",").strip()
        if arch:
            params["targetHardware"] = arch[:255]
        params["customAttributes"] = to_custom_attributes({
            "package_type": row.get("package_type"),
            "package_summary": row.get("summary"),
            "package_install_date": row.get("install_date"),
            "package_path": row.get("path"),
            "package_size": row.get("size"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
        if len(software) >= MAX_CHILDREN:
            break
    return software


def build_asset(ctx, hostname, attributes, status, tree):
    """Convert one Checkmk host into a runZero asset."""
    host_ips = []
    # The configured address is what an operator typed; the monitored address is
    # what Checkmk resolved and actually polls. Both are kept, the monitored one
    # first, because that is the address traffic went to.
    for value in [status.get("address"), attributes.get("ipaddress"), attributes.get("ipv6address")]:
        routable = routable_ip(value)
        if routable and routable not in host_ips:
            host_ips.append(routable)

    entries = inventory_interfaces(tree)
    netifs = build_interfaces(entries, host_ips)

    system = inv_pairs(tree, INV_SYSTEM)
    os_pairs = inv_pairs(tree, INV_OS)
    cpu = inv_pairs(tree, INV_CPU)
    memory = inv_pairs(tree, INV_MEMORY)
    bios = inv_pairs(tree, INV_BIOS)
    firmware = inv_pairs(tree, INV_FIRMWARE)

    serial = as_text(system.get("serial") or system.get("serial_number"), join=",").strip()
    manufacturer = as_text(system.get("manufacturer"), join=",").strip()
    model = as_text(system.get("product") or system.get("model") or system.get("model_name"), join=",").strip()
    alias = as_text(status.get("alias"), join=",").strip() or as_text(attributes.get("alias"), join=",").strip()

    primary_ip = host_ips[0] if host_ips else ""
    software = build_software(ctx, hostname, primary_ip, tree)

    # Labels are set in two places and both are real: the configuration carries
    # what an operator typed, while the monitoring row carries those plus any
    # the agent discovered.
    labels = dict(as_dict(attributes.get("labels")))
    labels.update(as_dict(status.get("labels")))
    host_tags = as_dict(status.get("tags"))

    tags = [VENDOR, "site:" + ctx["site"]]
    folder = as_text(attributes.get("folder"), join=",").strip() or as_text(status.get("filename"), join=",").strip()
    if folder:
        tags.append("folder:" + folder)
    state = HOST_STATES.get(as_text(status.get("state"), join=",").strip(), "")
    if state:
        tags.append("state:" + state)
    if serial:
        tags.append("serial:" + serial)
    for key in labels:
        tags.append("{}:{}".format(key, as_text(labels[key], join=",")))
    for group in as_text(status.get("groups"), join=",").split(","):
        group = group.strip()
        if group:
            tags.append("group:" + group)

    attrs = {
        "site": ctx["site"],
        "server": ctx["scope"],
        "host_name": hostname,
        "alias": alias,
        "folder": folder,
        "is_cluster": attributes.get("is_cluster"),
        "is_offline": attributes.get("is_offline"),
        "cluster_nodes": attributes.get("cluster_nodes"),
        "configured_ipaddress": attributes.get("ipaddress"),
        "configured_ipv6address": attributes.get("ipv6address"),
        "monitored_address": status.get("address"),
        "state": state,
        "state_code": status.get("state"),
        "state_type": status.get("state_type"),
        "hard_state": status.get("hard_state"),
        "has_been_checked": status.get("has_been_checked"),
        "check_command": status.get("check_command"),
        "last_check": status.get("last_check"),
        "last_state_change": status.get("last_state_change"),
        "last_time_up": status.get("last_time_up"),
        "host_groups": status.get("groups"),
        "services_total": status.get("num_services"),
        "services_ok": status.get("num_services_ok"),
        "services_warn": status.get("num_services_warn"),
        "services_crit": status.get("num_services_crit"),
        "services_unknown": status.get("num_services_unknown"),
        "monitored": "false" if not status else "true",
        "interface_count": len(netifs),
        "software_count": len(software),
        "inventory_present": "true" if tree else "false",
        "system_manufacturer": manufacturer,
        "system_product": system.get("product"),
        "system_serial": serial,
        "system_model": system.get("model"),
        "system_model_name": system.get("model_name"),
        "system_description": system.get("description"),
        "system_type": system.get("type"),
        "system_node_name": system.get("node_name"),
        "system_device_number": system.get("device_number"),
        "system_expresscode": system.get("expresscode"),
        "os_name": os_pairs.get("name"),
        "os_version": os_pairs.get("version"),
        "os_build": os_pairs.get("build"),
        "os_vendor": os_pairs.get("vendor"),
        "os_type": os_pairs.get("type"),
        "os_arch": os_pairs.get("arch"),
        "os_kernel_version": os_pairs.get("kernel_version"),
        "os_service_pack": os_pairs.get("service_pack"),
        "os_install_date": os_pairs.get("install_date"),
        "cpu_model": cpu.get("model"),
        "cpu_vendor": cpu.get("vendor"),
        "cpu_cores": cpu.get("cores"),
        "cpu_threads": cpu.get("threads"),
        "cpu_max_speed": cpu.get("max_speed"),
        "memory_total_ram": memory.get("total_ram_usable"),
        "memory_total_swap": memory.get("total_swap"),
        "bios_vendor": bios.get("vendor"),
        "bios_version": bios.get("version"),
        "bios_date": bios.get("date"),
        "firmware_vendor": firmware.get("vendor"),
        "firmware_version": firmware.get("version"),
    }
    for key in labels:
        attrs["label_" + as_text(key, join=",")] = labels[key]
    # Checkmk host tags are the mechanism sites use to classify hosts -
    # criticality, network segment, agent type. They arrive as tag_* keys on the
    # configuration attributes and as a map on the monitoring row.
    for key in attributes:
        if key.startswith("tag_"):
            attrs["host_" + as_text(key, join=",")] = attributes[key]
    for key in host_tags:
        attrs["host_tag_" + as_text(key, join=",")] = host_tags[key]

    params = {
        # A Checkmk host name is the primary key of the host: every API route is
        # keyed on it, it is unique within a site, and Checkmk has no numeric
        # surrogate to use instead. It is namespaced by both the server and the
        # site, because two sites on one server are independent monitoring
        # configurations that routinely reuse names.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], ctx["site"], hostname),
        # The alias is free text - "Web server, rack 4" is as common as a second
        # FQDN - so it only becomes a hostname when it actually looks like one.
        "hostnames": dedupe([hostname, alias if _hostname_like(alias) else ""]),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),
        "software": software,
    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    # The serial is carried as a custom attribute and a tag rather than as an
    # ImportAsset field: the constructor has no serial parameter.

    os_name = as_text(os_pairs.get("name"), join=",").strip()
    os_version = as_text(os_pairs.get("version"), join=",").strip()
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version

    for candidate in [system.get("type"), system.get("description"), system.get("product")]:
        mapped = DEVICE_TYPES.get(as_text(candidate, join=",").strip().lower(), "")
        if mapped:
            params["deviceType"] = mapped
            break

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    last_seen = parse_ts(status.get("last_check"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def collect(ctx, config_index):
    """Stream the monitoring query, building and reporting hosts one at a time.

    The Checkmk collections are not paginated - one request answers with every
    host, and with the inventory column that response carries a full hardware
    and software tree per host, which is the largest payload this integration
    ever handles. So the walk is over a streaming iterator rather than over
    pages, and each asset is reported as it is built, which keeps peak memory
    at one record rather than the whole estate."""
    stream, err = stream_values(ctx, status_url(ctx), "host status")
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("checkmk: authentication to the Checkmk site failed:", err)
        else:
            print("checkmk: failed to run the monitoring query:", err)
        return 0

    reported = 0
    skipped = 0
    seen = {}
    for entry in stream:
        record = as_dict(entry)
        status = as_dict(record.get("extensions"))
        # id and the name column are both the host name on this endpoint, and
        # unlike the configuration collection the title is the host name too.
        hostname = as_text(record.get("id"), join=",").strip() or as_text(status.get("name"), join=",").strip()
        if not hostname:
            skipped += 1
            print("checkmk: skipping a monitored host with no name")
            continue
        seen[hostname] = True

        # The endpoint decodes the mk_inventory column from its on-disk repr
        # into real JSON before serializing the row, so no second parse is
        # needed. A host that has never produced inventory has an empty tree.
        tree = as_dict(status.get(INVENTORY_COLUMN))
        if ctx["inventory"] and not tree:
            ctx["inventory_missing"] += 1

        reported += report_asset(build_asset(ctx, hostname, as_dict(config_index.get(hostname)), status, tree))

    # A host that has been added in the Setup but whose changes have not been
    # activated yet exists in the configuration and not in the monitoring core.
    # Those hosts are real - somebody has recorded an address for them - so they
    # are imported from the configuration alone rather than silently dropped.
    unmonitored = 0
    for hostname in sorted(config_index):
        if hostname in seen:
            continue
        unmonitored += 1
        reported += report_asset(build_asset(ctx, hostname, as_dict(config_index[hostname]), {}, {}))

    if skipped:
        print("checkmk: skipped {} host records with no host name".format(skipped))
    if unmonitored:
        print("checkmk: {} hosts are configured but not yet monitored".format(unmonitored))
    if ctx["inventory_missing"]:
        print("checkmk: {} hosts have no HW/SW inventory yet".format(ctx["inventory_missing"]))
    print("checkmk: reported {} hosts".format(reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("checkmk: could not determine the Checkmk host from the configured URL")
        return None

    site = get_string(kwargs, "site", default="").strip().strip("/")
    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")
    if not site:
        print("checkmk: the Checkmk site name is required; it is the first path segment of every API URL")
        return None
    if not username or not password:
        print("checkmk: a Checkmk automation user and its automation secret are required")
        return None

    ctx = {
        "base_url": base_url,
        "site": site,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
            # Checkmk's automation credential is sent as a Bearer token holding
            # two space-separated values, the user name and the secret. It is
            # not a base64 Basic header and not a single opaque token.
            "Authorization": "Bearer {} {}".format(username, password),
        }),
        "inventory": get_bool(kwargs, "collect_inventory", default=True),
        "software": get_bool(kwargs, "collect_software", default=True),
        "query": get_string(kwargs, "query", default="").strip(),
        "inventory_missing": 0,
        "auth_failed": False,
    }

    config_index = fetch_config(ctx)
    if ctx["auth_failed"]:
        # The two collections share one credential, so a rejected configuration
        # request means the monitoring query would be rejected as well. Stopping
        # here reports the real cause instead of a second, identical failure.
        return None
    if not collect(ctx, config_index):
        print("checkmk: no assets retrieved")
    return None

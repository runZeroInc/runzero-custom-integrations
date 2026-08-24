# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-puppetdb",
    "name": "PuppetDB",
    "type": "inbound",
    "description": "Imports Puppet nodes, their Facter facts, per-interface network addressing, and Puppet Enterprise package inventory from PuppetDB.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "PuppetDB URL",
            "type": "url",
            "required": True,
            "placeholder": "https://puppetdb.example.com:8081",
            "description": "Base URL of the PuppetDB query API. The /pdb/query/v4 path is appended automatically. Port 8081 is the TLS listener; port 8080 is the cleartext listener and is bound to localhost by default.",
        },
        {
            "key": "auth_token",
            "label": "X-Authentication token",
            "type": "secret",
            "required": False,
            "description": "Puppet Enterprise RBAC token, sent in the X-Authentication header. Leave blank on an open-source PuppetDB, which authenticates with a client certificate instead.",
        },
        {
            "key": "environment",
            "label": "Puppet environment",
            "type": "string",
            "required": False,
            "description": "Optional Puppet environment name, for example 'production'. Leave blank to import every node.",
        },
        {
            "key": "include_inactive",
            "label": "Import deactivated and expired nodes",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Also import nodes PuppetDB has deactivated or expired. These are decommissioned or silent machines, so they are excluded by default. Enabling this costs a second pass over the nodes and facts.",
        },
        {
            "key": "include_packages",
            "label": "Import package inventory",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch installed packages from the package-inventory endpoint. Package collection is a Puppet Enterprise feature that is off by default; an open-source PuppetDB has no such data and the feature switches itself off.",
        },
        {
            "key": "extra_facts",
            "label": "Additional fact names",
            "type": "string",
            "required": False,
            "description": "Comma-separated top-level Facter fact names to import in addition to the built-in set, for example 'role,datacenter'. Structured facts are imported whole and flattened into custom attributes.",
        },
        {
            "key": "page_size",
            "label": "Nodes per page",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 10000,
            "description": "Nodes requested per page of the node list.",
        },
        {
            "key": "fact_page_size",
            "label": "Fact rows per page",
            "type": "int",
            "required": False,
            "default": 2000,
            "min": 1,
            "max": 25000,
            "description": "Fact rows requested per page. PuppetDB pages this endpoint by individual fact row, not by node, so a larger page covers more nodes per request.",
        },
        {
            "key": "max_fact_rows",
            "label": "Maximum fact rows to index",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Cap on the (node, fact) rows the fact pre-index holds in memory. The whole-estate index includes full structured networking/dmi/os values, so a very large estate can otherwise exhaust the sandbox's memory before the first node is reported. 0 removes the cap. Nodes past the cap still import, without fact enrichment.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool', 'get_list')
load('json', json_encode='encode')
load('time', 'now', 'parse_ts')

load('coerce', 'as_dict', 'dedupe', 'dicts')
VENDOR = "puppetdb"
ATTR_PREFIX = "puppetdb"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

QUERY_PATH = "/pdb/query/v4"
NODES_PATH = QUERY_PATH + "/nodes"
FACTS_PATH = QUERY_PATH + "/facts"
PACKAGES_PATH = QUERY_PATH + "/package-inventory"

MAX_CHILDREN = 99

# Packages are fetched for the certnames on the node page that is being built,
# not for the whole estate, so neither the query string nor the response grows
# with the size of the installation. A batch of certnames well under a hundred
# keeps the encoded query far inside Jetty's default request header limit.
PACKAGE_BATCH = 25
PACKAGE_PAGE_SIZE = 5000

# The node states PuppetDB understands. The plain /nodes and /facts routes
# restrict themselves to active nodes unless the query names a state, so the
# active pass sends no state predicate at all and the optional inactive pass
# sends the one that selects deactivated and expired nodes. Asking for "any"
# instead would work, but PuppetDB elides that predicate entirely and a query
# that elides down to nothing is a shape worth not depending on.
STATE_ACTIVE = "active"
STATE_INACTIVE = "inactive"

# The facts worth importing. PuppetDB pages the facts endpoint by individual
# fact row rather than by node, and a Facter 4 node reports several hundred
# facts, so an unfiltered walk would read the whole fact table. Naming the facts
# that are actually mapped keeps the walk proportional to the estate.
#
# Facter 4 emits structured facts, and PuppetDB stores each one whole, so
# "networking" arrives as a single row whose value is the entire nested hash.
# The flat legacy names are requested alongside them because a Puppet agent
# still ships those and an older or non-Facter fact source may report only
# those.
STRUCTURED_FACTS = [
    "networking",
    "os",
    "dmi",
    "processors",
    "memory",
    "system_uptime",
]
SCALAR_FACTS = [
    "virtual",
    "is_virtual",
    "kernel",
    "kernelrelease",
    "kernelversion",
    "timezone",
    "fqdn",
    "hostname",
    "domain",
    "architecture",
    "hardwaremodel",
    "puppetversion",
    "aio_agent_version",
    "facterversion",
    "clientcert",
]
LEGACY_FACTS = [
    "operatingsystem",
    "operatingsystemrelease",
    "operatingsystemmajrelease",
    "osfamily",
    "lsbdistdescription",
    "manufacturer",
    "productname",
    "serialnumber",
    "uuid",
    "processorcount",
    "physicalprocessorcount",
    "memorysize_mb",
    "memorytotal",
    "ipaddress",
    "ipaddress6",
    "macaddress",
    "netmask",
    "interfaces",
    "bios_vendor",
    "bios_version",
    "bios_release_date",
]

# Loopback device names, dropped before interfaces are built.
LOOPBACK_IDENTIFIERS = ["lo", "lo0", "loopback"]

# An all-zero MAC means the source could not read one. Every node in that state
# would share a MAC, so it is dropped like loopback is.
EMPTY_MAC = "00:00:00:00:00:00"

# dmi.chassis.type as Facter reports it, lower-cased. Anything else is left
# unmapped so runZero's own fingerprinting decides.
CHASSIS_TYPES = {
    "desktop": "Desktop",
    "low profile desktop": "Desktop",
    "mini tower": "Desktop",
    "tower": "Desktop",
    "space-saving": "Desktop",
    "all in one": "Desktop",
    "notebook": "Laptop",
    "laptop": "Laptop",
    "portable": "Laptop",
    "sub notebook": "Laptop",
    "convertible": "Laptop",
    "detachable": "Laptop",
    "tablet": "Tablet",
    "hand held": "Mobile Device",
    "rack mount chassis": "Server",
    "main server chassis": "Server",
    "blade": "Server",
    "blade enclosure": "Server",
    "multi-system chassis": "Server",
    "expansion chassis": "Server",
}

# Values of the Facter virtual fact that mean the node is running on bare metal.
PHYSICAL_VIRTUAL = ["physical", "", "none"]

def _text(value):
    """Flatten a fact value into a plain string. Fact values are real JSON, so a
    structured fact arrives as a nested hash and is kept as compact JSON rather
    than as a Starlark repr."""
    if value == None:
        return ""
    if type(value) == "bool":
        return "true" if value else "false"
    if type(value) == "dict":
        return json_encode(value)
    if type(value) == "list":
        # Starlark forbids recursion, so the element cases are handled inline
        # rather than by calling back into this helper.
        parts = []
        for item in value:
            if item == None:
                continue
            if type(item) == "bool":
                parts.append("true" if item else "false")
            elif type(item) == "dict" or type(item) == "list":
                parts.append(json_encode(item))
            else:
                parts.append(str(item))
        return ",".join(parts)
    return str(value)
def _base_url(kwargs):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used: it keeps only the scheme and host and
    discards the path -- verified against the scanner, https://proxy/puppetdb
    comes back as https://proxy. PuppetDB's HTTP API is very often fronted by a
    reverse proxy that terminates TLS and mounts it under a prefix (the usual
    /puppetdb), because the service itself has no authentication of its own, so
    dropping the path would send every /pdb/query/v4 request to the wrong place
    on exactly the installs that are deployed correctly. librenms, netdisco and
    slurpit avoid it for the same reason.
    """
    return _text(get_string(kwargs, "url", default="")).strip().rstrip("/")
def _path(root, path):
    """Walk a dotted path through a structured fact, returning None when any
    step is missing or is not a hash."""
    node = root
    for key in path:
        if type(node) != "dict":
            return None
        node = node.get(key)
    return node

def _fact_text(facts, paths):
    """Return the first non-empty value among the named fact paths, as text.

    Each path is a list whose head is a fact name and whose tail walks into a
    structured fact, so ["os", "release", "full"] and ["operatingsystemrelease"]
    can be tried in order against whichever set of facts the node reports."""
    for path in paths:
        value = _path(facts, path)
        if value == None:
            continue
        text = _text(value).strip()
        if text:
            return text
    return ""
def _seen_ts(ctx, value):
    """Parse a timestamp and clamp it to the start of the run.

    A time in the future fails validation of the whole ImportAsset, not just the
    field, so a node whose clock or whose PuppetDB server clock runs fast would
    otherwise be dropped silently. The raw value is kept as a custom attribute
    either way."""
    parsed = parse_ts(value)
    if parsed == None:
        return None
    if parsed.unix > ctx["now"].unix:
        return ctx["now"]
    return parsed

def _latest_ts(ctx, values):
    """Return the most recent of a set of timestamps, already clamped."""
    latest = None
    for value in values:
        parsed = _seen_ts(ctx, value)
        if parsed == None:
            continue
        if latest == None or parsed.unix > latest.unix:
            latest = parsed
    return latest
def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable. The
    all-zero MAC is treated as absent because every node that fails to read one
    reports it."""
    mac = normalize_mac(_text(value).strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac

def _and(left, right):
    """Combine two optional AST query clauses."""
    if left == None:
        return right
    if right == None:
        return left
    return ["and", left, right]

def build_software(ctx, certname, address, packages):
    """Convert the packages Puppet Enterprise records against one node into
    Software records. The package-inventory endpoint publishes only the package
    name, its version, and the packaging system, and no CPE at all, so cpe23 is
    left unset rather than synthesized."""
    software = []
    seen = []
    for entry in packages:
        product = _text(entry.get("package_name")).strip()
        if not product:
            continue
        version = _text(entry.get("version")).strip()
        provider = _text(entry.get("provider")).strip()
        key = "{}:{}:{}".format(provider, product, version)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:{}:package:{}".format(VENDOR, ctx["scope"], certname, key)[:255],
            "product": product[:255],
        }
        # A node with no routable address gets no serviceAddress at all: the
        # platform filters loopback, so a 127.0.0.1 placeholder would only
        # vanish silently anyway.
        if address:
            params["serviceAddress"] = address
        if version:
            params["version"] = version[:255]
        if provider:
            params["customAttributes"] = to_custom_attributes(
                {"package_provider": provider},
                prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software

def collect_interfaces(networking):
    """Group everything Facter knows about each of a node's interfaces into one
    entry per device name.

    networking.interfaces is a hash keyed by device name, and each device holds
    its MAC plus bindings[] for IPv4 and bindings6[] for IPv6, each binding a
    hash of address, netmask, and network. An interface can carry several
    addresses, which is why the bindings arrays exist alongside the single ip
    and ip6 convenience keys, and both are read. Loopback devices are dropped by
    name before anything else."""
    ifaces = {}
    interfaces = as_dict(as_dict(networking).get("interfaces"))
    for name in interfaces:
        if name.lower() in LOOPBACK_IDENTIFIERS:
            continue
        entry = as_dict(interfaces[name])
        ips = []
        for binding in dicts(entry.get("bindings")) + dicts(entry.get("bindings6")):
            routable = routable_ip(binding.get("address"))
            if routable and routable not in ips:
                ips.append(routable)
        for value in [entry.get("ip"), entry.get("ip6")]:
            routable = routable_ip(value)
            if routable and routable not in ips:
                ips.append(routable)
        mac = _text(entry.get("mac")).strip()
        if not mac and not ips:
            continue
        ifaces[name] = {"identifier": name, "mac": mac, "ips": ips}
    return ifaces

def merge_interfaces(ifaces, node_mac, node_ips):
    """Reduce the per-device entries to the set that becomes network interfaces.

    Devices that report the same MAC are folded together, and the node's primary
    address and MAC are added last so a node whose facts carry no per-interface
    detail at all still gets an interface."""
    merged = []
    seen_macs = {}
    names = sorted(ifaces)
    for name in names:
        entry = ifaces[name]
        mac = _clean_mac(entry["mac"])
        if mac and mac in seen_macs:
            # A bond and its slaves, and a VLAN device and its parent, all
            # report the same MAC. They are one interface as far as runZero is
            # concerned, so their addresses are pooled under one record.
            target = merged[seen_macs[mac]]
            target["identifiers"].append(name)
            for ip in entry["ips"]:
                if ip not in target["ips"]:
                    target["ips"].append(ip)
            continue
        if not mac and not entry["ips"]:
            continue
        if mac:
            seen_macs[mac] = len(merged)
        merged.append({"identifiers": [name], "mac": mac, "ips": list(entry["ips"])})

    mac = _clean_mac(node_mac)
    if mac and mac in seen_macs:
        target = merged[seen_macs[mac]]
        for ip in node_ips:
            if ip not in target["ips"]:
                target["ips"].append(ip)
        return merged

    remaining = []
    for ip in node_ips:
        placed = False
        for entry in merged:
            if ip in entry["ips"]:
                placed = True
        if not placed and ip not in remaining:
            remaining.append(ip)
    if mac or remaining:
        merged.append({"identifiers": ["primary"], "mac": mac, "ips": remaining})
    return merged

def build_interfaces(merged):
    """Build one runZero network interface per Facter interface, so a multi-homed
    node keeps its per-NIC addressing instead of being collapsed onto a single
    address."""
    netifs = []
    for entry in merged:
        nic = network_interface(mac=entry["mac"], ips=entry["ips"])
        if nic:
            netifs.append(nic)
    return netifs

def build_asset(ctx, record, facts, packages):
    """Convert one PuppetDB node record and its facts into a runZero asset."""
    certname = _text(record.get("certname")).strip()
    networking = as_dict(facts.get("networking"))

    node_ips = []
    for path in [["networking", "ip"], ["networking", "ip6"], ["ipaddress"], ["ipaddress6"]]:
        routable = routable_ip(_fact_text(facts, [path]))
        if routable and routable not in node_ips:
            node_ips.append(routable)
    merged = merge_interfaces(
        collect_interfaces(networking),
        _fact_text(facts, [["networking", "mac"], ["macaddress"]]),
        node_ips,
    )
    netifs = build_interfaces(merged)

    # Software records need a service address; the address Facter marks as the
    # node's primary wins over whatever interface happened to be listed first.
    primary_ip = node_ips[0] if node_ips else ""
    for entry in merged:
        for ip in entry["ips"]:
            if not primary_ip:
                primary_ip = ip

    serial = _fact_text(facts, [["dmi", "product", "serial_number"], ["serialnumber"]])
    manufacturer = _fact_text(facts, [["dmi", "manufacturer"], ["manufacturer"]])
    # hardwaremodel is deliberately not a fallback here: Facter reports the CPU
    # architecture in it, so it would set every legacy node's model to x86_64.
    model = _fact_text(facts, [["dmi", "product", "name"], ["productname"]])
    chassis = _fact_text(facts, [["dmi", "chassis", "type"]])
    virtual = _fact_text(facts, [["virtual"]])
    is_virtual = _fact_text(facts, [["is_virtual"]])
    domain = _fact_text(facts, [["networking", "domain"], ["domain"]])
    fqdn = _fact_text(facts, [["networking", "fqdn"], ["fqdn"]])
    hostname = _fact_text(facts, [["networking", "hostname"], ["hostname"]])
    environment = _text(record.get("facts_environment")).strip() or _text(record.get("report_environment")).strip()
    report_status = _text(record.get("latest_report_status")).strip()
    deactivated = _text(record.get("deactivated")).strip()
    expired = _text(record.get("expired")).strip()

    software = build_software(ctx, certname, primary_ip, packages)

    tags = [VENDOR]
    if environment:
        tags.append("environment:" + environment)
    if serial:
        tags.append("serial:" + serial)
    if report_status:
        tags.append("report:" + report_status)
    if record.get("latest_report_noop") == True:
        tags.append("noop")
    if deactivated:
        tags.append("deactivated")
    if expired:
        tags.append("expired")

    attrs = {
        "certname": certname,
        "server": ctx["scope"],
        "deactivated": deactivated,
        "expired": expired,
        "catalog_environment": record.get("catalog_environment"),
        "facts_environment": record.get("facts_environment"),
        "report_environment": record.get("report_environment"),
        "catalog_timestamp": record.get("catalog_timestamp"),
        "facts_timestamp": record.get("facts_timestamp"),
        "report_timestamp": record.get("report_timestamp"),
        "latest_report_status": report_status,
        "latest_report_hash": record.get("latest_report_hash"),
        "latest_report_noop": record.get("latest_report_noop"),
        "latest_report_noop_pending": record.get("latest_report_noop_pending"),
        "latest_report_job_id": record.get("latest_report_job_id"),
        "latest_report_corrective_change": record.get("latest_report_corrective_change"),
        "cached_catalog_status": record.get("cached_catalog_status"),
        "fact_count": len(facts),
        "software_count": len(software),
        "interface_count": len(merged),
        # Devices folded onto one MAC are joined with +, so a bond reads
        # "bond0+eno1" rather than losing the slave device names.
        "interface_identifiers": [
            "+".join(dedupe(entry["identifiers"])) for entry in merged
        ],
        "interface_macs": [entry["mac"] for entry in merged if entry["mac"]],
        # Facter facts. Every one of these is absent on a node that has never
        # uploaded facts, and to_custom_attributes drops the empty values.
        "fact_fqdn": fqdn,
        "fact_hostname": hostname,
        "fact_domain": domain,
        "fact_primary_interface": _fact_text(facts, [["networking", "primary"]]),
        "fact_ip": _fact_text(facts, [["networking", "ip"], ["ipaddress"]]),
        "fact_ip6": _fact_text(facts, [["networking", "ip6"], ["ipaddress6"]]),
        "fact_mac": _fact_text(facts, [["networking", "mac"], ["macaddress"]]),
        "fact_netmask": _fact_text(facts, [["networking", "netmask"], ["netmask"]]),
        "fact_serial_number": serial,
        "fact_manufacturer": manufacturer,
        "fact_product_name": _fact_text(facts, [["dmi", "product", "name"], ["productname"]]),
        "fact_product_uuid": _fact_text(facts, [["dmi", "product", "uuid"], ["uuid"]]),
        "fact_chassis_type": chassis,
        "fact_bios_vendor": _fact_text(facts, [["dmi", "bios", "vendor"], ["bios_vendor"]]),
        "fact_bios_version": _fact_text(facts, [["dmi", "bios", "version"], ["bios_version"]]),
        "fact_bios_release_date": _fact_text(facts, [["dmi", "bios", "release_date"], ["bios_release_date"]]),
        "fact_os_name": _fact_text(facts, [["os", "name"], ["operatingsystem"]]),
        "fact_os_release": _fact_text(facts, [["os", "release", "full"], ["operatingsystemrelease"]]),
        "fact_os_major": _fact_text(facts, [["os", "release", "major"], ["operatingsystemmajrelease"]]),
        "fact_os_family": _fact_text(facts, [["os", "family"], ["osfamily"]]),
        "fact_os_description": _fact_text(facts, [["os", "distro", "description"], ["lsbdistdescription"]]),
        "fact_os_codename": _fact_text(facts, [["os", "distro", "codename"]]),
        "fact_os_architecture": _fact_text(facts, [["os", "architecture"], ["architecture"]]),
        "fact_os_hardware": _fact_text(facts, [["os", "hardware"], ["hardwaremodel"]]),
        "fact_selinux_enabled": _fact_text(facts, [["os", "selinux", "enabled"]]),
        "fact_kernel": _fact_text(facts, [["kernel"]]),
        "fact_kernel_release": _fact_text(facts, [["kernelrelease"]]),
        "fact_kernel_version": _fact_text(facts, [["kernelversion"]]),
        "fact_processor_count": _fact_text(facts, [["processors", "count"], ["processorcount"]]),
        "fact_processor_physical_count": _fact_text(facts, [["processors", "physicalcount"], ["physicalprocessorcount"]]),
        "fact_processor_cores": _fact_text(facts, [["processors", "cores"]]),
        "fact_processor_threads": _fact_text(facts, [["processors", "threads"]]),
        "fact_processor_isa": _fact_text(facts, [["processors", "isa"]]),
        "fact_processor_models": _fact_text(facts, [["processors", "models"]]),
        "fact_memory_total_bytes": _fact_text(facts, [["memory", "system", "total_bytes"]]),
        "fact_memory_total": _fact_text(facts, [["memory", "system", "total"], ["memorytotal"], ["memorysize_mb"]]),
        "fact_virtual": virtual,
        "fact_is_virtual": is_virtual,
        "fact_uptime_seconds": _fact_text(facts, [["system_uptime", "seconds"]]),
        "fact_timezone": _fact_text(facts, [["timezone"]]),
        "fact_puppet_version": _fact_text(facts, [["puppetversion"]]),
        "fact_agent_version": _fact_text(facts, [["aio_agent_version"]]),
        "fact_facter_version": _fact_text(facts, [["facterversion"]]),
        "fact_clientcert": _fact_text(facts, [["clientcert"]]),
    }
    for name in ctx["extra_facts"]:
        attrs["fact_" + name] = _fact_text(facts, [[name]])

    params = {
        # certname is PuppetDB's primary key and is stable across reboots,
        # renames, and re-addressing, but a node's addressing changes with every
        # DHCP lease and its hostname facts change with a rename, so network
        # churn must not disqualify a merge.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], certname),
        "hostnames": dedupe([certname, fqdn, hostname]),
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
    }
    if domain:
        params["domain"] = domain
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model

    os_name = _fact_text(facts, [["os", "name"], ["operatingsystem"]])
    os_version = _fact_text(facts, [["os", "release", "full"], ["operatingsystemrelease"]])
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version

    device_type = CHASSIS_TYPES.get(chassis.lower(), "")
    if is_virtual == "true" or (virtual and virtual.lower() not in PHYSICAL_VIRTUAL):
        device_type = "Virtual Machine"
    if device_type:
        params["deviceType"] = device_type

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    # PuppetDB records no creation time for a node, so firstSeenTS is
    # deliberately left unset rather than backfilled from a check-in time
    # that would move on every run.
    last_seen = _latest_ts(ctx, [
        record.get("report_timestamp"),
        record.get("facts_timestamp"),
        record.get("catalog_timestamp"),
    ])
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def query_pdb(ctx, path, query, order_by, limit, offset):
    """Fetch one page of a PuppetDB query endpoint, returning (rows, err).

    Every query endpoint answers with a bare JSON array rather than an envelope,
    and pages through the shared limit, offset, and order_by parameters. Results
    are explicitly unordered without order_by, so paging by offset is only
    stable when one is supplied."""
    params = {
        "limit": str(limit),
        "offset": str(offset),
        "order_by": json_encode(order_by),
    }
    if query != None:
        params["query"] = json_encode(query)
    data, err = get_json(ctx["base_url"] + path, params=params, **ctx["http_options"])
    if err:
        return None, err
    data = data or []
    if type(data) != "list":
        return None, "expected a JSON array from {}".format(path)
    return data, None

def state_query(state):
    """Build the node-state predicate for a pass.

    The plain /nodes and /facts routes add ["=", "node_state", "active"] to the
    query unless it already names a state, which is why the active pass needs no
    predicate of its own and the inactive pass names the state explicitly."""
    if state == STATE_INACTIVE:
        return ["=", "node_state", STATE_INACTIVE]
    return None

def fetch_facts(ctx, state, facts):
    """Index the mapped facts for every node in one paged walk over the facts
    endpoint, merging into the map the caller supplied.

    This is the whole reason the integration does not issue a request per node:
    GET /pdb/query/v4/facts answers for every node at once, one row per
    (certname, fact name) pair. The catch is real: PuppetDB pages that endpoint
    by fact row rather than by node, so one node's facts routinely straddle a
    page boundary. Treating each page as a complete fact set for the nodes it
    names would silently drop facts, so pages are merged into a single map keyed
    by certname instead."""
    query = _and(state_query(state), ["in", "name", ["array", ctx["fact_names"]]])
    if ctx["environment"]:
        query = _and(query, ["=", "environment", ctx["environment"]])
    order_by = [{"field": "certname"}, {"field": "name"}]

    rows = 0
    offset = 0
    capped = False
    _pager1 = pager("puppetdb-1")
    while _pager1.next():
        page, err = query_pdb(ctx, FACTS_PATH, query, order_by, ctx["fact_page_size"], offset)
        if err:
            print("puppetdb: failed to fetch facts, importing nodes without them:", err)
            return facts
        if not page:
            break
        for row in page:
            if type(row) != "dict":
                continue
            # The index bound: structured fact values are large, and the
            # index covers the whole estate before the first node is
            # reported, so an uncapped walk on a huge estate can hit the
            # sandbox's memory ceiling. Nodes past the cap still import,
            # without fact enrichment.
            if ctx["max_fact_rows"] and ctx["fact_rows_indexed"] >= ctx["max_fact_rows"]:
                capped = True
                break
            certname = _text(row.get("certname")).strip()
            name = _text(row.get("name")).strip()
            if not certname or not name:
                continue
            entry = facts.get(certname)
            if entry == None:
                entry = {}
                facts[certname] = entry
            entry[name] = row.get("value")
            ctx["fact_rows_indexed"] += 1
        rows += len(page)
        offset += len(page)
        if capped:
            print("puppetdb: fact index truncated at {} rows (max_fact_rows); remaining nodes import without fact enrichment".format(
                ctx["max_fact_rows"]))
            break
        if len(page) < ctx["fact_page_size"]:
            break

    print("puppetdb: indexed {} {} fact rows for {} nodes".format(rows, state, len(facts)))
    return facts

def fetch_packages(ctx, certnames):
    """Fetch the installed packages for one page of nodes.

    Package collection is a Puppet Enterprise feature, and the endpoint returns
    one row per (certname, package) pair for the whole estate, so the query is
    restricted to the certnames on the node page being built. That keeps this to
    a handful of requests per page rather than one per node, and keeps both the
    query string and the response bounded. A failure switches the feature off
    for the rest of the run rather than ending it."""
    packages = {}
    if not certnames:
        return packages
    order_by = [{"field": "certname"}, {"field": "package_name"}]

    start = 0
    _pager2 = pager("puppetdb-2")
    while _pager2.next():
        if start >= len(certnames):
            break
        batch = certnames[start:start + PACKAGE_BATCH]
        start += PACKAGE_BATCH
        query = _and(ctx["package_state"], ["in", "certname", ["array", batch]])

        offset = 0
        _pager3 = pager("puppetdb-3")
        while _pager3.next():
            page, err = query_pdb(ctx, PACKAGES_PATH, query, order_by, PACKAGE_PAGE_SIZE, offset)
            if err:
                ctx["packages"] = False
                if err.startswith("status 404") or err.startswith("status 400"):
                    print("puppetdb: this server has no package inventory, skipping packages:", err)
                elif err.startswith("status 403"):
                    print("puppetdb: not permitted to read package inventory, skipping packages:", err)
                else:
                    print("puppetdb: failed to fetch package inventory, skipping packages:", err)
                return packages
            if not page:
                break
            for row in page:
                if type(row) != "dict":
                    continue
                certname = _text(row.get("certname")).strip()
                if not certname:
                    continue
                entry = packages.get(certname)
                if entry == None:
                    entry = []
                    packages[certname] = entry
                # Anything past the per-asset cap is discarded here rather than
                # accumulated and thrown away at the ImportAsset boundary.
                if len(entry) < MAX_CHILDREN:
                    entry.append(row)
            offset += len(page)
            if len(page) < PACKAGE_PAGE_SIZE:
                break
    return packages

def build_assets(ctx, records, facts):
    """Convert a page of PuppetDB node records into runZero assets, enriching
    each with its facts and, when enabled, its package inventory."""
    certnames = []
    for record in records:
        if type(record) != "dict":
            continue
        certname = _text(record.get("certname")).strip()
        if not certname:
            print("puppetdb: skipping node with no certname")
            continue
        certnames.append(certname)

    packages = fetch_packages(ctx, certnames) if ctx["packages"] else {}

    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        certname = _text(record.get("certname")).strip()
        if not certname:
            continue
        assets.append(build_asset(ctx, record, facts.get(certname, {}), packages.get(certname, [])))
    return assets

def fetch_and_report_nodes(ctx, state, facts):
    """Fetch and stream nodes one page at a time so the full inventory is never
    held in memory at once."""
    query = state_query(state)
    if ctx["environment"]:
        query = _and(query, ["=", "facts_environment", ctx["environment"]])
    order_by = [{"field": "certname"}]

    reported = 0
    offset = 0
    _pager4 = pager("puppetdb-4")
    while _pager4.next():
        page, err = query_pdb(ctx, NODES_PATH, query, order_by, ctx["page_size"], offset)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("puppetdb: the PuppetDB server rejected the credential:", err)
            else:
                print("puppetdb: failed to fetch {} nodes: {}".format(state, err))
            return reported
        if not page:
            break
        reported += report_assets(build_assets(ctx, page, facts))
        offset += len(page)
        if len(page) < ctx["page_size"]:
            break

    print("puppetdb: reported {} {} nodes".format(reported, state))
    return reported

def main(**kwargs):
    base_url = _base_url(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("puppetdb: could not determine the PuppetDB host from the configured URL")
        return None

    auth_token = get_string(kwargs, "auth_token", default="").strip()
    headers = {"Accept": "application/json"}
    if auth_token:
        headers["X-Authentication"] = auth_token
    elif not get_string(kwargs, "tls_client_cert", default="").strip():
        # Neither credential is a hard requirement: PuppetDB's cleartext
        # listener authenticates nobody, and an installation that exposes it to
        # the Explorer is a supported configuration. The request is still made
        # so the server, not this script, decides.
        print("puppetdb: no client certificate and no X-Authentication token were configured;" +
              " the request will only succeed against an unauthenticated listener")

    extra_facts = []
    for name in get_list(kwargs, "extra_facts", default=[]):
        text = _text(name).strip()
        if text and text not in extra_facts:
            extra_facts.append(text)

    ctx = {
        "base_url": base_url,
        "http_options": get_http_options(kwargs, headers=headers),
        "scope": scope,
        "now": now(),
        "environment": get_string(kwargs, "environment", default="").strip(),
        "page_size": get_int(kwargs, "page_size", default=500),
        "fact_page_size": get_int(kwargs, "fact_page_size", default=2000),
        "max_fact_rows": get_int(kwargs, "max_fact_rows", default=0),
        "fact_rows_indexed": 0,
        "packages": get_bool(kwargs, "include_packages", default=False),
        "extra_facts": extra_facts,
        "fact_names": STRUCTURED_FACTS + SCALAR_FACTS + LEGACY_FACTS + extra_facts,
        "package_state": None,
    }

    states = [STATE_ACTIVE]
    if get_bool(kwargs, "include_inactive", default=False):
        states.append(STATE_INACTIVE)
        # One package query covers both passes, so it must not be restricted to
        # active nodes when the inactive pass is running.
        ctx["package_state"] = ["=", "node_state", "any"]

    facts = {}
    for state in states:
        fetch_facts(ctx, state, facts)

    reported = 0
    for state in states:
        reported += fetch_and_report_nodes(ctx, state, facts)
    if not reported:
        print("puppetdb: no assets retrieved")
    return None

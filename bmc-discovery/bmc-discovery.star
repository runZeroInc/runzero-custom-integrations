# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-bmc-discovery",
    "name": "BMC Helix Discovery",
    "type": "inbound",
    "description": "Imports hosts, software instances, and listening ports from BMC Helix Discovery.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The BMC key is authoritative and one Host node is one host, so the id
    # drives merges on its own. Only the break flags are tuned, and they only
    # matter for a first-contact merge against an asset runZero already
    # scanned, because MatchByForeignID never consults the MAC, IP, or name
    # break helpers: once the id matches, nothing can veto it. MAC and name
    # breaks are left on, because BMC reads the interface table and the OS
    # hostname off the host itself under credentials, so a total
    # disagreement there really does mean a different device, and the
    # hostname comparison already tolerates short-name versus FQDN.
    # no-ip-break is set because addresses are the one signal that ages
    # between scheduled discovery runs: a host that DHCP moved since BMC last
    # scanned it would otherwise have its correct MAC or hostname match
    # disqualified by a stale address and be imported as a duplicate.
    "matchBehavior": "no-ip-break",
    "params": [
        {
            "key": "url",
            "label": "BMC Discovery appliance URL",
            "type": "url",
            "required": True,
            "placeholder": "https://discovery.example.com",
            "description": "Base URL of the BMC Discovery appliance or Helix Discovery tenant. The /api/<version>/ path is appended automatically.",
        },
        {
            "key": "api_version",
            "label": "REST API version",
            "type": "string",
            "required": False,
            "default": "v1.3",
            "description": "Version segment of the appliance REST API path. The version tracks the appliance release: 21.3 publishes v1.3, 24.2 publishes v1.12, 25.2 publishes v1.14. Higher versions stay backwards compatible.",
        },
        {
            "key": "host_filter",
            "label": "Host filter",
            "type": "string",
            "required": False,
            "description": "Optional BMC Query Language condition appended to the host search as a WHERE clause, for example os_class = 'UNIX'. Leave blank to import every host.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "API token generated for a BMC Discovery user that holds the api-access permission.",
        },
        {
            "key": "include_details",
            "label": "Import software and listening ports",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch software instances and listening ports per host. Costs up to two extra searches per host; disable it to import the host inventory only.",
        },
        {
            "key": "detail_limit",
            "label": "Detail enrichment limit",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "description": "Maximum number of hosts to enrich with software and listening ports. Hosts past the limit are still imported, without software or services. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'routable_ip')
load('http', 'post_json', 'bearer', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_ts')

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "bmc-discovery"
ATTR_PREFIX = "bmc_discovery"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
SEARCH_PATH = "/data/search"
PAGE_SIZE = 200          # the documented default is 100; no maximum is published
DETAIL_PAGE_SIZE = 500   # rows collected for one host, single page only
MAX_CHILDREN = 99
MAX_INTERFACES = 32
MAX_HOSTNAMES = 16
MAX_ID = 255
PORT_FAILURE_BUDGET = 3  # consecutive port traversals allowed to fail before it is dropped
DIGITS = "0123456789"
HEX_DIGITS = "0123456789abcdefABCDEF"
TRANSPORTS = ["tcp", "udp", "sctp"]
# BMC stores a date attribute as a count of 100-nanosecond ticks since the Unix
# epoch, which is how the appliance's own queries convert one to seconds
# (abs(last_update_success) / 10000000). A value outside this window is not a
# tick count and is left alone rather than turned into a wrong first-seen date.
TICKS_PER_SECOND = 10000000
MIN_PLAUSIBLE_UNIX = 631152000   # 1990-01-01

# Host node attributes requested by the inventory search. Every name is either
# documented on the Host node reference or present in a captured
# /data/search?format=object Host response, so the SHOW clause should not name an
# attribute the datastore does not know about.
HOST_ATTRS = [
    "#id",
    "key",
    "name",
    "hostname",
    "local_fqdn",
    "domain",
    "dns_domain",
    "workgroup",
    "os",
    "os_class",
    "os_type",
    "os_version",
    "os_arch",
    "os_vendor",
    "os_build",
    "os_edition",
    "os_release_name",
    "service_pack",
    "kernel",
    "platform",
    "type",
    "role",
    "model",
    "product_model",
    "vendor",
    "serial",
    "uuid",
    "hostid",
    "machine_id",
    "virtual",
    "vm_class",
    "partition",
    "zonename",
    "ram",
    "logical_ram",
    "num_processors",
    "package_count",
    "patch_count",
    "cloud",
    "aws_instance_id",
    "azure_vm_id",
    "gce_instance_id",
    "openstack_instance_id",
    "management_ip_addr",
    "last_update_success",
    "age_count",
    "__all_ip_addrs",
    "__all_mac_addrs",
    "__all_dns_names",
]

# The fallback SHOW clause, used once if the full one is rejected. It names only
# the attributes needed to build an identifiable asset, so an appliance whose
# schema predates one of the attributes above still imports.
HOST_CORE_ATTRS = [
    "#id",
    "key",
    "name",
    "hostname",
    "local_fqdn",
    "domain",
    "dns_domain",
    "os",
    "os_type",
    "os_version",
    "type",
    "model",
    "vendor",
    "serial",
    "uuid",
    "virtual",
    "__all_ip_addrs",
    "__all_mac_addrs",
    "__all_dns_names",
]

# Software runs on its host through a single documented relationship.
SOFTWARE_TRAVERSE = ["Host:HostedSoftware:RunningSoftware:SoftwareInstance"]
SOFTWARE_ATTRS = [
    "#id", "key", "name", "short_name", "type", "instance", "product", "publisher",
    "version", "product_version", "release", "edition", "install_root", "listening_ports",
]

# A DiscoveredListeningPort is raw discovery data hanging off the DiscoveryAccess
# that observed it, not off the Host, so reaching it from a host takes four hops:
# Host -> HostInfo -> DiscoveryAccess -> NetworkConnectionList -> port. The chain
# is the reverse of the one BMC's own reporting queries walk in the other
# direction. It is the least verifiable part of this integration, so it is
# budgeted: a few failures in a row and the traversal is dropped for the rest of
# the run, leaving the listening_ports attribute of each software instance as the
# service source.
PORT_TRAVERSE = [
    "InferredElement:Inference:Primary:HostInfo",
    "DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess",
    "DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:NetworkConnectionList",
    "List:List:Member:DiscoveredListeningPort",
]
PORT_ATTRS = ["#id", "local_port", "protocol", "local_ip_addr", "state", "pid"]

# Names BMC reports for a host that has no real name of its own. local_fqdn is
# literally "localhost" on a large share of UNIX hosts, and letting that through
# would enrol one hostname for the whole estate in the trusted-name set.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "localhost6", "localhost6.localdomain6", "unknown", "none", "null"]
NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"

# BMC types a Host with free text assembled from the OS family and the role, so
# the device type is decided by keyword rather than by an exact-match table.
DEVICE_TYPE_KEYWORDS = [
    ("desktop", "Desktop"),
    ("workstation", "Desktop"),
    ("laptop", "Laptop"),
    ("hypervisor", "Hypervisor"),
    ("server", "Server"),
    ("mainframe", "Mainframe"),
    ("printer", "Printer"),
    ("storage", "Storage"),
]
def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is not numeric."""
    if type(value) == "int":
        return value
    text = str(value).strip()
    if not text or len(text) > 10:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)

def _list(value):
    """Coerce a field documented as a list into one, so a scalar cannot abort the
    run. BMC serializes an empty multi-valued attribute as null."""
    if value == None:
        return []
    if type(value) == "list":
        return value
    return [value]
def _last_seen_ts(value):
    """Parse the Host last_update_success attribute. BMC stores a date as
    100-nanosecond ticks since the epoch, but the REST layer is not documented
    to serialize it that way, so both shapes are handled: a number too large to
    be a Unix epoch is converted from ticks, and everything else -- an epoch in
    seconds or a text stamp -- is parsed as-is. parse_ts clamps a future value
    to now, so a fast appliance clock cannot drop the record."""
    if type(value) == "float":
        value = int(value)
    if type(value) == "int" and value > MIN_PLAUSIBLE_UNIX * TICKS_PER_SECOND:
        return parse_ts(value // TICKS_PER_SECOND)
    return parse_ts(value)

def _node_id(value):
    """Return a datastore node id that is safe to interpolate into a query, or an
    empty string. Node ids are hex, so anything else is rejected outright rather
    than escaped."""
    text = as_text(value, join=",").strip()
    if not text or len(text) > 64:
        return ""
    for index in range(len(text)):
        if text[index] not in HEX_DIGITS:
            return ""
    return text

def _foreign_id(record):
    """Return the identity of a host and how it was derived. BMC documents the
    key attribute as the globally unique key of the real-world entity and
    recommends it over the node id for exactly this purpose: the node id is not
    guaranteed to be stable and is not carried across the destruction and
    recreation of a node, whereas the key survives both."""
    key = as_text(record.get("key"), join=",").strip()
    if key:
        return key[:MAX_ID], "key"
    node_id = _node_id(record.get("#id"))
    if node_id:
        return "node:" + node_id, "node-id"
    return "", ""

def _names(record):
    """Collect the usable hostnames of a host. BMC reports local_fqdn as
    "localhost" on many UNIX hosts and sometimes names an unidentified host after
    its address, so placeholders and bare IPs are dropped, along with anything
    that is not shaped like a host name at all. runZero enrols custom-integration
    hostnames in the trusted-name set, and a name shared by the whole estate
    there is an estate-merging bug."""
    candidates = [record.get("hostname"), record.get("name"), record.get("local_fqdn")]
    candidates = candidates + _list(record.get("__all_dns_names"))
    out = []
    for candidate in candidates:
        text = as_text(candidate, join=",").strip()
        if not text or len(text) > 253 or text.lower() in PLACEHOLDER_NAMES:
            continue
        if ip_address(text) != None:
            continue
        usable = True
        for index in range(len(text)):
            if text[index] not in NAME_CHARS:
                usable = False
                break
        if usable and text not in out:
            out.append(text)
    return out[:MAX_HOSTNAMES]

def _device_type(record):
    """Map the free-text BMC host type onto the runZero device type vocabulary."""
    text = as_text(record.get("type"), join=",").strip().lower()
    if not text:
        return ""
    for keyword, device_type in DEVICE_TYPE_KEYWORDS:
        if keyword in text:
            return device_type
    return ""

def _envelopes(data):
    """Unwrap a /data/search response. The response is a list of per-kind
    envelopes, each carrying its own results and cursor, not a single object."""
    if type(data) == "list":
        return dicts(data)
    if type(data) == "dict":
        return [data]
    return []

def _rows(envelopes):
    """Collect the result rows of every envelope in one response."""
    rows = []
    for envelope in envelopes:
        rows = rows + dicts(envelope.get("results"))
    return rows

def build_query(kind, where, traversals, attrs):
    """Assemble one BMC Query Language search."""
    query = "SEARCH " + kind
    if where:
        query += " WHERE " + where
    for traversal in traversals:
        query += " TRAVERSE " + traversal
    return query + " SHOW " + ", ".join(attrs)

def run_search(ctx, query, offset, results_id, limit):
    """Run one page of a search. The cursor is the (offset, results_id) pair the
    previous response echoed back, and offset is never sent without results_id
    because the appliance rejects that combination. format, limit, and the cursor
    travel in the query string while the query itself travels in the body."""
    params = {"format": "object", "limit": str(limit)}
    if results_id and offset > 0:
        params["offset"] = str(offset)
        params["results_id"] = results_id
    return post_json(ctx["search_url"], json={"query": query}, params=params, **ctx["http_options"])

def fetch_detail_rows(ctx, node_id, traversals, attrs, label):
    """Traverse from one host to a related kind and return the rows. Only the
    first page is fetched: a per-host relationship set larger than
    DETAIL_PAGE_SIZE is far past the per-asset child cap anyway. The traversal is
    anchored on the datastore node id rather than the key, because the node id is
    hex and can be interpolated into a query safely. A failure is reported and
    treated as an empty result so that one unreadable host cannot end the run."""
    query = build_query("Host", "#id = '" + node_id + "'", traversals, attrs)
    data, err = run_search(ctx, query, 0, "", DETAIL_PAGE_SIZE)
    if err:
        print("bmc-discovery: failed to fetch {} for host {}: {}".format(label, node_id, err))
        return None
    return _rows(_envelopes(data or []))

def build_software(ctx, foreign_id, address, rows):
    """Convert the software instances running on one host into Software records.
    BMC publishes no CPE on a SoftwareInstance, so cpe23 is deliberately left
    unset rather than synthesized, and it records no CVE anywhere in the
    datastore, so this integration reports no vulnerabilities at all."""
    software = []
    seen = []
    for row in rows:
        product = as_text(row.get("product"), join=",").strip() or as_text(row.get("type"), join=",").strip() or as_text(row.get("name"), join=",").strip()
        if not product:
            continue
        key = as_text(row.get("key"), join=",").strip() or _node_id(row.get("#id")) or product
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:{}:si:{}".format(VENDOR, ctx["scope"], foreign_id, key)[:MAX_ID],
            "product": product[:255],
            "serviceAddress": address or "127.0.0.1",
        }
        publisher = as_text(row.get("publisher"), join=",").strip()
        if publisher:
            params["vendor"] = publisher[:255]
        version = as_text(row.get("version"), join=",").strip() or as_text(row.get("product_version"), join=",").strip()
        if version:
            params["version"] = version[:255]
        edition = as_text(row.get("edition"), join=",").strip()
        if edition:
            params["softwareEdition"] = edition[:255]
        install_root = as_text(row.get("install_root"), join=",").strip()
        if install_root:
            params["installedFrom"] = install_root[:255]
        params["customAttributes"] = to_custom_attributes({
            "software_key": key,
            "software_name": row.get("name"),
            "software_type": row.get("type"),
            "software_instance": row.get("instance"),
            "software_release": row.get("release"),
            "software_listening_ports": row.get("listening_ports"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software

def _port_row(row):
    """Extract (port, transport, address) from one listening port row. BMC names
    the socket attributes local_port, protocol, and local_ip_addr, but the
    alternatives are accepted too because the node has no published attribute
    reference and a renamed attribute simply arrives as null."""
    port = -1
    for key in ("local_port", "port", "port_number"):
        candidate = _to_int(row.get(key, -1))
        if candidate >= 0:
            port = candidate
            break

    transport = ""
    for key in ("protocol", "transport", "proto"):
        named = row.get(key)
        if named:
            transport = str(named).strip().lower()
            break
    if transport not in TRANSPORTS:
        transport = ""

    address = ""
    for key in ("local_ip_addr", "bound_address", "ip_addr", "address"):
        candidate = as_text(row.get(key), join=",").strip()
        # A socket bound to every interface is reported as 0.0.0.0 or ::, which
        # is a real fact about the listener but a useless service address.
        if not candidate or candidate in ("0.0.0.0", "::", "*"):
            continue
        routable = routable_ip(candidate)
        if routable:
            address = routable
            break

    return port, transport, address

def _add_service(services, seen, address, port, transport, source, extra):
    """Append one Service, skipping a socket already recorded for this host."""
    if port < 1 or port > 65535:
        return
    assumed = transport == ""
    if assumed:
        transport = "tcp"
    key = "{}/{}/{}".format(address, port, transport)
    if key in seen:
        return
    seen.append(key)
    attrs = {
        "service_source": source,
        "transport_source": "assumed" if assumed else "reported",
    }
    attrs.update(extra)
    services.append(Service(
        address=address,
        port=int(port),
        transport=transport,
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    ))

def build_services(host_ips, port_rows, software_rows):
    """Build Service objects for one host. The discovered listening ports come
    first: those are sockets the host itself reported as listening, which is what
    makes this a real service source rather than the far end of an observed
    connection. The listening_ports attribute of each software instance fills in
    behind them, because it costs no extra request and still covers a host whose
    raw discovery data has aged out of the datastore. A socket address is only
    honored when it is one of the host's own addresses, so a mis-traversed row
    cannot hang a service off an address that does not belong to this asset, and
    a host with no routable address of its own gets no services at all rather
    than a pile of services on a shared placeholder."""
    if not host_ips:
        return []
    host_address = host_ips[0]

    services = []
    seen = []
    for row in port_rows:
        port, transport, address = _port_row(row)
        if address not in host_ips:
            address = host_address
        _add_service(services, seen, address, port, transport, "DiscoveredListeningPort", {
            "listening_port_id": _node_id(row.get("#id")),
            "listening_port_state": row.get("state"),
        })

    for row in software_rows:
        name = as_text(row.get("product"), join=",").strip() or as_text(row.get("type"), join=",").strip() or as_text(row.get("name"), join=",").strip()
        for entry in _list(row.get("listening_ports")):
            _add_service(services, seen, host_address, _to_int(entry), "", "SoftwareInstance.listening_ports", {
                "listening_software": name,
            })

    return services

def build_asset(ctx, record, foreign_id, id_source):
    """Convert one BMC Host node into a runZero asset, optionally enriched with
    the software and listening ports reachable from it."""
    node_id = _node_id(record.get("#id"))

    ips = []
    for entry in _list(record.get("__all_ip_addrs")) + _list(record.get("management_ip_addr")):
        routable = routable_ip(as_text(entry, join=",").strip())
        if routable and routable not in ips:
            ips.append(routable)

    macs = dedupe(_list(record.get("__all_mac_addrs")))
    netifs = []
    if macs:
        for index in range(len(macs[:MAX_INTERFACES])):
            # BMC does not say which address belongs to which MAC, so the
            # addresses ride on the first interface and the rest carry MAC only.
            nic = network_interface(mac=macs[index], ips=ips if index == 0 else [])
            if nic:
                netifs.append(nic)
    elif ips:
        nic = network_interface(ips=ips)
        if nic:
            netifs.append(nic)

    address = ips[0] if ips else ""

    software = []
    services = []
    enriched = False
    if ctx["include_details"] and node_id:
        if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        else:
            ctx["detail_used"] += 1
            enriched = True
            software_rows = fetch_detail_rows(
                ctx, node_id, SOFTWARE_TRAVERSE, SOFTWARE_ATTRS, "software instances") or []
            software = build_software(ctx, foreign_id, address, software_rows)
            port_rows = []
            # A host with no routable address of its own cannot carry a Service,
            # so the port traversal is not worth a request.
            if ips and ctx["port_failures"] < PORT_FAILURE_BUDGET:
                port_rows = fetch_detail_rows(
                    ctx, node_id, PORT_TRAVERSE, PORT_ATTRS, "listening ports")
                if port_rows == None:
                    port_rows = []
                    ctx["port_failures"] += 1
                    if ctx["port_failures"] >= PORT_FAILURE_BUDGET:
                        print("bmc-discovery: the listening port traversal failed {} times; falling back to the listening_ports attribute of each software instance for the rest of the run".format(
                            ctx["port_failures"]))
                else:
                    ctx["port_failures"] = 0
            services = build_services(ips, port_rows, software_rows)

    tags = [VENDOR]
    os_class = as_text(record.get("os_class"), join=",").strip()
    if os_class:
        tags.append("os-class:" + os_class)
    if record.get("virtual") == True:
        tags.append("virtual")
    # cloud is documented as a flag meaning the host runs directly on a cloud
    # service, so it is tagged rather than used as a provider name.
    if record.get("cloud") == True:
        tags.append("cloud-hosted")

    attrs = {
        "key": foreign_id,
        "id_source": id_source,
        "node_id": node_id,
        "appliance": ctx["scope"],
        "kind": "Host",
        "name": record.get("name"),
        "hostname": record.get("hostname"),
        "local_fqdn": record.get("local_fqdn"),
        "dns_domain": record.get("dns_domain"),
        "domain": record.get("domain"),
        "workgroup": record.get("workgroup"),
        "type": record.get("type"),
        "role": record.get("role"),
        "platform": record.get("platform"),
        "os": record.get("os"),
        "os_class": os_class,
        "os_type": record.get("os_type"),
        "os_version": record.get("os_version"),
        "os_arch": record.get("os_arch"),
        "os_vendor": record.get("os_vendor"),
        "os_build": record.get("os_build"),
        "os_edition": record.get("os_edition"),
        "os_release_name": record.get("os_release_name"),
        "service_pack": record.get("service_pack"),
        "kernel": record.get("kernel"),
        "model": record.get("model"),
        "product_model": record.get("product_model"),
        "vendor": record.get("vendor"),
        "serial": record.get("serial"),
        "uuid": record.get("uuid"),
        "hostid": record.get("hostid"),
        "machine_id": record.get("machine_id"),
        "virtual": record.get("virtual"),
        "vm_class": record.get("vm_class"),
        "partition": record.get("partition"),
        "zonename": record.get("zonename"),
        "ram": record.get("ram"),
        "logical_ram": record.get("logical_ram"),
        "num_processors": record.get("num_processors"),
        "package_count": record.get("package_count"),
        "patch_count": record.get("patch_count"),
        "cloud": record.get("cloud"),
        "aws_instance_id": record.get("aws_instance_id"),
        "azure_vm_id": record.get("azure_vm_id"),
        "gce_instance_id": record.get("gce_instance_id"),
        "openstack_instance_id": record.get("openstack_instance_id"),
        "management_ip_addr": record.get("management_ip_addr"),
        # age_count counts consecutive successful updates and goes negative once
        # a host stops answering, which is how BMC decides to age it out.
        "age_count": record.get("age_count"),
        # The raw value is kept verbatim next to the parsed one, because the
        # parsed one is clamped to now when the appliance clock runs ahead.
        "last_update_success": record.get("last_update_success"),
        # The raw address lists are kept too: loopback and link-local are
        # filtered out of the network interfaces, not out of the record.
        "all_ip_addrs": record.get("__all_ip_addrs"),
        "all_mac_addrs": record.get("__all_mac_addrs"),
        "all_dns_names": record.get("__all_dns_names"),
        "detail_enriched": "true" if enriched else "false",
    }
    if enriched:
        attrs["software_instance_count"] = len(software)
        attrs["listening_port_count"] = len(services)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], foreign_id),
        "hostnames": _names(record),
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
        "services": services[:MAX_CHILDREN],    }

    os_name = as_text(record.get("os"), join=",").strip()
    if os_name:
        params["os"] = os_name
    os_version = as_text(record.get("os_version"), join=",").strip()
    if os_version:
        params["osVersion"] = os_version
    manufacturer = as_text(record.get("vendor"), join=",").strip()
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = as_text(record.get("model"), join=",").strip() or as_text(record.get("product_model"), join=",").strip()
    if model:
        params["model"] = model
    device_type = _device_type(record)
    if device_type:
        params["deviceType"] = device_type
    domain = as_text(record.get("dns_domain"), join=",").strip()
    if domain and ip_address(domain) == None:
        params["domain"] = domain

    last_ts = _last_seen_ts(record.get("last_update_success"))

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset

def build_assets(ctx, records):
    """Convert a page of BMC Host rows into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        foreign_id, id_source = _foreign_id(record)
        if not foreign_id:
            print("bmc-discovery: skipping host with no key and no node id: hostname=" + as_text(record.get("hostname"), join=","))
            continue
        if id_source == "node-id" and not ctx["node_id_warned"]:
            ctx["node_id_warned"] = True
            print("bmc-discovery: at least one host published no key; falling back to the datastore node id, which BMC does not guarantee to be stable across a rescan")
        assets.append(build_asset(ctx, record, foreign_id, id_source))
    return assets

def fetch_and_report_hosts(ctx):
    """Fetch and stream hosts one page at a time so the full inventory is never
    held in memory at once. Paging follows the cursor the appliance echoes back:
    each envelope reports next_offset and results_id, and the next request is
    rebuilt against the configured URL rather than following the absolute next
    link, which names the appliance by its own hostname and may not be reachable
    the way the Explorer reaches it."""
    attrs = HOST_ATTRS
    query = build_query("Host", ctx["host_filter"], [], attrs)
    reported = 0
    offset = 0
    results_id = ""
    warned = False

    _pager = pager("bmc-discovery")

    while _pager.next():

        page = _pager.page
        data, err = run_search(ctx, query, offset, results_id, PAGE_SIZE)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("bmc-discovery: authentication to the appliance failed:", err)
                return reported
            if page == 1 and len(attrs) > len(HOST_CORE_ATTRS):
                # An appliance older than one of the requested attributes rejects
                # the whole search, so the reduced attribute set is tried once
                # before the run is given up on.
                print("bmc-discovery: host search failed, retrying with the core attribute set:", err)
                attrs = HOST_CORE_ATTRS
                query = build_query("Host", ctx["host_filter"], [], attrs)
                data, err = run_search(ctx, query, offset, results_id, PAGE_SIZE)
            if err:
                print("bmc-discovery: failed to fetch hosts:", err)
                return reported

        envelopes = _envelopes(data or [])
        rows = _rows(envelopes)
        if not rows:
            break

        reported += report_assets(build_assets(ctx, rows))

        next_offset = -1
        next_results_id = ""
        cursors = 0
        for envelope in envelopes:
            envelope_id = as_text(envelope.get("results_id"), join=",").strip()
            candidate = _to_int(envelope.get("next_offset", -1))
            # A cursor that does not advance means the appliance is ignoring the
            # offset, so paging stops rather than looping on the same page.
            if envelope_id and candidate > offset:
                cursors += 1
                if next_offset < 0:
                    next_offset = candidate
                    next_results_id = envelope_id
        if cursors > 1 and not warned:
            warned = True
            print("bmc-discovery: the search returned {} paged result sets; only the first is followed".format(cursors))
        if next_offset < 0:
            break
        offset = next_offset
        results_id = next_results_id

    print("bmc-discovery: reported {} assets".format(reported))
    if ctx["detail_skipped"]:
        print("bmc-discovery: detail limit of {} reached; software and listening ports were not imported for {} of {} assets".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        fail("bmc-discovery: could not determine the appliance host from the configured URL")

    api_version = get_string(kwargs, "api_version", default="v1.3").strip().strip("/")
    if not api_version:
        api_version = "v1.3"

    http_options = get_http_options(kwargs, headers={
        # The appliance requires the capitalized scheme name; a lower-case
        # "bearer" has been rejected since the 21.3 release.
        "Authorization": bearer(get_string(kwargs, "api_token")),
        "Accept": "application/json",
    })

    detail_limit = get_int(kwargs, "detail_limit", default=500)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "search_url": base_url + "/api/" + api_version + SEARCH_PATH,
        "http_options": http_options,
        "scope": scope,
        "host_filter": get_string(kwargs, "host_filter", default="").strip(),
        "include_details": get_bool(kwargs, "include_details", default=True),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "port_failures": 0,
        "node_id_warned": False,
    }

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("bmc-discovery: no assets retrieved")
    return None

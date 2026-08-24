# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-opennms-horizon",
    "name": "OpenNMS Horizon",
    "type": "inbound",
    "description": "Imports monitored nodes, their IP interfaces, SNMP interfaces and MAC addresses, and their asset records from an OpenNMS Horizon server.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "OpenNMS URL",
            "type": "url",
            "required": True,
            "placeholder": "https://opennms.example.com:8980",
            "description": "Base URL of the OpenNMS server, including the port. Horizon listens on 8980 by default. OpenNMS is self-hosted, so there is no default host.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "An OpenNMS user in a role that can read the ReST API, such as ROLE_REST or ROLE_USER. The integration only reads.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "That user's password. OpenNMS authenticates the ReST API with HTTP Basic.",
        },
        {
            "key": "context_path",
            "label": "Application context path",
            "type": "string",
            "required": False,
            "default": "/opennms",
            "description": "The path OpenNMS is served under. This is /opennms on a default install and is only different when a reverse proxy rewrites it away.",
        },
        {
            "key": "collect_interfaces",
            "label": "Collect interfaces",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Collect IP interfaces and their MAC addresses. This is where addressing comes from, so it is on by default.",
        },
        {
            "key": "collect_snmp_interfaces",
            "label": "Collect SNMP-only interfaces",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Additionally walk the SNMP interface table, which supplies MAC addresses for ports that have no IP bound. Requires the v2 API; ignored when falling back to per-node requests.",
        },
        {
            "key": "collect_services",
            "label": "Record monitored services",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Walk the monitored-service list once and record each host's service names as a custom attribute. OpenNMS services carry no port number, so they are recorded as names and not imported as runZero services.",
        },
        {
            "key": "detail_limit",
            "label": "Per-node request limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Only used when the v2 interface endpoints are unavailable and the integration falls back to one request per node. Nodes past the limit are imported without interfaces. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Records per page",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 10000,
            "description": "Records requested per page. OpenNMS defaults to 10 when no limit is sent, which is why this is always supplied.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'from_timestamp', 'now')
load('re', re_match='match')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "opennms"
ATTR_PREFIX = "opennms"
ATTR_SEPARATOR = "_"

# The v1 tree is the stable contract and is what the node walk uses. The v2 tree
# is documented by OpenNMS itself as experimental, and is used only for the two
# global interface collections, which v1 does not offer at all.
V1_PATH = "/rest"
V2_PATH = "/api/v2"

NODES_PATH = "/nodes"
IFSERVICES_PATH = "/ifservices"
IPINTERFACES_PATH = "/ipinterfaces"
SNMPINTERFACES_PATH = "/snmpinterfaces"

MAX_ATTR_VALUES = 64

EMPTY_MAC = "00:00:00:00:00:00"

# OpenNMS node type, a single character on the node record.
NODE_TYPES = {"A": "active", "D": "deleted"}

# How the node label was chosen. A label sourced from an IP address is not a
# hostname, which is the whole reason this field is read.
LABEL_SOURCES = {
    "A": "address",
    "H": "hostname",
    "N": "netbios",
    "S": "sysname",
    "U": "user-defined",
}

# The SNMP primary flag on an IP interface.
PRIMARY_TYPES = {"P": "primary", "S": "secondary", "N": "not-eligible"}

# ifType values that describe a software construct rather than a network port:
# 24 softwareLoopback, 53 propVirtual, 131 tunnel, 150 mplsTunnel. LAG (161)
# and VLAN (135 l2vlan, 136 l3ipvlan) interfaces are deliberately NOT filtered
# here: they usually clone their parent port's MAC, which the same-MAC pooling
# in build_interfaces merges into one endpoint, and one that carries a unique
# MAC or an address is a real correlation signal that would be lost.
VIRTUAL_IF_TYPES = ["24", "53", "131", "150"]

# A DNS label sequence, used to decide whether an interface hostname is a real
# name or a stringified address.
HOSTNAME_RE = r"^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$"

# Names that pass as DNS labels but identify nothing. OpenNMS monitors the
# loopback of its own server as a matter of course, and the reverse-DNS name of
# 127.0.0.1 is "localhost" on essentially every install - so without this every
# OpenNMS node carrying a loopback interface would offer the same hostname, and
# runZero would treat that as a reason to merge unrelated hosts.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "localhost6",
                     "localhost6.localdomain6", "unknown", "none", "null", "-"]

# The sysDescription of a device, lower-cased, mapped to a runZero device type
# only where the string is unambiguous. Anything else is left for runZero's own
# fingerprinting, which is better at this than a substring match.
SYSDESCR_HINTS = [
    ("cisco ios", "Switch"),
    ("cisco nx-os", "Switch"),
    ("cisco adaptive security appliance", "Firewall"),
    ("juniper networks", "Router"),
    ("arista networks", "Switch"),
    ("procurve", "Switch"),
    ("aruba", "Switch"),
    ("fortigate", "Firewall"),
    ("palo alto networks", "Firewall"),
    ("windows", "Server"),
    ("linux", "Server"),
    ("darwin", "Desktop"),
    ("vmware esxi", "Hypervisor"),
    ("apc web/snmp", "UPS"),
    ("jetdirect", "Printer"),
]
def _key(value):
    """Normalize an identifier that OpenNMS types inconsistently.

    The same logical value is a JSON string in one place and an integer in
    another - a node's own id is "1" on the node record but 1 on every
    interface that refers to it - so anything used as a join key is compared as
    text."""
    if value == None:
        return ""
    if type(value) == "float":
        return str(int(value))
    return as_text(value, join=",").strip()


def _parse_millis(value):
    """Convert an OpenNMS timestamp to a time, clamping a future value to now.

    Every timestamp in the JSON representation is an epoch value in
    MILLISECONDS, serialized as a bare integer - Jackson's default rendering of
    java.util.Date. The ISO 8601 strings that appear in OpenNMS documentation
    are the XML representation and never reach this code. The clamp matters
    because the platform rejects an entire asset whose timestamp is after now,
    so a node whose last poll is recorded slightly ahead of the Explorer's
    clock would otherwise be dropped in full."""
    if type(value) == "float":
        value = int(value)
    if type(value) == "string":
        text = value.strip()
        if not re_match(r"^[0-9]+$", text):
            return None
        value = int(text)
    if type(value) != "int" or value <= 0:
        return None
    seconds = value // 1000
    if seconds <= 0:
        return None
    current = now()
    if seconds > current.unix:
        return current
    return from_timestamp(seconds)
def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable.

    OpenNMS stores a physical address as twelve bare hex characters with no
    separators, and the case is not consistent: the provisioner lower-cases
    what it normalizes from an ASCII SNMP response, while a raw six-byte
    response is stored as-is. normalize_mac accepts the unseparated form in
    either case, which is why nothing is reformatted here first."""
    mac = normalize_mac(as_text(value, join=",").strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac


def _hostname_like(value):
    """Report whether a string is usable as a hostname.

    An OpenNMS interface hostName is the reverse-DNS name when one resolved and
    a copy of the IP address when it did not, so an address has to be refused
    rather than imported as a name."""
    text = as_text(value, join=",").strip()
    if not text or len(text) > 253:
        return False
    if text.lower() in PLACEHOLDER_NAMES:
        return False
    if ip_address(text) != None:
        return False
    return re_match(HOSTNAME_RE, text) != None


def v1_url(ctx, path):
    """Build a URL in the stable v1 ReST tree."""
    return ctx["base_url"] + ctx["context"] + V1_PATH + path


def v2_url(ctx, path):
    """Build a URL in the experimental v2 tree."""
    return ctx["base_url"] + ctx["context"] + V2_PATH + path


def fetch_page(ctx, url, collection, offset, label):
    """Fetch one page of an OpenNMS collection, returning (records, err).

    Two behaviours make this less mechanical than it looks. OpenNMS applies a
    default limit of ten records when none is sent, so a limit is always
    supplied rather than relying on the server. And the v2 endpoints answer an
    empty result set with 204 and no body at all, which decodes to None rather
    than to an envelope, so that is treated as the end of the walk instead of
    as a malformed response."""
    query = "limit={}&offset={}".format(ctx["page_size"], offset)
    data, err = get_json(url + "?" + query, **ctx["http_options"])
    if err:
        return None, err
    if data == None:
        return [], None
    data = as_dict(data)
    if collection not in data:
        return [], None
    return dicts(data[collection]), None


def walk(ctx, url, collection, label, handler):
    """Page through a collection, handing each page to a handler.

    Returns the number of records seen, or -1 when the walk failed, which the
    callers use to distinguish "this endpoint is not available here" from "this
    endpoint is empty"."""
    seen = 0
    _pager1 = pager("opennms-horizon-1")
    while _pager1.next():
        page = _pager1.page - 1
        records, err = fetch_page(ctx, url, collection, page * ctx["page_size"], label)
        if err:
            print("opennms: failed to read {}: {}".format(label, err))
            return -1
        if not records:
            break
        handler(records)
        seen += len(records)
        if len(records) < ctx["page_size"]:
            break
    return seen


def index_ip_interfaces(ctx):
    """Index every IP interface in the estate by node id.

    This one call is what keeps the integration off a request per node, and it
    does double duty: OpenNMS inlines the whole SNMP interface object inside
    each IP interface rather than referring to it by id, so the physical
    address arrives with the address it is bound to and no join is needed.

    Returns None when the endpoint is unavailable, which is the signal to fall
    back to the per-node v1 route."""
    index = {}

    def absorb(records):
        for record in records:
            node = _key(record.get("nodeId"))
            if not node:
                continue
            index.setdefault(node, []).append(record)

    if walk(ctx, v2_url(ctx, IPINTERFACES_PATH), "ipInterface", "IP interfaces", absorb) < 0:
        return None
    print("opennms: indexed IP interfaces for {} nodes".format(len(index)))
    return index


def index_snmp_interfaces(ctx):
    """Index the SNMP interfaces that carry a physical address by node id.

    Interfaces with no address at all are dropped as they are read rather than
    stored, because on a switch they are the overwhelming majority - a
    48-port access switch reports every port - and none of them tells runZero
    anything. Only ports with a MAC survive into the index."""
    index = {}

    def absorb(records):
        for record in records:
            node = _key(record.get("nodeId"))
            mac = _clean_mac(record.get("physAddr"))
            if not node or not mac:
                continue
            index.setdefault(node, []).append(record)

    if walk(ctx, v2_url(ctx, SNMPINTERFACES_PATH), "snmpInterface", "SNMP interfaces", absorb) < 0:
        return None
    return index


def index_services(ctx):
    """Index monitored service names by node label and address.

    The global monitored-service list is a flattened view with its own shape:
    the envelope key is hyphenated, and it identifies a node by LABEL rather
    than by id. OpenNMS allows two nodes to share a label, so a label-only
    index would merge their service lists onto both assets - each service is
    therefore also keyed by label PLUS its own ipAddress, and the per-node
    lookup matches on an address the node actually carries. The label-only
    entries remain as the fallback for nodes whose interfaces were not
    collected. It carries no port number, because an OpenNMS monitored service
    has none anywhere in the model - the port a poller uses lives in
    poller-configuration.xml, not on the service - so these become names on
    the asset rather than runZero services."""
    index = {"by_addr": {}, "by_label": {}}

    def absorb(records):
        for record in records:
            label = as_text(record.get("node"), join=",").strip()
            name = as_text(record.get("serviceName"), join=",").strip()
            if not label or not name:
                continue
            addr = as_text(record.get("ipAddress"), join=",").strip()
            buckets = [index["by_label"].setdefault(label, {"names": [], "down": []})]
            if addr:
                buckets.append(index["by_addr"].setdefault(label + "|" + addr, {"names": [], "down": []}))
            for entry in buckets:
                if name not in entry["names"]:
                    entry["names"].append(name)
                if record.get("isDown") == True and name not in entry["down"]:
                    entry["down"].append(name)

    if walk(ctx, v1_url(ctx, IFSERVICES_PATH), "monitored-service", "monitored services", absorb) < 0:
        return {}
    return index


def lookup_services(service_index, record, ip_records):
    """Resolve one node's monitored services from the index.

    Matches by label plus one of the node's own collected addresses, so two
    nodes sharing a label do not merge service lists. When addresses were
    collected and none matches, the label-wide entry belongs to a different
    node with the same label (or the node has no services), so nothing is
    attached. A node with no collected addresses falls back to the label-wide
    entry, which is the old behavior."""
    if not service_index:
        return {}
    label = as_text(record.get("label"), join=",").strip()
    if not label:
        return {}
    by_addr = as_dict(service_index.get("by_addr"))
    merged = {"names": [], "down": []}
    matched = False
    for ip_record in ip_records:
        addr = as_text(as_dict(ip_record).get("ipAddress"), join=",").strip()
        if not addr:
            continue
        entry = by_addr.get(label + "|" + addr)
        if not entry:
            continue
        matched = True
        for name in entry["names"]:
            if name not in merged["names"]:
                merged["names"].append(name)
        for name in entry["down"]:
            if name not in merged["down"]:
                merged["down"].append(name)
    if matched:
        return merged
    if ip_records:
        return {}
    return as_dict(as_dict(service_index.get("by_label")).get(label))


def fetch_node_interfaces(ctx, node_id):
    """Fetch one node's IP interfaces directly.

    This is the fallback for a server whose v2 tree is unavailable. It is a
    request per node, which is why it is capped, and it is also why the v2
    route is tried first."""
    url = "{}{}/{}{}".format(v1_url(ctx, NODES_PATH), "", node_id, IPINTERFACES_PATH)
    records, err = fetch_page(ctx, url, "ipInterface", 0, "node interfaces")
    if err:
        ctx["detail_failed"] += 1
        if ctx["detail_failed"] <= 5:
            print("opennms: failed to read interfaces for node {}: {}".format(node_id, err))
        return []
    return records


def build_interfaces(ip_records, snmp_records):
    """Build runZero network interfaces from a node's interface records.

    Interfaces are grouped by SNMP ifIndex, which is what ties an address to
    the port it is configured on. An IP interface that OpenNMS never correlated
    to an SNMP interface has no ifIndex, and those addresses are pooled onto
    one address-only interface rather than being scattered across invented
    ones."""
    by_index = {}
    unbound = []
    for record in ip_records:
        routable = routable_ip(record.get("ipAddress"))
        if not routable:
            continue
        snmp = as_dict(record.get("snmpInterface"))
        index = _key(record.get("ifIndex")) or _key(snmp.get("ifIndex"))
        mac = _clean_mac(snmp.get("physAddr"))
        if not index:
            if routable not in unbound:
                unbound.append(routable)
            continue
        entry = by_index.setdefault(index, {"mac": "", "ips": []})
        if mac and not entry["mac"]:
            entry["mac"] = mac
        if routable not in entry["ips"]:
            entry["ips"].append(routable)

    for record in snmp_records:
        mac = _clean_mac(record.get("physAddr"))
        if not mac:
            continue
        if _key(record.get("ifType")) in VIRTUAL_IF_TYPES:
            continue
        index = _key(record.get("ifIndex"))
        entry = by_index.setdefault(index or mac, {"mac": "", "ips": []})
        if not entry["mac"]:
            entry["mac"] = mac

    # Ports that report the same MAC - a LAG and its members, a VLAN interface
    # and its parent - are one endpoint to runZero, so their addresses are
    # pooled rather than emitted as duplicates.
    merged = []
    seen_macs = {}
    for index in sorted(by_index):
        entry = by_index[index]
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

    if unbound:
        if merged:
            for ip in unbound:
                if ip not in merged[0]["ips"]:
                    merged[0]["ips"].append(ip)
        else:
            merged.append({"mac": "", "ips": unbound})

    netifs = []
    for entry in merged:
        nic = network_interface(mac=entry["mac"], ips=entry["ips"])
        # network_interface returns None when nothing usable survived, and a
        # list holding None aborts the whole run.
        if nic:
            netifs.append(nic)
    return netifs


def device_type_from(sysdescr, asset):
    """Map a node to a runZero device type, conservatively.

    The asset record's own category is checked first because an operator set
    it deliberately. sysDescription is only consulted for strings that name a
    class of device unambiguously; anything else is left unset so runZero's own
    fingerprinting decides, which it does better than a substring match."""
    category = as_text(asset.get("category"), join=",").strip().lower()
    if category and category != "unspecified":
        for needle, mapped in SYSDESCR_HINTS:
            if needle in category:
                return mapped
    text = as_text(sysdescr, join=",").strip().lower()
    for needle, mapped in SYSDESCR_HINTS:
        if needle in text:
            return mapped
    return ""


def build_asset(ctx, record, ip_records, snmp_records, services):
    """Convert one OpenNMS node into a runZero asset."""
    node_id = _key(record.get("id"))
    label = as_text(record.get("label"), join=",").strip()
    sysname = as_text(record.get("sysName"), join=",").strip()
    asset_record = as_dict(record.get("assetRecord"))

    netifs = build_interfaces(ip_records, snmp_records)

    hostnames = []
    # A node label is only a hostname when OpenNMS derived it from one. When
    # labelSource is "A" the label IS the IP address, and importing that as a
    # hostname would be a placeholder rather than a name.
    label_source = as_text(record.get("labelSource"), join=",").strip().upper()
    if label and label_source != "A" and _hostname_like(label):
        hostnames.append(label)
    if sysname and _hostname_like(sysname):
        hostnames.append(sysname)
    for item in ip_records:
        candidate = as_text(item.get("hostName"), join=",").strip()
        if _hostname_like(candidate):
            hostnames.append(candidate)

    manufacturer = as_text(asset_record.get("manufacturer") or asset_record.get("vendor"), join=",").strip()
    model = as_text(asset_record.get("modelNumber"), join=",").strip()
    serial = as_text(asset_record.get("serialNumber"), join=",").strip()
    sysdescr = as_text(record.get("sysDescription"), join=",").strip()

    categories = []
    for item in dicts(record.get("categories")):
        name = as_text(item.get("name"), join=",").strip()
        if name:
            categories.append(name)

    tags = [VENDOR]
    for name in categories:
        tags.append("category:" + name)
    location = as_text(record.get("location"), join=",").strip()
    if location:
        tags.append("location:" + location)
    foreign_source = as_text(record.get("foreignSource"), join=",").strip()
    if foreign_source:
        tags.append("requisition:" + foreign_source)
    if serial:
        tags.append("serial:" + serial)
    node_type = NODE_TYPES.get(as_text(record.get("type"), join=",").strip().upper(), "")
    if node_type:
        tags.append("type:" + node_type)

    service_names = services.get("names", [])
    attrs = {
        "node_id": node_id,
        "server": ctx["scope"],
        "label": label,
        "label_source": LABEL_SOURCES.get(label_source, label_source),
        "foreign_source": foreign_source,
        "foreign_id": record.get("foreignId"),
        "location": location,
        "node_type": node_type,
        "node_parent_id": record.get("nodeParentID"),
        "sys_name": sysname,
        "sys_contact": record.get("sysContact"),
        "sys_location": record.get("sysLocation"),
        "sys_description": sysdescr,
        "sys_object_id": record.get("sysObjectId"),
        "categories": categories,
        "create_time": record.get("createTime"),
        "last_capsd_poll": record.get("lastCapsdPoll"),
        "last_ingress_flow": record.get("lastIngressFlow"),
        "last_egress_flow": record.get("lastEgressFlow"),
        "interface_count": len(netifs),
        "ip_interface_count": len(ip_records),
        "snmp_interface_count": len(snmp_records),
        # OpenNMS monitored services have no port anywhere in the data model, so
        # they are recorded by name here rather than imported as runZero
        # services with an invented port.
        "monitored_services": service_names[:MAX_ATTR_VALUES],
        "monitored_service_count": len(service_names),
        "services_down": services.get("down", [])[:MAX_ATTR_VALUES],
        "asset_category": asset_record.get("category"),
        "asset_manufacturer": asset_record.get("manufacturer"),
        "asset_vendor": asset_record.get("vendor"),
        "asset_model_number": asset_record.get("modelNumber"),
        "asset_serial_number": asset_record.get("serialNumber"),
        "asset_number": asset_record.get("assetNumber"),
        "asset_operating_system": asset_record.get("operatingSystem"),
        "asset_description": asset_record.get("description"),
        "asset_department": asset_record.get("department"),
        "asset_building": asset_record.get("building"),
        "asset_room": asset_record.get("room"),
        "asset_rack": asset_record.get("rack"),
        "asset_slot": asset_record.get("slot"),
        "asset_region": asset_record.get("region"),
        "asset_division": asset_record.get("division"),
        "asset_circuit_id": asset_record.get("circuitId"),
        "asset_admin": asset_record.get("admin"),
        "asset_comment": asset_record.get("comment"),
        "asset_last_modified_by": asset_record.get("lastModifiedBy"),
        "asset_last_modified_date": asset_record.get("lastModifiedDate"),
    }
    for item in ip_records:
        primary = PRIMARY_TYPES.get(as_text(item.get("snmpPrimary"), join=",").strip().upper(), "")
        if primary == "primary":
            attrs["primary_interface_address"] = item.get("ipAddress")
            attrs["primary_interface_managed"] = item.get("isManaged")

    params = {
        # The OpenNMS node id is the primary key of the nodes table: every
        # sub-resource route is keyed on it, and it survives a rename, a
        # re-provision, and a change of address. It is namespaced by the server
        # because it is a per-install sequence with no wider meaning.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], node_id),
        "hostnames": dedupe(hostnames),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),
    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    # The serial is carried as a custom attribute and a tag rather than as an
    # ImportAsset field: the constructor has no serial parameter.

    # The asset record's operatingSystem is what an operator recorded;
    # sysDescription is what the device said about itself. Neither is a clean
    # name/version pair, so the description becomes the os string only when
    # there is nothing better, and no version is invented from it.
    operating_system = as_text(asset_record.get("operatingSystem"), join=",").strip()
    if operating_system:
        params["os"] = operating_system
    elif sysdescr:
        params["os"] = sysdescr[:255]

    device_type = device_type_from(sysdescr, asset_record)
    if device_type:
        params["deviceType"] = device_type

    first_seen = _parse_millis(record.get("createTime"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    # it has to be assigned after construction.
    last_seen = _parse_millis(record.get("lastCapsdPoll"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def collect(ctx, ip_index, snmp_index, service_index):
    """Walk the node list, streaming each page as it is built."""
    reported = 0
    skipped = 0
    _pager2 = pager("opennms-horizon-2")
    while _pager2.next():
        page = _pager2.page - 1
        records, err = fetch_page(ctx, v1_url(ctx, NODES_PATH), "node",
                                  page * ctx["page_size"], "nodes")
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("opennms: authentication to the OpenNMS server failed:", err)
            else:
                print("opennms: failed to fetch nodes:", err)
            return reported
        if not records:
            break

        assets = []
        for record in records:
            node_id = _key(record.get("id"))
            if not node_id:
                skipped += 1
                print("opennms: skipping node with no id: label=" + as_text(record.get("label"), join=","))
                continue

            if ip_index != None:
                ip_records = ip_index.get(node_id, [])
            elif ctx["interfaces"] and (not ctx["detail_limit"] or ctx["detail_used"] < ctx["detail_limit"]):
                ctx["detail_used"] += 1
                ip_records = fetch_node_interfaces(ctx, node_id)
            else:
                if ctx["interfaces"]:
                    ctx["detail_skipped"] += 1
                ip_records = []

            snmp_records = snmp_index.get(node_id, []) if snmp_index != None else []
            services = lookup_services(service_index, record, ip_records)
            assets.append(build_asset(ctx, record, ip_records, snmp_records, services))

        reported += report_assets(assets)
        print("opennms: reported {} nodes so far".format(reported))
        if len(records) < ctx["page_size"]:
            break

    if skipped:
        print("opennms: skipped {} nodes with no id".format(skipped))
    if ctx["detail_skipped"]:
        print("opennms: per-node request limit of {} reached; {} nodes were imported without interfaces".format(
            ctx["detail_limit"], ctx["detail_skipped"]))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("opennms: could not determine the OpenNMS host from the configured URL")
        return None

    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")
    if not username or not password:
        print("opennms: an OpenNMS username and password are required")
        return None

    context = get_string(kwargs, "context_path", default="/opennms").strip().rstrip("/")
    if context and not context.startswith("/"):
        context = "/" + context

    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "base_url": base_url,
        "context": context,
        "scope": scope,
        # OpenNMS does not send a 401 challenge by default, so the credential
        # has to be sent preemptively on the first request rather than in
        # response to one.
        "http_options": get_http_options(kwargs, headers={
            # Without this header OpenNMS answers XML, not JSON.
            "Accept": "application/json",
            "Authorization": basic(username, password),
        }),
        "page_size": get_int(kwargs, "page_size", default=200),
        "interfaces": get_bool(kwargs, "collect_interfaces", default=True),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "detail_failed": 0,
    }

    ip_index = None
    snmp_index = None
    if ctx["interfaces"]:
        ip_index = index_ip_interfaces(ctx)
        if ip_index == None:
            print("opennms: the v2 interface collection is unavailable; falling back to one request per node")
        elif get_bool(kwargs, "collect_snmp_interfaces", default=True):
            snmp_index = index_snmp_interfaces(ctx)

    service_index = index_services(ctx) if get_bool(kwargs, "collect_services", default=True) else {}

    if not collect(ctx, ip_index, snmp_index, service_index):
        print("opennms: no assets retrieved")
    return None

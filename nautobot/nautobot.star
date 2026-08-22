# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-nautobot",
    "name": "Nautobot",
    "type": "inbound",
    "description": "Imports devices and virtual machines, with their interfaces, MAC addresses, and IP addresses, from a Nautobot 2.x DCIM/IPAM instance.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Nautobot URL",
            "type": "url",
            "required": True,
            "placeholder": "https://nautobot.example.com",
            "description": "Base URL of the Nautobot server. The /api paths are appended automatically. Nautobot is self-hosted, so there is no default.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "A Nautobot API token belonging to a user with view permission on dcim.device, dcim.interface, ipam.ipaddress, and virtualization.virtualmachine.",
        },
        {
            "key": "api_version",
            "label": "REST API version",
            "type": "string",
            "required": False,
            "placeholder": "2.4",
            "description": "Optional Nautobot REST API version to pin, sent as 'Accept: application/json; version=<value>'. Leave blank to accept the server's default, which is its own current version.",
        },
        {
            "key": "import_devices",
            "label": "Import DCIM devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import racked and non-racked hardware from dcim/devices.",
        },
        {
            "key": "import_virtual_machines",
            "label": "Import virtual machines",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import virtualization/virtual-machines. These are separate objects in Nautobot with their own interfaces and IPs.",
        },
        {
            "key": "collect_interfaces",
            "label": "Collect interfaces",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch interfaces for each page of devices and virtual machines. This is where MAC addresses and non-primary IP addresses come from, so it is on by default. One extra request per page, not per device.",
        },
        {
            "key": "device_filter",
            "label": "Device filter",
            "type": "string",
            "required": False,
            "placeholder": "status=active&role=router",
            "description": "Optional URL query fragment appended to the device request, using Nautobot's own filter syntax, for example 'status=active' or 'location=DM01&location=DM02'. Values must already be URL-encoded. Leave blank to import every device the token can see.",
        },
        {
            "key": "virtual_machine_filter",
            "label": "Virtual machine filter",
            "type": "string",
            "required": False,
            "placeholder": "status=active",
            "description": "Optional URL query fragment appended to the virtual machine request, in the same form as the device filter.",
        },
        {
            "key": "page_size",
            "label": "Records per page",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Objects requested per page. Nautobot caps this at its MAX_PAGE_SIZE setting, which defaults to 1000.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_time', 'now', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "nautobot"
ATTR_PREFIX = "nautobot"
ATTR_SEPARATOR = "_"

DEVICES_PATH = "/api/dcim/devices/"
INTERFACES_PATH = "/api/dcim/interfaces/"
VMS_PATH = "/api/virtualization/virtual-machines/"
# The VMInterface collection is served from /virtualization/interfaces/, not
# from a /vm-interfaces/ path.
VM_INTERFACES_PATH = "/api/virtualization/interfaces/"
MANUFACTURERS_PATH = "/api/dcim/manufacturers/"

# Interfaces are fetched for one page of parents at a time by repeating the
# parent id in the query string. Repeating it 100 times would build a 4 KB
# query, which some reverse proxies in front of Nautobot truncate, so the ids
# are sent in batches of this size instead.
ID_BATCH = 25

# A Nautobot primary key is a UUID. Anything else in the id field is a sign the
# response is not what this integration expects, and is refused rather than used
# as an asset identity.
UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

# An all-zero MAC means the field was filled in with a placeholder.
EMPTY_MAC = "00:00:00:00:00:00"

# Nautobot interface types that describe a logical construct rather than a
# network adapter. A LAG, a bridge, and a virtual interface share the MAC of a
# real interface underneath them, so importing them adds nothing; a wireless
# link aggregation group is the same.
VIRTUAL_INTERFACE_TYPES = ["virtual", "bridge", "lag", "lte", "other"]

# Roles are free text in Nautobot, so only the conventional names shipped in
# example data and the Nautobot documentation are mapped. Anything else is left
# unset for runZero's own fingerprinting to decide.
ROLE_DEVICE_TYPES = {
    "router": "Router",
    "core router": "Router",
    "edge router": "Router",
    "switch": "Switch",
    "access switch": "Switch",
    "distribution switch": "Switch",
    "core switch": "Switch",
    "leaf switch": "Switch",
    "spine switch": "Switch",
    "leaf": "Switch",
    "spine": "Switch",
    "firewall": "Firewall",
    "access point": "Wireless Access Point",
    "wireless access point": "Wireless Access Point",
    "wlan controller": "Wireless Controller",
    "wireless controller": "Wireless Controller",
    "load balancer": "Load Balancer",
    "server": "Server",
    "compute": "Server",
    "storage": "Storage",
    "storage array": "Storage",
    "printer": "Printer",
    "camera": "IP Camera",
    "ip camera": "IP Camera",
    "ups": "UPS",
    "pdu": "Power Distribution Unit",
    "power distribution unit": "Power Distribution Unit",
    "console server": "Terminal Server",
    "patch panel": "Patch Panel",
}
def _named(value):
    """Return the display name of a Nautobot related object.

    At depth=0 a related field is a bare object carrying only id, url, and
    display; at depth=1 it is the full nested object. Both carry a usable label,
    so this reads whichever is present rather than requiring the caller to know
    which depth produced the response."""
    item = as_dict(value)
    for key in ["name", "model", "display", "label", "value"]:
        text = as_text(item.get(key), join=",").strip()
        if text:
            return text
    return ""
def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable."""
    mac = normalize_mac(as_text(value, join=",").strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac


def _mac_of(record):
    """Return the MAC on an interface record.

    Nautobot models this as a single nullable MACAddressCharField on both
    Interface and VMInterface - there is no many-to-many MAC relation in any
    2.x or 3.x release - and netaddr serializes it colon-separated and
    upper-case. normalize_mac accepts that form and every other."""
    return _clean_mac(record.get("mac_address"))


def _ips_of(record):
    """Collect every routable IP on an interface record.

    ip_addresses is a list of related objects. At depth=1 each is the full
    IPAddress object carrying address and host; at depth=0 only display is
    populated, and Nautobot's display for an IP address is the address itself,
    so both shapes yield an address."""
    ips = []
    for item in dicts(record.get("ip_addresses")):
        for key in ["address", "host", "display"]:
            routable = routable_ip(item.get(key))
            if routable:
                if routable not in ips:
                    ips.append(routable)
                break
    return ips


def build_query(pairs, extra):
    """Assemble a query string from ordered key/value pairs.

    The query is built by hand rather than through the params= kwarg for two
    reasons. Nautobot filters repeat a key to mean "any of these" - device=a&
    device=b - and a Starlark dict cannot hold a duplicate key, so params= can
    never express it. Passing params= alongside a URL that already carries a
    query would also replace that query rather than merge with it."""
    parts = []
    for pair in pairs:
        parts.append("{}={}".format(pair[0], pair[1]))
    extra = as_text(extra, join=",").strip().strip("&")
    if extra:
        parts.append(extra)
    return "&".join(parts)


def fetch_page(ctx, path, query, label):
    """Fetch one page of a Nautobot collection, returning (results, next_query, err).

    Nautobot paginates with the standard Django REST Framework envelope -
    count, next, previous, results - where next is an absolute URL. That URL is
    not requested directly: Nautobot builds it from the Host header of the
    incoming request, so behind a reverse proxy it can name a hostname the
    Explorer cannot reach, or a scheme it should not use. Only the query string
    is taken from it and re-issued against the configured base URL, which keeps
    the server's own cursor authoritative without trusting its idea of its own
    address."""
    url = ctx["base_url"] + path
    if query:
        url += "?" + query
    data, err = get_json(url, **ctx["http_options"])
    if err:
        return None, "", err
    data = as_dict(data)
    if "results" not in data:
        return None, "", "{} response carried no results list".format(label)
    following = ""
    next_url = data.get("next")
    if type(next_url) == "string" and next_url.strip():
        parsed = url_parse(next_url.strip())
        if parsed and parsed.raw_query:
            following = parsed.raw_query
    return dicts(data["results"]), following, None


def fetch_interfaces(ctx, path, filter_key, ids, label):
    """Index the interfaces belonging to one page of parents, keyed by parent id.

    This is the request that keeps the integration off an N+1. Nautobot's
    interface filters accept a repeated key, so one request covers every device
    on the current page rather than one request per device. The result is
    discarded when the page is done, so memory stays bounded by a page."""
    index = {}
    if not ids or not ctx["interfaces"]:
        return index

    batch_start = 0
    _pager1 = pager("nautobot-1")
    while _pager1.next():
        if batch_start >= len(ids):
            break
        batch = ids[batch_start:batch_start + ID_BATCH]
        batch_start += ID_BATCH

        pairs = [("depth", "1"), ("limit", str(ctx["page_size"]))]
        for value in batch:
            pairs.append((filter_key, value))
        query = build_query(pairs, "")

        _pager2 = pager("nautobot-2")

        while _pager2.next():
            records, following, err = fetch_page(ctx, path, query, label)
            if err:
                # A filter Nautobot does not recognize answers 400. That is a
                # version difference rather than a broken run, so interfaces are
                # abandoned for the rest of the import and the parents are still
                # imported with their primary addresses.
                print("nautobot: failed to fetch {}, continuing without them: {}".format(label, err))
                ctx["interfaces"] = False
                return index
            for record in records:
                parent = as_text(as_dict(record.get(ctx["parent_key"])).get("id"), join=",").strip()
                if not parent:
                    continue
                index.setdefault(parent, []).append(record)
            if not following:
                break
            query = following
    return index


def fetch_manufacturers(ctx):
    """Index every manufacturer by its UUID, once, for the whole run.

    This request exists because of how Nautobot's depth parameter works.
    depth=1 expands a device's device_type into a full object carrying the
    model and part number, but the objects nested *inside* that one fall back
    to depth 0 - and a depth-0 related object is only {id, object_type, url}.
    So device_type.manufacturer has no name at depth=1, and platform.manufacturer
    has none either. Raising the request to depth=2 would expand every other
    relation on the device as well and multiply the response size for one
    string. The manufacturer table instead has a few dozen rows on even a large
    install, so it is read once and joined locally."""
    index = {}
    query = build_query([("depth", "0"), ("limit", "1000")], "")
    _pager3 = pager("nautobot-3")
    while _pager3.next():
        records, following, err = fetch_page(ctx, MANUFACTURERS_PATH, query, "manufacturers")
        if err:
            print("nautobot: failed to read manufacturers, continuing without them:", err)
            return index
        for record in records:
            uuid = as_text(record.get("id"), join=",").strip()
            name = as_text(record.get("name"), join=",").strip()
            if uuid and name:
                index[uuid] = name
        if not following:
            break
        query = following
    return index


def _manufacturer(ctx, record):
    """Resolve a device's manufacturer name.

    The nested object usually carries only an id, so the name comes from the
    manufacturer index. The nested name is still preferred when it is present,
    because a caller running at a higher depth would have it inline."""
    for holder in [as_dict(record.get("device_type")), record]:
        nested = as_dict(holder.get("manufacturer"))
        if not nested:
            continue
        name = _named(nested)
        if name:
            return name
        resolved = ctx["manufacturers"].get(as_text(nested.get("id"), join=",").strip(), "")
        if resolved:
            return resolved
    # The platform is the last resort: a device with no manufacturer on its type
    # can still have one on the OS platform it runs.
    nested = as_dict(as_dict(record.get("platform")).get("manufacturer"))
    if nested:
        return _named(nested) or ctx["manufacturers"].get(as_text(nested.get("id"), join=",").strip(), "")
    return ""


def _software_version(record):
    """Return the running software version.

    SoftwareVersion, added in Nautobot 2.2, names its field "version" rather
    than "name", so the generic related-object reader would miss it and fall
    through to the display string, which prefixes the platform."""
    nested = as_dict(record.get("software_version"))
    if not nested:
        return ""
    version = as_text(nested.get("version"), join=",").strip()
    if version:
        return version
    return _named(nested)


def build_interfaces(records, primary_ips):
    """Build one runZero network interface per Nautobot interface.

    Interfaces that describe a logical construct - a LAG, a bridge, a virtual
    subinterface - are skipped, because they repeat the MAC of a physical
    interface underneath them and would add a duplicate rather than a second
    endpoint. Their addresses are still kept: an address configured on a bridge
    is a real address, so it is pooled and attached to the first physical
    interface, or to an address-only interface when there is no physical one."""
    merged = []
    pooled = []
    seen_macs = {}
    for record in records:
        if record.get("enabled") == False:
            continue
        # Interface.type is one of the few genuine choice fields left in the
        # 2.x API, so it arrives as {"value": "virtual", "label": "Virtual"}.
        # VMInterface has no type at all, which is why an absent one is treated
        # as a physical interface rather than skipped.
        raw_kind = as_text(as_dict(record.get("type")).get("value"), join=",").strip().lower()
        mac = _mac_of(record)
        ips = _ips_of(record)
        if raw_kind in VIRTUAL_INTERFACE_TYPES:
            for ip in ips:
                if ip not in pooled:
                    pooled.append(ip)
            continue
        if not mac and not ips:
            continue
        if mac and mac in seen_macs:
            target = merged[seen_macs[mac]]
            for ip in ips:
                if ip not in target["ips"]:
                    target["ips"].append(ip)
            continue
        if mac:
            seen_macs[mac] = len(merged)
        merged.append({"mac": mac, "ips": list(ips)})

    # An address configured on a bridge or a subinterface is still a real
    # address, and so is the device's primary IP, which Nautobot does not
    # attribute to any interface unless that interface listed it. Both are
    # attached to the first physical interface rather than inventing a second
    # endpoint with no MAC, which would look like a separate device.
    remaining = []
    for ip in pooled + primary_ips:
        if ip not in remaining:
            remaining.append(ip)
    if remaining:
        if merged:
            target = merged[0]
            for ip in remaining:
                if ip not in target["ips"]:
                    target["ips"].append(ip)
        else:
            merged.append({"mac": "", "ips": remaining})

    netifs = []
    for entry in merged:
        nic = network_interface(mac=entry["mac"], ips=entry["ips"])
        # network_interface returns None when nothing usable survived; a list
        # containing None aborts the whole run.
        if nic:
            netifs.append(nic)
    return netifs


def device_attributes(ctx, record, interfaces, primary_ips):
    """Everything worth keeping from a Nautobot device record, before it is
    coerced to the string->string shape custom attributes require."""
    device_type = as_dict(record.get("device_type"))
    location = as_dict(record.get("location"))
    return {
        "object": "device",
        "uuid": record.get("id"),
        "name": record.get("name"),
        "serial": record.get("serial"),
        "asset_tag": record.get("asset_tag"),
        "status": _named(record.get("status")),
        "role": _named(record.get("role")),
        "device_type": _named(device_type),
        "device_type_part_number": device_type.get("part_number"),
        "manufacturer": _manufacturer(ctx, record),
        "platform": _named(record.get("platform")),
        "platform_network_driver": as_dict(record.get("platform")).get("network_driver"),
        "platform_napalm_driver": as_dict(record.get("platform")).get("napalm_driver"),
        "software_version": _software_version(record),
        "location": _named(location),
        "location_facility": location.get("facility"),
        # Nautobot's display for a location is its whole hierarchy, which is the
        # only place the parent chain survives at depth=1.
        "location_path": location.get("display"),
        "rack": _named(record.get("rack")),
        "position": record.get("position"),
        "face": _named(record.get("face")),
        "tenant": _named(record.get("tenant")),
        "cluster": _named(record.get("cluster")),
        "device_redundancy_group": _named(record.get("device_redundancy_group")),
        "virtual_chassis": _named(record.get("virtual_chassis")),
        "vc_position": record.get("vc_position"),
        "primary_ip4": as_dict(record.get("primary_ip4")).get("address"),
        "primary_ip6": as_dict(record.get("primary_ip6")).get("address"),
        "comments": record.get("comments"),
        "created": record.get("created"),
        "last_updated": record.get("last_updated"),
        "interface_count": len(interfaces),
        "primary_ip_count": len(primary_ips),
    }


def vm_attributes(record, interfaces, primary_ips):
    """Everything worth keeping from a Nautobot virtual machine record."""
    return {
        "object": "virtual_machine",
        "uuid": record.get("id"),
        "name": record.get("name"),
        "status": _named(record.get("status")),
        "role": _named(record.get("role")),
        "cluster": _named(record.get("cluster")),
        "cluster_type": _named(as_dict(record.get("cluster")).get("cluster_type")),
        "platform": _named(record.get("platform")),
        "software_version": _software_version(record),
        "tenant": _named(record.get("tenant")),
        "location": _named(record.get("location")),
        "vcpus": record.get("vcpus"),
        "memory": record.get("memory"),
        "disk": record.get("disk"),
        "primary_ip4": as_dict(record.get("primary_ip4")).get("address"),
        "primary_ip6": as_dict(record.get("primary_ip6")).get("address"),
        "comments": record.get("comments"),
        "created": record.get("created"),
        "last_updated": record.get("last_updated"),
        "interface_count": len(interfaces),
        "primary_ip_count": len(primary_ips),
    }


def build_asset(ctx, record, kind, interfaces):
    """Convert one Nautobot device or virtual machine into a runZero asset."""
    uuid = as_text(record.get("id"), join=",").strip()
    name = as_text(record.get("name"), join=",").strip()

    primary_ips = []
    for key in ["primary_ip4", "primary_ip6"]:
        value = as_dict(record.get(key))
        routable = routable_ip(value.get("address") or value.get("host") or value.get("display"))
        if routable and routable not in primary_ips:
            primary_ips.append(routable)

    netifs = build_interfaces(interfaces, primary_ips)

    if kind == "device":
        attrs = device_attributes(ctx, record, interfaces, primary_ips)
    else:
        attrs = vm_attributes(record, interfaces, primary_ips)
    attrs["server"] = ctx["scope"]
    attrs["display"] = record.get("display")

    # Nautobot's custom fields are user-defined and are the reason many sites
    # adopt it, so they are imported under their own prefix rather than dropped.
    for key, value in as_dict(record.get("custom_fields")).items():
        attrs["custom_field_" + as_text(key, join=",")] = value

    tags = [VENDOR, kind.replace("_", "-")]
    for item in dicts(record.get("tags")):
        label = _named(item)
        if label:
            tags.append("tag:" + label)
    for key in ["status", "role", "location", "tenant", "platform"]:
        if attrs.get(key):
            tags.append(key + ":" + as_text(attrs[key], join=","))
    serial = as_text(record.get("serial"), join=",").strip()
    if serial:
        tags.append("serial:" + serial)

    params = {
        # The Nautobot primary key is a UUID assigned when the object is created
        # and never rewritten, so it is authoritative. It is namespaced by the
        # Nautobot host and by the object class, because a device and a virtual
        # machine are separate tables whose UUIDs could in principle collide.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], kind, uuid),
        "hostnames": dedupe([name]),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),
    }

    manufacturer = _manufacturer(ctx, record)
    model = _named(record.get("device_type"))
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    # The serial is carried as a custom attribute and a tag rather than as an
    # ImportAsset field: the constructor has no serial parameter.

    # Nautobot models the operating system in two places. software_version is
    # the version actually running, added in Nautobot 2.2; platform is the
    # configured OS family. The platform names the OS and the software version
    # names the release, so they are not alternatives to each other.
    platform = _named(record.get("platform"))
    software_version = _software_version(record)
    if platform:
        params["os"] = platform
    if software_version:
        params["osVersion"] = software_version

    if kind == "virtual_machine":
        params["deviceType"] = "Virtual Machine"
    else:
        role = _named(record.get("role")).strip().lower()
        mapped = ROLE_DEVICE_TYPES.get(role, "")
        if mapped:
            params["deviceType"] = mapped

    created = parse_ts(record.get("created"))
    if created:
        params["firstSeenTS"] = created

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    # it has to be assigned after construction.
    updated = parse_ts(record.get("last_updated"))
    if updated != None:
        asset.lastSeenTS = updated
    return asset


def collect(ctx, kind, path, iface_path, filter_key, extra_filter):
    """Walk one Nautobot collection, streaming each page as it is built.

    Every page is converted, reported, and released before the next is fetched,
    so peak memory is one page of records plus that page's interfaces rather
    than the whole estate."""
    ctx["parent_key"] = "device" if kind == "device" else "virtual_machine"
    label = kind.replace("_", " ") + " interfaces"

    query = build_query([("depth", "1"), ("limit", str(ctx["page_size"]))], extra_filter)
    reported = 0
    skipped = 0
    _pager4 = pager("nautobot-4")
    while _pager4.next():
        records, following, err = fetch_page(ctx, path, query, kind)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("nautobot: authentication to Nautobot failed while reading {}: {}".format(kind, err))
            else:
                print("nautobot: failed to fetch {}: {}".format(kind, err))
            return reported
        if not records:
            break

        ids = []
        for record in records:
            uuid = as_text(record.get("id"), join=",").strip()
            if uuid and re_match(UUID_RE, uuid) and uuid not in ids:
                ids.append(uuid)
        interfaces = fetch_interfaces(ctx, iface_path, filter_key, ids, label)

        assets = []
        for record in records:
            uuid = as_text(record.get("id"), join=",").strip()
            if not uuid or not re_match(UUID_RE, uuid):
                skipped += 1
                print("nautobot: skipping {} with no usable id: name={}".format(
                    kind, as_text(record.get("name"), join=",")))
                continue
            assets.append(build_asset(ctx, record, kind, interfaces.get(uuid, [])))

        reported += report_assets(assets)
        print("nautobot: reported {} {} records so far".format(reported, kind))
        if not following:
            break
        query = following

    if skipped:
        print("nautobot: skipped {} {} records with no usable id".format(skipped, kind))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("nautobot: could not determine the Nautobot host from the configured URL")
        return None

    api_token = get_string(kwargs, "api_token", default="").strip()
    if not api_token:
        print("nautobot: a Nautobot API token is required")
        return None

    # Nautobot's token scheme is "Token <key>", not "Bearer <key>". A Bearer
    # header is accepted by the framework and then rejected as anonymous, which
    # surfaces as an empty result set rather than a 401 on some deployments.
    accept = "application/json"
    api_version = get_string(kwargs, "api_version", default="").strip()
    if api_version:
        accept = "application/json; version=" + api_version

    ctx = {
        "base_url": base_url,
        "http_options": get_http_options(kwargs, headers={
            "Accept": accept,
            "Authorization": "Token " + api_token,
        }),
        "scope": scope,
        "page_size": get_int(kwargs, "page_size", default=100),
        "interfaces": get_bool(kwargs, "collect_interfaces", default=True),
        "parent_key": "device",
        "manufacturers": {},
    }
    ctx["manufacturers"] = fetch_manufacturers(ctx)

    total = 0
    if get_bool(kwargs, "import_devices", default=True):
        # The filter is "device", not "device_id". Both exist on Nautobot 2.x
        # and both accept a repeated value, but device_id is deprecated there
        # and was removed in Nautobot 3.x, while "device" accepts a UUID or a
        # name and survives both.
        total += collect(ctx, "device", DEVICES_PATH, INTERFACES_PATH, "device",
                         get_string(kwargs, "device_filter", default=""))
    if get_bool(kwargs, "import_virtual_machines", default=True):
        # The interface collection is retried for virtual machines even when the
        # device pass gave up on it, because the two endpoints have separate
        # filtersets and one can be unavailable without the other.
        ctx["interfaces"] = get_bool(kwargs, "collect_interfaces", default=True)
        total += collect(ctx, "virtual_machine", VMS_PATH, VM_INTERFACES_PATH, "virtual_machine",
                         get_string(kwargs, "virtual_machine_filter", default=""))

    if not total:
        print("nautobot: no assets retrieved")
    return None

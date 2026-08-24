# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-librenms",
    "name": "LibreNMS",
    "type": "inbound",
    "description": "Imports monitored devices from LibreNMS, plus the endpoints it has learned from their ARP and MAC forwarding tables.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # An 'endpoint' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'endpoint': "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "LibreNMS URL",
            "type": "url",
            "required": True,
            "placeholder": "https://librenms.example.com",
            "description": "Base URL of the LibreNMS web interface, including any path prefix it is reverse-proxied under. The /api/v0 path is appended automatically.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "LibreNMS API token, created at Settings > API > API Access. Sent as the X-Auth-Token header.",
        },
        {
            "key": "device_filter",
            "label": "Device filter",
            "type": "string",
            "required": False,
            "description": "Value for the /devices type parameter, for example active, up, down, ignored, or disabled. Leave blank to import every device.",
        },
        {
            "key": "collect_addresses",
            "label": "Collect device IP addresses",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch every address bound to each device's ports. One extra request per device.",
        },
        {
            "key": "collect_ports",
            "label": "Collect device ports",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch each device's ports for their interface MACs. One extra request per device. LibreNMS returns only ifName unless columns are named, so this integration always names them.",
        },
        {
            "key": "collect_arp",
            "label": "Collect the global ARP table",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import endpoints from the estate-wide ARP table. This is one request, not one per device.",
        },
        {
            "key": "collect_fdb",
            "label": "Collect the global MAC forwarding table",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import endpoints from the estate-wide FDB. Off by default: it is a single unpaginated response that can be very large on a switching estate.",
        },
        {
            "key": "port_columns",
            "label": "Port columns",
            "type": "string",
            "required": False,
            "default": "port_id,ifIndex,ifName,ifDescr,ifAlias,ifPhysAddress,ifOperStatus,ifAdminStatus,ifType,ifSpeed",
            "description": "Columns of the ports table to request. Naming a column that does not exist makes LibreNMS answer 400 and this integration then stops collecting ports for the run.",
        },
        {
            "key": "max_devices",
            "label": "Maximum devices",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on the number of devices imported in one run. 0 removes the cap.",
        },
        {
            "key": "max_discovered",
            "label": "Maximum discovered endpoints",
            "type": "int",
            "required": False,
            "default": 50000,
            "min": 0,
            "description": "Cap on the number of distinct ARP and FDB endpoint MACs imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", http_get="get", "get_json", "url_parse")
load("json", json_decode="decode")
load("jsonstream", "iter_array")
load("kwargs", "get_url_base", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "librenms"
ATTR_PREFIX = "librenms"
ATTR_SEPARATOR = "_"

API_BASE = "/api/v0"
# Kept in step with the port_columns parameter default in CONFIG. The ports
# endpoint returns ONLY ifName when no columns are named, so ifPhysAddress -
# the reason to call it at all - has to be asked for explicitly.
DEFAULT_PORT_COLUMNS = "port_id,ifIndex,ifName,ifDescr,ifAlias,ifPhysAddress,ifOperStatus,ifAdminStatus,ifType,ifSpeed"

HEXDIGITS = "0123456789abcdef"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-"]

# LibreNMS device type enum, mapped onto the runZero device type vocabulary.
# Values with no faithful equivalent stay as the librenms_type attribute.
DEVICE_TYPES = {
    "firewall": "Firewall",
    "printer": "Printer",
    "server": "Server",
    "storage": "Storage",
    "workstation": "Desktop",
    "wireless": "Wireless Access Point",
    "camera": "IP Camera",
    "power": "Power Distribution Unit",
    "loadbalancer": "Load Balancer",
    "network": "Network Device",
    "collaboration": "IP Phone",
    "environment": "Environmental Sensor",
    "sensor": "Environmental Sensor",
}
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    LibreNMS stores MACs as BARE 12-character lowercase hex with no separators
    - Mac::hex() is documented as "12 digit hex string 000a1fa3cc14" and the
    colon form exists only for display - so the input here normally arrives
    without separators. normalize_mac is deliberately not used: it clears the
    locally administered bit, and two randomized client MACs differing only in
    that bit would collapse onto one id.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    first = int(text[0:2], 16)
    if first % 2 == 1:
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


def _scope(base_url):
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used here. It keeps only the scheme and
    host, and LibreNMS is frequently reverse-proxied under a path prefix, so
    dropping the path would send every request to the wrong place on those
    installs.
    """
    return as_text(url, join=",").strip().rstrip("/")


def _api_error(body):
    """Render a LibreNMS error body as one line.

    Handler failures answer {"status":"error","message":"..."} with the real
    HTTP status. Authentication failures never reach that helper and come back
    in Laravel's own shape, {"message":"Unauthenticated."}, with no status key.
    """
    head = as_text(body, join=",").strip()
    if not head.startswith("{"):
        return head[:200]
    decoded = json_decode(head)
    if type(decoded) != "dict":
        return head[:200]
    return as_text(decoded.get("message"), join=",").strip() or head[:200]


def stream(ctx, path, key, params):
    """GET one endpoint and walk its collection without decoding it whole.

    Nothing in the LibreNMS API pages except the event log: /devices,
    /resources/ip/arp/all, and /resources/fdb each return their entire table in
    one response, and there is no limit or offset to ask for less. So the
    response is fetched with raw http.get and walked with
    jsonstream.iter_array, which yields one row at a time instead of
    materializing every row as a decoded value at once.

    Raw http.get accepts no retries kwarg, so these calls get one attempt. It
    also returns a body rather than a decoded value, so the envelope has to be
    inspected by hand - and iter_array ABORTS the script when its path is
    absent, so the body is checked for the collection key before it is
    streamed. LibreNMS answers 404 with a message when a collection is empty,
    which is a normal outcome rather than a failure.
    """
    url = ctx["base_url"] + API_BASE + path
    ctx["last_stream_status"] = 0
    resp = http_get(url, params=params, **ctx["raw_options"]) if params else http_get(url, **ctx["raw_options"])
    if resp == None:
        print("librenms: {} produced no response".format(path))
        return []
    ctx["last_stream_status"] = resp.status_code
    if resp.status_code == 404:
        print("librenms: {} returned 404 ({}); treating it as empty".format(path, _api_error(resp.body)))
        return []
    if resp.status_code == 401 or resp.status_code == 403:
        print("librenms: {} was refused: {}. Check the API token and the token user's device access.".format(
            path, _api_error(resp.body)))
        return []
    if resp.status_code < 200 or resp.status_code > 299:
        print("librenms: {} failed with status {}: {}".format(path, resp.status_code, _api_error(resp.body)))
        return []

    text = as_text(resp.body, join=",")
    marker = '"' + key + '"'
    # The whole body is scanned for the collection key, not a fixed head
    # window: LibreNMS can put a long message or count block ahead of the
    # collection, and a key past a short window used to make a populated
    # response look empty and be silently skipped. The presence check itself
    # stays, because iter_array ABORTS the script when its path is absent.
    if marker not in text:
        print("librenms: {} returned no {} collection: {}".format(path, key, _api_error(text)))
        return []
    return iter_array(text, path=key)


def fetch(ctx, path, key, params):
    """GET one small endpoint and return its collection as a list.

    Used for the per-device calls, which are bounded by a single device's port
    or address count and therefore do not need streaming. These go through
    get_json so they keep the default three retries.
    """
    url = ctx["base_url"] + API_BASE + path
    data, err = get_json(url, params=params, **ctx["http_options"]) if params else get_json(url, **ctx["http_options"])
    if err:
        # An empty collection is a 404 here, not an empty array, so it is not
        # worth a warning; anything else is.
        if err.startswith("status 404"):
            return []
        if err.startswith("status 400"):
            return None
        print("librenms: {} failed: {}".format(path, err))
        return []
    if type(data) != "dict":
        return []
    rows = data.get(key)
    if type(rows) != "list":
        return []
    return dicts(rows)


def device_addresses(ctx, device_id):
    """Return the addresses bound to a device's ports.

    /devices/{id}/ip merges the v4 and v6 result sets into ONE array under the
    key `addresses`, so the two row shapes are heterogeneous: v4 rows carry
    ipv4_address and ipv4_prefixlen, v6 rows carry ipv6_address,
    ipv6_compressed, and ipv6_prefixlen.
    """
    rows = fetch(ctx, "/devices/{}/ip".format(device_id), "addresses", None)
    if rows == None:
        return []
    addresses = []
    for row in rows:
        for field in ["ipv4_address", "ipv6_address", "ipv6_compressed"]:
            address = routable_ip(row.get(field))
            if address and address not in addresses:
                addresses.append(address)
    return addresses


def device_ports(ctx, device_id):
    """Return a device's ports, with the columns actually needed.

    The DEFAULT response is only ifName: get_device_ports() calls
    validate_column_list(..., ['ifName']) and that default is returned whenever
    no columns parameter is supplied. So ifPhysAddress - the whole reason to
    call this - is absent unless the columns are named explicitly. Naming a
    column the schema does not have raises InvalidTableColumnException and
    answers 400, which disables port collection for the rest of the run rather
    than repeating the same failure once per device.
    """
    if not ctx["collect_ports"]:
        return []
    rows = fetch(ctx, "/devices/{}/ports".format(device_id), "ports",
                 {"columns": ctx["port_columns"]})
    if rows == None:
        print("librenms: the ports request was rejected as an invalid column list. " +
              "Port collection is disabled for the rest of this run; adjust port_columns " +
              "to match this LibreNMS release.")
        ctx["collect_ports"] = False
        return []
    return rows


def build_device_asset(ctx, record, addresses, ports):
    """Convert one LibreNMS device row into a runZero asset."""
    device_id = as_text(record.get("device_id"), join=",").strip()

    # LibreNMS "hostname" is the polling target, which is very often an IP
    # literal rather than a name, so it is sniffed rather than assumed.
    polled = as_text(record.get("hostname"), join=",").strip()
    all_addresses = dedupe([routable_ip(record.get("ip")), routable_ip(polled)] + addresses)
    hostnames = dedupe([
        _hostname(polled),
        _hostname(record.get("sysName")),
        _hostname(record.get("display")),
    ])

    port_macs = []
    port_names = []
    for port in ports:
        mac = _mac_key(port.get("ifPhysAddress"))
        if mac and mac not in port_macs:
            port_macs.append(mac)
        name = as_text(port.get("ifName"), join=",").strip()
        if name:
            port_names.append(name)

    netifs = []
    primary = network_interface(mac=port_macs[0] if port_macs else "", ips=all_addresses)
    if primary:
        netifs.append(primary)
    for mac in port_macs[1:]:
        nic = network_interface(mac=mac)
        if nic:
            netifs.append(nic)

    if not hostnames and not netifs:
        # Nothing to correlate on: no usable name, no address, no port MAC. A
        # device polled at a loopback address with no sysName lands here; such
        # an asset can never merge with anything and is skipped rather than
        # imported as an orphan.
        print("librenms: skipping device {} with no usable hostname, address, or MAC".format(device_id))
        return None

    status_up = as_text(record.get("status"), join=",").strip() == "1"
    # This attribute set is an explicit ALLOWLIST rather than a copy of the
    # record with a few keys removed, and that is deliberate. /devices is built
    # from a plain SELECT d.* and the Device model declares no hidden fields, so
    # the response carries community, authname, authpass, authalgo, cryptopass,
    # cryptoalgo, and snmp_engine_id - the SNMP credentials for every monitored
    # device, in cleartext. Copying the record wholesale would write them into
    # runZero. Nothing here reads them.
    attrs = {
        "device_id": device_id,
        "server": ctx["scope"],
        "polling_target": polled,
        "sys_name": record.get("sysName"),
        "display": record.get("display"),
        "sys_descr": record.get("sysDescr"),
        "sys_contact": record.get("sysContact"),
        "sys_object_id": record.get("sysObjectID"),
        "os": record.get("os"),
        "version": record.get("version"),
        "hardware": record.get("hardware"),
        "features": record.get("features"),
        "serial": record.get("serial"),
        "type": record.get("type"),
        "purpose": record.get("purpose"),
        "notes": record.get("notes"),
        "location": record.get("location"),
        "location_id": record.get("location_id"),
        "lat": record.get("lat"),
        "lng": record.get("lng"),
        "status": "up" if status_up else "down",
        "status_reason": record.get("status_reason"),
        "disabled": record.get("disabled"),
        "ignore": record.get("ignore"),
        "uptime": record.get("uptime"),
        "snmp_version": record.get("snmpver"),
        "snmp_port": record.get("port"),
        "snmp_transport": record.get("transport"),
        "poller_group": record.get("poller_group"),
        "dependency_parent_hostname": record.get("dependency_parent_hostname"),
        "port_count": len(ports),
        "port_names": port_names[:50],
        "addresses": all_addresses,
        # Kept as raw strings. LibreNMS writes these as MySQL timestamps with
        # no zone, and a value read as UTC can land in the future, which makes
        # the platform reject the ENTIRE asset record rather than the field.
        "last_polled_raw": record.get("last_polled"),
        "last_discovered_raw": record.get("last_discovered"),
    }

    tags = [VENDOR, "librenms-device"]
    if not status_up:
        tags.append("librenms-down")
    if as_text(record.get("disabled"), join=",").strip() == "1":
        tags.append("librenms-disabled")
    if as_text(record.get("ignore"), join=",").strip() == "1":
        tags.append("librenms-ignored")
    serial = as_text(record.get("serial"), join=",").strip()
    if serial:
        tags.append("serial:" + serial)
    location = as_text(record.get("location"), join=",").strip()
    if location:
        tags.append("location:" + location)

    params = {
        # device_id is the primary key of the LibreNMS devices table and every
        # per-device route accepts it. It survives rename, re-address, OS
        # upgrade, and re-discovery, so it is allowed to drive merges.
        "id": "{}:{}:device:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        # A device polled over SNMP by DNS name may publish no address of its
        # own, and ifPhysAddress is frequently empty on virtual and aggregate
        # interfaces, so an absent MAC or a changed address must not
        # disqualify a merge against an asset runZero already discovered. That
        # is the integration-wide policy in CONFIG, which this type inherits.
        "assetType": "device",
    }

    os_name = as_text(record.get("os"), join=",").strip()
    if os_name:
        params["os"] = os_name
    version = as_text(record.get("version"), join=",").strip()
    if version:
        params["osVersion"] = version
    hardware = as_text(record.get("hardware"), join=",").strip()
    if hardware:
        params["model"] = hardware
    device_type = DEVICE_TYPES.get(as_text(record.get("type"), join=",").strip().lower(), "")
    if device_type:
        params["deviceType"] = device_type

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)


def _endpoint(index, order, ctx, mac):
    if mac not in index:
        if ctx["max_discovered"] and len(order) >= ctx["max_discovered"]:
            return None
        index[mac] = {
            "mac": mac,
            "ips": [],
            "sources": [],
            "device_ids": [],
            "port_ids": [],
            "vlans": [],
            "contexts": [],
        }
        order.append(mac)
    return index[mac]


def _append(record, key, value):
    text = as_text(value, join=",").strip()
    if text and text not in record[key]:
        record[key].append(text)


def _fold_arp_row(ctx, index, order, row):
    """Fold one ARP row into the endpoint index. Returns 1 when it counted."""
    if type(row) != "dict":
        return 0
    mac = _mac_key(row.get("mac_address"))
    if not mac:
        return 0
    record = _endpoint(index, order, ctx, mac)
    if record == None:
        return 0
    _append(record, "sources", "arp")
    ip = routable_ip(row.get("ipv4_address"))
    if ip:
        _append(record, "ips", ip)
    _append(record, "device_ids", row.get("device_id"))
    _append(record, "port_ids", row.get("port_id"))
    _append(record, "contexts", row.get("context_name"))
    return 1


def collect_arp(ctx, index, order):
    """Fold the estate-wide ARP table into the endpoint index.

    /api/v0/resources/ip/arp/all with no device parameter returns Ipv4Mac::all()
    - every ARP entry LibreNMS has learned across every device, in one
    unpaginated response. Rows are {port_id, device_id, mac_address,
    ipv4_address, context_name}. Note that the per-device form documented
    elsewhere as /devices/{id}/arp/all does NOT exist: there is no arp route
    under /devices at all, and the catch-all graph route would swallow it.

    Older LibreNMS releases follow the published docs instead and answer 400
    when arp/all is asked for without a device parameter. That used to end the
    endpoint collection with one log line and zero endpoints; those releases do
    accept the per-device form, so the walk falls back to one request per
    already-imported device.
    """
    seen = 0
    for row in stream(ctx, "/resources/ip/arp/all", "arp", None):
        seen += _fold_arp_row(ctx, index, order, row)
    if ctx.get("last_stream_status") == 400:
        print("librenms: this LibreNMS requires a device parameter with arp/all; retrying once per device")
        for device_id in ctx["device_names"]:
            for row in stream(ctx, "/resources/ip/arp/all", "arp", {"device": device_id}):
                seen += _fold_arp_row(ctx, index, order, row)
    return seen


def collect_fdb(ctx, index, order):
    """Fold the estate-wide MAC forwarding table into the endpoint index.

    /api/v0/resources/fdb returns every ports_fdb row LibreNMS can see, with no
    limit or offset available, so it is streamed for the same reason as the ARP
    table. Rows are {ports_fdb_id, port_id, mac_address, vlan_id, device_id,
    created_at, updated_at}. An empty table answers 404.
    """
    seen = 0
    for row in stream(ctx, "/resources/fdb", "ports_fdb", None):
        if type(row) != "dict":
            continue
        mac = _mac_key(row.get("mac_address"))
        if not mac:
            continue
        record = _endpoint(index, order, ctx, mac)
        if record == None:
            continue
        _append(record, "sources", "fdb")
        _append(record, "device_ids", row.get("device_id"))
        _append(record, "port_ids", row.get("port_id"))
        _append(record, "vlans", row.get("vlan_id"))
        seen += 1
    return seen


def build_endpoint_asset(ctx, record):
    """Convert one merged ARP/FDB endpoint into a runZero asset."""
    mac = record["mac"]
    nic = network_interface(mac=mac, ips=record["ips"])

    switches = []
    for device_id in record["device_ids"]:
        name = ctx["device_names"].get(device_id, "")
        switches.append("{} ({})".format(name, device_id) if name else device_id)

    attrs = {
        "server": ctx["scope"],
        "mac": mac,
        "sources": record["sources"],
        "addresses": record["ips"],
        "device_ids": record["device_ids"],
        "devices": switches,
        "port_ids": record["port_ids"],
        "port_names": [ctx["port_names"].get(port_id, "") for port_id in record["port_ids"]],
        "vlans": record["vlans"],
        "snmp_contexts": record["contexts"],
    }

    tags = [VENDOR, "librenms-endpoint"]
    for source in record["sources"]:
        tags.append("librenms-" + source)

    return ImportAsset(
        # An ARP or FDB entry has no identifier but its MAC. It is paired with
        # no-id-match so the id never drives a merge: a MAC that is reassigned,
        # spoofed, or randomized must not be able to pull a different device
        # onto an existing asset, and no break flag can veto a foreign-id match
        # once it happens.
        id="{}:{}:endpoint:{}".format(VENDOR, ctx["scope"], mac),
        hostnames=[],
        networkInterfaces=[nic] if nic else [],
        tags=tags,
        assetType="endpoint",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )


def collect_devices(ctx):
    """Stream /devices and report each batch of device assets."""
    params = {}
    if ctx["device_filter"]:
        params["type"] = ctx["device_filter"]

    reported = 0
    skipped = 0
    for record in stream(ctx, "/devices", "devices", params if params else None):
        if type(record) != "dict":
            continue
        device_id = as_text(record.get("device_id"), join=",").strip()
        if not device_id:
            print("librenms: skipping device with no device_id: hostname=" + as_text(record.get("hostname"), join=","))
            continue
        if ctx["max_devices"] and reported >= ctx["max_devices"]:
            skipped += 1
            continue

        addresses = device_addresses(ctx, device_id) if ctx["collect_addresses"] else []
        ports = device_ports(ctx, device_id)
        for port in ports:
            port_id = as_text(port.get("port_id"), join=",").strip()
            name = as_text(port.get("ifName"), join=",").strip()
            if port_id and name:
                ctx["port_names"][port_id] = name

        ctx["device_names"][device_id] = (as_text(record.get("sysName"), join=",").strip()
                                          or as_text(record.get("hostname"), join=",").strip())
        asset = build_device_asset(ctx, record, addresses, ports)
        if asset == None:
            continue
        report_asset(asset)
        reported += 1
    return reported, skipped


def main(**kwargs):
    base_url = _base(get_string(kwargs, "url"))
    scope = _scope(base_url)
    if not base_url or not scope:
        print("librenms: could not determine the LibreNMS host from the configured URL")
        return None

    headers = {
        "X-Auth-Token": get_string(kwargs, "api_token"),
        "Accept": "application/json",
    }
    http_options = get_http_options(kwargs, headers=dict(headers))
    # Raw http.get rejects a retries kwarg entirely, so the streamed calls get
    # one attempt each. The per-device calls keep the default three.
    raw_options = get_http_options(kwargs, headers=dict(headers))
    raw_options.pop("retries", None)

    max_devices = get_int(kwargs, "max_devices", default=5000)
    max_discovered = get_int(kwargs, "max_discovered", default=50000)

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": http_options,
        "raw_options": raw_options,
        "device_filter": as_text(get_string(kwargs, "device_filter", default=""), join=",").strip(),
        "collect_addresses": get_bool(kwargs, "collect_addresses", default=True),
        "collect_ports": get_bool(kwargs, "collect_ports", default=True),
        "port_columns": as_text(get_string(kwargs, "port_columns", default=DEFAULT_PORT_COLUMNS), join=",").strip(),
        "max_devices": max_devices if max_devices > 0 else 0,
        "max_discovered": max_discovered if max_discovered > 0 else 0,
        "device_names": {},
        "port_names": {},
        # Status of the most recent stream() response, read by collect_arp to
        # notice the older-release 400 on arp/all without a device parameter.
        "last_stream_status": 0,
    }

    devices, device_skipped = collect_devices(ctx)
    print("librenms: reported {} devices".format(devices))
    if device_skipped:
        print("librenms: device limit of {} reached; {} further devices were not imported".format(
            ctx["max_devices"], device_skipped))

    index = {}
    order = []
    if get_bool(kwargs, "collect_arp", default=True):
        print("librenms: ARP entries read: {}".format(collect_arp(ctx, index, order)))
    if get_bool(kwargs, "collect_fdb", default=False):
        print("librenms: FDB entries read: {}".format(collect_fdb(ctx, index, order)))

    endpoints = 0
    for mac in order:
        report_asset(build_endpoint_asset(ctx, index[mac]))
        endpoints += 1
    if endpoints:
        print("librenms: reported {} discovered endpoints".format(endpoints))
    if ctx["max_discovered"] and len(order) >= ctx["max_discovered"]:
        print("librenms: endpoint limit of {} reached; further endpoints were not imported".format(
            ctx["max_discovered"]))

    if not devices and not endpoints:
        print("librenms: no assets retrieved")
    return None

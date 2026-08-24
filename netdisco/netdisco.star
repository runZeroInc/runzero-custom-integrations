# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-netdisco",
    "name": "Netdisco",
    "type": "inbound",
    "description": "Imports switches and routers from Netdisco, plus the layer-2 nodes it has located on their switchports.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Netdisco URL",
            "type": "url",
            "required": True,
            "placeholder": "https://netdisco.example.com",
            "description": "Base URL of the Netdisco web application, including any path prefix it is mounted under.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "Netdisco user with the api role. Sent as the HTTP Basic username to POST /login.",
        },
        {
            "key": "password",
            "label": "Password or API key",
            "type": "secret",
            "required": True,
            "description": "Password for the Netdisco user, or a permanent API key issued with netdisco-do getapikey.",
        },
        {
            "key": "collect_nodes",
            "label": "Collect layer-2 nodes",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the MAC addresses Netdisco has located on each device's switchports. This is one extra request per device.",
        },
        {
            "key": "active_only",
            "label": "Active nodes only",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Ask Netdisco for currently-present nodes only. Netdisco retains departed nodes indefinitely, so turning this off imports history.",
        },
        {
            "key": "max_age_days",
            "label": "Maximum node age in days",
            "type": "int",
            "required": False,
            "default": 30,
            "min": 0,
            "description": "Drop nodes whose last sighting is older than this. 0 disables the age filter. Applied by this script, because the node endpoint has no age parameter.",
        },
        {
            "key": "collect_device_ips",
            "label": "Collect device interface addresses",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch each device's IP aliases so a switch matches on every address it answers to, not just its management IP. One extra request per device.",
        },
        {
            "key": "collect_ports",
            "label": "Collect switchport MACs",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch each device's ports for their interface MACs. Off by default: a chassis switch can return hundreds of ports and the device already carries a base MAC.",
        },
        {
            "key": "ip_inventory_subnets",
            "label": "IP inventory subnets",
            "type": "string",
            "required": False,
            "description": "Comma-separated CIDRs to pull from the IP Inventory report, which is the only endpoint that joins a node MAC to its IP and DNS name. Leave blank to import nodes with their MAC alone.",
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
            "key": "max_nodes",
            "label": "Maximum nodes",
            "type": "int",
            "required": False,
            "default": 50000,
            "min": 0,
            "description": "Cap on the number of distinct node MACs imported in one run. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Device page size",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 5000,
            "description": "Devices requested per call to /api/v1/search/device.",
        },
        {
            "key": "device_fields",
            "label": "Device fields",
            "type": "string",
            "required": False,
            "default": "ip,dns,name,description,location,contact,model,os,os_ver,vendor,serial,chassis_id,layers,uptime,mac,num_ports,snmp_ver,snmp_class,is_pseudo,creation,last_discover,last_macsuck,last_arpnip",
            "description": "Columns of the Netdisco device table to request. Any column name is valid; snmp_comm is deliberately excluded because it is the SNMP community in cleartext.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", "post_json", "basic", "url_parse")
load("kwargs", "get_url_base", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", "parse_time", 'parse_ts')

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "netdisco"
ATTR_PREFIX = "netdisco"
ATTR_SEPARATOR = "_"

# Kept in step with the device_fields parameter default in CONFIG. snmp_comm is
# deliberately absent: it is the SNMP community string in cleartext, and
# fields=all would hand it to runZero along with snmp_engineid and the log.
DEFAULT_DEVICE_FIELDS = "ip,dns,name,description,location,contact,model,os,os_ver,vendor,serial,chassis_id,layers,uptime,mac,num_ports,snmp_ver,snmp_class,is_pseudo,creation,last_discover,last_macsuck,last_arpnip"
# The IP Inventory report caps its own result set at 8192 rows server-side.
IP_INVENTORY_LIMIT = 8192
# How many "switch/port" sightings to record on a node that several switches see.
MAX_SIGHTINGS = 10

HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-", "0.0.0.0"]

# Netdisco's "layers" column is an eight-character bit string, MSB first, where
# each position is an OSI layer the device reported through SNMP sysServices.
LAYER_NAMES = ["7-application", "6-presentation", "5-session", "4-transport",
               "3-network", "2-datalink", "1-physical"]

# Coarse device typing from the layers the device claims. A device that claims
# layer 3 routes; one that only claims layer 2 switches. Netdisco has no device
# type field of its own.
def _device_type(layers):
    if not layers or len(layers) < 8:
        return ""
    # The string is MSB-first over an 8-bit sysServices value, so position i
    # carries layer 8-i: layer 3 (network) is index 5 and layer 2 (datalink)
    # is index 6.
    routes = layers[5] == "1"
    switches = layers[6] == "1"
    if routes and switches:
        return "Switch"
    if routes:
        return "Router"
    if switches:
        return "Switch"
    return ""
def _to_int(value):
    if type(value) == "int":
        return value
    text = as_text(value, join=",").strip()
    if not text or len(text) > 12:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    normalize_mac is deliberately avoided: it clears the locally administered
    bit, so two randomized client MACs that differ only in that bit would
    collapse onto one id. A switching estate's node table is full of them.
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
def _age_days(value, current):
    """Return how many days ago a timestamp is, or -1 when it cannot be read."""
    parsed = parse_ts(value)
    if parsed == None:
        return -1
    # Netdisco writes a zero date ("0001-01-01 00:00:00") for a node it has a
    # row for but no sighting time. That parses cleanly, so without this it
    # reads as two thousand years old and every such node is aged out -- which
    # silently drops exactly the nodes whose age is unknown. Unknown is -1,
    # the same answer an unparseable value gets, so the caller keeps the node.
    if parsed.unix <= 0:
        return -1
    delta = current.unix - parsed.unix
    if delta < 0:
        return 0
    return delta // 86400


def _netdisco_host(base_url):
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used here. It keeps only the scheme and
    host, and Netdisco is commonly reverse-proxied under a path prefix - its
    own `path` setting exists for exactly that - so dropping the path would
    send every request to the wrong place on those installs.
    """
    return as_text(url, join=",").strip().rstrip("/")


def login(base_url, username, password, http_options):
    """Exchange Basic credentials for an API token.

    POST /login answers {"api_key": "..."}. The token is then sent in the
    Authorization header in PLAIN TEXT - not as a Bearer token. Netdisco
    accepts an optional "Apikey " prefix and nothing else; a "Bearer " prefix
    is not recognised. Tokens expire after api_token_lifetime, one hour by
    default, which a run near the device cap can outlive - refresh_token
    handles that with one mid-run re-login.
    """
    data, err = post_json(base_url + "/login", json={}, **http_options)
    if err:
        print("netdisco: login failed:", err)
        return ""
    if type(data) != "dict":
        print("netdisco: login returned an unexpected body")
        return ""
    token = as_text(data.get("api_key"), join=",").strip()
    if not token:
        print("netdisco: login succeeded but returned no api_key")
        return ""
    return token


def refresh_token(ctx):
    """Re-login once when the API token is refused mid-run.

    Netdisco tokens expire after api_token_lifetime (one hour by default), so a
    run on a large estate can outlive its token: devices keep importing but
    every later enrichment and node call is refused, one log line each, and the
    node phase yields nothing. One re-login per run restores the header; a
    second refusal is a real permission problem and is not retried.
    """
    if ctx["relogged"]:
        return False
    ctx["relogged"] = True
    print("netdisco: the API token was refused mid-run (tokens expire after api_token_lifetime); logging in again")
    token = login(ctx["base_url"], "", "", ctx["login_options"])
    if not token:
        print("netdisco: re-login failed; continuing with the refused token")
        return False
    ctx["http_options"]["headers"]["Authorization"] = token
    return True


def fetch_list(ctx, path, params):
    """Call an endpoint documented to return a JSON array.

    Netdisco answers every /api/ request with application/json and substitutes
    an empty body with "[]", so an empty result is a valid array rather than an
    error. A failure is logged and returned as None so one unreadable device
    cannot end the run. An auth refusal triggers one re-login for the whole
    run, and the refused request is retried once with the fresh token.
    """
    url = ctx["base_url"] + path
    data, err = get_json(url, params=params, **ctx["http_options"]) if params else get_json(url, **ctx["http_options"])
    if err != None and ("status 401" in err or "status 403" in err) and refresh_token(ctx):
        data, err = get_json(url, params=params, **ctx["http_options"]) if params else get_json(url, **ctx["http_options"])
    if err:
        print("netdisco: {} failed: {}".format(path, err))
        return None
    if type(data) == "list":
        return dicts(data)
    if type(data) == "dict" and data.get("error") != None:
        print("netdisco: {} returned an error: {}".format(path, as_text(data.get("error"), join=",")))
        return None
    print("netdisco: {} returned an unexpected shape".format(path))
    return None


def device_ips(ctx, ip):
    """Return the extra addresses a device answers to, from the device_ip table
    ({ip, alias, subnet, port, dns, creation})."""
    rows = fetch_list(ctx, "/api/v1/object/device/{}/device_ips".format(ip), None)
    if rows == None:
        return [], []
    addresses = []
    names = []
    for row in rows:
        alias = routable_ip(row.get("alias"))
        if alias:
            addresses.append(alias)
        name = _hostname(row.get("dns"))
        if name:
            names.append(name)
    return dedupe(addresses), dedupe(names)


def device_port_macs(ctx, ip):
    """Return the interface MACs on a device's ports, from the device_port
    table. Ports carry no addresses of their own in Netdisco."""
    rows = fetch_list(ctx, "/api/v1/object/device/{}/ports".format(ip), None)
    if rows == None:
        return []
    macs = []
    for row in rows:
        mac = _mac_key(row.get("mac"))
        if mac and mac not in macs:
            macs.append(mac)
    return macs


def build_device_asset(ctx, record, extra_ips, extra_names, port_macs):
    """Convert one Netdisco device row into a runZero asset."""
    ip = as_text(record.get("ip"), join=",").strip()
    management = routable_ip(ip)

    addresses = dedupe(([management] if management else []) + extra_ips)
    hostnames = dedupe([_hostname(record.get("dns")), _hostname(record.get("name"))] + extra_names)

    netifs = []
    base_mac = _mac_key(record.get("mac"))
    primary = network_interface(mac=base_mac, ips=addresses)
    if primary:
        netifs.append(primary)
    for mac in port_macs:
        if mac == base_mac:
            continue
        nic = network_interface(mac=mac)
        if nic:
            netifs.append(nic)

    if not hostnames and not netifs:
        # Nothing to correlate on. A Netdisco pseudo device recorded against a
        # loopback address with no DNS name lands here; such an asset can never
        # merge with anything and is skipped rather than imported as an orphan.
        print("netdisco: skipping device {} with no usable hostname, address, or MAC".format(ip))
        return None

    layers = as_text(record.get("layers"), join=",").strip()
    serials = record.get("module_serials")
    attrs = {
        "management_ip": ip,
        "sys_name": record.get("name"),
        "dns": record.get("dns"),
        "description": record.get("description"),
        "location": record.get("location"),
        "contact": record.get("contact"),
        "vendor": record.get("vendor"),
        "model": record.get("model"),
        "os": record.get("os"),
        "os_version": record.get("os_ver"),
        "serial": record.get("serial"),
        "chassis_id": record.get("chassis_id"),
        "module_serials": serials if type(serials) == "list" else [],
        "layers": layers,
        "layer_names": [LAYER_NAMES[index] for index in range(7) if len(layers) == 8 and layers[index + 1] == "1"],
        "num_ports": record.get("num_ports"),
        "uptime": record.get("uptime"),
        "snmp_version": record.get("snmp_ver"),
        "snmp_class": record.get("snmp_class"),
        "is_pseudo": record.get("is_pseudo"),
        "vtp_domain": record.get("vtp_domain"),
        # The raw timestamps are kept verbatim because the parsed values are
        # clamped to now: Netdisco writes local time with no zone and there is
        # no way to recover the offset from the API.
        "creation_raw": record.get("creation"),
        "last_discover_raw": record.get("last_discover"),
        "last_macsuck_raw": record.get("last_macsuck"),
        "last_arpnip_raw": record.get("last_arpnip"),
        "first_seen_stamp": record.get("first_seen_stamp"),
        "last_discover_stamp": record.get("last_discover_stamp"),
        "netdisco_host": ctx["scope"],
    }
    if type(record.get("custom_fields")) == "dict":
        attrs["custom_fields"] = record.get("custom_fields")
    if type(record.get("tags")) == "list":
        attrs["device_tags"] = record.get("tags")

    tags = [VENDOR, "netdisco-device"]
    if record.get("is_pseudo") == True or as_text(record.get("is_pseudo"), join=",") == "1":
        tags.append("netdisco-pseudo-device")
    # ImportAsset has no serial field, so the chassis serial and any module
    # serials Netdisco has collected are carried as attributes and as tags.
    for serial in dedupe([record.get("serial")] + (serials if type(serials) == "list" else [])):
        tags.append("serial:" + serial)

    params = {
        # Netdisco's device table is keyed on the management IP and every
        # per-device route is addressed by it, so it is the vendor's identity
        # for the device. It is still an ADDRESS, which is why it is paired
        # with no-id-match: see the README's Asset identity section.
        "id": "{}:{}:device:{}".format(VENDOR, ctx["scope"], ip),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    os_name = as_text(record.get("os"), join=",").strip()
    if os_name:
        params["os"] = os_name
    os_version = as_text(record.get("os_ver"), join=",").strip()
    if os_version:
        params["osVersion"] = os_version
    vendor = as_text(record.get("vendor"), join=",").strip()
    if vendor:
        params["manufacturer"] = vendor
    model = as_text(record.get("model"), join=",").strip()
    if model:
        params["model"] = model
    device_type = _device_type(layers)
    if device_type:
        params["deviceType"] = device_type
    created = parse_ts(record.get("creation"))
    if created:
        params["firstSeenTS"] = created

    asset = ImportAsset(**params)
    last_seen = parse_ts(record.get("last_discover"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def collect_nodes(ctx, ip, device_name, index, order):
    """Fold one device's located nodes into the MAC index.

    /api/v1/object/device/{ip}/nodes returns rows straight from the node table:
    {mac, switch, port, active, time_first, time_recent, time_last, vlan}. The
    `oui` column is marked non-serializable upstream and never appears.

    active_only is the only query parameter this route accepts. Netdisco's age
    filtering (age_num / age_unit / daterange) belongs to the search endpoints,
    not this one, so max_age_days is applied here against time_last.
    """
    params = {"active_only": "true" if ctx["active_only"] else "false"}
    rows = fetch_list(ctx, "/api/v1/object/device/{}/nodes".format(ip), params)
    if rows == None:
        return 0, 0
    kept = 0
    aged_out = 0
    for row in rows:
        mac = _mac_key(row.get("mac"))
        if not mac:
            continue
        if ctx["max_age_days"] > 0:
            age = _age_days(row.get("time_last"), ctx["current"])
            if age > ctx["max_age_days"]:
                aged_out += 1
                continue
        if mac not in index:
            if ctx["max_nodes"] and len(order) >= ctx["max_nodes"]:
                continue
            index[mac] = {
                "mac": mac,
                "ips": [],
                "hostnames": [],
                "sightings": [],
                "switch": "",
                "switch_name": "",
                "port": "",
                "vlan": "",
                "time_last": "",
                "time_first": "",
                "active": None,
                "vendor": "",
            }
            order.append(mac)
        record = index[mac]
        switch = as_text(row.get("switch"), join=",").strip() or as_text(ip, join=",")
        port = as_text(row.get("port"), join=",").strip()
        sighting = "{}/{}".format(switch, port) if port else switch
        if sighting not in record["sightings"] and len(record["sightings"]) < MAX_SIGHTINGS:
            record["sightings"].append(sighting)
        # A node seen by several switches keeps the most recent sighting as its
        # primary location; an uplink port sees every MAC behind it, so the
        # newest sighting is the closest thing to the access port. The
        # comparison parses both timestamps; the string comparison is only the
        # fallback for a value parse_ts does not recognize, so a format change
        # in Netdisco cannot silently pick the wrong sighting.
        seen = as_text(row.get("time_last"), join=",")
        seen_ts = parse_ts(seen)
        prev_ts = parse_ts(record["time_last"])
        if seen_ts != None and prev_ts != None:
            newer = seen_ts.unix > prev_ts.unix
        else:
            newer = seen > record["time_last"]
        if not record["switch"] or newer:
            record["switch"] = switch
            record["switch_name"] = device_name
            record["port"] = port
            record["vlan"] = as_text(row.get("vlan"), join=",")
            record["time_last"] = seen
            record["time_first"] = as_text(row.get("time_first"), join=",")
            record["active"] = row.get("active")
        kept += 1
    return kept, aged_out


def collect_ip_inventory(ctx, index, order):
    """Attach IP and DNS data to located nodes from the IP Inventory report.

    /api/v1/report/ip/ipinventory is the only API surface that joins a node MAC
    to an address: the node endpoints return the node table alone, and
    /api/v1/search/node requires a q parameter naming a single host, so it
    cannot enumerate. The report unions device_ip, node_ip, and node_nbt and
    returns {ip, mac, dns, time_last, time_first, active, node, age, vendor,
    nbname} for one subnet at a time, which is why the subnets are a parameter.
    """
    attached = 0
    for subnet in ctx["ip_inventory_subnets"]:
        rows = fetch_list(ctx, "/api/v1/report/ip/ipinventory", {
            "subnet": subnet,
            "limit": str(IP_INVENTORY_LIMIT),
        })
        if rows == None:
            continue
        if len(rows) >= IP_INVENTORY_LIMIT:
            print("netdisco: IP inventory for {} hit the server-side cap of {} rows; narrow the subnet to see the rest".format(
                subnet, IP_INVENTORY_LIMIT))
        for row in rows:
            mac = _mac_key(row.get("mac"))
            if not mac or mac not in index:
                continue
            record = index[mac]
            ip = routable_ip(row.get("ip"))
            if ip and ip not in record["ips"]:
                record["ips"].append(ip)
                attached += 1
            for key in ["dns", "nbname"]:
                name = _hostname(row.get(key))
                if name and name not in record["hostnames"]:
                    record["hostnames"].append(name)
            if not record["vendor"]:
                record["vendor"] = as_text(row.get("vendor"), join=",").strip()
    return attached


def build_node_asset(ctx, record):
    """Convert one located node into a runZero asset."""
    mac = record["mac"]
    nic = network_interface(mac=mac, ips=record["ips"])

    attrs = {
        "netdisco_host": ctx["scope"],
        "mac": mac,
        "switch": record["switch"],
        "switch_name": record["switch_name"],
        "port": record["port"],
        "vlan": record["vlan"],
        "sightings": record["sightings"],
        "sighting_count": len(record["sightings"]),
        "time_first_raw": record["time_first"],
        "time_last_raw": record["time_last"],
        "active": record["active"],
        "vendor": record["vendor"],
        "addresses": record["ips"],
    }

    tags = [VENDOR, "netdisco-node"]
    if record["switch"]:
        tags.append("netdisco-switch:" + record["switch"])

    params = {
        # A located node has no identifier but its MAC, which is the leading
        # column of the node table's composite primary key. It is paired with
        # no-id-match so it never drives a merge; see the README.
        "id": "{}:{}:node:{}".format(VENDOR, ctx["scope"], mac),
        "hostnames": record["hostnames"],
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if record["vendor"]:
        params["manufacturer"] = record["vendor"]

    asset = ImportAsset(**params)
    first_seen = parse_ts(record["time_first"])
    if first_seen:
        asset.firstSeenTS = first_seen
    # Screened the same way _age_days screens it: a zero date is "never seen",
    # not a sighting in year one.
    last_seen = parse_ts(record["time_last"])
    if last_seen != None and last_seen.unix > 0:
        asset.lastSeenTS = last_seen
    return asset


def collect_devices(ctx):
    """Page /api/v1/search/device and stream each page of devices.

    Netdisco's device search takes limit and offset, and its own parameter
    documentation states that q is optional when both are supplied, in which
    case every device is returned ordered by dns then ip. That ordering is
    stable, which is what makes offset paging safe here. A short page ends the
    walk; there is no total count in the response.
    """
    devices = []
    reported = 0
    skipped = 0
    _pager = pager("netdisco")
    while _pager.next():
        page = _pager.page - 1
        offset = page * ctx["page_size"]
        if ctx["max_devices"] and offset >= ctx["max_devices"]:
            break
        rows = fetch_list(ctx, "/api/v1/search/device", {
            "limit": str(ctx["page_size"]),
            "offset": str(offset),
            "fields": ctx["device_fields"],
        })
        if rows == None:
            if page == 0:
                print("netdisco: the device search rejected limit/offset paging. Netdisco releases before " +
                      "the limit/offset parameters were added require a q parameter; upgrade Netdisco or " +
                      "collect a narrower estate.")
            break
        if not rows:
            break

        for record in rows:
            ip = as_text(record.get("ip"), join=",").strip()
            if not ip:
                print("netdisco: skipping device with no ip: name=" + as_text(record.get("name"), join=","))
                continue
            if ctx["max_devices"] and reported >= ctx["max_devices"]:
                skipped += 1
                continue
            extra_ips = []
            extra_names = []
            if ctx["collect_device_ips"]:
                extra_ips, extra_names = device_ips(ctx, ip)
            port_macs = device_port_macs(ctx, ip) if ctx["collect_ports"] else []
            asset = build_device_asset(ctx, record, extra_ips, extra_names, port_macs)
            if asset == None:
                continue
            report_asset(asset)
            devices.append((ip, _hostname(record.get("dns")) or _hostname(record.get("name"))))
            reported += 1

        if len(rows) < ctx["page_size"]:
            break

    return devices, reported, skipped


def main(**kwargs):
    base_url = _base(get_string(kwargs, "url"))
    scope = _netdisco_host(base_url)
    if not base_url or not scope:
        print("netdisco: could not determine the Netdisco host from the configured URL")
        return None

    login_options = get_http_options(kwargs, headers={
        "Authorization": basic(get_string(kwargs, "username"), get_string(kwargs, "password")),
        "Accept": "application/json",
    })
    token = login(base_url, get_string(kwargs, "username"), get_string(kwargs, "password"), login_options)
    if not token:
        return None

    max_devices = get_int(kwargs, "max_devices", default=5000)
    max_nodes = get_int(kwargs, "max_nodes", default=50000)
    max_age_days = get_int(kwargs, "max_age_days", default=30)
    subnets = []
    for entry in as_text(get_string(kwargs, "ip_inventory_subnets", default=""), join=",").split(","):
        value = entry.strip()
        if value:
            subnets.append(value)

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            # Netdisco wants the token as-is, not as a Bearer credential.
            "Authorization": token,
            "Accept": "application/json",
        }),
        # Kept for the one mid-run re-login: tokens expire after
        # api_token_lifetime, and a large estate can outlive one.
        "login_options": login_options,
        "relogged": False,
        "current": now(),
        "collect_nodes": get_bool(kwargs, "collect_nodes", default=True),
        "collect_device_ips": get_bool(kwargs, "collect_device_ips", default=True),
        "collect_ports": get_bool(kwargs, "collect_ports", default=False),
        "active_only": get_bool(kwargs, "active_only", default=True),
        "max_age_days": max_age_days if max_age_days > 0 else 0,
        "max_devices": max_devices if max_devices > 0 else 0,
        "max_nodes": max_nodes if max_nodes > 0 else 0,
        "page_size": get_int(kwargs, "page_size", default=200),
        "device_fields": get_string(kwargs, "device_fields", default=DEFAULT_DEVICE_FIELDS),
        "ip_inventory_subnets": subnets,
    }

    devices, device_count, device_skipped = collect_devices(ctx)
    print("netdisco: reported {} devices".format(device_count))
    if device_skipped:
        print("netdisco: device limit of {} reached; {} further devices were not imported".format(
            ctx["max_devices"], device_skipped))

    node_count = 0
    if ctx["collect_nodes"] and devices:
        index = {}
        order = []
        aged_out = 0
        for ip, name in devices:
            kept, aged = collect_nodes(ctx, ip, name, index, order)
            aged_out += aged
        if subnets:
            attached = collect_ip_inventory(ctx, index, order)
            print("netdisco: attached {} addresses to located nodes from the IP inventory report".format(attached))

        for mac in order:
            report_asset(build_node_asset(ctx, index[mac]))
            node_count += 1

        print("netdisco: reported {} located nodes".format(node_count))
        if aged_out:
            print("netdisco: {} node sightings older than {} days were dropped".format(aged_out, ctx["max_age_days"]))
        if ctx["max_nodes"] and len(order) >= ctx["max_nodes"]:
            print("netdisco: node limit of {} reached; further nodes were not imported".format(ctx["max_nodes"]))

    if not device_count and not node_count:
        print("netdisco: no assets retrieved")
    return None

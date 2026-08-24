# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-openwrt",
    "name": "OpenWrt",
    "type": "inbound",
    "description": "Imports an OpenWrt router and every host it has observed - DHCP leases, ARP and neighbor hints, and associated wireless stations - over the ubus JSON-RPC endpoint.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "OpenWrt URL",
            "type": "url",
            "required": True,
            "placeholder": "https://192.168.1.1",
            "description": "Base URL of the OpenWrt web interface. The ubus endpoint is resolved as <url>/ubus, so include any path prefix the device is reverse-proxied under.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "OpenWrt user for the ubus session, normally root. The account's rpcd ACL groups decide which ubus objects this integration may read.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for that user. This is the same credential used to sign in to LuCI.",
        },
        {
            "key": "import_router",
            "label": "Import the router itself",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Emit an asset for the OpenWrt device, built from system.board, system.info, and its own network devices.",
        },
        {
            "key": "collect_leases",
            "label": "Collect DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read luci-rpc getDHCPLeases for DHCPv4 and DHCPv6 leases. Returns nothing on a device that is not the DHCP server for its network.",
        },
        {
            "key": "collect_host_hints",
            "label": "Collect host hints",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read luci-rpc getHostHints, OpenWrt's merged MAC-to-address-to-name view over DHCP leases, the neighbor table, and /etc/ethers. This is the widest source of observed hosts.",
        },
        {
            "key": "collect_wireless",
            "label": "Collect wireless stations",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Enumerate radios with luci-rpc getWirelessDevices, then read the association list of each wireless interface with iwinfo assoclist. One extra request per wireless interface.",
        },
        {
            "key": "max_hosts",
            "label": "Maximum hosts",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on the number of observed hosts imported in one run. 0 removes the cap.",
        },
        {
            "key": "session_timeout",
            "label": "Session timeout in seconds",
            "type": "int",
            "required": False,
            "default": 900,
            "min": 60,
            "max": 86400,
            "description": "Lifetime requested for the ubus session. OpenWrt's own default is 300 seconds, which a slow run can outlive.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", "post_json", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_text', 'dicts')
VENDOR = "openwrt"
ATTR_PREFIX = "openwrt"
ATTR_SEPARATOR = "_"

# ubus requires a session id on every call. The all-zero id is the documented
# "no session" value and is what session.login itself is addressed with; rpcd's
# unauthenticated ACL grants exactly session.login and session.access to it.
NULL_SESSION = "00000000000000000000000000000000"

MAX_WIRELESS_INTERFACES = 64

HEXDIGITS = "0123456789abcdef"

# Hostnames that identify nothing. "openwrt" is the factory default carried by
# every unflashed device, so it is treated as a placeholder for the same reason
# "localhost" is: with no stable foreign id, merging falls back to MAC, IP, and
# hostname, and a name shared by every OpenWrt in the estate would merge them.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none",
                     "null", "-", "*", "0.0.0.0", "openwrt", "lede"]

# Interfaces that are not the router's own attachment to the network. br-lan and
# its bridge members are deliberately NOT here: on OpenWrt the LAN bridge is
# where the device's real address and MAC live.
VIRTUAL_DEVICE_PREFIXES = [
    "lo", "docker", "veth", "ifb", "teql", "gre", "gretap", "erspan", "tunl",
    "sit", "ip6tnl", "ip_vti", "ip6_vti", "wg", "tun", "tap", "nordlynx",
    "zt", "tailscale", "ham", "dummy", "bonding_masters",
]

# ubus status codes worth naming. 0 is success; the rest arrive as result[0].
UBUS_STATUS = {
    1: "invalid command",
    2: "invalid argument",
    3: "method not found",
    4: "not found",
    5: "no data",
    6: "permission denied",
    7: "timeout",
    8: "not supported",
    9: "unknown error",
    10: "connection failed",
}
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    ubus returns MACs upper-cased ("44:65:0D:AA:11:22"), and getHostHints uses
    them as object KEYS, so a canonical form is needed before anything can be
    indexed or compared.

    net.normalize_mac is deliberately not used: it clears the locally
    administered bit to help cross-source matching, which is right for an
    interface and wrong for an identity. Every randomized client MAC sets that
    bit, so 3a:22:fb:66:77:88 and 38:22:fb:66:77:88 would normalize to one
    value and two real phones would collapse into one asset. A router's host
    table is full of randomized MACs. This canonicalisation is lossless.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    # An odd first octet is a multicast/broadcast destination, never an endpoint.
    if int(text[0:2], 16) % 2 == 1:
        return ""
    if text == "000000000000":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text
def _is_virtual_device(name):
    """Report whether a network device name is a virtual or container adapter.

    A homelab router commonly carries docker0, veth*, and VPN interfaces whose
    addresses say nothing about where the router sits on the network - and
    docker0 in particular has the same deterministic MAC on every host that
    runs Docker, so importing it correlates unrelated devices to each other.
    """
    lowered = as_text(name, join=",").strip().lower()
    if not lowered:
        return True
    for prefix in VIRTUAL_DEVICE_PREFIXES:
        if lowered == prefix:
            return True
        # Match "docker0" and "veth1a2b" but not a real interface that merely
        # starts with the same letters, such as "wgan0" against "wg".
        if lowered.startswith(prefix) and len(lowered) > len(prefix):
            tail = lowered[len(prefix)]
            if tail in "0123456789-_.":
                return True
    return False

def _ubus_endpoint(url):
    """Return <configured url>/ubus.

    get_url_base is deliberately not used. It keeps only the scheme and host,
    and an OpenWrt device behind a reverse proxy is commonly mounted under a
    path prefix, so dropping the path would post to the wrong place.
    """
    return as_text(url, join=",").strip().rstrip("/") + "/ubus"

def _scope(url):
    parsed = url_parse(url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return as_text(url, join=",").split("://")[-1].split("/")[0].split(":")[0]

def ubus_call(ctx, obj, method, params):
    """Make one ubus JSON-RPC call and return (payload, error).

    Four response shapes were observed against a real OpenWrt 24.10.8, and all
    four are handled here because Starlark has no exceptions and an unguarded
    subscript ends the run:

      success          {"result": [0, {...}]}
      empty payload    {"result": [0]}              <- NO second element
      bad credential   {"result": [6]}              <- a status, not an error
      denied / expired {"error": {"code": -32002, "message": "Access denied"}}
      unknown object   {"error": {"code": -32000, "message": "Object not found"}}
    """
    ctx["request_id"] += 1
    payload = {
        "jsonrpc": "2.0",
        "id": ctx["request_id"],
        "method": "call",
        "params": [ctx["session"], obj, method, params],
    }
    data, err = post_json(ctx["endpoint"], json=payload, **ctx["http_options"])
    if err:
        return None, "transport: " + as_text(err, join=",")
    if type(data) != "dict":
        return None, "unexpected response body"

    error = data.get("error")
    if type(error) == "dict":
        code = as_text(error.get("code"), join=",")
        message = as_text(error.get("message"), join=",")
        if code == "-32002":
            return None, "access denied (-32002): the session has expired or the account's rpcd ACL does not grant {}.{}".format(obj, method)
        if code == "-32000":
            return None, "object not found (-32000): {} is not registered on this device".format(obj)
        return None, "ubus error {}: {}".format(code, message)

    result = data.get("result")
    if type(result) != "list" or len(result) == 0:
        return None, "unexpected result shape"

    status = result[0]
    if status != 0:
        name = UBUS_STATUS.get(status) or "status {}".format(status)
        return None, "ubus refused {}.{}: {}".format(obj, method, name)

    # A call that succeeds with an empty payload returns a ONE-element array.
    if len(result) < 2:
        return {}, None
    body = result[1]
    if type(body) != "dict":
        return {}, None
    return body, None

def login(ctx, username, password, timeout):
    """Exchange a username and password for a ubus session id."""
    ctx["session"] = NULL_SESSION
    payload, err = ubus_call(ctx, "session", "login", {
        "username": username,
        "password": password,
        "timeout": timeout,
    })
    if err:
        print("openwrt: login failed: " + err)
        return False
    session = as_text(payload.get("ubus_rpc_session"), join=",").strip()
    if not session:
        print("openwrt: login returned no session id")
        return False
    ctx["session"] = session

    # The login reply carries the ACL set this session was granted. Reading it
    # once turns an otherwise silent "access denied" later in the run into an
    # actionable message naming the object the account cannot reach.
    granted = {}
    acls = payload.get("acls")
    if type(acls) == "dict" and type(acls.get("ubus")) == "dict":
        granted = acls.get("ubus")
    ctx["granted"] = granted
    return True

def permitted(ctx, obj, method):
    """Report whether the session's ACLs list this object and method.

    rpcd expresses wildcard grants two ways, and both must be honored: a "*"
    object key covers every object (a login granted only the superuser ACL
    group returns exactly {"*": ["*"]}), and a "*" entry in a method list
    covers every method on that object.

    Absent ACL data this returns True, so an unusual rpcd configuration degrades
    to trying the call rather than refusing to.
    """
    granted = ctx.get("granted")
    if type(granted) != "dict" or not granted:
        return True
    for key in [obj, "*"]:
        methods = granted.get(key)
        if type(methods) != "list":
            continue
        if "*" in methods or method in methods:
            return True
    return False

def call_guarded(ctx, obj, method, params, why):
    """Call an object, skipping it with an explanation when the ACL forbids it.

    A denial is a capability gap, not a per-record skip: it is reported once
    per method, however many calls that method would have received.
    """
    if not permitted(ctx, obj, method):
        key = obj + "." + method
        if key not in ctx["acl_denied"]:
            ctx["acl_denied"][key] = True
            print("openwrt: {} unavailable: the account's rpcd ACL does not grant {}".format(
                why, key))
        return None
    payload, err = ubus_call(ctx, obj, method, params)
    if err:
        print("openwrt: {} failed: {}".format(obj + "." + method, err))
        return None
    return payload

def touch(index, order, ctx, mac):
    """Return the accumulator for one observed MAC, creating it if needed."""
    if mac in index:
        return index[mac]
    if ctx["max_hosts"] and len(order) >= ctx["max_hosts"]:
        return None
    record = {
        "mac": mac,
        "ips": [],
        "hostnames": [],
        "sources": [],
        "lease": {},
        "wireless": {},
    }
    index[mac] = record
    order.append(mac)
    return record

def add_source(record, source):
    if source not in record["sources"]:
        record["sources"].append(source)

def collect_host_hints(ctx, index, order):
    """Fold luci-rpc getHostHints into the MAC index.

    The payload is an object KEYED BY UPPER-CASE MAC, each value carrying
    {"ipaddrs": [...], "ip6addrs": [...]} and an optional "name". It is
    OpenWrt's own merge of the DHCP lease file, the kernel neighbor table, and
    /etc/ethers, which makes it the widest single view of what the router has
    seen - including statically addressed hosts that never took a lease.
    """
    payload = call_guarded(ctx, "luci-rpc", "getHostHints", {}, "host hints")
    if payload == None:
        return 0
    added = 0
    for raw_mac in payload:
        hint = payload[raw_mac]
        if type(hint) != "dict":
            continue
        mac = _mac_key(raw_mac)
        if not mac or mac in ctx["router_macs"]:
            continue
        record = touch(index, order, ctx, mac)
        if record == None:
            continue
        add_source(record, "host-hints")
        for key in ["ipaddrs", "ip6addrs"]:
            values = hint.get(key)
            if type(values) != "list":
                continue
            for value in values:
                address = routable_ip(value)
                if address and address not in record["ips"]:
                    record["ips"].append(address)
        name = _hostname(hint.get("name"))
        if name and name not in record["hostnames"]:
            record["hostnames"].append(name)
        added += 1
    return added

def collect_leases(ctx, index, order):
    """Fold luci-rpc getDHCPLeases into the MAC index.

    family is a REQUIRED integer argument - calling this method without it
    fails with ubus status 4 (not found), which is easily mistaken for the
    method being absent. 0 asks for both families and yields dhcp_leases plus
    dhcp6_leases.

    Lease fields observed: expires, hostname (ABSENT when dnsmasq recorded "*"),
    macaddr (upper case), duid (the client id, absent when unset), ipaddr. A
    DHCPv6 lease carries ip6addr / ip6addrs and duid rather than a macaddr.
    """
    payload = call_guarded(ctx, "luci-rpc", "getDHCPLeases", {"family": 0}, "DHCP leases")
    if payload == None:
        return 0
    added = 0
    for key in ["dhcp_leases", "dhcp6_leases"]:
        for lease in dicts(payload.get(key)):
            mac = _mac_key(lease.get("macaddr"))
            if not mac or mac in ctx["router_macs"]:
                continue
            record = touch(index, order, ctx, mac)
            if record == None:
                continue
            add_source(record, "dhcpv6-lease" if key == "dhcp6_leases" else "dhcp-lease")
            addresses = [lease.get("ipaddr"), lease.get("ip6addr")]
            if type(lease.get("ip6addrs")) == "list":
                addresses = addresses + lease.get("ip6addrs")
            for value in addresses:
                address = routable_ip(value)
                if address and address not in record["ips"]:
                    record["ips"].append(address)
            name = _hostname(lease.get("hostname"))
            if name and name not in record["hostnames"]:
                record["hostnames"].append(name)
            # expires is SECONDS REMAINING, not a timestamp. It is kept as an
            # attribute and never converted to a time: now + expires is in the
            # future, and a future timestamp makes the platform reject the
            # entire asset record rather than just the field. Lease detail is
            # keyed per family so a dual-stack client holding both a DHCPv4
            # and a DHCPv6 lease keeps both.
            family = "ipv6" if key == "dhcp6_leases" else "ipv4"
            detail = record["lease"]
            families = detail.get("family")
            if type(families) != "list":
                families = []
            if family not in families:
                families.append(family)
            detail["family"] = families
            detail[family + "_expires_seconds"] = lease.get("expires")
            detail[family + "_duid"] = lease.get("duid")
            added += 1
    return added

def wireless_interfaces(ctx):
    """Return [(ifname, ssid, radio)] for every configured wireless interface.

    getWirelessDevices is keyed by radio ("radio0"), and each radio carries an
    "interfaces" list whose entries hold the runtime ifname and the UCI config
    section with the SSID. iwinfo.devices would be the more direct enumeration
    but is NOT in the default LuCI ACL set, whereas getWirelessDevices is.
    """
    payload = call_guarded(ctx, "luci-rpc", "getWirelessDevices", {}, "wireless devices")
    if payload == None:
        return []
    found = []
    for radio in payload:
        entry = payload[radio]
        if type(entry) != "dict":
            continue
        for iface in dicts(entry.get("interfaces")):
            name = as_text(iface.get("ifname"), join=",").strip()
            if not name:
                continue
            ssid = as_text(iface.get("ssid"), join=",").strip()
            config = iface.get("config")
            if not ssid and type(config) == "dict":
                ssid = as_text(config.get("ssid"), join=",").strip()
            if len(found) >= MAX_WIRELESS_INTERFACES:
                print("openwrt: more than {} wireless interfaces; the rest are not read".format(
                    MAX_WIRELESS_INTERFACES))
                return found
            found.append((name, ssid, as_text(radio, join=",")))
    return found

def collect_wireless(ctx, index, order):
    """Fold each wireless interface's association list into the MAC index."""
    interfaces = wireless_interfaces(ctx)
    if not interfaces:
        return 0, 0
    added = 0
    for ifname, ssid, radio in interfaces:
        payload = call_guarded(ctx, "iwinfo", "assoclist", {"device": ifname},
                               "wireless stations on " + ifname)
        if payload == None:
            continue
        for station in dicts(payload.get("results")):
            mac = _mac_key(station.get("mac"))
            if not mac or mac in ctx["router_macs"]:
                continue
            record = touch(index, order, ctx, mac)
            if record == None:
                continue
            add_source(record, "wireless")
            record["wireless"] = {
                "ifname": ifname,
                "ssid": ssid,
                "radio": radio,
                "signal_dbm": station.get("signal"),
                "noise_dbm": station.get("noise"),
                "inactive_ms": station.get("inactive"),
                "connected_time_s": station.get("connected_time"),
            }
            added += 1
    return added, len(interfaces)

def router_devices(ctx):
    """Return (network_interfaces, own_macs, device_attributes) for the router.

    getNetworkDevices is keyed by device name; each value carries mac (upper
    case), ipaddrs [{address, netmask, broadcast}], ip6addrs, devtype, wireless,
    up, mtu, and a flags object including "loopback".
    """
    payload = call_guarded(ctx, "luci-rpc", "getNetworkDevices", {}, "router interfaces")
    if payload == None:
        return [], [], {}
    netifs = []
    own = []
    summary = []
    for name in payload:
        device = payload[name]
        if type(device) != "dict":
            continue
        flags = device.get("flags")
        if type(flags) == "dict" and flags.get("loopback") == True:
            continue
        if _is_virtual_device(name):
            continue
        mac = _mac_key(device.get("mac"))
        addresses = []
        for key in ["ipaddrs", "ip6addrs"]:
            entries = device.get(key)
            if type(entries) != "list":
                continue
            for entry in entries:
                value = entry.get("address") if type(entry) == "dict" else entry
                address = routable_ip(value)
                if address and address not in addresses:
                    addresses.append(address)
        if not mac and not addresses:
            continue
        if mac and mac not in own:
            own.append(mac)
        nic = network_interface(mac=mac, ips=addresses)
        # network_interface returns None when nothing usable survives, and a
        # networkInterfaces list containing None aborts the run.
        if nic:
            netifs.append(nic)
        summary.append("{}={}".format(name, mac or ",".join(addresses)))
    return netifs, own, {"devices": summary}

def build_router_asset(ctx, board, info, netifs, device_attrs):
    release = board.get("release")
    if type(release) != "dict":
        release = {}
    memory = info.get("memory")
    if type(memory) != "dict":
        memory = {}

    hostname = _hostname(board.get("hostname"))
    if not hostname and as_text(board.get("hostname"), join=",").strip():
        print("openwrt: the router reports the factory-default hostname " +
              "'{}', which every unflashed OpenWrt shares; it is not imported as a hostname ".format(
                  as_text(board.get("hostname"), join=",").strip()) +
              "so two devices cannot merge on it. The router still correlates on its MACs and addresses.")

    if not hostname and not netifs:
        print("openwrt: the router has no usable hostname, address, or MAC; not importing it")
        return None

    attrs = {
        "board_name": board.get("board_name"),
        "model": board.get("model"),
        "system": board.get("system"),
        "kernel": board.get("kernel"),
        "reported_hostname": board.get("hostname"),
        "distribution": release.get("distribution"),
        "version": release.get("version"),
        "revision": release.get("revision"),
        "target": release.get("target"),
        "description": release.get("description"),
        "builddate_raw": release.get("builddate"),
        "uptime_seconds": info.get("uptime"),
        "localtime_raw": info.get("localtime"),
        "memory_total": memory.get("total"),
        "memory_free": memory.get("free"),
        "memory_available": memory.get("available"),
        "interfaces": device_attrs.get("devices"),
        "host": ctx["scope"],
    }

    params = {
        # OpenWrt publishes no serial number and no machine id: system.board
        # returns a board name and a model string, both shared by every unit of
        # that hardware. The id is therefore scoped on the configured host and
        # is deliberately inert - see the README's Asset identity section.
        "id": "{}:{}:router".format(VENDOR, ctx["scope"]),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": netifs,
        "deviceType": "Router",
        "tags": [VENDOR, "openwrt-router"],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    distribution = as_text(release.get("distribution"), join=",").strip()
    params["os"] = distribution if distribution else "OpenWrt"
    version = as_text(release.get("version"), join=",").strip()
    if version:
        params["osVersion"] = version
    model = as_text(board.get("model"), join=",").strip()
    if model:
        params["model"] = model
    return ImportAsset(**params)

def build_host_asset(ctx, record):
    mac = record["mac"]
    nic = network_interface(mac=mac, ips=record["ips"])

    attrs = {
        "host": ctx["scope"],
        "mac": mac,
        "addresses": record["ips"],
        "observed_by": record["sources"],
        "router": ctx["router_name"],
    }
    for key in record["lease"]:
        attrs["lease_" + key] = record["lease"][key]
    for key in record["wireless"]:
        attrs["wifi_" + key] = record["wireless"][key]

    tags = [VENDOR, "openwrt-host"]
    for source in record["sources"]:
        tags.append("openwrt-" + source)
    ssid = as_text(record["wireless"].get("ssid"), join=",").strip()
    if ssid:
        tags.append("ssid:" + ssid)

    return ImportAsset(
        # A host the router observed has no identifier but its MAC. It is
        # canonicalised losslessly and paired with no-id-match so it never
        # drives a merge; see the README.
        id="{}:{}:host:{}".format(VENDOR, ctx["scope"], mac),
        hostnames=record["hostnames"],
        networkInterfaces=[nic] if nic else [],
        tags=tags,
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )

def main(**kwargs):
    url = get_string(kwargs, "url", default="")
    endpoint = _ubus_endpoint(url)
    scope = _scope(url)
    if not scope or endpoint == "/ubus":
        print("openwrt: could not determine the device host from the configured URL")
        return None

    max_hosts = get_int(kwargs, "max_hosts", default=5000)
    ctx = {
        "endpoint": endpoint,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
        }),
        "session": NULL_SESSION,
        "granted": {},
        # rpcd ACL denials already reported, keyed by object.method. The same
        # denial recurs for every wireless interface, so it is announced once
        # per method rather than once per call.
        "acl_denied": {},
        "request_id": 0,
        "max_hosts": max_hosts if max_hosts > 0 else 0,
        "router_macs": [],
        "router_name": "",
    }

    if not login(ctx, get_string(kwargs, "username"), get_string(kwargs, "password"),
                 get_int(kwargs, "session_timeout", default=900)):
        print("openwrt: no session, nothing collected. Confirm the account can sign in to LuCI, " +
              "and that uhttpd is serving the ubus endpoint (uci get uhttpd.main.ubus_prefix).")
        return None

    board = call_guarded(ctx, "system", "board", {}, "system board") or {}
    info = call_guarded(ctx, "system", "info", {}, "system info") or {}
    ctx["router_name"] = as_text(board.get("hostname"), join=",").strip()

    netifs, own_macs, device_attrs = router_devices(ctx)
    ctx["router_macs"] = own_macs

    router_count = 0
    if get_bool(kwargs, "import_router", default=True):
        asset = build_router_asset(ctx, board, info, netifs, device_attrs)
        if asset:
            report_assets(asset)
            router_count = 1

    index = {}
    order = []
    if get_bool(kwargs, "collect_host_hints", default=True):
        hinted = collect_host_hints(ctx, index, order)
        print("openwrt: host hints contributed {} entries".format(hinted))
    if get_bool(kwargs, "collect_leases", default=True):
        leased = collect_leases(ctx, index, order)
        print("openwrt: DHCP leases contributed {} entries".format(leased))
    if get_bool(kwargs, "collect_wireless", default=True):
        associated, radios = collect_wireless(ctx, index, order)
        print("openwrt: {} wireless interfaces contributed {} associated stations".format(
            radios, associated))

    host_count = 0
    for mac in order:
        report_asset(build_host_asset(ctx, index[mac]))
        host_count += 1

    if ctx["max_hosts"] and len(order) >= ctx["max_hosts"]:
        print("openwrt: host limit of {} reached; further hosts were not imported".format(
            ctx["max_hosts"]))
    print("openwrt: reported {} router and {} observed hosts".format(router_count, host_count))
    if not router_count and not host_count:
        print("openwrt: no assets retrieved")
    return None

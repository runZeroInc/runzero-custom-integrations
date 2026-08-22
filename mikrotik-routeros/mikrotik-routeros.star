# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-mikrotik-routeros",
    "name": "MikroTik RouterOS",
    "type": "inbound",
    "description": "Imports a MikroTik router and the devices it has observed - ARP entries, DHCP leases, CDP/LLDP/MNDP neighbors, and associated wireless stations - over the RouterOS v7 REST API.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Three asset types, and the router splits into two of them at RUNTIME on
    # whether /system/routerboard yielded a serial. The script selects the type
    # per asset with ImportAsset(assetType=...); the policy for each lives here.
    #
    # no-type-break. The reason is the router pair: "router" and
    # "router-unkeyed" are the SAME device under two grades of identifier, not
    # two kinds of thing. The grade is not even a permanent property of the
    # hardware - it is whatever /system/routerboard answered on this run, and
    # that menu can fail to read or come back empty on a router that answered it
    # last time - so a device can move between the two types without anything
    # about it changing. A type boundary must not be a reason to refuse the
    # merge back.
    #
    # This is necessary but NOT sufficient: the grade also decides the id
    # (mikrotik:routerboard:<serial> versus mikrotik:<host>:router), and two
    # foreign ids from one custom integration cannot share an asset whatever the
    # break flags say, so that flip still forks and is reconciled in runZero.
    #
    # Relaxing type-break is safe for the router/host pair because those two
    # populations are disjoint by construction rather than by convention: the
    # router's own interface MACs are collected first into ctx["router_macs"],
    # and the ARP, lease, neighbor, and wireless readers all skip any row whose
    # MAC is in that set, so the router can never also appear as an observed
    # host.
    #
    # Each type below carries its COMPLETE policy rather than stating only what
    # differs from the integration-wide value. Levels layer, and a broader level
    # survives wherever the type-specific one is silent, so splitting one kind's
    # flags across the two levels would silently leak them onto the other kind.
    "matchBehavior": "no-type-break",
    "assetTypeBehavior": {
        # A RouterBOARD serial is a globally unique hardware identifier, so it
        # is used as a real foreign id and IS allowed to drive merges. The
        # router's own addressing must not then veto the merge onto its own
        # asset.
        "router": "no-mac-break no-ip-break no-name-break",
        # CHR and x86 have no /system/routerboard menu at all. There is nothing
        # stable to key on, so the id falls back to the configured host and is
        # made inert: it must neither drive nor block a merge, and correlation
        # falls back to the interface MACs, the addresses, and the identity name.
        "router-unkeyed": "no-id-match no-id-break",
        # An observed device has no identifier but its MAC. It is canonicalised
        # losslessly and paired with no-id-match so it never drives a merge: a
        # MAC that is reassigned, spoofed, or randomized must not pull a
        # different device onto an existing asset, and no break flag can veto a
        # foreign-id match once it happens.
        "host": "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "RouterOS URL",
            "type": "url",
            "required": True,
            "placeholder": "https://192.168.88.1",
            "description": "Base URL of the RouterOS device. The REST API is resolved as <url>/rest, so include any path prefix if the device is behind a reverse proxy.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "RouterOS user in a group holding the read and rest-api policies.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for that user. Sent as HTTP Basic on every request; RouterOS REST has no token or session concept.",
        },
        {
            "key": "import_router",
            "label": "Import the router itself",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Emit an asset for the RouterOS device, built from system/resource, system/routerboard, system/identity, interface, and ip/address.",
        },
        {
            "key": "collect_arp",
            "label": "Collect ARP entries",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /ip/arp. Entries with no MAC (an incomplete resolution) are skipped.",
        },
        {
            "key": "collect_dhcp_leases",
            "label": "Collect DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /ip/dhcp-server/lease. Returns an empty list on a router that serves no DHCP.",
        },
        {
            "key": "collect_neighbors",
            "label": "Collect discovery neighbors",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /ip/neighbor, the CDP, LLDP, and MNDP neighbor table. These records carry a platform, board, and software version, so they produce the best-described assets of any source here.",
        },
        {
            "key": "collect_wireless",
            "label": "Collect wireless stations",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read the wireless registration tables. Three different menus exist across RouterOS versions and wireless packages; each is probed and a missing one is skipped.",
        },
        {
            "key": "bound_leases_only",
            "label": "Bound DHCP leases only",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import only leases in the bound state. RouterOS retains waiting and offered leases with their last known hostname, which are still devices the router has seen, so this is off by default.",
        },
        {
            "key": "max_hosts",
            "label": "Maximum hosts",
            "type": "int",
            "required": False,
            "default": 10000,
            "min": 0,
            "description": "Cap on the number of observed devices imported in one run. 0 removes the cap. RouterOS REST has no pagination, so this is the only bound on a large ARP table.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", "basic", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", "from_timestamp")

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "mikrotik"
ATTR_PREFIX = "mikrotik"
ATTR_SEPARATOR = "_"

HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null",
                     "-", "*", "0.0.0.0", "mikrotik", "routeros"]

# RouterOS interface types that are not a physical attachment to a network. A
# tunnel endpoint's synthesized MAC and its overlay address say nothing about
# where the router sits, and several of these share a well-known MAC across
# every device that runs them.
VIRTUAL_INTERFACE_TYPES = [
    "gre-tunnel", "gre6-tunnel", "ipip-tunnel", "ipipv6-tunnel", "eoip", "eoipv6",
    "vpls", "vrrp", "6to4-tunnel", "ipv6-tunnel", "wg", "wireguard", "l2tp-in",
    "l2tp-out", "pptp-in", "pptp-out", "sstp-in", "sstp-out", "ovpn-in", "ovpn-out",
    "pppoe-in", "pppoe-out", "ppp-out", "ppp-in", "zerotier", "traffic-eng", "loopback",
]

# The three registration tables, in probe order. RouterOS 7.13 moved legacy
# wireless and CAPsMAN v1 out of the base bundle into a separate package that
# CONFLICTS with the wifi-qcom drivers, so a given router has at most two of
# these and commonly only one. Each names its signal field differently.
WIRELESS_TABLES = [
    ("/interface/wifi/registration-table", "signal", "wifi"),
    ("/interface/wireless/registration-table", "signal-strength", "wireless"),
    ("/caps-man/registration-table", "rx-signal", "caps-man"),
]

# system-caps on a discovery neighbor is an LLDP capability list. Only the
# unambiguous ones are promoted to a device type; the raw value is always kept.
NEIGHBOR_CAP_TYPES = [
    ("wlan-ap", "Access Point"),
    ("telephone", "IP Phone"),
    ("router", "Router"),
    ("bridge", "Switch"),
]

DURATION_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
def _pick(record, keys):
    """Return the first non-empty value among keys.

    RouterOS OMITS a property entirely when it is unset rather than sending an
    empty value, and .get(k, default) returns None when the key exists holding
    a null, so every read goes through here or through `or`.
    """
    for key in keys:
        value = as_text(record.get(key), join=",").strip()
        if value:
            return value
    return ""


def _flag(record, key):
    """Read a RouterOS boolean.

    Every value in a REST reply is a JSON STRING, including booleans and
    numbers - "disabled":"false" is a non-empty and therefore truthy string.
    Testing truthiness the obvious way inverts the meaning of every flag.
    """
    return as_text(record.get(key), join=",").strip().lower() == "true"


def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    RouterOS returns MACs upper-cased. net.normalize_mac is deliberately not
    used: it clears the locally administered bit, and every randomized client
    MAC sets that bit, so two distinct phones on the guest SSID would collapse
    into one asset. Correct for an interface, wrong for an identity. This
    canonicalisation is lossless.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
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
def _duration_seconds(value):
    """Parse a RouterOS duration such as 7w6d9h34m or 2d23h40m10s into seconds.

    Returns -1 when the value is not a duration. RouterOS omits any component
    that is zero, so no unit can be assumed present, and sub-second components
    (ms, us) appear on some menus and are ignored rather than misread as
    minutes. time.parse_duration is not used: Go durations have no week or day
    unit, so it would reject the most common forms outright.
    """
    text = as_text(value, join=",").strip().lower()
    if not text or len(text) > 32:
        return -1
    total = 0
    number = ""
    index = 0
    for index in range(len(text)):
        char = text[index]
        if char in DIGITS:
            number += char
            continue
        if not number:
            return -1
        # "ms" and "us" are sub-second and are dropped. The trailing "s" of
        # each is consumed by this branch on the next iteration, which is
        # harmless because `number` is empty by then and the unit is skipped.
        if char in ["m", "u"] and index + 1 < len(text) and text[index + 1] == "s":
            number = ""
            continue
        if char == "s" and not number:
            continue
        seconds = DURATION_UNITS.get(char)
        if seconds == None:
            return -1
        total += int(number) * seconds
        number = ""
    if number:
        return -1
    return total


def _seen_time(ctx, value):
    """Convert a RouterOS 'time since' duration into an absolute timestamp.

    RouterOS reports last-seen, uptime, and last-activity as durations relative
    to the moment of the request, never as wall-clock times. Subtracting from
    now therefore always yields a time in the PAST, which matters because the
    platform rejects the entire asset record - not the field - on a future
    timestamp. from_timestamp requires an int, not a float.
    """
    seconds = _duration_seconds(value)
    if seconds < 0:
        return None
    stamp = ctx["now_unix"] - seconds
    if stamp <= 0 or stamp > ctx["now_unix"]:
        return None
    return from_timestamp(int(stamp))


def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately not used: it keeps only the scheme and host,
    and a router published through a reverse proxy is commonly mounted under a
    path prefix, so dropping the path would send every request to the wrong
    place.
    """
    return as_text(url, join=",").strip().rstrip("/")


def _scope(url):
    parsed = url_parse(url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return as_text(url, join=",").split("://")[-1].split("/")[0].split(":")[0]


def rest_get(ctx, path, required):
    """GET one RouterOS menu and return its rows, or None when unavailable.

    Every RouterOS REST read returns a JSON ARRAY, including single-record
    menus such as /system/resource. A menu belonging to a package that is not
    installed does NOT return an empty array or a 404 - it returns a 4xx whose
    detail carries the console error "no such command or directory (...)". An
    account without the right policy gets a 500, not a 403. Both are decoded
    here into an actionable message, and neither ends the run.
    """
    url = ctx["base"] + "/rest" + path
    data, err = get_json(url, **ctx["http_options"])
    if err:
        lowered = as_text(err, join=",").lower()
        if "no such command" in lowered or "no such item" in lowered:
            if required:
                print("mikrotik: {} is not available on this device (the package that provides it is not installed)".format(path))
            return None
        if "not enough permissions" in lowered:
            # .format binds tighter than +, so the whole message is built first.
            print(("mikrotik: {} refused: the account's group is missing a policy. " +
                   "A read-only user needs at least: " +
                   "/user group add name=runzero-ro policy=read,rest-api,api").format(path))
            return None
        if "status 401" in lowered:
            print("mikrotik: {} refused with 401: check the username and password, and that the user is permitted from this source address".format(path))
            return None
        print("mikrotik: {} failed: {}".format(path, err))
        return None
    if type(data) != "list":
        # A non-array 2xx body is either an error envelope or a login page.
        print("mikrotik: {} returned an unexpected shape; treating the menu as unavailable".format(path))
        return None
    return dicts(data)


def touch(index, order, ctx, mac):
    if mac in index:
        return index[mac]
    if ctx["max_hosts"] and len(order) >= ctx["max_hosts"]:
        return None
    record = {
        "mac": mac,
        "ips": [],
        "hostnames": [],
        "sources": [],
        "attrs": {},
        "manufacturer": "",
        "model": "",
        "os_version": "",
        "device_type": "",
        "last_seen": None,
        "ssid": "",
    }
    index[mac] = record
    order.append(mac)
    return record


def add_source(record, source):
    if source not in record["sources"]:
        record["sources"].append(source)


def add_ip(record, value):
    address = routable_ip(value)
    if address and address not in record["ips"]:
        record["ips"].append(address)


def add_name(record, value):
    name = _hostname(value)
    if name and name not in record["hostnames"]:
        record["hostnames"].append(name)


def note(record, key, value):
    text = as_text(value, join=",").strip()
    if text:
        record["attrs"][key] = text


def collect_arp(ctx, index, order):
    """Fold /ip/arp into the MAC index.

    An entry with complete=false has resolved no MAC and is a failed lookup,
    not a device, so it is skipped rather than imported as an address with no
    correlator.
    """
    rows = rest_get(ctx, "/ip/arp", False)
    if rows == None:
        return 0, 0
    kept = 0
    incomplete = 0
    for row in rows:
        mac = _mac_key(row.get("mac-address"))
        if not mac:
            incomplete += 1
            continue
        if mac in ctx["router_macs"]:
            continue
        record = touch(index, order, ctx, mac)
        if record == None:
            continue
        add_source(record, "arp")
        add_ip(record, row.get("address"))
        note(record, "arp_interface", row.get("interface"))
        note(record, "arp_status", row.get("status"))
        note(record, "arp_dynamic", row.get("dynamic"))
        # RouterOS is inconsistent about the case of this key between the
        # console namespace and the wire, so both spellings are read.
        note(record, "arp_from_dhcp", _pick(row, ["dhcp", "DHCP"]))
        note(record, "arp_published", row.get("published"))
        kept += 1
    return kept, incomplete


def collect_leases(ctx, index, order):
    """Fold /ip/dhcp-server/lease into the MAC index.

    The active-* properties exist only while a lease is bound and are omitted
    entirely otherwise, so active-address is the liveness test. host-name has
    no active- variant and persists on a stale lease, which is exactly why a
    waiting lease is still worth importing.
    """
    rows = rest_get(ctx, "/ip/dhcp-server/lease", False)
    if rows == None:
        return 0, 0
    kept = 0
    filtered = 0
    for row in rows:
        status = as_text(row.get("status"), join=",").strip().lower()
        if ctx["bound_leases_only"] and status != "bound":
            filtered += 1
            continue
        mac = _mac_key(_pick(row, ["active-mac-address", "mac-address"]))
        if not mac or mac in ctx["router_macs"]:
            continue
        record = touch(index, order, ctx, mac)
        if record == None:
            continue
        add_source(record, "dhcp-lease")
        add_ip(record, _pick(row, ["active-address", "address"]))
        add_name(record, row.get("host-name"))
        note(record, "lease_status", status)
        note(record, "lease_server", _pick(row, ["active-server", "server"]))
        note(record, "lease_dynamic", row.get("dynamic"))
        note(record, "lease_blocked", row.get("blocked"))
        note(record, "lease_comment", row.get("comment"))
        note(record, "lease_client_id", _pick(row, ["active-client-id", "client-id"]))
        note(record, "lease_class_id", row.get("class-id"))
        note(record, "lease_last_seen_raw", row.get("last-seen"))
        note(record, "lease_expires_after_raw", row.get("expires-after"))
        note(record, "lease_agent_circuit_id", row.get("agent-circuit-id"))
        note(record, "lease_agent_remote_id", row.get("agent-remote-id"))
        seen = _seen_time(ctx, row.get("last-seen"))
        if seen and (record["last_seen"] == None or seen.unix > record["last_seen"].unix):
            record["last_seen"] = seen
        kept += 1
    return kept, filtered


def collect_neighbors(ctx, index, order):
    """Fold /ip/neighbor - the CDP, LLDP, and MNDP table - into the MAC index.

    These are the best-described records the router holds: a neighbor announces
    its own identity, platform, board, and software version, so the resulting
    asset carries a manufacturer, model, and OS version rather than only an
    address.
    """
    rows = rest_get(ctx, "/ip/neighbor", False)
    if rows == None:
        return 0, 0
    kept = 0
    skipped = 0
    for row in rows:
        mac = _mac_key(row.get("mac-address"))
        if not mac:
            skipped += 1
            continue
        if mac in ctx["router_macs"]:
            continue
        record = touch(index, order, ctx, mac)
        if record == None:
            continue
        add_source(record, "neighbor")
        for key in ["address", "address4", "address6"]:
            add_ip(record, row.get(key))
        add_name(record, row.get("identity"))

        platform = as_text(row.get("platform"), join=",").strip()
        if platform and not record["manufacturer"]:
            record["manufacturer"] = platform
        board = as_text(row.get("board"), join=",").strip()
        if board and not record["model"]:
            record["model"] = board
        version = as_text(row.get("version"), join=",").strip()
        if version and not record["os_version"]:
            record["os_version"] = version

        caps = as_text(_pick(row, ["system-caps-enabled", "system-caps"]), join=",").lower()
        if caps and not record["device_type"]:
            for token, kind in NEIGHBOR_CAP_TYPES:
                if token in caps:
                    record["device_type"] = kind
                    break

        note(record, "neighbor_identity", row.get("identity"))
        note(record, "neighbor_platform", platform)
        note(record, "neighbor_board", board)
        note(record, "neighbor_version", version)
        note(record, "neighbor_interface", _pick(row, ["interface", "interface-name"]))
        note(record, "neighbor_remote_port", row.get("interface-name"))
        note(record, "neighbor_discovered_by", row.get("discovered-by"))
        note(record, "neighbor_system_caps", _pick(row, ["system-caps-enabled", "system-caps"]))
        note(record, "neighbor_system_description", row.get("system-description"))
        note(record, "neighbor_software_id", row.get("software-id"))
        note(record, "neighbor_uptime_raw", row.get("uptime"))
        kept += 1
    return kept, skipped


def wireless_ssids(ctx):
    """Map legacy wireless interface name to SSID.

    /interface/wireless/registration-table has NO ssid property - the newer
    /interface/wifi and /caps-man tables do. The SSID has to be joined from the
    interface configuration, so this is fetched only when that legacy table
    actually returned rows.
    """
    rows = rest_get(ctx, "/interface/wireless", False)
    if rows == None:
        return {}
    ssids = {}
    for row in rows:
        name = as_text(row.get("name"), join=",").strip()
        ssid = as_text(row.get("ssid"), join=",").strip()
        if name and ssid:
            ssids[name] = ssid
    return ssids


def collect_wireless(ctx, index, order):
    """Fold whichever registration tables this router has into the MAC index."""
    kept = 0
    tables = 0
    legacy_ssids = None
    for path, signal_key, flavor in WIRELESS_TABLES:
        rows = rest_get(ctx, path, False)
        if rows == None:
            continue
        tables += 1
        if not rows:
            continue
        if flavor == "wireless" and legacy_ssids == None:
            legacy_ssids = wireless_ssids(ctx)
        for row in rows:
            mac = _mac_key(row.get("mac-address"))
            if not mac or mac in ctx["router_macs"]:
                continue
            record = touch(index, order, ctx, mac)
            if record == None:
                continue
            add_source(record, "wireless")
            interface = _pick(row, ["interface", "ap"])
            ssid = as_text(row.get("ssid"), join=",").strip()
            if not ssid and flavor == "wireless" and legacy_ssids:
                ssid = as_text(legacy_ssids.get(interface), join=",").strip()
            if ssid and not record["ssid"]:
                record["ssid"] = ssid
            add_ip(record, row.get("last-ip"))
            note(record, "wifi_flavor", flavor)
            note(record, "wifi_interface", interface)
            note(record, "wifi_ssid", ssid)
            note(record, "wifi_signal_dbm", row.get(signal_key))
            note(record, "wifi_band", row.get("band"))
            note(record, "wifi_tx_rate", row.get("tx-rate"))
            note(record, "wifi_rx_rate", row.get("rx-rate"))
            note(record, "wifi_uptime_raw", row.get("uptime"))
            note(record, "wifi_last_activity_raw", row.get("last-activity"))
            note(record, "wifi_authorized", row.get("authorized"))
            note(record, "wifi_vlan_id", row.get("vlan-id"))
            note(record, "wifi_radio_name", row.get("radio-name"))
            seen = _seen_time(ctx, row.get("last-activity"))
            if seen and (record["last_seen"] == None or seen.unix > record["last_seen"].unix):
                record["last_seen"] = seen
            kept += 1
    return kept, tables


def router_interfaces(ctx):
    """Return (network_interfaces, own_macs, summary) for the router itself.

    /interface carries the MACs and /ip/address carries the addresses, joined
    on the interface name. Tunnel and VRRP interfaces are excluded by type: a
    VRRP address is shared with the peer router by design, and a tunnel's
    synthesized MAC identifies the tunnel rather than the device.
    """
    interfaces = rest_get(ctx, "/interface", True)
    addresses = rest_get(ctx, "/ip/address", False)

    by_interface = {}
    if addresses != None:
        for row in addresses:
            if _flag(row, "disabled") or _flag(row, "invalid"):
                continue
            name = _pick(row, ["actual-interface", "interface"])
            address = routable_ip(row.get("address"))
            if not name or not address:
                continue
            if name not in by_interface:
                by_interface[name] = []
            if address not in by_interface[name]:
                by_interface[name].append(address)

    netifs = []
    own = []
    summary = []
    if interfaces == None:
        return netifs, own, summary

    for row in interfaces:
        name = as_text(row.get("name"), join=",").strip()
        kind = as_text(row.get("type"), join=",").strip().lower()
        if kind in VIRTUAL_INTERFACE_TYPES:
            continue
        mac = _mac_key(row.get("mac-address"))
        ips = by_interface.get(name) or []
        if not mac and not ips:
            continue
        if mac and mac not in own:
            own.append(mac)
        nic = network_interface(mac=mac, ips=ips)
        # network_interface returns None when nothing usable survives, and a
        # networkInterfaces list containing None aborts the run.
        if nic:
            netifs.append(nic)
        summary.append("{}[{}]={}".format(name, kind, mac or ",".join(ips)))
    return netifs, own, summary


def build_router_asset(ctx, resource, routerboard, identity, netifs, summary):
    serial = as_text(routerboard.get("serial-number"), join=",").strip()
    hostname = _hostname(identity.get("name"))
    board = _pick(resource, ["board-name", "platform"])
    model = _pick(routerboard, ["model", "board-name"]) or board

    if not hostname and not netifs:
        print("mikrotik: the router has no usable hostname, address, or MAC; not importing it")
        return None

    attrs = {
        "host": ctx["scope"],
        "identity": identity.get("name"),
        "board_name": resource.get("board-name"),
        "platform": resource.get("platform"),
        "architecture": resource.get("architecture-name"),
        "cpu": resource.get("cpu"),
        "cpu_count": resource.get("cpu-count"),
        "cpu_frequency_mhz": resource.get("cpu-frequency"),
        "total_memory": resource.get("total-memory"),
        "free_memory": resource.get("free-memory"),
        "total_hdd_space": resource.get("total-hdd-space"),
        "uptime_raw": resource.get("uptime"),
        "build_time": resource.get("build-time"),
        "factory_software": resource.get("factory-software"),
        "routerboard": routerboard.get("routerboard"),
        "routerboard_model": routerboard.get("model"),
        "routerboard_revision": routerboard.get("revision"),
        "serial_number": serial,
        "firmware_type": routerboard.get("firmware-type"),
        "current_firmware": routerboard.get("current-firmware"),
        "upgrade_firmware": routerboard.get("upgrade-firmware"),
        "interfaces": summary,
    }

    tags = [VENDOR, "mikrotik-router"]
    if serial:
        tags.append("serial:" + serial)

    # The runtime condition selects the asset type, and the type selects the
    # merge policy; CONFIG["assetTypeBehavior"] carries the reasoning for both
    # grades, and CONFIG["matchBehavior"] explains why the two may still merge
    # with each other.
    if serial:
        asset_id = "{}:routerboard:{}".format(VENDOR, serial)
        asset_type = "router"
    else:
        asset_id = "{}:{}:router".format(VENDOR, ctx["scope"])
        asset_type = "router-unkeyed"

    params = {
        "id": asset_id,
        "assetType": asset_type,
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": netifs,
        "deviceType": "Router",
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        "manufacturer": "MikroTik",
        "os": "RouterOS",
    }
    version = as_text(resource.get("version"), join=",").strip()
    if version:
        params["osVersion"] = version
    if model:
        params["model"] = model

    asset = ImportAsset(**params)
    uptime = _seen_time(ctx, resource.get("uptime"))
    if uptime:
        # Uptime counts from boot, so now - uptime is the boot time. It is the
        # only absolute lifecycle moment RouterOS exposes about itself.
        asset.firstSeenTS = uptime
    return asset


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
    for key in record["attrs"]:
        attrs[key] = record["attrs"][key]

    tags = [VENDOR, "mikrotik-host"]
    for source in record["sources"]:
        tags.append("mikrotik-" + source)
    if record["ssid"]:
        tags.append("ssid:" + record["ssid"])

    params = {
        # Keyed on the losslessly canonicalised MAC, the only identifier an
        # observed device has; see the "host" entry in
        # CONFIG["assetTypeBehavior"] for the merge policy that requires.
        "id": "{}:{}:host:{}".format(VENDOR, ctx["scope"], mac),
        "assetType": "host",
        "hostnames": record["hostnames"],
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if record["manufacturer"]:
        params["manufacturer"] = record["manufacturer"]
    if record["model"]:
        params["model"] = record["model"]
    if record["os_version"]:
        params["osVersion"] = record["os_version"]
    if record["device_type"]:
        params["deviceType"] = record["device_type"]

    asset = ImportAsset(**params)
    # The constructor accepts firstSeenTS but rejects lastSeenTS.
    if record["last_seen"]:
        asset.lastSeenTS = record["last_seen"]
    return asset


def one_row(rows):
    """RouterOS returns an array even for a single-record menu."""
    if rows == None or not rows:
        return {}
    return rows[0]


def main(**kwargs):
    base = _base(get_string(kwargs, "url", default=""))
    scope = _scope(base)
    if not base or not scope:
        print("mikrotik: could not determine the router host from the configured URL")
        return None

    max_hosts = get_int(kwargs, "max_hosts", default=10000)
    current = now()
    ctx = {
        "base": base,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
            "Authorization": basic(get_string(kwargs, "username"), get_string(kwargs, "password")),
        }),
        "now_unix": current.unix,
        "max_hosts": max_hosts if max_hosts > 0 else 0,
        "bound_leases_only": get_bool(kwargs, "bound_leases_only", default=False),
        "router_macs": [],
        "router_name": "",
    }

    resource = one_row(rest_get(ctx, "/system/resource", True))
    if not resource:
        print("mikrotik: /system/resource returned nothing. RouterOS 7.1 or newer is required, " +
              "the www-ssl service must be enabled with a certificate assigned (or www for plain " +
              "HTTP on 7.9+), and the account needs the read and rest-api policies.")
        return None

    identity = one_row(rest_get(ctx, "/system/identity", False))
    # /system/routerboard does not exist on CHR or x86 builds. Its absence is
    # expected there and is not an error.
    routerboard = one_row(rest_get(ctx, "/system/routerboard", False))
    ctx["router_name"] = as_text(identity.get("name"), join=",").strip()

    netifs, own_macs, summary = router_interfaces(ctx)
    ctx["router_macs"] = own_macs

    router_count = 0
    if get_bool(kwargs, "import_router", default=True):
        asset = build_router_asset(ctx, resource, routerboard, identity, netifs, summary)
        if asset:
            report_assets(asset)
            router_count = 1
            if not as_text(routerboard.get("serial-number"), join=",").strip():
                print("mikrotik: no RouterBOARD serial is available (this is normal on CHR and x86), " +
                      "so the router asset is keyed on the configured host and its id will not drive merges")

    index = {}
    order = []
    if get_bool(kwargs, "collect_arp", default=True):
        kept, incomplete = collect_arp(ctx, index, order)
        print("mikrotik: ARP contributed {} entries ({} incomplete entries had no MAC and were skipped)".format(
            kept, incomplete))
    if get_bool(kwargs, "collect_dhcp_leases", default=True):
        kept, filtered = collect_leases(ctx, index, order)
        print("mikrotik: DHCP leases contributed {} entries ({} filtered as not bound)".format(kept, filtered))
    if get_bool(kwargs, "collect_neighbors", default=True):
        kept, skipped = collect_neighbors(ctx, index, order)
        print("mikrotik: discovery neighbors contributed {} entries ({} had no MAC and were skipped)".format(
            kept, skipped))
    if get_bool(kwargs, "collect_wireless", default=True):
        kept, tables = collect_wireless(ctx, index, order)
        print("mikrotik: {} of {} wireless registration tables were present and contributed {} stations".format(
            tables, len(WIRELESS_TABLES), kept))

    host_count = 0
    for mac in order:
        report_asset(build_host_asset(ctx, index[mac]))
        host_count += 1

    if ctx["max_hosts"] and len(order) >= ctx["max_hosts"]:
        print("mikrotik: host limit of {} reached; further devices were not imported".format(ctx["max_hosts"]))
    print("mikrotik: reported {} router and {} observed devices".format(router_count, host_count))
    if not router_count and not host_count:
        print("mikrotik: no assets retrieved")
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ntopng",
    "name": "ntopng",
    "type": "inbound",
    "description": "Imports passively observed local hosts from ntopng Community Edition, with their addresses, MACs, detected operating system, and traffic context.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # An IP address is not an identity: it is reassigned by DHCP, and the
    # next device to hold it is a different device. See the README.
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "ntopng URL",
            "type": "url",
            "required": True,
            "placeholder": "http://ntopng.example.com:3000",
            "description": "Base URL of the ntopng web interface. The default listener is HTTP on port 3000.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": False,
            "description": "ntopng user with read access. Leave blank when an API token is supplied.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": False,
            "description": "Password for that user, sent with HTTP Basic authentication.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": False,
            "description": "Per-user API token from the ntopng user preferences, sent as Authorization: Token <token>. Preferred over a password.",
        },
        {
            "key": "interface_ids",
            "label": "Interface ids",
            "type": "string",
            "required": False,
            "description": "Comma-separated ntopng interface ids to read. Leave blank to enumerate every monitored interface.",
        },
        {
            "key": "host_mode",
            "label": "Host selection",
            "type": "enum",
            "required": False,
            "default": "local",
            "options": ["local", "broadcast_domain", "all"],
            "description": "Which hosts to import. local is every host inside the configured local networks. all also returns every remote peer the network talked to, which is the public internet and is not inventory.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 250,
            "min": 1,
            "description": "Hosts requested per page, sent as perPage.",
        },
        {
            "key": "max_hosts",
            "label": "Maximum hosts per interface",
            "type": "int",
            "required": False,
            "default": 25000,
            "min": 1,
            "description": "Stop paging an interface after this many hosts. ntopng's active-host table has no reliable total, so this bounds a run against a very busy sensor.",
        },
        {
            "key": "include_macs",
            "label": "Join the MAC table",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read the layer 2 device table and fold each MAC's manufacturer, device type, and first-seen time onto the hosts using it.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'post_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool', 'get_list')
load('time', 'now', 'from_timestamp')

load('coerce', 'as_dict', 'as_list', 'as_text')
VENDOR = "ntopng"
ATTR_PREFIX = "ntopng"
ATTR_SEPARATOR = "_"
REST_BASE = "/lua/rest/v2/get"
HOSTS_PATH = REST_BASE + "/host/active.lua"
MACS_PATH = REST_BASE + "/mac/macs_list.lua"
INTERFACES_PATH = REST_BASE + "/ntopng/interfaces.lua"

# rest_utils.consts in scripts/lua/modules/rest_utils.lua. rc is 0 on success and
# negative on failure; the HTTP status carries the same information, but a
# reverse proxy that rewrites statuses leaves rc as the only reliable signal.
RC_CODES = {
    0: "OK",
    -1: "NOT_FOUND",
    -2: "INVALID_INTERFACE",
    -3: "NOT_GRANTED",
    -4: "INVALID_HOST",
    -5: "INVALID_ARGUMENTS",
    -6: "INTERNAL_ERROR",
    -7: "BAD_FORMAT",
    -8: "BAD_CONTENT",
    -59: "MISSING_PARAMETERS",
}

# ndpi_os in nDPI's src/include/ndpi_typedefs.h. ntopng passes the host's
# fingerprinted operating system through as this integer.
OS_NAMES = {
    0: "",
    1: "Windows",
    2: "macOS",
    3: "iOS",
    4: "Android",
    5: "Linux",
    6: "FreeBSD",
}

# ntopng's device_type_label strings mapped to runZero device types. The API
# returns the label, not the integer DeviceType from include/ntop_typedefs.h, so
# this is keyed on the label.
#
# The mapping is not cosmetic. runZero accepts a closed set of device types
# (IdentifyTypeFromCustomIntegration in the platform) and SILENTLY DISCARDS
# anything else -- no error, no log line, the asset simply ends up with no type.
# ntopng's own vocabulary overlaps that set by name in only three places, so
# passing device_type_label through verbatim, as this script used to, meant
# "Workstation" and "Networking" were thrown away at the far end while looking
# like they had been set.
#
# Labels with no honest runZero equivalent are mapped to "" and left unset
# rather than forced into the nearest-looking type: "Networking" does not say
# whether the device is a switch or a router, and a guess here would override
# fingerprinting, which can actually tell them apart.
DEVICE_TYPE_LABELS = {
    "printer": "Printer",
    "workstation": "Desktop",
    "laptop": "Laptop",
    "tablet": "Tablet",
    "phone": "Mobile",
    "tv": "Smart TV",
    "wifi": "WAP",
    "wireless": "WAP",
    "nas": "",
    "networking": "",
    "multimedia": "",
    "video": "",
    "iot": "",
    "unknown": "",
}

# Separator-free lowercase hex, because these are matched against the raw value
# before normalization -- see _real_mac for why the normalized form cannot be
# used here.
EMPTY_MAC_HEX = ["000000000000", "ffffffffffff"]

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "n/a", "none", "-", "broadcast", "multicast"]
HOSTNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
def _num(value):
    """Return a numeric field as an int, or None. ntopng emits some counters as
    JSON floats and some as integers depending on how Lua stored them."""
    kind = type(value)
    if kind == "int":
        return value
    if kind == "float":
        return int(value)
    return None

def _epoch(value, ceiling):
    """Convert a Unix epoch into a time value, clamped to the current time.

    from_timestamp takes an int and rejects a float with an error that aborts
    the whole script, and runZero drops an entire record whose first- or
    last-seen time is in the future, so both are handled here rather than being
    discovered on a sensor whose clock has drifted."""
    seconds = _num(value)
    if seconds == None or seconds <= 0:
        return None
    if seconds > ceiling.unix:
        return ceiling
    return from_timestamp(seconds)
def _real_mac(value):
    """Return a usable MAC, or an empty string.

    ntopng reports 00:00:00:00:00:00 for a host whose layer 2 address it never
    saw, which is every host reached through a router rather than observed on
    the monitored segment."""
    text = as_text(value)
    if not text:
        return ""
    # Compare the sentinels against the RAW hex, not the normalized value.
    # normalize_mac clears the locally-administered bit, which rewrites
    # ff:ff:ff:ff:ff:ff to fd:ff:ff:ff:ff:ff -- so testing the normalized form
    # let the broadcast address through and emitted it as a real MAC under a
    # fabricated spelling no NIC has ever had. 00:00:00:00:00:00 has the bit
    # clear already, which is why only broadcast slipped past.
    raw = text.lower().replace(":", "").replace("-", "").replace(".", "")
    if raw in EMPTY_MAC_HEX:
        return ""
    if normalize_mac(text) == None:
        return ""
    return text

def _hostname(value):
    """Return a value fit to be imported as a hostname, or an empty string.

    active.lua fills the name field from reverse DNS, then from a configured
    alias, and finally from the host key itself, so a host with no name arrives
    carrying its own IP address in the name field. It also appends a bracketed
    label - "web01 [alias]" - when the two differ, and a value with a bracket or
    a space in it is not a name."""
    text = as_text(value)
    if not text or len(text) > 253:
        return ""
    if text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    numeric = True
    for index in range(len(text)):
        if text[index] not in HOSTNAME_CHARS:
            return ""
        if text[index] not in "0123456789.":
            numeric = False
    if numeric:
        return ""
    return text

def _names_from(value):
    """Split active.lua's decorated name field into candidate hostnames.

    The endpoint composes this field as `name [label]` when the resolved name
    and the configured label differ, so both halves are considered and each is
    validated on its own."""
    text = as_text(value)
    if not text:
        return []
    candidates = []
    start = text.find("[")
    if start > 0 and text.endswith("]"):
        candidates.append(text[:start])
        candidates.append(text[start + 1:len(text) - 1])
    else:
        candidates.append(text)
    names = []
    for candidate in candidates:
        name = _hostname(candidate)
        if name and name not in names:
            names.append(name)
    return names

def call(ctx, path, payload, what):
    """Run one ntopng REST v2 read.

    The v2 endpoints are POSTs carrying a JSON body even though every one of
    them is a read, which is why this is a post_json and not a get_json; they
    are idempotent, so the helper's retry budget is safe to keep.

    ntopng's own source notes the failure mode that matters most here: "in case
    of invalid login, no error is returned but redirected to login". What the
    server actually answers is a 302 to the login page, never a 401 -- so a
    client that inspected only the status of the first response would see a
    redirect and no error. The HTTP helper follows redirects, so what reaches
    this function is the login page itself: HTML, with a 200 on it. That fails
    JSON decoding, and the decode failure is what this catches, so the case is
    named for what it is instead of being reported as a malformed response.

    (The 302 is directly observable: the container scenario's readiness gate
    polls /lua/login.lua rather than a REST endpoint precisely because every
    REST v2 URL answers 302 until the seed retires the default password.)"""
    data, err = post_json(ctx["url"] + path, json=payload, **ctx["http_options"])
    if err:
        if "invalid JSON" in err or "invalid character" in err:
            return None, "{}: the response was not JSON, which is what ntopng returns when it redirects an unauthenticated request to the login page".format(what)
        return None, "{}: {}".format(what, err)
    if type(data) != "dict":
        return None, "{}: the response was not a JSON object".format(what)
    rc = _num(data.get("rc"))
    if rc != None and rc != 0:
        label = RC_CODES.get(rc, "rc {}".format(rc))
        return None, "{}: {} ({})".format(what, label, as_text(data.get("rc_str")))
    return data, None

def fetch_interfaces(ctx):
    """List the interfaces ntopng is monitoring.

    Every host query is scoped to one interface id and answers
    INVALID_INTERFACE without it, so the ids have to be discovered before
    anything else can be read."""
    data, err = call(ctx, INTERFACES_PATH, {}, "listing interfaces")
    if err:
        print("ntopng:", err)
        return []
    interfaces = []
    for entry in as_list(data.get("rsp")):
        if type(entry) != "dict":
            continue
        ifid = _num(entry.get("ifid"))
        if ifid == None:
            continue
        interfaces.append({
            "ifid": ifid,
            "ifname": as_text(entry.get("ifname")),
            "name": as_text(entry.get("name")),
        })
    return interfaces

def fetch_macs(ctx, ifid):
    """Index the layer 2 device table for one interface.

    This is where ntopng keeps what it inferred about the device behind a MAC:
    the OUI manufacturer, and the device type its own discovery assigned. The
    host table carries neither, so the two have to be joined."""
    macs = {}
    offset = 0
    prev_signature = None
    _pager1 = pager("ntopng-1")
    while _pager1.next():
        payload = {
            "ifid": str(ifid),
            "start": offset,
            "length": ctx["page_size"],
        }
        data, err = call(ctx, MACS_PATH, payload, "fetching MACs for interface {}".format(ifid))
        if err:
            print("ntopng:", err)
            return macs
        rows = as_list(data.get("rsp"))
        if not rows:
            break
        # A proxy or build that ignores start/length answers every request
        # with the identical full list; without this guard the loop would spin
        # (deduped, importing nothing new) until the pager backstop raised.
        signature = (len(rows), str(rows[0]))
        if signature == prev_signature:
            print("ntopng: MAC listing for interface {} repeated a page at offset {}; stopping".format(ifid, offset))
            break
        prev_signature = signature
        for row in rows:
            if type(row) != "dict":
                continue
            mac = _real_mac(row.get("mac"))
            if not mac:
                continue
            normalized = normalize_mac(mac)
            if normalized == None or normalized in macs:
                continue
            device_type = as_dict(row.get("device_type"))
            macs[normalized] = {
                "manufacturer": as_text(row.get("manufacturer")),
                "device_type_label": as_text(device_type.get("device_type_label")),
                "seen_since": row.get("seen_since"),
                "hosts": _num(row.get("hosts")),
            }
        offset += len(rows)
        if len(rows) < ctx["page_size"]:
            break
    return macs

def build_asset(ctx, record, interface, macs):
    """Convert one ntopng host record into a runZero asset, or None when the
    record describes something that is not a device."""
    ip = routable_ip(record.get("ip"))
    if ip == None:
        return None

    # A multicast group and a broadcast address are traffic destinations, not
    # endpoints; ntopng tracks them alongside real hosts in the same table.
    if record.get("is_multicast") or record.get("is_broadcast"):
        return None

    vlan = _num(record.get("vlan"))
    if vlan == None:
        vlan = 0

    mac = _real_mac(record.get("mac"))
    normalized = normalize_mac(mac) if mac else None
    mac_record = macs.get(normalized, {}) if normalized else {}

    nic = network_interface(mac=mac, ips=[ip])
    if nic == None:
        return None

    hostnames = _names_from(record.get("name"))

    tags = [VENDOR, "interface:" + (interface["ifname"] or str(interface["ifid"]))]
    if vlan:
        tags.append("vlan:" + str(vlan))
    if record.get("is_blacklisted"):
        tags.append("ntopng-blacklisted")

    os_id = _num(record.get("os"))
    os_name = OS_NAMES.get(os_id, "") if os_id != None else ""

    thpt = as_dict(record.get("thpt"))
    byte_counts = as_dict(record.get("bytes"))
    flows = as_dict(record.get("num_flows"))
    pool = as_dict(record.get("pool"))

    attributes = {
        "host_key": as_text(record.get("key")),
        "server": ctx["scope"],
        "interface_id": interface["ifid"],
        "interface_name": interface["ifname"],
        "ip": ip,
        "vlan": vlan,
        "name": as_text(record.get("name")),
        "os_id": os_id,
        "os": os_name,
        "mac": as_text(record.get("mac")),
        "mac_manufacturer": mac_record.get("manufacturer", ""),
        "mac_device_type": mac_record.get("device_type_label", ""),
        "mac_first_seen_epoch": mac_record.get("seen_since"),
        "is_localhost": record.get("is_localhost"),
        "is_broadcast_domain": record.get("is_broadcast_domain"),
        "is_blacklisted": record.get("is_blacklisted"),
        "country": as_text(record.get("country")),
        "host_pool": as_text(pool.get("name")),
        "num_alerts": _num(record.get("num_alerts")),
        "active_flows": _num(flows.get("total")),
        "active_flows_as_client": _num(flows.get("as_client")),
        "active_flows_as_server": _num(flows.get("as_server")),
        "bytes_sent": _num(byte_counts.get("sent")),
        "bytes_received": _num(byte_counts.get("recvd")),
        "throughput_bps": _num(thpt.get("bps")),
        "first_seen_epoch": record.get("first_seen"),
        "last_seen_epoch": record.get("last_seen"),
    }

    params = {
        # The ntopng host key is the address and its VLAN. The interface id is
        # deliberately not part of it: the same host seen through two monitored
        # interfaces is one host, and an interface renumbered by an ntopng
        # restart must not re-key the estate.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], vlan, ip),
        "hostnames": hostnames,
        "networkInterfaces": [nic],
        "tags": tags,    }
    if os_name:
        params["os"] = os_name

    manufacturer = mac_record.get("manufacturer", "")
    if manufacturer:
        params["manufacturer"] = manufacturer
    device_type = DEVICE_TYPE_LABELS.get(
        mac_record.get("device_type_label", "").strip().lower(), "")
    if device_type:
        params["deviceType"] = device_type

    first_seen = _epoch(record.get("first_seen"), ctx["now"])
    if first_seen:
        params["firstSeenTS"] = first_seen
    last_seen = _epoch(record.get("last_seen"), ctx["now"])

    params["customAttributes"] = to_custom_attributes(
        attributes, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_and_report_interface(ctx, interface):
    """Page one interface's active-host table and stream it into runZero.

    Paging stops on the first short page rather than on a row count, because
    active.lua builds its response with `totalRows = total` where `total` is
    never assigned, so the field is nil in Lua and absent from the JSON. There
    is no reliable total to count towards."""
    ifid = interface["ifid"]
    macs = {}
    if ctx["include_macs"]:
        macs = fetch_macs(ctx, ifid)
        if macs:
            print("ntopng: indexed {} MACs on interface {}".format(len(macs), ifid))

    reported = 0
    skipped = 0
    seen_pages = 0
    _pager2 = pager("ntopng-2")
    while _pager2.next():
        page = _pager2.page
        payload = {
            "ifid": str(ifid),
            "mode": ctx["host_mode"],
            "currentPage": page,
            "perPage": ctx["page_size"],
        }
        data, err = call(ctx, HOSTS_PATH, payload, "fetching hosts on interface {}".format(ifid))
        if err:
            print("ntopng:", err)
            break

        rows = as_list(as_dict(data.get("rsp")).get("data"))
        if not rows:
            break
        seen_pages += len(rows)

        for record in rows:
            if type(record) != "dict":
                skipped += 1
                continue
            ip = routable_ip(record.get("ip"))
            if ip == None:
                skipped += 1
                continue
            vlan = _num(record.get("vlan"))
            if vlan == None:
                vlan = 0
            key = "{}:{}".format(vlan, ip)
            if key in ctx["seen"]:
                continue

            asset = build_asset(ctx, record, interface, macs)
            if asset == None:
                skipped += 1
                continue
            ctx["seen"][key] = True
            reported += report_asset(asset)
        if len(rows) < ctx["page_size"]:
            break
        if seen_pages >= ctx["max_hosts"]:
            print("ntopng: stopped at the {} host limit on interface {}".format(ctx["max_hosts"], ifid))
            break

    if skipped:
        print("ntopng: skipped {} records on interface {} that were not addressable endpoints".format(skipped, ifid))
    print("ntopng: reported {} assets from interface {}".format(reported, ifid))
    return reported

def main(**kwargs):
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("ntopng: no ntopng URL was configured")
        return None

    parsed = url_parse(url)
    if parsed == None or not parsed.hostname:
        print("ntopng: could not determine the ntopng host from the configured URL")
        return None
    scope = parsed.hostname

    token = get_string(kwargs, "api_token", default="").strip()
    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Token " + token
    elif username and password:
        headers["Authorization"] = basic(username, password)
    else:
        print("ntopng: configure either an API token or a username and password")
        return None

    page_size = get_int(kwargs, "page_size", default=250)
    if page_size < 1:
        page_size = 1
    max_hosts = get_int(kwargs, "max_hosts", default=25000)
    if max_hosts < 1:
        max_hosts = 1

    host_mode = get_string(kwargs, "host_mode", default="local").strip() or "local"

    ctx = {
        "url": url,
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
        "now": now(),
        "scope": scope,
        "page_size": page_size,
        "max_hosts": max_hosts,
        "host_mode": host_mode,
        "include_macs": get_bool(kwargs, "include_macs", default=True),
        "seen": {},
    }

    if host_mode == "all":
        print("ntopng: host_mode is 'all', so every remote peer the network contacted will be imported as an asset")

    interfaces = []
    configured = get_list(kwargs, "interface_ids", default=[])
    for value in configured:
        text = as_text(value)
        if not text:
            continue
        digits = True
        for index in range(len(text)):
            if text[index] not in "0123456789":
                digits = False
        if not digits:
            print("ntopng: ignoring interface id {}: not a number".format(text))
            continue
        interfaces.append({"ifid": int(text), "ifname": "", "name": ""})

    if not interfaces:
        interfaces = fetch_interfaces(ctx)
        if not interfaces:
            print("ntopng: no monitored interfaces were found")
            return None
        print("ntopng: found {} monitored interface(s)".format(len(interfaces)))

    reported = 0
    for interface in interfaces:
        reported += fetch_and_report_interface(ctx, interface)

    if not reported:
        print("ntopng: no assets retrieved")
    return None

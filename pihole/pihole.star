# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-pihole",
    "name": "Pi-hole",
    "type": "inbound",
    "description": "Imports the local network device table observed by a Pi-hole v6 server, with MAC, addresses, hostnames, and optional DHCP lease detail.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Pi-hole URL",
            "type": "url",
            "required": True,
            "placeholder": "https://pi.hole",
            "description": "Base URL of the Pi-hole web interface. The /api path is appended automatically.",
        },
        {
            "key": "password",
            "label": "Password or application password",
            "type": "secret",
            "required": True,
            "description": "The Pi-hole web password, or an application password created in Settings > Web interface / API. An application password is preferred because it can be revoked on its own.",
        },
        {
            "key": "max_devices",
            "label": "Maximum devices",
            "type": "int",
            "required": False,
            "default": 10000,
            "min": 1,
            "description": "Value sent as max_devices. The API defaults to 10 when this is omitted, so it is always sent.",
        },
        {
            "key": "max_addresses",
            "label": "Maximum addresses per device",
            "type": "int",
            "required": False,
            "default": 32,
            "min": 1,
            "description": "Value sent as max_addresses. A device that has held many addresses over time would otherwise be truncated to the API default.",
        },
        {
            "key": "include_leases",
            "label": "Join DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read the active DHCP leases and fold the client hostname, lease expiry, and client id onto the matching device. Only useful when Pi-hole is running the DHCP server.",
        },
        {
            "key": "include_ip_only_devices",
            "label": "Import devices with no MAC",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import the rows Pi-hole records for clients it never saw at layer 2. These are routed clients and upstream resolvers, stored under a synthetic ip-<address> hardware address, and they carry an address and nothing else.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'post_json', 'delete', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'from_timestamp')

load('coerce', 'as_dict', 'as_list', 'as_text')
VENDOR = "pihole"
ATTR_PREFIX = "pihole"
ATTR_SEPARATOR = "_"
API_SUFFIX = "/api"
# FTL stores a synthetic hardware address of this shape for a client whose real
# MAC it never observed - "Create mock hardware address in the style of
# 'ip-<IP address>', like 'ip-127.0.0.1'" (src/database/network-table.c). Those
# rows describe an address, not a network adapter, and the value must never be
# read as a MAC.
MOCK_MAC_PREFIX = "ip-"

# A lease or an ARP row that carries the all-zero address is describing the
# absence of one.
EMPTY_MACS = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]

# Names dnsmasq and Pi-hole write when there is no name. "pi.hole" is the
# appliance's own alias for itself and resolves on every Pi-hole network, so it
# is not evidence about the client that happens to be answering to it.
PLACEHOLDER_NAMES = [
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "unknown", "n/a", "none", "-", "pi.hole",
]
HOSTNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
def _epoch(value, ceiling):
    """Convert a Unix timestamp into a time value clamped to the current time.

    Every Pi-hole timestamp is an integer epoch, but from_timestamp rejects a
    float outright with an error that aborts the whole script, and FTL's own
    schema uses `number` for some of them, so the value is truncated first. The
    clamp matters because runZero drops the entire record - not the field - when
    a first- or last-seen time is in the future, and a Pi-hole whose clock has
    drifted forward would otherwise import nothing at all."""
    kind = type(value)
    if kind != "int" and kind != "float":
        return None
    seconds = int(value)
    if seconds <= 0:
        return None
    if seconds > ceiling.unix:
        return ceiling
    return from_timestamp(seconds)

def _real_mac(value):
    """Return a genuine MAC address, or an empty string.

    Rejects the synthetic ip-<address> hardware address FTL invents for a client
    it never saw at layer 2, and the all-zero and broadcast addresses, both of
    which appear in lease rows for clients identified some other way."""
    text = as_text(value)
    if not text or text.lower().startswith(MOCK_MAC_PREFIX):
        return ""
    normalized = normalize_mac(text)
    if normalized == None or normalized in EMPTY_MACS:
        return ""
    return text
def _hostname(value):
    """Return a value fit to be imported as a hostname, or an empty string.

    The names in the network table are whatever reverse DNS or the DHCP client
    supplied, so they include bare addresses, dnsmasq placeholders, and the
    appliance's own pi.hole alias. None of those identify the client."""
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

def open_session(api_url, password, http_options):
    """Exchange the password for a session id.

    Pi-hole issues a fixed, small number of API seats - the default is a handful
    - and a session holds one until it expires 30 minutes later or is deleted.
    A task that authenticates on every run without logging out will exhaust them
    and lock the administrator out of the web interface, which is why the caller
    always deletes the session at the end."""
    data, err = post_json(api_url + "/auth", json={"password": password}, **http_options)
    if err:
        if "429" in err:
            print("pihole: the login was rate-limited or no API seat was free:", err)
            print("pihole: raise webserver.api.max_sessions, or check for sessions left open by a previous run")
        elif "401" in err:
            print("pihole: the password was rejected:", err)
        else:
            print("pihole: failed to log in:", err)
        return "", False
    session = as_dict(as_dict(data).get("session"))
    if not session:
        print("pihole: the login response carried no session object")
        return "", False
    if not session.get("valid"):
        print("pihole: the login was refused:", as_text(session.get("message")))
        return "", False
    sid = as_text(session.get("sid"))
    if not sid:
        # A Pi-hole with no password set, or one that trusts this client's
        # address, answers with valid=true and a null sid. Subsequent reads
        # then need no session header at all.
        print("pihole: no session id was issued:", as_text(session.get("message")) or "no password is set")
    return sid, True

def close_session(ctx):
    """Release the API seat. Left open, it counts against the concurrent-session
    limit for the full 30-minute session lifetime."""
    if not ctx["sid"]:
        return
    # The raw delete() builtin raises on a transport error, and a raise here
    # would mark the task errored after every asset has already streamed. A
    # session-status probe with err-tuple semantics runs first, so a transport
    # that has already died is a printed skip rather than a raise; the seat
    # then simply ages out server-side.
    _, probe_err = get_json(ctx["api_url"] + "/auth", retries=0, **ctx["http_options"])
    if probe_err and probe_err.startswith("transport"):
        print("pihole: skipping the session release, the endpoint stopped answering:", probe_err)
        return
    resp = delete(ctx["api_url"] + "/auth", **ctx["http_options"])
    if resp == None or resp.status_code >= 300:
        status = resp.status_code if resp != None else "no response"
        print("pihole: failed to delete the API session:", status)

def fetch_version(ctx):
    """Read the component versions, so the run log names what it talked to."""
    data, err = get_json(ctx["api_url"] + "/info/version", **ctx["http_options"])
    if err:
        print("pihole: could not read the version:", err)
        return ""
    version = as_dict(as_dict(data).get("version"))
    core = as_dict(as_dict(version.get("core")).get("local"))
    ftl = as_dict(as_dict(version.get("ftl")).get("local"))
    parts = []
    if as_text(core.get("version")):
        parts.append("core " + as_text(core.get("version")))
    if as_text(ftl.get("version")):
        parts.append("FTL " + as_text(ftl.get("version")))
    return ", ".join(parts)

def fetch_leases(ctx):
    """Index the active DHCP leases by MAC and by address.

    Pi-hole serves DHCP through the dnsmasq embedded in pihole-FTL, so this
    table exists only when the Pi-hole is the network's DHCP server. When it is,
    a lease is a much stronger statement about a device than a DNS query: it
    names the client, its hardware address, and the address the server itself
    handed out."""
    by_mac = {}
    by_ip = {}
    data, err = get_json(ctx["api_url"] + "/dhcp/leases", **ctx["http_options"])
    if err:
        print("pihole: could not read the DHCP leases:", err)
        return by_mac, by_ip

    leases = as_list(as_dict(data).get("leases"))
    for lease in leases:
        if type(lease) != "dict":
            continue
        record = {
            "name": as_text(lease.get("name")),
            "hwaddr": as_text(lease.get("hwaddr")),
            "ip": as_text(lease.get("ip")),
            "expires": lease.get("expires"),
            "clientid": as_text(lease.get("clientid")),
        }
        mac = _real_mac(lease.get("hwaddr"))
        if mac:
            normalized = normalize_mac(mac)
            if normalized and normalized not in by_mac:
                by_mac[normalized] = record
        address = routable_ip(lease.get("ip"))
        if address and address not in by_ip:
            by_ip[address] = record

    print("pihole: read {} DHCP leases".format(len(leases)))
    return by_mac, by_ip

def collect_addresses(device):
    """Split a device's ips[] array into routable addresses and hostnames.

    Every entry pairs an address with the name Pi-hole last resolved for it, and
    a device routinely holds several: a v4 lease, a stable v6 address, and one
    or more SLAAC privacy addresses. Link-local is dropped here rather than left
    to the platform, which keeps fe80:: and 169.254 deliberately."""
    ips = []
    names = []
    last_seen = 0
    for entry in as_list(device.get("ips")):
        if type(entry) != "dict":
            continue
        address = routable_ip(entry.get("ip"))
        if address and address not in ips:
            ips.append(address)
        name = _hostname(entry.get("name"))
        if name and name not in names:
            names.append(name)
        seen = entry.get("lastSeen")
        if type(seen) == "int" and seen > last_seen:
            last_seen = seen
    return ips, names, last_seen

def build_asset(ctx, device):
    """Convert one row of Pi-hole's network table into a runZero asset, or None
    when the row identifies nothing importable."""
    device_id = device.get("id")
    raw_hwaddr = as_text(device.get("hwaddr"))
    mac = _real_mac(raw_hwaddr)
    ips, names, address_last_seen = collect_addresses(device)

    if not mac and not ctx["include_ip_only_devices"]:
        ctx["ip_only_skipped"] += 1
        return None

    nic = network_interface(mac=mac, ips=ips)
    if nic == None and not names:
        print("pihole: skipping device {}: no MAC, routable address, or usable hostname".format(device_id))
        return None

    lease = {}
    if mac:
        normalized = normalize_mac(mac)
        if normalized:
            lease = ctx["leases_by_mac"].get(normalized, {})
    if not lease:
        for address in ips:
            lease = ctx["leases_by_ip"].get(address, {})
            if lease:
                break

    hostnames = list(names)
    lease_name = _hostname(lease.get("name"))
    if lease_name and lease_name not in hostnames:
        hostnames.append(lease_name)

    tags = [VENDOR]
    interface = as_text(device.get("interface"))
    if interface and interface != "N/A":
        tags.append("interface:" + interface)
    if not mac:
        tags.append("no-layer2-identity")

    attributes = {
        "device_id": device_id,
        "server": ctx["scope"],
        "hwaddr": raw_hwaddr,
        "interface": interface,
        "mac_vendor": as_text(device.get("macVendor")),
        "num_queries": device.get("numQueries"),
        "first_seen_epoch": device.get("firstSeen"),
        "last_query_epoch": device.get("lastQuery"),
        "address_count": len(ips),
        "addresses": ips,
        "hostnames": names,
        "has_layer2_identity": "true" if mac else "false",
    }
    if lease:
        attributes["dhcp_lease_name"] = lease.get("name", "")
        attributes["dhcp_lease_ip"] = lease.get("ip", "")
        attributes["dhcp_lease_hwaddr"] = lease.get("hwaddr", "")
        attributes["dhcp_lease_expires_epoch"] = lease.get("expires")
        attributes["dhcp_client_id"] = lease.get("clientid", "")

    params = {
        # The network-table row id. It is deterministic and namespaced so the
        # asset can be traced back, but it never drives matching - see the
        # README's asset identity section.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": hostnames,
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
    }
    vendor = as_text(device.get("macVendor"))
    if vendor:
        params["manufacturer"] = vendor

    first_seen = _epoch(device.get("firstSeen"), ctx["now"])
    if first_seen:
        params["firstSeenTS"] = first_seen

    last_query = device.get("lastQuery")
    if address_last_seen > 0 and (type(last_query) != "int" or address_last_seen > last_query):
        last_query = address_last_seen
    last_seen = _epoch(last_query, ctx["now"])

    params["customAttributes"] = to_custom_attributes(
        attributes, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_and_report_devices(ctx):
    """Read the network table and stream it into runZero.

    /api/network/devices does not paginate: it answers with every device in one
    array, bounded only by max_devices, which the API defaults to 10 when it is
    not sent. That default is the single most important parameter here - omit it
    and a home network of forty devices imports four of them."""
    params = {
        "max_devices": str(ctx["max_devices"]),
        "max_addresses": str(ctx["max_addresses"]),
    }
    data, err = get_json(ctx["api_url"] + "/network/devices", params=params, **ctx["http_options"])
    if err:
        print("pihole: failed to read the network device table:", err)
        return 0

    devices = as_list(as_dict(data).get("devices"))
    if not devices:
        print("pihole: the network device table is empty")
        return 0
    if len(devices) >= ctx["max_devices"]:
        print("pihole: the response filled the max_devices limit of {}; raise it to be sure nothing was truncated".format(
            ctx["max_devices"]))

    reported = 0
    skipped = 0
    seen = {}
    for device in devices:
        if type(device) != "dict":
            skipped += 1
            continue
        device_id = device.get("id")
        if device_id == None or as_text(device_id) == "":
            skipped += 1
            print("pihole: skipping device with no id: hwaddr={}".format(as_text(device.get("hwaddr"))))
            continue
        key = as_text(device_id)
        if key in seen:
            continue
        seen[key] = True

        asset = build_asset(ctx, device)
        if asset == None:
            continue
        reported += report_asset(asset)
    if skipped:
        print("pihole: skipped {} malformed device rows".format(skipped))
    if ctx["ip_only_skipped"]:
        print("pihole: skipped {} devices with no layer 2 identity; enable include_ip_only_devices to import them".format(
            ctx["ip_only_skipped"]))
    print("pihole: reported {} assets".format(reported))
    return reported

def main(**kwargs):
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("pihole: no Pi-hole URL was configured")
        return None
    api_url = url if url.endswith(API_SUFFIX) else url + API_SUFFIX

    parsed = url_parse(url)
    if parsed == None or not parsed.hostname:
        fail("pihole: could not determine the Pi-hole host from the configured URL")
    scope = parsed.hostname

    password = get_string(kwargs, "password", default="")
    if not password:
        print("pihole: a password or application password is required")
        return None

    base_headers = {"Accept": "application/json"}
    sid, ok = open_session(api_url, password, get_http_options(kwargs, "http_", "tls_", base_headers))
    if not ok:
        # open_session has already printed which of the refusals happened; the
        # run cannot read anything without a seat.
        fail("pihole: could not open an API session")

    headers = dict(base_headers)
    if sid:
        # The session id travels in a header rather than the sid query
        # parameter, so it never reaches a proxy access log.
        headers["X-FTL-SID"] = sid

    max_devices = get_int(kwargs, "max_devices", default=10000)
    if max_devices < 1:
        max_devices = 1
    max_addresses = get_int(kwargs, "max_addresses", default=32)
    if max_addresses < 1:
        max_addresses = 1

    ctx = {
        "api_url": api_url,
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
        "now": now(),
        "scope": scope,
        "sid": sid,
        "max_devices": max_devices,
        "max_addresses": max_addresses,
        "include_ip_only_devices": get_bool(kwargs, "include_ip_only_devices", default=False),
        "ip_only_skipped": 0,
        "leases_by_mac": {},
        "leases_by_ip": {},
    }

    version = fetch_version(ctx)
    if version:
        print("pihole: connected to Pi-hole", version)

    if get_bool(kwargs, "include_leases", default=True):
        ctx["leases_by_mac"], ctx["leases_by_ip"] = fetch_leases(ctx)

    if not fetch_and_report_devices(ctx):
        print("pihole: no assets retrieved")

    close_session(ctx)
    return None

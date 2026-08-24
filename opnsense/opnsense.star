# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-opnsense",
    "name": "OPNsense",
    "type": "inbound",
    "description": "Imports the OPNsense firewall itself plus every host it observes through ARP, NDP, and DHCP leases.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # A 'host' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'host': "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "OPNsense URL",
            "type": "url",
            "required": True,
            "placeholder": "https://opnsense.example.com",
            "description": "Base URL of the OPNsense web interface. The /api/ path is appended automatically.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "OPNsense API key, issued at System > Access > Users > edit user > API keys. Sent as the HTTP Basic username.",
        },
        {
            "key": "api_secret",
            "label": "API secret",
            "type": "secret",
            "required": True,
            "description": "The API secret issued alongside the key. Sent as the HTTP Basic password.",
        },
        {
            "key": "collect_arp",
            "label": "Collect the ARP table",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import IPv4 neighbors from /api/diagnostics/interface/getArp.",
        },
        {
            "key": "collect_ndp",
            "label": "Collect the NDP table",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import IPv6 neighbors from /api/diagnostics/interface/getNdp.",
        },
        {
            "key": "collect_leases",
            "label": "Collect DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import Kea and dnsmasq DHCP leases. Backends that are not installed are skipped without failing the run.",
        },
        {
            "key": "include_expired",
            "label": "Include expired neighbors",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import ARP entries the kernel has already marked expired. Off by default because an expired entry is a host that has stopped answering.",
        },
        {
            "key": "max_hosts",
            "label": "Maximum discovered hosts",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 0,
            "description": "Cap on the number of discovered hosts imported in one run. 0 removes the cap.",
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

load('coerce', 'as_text', 'dicts')
VENDOR = "opnsense"
ATTR_PREFIX = "opnsense"
ATTR_SEPARATOR = "_"

HEXDIGITS = "0123456789abcdef"

# Hostnames that name no host. dnsmasq writes a literal "*" into its lease file
# when the client sent no hostname option, and the ARP collector writes "" when
# the reverse lookup returned "?".
PLACEHOLDER_NAMES = ["*", "?", "localhost", "localhost.localdomain", "unknown", "none", "null", "-"]

# Kea lease states, from the Kea lease4-get-all API.
LEASE_STATES = {0: "default", 1: "declined", 2: "expired-reclaimed", 3: "released"}
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    normalize_mac is deliberately not used here. It clears the locally
    administered bit of the first octet, so aa:bb:cc:dd:ee:ff and
    a8:bb:cc:dd:ee:ff both normalize to a8:bb:cc:dd:ee:ff. Every randomized
    client MAC carries that bit and a firewall's ARP table is full of them, so
    normalizing here would fold two distinct endpoints into one record. The
    emitted NetworkInterface still goes through network_interface, which is the
    correct behavior for matching on the wire.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    # A multicast or broadcast destination is not an endpoint. NDP tables list
    # 33:33:.. solicited-node entries and ff:ff:ff:ff:ff:ff shows up in ARP.
    first = int(text[0:2], 16)
    if first % 2 == 1:
        return ""
    if text == "000000000000" or text == "ffffffffffff":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    """Return a usable hostname, or "" for a placeholder or a bare address.

    A hostname that is really an IP correlates on a dimension runZero already
    has and reads as a name it does not, so it is dropped rather than imported.
    """
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text


def _appliance_host(base_url):
    """Return the OPNsense hostname, which scopes every imported id.

    The scheme and port are dropped so that reaching the same firewall on a
    different port does not change the identity of assets already imported.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def fetch(ctx, path, method, payload):
    """Call one OPNsense API endpoint. Failures are reported and returned as
    None so an uninstalled plugin or a permission gap cannot end the run."""
    url = ctx["base_url"] + path
    if method == "POST":
        data, err = post_json(url, json=payload, **ctx["http_options"])
    else:
        data, err = get_json(url, **ctx["http_options"])
    if err:
        print("opnsense: {} failed: {}".format(path, err))
        return None
    return data


def search_rows(ctx, path, payload):
    """Call an OPNsense bootgrid "search" endpoint and return its rows.

    These endpoints wrap their result as {total, rowCount, current, rows}. The
    grid parameters are read from the POST body only, so the request has to be
    a POST with rowCount -1 to defeat the server-side default of 9999.
    """
    data = fetch(ctx, path, "POST", payload)
    if type(data) != "dict":
        return None
    rows = data.get("rows")
    if type(rows) != "list":
        return None
    return dicts(rows)


def parse_version(versions):
    """Pull the product name and version out of systemInformation's versions[].

    The first element is built by OPNsense as "<product_name> <product_version>-
    <product_arch>", for example "OPNsense 25.7.1-amd64". Anything that does not
    match that shape is returned whole rather than guessed at, and a bare string
    where the array is documented is read as a one-element array.
    """
    if type(versions) == "string":
        versions = [versions]
    if type(versions) != "list" or not versions:
        return "OPNsense", ""
    first = as_text(versions[0], join=",").strip()
    if not first:
        return "OPNsense", ""
    parts = first.split(" ")
    if len(parts) < 2:
        return first, ""
    name = parts[0]
    version = parts[1]
    # Drop the architecture suffix but keep patch markers such as 25.1.5_4.
    if "-" in version:
        version = version.split("-")[0]
    return name, version


def build_firewall_asset(ctx):
    """Build the asset for the firewall itself from its system information and
    its own interface configuration."""
    info = fetch(ctx, "/api/diagnostics/system/systemInformation", "GET", None)
    config = fetch(ctx, "/api/diagnostics/interface/getInterfaceConfig", "GET", None)

    fqdn = ""
    os_name = "OPNsense"
    os_version = ""
    if type(info) == "dict":
        fqdn = as_text(info.get("name"), join=",").strip().rstrip(".")
        os_name, os_version = parse_version(info.get("versions"))

    # systemInformation reports "<hostname>.<domain>"; a default install ships
    # OPNsense.localdomain, and a firewall left at "localhost" would otherwise
    # correlate with every other host that reports the same placeholder.
    hostname = _hostname(fqdn)
    domain = ""
    if hostname and "." in hostname:
        short = hostname.split(".")[0]
        domain = hostname[len(short) + 1:]
        hostname = _hostname(short)

    netifs = []
    interface_names = []
    own_macs = []
    if type(config) == "dict":
        for device in sorted(config.keys()):
            entry = config.get(device)
            if type(entry) != "dict":
                continue
            # A firewall carries loopback, pflog, pfsync, and enc pseudo
            # devices with no address worth importing; network_interface
            # returns None for those and they are dropped rather than
            # producing networkInterfaces=[None], which aborts the run.
            ips = []
            for family in ["ipv4", "ipv6"]:
                for addr in dicts(entry.get(family)):
                    routable = routable_ip(addr.get("ipaddr"))
                    if routable and routable not in ips:
                        ips.append(routable)
            mac = _mac_key(entry.get("macaddr"))
            if not mac and not ips:
                continue
            nic = network_interface(mac=mac, ips=ips)
            if nic:
                netifs.append(nic)
                interface_names.append(device)
                if mac and mac not in own_macs:
                    own_macs.append(mac)

    attrs = {
        "appliance": ctx["scope"],
        "system_name": fqdn,
        "product": os_name,
        "product_version": os_version,
        "interfaces": interface_names,
        "interface_count": len(interface_names),
    }
    if type(info) == "dict" and type(info.get("versions")) == "list":
        attrs["versions"] = [as_text(item, join=",") for item in info.get("versions")]

    if not hostname and not netifs:
        return None, own_macs

    params = {
        "id": "{}:{}:appliance".format(VENDOR, ctx["scope"]),
        "hostnames": [hostname] if hostname else [],
        "domain": domain,
        "networkInterfaces": netifs,
        "deviceType": "Firewall",
        "os": os_name or "OPNsense",
        "tags": [VENDOR, "firewall"],
        # The appliance id is derived from the configured URL, not from a
        # vendor identifier, because OPNsense publishes none. It is stable for
        # a fixed credential, and the interface MACs and the hostname are the
        # signals that let it merge with an asset runZero scanned directly, so
        # none of them may disqualify that merge -- the integration-wide policy
        # in CONFIG, which this type inherits.
        "assetType": "firewall",
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if os_version:
        params["osVersion"] = os_version
    return ImportAsset(**params), own_macs


def _record(index, order, mac):
    """Return the accumulating record for one MAC, creating it on first sight."""
    if mac not in index:
        index[mac] = {
            "mac": mac,
            "ips": [],
            "hostnames": [],
            "sources": [],
            "interfaces": [],
            "attrs": {},
        }
        order.append(mac)
    return index[mac]


def _merge(record, source, ips, hostnames, interfaces, attrs):
    """Fold one observation of a MAC into its accumulating record."""
    if source not in record["sources"]:
        record["sources"].append(source)
    for ip in ips:
        if ip and ip not in record["ips"]:
            record["ips"].append(ip)
    for name in hostnames:
        if name and name not in record["hostnames"]:
            record["hostnames"].append(name)
    for interface in interfaces:
        if interface and interface not in record["interfaces"]:
            record["interfaces"].append(interface)
    for key in attrs:
        value = attrs[key]
        if value == None or value == "":
            continue
        if key not in record["attrs"]:
            record["attrs"][key] = value


def collect_arp(ctx, index, order, own_macs):
    """Fold the IPv4 ARP table into the MAC index.

    getArp returns a bare JSON array whose elements are built by
    scripts/interfaces/list_arp.py as
    {mac, ip, intf, expired, expires, permanent, type, manufacturer, hostname},
    with intf_description added by the controller.
    """
    rows = fetch(ctx, "/api/diagnostics/interface/getArp", "GET", None)
    if type(rows) != "list":
        return 0
    seen = 0
    for entry in dicts(rows):
        mac = _mac_key(entry.get("mac"))
        if not mac:
            continue
        # A permanent entry is one of the firewall's own interfaces, not a
        # neighbor, and importing it would attach the firewall's addresses to a
        # second asset.
        if entry.get("permanent") == True or mac in own_macs:
            continue
        if entry.get("expired") == True and not ctx["include_expired"]:
            continue
        ip = routable_ip(entry.get("ip"))
        record = _record(index, order, mac)
        _merge(record, "arp", [ip], [_hostname(entry.get("hostname"))],
               [as_text(entry.get("intf_description"), join=",") or as_text(entry.get("intf"), join=",")], {
                   "arp_interface": entry.get("intf"),
                   "arp_interface_description": entry.get("intf_description"),
                   "arp_type": entry.get("type"),
                   "arp_expired": entry.get("expired"),
                   "arp_expires": entry.get("expires"),
                   "manufacturer": entry.get("manufacturer"),
               })
        seen += 1
    return seen


def collect_ndp(ctx, index, order, own_macs):
    """Fold the IPv6 NDP table into the MAC index.

    getNdp returns a bare JSON array of {mac, ip, intf, manufacturer} with
    intf_description added by the controller. Most entries carry only a
    link-local address, which is filtered out; the MAC alone is still a usable
    correlator and the entry proves the host is on the segment.
    """
    rows = fetch(ctx, "/api/diagnostics/interface/getNdp", "GET", None)
    if type(rows) != "list":
        return 0
    seen = 0
    for entry in dicts(rows):
        mac = _mac_key(entry.get("mac"))
        if not mac or mac in own_macs:
            continue
        ip = routable_ip(entry.get("ip"))
        record = _record(index, order, mac)
        _merge(record, "ndp", [ip], [],
               [as_text(entry.get("intf_description"), join=",") or as_text(entry.get("intf"), join=",")], {
                   "ndp_interface": entry.get("intf"),
                   "ndp_interface_description": entry.get("intf_description"),
                   "manufacturer": entry.get("manufacturer"),
               })
        seen += 1
    return seen


def collect_leases(ctx, index, order, own_macs, path, source, payload):
    """Fold one DHCP lease table into the MAC index.

    Kea and dnsmasq expose different backends behind the same record shape:
    {address, hwaddr, hostname, client_id, expire, if, if_descr, if_name, ...}.
    A backend that is not installed answers with a non-2xx or an unusable body
    and is skipped, which is what makes probing both safe.
    """
    rows = search_rows(ctx, path, payload)
    if rows == None:
        return -1
    seen = 0
    for entry in rows:
        mac = _mac_key(entry.get("hwaddr"))
        if not mac or mac in own_macs:
            continue
        ip = routable_ip(entry.get("address"))
        state = entry.get("state")
        record = _record(index, order, mac)
        _merge(record, source, [ip], [_hostname(entry.get("hostname"))],
               [as_text(entry.get("if_descr"), join=",") or as_text(entry.get("if_name"), join=",") or as_text(entry.get("if"), join=",")], {
                   "dhcp_backend": source,
                   "dhcp_interface": entry.get("if_name") or entry.get("if"),
                   "dhcp_interface_description": entry.get("if_descr"),
                   "dhcp_client_id": entry.get("client_id"),
                   "dhcp_expire": entry.get("expire"),
                   "dhcp_state": LEASE_STATES.get(state, state) if type(state) == "int" else state,
                   "dhcp_reserved": entry.get("is_reserved"),
                   "manufacturer": entry.get("mac_info"),
               })
        seen += 1
    return seen


def build_host_asset(ctx, record):
    """Convert one merged MAC record into a runZero asset."""
    mac = record["mac"]
    nic = network_interface(mac=mac, ips=record["ips"])

    attrs = dict(record["attrs"])
    attrs["appliance"] = ctx["scope"]
    attrs["mac"] = mac
    attrs["sources"] = record["sources"]
    attrs["segments"] = record["interfaces"]
    attrs["addresses"] = record["ips"]

    tags = [VENDOR, "opnsense-discovered"]
    for source in record["sources"]:
        tags.append("opnsense-" + source)

    return ImportAsset(
        # The MAC is the natural key of every table read here and OPNsense
        # issues no identifier of its own, so it is what the record is keyed on.
        # It is paired with no-id-match so the id never drives a merge: a MAC
        # that is reassigned, spoofed, or randomized must not be able to pull a
        # different device onto an existing asset, and no break flag can veto a
        # foreign-id match once it happens.
        id="{}:{}:host:{}".format(VENDOR, ctx["scope"], mac),
        hostnames=record["hostnames"],
        networkInterfaces=[nic] if nic else [],
        tags=tags,
        assetType="host",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )


def report_hosts(ctx, index, order):
    """Stream the merged host records to runZero, one asset per call."""
    limit = ctx["max_hosts"]
    reported = 0
    skipped = 0
    for mac in order:
        if limit and reported >= limit:
            skipped += 1
            continue
        record = index[mac]
        # An entry with no routable address and no name still carries a MAC,
        # which is a correlator on its own; one with nothing at all cannot
        # merge with anything and is not imported.
        if not record["ips"] and not record["hostnames"] and not record["mac"]:
            continue
        report_asset(build_host_asset(ctx, record))
        reported += 1
    return reported, skipped


def main(**kwargs):
    base_url = get_url_base(kwargs)
    scope = _appliance_host(base_url)
    if not scope:
        print("opnsense: could not determine the firewall host from the configured URL")
        return None

    max_hosts = get_int(kwargs, "max_hosts", default=20000)
    if max_hosts < 0:
        max_hosts = 0

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Authorization": basic(get_string(kwargs, "api_key"), get_string(kwargs, "api_secret")),
            "Accept": "application/json",
        }),
        "include_expired": get_bool(kwargs, "include_expired", default=False),
        "max_hosts": max_hosts,
    }

    firewall, own_macs = build_firewall_asset(ctx)
    firewall_count = 0
    if firewall == None:
        # Both the system-information and the interface-configuration calls
        # failed, so the firewall record would carry no hostname, no address,
        # and no MAC. Such an asset can never merge with anything and is worse
        # than no asset at all, so it is not emitted.
        print("opnsense: the firewall itself could not be identified; " +
              "check that the API user can read the dashboard and interface diagnostics")
    else:
        report_assets(firewall)
        firewall_count = 1

    index = {}
    order = []
    if get_bool(kwargs, "collect_arp", default=True):
        print("opnsense: ARP entries read: {}".format(collect_arp(ctx, index, order, own_macs)))
    if get_bool(kwargs, "collect_ndp", default=True):
        print("opnsense: NDP entries read: {}".format(collect_ndp(ctx, index, order, own_macs)))
    if get_bool(kwargs, "collect_leases", default=True):
        # OPNsense has moved from ISC dhcpd to Kea and dnsmasq and either, both,
        # or neither may be serving DHCP. ISC dhcpd never had a lease API at
        # all. Both supported backends are probed and a missing one is a normal
        # outcome, not an error.
        found = False
        for path, source, payload in [
            ("/api/kea/leases4/search", "kea4", {"current": 1, "rowCount": -1}),
            ("/api/kea/leases6/search", "kea6", {"current": 1, "rowCount": -1}),
            ("/api/dnsmasq/leases/search", "dnsmasq", {"current": 1, "rowCount": -1}),
        ]:
            count = collect_leases(ctx, index, order, own_macs, path, source, payload)
            if count < 0:
                print("opnsense: DHCP backend {} is not available; skipping it".format(source))
                continue
            found = True
            print("opnsense: {} leases read: {}".format(source, count))
        if not found:
            print("opnsense: no DHCP lease backend answered; falling back to ARP and NDP only")

    reported, skipped = report_hosts(ctx, index, order)
    print("opnsense: reported {} firewall and {} discovered hosts".format(firewall_count, reported))
    if skipped:
        print("opnsense: host limit of {} reached; {} further hosts were not imported".format(
            ctx["max_hosts"], skipped))
    return None

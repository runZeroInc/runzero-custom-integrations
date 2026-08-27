# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-adguard-home",
    "name": "AdGuard Home",
    "type": "inbound",
    "description": "Imports DHCP leases and observed DNS clients from AdGuard Home.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Both client id forms are address-derived. A DHCP address is reassigned, a
    # MAC is randomized per network by every current phone, and neither is a
    # device identifier - so the id must never drive or block a merge, and
    # correlation falls back to the MAC, IP, and hostname on the record.
    "matchBehavior": "no-id-match no-id-break",
    # The appliance is the one record with a stable, non-address-derived id, so
    # its id does drive merges; what must not disqualify a merge is a changed
    # MAC, address, or name, since all three move when the host is re-homed.
    "assetTypeBehavior": {
        "appliance": "no-mac-break no-ip-break no-name-break",
    },
    "params": [
        {
            "key": "url",
            "label": "AdGuard Home URL",
            "type": "url",
            "required": True,
            "placeholder": "http://adguard.example.com:3000",
            "description": "Base URL of the AdGuard Home web interface. The /control/ path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "AdGuard Home web interface user. Sent as the HTTP Basic username on every request.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for that user. Sent as the HTTP Basic password on every request.",
        },
        {
            "key": "collect_dhcp",
            "label": "Collect DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /control/dhcp/status for dynamic and static leases. These are the only records that carry a MAC address.",
        },
        {
            "key": "collect_clients",
            "label": "Collect observed DNS clients",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /control/clients for runtime clients AdGuard Home has seen send a query, plus the persistent client list that names them.",
        },
        {
            "key": "include_persistent_only",
            "label": "Import persistent clients with no observation",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import configured client entries whose only identifier is an address AdGuard Home has never seen. Off by default because a persistent client is a policy rule, not evidence a device exists.",
        },
        {
            "key": "max_clients",
            "label": "Maximum clients",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 0,
            "description": "Cap on the number of client assets imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface")
load("http", "get_json", "basic", "url_parse")
load("kwargs", "get_url_base", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_text', 'dicts')
VENDOR = "adguard-home"
ATTR_PREFIX = "adguard"
ATTR_SEPARATOR = "_"

HEXDIGITS = "0123456789abcdef"

# Addresses that must never reach a network interface. The platform already
# drops loopback, multicast, and unspecified, but it deliberately KEEPS
# link-local, and AdGuard Home reports fe80:: sources for hosts querying over
# IPv6 on the local segment - a range every host invents for itself.
EXCLUDED_V4 = ["127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32", "255.255.255.255/32"]
# ff00::/8 is IPv6 multicast and fe00::/9 is reserved -- neither names a host.
# Both reach here in practice: AdGuard Home reads /etc/hosts, which on a Debian
# base ships ip6-allnodes (ff02::1), ip6-allrouters (ff02::2), ip6-mcastprefix
# (ff00::) and ip6-localnet (fe00::). Confirmed against a real container: those
# became four phantom assets, and fe00:: passed the filter entirely because
# fe80::/10 only covers fe8/fe9/fea/feb.
EXCLUDED_V6 = ["::1/128", "::/128", "fe80::/10", "ff00::/8", "fe00::/9"]

# Names that name no host. AdGuard Home fills a runtime client's name from
# reverse DNS, which commonly returns the resolver's own view of an unnamed
# address, and its DHCP server stores an empty hostname when the client sent no
# option 12.
PLACEHOLDER_NAMES = ["*", "?", "localhost", "localhost.localdomain", "unknown", "none", "null", "-"]

# Interface names that belong to container plumbing rather than to the host.
# AdGuard Home is very often run in Docker beside other containers, and
# /control/dhcp/interfaces enumerates every interface the host has.
VIRTUAL_INTERFACE_PREFIXES = [
    "lo", "docker", "veth", "br-", "virbr", "vnet", "cni", "flannel", "cali",
    "tun", "tap", "wg", "zt", "kube-",
]
def _strings(value):
    """Coerce a field documented as a list of strings into one."""
    if type(value) == "string":
        return [value]
    if type(value) != "list":
        return []
    return [item for item in value if type(item) == "string"]


def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    normalize_mac is deliberately not used here. It clears the locally
    administered bit of the first octet, so aa:bb:cc:dd:ee:ff and
    a8:bb:cc:dd:ee:ff both normalize to the same value. Modern phones and
    laptops randomize their MAC and every randomized address sets that bit, so
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
    first = int(text[0:2], 16)
    # A multicast or broadcast destination is not an endpoint.
    if first % 2 == 1:
        return ""
    if text == "000000000000" or text == "ffffffffffff":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])


def _routable_ip(value):
    """Return the canonical form of a routable IP, or "" when the value is not
    an address or is one that identifies nothing. AdGuard Home reports IPv6
    query sources with a zone suffix on some platforms, so it is removed first.
    """
    text = as_text(value, join=",").strip()
    if not text:
        return ""
    if "%" in text:
        text = text.split("%")[0]
    if "/" in text:
        # A persistent client id may be a CIDR, which names a range rather than
        # a host and is handled by the caller.
        return ""
    addr = ip_address(text)
    if addr == None:
        return ""
    canonical = str(addr)
    excluded = EXCLUDED_V4 if addr.version == 4 else EXCLUDED_V6
    for cidr in excluded:
        if ip_in_network(canonical, cidr):
            return ""
    return canonical


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


def _is_virtual_interface(name):
    """Report whether an interface name belongs to container plumbing."""
    lowered = as_text(name, join=",").strip().lower()
    if not lowered:
        return True
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix):
            rest = lowered[len(prefix):]
            if not rest:
                return True
            if rest[0] in "0123456789-_.":
                return True
    return False


def _appliance_host(base_url):
    """Return the AdGuard Home hostname, which scopes every imported id.

    The scheme and port are dropped so that reaching the same instance on a
    different port does not change the identity of assets already imported.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def fetch(ctx, path):
    """Call one AdGuard Home endpoint. Failures are reported and returned as
    None so a disabled DHCP server or a permission gap cannot end the run."""
    data, err = get_json(ctx["base_url"] + path, **ctx["http_options"])
    if err:
        print("adguard-home: {} failed: {}".format(path, err))
        return None
    return data


def collect_appliance_interfaces(ctx):
    """Return the AdGuard Home host's own interfaces.

    /control/dhcp/interfaces is the only endpoint that reports the host's
    hardware addresses. It answers with a map of interface name to
    {name, hardware_address, flags, gateway_ip, ipv4_addresses,
    ipv6_addresses}, and it is served whether or not the DHCP server is
    running - but not on platforms where DHCP is unsupported, so a failure here
    is degraded detail rather than an error.
    """
    data = fetch(ctx, "/control/dhcp/interfaces")
    if type(data) != "dict":
        return [], []
    netifs = []
    names = []
    for name in sorted(data.keys()):
        entry = data.get(name)
        if type(entry) != "dict":
            continue
        label = as_text(entry.get("name"), join=",") or name
        if _is_virtual_interface(label):
            continue
        ips = []
        for family in ["ipv4_addresses", "ipv6_addresses"]:
            for value in _strings(entry.get(family)):
                routable = _routable_ip(value)
                if routable and routable not in ips:
                    ips.append(routable)
        mac = _mac_key(entry.get("hardware_address"))
        if not mac and not ips:
            continue
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)
            names.append(label)
    return netifs, names


def build_appliance_asset(ctx, status, dhcp):
    """Build the asset for the AdGuard Home host itself.

    /control/status carries the version and the addresses the DNS server is
    bound to; /control/dhcp/interfaces carries the host's own NICs. There is no
    serial and no hostname anywhere in the API, so the name comes from the
    configured URL.
    """
    version = ""
    dns_addresses = []
    if type(status) == "dict":
        version = as_text(status.get("version"), join=",").strip().lstrip("v")
        for value in _strings(status.get("dns_addresses")):
            routable = _routable_ip(value)
            if routable and routable not in dns_addresses:
                dns_addresses.append(routable)

    netifs, interface_names = collect_appliance_interfaces(ctx)

    # A host bound to 0.0.0.0 reports no usable address at all, and one reached
    # by IP has no name. Falling back to the bound addresses and then to the
    # address in the configured URL keeps the appliance correlatable either way.
    hostname = _hostname(ctx["scope"])
    if not netifs:
        fallback = list(dns_addresses)
        if not fallback:
            configured = _routable_ip(ctx["scope"])
            if configured:
                fallback.append(configured)
        nic = network_interface(mac="", ips=fallback)
        if nic:
            netifs.append(nic)

    attrs = {
        "appliance": ctx["scope"],
        "product_version": version,
        "dns_addresses": dns_addresses,
        "interfaces": interface_names,
    }
    if type(status) == "dict":
        attrs["dns_port"] = status.get("dns_port")
        attrs["http_port"] = status.get("http_port")
        attrs["protection_enabled"] = status.get("protection_enabled")
        attrs["running"] = status.get("running")
        attrs["dhcp_available"] = status.get("dhcp_available")
        attrs["language"] = status.get("language")
    if type(dhcp) == "dict":
        attrs["dhcp_enabled"] = dhcp.get("enabled")
        attrs["dhcp_interface"] = dhcp.get("interface_name")

    params = {
        # AdGuard Home publishes no identifier for itself, so the appliance is
        # keyed on the host in the configured URL. That is stable for a fixed
        # credential, and the bound addresses and the hostname are what let it
        # merge with an asset runZero scanned directly, so none of them may
        # disqualify that merge.
        "id": "{}:{}:appliance".format(VENDOR, ctx["scope"]),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": netifs,
        "os": "AdGuard Home",
        "deviceType": "Server",
        "tags": [VENDOR, "dns-server"],
        "assetType": "appliance",
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if version:
        params["osVersion"] = version
    return ImportAsset(**params)


def _record(index, order, key):
    """Return the accumulating record for one client key, creating it on first
    sight."""
    if key not in index:
        index[key] = {
            "key": key,
            "mac": "",
            "ips": [],
            "hostnames": [],
            "sources": [],
            "tags": [],
            "attrs": {},
            "observed": False,
        }
        order.append(key)
    return index[key]


def _merge(record, source, mac, ips, hostnames, attrs):
    """Fold one observation of a client into its accumulating record."""
    if source and source not in record["sources"]:
        record["sources"].append(source)
    if mac and not record["mac"]:
        record["mac"] = mac
    for ip in ips:
        if ip and ip not in record["ips"]:
            record["ips"].append(ip)
    for name in hostnames:
        if name and name not in record["hostnames"]:
            record["hostnames"].append(name)
    for key in attrs:
        value = attrs[key]
        if value == None or value == "":
            continue
        if key not in record["attrs"]:
            record["attrs"][key] = value


def _by_mac(index, order, mac_index, mac):
    """Return the record for a MAC, which is the strongest key AdGuard Home
    offers, creating it on first sight."""
    key = "mac:" + mac
    record = _record(index, order, key)
    record["mac"] = mac
    mac_index[mac] = key
    return record


def _by_ip(index, order, ip_index, mac_index, ip):
    """Return the record that owns an address, preferring one already keyed on
    a MAC so a lease and a query source for the same host stay one asset."""
    existing = ip_index.get(ip)
    if existing:
        return index[existing]
    key = "ip:" + ip
    record = _record(index, order, key)
    ip_index[ip] = key
    return record


def collect_leases(ctx, index, order, ip_index, mac_index, dhcp):
    """Fold the DHCP lease tables into the client index.

    /control/dhcp/status returns {enabled, interface_name, v4, v6, leases,
    static_leases}. Both lease arrays carry {mac, ip, hostname, expires}, which
    is the only place in the API a MAC appears, so these records anchor every
    address they cover.
    """
    if type(dhcp) != "dict":
        return 0, 0
    dynamic = 0
    static = 0
    for source, key in [("dhcp", "leases"), ("dhcp-static", "static_leases")]:
        for entry in dicts(dhcp.get(key)):
            mac = _mac_key(entry.get("mac"))
            ip = _routable_ip(entry.get("ip"))
            if not mac and not ip:
                continue
            if mac:
                record = _by_mac(index, order, mac_index, mac)
                if ip:
                    ip_index[ip] = record["key"]
            else:
                record = _by_ip(index, order, ip_index, mac_index, ip)
            record["observed"] = True
            _merge(record, source, mac, [ip], [_hostname(entry.get("hostname"))], {
                "dhcp_hostname": entry.get("hostname"),
                "dhcp_expires": entry.get("expires"),
                "dhcp_static": "true" if key == "static_leases" else "false",
            })
            if key == "leases":
                dynamic += 1
            else:
                static += 1
    return dynamic, static


def collect_auto_clients(ctx, index, order, ip_index, mac_index, clients):
    """Fold the runtime client list into the client index.

    auto_clients[] elements are {ip, name, source, whois_info}. AdGuard Home
    fills them from whatever told it about the address - rDNS, its own ARP
    table, its DHCP server, or /etc/hosts - so source is recorded rather than
    trusted, and an address is all the identity there is.
    """
    if type(clients) != "dict":
        return 0
    seen = 0
    for entry in dicts(clients.get("auto_clients")):
        ip = _routable_ip(entry.get("ip"))
        if not ip:
            continue
        record = _by_ip(index, order, ip_index, mac_index, ip)
        record["observed"] = True
        whois = entry.get("whois_info")
        attrs = {
            "client_source": entry.get("source"),
            "client_name": entry.get("name"),
        }
        # whois_info is always an object here, and AdGuard Home populates only
        # these three keys; it is empty when the WHOIS lookup is disabled or
        # the address is private.
        if type(whois) == "dict":
            for field in ["orgname", "country", "city"]:
                value = whois.get(field)
                if value != None and value != "":
                    attrs["whois_" + field] = value
        _merge(record, "dns-client", "", [ip], [_hostname(entry.get("name"))], attrs)
        seen += 1
    return seen


def collect_persistent_clients(ctx, index, order, ip_index, mac_index, clients):
    """Fold the configured client list into the client index.

    clients[] elements carry an operator-assigned name and an ids[] array whose
    members are, in AdGuard Home's own words, an IP, a CIDR, a MAC, or a
    ClientID. Only the first and third name a single host; a CIDR names a range
    and a ClientID names a DNS-over-TLS or DNS-over-QUIC session rather than an
    address, so both are kept as attributes and never key an asset.
    """
    if type(clients) != "dict":
        return 0, 0
    named = 0
    created = 0
    for entry in dicts(clients.get("clients")):
        name = as_text(entry.get("name"), join=",").strip()
        macs = []
        ips = []
        other = []
        for value in _strings(entry.get("ids")):
            mac = _mac_key(value)
            if mac:
                macs.append(mac)
                continue
            ip = _routable_ip(value)
            if ip:
                ips.append(ip)
                continue
            other.append(value)

        attrs = {
            "persistent_client": name,
            "persistent_client_ids": _strings(entry.get("ids")),
            "persistent_client_tags": _strings(entry.get("tags")),
            "filtering_enabled": entry.get("filtering_enabled"),
            "safebrowsing_enabled": entry.get("safebrowsing_enabled"),
            "parental_enabled": entry.get("parental_enabled"),
            "blocked_services": _strings(entry.get("blocked_services")),
        }
        if other:
            attrs["persistent_client_other_ids"] = other

        targets = []
        for mac in macs:
            key = mac_index.get(mac)
            if key:
                targets.append(index[key])
            elif ctx["include_persistent_only"]:
                record = _by_mac(index, order, mac_index, mac)
                created += 1
                targets.append(record)
        for ip in ips:
            key = ip_index.get(ip)
            if key:
                targets.append(index[key])
            elif ctx["include_persistent_only"]:
                record = _by_ip(index, order, ip_index, mac_index, ip)
                created += 1
                targets.append(record)

        for record in targets:
            # Neither the entry's other addresses nor its name are propagated
            # onto the record. An operator is free to group several devices
            # under one client entry, so copying its whole ids[] onto each
            # target would give three assets the same three addresses and let
            # runZero merge them into one; and the name is free text such as
            # "Kids tablet" rather than a hostname, so it is recorded as an
            # attribute instead of a name that could correlate unrelated hosts.
            _merge(record, "persistent-client", "", [], [], attrs)
            for tag in _strings(entry.get("tags")):
                if tag not in record["tags"]:
                    record["tags"].append(tag)
            named += 1
    return named, created


def build_client_asset(ctx, record):
    """Convert one merged client record into a runZero asset."""
    nic = network_interface(mac=record["mac"], ips=record["ips"])

    attrs = dict(record["attrs"])
    attrs["appliance"] = ctx["scope"]
    attrs["sources"] = record["sources"]
    attrs["addresses"] = record["ips"]
    if record["mac"]:
        attrs["mac"] = record["mac"]

    tags = [VENDOR, "adguard-observed"]
    for tag in record["tags"]:
        tags.append(tag)

    if record["mac"]:
        # A MAC is the only durable key AdGuard Home publishes and it comes
        # from the DHCP server, which is the one component that sees layer 2.
        asset_id = "{}:{}:client:{}".format(VENDOR, ctx["scope"], record["mac"])
    else:
        # Everything else is an address AdGuard Home saw a query from. It is
        # deterministic, which is what identity needs, but it is not the device.
        asset_id = "{}:{}:client-ip:{}".format(VENDOR, ctx["scope"], record["ips"][0])

    return ImportAsset(
        id=asset_id,
        hostnames=record["hostnames"],
        networkInterfaces=[nic] if nic else [],
        tags=tags,
        # Both id forms above are address-derived, which is the integration-wide
        # policy in CONFIG; only the appliance overrides it.
        assetType="client",
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )


def report_clients(ctx, index, order):
    """Stream the merged client records to runZero in bounded batches."""
    limit = ctx["max_clients"]
    reported = 0
    skipped = 0
    dropped = 0
    for key in order:
        record = index[key]
        # A record with neither a MAC nor an address cannot be keyed and cannot
        # merge with anything, so it is counted rather than invented.
        if not record["mac"] and not record["ips"]:
            dropped += 1
            continue
        if limit and reported >= limit:
            skipped += 1
            continue
        report_asset(build_client_asset(ctx, record))
        reported += 1
    return reported, skipped, dropped


def main(**kwargs):
    base_url = get_url_base(kwargs)
    scope = _appliance_host(base_url)
    if not scope:
        fail("adguard-home: could not determine the host from the configured URL")

    max_clients = get_int(kwargs, "max_clients", default=20000)
    if max_clients < 0:
        max_clients = 0

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Authorization": basic(get_string(kwargs, "username"), get_string(kwargs, "password")),
            "Accept": "application/json",
        }),
        "include_persistent_only": get_bool(kwargs, "include_persistent_only", default=False),
        "max_clients": max_clients,
    }

    status = fetch(ctx, "/control/status")

    dhcp = None
    if get_bool(kwargs, "collect_dhcp", default=True):
        # AdGuard Home answers this endpoint even when its DHCP server is off,
        # and returns 501 on platforms where DHCP is not supported at all, so a
        # failure here is a normal outcome rather than a reason to stop.
        dhcp = fetch(ctx, "/control/dhcp/status")

    clients = None
    if get_bool(kwargs, "collect_clients", default=True):
        clients = fetch(ctx, "/control/clients")

    if status == None and dhcp == None and clients == None:
        print("adguard-home: no endpoint answered; check the URL and credentials")
        return None

    report_assets(build_appliance_asset(ctx, status, dhcp))

    index = {}
    order = []
    ip_index = {}
    mac_index = {}

    dynamic, static = collect_leases(ctx, index, order, ip_index, mac_index, dhcp)
    if dhcp != None:
        print("adguard-home: DHCP leases read: {} dynamic, {} static".format(dynamic, static))

    observed = collect_auto_clients(ctx, index, order, ip_index, mac_index, clients)
    if clients != None:
        print("adguard-home: runtime clients read: {}".format(observed))
        named, created = collect_persistent_clients(ctx, index, order, ip_index, mac_index, clients)
        print("adguard-home: persistent client entries applied: {} ({} created)".format(named, created))

    reported, skipped, dropped = report_clients(ctx, index, order)
    print("adguard-home: reported 1 appliance and {} clients".format(reported))
    if dropped:
        print("adguard-home: {} client records had no address or MAC and were skipped".format(dropped))
    if skipped:
        print("adguard-home: client limit of {} reached; {} further clients were not imported".format(
            ctx["max_clients"], skipped))
    return None

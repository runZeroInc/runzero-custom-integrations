# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-efficientip-solidserver",
    "name": "EfficientIP SOLIDserver",
    "type": "inbound",
    # The unit of import is the assigned IPAM address, enriched with DHCP
    # leases, DHCP reservations, and DNS records. Free addresses are never
    # imported.
    "description": "Imports assigned IPAM addresses from an EfficientIP SOLIDserver DDI appliance, enriched with DHCP lease, DHCP reservation, and DNS data.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The id is a composite of space and address, not a device identity: a
    # DHCP client that moves subnets gets a different one. It is stable enough
    # to keep repeated polls from duplicating assets, but it must not drive or
    # block matching, so correlation falls back to the MAC, IP, and hostnames
    # carried on every record.
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "SOLIDserver URL",
            "type": "url",
            "required": True,
            "placeholder": "https://solidserver.example.com",
            "description": "Base URL of the SOLIDserver appliance. The /rest/ path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "SOLIDserver user with read access to IPAM, DHCP, and DNS modules. Sent base64-encoded in the X-IPM-Username header on every request.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "space",
            "label": "Space name",
            "type": "string",
            "required": False,
            "description": "Import only this IPAM space (site). Leave blank to enumerate and import every space. Deployments with overlapping address space should run one task per space.",
        },
        {
            "key": "include_ipv6",
            "label": "Import IPv6 addresses",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "include_dhcp",
            "label": "Join DHCP leases and reservations",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Join DHCP lease and static reservation records onto matching addresses for MAC, client hostname, lease timing, and OS fingerprint.",
        },
        {
            "key": "include_dns",
            "label": "Join DNS records",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Join A and AAAA records onto matching addresses for additional hostnames. Large DNS estates make this a long walk.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 10000,
            "description": "Rows per request. SOLIDserver documents no server-side default, so an explicit limit is always sent.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("http", "get_json")
load("base64", base64_encode="encode")
load("kwargs", "require", "get_string", "get_int", "get_bool", "get_url_base", "get_http_options")
load("net", "ip_address", "network_interface", "clean_hostnames")
load("time", "from_timestamp")
load("coerce", "as_int")
load("runzero.progress", progress_info="info")

SITE_SERVICE = "ip_site_list"
ADDRESS_SERVICE = "ip_address_list"
ADDRESS6_SERVICE = "ip6_address6_list"
LEASE_SERVICE = "dhcp_range_lease_list"
LEASE6_SERVICE = "dhcp6_lease6_list"
STATIC_SERVICE = "dhcp_static_list"
STATIC6_SERVICE = "dhcp6_static6_list"
DNS_SERVICE = "dns_rr_list"

MAX_HOSTNAMES = 99

def rest_url(base_url, service):
    return base_url + "/rest/" + service

def auth_headers(username, password):
    """SOLIDserver native authentication: both values base64-encoded, one per
    header, on every request."""
    return {
        "X-IPM-Username": base64_encode(username),
        "X-IPM-Password": base64_encode(password),
        "Content-Type": "application/json",
    }

def quote_where(value):
    """Escape a value for a single-quoted WHERE literal by doubling quotes."""
    return str(value or "").replace("'", "''")

def fetch_rows(base_url, http_options, service, where, orderby, page_size, label):
    """Walk one list service and return every row.

    A page shorter than the limit, or a 204 (which get_json surfaces as data
    None with no err), ends the walk.
    """
    rows = []
    offset = 0
    p = pager(label)
    while p.next():
        params = {"limit": str(page_size), "offset": str(offset)}
        if where:
            params["WHERE"] = where
        if orderby:
            params["ORDERBY"] = orderby
        options = dict(http_options)
        options["params"] = params
        data, err = get_json(rest_url(base_url, service), **options)
        if err:
            print("efficientip: {} failed: {}".format(service, err))
            if err.startswith("status 401"):
                print("efficientip: check the username and password and the user's module permissions")
            break
        if data == None:
            break
        if type(data) != "list":
            print("efficientip: {} returned an unexpected {}".format(service, type(data)))
            break
        for row in data:
            if type(row) == "dict":
                rows.append(row)
        if len(data) < page_size:
            break
        offset += page_size
    return rows

def stream_rows(base_url, http_options, service, where, orderby, page_size, label, handler, fatal=False):
    """Walk one list service, calling handler(row) per row instead of
    accumulating, so a large address estate is never held in memory."""
    count = 0
    offset = 0
    p = pager(label)
    while p.next():
        params = {"limit": str(page_size), "offset": str(offset)}
        if where:
            params["WHERE"] = where
        if orderby:
            params["ORDERBY"] = orderby
        options = dict(http_options)
        options["params"] = params
        data, err = get_json(rest_url(base_url, service), **options)
        if err:
            # The IPv4 address service IS the inventory, so its failure ends the
            # task. The IPv6 service and the enrichment reads are not: an
            # install without them still has an estate worth importing.
            if fatal:
                fail("efficientip: {} failed: {}".format(service, err))
            print("efficientip: {} failed: {}".format(service, err))
            break
        if data == None:
            break
        if type(data) != "list":
            print("efficientip: {} returned an unexpected {}".format(service, type(data)))
            break
        for row in data:
            if type(row) == "dict":
                count += handler(row)
        if len(data) < page_size:
            break
        offset += page_size
    return count

def clean_mac(value):
    """Return a usable MAC, dropping SOLIDserver's EIP:-prefixed pseudo-MACs
    minted for reservations that have no real hardware address."""
    mac = str(value or "").strip()
    if not mac or mac.upper().startswith("EIP:"):
        return ""
    return mac

def parse_epoch(value):
    """SOLIDserver serializes every value as a string, including the decimal
    UNIX timestamps on leases. Zero and unparseable values become None."""
    seconds = as_int(value, default=0)
    if seconds <= 0:
        return None
    return from_timestamp(seconds)

HEX_DIGITS = "0123456789abcdefABCDEF"

def v6_from_hex(text):
    """Convert SOLIDserver's bare 32-hex-digit IPv6 column form (ip6_addr,
    dhcplease6_ip6_addr, ...) into colon notation, or return "" when the value
    is not that shape."""
    if len(text) != 32:
        return ""
    for index in range(32):
        if text[index] not in HEX_DIGITS:
            return ""
    groups = []
    for index in range(0, 32, 4):
        groups.append(text[index:index + 4])
    return ":".join(groups)

def canonical_ip(value):
    """Return the canonical text of an address, so join keys agree between the
    long-form IPv6 DNS emits, the forms the IPAM tables hold, and the bare hex
    form some v6 columns use."""
    text = str(value or "").strip()
    if not text:
        return ""
    addr = ip_address(text)
    if addr == None:
        hex_form = v6_from_hex(text)
        if hex_form:
            addr = ip_address(hex_form)
    if addr == None:
        return ""
    return str(addr)

def build_lease_maps(base_url, http_options, page_size, include_v6):
    """Index DHCP leases and reservations by address.

    DHCP services are appliance-global rather than space-scoped, so the join
    is global; in an estate with overlapping address space across spaces the
    joined DHCP details can belong to the twin address in another space.
    """
    leases = {}
    for row in fetch_rows(base_url, http_options, LEASE_SERVICE, "", "", page_size, "eip-leases"):
        ip = canonical_ip(row.get("dhcplease_addr"))
        if ip:
            leases[ip] = row
    if include_v6:
        for row in fetch_rows(base_url, http_options, LEASE6_SERVICE, "", "", page_size, "eip-leases6"):
            ip = canonical_ip(row.get("dhcplease6_ip6_addr"))
            if ip:
                leases[ip] = {
                    "dhcplease_mac_addr": row.get("dhcplease6_mac_addr", ""),
                    "dhcplease_clientname": row.get("dhcplease6_clientname", ""),
                    "dhcplease_first_time": row.get("dhcplease6_first_time", ""),
                    "dhcplease_time": row.get("dhcplease6_time", ""),
                    "dhcplease_end_time": row.get("dhcplease6_end_time", ""),
                    "dhcplease_client_ident": row.get("dhcplease6_client_duid", ""),
                }

    statics = {}
    for row in fetch_rows(base_url, http_options, STATIC_SERVICE, "", "", page_size, "eip-statics"):
        ip = canonical_ip(row.get("dhcphost_addr"))
        if ip:
            statics[ip] = row
    if include_v6:
        for row in fetch_rows(base_url, http_options, STATIC6_SERVICE, "", "", page_size, "eip-statics6"):
            ip = canonical_ip(row.get("dhcphost6_addr"))
            if ip:
                statics[ip] = {
                    "dhcphost_name": row.get("dhcphost6_name", ""),
                    "dhcphost_mac_addr": row.get("dhcphost6_mac_addr", ""),
                    "dhcphost_domain": row.get("dhcphost6_domain", ""),
                    "dhcphost_state": row.get("dhcphost6_state", ""),
                }
    return leases, statics

def build_dns_map(base_url, http_options, page_size):
    """Index A and AAAA record names by canonical address."""
    names = {}
    where = "rr_type='A' OR rr_type='AAAA'"
    for row in fetch_rows(base_url, http_options, DNS_SERVICE, where, "", page_size, "eip-dns"):
        ip = canonical_ip(row.get("value1"))
        name = str(row.get("rr_full_name", "") or "").strip()
        if not ip or not name:
            continue
        existing = names.get(ip, [])
        if name not in existing:
            existing.append(name)
        names[ip] = existing
    return names

def hostnames_for(row, name_field, lease, static, dns_names):
    """Collect the IPAM, DHCP, and DNS names for one address."""
    candidates = [row.get(name_field, "")]
    if static:
        candidates.append(static.get("dhcphost_name", ""))
        candidates.append(static.get("db_hostname", ""))
    if lease:
        candidates.append(lease.get("dhcplease_clientname", ""))
    for name in dns_names:
        candidates.append(name)
    return clean_hostnames(candidates)[:MAX_HOSTNAMES]

def build_asset(row, ip, is_v6, site_name, appliance_host, lease, static, dns_names):
    """Build one ImportAsset from an IPAM address row and its joins."""
    if is_v6:
        mac = clean_mac(row.get("ip6_mac_addr"))
        name_field = "ip6_name"
        subnet_name = str(row.get("subnet6_name", "") or "")
        class_params = str(row.get("ip6_class_parameters", "") or "")
        row_id = str(row.get("ip6_id", "") or "")
    else:
        mac = clean_mac(row.get("mac_addr"))
        name_field = "name"
        subnet_name = str(row.get("subnet_name", "") or "")
        class_params = str(row.get("ip_class_parameters", "") or "")
        row_id = str(row.get("ip_id", "") or "")

    if not mac and static:
        mac = clean_mac(static.get("dhcphost_mac_addr"))
    if not mac and lease:
        mac = clean_mac(lease.get("dhcplease_mac_addr"))

    nic = network_interface(mac=mac, ips=[ip])
    netifs = [nic] if nic else []

    attrs = {
        # The row id is recorded so an operator can follow an asset back into
        # SOLIDserver, but it is not the imported id because a delete-recreate
        # of the same address mints a new one.
        "rowId": row_id,
        "ipAddress": ip,
        "space": site_name,
        "subnet": subnet_name,
        "classParameters": class_params,
    }

    if lease:
        attrs["dhcp"] = {
            "clientName": lease.get("dhcplease_clientname", ""),
            "mac": lease.get("dhcplease_mac_addr", ""),
            "clientIdentifier": lease.get("dhcplease_client_ident", ""),
            "firstTime": lease.get("dhcplease_first_time", ""),
            "lastRenewal": lease.get("dhcplease_time", ""),
            "endTime": lease.get("dhcplease_end_time", ""),
            "fingerbankOS": lease.get("dhcplease_fingerbank_os", ""),
            "macVendor": lease.get("mac_vendor", ""),
            "server": lease.get("dhcp_name", ""),
        }
    if static:
        attrs["reservation"] = {
            "name": static.get("dhcphost_name", ""),
            "mac": static.get("dhcphost_mac_addr", ""),
            "domain": static.get("dhcphost_domain", ""),
            "state": static.get("dhcphost_state", ""),
        }
    if dns_names:
        attrs["dnsNames"] = dns_names

    asset_args = {
        # The space is part of the id because SOLIDserver spaces routinely
        # carry the same RFC 1918 address ranges, and those are different
        # devices. The appliance host keeps two appliances polled into one
        # runZero organization from colliding.
        "id": "efficientip:{}:{}:{}".format(appliance_host, site_name, ip),
        "hostnames": hostnames_for(row, name_field, lease, static, dns_names),
        "networkInterfaces": netifs,
        "tags": ["efficientip", "space:" + site_name.replace(" ", "-")[:64]],
        "customAttributes": to_custom_attributes(attrs, prefix="efficientip", separator="_"),
    }

    first_seen = None
    last_seen = None
    if lease:
        first_seen = parse_epoch(lease.get("dhcplease_first_time"))
        # The lease end time is the future expiry, not an observation, so only
        # the last renewal is evidence the device was seen.
        last_seen = parse_epoch(lease.get("dhcplease_time"))
    if first_seen != None:
        asset_args["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_args)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_sites(base_url, http_options, page_size, only_space):
    """Return the IPAM spaces to walk as a list of (site_id, site_name)."""
    where = ""
    if only_space:
        where = "site_name='{}'".format(quote_where(only_space))
    sites = []
    for row in fetch_rows(base_url, http_options, SITE_SERVICE, where, "", page_size, "eip-sites"):
        site_id = str(row.get("site_id", "") or "")
        site_name = str(row.get("site_name", "") or "")
        if site_id and site_name:
            sites.append((site_id, site_name))
    return sites

def main(**kwargs):
    require(kwargs, "url", "username", "password")
    base_url = get_url_base(kwargs)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    only_space = get_string(kwargs, "space", default="").strip()
    include_v6 = get_bool(kwargs, "include_ipv6", default=True)
    include_dhcp = get_bool(kwargs, "include_dhcp", default=True)
    include_dns = get_bool(kwargs, "include_dns", default=False)
    page_size = get_int(kwargs, "page_size", default=1000)
    if page_size < 1:
        page_size = 1000

    # Hostname only, no port: the id namespace must not change if the
    # appliance is later reached on a different port.
    appliance_host = base_url.split("://")[-1].split("/")[0].split(":")[0].lower()
    http_options = get_http_options(kwargs, headers=auth_headers(username, password))

    sites = fetch_sites(base_url, http_options, page_size, only_space)
    if not sites:
        if only_space:
            print("efficientip: no space named {} was found".format(only_space))
        else:
            print("efficientip: no spaces retrieved")
        return None

    leases = {}
    statics = {}
    if include_dhcp:
        leases, statics = build_lease_maps(base_url, http_options, page_size, include_v6)
        print("efficientip: indexed {} leases and {} reservations".format(len(leases), len(statics)))

    dns_map = {}
    if include_dns:
        dns_map = build_dns_map(base_url, http_options, page_size)
        print("efficientip: indexed DNS names for {} addresses".format(len(dns_map)))

    reported = 0
    for site_id, site_name in sites:
        progress_info("importing space {}".format(site_name))

        def report_v4(row):
            # The list interleaves pseudo-rows describing free gaps with the
            # assigned addresses; only type "ip" rows are devices. The WHERE
            # below filters server-side, and this guard keeps an appliance
            # that ignores the clause from importing its free space.
            if str(row.get("type", "") or "") == "free":
                return 0
            ip = canonical_ip(row.get("hostaddr"))
            if not ip:
                return 0
            return report_asset(build_asset(row, ip, False, site_name, appliance_host,
                                            leases.get(ip), statics.get(ip),
                                            dns_map.get(ip, [])))

        where = "site_id='{}' AND type='ip'".format(quote_where(site_id))
        count = stream_rows(base_url, http_options, ADDRESS_SERVICE, where,
                            "ip_addr", page_size, "eip-addr4", report_v4, fatal=True)
        reported += count
        print("efficientip: space {}: reported {} IPv4 addresses".format(site_name, count))

        if include_v6:
            def report_v6(row):
                if str(row.get("type", "") or "") == "free":
                    return 0
                # Installs differ in whether ip6_address6_list rows carry a
                # ready-made hostaddr; the hex ip6_addr column is the fallback
                # so those rows enrich the import instead of being silently
                # skipped.
                ip = canonical_ip(row.get("hostaddr"))
                if not ip:
                    ip = canonical_ip(row.get("ip6_addr"))
                if not ip:
                    return 0
                return report_asset(build_asset(row, ip, True, site_name, appliance_host,
                                                leases.get(ip), statics.get(ip),
                                                dns_map.get(ip, [])))

            where6 = "site_id='{}'".format(quote_where(site_id))
            count6 = stream_rows(base_url, http_options, ADDRESS6_SERVICE, where6,
                                 "ip6_id", page_size, "eip-addr6", report_v6)
            reported += count6
            print("efficientip: space {}: reported {} IPv6 addresses".format(site_name, count6))

    if not reported:
        print("efficientip: no assets retrieved")
    print("efficientip: reported {} assets".format(reported))
    return None

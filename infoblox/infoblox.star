# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-infoblox",
    "name": "Infoblox NIOS",
    "type": "inbound",
    # The unit of import is the ipv4address object and nothing else. DHCP leases
    # and record:host objects are JOINED onto those addresses for their MAC,
    # client hostname, lease timing, aliases and device type -- neither becomes
    # an asset of its own. The description used to name all three as if they
    # were separate imports, and to imply IPv6 coverage the script does not have.
    "description": "Imports IPv4 IPAM addresses from an Infoblox NIOS Grid over WAPI, enriched with DHCP leases and host records.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The id is a composite of address and view, not a device identity: a
    # DHCP client that moves subnets gets a different one. It is stable
    # enough to keep repeated polls from duplicating assets, but it must
    # not drive or block matching, so correlation falls back to the MAC,
    # IP, and hostnames carried on every record.
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Grid Manager URL",
            "type": "url",
            "required": True,
            "placeholder": "https://gridmaster.example.com",
            "description": "Base URL of the Grid Manager or a Grid member that serves WAPI. The /wapi/<version>/ path is appended automatically.",
        },
        {
            "key": "wapi_version",
            "label": "WAPI version",
            "type": "string",
            "required": False,
            "default": "v2.13.1",
            "placeholder": "v2.13.1",
            "description": "WAPI version segment of the request URL. Must be a version the Grid supports; check https://<grid>/wapidoc/ for the version shipped on the appliance.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "NIOS user with API access. Sent with the password as HTTP Basic credentials on every request.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the NIOS user.",
        },
        {
            "key": "network_view",
            "label": "Network view",
            "type": "string",
            "required": False,
            "description": "Import only this network view. Leave blank to enumerate and import every network view on the Grid. Grids with overlapping address space should run one task per view.",
        },
        {
            "key": "include_leases",
            "label": "Import DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Join DHCP lease records onto the matching addresses for MAC, client hostname, lease timing, and DHCP fingerprint.",
        },
        {
            "key": "include_host_records",
            "label": "Import host records",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Join record:host objects onto the matching addresses for aliases, device vendor, device type, and location.",
        },
        {
            "key": "include_unused_addresses",
            "label": "Import unused addresses",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import every address IPAM knows about instead of only those with status USED. This can emit one asset per address in every managed network.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 10000,
            "description": "Value sent as _max_results on every paged WAPI read. Lower this if the Grid rejects large result sets.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'basic')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_ts')

DEFAULT_WAPI_VERSION = "v2.13.1"
DEFAULT_PAGE_SIZE = 1000

NETWORKVIEW_OBJECT = "networkview"
NETWORK_OBJECT = "network"
ADDRESS_OBJECT = "ipv4address"
LEASE_OBJECT = "lease"
HOST_OBJECT = "record:host"

# Every object below already returns its documented basic fields, so only the
# extras are requested. The request key carries a literal trailing "+", which is
# what asks WAPI to add these to the basic set; plain "_return_fields" replaces
# it and would drop ip_address, network_view, and the rest.
ADDRESS_RETURN_FIELDS = "comment,extattrs,fingerprint"
LEASE_RETURN_FIELDS = ("binding_state,client_hostname,cltt,ends,fingerprint,hardware," +
                       "network,protocol,served_by,starts,uid,username")
HOST_RETURN_FIELDS = ("aliases,comment,device_description,device_location,device_type," +
                      "device_vendor,extattrs,network_view,zone")
NETWORK_RETURN_FIELDS = "comment,extattrs"

# Name of the built-in network view, used only as a fallback so a view that
# comes back without a name can never widen an id to an empty scope.
DEFAULT_NETWORK_VIEW = "default"

# An address can carry more than one lease row over time; the most current
# binding wins, then the most recent client transaction time.
LEASE_STATE_RANK = {
    "ACTIVE": 3,
    "STATIC": 2,
    "BACKUP": 1,
}

# DHCP fingerprints are free-form vendor strings, so only the substrings that
# name a device class outright are promoted to deviceType. Anything else stays
# in the custom attributes and the tag, where it cannot misclassify an asset.
FINGERPRINT_DEVICE_TYPES = [
    ("printer", "Printer"),
    ("ip phone", "IP Phone"),
    ("voip", "IP Phone"),
    ("ip camera", "IP Camera"),
    ("access point", "Wireless Access Point"),
    ("firewall", "Firewall"),
    ("router", "Router"),
]

MAX_HOSTNAMES = 99
MAX_TAG_LENGTH = 64

# get_json performs a single attempt unless a retry budget is supplied, so the
# transient-status list and Retry-After handling stay inert without this.
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0


def _grid_host(base_url):
    """Return the Grid hostname, which is the scope every imported id is under.

    The scheme is dropped so that switching the configured URL between http and
    https does not change the identity of already-imported assets.
    """
    return base_url.split("://")[-1]


def _wapi_base(base_url, wapi_version):
    """Return the WAPI base URL, e.g. https://grid.example.com/wapi/v2.13.1/."""
    version = wapi_version.strip().replace("/", "")
    if not version:
        version = DEFAULT_WAPI_VERSION
    if not version.startswith("v"):
        version = "v" + version
    return base_url + "/wapi/" + version + "/"


def _auth_hint(err):
    """Print a credential hint for the statuses that mean WAPI rejected the user."""
    if err.startswith("status 401") or err.startswith("status 403"):
        print("infoblox: check the username and password and that the NIOS user has API access")


def _first_params(page_size, return_fields, filters):
    """Build the first-page query for a paged WAPI object read."""
    params = {
        "_return_as_object": "1",
        "_paging": "1",
        "_max_results": str(page_size),
    }
    if return_fields:
        params["_return_fields+"] = return_fields
    for key in filters:
        params[key] = filters[key]
    return params


def _page_params(page_id):
    """Build the follow-up query for a paged WAPI object read.

    WAPI resumes a paged read from the page id alone; the original search
    parameters are held server-side and re-sending them is not required.
    """
    return {
        "_return_as_object": "1",
        "_page_id": page_id,
    }


def _get_page(url, http_options, params):
    """Fetch one WAPI page and return (records, next_page_id, err).

    _return_as_object=1 wraps the rows in a `result` list and adds
    `next_page_id` on every page but the last, which is the documented
    termination condition for a paged read.
    """
    options = dict(http_options)
    options["params"] = params
    data, err = get_json(url, **options)
    if err:
        return [], "", err
    data = data or {}
    if type(data) != "dict":
        return [], "", "unexpected response of type " + type(data)
    records = data.get("result", [])
    if type(records) != "list":
        return [], "", "unexpected result of type " + type(records)
    return records, str(data.get("next_page_id", "") or ""), None


def _parse_epoch(value):
    """Convert a WAPI Timestamp, which is epoch seconds, into a time object.

    parse_ts treats a non-positive or unparseable value as absent and clamps
    future values to now. The clamp is what keeps the record alive: an active
    lease's `ends` is in the future by definition, and the platform silently
    drops any record whose lastSeenTS is ahead of now. The raw values survive
    in the infoblox_dhcp_* custom attributes."""
    return parse_ts(value)


def _extattrs(value):
    """Flatten a WAPI extensible-attribute map of {name: {"value": v}} to {name: v}."""
    if type(value) != "dict":
        return {}
    flat = {}
    for name in value:
        entry = value[name]
        if type(entry) == "dict":
            flat[name] = entry.get("value", "")
        else:
            flat[name] = entry
    return flat


def _lease_rank(record):
    """Rank a lease so the most current binding wins when an address has several."""
    state = str(record.get("binding_state", "") or "").upper()
    stamp = record.get("cltt")
    if type(stamp) != "int":
        stamp = record.get("ends")
    if type(stamp) != "int":
        stamp = 0
    return (LEASE_STATE_RANK.get(state, 0), stamp)


def _fingerprint_device_type(fingerprint):
    """Return a device type for the DHCP fingerprints that name one outright."""
    lowered = fingerprint.lower()
    for entry in FINGERPRINT_DEVICE_TYPES:
        if entry[0] in lowered:
            return entry[1]
    return ""


def _hostnames(record, lease, host):
    """Return the DNS and DHCP names for an address, de-duplicated case-insensitively."""
    candidates = []
    for name in record.get("names", []) or []:
        candidates.append(name)
    if host:
        candidates.append(host.get("name", ""))
        for alias in host.get("aliases", []) or []:
            candidates.append(alias)
    if lease:
        candidates.append(lease.get("client_hostname", ""))

    names = []
    seen = {}
    for value in candidates:
        value = str(value or "").strip()
        if not value:
            continue
        if seen.get(value.lower(), False):
            continue
        seen[value.lower()] = True
        names.append(value)
    return names[:MAX_HOSTNAMES]


def _tags(record, view, fingerprint):
    """Return the search tags for an address, including its network view."""
    tags = ["infoblox", "network-view:" + view]
    for usage in record.get("usage", []) or []:
        usage = str(usage or "").strip().lower()
        if usage:
            tags.append("usage:" + usage)
    if record.get("is_conflict", False):
        tags.append("infoblox-conflict")
    if fingerprint:
        tags.append("dhcp-fingerprint:" + fingerprint[:MAX_TAG_LENGTH])
    return tags


def build_asset(record, ip, view, grid_host, network, lease, host):
    """Build one ImportAsset from an ipv4address row and its optional joins."""
    mac = str(record.get("mac_address", "") or "")
    if not mac and lease:
        mac = str(lease.get("hardware", "") or "")
    nic = network_interface(mac=mac, ips=[ip])
    netifs = [nic] if nic else []

    # The address object carries its own DHCP fingerprint; the lease copy is
    # used only when IPAM has not recorded one for the address itself.
    fingerprint = str(record.get("fingerprint", "") or "")
    if not fingerprint and lease:
        fingerprint = str(lease.get("fingerprint", "") or "")

    attrs = {
        # _ref is the WAPI object reference. It is recorded so an operator can
        # follow an asset back into Grid Manager, but it is not used as the
        # imported id because renaming the underlying object changes it.
        "ref": record.get("_ref", ""),
        "ip_address": ip,
        "network_view": view,
        "network": record.get("network", ""),
        "status": record.get("status", ""),
        "usage": record.get("usage", []),
        "types": record.get("types", []),
        "objects": record.get("objects", []),
        "is_conflict": record.get("is_conflict", False),
        "lease_state": record.get("lease_state", ""),
        "dhcp_client_identifier": record.get("dhcp_client_identifier", ""),
        "fingerprint": fingerprint,
        "comment": record.get("comment", ""),
        "ea": _extattrs(record.get("extattrs")),
    }

    if network:
        attrs["network_comment"] = network.get("comment", "")
        attrs["network_ea"] = _extattrs(network.get("extattrs"))

    if lease:
        # Named "dhcp" rather than "lease" so the flattened keys cannot collide
        # with the address object's own lease_state field.
        attrs["dhcp"] = {
            "binding_state": lease.get("binding_state", ""),
            "hardware": lease.get("hardware", ""),
            "client_hostname": lease.get("client_hostname", ""),
            "network": lease.get("network", ""),
            "protocol": lease.get("protocol", ""),
            "served_by": lease.get("served_by", ""),
            "uid": lease.get("uid", ""),
            "username": lease.get("username", ""),
            "fingerprint": lease.get("fingerprint", ""),
            "starts": lease.get("starts", ""),
            "ends": lease.get("ends", ""),
            "cltt": lease.get("cltt", ""),
        }

    if host:
        attrs["host"] = {
            "name": host.get("name", ""),
            # `view` on record:host is the DNS view, which is a different
            # namespace from the network view used to scope the id.
            "dns_view": host.get("view", ""),
            "zone": host.get("zone", ""),
            "device_type": host.get("device_type", ""),
            "device_vendor": host.get("device_vendor", ""),
            "device_description": host.get("device_description", ""),
            "device_location": host.get("device_location", ""),
            "aliases": host.get("aliases", []),
            "comment": host.get("comment", ""),
            "ea": _extattrs(host.get("extattrs")),
        }

    asset_args = {
        # The network view is part of the id because a Grid routinely carries
        # the same RFC 1918 address in several views, and those are different
        # devices. This is the same tuple WAPI itself uses for the name part of
        # an ipv4address reference.
        "id": "infoblox:{}:{}:{}".format(grid_host, view, ip),
        "hostnames": _hostnames(record, lease, host),
        "networkInterfaces": netifs,
        "tags": _tags(record, view, fingerprint),
        "customAttributes": to_custom_attributes(attrs, prefix="infoblox", separator="_"),    }

    # An operator-maintained device_type on the host record is a deliberate
    # classification, so it outranks the fingerprint guess.
    device_type = ""
    if host:
        device_type = str(host.get("device_type", "") or "").strip()
    if not device_type:
        device_type = _fingerprint_device_type(fingerprint)
    if device_type:
        asset_args["deviceType"] = device_type

    if host:
        vendor = str(host.get("device_vendor", "") or "").strip()
        if vendor:
            asset_args["manufacturer"] = vendor

    # IPAM records no lifecycle timestamps on an address, so the only first and
    # last seen evidence comes from a joined DHCP lease.
    first_seen = None
    last_seen = None
    if lease:
        first_seen = _parse_epoch(lease.get("starts"))
        last_seen = _parse_epoch(lease.get("cltt"))
        if not last_seen:
            last_seen = _parse_epoch(lease.get("ends"))
    if first_seen:
        asset_args["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_args)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def fetch_network_views(base, http_options, page_size):
    """Return the name of every network view configured on the Grid.

    Views are enumerated rather than assumed because a WAPI address read has to
    name the view it applies to, and an unqualified read is scoped to whichever
    view the Grid treats as default.
    """
    views = []
    url = base + NETWORKVIEW_OBJECT
    params = _first_params(page_size, "", {})
    _pager1 = pager("infoblox-1")
    while _pager1.next():
        records, page_id, err = _get_page(url, http_options, params)
        if err:
            _auth_hint(err)
            # Every later read is scoped by a network view, so a failed view
            # list is the run and not a NIOS with no views defined.
            fail("infoblox: failed to list network views: {}".format(err))
        for record in records:
            if type(record) != "dict":
                continue
            name = str(record.get("name", "") or "")
            if name:
                views.append(name)
        if not page_id:
            break
        params = _page_params(page_id)
    return views


def fetch_networks(base, http_options, page_size, view):
    """Return the IPv4 networks defined in one network view.

    An ipv4address read has to be filtered by network or by address, so the
    networks are enumerated first and each one is then walked in turn.
    """
    networks = []
    url = base + NETWORK_OBJECT
    params = _first_params(page_size, NETWORK_RETURN_FIELDS, {"network_view": view})
    _pager2 = pager("infoblox-2")
    while _pager2.next():
        records, page_id, err = _get_page(url, http_options, params)
        if err:
            print("infoblox: failed to list networks in view {}:".format(view), err)
            _auth_hint(err)
            return networks
        for record in records:
            if type(record) != "dict":
                continue
            if str(record.get("network", "") or ""):
                networks.append(record)
        if not page_id:
            break
        params = _page_params(page_id)
    return networks


def fetch_lease_map(base, http_options, page_size, view):
    """Index the DHCP leases of one network view by leased address."""
    leases = {}
    url = base + LEASE_OBJECT
    params = _first_params(page_size, LEASE_RETURN_FIELDS, {"network_view": view})
    _pager3 = pager("infoblox-3")
    while _pager3.next():
        records, page_id, err = _get_page(url, http_options, params)
        if err:
            print("infoblox: failed to list leases in view {}:".format(view), err)
            _auth_hint(err)
            return leases
        for record in records:
            if type(record) != "dict":
                continue
            address = str(record.get("address", "") or "")
            if not address:
                continue
            existing = leases.get(address)
            if existing and _lease_rank(existing) >= _lease_rank(record):
                continue
            leases[address] = record
        if not page_id:
            break
        params = _page_params(page_id)
    return leases


def fetch_host_map(base, http_options, page_size, view):
    """Index the host records of one network view by each of their IPv4 addresses.

    A host record can hold several addresses, so one record is indexed under
    each of them; the addresses themselves remain the unit of import.
    """
    hosts = {}
    url = base + HOST_OBJECT
    params = _first_params(page_size, HOST_RETURN_FIELDS, {"network_view": view})
    _pager4 = pager("infoblox-4")
    while _pager4.next():
        records, page_id, err = _get_page(url, http_options, params)
        if err:
            print("infoblox: failed to list host records in view {}:".format(view), err)
            _auth_hint(err)
            return hosts
        for record in records:
            if type(record) != "dict":
                continue
            for entry in record.get("ipv4addrs", []) or []:
                if type(entry) != "dict":
                    continue
                address = str(entry.get("ipv4addr", "") or "")
                if not address or address in hosts:
                    continue
                hosts[address] = record
        if not page_id:
            break
        params = _page_params(page_id)
    return hosts


def fetch_and_report_addresses(base, http_options, page_size, grid_host, view, network,
                               lease_map, host_map, only_used):
    """Fetch and stream one network's addresses a page at a time so the whole
    address space is never held in memory at once."""
    reported = 0
    skipped = 0
    url = base + ADDRESS_OBJECT
    cidr = str(network.get("network", "") or "")
    filters = {"network": cidr, "network_view": view}
    if only_used:
        filters["status"] = "USED"
    params = _first_params(page_size, ADDRESS_RETURN_FIELDS, filters)

    _pager5 = pager("infoblox-5")

    while _pager5.next():
        records, page_id, err = _get_page(url, http_options, params)
        if err:
            print("infoblox: failed to fetch addresses for {} in view {}:".format(cidr, view), err)
            _auth_hint(err)
            return reported, skipped

        assets = []
        for record in records:
            if type(record) != "dict":
                skipped += 1
                continue
            ip = str(record.get("ip_address", "") or "")
            if not ip:
                skipped += 1
                print("infoblox: skipping address with no ip_address in view {} network {}".format(view, cidr))
                continue
            assets.append(build_asset(record, ip, view, grid_host, network,
                                      lease_map.get(ip), host_map.get(ip)))
        if assets:
            reported += report_assets(assets)

        if not page_id:
            break
        params = _page_params(page_id)
    return reported, skipped


def main(**kwargs):
    base_url = get_url_base(kwargs)
    grid_host = _grid_host(base_url)
    base = _wapi_base(base_url, get_string(kwargs, "wapi_version", default=DEFAULT_WAPI_VERSION))
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    only_view = get_string(kwargs, "network_view", default="").strip()
    include_leases = get_bool(kwargs, "include_leases", default=True)
    include_host_records = get_bool(kwargs, "include_host_records", default=False)
    only_used = not get_bool(kwargs, "include_unused_addresses", default=False)
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE

    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(username, password),
        "Accept": "application/json",
    })
    http_options["retries"] = HTTP_RETRIES
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    views = [only_view]
    if not only_view:
        views = fetch_network_views(base, http_options, page_size)
    if not views:
        print("infoblox: no network views retrieved")
        return None

    reported = 0
    for view in views:
        view = view or DEFAULT_NETWORK_VIEW
        lease_map = {}
        if include_leases:
            lease_map = fetch_lease_map(base, http_options, page_size, view)
        host_map = {}
        if include_host_records:
            host_map = fetch_host_map(base, http_options, page_size, view)

        networks = fetch_networks(base, http_options, page_size, view)
        print("infoblox: view {}: {} networks, {} leases, {} host addresses".format(
            view, len(networks), len(lease_map), len(host_map)))

        view_reported = 0
        view_skipped = 0
        for network in networks:
            count, dropped = fetch_and_report_addresses(base, http_options, page_size,
                                                        grid_host, view, network,
                                                        lease_map, host_map, only_used)
            view_reported += count
            view_skipped += dropped
        reported += view_reported
        print("infoblox: view {}: reported {} addresses".format(view, view_reported))
        if view_skipped:
            print("infoblox: view {}: skipped {} records with no usable address".format(view, view_skipped))

    if not reported:
        print("infoblox: no assets retrieved")
    return None

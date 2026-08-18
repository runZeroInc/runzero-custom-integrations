# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-sophos-central",
    "name": "Sophos Central",
    "type": "inbound",
    "description": "Imports managed endpoints from Sophos Central.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The endpoint id survives rename, reimage, and address changes, while
    # these are EDR-managed laptops whose MAC, IP, and hostname churn with
    # every wireless network, VPN session, and MAC randomization cycle.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Sophos Central API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://api.central.sophos.com",
            "description": "Common API URL used for the whoami and tenant lookups. The per-tenant data region host is discovered automatically.",
        },
        {
            "key": "auth_url",
            "label": "Sophos ID authentication URL",
            "type": "url",
            "required": False,
            "default": "https://id.sophos.com",
            "description": "Base URL of the Sophos ID OAuth2 token service.",
        },
        {
            "key": "tenant_ids",
            "label": "Tenant IDs",
            "type": "string",
            "required": False,
            "description": "Comma-separated tenant IDs to import. Only used with partner or organization credentials; leave blank to import every managed tenant. Ignored for tenant-level credentials.",
        },
        {
            "key": "client_id",
            "label": "API credential client ID",
            "type": "string",
            "required": True,
            "description": "Client ID of the Sophos Central API credential or service principal.",
        },
        {
            "key": "client_secret",
            "label": "API credential client secret",
            "type": "secret",
            "required": True,
            "description": "Client secret issued alongside the client ID. It is shown only once when the credential is created.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 500,
            "description": "Endpoints requested per page. Sophos publishes its own ceiling as pages.maxSize in every response and this value is lowered automatically to match it.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "network_interface", "ip_in_network")
load("http", "get_json", "post_json", "bearer", "url_encode")
load("time", "now", "parse_time", 'parse_ts')
load("re", re_match="match")
load("kwargs", "require", "get_string", "get_int", "get_list", "get_url_base", "get_http_options")

load('coerce', 'as_dict', 'as_list')
TOKEN_PATH = "/api/v2/oauth2/token"
WHOAMI_PATH = "/whoami/v1"
ENDPOINTS_PATH = "/endpoint/v1/endpoints"

# The route reference gives no numeric ceiling for pageSize. Observed responses
# report "maxSize": 500 while the docs examples show 100, so the request starts
# conservatively and is widened or narrowed to whatever pages.maxSize reports.
MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100
# The partner and organization tenant lists are page/pageSize paginated rather
# than cursor paginated. 50 is their documented default page size.
TENANT_PAGE_SIZE = 50
# Without a view the API returns "summary"; "basic" is only id, type, tenant,
# and hostname. "full" is the only view that carries the addresses, health
# detail, assigned products, and group this import maps.
ENDPOINT_VIEW = "full"

# Sophos enforces 100 requests per minute (bursting to 300) and 200,000 per day
# across every API, per credential, and answers with 429. It documents no
# Retry-After header and prescribes exponential backoff instead, so the shared
# helper's backoff is widened rather than left at one second.
RETRY_BACKOFF = 2.0

MAX_INTERFACES = 32
MAX_TAGS = 99

ATTR_PREFIX = "sophos_central"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# The endpoint type is a coarse class with three documented values: "computer",
# "server", and "securityVm" (which Sophos records as no longer used).
# "computer" covers desktops and laptops without distinguishing them, so it is
# deliberately left unmapped rather than asserting a hardware form factor
# runZero fingerprints better itself.
DEVICE_TYPES = {
    "server": "Server",
    "securityVm": "Virtual Machine",
}

# Agent-reported address lists routinely contain nothing but loopback or
# link-local addresses. Letting those reach a NetworkInterface makes every such
# host share an address and invites runZero to merge the whole estate onto one
# asset, so they are filtered out and kept as custom attributes instead.
EXCLUDED_NETWORKS = [
    "127.0.0.0/8",
    "0.0.0.0/32",
    "169.254.0.0/16",
    "::1/128",
    "::/128",
    "fe80::/10",
]

TIMESTAMP_ZONED_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"


def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()
def _truthy(value):
    """Read a flag that arrives as either a JSON bool or a "true"/"false" string."""
    if type(value) == "bool":
        return value
    return _clean(value).lower() == "true"


def _routable(value):
    """Reject loopback, unspecified, and link-local addresses."""
    for cidr in EXCLUDED_NETWORKS:
        if ip_in_network(value, cidr):
            return False
    return True
def _os_version(os_info):
    """Join the OS version components Sophos reports as separate numbers."""
    parts = []
    for key in ["majorVersion", "minorVersion", "build"]:
        value = os_info.get(key)
        if value == None or value == "":
            break
        parts.append(str(value))
    return ".".join(parts)


def _service_summary(services):
    """Summarize the Sophos component services that are not running."""
    stopped = []
    total = 0
    for detail in as_list(services.get("serviceDetails")):
        if type(detail) != "dict":
            continue
        total += 1
        if _clean(detail.get("status")).lower() != "running":
            name = _clean(detail.get("name"))
            if name:
                stopped.append(name)
    return stopped, total


def build_network_interfaces(record):
    """Build interfaces from the parallel address and MAC lists.

    Sophos publishes macAddresses, ipv4Addresses, and ipv6Addresses as three
    independent lists with no documented correlation between them, so pairing a
    MAC with an address would assert a binding the API never states. The usable
    addresses go on one interface of their own and each MAC gets an interface
    carrying only itself.
    """
    ips = []
    for key in ["ipv4Addresses", "ipv6Addresses"]:
        for value in as_list(record.get(key)):
            text = _clean(value)
            if text and _routable(text):
                ips.append(text)

    netifs = []
    if ips:
        nic = network_interface(ips=ips)
        if nic:
            netifs.append(nic)
    for value in as_list(record.get("macAddresses"))[:MAX_INTERFACES]:
        mac = _clean(value)
        if not mac:
            continue
        nic = network_interface(mac=mac)
        if nic:
            netifs.append(nic)
    return netifs


def build_asset(tenant_id, record):
    """Convert one Sophos Central endpoint into a runZero ImportAsset."""
    endpoint_id = _clean(record.get("id"))
    if not endpoint_id:
        print("sophos-central: skipping endpoint with no id: hostname=" + _clean(record.get("hostname")))
        return None

    os_info = as_dict(record.get("os"))
    health = as_dict(record.get("health"))
    services = as_dict(health.get("services"))
    threats = as_dict(health.get("threats"))
    person = as_dict(record.get("associatedPerson"))
    group = as_dict(record.get("group"))
    lockdown = as_dict(record.get("lockdown"))
    cloud = as_dict(record.get("cloud"))
    isolation = as_dict(record.get("isolation"))
    encryption = as_dict(record.get("encryption"))

    # groupHierarchy runs from the endpoint's own group up to the top-level
    # group, so it is reversed into a readable top-down path.
    hierarchy = []
    for entry in as_list(record.get("groupHierarchy"))[::-1]:
        if type(entry) != "dict":
            continue
        name = _clean(entry.get("name"))
        if name:
            hierarchy.append(name)

    product_codes = []
    product_versions = []
    for product in as_list(record.get("assignedProducts")):
        if type(product) != "dict":
            continue
        code = _clean(product.get("code"))
        if not code:
            continue
        product_codes.append(code)
        version = _clean(product.get("version"))
        status = _clean(product.get("status"))
        product_versions.append("{}={}/{}".format(code, version or "unknown", status or "unknown"))

    stopped_services, service_count = _service_summary(services)

    serial_number = _clean(record.get("serialNumber"))

    attrs = {
        # These are the Sophos agent components, not a third-party software
        # inventory; the Endpoint API publishes no installed-application list.
        "assigned_products": product_codes,
        "assigned_product_versions": product_versions,
        "associated_person_id": _clean(person.get("id")),
        "associated_person_name": _clean(person.get("name")),
        "associated_person_via_login": _clean(person.get("viaLogin")),
        "cloned": record.get("cloned"),
        "cloud_instance_id": _clean(cloud.get("instanceId")),
        "cloud_provider": _clean(cloud.get("provider")),
        "encryption_overall_status": _clean(encryption.get("overallStatus")),
        "endpoint_id": endpoint_id,
        "group_hierarchy": " / ".join(hierarchy),
        "group_id": _clean(group.get("id")),
        "group_name": _clean(group.get("name")),
        "health_overall": _clean(health.get("overall")),
        "health_services": _clean(services.get("status")),
        "health_services_not_running": stopped_services,
        "health_services_total": service_count,
        "health_threats": _clean(threats.get("status")),
        # The raw lists are preserved because the interfaces above deliberately
        # drop loopback and link-local addresses.
        "ipv4_addresses": as_list(record.get("ipv4Addresses")),
        "ipv6_addresses": as_list(record.get("ipv6Addresses")),
        "isolation_admin": isolation.get("adminIsolated"),
        "isolation_self": isolation.get("selfIsolated"),
        "isolation_status": _clean(isolation.get("status")),
        "last_agent_update_at": _clean(record.get("lastAgentUpdateAt")),
        "last_os_update_at": _clean(record.get("lastOsUpdateAt")),
        "last_seen_at": _clean(record.get("lastSeenAt")),
        "lockdown_status": _clean(lockdown.get("status")),
        "mac_addresses": as_list(record.get("macAddresses")),
        "online": record.get("online"),
        "os_build": os_info.get("build"),
        "os_is_server": os_info.get("isServer"),
        "os_platform": _clean(os_info.get("platform")),
        "serial_number": serial_number,
        "tamper_protection_enabled": record.get("tamperProtectionEnabled"),
        "tamper_protection_supported": record.get("tamperProtectionSupported"),
        "tenant_id": tenant_id,
        "type": _clean(record.get("type")),
    }

    tags = ["sophos-central"]
    overall = _clean(health.get("overall"))
    if overall:
        tags.append("health:" + overall)
    group_name = _clean(group.get("name"))
    if group_name:
        tags.append("group:" + group_name)
    if serial_number:
        tags.append("serial:" + serial_number)
    if record.get("tamperProtectionEnabled") != None and not _truthy(record.get("tamperProtectionEnabled")):
        tags.append("tamper-protection:disabled")
    if _clean(isolation.get("status")) == "isolated":
        tags.append("isolated")
    # Endpoint tags are the tenant's own key:value labels, capped at 15 by the
    # API, and already carry a rendered "key:value" displayString.
    for entry in as_list(record.get("tags")):
        if type(entry) != "dict":
            continue
        label = _clean(entry.get("displayString"))
        if not label:
            key = _clean(entry.get("key"))
            if not key:
                continue
            label = "{}:{}".format(key, _clean(entry.get("value")))
        tags.append(label)

    params = {
        # The endpoint UUID is unique within a tenant, and one data region host
        # serves many tenants, so the tenant is part of the identity.
        "id": "sophos-central:{}:{}".format(tenant_id, endpoint_id),
        "hostnames": [_clean(record.get("hostname"))],
        "networkInterfaces": build_network_interfaces(record),
        "tags": tags[:MAX_TAGS],        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                 separator=ATTR_SEPARATOR),
    }

    os_name = _clean(os_info.get("name")) or _clean(os_info.get("platform"))
    if os_name:
        params["os"] = os_name
    os_version = _os_version(os_info)
    if os_version:
        params["osVersion"] = os_version

    endpoint_type = _clean(record.get("type"))
    device_type = DEVICE_TYPES.get(endpoint_type, "")
    if not device_type and _truthy(os_info.get("isServer")):
        device_type = "Server"
    if device_type:
        params["deviceType"] = device_type

    asset = ImportAsset(**params)
    last_seen = parse_ts(record.get("lastSeenAt"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(tenant_id, records):
    """Convert one page of endpoint records into ImportAsset objects."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        asset = build_asset(tenant_id, record)
        if asset:
            assets.append(asset)
    return assets


def fetch_access_token(auth_url, client_id, client_secret, config_kwargs):
    """Exchange Sophos Central API credentials for a bearer token."""
    options = get_http_options(config_kwargs, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    options["retry_backoff"] = RETRY_BACKOFF

    body = url_encode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        # Sophos requires the literal scope "token" for this grant.
        "scope": "token",
    })
    data, err = post_json(auth_url + TOKEN_PATH, body=bytes(body), **options)
    if err:
        print("sophos-central: failed to obtain an access token:", err)
        return ""

    data = data or {}
    token = _clean(data.get("access_token"))
    if not token:
        print("sophos-central: token response contained no access_token")
    return token


def fetch_whoami(base_url, http_options):
    """Identify the credential and discover its API hosts.

    Returns (id, id_type, data_region_host, global_host). The data region host
    is the regional base URL every tenant-scoped call must use; it is only
    populated for tenant-level credentials.
    """
    data, err = get_json(base_url + WHOAMI_PATH, **http_options)
    if err:
        print("sophos-central: failed to identify the credential:", err)
        return "", "", "", ""

    data = data or {}
    hosts = as_dict(data.get("apiHosts"))
    return (_clean(data.get("id")), _clean(data.get("idType")).lower(),
            _clean(hosts.get("dataRegion")), _clean(hosts.get("global")))


def fetch_tenants(global_url, http_options, id_type, entity_id, wanted):
    """List the tenants a partner or organization credential manages.

    Each tenant carries its own apiHost, which is the regional base URL that
    tenant's data must be read from.
    """
    tenants = []
    seen = {}
    # The header name is X-Partner-ID or X-Organization-ID depending on which
    # kind of credential whoami reported.
    options = {}
    for key, value in http_options.items():
        options[key] = value
    headers = {}
    for key, value in as_dict(http_options.get("headers")).items():
        headers[key] = value
    headers["X-" + id_type.capitalize() + "-ID"] = entity_id
    options["headers"] = headers

    path = "/{}/v1/tenants".format(id_type)
    _pager1 = pager("sophos-central-1")
    while _pager1.next():
        page = _pager1.page
        data, err = get_json(global_url + path,
                             params={"page": page, "pageSize": TENANT_PAGE_SIZE,
                                     "pageTotal": "true"},
                             **options)
        if err:
            print("sophos-central: failed to list {} tenants:".format(id_type), err)
            return tenants

        data = data or {}
        items = as_list(data.get("items"))
        if not items:
            break

        for item in items:
            if type(item) != "dict":
                continue
            tenant_id = _clean(item.get("id"))
            if not tenant_id or tenant_id in seen:
                continue
            if wanted and tenant_id not in wanted:
                continue
            api_host = _clean(item.get("apiHost"))
            if not api_host:
                print("sophos-central: skipping tenant with no apiHost: id=" + tenant_id)
                continue
            seen[tenant_id] = True
            tenants.append({"id": tenant_id, "api_host": api_host,
                            "name": _clean(item.get("name"))})

        # With pageTotal=true the envelope carries "total" as the page count
        # (17 items at size 2 is reported as total 9). Trust it when present,
        # because a server that clamps pageSize below the requested value would
        # otherwise look like the last page on every request.
        pages = as_dict(data.get("pages"))
        total = pages.get("total")
        if type(total) == "int":
            if page >= total:
                break
        elif len(items) < TENANT_PAGE_SIZE:
            break
    return tenants


def fetch_and_report_endpoints(tenant, http_options, page_size):
    """Fetch and stream one tenant's endpoints a page at a time so the full
    inventory is never held in memory at once."""
    reported = 0
    from_key = ""

    options = {}
    for key, value in http_options.items():
        options[key] = value
    headers = {}
    for key, value in as_dict(http_options.get("headers")).items():
        headers[key] = value
    headers["X-Tenant-ID"] = tenant["id"]
    options["headers"] = headers

    _pager2 = pager("sophos-central-2")

    while _pager2.next():
        params = {"pageSize": page_size, "view": ENDPOINT_VIEW}
        if from_key:
            # pageFromKey takes the opaque nextKey from the previous page. It
            # is a key, not a URL, so params stays intact across pages.
            params["pageFromKey"] = from_key

        data, err = get_json(tenant["api_host"] + ENDPOINTS_PATH, params=params, **options)
        if err:
            print("sophos-central: failed to fetch endpoints for tenant {}:".format(tenant["id"]), err)
            return reported

        data = data or {}
        items = as_list(data.get("items"))
        if not items:
            break

        reported += report_assets(build_assets(tenant["id"], items))

        pages = as_dict(data.get("pages"))
        # Every response publishes the ceiling the route will actually honor.
        max_size = pages.get("maxSize")
        if type(max_size) == "int" and max_size > 0 and max_size < page_size:
            print("sophos-central: lowering page size to the reported maximum of {}".format(max_size))
            page_size = max_size

        # nextKey is absent once there are no more pages; it is the documented
        # termination condition and pages.total is not used for it.
        next_key = _clean(pages.get("nextKey"))
        if not next_key:
            break
        if next_key == from_key:
            # A cursor that never advances would otherwise re-fetch page one
            # until the page ceiling is hit.
            print("sophos-central: stopping tenant {}: pagination cursor did not advance".format(tenant["id"]))
            break
        from_key = next_key

    return reported


def main(**kwargs):
    require(kwargs, "url", "client_id", "client_secret")
    base_url = get_url_base(kwargs)
    auth_url = get_url_base(kwargs, "auth_url")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    wanted = {}
    for value in get_list(kwargs, "tenant_ids", default=[]):
        tenant_id = _clean(value)
        if tenant_id:
            wanted[tenant_id] = True

    token = fetch_access_token(auth_url, client_id, client_secret, kwargs)
    if not token:
        return None

    http_options = get_http_options(kwargs, headers={
        "Authorization": bearer(token),
        "Accept": "application/json",
    })
    http_options["retry_backoff"] = RETRY_BACKOFF

    entity_id, id_type, data_region, global_host = fetch_whoami(base_url, http_options)
    if not entity_id or not id_type:
        return None

    tenants = []
    if id_type == "tenant":
        if wanted:
            print("sophos-central: ignoring the tenant IDs field, these are tenant-level credentials")
        if not data_region:
            print("sophos-central: whoami returned no apiHosts.dataRegion for this tenant")
            return None
        tenants.append({"id": entity_id, "api_host": data_region, "name": ""})
    elif id_type == "partner" or id_type == "organization":
        tenants = fetch_tenants(global_host or base_url, http_options, id_type,
                                entity_id, wanted)
        print("sophos-central: {} credential manages {} importable tenants".format(
            id_type, len(tenants)))
        found = {}
        for tenant in tenants:
            found[tenant["id"]] = True
        for tenant_id in wanted:
            if tenant_id not in found:
                print("sophos-central: requested tenant is not managed by this credential: id=" + tenant_id)
    else:
        print("sophos-central: unsupported credential type: " + id_type)
        return None

    if not tenants:
        print("sophos-central: no tenants to import")
        return None

    reported = 0
    for tenant in tenants:
        reported += fetch_and_report_endpoints(tenant, http_options, page_size)

    print("sophos-central: reported {} endpoints across {} tenants".format(reported, len(tenants)))
    if not reported:
        print("sophos-central: no assets retrieved")
    return None

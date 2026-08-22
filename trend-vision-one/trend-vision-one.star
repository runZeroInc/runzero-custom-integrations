# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-trend-vision-one",
    "name": "Trend Micro Vision One",
    "type": "inbound",
    "description": "Imports managed endpoints and their installed Trend agent products from Trend Micro Vision One Endpoint Security.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # agentGuid is the platform's own identifier for the endpoint and is the
    # only stable handle in the payload, so it drives matching. The three
    # break rules are relaxed around it because every other signal here is
    # weak or absent: the inventory listing carries no MAC at all unless the
    # adapter pass is enabled, ipAddresses are DHCP leases on roaming
    # laptops, and endpointName follows a rename. Leaving those breaks on
    # would let ordinary network churn fork one endpoint into two assets.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "api_host",
            "label": "Vision One API host",
            "type": "url",
            "required": True,
            "default": "https://api.xdr.trendmicro.com",
            "description": "Regional API domain for the Vision One console your tenant is provisioned in; an API key only works against its own region. United States https://api.xdr.trendmicro.com, Australia https://api.au.xdr.trendmicro.com, Germany/EU https://api.eu.xdr.trendmicro.com, India https://api.in.xdr.trendmicro.com, Singapore https://api.sg.xdr.trendmicro.com, UAE https://api.mea.xdr.trendmicro.com, United Kingdom https://api.uk.xdr.trendmicro.com, US Government https://api.usgov.xdr.trendmicro.com, Japan https://api.xdr.trendmicro.co.jp.",
        },
        {
            "key": "api_token",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Vision One API key. A role carrying the Endpoint Inventory 'View' permission is sufficient.",
        },
        {
            "key": "inventory_filter",
            "label": "Inventory filter",
            "type": "string",
            "required": False,
            "description": "Optional Vision One filter expression sent as the TMV1-Filter header, e.g. osPlatform eq 'windows' or not (eppAgentStatus eq 'off'). Leave blank to import every endpoint.",
        },
        {
            "key": "import_software",
            "label": "Import Trend agent products as software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Record the endpoint protection agent and XDR sensor products, with their agent versions, as software. This is not a general software inventory: Vision One only reports its own agents.",
        },
        {
            "key": "fetch_interfaces",
            "label": "Fetch MAC addresses",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Make one extra request per endpoint to read its adapter list. The endpoint inventory carries IP addresses but no MAC addresses, so this is the only way to import them. Off by default because it costs one request per endpoint.",
        },
        {
            "key": "interface_limit",
            "label": "MAC address lookup limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of endpoints to look up adapters for. Endpoints past the limit are still imported, with the addresses from the inventory listing only. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Records requested per page through the top parameter.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', 'get_json', 'bearer', 'url_parse')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict', 'dicts')
VENDOR = "trend-vision-one"
# to_custom_attributes joins the prefix to each key with the separator, so the
# prefix is passed without a trailing underscore and the separator supplies it.
ATTR_PREFIX = "trend_vision_one"
SOFTWARE_VENDOR = "Trend Micro"

ENDPOINTS_PATH = "/v3.0/endpointSecurity/endpoints"

MAX_SOFTWARE_PER_ASSET = 99

# Vision One publishes per-API request quotas that vary by endpoint and license,
# and answers 429 with Retry-After once a quota is spent. get_json already
# retries those; the backoff is widened so a large adapter pass does not spend
# its whole retry budget racing the quota window.
HTTP_RETRY_BACKOFF = 2.0

# The API reports endpoint type as desktop or server; both map onto a runZero
# device type. Anything else is left unset rather than guessed at.
DEVICE_TYPES = {"desktop": "Desktop", "server": "Server"}

# The documented "not isolated" state. Anything else is worth a tag.
ISOLATION_NORMAL = "off"

# agentGuid is interpolated into the detail request path, so it is screened down
# to characters that cannot change which resource is addressed. Every observed
# value is a UUID; anything outside this set simply skips the detail lookup.
PATH_SAFE_RE = r"^[A-Za-z0-9._~-]+$"


def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()
def _strings(value):
    """Coerce a field documented as a list of strings into one, dropping empties."""
    if type(value) != "list":
        return []
    return [_clean(item) for item in value if _clean(item)]
def _latest(first, second):
    """Return the later of two parsed timestamps, tolerating either being None."""
    if not first:
        return second
    if not second:
        return first
    if second.unix > first.unix:
        return second
    return first
def _scope(base_url):
    """Return the regional API hostname used to namespace asset ids."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url


def build_software(scope, agent_guid, endpoint):
    """Convert the Trend products installed on one endpoint into Software records.

    These are the endpoint protection agent and the XDR sensor themselves, named
    by eppAgent.productNames / edrSensor.productNames and versioned by the agent
    version each component reports. Vision One's endpoint inventory carries no
    general software inventory, so nothing else is claimed here. The pattern and
    engine content versions the agents also report are security content updates
    rather than installed products, and stay on the asset as attributes.
    """
    software = []
    seen = {}
    for key in ["eppAgent", "edrSensor"]:
        component = as_dict(endpoint.get(key))
        version = _clean(component.get("version"))
        for product in _strings(component.get("productNames")):
            if product in seen:
                continue
            seen[product] = True
            params = {
                "id": "{}:{}:{}:{}".format(VENDOR, scope, agent_guid, product),
                "vendor": SOFTWARE_VENDOR,
                "product": product,
                # The agent is not a listening service, so the loopback
                # placeholder stands in for the address the type requires.
                "serviceAddress": "127.0.0.1",
            }
            if version:
                params["version"] = version
            # cpe23 is deliberately unset: Vision One publishes no CPE for its
            # own agents, and Software.cpe23 only accepts the CPE 2.2 cpe:/a:
            # binding, so a hand-built string would fail validation.
            software.append(Software(**params))
    return software


def build_network_interfaces(endpoint, detail):
    """Build one interface per reported adapter, falling back to the flat address
    array from the inventory listing for anything the adapter list missed."""
    netifs = []
    covered = {}
    # interfaces[] only comes back from the per-endpoint profile, and it is the
    # sole source of MAC addresses anywhere in this API.
    for adapter in dicts(detail.get("interfaces")):
        mac = _clean(adapter.get("macAddress"))
        ips = []
        for value in _strings(adapter.get("ipAddresses")):
            routable = routable_ip(value)
            if routable and routable not in covered:
                ips.append(routable)
                covered[routable] = True
        # network_interface returns None when neither the MAC nor any address
        # survived, which is what a loopback-only adapter reduces to.
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)

    leftovers = []
    for value in _strings(endpoint.get("ipAddresses")):
        routable = routable_ip(value)
        if routable and routable not in covered:
            leftovers.append(routable)
            covered[routable] = True
    if leftovers:
        nic = network_interface(ips=leftovers)
        if nic:
            netifs.append(nic)

    # lastUsedIp is deliberately excluded. It is the address the endpoint most
    # recently connected from, which for an agent checking in through a Service
    # Gateway, a proxy, or a NAT gateway is the shared egress address rather
    # than an address the endpoint owns. It is kept as an attribute instead.
    return netifs


def build_asset(scope, endpoint, detail, import_software):
    """Convert one endpoint record, optionally merged with its detailed profile,
    into an ImportAsset."""
    agent_guid = _clean(endpoint.get("agentGuid"))
    if not agent_guid:
        print("trend-vision-one: skipping endpoint with no agentGuid: name=" +
              _clean(endpoint.get("endpointName")))
        return None

    epp = as_dict(endpoint.get("eppAgent"))
    edr = as_dict(endpoint.get("edrSensor"))
    detail_epp = as_dict(detail.get("eppAgent"))
    detail_edr = as_dict(detail.get("edrSensor"))
    detail_os = as_dict(detail.get("os"))

    endpoint_name = _clean(endpoint.get("endpointName")) or _clean(detail.get("endpointName"))
    endpoint_type = _clean(endpoint.get("type")) or _clean(detail.get("type"))
    os_name = _clean(endpoint.get("osName")) or _clean(detail_os.get("name"))
    os_version = _clean(endpoint.get("osVersion")) or _clean(detail_os.get("version"))
    isolation_status = _clean(endpoint.get("isolationStatus")) or _clean(detail.get("isolationStatus"))
    epp_status = _clean(epp.get("status")) or _clean(detail_epp.get("status"))
    edr_status = _clean(edr.get("status")) or _clean(detail_edr.get("status"))

    product_names = []
    for component in [epp, edr, detail_epp, detail_edr]:
        for product in _strings(component.get("productNames")):
            if product not in product_names:
                product_names.append(product)

    macs = []
    for adapter in dicts(detail.get("interfaces")):
        mac = _clean(adapter.get("macAddress"))
        if mac and mac not in macs:
            macs.append(mac)

    attrs = {
        "agent_guid": agent_guid,
        "agent_update_policy": _clean(endpoint.get("agentUpdatePolicy")),
        "agent_update_status": _clean(endpoint.get("agentUpdateStatus")),
        "cpu_architecture": _clean(endpoint.get("cpuArchitecture")),
        "credit_allocated_licenses": _strings(endpoint.get("creditAllocatedLicenses")),
        "description": _clean(detail.get("description")),
        "display_name": _clean(endpoint.get("displayName")) or _clean(detail.get("displayName")),
        "edr_sensor_advanced_risk_telemetry_status":
            _clean(edr.get("advancedRiskTelemetryStatus")),
        "edr_sensor_component_update_policy": _clean(edr.get("componentUpdatePolicy")),
        "edr_sensor_component_update_status": _clean(edr.get("componentUpdateStatus")),
        "edr_sensor_connectivity": _clean(edr.get("connectivity")),
        "edr_sensor_endpoint_group": _clean(edr.get("endpointGroup")),
        "edr_sensor_last_connected": _clean(edr.get("lastConnectedDateTime")),
        "edr_sensor_product_names": _strings(edr.get("productNames")),
        "edr_sensor_status": edr_status,
        "edr_sensor_version": _clean(edr.get("version")),
        "endpoint_name": endpoint_name,
        "epp_agent_component_update_policy": _clean(epp.get("componentUpdatePolicy")),
        "epp_agent_component_update_status": _clean(epp.get("componentUpdateStatus")),
        "epp_agent_component_version": _clean(epp.get("componentVersion")),
        "epp_agent_endpoint_group": _clean(epp.get("endpointGroup")),
        "epp_agent_kernel_support_package_version":
            _clean(epp.get("kernelSupportPackageVersion")),
        "epp_agent_last_connected": _clean(epp.get("lastConnectedDateTime")),
        "epp_agent_last_scanned": _clean(epp.get("lastScannedDateTime")),
        "epp_agent_policy_name": _clean(epp.get("policyName")),
        "epp_agent_product_names": _strings(epp.get("productNames")),
        "epp_agent_protection_manager": _clean(epp.get("protectionManager")),
        "epp_agent_status": epp_status,
        "epp_agent_version": _clean(epp.get("version")),
        "ip_addresses": _strings(endpoint.get("ipAddresses")),
        "isolation_status": isolation_status,
        # Kept off the interface list on purpose; see build_network_interfaces.
        "last_used_ip": _clean(endpoint.get("lastUsedIp")),
        "last_logged_on_user": _clean(endpoint.get("lastLoggedOnUser")),
        "mac_addresses": macs,
        "os_architecture": _clean(endpoint.get("osArchitecture")) or
                           _clean(detail_os.get("architecture")),
        "os_kernel_version": _clean(endpoint.get("osKernelVersion")) or
                             _clean(detail_os.get("kernelVersion")),
        "os_linux_distribution": _clean(detail_os.get("linuxDistribution")),
        "os_name": os_name,
        "os_platform": _clean(endpoint.get("osPlatform")) or _clean(detail_os.get("platform")),
        "os_version": os_version,
        "recommended_actions": _strings(detail.get("recommendedActions")),
        "security_policy": _clean(endpoint.get("securityPolicy")),
        "security_policy_overridden_status":
            _clean(endpoint.get("securityPolicyOverriddenStatus")),
        "serial_number": _clean(endpoint.get("serialNumber")) or _clean(detail.get("serialNumber")),
        "service_gateway_or_proxy": _clean(endpoint.get("serviceGatewayOrProxy")),
        "type": endpoint_type,
        "version_control_policy": _clean(endpoint.get("versionControlPolicy")),
    }

    tags = ["trend-vision-one"]
    for product in product_names:
        tags.append("product:" + product)
    if epp_status:
        tags.append("status:epp-" + epp_status)
    if edr_status:
        tags.append("status:edr-" + edr_status)
    if not epp_status and not edr_status:
        tags.append("status:unmanaged")
    if isolation_status and isolation_status != ISOLATION_NORMAL:
        tags.append("isolation:" + isolation_status)

    params = {
        "id": "{}:{}:{}".format(VENDOR, scope, agent_guid),
        "hostnames": [endpoint_name],
        "networkInterfaces": build_network_interfaces(endpoint, detail),
        "tags": tags,        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                 separator="_"),
    }

    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    device_type = DEVICE_TYPES.get(endpoint_type.lower(), "")
    if device_type:
        params["deviceType"] = device_type
    if import_software:
        software = build_software(scope, agent_guid, endpoint)
        if software:
            params["software"] = software[:MAX_SOFTWARE_PER_ASSET]

    asset = ImportAsset(**params)
    # Both agents report their own connection time and either may be absent,
    # so the later of the two is used.
    last_seen = _latest(parse_ts(epp.get("lastConnectedDateTime")),
                        parse_ts(edr.get("lastConnectedDateTime")))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def fetch_endpoint_detail(base_url, http_options, agent_guid):
    """Fetch the detailed profile of one endpoint, which is where the adapter
    list, and with it the MAC addresses, lives."""
    url = "{}{}/{}".format(base_url, ENDPOINTS_PATH, agent_guid)
    data, err = get_json(url, retry_backoff=HTTP_RETRY_BACKOFF, **http_options)
    if err:
        return {}, err
    return as_dict(data), None


def build_assets(base_url, detail_options, scope, rows, import_software,
                 fetch_interfaces, budget):
    """Convert one page of endpoint records into ImportAsset objects, looking up
    adapter details for up to `budget` of them.

    Returns the assets and the number of detail lookups spent. A single failing
    lookup is logged and skipped rather than abandoning the run, because one
    unreachable endpoint should not cost the whole import.
    """
    assets = []
    spent = 0
    for row in rows:
        detail = {}
        agent_guid = _clean(row.get("agentGuid"))
        if (fetch_interfaces and re_match(PATH_SAFE_RE, agent_guid) and
                (budget == None or spent < budget)):
            spent += 1
            detail, err = fetch_endpoint_detail(base_url, detail_options, agent_guid)
            if err:
                print("trend-vision-one: failed to fetch details for {}: {}".format(
                    agent_guid, err))
                detail = {}
        asset = build_asset(scope, row, detail, import_software)
        if asset:
            assets.append(asset)
    return assets, spent


def fetch_and_report_endpoints(base_url, list_options, detail_options, scope, page_size,
                               import_software, fetch_interfaces, interface_limit):
    """Fetch and stream endpoints one page at a time so the full inventory is
    never held in memory at once."""
    reported = 0
    detailed = 0
    url = base_url + ENDPOINTS_PATH
    first = True
    _pager = pager("trend-vision-one")
    while _pager.next():
        if first:
            data, err = get_json(url, params={"top": page_size},
                                 retry_backoff=HTTP_RETRY_BACKOFF, **list_options)
        else:
            # nextLink is an absolute URL that already carries the paging cursor
            # in its query string. Passing params= here, even an empty dict,
            # replaces that query string and silently restarts pagination at the
            # first page, so it is followed with no params at all.
            data, err = get_json(url, retry_backoff=HTTP_RETRY_BACKOFF, **list_options)
        if err:
            print("trend-vision-one: failed to fetch endpoints:", err)
            return reported, detailed
        data = data or {}
        items = data.get("items", [])
        if type(items) != "list":
            print("trend-vision-one: stopping: unexpected items shape from", url)
            return reported, detailed
        rows = [row for row in items if type(row) == "dict"]

        if first and type(data.get("totalCount")) == "int":
            print("trend-vision-one: {} endpoints reported by the API".format(
                data["totalCount"]))

        budget = None
        if interface_limit > 0:
            budget = interface_limit - detailed
            if budget <= 0:
                fetch_interfaces = False
                budget = 0
        assets, spent = build_assets(base_url, detail_options, scope, rows,
                                     import_software, fetch_interfaces, budget)
        detailed += spent
        reported += report_assets(assets)

        next_link = _clean(data.get("nextLink"))
        if not next_link or next_link == url:
            break
        # The cursor is only followed while it stays on the configured regional
        # API host, so a rewritten or redirected link cannot walk the credential
        # onto another host. Stopping here truncates the import, so say so.
        if _scope(next_link) != scope:
            print("trend-vision-one: stopping: nextLink left the configured API host")
            break
        first = False
        url = next_link
    return reported, detailed


def main(**kwargs):
    require(kwargs, "api_host", "api_token")
    base_url = get_url_base(kwargs, "api_host")
    api_token = get_string(kwargs, "api_token")
    inventory_filter = get_string(kwargs, "inventory_filter", default="")
    import_software = get_bool(kwargs, "import_software", default=True)
    fetch_interfaces = get_bool(kwargs, "fetch_interfaces", default=False)
    interface_limit = get_int(kwargs, "interface_limit", default=1000)
    page_size = get_int(kwargs, "page_size", default=100)
    if page_size < 1 or page_size > 1000:
        page_size = 100
    if interface_limit < 0:
        interface_limit = 0

    headers = {
        "Authorization": bearer(api_token),
        "Accept": "application/json",
    }
    detail_options = get_http_options(kwargs, headers=headers)

    # The endpoint inventory takes its filter through a request header rather
    # than a query parameter, and the header has to ride along on every page
    # including the ones reached through nextLink.
    list_headers = dict(headers)
    if inventory_filter:
        list_headers["TMV1-Filter"] = inventory_filter
    list_options = get_http_options(kwargs, headers=list_headers)

    scope = _scope(base_url)
    reported, detailed = fetch_and_report_endpoints(
        base_url, list_options, detail_options, scope, page_size,
        import_software, fetch_interfaces, interface_limit)
    print("trend-vision-one: reported {} endpoints".format(reported))
    if fetch_interfaces:
        print("trend-vision-one: fetched adapter details for {} endpoints".format(detailed))
    if not reported:
        print("trend-vision-one: no assets retrieved")
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-bitdefender-gravityzone",
    "name": "Bitdefender GravityZone",
    "type": "inbound",
    "description": "Imports endpoints from the Bitdefender GravityZone Control Center network inventory.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # id-break and mac-break are deliberately left ON, and only the two weak
    # signals are relaxed.
    # 
    # no-ip-break: details.ip is a single primary address, which on a laptop
    # is a DHCP lease and on a VPN-connected host is the tunnel address. When
    # it disagrees with what runZero scanned, the IP break helper sees no
    # overlap and vetoes an otherwise good MAC or hostname merge.
    # 
    # no-name-break: `name` is the machine name as the agent last reported
    # it, so it lags a rename, and on Linux endpoints it routinely differs
    # from the DNS name runZero discovers. The break helper already forgives
    # short-name versus FQDN, but it cannot forgive a stale name.
    # 
    # mac-break stays on because this API returns the complete macs[] array
    # in the listing, and the helper breaks only when two MAC sets do not
    # overlap at all. With a full set that check is meaningful, so it is the
    # guard that keeps a shared virtual-adapter MAC from folding unrelated
    # machines together.
    # 
    # id-break stays on because a second GravityZone id landing on an asset
    # that already carries one is real information: it means the endpoint was
    # re-enrolled or cloned. Turning it off would merge that away silently.
    # See the README for when an operator should add no-id-break instead.
    "matchBehavior": "no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "GravityZone Control Center URL",
            "type": "url",
            "required": True,
            "placeholder": "https://cloud.gravityzone.bitdefender.com",
            "description": "Base URL of the Control Center that issued the API key. Cloud tenants are shown their own regional host on the API keys page in My Account; an on-premises GravityZone appliance uses its own console hostname. Do not include the /api path.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "GravityZone API key with the Network API enabled. It is sent as the HTTP Basic username with an empty password, which is how the Control Center expects it.",
        },
        {
            "key": "parent_id",
            "label": "Parent company or group ID",
            "type": "string",
            "required": False,
            "description": "Network inventory node to import from. Leave blank to import everything under the company the API key belongs to, which is looked up automatically. Set it to a company ID on a partner console, or to a group ID to import one branch of the network tree.",
        },
        {
            "key": "include_unmanaged",
            "label": "Include endpoints without a Bitdefender agent",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import machines GravityZone has discovered but does not manage, in addition to the ones running Bitdefender Endpoint Security Tools. Useful for spotting endpoints with no EDR coverage; these records carry much less detail.",
        },
        {
            "key": "fetch_details",
            "label": "Fetch per-endpoint details",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Make one extra request per endpoint to read its last check-in time, agent and engine versions, protection modules, malware status, and last logged-in users. Off by default because it costs one request per endpoint.",
        },
        {
            "key": "detail_limit",
            "label": "Per-endpoint detail limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of endpoints to look up details for. Endpoints past the limit are still imported from the inventory listing alone, and the number skipped is logged. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Records requested per page through the perPage parameter. Version 1.1 of the Network API accepts up to 1000; the API's own default is 30.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ip')
load('http', 'post_json', 'basic', 'url_parse')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict')
VENDOR = "bitdefender-gravityzone"
# to_custom_attributes joins the prefix to each key with the separator, so the
# prefix is passed without a trailing underscore and the separator supplies it.
ATTR_PREFIX = "bitdefender_gravityzone"

# GravityZone is JSON-RPC 2.0 over HTTP, not REST: every method is a POST to the
# service endpoint for its API version, with the method name in the body.
API_ROOT = "/api"
NETWORK_SERVICE = "/v1.1/jsonrpc/network"
NETWORK_DETAIL_SERVICE = "/v1.0/jsonrpc/network"
COMPANIES_SERVICE = "/v1.0/jsonrpc/companies"

METHOD_INVENTORY = "getNetworkInventoryItems"
METHOD_COMPANY = "getCompanyDetails"
METHOD_ENDPOINT_DETAILS = "getManagedEndpointDetails"

# The JSON-RPC id is echoed back and is only used to correlate a response with
# its request. One call is in flight at a time, so a constant is enough.
RPC_ID = "runzero"

# Version 1.1 of getNetworkInventoryItems accepts perPage up to 1000. Version
# 1.0 of the same method caps it at 100, which is why the version matters here.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000

# Endpoint ids are interpolated into a JSON body rather than a URL, but they are
# still screened before being used to address a resource. Every observed value is
# a 24-character hex object id; anything else simply skips the detail lookup.
ENDPOINT_ID_RE = r"^[A-Za-z0-9._~-]+$"

# getManagedEndpointDetails reports connectivity as an integer. Offline and
# suspended are only ever reported for endpoints under an active virtualization
# integration, so an absent state is not the same as "offline".
ENDPOINT_STATES = {0: "unknown", 1: "online", 2: "offline", 3: "suspended"}

# Inventory item types. Only the three that are endpoints are imported; the rest
# are the company, folder, group, and container-host nodes that share the tree.
ITEM_TYPE_NAMES = {
    1: "company",
    2: "root-container",
    3: "company-folder",
    4: "group",
    5: "computer",
    6: "virtual-machine",
    7: "ec2-instance",
    14: "containers-group",
    15: "container-host-folder",
    16: "container",
}
ENDPOINT_ITEM_TYPES = [5, 6, 7]

# The physical nature of the endpoint, as reported inside details. This is not
# specific enough to claim a runZero deviceType (it does not distinguish a
# desktop from a server), so it is only recorded as an attribute.
MACHINE_TYPES = {0: "other", 1: "computer", 2: "virtual-machine", 3: "ec2-instance"}

# Documented JSON-RPC error codes, named so a failure reads as a cause rather
# than as a number. -32003 is delivered with HTTP 429 rather than 200, so the
# HTTP helper retries it before it can ever reach here.
RPC_ERROR_NAMES = {
    "-32700": "parse error",
    "-32600": "invalid request",
    "-32601": "method not found",
    "-32602": "invalid params",
    "-32000": "server error",
    "-32001": "authorization error",
    "-32002": "resource not found",
    "-32003": "too many requests",
}

def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()
def _strings(value):
    """Coerce a field documented as a list of strings into one, dropping empties."""
    if type(value) != "list":
        return []
    return [_clean(item) for item in value if _clean(item)]

def _console(base_url):
    """Return the Control Center hostname used to namespace asset ids."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url

def rpc(base_url, service, http_options, method, params):
    """Issue one JSON-RPC 2.0 call and return (result, err).

    GravityZone answers a failed call with HTTP 200 and an `error` object in the
    body, so post_json reports success and the failure has to be read out of the
    payload explicitly. Only the code and message are surfaced; the `data` member
    can echo request parameters back and is not logged.

    Every method used here is a read, so the default retry budget on post_json is
    safe: a repeated call cannot create or change anything.
    """
    url = base_url + API_ROOT + service
    body = {
        "id": RPC_ID,
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    data, err = post_json(url, json=body, **http_options)
    if err:
        return None, err
    data = as_dict(data)
    rpc_error = as_dict(data.get("error"))
    if rpc_error:
        code = _clean(rpc_error.get("code")) or "unknown"
        return None, "json-rpc error {} ({}): {}".format(
            code, RPC_ERROR_NAMES.get(code, "undocumented code"),
            _clean(rpc_error.get("message")) or "no message")
    if "error" in data and data.get("error") != None:
        return None, "json-rpc error: " + _clean(data.get("error"))
    return data.get("result"), None

def build_network_interfaces(details):
    """Build interfaces from the endpoint's MAC list and primary address.

    Every MAC GravityZone reports is used, not just the first: the array holds
    the machine's real adapters, and keeping only one both loses merge signal and
    makes runZero's MAC conflict check fire on the wrong adapter. GravityZone
    does not say which address belongs to which adapter, so the single reported
    address is attached to the first interface and the remaining MACs stand
    alone.
    """
    macs = []
    for value in _strings(details.get("macs")):
        # The MACs are normalized by network_interface, which also clears the
        # locally-administered bit. That is correct for an interface and is why
        # no MAC from this list is ever allowed near the asset id.
        if value not in macs:
            macs.append(value)

    ips = []
    routable = routable_ip(details.get("ip"))
    if routable:
        ips.append(routable)

    netifs = []
    if not macs:
        nic = network_interface(ips=ips)
        return [nic] if nic else []
    for index in range(len(macs)):
        nic = network_interface(mac=macs[index], ips=ips if index == 0 else [])
        if nic:
            netifs.append(nic)
    return netifs

def build_asset(console, item, detail):
    """Convert one network inventory item, optionally merged with its detailed
    profile, into an ImportAsset."""
    endpoint_id = _clean(item.get("id"))
    if not endpoint_id:
        print("bitdefender-gravityzone: skipping inventory item with no id: name=" +
              _clean(item.get("name")))
        return None

    details = as_dict(item.get("details"))
    company_id = _clean(item.get("companyId")) or _clean(detail.get("companyId"))

    name = _clean(item.get("name")) or _clean(detail.get("name"))
    fqdn = _clean(details.get("fqdn"))
    os_version = _clean(details.get("operatingSystemVersion")) or \
                 _clean(detail.get("operatingSystem"))

    policy = as_dict(details.get("policy")) or as_dict(detail.get("policy"))
    group = as_dict(detail.get("group"))
    agent = as_dict(detail.get("agent"))
    malware = as_dict(detail.get("malwareStatus"))
    # modules, productOutdated, riskScore, and lastSuccessfulScan are documented
    # on the inventory listing as well as on the per-endpoint detail, so the
    # listing is preferred and the detail only fills gaps. That keeps the EDR
    # module picture available without the extra request per endpoint.
    modules = as_dict(details.get("modules")) or as_dict(detail.get("modules"))
    risk = as_dict(details.get("riskScore")) or as_dict(detail.get("riskScore"))
    last_scan = as_dict(details.get("lastSuccessfulScan")) or \
                as_dict(detail.get("lastSuccessfulScan"))

    product_outdated = details.get("productOutdated")
    if product_outdated == None:
        product_outdated = agent.get("productOutdated")

    state = detail.get("state")
    state_name = ""
    if type(state) == "int":
        state_name = ENDPOINT_STATES.get(state, "")

    item_type = item.get("type")
    machine_type = details.get("machineType")

    managed = details.get("managedWithBest")
    if managed == None:
        managed = detail.get("managedWithBest")

    attrs = {
        # ssid is Bitdefender's key for the Active Directory security
        # identifier, not a wireless network name. It is renamed here because an
        # attribute called ssid would be actively misleading in a runZero search.
        "ad_sid": _clean(details.get("ssid")),
        "agent_engine_version": _clean(agent.get("engineVersion")),
        "agent_last_update": _clean(agent.get("lastUpdate")),
        "agent_product_outdated": product_outdated,
        "agent_product_version": _clean(agent.get("productVersion")),
        "agent_signature_outdated": agent.get("signatureOutdated"),
        "agent_type": agent.get("type"),
        "company_id": company_id,
        "endpoint_id": endpoint_id,
        "fqdn": fqdn,
        "group_id": _clean(details.get("groupId")) or _clean(group.get("id")),
        "group_name": _clean(group.get("name")),
        "inventory_type": item_type,
        "inventory_type_name": ITEM_TYPE_NAMES.get(item_type, "") if type(item_type) == "int" else "",
        "is_container_host": details.get("isContainerHost"),
        "is_managed": details.get("isManaged"),
        # Kept verbatim so an operator can see what the console actually sent,
        # including a loopback address that was filtered out of the interfaces.
        "ip": _clean(details.get("ip")) or _clean(detail.get("ip")),
        "label": _clean(details.get("label")) or _clean(detail.get("label")),
        "last_logged_users": _strings(detail.get("lastLoggedUsers")),
        "last_scan_date": _clean(last_scan.get("date")),
        "last_scan_name": _clean(last_scan.get("name")),
        "last_seen": _clean(detail.get("lastSeen")),
        "machine_type": machine_type,
        "machine_type_name": MACHINE_TYPES.get(machine_type, "") if type(machine_type) == "int" else "",
        "macs": _strings(details.get("macs")),
        "malware_detection": malware.get("detection"),
        "malware_infected": malware.get("infected"),
        "managed_exchange_server": details.get("managedExchangeServer"),
        "managed_relay": details.get("managedRelay"),
        "managed_with_best": managed,
        "modules": modules,
        "moving_state": as_dict(details.get("movingInfo")).get("state"),
        "name": name,
        "operating_system_version": os_version,
        "parent_id": _clean(item.get("parentId")),
        "policy_applied": policy.get("applied"),
        "policy_id": _clean(policy.get("id")),
        "policy_name": _clean(policy.get("name")),
        "risk_score": risk,
        "security_server": details.get("securityServer"),
        "state": state,
        "state_name": state_name,
    }

    tags = ["bitdefender-gravityzone"]
    if managed == True:
        tags.append("management:managed")
    elif managed == False or details.get("isManaged") == False:
        tags.append("management:unmanaged")
    if state_name:
        tags.append("status:" + state_name)
    if malware.get("infected") == True:
        tags.append("malware:infected")
    if product_outdated == True:
        tags.append("agent:outdated")
    if agent.get("signatureOutdated") == True:
        tags.append("agent:signature-outdated")
    # The module map is the EDR coverage answer: an endpoint can carry the
    # antimalware agent without the EDR sensor, and that gap is worth a tag.
    if modules:
        if modules.get("edrSensor") == True:
            tags.append("module:edr-sensor")
        else:
            tags.append("module:no-edr-sensor")

    params = {
        # The GravityZone endpoint id is the handle every Network API method
        # takes, so it is the foreign id. It is a console-scoped object id, so
        # the Control Center host and the owning company both namespace it: one
        # cloud console serves many tenants and a partner credential can walk
        # several companies in a single run.
        "id": "{}:{}:{}:{}".format(VENDOR, console, company_id or "unknown",
                                   endpoint_id),
        "hostnames": [name, fqdn],
        "networkInterfaces": build_network_interfaces(details),
        "tags": tags,        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                 separator="_"),
    }

    if os_version:
        params["os"] = os_version

    asset = ImportAsset(**params)
    # The last check-in exists only on the per-endpoint detail response,
    # never in the listing.
    last_seen = parse_ts(detail.get("lastSeen"))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_endpoint_detail(base_url, http_options, endpoint_id):
    """Fetch the detailed profile of one endpoint, which is where the check-in
    time, agent versions, protection modules, and logged-in users live."""
    params = {
        "endpointId": endpoint_id,
        "options": {
            # Scan logs are a large per-endpoint list that maps to nothing in
            # runZero, so they are not requested.
            "includeScanLogs": False,
            "returnProductOutdated": True,
            "includeLastLoggedUsers": True,
        },
    }
    result, err = rpc(base_url, NETWORK_DETAIL_SERVICE, http_options,
                      METHOD_ENDPOINT_DETAILS, params)
    if err:
        return {}, err
    return as_dict(result), None

def build_assets(base_url, http_options, console, items, ctx):
    """Convert one page of network inventory items into ImportAsset objects,
    looking up per-endpoint details while the budget lasts.

    A single failing detail lookup is logged and skipped rather than abandoning
    the run, because one unreachable endpoint should not cost the whole import.
    """
    assets = []
    for item in items:
        if type(item) != "dict":
            continue
        # The inventory tree holds companies, folders, groups, and container
        # nodes alongside endpoints. `type` names which one this is, so it is
        # the discriminator when present. A details object is required either
        # way: endpoints carry one and structural nodes do not, which is the
        # fallback when a response omits `type`, and a typed endpoint without
        # details has nothing to import beyond a name. The skip is counted and
        # reported rather than silently producing a nearly empty asset.
        item_type = item.get("type")
        if type(item_type) == "int" and item_type not in ENDPOINT_ITEM_TYPES:
            ctx["not_endpoints"] += 1
            continue
        if type(item.get("details")) != "dict":
            ctx["not_endpoints"] += 1
            continue
        detail = {}
        endpoint_id = _clean(item.get("id"))
        if ctx["fetch_details"] and re_match(ENDPOINT_ID_RE, endpoint_id):
            if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
                ctx["detail_skipped"] += 1
            else:
                ctx["detail_used"] += 1
                detail, err = fetch_endpoint_detail(base_url, http_options,
                                                    endpoint_id)
                if err:
                    print("bitdefender-gravityzone: failed to fetch details for {}: {}".format(
                        endpoint_id, err))
                    detail = {}
        asset = build_asset(console, item, detail)
        if asset:
            assets.append(asset)
    return assets

def fetch_parent_id(base_url, http_options):
    """Resolve the network inventory node to walk.

    getNetworkInventoryItems requires a parentId, so the company the API key
    belongs to is looked up first and its id is used as the root.
    """
    result, err = rpc(base_url, COMPANIES_SERVICE, http_options,
                      METHOD_COMPANY, {})
    if err:
        return "", err
    company = as_dict(result)
    company_id = _clean(company.get("id"))
    if not company_id:
        return "", "company details returned no id"
    print("bitdefender-gravityzone: importing under company {} ({})".format(
        company_id, _clean(company.get("name")) or "unnamed"))
    return company_id, None

def fetch_and_report_endpoints(base_url, http_options, console, parent_id, ctx):
    """Fetch and stream the network inventory one page at a time so the full set
    is never held in memory at once.

    Returns (reported, walk_err). The caller prints its summary before failing
    on walk_err, so a truncated walk is not filed as a complete estate."""
    reported = 0
    walk_err = None
    filters = {
        "type": {
            "computers": True,
            "virtualMachines": True,
        },
        "depth": {
            "allItemsRecursively": True,
        },
    }
    if not ctx["include_unmanaged"]:
        # Restricting to endpoints running Bitdefender Endpoint Security Tools.
        # Dropping the whole security filter is what widens the walk to machines
        # GravityZone has discovered but does not manage.
        filters["security"] = {
            "management": {
                "managedWithBest": True,
            },
        }

    total_pages = 0
    _pager = pager("bitdefender-gravityzone")
    while _pager.next():
        page = _pager.page
        params = {
            "page": page,
            "perPage": ctx["page_size"],
            "filters": filters,
        }
        # parentId is documented to default to the company the API key belongs
        # to, so it is omitted rather than sent empty when it could not be
        # resolved. That keeps the run alive on a key without Companies API
        # access.
        if parent_id:
            params["parentId"] = parent_id
        result, err = rpc(base_url, NETWORK_SERVICE, http_options,
                          METHOD_INVENTORY, params)
        if err:
            print("bitdefender-gravityzone: failed to fetch inventory page {}: {}".format(page, err))
            walk_err = "failed to fetch inventory page {} after reporting {}: {}".format(
                page, reported, err)
            break
        result = as_dict(result)
        items = result.get("items")
        if type(items) != "list":
            walk_err = "unexpected items shape on inventory page {} after reporting {}".format(
                page, reported)
            break
        # Version 1.1 of this method returns pagesCount and total on the FIRST
        # page only, so they are captured there and not re-read afterwards.
        if page == 1:
            if type(result.get("total")) == "int":
                print("bitdefender-gravityzone: {} inventory items reported by the API".format(
                    result["total"]))
            if type(result.get("pagesCount")) == "int" and result["pagesCount"] > 0:
                total_pages = result["pagesCount"]

        reported += report_assets(build_assets(base_url, http_options, console,
                                               items, ctx))

        # hasMoreRecords is the version 1.1 stop condition and is authoritative
        # when present. pagesCount from the first page is the version 1.0
        # equivalent. A short or empty page is the last resort, so a console
        # that reports neither still terminates.
        if not items:
            break
        has_more = result.get("hasMoreRecords")
        if type(has_more) == "bool":
            if not has_more:
                break
        elif total_pages:
            if page >= total_pages:
                break
        elif len(items) < ctx["page_size"]:
            break
    return reported, walk_err

def main(**kwargs):
    require(kwargs, "url", "api_key")
    base_url = get_url_base(kwargs)
    parent_id = get_string(kwargs, "parent_id", default="")
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE
    if detail_limit < 0:
        detail_limit = 0

    # The Control Center takes the API key as the HTTP Basic username with an
    # empty password. basic() with no password argument produces exactly the
    # base64 of "<key>:" that it expects.
    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(get_string(kwargs, "api_key")),
        "Accept": "application/json",
    })

    ctx = {
        "detail_limit": detail_limit,
        "detail_skipped": 0,
        "detail_used": 0,
        "fetch_details": get_bool(kwargs, "fetch_details", default=False),
        "include_unmanaged": get_bool(kwargs, "include_unmanaged", default=False),
        "not_endpoints": 0,
        "page_size": page_size,
    }

    if not parent_id:
        parent_id, err = fetch_parent_id(base_url, http_options)
        if err:
            # Not fatal: parentId defaults to the company the API key belongs
            # to, so the walk is still attempted without it. A key without
            # Companies API access lands here.
            print("bitdefender-gravityzone: could not resolve the parent company ({});".format(err) +
                  " continuing with the API key's default company")

    console = _console(base_url)
    reported, walk_err = fetch_and_report_endpoints(base_url, http_options, console,
                                                    parent_id, ctx)
    print("bitdefender-gravityzone: reported {} endpoints".format(reported))
    if ctx["not_endpoints"]:
        print("bitdefender-gravityzone: skipped {} inventory items that are not endpoints".format(
            ctx["not_endpoints"]))
    if ctx["detail_skipped"]:
        print("bitdefender-gravityzone: detail limit of {} reached; agent, module, and check-in data were not imported for {} of {} endpoints".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    if walk_err != None:
        fail("bitdefender-gravityzone: " + walk_err)
    if not reported:
        print("bitdefender-gravityzone: no assets retrieved")
    return None

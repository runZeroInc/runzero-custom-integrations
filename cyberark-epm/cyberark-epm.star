# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cyberark-epm",
    "name": "CyberArk EPM",
    "type": "inbound",
    "description": "Imports endpoint computers from CyberArk Endpoint Privilege Manager (EPM) SaaS.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The EPM agent id is a GUID minted at agent install and is the key every
    # endpoint API is addressed by, so it drives merging. Endpoints are largely
    # laptops and desktops whose names and addresses drift; none of that may
    # veto an id merge. An agent reinstall mints a new id and always forks the
    # asset -- that is reconciled in runZero, not with flags.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "EPM dispatcher URL",
            "type": "url",
            "required": False,
            "default": "https://login.epm.cyberark.com",
            "description": "The EPM logon dispatcher. The logon response names the tenant's manager host, and every data call goes there instead.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "EPM user with API access. SAML-only users cannot authenticate this way.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "application_id",
            "label": "Application ID",
            "type": "string",
            "required": False,
            "default": "runZero",
            "description": "Free-form caller name recorded by EPM for API sessions.",
        },
        {
            "key": "set_name",
            "label": "Set name",
            "type": "string",
            "required": False,
            "description": "Import only the named set. Leave blank to import every set the user can see.",
        },
        {
            "key": "include_details",
            "label": "Fetch per-endpoint details",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Enrich each endpoint with OS version, MAC addresses, serial number, and FQDN. This is one extra API call per endpoint against a budget of 1000 calls per 5 minutes, so it is capped by the limit below.",
        },
        {
            "key": "detail_limit",
            "label": "Detail call cap",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 100000,
            "description": "Maximum number of per-endpoint detail calls per run. Endpoints beyond the cap are imported without the extra detail and the skip is logged.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 1000,
            "description": "Endpoints per page. The endpoints API caps this at 1000.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "Software")
load("http", "get_json", "post_json")
load("kwargs", "require", "get_string", "get_int", "get_bool", "get_url_base", "get_http_options")
load("net", "network_interface", "routable_ip", "routable_ips", "clean_hostname")
load("time", "parse_ts")
load("runzero.progress", progress_report="report")

SETS_PAGE = 100

# The filter body sent when an empty search body is rejected. Platform is the
# only always-present field to filter on; the documented values are exactly
# these three, so endpoints reporting an unknown platform could be missed by
# this fallback, which is why the empty body is tried first.
PLATFORM_FILTER = "platform IN \"Windows\", \"MacOS\", \"Linux\""

DETAIL_FILTER = "inventoryType IN \"OsInfo, Hardware, Network, DomainInfo\""

# EPM platformType values map one-to-one onto runZero device types.
DEVICE_TYPES = {
    "desktop": "Desktop",
    "laptop": "Laptop",
    "server": "Server",
}


def logon(dispatcher, username, password, application_id, config):
    """Authenticate at the dispatcher and return (manager_url, token)."""
    options = get_http_options(config, headers={"Content-Type": "application/json"})
    data, err = post_json(dispatcher + "/EPM/API/Auth/EPM/Logon",
                          json={
                              "Username": username,
                              "Password": password,
                              "ApplicationID": application_id,
                          },
                          **options)
    if err:
        print("cyberark-epm: logon failed:", err)
        if err.startswith("status 401") or err.startswith("status 403"):
            print("cyberark-epm: check the username and password; SAML-only users cannot use this endpoint")
        return "", ""
    if type(data) != "dict":
        print("cyberark-epm: unexpected logon response")
        return "", ""
    manager = str(data.get("ManagerURL", "") or "").rstrip("/")
    token = str(data.get("EPMAuthenticationResult", "") or "")
    if manager and not manager.startswith("http"):
        manager = "https://" + manager
    if not manager or not token:
        print("cyberark-epm: logon response carried no ManagerURL or session token")
        return "", ""
    return manager, token


def auth_options(config, token):
    """Build the HTTP options for data calls.

    EPM's documented header is `Authorization: basic <token>` with the session
    token passed verbatim -- it is not an HTTP Basic credential.
    """
    return get_http_options(config, headers={
        "Authorization": "basic " + token,
        "Content-Type": "application/json",
    })


def fetch_sets(manager, options):
    """Return every set as a list of {Id, Name} dicts."""
    sets = []
    offset = 0
    p = pager("epm-sets")
    while p.next():
        data, err = get_json(manager + "/EPM/API/Sets",
                             params={"Offset": str(offset), "Limit": str(SETS_PAGE)},
                             **options)
        if err:
            print("cyberark-epm: failed to list sets:", err)
            return sets
        if type(data) != "dict":
            return sets
        page = data.get("Sets", []) or []
        for entry in page:
            if type(entry) == "dict" and entry.get("Id"):
                sets.append(entry)
        if len(page) < SETS_PAGE:
            break
        offset += SETS_PAGE
    return sets


def search_endpoints_page(manager, options, set_id, offset, limit, body):
    """Fetch one page from the endpoints search API.

    Returns (endpoints, err). The offset/limit ride in the query string and the
    filter in the body, per the API contract.
    """
    url = "{}/EPM/API/Sets/{}/Endpoints/search?offset={}&limit={}&sortBy=Name&sortDir=asc".format(
        manager, set_id, offset, limit)
    data, err = post_json(url, json=body, **options)
    if err:
        return [], err
    if type(data) != "dict":
        return [], "unexpected response of type " + type(data)
    endpoints = data.get("endpoints", []) or []
    if type(endpoints) != "list":
        return [], "unexpected endpoints field of type " + type(endpoints)
    return endpoints, None


def fetch_endpoint_details(manager, options, set_id, endpoint_id):
    """Fetch one endpoint's inventory detail, or None."""
    url = "{}/EPM/API/Sets/{}/Endpoints/{}/search".format(manager, set_id, endpoint_id)
    data, err = post_json(url, json={"filter": DETAIL_FILTER}, **options)
    if err:
        print("cyberark-epm: detail fetch failed for endpoint {}: {}".format(endpoint_id, err))
        return None
    if type(data) != "dict":
        return None
    return data


def detail_interfaces(detail):
    """Build interfaces from a detail record's network adapter inventory."""
    interfaces = []
    inventory = detail.get("inventory", {}) or {}
    if type(inventory) != "dict":
        return interfaces
    network = inventory.get("network", {}) or {}
    if type(network) != "dict":
        return interfaces
    for adapter in network.get("networkAdapters", []) or []:
        if type(adapter) != "dict":
            continue
        ips = []
        for subnet in adapter.get("ipSubnets", []) or []:
            if type(subnet) == "dict" and subnet.get("ipAddress"):
                ips.append(str(subnet.get("ipAddress")))
        ips = routable_ips(ips)
        mac = str(adapter.get("macAddress", "") or "")
        # The all-zero value is a placeholder Windows reports for virtual and
        # disconnected adapters, not an address.
        if mac.replace(":", "").replace("-", "").strip("0") == "":
            mac = ""
        if not mac and not ips:
            continue
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            interfaces.append(nic)
    return interfaces


def apply_detail(asset_args, attrs, detail):
    """Fold a detail record's inventory into the asset under construction."""
    interfaces = detail_interfaces(detail)
    if interfaces:
        asset_args["networkInterfaces"] = interfaces

    inventory = detail.get("inventory", {}) or {}
    if type(inventory) != "dict":
        return

    os_info = inventory.get("osInfo", {}) or {}
    if type(os_info) == "dict":
        os_block = os_info.get("os", {}) or {}
        if type(os_block) == "dict":
            os_name = str(os_block.get("version", "") or "")
            os_build = str(os_block.get("build", "") or "")
            if os_name:
                asset_args["os"] = os_name
            if os_build:
                asset_args["osVersion"] = os_build

    hardware = inventory.get("hardware", {}) or {}
    if type(hardware) == "dict":
        machine = hardware.get("machineInfo", {}) or {}
        if type(machine) == "dict":
            vendor = str(machine.get("vendor", "") or "")
            if vendor:
                asset_args["manufacturer"] = vendor
            model = str(machine.get("model", "") or "")
            if model:
                asset_args["model"] = model
            serial = str(machine.get("serialNumber", "") or "")
            if serial:
                attrs["serialNumber"] = serial

    domain = inventory.get("domainInfo", {}) or {}
    if type(domain) == "dict":
        fqdn = clean_hostname(domain.get("computerNameDnsFullyQualified"))
        if fqdn:
            names = asset_args.get("hostnames", [])
            if fqdn not in names:
                names.append(fqdn)
            asset_args["hostnames"] = names
        domain_name = str(domain.get("domainDnsName", "") or "")
        if domain_name:
            attrs["domain"] = domain_name


def build_asset(record, namespace, set_name, detail):
    """Build one ImportAsset from an endpoints-search record."""
    # legacyId is the AgentId of the deprecated computers API; preferring it
    # keeps the foreign id identical whichever API a tenant is served by.
    endpoint_id = str(record.get("legacyId", "") or "") or str(record.get("id", "") or "")
    if not endpoint_id:
        print("cyberark-epm: skipping endpoint with no id: name=" + str(record.get("name", "")))
        return None

    hostnames = []
    name = clean_hostname(record.get("name"))
    if name:
        hostnames.append(name)

    attrs = {
        "endpointId": str(record.get("id", "") or ""),
        "legacyId": str(record.get("legacyId", "") or ""),
        "setId": str(record.get("setId", "") or ""),
        "setName": set_name,
        "connectionStatus": str(record.get("connectionStatus", "") or ""),
        "loggedInUser": str(record.get("loggedInUser", "") or ""),
        "agentVersion": str(record.get("version", "") or ""),
        "npvdi": str(record.get("npvdi", "")),
        "threatProtectionStatus": str(record.get("threatProtectionStatus", "") or ""),
        "upgradeStatus": str(record.get("upgradeStatus", "") or ""),
        "suspendedMode": str(record.get("suspendedMode", "")),
        "supportMode": str(record.get("supportMode", "")),
        "installTime": str(record.get("installTime", "") or ""),
        "lastConnected": str(record.get("lastConnected", "") or ""),
        "reportedIP": str(record.get("ip", "") or ""),
    }

    asset_args = {
        "id": "cyberark-epm:{}:{}".format(namespace, endpoint_id),
        "hostnames": hostnames,
        "os": str(record.get("platform", "") or ""),
    }

    ip = routable_ip(str(record.get("ip", "") or ""))
    if ip:
        nic = network_interface(mac=None, ips=[ip])
        if nic:
            asset_args["networkInterfaces"] = [nic]

    device_type = DEVICE_TYPES.get(str(record.get("platformType", "") or "").lower())
    if device_type:
        asset_args["deviceType"] = device_type

    agent_version = str(record.get("version", "") or "")
    if agent_version:
        asset_args["software"] = [Software(
            id="cyberark-epm-agent",
            vendor="CyberArk",
            product="Endpoint Privilege Manager agent",
            version=agent_version,
        )]

    if detail != None:
        apply_detail(asset_args, attrs, detail)

    asset_args["customAttributes"] = {k: v for k, v in attrs.items() if v}

    first_seen = parse_ts(record.get("installTime"))
    if first_seen != None:
        asset_args["firstSeenTS"] = first_seen
    asset = ImportAsset(**asset_args)
    last_seen = parse_ts(record.get("lastConnected"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def legacy_record(computer):
    """Reshape a deprecated computers-API record into the endpoints shape."""
    return {
        "id": computer.get("AgentId", ""),
        "legacyId": computer.get("AgentId", ""),
        "name": computer.get("ComputerName", ""),
        "platform": computer.get("Platform", ""),
        "platformType": computer.get("ComputerType", ""),
        "version": computer.get("AgentVersion", ""),
        "connectionStatus": computer.get("Status", ""),
        "loggedInUser": computer.get("LoggedIn", ""),
        "installTime": computer.get("InstallTime", ""),
        "lastConnected": computer.get("LastSeen", ""),
    }


def import_set_legacy(manager, options, set_entry, namespace, page_size):
    """Walk one set with the deprecated computers API. Returns assets reported."""
    set_id = str(set_entry.get("Id"))
    set_name = str(set_entry.get("Name", "") or "")
    limit = min(page_size, 4999)
    offset = 0
    reported = 0
    p = pager("epm-computers")
    while p.next():
        data, err = get_json("{}/EPM/API/Sets/{}/Computers".format(manager, set_id),
                             params={"offset": str(offset), "limit": str(limit)},
                             **options)
        if err:
            print("cyberark-epm: computers fetch failed for set {}: {}".format(set_name, err))
            break
        if type(data) != "dict":
            break
        computers = data.get("Computers", []) or []
        for computer in computers:
            if type(computer) != "dict":
                continue
            reported += report_asset(build_asset(legacy_record(computer), namespace, set_name, None))
        if len(computers) < limit:
            break
        offset += limit
    return reported


def import_set(manager, options, set_entry, namespace, page_size,
               want_details, detail_budget):
    """Walk one set's endpoints. Returns (reported, detail_budget, use_legacy)."""
    set_id = str(set_entry.get("Id"))
    set_name = str(set_entry.get("Name", "") or "")
    offset = 0
    reported = 0
    body = {}
    detail_skipped = 0
    p = pager("epm-endpoints")
    while p.next():
        endpoints, err = search_endpoints_page(manager, options, set_id, offset, page_size, body)
        if err and err.startswith("status 400") and body == {}:
            # Some tenants reject an empty search body; retry with the
            # documented platform filter.
            body = {"filter": PLATFORM_FILTER}
            print("cyberark-epm: empty search body rejected; retrying with a platform filter")
            continue
        if err and (err.startswith("status 404") or err.startswith("status 405")):
            # The endpoints API is absent on this tenant; use the deprecated
            # computers API instead.
            print("cyberark-epm: endpoints API unavailable; falling back to the computers API")
            return import_set_legacy(manager, options, set_entry, namespace, page_size), detail_budget, True
        if err:
            print("cyberark-epm: endpoint search failed for set {}: {}".format(set_name, err))
            break

        for record in endpoints:
            if type(record) != "dict":
                continue
            detail = None
            if want_details:
                real_id = str(record.get("id", "") or "")
                if real_id and detail_budget > 0:
                    detail_budget -= 1
                    detail = fetch_endpoint_details(manager, options, set_id, real_id)
                elif real_id:
                    detail_skipped += 1
            reported += report_asset(build_asset(record, namespace, set_name, detail))

        if len(endpoints) < page_size:
            break
        offset += page_size

    if detail_skipped:
        print("cyberark-epm: detail cap reached; {} endpoints in set {} imported without detail".format(
            detail_skipped, set_name))
    return reported, detail_budget, False


def main(**kwargs):
    require(kwargs, "username", "password")
    dispatcher = get_url_base(kwargs)
    if not dispatcher:
        dispatcher = "https://login.epm.cyberark.com"
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    application_id = get_string(kwargs, "application_id", default="runZero")
    only_set = get_string(kwargs, "set_name", default="").strip()
    want_details = get_bool(kwargs, "include_details", default=False)
    detail_budget = get_int(kwargs, "detail_limit", default=500)
    page_size = get_int(kwargs, "page_size", default=1000)
    if page_size < 1 or page_size > 1000:
        page_size = 1000

    manager, token = logon(dispatcher, username, password, application_id, kwargs)
    if not token:
        return None
    # Asset ids are scoped on the tenant's manager hostname (no port), which
    # is stable per tenant, rather than the shared regional dispatcher.
    namespace = manager.split("://")[-1].split("/")[0].split(":")[0].lower()
    print("cyberark-epm: authenticated; manager is", namespace)

    options = auth_options(kwargs, token)
    sets = fetch_sets(manager, options)
    if only_set:
        sets = [s for s in sets if str(s.get("Name", "")) == only_set]
        if not sets:
            print("cyberark-epm: no set named {} is visible to this user".format(only_set))
            return None
    if not sets:
        print("cyberark-epm: no sets retrieved")
        return None
    print("cyberark-epm: importing {} set(s)".format(len(sets)))

    reported = 0
    use_legacy = False
    for i, set_entry in enumerate(sets):
        if use_legacy:
            count = import_set_legacy(manager, options, set_entry, namespace, page_size)
        else:
            count, detail_budget, use_legacy = import_set(
                manager, options, set_entry, namespace, page_size,
                want_details, detail_budget)
        reported += count
        progress_report((i + 1) * 100 // len(sets),
                        "imported {} endpoints from {} set(s)".format(reported, i + 1))

    print("cyberark-epm: reported {} assets".format(reported))
    return None

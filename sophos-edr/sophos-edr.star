# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-sophos-edr",
    "name": "Sophos EDR",
    "type": "inbound",
    "description": "Imports computer and server endpoints from Sophos Central with health, protection, isolation, encryption, and cloud metadata.",
    "version": "26081400",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "client_id",
            "label": "Client ID",
            "type": "string",
            "required": True,
            "description": "Sophos Central API credential client ID",
        },
        {
            "key": "client_secret",
            "label": "Client secret",
            "type": "secret",
            "required": True,
            "description": "Sophos Central API credential client secret",
        },
        {
            "key": "tenant_id",
            "label": "Tenant ID",
            "type": "string",
            "required": False,
            "description": "Only needed for partner or organization service principals; discovered automatically for tenant credentials",
        },
        {
            "key": "data_region_url",
            "label": "Data region URL",
            "type": "url",
            "required": False,
            "placeholder": "https://api-us03.central.sophos.com",
            "description": "Only needed with an explicit tenant ID; discovered automatically for tenant credentials",
        },
        {
            "key": "endpoint_types",
            "label": "Endpoint types",
            "type": "enum",
            "required": False,
            "multi": True,
            "options": ["computer", "server"],
            "description": "Endpoint types to import; leave blank to import all",
        },
        {
            "key": "last_seen_days",
            "label": "Last seen within days",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import endpoints seen within the last N days; 0 imports all",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# Sophos Central (EDR) -> runZero ImportAsset integration
#
# Flow:
#   1. OAuth2 client-credentials exchange at id.sophos.com for a JWT (1h TTL).
#   2. GET /whoami/v1 to discover the tenant ID and regional API host, unless
#      both are supplied explicitly (partner / organization credentials).
#   3. Page through GET {dataRegion}/endpoint/v1/endpoints?view=full using
#      key-based pagination (pages.nextKey), streaming each page to runZero.

load("runzero.types", "ImportAsset", "Software", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "bearer", "oauth2_token")
load("kwargs", "require", "get_string", "get_int", "get_list", "get_http_options")

TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
PAGE_SIZE = 100  # documented maximum for GET /endpoint/v1/endpoints
MAX_PAGES = 10000


def _log(msg):
    print("[SOPHOS-EDR] " + msg)


def get_token(config_kwargs, client_id, client_secret):
    return oauth2_token(
        token_url=TOKEN_URL,
        client_id=client_id,
        client_secret=client_secret,
        scope="token",
        **get_http_options(config_kwargs)
    )


def fetch_page(config_kwargs, region_url, token, tenant_id, params):
    headers = {
        "Authorization": bearer(token),
        "X-Tenant-ID": tenant_id,
        "Accept": "application/json",
    }
    return get_json(region_url + "/endpoint/v1/endpoints", params=params, **get_http_options(config_kwargs, headers=headers))


def join_pairs(items, key_field, value_field):
    """Render a list of objects as 'key=value; ...' for custom attributes."""
    pairs = []
    for item in items or []:
        key = item.get(key_field)
        if not key:
            continue
        pairs.append("{}={}".format(key, item.get(value_field, "")))
    return "; ".join(pairs)


def join_group_hierarchy(groups):
    names = []
    for group in groups or []:
        name = group.get("name")
        if name:
            names.append(name)
    return " > ".join(names)


def format_tags(tags):
    out = []
    for tag in tags or []:
        if type(tag) == "string":
            out.append(tag)
        elif type(tag) == "dict":
            parts = []
            for key in sorted(tag.keys()):
                val = tag[key]
                if type(val) in ("string", "int", "bool"):
                    parts.append("{}={}".format(key, val))
            if parts:
                out.append(" ".join(parts))
    return "; ".join(out)


def build_os_version(os_info):
    parts = []
    for key in ("majorVersion", "minorVersion", "build"):
        val = os_info.get(key)
        if val == None:
            break
        parts.append(str(val))
    return ".".join(parts)


def build_nics(endpoint):
    # The API returns uncorrelated IP and MAC lists: attach all IPs to the
    # first MAC and emit the remaining MACs as their own interfaces.
    macs = endpoint.get("macAddresses") or []
    ips = (endpoint.get("ipv4Addresses") or []) + (endpoint.get("ipv6Addresses") or [])
    nics = []
    primary = network_interface(mac=macs[0] if macs else None, ips=ips)
    if primary:
        nics.append(primary)
    for mac in macs[1:]:
        nic = network_interface(mac=mac)
        if nic:
            nics.append(nic)
    return nics


def build_software(endpoint):
    software = []
    for product in endpoint.get("assignedProducts") or []:
        code = product.get("code")
        if not code:
            continue
        software.append(Software(
            id=code,
            vendor="Sophos",
            product=code,
            version=product.get("version") or "",
            customAttributes=to_custom_attributes({"status": product.get("status")}),
        ))
    return software


def build_asset(endpoint, tenant_id):
    endpoint_id = endpoint.get("id")
    if not endpoint_id:
        _log("WARN: skipping endpoint record with no id")
        return None

    os_info = endpoint.get("os") or {}
    health = endpoint.get("health") or {}
    threats = health.get("threats") or {}
    services = health.get("services") or {}
    group = endpoint.get("group") or {}
    person = endpoint.get("associatedPerson") or {}
    lockdown = endpoint.get("lockdown") or {}
    isolation = endpoint.get("isolation") or {}
    cloud = endpoint.get("cloud") or {}
    encryption = endpoint.get("encryption") or {}

    attrs = {
        "type": endpoint.get("type"),
        "tenant.id": (endpoint.get("tenant") or {}).get("id") or tenant_id,
        "online": endpoint.get("online"),
        "cloned": endpoint.get("cloned"),
        "serialNumber": endpoint.get("serialNumber"),
        "lastSeenAt": endpoint.get("lastSeenAt"),
        "lastOsUpdateAt": endpoint.get("lastOsUpdateAt"),
        "lastAgentUpdateAt": endpoint.get("lastAgentUpdateAt"),
        "health.overall": health.get("overall"),
        "health.threats.status": threats.get("status"),
        "health.services.status": services.get("status"),
        "health.services.details": join_pairs(services.get("serviceDetails"), "name", "status"),
        "os.platform": os_info.get("platform"),
        "os.isServer": os_info.get("isServer"),
        "group.id": group.get("id"),
        "group.name": group.get("name"),
        "groupHierarchy": join_group_hierarchy(endpoint.get("groupHierarchy")),
        "associatedPerson.id": person.get("id"),
        "associatedPerson.name": person.get("name"),
        "associatedPerson.viaLogin": person.get("viaLogin"),
        "tamperProtectionEnabled": endpoint.get("tamperProtectionEnabled"),
        "tamperProtectionSupported": endpoint.get("tamperProtectionSupported"),
        "lockdown.status": lockdown.get("status"),
        "lockdown.updateStatus": lockdown.get("updateStatus"),
        "isolation.status": isolation.get("status"),
        "isolation.adminIsolated": isolation.get("adminIsolated"),
        "isolation.selfIsolated": isolation.get("selfIsolated"),
        "cloud.provider": cloud.get("provider"),
        "cloud.instanceId": cloud.get("instanceId"),
        "encryption.volumes": join_pairs(encryption.get("volumes"), "volumeId", "status"),
        "tags": format_tags(endpoint.get("tags")),
    }

    device_type = ""
    if endpoint.get("type") == "server" or os_info.get("isServer"):
        device_type = "Server"

    return ImportAsset(
        id="sophos:{}:{}".format(tenant_id, endpoint_id),
        hostnames=[endpoint.get("hostname")],
        os=os_info.get("name") or os_info.get("platform") or "",
        osVersion=build_os_version(os_info),
        deviceType=device_type,
        networkInterfaces=build_nics(endpoint),
        software=build_software(endpoint)[:99],
        customAttributes=to_custom_attributes(attrs),
        # The Sophos endpoint ID is authoritative; do not let IP/MAC/name
        # churn between polls fragment the asset.
        matchBehavior="no-mac-break no-ip-break no-name-break",
    )


def main(*args, **kwargs):
    require(kwargs, "client_id", "client_secret")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    tenant_id = get_string(kwargs, "tenant_id", default="")
    region_url = get_string(kwargs, "data_region_url", default="").rstrip("/")
    endpoint_types = get_list(kwargs, "endpoint_types", default=[])
    last_seen_days = get_int(kwargs, "last_seen_days", default=0)

    token = get_token(kwargs, client_id, client_secret)

    if not tenant_id or not region_url:
        info, err = get_json(WHOAMI_URL, **get_http_options(kwargs, headers={"Authorization": bearer(token), "Accept": "application/json"}))
        if err:
            _log("ERROR: whoami lookup failed: " + err)
            return None
        id_type = info.get("idType", "")
        if not tenant_id:
            if id_type != "tenant":
                _log("ERROR: credential is a '{}' service principal; set the tenant_id and data_region_url parameters to target a specific tenant".format(id_type))
                return None
            tenant_id = info.get("id", "")
        if not region_url:
            region_url = ((info.get("apiHosts") or {}).get("dataRegion") or "").rstrip("/")

    if not tenant_id or not region_url:
        _log("ERROR: could not determine the tenant ID and data region URL")
        return None

    params = {"pageSize": PAGE_SIZE, "view": "full"}
    if endpoint_types:
        params["type"] = ",".join(endpoint_types)
    if last_seen_days > 0:
        params["lastSeenAfter"] = "-P{}D".format(last_seen_days)

    total = 0
    pages = 0
    for _ in range(MAX_PAGES):
        data, err = fetch_page(kwargs, region_url, token, tenant_id, params)
        if err and err.startswith("status 401"):
            _log("access token expired; requesting a new one")
            token = get_token(kwargs, client_id, client_secret)
            data, err = fetch_page(kwargs, region_url, token, tenant_id, params)
        if err:
            _log("ERROR: endpoint fetch failed: " + err)
            break

        page_assets = []
        for endpoint in (data or {}).get("items") or []:
            asset = build_asset(endpoint, tenant_id)
            if asset != None:
                page_assets.append(asset)

        # Stream each page to runZero so the full inventory is never held in memory.
        total += report_assets(page_assets)
        pages += 1
        _log("page {}: reported {} endpoints ({} total)".format(pages, len(page_assets), total))

        next_key = ((data or {}).get("pages") or {}).get("nextKey")
        if not next_key:
            break
        params["pageFromKey"] = next_key

    _log("SUCCESS: reported {} assets from {} pages".format(total, pages))
    return None

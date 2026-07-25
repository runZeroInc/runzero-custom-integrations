# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-automox",
    "name": "Automox",
    "type": "inbound",
    "description": "Imports endpoints from the Automox platform.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "organization_hint",
            "label": "Organization hint",
            "type": "string",
            "required": False,
            "description": "Optional Automox organization ID or name",
        },
        {
            "key": "api_token",
            "label": "Automox API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
## Automox!

load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')

AUTOMOX_BASE_URL = "https://console.automox.com/api"
AUTOMOX_SERVERS_URL = AUTOMOX_BASE_URL + "/servers"
AUTOMOX_ORGS_URL = AUTOMOX_BASE_URL + "/orgs"

def looks_numeric(v):
    if v == None:
        return False
    s = str(v)
    if s == "":
        return False
    return s.isdigit()

def normalize_list(decoded):
    if decoded == None:
        return []
    t = type(decoded)
    if t == "list":
        return decoded
    if t == "dict":
        if "data" in decoded and type(decoded["data"]) == "list":
            return decoded["data"]
        if "results" in decoded and type(decoded["results"]) == "list":
            return decoded["results"]
        if "items" in decoded and type(decoded["items"]) == "list":
            return decoded["items"]
        if "records" in decoded and type(decoded["records"]) == "list":
            return decoded["records"]
        fail("Unexpected dict response (no data/results/items/records list field).")
    fail("Unexpected response type: " + t)

def get_orgs(http_options):
    orgs = []
    page = 0
    limit = 500

    while True:
        params = {"limit": str(limit), "page": str(page)}
        data, err = get_json(AUTOMOX_ORGS_URL, params=params, **http_options)

        if err:
            fail("Failed to fetch orgs from Automox: " + err)

        batch = normalize_list(data)
        if not batch:
            break

        for o in batch:
            orgs.append(o)

        page = page + 1

    return orgs

def choose_org_id(http_options, org_hint):
    if looks_numeric(org_hint):
        return str(org_hint)

    orgs = get_orgs(http_options)
    if not orgs:
        fail("No organizations returned from Automox; cannot determine org_id.")

    oid = orgs[0].get("id", None)
    if oid == None:
        fail("Automox /orgs response missing 'id'.")
    return str(oid)

def fetch_org_packages(http_options, org_id):
    url = AUTOMOX_BASE_URL + "/orgs/" + str(org_id) + "/packages"
    packages = []
    page = 0
    limit = 500

    while True:
        params = {"limit": str(limit), "page": str(page), "o": str(org_id)}
        data, err = get_json(url, params=params, **http_options)

        if err:
            fail("Failed to fetch org packages from Automox: " + err)

        batch = normalize_list(data)
        if not batch:
            break

        for p in batch:
            packages.append(p)

        page = page + 1

    return packages

def index_software_by_server(packages):
    by_server = {}

    for soft in packages:
        sid = soft.get("server_id", None)
        if sid == None:
            continue

        sw = Software(
            id=str(soft.get("id", "")),
            installedFrom=str(soft.get("repo", "")),
            product=str(soft.get("display_name", "")),
            version=str(soft.get("version", "")),
            customAttributes=to_custom_attributes({
                "server_id": soft.get("server_id"),
                "package_id": soft.get("package_id"),
                "software_id": soft.get("software_id"),
                "installed": soft.get("installed"),
                "ignored": soft.get("ignored"),
                "group_ignored": soft.get("group_ignored"),
                "deferred_until": soft.get("deferred_until"),
                "group_deferred_until": soft.get("group_deferred_until"),
                "name": soft.get("name"),
                "cves": soft.get("cves"),
                "cve_score": soft.get("cve_score"),
                "agent_severity": soft.get("agent_severity"),
                "severity": soft.get("severity"),
                "package_version_id": soft.get("package_version_id"),
                "os_name": soft.get("os_name"),
                "os_version": soft.get("os_version"),
                "os_version_id": soft.get("os_version_id"),
                "create_time": soft.get("create_time"),
                "requires_reboot": soft.get("requires_reboot"),
                "patch_classification_category_id": soft.get("patch_classification_category_id"),
                "patch_scope": soft.get("patch_scope"),
                "is_uninstallable": soft.get("is_uninstallable"),
                "secondary_id": soft.get("secondary_id"),
                "is_managed": soft.get("is_managed"),
                "impact": soft.get("impact"),
                "organization_id": soft.get("organization_id"),
            }),
        )

        key = str(sid)
        if key not in by_server:
            by_server[key] = []
        by_server[key].append(sw)

    return by_server

def build_network_interfaces_from_device(device):
    details = device.get("details", device.get("detail", {}))
    if type(details) == "dict":
        nics = details.get("NICS", None)
        if type(nics) == "list" and nics:
            out = []
            for nic in nics[:99]:
                mac = nic.get("MAC", "")
                ips = nic.get("IPS", [])
                out.append(network_interface(ips=ips, mac=mac))
            if out:
                return out

    ips = device.get("ip_addrs", []) + device.get("ip_addrs_private", [])
    return [network_interface(ips=ips, mac="")]

def build_device_asset(device, sw_by_server):
    device_id = device.get("id")
    if not device_id:
        print("automox: skipping device with no id: name=" + str(device.get("name", "")))
        return None

    custom_attrs = {
        "os_version": device.get("os_version", ""),
        "os_name": device.get("os_name", ""),
        "os_family": device.get("os_family", ""),
        "agent_version": device.get("agent_version", ""),
        "compliant": str(device.get("compliant", "")),
        "last_logged_in_user": device.get("last_logged_in_user", ""),
        "serial_number": device.get("serial_number", ""),
        "agent_status": device.get("status", {}).get("agent_status", ""),
    }

    return ImportAsset(
        id=str(device_id),
        networkInterfaces=build_network_interfaces_from_device(device),
        hostnames=[device.get("name", "")],
        os_version=device.get("os_version", ""),
        os=device.get("os_family", "") + " " +  device.get("os_name", ""),
        software=sw_by_server.get(str(device_id), []),
        customAttributes=to_custom_attributes(custom_attrs),
        trust_device_type=True,
        trust_os=True,
        trust_os_version=True,
    )

def stream_device_assets(http_options, org_hint, sw_by_server):
    """Paginate Automox devices, building and streaming each page of assets via
    report_assets so the full device set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    page = 0
    limit = 500
    use_o = looks_numeric(org_hint)

    while True:
        params = {"limit": str(limit), "page": str(page), "include_details": "1"}
        if use_o:
            params["o"] = str(org_hint)

        data, err = get_json(AUTOMOX_SERVERS_URL, params=params, **http_options)

        if err and err.startswith("status 404") and use_o:
            use_o = False
            reported = 0
            page = 0
            continue

        if err:
            fail("Failed to fetch devices from Automox: " + err)

        batch = normalize_list(data)
        if not batch:
            break

        page_assets = []
        for device in batch:
            asset = build_device_asset(device, sw_by_server)
            if asset:
                page_assets.append(asset)
        reported += report_assets(page_assets)

        page = page + 1

    return reported

def build_assets(api_token, org_hint, config_kwargs):
    headers = {"Authorization": "Bearer " + api_token, "Content-Type": "application/json"}
    http_options = get_http_options(config_kwargs, headers=headers)

    org_id = choose_org_id(http_options, org_hint)

    packages = fetch_org_packages(http_options, org_id)
    sw_by_server = index_software_by_server(packages)

    return stream_device_assets(http_options, org_hint, sw_by_server)

def main(**kwargs):
    org_hint = kwargs.get("organization_hint", None)
    api_token = kwargs.get("api_token", None)

    if not api_token:
        fail("Missing api_token (Automox API token).")

    # Assets are streamed page-by-page via report_assets in build_assets.
    build_assets(api_token, org_hint, kwargs)
    return None

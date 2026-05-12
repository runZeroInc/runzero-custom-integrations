## Automox!

load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')
load('uuid', 'new_uuid')

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

def get_automox_devices(headers, org_hint):
    devices = []
    page = 0
    limit = 500
    use_o = looks_numeric(org_hint)

    while True:
        params = {"limit": str(limit), "page": str(page), "include_details": "1"}
        if use_o:
            params["o"] = str(org_hint)

        resp = http_get(AUTOMOX_SERVERS_URL, headers=headers, params=params)

        if resp.status_code == 404 and use_o:
            use_o = False
            devices = []
            page = 0
            continue

        if resp.status_code != 200:
            fail("Failed to fetch devices from Automox: " + str(resp.status_code))

        batch = normalize_list(json_decode(resp.body))
        if not batch:
            break

        for d in batch:
            devices.append(d)

        page = page + 1

    return devices

def get_orgs(headers):
    orgs = []
    page = 0
    limit = 500

    while True:
        params = {"limit": str(limit), "page": str(page)}
        resp = http_get(AUTOMOX_ORGS_URL, headers=headers, params=params)

        if resp.status_code != 200:
            fail("Failed to fetch orgs from Automox: " + str(resp.status_code))

        batch = normalize_list(json_decode(resp.body))
        if not batch:
            break

        for o in batch:
            orgs.append(o)

        page = page + 1

    return orgs

def choose_org_id(headers, org_hint):
    if looks_numeric(org_hint):
        return str(org_hint)

    orgs = get_orgs(headers)
    if not orgs:
        fail("No organizations returned from Automox; cannot determine org_id.")

    oid = orgs[0].get("id", None)
    if oid == None:
        fail("Automox /orgs response missing 'id'.")
    return str(oid)

def fetch_org_packages(headers, org_id):
    url = AUTOMOX_BASE_URL + "/orgs/" + str(org_id) + "/packages"
    packages = []
    page = 0
    limit = 500

    while True:
        params = {"limit": str(limit), "page": str(page), "o": str(org_id)}
        resp = http_get(url, headers=headers, params=params)

        if resp.status_code != 200:
            fail("Failed to fetch org packages from Automox: " + str(resp.status_code))

        batch = normalize_list(json_decode(resp.body))
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
            customAttributes={
                "server_id": str(soft.get("server_id", "")),
                "package_id": str(soft.get("package_id", "")),
                "software_id": str(soft.get("software_id", "")),
                "installed": str(soft.get("installed", "")),
                "ignored": str(soft.get("ignored", "")),
                "group_ignored": str(soft.get("group_ignored", "")),
                "deferred_until": str(soft.get("deferred_until", "")),
                "group_deferred_until": str(soft.get("group_deferred_until", "")),
                "name": str(soft.get("name", "")),
                "cves": str(soft.get("cves", "")),
                "cve_score": str(soft.get("cve_score", "")),
                "agent_severity": str(soft.get("agent_severity", "")),
                "severity": str(soft.get("severity", "")),
                "package_version_id": str(soft.get("package_version_id", "")),
                "os_name": str(soft.get("os_name", "")),
                "os_version": str(soft.get("os_version", "")),
                "os_version_id": str(soft.get("os_version_id", "")),
                "create_time": str(soft.get("create_time", "")),
                "requires_reboot": str(soft.get("requires_reboot", "")),
                "patch_classification_category_id": str(soft.get("patch_classification_category_id", "")),
                "patch_scope": str(soft.get("patch_scope", "")),
                "is_uninstallable": str(soft.get("is_uninstallable", "")),
                "secondary_id": str(soft.get("secondary_id", "")),
                "is_managed": str(soft.get("is_managed", "")),
                "impact": str(soft.get("impact", "")),
                "organization_id": str(soft.get("organization_id", "")),
            },
        )

        key = str(sid)
        if key not in by_server:
            by_server[key] = []
        by_server[key].append(sw)

    return by_server

def build_network_interface(ips, mac=None):
    ip4s = []
    ip6s = []

    for ip in ips[:99]:
        if not ip:
            continue
        addr = ip_address(ip)
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def build_network_interfaces_from_device(device):
    details = device.get("details", device.get("detail", {}))
    if type(details) == "dict":
        nics = details.get("NICS", None)
        if type(nics) == "list" and nics:
            out = []
            for nic in nics[:99]:
                mac = nic.get("MAC", "")
                ips = nic.get("IPS", [])
                out.append(build_network_interface(ips, mac))
            if out:
                return out

    ips = device.get("ip_addrs", []) + device.get("ip_addrs_private", [])
    return [build_network_interface(ips, "")]

def build_assets(api_token, org_hint):
    headers = {"Authorization": "Bearer " + api_token, "Content-Type": "application/json"}

    devices = get_automox_devices(headers, org_hint)
    org_id = choose_org_id(headers, org_hint)

    packages = fetch_org_packages(headers, org_id)
    sw_by_server = index_software_by_server(packages)

    assets = []
    for device in devices:
        device_id = device.get("id", new_uuid())

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

        assets.append(
            ImportAsset(
                id=str(device_id),
                networkInterfaces=build_network_interfaces_from_device(device),
                hostnames=[device.get("name", "")],
                os_version=device.get("os_version", ""),
                os=device.get("os_family", "") + " " +  device.get("os_name", ""),
                software=sw_by_server.get(str(device_id), []),
                customAttributes=custom_attrs,
                trust_device_type=True,
                trust_os=True,
                trust_os_version=True
            )
        )

    return assets

def main(**kwargs):
    org_hint = kwargs.get("access_key", None)
    api_token = kwargs.get("access_secret", None)

    if not api_token:
        fail("Missing access_secret (Automox API token).")

    assets = build_assets(api_token, org_hint)
    if not assets:
        return None
    return assets

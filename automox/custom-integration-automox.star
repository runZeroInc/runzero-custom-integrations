## Automox!

load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')
load('uuid', 'new_uuid')

AUTOMOX_API_URL = "https://console.automox.com/api/servers"

def get_automox_devices(headers):
    """Retrieve all devices from Automox using pagination"""

    query = {
        "limit": "500",
        "page": "0"
    }

    devices = []

    while True:
        response = http_get(AUTOMOX_API_URL, headers=headers, params=query)

        if response.status_code != 200:
            print("Failed to fetch devices from Automox. Status:", response.status_code)
            return devices

        batch = json_decode(response.body)

        if not batch:
            break  # Stop fetching if no more results are returned

        devices.extend(batch)
        query["page"] = str(int(query["page"]) + 1)

    print("Loaded", len(devices), "devices")
    return devices

def build_assets(api_token, org_id=None):
    """Convert Automox device data into runZero asset format"""
    headers = {
        "Authorization": "Bearer " + api_token,
        "Content-Type": "application/json"
    }
    all_devices = get_automox_devices(headers)
    assets = []

    for device in all_devices:
        device_id = device.get("id", new_uuid())
        custom_attrs = {
            "os_version": device.get("os_version", ""),
            "os_name": device.get("os_name", ""),
            "os_family": device.get("os_family", ""),
            "agent_version": device.get("agent_version", ""),
            "compliant": str(device.get("compliant", "")),
            "last_logged_in_user": device.get("last_logged_in_user", ""),
            "serial_number": device.get("serial_number", ""),
            "agent_status": device.get("status", {}).get("agent_status", "")
        }

        mac_address = ""
        if device.get("detail", {}).get("NICS"):
            mac_address = device["detail"]["NICS"][0].get("MAC", "")

        # Collect IPs
        ips = device.get("ip_addrs", []) + device.get("ip_addrs_private", [])

        # Append software if org_id is passed
        if org_id:
            software_list = build_software_list(org_id, device_id, headers)

        assets.append(
            ImportAsset(
                id=str(device_id),
                networkInterfaces=[build_network_interface(ips, mac_address)],
                hostnames=[device.get("name", "")],
                os_version=device.get("os_version", ""),
                os=device.get("os_name", ""),
                customAttributes=custom_attrs
            )
        )
    return assets

def build_software_list(org_id, device_id, headers):
    # Fetch software inventory from Automox API
    automox_software_url = "https://console.automox.com/api/servers/" + str(device_id) + "/packages?o=" + str(org_id)
    
    software_response = http_get(automox_software_url, headers=headers)
    
    if software_response.status_code != 200:
        fail("Failed to fetch software inventory: " + str(software_response.status_code))
        
    software_inventory = json_decode(software_response.body)
    
    software_list = []
    for soft in software_inventory:
        transformed_software = Software (
            id = str(soft.get("id", "")),
            installedFrom = str(soft.get("repo", "")),
            product = str(soft.get("display_name", "")),
            version = str(soft.get("version", "")),
            customAttributes = {
                "server_id": str(soft.get("server_id", "")),
                "package_id": str(soft.get("package_id", "")),
                "software_id": str(soft.get("software_id", "")),
                "installed": soft.get("installed", ""),
                "ignored": soft.get("ignored", ""),
                "group_ignored": soft.get("group_ignored", ""),
                "deferred_until": soft.get("deferred_until", ""),
                "group_deferred_until": soft.get("group_deferred_until", ""),
                "name": str(soft.get("name", "")),
                "cves": str(soft.get("cves", "")),
                "cve_score": soft.get("cve_score", ""),
                "agent_severity": str(soft.get("agent_severity", "")),
                "severity": str(soft.get("severity", "")),
                "package_version_id": str(soft.get("package_version_id", "")),
                "os_name": str(soft.get("os_name", "")),
                "os_version": str(soft.get("os_version", "")),
                "os_version_id": str(soft.get("os_version_id", "")),
                "create_time": str(soft.get("create_time", "")),
                "requires_reboot": soft.get("requires_reboot", ""),
                "patch_classification_category_id": str(soft.get("patch_classification_category_id", "")),
                "patch_scope": str(soft.get("patch_scope", "")),
                "is_uninstallable": soft.get("is_uninstallable", ""),
                "secondary_id": str(soft.get("secondary_id", "")),
                "is_managed": soft.get("is_managed", ""),
                "impact": str(soft.get("impact", "")),
                "organization_id": str(soft.get("organization_id", ""))
            },                  
        )        
        # Only append if not empty
        if transformed_software:
            software_list.append(transformed_software)
    
    return software_list

def build_network_interface(ips, mac=None):
    """Convert IPs and MAC addresses into a NetworkInterface object"""
    ip4s = []
    ip6s = []

    for ip in ips[:99]:
        if ip:
            ip_addr = ip_address(ip)
            if ip_addr.version == 4:
                ip4s.append(ip_addr)
            elif ip_addr.version == 6:
                ip6s.append(ip_addr)
        else:
            continue

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    """Main function to retrieve and return Automox asset data"""
    org_id = kwargs.get("access_key", None)
    api_token = kwargs['access_secret']  # Use API token from runZero credentials

    assets = build_assets(api_token, org_id)
    
    if not assets:
        print("No assets retrieved from Automox")
        return None

    return assets

#
# runZero Starlark script for Ubiquiti UniFi Network Integration API
#
# This version adds the ability to extract UniFi network devices (switches, APs)
# and provides toggles to enable/disable client and device extraction.
#

# Load necessary runZero and Starlark libraries
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get', url_encode='url_encode')
load('time', 'parse_time')

# --- USER CONFIGURATION ---
# IMPORTANT: Update these variables to match your UniFi Network Controller setup.

# The base URL of your UniFi Network Controller (e.g., https://192.168.1.1)
UNIFI_CONTROLLER_URL = "https://<your-unifi-controller-url>"
# The NAME of the site you want to pull data from.
UNIFI_SITE_NAME = "Default"
# Set to True to extract client devices, False to skip.
EXTRACT_CLIENTS = True
# Set to True to extract UniFi network devices (switches, APs), False to skip.
EXTRACT_DEVICES = True
# (Optional) A filter to apply to the client query. Leave as "" to disable.
# Example: "ipAddress.eq('192.168.5.5')" or "type.eq('WIRED')"
UNIFI_CLIENT_API_FILTER = ""
# UniFi controllers often use self-signed certificates. Set to True to allow this.
INSECURE_SKIP_VERIFY = True
# The number of items to request per API call. 100 is a safe default.
PAGE_LIMIT = 100

# --- END OF USER CONFIGURATION ---

def get_site_id(base_url, api_key, site_name):
    """
    Finds the UUID for a given site name.
    """
    sites_url = base_url + "/proxy/network/integration/v1/sites"
    headers = { "X-API-KEY": api_key, "Accept": "application/json" }
    
    print("Attempting to find ID for site '{}'...".format(site_name))
    response = http_get(url=sites_url, headers=headers, insecure_skip_verify=INSECURE_SKIP_VERIFY)

    if response.status_code != 200:
        print("Failed to get sites list. Status code: {}".format(response.status_code))
        return None

    response_json = json_decode(response.body)

    if type(response_json) != "dict" or "data" not in response_json:
        print("API did not return a valid sites object.")
        return None
    
    for site in response_json.get("data", []):
        if site.get("name") == site_name:
            site_id = site.get("id")
            print("Found site ID: {}".format(site_id))
            return site_id
            
    print("Error: Could not find a site with the name '{}'.".format(site_name))
    return None

def get_all_clients(base_url, api_key, site_id):
    """
    Fetches all client devices from the UniFi API, handling pagination and an optional filter.
    """
    all_clients = []
    offset = 0

    while True:
        params = {"offset": str(offset), "limit": str(PAGE_LIMIT)}
        
        if UNIFI_CLIENT_API_FILTER:
            params["filter"] = UNIFI_CLIENT_API_FILTER
            
        clients_url = base_url + "/proxy/network/integration/v1/sites/{}/clients?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response = http_get(url=clients_url, headers=headers, insecure_skip_verify=INSECURE_SKIP_VERIFY)

        if response.status_code != 200:
            print("Failed to retrieve clients. Status code: {}".format(response.status_code))
            break

        response_json = json_decode(response.body)
        if type(response_json) != "dict":
            print("API did not return a valid JSON object while fetching clients.")
            break
        
        clients_batch = response_json.get("data", [])
        if not clients_batch:
            break
        
        all_clients.extend(clients_batch)
        total_count = response_json.get("totalCount", 0)
        current_count = len(all_clients)
        print("Fetched {}/{} clients...".format(current_count, total_count))

        if current_count >= total_count:
            break
        
        offset += PAGE_LIMIT
        
    return all_clients

def get_all_devices(base_url, api_key, site_id):
    """
    Fetches all network devices (switches, APs, etc.) from the UniFi API, handling pagination.
    """
    all_devices = []
    offset = 0

    while True:
        params = {"offset": str(offset), "limit": str(PAGE_LIMIT)}
        devices_url = base_url + "/proxy/network/integration/v1/sites/{}/devices?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response = http_get(url=devices_url, headers=headers, insecure_skip_verify=INSECURE_SKIP_VERIFY)

        if response.status_code != 200:
            print("Failed to retrieve devices. Status code: {}".format(response.status_code))
            break

        response_json = json_decode(response.body)
        if type(response_json) != "dict":
            print("API did not return a valid JSON object while fetching devices.")
            break
        
        devices_batch = response_json.get("data", [])
        if not devices_batch:
            break
        
        all_devices.extend(devices_batch)
        total_count = response_json.get("totalCount", 0)
        current_count = len(all_devices)
        print("Fetched {}/{} devices...".format(current_count, total_count))

        if current_count >= total_count:
            break
        
        offset += PAGE_LIMIT
        
    return all_devices

def build_network_interface(ips, mac):
    """
    A helper function to build a runZero NetworkInterface object.
    """
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        if ip:
            ip_addr = ip_address(ip)
            if ip_addr.version == 4:
                ip4s.append(ip_addr)
            elif ip_addr.version == 6:
                ip6s.append(ip_addr)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def build_client_assets(clients_json):
    """
    Converts client data from UniFi into a list of runZero ImportAsset objects.
    """
    assets = []
    for client in clients_json:
        mac = client.get("macAddress")
        hostname = client.get("name")

        if mac and hostname:
            mac_parts = mac.split(":")
            if len(mac_parts) == 6:
                mac_suffix = " " + ":".join(mac_parts[4:])
                if hostname.endswith(mac_suffix):
                    hostname = hostname.removesuffix(mac_suffix)

        if not mac:
            continue

        ip = client.get("ipAddress")
        ips = [ip] if ip else []
        network = build_network_interface(ips=ips, mac=mac)
        hostnames = [hostname] if hostname else []
        connectedAt = parse_time(client.get("connectedAt"))

        custom_attrs = {
            "unifi_id": client.get("id", ""),
            "connectionType": client.get("type", ""),
            "connectedAt": connectedAt,
            "connectedAtTS": connectedAt.unix,
            "uplinkDeviceId": client.get("uplinkDeviceId", "")
        }
        
        assets.append(
            ImportAsset(
                id=mac,
                hostnames=hostnames,
                networkInterfaces=[network],
                customAttributes=custom_attrs
            )
        )
    return assets

def build_device_assets(devices_json):
    """
    Converts UniFi device data into a list of runZero ImportAsset objects.
    """
    assets = []
    for device in devices_json:
        mac = device.get("macAddress")
        if not mac:
            continue

        ip = device.get("ipAddress")
        ips = [ip] if ip else []
        network = build_network_interface(ips=ips, mac=mac)
        
        hostname = device.get("name")
        hostnames = [hostname] if hostname else []

        model = device.get("model", "UniFi Device")
        device_type = "Unknown"
        # Attempt to determine a more specific device type from the model name
        if "USW" in model:
            device_type = "Switch"
        elif "UAP" in model or "U6" in model:
            device_type = "WAP"
        elif "UDM" in model or "USG" in model:
            device_type = "Gateway"

        custom_attrs = {
            "unifi_id": device.get("id", ""),
            "unifi_state": device.get("state", ""),
            "unifi_features": ", ".join(device.get("features", [])),
            "unifi_interfaces": ", ".join(device.get("interfaces", []))
        }
        
        assets.append(
            ImportAsset(
                id=mac,
                hostnames=hostnames,
                networkInterfaces=[network],
                manufacturer="Ubiquiti",
                model=model,
                deviceType=device_type,
                customAttributes=custom_attrs
            )
        )
    return assets


def main(**kwargs):
    """
    The main entrypoint for the runZero custom integration script.
    """
    api_key = kwargs.get('access_secret')

    if not api_key:
        print("UniFi Network API Key (access_secret) not provided in credentials.")
        return []

    if UNIFI_CONTROLLER_URL == "https://<your-unifi-controller-url>":
        print("ERROR: Please update the UNIFI_CONTROLLER_URL variable in the script.")
        return []

    # 1. Find the Site ID from the Site Name
    site_id = get_site_id(UNIFI_CONTROLLER_URL, api_key, UNIFI_SITE_NAME)
    if not site_id:
        return []

    all_assets = []

    # 2. Get and process clients if enabled
    if EXTRACT_CLIENTS:
        print("--- Starting Client Extraction ---")
        clients = get_all_clients(UNIFI_CONTROLLER_URL, api_key, site_id)
        if not clients:
            print("No clients returned. This could be due to the filter applied or none exist.")
        else:
            print("Total clients found: {}.".format(len(clients)))
            client_assets = build_client_assets(clients)
            all_assets.extend(client_assets)
            print("Created {} client assets for import.".format(len(client_assets)))
    else:
        print("--- Skipping Client Extraction (EXTRACT_CLIENTS is False) ---")

    # 3. Get and process devices if enabled
    if EXTRACT_DEVICES:
        print("--- Starting Device Extraction ---")
        devices = get_all_devices(UNIFI_CONTROLLER_URL, api_key, site_id)
        if not devices:
            print("No devices found.")
        else:
            print("Total devices found: {}.".format(len(devices)))
            device_assets = build_device_assets(devices)
            all_assets.extend(device_assets)
            print("Created {} device assets for import.".format(len(device_assets)))
    else:
        print("--- Skipping Device Extraction (EXTRACT_DEVICES is False) ---")

    print("--- Import Summary ---")
    print("Total assets created: {}.".format(len(all_assets)))
    return all_assets

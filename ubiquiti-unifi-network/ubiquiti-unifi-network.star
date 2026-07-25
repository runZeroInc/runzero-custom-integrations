# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-ubiquiti-unifi-network",
    "name": "Ubiquiti UniFi Network",
    "type": "inbound",
    "description": "Imports devices from a UniFi Network controller.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "UniFi controller URL",
            "type": "url",
            "required": True,
            "placeholder": "https://controller.example.com",
        },
        {
            "key": "site_name",
            "label": "Site name",
            "type": "string",
            "required": False,
            "default": "Default",
        },
        {
            "key": "extract_clients",
            "label": "Extract clients",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "extract_devices",
            "label": "Extract devices",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "client_api_filter",
            "label": "Client API filter",
            "type": "string",
            "required": False,
        },
        {
            "key": "page_limit",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
#
# runZero Starlark script for Ubiquiti UniFi Network Integration API
#
# This version adds the ability to extract UniFi network devices (switches, APs)
# and provides toggles to enable/disable client and device extraction.
#

# Load necessary runZero and Starlark libraries
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', url_encode='url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_bool', 'get_string', 'get_int')
load('time', 'parse_time')

DEFAULT_SITE_NAME = "Default"
DEFAULT_EXTRACT_CLIENTS = True
DEFAULT_EXTRACT_DEVICES = True
DEFAULT_CLIENT_API_FILTER = ""
DEFAULT_PAGE_LIMIT = 100

def get_site_id(base_url, api_key, site_name, config_kwargs):
    """
    Finds the UUID for a given site name.
    """
    sites_url = base_url + "/proxy/network/integration/v1/sites"
    headers = { "X-API-KEY": api_key, "Accept": "application/json" }
    
    print("Attempting to find ID for site '{}'...".format(site_name))
    response_json, err = get_json(url=sites_url, **get_http_options(config_kwargs, headers=headers))

    if err:
        print("Failed to get sites list:", err)
        return None

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

def get_all_clients(base_url, api_key, site_id, page_limit, client_filter, config_kwargs):
    """
    Fetches all client devices from the UniFi API, building and streaming each
    page of assets via report_assets so the full client set is never buffered.
    Returns the number of client assets reported.
    """
    reported = 0
    offset = 0

    while True:
        params = {"offset": str(offset), "limit": str(page_limit)}

        if client_filter:
            params["filter"] = client_filter
            
        clients_url = base_url + "/proxy/network/integration/v1/sites/{}/clients?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=clients_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            print("Failed to retrieve clients:", err)
            break
        if type(response_json) != "dict":
            print("API did not return a valid JSON object while fetching clients.")
            break
        
        clients_batch = response_json.get("data", [])
        if not clients_batch:
            break
        
        reported += report_assets(build_client_assets(clients_batch))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(clients_batch)
        print("Fetched {}/{} clients...".format(current_count, total_count))

        if current_count >= total_count:
            break

        offset += page_limit

    return reported

def get_all_devices(base_url, api_key, site_id, page_limit, config_kwargs):
    """
    Fetches all network devices (switches, APs, etc.) from the UniFi API,
    building and streaming each page of assets via report_assets. Returns the
    number of device assets reported.
    """
    reported = 0
    offset = 0

    while True:
        params = {"offset": str(offset), "limit": str(page_limit)}
        devices_url = base_url + "/proxy/network/integration/v1/sites/{}/devices?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=devices_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            print("Failed to retrieve devices:", err)
            break
        if type(response_json) != "dict":
            print("API did not return a valid JSON object while fetching devices.")
            break
        
        devices_batch = response_json.get("data", [])
        if not devices_batch:
            break
        
        reported += report_assets(build_device_assets(devices_batch))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(devices_batch)
        print("Fetched {}/{} devices...".format(current_count, total_count))

        if current_count >= total_count:
            break

        offset += page_limit

    return reported

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
        network = network_interface(ips=ips, mac=mac)
        hostnames=[hostname]
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
                customAttributes=to_custom_attributes(custom_attrs),
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
        network = network_interface(ips=ips, mac=mac)
        
        hostname = device.get("name")
        hostnames=[hostname]

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
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )
    return assets


def main(**kwargs):
    """
    The main entrypoint for the runZero custom integration script.
    """
    base_url = get_url_base(kwargs)
    site_name = get_string(kwargs, "site_name", DEFAULT_SITE_NAME)
    extract_clients = get_bool(kwargs, "extract_clients", DEFAULT_EXTRACT_CLIENTS)
    extract_devices = get_bool(kwargs, "extract_devices", DEFAULT_EXTRACT_DEVICES)
    client_filter = get_string(kwargs, "client_api_filter", DEFAULT_CLIENT_API_FILTER)
    page_limit = get_int(kwargs, "page_limit", DEFAULT_PAGE_LIMIT)

    api_key = kwargs.get('api_key')

    if not api_key:
        print("UniFi Network API key not provided in credentials.")
        return None

    # 1. Find the Site ID from the Site Name
    site_id = get_site_id(base_url, api_key, site_name, kwargs)
    if not site_id:
        return None

    total = 0

    # 2. Get and process clients if enabled
    if extract_clients:
        print("--- Starting Client Extraction ---")
        client_count = get_all_clients(base_url, api_key, site_id, page_limit, client_filter, kwargs)
        print("Created {} client assets for import.".format(client_count))
        total += client_count
    else:
        print("--- Skipping Client Extraction (extract_clients is False) ---")

    # 3. Get and process devices if enabled
    if extract_devices:
        print("--- Starting Device Extraction ---")
        device_count = get_all_devices(base_url, api_key, site_id, page_limit, kwargs)
        print("Created {} device assets for import.".format(device_count))
        total += device_count
    else:
        print("--- Skipping Device Extraction (extract_devices is False) ---")

    print("--- Import Summary ---")
    print("Total assets created: {}.".format(total))
    # Assets are streamed via report_assets above; nothing to return here.
    return None

## Kandji

load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('http', http_get='get')
load('net', 'ip_address')

KANDJI_API_URL = "https://{sub_domain}.kandji.io/api/v1"
PAGE_LIMIT = 300  # Number of devices to fetch per request

def get_device_list(api_token):
    """Fetch all devices from Kandji with pagination."""
    headers = {
        "Authorization": "Bearer " + api_token,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    devices = []
    offset = 0

    while True:
        params = {
            "limit": str(PAGE_LIMIT),
            "offset": str(offset)
        }
        response = http_get(KANDJI_API_URL + "/devices", headers=headers, params=params)
        
        if response.status_code != 200:
            print("Error fetching device list from Kandji", response.status_code)
            break
        
        data = json_decode(response.body)

        if not data:
            break
        
        devices.extend(data)
        offset += PAGE_LIMIT

    return devices

def get_device_details(api_token, device_id):
    """Fetch detailed information for a single device."""
    headers = {
        "Authorization": "Bearer " + api_token,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    url = "{}/devices/{}/details".format(KANDJI_API_URL, device_id)
    response = http_get(url, headers=headers)
    
    if response.status_code != 200:
        print("Error fetching details for device:", device_id)
        return None
    
    return json_decode(response.body)

def build_assets(api_token):
    """Retrieve Kandji devices and transform them into runZero assets."""
    devices = get_device_list(api_token)
    assets = []

    for device in devices:
        device_id = device.get("device_id", "")
        details = get_device_details(api_token, device_id)
        if not details:
            continue

        general = details.get("general", "")
        agent_details = details.get("kandji_agent", "")
        network = details.get("network", "")
        hardware_overview = details.get("hardware_overview", "")
        
        hostname = network.get("local_hostname", "")
        mac_address = network.get("mac_address", "")

        ips = [network.get("ip_address", []) + network.get("public_ip", [])]
        
        serial_number = hardware_overview.get("serial_number", "")
        os_version = general.get("os_version", "")
        model = general.get("model", "")

        custom_attrs = {
            "model": model,
            "serial_number": serial_number
        }
        
        assets.append(
            ImportAsset(
                id=device_id,
                hostnames=[hostname],
                networkInterfaces=[build_network_interface(ips,mac_address)],
                os=model,
                os_version=os_version,
                customAttributes=custom_attrs
            )
        )

    return assets

def build_network_interface(ips, mac=None):
    """Convert IPs and MAC addresses into a NetworkInterface object"""
    ip4s = []
    ip6s = []

    for ip in ips[:99]:
        if ip:
            ip_addr = ip_address(ip)
            if ip_addr == None:
                continue
            elif ip_addr.version == 4:
                ip4s.append(ip_addr)
            elif ip_addr.version == 6:
                ip6s.append(ip_addr)
            else:
                continue

    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    api_token = kwargs['access_secret']

    assets = build_assets(api_token)

    if not assets:
        print("No assets found in Kandji")
        return None

    return assets

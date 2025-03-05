## Cortex XDR integration

load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

CORTEX_API_URL = "<UPDATE_ME>/public_api/v1/"

def do_cortex_api_call(api_key, api_key_id, api_call, post_data={}):
    """Perform API request to Cortex XDR, handling authentication"""

    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key,
        "Content-Type": "application/json"
    }

    response = http_post(CORTEX_API_URL + api_call, headers=headers, body=bytes(json_encode(post_data)))

    if response.status_code != 200:
        print("API call failed:", response.status_code)
        return None

    return json_decode(response.body)

def get_all_cortex_endpoints(api_key, api_key_id):
    """Retrieve all Cortex XDR endpoints using pagination"""
    cortex_filter = {"request_data": {"search_from": 0, "search_to": 100}}
    all_endpoints = []
    page_size = 100

    while True:
        result = do_cortex_api_call(api_key, api_key_id, "endpoints/get_endpoint", cortex_filter)

        if not result or "reply" not in result:
            print("Error retrieving endpoints")
            break

        fetched_endpoints = result["reply"].get("endpoints", [])
        all_endpoints.extend(fetched_endpoints)

        if len(fetched_endpoints) < page_size:
            break  # Stop when fewer than page_size results are returned

        cortex_filter["request_data"]["search_from"] += page_size
        cortex_filter["request_data"]["search_to"] += page_size

    print("Loaded", len(all_endpoints), "endpoints")
    return all_endpoints

def build_assets(api_key, api_key_id):
    """Convert Cortex XDR endpoint data into runZero asset format"""
    all_endpoints = get_all_cortex_endpoints(api_key, api_key_id)
    assets = []

    for endpoint in all_endpoints:
        custom_attrs = {
            "operational_status": endpoint.get("operational_status", ""),
            "agent_status": endpoint.get("endpoint_status", ""),
            "agent_type": endpoint.get("endpoint_type", ""),
            "last_seen": str(int(endpoint.get("last_seen", 0) / 1000)),
            "first_seen": str(int(endpoint.get("first_seen", 0) / 1000)),
            "groups": ";".join(endpoint.get("group_name", [])),
            "assigned_prevention_policy": endpoint.get("assigned_prevention_policy", ""),
            "assigned_extensions_policy": endpoint.get("assigned_extensions_policy", ""),
            "endpoint_version": endpoint.get("endpoint_version", "")
        }

        mac_address = endpoint.get("mac_address", [""])[0] if endpoint.get("mac_address") else ""

        assets.append(
            ImportAsset(
                id=str(endpoint.get("endpoint_id", new_uuid())),
                networkInterfaces=[build_network_interface(endpoint.get("ip", []) + endpoint.get("ipv6", []), mac_address)],
                hostnames=[endpoint.get("endpoint_name", "")],
                os_version=endpoint.get("os_version", ""),
                os=endpoint.get("operating_system", ""),
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
            if ip_addr.version == 4:
                ip4s.append(ip_addr)
            elif ip_addr.version == 6:
                ip6s.append(ip_addr)
        else:
            continue

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    """Main function to retrieve and return Cortex XDR asset data"""
    api_key = kwargs['access_secret']  # Use API token from runZero credentials
    api_key_id = kwargs['access_key']  # Use API key ID

    assets = build_assets(api_key, api_key_id)
    
    if not assets:
        print("No assets retrieved from Cortex XDR")
        return None

    return assets

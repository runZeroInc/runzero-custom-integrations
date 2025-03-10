load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')

JAMF_URL = 'https://<UPDATE_ME>.jamfcloud.com'
MAX_REQUESTS = 100  # Number of API calls before getting a new token

def get_bearer_token(client_id, client_secret):
    """Obtain a new bearer token and return it with an initial request count."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'accept': 'application/json'}
    params = {'client_id': client_id, 'client_secret': client_secret, 'grant_type': 'client_credentials'}
    url = "{}/api/oauth/token".format(JAMF_URL)

    resp = http_post(url, headers=headers, body=bytes(url_encode(params)))
    if resp.status_code != 200:
        print("Failed to retrieve bearer token. Status code:", resp.status_code)
        return None, 0

    body_json = json_decode(resp.body)
    if not body_json:
        print("Invalid JSON response for bearer token")
        return None, 0

    token = body_json['access_token']
    return token, 0  # Reset request counter when new token is obtained

def get_valid_token(token, request_count, client_id, client_secret):
    """Renew token after a certain number of requests."""
    if token and request_count < MAX_REQUESTS:
        return token, request_count + 1
    else:
        print("Fetching new token after", request_count, "requests")
        return get_bearer_token(client_id, client_secret)

def http_request(method, url, headers=None, params=None, body=None, token=None, request_count=None, client_id=None, client_secret=None):
    """Handles HTTP requests, gets a new token after MAX_REQUESTS, and retries if 403 occurs."""
    token, request_count = get_valid_token(token, request_count, client_id, client_secret)
    if not token:
        return None, token, request_count
    
    if not params:
        params = {}

    if not headers:
        headers = {}

    headers["Authorization"] = "Bearer {}".format(token)

    if method == "GET":
        response = http_get(url=url, headers=headers, params=params)
    elif method == "POST":
        response = http_post(url=url, headers=headers, body=body)
    else:
        print("Unsupported HTTP method:", method)
        return None, token, request_count

    print("API Response Status:", response.status_code)

    # If 403 Forbidden is encountered, get a new token and retry once
    if response.status_code == 403:
        print("Received 403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(client_id, client_secret)
        if not token:
            return None, token, request_count

        headers["Authorization"] = "Bearer {}".format(token)

        # Retry with new token
        if method == "GET":
            response = http_get(url=url, headers=headers, params=params)
        elif method == "POST":
            response = http_post(url=url, headers=headers, body=body)

    return response, token, request_count

def get_jamf_inventory(token, request_count, client_id, client_secret):
    hasNextPage = True
    page = 0
    page_size = 500
    endpoints = []
    url = JAMF_URL + '/api/v1/computers-inventory'

    while hasNextPage:
        params = {"page": page, "page-size": page_size}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve inventory. Status code:", resp.status_code)
            return endpoints, token, request_count

        inventory = json_decode(resp.body)
        results = inventory.get('results', [])
        if not results:
            hasNextPage = False
            continue

        endpoints.extend(results)
        page += 1

    return endpoints, token, request_count

def get_jamf_details(token, request_count, client_id, client_secret, inventory):
    endpoints_final = []
    for item in inventory:
        uid = item.get('id', None)
        if not uid:
            print("ID not found in inventory item:", item)
            continue

        url = "{}/api/v1/computers-inventory-detail/{}".format(JAMF_URL, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve details for ID:", uid, "Status code:", resp.status_code)
            continue

        extra = json_decode(resp.body)
        item.update(extra)
        endpoints_final.append(item)

    return endpoints_final, token, request_count

def asset_ips(item):
    # handle IPs
    general = item.get("general", {})
    ips = []
    last_ip_address = general.get("lastIpAddress", "")
    if last_ip_address:
        ips.append(last_ip_address)

    last_reported_ip = general.get("lastReportedIp", "")
    if last_reported_ip:
        ips.append(last_reported_ip)

    return ips


def asset_os_hardware(item):
    # OS and hardware
    operating_system = item.get("operatingSystem", None)
    if not operating_system:
        print('operatingSystem key not found in item {}'.format(item))
        return {}

    hardware = item.get("hardware", None)
    if not hardware:
        print('hardware key not found in item {}'.format(item))
        return {}

    macs = []
    mac = hardware.get("macAddress", "")
    if mac:
        macs.append(mac)

    alt_mac = hardware.get("altMacAddress", "")
    if alt_mac:
        macs.append(alt_mac)

    return {
        'os_name': operating_system.get("name", ""),
        'os_version': operating_system.get("version", ""),
        'model': hardware.get("model", ""),
        'manufacturer': hardware.get("make", ""),
        'macs': macs
    }


def asset_networks(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        ip_addr = ip_address(ip)
        if ip_addr.version == 4:
            ip4s.append(ip_addr)
        elif ip_addr.version == 6:
            ip6s.append(ip_addr)
        else:
            continue

    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)


def build_asset(item):
    print(item)
    asset_id = item.get('udid', None)
    if not asset_id:
        print("udid not found in asset item {}".format(item))
        return

    general = item.get("general", None)
    if not general:
        print("general not found in asset item {}".format(item))
        return

    # OS and hardware
    os_hardware = asset_os_hardware(item)

    # create network interfaces
    ips = asset_ips(item)
    networks = []
    for m in os_hardware.get('macs', []):
        network = asset_networks(ips=ips, mac=m)
        networks.append(network)

    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        os=os_hardware.get('os', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
    )


def build_assets(inventory):
    assets = []
    for item in inventory:
        asset = build_asset(item)
        print("asset: {}".format(asset))
        assets.append(asset)

    return assets

def main(*args, **kwargs):
    """Main entry point for the script."""
    client_id = kwargs['access_key']
    client_secret = kwargs['access_secret']

    token, request_count = get_bearer_token(client_id, client_secret)
    if not token:
        print("Failed to get bearer_token")
        return None

    inventory, token, request_count = get_jamf_inventory(token, request_count, client_id, client_secret)
    if not inventory:
        print("No inventory data found")
        return None

    details, token, request_count = get_jamf_details(token, request_count, client_id, client_secret, inventory)
    if not details:
        print("No details retrieved")
        return None

    print("Successfully retrieved assets")
    assets = build_assets(details)

    if not assets:
        print("no assets")

    return assets

load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('time', 'sleep' )

CLAROTY_API_URL = 'https://api.claroty.com/api/v1'

PAGE_SIZE = 50   # Max devices per request (smaller pages reduce per-request timeout risk)
API_TIMEOUT = 300  # Seconds to wait for API responses
VULN_PAGE_SIZE = 100  # Max vulnerabilities per API call
MAX_VULNS = None  # Set to None for all, or an integer for a limit (e.g., 50)

MAX_RETRIES = 3          # Number of retry attempts on transient failures
RETRY_DELAY_SECONDS = 5  # Seconds to wait between retries
RETRY_STATUSES = [408, 429, 500, 502, 503, 504]  # HTTP status codes worth retrying

# Perform an HTTP POST with automatic retries on transient failures
def post_with_retry(url, headers, payload):
    attempt = 0
    response = None
    while attempt < MAX_RETRIES:
        response = http_post(url, headers=headers, body=bytes(json_encode(payload)), timeout=API_TIMEOUT)
        if response.status_code == 200:
            return response
        if response.status_code in RETRY_STATUSES:
            attempt += 1
            print("Request failed with status {} (attempt {}/{}), retrying in {}s...".format(
                response.status_code, attempt, MAX_RETRIES, RETRY_DELAY_SECONDS))
            sleep(RETRY_DELAY_SECONDS)
        else:
            # Non-retryable error — return immediately so caller can handle it
            return response
    return response

# Fetch all devices from Claroty API with pagination
def get_devices(api_key):
    
    url = "{}/devices".format(CLAROTY_API_URL)
    headers = {
        "Authorization": "Bearer {}".format(api_key),
        "Content-Type": "application/json",
    }

    all_devices = []
    hasNextPage = True
    
    while hasNextPage == True:
        payload = {
            "filter_by": {
                "field": "retired",
                "operation": "in",
                "value": [False]
            },
            "offset": len(all_devices),
            "limit": PAGE_SIZE,
            "fields": [
                "uid",
                "device_name",
                "ip_list",
                "mac_list",
                "retired"
            ],
            "include_count": True
        }

        response = post_with_retry(url, headers, payload)
        if response == None or response.status_code != 200:
            print("Failed to fetch devices after retries. Status: {}".format(
                response.status_code if response != None else "no response"))
            break

        response_json = json_decode(response.body)
        page_devices = response_json.get("results", [])

        all_devices.extend(page_devices)

        if len(page_devices) < PAGE_SIZE:
            hasNextPage = False
    
    return all_devices

def build_assets(api_key, devices):
    assets = []
    for device in devices:
        uid = device.get("uid")
        name = device.get("device_name", "Unnamed Device")
        ips = device.get("ip_list", [])
        macs = device.get("mac_list", [])
        
        if not ips and not macs:
            continue  # Skip devices without IPs or MACs

        mac = macs[0] if macs else None
        network_interface = build_network_interface(ips, mac)

        asset = ImportAsset(
            id=uid,
            name=name,
            networkInterfaces=[network_interface]
        )
        assets.append(asset)
    
    return assets

# Build runZero network interfaces from Claroty device data
def build_network_interface(ips, mac):
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

def main(**kwargs):
    api_key = kwargs['access_secret']

    devices = get_devices(api_key)
    
    if not devices:
        print("No devices found.")
        return None

    assets = build_assets(api_key, devices)
    
    if not assets:
        print("No assets created.")
    
    return assets
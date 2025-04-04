load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')

JAMF_URL = 'https://<UPDATE_ME>.jamfcloud.com'
# Number of API calls before getting a new token - workaround since we don't have a time library yet
MAX_REQUESTS = 100  

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

    if response.status_code == 403:
        print("Received 403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(client_id, client_secret)
        if not token:
            return None, token, request_count

        headers["Authorization"] = "Bearer {}".format(token)

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

def get_mobile_device_inventory(token, request_count, client_id, client_secret):
    """Retrieve mobile device inventory from JAMF"""
    hasNextPage = True
    page = 0
    page_size = 100
    mobile_devices = []
    url = JAMF_URL + "/api/v2/mobile-devices/detail"

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "section": "GENERAL"}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve mobile device inventory. Status code:", resp.status_code)
            return mobile_devices, token, request_count

        inventory = json_decode(resp.body)
        results = inventory.get('results', [])
        if not results:
            hasNextPage = False
            continue

        mobile_devices.extend(results)
        page += 1

    return mobile_devices, token, request_count

def get_mobile_device_details(token, request_count, client_id, client_secret, inventory):
    """Retrieve detailed mobile device data"""
    mobile_devices_final = []
    for item in inventory:
        uid = item.get('mobileDeviceId', None)
        if not uid:
            print("ID not found in mobile device item:", item)
            continue

        url = "{}/api/v2/mobile-devices/{}".format(JAMF_URL, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve details for mobile device ID:", uid, "Status code:", resp.status_code)
            continue

        extra = json_decode(resp.body)
        item.update(extra)
        mobile_devices_final.append(item)

    return mobile_devices_final, token, request_count\
    
def asset_ips(item):
    # handle IPs
    general = item.get("general", {})
    ips = []
    last_ip_address = general.get("lastIpAddress", general.get("ipAddress", None))
    if last_ip_address:
        ips.append(last_ip_address)

    last_reported_ip = general.get("lastReportedIp", "")
    if last_reported_ip:
        ips.append(last_reported_ip)

    return ips


def asset_os_hardware(item):
    """ Extracts OS and hardware details for both computers and mobile devices """

    # Handle computer assets (which have "operatingSystem" and "hardware" fields)
    operating_system = item.get("operatingSystem", None)
    hardware = item.get("hardware", None)

    # Handle mobile assets (which store OS and hardware info under "general")
    general = item.get("general", None)

    # Determine OS details
    if operating_system:
        os_name = operating_system.get("name", "")
        os_version = operating_system.get("version", "")
    elif general:
        os_name = "iOS"  # Assuming all mobile assets here are iOS
        os_version = general.get("osVersion", "")
    else:
        print('OS information not found in item {}'.format(item))
        return {}

    # Determine hardware details
    if hardware:
        model = hardware.get("model", "")
        manufacturer = hardware.get("make", "")
        macs = [
            mac for mac in [hardware.get("macAddress", ""), hardware.get("altMacAddress", "")]
            if mac
        ]
    elif general:
        model = item.get("model", "")
        manufacturer = "Apple"  # Default for mobile assets
        macs = [item.get("wifiMacAddress", "")] if item.get("wifiMacAddress") else []
    else:
        print('Hardware information not found in item {}'.format(item))
        return {}

    return {
        'os_name': os_name,
        'os_version': os_version,
        'model': model,
        'manufacturer': manufacturer,
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
    compute_asset_id = item.get("udid", None)
    mobile_asset_id = item.get('mobileDeviceId', None)
    asset_id = compute_asset_id if compute_asset_id else mobile_asset_id
    if not asset_id:
        print("asset id not found in asset item {}".format(item))
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
        assets.append(asset)
    return assets

def build_mobile_asset(item):
    """ Constructs the runZero ImportAsset object for mobile devices """

    # Retrieve asset ID (UDID takes priority, fallback to mobileDeviceId)
    mobile_asset_id = item.get("udid", item.get("mobileDeviceId", None))
    if not mobile_asset_id:
        print("Mobile asset ID not found in asset item:", item)
        return None

    general = item.get("general", None)
    if not general:
        print("General section missing in mobile asset item:", item)
        return None
    
    name = item.get("name", "")
    # Extract OS and hardware information
    os_hardware = asset_os_hardware(item)

    # Extract IPs and network interfaces
    ips = asset_ips(item)
    networks = []
    for mac in os_hardware.get('macs', []):
        if mac:
            network = asset_networks(ips=ips, mac=mac)
            networks.append(network)

    return ImportAsset(
        id=mobile_asset_id,
        networkInterfaces=networks,
        hostnames=[name],
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        customAttributes={
            "device_name": item.get("name", ""),
            "serial_number": item.get("serialNumber", ""),
            "model_identifier": item.get("modelIdentifier", ""),
            "device_type": item.get("deviceType", ""),
            "os_build": general.get("osBuild", ""),
            "last_inventory_update": general.get("lastInventoryUpdateDate", ""),
            "last_enrolled_date": general.get("lastEnrolledDate", ""),
            "mdm_profile_expiration": general.get("mdmProfileExpirationDate", ""),
            "time_zone": general.get("timeZone", ""),
            "management_id": item.get("managementId", ""),
            "itunes_store_account_active": general.get("itunesStoreAccountActive", ""),
            "exchange_device_id": general.get("exchangeDeviceId", ""),
            "tethered": general.get("tethered", ""),
            "supervised": general.get("supervised", ""),
            "device_ownership_type": general.get("deviceOwnershipType", ""),
            "declarative_mgmt_enabled": general.get("declarativeDeviceManagementEnabled", ""),
            "cloud_backup_enabled": general.get("cloudBackupEnabled", ""),
            "last_cloud_backup_date": general.get("lastCloudBackupDate", ""),
            "device_locator_service": general.get("deviceLocatorServiceEnabled", ""),
            "diagnostic_reporting_enabled": general.get("diagnosticAndUsageReportingEnabled", ""),
            "app_analytics_enabled": general.get("appAnalyticsEnabled", "")
        }
    )


def build_mobile_assets(inventory):
    """ Converts the mobile device inventory into runZero assets """
    assets = []
    for item in inventory:
        asset = build_mobile_asset(item)
        if asset:
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

    # Fetch and process computer inventory
    inventory, token, request_count = get_jamf_inventory(token, request_count, client_id, client_secret)
    if not inventory:
        print("No inventory data found for computers")

    details, token, request_count = get_jamf_details(token, request_count, client_id, client_secret, inventory)
    if not details:
        print("No details retrieved for computers")

    # Fetch and process mobile device inventory
    mobile_inventory, token, request_count = get_mobile_device_inventory(token, request_count, client_id, client_secret)
    if not mobile_inventory:
        print("No inventory data found for mobile devices")

    mobile_details, token, request_count = get_mobile_device_details(token, request_count, client_id, client_secret, mobile_inventory)
    if not mobile_details:
        print("No details retrieved for mobile devices")

    print("Successfully retrieved assets")
    assets = build_assets(details) + build_mobile_assets(mobile_details)

    if not assets:
        print("No assets found")

    return assets

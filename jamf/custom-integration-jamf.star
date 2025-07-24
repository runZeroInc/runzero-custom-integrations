load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('time', 'now', 'parse_duration')
load('flatten_json', 'flatten')

JAMF_URL = 'https://<UPDATE_ME>.jamfcloud.com'
DAYS_AGO = 60  # Adjust as needed
duration_str = "-{}h".format(DAYS_AGO * 24)  # Go duration format, e.g. "-720h" for 30 days
ago_duration = parse_duration(duration_str)
start_time = now() + ago_duration  # Subtracting the duration
START_DATE = str(start_time)[:10]  # "YYYY-MM-DD"
MAX_REQUESTS = 100
COMPUTER_ASSETS = True
MOBILE_ASSETS = True
DEV_MODE = False

def sanitize_string(s):
    if s:
        return s.replace(" ", "_").replace(".", "").replace("+", "").replace("(", "").replace(")", "").lower()
    else:
        return None

def get_bearer_token(client_id, client_secret):
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
    return token, 0

def get_valid_token(token, request_count, client_id, client_secret):
    if token and request_count < MAX_REQUESTS:
        return token, request_count + 1
    else:
        print("Fetching new token after", request_count, "requests")
        return get_bearer_token(client_id, client_secret)

def http_request(method, url, headers=None, params=None, body=None, token=None, request_count=None, client_id=None, client_secret=None):
    token, request_count = get_valid_token(token, request_count, client_id, client_secret)
    if not token:
        return None, token, request_count

    headers = headers or {}
    params = params or {}
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
        print("403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(client_id, client_secret)
        if not token:
            return None, token, request_count
        headers["Authorization"] = "Bearer {}".format(token)
        if method == "GET":
            response = http_get(url=url, headers=headers, params=params, timeout=300)
        elif method == "POST":
            response = http_post(url=url, headers=headers, body=body)

    return response, token, request_count

def get_jamf_inventory(token, request_count, client_id, client_secret):
    hasNextPage = True
    page = 0
    page_size = 100
    endpoints = []
    # hardcoded filter for the time being until we support datetime
    url = JAMF_URL + '/api/v1/computers-inventory'

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "filter": 'general.lastContactTime=ge="{}T00:00:00Z"'.format(START_DATE)}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve inventory. Status code:", getattr(resp, 'status_code', 'None'))
            return endpoints, token, request_count

        inventory = json_decode(resp.body)
        if not inventory:
            print("Invalid or empty JSON response for inventory:", resp.body)
            return endpoints, token, request_count

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
        uid = item.get('id')
        if not uid:
            print("ID not found in inventory item:", item)
            continue

        url = "{}/api/v1/computers-inventory-detail/{}".format(JAMF_URL, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve details for ID:", uid, "Status code:", getattr(resp, 'status_code', 'None'))
            continue

        extra = json_decode(resp.body)
        if DEV_MODE:
            build_asset(extra)
        if not extra:
            print("Invalid JSON for detail:", resp.body)
            continue

        item.update(extra)
        endpoints_final.append(item)

    return endpoints_final, token, request_count

def get_mobile_device_inventory(token, request_count, client_id, client_secret):
    hasNextPage = True
    page = 0
    page_size = 100
    mobile_devices = []
    # hardcoded filter for the time being until we support datetime
    url = JAMF_URL + "/api/v2/mobile-devices/detail"

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "section": "GENERAL", "filter": 'lastInventoryUpdateDate=ge="{}T00:00:00Z"'.format(START_DATE)}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve mobile device inventory. Status code:", getattr(resp, 'status_code', 'None'))
            return mobile_devices, token, request_count

        inventory = json_decode(resp.body)
        if not inventory:
            print("Invalid or empty JSON response for mobile inventory:", resp.body)
            return mobile_devices, token, request_count

        results = inventory.get('results', [])

        if not results:
            hasNextPage = False
            continue

        mobile_devices.extend(results)
        page += 1

    return mobile_devices, token, request_count

def get_mobile_device_details(token, request_count, client_id, client_secret, inventory):
    mobile_devices_final = []
    for item in inventory:
        uid = item.get('mobileDeviceId')
        if not uid:
            print("ID not found in mobile device item:", item)
            continue

        url = "{}/api/v2/mobile-devices/{}/detail".format(JAMF_URL, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count, client_id=client_id, client_secret=client_secret)
        if not resp or resp.status_code != 200:
            print("Failed to retrieve details for mobile device ID:", uid, "Status code:", getattr(resp, 'status_code', 'None'))
            continue

        extra = json_decode(resp.body)
        if DEV_MODE:
            build_mobile_asset(extra)
        if not extra:
            print("Invalid JSON for mobile detail:", resp.body)
            continue

        item.update(extra)
        mobile_devices_final.append(item)

    return mobile_devices_final, token, request_count

def is_private_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.20.") or
        ip.startswith("172.21.") or
        ip.startswith("172.22.") or
        ip.startswith("172.23.") or
        ip.startswith("172.24.") or
        ip.startswith("172.25.") or
        ip.startswith("172.26.") or
        ip.startswith("172.27.") or
        ip.startswith("172.28.") or
        ip.startswith("172.29.") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.")
    )

def asset_ips(item):
    general = item.get("general") or {}
    ips = []
    for key in ["lastIpAddress", "ipAddress", "lastReportedIp"]:
        ip = general.get(key)
        # only add Private IPs to the inventory 
        # remote assets put a lot of junk in the inventory with ISP public IP addresses
        if ip and is_private_ip(ip):
            ips.append(ip)
    return ips

def asset_networks(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        ip_addr = ip_address(ip)
        if ip_addr.version == 4:
            ip4s.append(ip_addr)
        elif ip_addr.version == 6:
            ip6s.append(ip_addr)
    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def asset_os_hardware(item):
    operating_system = item.get("operatingSystem") or {}
    hardware = item.get("hardware") or {}
    general = item.get("general") or {}

    os_name = operating_system.get("name", "") if operating_system else "iOS"
    os_version = operating_system.get("version", "") or general.get("osVersion", "")
    model = hardware.get("model", "") or item.get("model", "")
    manufacturer = hardware.get("make", "") or "Apple"
    macs = [mac for mac in [hardware.get("macAddress", ""), hardware.get("altMacAddress", ""), item.get("wifiMacAddress", "")] if mac]
    serial_number = hardware.get("serialNumber", "")

    return {
        'os_name': os_name,
        'os_version': os_version,
        'model': model,
        'manufacturer': manufacturer,
        'macs': macs,
        'serial_number': serial_number
    }

def build_asset(item):
    if not item:
        return

    asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not asset_id:
        print("Asset ID not found:", item)
        return

    general = item.get("general") or {}
    name = general.get("displayName", "")

    os_hardware = asset_os_hardware(item) or {}
    ips = asset_ips(item)
    networks = [asset_networks(ips, mac) for mac in os_hardware.get("macs", []) if mac]

    security = item.get("security") or {}
    disk = item.get("diskEncryption") or {}
    boot = disk.get("bootPartitionEncryptionDetails") or {}
    user = item.get("userAndLocation") or {}
    

    # add flattened version of certain attributes
    custom_attributes = {}
    # add extension attributes
    main_ext_attrs = item.get("extensionAttributes", [])
    if len(main_ext_attrs) > 0:
        for ext in main_ext_attrs:
            ext_name = sanitize_string(ext.get("name", None))
            ext_values = ext.get("values", None) or ext.get("value", None)
            if ext_name and ext_values:
                key_name = "ext_attr_" + ext_name
                custom_attributes[key_name] = ",".join(ext_values)
    # add user extension attributes
    user_ext_attrs = item.get("userAndLocation", {}).get("extensionAttributes", [])
    if len(user_ext_attrs) > 0:
        for ext in user_ext_attrs:
            user_ext_name = sanitize_string(ext.get("name", None))
            user_ext_values = ext.get("values", None) or ext.get("value", None)
            if user_ext_name and user_ext_values:
                key_name = "ext_attr_" + user_ext_name
                custom_attributes[key_name] = ",".join(user_ext_values)

    for key in item.keys():
        if key not in ["purchasing", "storage", "packageReceipts", "contentCaching", "extensionAttributes", "userAndLocation"]:
            if type(item[key]) == "dict":
                custom_attributes.update(flatten(item[key]))
            elif type(item[key]) == "string":
                custom_attributes[key] = item[key]
            elif type(item[key]) == "list":
                # skip lists unless we have more context on them like extensionAttributes
                continue

    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        hostnames=[name],
        customAttributes=custom_attributes,
    )

def build_assets(inventory):
    assets = []
    print("Total inventory items:", len(inventory))
    for item in inventory:
        asset = build_asset(item)
        if asset:
            assets.append(asset)
    return assets

def build_mobile_asset(item):
    if not item:
        return None
    mobile_asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not mobile_asset_id:
        print("Mobile asset ID not found:", item)
        return None

    general = item.get("general") or {}
    name = item.get("name", "")
    os_hardware = asset_os_hardware(item)
    ips = asset_ips(item)
    networks = [asset_networks(ips, mac) for mac in os_hardware.get("macs", []) if mac]

    # add flattened version of certain attributes
    custom_attributes = {}
    for key in item.keys():
        if key == "extensionAttributes":
            for ext in item["extensionAttributes"]:
                ext_name = ext.get("name", None).replace(" ", "_").lower()
                ext_values = ext.get("values", None) or ext.get("value", None)
                if ext_name and ext_values:
                    key_name = "ext_attr_" + ext_name
                    custom_attributes[key_name] = ",".join(ext_values)
        elif key not in ["applications", "certificates", "purchasing", "serviceSubscription", "ebooks", "fonts", ]:
            if type(item[key]) == "dict":
                custom_attributes.update(flatten(item[key]))
            elif type(item[key]) == "string" or type(item[key]) == "bool":
                custom_attributes[key] = str(item[key])
            elif type(item[key]) == "list":
                # skip lists unless we have more context on them like extensionAttributes
                continue
        else:
            continue

    return ImportAsset(
        id=mobile_asset_id,
        networkInterfaces=networks,
        hostnames=[name.replace(" ", "-")],
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        customAttributes=custom_attributes
    )

def build_mobile_assets(inventory):
    assets = []
    print("Total mobile device inventory:", len(inventory))
    for item in inventory:
        asset = build_mobile_asset(item)
        if asset:
            assets.append(asset)
    return assets

def main(*args, **kwargs):
    client_id = kwargs['access_key']
    client_secret = kwargs['access_secret']

    token, request_count = get_bearer_token(client_id, client_secret)
    if not token:
        print("Failed to get bearer token")
        return None

    # Build assets
    assets = []
    if COMPUTER_ASSETS:
        # Fetch and process computer inventory
        inventory, token, request_count = get_jamf_inventory(token, request_count, client_id, client_secret)
        if not inventory:
            print("No inventory data found for computers")
        
        details, token, request_count = get_jamf_details(token, request_count, client_id, client_secret, inventory)
        if not details:
            print("No details retrieved for computers")
        computer_assets = build_assets(details)
        assets.extend(computer_assets)
    if MOBILE_ASSETS:
        # Fetch and process mobile device inventory
        mobile_inventory, token, request_count = get_mobile_device_inventory(token, request_count, client_id, client_secret)
        if not mobile_inventory:
            print("No inventory data found for mobile devices")

        mobile_details, token, request_count = get_mobile_device_details(token, request_count, client_id, client_secret, mobile_inventory)
        if not mobile_details:
            print("No details retrieved for mobile devices")
        mobile_assets = build_mobile_assets(mobile_details)
        assets.extend(mobile_assets)
    return assets

# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-jamf",
    "name": "JAMF",
    "type": "inbound",
    "description": "Imports computers and mobile devices from Jamf Pro.",
    "version": "26061000",
    "params": [
        {
            "key": "url",
            "label": "Jamf base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<tenant>.jamfcloud.com",
        },
        {
            "key": "client_id",
            "label": "API client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "API client secret",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'to_custom_attributes')
load('net', 'ip_address')
load('http', 'get_json', 'post_json', 'bearer', 'oauth2_token')
load('kwargs', 'get_url_base', 'get_http_options')
load('time', 'now', 'parse_duration')
load('flatten_json', 'flatten')
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

def get_bearer_token(base_url, client_id, client_secret, config_kwargs):
    token = oauth2_token(
        "{}/api/oauth/token".format(base_url),
        client_id=client_id,
        client_secret=client_secret,
        **get_http_options(config_kwargs)
    )
    return token, 0

def get_valid_token(token, request_count, base_url, client_id, client_secret, config_kwargs):
    if token and request_count < MAX_REQUESTS:
        return token, request_count + 1
    else:
        print("Fetching new token after", request_count, "requests")
        return get_bearer_token(base_url, client_id, client_secret, config_kwargs)

def http_request(method, url, config_kwargs=None, headers=None, params=None, body=None, token=None, request_count=None, base_url=None, client_id=None, client_secret=None):
    token, request_count = get_valid_token(token, request_count, base_url, client_id, client_secret, config_kwargs)
    if not token:
        return None, "no token", token, request_count

    headers = dict(headers or {})
    headers["Authorization"] = bearer(token)
    http_options = get_http_options(config_kwargs, headers=headers)

    if method == "GET":
        data, err = get_json(url=url, params=params or {}, **http_options)
    elif method == "POST":
        data, err = post_json(url=url, body=body, **http_options)
    else:
        return None, "unsupported method: " + method, token, request_count

    if err and err.startswith("status 403"):
        print("403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(base_url, client_id, client_secret, config_kwargs)
        if not token:
            return None, "refresh failed", token, request_count
        headers["Authorization"] = bearer(token)
        http_options = get_http_options(config_kwargs, headers=headers)
        if method == "GET":
            data, err = get_json(url=url, params=params or {}, timeout=300, **http_options)
        elif method == "POST":
            data, err = post_json(url=url, body=body, **http_options)

    return data, err, token, request_count

def stream_computer_assets(base_url, config_kwargs, token, request_count, client_id, client_secret):
    """Paginate computer inventory, fetch per-device details, then build and
    stream each page of assets via report_assets so the full inventory is never
    held in memory. Returns (reported_count, token, request_count)."""
    hasNextPage = True
    page = 0
    page_size = 100
    reported = 0
    # hardcoded filter for the time being until we support datetime
    url = base_url + '/api/v1/computers-inventory'

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "filter": 'general.lastContactTime=ge="{}T00:00:00Z"'.format(START_DATE)}
        inventory, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, params=params, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve inventory:", err)
            return reported, token, request_count

        if not inventory:
            print("Empty inventory response")
            return reported, token, request_count

        results = inventory.get('results', [])

        if not results:
            hasNextPage = False
            continue

        details, token, request_count = get_jamf_details(base_url, config_kwargs, token, request_count, client_id, client_secret, results)
        reported += report_assets(build_assets(details))
        page += 1

    return reported, token, request_count

def get_jamf_details(base_url, config_kwargs, token, request_count, client_id, client_secret, inventory):
    endpoints_final = []
    for item in inventory:
        uid = item.get('id')
        if not uid:
            print("ID not found in inventory item:", item)
            continue

        url = "{}/api/v1/computers-inventory-detail/{}".format(base_url, uid)
        extra, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve details for ID:", uid, err)
            continue

        if DEV_MODE:
            build_asset(extra)
        if not extra:
            print("Empty detail for ID:", uid)
            continue

        item.update(extra)
        endpoints_final.append(item)

    return endpoints_final, token, request_count

def stream_mobile_assets(base_url, config_kwargs, token, request_count, client_id, client_secret):
    """Paginate mobile device inventory, fetch per-device details, then build and
    stream each page of assets via report_assets so the full inventory is never
    held in memory. Returns (reported_count, token, request_count)."""
    hasNextPage = True
    page = 0
    page_size = 100
    reported = 0
    # hardcoded filter for the time being until we support datetime
    url = base_url + "/api/v2/mobile-devices/detail"

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "section": "GENERAL", "filter": 'lastInventoryUpdateDate=ge="{}T00:00:00Z"'.format(START_DATE)}
        inventory, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, params=params, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve mobile device inventory:", err)
            return reported, token, request_count

        if not inventory:
            print("Empty mobile inventory response")
            return reported, token, request_count

        results = inventory.get('results', [])

        if not results:
            hasNextPage = False
            continue

        details, token, request_count = get_mobile_device_details(base_url, config_kwargs, token, request_count, client_id, client_secret, results)
        reported += report_assets(build_mobile_assets(details))
        page += 1

    return reported, token, request_count

def get_mobile_device_details(base_url, config_kwargs, token, request_count, client_id, client_secret, inventory):
    mobile_devices_final = []
    for item in inventory:
        uid = item.get('mobileDeviceId')
        if not uid:
            print("ID not found in mobile device item:", item)
            continue

        url = "{}/api/v2/mobile-devices/{}/detail".format(base_url, uid)
        extra, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve details for mobile device ID:", uid, err)
            continue

        if DEV_MODE:
            build_mobile_asset(extra)
        if not extra:
            print("Empty detail for mobile device ID:", uid)
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
        customAttributes=to_custom_attributes(custom_attributes),
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
        customAttributes=to_custom_attributes(custom_attributes),
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
    base_url = get_url_base(kwargs)
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']

    token, request_count = get_bearer_token(base_url, client_id, client_secret, kwargs)
    if not token:
        print("Failed to get bearer token")
        return None

    # Assets are streamed page-by-page via report_assets.
    if COMPUTER_ASSETS:
        # Fetch and process computer inventory
        _, token, request_count = stream_computer_assets(base_url, kwargs, token, request_count, client_id, client_secret)
    if MOBILE_ASSETS:
        # Fetch and process mobile device inventory
        _, token, request_count = stream_mobile_assets(base_url, kwargs, token, request_count, client_id, client_secret)
    return None

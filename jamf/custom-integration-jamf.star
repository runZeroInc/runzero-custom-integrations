load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('time', 'now', 'parse_duration')

JAMF_URL = 'https://<UPDATE_ME>.jamfcloud.com'
DAYS_AGO = 60  # Adjust as needed
duration_str = "-{}h".format(DAYS_AGO * 24)  # Go duration format, e.g. "-720h" for 30 days
ago_duration = parse_duration(duration_str)
start_time = now() + ago_duration  # Subtracting the duration
START_DATE = str(start_time)[:10]  # "YYYY-MM-DD"
MAX_REQUESTS = 100

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

def build_asset(item):
    if not item:
        return None
    
    # Extract the main asset ID (UDID or Mobile Device ID)
    asset_id = item.get("udid") or item.get("id")
    if not asset_id:
        print("Asset ID not found: {}".format(item))
        return None

    # Extract basic info
    general = item.get("general", {})
    name = general.get("name", "")
    site = general.get("site", {})
    site_name = site.get("name", "")
    site_id = site.get("id", "")

    # Extract hardware details
    hardware = item.get("hardware", {})
    serial_number = hardware.get("serialNumber", "")
    manufacturer = hardware.get("make", "")
    model = hardware.get("model", "")
    model_identifier = hardware.get("modelIdentifier", "")
    macs = [hardware.get("macAddress", ""), hardware.get("altMacAddress", "")]
    ips = [general.get("lastIpAddress", ""), general.get("lastReportedIp", "")]
    networks = [asset_networks(ips, mac) for mac in macs if mac]

    # Collect all attributes
    custom_attributes = {
        "name": name,
        "serial_number": serial_number,
        "site_name": site_name,
        "site_id": site_id,
        "platform": general.get("platform", ""),
        "barcode1": general.get("barcode1", ""),
        "barcode2": general.get("barcode2", ""),
        "asset_tag": general.get("assetTag", ""),
        "last_contact_time": general.get("lastContactTime", ""),
        "last_reported_ip": general.get("lastReportedIp", ""),
        "report_date": general.get("reportDate", ""),
        "last_cloud_backup_date": general.get("lastCloudBackupDate", ""),
        "last_enrolled_date": general.get("lastEnrolledDate", ""),
        "mdm_profile_expiration": general.get("mdmProfileExpiration", ""),
        "initial_entry_date": general.get("initialEntryDate", ""),
        "distribution_point": general.get("distributionPoint", ""),
        "enrolled_via_automated_device_enrollment": str(general.get("enrolledViaAutomatedDeviceEnrollment", False)),
        "user_approved_mdm": str(general.get("userApprovedMdm", False)),
        "declarative_device_mgmt_enabled": str(general.get("declarativeDeviceManagementEnabled", False)),
        "itunes_store_account_active": str(general.get("itunesStoreAccountActive", False)),
        "management_id": general.get("managementId", ""),
    }

    # Handle nested structures like MDM, enrollment methods, and remote management
    enrollment_method = general.get("enrollmentMethod", {})
    custom_attributes.update({
        "enrollment_method_id": enrollment_method.get("id", ""),
        "enrollment_method_object_name": enrollment_method.get("objectName", ""),
        "enrollment_method_object_type": enrollment_method.get("objectType", ""),
    })

    remote_management = general.get("remoteManagement", {})
    custom_attributes.update({
        "remote_management_managed": str(remote_management.get("managed", False))
    })

    mdm_capable = general.get("mdmCapable", {})
    custom_attributes.update({
        "mdm_capable": str(mdm_capable.get("capable", False)),
        "mdm_capable_users": ",".join(mdm_capable.get("capableUsers", []))
    })

    # Handle extension attributes
    extension_attributes = item.get("extensionAttributes", [])
    for ea in extension_attributes:
        ea_name = ea.get("name", "").replace(" ", "_").lower()
        ea_values = ea.get("values", [])
        custom_attributes["extension_attr_{}".format(ea_name)] = ",".join([str(v) for v in ea_values])

    # Handle user and location
    user_location = item.get("userAndLocation", {})
    custom_attributes.update({
        "user_username": user_location.get("username", ""),
        "user_realname": user_location.get("realname", ""),
        "user_email": user_location.get("email", ""),
        "user_position": user_location.get("position", ""),
        "user_phone": user_location.get("phone", ""),
        "user_department_id": user_location.get("departmentId", ""),
        "user_building_id": user_location.get("buildingId", ""),
        "user_room": user_location.get("room", "")
    })

    # Handle security settings
    security = item.get("security", {})
    for key, value in security.items():
        custom_attributes["security_{}".format(key)] = str(value)

    # Handle disk encryption
    disk_encryption = item.get("diskEncryption", {})
    for key, value in disk_encryption.items():
        if type(value) == "dict":
            for sub_key, sub_value in value.items():
                custom_attributes["diskEncryption_{}_{}".format(key, sub_key)] = str(sub_value)
        elif type(value) == "list":
            custom_attributes["diskEncryption_{}".format(key)] = ",".join([str(v) for v in value])
        else:
            custom_attributes["diskEncryption_{}".format(key)] = str(value)

    # Handle applications
    applications = item.get("applications", [])
    custom_attributes["installed_applications"] = ",".join(
        ["{} (v{})".format(app.get("name", ""), app.get("version", "")) for app in applications]
    )

    # Build the asset
    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        hostnames=[name.replace(" ", "-")],
        os=hardware.get("model", ""),
        osVersion=hardware.get("modelIdentifier", ""),
        manufacturer=manufacturer,
        model=model,
        customAttributes=custom_attributes
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
    
    # Extract the main asset ID (UDID or Mobile Device ID)
    mobile_asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not mobile_asset_id:
        print("Mobile asset ID not found: {}".format(item))
        return None

    # Extract basic device info
    name = item.get("name", "")
    serial_number = item.get("serialNumber", "")
    os_version = item.get("osVersion", "")
    os_build = item.get("osBuild", "")
    manufacturer = "Apple"
    model = item.get("modelIdentifier", "")
    ip_address = item.get("ipAddress", "")
    wifi_mac = item.get("wifiMacAddress", "")
    bluetooth_mac = item.get("bluetoothMacAddress", "")

    # Network interfaces
    ips = [ip_address] if ip_address else []
    macs = [wifi_mac, bluetooth_mac]
    networks = [asset_networks(ips, mac) for mac in macs if mac]

    # Collect all attributes
    custom_attributes = {
        "name": name,
        "serial_number": serial_number,
        "asset_tag": item.get("assetTag", ""),
        "os_version": os_version,
        "os_build": os_build,
        "enforce_name": str(item.get("enforceName", False)),
        "last_inventory_update": item.get("lastInventoryUpdateTimestamp", ""),
        "os_supplemental_build": item.get("osSupplementalBuildVersion", ""),
        "os_rapid_security_response": item.get("osRapidSecurityResponse", ""),
        "software_update_device_id": item.get("softwareUpdateDeviceId", ""),
        "managed": str(item.get("managed", False)),
        "time_zone": item.get("timeZone", ""),
        "initial_entry_ts": item.get("initialEntryTimestamp", ""),
        "last_enrollment_ts": item.get("lastEnrollmentTimestamp", ""),
        "mdm_profile_expiration": item.get("mdmProfileExpirationTimestamp", ""),
        "device_ownership_level": item.get("deviceOwnershipLevel", ""),
        "enrollment_method": item.get("enrollmentMethod", ""),
        "enrollment_session_token_valid": str(item.get("enrollmentSessionTokenValid", False)),
        "declarative_mgmt_enabled": str(item.get("declarativeDeviceManagementEnabled", False)),
        "management_id": item.get("managementId", ""),
    }

    # Site information
    site = item.get("site", {})
    if site:
        custom_attributes.update({
            "site_id": site.get("id", ""),
            "site_name": site.get("name", ""),
        })

    # Location information
    location = item.get("location", {})
    if location:
        custom_attributes.update({
            "username": location.get("username", ""),
            "real_name": location.get("realName", ""),
            "email_address": location.get("emailAddress", ""),
            "position": location.get("position", ""),
            "phone_number": location.get("phoneNumber", ""),
            "department_id": location.get("departmentId", ""),
            "building_id": location.get("buildingId", ""),
            "room": location.get("room", ""),
        })

    # Extension attributes
    extension_attributes = item.get("extensionAttributes", [])
    for ea in extension_attributes:
        ea_name = ea.get("name", "").replace(" ", "_").lower()
        ea_value = ea.get("value", [])
        custom_attributes["extension_attr_{}".format(ea_name)] = ",".join([str(v) for v in ea_value])

    # OS-specific attributes
    for os_type in ["ios", "tvos", "watchos", "visionos"]:
        os_data = item.get(os_type, {})
        if os_data:
            for key, value in os_data.items():
                # Handle nested dictionaries (like purchasing, security, etc.)
                if type(value) == "dict":
                    for sub_key, sub_value in value.items():
                        custom_attributes["{}_{}_{}".format(os_type, key, sub_key)] = str(sub_value)
                # Handle lists (like applications, certificates, etc.)
                elif type(value) == "list":
                    custom_attributes["{}_{}".format(os_type, key)] = ",".join([str(v) for v in value])
                # Handle simple key-value pairs
                else:
                    custom_attributes["{}_{}".format(os_type, key)] = str(value)

    # Build the asset
    return ImportAsset(
        id=mobile_asset_id,
        networkInterfaces=networks,
        hostnames=[name.replace(" ", "-")],
        os="iOS",
        osVersion=os_version,
        manufacturer=manufacturer,
        model=model,
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

    # Build assets
    computer_assets = build_assets(details)
    mobile_assets = build_mobile_assets(mobile_details)
    return computer_assets + mobile_assets

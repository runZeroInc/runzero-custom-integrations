load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')

JAMF_URL = 'https://<UPDATE_ME>.jamfcloud.com'
START_DATE = '2025-03-08' # pulls assets that have checked in since this date ... format: YYYY-MM-DD
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
            response = http_get(url=url, headers=headers, params=params)
        elif method == "POST":
            response = http_post(url=url, headers=headers, body=body)

    return response, token, request_count

def get_jamf_inventory(token, request_count, client_id, client_secret):
    hasNextPage = True
    page = 0
    page_size = 100
    endpoints = []
    # hardcoded filter for the time being until we support datetime
    url = JAMF_URL + '/api/v1/computers-inventory?filter=general.lastContactTime%3Dge%3D%22{}%22'.format(START_DATE)

    while hasNextPage:
        params = {"page": page, "page-size": page_size}
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
    url = JAMF_URL + "/api/v2/mobile-devices/detail?filter=general.lastInventoryUpdateDate%3Dge%3D%2220{}%22".format(START_DATE)

    while hasNextPage:
        params = {"page": page, "page-size": page_size, "section": "GENERAL"}
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

        url = "{}/api/v2/mobile-devices/{}".format(JAMF_URL, uid)
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

def asset_os_hardware(item):
    operating_system = item.get("operatingSystem") or {}
    hardware = item.get("hardware") or {}
    general = item.get("general") or {}

    os_name = operating_system.get("name", "") if operating_system else "iOS"
    os_version = operating_system.get("version", "") or general.get("osVersion", "")
    model = hardware.get("model", "") or item.get("model", "")
    manufacturer = hardware.get("make", "") or "Apple"
    macs = [mac for mac in [hardware.get("macAddress", ""), hardware.get("altMacAddress", ""), item.get("wifiMacAddress", "")] if mac]

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
    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def build_asset(item):
    if not item:
        return

    asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not asset_id:
        print("Asset ID not found:", item)
        return

    general = item.get("general") or {}
    name = general.get("name", "")

    os_hardware = asset_os_hardware(item) or {}
    ips = asset_ips(item)
    networks = [asset_networks(ips, mac) for mac in os_hardware.get("macs", []) if mac]

    security = item.get("security") or {}
    disk = item.get("diskEncryption") or {}
    boot = disk.get("bootPartitionEncryptionDetails") or {}
    user = item.get("userAndLocation") or {}

    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        hostnames=[name],
        customAttributes={
            "last_seen_TS": general.get("lastContactTime", ""),
            "security_sipStatus": security.get("sipStatus", ""),
            "security_gatekeeperStatus": security.get("gatekeeperStatus", ""),
            "security_xprotectVersion": security.get("xprotectVersion", ""),
            "security_autoLoginDisabled": security.get("autoLoginDisabled", ""),
            "security_remoteDesktopEnabled": security.get("remoteDesktopEnabled", ""),
            "security_activationLockEnabled": security.get("activationLockEnabled", ""),
            "security_secureBootLevel": security.get("secureBootLevel", ""),
            "security_externalBootLevel": security.get("externalBootLevel", ""),
            "security_bootstrapTokenAllowed": security.get("bootstrapTokenAllowed", ""),
            "security_bootstrapTokenEscrowedStatus": security.get("bootstrapTokenEscrowedStatus", ""),
            "security_recoveryLockEnabled": security.get("recoveryLockEnabled", ""),
            "security_firewallEnabled": security.get("firewallEnabled", ""),
            "security_lastAttestationAttempt": security.get("lastAttestationAttempt", ""),
            "security_lastSuccessfulAttestation": security.get("lastSuccessfulAttestation", ""),
            "security_attestationStatus": security.get("attestationStatus", ""),
            "diskEncryption_individualRecoveryKeyValidityStatus": disk.get("individualRecoveryKeyValidityStatus", ""),
            "diskEncryption_institutionalRecoveryKeyPresent": disk.get("institutionalRecoveryKeyPresent", ""),
            "diskEncryption_diskEncryptionConfigurationName": disk.get("diskEncryptionConfigurationName", ""),
            "diskEncryption_fileVault2Enabled": disk.get("fileVault2Enabled", ""),
            "diskEncryption_fileVault2EligibilityMessage": disk.get("fileVault2EligibilityMessage", ""),
            "diskEncryption_fileVault2EnabledUserNames": disk.get("fileVault2EnabledUserNames", ""),
            "diskEncryption_bootPartitionEncryptionDetails_partitionName": boot.get("partitionName", ""),
            "diskEncryption_bootPartitionEncryptionDetails_partitionFileVault2State": boot.get("partitionFileVault2State", ""),
            "diskEncryption_bootPartitionEncryptionDetails_partitionFileVault2Percent": boot.get("partitionFileVault2Percent", ""),
            "userAndLocation_username": user.get("username", ""),
            "userAndLocation_realname": user.get("realname", ""),
            "userAndLocation_email": user.get("email", ""),
            "userAndLocation_position": user.get("position", ""),
            "userAndLocation_phone": user.get("phone", ""),
            "userAndLocation_departmentId": user.get("departmentId", ""),
            "userAndLocation_buildingId": user.get("buildingId", ""),
            "userAndLocation_room": user.get("room", "")
        }
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

    return ImportAsset(
        id=mobile_asset_id,
        networkInterfaces=networks,
        hostnames=[name.replace(" ", "-")],
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        customAttributes={
            "last_seen_TS": general.get("lastInventoryUpdateDate", ""),
            "device_name": name,
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

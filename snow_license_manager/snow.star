load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('base64', base64_encode='encode', base64_decode='decode')
load('flatten_json', 'flatten')
load('http', http_get='get', http_post='post', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('uuid', 'new_uuid')

#Change the URL to match your Snow Software License Manager server
SNOW_BASE_URL = 'https://<Snow license manager URL>'
SNOW_CUSTOMER_ID = ''
RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets, creds):
    assets_import = []
    for entry in assets:
        item = entry.get('Body', {})
        asset_id = str(item.get('Id', new_uuid))
        hostname = item.get('Name', '')
        vendor = item.get('Manufacturer', '')
        model = item.get('Model', '')
        os = item.get('OperatingSystem', '')
        os_version = item.get('OperatingSystemServicePack', '')

        # create the network interfaces
        interfaces = []
        adapters = item.get('Hardware', {}).get('NetworkAdapters', [])
        for adapter in adapters:
            addresses = adapter.get('IpAddress', '').split(';')
            if type(addresses) != 'list':
                addresses = [addresses]
            interface = build_network_interface(ips=addresses, mac=adapter.get('MacAddress', None))
            interfaces.append(interface)

        # Retrieve and map custom attributes
        organization = item.get('Organization', '')
        org_checksum = item.get('OrgChecksum', '')
        is_virtual = item.get('IsVirtual', '')
        status = item.get('Status', '')
        last_scan_date = item.get('LastScanDate', '')
        updated_by = item.get('UpdatedBy', '')
        updated_date = item.get('UpdatedData', '')
        domain = item.get('Domain', '')
        total_disk_space = item.get('TotalDiskSpace', '')
        physical_memory = item.get('PhyscialMemory', '')
        processor_type = item.get('ProcessorType', '')
        processor_count = item.get('ProcessorCount', '')
        core_count = item.get('CoreCount', '')
        bios_sn = item.get('BiosSerialNumber', '')
        hyperv_name = item.get('HypervisorName', '')
        is_portable = item.get('IsPortable', '')
        is_server = item.get('IsServer', '')
        most_freq_user = item.get('MostFrequentUserId', '')
        most_recent_user = item.get('MostRecentUserId', '')

        custom_attributes = {
            'organization': organization,
            'orgChecksum': org_checksum,
            'isVirtual': is_virtual,
            'status': status,
            'lastScanDate': last_scan_date,
            'updatedBy': updated_by,
            'updatedDate': updated_date,
            'domain': domain,
            'totalDiskSpace': total_disk_space,
            'physicalMemory': physical_memory,
            'processorType': processor_type,
            'processorCount': processor_count,
            'coreCount': core_count,
            'biosSerialNumber': bios_sn,
            'hypervisorName': hyperv_name,
            'isPortable': is_portable,
            'isServer': is_server,
            'mostFrequentUserId': most_freq_user,
            'mostRecentUserId': most_recent_user
        }
        hw = item.get('Hardware', {})
        custom_attributes['hardware.biosSerialNumber'] = hw.get('BiosSerialNumber', '')
        custom_attributes['hardware.biosVersion'] = hw.get('BiosVersion', '')
        custom_attributes['hardware.biosDate'] = hw.get('BiosDate', '')
        custom_attributes['hardware.processorType'] = hw.get('ProcessorType', '')
        custom_attributes['hardware.numberOfProcessors'] = hw.get('NumberOfProcessors', '')
        custom_attributes['hardware.coresPerProcessor.'] = hw.get('CoresPerProcessor', '')
        custom_attributes['hardware.physicalMemoryMb'] = hw.get('PhysicalMemoryMb', '')
        custom_attributes['hardware.memorySlots'] = hw.get('MemorySlots', '')
        custom_attributes['hardware.memorySlotsAvailable'] = hw.get('MemorySlotsAvailable', '')
        custom_attributes['hardware.systemDiskSpaceMb'] = hw.get('SystemDiskSpaceMb', '')
        custom_attributes['hardware.systemDiskSpaceAvailableMb'] = hw.get('SystemDiskSpaceAvailableMb', '')
        custom_attributes['hardware.totalDiskSpaceMb'] = hw.get('TotalDiskSpaceMb', '')
        custom_attributes['hardware.totalDiskSpaceAvailableMb'] = hw.get('TotalDiskSpaceAvailableMb', '')

        # logical_disks = hw.get('LogicalDisks', {})
        # optical_drives = hw.get('OpticalDrives', [])
        # display_adapters = hw.get('DisplayAdapters', [])
        # monitors = hw.get('Monitors', [])


        # Retrieve software information for asset
        # create software entries
        software = []
        applications = get_apps(asset_id, creds)
        for app in applications:
            software_entry = build_app(app)
            software.append(software_entry)

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                manufacturer=vendor,
                model=model,
                os=os,
                os_version=os_version,
                networkInterfaces=interfaces,
                customAttributes=custom_attributes,
                software=software
            )
        )
    return assets_import

def build_network_interface(ips, mac):
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
    else:
        return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    
def build_app(software_entry):
    app = software_entry.get('Body', {})
    app_id = app.get('Id', None)
    # if app_id:
    #     software_details = get_app_details(app_id)
    #installed = app.get('InstallDate', '')
    product = app.get('FamilyName', '')
    vendor = app.get('ManufacturerName', '')

    # Map custom attributes from software
    name = app.get('Name', '')
    manufacturer_id = app.get('ManufacturerId', '')
    manufacturer_name = app.get('ManufacturerName', '')
    family_id = app.get('FamilyId', '')
    family_name = app.get('FamilyName', '')
    bundled_app_id = app.get('BundleApplicationId', '')
    bundled_app_name = app.get('BundleApplicationName', '')
    last_used = app.get('LastUsed', '')
    first_used = app.get('FirstUsed', '')
    install_date = app.get('InstallDate', '')
    discvovered_date = app.get('DiscoveredDate', '')
    run = app.get('Run', '')
    avg_usage_time = app.get('AvgUsageTime', '')
    users = app.get('Users', '')
    license_reqd = app.get('LicenseRequired', '')
    is_installed = app.get('IsInstalled', '')
    is_blacklisted = app.get('IsBlacklisted', '')
    is_whitelisted = app.get('IsWhitelisted', '')
    is_virtual = app.get('IsVirtual', '')
    is_oem = app.get('IsOEM', '')
    is_msdn = app.get('IsMSDN', '')
    is_webapp = app.get('IsWebApplication', '')
    app_cost = app.get('ApplicationItemCost', '')
    custom_attributes = {
        'name': name,
        'manufacturer.id': manufacturer_id,
        'manufacturer.name': manufacturer_name,
        'family.id': family_id,
        'family.name': family_name,
        'bundled.application.id': bundled_app_id,
        'bundled.application.name': bundled_app_name,
        'last.used': last_used,
        'first.used': first_used,
        'install.date': install_date,
        'discovered.date': discvovered_date,
        'run': run,
        'average.usage.time': avg_usage_time,
        'users': users,
        'license.required': license_reqd,
        'is.installed': is_installed,
        'is.blacklisted': is_blacklisted,
        'is.whitelisted': is_whitelisted,
        'is.virtual': is_virtual,
        'is.oem': is_oem,
        'is.msdn': is_msdn,
        'is.web.application': is_webapp,
        'application.item.cost': app_cost
    }

    return Software(
        id=app_id,
        product=product,
        vendor=vendor,
        customAttributes=custom_attributes
        )

def get_computers(creds):
    items_returned = 0
    total_items = 10000
    assets_all = []

    while True:
        url = SNOW_BASE_URL + '/api/customers/' + SNOW_CUSTOMER_ID + '/computers?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        params = {'$inlinecount': 'allpages',
                    '$skip': str(items_returned)}
        response = http_get(url, headers=headers, params=params)
        if response.status_code != 200:
            print('failed to retrieve assets at $skip=' + str(items_returned),  'status code: ' + str(response.status_code))
        else:
            data = json_decode(response.body)
            meta = data['Meta']
            has_page_size = False
            for item in meta:
                if item['Name'] == 'Count':
                    total_items = item.get('Value')
                if item['Name'] == 'PageSize':
                    has_page_size = True
                    items_returned += item.get('Value')
            computers = data['Body']
            assets_all.extend(computers)
            if not has_page_size: # The last page lacks the page size meta value
                break
            print(str(items_returned) + ' computers of ' + str(total_items) + ' returned from API')            

    return assets_all

def get_apps(asset_id, creds):
    items_returned = 0
    total_items = 10000
    applications_all = []

    while True:
        url = SNOW_BASE_URL + '/api/customers/' + SNOW_CUSTOMER_ID + '/computers/' + str(asset_id) + '/applications?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        params = {'$inlinecount': 'allpages',
                  '$skip': str(items_returned)}
        response = http_get(url, headers=headers, params=params)
        if response.status_code != 200:
            print('failed to retrieve application for ' + str(asset_id) + ' at $skip=' + str(items_returned), 'status code: ' + str(response.status_code))
        else:
            data = json_decode(response.body)
            meta = data['Meta']
            has_page_size = False
            for item in meta:
                if item['Name'] == 'Count':
                    total_items = item.get('Value')
                if item['Name'] == 'PageSize':
                    has_page_size = True
                    items_returned += item.get('Value')
            applications = data['Body']
            applications_all.extend(applications)
            if not has_page_size: # The last page lacks the page size meta value
                break
            print(str(items_returned) + ' applications of ' + str(total_items) + ' returned from API')            

    return applications_all

def get_app_details(app_id, creds):
    url = SNOW_BASE_URL + '/api/customers/' + SNOW_CUSTOMER_ID + '/applications/' + str(app_id)
    headers = {'Accept': 'application/json',
               'Authorization': 'Basic ' + creds}
    response = http_get(url, headers=headers)
    if response.status_code != 200:
        print('failed to retrieve application details for ' + str(app_id), 'status code: ' + str(response.status_code))
    else:
        data = json_decode(response.body)
        details = data['Body']

    return details

def main(*args, **kwargs):
    username = kwargs['access_key']
    password = kwargs['access_secret']
    b64_creds = base64_encode(username + ":" + password)
    assets = get_computers(b64_creds)
    
    # Format asset list for import into runZero
    import_assets = build_assets(assets, b64_creds)
    if not import_assets:
        print('no assets')
        return None

    return import_assets
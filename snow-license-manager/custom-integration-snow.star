load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('base64', base64_encode='encode', base64_decode='decode')
load('http', http_get='get', http_post='post', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('time', 'parse_time')
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
        hw = item.get('Hardware', {})
        bios_date = hw.get('BiosDate', '')
        #Reformat bios_date timestamp for runZero parsing
        if bios_date and bios_date != '':
            bios_date = parse_time(bios_date + 'Z').unix
        bios_sn = item.get('BiosSerialNumber', '')
        bios_version = hw.get('BiosVersion', '')
        core_count = item.get('CoreCount', '')
        cores_per_proc = hw.get('CoresPerProcessor', '')
        domain = item.get('Domain', '')
        hyperv_name = item.get('HypervisorName', '')
        is_portable = item.get('IsPortable', '')
        is_server = item.get('IsServer', '')
        is_virtual = item.get('IsVirtual', '')
        last_scan_date = item.get('LastScanDate', '')
        # Reformat last_scan_date timestamp for runZero parsing
        if last_scan_date and last_scan_date != '':
            last_scan_date = parse_time(last_scan_date + 'Z').unix
        memory_slots = hw.get('MemorySlots', '')
        memory_slots_avail = hw.get('MemorySlotsAvailable', '')
        most_freq_user = item.get('MostFrequentUserId', '')
        most_recent_user = item.get('MostRecentUserId', '')
        number_of_procs = hw.get('NumberOfProcessors', '')
        organization = item.get('Organization', '')
        org_checksum = item.get('OrgChecksum', '')
        processor_count = item.get('ProcessorCount', '')
        physical_memory = item.get('PhysicalMemory', '')
        physical_memory_mb = hw.get('PhysicalMemoryMb', '')
        processor_type = item.get('ProcessorType', '')
        status = item.get('Status', '')
        system_disk_space_mb = hw.get('SystemDiskSpaceMb', '')
        system_disk_space_avail_mb = hw.get('SystemDiskSpaceAvailableMb', '')
        total_disk_space = item.get('TotalDiskSpace', '')
        total_disk_space_mb = hw.get('TotalDiskSpaceMb', '')
        total_disk_space_avail_mb = hw.get('TotalDiskSpaceAvailableMb', '')
        updated_by = item.get('UpdatedBy', '')
        updated_date = item.get('UpdatedData', '')

        custom_attributes = {
            'biosDate': bios_date,
            'biosSerialNumber': bios_sn,
            'biosVersion': bios_version,
            'coreCount': core_count,
            'coresPerProcessor': cores_per_proc,
            'domain': domain,
            'hypervisorName': hyperv_name,
            'isPortable': is_portable,
            'isServer': is_server,
            'isVirtual': is_virtual,
            'lastScanDate': last_scan_date,
            'memorySlots': memory_slots,
            'memorySlotsAvailable': memory_slots_avail,
            'mostFrequentUserId': most_freq_user,
            'mostRecentUserId': most_recent_user,
            'numberOfProcessors': number_of_procs,
            'organization': organization,
            'orgChecksum': org_checksum,
            'processorCount': processor_count,
            'physicalMemory': physical_memory,
            'physicalMemoryMb': physical_memory_mb,
            'processorType': processor_type,
            'status': status,
            'systemDiskSpaceMb': system_disk_space_mb,
            'systemDiskSpaceAvailableMb': system_disk_space_avail_mb,
            'totalDiskSpace': total_disk_space,
            'totalDiskSpaceMb': total_disk_space_mb,
            'totalDiskSpaceAvailableMb': total_disk_space_avail_mb,
            'updatedBy': updated_by,
            'updatedDate': updated_date
        }
        
        logical_disks = hw.get('LogicalDisks', None)
        if logical_disks and type(logical_disks) == 'list':
            for disk in logical_disks:
                if disk:
                    for k, v in disk.items():
                        custom_attributes['logicalDisks.' + str(logical_disks.index(disk)) + '.' + k] = v
        if logical_disks and type(logical_disks) == 'dict':
            for k, v in logical_disks.items():
                custom_attributes['logicalDisks.0.' + k] = v


        optical_drives = hw.get('OpticalDrives', None)
        if optical_drives and type(optical_drives) == 'list':
            for drive in optical_drives:
                if drive:
                    for k, v in drive.items():
                        custom_attributes['opticalDrives.' + str(optical_drives.index(drive)) + '.' + k] = v
        if optical_drives and type(optical_drives) == 'dict':
            for k, v in optical_drives.items():
                    custom_attributes['opticalDrives.0.' + k] = v

        display_adapters = hw.get('DisplayAdapters', None)
        if display_adapters and type(display_adapters) == 'list':
            for adapter in display_adapters:
                if adapter:
                    for k, v in adapter.items():
                        custom_attributes['displayAdapter.' + str(display_adapters.index(adapter)) + '.' + k] = v
        if display_adapters and type(display_adapters) == 'dict':
            for k, v in display_adapters.items():
                    custom_attributes['displayAdapter.0.' + k] = v

        monitors = hw.get('Monitors', None)
        if monitors and type(monitors) == 'list':
            for monitor in monitors:
                if monitor:
                    for k, v in monitor.items():
                        custom_attributes['monitor.' + str(monitors.index(monitor)) + '.' + k] = v
        if monitors and type(monitors) == 'dict':
            for k, v in monitors.items():
                    custom_attributes['monitor.0.' + k] = v

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
    # Reformat last_used timestamp for runZero parsing
    if last_used and last_used != '':
        last_used = parse_time(last_used + 'Z').unix
    else:
        last_used = 'n/a'
    first_used = app.get('FirstUsed', '')
    # Reformat first_used timestamp for runZero parsing
    if first_used and first_used != '':
        first_used = parse_time(first_used + 'Z').unix
    else:
        first_used = 'n/a'
    install_date = app.get('InstallDate', '')
    # Reformat install_date timestamp for runZero parsing
    if install_date and install_date != '':
        install_date = parse_time(install_date + 'Z').unix
    else:
        install_date = 'n/a'
    discovered_date = app.get('DiscoveredDate', '')
    # Reformat discovered_date timestamp for runZero parsing
    if discovered_date and discovered_date != '':
        discovered_date = parse_time(discovered_date + 'Z').unix
    else:
        discovered_date = 'n/a'
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
        'discovered.date': discovered_date,
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
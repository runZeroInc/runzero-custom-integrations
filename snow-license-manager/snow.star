# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-snow-license-manager",
    "name": "Snow License Manager",
    "type": "inbound",
    "description": "Imports devices from Snow License Manager.",
    "version": "26061000",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "url",
            "label": "Snow base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://snow.example.com",
        },
        {
            "key": "customer_id",
            "label": "Customer ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('base64', base64_encode='encode', base64_decode='decode')
load('http', 'get_json', 'url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')
load('net', 'network_interface')
load('time', 'parse_time')

def build_assets(base_url, customer_id, assets, creds, config_kwargs):
    assets_import = []
    for entry in assets:
        item = entry.get('Body', {})
        raw_id = item.get('Id') or item.get('BiosSerialNumber')
        if not raw_id:
            print("snow: skipping computer with no Id/BiosSerialNumber: name=" + str(item.get('Name', '')))
            continue
        asset_id = str(raw_id)
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
            interface = network_interface(ips=addresses, mac=adapter.get('MacAddress', None))
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
        applications = get_apps(base_url, customer_id, asset_id, creds, config_kwargs)
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
                customAttributes=to_custom_attributes(custom_attributes),
                software=software,
            )
        )
    return assets_import

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
        'manufacturerId': manufacturer_id,
        'manufacturerName': manufacturer_name,
        'familyId': family_id,
        'familyName': family_name,
        'bundledApplicationId': bundled_app_id,
        'bundledApplicationName': bundled_app_name,
        'lastUsedTS': last_used,
        'firstUsedTS': first_used,
        'installDateTS': install_date,
        'discoveredDateTS': discovered_date,
        'run': run,
        'averageUsageTime': avg_usage_time,
        'users': users,
        'licenseRequired': license_reqd,
        'isInstalled': is_installed,
        'isBlacklisted': is_blacklisted,
        'isWhitelisted': is_whitelisted,
        'isVirtual': is_virtual,
        'isOem': is_oem,
        'isMsdn': is_msdn,
        'isWebApplication': is_webapp,
        'applicationItemCost': app_cost
    }

    return Software(
        id=app_id,
        product=product,
        vendor=vendor,
        customAttributes=to_custom_attributes(custom_attributes)
        )

def get_computers(base_url, customer_id, creds, config_kwargs):
    """Paginate computers, building and streaming each page of assets (including
    their per-computer applications) via report_assets so the full computer set
    is never held in memory. Returns the number of assets reported."""
    items_returned = 0
    total_items = 10000
    reported = 0

    while True:
        url = base_url + '/api/customers/' + customer_id + '/computers?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        http_options = get_http_options(config_kwargs, headers=headers)
        params = {'$inlinecount': 'allpages',
                    '$skip': str(items_returned)}
        data, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve assets at $skip=' + str(items_returned) + ': ' + err)
            break
        elif data:
            meta = data['Meta']
            has_page_size = False
            for item in meta:
                if item['Name'] == 'Count':
                    total_items = item.get('Value')
                if item['Name'] == 'PageSize':
                    has_page_size = True
                    items_returned += item.get('Value')
            computers = data['Body']
            reported += report_assets(build_assets(base_url, customer_id, computers, creds, config_kwargs))
            if not has_page_size: # The last page lacks the page size meta value
                break
            print(str(items_returned) + ' computers of ' + str(total_items) + ' returned from API')
        else:
            break

    return reported

def get_apps(base_url, customer_id, asset_id, creds, config_kwargs):
    items_returned = 0
    total_items = 10000
    applications_all = []

    while True:
        url = base_url + '/api/customers/' + customer_id + '/computers/' + str(asset_id) + '/applications?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        http_options = get_http_options(config_kwargs, headers=headers)
        params = {'$inlinecount': 'allpages',
                  '$skip': str(items_returned)}
        data, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve application for ' + str(asset_id) + ' at $skip=' + str(items_returned) + ': ' + err)
        elif data:
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

def get_app_details(base_url, customer_id, app_id, creds, config_kwargs):
    url = base_url + '/api/customers/' + customer_id + '/applications/' + str(app_id)
    headers = {'Accept': 'application/json',
               'Authorization': 'Basic ' + creds}
    data, err = get_json(url, **get_http_options(config_kwargs, headers=headers))
    if err:
        print('failed to retrieve application details for ' + str(app_id) + ': ' + err)
        details = None
    else:
        details = (data or {}).get('Body')

    return details

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    customer_id = get_string(kwargs, 'customer_id')
    username = kwargs['username']
    password = kwargs['password']
    b64_creds = base64_encode(username + ":" + password)

    # Computers (and their applications) are streamed page-by-page via
    # report_assets in get_computers.
    reported = get_computers(base_url, customer_id, b64_creds, kwargs)
    if not reported:
        print('no assets')

    return None
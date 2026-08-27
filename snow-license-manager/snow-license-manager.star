# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-snow-license-manager",
    "name": "Snow License Manager",
    "type": "inbound",
    "description": "Imports devices from Snow License Manager.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Backstop for the Meta-driven pagers below: the walk normally ends when a
    # page arrives without the PageSize meta entry, and if a server never omits
    # it this is what stops the loop instead of the 1,000,000-page default.
    "maxPages": 10000,
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
load('base64', base64_encode='encode')
load('coerce', 'as_text', 'as_dict', 'as_list', 'dicts', 'as_int')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')
load('net', 'network_interface')
load('time', 'parse_ts')

def _ts_attr(value, default=''):
    """Unix epoch for a Snow timestamp attribute, or the raw value when it
    cannot be parsed. parse_ts never raises, so one date-only or already-offset
    timestamp on one record cannot abort the whole import."""
    ts = parse_ts(value)
    if ts:
        return ts.unix
    return value if value else default

def _is_true(value):
    """Read a Snow boolean, which arrives as a bool, a string, or 0/1."""
    if type(value) == "bool":
        return value
    if type(value) == "int":
        return value == 1
    if type(value) == "string":
        return value.strip().lower() in ["true", "1", "yes"]
    return False

def device_type(item):
    """Return the runZero device type for a Snow computer, or None.

    Snow records the chassis as flags on the computer rather than as a type,
    so only the true cases say anything. A computer that is neither a server
    nor portable could be a desktop, a virtual machine, or a thin client --
    Snow's IsVirtual is set independently of both -- so the false case is left
    unmapped rather than assumed to be a desktop. That also means a field this
    Snow installation does not return produces no device type at all, instead
    of a wrong one.
    """
    if _is_true(item.get('IsServer')):
        return "Server"
    if _is_true(item.get('IsPortable')):
        return "Laptop"
    return None

def _indexed_attrs(custom_attributes, prefix, value):
    """Flatten a hardware sub-collection (disks, drives, adapters, monitors)
    into indexed custom attribute keys. The collection arrives as a list of
    dicts or, for a single entry, as a bare dict; anything else is skipped."""
    entries = dicts(value)
    for index in range(len(entries)):
        for k, v in entries[index].items():
            custom_attributes[prefix + '.' + str(index) + '.' + str(k)] = v

def get_computer_detail(base_url, customer_id, asset_id, creds, config_kwargs):
    """Fetch one computer's full record and return its Body dict, or {}.

    Only called when a computers-list row carries no Hardware block at all --
    the fallback for an SLM build whose list returns summary rows."""
    url = base_url + '/api/customers/' + customer_id + '/computers/' + str(asset_id)
    headers = {'Accept': 'application/json',
               'Authorization': 'Basic ' + creds}
    http_options = get_http_options(config_kwargs, headers=headers)
    data, err = get_json(url, **http_options)
    if err:
        print('failed to retrieve computer detail for ' + str(asset_id) + ': ' + err)
        return {}
    return as_dict(as_dict(data).get('Body'))

def build_assets(base_url, customer_id, assets, creds, config_kwargs):
    assets_import = []
    for entry in dicts(assets):
        item = as_dict(entry.get('Body'))
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

        # The list row is expected to carry the Hardware block, but whether the
        # real SLM computers LIST returns full rows or summary rows is not
        # confirmed against a live install. When Hardware is absent entirely,
        # the per-computer detail record is fetched as a fallback so a
        # summary-row server still imports interfaces instead of hostname-only
        # records; a server whose list rows are full never pays the extra call.
        hw = item.get('Hardware')
        if hw == None:
            detail = get_computer_detail(base_url, customer_id, asset_id, creds, config_kwargs)
            hw = detail.get('Hardware')
        hw = as_dict(hw)

        # create the network interfaces
        interfaces = []
        for adapter in dicts(hw.get('NetworkAdapters')):
            addresses = as_text(adapter.get('IpAddress')).split(';')
            interface = network_interface(ips=addresses, mac=adapter.get('MacAddress', None))
            # network_interface returns None when nothing usable survives;
            # appending it aborts the whole run at ImportAsset.
            if interface:
                interfaces.append(interface)

        # Retrieve and map custom attributes
        bios_date = _ts_attr(hw.get('BiosDate'))
        bios_sn = item.get('BiosSerialNumber', '')
        bios_version = hw.get('BiosVersion', '')
        core_count = item.get('CoreCount', '')
        cores_per_proc = hw.get('CoresPerProcessor', '')
        domain = item.get('Domain', '')
        hyperv_name = item.get('HypervisorName', '')
        is_portable = item.get('IsPortable', '')
        is_server = item.get('IsServer', '')
        is_virtual = item.get('IsVirtual', '')
        last_scan_date = _ts_attr(item.get('LastScanDate'))
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
        # Both spellings: 'UpdatedData' is what this script always read, but
        # 'UpdatedDate' is the plausible real field name; neither is confirmed
        # against a live install, so whichever is present wins.
        updated_date = item.get('UpdatedDate') or item.get('UpdatedData', '')

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
        
        # Each of these arrives as a list of dicts or, for a single entry, as a
        # bare dict; dicts() accepts both and skips nulls and stray strings.
        _indexed_attrs(custom_attributes, 'logicalDisks', hw.get('LogicalDisks'))
        _indexed_attrs(custom_attributes, 'opticalDrives', hw.get('OpticalDrives'))
        _indexed_attrs(custom_attributes, 'displayAdapter', hw.get('DisplayAdapters'))
        _indexed_attrs(custom_attributes, 'monitor', hw.get('Monitors'))

        # Retrieve software information for asset
        # create software entries
        software = []
        applications = get_apps(base_url, customer_id, asset_id, creds, config_kwargs)
        for app in applications:
            software_entry = build_app(app)
            # build_app declines rows with no Id rather than aborting the run.
            if software_entry:
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
                deviceType=device_type(item),
                networkInterfaces=interfaces,
                customAttributes=to_custom_attributes(custom_attributes),
                software=software,
            )
        )
    return assets_import

def build_app(software_entry):
    """Convert one application row into a Software record, or None to skip it."""
    app = as_dict(as_dict(software_entry).get('Body'))
    app_id = app.get('Id', None)
    if not app_id:
        # Software(id=None) fails the whole record; skip the row instead.
        print('snow: skipping application row with no Id: name=' + str(app.get('Name', '')))
        return None
    # NO PER-APPLICATION DETAIL CALL IS MADE HERE, DELIBERATELY.
    #
    # A `get_app_details()` helper used to sit below, wrapping
    # GET /api/customers/{customer_id}/applications/{app_id}, with its call site
    # on this line commented out. It has been removed rather than re-enabled:
    #
    #  - It could not have worked as written. The call site passed one argument
    #    to a five-parameter function, and build_app() receives only the
    #    application row -- it holds no base_url, customer_id, credentials or
    #    http options to pass. Uncommenting it would have aborted the script.
    #  - The cost is not N+1 but N*M: one request per (computer, application)
    #    pair, on top of the per-computer applications call that is already the
    #    most expensive thing this integration does. The same application is
    #    installed on hundreds of computers and would be fetched once for each.
    #  - It buys almost nothing. That endpoint returns the GLOBAL application
    #    record, and the manufacturer, family and bundle fields it carries are
    #    already on the per-computer row read below. What it adds beyond those
    #    is licensing state -- which the whole catalog exposes in ONE request at
    #    GET /api/customers/{customer_id}/applications. If licensing is ever
    #    wanted, that catalog read joined on Id is the way to get it, not a
    #    per-computer-per-application walk.
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
    # Timestamps become unix epochs via parse_ts, which never raises; a value
    # that cannot be parsed is carried raw and an absent one reads 'n/a'.
    last_used = _ts_attr(app.get('LastUsed'), 'n/a')
    first_used = _ts_attr(app.get('FirstUsed'), 'n/a')
    install_date = _ts_attr(app.get('InstallDate'), 'n/a')
    discovered_date = _ts_attr(app.get('DiscoveredDate'), 'n/a')
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

    _pager = pager("computers")
    while _pager.next():
        url = base_url + '/api/customers/' + customer_id + '/computers?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        http_options = get_http_options(config_kwargs, headers=headers)
        params = {'$inlinecount': 'allpages',
                    '$skip': str(items_returned)}
        data, err = get_json(url, params=params, **http_options)
        if err:
            fail('snow-license-manager: failed to retrieve assets at $skip=' + str(items_returned) + ': ' + err)
        elif data:
            # Direct indexing on the envelope aborts the run if a 200 arrives
            # without the Meta/Body shape, so every level is coerced instead.
            data = as_dict(data)
            has_page_size = False
            page_size = 0
            for item in dicts(data.get('Meta')):
                name = item.get('Name')
                if name == 'Count':
                    total_items = as_int(item.get('Value'))
                if name == 'PageSize':
                    has_page_size = True
                    page_size = as_int(item.get('Value'))
            computers = as_list(data.get('Body'), wrap=False)
            reported += report_assets(build_assets(base_url, customer_id, computers, creds, config_kwargs))
            if not has_page_size or page_size <= 0:
                # The last page lacks the PageSize meta value, and a PageSize
                # that cannot advance $skip would re-request the same rows.
                break
            items_returned += page_size
            print(str(items_returned) + ' computers of ' + str(total_items) + ' returned from API')
        else:
            break

    return reported

def get_apps(base_url, customer_id, asset_id, creds, config_kwargs):
    items_returned = 0
    total_items = 10000
    applications_all = []

    # Labelled separately from the computer walk: this one runs once per
    # computer, so its ceiling is per-computer rather than for the whole run.
    _pager = pager("applications")
    while _pager.next():
        url = base_url + '/api/customers/' + customer_id + '/computers/' + str(asset_id) + '/applications?'
        headers = {'Accept': 'application/json',
                   'Authorization': 'Basic ' + creds}
        http_options = get_http_options(config_kwargs, headers=headers)
        params = {'$inlinecount': 'allpages',
                  '$skip': str(items_returned)}
        data, err = get_json(url, params=params, **http_options)
        if err:
            # break, not fall through: the loop's only other exit is a page
            # without the PageSize meta value, so continuing here re-issues the
            # identical failing request forever and hangs the whole task on one
            # unhappy computer. Same shape as get_computers.
            print('failed to retrieve application for ' + str(asset_id) + ' at $skip=' + str(items_returned) + ': ' + err)
            break
        elif data:
            # Same envelope coercion as get_computers: a 200 without the
            # Meta/Body shape must not abort the run.
            data = as_dict(data)
            has_page_size = False
            page_size = 0
            for item in dicts(data.get('Meta')):
                name = item.get('Name')
                if name == 'Count':
                    total_items = as_int(item.get('Value'))
                if name == 'PageSize':
                    has_page_size = True
                    page_size = as_int(item.get('Value'))
            applications_all.extend(dicts(data.get('Body')))
            if not has_page_size or page_size <= 0:
                # The last page lacks the PageSize meta value, and a PageSize
                # that cannot advance $skip would re-request the same rows.
                break
            items_returned += page_size
            print(str(items_returned) + ' applications of ' + str(total_items) + ' returned from API')
        else:
            # A 2xx with an empty body decodes to None, which matches neither
            # branch above. Without this it is the second way to spin here.
            print('empty applications response for ' + str(asset_id) + ' at $skip=' + str(items_returned))
            break

    return applications_all

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
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('http', http_get='get', http_post='post', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('time', 'parse_time')
load('uuid', 'new_uuid')

#Change the URL to match your Guardicore Centra server
CENTRA_BASE_URL = 'https://<Guardicore Centra URL>'
RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets):
    assets_import = []
    for asset in assets:
        asset_id = str(asset.get('id', new_uuid))
        agent_info = asset.get('guest_agent_details', {})
        hardware = agent_info.get('hardware', {})
        os_info = agent_info.get('os_details', {})
        hostname = agent_info.get('hostname', '')
        os = os_info.get('os_version_name', '')
        vendor = hardware.get('vendor', '')
        first_seen = asset.get('first_seen', None)

        # create the network interfaces
        interfaces = []
        networks = agent_info.get('network', [])
        for network in networks:
            ips = [address.get('address', '') for address in network.get('ip_addresses', [])]
            interface = build_network_interface(ips=ips, mac=network.get('hardware_address', None))
            interfaces.append(interface)

        # Retrieve and map custom attributes
        active = asset.get('active', '')
        agent_last_seen = asset.get('last_guest_agent_details_update', '')
        agent_type = agent_info.get('agent_type', '')
        agent_version = agent_info.get('agent_version', '')
        arch = hardware.get('architecture', '')
        bios_uuid = asset.get('bios_uuid', '')
        client_cert = agent_info.get('client_cert_ssl_cn_name', '')
        comments = asset.get('comments', '')
        doc_version = asset.get('doc_version', '')
        hw_uuid = hardware.get('hw_uuid', '')
        is_on = asset.get('is_on', '')
        labels = agent_info.get('labels', [])
        last_seen = asset.get('last_seen', '')
        kernel_major = os_info.get('os_kernel_major', '')
        kernel_minor = os_info.get('os_kernel_minor', '')
        os_kernel = str(kernel_major) + '.' + str(kernel_minor)
        os_type = os_info.get('os_type', '')
        proc_count = os_info.get('num_of_processors', '')
        recent_domains = asset.get('recent_domains', [])
        serial = hardware.get('serial', '')
        status = asset.get('status', '')
        vm_id = asset.get('vm_id', '')
        vm_name = asset.get('vm_name', '')

        custom_attributes = {
            'active': active,
            'agent.LastSeenTS': agent_last_seen,
            'agent.type': agent_type,
            'agent.Version': agent_version,
            'biosUuid': bios_uuid,
            'client_cert': client_cert,
            'comments': comments,
            'docVersion': doc_version,
            'hardware.Arch': arch,
            'hardware.SerialNumber': serial,
            'hardware.Uuid': hw_uuid,
            'isOn': is_on,
            'labels': labels,
            'firstSeenTS': first_seen
            'lastSeenTS': last_seen,
            'recentDomains': recent_domains,
            'status': status,
            'osInfo.fullKernelVersion': os_kernel,
            'osInfo.osType': os_type,
            'processorCount': proc_count,
            'vmId': vm_id,
            'vmName': vm_name
        }

        agent_labels = agent_info.get('labels', [])
        for label in agent_labels:
            custom_attributes['agent.labels.' + str(agent_labels.index(label))] = label
        labels = asset.get('labels', [])
        for label in labels:
            for k, v in label.items():
                custom_attributes['labels.' + str(labels.index(label)) + '.' + k ] = v
        metadata = asset.get('metadata', [])
        for data in metadata:
            custom_attributes['metadata.' + str(metadata.index(data))] = ':'.join(data)
        orc_details = asset.get('orchestration_details', [])
        for detail in orc_details:
            for k, v in detail.items():
                custom_attributes['orchestrationDetails.' + str(orc_details.index(detail)) + '.' + k ] = v
        agent_supported_features = agent_info.get('supported_features', {}).get('RevealAgent', [])
        for feature in agent_supported_features:
            custom_attributes['agent.supportedFeatures.' + str(agent_supported_features.index(feature))] = feature

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                manufacturer=vendor,
                hostnames=[hostname],
                os=os,
                networkInterfaces=interfaces,
                customAttributes=custom_attributes
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

def get_assets(token):
    assets_all = []
    results_per_page = 1000
    start = 0
    last_return = 1000

    # Return all 'status:on' assets
    while True:
        url = CENTRA_BASE_URL + '/api/v4.0/assets?'
        headers = {'Accept': 'application/json',
                    'Authorization': 'Bearer ' + token}
        params = {'max_results': results_per_page,
                  'start_at': start,
                  'status': 'on'}
        response = http_get(url, headers=headers, params=params)
        if response.status_code != 200:
            print('failed to retrieve "on" assets ' + str(start) + ' to ' + str(start + results_per_page), 'status code: ' + str(response.status_code))
            break
        else:
            data = json_decode(response.body)
            assets = data['objects']
            assets_all.extend(assets)
            last_return = len(assets)
            start += last_return
            if last_return < results_per_page:
                start = 0
                last_return = 1000
                break
    # Return all 'status:off' assets. Remove this while loop to restrict import to only status 'on' assets.
    while True:
        url = CENTRA_BASE_URL + '/api/v3.0/assets?'
        headers = {'Accept': 'application/json',
                    'Authorization': 'Bearer ' + token}
        params = {'max_results': results_per_page,
                  'start_at': start,
                  'status': 'off'}
        response = http_get(url, headers=headers, params=params)
        if response.status_code != 200:
            print('failed to retrieve "off" assets ' + str(start) + ' to ' + str(start + results_per_page), 'status code: ' + str(response.status_code))
            break
        else:
            data = json_decode(response.body)
            assets = data['objects']
            assets_all.extend(assets)
            last_return = len(assets)
            start += last_return
            if last_return < results_per_page:
                break            

    return assets_all

def get_token(username, password):
    url = CENTRA_BASE_URL + '/api/v3.0/authenticate'
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username,
              'password': password}
    
    response = http_post(url, headers=headers, body=bytes(json_encode(payload)))
    if response.status_code != 200:
        print('authentication failed: ' + str(response.status_code))
        return None

    auth_data = json_decode(response.body)
    if not auth_data:
        print('invalid authentication data')
        return None

    return auth_data['access_token']  

def main(*args, **kwargs):
    username = kwargs['access_key']
    password = kwargs['access_secret']
    token = get_token(username, password)
    assets = get_assets(token)
    
    # Format asset list for import into runZero
    import_assets = build_assets(assets)
    if not import_assets:
        print('no assets')
        return None

    return import_assets
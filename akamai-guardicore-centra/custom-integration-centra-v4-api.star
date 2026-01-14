load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('http', http_get='get', http_post='post', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('time', 'parse_time')
load('uuid', 'new_uuid')

#Change the URL to match your Guardicore Centra server
CENTRA_BASE_URL = 'https://<Guardicore Centra URL>'
RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets, token):
    assets_import = []
    label_mapping = {}
    for asset in assets:
        agent_info = asset.get('agent', {})
        os_info = asset.get('os_info', {})
        asset_id = agent_info.get('id', str(new_uuid))
        hostname = asset.get('name', '')
        os = os_info.get('type', '')
        first_seen = asset.get('first_seen', '')
        #reformat first_seen timestamp for runZero parsing
        if first_seen != '':
            split_space = first_seen.split(' ')
            first_seen = parse_time(split_space[0] + 'T' + split_space[1] + 'Z')

        # create the network interfaces
        interfaces = []
        nics = asset.get('nics', [])
        for nic in nics:
            addresses = nic.get('ip_addresses', [])
            interface = build_network_interface(ips=addresses, mac=nic.get('mac_address', None))
            interfaces.append(interface)

        # Retrieve and map custom attributes
        
        orchestration_metadata = asset.get('orchestration_metadata', {})
        scoping_details = asset.get('scoping_details', {}).get('worksite', {})
        agent_id = agent_info.get('id', '')
        agent_last_seen = agent_info.get('agent_last_seen', '')
        #reformat agent_last_seen timestamp for runZero parsing
        if agent_last_seen != '':
            split_space = agent_last_seen.split(' ')
            agent_last_seen = parse_time(split_space[0] + 'T' + split_space[1] + 'Z').unix
        agent_version = agent_info.get('agent_version', '')
        asset_type = asset.get('asset_type', '')
        bios_uuid = asset.get('bios_uuid', '')
        comments = asset.get('comments', '')
        instance_id = asset.get('instance_is', '')
        last_seen = asset.get('last_seen', '')
        #reformat last_seen timestamp for runZero parsing
        if last_seen != '':
            split_space = last_seen.split(' ')
            last_seen = parse_time(split_space[0] + 'T' + split_space[1] + 'Z').unix
        mssp_tenant = asset.get('mssp_tenant_name', '')
        orc_asset_type = orchestration_metadata.get('asset_type', '')
        orc_dev_name = orchestration_metadata.get('f5_device_hostname', '')
        orc_partition = orchestration_metadata.get('partition', '')
        orc_vs_name = orchestration_metadata.get('vs_name', '')
        os_kernel = os_info.get('full_kernel_version', '')
        status = asset.get('status', '')
        worksite_mod = scoping_details.get('modified', '')
        worksite_name = scoping_details.get('name', '')

        labels = asset.get('labels', [])
        label_guids = [v for item in labels for k,v in item.items() if k == 'id']
        label_names = []
        for guid in label_guids:
            name = label_mapping.get(guid, None)
            if not name:
                new_mapping = get_labels(guid, token)
                for k, v in new_mapping.items():
                    label_mapping[k] = v
                name = label_mapping.get(guid, '')
            label_names.append(name)

        tags = []
        for label in label_names:
            split_tag = label.split(':').strip()
            reformat = split_tag[0] + '=' + split_tag[1]
            tag_string = tag_string + ' ' + reformat
            tags.append(tag_string)
        

        custom_attributes = {
            'agent.Id': agent_id,
            'agent.LastSeenTS': agent_last_seen,
            'agent.Version': agent_version,
            'assetType': asset_type,
            'biosUuid': bios_uuid,
            'comments': comments,
            'instanceId': instance_id,
            'labels': label_names,
            'lastSeenTS': last_seen,
            'msspTenantName': mssp_tenant,
            'osInfo.fullKernelVersion': os_kernel,
            'scopingDetails.worksite.modified': worksite_mod,
            'scopingDetails.worksite.name': worksite_name,
            'status': status,
            'orchestrationMetadata.assetType': orc_asset_type,
            'orchestrationMetadata.f5DeviceHostname': orc_dev_name,
            'orchestrationMetadata.partition': orc_partition,
            'orchestrationMetadata.vsName': orc_vs_name
        }

        label_groups = asset.get('label_groups', [])
        for group in label_groups:
            for k, v in group.items():
                custom_attributes['labelGroup.' + str(label_groups.index(group)) + '.' + k] = v
        orchestration_details = asset.get('orchestration_details', [])
        for detail in orchestration_details:
            for k, v in detail.items():
                custom_attributes['orchestrationDetails.' + str(orchestration_details.index(detail)) + '.' + k] = v

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                os=os,
                first_seen_ts=first_seen,
                networkInterfaces=interfaces,
                customAttributes=custom_attributes,
                tags=tags
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

def get_labels(guid, token):
    url = CENTRA_BASE_URL + '/api/v4.0/labels/' + guid + '?'
    headers = {'Accept': 'application/json',
            'Authorization': 'Bearer ' + token}
    params = {'asset_limit': 1}
    response = http_get(url, headers=headers, params=params)
    if response.status_code != 200:
        print('failed to retrieve label info for  ' + guid, 'status code: ' + str(response.status_code))
    data = json_decode(response.body)
    label_info = data['objects']
    label_key = label_info[0].get('key', '')
    label_value = label_info[0].get('value', '')
    label_mapping = { guid: label_key + ': ' + label_value }
    return label_mapping

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
                  'status': 'on',
                  'expand': 'agent'}
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
        url = CENTRA_BASE_URL + '/api/v4.0/assets?'
        headers = {'Accept': 'application/json',
                    'Authorization': 'Bearer ' + token}
        params = {'max_results': results_per_page,
                  'start_at': start,
                  'status': 'off',
                  'expand': 'agent'}
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
    import_assets = build_assets(assets, token)
    if not import_assets:
        print('no assets')
        return None

    return import_assets
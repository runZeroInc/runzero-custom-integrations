# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-akamai-guardicore-centra-v4-api",
    "name": "Akamai Guardicore Centra",
    "type": "inbound",
    "description": "Imports Centra agents and assets via the Centra v3 or v4 API.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Centra URL",
            "type": "url",
            "required": True,
            "placeholder": "https://centra.example.com",
            "group": "Connection",
        },
        {
            "key": "username",
            "label": "Centra username",
            "type": "string",
            "required": True,
            "group": "Authentication",
        },
        {
            "key": "password",
            "label": "Centra password",
            "type": "secret",
            "required": True,
            "group": "Authentication",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('http', 'get_json', 'post_json', 'bearer')
load('kwargs', 'get_url_base', 'get_http_options')
load('net', 'network_interface')
load('time', 'parse_time')


def build_assets(base_url, assets, token, config_kwargs, label_mapping):
    assets_import = []
    for asset in assets:
        agent_info = asset.get('agent', {})
        os_info = asset.get('os_info', {})
        raw_id = asset.get('id') or asset.get('bios_uuid') or asset.get('instance_id')
        if not raw_id:
            print("centra-v4: skipping asset with no stable id: name=" + str(asset.get('name', '')))
            continue
        asset_id = str(raw_id)
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
            interface = network_interface(ips=addresses, mac=nic.get('mac_address', None))
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
                new_mapping = get_labels(base_url, guid, token, config_kwargs)
                for k, v in new_mapping.items():
                    label_mapping[k] = v
                name = label_mapping.get(guid, '')
            label_names.append(name)

        tags = []
        for label in label_names:
            split_label = label.split(':')
            tag = split_label[0].strip().replace(' ', '_') + '=' + split_label[1].strip().replace(' ', '_')
            tags.append(tag)
        

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
                customAttributes=to_custom_attributes(custom_attributes),
                tags=tags,
            )
        )
    return assets_import

def get_labels(base_url, guid, token, config_kwargs):
    url = base_url + '/api/v4.0/labels/' + guid + '?'
    headers = {'Accept': 'application/json',
            'Authorization': bearer(token)}
    params = {'asset_limit': 1}
    data, err = get_json(url, params=params, **get_http_options(config_kwargs, headers=headers))
    if err:
        print('failed to retrieve label info for ' + guid + ': ' + err)
        return {}
    label_info = (data or {}).get('objects', [])
    if not label_info:
        return {}
    label_key = label_info[0].get('key', '')
    label_value = label_info[0].get('value', '')
    return { guid: label_key + ': ' + label_value }

def stream_assets(base_url, token, config_kwargs):
    """Paginate Centra assets ('on' then 'off'), building and streaming each page
    via report_assets so the full asset set is never held in memory. The label
    cache is shared across pages to avoid redundant label lookups. Returns the
    number of assets reported."""
    label_mapping = {}
    reported = 0
    results_per_page = 1000

    for status in ('on', 'off'):
        # Return all assets for this status. Remove 'off' from the tuple above to
        # restrict import to only status 'on' assets.
        start = 0
        while True:
            url = base_url + '/api/v4.0/assets?'
            headers = {'Accept': 'application/json',
                        'Authorization': bearer(token)}
            http_options = get_http_options(config_kwargs, headers=headers)
            params = {'max_results': results_per_page,
                      'start_at': start,
                      'status': status,
                      'expand': 'agent'}
            data, err = get_json(url, params=params, **http_options)
            if err:
                print('failed to retrieve "' + status + '" assets ' + str(start) + ' to ' + str(start + results_per_page) + ': ' + err)
                break
            assets = (data or {}).get('objects', [])
            reported += report_assets(build_assets(base_url, assets, token, config_kwargs, label_mapping))
            last_return = len(assets)
            start += last_return
            if last_return < results_per_page:
                break

    return reported

def get_token(base_url, username, password, config_kwargs):
    url = base_url + '/api/v3.0/authenticate'
    data, err = post_json(url, json={'username': username, 'password': password}, **get_http_options(config_kwargs))
    if err:
        print('authentication failed:', err)
        return None
    if not data:
        print('invalid authentication data')
        return None
    return data.get('access_token')

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    username = kwargs['username']
    password = kwargs['password']
    token = get_token(base_url, username, password, kwargs)

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(base_url, token, kwargs)
    if not reported:
        print('no assets')

    return None
# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-akamai-guardicore-centra-v3-api",
    "name": "Akamai Guardicore Centra (v3)",
    "type": "inbound",
    "description": "Imports assets from Akamai Guardicore Centra using the v3 API.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Centra URL",
            "type": "url",
            "required": True,
            "placeholder": "https://centra.example.com",
            "description": "Centra API base URL.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Centra API username.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Centra API password.",
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


def build_assets(assets):
    assets_import = []
    for asset in assets:
        agent_info = asset.get('guest_agent_details', {})
        hardware = agent_info.get('hardware', {})
        raw_id = asset.get('id') or asset.get('bios_uuid') or hardware.get('hw_uuid')
        if not raw_id:
            print("centra-v3: skipping asset with no stable id: name=" + str(asset.get('name', '')))
            continue
        asset_id = str(raw_id)
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
            interface = network_interface(ips=ips, mac=network.get('hardware_address', None))
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
            'firstSeenTS': first_seen,
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
                customAttributes=to_custom_attributes(custom_attributes),
            )
        )
    return assets_import

def stream_assets(base_url, token, config_kwargs):
    """Paginate Centra assets ('on' then 'off'), building and streaming each page
    via report_assets so the full asset set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    results_per_page = 1000

    # The 'on' and 'off' status queries historically target different API
    # versions; preserve those endpoints exactly.
    status_urls = [('on', base_url + '/api/v4.0/assets?'), ('off', base_url + '/api/v3.0/assets?')]

    for status, url in status_urls:
        # Remove the 'off' entry above to restrict import to only status 'on'
        # assets.
        start = 0
        while True:
            headers = {'Accept': 'application/json',
                        'Authorization': bearer(token)}
            http_options = get_http_options(config_kwargs, headers=headers)
            params = {'max_results': results_per_page,
                      'start_at': start,
                      'status': status}
            data, err = get_json(url, params=params, **http_options)
            if err:
                print('failed to retrieve "' + status + '" assets ' + str(start) + ' to ' + str(start + results_per_page) + ': ' + err)
                break
            assets = (data or {}).get('objects', [])
            reported += report_assets(build_assets(assets))
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
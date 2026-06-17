# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-ivanti-neurons",
    "name": "Ivanti Neurons",
    "type": "inbound",
    "description": "Imports devices from Ivanti Neurons.",
    "version": "26052700",
    "params": [
        {
            "key": "url",
            "label": "Ivanti Neurons URL",
            "type": "url",
            "required": True,
            "placeholder": "https://neurons.example.com",
        },
        {
            "key": "tenant_id",
            "label": "Tenant ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_id",
            "label": "OAuth client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "OAuth client secret",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', http_get='get', http_post='post', 'get_json', 'url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')
load('uuid', 'new_uuid')

def build_assets(assets):
    assets_import = []
    for asset in assets:
        asset_id = str(asset.get('DiscoveryId', str(new_uuid)))
        hostname = asset.get('DeviceName', '')
        os = asset.get('OS', {}).get('Name', '')
        os_version = asset.get('OS', {}).get('Version', '')
        os = os + ' ' + os_version if os_version else os
        model = asset.get('System', {}).get('Model', '')

        # create the network interfaces
        tcpip = asset.get('Network', {}).get('TCPIP', {})
        address_list = list(tcpip.values())
        interfaces = network_interface(ips=address_list, mac=None)

        #map additional custom attributes
        displayname = asset.get('DisplayName', '')
        device_id = asset.get('DeviceID', '')

        custom_attributes = {
                             'discoveryId': asset_id,
                             'deviceName': hostname,
                             'deviceId': device_id,
                             'displayName': displayname,
                             'os.name': os,
                             'os.version': os_version,
                             'system.model': model
                            }

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                os=os,
                model=model,
                networkInterfaces=[interfaces],
                customAttributes=to_custom_attributes(custom_attributes),
            )
        )
    return assets_import

def get_assets(base_url, token, config_kwargs):
    assets_all = []
    url = base_url + '/api/apigatewaydataservices/v1/devices'
    headers = {'Accept': 'application/json',
                'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)
    total_assets = 1000
    while len(assets_all) < (total_assets - 1):
        data, err = get_json(url, **http_options)
        if err:
            print('failed to retrieve devices from ' + url + ': ' + err)
            break
        if not data:
            break
        assets = data['value']
        assets_all.extend(assets)
        total_assets = data.get('@odata.count')
        url = data.get('@odata.nextLink')

    return assets_all

def get_token(base_url, tenant_id, client_id, client_secret, config_kwargs):
    url = base_url + '/api/apigatewaydataservices/v1/token'
    headers = {'Content-Type': 'application/json',
               'X-ClientSecret': client_secret,
               'X-TenantId': tenant_id,
               'X-ClientId': client_id}
    response = http_get(url, **get_http_options(config_kwargs, headers=headers))
    if response.status_code != 200:
        print('authentication failed: ' + str(response.status_code))
        return None
    auth_data = response.body
    if not auth_data:
        print('invalid authentication data')
        return None

    return auth_data

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    tenant_id = get_string(kwargs, 'tenant_id')
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']
    token = get_token(base_url, tenant_id, client_id, client_secret, kwargs)
    assets = get_assets(base_url, token, kwargs)
    
    # Build and stream asset import via report_assets instead of returning a list
    if not report_assets(build_assets(assets)):
        print('no assets')

    return None
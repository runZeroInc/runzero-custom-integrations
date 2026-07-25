# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-solarwinds-information-service",
    "name": "SolarWinds Information Service",
    "type": "inbound",
    "description": "Imports devices via the SolarWinds Information Service (SWIS) API.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "SWIS URL",
            "type": "url",
            "required": False,
            "default": "https://localhost:17774",
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
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('base64', base64_encode='encode', base64_decode='decode')
load('http', 'get_json', 'url_encode')
load('kwargs', 'get_url_base', 'get_http_options')
load('net', 'network_interface')

RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets):
    assets_import = []
    for asset in assets:
        raw_id = asset.get('NodeId') or asset.get('Fqdn') or asset.get('IpAddress')
        if not raw_id:
            print("swis: skipping node with no NodeId/Fqdn/IpAddress")
            continue
        asset_id = str(raw_id)
        hostname = asset.get('Fqdn', '')
        os = asset.get('OsVersion', '')
        vendor = asset.get('Vendor', '')

        # create the network interfaces
        interfaces = []
        addresses = asset.get('IpAddress', [])
        interface = network_interface(ips=[addresses], mac=None)
        interfaces.append(interface)

        # Retrieve and map custom attributes
        custom_attributes = to_custom_attributes({
            'percentCpuUtilization':    asset.get('CpuPercentUtilization'),
            'discoveryProfileId':       asset.get('DiscoveryProfileId'),
            'percentMemoryUtilization': asset.get('PercentMemoryUsed'),
            'memoryUtilized':           asset.get('MemoryUsed'),
            'pollers':                  asset.get('Pollers'),
            'responseTime':             asset.get('ResponseTime'),
            'snmp.port':                asset.get('SnmpPort'),
            'snmp.version':             asset.get('SnmpVersion'),
            'status':                   asset.get('Status'),
            'sysObjectId':              asset.get('SysObjectId'),
            'uptime':                   asset.get('Uptime'),
        })

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                os=os,
                manufacturer=vendor,
                networkInterfaces=interfaces,
                customAttributes=custom_attributes,
            )
        )
    return assets_import

def get_assets(base_url, creds, config_kwargs):

    url = base_url + '/SolarWinds/InformationService/v3/Json/Query?'
    headers = {'Accept': 'application/json',
                'Authorization': 'Basic ' + creds}
    http_options = get_http_options(config_kwargs, headers=headers)
    # Populate the SWQL query to return desired assets and attributes in the params query value e.g. 
    # params = {'query': 'SELECT N.NodeID, N.OsVersion, N.Fqdn, N.Vendor, N.IPAddress, N.CpuPercentUtilization, N.DiscoveryProfileId, N.PercentMemoryUsed, N.MemoryUsed, N.Pollers, N.responseTime, N.snmp.port, N.snmp.version, N.status, N.sysObjectId, N.Uptime FROM Orion.Nodes'}
    params = {'query': ''}
    data, err = get_json(url, params=params, **http_options)
    if err:
        print('failed to retrieve assets:', err)
        return []
    assets = (data or {}).get('results', [])

    return assets

def main(*args, **kwargs):
    base_url = get_url_base(kwargs, default='https://localhost:17774')
    username = kwargs['username']
    password = kwargs['password']
    b64_creds = base64_encode(username + ":" + password)
    assets = get_assets(base_url, b64_creds, kwargs)
    
    # Build and stream asset import via report_assets instead of returning a list
    if not report_assets(build_assets(assets)):
        print('no assets')

    return None

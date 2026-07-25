# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-ninjaone",
    "name": "NinjaOne",
    "type": "inbound",
    "description": "Imports devices from NinjaOne.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "api_url",
            "label": "NinjaOne API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://us2.ninjarmm.com",
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
load('http', 'get_json', 'oauth2_token', 'bearer')
load('kwargs', 'get_http_options', 'get_string')

def get_token(api_url, client_id, client_secret, config_kwargs):
    return oauth2_token(
        api_url + '/ws/oauth/token',
        client_id=client_id,
        client_secret=client_secret,
        scope="monitoring",
        **get_http_options(config_kwargs)
    )

def get_assets(api_url, token, config_kwargs):
    hasNextPage = True
    after = ''
    page_size = 500
    assets = []
    reported = 0

    url = api_url + "/v2/devices-detailed"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)

    while hasNextPage:
        query = {'pageSize': page_size, 'after': after}
        assets, err = get_json(url, params=query, **http_options)

        if err:
            print('failed to retrieve assets:', err)
            return reported

        if len(assets) == page_size:
            # Build and stream this page before fetching the next so the full
            # device set is never held in memory at once.
            reported += report_assets(build_assets(assets))
            last_node = page_size - 1
            after = assets[last_node].get('id', '')
            if not after:
                print('failed to retrieve last node id')
                return reported
        elif len(assets) > 0 and len(assets) < page_size:
            reported += report_assets(build_assets(assets))
            hasNextPage = False
        else:
            hasNextPage = False

    return reported

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:
        id = item.get('id')
        if not id:
            print("ninjaone: skipping device with no id: systemName=" + str(item.get('systemName', '')))
            continue

        display_name = item.get('displayName', '')
        system_name = item.get('systemName', '')
        dns_name = item.get('')

        # parse network interfaces
        ips = []
        macs = []
        networks = []

        ips = item.get('ipAddresses', [])
        
        # check for assets with weird address blocks and rebuilt ips
        rebuilt_ips = []
        for ip in ips:
            if '|' in ip:
                rebuilt_ips.extend(ip.split('|'))
            elif ip == '':
                continue
            else:
                rebuilt_ips.append(ip)
        ips = rebuilt_ips

        # check for assets with no ip address
        if len(ips) == 0:
            ips.append('127.0.0.1')

        macs = item.get('macAddresses', [])    
        if macs:
            for m in macs:
                network = network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = network_interface(ips=ips, mac=None)
            networks.append(network)

        imported_assets.append(
            ImportAsset(
                id=str(id),
                hostnames=[
                    item.get('displayName', ''), 
                    item.get('systemName', ''),
                    item.get('dnsName', ''),
                    item.get('netbiosName', '')
                ],
                networkInterfaces=networks,
                os=item.get('os', {}).get('name', ''),
                manufacturer=item.get('system', {}).get('manufacturer', ''),
                customAttributes=to_custom_attributes({
                    'id':id,
                    'displayName':item.get('displayName'),
                    'systemName':item.get('systemName'),
                    'dnsName':item.get('dnsName'),
                    'netbiosName':item.get('netbiosName'),
                    'nodeClass':item.get('nodeClass'),
                    'nodeRoleId':item.get('nodeRoleId'),
                    'rolePolicyId':item.get('rolePolicyId'),
                    'policyId':item.get('policyId'),
                    'approvalStatus':item.get('approvalStatus'),
                    'offline':item.get('offline'),
                    'ipAddresses':item.get('ipAddresses'),
                    'macAddresses':item.get('macAddresses'),
                    'publicIP':item.get('publicIP'),
                    'osManufacturer':item.get('os', {}).get('manufacturer'),
                    'osName':item.get('os', {}).get('name'),
                    'osArchitecture':item.get('os', {}).get('architecture'),
                    'osBuildNumber':item.get('os', {}).get('buildNumber'),
                    'osReleaseId':item.get('os', {}).get('manufacturer'),
                    'osServicePackMajorVersion':item.get('os', {}).get('servicePackMajorVersion'),
                    'osServicePackMinorVersion':item.get('os', {}).get('servicePackMinorVersion'),
                    'osLanguage':item.get('os', {}).get('language'),
                    'osNeedsReboot':item.get('os', {}).get('needsReboot'),
                    'systemManufacturer':item.get('system', {}).get('manufacturer'),
                    'systemModel':item.get('system', {}).get('model'),
                    'systemBiosSerialNumber':item.get('system', {}).get('biosSerialNumber'),
                    'systemSerialNumber':item.get('system', {}).get('serialNumberr'),
                    'systemDomain':item.get('system', {}).get('domain'),
                    'systemDomainRole':item.get('system', {}).get('domainRole'),
                    'systemProcessors':item.get('system', {}).get('numberOfProcessors'),
                    'systemTotalPhysicalMemory':item.get('system', {}).get('totalPhysicalMemory'),
                    'systemVirtualMachine':item.get('system', {}).get('virtualMachine'),
                    'systemChassisType':item.get('system', {}).get('chassisType'),
                    'lastLoggedInUser':item.get('lastLoggedInUser'),
                    'deviceType':item.get('deviceType')
                }),
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    # kwargs!!
    api_url = get_string(kwargs, 'api_url').rstrip('/')
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']

    # get bearer token
    token = get_token(api_url, client_id, client_secret, kwargs)
    if not token:
        print('failed to retrieve bearer token')
        return None
    
    # get and stream assets page-by-page via report_assets
    reported = get_assets(api_url, token, kwargs)
    if not reported:
        print('no assets retrieved')
    
    return None
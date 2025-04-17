load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

NINJAONE_API_URL = 'https://us2.ninjarmm.com'

def get_token(client_id, client_secret):
    url = NINJAONE_API_URL + '/ws/oauth/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": "monitoring"}
    
    resp = http_post(url, headers=headers, body=bytes(url_encode(payload)))
    if resp.status_code != 200:
        print('authentication failed: ', resp.status_code)
        return None

    auth_data = json_decode(resp.body)
    if not auth_data:
        print('invalid authentication data')
        return None

    return auth_data.get('access_token')

def get_assets(token):
    hasNextPage = True
    after = ''
    page_size = 500
    assets = []
    assets_all = []

    url = NINJAONE_API_URL + "/v2/devices-detailed"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}

    while hasNextPage:
        query = {'pageSize': page_size, 'after': after}
        response = http_get(url, headers=headers, params=query)

        if response.status_code != 200:
            print('failed to retrieve assets', response.status_code)
            return None

        assets = json_decode(response.body)

        if len(assets) == page_size:
            assets_all.extend(assets)
            last_node = page_size - 1
            after = assets[last_node].get('id', '')
            if not after:
                print('failed to retrieve last node id')
                return None
        elif len(assets) > 0 and len(assets) < page_size:
            assets_all.extend(assets)
            hasNextPage = False
        else:
            hasNextPage = False

    return assets_all

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:
        id = item.get('id', new_uuid)

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
                network = build_network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = build_network_interface(ips=ips, mac=None)
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
                customAttributes={
                    'id':id,
                    'displayName':item.get('displayName', ''), 
                    'systemName':item.get('systemName', ''),
                    'dnsName':item.get('dnsName', ''),
                    'netbiosName':item.get('netbiosName', ''),
                    'nodeClass':item.get('nodeClass', ''),
                    'nodeRoleId':item.get('nodeRoleId', ''),
                    'rolePolicyId':item.get('rolePolicyId', ''),
                    'policyId':item.get('policyId', ''),
                    'approvalStatus':item.get('approvalStatus', ''),
                    'offline':item.get('offline', ''),
                    'ipAddresses':item.get('ipAddresses', ''),
                    'macAddresses':item.get('macAddresses', ''),
                    'publicIP':item.get('publicIP', ''),
                    'osManufacturer':item.get('os', {}).get('manufacturer', ''),
                    'osName':item.get('os', {}).get('name', ''),
                    'osArchitecture':item.get('os', {}).get('architecture', ''),
                    'osBuildNumber':item.get('os', {}).get('buildNumber', ''),
                    'osReleaseId':item.get('os', {}).get('manufacturer', ''),
                    'osServicePackMajorVersion':item.get('os', {}).get('servicePackMajorVersion', ''),
                    'osServicePackMinorVersion':item.get('os', {}).get('servicePackMinorVersion', ''),
                    'osLanguage':item.get('os', {}).get('language', ''),
                    'osNeedsReboot':item.get('os', {}).get('needsReboot', ''),
                    'systemManufacturer':item.get('system', {}).get('manufacturer', ''),
                    'systemModel':item.get('system', {}).get('model', ''),
                    'systemBiosSerialNumber':item.get('system', {}).get('biosSerialNumber', ''),
                    'systemSerialNumber':item.get('system', {}).get('serialNumberr', ''),                    
                    'systemDomain':item.get('system', {}).get('domain', ''),
                    'systemDomainRole':item.get('system', {}).get('domainRole', ''),
                    'systemProcessors':item.get('system', {}).get('numberOfProcessors', ''),
                    'systemTotalPhysicalMemory':item.get('system', {}).get('totalPhysicalMemory', ''),
                    'systemVirtualMachine':item.get('system', {}).get('virtualMachine', ''),
                    'systemChassisType':item.get('system', {}).get('chassisType', ''),
                    'lastLoggedInUser':item.get('lastLoggedInUser', ''),
                    'deviceType':item.get('deviceType', '')
                }
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
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
    
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    # kwargs!!
    client_id = kwargs['access_key']
    client_secret = kwargs['access_secret']

    # get bearer token
    token = get_token(client_id, client_secret)
    if not token:
        print('failed to retrieve bearer token')
        return None
    
    # get assets
    assets = get_assets(token)
    if not assets:
        print('failed to retrieve assets')
        return None
    
    # build asset import
    imported_assets = build_assets(assets)
    
    return imported_assets
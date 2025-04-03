load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

NETSKOPE_API_URL = 'https://<your-netskope-account>.goskope.com/api'

def get_assets(token):
    hasNextPage = True
    page_offset = 0
    page_limit = 500
    assets = []
    assets_all = []

    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}

    while hasNextPage:
        query = '?offset={}&limit={}'.format(page_offset, page_limit)
        url = NETSKOPE_API_URL + '/v2/events/datasearch/clientstatus' + query

        response = http_get(url, headers=headers)

        if response.status_code != 200:
            print('failed to retrieve assets', response.status_code)
            return None

        assets = json_decode(response.body)['result']

        if len(assets) == page_limit:
            assets_all.extend(assets)
            page_offset = page_offset + page_limit
        elif len(assets) > 0 and len(assets) < page_limit:
            assets_all.extend(assets)
            hasNextPage = False
        else:
            print('something weird happened')
            hasNextPage = False

    return assets_all

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:

        # parse network interfaces
        ips = []
        macs = []
        networks = []
               
        ips.append(item.get('last_connected_from_private_ip', '127.0.0.1'))

        macs = item.get('host_info', {}).get('mac_addresses', [])    
        if macs:
            for m in macs:
                network = build_network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = build_network_interface(ips=ips, mac=None)
            networks.append(network)
                
        imported_assets.append(
            ImportAsset(
                id=item.get('_id', new_uuid),
                hostnames=[
                    item.get('host_info', {}).get('hostname', ''), 
                ],
                networkInterfaces=[networks],
                os=item.get('host_info', {}).get('os', ''),
                osVersion=item.get('host_info', {}).get('os_version', ''),
                manufacturer=item.get('host_info', {}).get('device_make', ''),
                model=item.get('host_info', {}).get('device_model', ''),
                #last_seen_ts=item.get('host_info, {}').get('last_update_timestamp', 0),
                customAttributes={
                    'clientInstallTime':item.get('client_install_time', 0),
                    'clientVersion':item.get('client_version', ''),
                    'deviceHash':item.get('device_hash', ''),
                    'deviceId':item.get('device_id', ''),
                    'guid':item.get('guid', ''),
                    'serialNumber':item.get('host_info', {}).get('serial_number', ''),
                    'serviceIdentifier':item.get('_service_identifier', ''),
                    'steeringConfig':item.get('host_info', {}).get(''),
                    'userInfoDeviceClassificationStatus':item.get('user_info', {}).get('device_classification_status', ''),
                    'userInfoOrgKey':item.get('user_info', {}).get('orgkey', ''),
                    'userInfoUserKey':item.get('user_info', {}).get('userkey', ''),
                    'userName':item.get('username', ''),
                    'userGroup':item.get('usergroup', [])
                }
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
def build_network_interface(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        print(ip)
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
    token = kwargs['access_secret']
    
    # get assets
    assets = get_assets(token)
    if not assets:
        print('failed to retrieve assets')
        return None
    
    # build asset import
    imported_assets = build_assets(assets)
    
    return imported_assets
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

NETSKOPE_API_URL = 'https://<your-netskope-account>.goskope.com/api'
NETSKOPE_API_GROUPBYS = 'nsdeviceuid'
NETSKOPE_API_ATTRIBUTES = [
    'deleted',
    'device_classification_status',
    'device_id',
    'device_make',
    'device_model',
    'groups',
    'hostname',
    'mac_addresses',
    'nsdeviceuid',
    'ns_tenant_id',
    'organization_unit',
    'os',
    'os_version',
    'serial_number',
    'steering_config',
    'timestamp',
    'ur_normalized',
    'user',
    'userkey',
    'usergroup',
    'user_added_time',
    'user_status'
]

def get_assets(token):
    hasNextPage = True
    page_offset = 0
    page_limit = 20000
    assets = []
    assets_all = []

    fields = ','.join(NETSKOPE_API_ATTRIBUTES)
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}

    while hasNextPage:
        query = '?groupbys={}&fields={}&offset={}&limit={}'.format(NETSKOPE_API_GROUPBYS, fields, page_offset, page_limit)
        url = NETSKOPE_API_URL + '/v2/events/datasearch/clientstatus' + query

        response = http_get(url, headers=headers, timeout=300)

        if response.status_code != 200:
            print('failed to retrieve assets', response.status_code)
            return None

        assets = json_decode(response.body)['result']
        print(assets)

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

        # parse operating system
        os_name = item.get('os', '')
        os_version = item.get('os_version', '')

        if 'Mac' in os_name:
            os = 'macOS'
        else:
            os = os_name

        # parse network interfaces
        ips = ["127.0.0.1"]
        macs = []
        networks = []
               
        macs = item.get('mac_addresses', [])       
        if macs:
            for m in macs:
                network = build_network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = build_network_interface(ips=ips, mac=None)
            networks.append(network)

        imported_assets.append(
            ImportAsset(
                id=item.get('_id', {}).get('nsdeviceuid', new_uuid),
                hostnames=[item.get('hostname', '')],
                networkInterfaces=networks,
                os=os,
                #os_version=os_version,
                manufacturer=item.get('device_make', ''),
                model=item.get('device_model', ''),
                customAttributes={
                    'clientVersion':item.get('client_version', ''),
                    'deviceId':item.get('device_id', ''),
                    'deleted':item.get('deleted', ''),
                    'groups':item.get('groups', []),
                    'nsdeviceuid':item.get('_id', {}).get('nsdeviceuid', ''),
                    'ns_tenant_id':item.get('ns_tenant_id', ''),
                    'osName':item.get('os', ''),
                    'osVersion':item.get('os_version', ''),
                    'serialNumber':item.get('serial_number', ''),
                    'steeringConfig':item.get('steering_config', ''),
                    'netskopeTS':item.get('timestamp', ''),
                    'userInfoDeviceClassificationStatus':item.get('device_classification_status', ''),
                    'userInfoUserKey':item.get('userkey', ''),
                    'userName':item.get('username', ''),
                    'userNormalized':item.get('ur_normalized', ''),
                    'userSource':item.get('user_source', ''),
                    'userStatus':item.get('user_status', ''),
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
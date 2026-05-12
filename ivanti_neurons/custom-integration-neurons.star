load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get', http_post='post', 'url_encode')
load('uuid', 'new_uuid')

#Change the URL to match your Ivanti Neurons app registration
NEURONS_AUTH_URL = 'https://<ivanti neurons URL>'
NEURONS_TENANT_ID = '<tanant ID from URL>'
RUNZERO_REDIRECT = 'https://console.runzero.com/'

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
        interfaces = build_network_interface(ips=address_list, mac=None)

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
    url = NEURONS_AUTH_URL + '/api/apigatewaydataservices/v1/devices'
    headers = {'Accept': 'application/json',
                'Authorization': 'Bearer ' + token}
    total_assets = 1000
    while len(assets_all) < (total_assets - 1):
        response = http_get(url, headers=headers)
        if response.status_code != 200:
            print('failed to retrieve devices from ' + url, 'status code: ' + str(response.status_code))
            break
        else:
            data = json_decode(response.body)
            assets = data['value']
            assets_all.extend(assets)
            total_assets = data.get('@odata.count')
            url = data.get('@odata.nextLink')   

    return assets_all

def get_token(client_id, client_secret):
    url = NEURONS_AUTH_URL + '/api/apigatewaydataservices/v1/token'
    headers = {'Content-Type': 'application/json',
               'X-ClientSecret': client_secret,
               'X-TenantId': NEURONS_TENANT_ID,
               'X-ClientId': client_id}
    response = http_get(url, headers=headers)
    if response.status_code != 200:
        print('authentication failed: ' + str(response.status_code))
        return None
    auth_data = response.body
    if not auth_data:
        print('invalid authentication data')
        return None

    return auth_data

def main(*args, **kwargs):
    client_id = kwargs['access_key']
    client_secret = kwargs['access_secret']
    token = get_token(client_id, client_secret)
    assets = get_assets(token)
    
    # Format asset list for import into runZero
    import_assets = build_assets(assets)
    if not import_assets:
        print('no assets')
        return None

    return import_assets
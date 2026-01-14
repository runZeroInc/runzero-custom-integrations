load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('base64', base64_encode='encode', base64_decode='decode')
load('http', http_get='get', http_post='post', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('uuid', 'new_uuid')

SWIS_BASE_URL = 'https://localhost:17774'
RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets):
    assets_import = []
    for asset in assets:
        asset_id = str(asset.get('NodeId', str(new_uuid)))
        hostname = asset.get('Fqdn', '')
        os = asset.get('OsVersion', '')
        vendor = asset.get('Vendor', '')

        # create the network interfaces
        interfaces = []
        addresses = asset.get('IpAddress', [])
        interface = build_network_interface(ips=[addresses], mac=None)
        interfaces.append(interface)

        # Retrieve and map custom attributes
        cpu_util = str(asset.get('CpuPercentUtilization', ''))
        discovery_profile_id = str(asset.get('DiscoveryProfileId', ''))
        mem_util_perc = str(asset.get('PercentMemoryUsed', ''))
        mem_util = str(asset.get('MemoryUsed', ''))
        pollers = asset.get('Pollers', '')
        response_time = str(asset.get('ResponseTime', ''))
        snmp_port = str(asset.get('SnmpPort', ''))
        snmp_version = str(asset.get('SnmpVersion', ''))
        status = asset.get('Status', '')
        sys_object_id = asset.get('SysObjectId', '')
        uptime = str(asset.get('Uptime', ''))

        custom_attributes = {
            'percentCpuUtilization': cpu_util,
            'discoveryProfileId': discovery_profile_id,
            'percentMemoryUtilization': mem_util_perc,
            'memoryUtilized': mem_util,
            'pollers': pollers,
            'responseTime': response_time,
            'snmp.port': snmp_port,
            'snmp.version': snmp_version,
            'status': status,
            'sysObjectId': sys_object_id,
            'uptime': uptime
        }

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                os=os,
                manufacturer=vendor,
                networkInterfaces=interfaces,
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

def get_assets(creds):

    url = SWIS_BASE_URL + 'SolarWinds/InformationService/v3/Json/Query?'
    headers = {'Accept': 'application/json',
                'Authorization': 'Basic ' + creds}
    # Populate the SWQL query to return desired assets and attributes in the params query value e.g. 
    # params = {'query': 'SELECT N.NodeID, N.OsVersion, N.Fqdn, N.Vendor, N.IPAddress, N.CpuPercentUtilization, N.DiscoveryProfileId, N.PercentMemoryUsed, N.MemoryUsed, N.Pollers, N.responseTime, N.snmp.port, N.snmp.version, N.status, N.sysObjectId, N.Uptime FROM Orion.Nodes'}
    params = {'query': ''}
    response = http_get(url, headers=headers, params=params)
    if response.status_code != 200:
        print('failed to retrieve assets',  'status code: ' + str(response.status_code))
    data = json_decode(response.body)
    assets_all.extend(data)           

    return assets_all

def main(*args, **kwargs):
    username = kwargs['access_key']
    password = kwargs['access_secret']
    b64_creds = base64_encode(username + ":" + password)
    assets = get_assets(b64_creds)
    
    # Format asset list for import into runZero
    import_assets = build_assets(assets)
    if not import_assets:
        print('no assets')
        return None

    return import_assets
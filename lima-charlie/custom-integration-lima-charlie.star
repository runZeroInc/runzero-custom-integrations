load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

LIMACHARLIE_JWT_URL = 'https://jwt.limacharlie.io'
LIMACHARLIE_BASE_URL = 'https://api.limacharlie.io/v1'

# Exclusion list for sensors that you want to ignore by hostname.
SENSORS_TO_IGNORE = [
    # sensor_hostname_01,
    # sensor_hostname_02,
    # sensor_hostname_03
]

# List of attributes that are not pulled into runZero. 
# Note: sid, hostname, mac_addr, int_ip and ext_ip are imported as core asset attributes so 
# they are ignored for the purpose of custom LimaCharlie attributes.
CUSTOM_ATTRIBS_TO_IGNORE = [
    'sid',
    'hostname',
    'mac_addr',
    'int_ip',
    'ext_ip'
]

# Filter based on what architectures you want to import into runZero
# By default, Chromium browsed based extensions are excluded from import
ARCHITECTURE = {
    1: True,   # x86
    2: True,   # x64
    3: True,   # arm
    4: True,   # arm64
    5: True,   # alpine64
    6: False,  # chromium
    7: True,   # wireguard
    8: True,   # arml
    9: False,  # usp_adapter
}

def get_token(oid, token):
    url = '{}/?oid={}'.format(LIMACHARLIE_JWT_URL, oid)
    headers = {
        'Content-Type': 'application/json',
        'X-LC-Secret': token
    }

    response = http_post(url, headers=headers)
    if response.status_code != 200:
        print('Failed to fetch token. ', response)
        return None
    else:
        response_json = json_decode(response.body)
        return response_json['jwt']

def build_assets(sensors):
    assets = []
    for item in sensors:
        sid = item.get('sid')        
        hostname = item.get('hostname', '')
        arch_id = item.get('arch', '')

        if hostname in SENSORS_TO_IGNORE:
            print('Skipping sensor because it has been explicitly ignored in custom integration script:', sid, hostname)
        elif not ARCHITECTURE.get(arch_id):
            print('Skipping sensor because sensor architecture', arch_id, 'has been set to False in custom integration script:', sid, hostname)
        else:
            # Parse IPs and mac addresses and build network interfaces      
            ips = []
            int_ip = item.get('int_ip', '')
            if int_ip:
                ips.append(int_ip)
            ext_ip = item.get('ext_ip', '')
            if ext_ip:
                ips.append(ext_ip)

            mac = item.get('mac_addr', '')
            if mac:
                mac = mac.replace("-", ":")
                network = build_network_interface(ips=ips, mac=mac)
            else:
                network = build_network_interface(ips=ips, mac=None)

            # Parse additional attributes collected from sensors, ignore attributes defined in ATTRIBS_TO_IGNORE
            custom_attrs = {}
            for key, value in item.items():
                if type(value) != 'dict':
                    if key not in CUSTOM_ATTRIBS_TO_IGNORE:
                        custom_attrs[key] = str(value)[:1023]

            assets.append(
                ImportAsset(
                    id=sid,
                    hostnames=[hostname],
                    networkInterfaces=[network],
                    customAttributes=custom_attrs
                )
            )

    return assets

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
    oid = kwargs['access_key']
    access_token = kwargs['access_secret']
    token = get_token(oid, access_token)
        
    # Get sensors
    url = '{}/{}/{}'.format(LIMACHARLIE_BASE_URL, 'sensors', oid)
    sensors = http_get(url, headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    if sensors.status_code != 200:
        print('Failed to fetch sensors. ', sensors)
        return None

    sensors_json = json_decode(sensors.body)['sensors']

    assets = build_assets(sensors_json)
    if not assets:
        print('No sensors were retrieved.')
    
    return assets
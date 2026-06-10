# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-limacharlie",
    "name": "LimaCharlie",
    "type": "inbound",
    "description": "Imports endpoints from LimaCharlie.",
    "version": "26052700",
    "params": [
        {
            "key": "organization_id",
            "label": "Organization ID (OID)",
            "type": "string",
            "required": True,
        },
        {
            "key": "api_token",
            "label": "API access token",
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
load('http', 'get_json', 'post_json', 'bearer')
load('kwargs', 'get_http_options')
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

def get_token(oid, token, config_kwargs):
    url = '{}/?oid={}'.format(LIMACHARLIE_JWT_URL, oid)
    headers = {
        'Content-Type': 'application/json',
        'X-LC-Secret': token
    }

    response_json, err = post_json(url, **get_http_options(config_kwargs, headers=headers))
    if err:
        print('Failed to fetch token:', err)
        return None
    return (response_json or {}).get('jwt')

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
                network = network_interface(ips=ips, mac=mac)
            else:
                network = network_interface(ips=ips, mac=None)

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
                    customAttributes=to_custom_attributes(custom_attrs),
                )
            )

    return assets

def main(**kwargs):
    oid = kwargs['organization_id']
    access_token = kwargs['api_token']
    token = get_token(oid, access_token, kwargs)
        
    # Get sensors
    url = '{}/{}/{}'.format(LIMACHARLIE_BASE_URL, 'sensors', oid)
    data, err = get_json(url, **get_http_options(kwargs, headers={"Authorization": bearer(token)}))
    if err:
        print('Failed to fetch sensors:', err)
        return None

    sensors_json = (data or {}).get('sensors', [])

    assets = build_assets(sensors_json)
    if not assets:
        print('No sensors were retrieved.')
    
    return assets
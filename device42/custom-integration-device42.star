load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')
load('uuid', 'new_uuid')

DEVICE42_HOST     = 'swaggerdemo.device42.com'
DEVICE42_ENDPOINT = '/api/1.0/devices/all/'
PAGE_SIZE         = 1000

def build_network_interface(ips, mac):
    ip4s, ip6s = [], []
    for ip in ips:
        addr = ip_address(ip)
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)
    return NetworkInterface(
        macAddress=mac,
        ipv4Addresses=ip4s,
        ipv6Addresses=ip6s,
    )

def build_network_interfaces(mac_entries, ip_entries):
    interfaces = []
    seen_macs = {}
    for ip_obj in ip_entries:
        ip_str = ip_obj.get('ip')
        if not ip_str:
            continue
        macaddr = ip_obj.get('macaddress') or ip_obj.get('mac_address')
        seen_macs[macaddr] = seen_macs.get(macaddr, [])
        seen_macs[macaddr].append(ip_str)
        interfaces.append(build_network_interface([ip_str], macaddr))

    for m in mac_entries:
        mac_addr = m.get('mac') or m.get('mac_address')
        if mac_addr not in seen_macs:
            interfaces.append(build_network_interface([], mac_addr))

    return interfaces

def build_assets(devices):
    assets = []
    for d in devices:
        asset_id = str(d.get('id') or d.get('uuid') or new_uuid())

        hostnames = []
        for key in ('name', 'preferred_alias', 'virtual_host_name'):
            val = d.get(key)
            if val and val not in hostnames:
                hostnames.append(val)

        mac_entries = d.get('macAddresses', []) + d.get('mac_addresses', [])
        ip_entries  = d.get('ipAddresses', [])  + d.get('ip_addresses', [])
        network_ifaces = build_network_interfaces(mac_entries, ip_entries)

        asset_os = d.get('os')
        asset_os_version = d.get('osver') or d.get('osverno')
        asset_model = d.get('hw_model')
        asset_manufacturer = d.get('manufacturer')
        asset_device_type = d.get('type') or d.get('device_sub_type') or d.get('virtual_subtype')

        asset_tags = []
        raw_tags = d.get('tags') or []
        if type(raw_tags) == list:
            for t in raw_tags:
                asset_tags.append(str(t))

        exclude_keys = [
            'id', 'uuid', 'device_id', 'macAddresses', 'mac_addresses',
            'ipAddresses', 'ip_addresses', 'name', 'preferred_alias',
            'virtual_host_name', 'os', 'osver', 'osverno', 'hw_model',
            'manufacturer', 'type', 'device_sub_type', 'virtual_subtype',
            'tags',
        ]

        custom = {}
        for k, v in d.items():
            if k in exclude_keys:
                continue
            custom[k] = str(v)[:1023]

        assets.append(
            ImportAsset(
                id=asset_id,
                hostnames=hostnames,
                os=asset_os,
                osVersion=asset_os_version,
                model=asset_model,
                manufacturer=asset_manufacturer,
                deviceType=asset_device_type,
                tags=asset_tags,
                networkInterfaces=network_ifaces,
                customAttributes=custom,
            )
        )
    return assets

def main(**kwargs):
    auth_type = kwargs['access_key'].lower()
    secret = kwargs['access_secret']
    
    if auth_type == 'basic':
        headers = {
            'Authorization': 'Basic ' + secret,
            'Accept': 'application/json',
        }
    elif auth_type == 'bearer':
        headers = {
            'Authorization': 'Bearer ' + secret,
            'Accept': 'application/json',
        }
    else:
        print('Unsupported access_key (must be "basic" or "bearer")')
        return None

    offset = 0
    all_devices = []
    while True:
        url = 'https://{}{}?format=json&limit={}&offset={}'.format(
            DEVICE42_HOST, DEVICE42_ENDPOINT, PAGE_SIZE, offset
        )
        resp = http_get(url, headers=headers)

        if resp.status_code != 200:
            print('Device42 API error:', resp.status_code, resp.body)
            return None

        body = json_decode(resp.body)
        if body.get('code', 0) != 0:
            print('Device42 API logical error:', body.get('msg'))
            return None

        page = body.get('Devices', [])
        if not page:
            break

        all_devices.extend(page)
        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    if not all_devices:
        print('No devices returned')
        return None

    return build_assets(all_devices)


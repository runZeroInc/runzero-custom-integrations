# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-device42",
    "name": "Device42",
    "type": "inbound",
    "description": "Imports configuration items from Device42.",
    "version": "26061000",
    "params": [
        {
            "key": "auth_scheme",
            "label": "Auth scheme",
            "type": "enum",
            "required": True,
            "options": ["basic", "bearer"],
            "default": "basic",
        },
        {
            "key": "credential",
            "label": "Credential",
            "type": "secret",
            "required": True,
            "description": "Base64 user:pass for basic, or bearer token",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json')
load('kwargs', 'get_http_options')
load('uuid', 'new_uuid')

DEVICE42_HOST     = 'swaggerdemo.device42.com'
DEVICE42_ENDPOINT = '/api/1.0/devices/all/'
PAGE_SIZE         = 1000

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
        interfaces.append(network_interface(ips=[ip_str], mac=macaddr))

    for m in mac_entries:
        mac_addr = m.get('mac') or m.get('mac_address')
        if mac_addr not in seen_macs:
            interfaces.append(network_interface(ips=[], mac=mac_addr))

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
                customAttributes=to_custom_attributes(custom),
            )
        )
    return assets

def main(**kwargs):
    auth_type = kwargs['auth_scheme'].lower()
    secret = kwargs['credential']
    
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
        print('Unsupported auth_scheme (must be "basic" or "bearer")')
        return None
    http_options = get_http_options(kwargs, headers=headers)

    offset = 0
    total = 0
    while True:
        url = 'https://{}{}?format=json&limit={}&offset={}'.format(
            DEVICE42_HOST, DEVICE42_ENDPOINT, PAGE_SIZE, offset
        )
        body, err = get_json(url, **http_options)

        if err:
            print('Device42 API error:', err)
            return None
        if body.get('code', 0) != 0:
            print('Device42 API logical error:', body.get('msg'))
            return None

        page = body.get('Devices', [])
        if not page:
            break

        # Build and stream this page's assets, then let it be reclaimed before
        # fetching the next page so memory stays bounded by a single page.
        report_assets(build_assets(page))
        total += len(page)

        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    if total == 0:
        print('No devices returned')

    return None


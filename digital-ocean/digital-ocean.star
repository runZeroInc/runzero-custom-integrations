# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-digital-ocean",
    "name": "Digital Ocean",
    "type": "inbound",
    "description": "Imports droplets from DigitalOcean.",
    "version": "26052700",
    "params": [
        {
            "key": "api_token",
            "label": "API token",
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
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('uuid', 'new_uuid')

DIGITAL_OCEAN_API_URL = 'https://api.digitalocean.com/v2/'

def collect_ips(networks):
    """Pull the v4 and v6 addresses out of a DigitalOcean `networks` block."""
    ips = []
    if not networks:
        return ips
    for v in networks.get('v4', []) or []:
        ip = v.get('ip_address', '')
        if ip:
            ips.append(ip)
    for v in networks.get('v6', []) or []:
        ip = v.get('ip_address', '')
        if ip:
            ips.append(ip)
    return ips

def format_tags(tags):
    """Convert DigitalOcean `key:value` tags to runZero `key=value` tags."""
    out = []
    for t in tags or []:
        if ':' in t:
            k, v = t.split(':', 1)
            out.append(k + '=' + v)
        else:
            out.append(t)
    return out

def build_assets(assets_json):
    assets = []
    for item in assets_json:
        nic = network_interface(ips=collect_ips(item.get('networks', {})))
        nics = [nic] if nic else []

        image = item.get('image', {}) or {}
        region = item.get('region', {}) or {}

        assets.append(ImportAsset(
            id=str(item.get('id') or new_uuid()),
            hostnames=[item.get('name', '')],
            networkInterfaces=nics,
            os=image.get('distribution', ''),
            tags=format_tags(item.get('tags')),
            customAttributes=to_custom_attributes({
                "id": item.get('id'),
                "size_slug": item.get('size_slug'),
                "memory": item.get('memory'),
                "vcpus": item.get('vcpus'),
                "disk": item.get('disk'),
                "locked": item.get('locked'),
                "status": item.get('status'),
                "created_at": item.get('created_at'),
                "vpcUUID": item.get('vpc_uuid'),
                "image.id": image.get('id'),
                "image.name": image.get('name'),
                "image.distribution": image.get('distribution'),
                "image.type": image.get('type'),
                "image.public": image.get('public'),
                "image.status": image.get('status'),
                "region.name": region.get('name'),
                "region.available": region.get('available'),
            }),
        ))
    return assets

def main(**kwargs):
    token = kwargs['api_token']
    headers = {"Authorization": bearer(token)}
    http_options = get_http_options(kwargs, headers=headers)

    data, err = get_json(DIGITAL_OCEAN_API_URL + 'droplets', **http_options)
    if err:
        print('failed to retrieve droplets:', err)
        return None

    droplets = (data or {}).get('droplets', [])
    # Stream assets to runZero via report_assets instead of returning a list.
    if not report_assets(build_assets(droplets)):
        print('no assets')
    return None

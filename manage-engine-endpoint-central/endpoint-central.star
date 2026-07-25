# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-manageengine-endpoint-central",
    "name": "ManageEngine Endpoint Central",
    "type": "inbound",
    "description": "Imports endpoints from ManageEngine Endpoint Central.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Endpoint Central URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ec.example.com",
        },
        {
            "key": "oauth_token",
            "label": "OAuth token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'to_custom_attributes')
load('net', 'ip_address')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options')

API_VERSION     = '1.4'
SCAN_ENDPOINT   = '/api/' + API_VERSION + '/inventory/scancomputers'
PAGE_LIMIT      = 1000

def build_network_interfaces(device):
    ip_field = device.get('ip_address') or ''
    mac       = device.get('mac_address')
    # support comma-separated IPs if ever present
    ips = [p.strip() for p in ip_field.split(',') if p.strip()]
    ipv4s = []
    ipv6s = []
    for ip in ips:
        addr = ip_address(ip)
        if addr:
            if addr.version == 4:
                ipv4s.append(addr)
            else:
                ipv6s.append(addr)
    return [ NetworkInterface(macAddress=mac,
                              ipv4Addresses=ipv4s,
                              ipv6Addresses=ipv6s) ]

def build_assets(devices):
    assets = []
    for d in devices:
        raw_id = d.get('resource_id') or d.get('id')
        if not raw_id:
            print("endpoint-central: skipping device with no resource_id/id: name=" + str(d.get('resource_name', '')))
            continue
        asset_id = str(raw_id)
        hostname = d.get('resource_name') or d.get('resource_name', '') or ''
        # build networkInterfaces
        net_ifaces = build_network_interfaces(d)

        # everything else goes into customAttributes (truncate to 1023 chars)
        custom = {}
        for k, v in d.items():
            if k in ('resource_id','id','resource_name','ip_address','mac_address'):
                continue
            custom[k] = str(v)[:1023]

        assets.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                networkInterfaces=net_ifaces,
                customAttributes=to_custom_attributes(custom),
            )
        )
    return assets

def main(**kwargs):
    # oauth_token is your auth token.
    base_url = get_url_base(kwargs)
    token = kwargs['oauth_token']
    headers = {
        'Authorization': token,
        'Accept':        'application/json',
    }
    http_options = get_http_options(kwargs, headers=headers)

    page        = 1
    reported    = 0
    while True:
        url = base_url + SCAN_ENDPOINT
        params = {"pagelimit": PAGE_LIMIT, "page": page}
        body, err = get_json(url, params=params, timeout=3600, **http_options)
        if err:
            print('Scan API error:', err)
            return None

        body    = body or {}
        msg     = body.get('message_response', {})
        devices = msg.get('scancomputers', [])
        if not devices:
            break

        # Build and stream each page via report_assets so the full device set
        # is never held in memory.
        reported += report_assets(build_assets(devices))
        if len(devices) < PAGE_LIMIT:
            break
        page += 1

    if not reported:
        print('No devices returned')

    return None
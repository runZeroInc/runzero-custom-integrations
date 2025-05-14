load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')
load('uuid', 'new_uuid')

EC_HOST         = '<UPDATE_ME>'
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
        asset_id = str(d.get('resource_id', d.get('id', new_uuid())))
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
                hostnames=[hostname] if hostname else [],
                networkInterfaces=net_ifaces,
                customAttributes=custom,
            )
        )
    return assets

def main(**kwargs):
    # access_secret is your auth_token
    token = kwargs['access_secret']
    headers = {
        'Authorization': token,
        'Accept':        'application/json',
    }

    page        = 1
    all_devices = []
    while True:
        url = 'https://' + EC_HOST + SCAN_ENDPOINT
        params = {"pagelimit": PAGE_LIMIT, "page": page}
        resp = http_get(url, headers=headers, params=params, timeout=3600)
        if resp.status_code != 200:
            print('Scan API error:', resp.status_code, resp.body)
            return None

        body    = json_decode(resp.body)
        msg     = body.get('message_response', {})
        devices = msg.get('scancomputers', [])
        if not devices:
            break

        all_devices.extend(devices)
        if len(devices) < PAGE_LIMIT:
            break
        page += 1

    if not all_devices:
        print('No devices returned')
        return None

    return build_assets(all_devices)
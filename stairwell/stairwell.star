# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-stairwell",
    "name": "Stairwell",
    "type": "inbound",
    "description": "Imports environment data from Stairwell.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "environment_id",
            "label": "Environment ID",
            "type": "string",
            "required": True,
        },
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
load('http', 'get_json')
load('kwargs', 'get_http_options')

STAIRWELL_API_URL = 'https://app.stairwell.com'

def stream_assets(env, token, config_kwargs):
    """Paginate Stairwell assets, building and streaming each page via
    report_assets so the full asset set is never held in memory. Returns the
    number of assets reported."""
    hasNextPage = True
    page_size = 5
    reported = 0

    url = STAIRWELL_API_URL + "/v1/environments/" + env + "/assets"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)
    params = {'limit': page_size}

    while hasNextPage:
        assets, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve assets:', err)
            return reported

        reported += report_assets(build_assets(assets.get('assets', [])))

        next_token = assets.get('nextPageToken', '')
        if next_token:
            params = {'next_page_token': next_token, 'limit': page_size}
        else:
            hasNextPage = False

    return reported

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:

        # parse ip address
        ips = []
        ip = item.get('ipAddress', '')

        # check for no ip address
        if not ip:
            ip = '127.0.0.1'

        # strip interface from ipv6 address
        if '%' in ip:
            ip = ip.split('%')[0]

        ips.append(ip)

        # parse mac address
        macs = []
        mac = item.get('macAddress', '')

        if not mac or mac == '-':
            continue
        else:
            macs.append(mac)

        # create network interfaces
        networks = []
        if macs:
            for m in macs:
                network = network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = network_interface(ips=ips, mac=None)
            networks.append(network)

        # parse operating system
        os_raw = item.get('os', '')
        os_version_raw = item.get('osVersion', '')

        if 'macOS' in os_raw:
            os = 'macOS ' + os_version_raw
        elif 'Ubuntu' in os_raw:
            os = 'Ubuntu ' + os_version_raw
        elif 'Linux' in os_raw:
            os = 'Linux'
        else:
            os = os_raw

        # still need to sort out tag parsing and add logic to convert lastCheckinTime to epoch format

        imported_assets.append(
            ImportAsset(
                id=str(item.get('name', '').split('/')[1]),
                hostnames=[item.get('label', '')],
                networkInterfaces=networks,
                os=os,
                osVersion = item.get('osVersion', ''),
                customAttributes=to_custom_attributes({
                    'createTime':item.get('createTime'),
                    'lastCheckinTime':item.get('lastCheckinTime'),
                    'environment':item.get('environment'),
                    'forwarderVersion':item.get('forwarderVersion'),
                    'uploadToken':item.get('uploadToken'),
                    'backscanState':item.get('backscanState'),
                    'os.raw':os_raw,
                    'state':item.get('state')
                }),
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    # kwargs!!
    env = kwargs['environment_id']
    token = kwargs['api_token']

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(env, token, kwargs)
    if not reported:
        print('failed to retrieve assets')

    return None
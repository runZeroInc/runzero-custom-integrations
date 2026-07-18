# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-netskope",
    "name": "Netskope",
    "type": "inbound",
    "description": "Imports devices from Netskope.",
    "version": "26061000",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "url",
            "label": "Netskope tenant URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<tenant>.goskope.com",
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
load('kwargs', 'get_url_base', 'get_http_options')

NETSKOPE_API_GROUPBYS = 'nsdeviceuid'
NETSKOPE_API_ATTRIBUTES = [
    'deleted',
    'device_classification_status',
    'device_id',
    'device_make',
    'device_model',
    'groups',
    'hostname',
    'mac_addresses',
    'nsdeviceuid',
    'ns_tenant_id',
    'organization_unit',
    'os',
    'os_version',
    'serial_number',
    'steering_config',
    'timestamp',
    'ur_normalized',
    'user',
    'userkey',
    'usergroup',
    'user_added_time',
    'user_status'
]

def get_assets(base_url, token, config_kwargs):
    hasNextPage = True
    page_offset = 0
    page_limit = 20000
    assets = []
    reported = 0

    fields = ','.join(NETSKOPE_API_ATTRIBUTES)
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)

    while hasNextPage:
        query = '?groupbys={}&fields={}&offset={}&limit={}'.format(NETSKOPE_API_GROUPBYS, fields, page_offset, page_limit)
        url = base_url + '/api/v2/events/datasearch/clientstatus' + query

        response, err = get_json(url, timeout=300, **http_options)

        if err:
            print('failed to retrieve assets:', err)
            return reported

        assets = (response or {}).get('result', [])

        if len(assets) == page_limit:
            # Build and stream this page before fetching the next so the full
            # device set is never held in memory at once.
            reported += report_assets(build_assets(assets))
            page_offset = page_offset + page_limit
        elif len(assets) > 0 and len(assets) < page_limit:
            reported += report_assets(build_assets(assets))
            hasNextPage = False
        else:
            hasNextPage = False

    return reported

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:

        # parse operating system
        os_name = item.get('os', '')
        os_version = item.get('os_version', '')

        if 'Mac' in os_name:
            os = 'macOS'
        else:
            os = os_name

        # parse network interfaces
        ips = ["127.0.0.1"]
        macs = []
        networks = []
               
        macs = item.get('mac_addresses', [])       
        if macs:
            for m in macs:
                network = network_interface(ips=ips, mac=m)
                networks.append(network)
        else:
            network = network_interface(ips=ips, mac=None)
            networks.append(network)

        raw_id = item.get('_id', {}).get('nsdeviceuid') or item.get('device_id')
        if not raw_id:
            print("netskope: skipping record with no nsdeviceuid/device_id")
            continue

        imported_assets.append(
            ImportAsset(
                id=str(raw_id),
                hostnames=[item.get('hostname', '')],
                networkInterfaces=networks,
                os=os,
                #os_version=os_version,
                manufacturer=item.get('device_make', ''),
                model=item.get('device_model', ''),
                customAttributes=to_custom_attributes({
                    'clientVersion':item.get('client_version'),
                    'deviceId':item.get('device_id'),
                    'deleted':item.get('deleted'),
                    'groups':item.get('groups', []),
                    'nsdeviceuid':item.get('_id', {}).get('nsdeviceuid'),
                    'ns_tenant_id':item.get('ns_tenant_id'),
                    'osName':item.get('os'),
                    'osVersion':item.get('os_version'),
                    'serialNumber':item.get('serial_number'),
                    'steeringConfig':item.get('steering_config'),
                    'netskopeTS':item.get('timestamp'),
                    'userInfoDeviceClassificationStatus':item.get('device_classification_status'),
                    'userInfoUserKey':item.get('userkey'),
                    'userName':item.get('username'),
                    'userNormalized':item.get('ur_normalized'),
                    'userSource':item.get('user_source'),
                    'userStatus':item.get('user_status'),
                    'userGroup':item.get('usergroup', [])
                }),
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    # kwargs!!
    base_url = get_url_base(kwargs)
    token = kwargs['api_token']
    
    # get and stream assets page-by-page via report_assets
    reported = get_assets(base_url, token, kwargs)
    if not reported:
        print('no assets retrieved')
    
    return None
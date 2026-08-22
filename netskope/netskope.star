# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-netskope",
    "name": "Netskope",
    "type": "inbound",
    "description": "Imports devices from Netskope.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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

def device_type_for_os(os_name):
    """Return a runZero device type for a Netskope os value, or ''.

    Netskope's own os vocabulary separates a server from a desktop: the client
    data API documents the enum as 0 Windows, 1 Mac, 3 Android, 4 *Windows
    Server*, and the datasearch event carries the readable text rather than the
    number. That separation is the only statement of role anywhere in the
    clientstatus record, so it is the one thing worth handing runZero, which
    prefers its own hardware fingerprint and falls back to this only when the
    make and model -- routinely "VMware, Inc." / "VMware Virtual Platform" on
    exactly these hosts -- tell it nothing.

    Android and Mac are deliberately unmapped. Each covers two runZero types
    without distinguishing them (a phone or a tablet; a desktop or a laptop),
    and device_model is a better answer to that question than a coin flip.
    """
    if 'server' in os_name.lower():
        return 'Server'
    return ''

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
        # .get's default only applies when the key is ABSENT, not when it is
        # present with a null value. Netskope sends an explicit null for a
        # client it has not classified, and `'Mac' in None` aborts the script --
        # every healthy record in the same page was lost with it.
        os_name = item.get('os') or ''
        os_version = item.get('os_version') or ''

        if 'Mac' in os_name:
            os = 'macOS'
        else:
            os = os_name

        # parse network interfaces
        #
        # The clientstatus event carries MAC addresses and no IP at all, so a MAC
        # is the only thing an interface can be built from. There used to be a
        # hardcoded ips = ["127.0.0.1"] passed to every network_interface call
        # here. It was inert only because the platform's NormalizeAddress rejects
        # loopback before it reaches an asset -- verified: network_interface
        # returns NetworkInterface(ipv4_addresses=["127.0.0.1"], mac_address=...)
        # and the address is dropped one layer later. Correctness that depends on
        # a filter somewhere else is not correctness, so the literal is gone: an
        # asset with no address now has no interface.
        #
        # .get's default only applies when the key is ABSENT, so `or []` covers
        # the record that sends an explicit null, and network_interface returns
        # None when nothing usable survives -- a MAC the platform cannot read,
        # or no MAC at all. Appending that None would make ImportAsset abort the
        # whole run, so only a real interface is kept.
        networks = []
        for m in (item.get('mac_addresses') or []):
            network = network_interface(mac=m)
            if network:
                networks.append(network)

        # Same null-versus-absent trap: a record whose _id is present but null
        # would abort on .get, so the fallback is spelled `or {}` rather than
        # given as a .get default.
        raw_id = (item.get('_id') or {}).get('nsdeviceuid') or item.get('device_id')
        if not raw_id:
            print("netskope: skipping record with no nsdeviceuid/device_id")
            continue

        params = dict(
                id=str(raw_id),
                hostnames=[item.get('hostname') or ''],
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
                    'nsdeviceuid':(item.get('_id') or {}).get('nsdeviceuid'),
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

        # Omitted rather than set to '' when the os names no role: an empty
        # deviceType is still a value and displaces the type runZero would
        # otherwise derive for itself.
        device_type = device_type_for_os(os_name)
        if device_type:
            params['deviceType'] = device_type

        imported_assets.append(ImportAsset(**params))
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
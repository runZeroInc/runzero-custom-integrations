# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-ivanti-neurons",
    "name": "Ivanti Neurons",
    "type": "inbound",
    "description": "Imports devices from Ivanti Neurons.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Neurons serves the device scroll in pages of 500 and the walk is driven
    # entirely by @odata.nextLink. 500 pages x 500 rows = 250,000 devices, past
    # the endpoint count of the largest Neurons tenant. The repeated-link check
    # in the walk catches a stuck scroll first and says so precisely; this is
    # the backstop for a landscape that mints a NEW link every time while never
    # advancing, and reaching it raises so a truncated import is reported as an
    # error rather than looking complete.
    "maxPages": 500,
    "params": [
        {
            "key": "url",
            "label": "Ivanti Neurons URL",
            "type": "url",
            "required": True,
            "placeholder": "https://nvuprd-sfc.ivanticloud.com",
            "description": "The host part of the Neurons Auth Url shown during App Registration. Neurons has no per-tenant subdomain; it serves six fixed regional landscape hosts (nvuprd AMER, fruprd EU, ukuprd EMEA, mluprd APAC, tkuprd JPN, ttuprd CAN, each .ivanticloud.com). Always use the host from your own App Registration rather than assuming a region.",
        },
        {
            "key": "tenant_id",
            "label": "Tenant ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_id",
            "label": "OAuth client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "OAuth client secret",
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
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')

# Distributions that ship only as a server platform, matched against OS.Name.
# Ubuntu, Debian, Fedora, openSUSE and macOS are deliberately absent: each is as
# often a workstation as a server. So is SUSE Linux Enterprise *Desktop*, which
# is why the list carries sles and not a bare "suse" substring.
SERVER_OS_NAMES = [
    "red hat enterprise", "rhel", "centos", "rocky linux", "almalinux",
    "amazon linux", "oracle linux", "suse linux enterprise server", "sles",
]


def _device_type(os_name):
    """Return a runZero device type for one Neurons device, or "".

    The documented device object is DisplayName, DiscoveryId, DeviceName,
    Network.TCPIP, OS.Name, OS.Version and System.Model -- there is no chassis
    or asset-class field anywhere in it -- so the only genuine statement of role
    is an OS that says what it is. "Windows Server 2022" and the server-only
    distributions above are unambiguous.

    A bare "Windows 11 Pro", "Ubuntu" or "macOS" stays unset: it is a desktop or
    a laptop and the record cannot say which, and a wrong hint is worse than
    none.

    This is only a hint. runZero prefers what it derives from the hardware or
    from its own scan, and System.Model is reported alongside it -- but that
    model is routinely a hypervisor placeholder such as "VMware7,1", which
    fingerprints nothing, and that is exactly the gap this fills.
    """
    text = os_name.lower()
    if "server" in text:
        return "Server"
    for name in SERVER_OS_NAMES:
        if name in text:
            return "Server"
    return ""


def _dict_field(record, key):
    """Return a nested object field as a dict. A present-but-null or non-object
    value becomes {}, because .get defaults only apply when the key is ABSENT
    and calling .get on None aborts the whole run."""
    value = record.get(key)
    return value if type(value) == "dict" else {}


def build_assets(tenant_id, assets):
    assets_import = []
    # A device with neither id has nothing stable to key on. Counted rather
    # than logged per record, with one name kept for diagnosis, so a degraded
    # export cannot become one line per device.
    skipped = 0
    skipped_name = ""
    malformed = 0
    for asset in assets:
        # A non-object element in value[] has no fields to read at all.
        if type(asset) != "dict":
            malformed += 1
            continue
        raw_id = asset.get('DiscoveryId') or asset.get('DeviceID')
        if not raw_id:
            skipped += 1
            if skipped == 1:
                skipped_name = str(asset.get('DeviceName', ''))
            continue
        asset_id = str(raw_id)
        hostname = asset.get('DeviceName', '') or ''
        os_info = _dict_field(asset, 'OS')
        os_name = str(os_info.get('Name') or '')
        os_version = str(os_info.get('Version') or '')
        os = os_name + ' ' + os_version if os_version else os_name
        model = str(_dict_field(asset, 'System').get('Model') or '')

        # create the network interfaces
        #
        # _dict_field on both hops: a device carrying "Network": null (or a
        # non-object TCPIP) must degrade to no addresses, not abort the run.
        tcpip = _dict_field(_dict_field(asset, 'Network'), 'TCPIP')
        address_list = list(tcpip.values())

        # network_interface returns None when nothing usable survives, and
        # passing [None] to ImportAsset aborts the ENTIRE run -- losing every
        # device already parsed, not just this one -- so the interface is only
        # added when one was actually built. Such a device still correlates on
        # its hostname.
        nic = network_interface(ips=address_list, mac=None)
        interfaces = [nic] if nic else []

        #map additional custom attributes
        displayname = asset.get('DisplayName', '')
        device_id = asset.get('DeviceID', '')

        custom_attributes = {
                             'discoveryId': asset_id,
                             'deviceName': hostname,
                             'deviceId': device_id,
                             'displayName': displayname,
                             'os.name': os,
                             'os.version': os_version,
                             'system.model': model
                            }

        # Build assets for import. The foreign id is scoped by the tenant id so
        # two Neurons tenants imported into one runZero org cannot collide --
        # Neurons has no per-tenant subdomain, so the DiscoveryId alone carried
        # no tenant scope at all. The tenant id arrives through CONFIG, but it
        # is the immutable tenant key the gateway itself routes on (sent as
        # X-TenantId on the token call): changing it points the credential at a
        # different tenant outright, which SHOULD re-identify. The
        # DiscoveryId/DeviceID leaf is unchanged.
        asset_params = {
            'id': 'ivanti-neurons:{}:{}'.format(tenant_id, asset_id),
            'hostnames': [hostname],
            'os': os,
            'model': model,
            'networkInterfaces': interfaces,
            'customAttributes': to_custom_attributes(custom_attributes),
        }

        # Omitted rather than set to '' when the OS names no role: an empty
        # deviceType is still a value and displaces the type runZero would
        # otherwise derive for itself.
        device_type = _device_type(os_name)
        if device_type:
            asset_params['deviceType'] = device_type

        assets_import.append(ImportAsset(**asset_params))
    if skipped > 0:
        print("ivanti-neurons: skipped {} assets with no DiscoveryId/DeviceID (first name: {})".format(
            skipped, skipped_name))
    if malformed > 0:
        print("ivanti-neurons: skipped {} non-object records in the device list".format(malformed))
    return assets_import

def get_and_report_assets(base_url, tenant_id, token, config_kwargs):
    """Walk the device scroll and stream each page to runZero as it arrives, so
    memory stays bounded by one page and an interrupted walk keeps everything
    already reported. Returns the count reported."""
    reported = 0
    collected = 0
    url = base_url + '/api/apigatewaydataservices/v1/devices'
    headers = {'Accept': 'application/json',
                'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)
    total_assets = None
    seen_links = {}

    # Ivanti documents the scroll as "keep calling the next link until you
    # receive an empty response", so the walk is driven by @odata.nextLink
    # rather than by a row count. CONFIG maxPages backs it via pager(): the
    # repeated-link check below catches a stuck scroll first and says so
    # precisely, and the pager raise is the backstop for a landscape that mints
    # a NEW link every time while never advancing -- an incomplete import is
    # reported as an error rather than silently truncated.
    _pager = pager("devices")
    while _pager.next():
        data, err = get_json(url, **http_options)
        if err:
            fail('ivanti-neurons: failed to retrieve devices from ' + url + ': ' + err)
        if not data:
            break

        # Every field of the OData envelope is optional in a degraded or error
        # response, and Starlark has no exception handling -- so an abort here
        # would lose the rest of the walk. data['value'] as direct key access
        # was exactly that abort.
        if type(data) != "dict":
            print('ivanti-neurons: expected an object from ' + url + ', stopping the walk')
            break
        assets = data.get('value')
        if type(assets) != "list":
            print('ivanti-neurons: response carried no value array, stopping the walk')
            break
        if not assets:
            break  # the empty response Ivanti documents as the end of the walk
        collected += len(assets)
        reported += report_assets(build_assets(tenant_id, assets))

        # Only adopted when it is actually a number; an absent @odata.count
        # leaves the walk to terminate on the next link instead of aborting.
        count = data.get('@odata.count')
        if type(count) == "int":
            total_assets = count

        url = data.get('@odata.nextLink')
        if not url:
            break
        # A next link that has already been followed means the scroll is stuck:
        # the landscape is answering the same cursor with the same page, and
        # following it again can only produce the same page a third time. Say so
        # and stop, rather than repeating it until the page ceiling.
        if url in seen_links:
            print('ivanti-neurons: the scroll returned a next link it had already served, so it is not advancing; stopping with {} devices collected'.format(
                collected))
            break
        seen_links[url] = True
        # A landscape that keeps handing back a next link cannot spin forever:
        # once the tenant's own reported total has arrived, the walk is done.
        if total_assets != None and collected >= total_assets:
            break

    return reported

def get_token(base_url, tenant_id, client_id, client_secret, config_kwargs):
    url = base_url + '/api/apigatewaydataservices/v1/token'
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'X-ClientSecret': client_secret,
               'X-TenantId': tenant_id,
               'X-ClientId': client_id}
    auth_data, err = get_json(url, **get_http_options(config_kwargs, headers=headers))
    if err:
        fail('ivanti-neurons: authentication failed: ' + err)
    if not auth_data:
        fail('ivanti-neurons: the token endpoint returned an empty response')

    # The token call answers with a JSON object whose access_token field holds
    # the bearer token. This used to return the raw response body, so every
    # device request carried the entire JSON document after the Bearer keyword
    # and Ivanti refused all of them.
    if type(auth_data) != "dict":
        fail('ivanti-neurons: the authentication response was not a JSON object')
    token = auth_data.get('access_token')
    if not token:
        # A rejected client pair is reported here rather than in the status
        # line: a 200 with no access_token is the whole signal.
        fail('ivanti-neurons: authentication response carried no access_token')

    return token

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    tenant_id = get_string(kwargs, 'tenant_id')
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']
    # get_token ends the task in error itself when the exchange fails or the
    # response carries no access_token, so the token here is always usable --
    # 'Bearer ' + None would otherwise abort with a type error.
    token = get_token(base_url, tenant_id, client_id, client_secret, kwargs)

    # Each page is built and streamed inside the walk, so nothing is buffered
    # across pages.
    reported = get_and_report_assets(base_url, tenant_id, token, kwargs)
    print('ivanti-neurons: reported {} assets'.format(reported))

    return None
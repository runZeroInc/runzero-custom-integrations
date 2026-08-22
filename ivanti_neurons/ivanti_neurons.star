# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ivanti-neurons",
    "name": "Ivanti Neurons",
    "type": "inbound",
    "description": "Imports devices from Ivanti Neurons.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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

# A hard bound on the OData scroll below. Neurons serves the scroll in pages of
# 500 and the walk is driven entirely by @odata.nextLink, so a landscape that
# keeps issuing a next link -- or reissues one already served -- has no other
# end. 500 pages x 500 rows = 250,000 devices, past the endpoint count of the
# largest Neurons tenant. The repeated-link check below normally catches a stuck
# scroll first and says so precisely; this is the backstop for a landscape that
# mints a NEW link every time while never advancing. Reaching it is logged,
# because a silently truncated import looks exactly like a complete one.
MAX_PAGES = 500

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


def build_assets(assets):
    assets_import = []
    # A device with neither id has nothing stable to key on. Counted rather
    # than logged per record, with one name kept for diagnosis, so a degraded
    # export cannot become one line per device.
    skipped = 0
    skipped_name = ""
    for asset in assets:
        raw_id = asset.get('DiscoveryId') or asset.get('DeviceID')
        if not raw_id:
            skipped += 1
            if skipped == 1:
                skipped_name = str(asset.get('DeviceName', ''))
            continue
        asset_id = str(raw_id)
        hostname = asset.get('DeviceName', '')
        os_name = asset.get('OS', {}).get('Name', '')
        os_version = asset.get('OS', {}).get('Version', '')
        os = os_name + ' ' + os_version if os_version else os_name
        model = asset.get('System', {}).get('Model', '')

        # create the network interfaces
        #
        # `or {}` rather than a .get default on both hops: the default only
        # applies when the key is ABSENT, so a device carrying "Network": null
        # returned None from the first .get, and calling .get on None aborted
        # the script.
        tcpip = (asset.get('Network') or {}).get('TCPIP') or {}
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

        # Build assets for import
        asset_params = {
            'id': asset_id,
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
    return assets_import

def get_assets(base_url, token, config_kwargs):
    assets_all = []
    url = base_url + '/api/apigatewaydataservices/v1/devices'
    headers = {'Accept': 'application/json',
                'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)
    total_assets = None
    seen_links = {}

    # Ivanti documents the scroll as "keep calling the next link until you
    # receive an empty response", so the walk is driven by @odata.nextLink
    # rather than by a row count. The previous condition,
    # len(assets_all) < total_assets - 1, did neither job: it aborted the whole
    # script whenever @odata.count was absent, because that made it evaluate
    # None - 1, and when the count WAS present it stopped one record short of it
    # and silently dropped the final page.
    #
    # MAX_PAGES + 1 iterations, with the last reserved for the ceiling message.
    # The loop has seven ways out and none of them is the ceiling, so this is the
    # one place the exhausted case can be reported without a flag that has to be
    # kept in step with every one of those breaks. The extra iteration issues no
    # request: the ceiling is still exactly MAX_PAGES pages.
    for _page in range(0, MAX_PAGES + 1):
        if _page == MAX_PAGES:
            print('ivanti-neurons: stopped at the {} page ceiling with {} devices collected; the scroll never ended, so this run is truncated'.format(
                MAX_PAGES, len(assets_all)))
            break

        data, err = get_json(url, **http_options)
        if err:
            print('ivanti-neurons: failed to retrieve devices from ' + url + ': ' + err)
            break
        if not data:
            break

        # Every field of the OData envelope is optional in a degraded or error
        # response, and Starlark has no exception handling -- so an abort here
        # loses every device already collected, not just this page. data['value']
        # was direct key access, which is exactly that abort.
        if type(data) != "dict":
            print('ivanti-neurons: expected an object from ' + url + ', stopping the walk')
            break
        assets = data.get('value')
        if type(assets) != "list":
            print('ivanti-neurons: response carried no value array, stopping the walk')
            break
        if not assets:
            break  # the empty response Ivanti documents as the end of the walk
        assets_all.extend(assets)

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
                len(assets_all)))
            break
        seen_links[url] = True
        # A landscape that keeps handing back a next link cannot spin forever:
        # once the tenant's own reported total has arrived, the walk is done.
        if total_assets != None and len(assets_all) >= total_assets:
            break

    return assets_all

def get_token(base_url, tenant_id, client_id, client_secret, config_kwargs):
    url = base_url + '/api/apigatewaydataservices/v1/token'
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'X-ClientSecret': client_secret,
               'X-TenantId': tenant_id,
               'X-ClientId': client_id}
    auth_data, err = get_json(url, **get_http_options(config_kwargs, headers=headers))
    if err:
        print('ivanti-neurons: authentication failed: ' + err)
        return None
    if not auth_data:
        print('ivanti-neurons: invalid authentication data')
        return None

    # The token call answers with a JSON object whose access_token field holds
    # the bearer token. This used to return the raw response body, so every
    # device request carried the entire JSON document after the Bearer keyword
    # and Ivanti refused all of them.
    if type(auth_data) != "dict":
        print('ivanti-neurons: authentication response was not a JSON object')
        return None
    token = auth_data.get('access_token')
    if not token:
        print('ivanti-neurons: authentication response carried no access_token')
        return None

    return token

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    tenant_id = get_string(kwargs, 'tenant_id')
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']
    token = get_token(base_url, tenant_id, client_id, client_secret, kwargs)
    # 'Bearer ' + None aborts the script, so a token call that failed has to end
    # the run here. This line is also what separates a clean stop from that
    # abort in the task log -- an aborted run never reaches it.
    if not token:
        print('ivanti-neurons: no access token, nothing to import')
        return None
    assets = get_assets(base_url, token, kwargs)
    
    # Build and stream asset import via report_assets instead of returning a list
    reported = report_assets(build_assets(assets))
    print('ivanti-neurons: reported {} assets'.format(reported))

    return None
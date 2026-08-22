# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ninjaone",
    "name": "NinjaOne",
    "type": "inbound",
    "description": "Imports devices from NinjaOne.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "api_url",
            "label": "NinjaOne API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://us2.ninjarmm.com",
            "description": "The NinjaOne instance you sign in to. There are five: app.ninjarmm.com, us2.ninjarmm.com, eu.ninjarmm.com, ca.ninjarmm.com, oc.ninjarmm.com. There is no per-tenant subdomain, and any instance but your own answers 404.",
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
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 1,
            "description": "Safety ceiling on the paging walk. Raise it if a run reports hitting the limit.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'oauth2_token', 'bearer')
load('kwargs', 'get_url_base', 'get_http_options', 'get_int')

# devices-detailed takes no page-size option that this script exposes; 500 is
# the page it asks for and the row count that means "there is more".
PAGE_SIZE = 500

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so the page ceiling is that target
# divided by the page size. At 500 devices a page that is 20,000 pages.
#
# The ceiling is a backstop, not the working guard. The walk's two exits are an
# empty page and a short page, and a server that ignores `after` produces
# neither -- it answers every request with the same full page -- so the
# no-progress check on the keyset cursor catches that on the first repeat.
# Either stop is logged, because a truncated import that says nothing looks
# exactly like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = (MAX_RECORDS + PAGE_SIZE - 1) // PAGE_SIZE

def retrieved_of(reported):
    """The 'retrieved x' clause of a truncation message. devices-detailed
    returns a bare JSON array with no row total anywhere in the response or its
    headers, so this always takes the no-total form rather than printing a
    denominator the script invented."""
    return 'retrieved {} assets, total not reported'.format(reported)

def get_token(api_url, client_id, client_secret, config_kwargs):
    return oauth2_token(
        api_url + '/ws/oauth/token',
        client_id=client_id,
        client_secret=client_secret,
        scope="monitoring",
        **get_http_options(config_kwargs)
    )

def get_assets(api_url, token, config_kwargs, max_pages):
    after = ''
    reported = 0
    pages = 0
    capped = True

    url = api_url + "/v2/devices-detailed"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)

    for _page in range(0, max_pages):
        query = {'pageSize': PAGE_SIZE, 'after': after}
        devices, err = get_json(url, params=query, **http_options)

        if err:
            print('failed to retrieve assets:', err)
            return reported

        # devices-detailed is documented to answer with an array. An error
        # document served with a 200 would be a dict, and len() on it below
        # would not abort but every later index would, so stop the walk here
        # rather than part-way through building a page.
        if type(devices) != 'list':
            print('ninjaone: unexpected response shape, wanted a list of devices')
            capped = False
            break

        pages += 1

        if len(devices) < PAGE_SIZE:
            # A short page is the last page; an empty one carries nothing.
            if devices:
                reported += report_assets(build_assets(devices))
            capped = False
            break

        next_after = devices[PAGE_SIZE - 1].get('id', '')
        if not next_after:
            print('failed to retrieve last node id')
            return reported

        # `after` is a keyset cursor: the id of the last row served. A page
        # whose last id repeats the previous one means the server ignored
        # `after` or replayed a cached response, so every later request would
        # fetch these same rows again. The walk's only exits are an empty page
        # and a short page, and a repeated FULL page is neither, so this is the
        # guard that actually fires -- stop on the first repeat, and stop
        # BEFORE reporting, so a replayed page is not imported a second time.
        if str(next_after) == str(after):
            print('ninjaone: paging stopped after {} pages (API returned the same cursor twice, {})'.format(
                pages, retrieved_of(reported)))
            capped = False
            break

        # Build and stream this page before fetching the next so the full
        # device set is never held in memory at once.
        reported += report_assets(build_assets(devices))
        after = next_after

    if capped:
        print('ninjaone: page limit of {} hit (integration safety limit, {}) - raise the max_pages parameter to import the rest'.format(
            max_pages, retrieved_of(reported)))

    return reported

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:
        id = item.get('id')
        if not id:
            print("ninjaone: skipping device with no id: systemName=" + str(item.get('systemName', '')))
            continue

        # NinjaOne exposes four names and a device may carry any subset of them.
        # Empty values are dropped rather than passed through: an ImportAsset
        # built with "" in hostnames carries a blank name for every device
        # missing that field, which is noise at best and a merge signal shared
        # by unrelated assets at worst.
        hostnames = []
        for key in ['displayName', 'systemName', 'dnsName', 'netbiosName']:
            name = item.get(key, '')
            if name and name not in hostnames:
                hostnames.append(name)

        # parse network interfaces
        ips = []
        macs = []
        networks = []

        ips = item.get('ipAddresses', [])
        
        # check for assets with weird address blocks and rebuilt ips
        rebuilt_ips = []
        for ip in ips:
            if '|' in ip:
                rebuilt_ips.extend(ip.split('|'))
            elif ip == '':
                continue
            else:
                rebuilt_ips.append(ip)
        ips = rebuilt_ips

        # Assets with no IP address get no synthetic one. A placeholder such as
        # 127.0.0.1 is identical on every host, so IP matching would pull every
        # address-less device onto the same existing asset and merge unrelated
        # machines. These devices still correlate on MAC and hostname.

        macs = item.get('macAddresses', [])
        if macs:
            for m in macs:
                network = network_interface(ips=ips, mac=m)
                if network:
                    networks.append(network)
        elif ips:
            network = network_interface(ips=ips, mac=None)
            if network:
                networks.append(network)

        imported_assets.append(
            ImportAsset(
                id=str(id),
                hostnames=hostnames,
                networkInterfaces=networks,
                os=item.get('os', {}).get('name', ''),
                manufacturer=item.get('system', {}).get('manufacturer', ''),
                customAttributes=to_custom_attributes({
                    'id':id,
                    'displayName':item.get('displayName'),
                    'systemName':item.get('systemName'),
                    'dnsName':item.get('dnsName'),
                    'netbiosName':item.get('netbiosName'),
                    'nodeClass':item.get('nodeClass'),
                    'nodeRoleId':item.get('nodeRoleId'),
                    'rolePolicyId':item.get('rolePolicyId'),
                    'policyId':item.get('policyId'),
                    'approvalStatus':item.get('approvalStatus'),
                    'offline':item.get('offline'),
                    'ipAddresses':item.get('ipAddresses'),
                    'macAddresses':item.get('macAddresses'),
                    'publicIP':item.get('publicIP'),
                    'osManufacturer':item.get('os', {}).get('manufacturer'),
                    'osName':item.get('os', {}).get('name'),
                    'osArchitecture':item.get('os', {}).get('architecture'),
                    'osBuildNumber':item.get('os', {}).get('buildNumber'),
                    'osReleaseId':item.get('os', {}).get('manufacturer'),
                    'osServicePackMajorVersion':item.get('os', {}).get('servicePackMajorVersion'),
                    'osServicePackMinorVersion':item.get('os', {}).get('servicePackMinorVersion'),
                    'osLanguage':item.get('os', {}).get('language'),
                    'osNeedsReboot':item.get('os', {}).get('needsReboot'),
                    'systemManufacturer':item.get('system', {}).get('manufacturer'),
                    'systemModel':item.get('system', {}).get('model'),
                    'systemBiosSerialNumber':item.get('system', {}).get('biosSerialNumber'),
                    'systemSerialNumber':item.get('system', {}).get('serialNumberr'),
                    'systemDomain':item.get('system', {}).get('domain'),
                    'systemDomainRole':item.get('system', {}).get('domainRole'),
                    'systemProcessors':item.get('system', {}).get('numberOfProcessors'),
                    'systemTotalPhysicalMemory':item.get('system', {}).get('totalPhysicalMemory'),
                    'systemVirtualMachine':item.get('system', {}).get('virtualMachine'),
                    'systemChassisType':item.get('system', {}).get('chassisType'),
                    'lastLoggedInUser':item.get('lastLoggedInUser'),
                    'deviceType':item.get('deviceType')
                }),
            )
        )
    return imported_assets

# build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    # The instance root only. Operators are told to copy the host they sign in
    # to, so the value often arrives with the console's path and fragment
    # attached; get_url_base keeps just scheme and host.
    api_url = get_url_base(kwargs, 'api_url')
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']
    # CONFIG defaults are applied by the Console, not by the plain script
    # --kwargs path, so the default is repeated here.
    max_pages = get_int(kwargs, 'max_pages', default=MAX_PAGES)
    if max_pages < 1:
        max_pages = MAX_PAGES

    # get bearer token
    token = get_token(api_url, client_id, client_secret, kwargs)
    if not token:
        print('failed to retrieve bearer token')
        return None

    # get and stream assets page-by-page via report_assets
    reported = get_assets(api_url, token, kwargs, max_pages)
    if not reported:
        print('no assets retrieved')
    
    return None
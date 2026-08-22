# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-manageengine-endpoint-central",
    "name": "ManageEngine Endpoint Central",
    "type": "inbound",
    "description": "Imports endpoints from ManageEngine Endpoint Central.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options')

API_VERSION     = '1.4'
SCAN_ENDPOINT   = '/api/' + API_VERSION + '/inventory/scancomputers'
PAGE_LIMIT      = 1000

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so every page ceiling is that target
# divided by the page size. At 1000 rows a page that is 10,000 pages.
#
# The ceiling is a backstop, not the working guard. The walk's two exits are an
# empty page and a short page, and a server that ignores `page` produces
# neither -- it just keeps answering with the same full page -- so the
# no-progress check below catches that on the first repeat. Either stop is
# logged, because a truncated import that says nothing looks exactly like a
# complete one.
MAX_RECORDS     = 10000000
MAX_PAGES       = (MAX_RECORDS + PAGE_LIMIT - 1) // PAGE_LIMIT

def page_signature(devices):
    """A fingerprint of one page's rows, used to notice a server that answers
    every page number with the same page."""
    ids = []
    for d in devices:
        ids.append(str(d.get('resource_id') or d.get('id') or ''))
    return ','.join(ids)

def reported_total(body):
    """Endpoint Central returns a metadata object alongside message_response on
    the paginated inventory APIs. Read the row total from it when it is there,
    and answer None when it is not -- a total this script invented would be
    worse than saying the API did not report one."""
    if type(body) != 'dict':
        return None
    meta = body.get('metadata', {})
    if type(meta) != 'dict':
        return None
    total = meta.get('total', meta.get('total_records'))
    if type(total) == 'int' and total >= 0:
        return total
    return None

def retrieved_of(reported, total):
    """The 'Retrieved x/y' clause of a truncation message, or the no-total form
    the house style requires when the API does not report one."""
    if total == None:
        return 'Retrieved {} assets; the API does not report a total'.format(reported)
    return 'Retrieved {}/{} available assets'.format(reported, total)

def build_network_interfaces(device):
    """Return this device's interfaces, or an empty list when it has none.

    Endpoint Central reports agent-managed endpoints, and a row for a machine
    that has enrolled but not yet completed an inventory scan carries neither
    ip_address nor mac_address. This used to build a NetworkInterface
    unconditionally and return it in a one-element list, so such a row produced
    an interface with no MAC and no address -- an empty interface that says
    nothing, cannot correlate, and only adds noise to the asset. Building the
    interface through net.network_interface answers None in exactly that case,
    and the guard turns it into no interface at all rather than an empty one.
    """
    ip_field = device.get('ip_address') or ''
    mac = device.get('mac_address')
    # support comma-separated IPs if ever present
    ips = [p.strip() for p in ip_field.split(',') if p.strip()]
    # network_interface classifies v4/v6 itself, strips port and zone suffixes,
    # dedupes, and caps each family at 99. It also replaces the previous
    # hand-rolled loop, which read .version off ip_address()'s return value --
    # that is None for an unparseable address and reading it aborts the script.
    iface = network_interface(ips=ips, mac=mac)
    if not iface:
        return []
    return [iface]

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
    capped      = True
    total       = None
    last_signature = None
    for _page in range(0, MAX_PAGES):
        url = base_url + SCAN_ENDPOINT
        params = {"pagelimit": PAGE_LIMIT, "page": page}
        body, err = get_json(url, params=params, timeout=3600, **http_options)
        if err:
            print('Scan API error:', err)
            return None

        body    = body or {}
        # message_response is documented as an object; reading .get off a list
        # would abort the script, so an array-shaped error document has to stop
        # the walk rather than end the run silently.
        if type(body) != 'dict' or type(body.get('message_response', {})) != 'dict':
            print('endpoint-central: unexpected response shape, wanted an object')
            capped = False
            break
        total   = reported_total(body) if total == None else total
        msg     = body.get('message_response', {})
        devices = msg.get('scancomputers', [])
        if not devices:
            capped = False
            break

        # A page identical to the one before it means the server stopped
        # advancing -- a `page` it ignored, or a cached response replayed. The
        # walk's exits are an empty page and a short page, so a repeated FULL
        # page produces neither and the walk would re-import it until the
        # ceiling. Stop on the first repeat.
        signature = page_signature(devices)
        if signature == last_signature:
            print('endpoint-central: pagination stopped making progress at page {}; the server repeated the previous page. {}'.format(
                page, retrieved_of(reported, total)))
            capped = False
            break
        last_signature = signature

        # Build and stream each page via report_assets so the full device set
        # is never held in memory.
        reported += report_assets(build_assets(devices))
        if len(devices) < PAGE_LIMIT:
            capped = False
            break
        page += 1

    if capped:
        print('endpoint-central: page limit of {} hit (integration safety limit). {}'.format(
            MAX_PAGES, retrieved_of(reported, total)))

    if not reported:
        print('No devices returned')

    return None
# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-stairwell",
    "name": "Stairwell",
    "type": "inbound",
    "description": "Imports environment data from Stairwell.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Stairwell API URL",
            "type": "url",
            "required": False,
            "default": "https://app.stairwell.com",
            "placeholder": "https://app.stairwell.com",
            "description": "Stairwell's API endpoint. Override only for a regional or non-production deployment.",
        },
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
        {
            "key": "page_size",
            "label": "Assets per page",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "How many assets to request per page. Sent as both `limit` and `page_size`.",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Optional ceiling on the paging walk below the CONFIG maxPages backstop. 0 uses the backstop.",
        },
    ],
    # Backstop for the paging walk: 100,000 pages at the default 100-asset page
    # is the repo-wide ten-million-record target. Hitting it raises rather than
    # truncating silently; see pager() in docs/starlark-helpers.md.
    "maxPages": 100000,
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface', 'ip_in_network')
load('http', 'get_json')
load('kwargs', 'get_http_options', 'get_int')
load('coerce', 'as_list')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script.
DEFAULT_STAIRWELL_API_URL = 'https://app.stairwell.com'

# Default for the page_size parameter, repeated here because CONFIG defaults
# are applied by the Console, not by the plain `script --kwargs` path.
DEFAULT_PAGE_SIZE = 100

def reported_total(body):
    """Stairwell's list APIs follow the Google resource style, where a total is
    optional and arrives as totalSize. Read it when it is there and answer None
    when it is not -- a total this script invented would be worse than saying
    the API did not report one."""
    if type(body) != 'dict':
        return None
    total = body.get('totalSize', body.get('total_size'))
    if type(total) == 'int' and total >= 0:
        return total
    if type(total) == 'string' and total.isdigit():
        return int(total)
    return None

def retrieved_of(reported, total):
    """The 'retrieved x' clause of a truncation message, in the with-total form
    when the API reported one and the no-total form when it did not."""
    if total == None:
        return 'retrieved {} assets, total not reported'.format(reported)
    return 'retrieved {}/{} available assets'.format(reported, total)

def stream_assets(base_url, env, token, config_kwargs, max_pages, page_size):
    """Paginate Stairwell assets, building and streaming each page via
    report_assets so the full asset set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    total = None
    token_seen = ''

    url = base_url + "/v1/environments/" + env + "/assets"

    # Stairwell's quickstart shows `Authorization: Bearer <token>` while its own
    # OpenAPI securityScheme declares the raw token with no prefix. Start with
    # Bearer; a 401 on that form retries the same request once with the raw
    # token, and whichever form the tenant accepted is kept for the rest of the
    # run.
    raw_auth = False

    # The request parameter spellings could not be confirmed against a live
    # tenant: the response follows the Google resource style (assets,
    # nextPageToken, totalSize), where the REQUEST fields would be page_token
    # and page_size, but Stairwell's quickstart shows limit. Send both spellings
    # of both parameters -- the server reads the one it knows and ignores the
    # other, so either convention pages correctly.
    params = {'limit': page_size, 'page_size': page_size}

    p = pager('assets', limit=max_pages)
    while p.next():
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token if raw_auth else 'Bearer ' + token,
        }
        http_options = get_http_options(config_kwargs, headers=headers)
        body, err = get_json(url, params=params, **http_options)
        if err and err.startswith('status 401') and not raw_auth:
            print('stairwell: Bearer authorization rejected (401), retrying with the raw token form')
            raw_auth = True
            headers['Authorization'] = token
            http_options = get_http_options(config_kwargs, headers=headers)
            body, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve assets:', err)
            return reported

        # The documented response is an object carrying "assets" and
        # "nextPageToken". Verify that before reading it: .get on a list aborts
        # the script, so a bare array or an error document would end the run
        # with no explanation rather than stopping cleanly here.
        if type(body) != "dict":
            print('stairwell: unexpected response shape, wanted an object')
            break

        if total == None:
            total = reported_total(body)

        next_token = body.get('nextPageToken', '')

        # nextPageToken is the only thing that advances this walk, so a token
        # identical to the one just sent means the server is not advancing --
        # a cursor it ignored, or a cached response replayed -- and every later
        # request would return these same rows. There is no other exit from
        # that state, so stop on the first repeat, and stop BEFORE reporting so
        # the replayed page is not imported a second time. This guard is
        # complementary to the pager() ceiling: the pager catches a cursor that
        # rotates forever, this catches one that stopped advancing.
        if next_token and next_token == token_seen:
            print('stairwell: paging stopped after {} pages (API returned the same cursor twice, {})'.format(
                p.page, retrieved_of(reported, total)))
            break

        reported += report_assets(build_assets(body.get('assets')))

        if not next_token:
            break
        token_seen = next_token
        params = {
            'limit': page_size,
            'page_size': page_size,
            'next_page_token': next_token,
            'page_token': next_token,
        }

    return reported

def is_loopback(ip):
    """True for 127.0.0.0/8 and ::1. ip_in_network answers False across address
    families, so the v6 case is a literal compare rather than a second CIDR."""
    return ip == '::1' or ip_in_network(ip, '127.0.0.0/8')

def build_assets(assets_json):
    imported_assets = []
    # `assets` can be present-but-null, and a row can be something other than an
    # object; either used to abort the run mid-walk. as_list turns null into an
    # empty list, and the type check skips the malformed row with a log line.
    for item in as_list(assets_json, wrap=False):
        if type(item) != 'dict':
            print('stairwell: skipping non-object asset row')
            continue

        # parse ip address
        ips = []
        ip = item.get('ipAddress', '') or ''

        # strip interface from ipv6 address
        if '%' in ip:
            ip = ip.split('%')[0]

        # An address-less record used to be given a synthetic 127.0.0.1.
        # Loopback is the same value on every host, so an interface carrying it
        # is a correlation key that matches every other address-less asset --
        # inert only because the platform strips loopback before it reaches an
        # asset, and correctness that depends on a filter somewhere else is not
        # correctness. Report no address instead, and drop a loopback the API
        # itself reports for the same reason.
        if ip and not is_loopback(ip):
            ips.append(ip)

        # parse mac address. '-' is Stairwell's placeholder for "none reported".
        mac = item.get('macAddress', '') or ''
        if mac == '-':
            mac = ''

        # create network interfaces. A missing MAC used to `continue` here, and
        # this loop is over ASSETS: a host that reported an address and a label
        # was dropped entirely rather than losing only its interface, with no
        # log line and no count. Build whatever survives instead --
        # network_interface returns None when neither a usable address nor a MAC
        # is left, and appending that aborts the whole run at ImportAsset, so an
        # interface-less asset is one with an empty list.
        networks = []
        network = network_interface(ips=ips, mac=mac or None)
        if network:
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

        # The resource name is environments/<env>/assets/<asset>, so the asset
        # id is the LAST component. Taking index 1 returned the environment
        # instead, giving every asset in an environment the same foreign id and
        # collapsing them onto a single runZero asset; it also aborted the run
        # on any name with no separator.
        name = item.get('name', '') or ''
        parts = [p for p in name.split('/') if p]
        if not parts:
            print('stairwell: skipping asset with no resource name')
            continue
        asset_id = parts[-1]

        # The one record still worth dropping, and now for a stated reason: with
        # no interface and no label the asset carries nothing to correlate on,
        # so it can never merge with anything runZero already knows and only
        # accumulates as an orphan on every run.
        label = item.get('label', '') or ''
        if not networks and not label:
            print('stairwell: skipping asset {} with no address, MAC, or label'.format(asset_id))
            continue

        imported_assets.append(
            ImportAsset(
                id=asset_id,
                hostnames=[label],
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
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_STAIRWELL_API_URL).rstrip('/')
    # CONFIG defaults are applied by the Console, not by the plain script
    # --kwargs path, so the defaults are repeated here. max_pages of 0 defers
    # entirely to the CONFIG maxPages backstop, which pager() enforces.
    max_pages = get_int(kwargs, 'max_pages', default=0)
    if max_pages < 0:
        max_pages = 0
    page_size = get_int(kwargs, 'page_size', default=DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(base_url, env, token, kwargs, max_pages, page_size)
    if not reported:
        print('failed to retrieve assets')

    return None
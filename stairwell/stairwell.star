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
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 2000000,
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
load('net', 'network_interface', 'ip_in_network')
load('http', 'get_json')
load('kwargs', 'get_http_options', 'get_int')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script.
DEFAULT_STAIRWELL_API_URL = 'https://app.stairwell.com'

# The `limit` this script asks for. It is not exposed as a parameter, and five
# rows a page is small enough that the record-derived ceiling below lands on a
# very large page count -- see the note there.
PAGE_SIZE = 5

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so the page ceiling is that target
# divided by the page size. At 5 assets a page that is 2,000,000 pages, which is
# a large number of requests precisely because the page is small; the ceiling is
# stated in RECORDS so it never truncates a real environment, and raising
# PAGE_SIZE would lower it proportionally.
#
# The ceiling is a backstop, not the working guard. The walk's only exit is a
# response with no nextPageToken, so a server that echoes the same token forever
# never reaches it -- the no-progress check on the token catches that on the
# first repeat. Either stop is logged, because a truncated import that says
# nothing looks exactly like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = (MAX_RECORDS + PAGE_SIZE - 1) // PAGE_SIZE

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

def stream_assets(base_url, env, token, config_kwargs, max_pages):
    """Paginate Stairwell assets, building and streaming each page via
    report_assets so the full asset set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    pages = 0
    capped = True
    total = None
    token_seen = ''

    url = base_url + "/v1/environments/" + env + "/assets"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
    http_options = get_http_options(config_kwargs, headers=headers)
    params = {'limit': PAGE_SIZE}

    for _page in range(0, max_pages):
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
            capped = False
            break

        pages += 1
        if total == None:
            total = reported_total(body)

        next_token = body.get('nextPageToken', '')

        # nextPageToken is the only thing that advances this walk, so a token
        # identical to the one just sent means the server is not advancing --
        # a cursor it ignored, or a cached response replayed -- and every later
        # request would return these same rows. There is no other exit from
        # that state, so stop on the first repeat, and stop BEFORE reporting so
        # the replayed page is not imported a second time.
        if next_token and next_token == token_seen:
            print('stairwell: paging stopped after {} pages (API returned the same cursor twice, {})'.format(
                pages, retrieved_of(reported, total)))
            capped = False
            break

        reported += report_assets(build_assets(body.get('assets', [])))

        if not next_token:
            capped = False
            break
        token_seen = next_token
        params = {'next_page_token': next_token, 'limit': PAGE_SIZE}

    if capped:
        print('stairwell: page limit of {} hit (integration safety limit, {}) - raise the max_pages parameter to import the rest'.format(
            max_pages, retrieved_of(reported, total)))

    return reported

def is_loopback(ip):
    """True for 127.0.0.0/8 and ::1. ip_in_network answers False across address
    families, so the v6 case is a literal compare rather than a second CIDR."""
    return ip == '::1' or ip_in_network(ip, '127.0.0.0/8')

def build_assets(assets_json):
    imported_assets = []
    for item in assets_json:

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
    # --kwargs path, so the default is repeated here.
    max_pages = get_int(kwargs, 'max_pages', default=MAX_PAGES)
    if max_pages < 1:
        max_pages = MAX_PAGES

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(base_url, env, token, kwargs, max_pages)
    if not reported:
        print('failed to retrieve assets')

    return None
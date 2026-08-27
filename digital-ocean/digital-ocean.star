# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-digital-ocean",
    "name": "Digital Ocean",
    "type": "inbound",
    "description": "Imports droplets from DigitalOcean.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Upper bound on the droplet page walk, so a server that keeps handing back
    # a next link can never spin forever. 1,000 pages x 200 droplets covers any
    # real account.
    "maxPages": 1000,
    "params": [
        {
            "key": "url",
            "label": "DigitalOcean API URL",
            "type": "url",
            "required": False,
            "default": "https://api.digitalocean.com",
            "placeholder": "https://api.digitalocean.com",
            "description": "DigitalOcean's API endpoint. Override only for a regional or non-production deployment.",
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
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a proxy or non-production deployment can be reached
# without editing the script. The /v2 API prefix is applied in the code below,
# so the parameter carries only the scheme and host.
DEFAULT_DIGITAL_OCEAN_URL = 'https://api.digitalocean.com'

# Every record this integration imports comes from /v2/droplets, and a Droplet
# is DigitalOcean's cloud compute instance -- there is no other kind of record
# in the collection, so the role is carried by the resource itself rather than
# guessed from an image name or size slug. runZero types the equivalent AWS and
# GCP compute instances the same way.
DROPLET_DEVICE_TYPE = "Server"

def collect_ips(networks):
    """Pull the v4 and v6 addresses out of a DigitalOcean `networks` block."""
    ips = []
    if not networks:
        return ips
    for v in networks.get('v4', []) or []:
        ip = v.get('ip_address', '')
        if ip:
            ips.append(ip)
    for v in networks.get('v6', []) or []:
        ip = v.get('ip_address', '')
        if ip:
            ips.append(ip)
    return ips

def format_tags(tags):
    """Convert DigitalOcean `key:value` tags to runZero `key=value` tags.

    DO tags are strings today, but `':' in t` on anything else aborts the whole
    run, so stray scalars are stringified and container values are dropped."""
    out = []
    for t in tags or []:
        if t == None or type(t) in ("dict", "list"):
            continue
        t = str(t)
        if not t:
            continue
        if ':' in t:
            k, v = t.split(':', 1)
            out.append(k + '=' + v)
        else:
            out.append(t)
    return out

def build_assets(assets_json):
    assets = []
    for item in assets_json:
        # A non-object element in the droplets array would abort the run at
        # .get, losing every droplet after it; skip it with a note instead.
        if type(item) != "dict":
            print("digital-ocean: skipping non-object droplet entry")
            continue
        item_id = item.get('id')
        if not item_id:
            print("digital-ocean: skipping droplet with no id: name=" + str(item.get('name', '')))
            continue
        nic = network_interface(ips=collect_ips(item.get('networks', {})))
        nics = [nic] if nic else []

        image = item.get('image', {}) or {}
        region = item.get('region', {}) or {}

        assets.append(ImportAsset(
            id=str(item_id),
            hostnames=[item.get('name', '')],
            networkInterfaces=nics,
            os=image.get('distribution', ''),
            deviceType=DROPLET_DEVICE_TYPE,
            tags=format_tags(item.get('tags')),
            customAttributes=to_custom_attributes({
                "id": item.get('id'),
                "size_slug": item.get('size_slug'),
                "memory": item.get('memory'),
                "vcpus": item.get('vcpus'),
                "disk": item.get('disk'),
                "locked": item.get('locked'),
                "status": item.get('status'),
                "created_at": item.get('created_at'),
                "vpcUUID": item.get('vpc_uuid'),
                "image.id": image.get('id'),
                "image.name": image.get('name'),
                "image.distribution": image.get('distribution'),
                "image.type": image.get('type'),
                "image.public": image.get('public'),
                "image.status": image.get('status'),
                "region.name": region.get('name'),
                "region.available": region.get('available'),
            }),
        ))
    return assets

def main(**kwargs):
    token = kwargs['api_token']
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_DIGITAL_OCEAN_URL).rstrip('/')
    headers = {"Authorization": bearer(token)}
    http_options = get_http_options(kwargs, headers=headers)

    # DigitalOcean pages at 20 droplets by default and publishes the next page as
    # an absolute URL in links.pages.next. Fetching only the first page silently
    # truncated every account with more than one page, so the walk follows that
    # cursor to the end. per_page is raised to the API maximum to keep the number
    # of round trips down.
    url = base_url + '/v2/droplets?per_page=200'
    reported = 0

    # The cursor comes from the server, so bound the walk with pager() rather
    # than trusting it to terminate; reaching CONFIG maxPages raises instead of
    # silently truncating.
    p = pager("droplets")
    while p.next():
        if not url:
            break

        data, err = get_json(url, **http_options)
        if err:
            fail('digital-ocean: failed to retrieve droplets: {}'.format(err))

        body = data or {}
        if type(body) != "dict":
            fail('digital-ocean: unexpected response shape, wanted an object')

        # Stream each page via report_assets instead of accumulating the
        # estate. A present-but-null droplets field must not abort the walk.
        reported += report_assets(build_assets(body.get('droplets') or []))

        links = body.get('links') or {}
        url = (links.get('pages') or {}).get('next', '')

    if not reported:
        print('no assets')
    return None

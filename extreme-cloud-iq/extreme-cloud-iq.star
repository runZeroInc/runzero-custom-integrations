# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-extreme-networks-cloudiq",
    "name": "Extreme Networks CloudIQ",
    "type": "inbound",
    "description": "Imports access points and switches from Extreme CloudIQ.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # A BACKSTOP, not the primary guard: the walk's real runaway protection is
    # the repeated-page check in the loop, which notices a tenant that ignores
    # `page` after two requests. 100,000 pages x 100 rows = 10,000,000 devices,
    # past any real XIQ deployment; reaching it raises rather than quietly
    # truncating.
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "Extreme CloudIQ API URL",
            "type": "url",
            "required": False,
            "default": "https://api.extremecloudiq.com",
            "placeholder": "https://api.extremecloudiq.com",
            "description": "Extreme CloudIQ's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('http', 'get_json', 'post_json', 'bearer')
load('flatten_json', 'flatten')
load('net', 'ip_address')
load('kwargs', 'get_http_options')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_EXTREME_CLOUD_IQ_URL = 'https://api.extremecloudiq.com'

SKIP_UNMANAGED = False

PAGE_SIZE = 100

# device_function is the XiqDeviceFunction enum from Extreme's published
# OpenAPI specification, and every documented value is listed here except the
# two bare VPN gateway forms: unlike ROUTER_AS_L2_VPN_GATEWAY and
# ROUTER_AS_L3_VPN_GATEWAY those name a role without naming the chassis, so
# they are left for runZero to fingerprint.
#
# The raw value used to be handed to ImportAsset directly, which sent a literal
# empty string for a device reporting no function at all. An empty deviceType is
# still a value: it displaces the type runZero derives from the hardware, so an
# unmapped function now omits the field entirely.
DEVICE_TYPES = {
    'AP': 'WAP',
    'SWITCH': 'Switch',
    'SWITCH_HAC': 'Switch',
    'SWITCH_DELL': 'Switch',
    'ROUTER': 'Router',
    'ROUTER_AS_L2_VPN_GATEWAY': 'Router',
    'ROUTER_AS_L3_VPN_GATEWAY': 'Router',
}

def asset_networks(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        ip_obj = ip_address(ip)
        # ip_address answers None for a malformed value, and .version on None
        # aborts the run mid-page; one bad address must only cost itself.
        if ip_obj == None:
            continue
        if ip_obj.version == 4:
            ip4s.append(ip_obj)
        elif ip_obj.version == 6:
            ip6s.append(ip_obj)
    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)


def retrieved_of(retrieved, total):
    """The "Retrieved X/Y available assets" half of a truncation message.

    A truncated run has to say how much of the estate it actually got: a bare
    count tells the reader nothing about whether the import is nearly complete
    or stopped at the first percent. Where the API reports no total, say so
    plainly rather than printing a bare slash or inventing a denominator.
    """
    if type(total) == "int" and total > 0:
        return "Retrieved {}/{} available assets".format(retrieved, total)
    return "Retrieved {} assets; the API does not report a total".format(retrieved)


def page_signature(devices):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the server re-served one
    page rather than advancing through the inventory. Comparing ends rather
    than every row keeps this O(1) per page, and it is enough for the failure
    it guards against -- a tenant that ignores `page` returns byte-identical
    responses, not a rearrangement of one.
    """
    if not devices:
        return "empty"
    first = devices[0]
    last = devices[-1]
    first_id = first.get("id", "") if type(first) == "dict" else ""
    last_id = last.get("id", "") if type(last) == "dict" else ""
    return "{}|{}|{}".format(len(devices), first_id, last_id)


def main(*args, **kwargs):
    username = kwargs.get('username')
    password = kwargs.get('password')
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_EXTREME_CLOUD_IQ_URL).rstrip('/')

    # get_http_options wires the full shared option set -- TLS material beyond
    # insecure_skip_verify, the user agent, proxy, timeouts -- and get_json/
    # post_json retry the transient statuses (429/5xx) with backoff. The old
    # requests.Session honored only tls_disable_validation and retried nothing,
    # so a rate-limited page truncated the import.
    http_options = get_http_options(kwargs, headers={"Accept": "application/json"})

    # post_json checks the status BEFORE decoding and reports a non-JSON 200
    # body as an error string, so the HTML page a proxy answers with -- or an
    # empty body -- ends the task naming the login rather than aborting inside
    # json_decode. Logging in mints a token and changes nothing, so the default
    # retry policy is safe here.
    login_body, err = post_json(base_url + "/login",
                                json={"username": username, "password": password},
                                **http_options)
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("extreme-cloud-iq: check the username and password")
        fail("extreme-cloud-iq: login failed: {}".format(err))
    if type(login_body) != "dict":
        fail("extreme-cloud-iq: the login endpoint returned an unexpected response shape, wanted an object")

    token = login_body.get("access_token")
    if not token:
        print("Access token not found in response.")
        return None

    http_options["headers"]["Authorization"] = bearer(token)

    reported = 0
    limit = PAGE_SIZE
    last_signature = ""
    # XIQ reports the size of the whole inventory alongside every page. It is
    # captured so a truncated run can say what fraction of the estate it got,
    # rather than a bare count the reader cannot judge.
    total_count = None

    # CONFIG maxPages backstops the walk via pager(); the repeated-page check
    # below remains the primary runaway guard.
    p = pager("devices")
    while p.next():
        page = p.page
        # `views` (uppercase enum values) is XIQ's documented parameter for the
        # FULL device view. Earlier revisions sent only `view=full`, which XIQ
        # ignores as an unknown parameter, so the run worked but silently lost
        # the FULL-view extras. Both spellings are sent so the request works
        # whichever one the deployment honors.
        url = "{}/devices?page={}&limit={}&view=full&views=FULL".format(base_url, page, limit)
        print("Fetching page:", page)
        devices_body, err = get_json(url, **http_options)
        if err:
            fail("extreme-cloud-iq: failed to fetch page {}: {}".format(page, err))

        # The documented response is an object with a "data" array; reading .get
        # off a list would abort the script.
        if type(devices_body) != "dict":
            fail("extreme-cloud-iq: unexpected response shape on page {}, wanted an object".format(page))

        reported_total = devices_body.get("total_count")
        if type(reported_total) == "int" and reported_total >= 0:
            total_count = reported_total

        # A present-but-null data field defeats the .get default, and anything
        # but a list would abort the signature check below.
        devices = devices_body.get("data") or []
        if type(devices) != "list":
            print("Unexpected data field shape on page", page, "- wanted a list")
            break
        if not devices:
            print("No devices on page", page)
            break

        # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it means
        # XIQ is ignoring `page` and re-serving the same rows, so the walk is
        # not advancing and continuing can only re-report devices already
        # reported. This is checked BEFORE the page is reported, so the repeated
        # rows never reach runZero, and it can never truncate genuine data: it
        # only fires on a page that adds nothing. It catches the stuck tenant in
        # two requests where the page ceiling would take 100,000.
        signature = page_signature(devices)
        if signature == last_signature:
            print("extreme-cloud-iq: paging stopped after {} pages: the API returned the same page twice. {}".format(
                page, retrieved_of(reported, total_count)))
            break
        last_signature = signature

        page_assets = []
        for device in devices:
            # A non-object element in the data array has no fields to read and
            # would abort the run at .get; skip it with a note instead.
            if type(device) != "dict":
                print("Skipping non-object device record.")
                continue

            device_id = device.get("id") or device.get("serial_number")
            if not device_id:
                print("Skipping device with no id or serial number.")
                continue

            if device.get("device_admin_state", "") != "MANAGED" and SKIP_UNMANAGED:
                print("Skipping unmanaged device.")
                continue

            ips = []
            if "ip_address" in device and device["ip_address"]:
                ips.append(device["ip_address"])
            if "ipv6_address" in device and device["ipv6_address"]:
                ips.append(device["ipv6_address"])

            mac = device.get("mac_address", "")

            asset_params = {
                "id": str(device_id),
                # A present-but-null hostname defeats the .get default and a
                # None in the hostnames list aborts the whole run.
                "hostnames": [device.get("hostname") or ""],
                "networkInterfaces": [asset_networks(ips, mac)],
                "customAttributes": {},
            }
            device_type = DEVICE_TYPES.get(str(device.get("device_function") or "").strip().upper(), "")
            if device_type:
                asset_params["deviceType"] = device_type

            asset = ImportAsset(**asset_params)

            for key in device.keys():
                if key not in ["id", "hostname", "mac_address", "ip_address", "ipv6_address"]:
                    val = device[key]
                    if type(val) == "dict":
                        asset.customAttributes.update(flatten(val))
                    elif type(val) in ["string", "int", "bool"]:
                        asset.customAttributes[key] = str(val)

            page_assets.append(asset)

        # Build and stream each page via report_assets so the full device set
        # is never held in memory.
        reported += report_assets(page_assets)

        if len(devices) < limit:
            break

    print("Total assets imported:", reported)
    return None

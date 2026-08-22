# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-extreme-networks-cloudiq",
    "name": "Extreme Networks CloudIQ",
    "type": "inbound",
    "description": "Imports access points and switches from Extreme CloudIQ.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
load('requests', 'Session')
load('json', json_encode='encode', json_decode='decode')
load('flatten_json', 'flatten')
load('net', 'ip_address')
load('kwargs', 'get_bool')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_EXTREME_CLOUD_IQ_URL = 'https://api.extremecloudiq.com'

SKIP_UNMANAGED = False

PAGE_SIZE = 100

# A BACKSTOP, not the primary guard. The walk's real runaway protection is the
# repeated-page check in the loop below, which notices a tenant that ignores
# `page` after two requests. A page ceiling is a poor first line of defence: an
# XIQ that keeps re-serving one page would be hammered for the whole ceiling
# before anything stopped it.
#
# The number is derived from a record target rather than hand-picked, so it
# scales with the page size instead of encoding a guess about tenant size:
# 100,000 pages x 100 rows = 10,000,000 devices, past any real XIQ deployment.
# With the repeated-page check in front of it this should never be reached;
# reaching it anyway is logged, because a truncated import that says nothing
# looks exactly like a complete one.
MAX_PAGES = 100000

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

    session = Session(insecure_skip_verify=get_bool(kwargs, 'tls_disable_validation', False))
    session.headers.set('Content-Type', 'application/json')
    session.headers.set('Accept', 'application/json')
    if kwargs.get('http_user_agent'):
        session.headers.set('User-Agent', kwargs.get('http_user_agent'))

    login_payload = {
        "username": username,
        "password": password
    }
    login_resp = session.post(base_url + "/login", json=login_payload)
    print("Login response code:", login_resp.status_code)
    login_body = json_decode(login_resp.body)
    print("Login response body:", login_body.keys())

    if not login_resp or login_resp.status_code != 200:
        return []

    token = login_body.get("access_token")
    if not token:
        print("Access token not found in response.")
        return []

    session.headers.set("Authorization", "Bearer {}".format(token))

    reported = 0
    page = 1
    limit = PAGE_SIZE
    last_signature = ""
    # XIQ reports the size of the whole inventory alongside every page. It is
    # captured so a truncated run can say what fraction of the estate it got,
    # rather than a bare count the reader cannot judge.
    total_count = None

    # MAX_PAGES + 1 iterations, with the last one reserved for the ceiling
    # message. The loop has six different ways out and none of them is the
    # ceiling, so this is the one place the exhausted case can be reported
    # without a flag to keep in step with every one of those breaks. The extra
    # iteration issues no request: the ceiling is still exactly MAX_PAGES pages.
    for _page in range(0, MAX_PAGES + 1):
        if _page == MAX_PAGES:
            print("extreme-cloud-iq: page limit of {} hit (integration safety limit). {}".format(
                MAX_PAGES, retrieved_of(reported, total_count)))
            break

        url = "{}/devices?page={}&limit={}&view=full".format(base_url, page, limit)
        print("Fetching page:", page)
        resp = session.get(url)
        if not resp:
            print("No response for page", page)
            break
        print("Page response code:", resp.status_code)

        # Check the status before decoding, not after. json_decode has no
        # recoverable failure mode — it aborts the script — so handing it the
        # HTML error page that accompanies a 401 or a 502 would end the run
        # rather than break out of this loop.
        if resp.status_code != 200:
            break

        body = resp.body.strip() if resp.body else ""
        if not body.startswith("{") and not body.startswith("["):
            print("Non-JSON response body on page", page)
            break
        devices_body = json_decode(body)

        # The documented response is an object with a "data" array; reading .get
        # off a list would abort the script.
        if type(devices_body) != "dict":
            print("Unexpected response shape on page", page, "- wanted an object")
            break

        reported_total = devices_body.get("total_count")
        if type(reported_total) == "int" and reported_total >= 0:
            total_count = reported_total

        devices = devices_body.get("data", [])
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
                "hostnames": [device.get("hostname", "")],
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
        page += 1

    print("Total assets imported:", reported)
    return None

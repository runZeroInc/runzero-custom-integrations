# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-kandji",
    "name": "Kandji",
    "type": "inbound",
    "description": "Imports devices from Kandji.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # The repo-wide record target for a bounded walk: no integration should
    # import more than ten million records in one run, so the page ceiling is
    # that target divided by the 300-device page size.
    "maxPages": 33334,
    "params": [
        {
            "key": "url",
            "label": "Kandji API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<subdomain>.api.kandji.io/api/v1",
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
## Kandji

load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('net', 'network_interface')

PAGE_LIMIT = 300  # Number of devices to fetch per request

# CONFIG["maxPages"] bounds the walk through pager() below. The ceiling is a
# backstop, not the working guard: the walk's only exit is a page that comes
# back empty, so a Kandji that ignores `offset` -- or a proxy that replays one
# response -- would otherwise fetch the same page forever; the no-progress
# check in stream_devices catches that on the first repeat and logs the stop,
# because a truncated import that says nothing looks exactly like a complete
# one. Exhausting maxPages itself raises, naming the label and the key.

# Kandji names the device family rather than the operating system, and the set
# is closed because Kandji only manages Apple hardware. An unmapped value is
# passed through as reported rather than guessed at.
PLATFORM_OS = {
    "mac": "macOS",
    "iphone": "iOS",
    "ipad": "iPadOS",
    "appletv": "tvOS",
    "apple tv": "tvOS",
    "vision": "visionOS",
}

# The same closed device family also names the form factor for three of its
# values. "mac" is absent because it covers laptops and desktops alike and is
# refined from the hardware model below instead, and "vision" is absent because
# runZero has no device type for a headset -- inventing one would displace the
# fingerprint rather than improve it.
PLATFORM_DEVICE_TYPES = {
    "iphone": "Mobile",
    "ipad": "Tablet",
    "appletv": "Smart TV",
    "apple tv": "Smart TV",
}

# general.model is the Apple marketing name ("MacBook Pro (16-inch, 2023)",
# "Mac mini (2023)"), which names the chassis outright. Matched in order, so
# "MacBook Pro" is claimed as a laptop before "Mac Pro" can see it. A model
# that names no chassis falls through and stays unset.
MODEL_DEVICE_TYPES = [
    ("macbook", "Laptop"),
    ("imac", "Desktop"),
    ("mac mini", "Desktop"),
    ("macmini", "Desktop"),
    ("mac studio", "Desktop"),
    ("macstudio", "Desktop"),
    ("mac pro", "Desktop"),
    ("macpro", "Desktop"),
]

def _model_device_type(model):
    """Return the runZero device type named by an Apple hardware model, or an
    empty string when the model names no chassis."""
    value = str(model or "").strip().lower()
    if not value:
        return ""
    for entry in MODEL_DEVICE_TYPES:
        if entry[0] in value:
            return entry[1]
    return ""

def _section(details, key):
    """Return one object-valued section of the details document, or {} when the
    section is null, absent, or not an object -- reading .get off any of those
    would abort the script."""
    value = details.get(key)
    if type(value) != "dict":
        return {}
    return value

def _auth_headers(api_token):
    return {
        "Authorization": bearer(api_token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def _page_signature(devices):
    """A fingerprint of one page's rows, used to notice a server that answers
    every offset with the same page."""
    ids = []
    for device in devices:
        if type(device) == "dict":
            ids.append(str(device.get("device_id", "")))
        else:
            ids.append(str(device))
    return ",".join(ids)

def stream_devices(api_url, api_token, config_kwargs):
    """Fetch devices from Kandji with pagination, building and streaming each
    page of assets (including per-device details) via report_assets so the full
    device set is never held in memory. Returns the number of assets reported."""
    headers = _auth_headers(api_token)
    http_options = get_http_options(config_kwargs, headers=headers)
    reported = 0
    offset = 0
    last_signature = None
    p = pager("kandji-devices")
    while p.next():
        params = {"limit": str(PAGE_LIMIT), "offset": str(offset)}
        data, err = get_json(api_url + "/devices", params=params, **http_options)
        if err:
            print("Error fetching device list from Kandji:", err)
            break
        if not data:
            break

        # A page identical to the one before it means the server stopped
        # advancing -- an offset it ignored, or a cached response replayed --
        # and since the only exit is an empty page, the walk would otherwise
        # re-import that page until the ceiling. Stop on the first repeat.
        signature = _page_signature(data)
        if signature == last_signature:
            print("kandji: pagination stopped making progress at offset {}; the server repeated the previous page. Retrieved {} assets; the API does not report a total".format(
                offset, reported))
            break
        last_signature = signature

        reported += report_assets(build_assets(api_url, api_token, data, config_kwargs))
        offset += PAGE_LIMIT

    return reported

def get_device_details(api_url, api_token, device_id, config_kwargs):
    """Fetch detailed information for a single device."""
    url = "{}/devices/{}/details".format(api_url, device_id)
    data, err = get_json(url, **get_http_options(config_kwargs, headers=_auth_headers(api_token)))
    if err:
        print("Error fetching details for device:", device_id, err)
        return None
    # The details document is an object. A list-shaped 2xx body would abort the
    # script at the first .get, so the shape is checked rather than assumed.
    if type(data) != "dict":
        print("kandji: unexpected details shape for device {}; wanted an object".format(device_id))
        return None
    return data

def build_assets(api_url, api_token, devices, config_kwargs):
    """Transform a page of Kandji devices into runZero assets."""
    assets = []

    for device in devices:
        # A non-dict row -- null, a bare string -- would abort the script at
        # the first .get, losing the rest of the page. Skip it and say so.
        if type(device) != "dict":
            print("kandji: skipping non-object device record: " + str(device))
            continue
        device_id = device.get("device_id", "")
        # Without this, an id-less row was passed to get_device_details anyway,
        # which requested /devices//details -- a URL for no device -- and the
        # only trace was a generic "Error fetching details for device:" line with
        # an empty id in it. Skip it here, and say which record it was.
        if not device_id:
            print("kandji: skipping device with no device_id: name=" + str(device.get("device_name", "")))
            continue
        details = get_device_details(api_url, api_token, device_id, config_kwargs)
        if not details:
            continue

        general = _section(details, "general")
        network = _section(details, "network")
        hardware = _section(details, "hardware_overview")

        # network_interface() classifies v4/v6 automatically, strips
        # ports/zones, dedupes, and returns None when nothing usable
        # is present.
        #
        # public_ip is deliberately NOT included. It is the egress address of
        # whatever gateway the device is behind, so every device in an office
        # reports the same one, and pairing it with each device's own MAC
        # correlates the whole fleet onto a single address. It is kept as an
        # attribute instead.
        ips = []
        v = network.get("ip_address")
        if v:
            if type(v) == "list":
                ips.extend(v)
            else:
                ips.append(v)
        nic = network_interface(mac=network.get("mac_address"), ips=ips)
        nics = [nic] if nic else []

        # general.model is the hardware model, so assigning it to os imported
        # "MacBook Pro (16-inch, 2023)" as the operating system and left the
        # real OS out entirely. The model still reaches runZero as an attribute.
        platform = str(general.get("platform", "") or device.get("platform", "") or "").strip()
        os_name = PLATFORM_OS.get(platform.lower(), platform)

        params = {
            "id": device_id,
            "hostnames": [network.get("local_hostname", "")],
            "networkInterfaces": nics,
            "os": os_name,
            "os_version": general.get("os_version", ""),
            "customAttributes": to_custom_attributes({
                "model": general.get("model"),
                "platform": platform,
                "public_ip": network.get("public_ip"),
                "serial_number": hardware.get("serial_number"),
            }),
        }

        # The device family answers for a phone, tablet, or Apple TV; a Mac has
        # to be resolved from its model. Omitted rather than set to "" when
        # neither names a chassis, because an empty deviceType is still a value
        # and displaces the type runZero fingerprints for itself.
        device_type = PLATFORM_DEVICE_TYPES.get(platform.lower(), "")
        if not device_type:
            device_type = _model_device_type(general.get("model"))
        if device_type:
            params["deviceType"] = device_type

        assets.append(ImportAsset(**params))

    return assets

def main(**kwargs):
    api_url = kwargs['url'].rstrip('/')
    api_token = kwargs['api_token']
    # Devices (and their details) are streamed page-by-page via report_assets.
    reported = stream_devices(api_url, api_token, kwargs)
    if not reported:
        print("No assets found in Kandji")
    return None

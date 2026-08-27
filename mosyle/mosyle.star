# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-mosyle",
    "name": "Mosyle",
    "type": "inbound",
    "description": "Imports devices from Mosyle.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Mosyle API URL",
            "type": "url",
            "required": False,
            "default": "https://managerapi.mosyle.com/v2",
            "placeholder": "https://managerapi.mosyle.com/v2",
            "description": "Mosyle's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Mosyle API token (sent in headers)",
        },
        {
            "key": "email",
            "label": "Account email",
            "type": "string",
            "required": False,
            "group": "Account login",
        },
        {
            "key": "password",
            "label": "Account password",
            "type": "secret",
            "required": False,
            "group": "Account login",
        },
        {
            "key": "legacy_credentials",
            "label": "Legacy JSON credential",
            "type": "secret",
            "required": False,
            "group": "Legacy",
            "description": "Back-compat: JSON object with email and password",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset')
load('net', 'network_interface')
load('flatten_json', 'flatten')
load('kwargs', 'get_bool', 'get_http_options')
load('http', 'post_json')
load('coerce', 'as_dict', 'dicts')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_MOSYLE_API_URL = "https://managerapi.mosyle.com/v2"

# listdevices takes no page-size option -- the page size is Mosyle's to choose,
# and it serves 500 devices a page -- so the ceiling is stated in records and
# divided by that observed size. The repo-wide record target for a bounded walk
# is ten million per run: 10,000,000 / 500 = 20,000 pages, applied per OS family.
#
# The ceiling is a backstop, not the working guard. The walk's only exit is a
# page that comes back empty, so a tenant whose `page` option is ignored -- or a
# cached response replayed -- would never reach it; the no-progress check in the
# walk catches that on the first repeat. Either stop is logged, because a
# truncated import that says nothing looks exactly like a complete one.
MAX_RECORDS = 10000000
MOSYLE_PAGE_SIZE = 500
MAX_PAGES = (MAX_RECORDS + MOSYLE_PAGE_SIZE - 1) // MOSYLE_PAGE_SIZE

def page_signature(devices):
    """A fingerprint of one page's rows, used to notice a server that answers
    every page number with the same page."""
    ids = []
    for d in devices:
        ids.append(str(d.get("deviceudid") or d.get("serial_number") or ""))
    return ",".join(ids)

def parse_credentials(secret):
    """
    Parse legacy_credentials provided as a dict or JSON string containing email/username and password.
    """
    if not secret:
        return None, None

    creds = secret
    if type(secret) == "string":
        if secret.find("{") != -1:
            creds = json_decode(secret)
        else:
            print("legacy_credentials must be a JSON string with email/password")
            return None, None

    if type(creds) == "dict":
        email = creds.get("email") or creds.get("username")
        password = creds.get("password")
        if email and password:
            return email, password
        else:
            print("Missing email or password in legacy_credentials")
            return None, None

    return None, None

def get_bearer_token(session, base_url, access_token, email, password):
    """
    Perform JWT login and return the bearer token from the Authorization header.
    """
    login_url = "{}/login".format(base_url)
    payload = {
        "accessToken": access_token,
        "email": email,
        "password": password,
    }
    resp = session.post(login_url, json=payload)
    if not resp or resp.status_code != 200:
        fail("mosyle: login failed: {}".format(
            "status {}".format(resp.status_code) if resp else "no response from the server"))
    auth_header = None
    if resp.headers:
        if "Authorization" in resp.headers:
            auth_header = resp.headers.get("Authorization", None)
        elif "authorization" in resp.headers:
            auth_header = resp.headers.get("authorization", None)

    if auth_header:
        print("Login succeeded with bearer token")
        return auth_header[0].split(" ")[1]
    else:
        fail("mosyle: login succeeded but no Authorization header carried a bearer token")


# Mosyle manages Apple hardware only, and the model name is the one field that
# separates the form factors inside a platform family: the "ios" family covers
# iPhone, iPad and iPod alike, and "mac" covers both portable and desktop Macs.
# The platform family alone is therefore not enough, and a device whose model
# Mosyle has not reported yet gets no type rather than a guess -- an invented
# deviceType overrides runZero's own fingerprinting.
MODEL_DEVICE_TYPES = [
    ("ipad", "Tablet"),
    ("iphone", "Mobile"),
    ("ipod", "Mobile"),
    ("appletv", "Smart TV"),
    ("macbook", "Laptop"),
    ("imac", "Desktop"),
    ("macmini", "Desktop"),
    ("macstudio", "Desktop"),
    ("macpro", "Desktop"),
]

# tvos is asked for as its own listdevices family, so an Apple TV is known from
# the request even when the model name is missing. visionos has no counterpart
# in runZero's device-type vocabulary, so it is deliberately absent here.
OS_FAMILY_DEVICE_TYPES = {
    "tvos": "Smart TV",
}

def device_type(os_family, model):
    """Return the runZero device type for a Mosyle device, or None if unknown."""
    # Model names are spaced and cased inconsistently between the marketing
    # name ("Mac mini", "Apple TV 4K") and the model identifier ("Macmini9,1",
    # "AppleTV11,1"), so both collapse to the same key before matching. A model
    # that arrives as anything but a string would abort the run on .lower(),
    # and Starlark has no exception handling, so the type is checked first.
    if type(model) != "string":
        return OS_FAMILY_DEVICE_TYPES.get(os_family, None)
    key = model.lower().replace(" ", "").replace("-", "")
    for prefix, mapped in MODEL_DEVICE_TYPES:
        if prefix in key:
            return mapped
    return OS_FAMILY_DEVICE_TYPES.get(os_family, None)

def collect_hostnames(device):
    names = []
    for key in ["device_name", "devicename", "HostName", "LocalHostName", "hostname"]:
        name = device.get(key, "")
        # A name that arrives as anything but a string (a number, an object)
        # must not reach .replace -- a raise here would abort the whole run.
        if type(name) != "string":
            continue
        if name and name not in names:
            safe_name = name.replace(" ", "-")
            names.append(safe_name)
    return names

def parse_tags(raw_tags, asset_tag):
    tags = []
    if raw_tags and type(raw_tags) == "string":
        for chunk in raw_tags.split(","):
            for part in chunk.split():
                part = part.strip()
                if part and part not in tags:
                    tags.append(part)
    if asset_tag and asset_tag not in tags:
        tags.append(asset_tag)
    return tags if tags else None

def build_custom_attributes(device, used_keys):
    flat = flatten(device)
    attrs = {}
    for key in flat:
        if key in used_keys:
            continue
        value = flat.get(key)
        if value == None:
            continue
        attrs[key] = "{}".format(value)
    return attrs if attrs else None

def main(*args, **kwargs):
    """
    Custom integration for importing Mosyle device inventory into runZero.
    Requires api_token and legacy_credentials (JSON or dict with email/username and password).
    """
    api_token = kwargs.get("api_token")
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get("url") or DEFAULT_MOSYLE_API_URL).rstrip("/")
    email = kwargs.get("email")
    password = kwargs.get("password")
    if not email or not password:
        email, password = parse_credentials(kwargs.get("legacy_credentials"))
    if not api_token or not email or not password:
        fail("Missing required credentials")

    session = Session(insecure_skip_verify=get_bool(kwargs, 'tls_disable_validation', False))
    session.headers.set("Content-Type", "application/json")
    session.headers.set("Accept", "application/json")
    session.headers.set("User-Agent", kwargs.get("http_user_agent") or "runZeroCustomScript/1.0")

    bearer = get_bearer_token(session, base_url, api_token, email, password)
    if not bearer:
        return []

    # The device walk goes through post_json rather than the login Session:
    # it retries transient failures (429/5xx) with backoff by default, checks
    # the status, and decodes defensively, so one throttle response or a
    # non-JSON 200 body no longer truncates an OS family's import. It also
    # honors the full HTTP/TLS option sets, which the Session cannot carry.
    walk_options = get_http_options(kwargs, headers={
        "Authorization": "Bearer {}".format(bearer),
        "Accept": "application/json",
    })

    reported = 0

    for os_type in ["ios", "mac", "tvos", "visionos"]:
        print("Fetching {} devices".format(os_type))
        page = 0
        capped = True
        last_signature = None

        for _page in range(0, MAX_PAGES):
            list_url = "{}/listdevices".format(base_url)
            list_payload = {
                "accessToken": api_token,
                "options": {
                    "os": os_type,
                    "page": page,
                },
            }

            data, err = post_json(list_url, json=list_payload, **walk_options)
            if err:
                print("Device list request failed on page {}: {}".format(page, err))
                capped = False
                break

            data = as_dict(data)
            response = as_dict(data.get("response"))
            raw_devices = response.get("devices")
            if not raw_devices:
                capped = False
                break

            # dicts() keeps only the object members: one null or string row in
            # the devices array must skip, not raise on d.get and abort the run.
            devices = dicts(raw_devices)
            if type(raw_devices) == "list" and len(devices) < len(raw_devices):
                print("mosyle: skipped {} non-object device rows on {} page {}".format(
                    len(raw_devices) - len(devices), os_type, page))
            if not devices:
                capped = False
                break

            # A page identical to the one before it means Mosyle stopped
            # advancing -- a `page` option it ignored, or a cached response
            # replayed. The walk's only exit is an empty page, so it would
            # otherwise re-import that page until the ceiling. Stop on the first
            # repeat. Mosyle reports no row total, so the message says so rather
            # than printing a denominator this script invented.
            signature = page_signature(devices)
            if signature == last_signature:
                print("mosyle: pagination stopped making progress on {} at page {}; the server repeated the previous page. Retrieved {} assets; the API does not report a total".format(
                    os_type, page, reported))
                capped = False
                break
            last_signature = signature

            page_assets = []
            for d in devices:
                device_id = d.get("deviceudid") or d.get("serial_number") or ""
                if not device_id:
                    continue

                hostnames = collect_hostnames(d)

                wifi_mac = d.get("wifi_mac_address")
                eth_mac = d.get("ethernet_mac_address")
                wifi_ips = []
                if d.get("last_ip_beat"):
                    wifi_ips.append(d.get("last_ip_beat"))
                eth_ips = []
                if d.get("last_lan_ip"):
                    eth_ips.append(d.get("last_lan_ip"))

                network_interfaces = []
                
                # ips takes the address list and mac takes the MAC; these two
                # arguments were passed the other way round, so every interface
                # was built from a MAC-as-address and an address-as-MAC and no
                # device ever carried a usable address.
                if len(wifi_ips) > 0 and wifi_mac:
                    wifi_iface = network_interface(ips=wifi_ips, mac=wifi_mac)
                    if wifi_iface:
                        network_interfaces.append(wifi_iface)

                if len(eth_ips) > 0 and eth_mac:
                    eth_iface = network_interface(ips=eth_ips, mac=eth_mac)
                    if eth_iface:
                        network_interfaces.append(eth_iface)

                model = d.get("device_model_name") or d.get("model_name") or d.get("device_model") or d.get("model") or ""
                os_name = d.get("os", "")
                os_version = d.get("osversion", "")
                tags = parse_tags(d.get("tags"), d.get("asset_tag"))

                used_keys = set([
                    "deviceudid",
                    "serial_number",
                    "device_name",
                    "devicename",
                    "HostName",
                    "LocalHostName",
                    "hostname",
                    "os",
                    "osversion",
                    "wifi_mac_address",
                    "ethernet_mac_address",
                    "last_ip_beat",
                    "last_lan_ip",
                    "device_model_name",
                    "model_name",
                    "device_model",
                    "model",
                    "tags",
                    "asset_tag",
                ])
                custom_attrs = build_custom_attributes(d, used_keys)

                asset = ImportAsset(
                    id=device_id,
                    hostnames=hostnames,
                    os=os_name,
                    osVersion=os_version,
                    model=model,
                    deviceType=device_type(os_type, model),
                    networkInterfaces=network_interfaces if network_interfaces else None,
                    tags=tags,
                    customAttributes=custom_attrs,
                )
                page_assets.append(asset)

            # Build and stream each page via report_assets so the full device
            # set is never held in memory.
            reported += report_assets(page_assets)
            page += 1

        if capped:
            print("mosyle: page limit of {} hit (integration safety limit). Retrieved {} assets; the API does not report a total".format(
                MAX_PAGES, reported))

    if not reported:
        print("no assets")

    return None

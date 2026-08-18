# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-extrahop",
    "name": "ExtraHop Reveal(x)",
    "type": "inbound",
    "description": "Imports passively discovered devices from ExtraHop Reveal(x).",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # discovery_id is authoritative inside the appliance scope, and once it
    # matches, network churn cannot fragment the asset: a foreign-id match
    # is never disqualified by a conflicting MAC, IP, or name. These flags
    # therefore only govern first contact, before any id has matched.
    # name-break and ip-break are relaxed because both are wire-observed and
    # churn — the five name sources come and go with the protocols in use,
    # and DHCP reassigns the address. mac-break is kept on: the MAC is now
    # suppressed for L3 records above, so a MAC that does reach an interface
    # is genuinely that device's own and a conflict is real evidence.
    "matchBehavior": "no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "ExtraHop URL",
            "type": "url",
            "required": True,
            "placeholder": "https://sensor.example.com",
            "description": "Base URL of the sensor, RevealX Enterprise console, or the RevealX 360 API endpoint. For RevealX 360 use the hostname shown on the API Access page, without the /oauth2/token suffix.",
        },
        {
            "key": "deployment",
            "label": "Deployment type",
            "type": "enum",
            "required": True,
            "options": ["enterprise", "reveal360"],
            "default": "enterprise",
            "description": "enterprise for a sensor or RevealX Enterprise console authenticated with an API key; reveal360 for the RevealX 360 cloud console authenticated with REST API credentials.",
        },
        {
            "key": "client_id",
            "label": "RevealX 360 client ID",
            "type": "string",
            "visibleIf": "deployment",
            "visibleIfValue": "reveal360",
            "requiredIf": "deployment",
            "requiredIfValue": "reveal360",
            "description": "ID of the RevealX 360 REST API credentials.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "visibleIf": "deployment",
            "visibleIfValue": "enterprise",
            "requiredIf": "deployment",
            "requiredIfValue": "enterprise",
            "description": "API key generated on the sensor or RevealX Enterprise console.",
        },
        {
            "key": "client_secret",
            "label": "RevealX 360 client secret",
            "type": "secret",
            "visibleIf": "deployment",
            "visibleIfValue": "reveal360",
            "requiredIf": "deployment",
            "requiredIfValue": "reveal360",
            "description": "Secret of the RevealX 360 REST API credentials.",
        },
        {
            "key": "lookback_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import devices seen on the wire within this many days. Zero imports every device the system has ever discovered.",
        },
        {
            "key": "require_ip_address",
            "label": "Only import devices with an IP address",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Applies the documented ipaddr/exists filter. Disable to also import layer 2 parent devices, which are identified only by MAC address.",
        },
        {
            "key": "include_software",
            "label": "Import observed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch wire-observed software for each device. This issues one extra request per device, so leave it disabled on large estates.",
        },
        {
            "key": "page_size",
            "label": "Devices per request",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 10000,
            "description": "Value sent as the limit field of the device search body.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'post_json', 'basic', 'bearer')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'from_timestamp')

TOKEN_PATH = "/oauth2/token"
NETWORKS_PATH = "/api/v1/networks"
DEVICES_SEARCH_PATH = "/api/v1/devices/search"
DEVICE_SOFTWARE_PATH = "/api/v1/devices/{}/software"

TOKEN_BODY = "grant_type=client_credentials"

# active_from=1 with active_until=0 is ExtraHop's documented recipe for "every
# device the system has discovered": 1 is one millisecond past the epoch and 0
# means the time of the request.
ACTIVE_FROM_ALL = 1
MS_PER_DAY = 86400000

CHILD_LIMIT = 99
# get_json retries the transient statuses and honors Retry-After on its own;
# three retries is its default. Only the backoff factor is widened here.
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0

# ExtraHop assigns a role from observed traffic. The tokens come from the
# documented custom_type enum on PATCH /devices/{id}, which is the same
# vocabulary the read-only role and auto_role fields use. Anything not listed
# is passed through with underscores expanded rather than dropped.
ROLE_DEVICE_TYPE = {
    "attack_simulator": "Attack Simulator",
    "db_server": "Database Server",
    "dhcp_server": "DHCP Server",
    "dns_server": "DNS Server",
    "domain_controller": "Domain Controller",
    "file_server": "File Server",
    "firewall": "Firewall",
    "gateway": "Router",
    "http_server": "Web Server",
    "ip_camera": "IP Camera",
    "load_balancer": "Load Balancer",
    "medical_device": "Medical Device",
    "mobile_device": "Mobile Device",
    "nat_gateway": "Router",
    "pc": "Desktop",
    "printer": "Printer",
    "scanner": "Scanner",
    "voip_phone": "VoIP Phone",
    "vpn_gateway": "VPN Gateway",
    "web_proxy": "Proxy Server",
    "wifi_ap": "Wireless Access Point",
}

# Roles that carry no classification value. "other" is ExtraHop's explicit
# "unclassified" token, so mapping it to a deviceType would assert something
# the sensor did not observe.
ROLE_UNKNOWN = ["", "other"]

# Names ExtraHop synthesizes rather than observes. display_name falls back to
# default_name when nobody has renamed the device, and default_name is built
# from the vendor plus a MAC fragment ("VMware 83B4FB"), so it is metadata
# rather than a hostname.
NAME_FIELDS = ["dns_name", "custom_name", "netbios_name", "dhcp_name", "cdp_name"]


def _text(value):
    """Return a trimmed string for a JSON value, treating absent values as empty.

    Vendor-recorded samples of this API contain the literal string "None" where
    the live API returns JSON null, because the recording tool stringified
    Python None. Both forms are normalized to empty here so that neither leaks
    into a hostname, a device type, or a custom attribute.
    """
    if value == None:
        return ""
    text = str(value).strip()
    if text == "None" or text == "null":
        return ""
    return text


def _scrub(attrs):
    """Return the attribute dict with stringified nulls reduced to empty values.

    to_custom_attributes drops empty values, so normalizing here keeps "None"
    out of the imported attributes without listing every field in an exclude
    set. See _text for why the literal strings appear at all.
    """
    cleaned = {}
    for key in attrs:
        value = attrs[key]
        if type(value) == "string" and (value == "None" or value == "null"):
            continue
        cleaned[key] = value
    return cleaned


def _epoch_ms(value):
    """Convert an ExtraHop epoch-milliseconds timestamp into a time, or None.

    Device timestamps are documented as "milliseconds since the epoch". The
    field is occasionally delivered as a numeric string, so digit strings are
    accepted as well. Zero and negative values mean "never set" and yield None
    rather than a 1970 timestamp.
    """
    if value == None:
        return None
    if type(value) == "string":
        if not value.isdigit():
            return None
        value = int(value)
    if type(value) == "float":
        value = int(value)
    if type(value) != "int" or value <= 0:
        return None
    return from_timestamp(value // 1000)


def _node_key(node_id):
    """Return the dict key for a node_id, which is null on a standalone sensor."""
    if node_id == None:
        return ""
    return str(node_id)


def _hostnames(device):
    """Return the observed names for a device, de-duplicated case-insensitively.

    ExtraHop learns names from five independent wire sources plus an optional
    operator-supplied custom name, and any subset of them can be populated for
    one device. display_name is included only when it differs from
    default_name, because it mirrors default_name unless somebody renamed the
    device, and default_name is a synthesized vendor-plus-MAC label.
    """
    names = []
    seen = {}
    candidates = []
    for field in NAME_FIELDS:
        candidates.append(_text(device.get(field)))
    display_name = _text(device.get("display_name"))
    if display_name and display_name != _text(device.get("default_name")):
        candidates.append(display_name)

    for name in candidates:
        if not name:
            continue
        if seen.get(name.lower(), False):
            continue
        seen[name.lower()] = True
        names.append(name)
    return names


def _device_type(device):
    """Return a runZero device type from the ExtraHop role, or an empty string.

    role is the effective role, which is auto_role unless an operator has
    overridden it, so role is preferred and auto_role is the fallback.
    """
    for field in ["role", "auto_role"]:
        role = _text(device.get(field)).lower()
        if role in ROLE_UNKNOWN:
            continue
        mapped = ROLE_DEVICE_TYPE.get(role, "")
        if mapped:
            return mapped
        return role.replace("_", " ").title()
    return ""


def _model(device):
    """Return the most specific model string ExtraHop holds for a device."""
    for field in ["custom_model", "model_override", "model"]:
        model = _text(device.get(field))
        if model:
            return model
    return ""


def _console_link(base_url, appliance_uuid, discovery_id):
    """Return the RevealX UI deep link for a device.

    The UI addresses a device by the appliance UUID and the discovery ID joined
    with a period, which is the same pair used as this integration's identity
    scope.
    """
    return "{}/extrahop/#/metrics/devices/{}.{}/overview/".format(
        base_url, appliance_uuid, discovery_id)


def build_software(records):
    """Convert wire-observed software records into Software objects.

    ExtraHop publishes no CPE for observed software, so Software.cpe23 is never
    set. Assigning an unvalidated string there would fail the ^cpe:/a:.*
    validation the type applies.
    """
    software = []
    for record in records:
        if type(record) != "dict":
            continue
        name = _text(record.get("name"))
        if not name:
            continue
        attrs = {
            "software_type": record.get("software_type", ""),
            "description": record.get("description", ""),
        }
        software.append(Software(
            id=_text(record.get("id"))[:255] or name[:255],
            product=name[:255],
            version=_text(record.get("version"))[:255],
            # Software rows describe what the sensor saw the device speak, not
            # a listening socket, so there is no real address to report.
            serviceAddress="127.0.0.1",
            customAttributes=to_custom_attributes(_scrub(attrs), prefix="extrahop", separator="_"),
        ))
    return software


def build_asset(device, base_url, appliance_uuid, discovery_id, software):
    """Build a single ImportAsset from one ExtraHop device record."""
    # An ExtraHop L3 device is observed through a router: it inherits macaddr
    # from its L2 parent, so every host behind one router reports that router's
    # MAC. Emitting it would group unrelated hosts together by MAC, so the
    # address is suppressed for L3 records and kept as a custom attribute. Only
    # an L2 record's MAC is genuinely its own.
    mac = _text(device.get("macaddr"))
    if device.get("is_l3"):
        mac = ""
    nic = network_interface(
        mac=mac,
        ips=[_text(device.get("ipaddr4")), _text(device.get("ipaddr6"))],
    )
    netifs = [nic] if nic else []

    tags = ["extrahop"]
    analysis = _text(device.get("analysis"))
    if analysis:
        tags.append("analysis:" + analysis)
    if device.get("on_watchlist", False) == True:
        tags.append("watchlist")
    if device.get("critical", False) == True:
        tags.append("high-value")

    attrs = {
        "discovery_id": discovery_id,
        # The numeric id is scoped to one sensor and changes per sensor for the
        # same physical device, so it is recorded for support lookups but is
        # deliberately not part of the asset identity.
        "device_id": device.get("id", ""),
        "extrahop_id": device.get("extrahop_id", ""),
        "appliance_uuid": appliance_uuid,
        "node_id": device.get("node_id", ""),
        "parent_id": device.get("parent_id", ""),
        "url": _console_link(base_url, appliance_uuid, discovery_id),
        "device_class": device.get("device_class", ""),
        "role": device.get("role", ""),
        "auto_role": device.get("auto_role", ""),
        "default_name": device.get("default_name", ""),
        "display_name": device.get("display_name", ""),
        "description": device.get("description", ""),
        "vlan_id": device.get("vlanid", ""),
        "subnet_id": device.get("subnet_id", ""),
        "analysis": analysis,
        "analysis_level": device.get("analysis_level", ""),
        "is_l3": device.get("is_l3", ""),
        "on_watchlist": device.get("on_watchlist", ""),
        "critical": device.get("critical", ""),
        "custom_criticality": device.get("custom_criticality", ""),
        "activity": device.get("activity", ""),
        "cloud_account": device.get("cloud_account", ""),
        "cloud_instance_id": device.get("cloud_instance_id", ""),
        "cloud_instance_name": device.get("cloud_instance_name", ""),
        "cloud_instance_type": device.get("cloud_instance_type", ""),
        "vpc_id": device.get("vpc_id", ""),
        "user_mod_time": device.get("user_mod_time", ""),
    }

    asset_args = {
        "id": "extrahop:{}:{}".format(appliance_uuid, discovery_id),
        "hostnames": _hostnames(device),
        "networkInterfaces": netifs,
        "manufacturer": _text(device.get("vendor")),
        "model": _model(device),
        "tags": tags,
        "software": software[:CHILD_LIMIT],
        # prefix is joined to each key with separator, so this yields
        # "extrahop_discovery_id" rather than "extrahop_.discovery_id".
        "customAttributes": to_custom_attributes(_scrub(attrs), prefix="extrahop", separator="_"),    }

    device_type = _device_type(device)
    if device_type:
        asset_args["deviceType"] = device_type

    first_seen = _epoch_ms(device.get("discover_time"))
    if first_seen:
        asset_args["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_args)

    # last_seen_time is the device's own last-activity timestamp and is the
    # correct last-seen signal; mod_time is when the record last changed, which
    # tracks activity closely and covers systems that leave last_seen_time
    last_seen = _epoch_ms(device.get("last_seen_time"))
    if not last_seen:
        last_seen = _epoch_ms(device.get("mod_time"))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(devices, base_url, http_options, appliance_uuids, seen, include_software):
    """Build one page of ImportAssets, skipping devices already seen this run.

    The device search is paged with limit and offset over a live inventory that
    has no documented sort order, so a device can surface in more than one page.
    Only the discovery IDs are retained between pages, never the device records.
    """
    assets = []
    for device in devices:
        if type(device) != "dict":
            print("extrahop: skipping malformed device record")
            continue

        discovery_id = _text(device.get("discovery_id"))
        if not discovery_id:
            print("extrahop: skipping device with no discovery_id: device_id=" + _text(device.get("id")))
            continue

        node_key = _node_key(device.get("node_id"))
        appliance_uuid = appliance_uuids.get(node_key, "")
        if not appliance_uuid:
            print("extrahop: skipping device with no appliance UUID: discovery_id={} node_id={}".format(
                discovery_id, node_key))
            continue

        asset_key = appliance_uuid + "." + discovery_id
        if seen.get(asset_key, False):
            continue
        seen[asset_key] = True

        software = []
        if include_software:
            software = fetch_software(base_url, http_options, device.get("id"))

        assets.append(build_asset(device, base_url, appliance_uuid, discovery_id, software))
    return assets


def fetch_software(base_url, http_options, device_id):
    """Fetch the software observed on one device.

    The software sub-resource is keyed by the numeric device id rather than the
    discovery ID, because that is what the documented path parameter takes.
    """
    if device_id == None or device_id == "":
        return []
    url = base_url + DEVICE_SOFTWARE_PATH.format(device_id)
    data, err = get_json(url, **http_options)
    if err:
        print("extrahop: failed to fetch software for device {}: {}".format(device_id, err))
        return []
    return build_software(data or [])


def fetch_access_token(base_url, kwargs, client_id, client_secret):
    """Exchange RevealX 360 REST API credentials for a bearer token.

    The token endpoint takes a client_credentials grant as a form body and
    authenticates the client with HTTP Basic, so it is issued directly rather
    than through the generic oauth2_token helper, which does not document where
    it places the client credentials.
    """
    options = get_http_options(kwargs, headers={
        "Authorization": basic(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    options["retries"] = HTTP_RETRIES
    options["retry_backoff"] = HTTP_RETRY_BACKOFF

    data, err = post_json(base_url + TOKEN_PATH, body=bytes(TOKEN_BODY), **options)
    if err:
        print("extrahop: failed to obtain a RevealX 360 access token:", err)
        if err.startswith("status 401") or err.startswith("status 403"):
            print("extrahop: check the RevealX 360 client ID and secret")
        return ""
    data = data or {}
    token = _text(data.get("access_token"))
    if not token:
        print("extrahop: RevealX 360 token response contained no access_token")
    return token


def build_authorization(base_url, kwargs, deployment):
    """Return the Authorization header value for the configured deployment."""
    if deployment == "reveal360":
        client_id = get_string(kwargs, "client_id", default="")
        client_secret = get_string(kwargs, "client_secret", default="")
        if not client_id or not client_secret:
            print("extrahop: the reveal360 deployment requires client_id and client_secret")
            return ""
        token = fetch_access_token(base_url, kwargs, client_id, client_secret)
        if not token:
            return ""
        return bearer(token)

    api_key = get_string(kwargs, "api_key", default="")
    if not api_key:
        print("extrahop: the enterprise deployment requires api_key")
        return ""
    return "ExtraHop apikey=" + api_key


def fetch_appliance_uuids(base_url, http_options):
    """Map each node_id to its appliance UUID, or return None when unavailable.

    A console returns one network per connected sensor; a standalone sensor
    returns a single network whose node_id is null, which is keyed here as the
    empty string so that devices reporting a null node_id resolve to it.
    """
    data, err = get_json(base_url + NETWORKS_PATH, **http_options)
    if err:
        print("extrahop: failed to fetch networks:", err)
        if err.startswith("status 401") or err.startswith("status 403"):
            print("extrahop: check the credential and its privilege level")
        return None

    uuids = {}
    for network in data or []:
        if type(network) != "dict":
            continue
        appliance_uuid = _text(network.get("appliance_uuid"))
        if not appliance_uuid:
            continue
        uuids[_node_key(network.get("node_id"))] = appliance_uuid

    if not uuids:
        print("extrahop: no appliance UUIDs returned by", NETWORKS_PATH)
        return None
    return uuids


def build_search_body(page_size, offset, lookback_days, require_ip_address):
    """Build the POST /devices/search body for one page.

    A negative active_from is evaluated relative to the current time in
    milliseconds, so the lookback window is expressed directly in that form.
    """
    body = {
        "limit": page_size,
        "offset": offset,
        "active_until": 0,
    }
    if lookback_days > 0:
        body["active_from"] = -1 * lookback_days * MS_PER_DAY
    else:
        body["active_from"] = ACTIVE_FROM_ALL
    if require_ip_address:
        body["filter"] = {
            "operator": "and",
            "rules": [{"field": "ipaddr", "operator": "exists"}],
        }
    return body


def fetch_and_report_devices(base_url, http_options, appliance_uuids, page_size,
                             lookback_days, require_ip_address, include_software):
    """Fetch and stream devices one page at a time so the full set is never
    held in memory at once."""
    reported = 0
    offset = 0
    seen = {}
    url = base_url + DEVICES_SEARCH_PATH

    _pager = pager("extrahop")

    while _pager.next():
        body = build_search_body(page_size, offset, lookback_days, require_ip_address)
        data, err = post_json(url, json=body, **http_options)
        if err:
            print("extrahop: failed to fetch devices:", err)
            if err.startswith("status 401") or err.startswith("status 403"):
                print("extrahop: check the credential and its privilege level")
            return reported
        # The endpoint returns a bare JSON array, and an empty 2xx body decodes
        # to None.
        devices = data or []
        if type(devices) != "list":
            print("extrahop: unexpected device search response shape")
            return reported
        if not devices:
            break

        assets = build_assets(devices, base_url, http_options, appliance_uuids,
                              seen, include_software)
        if assets:
            reported += report_assets(assets)

        if len(devices) < page_size:
            break
        offset += page_size

    print("extrahop: reported {} devices".format(reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    deployment = get_string(kwargs, "deployment", default="enterprise")
    lookback_days = get_int(kwargs, "lookback_days", default=0)
    require_ip_address = get_bool(kwargs, "require_ip_address", default=True)
    include_software = get_bool(kwargs, "include_software", default=False)
    page_size = get_int(kwargs, "page_size", default=1000)

    authorization = build_authorization(base_url, kwargs, deployment)
    if not authorization:
        return None

    http_options = get_http_options(kwargs, headers={
        "Authorization": authorization,
        "Accept": "application/json",
    })
    http_options["retries"] = HTTP_RETRIES
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    # The appliance UUID is the uniqueness scope for a discovery ID, so it is
    # resolved before any asset is built. Falling back to another scope token
    # would re-identify every asset on the next run, so the run stops instead.
    appliance_uuids = fetch_appliance_uuids(base_url, http_options)
    if appliance_uuids == None:
        print("extrahop: cannot resolve appliance UUIDs, no assets imported")
        return None

    reported = fetch_and_report_devices(base_url, http_options, appliance_uuids,
                                        page_size, lookback_days,
                                        require_ip_address, include_software)
    if not reported:
        print("extrahop: no assets retrieved")
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-palo-alto-device-security",
    "name": "Palo Alto Networks Device Security",
    "type": "inbound",
    "description": "Imports devices and vulnerabilities from Palo Alto Networks Device Security.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # deviceid is not an opaque device key: IoT Security documents it as the
    # device's MAC address, or its IP address for static-IP-only devices. An
    # address-derived id must not drive matching, because a foreign-id match
    # is never disqualified by a conflicting MAC, IP, or hostname — so a
    # static IP reassigned to a different device would merge that device
    # into the original asset with nothing able to veto it. Correlate on the
    # MAC, IP, and hostname the record already carries instead, as
    # aruba-clearpass and forescout-counteract do with the same identifier
    # class. The id is still emitted so the record has a stable key.
    "matchBehavior": "no-id-match no-id-break",
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "Device Security API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://api.strata.paloaltonetworks.com",
            "description": "Base URL of the IoT public API.",
        },
        {
            "key": "auth_url",
            "label": "Strata Cloud Manager auth URL",
            "type": "url",
            "required": False,
            "default": "https://auth.apps.paloaltonetworks.com",
            "description": "Base URL of the OAuth2 token service.",
        },
        {
            "key": "tsg_id",
            "label": "Tenant Service Group ID",
            "type": "string",
            "required": True,
            "description": "Strata Cloud Manager TSG ID requested as the token scope.",
        },
        {
            "key": "client_id",
            "label": "Service account client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "Service account client secret",
            "type": "secret",
            "required": True,
        },
        {
            "key": "lookback_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 30,
            "min": 0,
            "description": "Only import devices active, and vulnerabilities detected, within this many days. Set to 0 to import the entire inventory with no time filter.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'ip_address')
load('http', 'get_json', 'post_json', 'bearer', 'basic', 'url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int')
load('time', 'now', 'parse_time', 'parse_duration', 'parse_ts')
load('re', re_match='match')

TOKEN_PATH = "/oauth2/access_token"
DEVICE_PATH = "/iot/pub/v2/device/list"
VULNERABILITY_PATH = "/iot/pub/v1/vulnerability/list"

# The documented maximum pagelength is 1000 for both endpoints. The vulnerability
# docs recommend a smaller page for large tenants because each item carries the
# full device context.
DEVICE_PAGE_SIZE = 500
VULNERABILITY_PAGE_SIZE = 100

# Both endpoints are rate limited to 60 requests per minute, so let the shared
# HTTP helper absorb 429/5xx with its own backoff instead of failing the task.
RETRIES = 3

MAX_VULNS_PER_ASSET = 99
ATTR_PREFIX = "panw_device_security"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_SCORE = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}

# Hostnames that identify nothing. Every device whose name the sensor never
# learned carries the same one, so importing them merges unrelated assets.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none",
                     "null", "-", "n/a", "*"]

# Device attributes copied verbatim into custom attributes. The v2 inventory
# returns every field published by /iot/pub/v1/device/attributes when no
# projection is requested, and field spellings differ between tenant
# generations, so both spellings are listed where they are known to vary.
DEVICE_ATTR_FIELDS = [
    "deviceid",
    "profile",
    "profile_type",
    "profile_vertical",
    "category",
    "display_profile_category",
    "vlan",
    "subnet",
    "site_name",
    "siteid",
    "location",
    "dnac_location",
    "department",
    "asset_tag",
    "display_tags",
    "description",
    "display_desc",
    "risk_score",
    "risk_level",
    "confidence_score",
    "Serial_Number",
    "sn",
    "Switch_Name",
    "Switch_IP",
    "Switch_Port",
    "Access_Point_Name",
    "Access_Point_IP",
    "SSID",
    "wire_or_wireless",
    "DHCP",
    "config_source",
    "os_support",
    "os_end_of_support",
    "osCombined",
    "osVerFirmwareVer",
    "EPP",
    "trafficRestricted",
    "first_seen_date",
    "last_activity",
    "attr",
]

# Vulnerability instance fields that describe the device the finding sits on,
# mapped onto the inventory field names so one asset builder serves both.
VULN_DEVICE_FIELDS = {
    "deviceid": "deviceid",
    "name": "hostname",
    "ip": "ip_address",
    "vendor": "vendor",
    "model": "model",
    "os": "osGroup",
    "osCombined": "osCombined",
    "sn": "sn",
    "profile": "profile",
    "profile_vertical": "profile_vertical",
    "display_profile_category": "category",
    "asset_tag": "asset_tag",
    "siteid": "siteid",
    "risk_score": "risk_score",
    "risk_level": "risk_level",
    "date": "last_activity",
}


def _first(record, keys):
    """Return the first populated value among alternate vendor field names."""
    for key in keys:
        value = record.get(key)
        if value != None and value != "":
            return value
    return ""


def _hostname(value):
    """Return a value fit to import as a hostname, or "".

    IoT Security fills hostname with the device's IP address when it never
    learned a real name, and an IP-as-hostname is a merge hazard: the same
    string lands on whichever device holds the address next.
    """
    text = str(value or "").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text
def _start_time(lookback_days):
    """Build the stime bound; an empty string means no time filter at all."""
    if lookback_days <= 0:
        return ""
    cutoff = now() + parse_duration("-{}h".format(lookback_days * 24))
    return cutoff.format("2006-01-02T15:04:05Z")


def _device_from_vulnerability(item):
    """Project a vulnerability instance onto the inventory device field names."""
    device = {}
    for source, target in VULN_DEVICE_FIELDS.items():
        value = item.get(source)
        if value != None and value != "":
            device[target] = value
    return device


def build_vulnerability(item):
    """Convert one vulnerability instance into a runZero Vulnerability."""
    ticket_id = str(item.get("zb_ticketid", ""))
    name = str(item.get("vulnerability_name", ""))
    if not ticket_id and not name:
        return None

    level = str(item.get("risk_level", "")).upper()
    rank = SEVERITY_RANK.get(level, 0)
    score = SEVERITY_SCORE.get(level, 0.0)

    params = {
        "id": ticket_id or name,
        "name": name,
        "severityRank": rank,
        "severityScore": float(score),
        "riskRank": rank,
        "riskScore": float(score),
        "customAttributes": to_custom_attributes({
            "ticket_id": ticket_id,
            "ticket_state": item.get("ticketState"),
            "risk_level": item.get("risk_level"),
            "risk_score": item.get("risk_score"),
            "remediate_workorder": item.get("remediate_workorder"),
            "detected_date": item.get("detected_date"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    if re_match(CVE_PATTERN, name):
        params["cve"] = name

    solution = item.get("remediate_instruction", "")
    if solution:
        params["solution"] = str(solution)[:1024]

    detected = parse_ts(item.get("detected_date"))
    if detected:
        params["firstDetectedTS"] = detected

    return Vulnerability(**params)


def build_asset(device, vulns, tsg_id):
    """Convert one Device Security device into a runZero ImportAsset."""
    device_id = str(device.get("deviceid", "")).strip()
    if not device_id:
        print("palo-alto-device-security: skipping device with no deviceid: hostname=" + str(device.get("hostname", "")))
        return None

    raw_ip = _first(device, ["ip_address", "ip"])
    ips = []
    if type(raw_ip) == "list":
        for entry in raw_ip:
            ips.append(str(entry))
    elif raw_ip:
        ips.append(str(raw_ip))

    # routable_ips drops loopback, unspecified, and link-local values: an
    # APIPA address a device invents when DHCP fails identifies nothing and
    # would correlate unrelated hosts to each other.
    nic = network_interface(mac=str(_first(device, ["mac_address", "MAC", "mac"])), ips=routable_ips(ips))
    netifs = [nic] if nic else []

    tags = []
    site = str(_first(device, ["site_name", "siteName"]))
    if site:
        tags.append("site:" + site)
    profile = str(device.get("profile", ""))
    if profile:
        tags.append("profile:" + profile)
    risk_level = str(device.get("risk_level", ""))
    if risk_level:
        tags.append("risk:" + risk_level)
    for tag in device.get("allTags", []) or []:
        if type(tag) == "dict" and tag.get("tagValue"):
            tags.append(str(tag.get("tagValue")))

    attrs = {}
    for key in DEVICE_ATTR_FIELDS:
        attrs[key] = device.get(key)
    # Tenant-defined attributes arrive as a list of single-key objects, for
    # example [{"Purdue Level": "Level 0"}, {"Asset Criticality": "High"}].
    for entry in device.get("customAttributes", []) or []:
        if type(entry) == "dict":
            for key, value in entry.items():
                attrs[key] = value
    if vulns:
        attrs["vulnerability_count"] = len(vulns)

    params = {
        "id": "palo-alto-device-security:{}:{}".format(tsg_id, device_id),
        # _hostname rejects placeholder names and values that are really IP
        # addresses, which this API reports for devices with no real name.
        "hostnames": [_hostname(device.get("hostname"))],
        "networkInterfaces": netifs,
        "tags": tags,
        "vulnerabilities": vulns[:MAX_VULNS_PER_ASSET],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),    }

    os_name = _first(device, ["osGroup", "os_group", "os"])
    if os_name:
        params["os"] = str(os_name)
    os_version = _first(device, ["os_ver", "os_version", "osVersion"])
    if os_version:
        params["osVersion"] = str(os_version)
    vendor = device.get("vendor", "")
    if vendor:
        params["manufacturer"] = str(vendor)
    model = device.get("model", "")
    if model:
        params["model"] = str(model)
    # category is the coarse device class ("Infusion System", "Camera");
    # profile is the make/model-specific classification and stays an attribute.
    category = _first(device, ["category", "display_profile_category"])
    if category:
        params["deviceType"] = str(category)

    first_seen = parse_ts(_first(device, ["first_seen_date", "firstSeenDate"]))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = parse_ts(_first(device, ["last_activity", "date"]))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(devices, vuln_index, tsg_id):
    """Build a page of assets, consuming any indexed findings for each device."""
    assets = []
    for device in devices:
        device_id = str(device.get("deviceid", "")).strip()
        entry = vuln_index.pop(device_id, None) if device_id else None
        asset = build_asset(device, entry["vulns"] if entry else [], tsg_id)
        if asset:
            assets.append(asset)
    return assets


def fetch_access_token(auth_url, tsg_id, client_id, client_secret, config_kwargs):
    """Exchange Strata Cloud Manager client credentials for a bearer token."""
    options = get_http_options(config_kwargs, headers={
        "Authorization": basic(client_id, client_secret),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    options["retries"] = RETRIES

    body = url_encode({"grant_type": "client_credentials", "scope": "tsg_id:" + tsg_id})
    data, err = post_json(auth_url + TOKEN_PATH, body=bytes(body), **options)
    if err:
        print("palo-alto-device-security: failed to obtain an access token:", err)
        return ""

    data = data or {}
    token = data.get("access_token", "")
    if not token:
        print("palo-alto-device-security: token response contained no access_token")
    return token


def _api_options(config_kwargs, token):
    """Collect the HTTP options used for every API call under a given token."""
    options = get_http_options(config_kwargs, headers={
        "Authorization": bearer(token),
        "Accept": "application/json",
    })
    options["retries"] = RETRIES
    return options


def fetch_json(ctx, url, params):
    """GET one API page, re-minting the access token once on a 401.

    Strata Cloud Manager access tokens expire after roughly 15 minutes and
    both endpoints are capped at 60 requests per minute, so a large tenant's
    run outlives its first token. A 401 mid-run therefore means the token
    aged out rather than that the credential is wrong: one refresh and one
    retry of the failed request keeps the walk going."""
    for attempt in range(2):
        data, err = get_json(url, params=params, **ctx["http_options"])
        if not err:
            return data, None
        if err.startswith("status 401") and attempt == 0:
            print("palo-alto-device-security: access token rejected mid-run, requesting a new one")
            token = fetch_access_token(ctx["auth_url"], ctx["tsg_id"], ctx["client_id"],
                                       ctx["client_secret"], ctx["kwargs"])
            if token:
                ctx["http_options"] = _api_options(ctx["kwargs"], token)
                continue
        return None, err
    return None, "unreachable"


def fetch_vulnerability_index(ctx, stime):
    """Index confirmed vulnerability instances by device id, keeping only the
    findings and the device context needed to attach them to an asset."""
    index = {}
    kept = 0
    offset = 0

    p = pager("vulnerabilities")
    while p.next():
        params = {
            "type": "vulnerability",
            "status": "Confirmed",
            "groupby": "device",
            "offset": offset,
            "pagelength": VULNERABILITY_PAGE_SIZE,
        }
        if stime:
            params["stime"] = stime

        data, err = fetch_json(ctx, ctx["base_url"] + VULNERABILITY_PATH, params)
        if err:
            print("palo-alto-device-security: failed to fetch vulnerabilities:", err)
            return index

        data = data or {}
        items = data.get("items", []) or []
        if type(items) != "list":
            print("palo-alto-device-security: unexpected vulnerability payload, skipping findings")
            return index
        if not items:
            break

        for item in items:
            device_id = str(item.get("deviceid", "")).strip()
            if not device_id:
                continue
            vuln = build_vulnerability(item)
            if not vuln:
                continue
            entry = index.get(device_id)
            if not entry:
                entry = {"device": _device_from_vulnerability(item), "vulns": []}
                index[device_id] = entry
            if len(entry["vulns"]) < MAX_VULNS_PER_ASSET:
                entry["vulns"].append(vuln)
                kept += 1

        if len(items) < VULNERABILITY_PAGE_SIZE:
            break
        offset += VULNERABILITY_PAGE_SIZE

    print("palo-alto-device-security: indexed {} vulnerabilities across {} devices".format(kept, len(index)))
    return index


def fetch_and_report_devices(ctx, stime, vuln_index):
    """Fetch and stream devices one page at a time so the full inventory is
    never held in memory at once."""
    reported = 0
    offset = 0

    p = pager("devices")
    while p.next():
        params = {"offset": offset, "pagelength": DEVICE_PAGE_SIZE, "sortdirection": "asc"}
        if stime:
            params["stime"] = stime

        data, err = fetch_json(ctx, ctx["base_url"] + DEVICE_PATH, params)
        if err:
            print("palo-alto-device-security: failed to fetch devices:", err)
            return reported

        data = data or {}
        devices = data.get("devices", []) or []
        if not devices:
            break

        reported += report_assets(build_assets(devices, vuln_index, ctx["tsg_id"]))
        if len(devices) < DEVICE_PAGE_SIZE:
            break
        offset += DEVICE_PAGE_SIZE

    return reported


def report_unmatched_vulnerabilities(vuln_index, tsg_id):
    """Report assets for devices that carry findings but never appeared in the
    inventory page set, so their vulnerabilities are not silently dropped."""
    reported = 0

    for _device_id, entry in vuln_index.items():
        asset = build_asset(entry["device"], entry["vulns"], tsg_id)
        if not asset:
            continue
        reported += report_asset(asset)
    if reported:
        print("palo-alto-device-security: reported {} devices seen only in vulnerability data".format(reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    auth_url = get_url_base(kwargs, "auth_url")
    tsg_id = get_string(kwargs, "tsg_id")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    lookback_days = get_int(kwargs, "lookback_days", default=30)

    token = fetch_access_token(auth_url, tsg_id, client_id, client_secret, kwargs)
    if not token:
        return None

    ctx = {
        "base_url": base_url,
        "auth_url": auth_url,
        "tsg_id": tsg_id,
        "client_id": client_id,
        "client_secret": client_secret,
        "kwargs": kwargs,
        "http_options": _api_options(kwargs, token),
    }

    stime = _start_time(lookback_days)
    if not stime:
        print("palo-alto-device-security: lookback disabled, importing the full inventory")

    vuln_index = fetch_vulnerability_index(ctx, stime)
    reported = fetch_and_report_devices(ctx, stime, vuln_index)
    reported += report_unmatched_vulnerabilities(vuln_index, tsg_id)

    if not reported:
        print("palo-alto-device-security: no assets retrieved")
    return None

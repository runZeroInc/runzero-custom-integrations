# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-slurpit",
    "name": "Slurp'it",
    "type": "inbound",
    "description": "Imports discovered network devices from a self-hosted Slurp'it instance, with site, vendor, and SNMP location context.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "maxPages": 10000,
    "params": [
        {
            "key": "url",
            "label": "Slurp'it URL",
            "type": "url",
            "required": True,
            "placeholder": "https://slurpit.example.com",
            "description": "Base URL of the Slurp'it portal. The /api path is appended automatically. Include a path prefix only if the portal is reverse-proxied under one.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Slurp'it API key, created under Settings -> API keys. Sent as an Authorization: Bearer credential.",
        },
        {
            "key": "include_disabled",
            "label": "Include disabled devices",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import devices Slurp'it has flagged disabled. Slurp'it disables a device automatically after it has been unreachable for the configured number of days, so these are largely departed hardware.",
        },
        {
            "key": "collect_sites",
            "label": "Collect site details",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /api/sites once and attach each device's street, city, and country to its asset. One extra request per run.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 512,
            "min": 1,
            "max": 10000,
            "description": "Devices requested per call. Slurp'it's own SDK defaults to 1000; its NetBox plugin uses 512.",
        },
        {
            "key": "max_devices",
            "label": "Maximum devices",
            "type": "int",
            "required": False,
            "default": 50000,
            "min": 0,
            "description": "Cap on devices imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", "bearer", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", "parse_time", 'parse_ts')

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "slurpit"
ATTR_PREFIX = "slurpit"
ATTR_SEPARATOR = "_"

DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-", "n/a"]

# Slurp'it's free tier discovers an unlimited number of devices but only PARSES
# data for a licensed count. Beyond that count the portal substitutes these
# literals into the field rather than leaving it blank, so they must be
# screened or they become a serial number and an OS version on every asset.
LICENSE_PLACEHOLDERS = [
    "license required",
    "license limit reached",
    "license expired",
]

# Slurp'it's device_type is free text from its vendor templates.
DEVICE_TYPE_MAP = {
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "wireless": "Wireless Access Point",
    "accesspoint": "Wireless Access Point",
    "access point": "Wireless Access Point",
    "loadbalancer": "Load Balancer",
    "load balancer": "Load Balancer",
    "server": "Server",
    "storage": "Storage",
}
def _to_int(value):
    if type(value) == "int":
        return value
    text = as_text(value, join=",").strip()
    if not text or len(text) > 12:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _clean(value):
    """A field value with Slurp'it's license placeholders removed."""
    text = as_text(value, join=",").strip()
    if not text or text.lower() in LICENSE_PLACEHOLDERS:
        return ""
    return text


def _truthy(value):
    """Slurp'it sends booleans as the STRINGS '0' and '1', not as JSON bools."""
    if type(value) == "bool":
        return value
    text = as_text(value, join=",").strip().lower()
    return text in ["1", "true", "yes", "on"]
def _hostname(value):
    text = _clean(value).rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text
def _scope(base_url):
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used: it discards the path, which breaks a
    portal reached through a reverse proxy mounted under a prefix. /api is
    appended to whatever is configured, which is exactly what Slurp'it's own
    SDK does with its base_url.
    """
    return as_text(url, join=",").strip().rstrip("/")


def fetch(ctx, path, params):
    """GET one Slurp'it endpoint.

    /api/devices, /api/sites, and /api/planning all answer with a BARE JSON
    ARRAY - no envelope, no total count. Some other endpoints wrap their rows
    in {"rows": [...]}, so both shapes are accepted.
    """
    url = ctx["base_url"] + "/api" + path
    data, err = get_json(url, params=params, **ctx["http_options"]) if params else get_json(url, **ctx["http_options"])
    if err:
        if "401" in err or "403" in err:
            print("slurpit: {} was rejected: {}. Check the API key and that it has not been revoked.".format(path, err))
            return None
        print("slurpit: {} failed: {}".format(path, err))
        return None
    if type(data) == "list":
        return dicts(data)
    if type(data) == "dict":
        rows = data.get("rows")
        if type(rows) == "list":
            return dicts(rows)
        print("slurpit: {} returned an object where a list was expected".format(path))
        return None
    print("slurpit: {} returned an unexpected shape".format(path))
    return None


def preflight(ctx):
    """Confirm the portal is reachable and the key is accepted.

    GET /api/platform/ping answers {"status": "up"}. It is the same check
    Slurp'it's own NetBox plugin makes before a sync.
    """
    url = ctx["base_url"] + "/api/platform/ping"
    data, err = get_json(url, **ctx["http_options"])
    if err:
        if "401" in err or "403" in err:
            print("slurpit: the API key was rejected by /api/platform/ping: {}. ".format(err) +
                  "Create a key under Settings -> API keys and confirm it is active.")
        elif "404" in err:
            print("slurpit: /api/platform/ping returned 404. Check that the URL points at the " +
                  "Slurp'it portal itself and includes any path prefix it is proxied under.")
        else:
            print("slurpit: /api/platform/ping failed:", err)
        return False
    if type(data) == "dict":
        status = as_text(data.get("status"), join=",").strip().lower()
        if status and status != "up":
            print("slurpit: the portal reports status '{}' rather than 'up'; continuing anyway".format(status))
    return True


def collect_sites(ctx):
    """Read the site table once and index it by site name.

    A device carries `site` as a NAME string rather than an id, so the index is
    keyed on sitename.
    """
    rows = fetch(ctx, "/sites", None)
    if not rows:
        return {}
    index = {}
    for row in rows:
        name = as_text(row.get("sitename"), join=",").strip()
        if not name:
            continue
        index[name.lower()] = {
            "description": row.get("description"),
            "street": row.get("street"),
            "city": row.get("city"),
            "county": row.get("county"),
            "state": row.get("state"),
            "zipcode": row.get("zipcode"),
            "country": row.get("country"),
            "status": row.get("status"),
        }
    return index


def build_asset(ctx, record):
    """Convert one Slurp'it device into a runZero asset."""
    device_id = as_text(record.get("id"), join=",").strip()
    if not device_id:
        print("slurpit: skipping device row with no id")
        return None

    ip = routable_ip(record.get("address"))
    hostname = _hostname(record.get("hostname"))
    fqdn = _hostname(record.get("fqdn"))

    if not ip and not hostname and not fqdn:
        print("slurpit: skipping device {} with no usable address or hostname".format(device_id))
        return None

    # Slurp'it discovers over SSH/telnet and does not report a device MAC on
    # the device record itself, so the management address is the only
    # correlator besides the name.
    nic = network_interface(ips=[ip] if ip else [])

    site_name = as_text(record.get("site"), join=",").strip()
    site = ctx["sites"].get(site_name.lower(), {})

    tag_values = []
    raw_tags = record.get("tags")
    if type(raw_tags) == "list":
        tag_values = dedupe(raw_tags)
    else:
        for part in as_text(raw_tags, join=",").split(","):
            value = part.strip()
            if value:
                tag_values.append(value)

    brand = _clean(record.get("brand"))
    device_os = _clean(record.get("device_os"))
    os_version = _clean(record.get("os_version"))
    serial = _clean(record.get("serial"))
    device_type = _clean(record.get("device_type"))

    attrs = {
        "device_id": device_id,
        "hostname": record.get("hostname"),
        "fqdn": record.get("fqdn"),
        "address": record.get("address"),
        "family": record.get("family"),
        "brand": brand,
        "device_os": device_os,
        "os_version": os_version,
        "serial": serial,
        "device_type": device_type,
        "description": record.get("description"),
        "site": site_name,
        "group_name": record.get("group_name"),
        "parent": record.get("parent"),
        "port": record.get("port"),
        "telnet": record.get("telnet"),
        "disabled": _truthy(record.get("disabled")),
        "blacklisted": _truthy(record.get("blacklisted")),
        "tags": tag_values,
        "snmp_contact": record.get("snmp_contact"),
        "snmp_location": record.get("snmp_location"),
        "snmp_description": record.get("snmp_description"),
        "snmp_uptime": record.get("snmp_uptime"),
        "snmp_port": record.get("snmp_port"),
        # Raw timestamps are kept verbatim because the parsed values are
        # clamped to now: Slurp'it writes local time with no zone.
        "added_raw": record.get("added"),
        "last_seen_raw": record.get("last_seen"),
        "createddate_raw": record.get("createddate"),
        "changeddate_raw": record.get("changeddate"),
        "site_street": site.get("street"),
        "site_city": site.get("city"),
        "site_country": site.get("country"),
        "site_description": site.get("description"),
        "slurpit_host": ctx["scope"],
    }

    tags = [VENDOR]
    if site_name:
        tags.append("site:" + site_name)
    if brand:
        tags.append("brand:" + brand)
    if _truthy(record.get("disabled")):
        tags.append("slurpit-disabled")
    for value in tag_values:
        tags.append("slurpit-tag:" + value)
    # ImportAsset has no serial field, so the chassis serial is carried as an
    # attribute and as a tag.
    if serial:
        tags.append("serial:" + serial)

    params = {
        # Slurp'it's device id is an integer primary key on the portal's own
        # device table. It survives a re-scan - Slurp'it updates rows rather
        # than recreating them, and ages an unreachable device out by flipping
        # `disabled` first - which is why Slurp'it's own NetBox and Nautobot
        # plugins reconcile on it rather than on hostname.
        "id": "{}:{}:device:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": dedupe([hostname, fqdn]),
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    if brand:
        params["manufacturer"] = brand
    if device_os:
        params["os"] = device_os
    if os_version:
        params["osVersion"] = os_version
    mapped = DEVICE_TYPE_MAP.get(device_type.lower(), "")
    if mapped:
        params["deviceType"] = mapped

    asset = ImportAsset(**params)
    created = parse_ts(record.get("createddate")) or parse_ts(record.get("added"))
    if created:
        asset.firstSeenTS = created
    last_seen = parse_ts(record.get("last_seen")) or parse_ts(record.get("changeddate"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def collect_devices(ctx):
    """Page /api/devices and stream each page.

    Pagination is offset/limit with no total count in the response, so a short
    page ends the walk - the same termination rule Slurp'it's own SDK pager
    uses.
    """
    reported = 0
    skipped_disabled = 0
    capped = 0

    _pager = pager("slurpit")

    while _pager.next():

        page = _pager.page - 1
        offset = page * ctx["page_size"]
        if ctx["max_devices"] and offset >= ctx["max_devices"]:
            capped += 1
            break
        rows = fetch(ctx, "/devices", {
            "offset": str(offset),
            "limit": str(ctx["page_size"]),
        })
        if rows == None:
            break
        if not rows:
            break

        for record in rows:
            if not ctx["include_disabled"] and _truthy(record.get("disabled")):
                skipped_disabled += 1
                continue
            if ctx["max_devices"] and reported >= ctx["max_devices"]:
                capped += 1
                continue
            asset = build_asset(ctx, record)
            if asset == None:
                continue
            report_asset(asset)
            reported += 1

        if len(rows) < ctx["page_size"]:
            break

    return reported, skipped_disabled, capped


def main(**kwargs):
    base_url = _base(get_string(kwargs, "url"))
    scope = _scope(base_url)
    if not base_url or not scope:
        print("slurpit: could not determine the Slurp'it host from the configured URL")
        return None

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "include_disabled": get_bool(kwargs, "include_disabled", default=False),
        "page_size": get_int(kwargs, "page_size", default=512),
        "max_devices": max(0, get_int(kwargs, "max_devices", default=50000)),
        "sites": {},
        "http_options": get_http_options(kwargs, headers={
            "Authorization": bearer(get_string(kwargs, "api_key")),
            "Accept": "application/json",
        }),
    }

    if not preflight(ctx):
        return None

    if get_bool(kwargs, "collect_sites", default=True):
        ctx["sites"] = collect_sites(ctx)

    reported, skipped_disabled, capped = collect_devices(ctx)
    print("slurpit: reported {} devices".format(reported))
    if skipped_disabled:
        print("slurpit: skipped {} disabled devices; enable 'Include disabled devices' to import them".format(
            skipped_disabled))
    if capped:
        print("slurpit: device limit of {} reached; further devices were not imported".format(ctx["max_devices"]))
    if not reported:
        print("slurpit: no assets retrieved")
    return None

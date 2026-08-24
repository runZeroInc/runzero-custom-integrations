# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-tp-link-omada",
    "name": "TP-Link Omada",
    "type": "inbound",
    "description": "Imports Omada-managed access points, switches, and gateways, plus the wired and wireless clients attached to them, from an Omada controller's Open API.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # A 'client' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'client': "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "Omada controller URL",
            "type": "url",
            "required": True,
            "placeholder": "https://omada.example.com:8043",
            "description": "Base URL of the Omada controller. A self-hosted software controller defaults to port 8043 over HTTPS. For the Omada Cloud-Based Controller use the regional northbound host, for example https://use1-omada-northbound.tplinkcloud.com, https://euw1-omada-northbound.tplinkcloud.com, or https://aps1-omada-northbound.tplinkcloud.com.",
        },
        {
            "key": "omadac_id",
            "label": "Omada controller ID (omadacId)",
            "type": "string",
            "required": True,
            "description": "The controller's own identifier. It is shown on the Open API page beside the application, appears in the controller's web URL, and is returned unauthenticated by GET /api/info. Every Open API path contains it.",
        },
        {
            "key": "client_id",
            "label": "Open API client ID",
            "type": "secret",
            "required": True,
            "description": "Client ID of the Open API application created under Global View > Settings > Platform Integration > Open API.",
        },
        {
            "key": "client_secret",
            "label": "Open API client secret",
            "type": "secret",
            "required": True,
            "description": "Client secret of that application. It is shown once, when the application is created.",
        },
        {
            "key": "site_ids",
            "label": "Site IDs",
            "type": "string",
            "required": False,
            "description": "Optional comma-separated list of siteId values to import. Leave blank to walk every site the application has privileges for.",
        },
        {
            "key": "extract_devices",
            "label": "Import Omada devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the access points, switches, and gateways the controller manages.",
        },
        {
            "key": "extract_clients",
            "label": "Import clients",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the wired and wireless clients attached to those devices. Client MAC addresses are frequently randomized by the client itself, which is why client assets are imported with a non-authoritative identity -- see the README.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Rows requested per page. The Open API accepts up to 1000.",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages per collection",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 10000,
            "description": "Hard stop on how many pages one collection may fetch. Hitting it fails the run rather than truncating silently.",
        },
    ],
    # Backstop for the pager() loop guards; the max_pages parameter tightens the
    # per-collection bound below this and cannot raise it past it.
    "maxPages": 10000,
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", "get_json", "post_json")
load("kwargs", "require", "get_http_options", "get_string", "get_bool", "get_int", "get_list")
load("time", "now", "from_timestamp")
load("re", re_sub="sub")

load('coerce', 'as_dict')
VENDOR = "tp-link-omada"
ATTR_PREFIX = "omada"
ATTR_SEPARATOR = "_"

TOKEN_PATH = "/openapi/authorize/token?grant_type=client_credentials"
SITES_PATH = "/openapi/v1/{}/sites"
DEVICES_PATH = "/openapi/v1/{}/sites/{}/devices"
CLIENTS_PATH = "/openapi/v1/{}/sites/{}/clients"

# Every Open API response is wrapped in {"errorCode": N, "msg": "...",
# "result": ...}. Zero is success; an HTTP 200 with a non-zero errorCode is a
# failure and must not be read as data.
ERR_OK = 0

# The controller reports an expired or invalid access token in the envelope
# rather than with a 401, so the code has to be recognised by value. -44112 and
# -44113 are the two seen on a data request; the -441xx family below is what a
# refresh answers with when the refresh token itself is spent.
TOKEN_ERROR_CODES = [-44112, -44113, -44114, -44111, -44106]

# The controller answers -1600 for a path this firmware does not implement.
# Treated as "this collection is unavailable here", not as a run failure.
ERR_UNSUPPORTED = -1600

# Devices report status as an integer on the Open API path, where 1 means
# connected. The legacy /api/v2 path uses the same field name with completely
# different values, which is why nothing here is shared with that API.
DEVICE_STATUS = {
    0: "disconnected",
    1: "connected",
    2: "pending",
}

DEVICE_TYPES = {
    "ap": "Wireless Access Point",
    "eap": "Wireless Access Point",
    "switch": "Switch",
    "gateway": "Router",
}

INVALID_MACS = ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"]

# lastSeen is an integer epoch. The controller sends milliseconds on the paths
# where it has been observed, but the unit is not documented, so the magnitude
# decides: a seconds value of the present era is ~1.8e9 and a milliseconds value
# ~1.8e12, which this threshold separates cleanly for any date this century.
MS_THRESHOLD = 100000000000

def _clean(value):
    """Return a trimmed string for a scalar, or "" for anything else."""
    if type(value) == "string":
        return value.strip()
    if type(value) == "int" or type(value) == "float":
        return str(value)
    return ""
def _canonical_mac(value):
    """Return an uppercase colon-separated MAC, or "" when the value is not one.

    This is deliberately NOT net.normalize_mac. That helper clears the
    locally-administered bit so that a randomized MAC matches across sources,
    which is right for a network interface and wrong for an identifier: every
    randomized client MAC sets that bit, so 02:...:01 and 00:...:01 normalize to
    one value and two distinct endpoints fold into a single asset. This
    canonicaliser only changes separators and case, so nothing is lost.
    """
    hexonly = re_sub("[^0-9A-Fa-f]", "", _clean(value)).upper()
    if len(hexonly) != 12:
        return ""
    parts = []
    for index in range(0, 12, 2):
        parts.append(hexonly[index:index + 2])
    canonical = ":".join(parts)
    if canonical in INVALID_MACS:
        return ""
    return canonical
def _addresses(record, keys):
    """Collect the routable addresses named by keys, flattening list fields."""
    found = []
    for key in keys:
        value = record.get(key)
        candidates = value if type(value) == "list" else [value]
        for candidate in candidates:
            canonical = routable_ip(candidate)
            if canonical and canonical not in found:
                found.append(canonical)
    return found

def _hostname(value, mac):
    """Return a usable hostname, or "".

    Omada names an unnamed device or client after its own MAC address, and a
    MAC is already carried by the interface -- importing it again as a hostname
    adds nothing and puts a non-name in the name field.
    """
    text = _clean(value)
    if not text:
        return ""
    lowered = text.lower()
    if lowered in ["localhost", "unknown", "unknown device", "-"]:
        return ""
    if _canonical_mac(text) != "":
        return ""
    if mac and lowered.replace("-", ":") == mac.lower():
        return ""
    if ip_address(text) != None:
        return ""
    return text

def _last_seen(value, ceiling):
    """Return lastSeen as a time clamped to now, or None.

    A timestamp in the future does not fail the field, it fails the whole
    ImportAsset, so a controller with a skewed clock would import nothing.
    """
    if type(value) != "int" and type(value) != "float":
        return None
    number = int(value)
    if number <= 0:
        return None
    seconds = number // 1000 if number >= MS_THRESHOLD else number
    if seconds <= 0:
        return None
    parsed = from_timestamp(seconds)
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed

def _envelope(payload):
    """Split an Open API response into (result, errorCode, msg).

    A response that is not an object, or that carries no integer errorCode, is
    reported as errorCode None so the caller can say so rather than reading a
    missing field as success.
    """
    if type(payload) != "dict":
        return None, None, "response was not a JSON object"
    code = payload.get("errorCode")
    if type(code) != "int":
        return None, None, "response carried no errorCode"
    return payload.get("result"), code, _clean(payload.get("msg"))

def mint_token(ctx):
    """Run the client_credentials grant and store the access token.

    Returns True on success. The grant type travels in the query string and the
    three credentials in the JSON body, which is how the controller wants them;
    sending the credentials as query parameters is rejected.
    """
    url = ctx["base_url"] + TOKEN_PATH
    body = {
        "omadacId": ctx["omadac_id"],
        "client_id": ctx["client_id"],
        "client_secret": ctx["client_secret"],
    }
    payload, err = post_json(url, json=body, **get_http_options(
        ctx["kwargs"], "http_", "tls_", {"Accept": "application/json"}))
    if err:
        print("{}: token request failed: {}".format(VENDOR, err))
        return False

    result, code, msg = _envelope(payload)
    if code != ERR_OK:
        print("{}: token request returned errorCode {}: {}".format(VENDOR, code, msg))
        return False

    token = _clean(as_dict(result).get("accessToken"))
    if not token:
        print("{}: token response carried no accessToken".format(VENDOR))
        return False
    ctx["token"] = token
    return True

def api_get(ctx, path, label):
    """GET one Open API path, refreshing the access token once if it has expired.

    Returns (result, errorCode). The errorCode is returned so a caller can tell
    an unsupported endpoint apart from a real failure.
    """
    for attempt in [0, 1]:
        headers = {
            "Accept": "application/json",
            # A non-standard scheme, and it is not "Bearer": the controller
            # requires the literal form "AccessToken=<token>".
            "Authorization": "AccessToken=" + ctx["token"],
        }
        payload, err = get_json(ctx["base_url"] + path, **get_http_options(
            ctx["kwargs"], "http_", "tls_", headers))

        if err:
            if attempt == 0 and err.startswith("status 401"):
                print("{}: {} answered 401, refreshing the access token".format(VENDOR, label))
                if mint_token(ctx):
                    continue
            print("{}: {} request failed: {}".format(VENDOR, label, err))
            return None, None

        result, code, msg = _envelope(payload)
        if code == ERR_OK:
            return result, code
        if attempt == 0 and code in TOKEN_ERROR_CODES:
            print("{}: {} returned token errorCode {}, refreshing the access token".format(
                VENDOR, label, code))
            if mint_token(ctx):
                continue
        print("{}: {} returned errorCode {}: {}".format(VENDOR, label, code, msg))
        return None, code
    return None, None

def walk_pages(ctx, path, label, build):
    """Page through one Open API collection, streaming each page as it arrives.

    Returns the number of assets reported. Each page is turned into assets and
    handed to report_assets before the next page is requested, so peak memory is
    one page rather than one estate.

    A response whose result is a bare list rather than a paginated envelope is
    treated as the whole collection and the walk stops after it. Without that
    check a firmware that ignores the page parameter would answer page 2 with
    the same rows and the run would loop.

    The loop guard is pager(): hitting the max_pages ceiling raises with the
    loop label rather than ending silently, so a truncated import reads as an
    error instead of a complete run.
    """
    reported = 0
    p = pager(label, limit=ctx["max_pages"])
    while p.next():
        page = p.page
        separator = "&" if "?" in path else "?"
        paged = "{}{}page={}&pageSize={}".format(path, separator, page, ctx["page_size"])
        result, code = api_get(ctx, paged, label)
        if result == None:
            if code == ERR_UNSUPPORTED:
                print("{}: {} is not available on this controller, skipping".format(VENDOR, label))
            break

        rows = []
        paginated = False
        if type(result) == "dict" and type(result.get("data")) == "list":
            rows = result["data"]
            paginated = True
        elif type(result) == "list":
            rows = result

        if rows:
            reported += report_assets(build(ctx, rows))
        if not paginated or not rows:
            break

        total = result.get("totalRows")
        if type(total) == "int" and page * ctx["page_size"] >= total:
            break
        if len(rows) < ctx["page_size"]:
            break
    return reported

def build_devices(ctx, rows):
    """Convert one page of Omada devices into ImportAssets."""
    assets = []
    ceiling = ctx["ceiling"]
    for row in rows:
        if type(row) != "dict":
            print("{}: skipping device row that is not an object".format(VENDOR))
            continue

        mac = _canonical_mac(row.get("mac"))
        if not mac:
            print("{}: skipping device with no usable mac in site {}".format(
                VENDOR, ctx["site_id"]))
            continue

        asset_id = "{}:{}:device:{}".format(VENDOR, ctx["omadac_id"], mac)
        if asset_id in ctx["seen"]:
            print("{}: skipping duplicate device {}".format(VENDOR, mac))
            continue
        ctx["seen"][asset_id] = True

        addresses = _addresses(row, ["ip", "ipv6List"])
        nic = network_interface(mac=mac, ips=addresses)
        interfaces = [nic] if nic else []

        device_type = _clean(row.get("type")).lower()
        status = row.get("status")
        raw = {
            "site_id": ctx["site_id"],
            "site_name": ctx["site_name"],
            "device_type": _clean(row.get("type")),
            "status": DEVICE_STATUS.get(status, _clean(status)),
            "serial_number": _clean(row.get("sn")),
            "firmware_version": _clean(row.get("firmwareVersion")),
            "compound_model": _clean(row.get("compoundModel")),
            "need_upgrade": row.get("needUpgrade"),
            "uptime": _clean(row.get("uptime")),
            "cpu_util": row.get("cpuUtil"),
            "mem_util": row.get("memUtil"),
            "ip": _clean(row.get("ip")),
            "last_seen": _clean(row.get("lastSeen")),
        }

        tags = []
        serial = _clean(row.get("sn"))
        if serial:
            tags.append("serial:" + serial)

        asset = ImportAsset(
            id=asset_id,
            hostnames=[_hostname(row.get("name"), mac)],
            networkInterfaces=interfaces,
            manufacturer="TP-Link",
            model=_clean(row.get("model")),
            osVersion=_clean(row.get("firmwareVersion")),
            deviceType=DEVICE_TYPES.get(device_type, ""),
            tags=tags,
            customAttributes=to_custom_attributes(
                raw, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            # The identifier is the device's burned-in MAC, which is what the
            # controller itself keys a device by -- every per-device Open API
            # path is addressed by MAC. It is one per physical device and is not
            # randomized on TP-Link infrastructure hardware, so it may drive a
            # merge; a changed address or a renamed AP must not block one. That
            # is the integration-wide policy in CONFIG, which this type inherits.
            assetType="device",
        )

        last_seen = _last_seen(row.get("lastSeen"), ceiling)
        if last_seen != None:
            asset.lastSeenTS = last_seen

        assets.append(asset)
    return assets

def build_clients(ctx, rows):
    """Convert one page of Omada clients into ImportAssets."""
    assets = []
    ceiling = ctx["ceiling"]
    for row in rows:
        if type(row) != "dict":
            print("{}: skipping client row that is not an object".format(VENDOR))
            continue

        mac = _canonical_mac(row.get("mac"))
        if not mac:
            print("{}: skipping client with no usable mac in site {}".format(
                VENDOR, ctx["site_id"]))
            continue

        asset_id = "{}:{}:client:{}".format(VENDOR, ctx["omadac_id"], mac)
        if asset_id in ctx["seen"]:
            print("{}: skipping duplicate client {}".format(VENDOR, mac))
            continue
        ctx["seen"][asset_id] = True

        addresses = _addresses(row, ["ip", "ipv6List"])
        nic = network_interface(mac=mac, ips=addresses)
        interfaces = [nic] if nic else []

        hostname = _hostname(row.get("name"), mac)
        if not hostname:
            hostname = _hostname(row.get("hostName"), mac)

        vendor = _clean(row.get("vendor"))

        raw = {
            "site_id": ctx["site_id"],
            "site_name": ctx["site_name"],
            "device_type": _clean(row.get("deviceType")),
            "device_category": _clean(row.get("deviceCategory")),
            "os_name": _clean(row.get("osName")),
            "wireless": row.get("wireless"),
            "active": row.get("active"),
            "guest": row.get("guest"),
            "blocked": row.get("blocked"),
            "ssid": _clean(row.get("ssid")),
            "network_name": _clean(row.get("networkName")),
            "vlan_id": row.get("vid"),
            "ap_name": _clean(row.get("apName")),
            "ap_mac": _clean(row.get("apMac")),
            "switch_name": _clean(row.get("switchName")),
            "switch_mac": _clean(row.get("switchMac")),
            "gateway_name": _clean(row.get("gatewayName")),
            "gateway_mac": _clean(row.get("gatewayMac")),
            "port": row.get("port"),
            "signal_level": row.get("signalLevel"),
            "rssi": row.get("rssi"),
            "connect_type": row.get("connectType"),
            "connect_dev_type": _clean(row.get("connectDevType")),
            "uptime": row.get("uptime"),
            "last_seen": _clean(row.get("lastSeen")),
        }

        asset = ImportAsset(
            id=asset_id,
            hostnames=[hostname],
            networkInterfaces=interfaces,
            manufacturer=vendor,
            model=_clean(row.get("model")),
            os=_clean(row.get("osName")),
            customAttributes=to_custom_attributes(
                raw, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            # A client's MAC is the only identifier Omada has for it, and a
            # modern phone or laptop invents a new one per SSID. The identifier
            # is therefore derived rather than issued, so it must neither drive
            # nor block a merge; correlation falls back to the MAC, the address,
            # and the hostname.
            assetType="client",
        )

        last_seen = _last_seen(row.get("lastSeen"), ceiling)
        if last_seen != None:
            asset.lastSeenTS = last_seen

        assets.append(asset)
    return assets

def list_sites(ctx):
    """Return the sites to walk as a list of (siteId, name).

    A configured site list is used verbatim, so an application whose privileges
    do not include the sites collection can still import the sites it can read.
    """
    if ctx["site_ids"]:
        return [(site_id, "") for site_id in ctx["site_ids"]]

    sites = []
    p = pager("sites", limit=ctx["max_pages"])
    while p.next():
        page = p.page
        path = "{}?page={}&pageSize={}".format(
            SITES_PATH.format(ctx["omadac_id"]), page, ctx["page_size"])
        result, _code = api_get(ctx, path, "sites")
        if result == None:
            break

        rows = []
        paginated = False
        if type(result) == "dict" and type(result.get("data")) == "list":
            rows = result["data"]
            paginated = True
        elif type(result) == "list":
            rows = result

        for row in rows:
            if type(row) != "dict":
                continue
            site_id = _clean(row.get("siteId")) or _clean(row.get("id"))
            if not site_id:
                print("{}: skipping site row with no siteId".format(VENDOR))
                continue
            sites.append((site_id, _clean(row.get("name"))))

        if not paginated or not rows:
            break
        total = result.get("totalRows")
        if type(total) == "int" and page * ctx["page_size"] >= total:
            break
        if len(rows) < ctx["page_size"]:
            break
    return sites

def main(*args, **kwargs):
    require(kwargs, "url", "omadac_id", "client_id", "client_secret")

    base_url = get_string(kwargs, "url").strip().removesuffix("/")
    ctx = {
        "kwargs": kwargs,
        "base_url": base_url,
        "omadac_id": get_string(kwargs, "omadac_id").strip(),
        "client_id": get_string(kwargs, "client_id"),
        "client_secret": get_string(kwargs, "client_secret"),
        "site_ids": [s for s in get_list(kwargs, "site_ids", default=[]) if s.strip()],
        "page_size": get_int(kwargs, "page_size", default=100),
        "max_pages": get_int(kwargs, "max_pages", default=200),
        "token": "",
        "ceiling": now(),
        "seen": {},
        "site_id": "",
        "site_name": "",
    }

    if not mint_token(ctx):
        return None

    extract_devices = get_bool(kwargs, "extract_devices", default=True)
    extract_clients = get_bool(kwargs, "extract_clients", default=True)

    sites = list_sites(ctx)
    if not sites:
        print("{}: no sites available to this Open API application".format(VENDOR))
        return None

    total = 0
    for site_id, site_name in sites:
        ctx["site_id"] = site_id
        ctx["site_name"] = site_name

        if extract_devices:
            total += walk_pages(
                ctx,
                DEVICES_PATH.format(ctx["omadac_id"], site_id),
                "devices for site " + site_id,
                build_devices,
            )
        if extract_clients:
            total += walk_pages(
                ctx,
                CLIENTS_PATH.format(ctx["omadac_id"], site_id),
                "clients for site " + site_id,
                build_clients,
            )

    print("{}: reported {} assets across {} site(s)".format(VENDOR, total, len(sites)))
    # Assets are streamed with report_assets, so nothing is buffered here.
    return None

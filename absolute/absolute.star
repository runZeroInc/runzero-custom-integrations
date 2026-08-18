# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-absolute",
    "name": "Absolute Secure Endpoint",
    "type": "inbound",
    "description": "Imports devices and installed software from Absolute Secure Endpoint.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # deviceUid is the account's permanent handle for the device and it
    # survives rename, reimage and hardware refresh, while the laptops this
    # source tracks roam constantly and often report no adapter at all.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "api_host",
            "label": "Absolute API host",
            "type": "url",
            "required": True,
            "default": "https://api.absolute.com",
            "description": "Regional API endpoint that matches your Secure Endpoint Console address. CA1 Montreal (cc.absolute.com) https://api.absolute.com, US1 Oregon (cc.us.absolute.com) https://api.us.absolute.com, EU2 Frankfurt (cc.eu2.absolute.com) https://api.eu2.absolute.com, UK1 London (cc.uk1.absolute.com) https://api.uk1.absolute.com, IN1 Mumbai (cc.in1.absolute.com) https://api.in1.absolute.com, FR1 FedRAMP (cc.fr1.absolutegov.com) https://api.fr1.absolutegov.com.",
            # One host per Absolute data centre, each paired with the console
            # address an operator logs in to:
            #   cc.absolute.com            -> api.absolute.com            CA1 Montreal
            #   cc.us.absolute.com         -> api.us.absolute.com         US1 Oregon
            #   cc.eu2.absolute.com        -> api.eu2.absolute.com        EU2 Frankfurt
            #   cc.uk1.absolute.com        -> api.uk1.absolute.com        UK1 London
            #   cc.in1.absolute.com        -> api.in1.absolute.com        IN1 Mumbai
            #   cc.fr1.absolutegov.com     -> api.fr1.absolutegov.com     FR1 FedRAMP
            #
            # UK1 was missing. It is absent from Absolute's own API reference --
            # the console-to-API table in their OpenAPI strings file names the
            # other five and not this one -- but the region is real and in
            # production: it is listed on Absolute's sub-processor page as an AWS
            # London deployment, api.uk1.absolute.com holds a dedicated
            # certificate for uk1.absolute.com, and it answers 401 to an
            # unauthenticated /v3 call exactly as its siblings do.
            #
            # There is deliberately no api.ca1.absolute.com entry. The name
            # resolves, but it serves a certificate for api.absolute.com with no
            # matching SAN, so every TLS client fails on it; the Canadian data
            # centre's API host is the unprefixed api.absolute.com above.
        },
        {
            "key": "token_id",
            "label": "API token ID",
            "type": "string",
            "required": True,
            "description": "Token ID from Settings > API management in the Secure Endpoint Console.",
        },
        {
            "key": "secret_key",
            "label": "API secret key",
            "type": "secret",
            "required": True,
            "description": "Secret key issued alongside the token ID for a generated (symmetric) token.",
        },
        {
            "key": "import_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Make a second pass over the software report and attach applications to each device.",
        },
        {
            "key": "active_only",
            "label": "Only import active agents",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Restrict the import to devices whose agent status is Active.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 500,
            "description": "Records requested per page. The device report caps this at 500.",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 1,
            "description": "Safety ceiling on the paging walk. Raise it if a run reports hitting the limit.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "Software", "to_custom_attributes")
load("net", "network_interface")
load("http", "post_json", "url_encode", "url_parse")
load("jwt", jwt_encode="encode")
load("time", "parse_time", "now", 'parse_ts')
load("re", re_match="match")
load("kwargs", "require", "get_string", "get_bool", "get_int", "get_url_base", "get_http_options")

# Every v3 call is a signed envelope POSTed here as text/plain; the real method,
# path and query string travel inside the JOSE header rather than the URL.
VALIDATE_PATH = "/jws/validate"
DEVICES_URI = "/v3/reporting/devices"
SOFTWARE_URI = "/v3/reporting/applications-advanced"

HTTP_RETRIES = 3
# Absolute allows 20 requests per second per account across all endpoints, so
# back off generously rather than hammering a shared budget.
HTTP_RETRY_BACKOFF = 2.0

MAX_PAGE_SIZE = 500

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so every page ceiling is that target
# divided by the page size. At the 500-record maximum that is
# ceil(10,000,000 / 500) = 20,000 pages, which is the declared max_pages default.
#
# The ceiling is a backstop, not the working guard. The working guard is the
# no-progress check in each walk: a cursor the server never advances means the
# ceiling itself becomes the request count, and no page cap set from a record
# target can be small enough to catch that quickly without truncating a real
# estate. Either stop is logged, because a truncated import that says nothing
# looks exactly like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = 20000
MAX_SOFTWARE_PER_ASSET = 99

# Only fields listed by the published `select` options are requested; an
# unknown field name makes the whole request fail with a 400. The top level
# object and its nested parameters cannot both appear in one select list.
DEVICE_SELECT = ",".join([
    "accountUid",
    "agentStatus",
    "agentVersion",
    "bios.assetTag",
    "bios.id",
    "bios.serialNumber",
    "bios.smBiosVersion",
    "bios.version",
    "bios.versionDate",
    "chassisType",
    "deviceName",
    "deviceStatus.reported",
    "deviceStatus.type",
    "deviceUid",
    "domain",
    "esn",
    "espInfo.encryptionStatus",
    "firstCallDateTimeUtc",
    "fullSystemName",
    "geoData.location.accuracy",
    "geoData.location.geoAddress.city",
    "geoData.location.geoAddress.country",
    "geoData.location.geoAddress.countryCode",
    "geoData.location.geoAddress.state",
    "geoData.location.lastUpdateDateTimeUtc",
    "geoData.location.locationTechnology",
    "geoData.location.point.coordinates",
    "isStolen",
    "lastConnectedDateTimeUtc",
    "lastUpdatedDateTimeUtc",
    "localIp",
    "networkAdapters.adapterType",
    "networkAdapters.ipV4Address",
    "networkAdapters.ipV6Address",
    "networkAdapters.macAddress",
    "networkAdapters.name",
    "networkSSID",
    "operatingSystem.architecture",
    "operatingSystem.currentBuild",
    "operatingSystem.installDateTimeUtc",
    "operatingSystem.lastBootDateTimeUtc",
    "operatingSystem.name",
    "operatingSystem.serialNumber",
    "operatingSystem.version",
    "platformOSType",
    "policyGroupName",
    "policyGroupUid",
    "publicIp",
    "serialNumber",
    "systemManufacturer",
    "systemModel",
    "systemType",
    "username",
])

SOFTWARE_SELECT = ",".join([
    "appId",
    "appName",
    "appPublisher",
    "appVersion",
    "deviceAppId",
    "deviceUid",
    "installDateTimeUtc",
    "installPath",
])

# The software report is grouped by device so a streaming pass can emit one
# asset per device without buffering the whole account.
SOFTWARE_SORT = "deviceUid:asc,appId:asc"

# A device the agent has never reached carries no usable interface data, and
# these placeholders show up in the address fields when a lookup failed.
UNUSABLE_IPS = ["", "0.0.0.0", "::", "unknown", "n/a"]


def _encode_value(value):
    """Percent-encode one query-string value the way Absolute canonicalizes it."""
    # url_encode returns "v=<escaped>" and escapes a space as "+", but Absolute
    # documents %20, so drop the key and convert the one differing character.
    return url_encode({"v": str(value)})[2:].replace("+", "%20")


def _region_scope(base_url):
    """Return the regional API hostname used to namespace asset ids."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url
def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()


def build_query_string(select, page_size, sort_by, agent_status, next_page):
    """Assemble the canonical query string that gets signed into the JOSE header."""
    query = "select=" + _encode_value(select)
    if sort_by:
        query += "&sortBy=" + _encode_value(sort_by)
    if agent_status:
        query += "&agentStatus=" + _encode_value(agent_status)
    query += "&pageSize=" + str(page_size)
    if next_page:
        # Absolute warns that altering the cursor breaks pagination, so the
        # opaque token is appended verbatim exactly as the docs show it.
        query += "&nextPage=" + next_page
    return query


def sign_request(token_id, secret_key, method, uri, query_string):
    """Build the compact HS256 JWS that carries one Absolute API request."""
    header = {
        "alg": "HS256",
        "kid": token_id,
        "method": method,
        "content-type": "application/json",
        "uri": uri,
        "query-string": query_string,
        # Epoch milliseconds; time.now().unix is only second precision.
        "issuedAt": now().unix_nano // 1000000,
    }
    # GET requests carry an empty payload, still wrapped in the data key.
    return jwt_encode({"data": {}}, secret_key, algorithm="HS256", headers=header)


def fetch_page(base_url, http_options, token_id, secret_key, uri, query_string):
    """Sign one request, POST it to the JWS validator, and return (data, next_page, err)."""
    signed = sign_request(token_id, secret_key, "GET", uri, query_string)
    body, err = post_json(base_url + VALIDATE_PATH, body=bytes(signed),
                          retries=HTTP_RETRIES, retry_backoff=HTTP_RETRY_BACKOFF,
                          **http_options)
    if err:
        return [], "", err
    body = body or {}
    rows = body.get("data", []) or []
    if type(rows) != "list":
        # A 2xx body that is not the documented {"data": [...]} envelope.
        return [], "", "unexpected data shape: " + type(rows)
    pagination = (body.get("metadata", {}) or {}).get("pagination", {}) or {}
    return rows, _clean(pagination.get("nextPage")), None


def build_software(rows):
    """Convert the software report rows for one device into Software objects."""
    software = []
    seen = {}
    for row in rows:
        product = _clean(row.get("appName"))
        if not product:
            continue
        version = _clean(row.get("appVersion"))
        # deviceAppId is unique per device/application pair; fall back to the
        # name and version so a row missing it still yields a stable id.
        software_id = _clean(row.get("deviceAppId"))
        if not software_id:
            software_id = "{}:{}".format(product, version)
        software_id = software_id[:255]
        if software_id in seen:
            continue
        seen[software_id] = True

        params = {
            "id": software_id,
            "product": product,
            # Absolute reports installed inventory, not listening services, so
            # there is no real socket to attach the record to.
            "serviceAddress": "127.0.0.1",
        }
        if version:
            params["version"] = version
        publisher = _clean(row.get("appPublisher"))
        if publisher:
            params["vendor"] = publisher
        install_path = _clean(row.get("installPath"))
        if install_path:
            params["installedFrom"] = install_path
        installed_at = parse_ts(row.get("installDateTimeUtc"))
        if installed_at:
            params["installedAt"] = installed_at
        # Absolute publishes no CPE for applications, and Software.cpe23 only
        # accepts the CPE 2.2 "cpe:/a:" binding, so the field is left unset.
        software.append(Software(**params))
    return software


def build_network_interfaces(device):
    """Build interfaces from the reported network adapters, falling back to localIp."""
    netifs = []
    covered = {}
    for adapter in device.get("networkAdapters", []) or []:
        mac = _clean(adapter.get("macAddress"))
        ips = []
        for key in ["ipV4Address", "ipV6Address"]:
            # Absolute documents these as "the addresses" for the adapter, so
            # split the common separators before handing them to the helper.
            for part in _clean(adapter.get(key)).replace(";", ",").replace(" ", ",").split(","):
                candidate = _clean(part)
                if candidate and candidate.lower() not in UNUSABLE_IPS:
                    ips.append(candidate)
                    covered[candidate] = True
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)

    # The device-level localIp is the last address the agent called home from;
    # add it only when no adapter already reported it.
    local_ip = _clean(device.get("localIp"))
    if local_ip and local_ip.lower() not in UNUSABLE_IPS and local_ip not in covered:
        nic = network_interface(ips=[local_ip])
        if nic:
            netifs.append(nic)
    # publicIp is deliberately excluded: it is the NAT egress address shared by
    # every device behind one gateway, and attaching it to an interface would
    # invite unrelated laptops to merge together.
    return netifs


def build_asset(scope, device):
    """Convert one device report record into an ImportAsset."""
    device_uid = _clean(device.get("deviceUid"))
    if not device_uid:
        print("absolute: skipping device with no deviceUid: esn=" + _clean(device.get("esn")))
        return None

    operating_system = device.get("operatingSystem", {}) or {}
    bios = device.get("bios", {}) or {}
    esp_info = device.get("espInfo", {}) or {}
    device_status = device.get("deviceStatus", {}) or {}
    location = (device.get("geoData", {}) or {}).get("location", {}) or {}
    geo_address = location.get("geoAddress", {}) or {}
    point = location.get("point", {}) or {}

    serial_number = _clean(device.get("serialNumber"))
    esn = _clean(device.get("esn"))

    attrs = {
        "account_uid": _clean(device.get("accountUid")),
        "agent_status": _clean(device.get("agentStatus")),
        "agent_version": _clean(device.get("agentVersion")),
        "bios_asset_tag": _clean(bios.get("assetTag")),
        "bios_id": _clean(bios.get("id")),
        "bios_serial_number": _clean(bios.get("serialNumber")),
        "bios_smbios_version": _clean(bios.get("smBiosVersion")),
        "bios_version": _clean(bios.get("version")),
        "bios_version_date": _clean(bios.get("versionDate")),
        "chassis_type": _clean(device.get("chassisType")),
        "device_status_reported": _clean(device_status.get("reported")),
        "device_status_type": _clean(device_status.get("type")),
        "device_uid": device_uid,
        "encryption_status": _clean(esp_info.get("encryptionStatus")),
        "esn": esn,
        "first_call": _clean(device.get("firstCallDateTimeUtc")),
        "geo_accuracy": location.get("accuracy"),
        "geo_city": _clean(geo_address.get("city")),
        "geo_coordinates": point.get("coordinates"),
        "geo_country": _clean(geo_address.get("country")),
        "geo_country_code": _clean(geo_address.get("countryCode")),
        "geo_last_update": _clean(location.get("lastUpdateDateTimeUtc")),
        "geo_state": _clean(geo_address.get("state")),
        "geo_technology": _clean(location.get("locationTechnology")),
        "is_stolen": device.get("isStolen"),
        "last_connected": _clean(device.get("lastConnectedDateTimeUtc")),
        "last_updated": _clean(device.get("lastUpdatedDateTimeUtc")),
        "network_ssid": _clean(device.get("networkSSID")),
        "os_architecture": _clean(operating_system.get("architecture")),
        "os_build": _clean(operating_system.get("currentBuild")),
        "os_install_date": _clean(operating_system.get("installDateTimeUtc")),
        "os_last_boot": _clean(operating_system.get("lastBootDateTimeUtc")),
        "os_serial_number": _clean(operating_system.get("serialNumber")),
        "platform_os_type": _clean(device.get("platformOSType")),
        "policy_group_name": _clean(device.get("policyGroupName")),
        "policy_group_uid": _clean(device.get("policyGroupUid")),
        "public_ip": _clean(device.get("publicIp")),
        "serial_number": serial_number,
        "username": _clean(device.get("username")),
    }

    tags = ["absolute"]
    if serial_number:
        tags.append("serial:" + serial_number)
    if device.get("isStolen"):
        tags.append("stolen")

    params = {
        "id": "absolute:{}:{}".format(scope, device_uid),
        "hostnames": [_clean(device.get("deviceName")), _clean(device.get("fullSystemName"))],
        "networkInterfaces": build_network_interfaces(device),
        "tags": tags,        # prefix is joined to each key with separator, so this yields
        # "absolute_serial_number" rather than "absolute_.serial_number".
        "customAttributes": to_custom_attributes(attrs, prefix="absolute", separator="_"),
    }

    domain = _clean(device.get("domain"))
    if domain:
        params["domain"] = domain
    os_name = _clean(operating_system.get("name"))
    if os_name:
        params["os"] = os_name
    os_version = _clean(operating_system.get("version"))
    if os_version:
        params["osVersion"] = os_version
    manufacturer = _clean(device.get("systemManufacturer"))
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = _clean(device.get("systemModel"))
    if model:
        params["model"] = model
    device_type = _clean(device.get("systemType")) or _clean(device.get("chassisType"))
    if device_type:
        params["deviceType"] = device_type

    first_seen = parse_ts(device.get("firstCallDateTimeUtc"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = parse_ts(device.get("lastConnectedDateTimeUtc"))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(scope, devices):
    """Convert one page of device report records into ImportAsset objects."""
    assets = []
    for device in devices:
        asset = build_asset(scope, device)
        if asset:
            assets.append(asset)
    return assets


def build_software_asset(scope, device_uid, rows):
    """Build an enrichment asset that carries one device's installed software."""
    software = build_software(rows)
    if not software:
        return None
    return ImportAsset(
        id="absolute:{}:{}".format(scope, device_uid),
        software=software[:MAX_SOFTWARE_PER_ASSET],
    )


def retrieved_of(reported, total):
    """The retrieved/available half of a truncation message.

    A bare count says nothing about whether the import is nearly complete or
    stopped at the first percent, so pair it with whatever total the API
    reported. Absolute's v3 reporting envelope carries only a nextPage cursor
    in `metadata.pagination`, never a row count, so this always takes the
    second branch here -- but say that plainly rather than printing a bare
    slash or inventing a denominator.
    """
    if type(total) == "int" and total > 0:
        return "retrieved {}/{} available assets".format(reported, total)
    return "retrieved {} assets, total not reported".format(reported)


def page_ceiling(config_kwargs, page_size):
    """The paging ceiling for one walk.

    An explicit max_pages wins. Otherwise the ceiling is the repo-wide ten
    million record target divided by the page size actually in use: the
    declared CONFIG default is that arithmetic at the 500-record maximum, and
    an operator who shrinks the page size should still reach the same record
    target rather than a fifth of it.
    """
    requested = get_int(config_kwargs, "max_pages", default=MAX_PAGES)
    if requested != MAX_PAGES:
        return requested
    if page_size > 0:
        return (MAX_RECORDS + page_size - 1) // page_size
    return MAX_PAGES


def fetch_and_report_devices(base_url, http_options, token_id, secret_key, scope,
                             page_size, agent_status, max_pages):
    """Fetch and stream devices one page at a time so the full set is never
    held in memory at once."""
    reported = 0
    next_page = ""
    pages = 0
    capped = True
    for _page in range(0, max_pages):
        query = build_query_string(DEVICE_SELECT, page_size, "", agent_status, next_page)
        rows, cursor, err = fetch_page(base_url, http_options, token_id, secret_key,
                                       DEVICES_URI, query)
        if err:
            print("absolute: failed to fetch devices:", err)
            return reported
        pages += 1
        if not rows:
            capped = False
            break
        reported += report_assets(build_assets(scope, rows))
        if not cursor:
            capped = False
            break
        if cursor == next_page:
            # A cursor that never advances would otherwise re-fetch page one
            # until the page ceiling is hit, which at a ten-million-record
            # target is not a guard at all.
            print("absolute: paging stopped after {} pages (API returned the same cursor twice walking devices, {})".format(
                pages, retrieved_of(reported, None)))
            capped = False
            break
        next_page = cursor
    if capped:
        print("absolute: page limit of {} hit (integration safety limit, walking devices, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(reported, None)))
    return reported


def fetch_and_report_software(base_url, http_options, token_id, secret_key, scope,
                              page_size, max_pages):
    """Stream the software report, emitting one enrichment asset per device.

    The report is sorted by deviceUid so rows for a device arrive together; a
    partial group is carried across the page boundary and flushed once the next
    device id appears, which keeps memory bounded to a single device.
    """
    reported = 0
    next_page = ""
    current_uid = ""
    current_rows = []
    pages = 0
    capped = True
    for _page in range(0, max_pages):
        query = build_query_string(SOFTWARE_SELECT, page_size, SOFTWARE_SORT, "", next_page)
        rows, cursor, err = fetch_page(base_url, http_options, token_id, secret_key,
                                       SOFTWARE_URI, query)
        if err:
            print("absolute: failed to fetch software:", err)
            return reported
        pages += 1
        if not rows:
            capped = False
            break
        for row in rows:
            device_uid = _clean(row.get("deviceUid"))
            if not device_uid:
                continue
            if device_uid != current_uid:
                if current_uid and current_rows:
                    asset = build_software_asset(scope, current_uid, current_rows)
                    if asset:
                        reported += report_assets(asset)
                current_uid = device_uid
                current_rows = []
            current_rows.append(row)
        if not cursor:
            capped = False
            break
        if cursor == next_page:
            print("absolute: paging stopped after {} pages (API returned the same cursor twice walking software, {})".format(
                pages, retrieved_of(reported, None)))
            capped = False
            break
        next_page = cursor

    if capped:
        print("absolute: page limit of {} hit (integration safety limit, walking software, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(reported, None)))

    if current_uid and current_rows:
        asset = build_software_asset(scope, current_uid, current_rows)
        if asset:
            reported += report_assets(asset)
    return reported


def main(**kwargs):
    require(kwargs, "api_host", "token_id", "secret_key")
    base_url = get_url_base(kwargs, "api_host")
    token_id = get_string(kwargs, "token_id")
    secret_key = get_string(kwargs, "secret_key")
    import_software = get_bool(kwargs, "import_software", default=False)
    active_only = get_bool(kwargs, "active_only", default=False)
    page_size = get_int(kwargs, "page_size", default=MAX_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    # The signed envelope is always posted as text/plain; the JOSE header
    # carries the application/json content type of the wrapped request.
    http_options = get_http_options(kwargs, headers={"Content-Type": "text/plain"})
    scope = _region_scope(base_url)
    agent_status = "A" if active_only else ""

    max_pages = page_ceiling(kwargs, page_size)

    reported = fetch_and_report_devices(base_url, http_options, token_id, secret_key,
                                        scope, page_size, agent_status, max_pages)
    print("absolute: reported {} devices".format(reported))
    if not reported:
        print("absolute: no assets retrieved")

    if import_software:
        enriched = fetch_and_report_software(base_url, http_options, token_id, secret_key,
                                             scope, page_size, max_pages)
        print("absolute: reported software for {} devices".format(enriched))

    return None

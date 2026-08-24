# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ubiquiti-unifi-site-manager",
    "name": "Ubiquiti UniFi Site Manager",
    "type": "inbound",
    "description": "Imports every UniFi device across every console on a UI account from the Site Manager cloud API, enriched with console hardware detail and site names.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The id is the field Ubiquiti issues, but in every published example
    # its value is the device's MAC with the separators removed, and this
    # script cannot tell the two apart. An identifier derived from an
    # address identifies an address rather than a device: normalize_mac
    # clears the locally administered bit for cross-source matching, so two
    # distinct endpoints can fold onto one value, which is right for an
    # interface and wrong for identity. It is therefore kept as a stable,
    # namespaced record key and is NOT allowed to drive or block a merge --
    # correlation falls back to the MAC, the reported address, and the name,
    # which is the same posture aruba-clearpass and forescout-counteract
    # take for this class of identifier. The sibling ubiquiti-unifi-protect
    # sidestepped the problem by keying on a Mongo ObjectId instead; the
    # Site Manager API publishes no comparable non-MAC id here.
    "matchBehavior": "no-id-match no-id-break",
    # The 'host' records are the exception: their id is issued by the vendor
    # rather than derived from an address, so it may drive a merge, and only
    # a changed MAC, address, or name must not veto one.
    "assetTypeBehavior": {
        'host': "no-mac-break no-ip-break no-name-break",
    },
    "params": [
        {
            "key": "url",
            "label": "Site Manager API URL",
            "type": "url",
            "required": False,
            "default": "https://api.ui.com",
            "placeholder": "https://api.ui.com",
            "description": "Base URL of the Site Manager API. The vendor endpoint is https://api.ui.com and is the default; override it only to reach the API through a proxy.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Created at https://unifi.ui.com under Settings > API Keys. It is shown once. The key inherits the UI account's console access and is read-only.",
        },
        {
            "key": "extract_devices",
            "label": "Import UniFi devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import every adopted device across every console: gateways, switches, access points, cameras, and the consoles themselves.",
        },
        {
            "key": "extract_hosts",
            "label": "Read console detail",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read GET /v1/hosts to enrich each console with its hardware model, serial, firmware, LAN addresses, and timezone, and to import a console that the device list does not cover. Turning this off leaves consoles with only the fields the device list carries.",
        },
        {
            "key": "extract_sites",
            "label": "Attach site names",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read GET /v1/sites and attach the site name, description, timezone, and ISP to the devices of each console.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 500,
            "description": "Rows requested per page. The API caps this at 500.",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages per collection",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 10000,
            "description": "Hard stop on how many pages one collection may fetch, so a cursor that never clears cannot turn a run into an unbounded request loop.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", "url_encode", "url_parse")
load("kwargs", "require", "get_http_options", "get_string", "get_bool", "get_int")
load("time", "parse_ts")

load('coerce', 'as_dict', 'as_list')
VENDOR = "unifi-site-manager"
ATTR_PREFIX = "unifi"
ATTR_SEPARATOR = "_"

DEFAULT_BASE_URL = "https://api.ui.com"

HOSTS_PATH = "/v1/hosts"
SITES_PATH = "/v1/sites"
DEVICES_PATH = "/v1/devices"

# Device families, matched against the shortname the API reports. Only families
# whose type is unambiguous are mapped; anything else is left unset rather than
# guessed at, and the raw shortname and productLine are always kept as
# attributes.
SHORTNAME_TYPES = [
    ("UVC", "IP Camera"),
    ("UVP", "VoIP Phone"),
    ("UDM", "Router"),
    ("UXG", "Router"),
    ("USG", "Router"),
    ("UCG", "Router"),
    ("UDW", "Router"),
    ("USW", "Switch"),
    ("USL", "Switch"),
    ("US-", "Switch"),
    ("USMINI", "Switch"),
    ("UAP", "Wireless Access Point"),
    ("UALR", "Wireless Access Point"),
    ("UWB", "Wireless Access Point"),
    ("U6", "Wireless Access Point"),
    ("U7", "Wireless Access Point"),
    ("UCK", "Server"),
]

# productLine is the coarser signal, used only when the shortname says nothing.
PRODUCT_LINE_TYPES = {
    "protect": "IP Camera",
}


def _clean(value):
    """Return a trimmed string for a scalar, or "" for anything else."""
    if type(value) == "string":
        return value.strip()
    if type(value) == "int" or type(value) == "float":
        return str(value)
    return ""
def _add_ips(found, values):
    """Append the routable addresses in values to found, de-duplicated."""
    for value in values:
        canonical = routable_ip(value)
        if canonical and canonical not in found:
            found.append(canonical)
    return found


def _hostname(value):
    """Return a usable hostname, or "".

    A UniFi device with no name is named after its own address or its model, and
    a console's name is often the same FQDN as its hostname; a bare address in
    the hostname field merges on something that already merges and outlives the
    lease that made it true.
    """
    text = _clean(value)
    if not text:
        return ""
    if text.lower() in ["localhost", "unknown", "unifi", "-"]:
        return ""
    if ip_address(text) != None:
        return ""
    return text


def _timestamp(value):
    """Return a parsed timestamp clamped to now, or None.

    parse_ts never raises: this API emits an EMPTY STRING for a date-time it
    does not have -- registrationTime and latestBackupTime both appear as "" in
    Ubiquiti's own examples -- and a malformed value must cost the field, not
    the run. The default clamp matters too: a future timestamp does not fail
    the field, it fails the entire ImportAsset, so an unclamped value from a
    device with a bad clock would drop the asset.
    """
    text = _clean(value)
    if not text:
        return None
    return parse_ts(text)


def _device_type(shortname, product_line):
    """Return a runZero device type for the families that name one unambiguously."""
    upper = shortname.upper()
    for prefix, device_type in SHORTNAME_TYPES:
        if upper.startswith(prefix):
            return device_type
    return PRODUCT_LINE_TYPES.get(product_line.lower(), "")


def fetch_page(ctx, path, cursor, label):
    """Fetch one page of a Site Manager collection.

    Returns (rows, nextToken). The query is built onto the URL rather than
    passed as params=, because params= REPLACES a URL's query string instead of
    merging with it -- passing it alongside a cursor silently wipes the cursor
    and restarts pagination from the first page, which is an infinite loop
    rather than an error.
    """
    query = {"pageSize": str(ctx["page_size"])}
    if cursor:
        query["nextToken"] = cursor
    url = "{}{}?{}".format(ctx["base_url"], path, url_encode(query))

    payload, err = get_json(url, **ctx["http_options"])
    if err:
        print("{}: {} request failed: {}".format(VENDOR, label, err))
        return None, ""
    if type(payload) != "dict":
        print("{}: {} response was not a JSON object".format(VENDOR, label))
        return None, ""

    data = payload.get("data")
    if type(data) != "list":
        code = _clean(payload.get("code"))
        message = _clean(payload.get("message"))
        if code or message:
            print("{}: {} returned {}: {}".format(VENDOR, label, code, message))
        else:
            print("{}: {} response carried no data array".format(VENDOR, label))
        return None, ""

    return data, _clean(payload.get("nextToken"))


def index_hosts(ctx):
    """Return every console keyed by its host id.

    Only the fields this integration uses are kept, so the index costs a few
    hundred bytes per console rather than the whole reportedState document,
    which on a UniFi OS console is several kilobytes of controller inventory.
    """
    hosts = {}
    cursor = ""
    p = pager("hosts", limit=ctx["max_pages"])
    while p.next():
        rows, cursor = fetch_page(ctx, HOSTS_PATH, cursor, "hosts")
        if rows == None:
            break
        for row in rows:
            if type(row) != "dict":
                print("{}: skipping host row that is not an object".format(VENDOR))
                continue
            host_id = _clean(row.get("id"))
            if not host_id:
                print("{}: skipping host with no id".format(VENDOR))
                continue

            state = as_dict(row.get("reportedState"))
            hardware = as_dict(state.get("hardware"))

            addresses = []
            _add_ips(addresses, [state.get("ip")])
            _add_ips(addresses, as_list(state.get("ipAddrs")))

            hosts[host_id] = {
                "id": host_id,
                "type": _clean(row.get("type")),
                # hardware.mac is preferred over reportedState.mac: the two
                # differ in Ubiquiti's own example, and hardware.mac is the one
                # that matches hardware.serialno and the device list's mac.
                "mac": _clean(hardware.get("mac")),
                "model": _clean(hardware.get("name")),
                "shortname": _clean(hardware.get("shortname")),
                "serial": _clean(hardware.get("serialno")),
                # UniFi OS keeps the firmware version inside hardware; a
                # self-hosted Network server reports firmware_version instead,
                # in a snake_case reportedState that shares no field names with
                # the console shape.
                "firmware": _clean(hardware.get("firmwareVersion")) or _clean(state.get("firmware_version")),
                "version": _clean(state.get("version")),
                "hostname": _clean(state.get("hostname")),
                "name": _clean(state.get("name")),
                "state": _clean(state.get("state")),
                "timezone": _clean(state.get("timezone")),
                "direct_connect": _clean(state.get("directConnectDomain")),
                "addresses": addresses,
                # The top-level ipAddress is the address the CLOUD saw, which
                # for a console behind NAT is the site's public WAN address --
                # shared by every device at that site. It is recorded and
                # deliberately never placed on an interface.
                "cloud_address": _clean(row.get("ipAddress")),
                "blocked": row.get("isBlocked"),
                "owner": row.get("owner"),
                "registration_time": _clean(row.get("registrationTime")),
                "last_state_change": _clean(row.get("lastConnectionStateChange")),
                "covered": False,
            }
        if not cursor:
            break
    return hosts


def index_sites(ctx):
    """Return the site records for each console, keyed by host id."""
    sites = {}
    cursor = ""
    p = pager("sites", limit=ctx["max_pages"])
    while p.next():
        rows, cursor = fetch_page(ctx, SITES_PATH, cursor, "sites")
        if rows == None:
            break
        for row in rows:
            if type(row) != "dict":
                continue
            host_id = _clean(row.get("hostId"))
            if not host_id:
                continue
            meta = as_dict(row.get("meta"))
            statistics = as_dict(row.get("statistics"))
            isp = as_dict(statistics.get("ispInfo"))
            entry = {
                "site_id": _clean(row.get("siteId")),
                "site_name": _clean(meta.get("name")),
                "site_desc": _clean(meta.get("desc")),
                "site_timezone": _clean(meta.get("timezone")),
                "site_gateway_mac": _clean(meta.get("gatewayMac")),
                "site_isp": _clean(isp.get("name")),
            }
            # A console can host several sites. The first is attached and the
            # rest are counted, rather than concatenating names that would then
            # be wrong for every device on the console.
            if host_id in sites:
                sites[host_id]["site_count"] = sites[host_id].get("site_count", 1) + 1
            else:
                entry["site_count"] = 1
                sites[host_id] = entry
        if not cursor:
            break
    return sites


def _device_attrs(device, host, site, host_id, host_name, updated_at):
    """Return the custom attributes for one device."""
    raw = {
        "host_id": host_id,
        "host_name": host_name,
        "product_line": _clean(device.get("productLine")),
        "shortname": _clean(device.get("shortname")),
        "model": _clean(device.get("model")),
        "status": _clean(device.get("status")),
        "firmware_status": _clean(device.get("firmwareStatus")),
        "update_available": _clean(device.get("updateAvailable")),
        "is_console": device.get("isConsole"),
        "is_managed": device.get("isManaged"),
        "startup_time": _clean(device.get("startupTime")),
        "adoption_time": _clean(device.get("adoptionTime")),
        "note": _clean(device.get("note")),
        "updated_at": updated_at,
    }
    if site:
        for key in ["site_id", "site_name", "site_desc", "site_timezone", "site_isp"]:
            raw[key] = site.get(key, "")
        if site.get("site_count", 1) > 1:
            raw["site_count"] = site.get("site_count")
    if host:
        raw["console_serial"] = host.get("serial", "")
        raw["console_firmware"] = host.get("firmware", "")
        raw["console_state"] = host.get("state", "")
        raw["console_timezone"] = host.get("timezone", "")
        raw["console_direct_connect"] = host.get("direct_connect", "")
        raw["console_cloud_address"] = host.get("cloud_address", "")
        raw["console_registration_time"] = host.get("registration_time", "")
    return to_custom_attributes(raw, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)


def build_device(ctx, device, host_id, host_name, updated_at):
    """Convert one device row into an ImportAsset, or None when it has no id."""
    if type(device) != "dict":
        print("{}: skipping device row that is not an object".format(VENDOR))
        return None

    device_id = _clean(device.get("id"))
    if not device_id:
        print("{}: skipping device with no id under host {}".format(VENDOR, host_id))
        return None

    asset_id = "{}:{}:device:{}".format(VENDOR, ctx["namespace"], device_id)
    if asset_id in ctx["seen"]:
        print("{}: skipping duplicate device id {}".format(VENDOR, device_id))
        return None
    ctx["seen"][asset_id] = True

    host = ctx["hosts"].get(host_id)
    site = ctx["sites"].get(host_id)

    addresses = _add_ips([], [device.get("ip")])
    mac = _clean(device.get("mac"))

    # A console's own row carries only its management address, while the host
    # record knows every address the appliance holds. They are the same box, so
    # the host's addresses are folded in.
    if host and device.get("isConsole") == True:
        _add_ips(addresses, host.get("addresses", []))
        if not mac:
            mac = host.get("mac", "")

    nic = network_interface(mac=mac, ips=addresses)
    interfaces = [nic] if nic else []

    hostname = _hostname(device.get("name"))
    if host and device.get("isConsole") == True and not hostname:
        hostname = _hostname(host.get("hostname"))

    shortname = _clean(device.get("shortname"))
    tags = []
    if host and device.get("isConsole") == True and host.get("serial"):
        tags.append("serial:" + host.get("serial"))

    asset = ImportAsset(
        id=asset_id,
        hostnames=[hostname],
        networkInterfaces=interfaces,
        manufacturer="Ubiquiti",
        model=_clean(device.get("model")),
        osVersion=_clean(device.get("version")),
        deviceType=_device_type(shortname, _clean(device.get("productLine"))),
        tags=tags,
        customAttributes=_device_attrs(device, host, site, host_id, host_name, updated_at),    )

    # updatedAt is when the cloud last refreshed this host's device list, not
    # when the device was last observed. It is only claimed as a sighting for a
    # device the same refresh reported online; for an offline device the value
    # says when the cloud last looked, which is not the same thing.
    if _clean(device.get("status")).lower() == "online":
        seen = _timestamp(updated_at)
        if seen != None:
            asset.lastSeenTS = seen

    return asset


def build_devices(ctx, groups):
    """Convert one page of host-grouped device rows into ImportAssets."""
    assets = []
    for group in groups:
        if type(group) != "dict":
            print("{}: skipping device group that is not an object".format(VENDOR))
            continue
        host_id = _clean(group.get("hostId"))
        host_name = _clean(group.get("hostName"))
        updated_at = _clean(group.get("updatedAt"))

        host = ctx["hosts"].get(host_id)
        if host:
            host["covered"] = True

        for device in as_list(group.get("devices")):
            asset = build_device(ctx, device, host_id, host_name, updated_at)
            if asset != None:
                assets.append(asset)
    return assets


def build_orphan_hosts(ctx):
    """Return assets for consoles the device list never mentioned.

    A console that the device collection did not cover -- because it is offline,
    because it is a self-hosted Network server rather than adopted hardware, or
    because the two collections simply disagree -- would otherwise be invisible.

    The identifier matters more than the asset here. A console with a hardware
    MAC is given the identifier the device collection WOULD have given it, which
    is that MAC in the vendor's own uppercase colonless form, so that the same
    console keeps one identity whichever collection reports it next time. A
    self-hosted Network server has no hardware MAC and cannot appear in the
    device collection at all, so it keeps its host id.
    """
    assets = []
    for host_id in sorted(ctx["hosts"]):
        host = ctx["hosts"][host_id]
        if host["covered"]:
            continue

        mac = host["mac"]
        if mac:
            asset_id = "{}:{}:device:{}".format(
                VENDOR, ctx["namespace"], mac.replace(":", "").replace("-", "").upper())
            # Derived from an address, so it must not drive or block a merge.
            # See build_device for the full reasoning. No type of its own: this
            # is the integration-wide policy, which CONFIG already declares.
            asset_type = ""
        else:
            asset_id = "{}:{}:host:{}".format(VENDOR, ctx["namespace"], host_id)
            # The host id is an opaque UUID Ubiquiti issues, not an address, so
            # it is allowed to drive a merge. A self-hosted Network Server
            # publishes at most one address and no MAC, so network churn must
            # not veto one. That is the 'host' entry in CONFIG's
            # assetTypeBehavior, which only applies if the type is set here.
            asset_type = "host"
        if asset_id in ctx["seen"]:
            continue
        ctx["seen"][asset_id] = True

        nic = network_interface(mac=mac, ips=host["addresses"])
        interfaces = [nic] if nic else []
        hostname = _hostname(host["hostname"]) or _hostname(host["name"])
        if not interfaces and not hostname:
            print("{}: skipping host {} with no address, MAC, or hostname".format(VENDOR, host_id))
            continue

        site = ctx["sites"].get(host_id)
        raw = {
            "host_id": host_id,
            "host_type": host["type"],
            "state": host["state"],
            "timezone": host["timezone"],
            "direct_connect": host["direct_connect"],
            "console_cloud_address": host["cloud_address"],
            "console_serial": host["serial"],
            "blocked": host["blocked"],
            "owner": host["owner"],
            "registration_time": host["registration_time"],
            "last_state_change": host["last_state_change"],
            "covered_by_device_list": False,
        }
        if site:
            for key in ["site_id", "site_name", "site_desc", "site_timezone", "site_isp"]:
                raw[key] = site.get(key, "")

        tags = []
        if host["serial"]:
            tags.append("serial:" + host["serial"])

        asset = ImportAsset(
            id=asset_id,
            hostnames=[hostname],
            networkInterfaces=interfaces,
            manufacturer="Ubiquiti",
            model=host["model"],
            osVersion=host["firmware"] or host["version"],
            deviceType=_device_type(host["shortname"], ""),
            tags=tags,
            customAttributes=to_custom_attributes(
                raw, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            assetType=asset_type,
        )

        last_change = _timestamp(host["last_state_change"])
        if last_change != None and host["state"].lower() == "connected":
            asset.lastSeenTS = last_change

        assets.append(asset)
    return assets


def main(*args, **kwargs):
    require(kwargs, "api_key")

    base_url = get_string(kwargs, "url", default=DEFAULT_BASE_URL).strip().removesuffix("/")
    if not base_url:
        base_url = DEFAULT_BASE_URL

    parsed = url_parse(base_url)
    namespace = parsed.hostname.lower() if parsed and parsed.hostname else base_url

    headers = {
        "X-API-Key": get_string(kwargs, "api_key"),
        "Accept": "application/json",
    }
    ctx = {
        "base_url": base_url,
        "namespace": namespace,
        "page_size": get_int(kwargs, "page_size", default=100),
        "max_pages": get_int(kwargs, "max_pages", default=200),
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
        "hosts": {},
        "sites": {},
        "seen": {},
    }

    extract_devices = get_bool(kwargs, "extract_devices", default=True)
    extract_hosts = get_bool(kwargs, "extract_hosts", default=True)
    extract_sites = get_bool(kwargs, "extract_sites", default=True)

    if extract_hosts:
        ctx["hosts"] = index_hosts(ctx)
    if extract_sites:
        ctx["sites"] = index_sites(ctx)

    reported = 0
    if extract_devices:
        cursor = ""
        # pager raises when the bound is hit with a cursor still pending, so an
        # incomplete import is reported as an error instead of silently
        # truncated. Same for the hosts and sites walks above.
        p = pager("devices", limit=ctx["max_pages"])
        while p.next():
            groups, cursor = fetch_page(ctx, DEVICES_PATH, cursor, "devices")
            if groups == None:
                break
            if groups:
                reported += report_assets(build_devices(ctx, groups))
            if not cursor:
                break

    if extract_hosts:
        orphans = build_orphan_hosts(ctx)
        if orphans:
            reported += report_assets(orphans)

    print("{}: reported {} assets from {} console(s)".format(
        VENDOR, reported, len(ctx["hosts"])))
    # Devices are streamed with report_assets a page at a time; only the console
    # index and the leftover consoles are held, and both are one entry per
    # console rather than one per device.
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-workspace-one-uem",
    "name": "Workspace ONE UEM",
    "type": "inbound",
    "description": "Imports enrolled devices, pending OS updates, and installed applications from Omnissa Workspace ONE UEM.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Workspace ONE UEM API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://asXXX.awmdm.com",
            "description": "REST API URL shown under Settings > System > Advanced > API > REST API.",
        },
        {
            "key": "username",
            "label": "API username",
            "type": "string",
            "required": True,
            "description": "Workspace ONE UEM administrator account with a read-only role.",
        },
        {
            "key": "password",
            "label": "API password",
            "type": "secret",
            "required": True,
            "description": "Password for the administrator account. Sent as HTTP Basic auth.",
        },
        {
            "key": "api_key",
            "label": "API key (tenant code)",
            "type": "secret",
            "required": True,
            "description": "REST API key from Settings > System > Advanced > API > REST API. Sent as the aw-tenant-code header alongside Basic auth; both are required.",
        },
        {
            "key": "organization_group_id",
            "label": "Organization group ID",
            "type": "string",
            "required": False,
            "description": "Numeric organization group ID to limit the search to. Defaults to the API user's own organization group.",
        },
        {
            "key": "include_os_updates",
            "label": "Import pending OS updates",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch pending OS and firmware updates per device and attach them as patch-level attributes. Costs one extra request per device.",
        },
        {
            "key": "include_software",
            "label": "Import installed applications",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch installed and assigned applications per device. Costs at least one extra request per device.",
        },
        {
            "key": "detail_device_limit",
            "label": "Per-device detail limit",
            "type": "int",
            "required": False,
            "default": 250,
            "min": 1,
            "description": "Maximum number of devices to query for OS updates and installed applications. Devices past this limit are imported without that detail and the skipped count is logged.",
        },
        {
            "key": "page_size",
            "label": "Device page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 500,
            "description": "Devices requested per page from the device search endpoint.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac')
load('http', 'get_json', 'basic')
load('time', 'parse_ts')
load('re', re_match='match')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')

DEVICES_PATH = "/api/mdm/devices/search"
DEVICE_APPS_PATH = "/api/mdm/devices/{}/apps/search"
DEVICE_OSUPDATE_PATH = "/api/mdm/devices/{}/osupdate"

# Workspace ONE UEM selects a response schema from the Accept header rather than
# the URL. The device search and OS update endpoints are consumed at version 2,
# which is the PascalCase "Devices"/"Total" envelope. The per-device application
# search is a version 1 endpoint and returns the lower-case "app_items" envelope.
ACCEPT_DEVICES = "application/json;version=2"
ACCEPT_APPS = "application/json;version=1"

# The device search endpoint pages over an unstable default ordering, so the
# sort is pinned explicitly. Without it a device can be seen twice or missed
# entirely when the inventory changes between page requests.
DEVICE_ORDER_BY = "deviceid"
DEVICE_SORT_ORDER = "ASC"

APP_PAGE_SIZE = 100

# Workspace ONE UEM publishes a per-tenant request budget and reports it on
# every response through X-RateLimit-Limit / -Remaining / -Reset, returning 429
# once the budget is spent. get_json defaults to a single attempt, so the retry
# budget is opted into explicitly here; Retry-After is honored by the helper.
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0
HTTP_RETRY_MAX_BACKOFF = 60.0

CHILD_LIMIT = 99
MAX_OS_UPDATES_LISTED = 20

# Workspace ONE UEM writes the sentinel 0001-01-01T00:00:00 instead of null
# when a timestamp has never been set, and it also emits local timestamps with
# no zone designator. Both go straight through parse_ts: the sentinel's
# non-positive epoch yields None, zone-less values are read as UTC, and a
# future value is clamped to now rather than costing the record.

# Version strings arrive either bare ("10.0.18363") or prefixed with a product
# name ("iOS 14.6"), so the name and version are separated at the first digit.
OS_VERSION_RE = r"^([^0-9]*?)\s*([0-9][0-9A-Za-z.\-_]*)$"

# A friendly name is an operator-chosen label, not a resolvable name. Only
# values that are actually hostname shaped are promoted to hostnames.
HOSTNAME_RE = r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,252}[A-Za-z0-9])?$"

# Workspace ONE UEM reports the platform family, which fixes the OS name but
# never the version.
PLATFORM_OS = {
    "apple": "iOS",
    "appleios": "iOS",
    "ios": "iOS",
    "ipados": "iPadOS",
    "appleosx": "macOS",
    "applemacos": "macOS",
    "macos": "macOS",
    "osx": "macOS",
    "android": "Android",
    "androidamazon": "Android",
    "winrt": "Windows",
    "windows": "Windows",
    "windowspc": "Windows",
    "windowsdesktop": "Windows",
    "windowsrugged": "Windows",
    "windowsphone": "Windows Phone",
    "blackberry": "BlackBerry",
    "chromeos": "Chrome OS",
    "tizen": "Tizen",
    "qnx": "QNX",
}

# Platforms that are unambiguously handheld. Windows and Chrome OS are absent on
# purpose: the platform alone cannot separate a laptop from a desktop, so those
# devices are left for runZero's own fingerprinting unless the model says more.
MOBILE_PLATFORMS = ["apple", "appleios", "ios", "android", "androidamazon", "windowsphone", "blackberry"]
DESKTOP_PLATFORMS = ["appleosx", "applemacos", "macos", "osx"]

# Ownership is returned as a single-letter code by the search endpoint.
OWNERSHIP = {"c": "corporate", "e": "employee", "s": "shared"}

# Addresses that must never reach a NetworkInterface: an agent that reports only
# a loopback or link-local address would otherwise merge every such host onto a
# single runZero asset.
UNUSABLE_IP_PREFIXES = ["127.", "0.0.0.0", "169.254.", "fe8", "fe9", "fea", "feb"]
UNUSABLE_IPS = ["::1", "::", "0.0.0.0", "0:0:0:0:0:0:0:1"]


def _clean(value):
    """Return a value as a trimmed string, mapping None and containers to empty."""
    if value == None:
        return ""
    if type(value) == "dict" or type(value) == "list":
        return ""
    if type(value) == "bool":
        if value:
            return "true"
        return "false"
    return str(value).strip()


def _scalar(value):
    """Unwrap the {"Value": x} envelope Workspace ONE UEM uses for numeric ids."""
    if type(value) == "dict":
        return _clean(value.get("Value"))
    return _clean(value)
def _usable_ip(value):
    """Return an address string only when it is routable enough to merge on."""
    text = _clean(value).lower()
    if not text or text in UNUSABLE_IPS:
        return ""
    for prefix in UNUSABLE_IP_PREFIXES:
        if text.startswith(prefix):
            return ""
    return text


def _tag_value(prefix, value):
    """Build a key:value tag, collapsing whitespace so the tag stays one token."""
    text = _clean(value)
    if not text:
        return ""
    return prefix + ":" + text.replace(" ", "-")


def _split_os(operating_system, platform_name):
    """Split the reported OS string into a name and a version.

    The search endpoint usually reports a bare version ("10.0.18363") and leaves
    the product name to the Platform field, but some platforms prefix the name
    ("iOS 14.6"), so both shapes are handled.
    """
    default_name = PLATFORM_OS.get(platform_name.lower(), "")
    text = _clean(operating_system)
    if not text:
        return default_name, ""
    matched = re_match(OS_VERSION_RE, text)
    if matched:
        name = matched.groups[1].strip()
        version = matched.groups[2].strip()
        if not name:
            name = default_name
        return name, version
    if default_name:
        return default_name, ""
    return text, ""


def _device_type(platform_name, model):
    """Map platform and model onto a runZero device type.

    The model is checked first because it is the only field that separates a
    tablet from a phone or a MacBook from an iMac. Windows and Chrome OS
    platforms fall through to an empty string rather than guessing between
    laptop and desktop, which leaves runZero's own fingerprinting in charge.
    """
    model_text = model.lower()
    platform_text = platform_name.lower()
    if "ipad" in model_text or "tablet" in model_text or "galaxy tab" in model_text:
        return "Tablet"
    if "iphone" in model_text or "ipod" in model_text:
        return "Mobile"
    if "book" in model_text:
        return "Laptop"
    if platform_text in MOBILE_PLATFORMS:
        return "Mobile"
    if platform_text in DESKTOP_PLATFORMS:
        return "Desktop"
    return ""


def _hostnames(device):
    """Return the names that are safe to merge on.

    HostName and LocalHostName are reported by the device itself. The friendly
    and reported names are operator-facing labels that routinely contain spaces
    and possessives ("user123's Laptop"), so they are only promoted when they
    are hostname shaped; the raw values are kept as custom attributes either way.
    """
    names = []
    for key in ["HostName", "LocalHostName", "DeviceFriendlyName", "DeviceReportedName"]:
        candidate = _clean(device.get(key))
        if not candidate or candidate in names:
            continue
        if not re_match(HOSTNAME_RE, candidate):
            continue
        names.append(candidate)
    return names


def _network_interfaces(device):
    """Build interfaces from the per-adapter network info plus the primary MAC.

    DeviceNetworkInfo carries one entry per adapter with its own MAC and IP.
    Loopback and link-local addresses are dropped before the interface is built.
    The top-level MacAddress is added as a MAC-only interface when no adapter
    already reported it, which is the common case for mobile devices that
    publish no address at all.
    """
    netifs = []
    seen_macs = []
    raw_ips = []

    entries = device.get("DeviceNetworkInfo", [])
    if type(entries) != "list":
        entries = []
    for entry in entries:
        if type(entry) != "dict":
            continue
        raw = _clean(entry.get("IPAddress"))
        if raw:
            raw_ips.append(raw)
        entry_mac = _clean(entry.get("MACAddress"))
        usable = _usable_ip(raw)
        nic = network_interface(mac=entry_mac, ips=[usable] if usable else [])
        if not nic:
            continue
        normalized = normalize_mac(entry_mac)
        if normalized:
            seen_macs.append(normalized)
        netifs.append(nic)

    primary_mac = _clean(device.get("MacAddress"))
    normalized_primary = normalize_mac(primary_mac)
    if primary_mac and normalized_primary not in seen_macs:
        nic = network_interface(mac=primary_mac)
        if nic:
            netifs.append(nic)

    return netifs[:CHILD_LIMIT], raw_ips


def build_software(app_items):
    """Convert one device's app_items array into Software objects."""
    software = []
    for entry in app_items:
        if type(entry) != "dict":
            continue
        name = _clean(entry.get("name"))
        if not name:
            continue
        bundle_id = _clean(entry.get("bundle_id"))
        installed_version = _clean(entry.get("installed_version"))
        assigned_version = _clean(entry.get("assigned_version"))
        attrs = {
            "bundle_id": bundle_id,
            "assigned_version": assigned_version,
        }
        # No CPE is published for these applications, so cpe23 is left unset
        # rather than synthesized.
        software.append(Software(
            id=(bundle_id or name)[:255],
            product=name[:255],
            version=(installed_version or assigned_version)[:255],
            serviceAddress="127.0.0.1",
            customAttributes=to_custom_attributes(attrs, prefix="workspace_one", separator="_"),
        ))
        if len(software) >= CHILD_LIMIT:
            break
    return software


def build_os_update_attributes(updates):
    """Summarize pending OS updates into flat patch-level attributes."""
    pending = []
    critical = 0
    restart = False
    for update in updates:
        if type(update) != "dict":
            continue
        name = _clean(update.get("deviceUpdateName"))
        version = _clean(update.get("deviceUpdateVersion"))
        label = (name + " " + version).strip()
        if label and len(pending) < MAX_OS_UPDATES_LISTED:
            pending.append(label)
        if update.get("isCritical") == True:
            critical += 1
        if update.get("restartRequired") == True:
            restart = True
    return {
        "os_update_pending_count": len(updates),
        "os_update_critical_count": critical,
        "os_update_restart_required": restart,
        "os_update_pending": pending,
        "os_update_latest": pending[0] if pending else "",
    }


def build_asset(device, tenant_host, software, os_update_attrs):
    """Build a single ImportAsset from one Workspace ONE UEM device record."""
    device_uuid = _scalar(device.get("Uuid")).lower()
    platform_name = _clean(device.get("Platform"))
    model = _clean(device.get("Model"))
    serial_number = _clean(device.get("SerialNumber"))
    os_name, os_version = _split_os(device.get("OperatingSystem"), platform_name)
    netifs, raw_ips = _network_interfaces(device)

    tags = ["workspace-one-uem"]
    for tag in [
        _tag_value("serial", serial_number),
        _tag_value("enrollment", device.get("EnrollmentStatus")),
        _tag_value("compliance", device.get("ComplianceStatus")),
        _tag_value("platform", platform_name),
        _tag_value("ownership", OWNERSHIP.get(_clean(device.get("Ownership")).lower(), device.get("Ownership"))),
    ]:
        if tag:
            tags.append(tag)
    if device.get("CompromisedStatus") == True:
        tags.append("compromised")

    location_group = device.get("LocationGroupId", {})
    if type(location_group) != "dict":
        location_group = {}
    user = device.get("UserId", {})
    if type(user) != "dict":
        user = {}

    attrs = {
        "device_uuid": device_uuid,
        "device_id": _scalar(device.get("Id")),
        "serial_number": serial_number,
        "udid": _clean(device.get("Udid")),
        "imei": _clean(device.get("Imei")),
        "asset_number": _clean(device.get("AssetNumber")),
        "eas_id": _clean(device.get("EasId")),
        "friendly_name": _clean(device.get("DeviceFriendlyName")),
        "reported_name": _clean(device.get("DeviceReportedName")),
        "host_name": _clean(device.get("HostName")),
        "local_host_name": _clean(device.get("LocalHostName")),
        "mac_address": _clean(device.get("MacAddress")),
        # The unfiltered address list is preserved even when every entry was
        # dropped as loopback or link-local.
        "ip_addresses": ",".join(raw_ips),
        "user_name": _clean(device.get("UserName")),
        "user_email_address": _clean(device.get("UserEmailAddress")),
        "user_id": _scalar(user.get("Id")),
        "enrollment_user_uuid": _clean(device.get("EnrollmentUserUuid")),
        "ownership": _clean(device.get("Ownership")),
        "platform": platform_name,
        "model": model,
        "operating_system": _clean(device.get("OperatingSystem")),
        "os_build_version": _clean(device.get("OSBuildVersion")),
        "oem_info": _clean(device.get("OEMInfo")),
        "processor_architecture": _clean(device.get("ProcessorArchitecture")),
        "total_physical_memory": _clean(device.get("TotalPhysicalMemory")),
        "available_physical_memory": _clean(device.get("AvailablePhysicalMemory")),
        "device_capacity": _clean(device.get("DeviceCapacity")),
        "available_device_capacity": _clean(device.get("AvailableDeviceCapacity")),
        "battery_level": _clean(device.get("BatteryLevel")),
        "enrollment_status": _clean(device.get("EnrollmentStatus")),
        "compliance_status": _clean(device.get("ComplianceStatus")),
        "compromised_status": _clean(device.get("CompromisedStatus")),
        "is_supervised": _clean(device.get("IsSupervised")),
        "data_encryption": _clean(device.get("DataEncryptionYN")),
        "system_integrity_protection": _clean(device.get("SystemIntegrityProtectionEnabled")),
        "enrolled_via_dep": _clean(device.get("EnrolledViaDEP")),
        "user_approved_enrollment": _clean(device.get("UserApprovedEnrollment")),
        "managed_by": _clean(device.get("ManagedBy")),
        "security_patch_date": _clean(device.get("SecurityPatchDate")),
        "is_security_patch_update": _clean(device.get("IsSecurityPatchUpdate")),
        "last_seen": _clean(device.get("LastSeen")),
        "last_enrolled_on": _clean(device.get("LastEnrolledOn")),
        "last_compliance_check_on": _clean(device.get("LastComplianceCheckOn")),
        "last_system_sample_time": _clean(device.get("LastSystemSampleTime")),
        "location_group_id": _scalar(location_group.get("Id")),
        "location_group_name": _clean(device.get("LocationGroupName")) or _clean(location_group.get("Name")),
        "location_group_uuid": _clean(location_group.get("Uuid")),
        "phone_number": _clean(device.get("PhoneNumber")),
        "wifi_ssid": _clean(device.get("WifiSsid")),
        "time_zone": _clean(device.get("TimeZone")),
        "tenant_host": tenant_host,
    }
    for key in os_update_attrs:
        attrs[key] = os_update_attrs[key]

    asset = ImportAsset(
        # The device UUID is authoritative within a tenant but a re-enrollment
        # mints a new one, so MAC, IP, and hostname churn must not disqualify a
        # merge back onto the hardware runZero already knows about.
        id="workspace-one-uem:{}:{}".format(tenant_host, device_uuid),
        hostnames=_hostnames(device),
        networkInterfaces=netifs,
        os=os_name,
        osVersion=os_version,
        manufacturer=_clean(device.get("OEMInfo")),
        model=model,
        deviceType=_device_type(platform_name, model),
        tags=tags,
        software=software[:CHILD_LIMIT],
        customAttributes=to_custom_attributes(attrs, prefix="workspace_one", separator="_"),
    )

    enrolled = parse_ts(device.get("LastEnrolledOn"))
    if enrolled:
        asset.firstSeenTS = enrolled
    # The ImportAsset constructor rejects lastSeenTS, so it is assigned after
    # construction.
    last_seen = parse_ts(device.get("LastSeen"))
    if last_seen:
        asset.lastSeenTS = last_seen

    return asset


def fetch_device_apps(base_url, http_options, device_uuid):
    """Fetch every page of installed and assigned applications for one device."""
    app_items = []
    url = base_url + DEVICE_APPS_PATH.format(device_uuid)
    _pager1 = pager("workspace-one-uem-1")
    while _pager1.next():
        page = _pager1.page - 1
        data, err = get_json(url, params={"page": page, "pagesize": APP_PAGE_SIZE},
                             **http_options)
        if err:
            print("workspace-one-uem: failed to fetch applications for one device:", err)
            return app_items
        # An empty 204 body decodes to None, which is how this endpoint signals
        # that a device has no application inventory.
        data = data or {}
        items = data.get("app_items", []) or []
        if not items:
            break
        for item in items:
            app_items.append(item)
            if len(app_items) >= CHILD_LIMIT:
                return app_items
        total = data.get("TotalResults", 0) or 0
        if (page + 1) * APP_PAGE_SIZE >= total:
            break
    return app_items


def fetch_os_updates(base_url, http_options, device_uuid):
    """Fetch pending OS and firmware updates for one device."""
    url = base_url + DEVICE_OSUPDATE_PATH.format(device_uuid)
    data, err = get_json(url, **http_options)
    if err:
        print("workspace-one-uem: failed to fetch OS updates for one device:", err)
        return []
    data = data or {}
    updates = data.get("OSUpdateList", []) or []
    if type(updates) != "list":
        return []
    return updates


def build_assets(devices, tenant_host, base_url, apps_options, detail_options,
                 include_os_updates, include_software, detail_state):
    """Build one page of ImportAssets, attaching optional per-device detail."""
    assets = []
    for device in devices:
        if type(device) != "dict":
            print("workspace-one-uem: skipping malformed device record")
            continue
        device_uuid = _scalar(device.get("Uuid"))
        if not device_uuid:
            print("workspace-one-uem: skipping device with no Uuid: id=" + _scalar(device.get("Id")))
            continue

        software = []
        os_update_attrs = {}
        if include_os_updates or include_software:
            if detail_state["fetched"] < detail_state["limit"]:
                detail_state["fetched"] += 1
                if include_software:
                    software = build_software(
                        fetch_device_apps(base_url, apps_options, device_uuid))
                if include_os_updates:
                    os_update_attrs = build_os_update_attributes(
                        fetch_os_updates(base_url, detail_options, device_uuid))
            else:
                detail_state["skipped"] += 1

        assets.append(build_asset(device, tenant_host, software, os_update_attrs))
    return assets


def fetch_and_report_devices(base_url, tenant_host, devices_options, apps_options,
                             page_size, organization_group_id, include_os_updates,
                             include_software, detail_state):
    """Fetch and stream devices one page at a time so the full inventory is never
    held in memory at once.

    Returns (reported, walk_err). The caller prints its summary before failing
    on walk_err, so a truncated walk is not filed as a complete estate."""
    reported = 0
    walk_err = None
    url = base_url + DEVICES_PATH

    _pager2 = pager("workspace-one-uem-2")

    while _pager2.next():

        page = _pager2.page - 1
        params = {
            "page": page,
            "pagesize": page_size,
            "orderby": DEVICE_ORDER_BY,
            "sortorder": DEVICE_SORT_ORDER,
        }
        if organization_group_id:
            # lgid is the documented organization-group filter on the v1
            # search schema; whether the version-2 Accept schema honors the
            # same spelling is unconfirmed, so the OG UUID-era alias is sent
            # alongside it. Servers ignore the query parameter they do not
            # know, so sending both is safe and one of them filters.
            params["lgid"] = organization_group_id
            params["organizationgroupid"] = organization_group_id

        data, err = get_json(url, params=params, **devices_options)
        if err:
            print("workspace-one-uem: failed to fetch devices on page {}: {}".format(page, err))
            if err.startswith("status 401"):
                print("workspace-one-uem: check the API username and password")
            if err.startswith("status 403"):
                print("workspace-one-uem: check the API key and that the account holds a read-only API role")
            walk_err = "failed to fetch devices after reporting {}: {}".format(reported, err)
            break
        # A search with no matches answers 204 with an empty body.
        data = data or {}
        devices = data.get("Devices", []) or []
        if not devices:
            break

        assets = build_assets(devices, tenant_host, base_url, apps_options,
                              devices_options, include_os_updates, include_software,
                              detail_state)
        if assets:
            reported += report_assets(assets)

        total = data.get("Total", 0) or 0
        print("workspace-one-uem: reported {} of {} devices".format(reported, total))
        if (page + 1) * page_size >= total:
            break

    return reported, walk_err


def main(**kwargs):
    require(kwargs, "url", "username", "password", "api_key")
    base_url = get_url_base(kwargs)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    api_key = get_string(kwargs, "api_key")
    organization_group_id = get_string(kwargs, "organization_group_id", default="")
    include_os_updates = get_bool(kwargs, "include_os_updates", default=False)
    include_software = get_bool(kwargs, "include_software", default=False)
    detail_device_limit = get_int(kwargs, "detail_device_limit", default=250)
    page_size = get_int(kwargs, "page_size", default=500)

    # The tenant hostname scopes device UUIDs, and dropping the scheme keeps the
    # asset identity stable if the configured URL ever changes protocol.
    tenant_host = base_url.split("://")[-1]

    auth = basic(username, password)
    devices_options = get_http_options(kwargs, headers={
        "Authorization": auth,
        "aw-tenant-code": api_key,
        "Accept": ACCEPT_DEVICES,
    })
    apps_options = get_http_options(kwargs, headers={
        "Authorization": auth,
        "aw-tenant-code": api_key,
        "Accept": ACCEPT_APPS,
    })
    for options in [devices_options, apps_options]:
        options["retries"] = HTTP_RETRIES
        options["retry_backoff"] = HTTP_RETRY_BACKOFF
        options["retry_max_backoff"] = HTTP_RETRY_MAX_BACKOFF

    detail_state = {"fetched": 0, "skipped": 0, "limit": detail_device_limit}
    reported, walk_err = fetch_and_report_devices(base_url, tenant_host, devices_options,
                                                  apps_options, page_size, organization_group_id,
                                                  include_os_updates, include_software, detail_state)

    if include_os_updates or include_software:
        print("workspace-one-uem: fetched per-device detail for {} devices".format(detail_state["fetched"]))
        if detail_state["skipped"]:
            print("workspace-one-uem: skipped per-device detail for {} devices; raise the per-device detail limit ({}) to cover more".format(
                detail_state["skipped"], detail_device_limit))
    if walk_err != None:
        fail("workspace-one-uem: " + walk_err)
    if not reported:
        print("workspace-one-uem: no assets retrieved")
    return None

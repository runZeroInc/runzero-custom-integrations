# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-miradore",
    "name": "Miradore",
    "type": "inbound",
    "description": "Imports managed devices, hardware, OS, installed software, owners, and network addresses from Miradore.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Device.ID is the Miradore site's own database key for the enrollment, so it
    # is stable across runs and one-per-device. What churns on an MDM fleet is
    # everything else: phones roam between networks, pick up new DHCP leases, and
    # are renamed by their owners. Keep id-based merging authoritative and stop
    # drift in the other three dimensions from blocking a legitimate merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "ownershipAttributes": ["miradore_user_email"],
    # The repo-wide record target is ten million per run; at the default 500 rows
    # a page that is 20,000 pages.
    "maxPages": 20000,
    "params": [
        {
            "key": "url",
            "label": "Miradore base URL",
            "description": "Miradore Online, or the base URL of an on-premises Miradore server.",
            "type": "url",
            "required": True,
            "default": "https://online.miradore.com",
            "placeholder": "https://online.miradore.com",
        },
        {
            "key": "api_key",
            "label": "API v1 authentication key",
            "description": "Authentication key generated in the Miradore console under System > Infrastructure diagram. The key identifies the site on its own, so the site name is not needed.",
            "type": "secret",
            "required": True,
        },
        {
            "key": "site_name",
            "label": "Miradore site name",
            "description": "The site name shown in the Miradore console. The API does not need it -- the authentication key already selects the site -- but it scopes imported asset IDs, because Miradore numbers devices per site and every site has a device 1.",
            "type": "string",
            "required": True,
        },
        {
            "key": "page_size",
            "label": "Devices per page",
            "description": "Maps to the API's rows option. Capped at 25 while application inventory is enabled, because a page of devices with their applications is roughly 34 times larger and the parsed page has to fit in the Explorer's memory budget.",
            "type": "int",
            "default": 100,
            "min": 1,
            "max": 5000,
        },
        {
            "key": "include_software",
            "label": "Import installed applications",
            "description": "Adds each device's application inventory. This is the single largest part of the response, so turning it off makes a run substantially faster.",
            "type": "bool",
            "default": True,
        },
        {
            "key": "include_deleted",
            "label": "Include deleted and auto-generated devices",
            "description": "By default only Active and New devices are imported. Miradore keeps Deleted records in the database and returns them to the API.",
            "type": "bool",
            "default": False,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

# Miradore exposes two APIs, and only one of them can enumerate devices.
#
# API v2 (https://www.miradore.com/knowledge/integrations/miradore-api-v2/) is a
# device *management* API. Its OpenAPI document
# (https://online.miradore.com/swagger/v2/swagger.json) declares no collection
# GET for devices at all: the only device reads are /api/v2/Device/{id}/Location,
# /api/v2/Device/{id}/CustomAttribute, and /api/v2/Device/SuspendedDevices, and
# the Device schema appears solely as the request body of POST /api/v2/Device and
# PATCH /api/v2/Device/{id} -- never as a response. That schema also carries no
# operating system, serial number, MAC, IP, or software field. Nothing in the
# whole v2 document accepts a paging parameter. Miradore's own v2 documentation
# says so outright: "The device ID can be retrieved using Miradore API v1, as an
# attribute of the Device item."
#
# So this integration reads API v1, which is the reporting interface and the only
# way to list devices. Its specification is the "Miradore API Specification"
# PDF linked from
# https://www.miradore.com/knowledge/integrations/programmers-guide-to-api-v1/
# (version 1.14 was used here). Every attribute in the select lists below comes
# from that document's Appendix 2.
#
# Two consequences of v1 that shape the code:
#   - v1 answers in XML, not JSON, so this uses raw http.get plus xml.parse.
#     Raw http.get takes no retry budget, so a failed page is not retried.
#   - v1 authenticates with the key in the URL query string. The request URL is
#     therefore a secret and is never logged; see safe_label().

load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('http', http_get='get', 'url_encode')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames', 'normalize_mac')
load('xml', xml_parse='parse')
load('time', 'now', 'parse_ts', 'sleep')
load('re', re_match='match')
load('coerce', 'as_text')

VENDOR = "miradore"

# The Device item is the only one this script reads. Everything else it needs is
# reachable as a child item of Device, so one paged walk covers the whole import.
ITEM_PATH = "/API/Device"

# Attributes are requested explicitly because v1 returns only a small predefined
# default set otherwise, and the specification's own advice is to "always define
# explicitly the attributes required by the caller end".
#
# The list is split so that one unrecognized attribute cannot cost the entire
# import. If a site's schema rejects the full list, fetch_page falls back to
# SELECT_CORE -- which holds only identity, addressing, and OS -- for the rest of
# the run. Every attribute below is from Appendix 2 of the v1 specification.
SELECT_CORE = [
    "ID",
    "Platform",
    "OSVersionName",
    "IPAddress",
    "MACAddress",
    "InvDevice.DeviceName",
    "InvDevice.Manufacturer",
    "InvDevice.Model",
    "InvDevice.SerialNumber",
    "InvOS.Platform",
    "InvOS.Version",
    "Status",
]

SELECT_EXTRA = [
    "LocalIpAddress",
    "AndroidID",
    "LastReported",
    "Created",
    "Modified",
    "OnlineStatus",
    "PurchaseDate",
    "WarrantyEndDate",
    "InvDevice.MarketingName",
    "InvDevice.ProductName",
    "InvDevice.HardwareSerialNumber",
    "InvDevice.IMEI",
    "InvDevice.UDID",
    "InvDevice.WiFiMAC",
    "InvDevice.BluetoothMAC",
    "InvDevice.DeviceType",
    "InvDevice.SoftwareVersion",
    "InvOS.Build",
    "InvOS.Language",
    "User.ID",
    "User.Name",
    "User.Email",
    "User.Firstname",
    "User.Lastname",
    "User.PhoneNumber",
    "Location.Name",
    "Location.FullName",
    "Organization.Name",
    "Organization.FullName",
    "Category.Name",
    "Tag.Name",
    "Client.Version",
    "Client.ManagementType",
    "BIOS.Manufacturer",
    "BIOS.SerialNumber",
    "BIOS.Version",
    "InvStorage.Volume",
    "InvStorage.TotalSpace",
    "InvStorage.FreeSpace",
    "InvStorage.Type",
]

SELECT_SOFTWARE = [
    "InvApplication.Name",
    "InvApplication.Version",
    "InvApplication.Identifier",
]

# v1 renders DateTime as "dd.MM.yyyy HH:mm:ss" by default. The API can be asked
# for another rendering with the dateformat option, and an earlier version of
# this script did that to get an unambiguous one -- but a live Miradore Online
# site answers 500 to a query carrying it, because the format string's spaces and
# colons sit inside an options value that is itself comma- and equals-delimited.
# So the query stays plain and the default rendering is parsed here instead.
#
# Both orderings are accepted: day-first is what the documentation specifies, and
# year-first is recognized as well so a site configured for it is not silently
# left without timestamps. Nothing else is guessed at -- a value matching neither
# shape yields no timestamp rather than a transposed day and month.
TS_PATTERN_DAY_FIRST = "^[0-9]{2}\\.[0-9]{2}\\.[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$"
TS_PATTERN_YEAR_FIRST = "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$"

# Miradore's Platform enumeration, mapped to the OS name runZero fingerprints
# against. "Other" and "Unknown" are deliberately absent: they carry no
# information, and passing them through would displace a real fingerprint.
PLATFORM_OS = {
    "android": "Android",
    "ios": "iOS",
    "macos": "macOS",
    "windowsdesktop": "Windows",
    "windowsphone": "Windows Phone",
}

# Matched in order against the model name with spaces removed, so "MacBook Pro"
# is claimed as a laptop before "Mac Pro" can see it.
#
# "tab" is last because it is the loosest match and only needs to catch what the
# platform cannot: Android covers phones and tablets alike, so a Galaxy Tab or a
# Lenovo Tab would otherwise be typed as a phone by PLATFORM_DEVICE_TYPES below.
# None of the entries above it contain the substring, so the order is what keeps
# it from stealing an iPad or a ThinkPad.
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
    ("tab", "Tablet"),
]

# Only for platforms where the form factor follows from the platform alone.
# WindowsDesktop and macOS are absent because each covers both laptops and
# desktops. macOS is settled from the model list above, which names every current
# Mac chassis. Windows hardware is not: naming every OEM laptop line would be a
# guess, and runZero fingerprints a Windows machine's chassis better than a model
# string match would, so those are deliberately left unset rather than assumed.
PLATFORM_DEVICE_TYPES = {
    "ios": "Mobile",
    "android": "Mobile",
    "windowsphone": "Mobile",
}

# Device.Status values worth importing when include_deleted is off. Deleted
# records stay in the Miradore database and are returned by the API;
# AutoGenerated records are placeholders Miradore creates for devices it has seen
# but does not manage.
ACTIVE_STATUSES = ["active", "new"]

# Requesting InvApplication multiplies the response about 34x. Measured against
# a live site: a device costs ~1.3 KB without its applications and ~45 KB with
# them. What has to fit in the Explorer's memory budget is not the raw response
# but the parsed XML document, which expands roughly 70x over it -- so a single
# page holding 186 devices with applications (8.4 MB of XML) took ~578 MB and was
# killed against a 512 MB limit, reporting nothing.
#
# Twenty-five devices a page is about 1.1 MB of XML at the ~45 KB per device an
# application inventory costs. What makes this safe at any estate size is that
# the bound is per page, not per estate: a fleet ten times larger takes ten times
# the requests at the same peak memory.
#
# The cap applies only when applications are actually requested; without them a
# page of 500 is still well under 700 KB, so the operator's page size stands.
SOFTWARE_PAGE_LIMIT = 25

# Software rows per device. A managed Mac reports several hundred applications --
# on a real estate the average was ~350 and a cap of 99 silently discarded two
# thirds of the inventory. Raising it costs almost nothing in memory: the whole
# page is already parsed either way, and assets are streamed out one at a time
# with report_asset rather than accumulated, so this bounds one asset, not the run.
MAX_CHILDREN = 999
MAX_INTERFACES = 32
MAX_VALUE_LEN = 1024   # custom attribute values are truncated at this length


def el_text(element, path):
    """Text of the first child at `path`, or "" when absent."""
    if element == None:
        return ""
    node = element.find(path)
    if node == None:
        return ""
    return as_text(node.text).strip()


# A List-typed attribute is requested by its singular item name in `select`
# ("Tag.Name", "InvApplication.Name") but comes back wrapped in a plural
# container: <Tags><Tag>...</Tag></Tags>. The specification's Appendix 2 names
# only the singular, and its response examples show no List attribute at all, so
# the wrapper is visible only against a live site. Reading the singular as a
# direct child of <Device> finds nothing and costs software, tags, and storage
# silently -- verified against a real Miradore Online site, 2026-08-18.
TAGS_PATH = "Tags/Tag"
APPLICATIONS_PATH = "InvApplications/InvApplication"
STORAGE_PATH = "InvStorages/InvStorage"


def el_texts(element, path, field):
    """`field` of every child matching `path`."""
    values = []
    if element == None:
        return values
    for node in element.find_all(path):
        value = as_text(node.find(field).text).strip() if node.find(field) != None else ""
        if value:
            values.append(value)
    return values


def first_text(element, paths):
    """First non-empty value among `paths`, or ""."""
    for path in paths:
        value = el_text(element, path)
        if value:
            return value
    return ""


def parse_reported_ts(value, ceiling):
    """Parse a Miradore timestamp, or return None.

    Three guards, each protecting against a failure that costs whole assets
    rather than one field:
      - the ordering is established from the shape before parsing, so a day
        and a month are never transposed;
      - the value is pinned to UTC, because v1 stamps have no zone and an
        unzoned stamp is not parseable;
      - the result is clamped to the current time. runZero rejects any
        ImportAsset carrying a future timestamp, and rejects the whole record
        rather than the field, so a site whose clock or zone runs ahead of the
        Explorer's would otherwise import nothing at all.
    The unparsed string is kept as a custom attribute either way.
    """
    if not value:
        return None
    if re_match(TS_PATTERN_DAY_FIRST, value) != None:
        # dd.MM.yyyy HH:mm:ss -> yyyy-MM-ddTHH:mm:ssZ. The pattern above has
        # already fixed every offset, so these slices cannot land mid-field.
        iso = "{}-{}-{}T{}Z".format(value[6:10], value[3:5], value[0:2], value[11:19])
    elif re_match(TS_PATTERN_YEAR_FIRST, value) != None:
        iso = value.replace(" ", "T") + "Z"
    else:
        return None
    parsed = parse_ts(iso)
    if parsed == None:
        return None
    # Miradore writes 0001-01-01 for "never"; that is not a real observation.
    if parsed.unix <= 0:
        return None
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed


def build_query(ctx, page):
    """Build the v1 query string for one page.

    This is deliberately the plainest query the specification documents -- auth,
    select, and the rows/page options, exactly the shape of its own paging
    example. Two things an earlier version added are gone because a live site
    answered 500 to both: the dateformat option (see TS_PATTERN_DAY_FIRST above) and
    orderby. Ordering would have made the paged walk stricter, but a walk that
    500s is not stricter than one that works, and the no-progress guard in main
    still catches a source that never advances.

    Each key is encoded separately so the order stays fixed and the auth key --
    which may contain characters that are significant in a query string -- is
    escaped.
    """
    parts = [url_encode({"auth": ctx["api_key"]})]
    # An empty select is the last rung of the ladder: the API then returns its
    # own default attribute set, which is small but always accepted.
    if ctx["select"]:
        parts.append(url_encode({"select": ",".join(ctx["select"])}))
    parts.append(url_encode({"options": "rows={},page={}".format(ctx["page_size"], page)}))
    return "&".join(parts)


def candidate_paths(base_url, site_name):
    """Request paths to try, most likely first.

    Miradore Online serves each site under its own path segment -- a site's
    console is at https://online.miradore.com/<site>/ -- and that is the shape
    the v2 documentation uses for its own URLs. The site-less form is kept as a
    fallback for a deployment that serves the API at the root, and the site
    segment is skipped when the configured base URL already ends with it, so a
    base URL that already names the site is not doubled.
    """
    paths = []
    for name in [site_name, site_name.lower()]:
        # The segment is case-sensitive: a live site answers 200 to /acme/ and
        # 500 to /Acme/, /ACME/ and every other casing, exactly as it does for a
        # site that does not exist. Since a console site name is not always
        # written the way the URL wants it, the lower-case form is tried as well
        # rather than making the operator discover the difference from a 500.
        candidate = "/" + name + ITEM_PATH
        if name and not base_url.endswith("/" + name) and candidate not in paths:
            paths.append(candidate)
    paths.append(ITEM_PATH)
    return paths


def choose_path(ctx):
    """Pick the request path, returning an error string when none answered.

    Each candidate is tried with the cheapest query the API accepts -- no select,
    one row -- so this costs one extra request and cannot fail for any reason
    except the endpoint itself.

    It has to be done at runtime because nothing else settles it. The v1
    specification's base URL (https://<site>.online.miradore.com/API/) no longer
    resolves; no such DNS record exists. Both surviving forms answer 401 to an
    invalid key, so a probe without a real credential cannot tell them apart, and
    a site that wants the segment answers 500 -- not 404 -- to the form without
    it. Only a real request distinguishes them.
    """
    last = "no request path was tried"
    for path in candidate_paths(ctx["url"], ctx["site_name"]):
        probe = {}
        probe.update(ctx)
        probe["path"] = path
        probe["select"] = []
        probe["page_size"] = 1
        _, _, err, _ = fetch_page(probe, 1)
        if err == None:
            ctx["path"] = path
            print("miradore: using {}".format(path))
            return None
        if "401" in err:
            # The endpoint is right and the credential is not. No other path
            # does better, and saying so beats blaming the last one tried.
            ctx["path"] = path
            return err
        print("miradore: {} did not answer ({})".format(path, err))
        last = err
    return last


def safe_label(ctx, page):
    """A log label for a request. The URL itself is never logged: the v1
    authentication key travels in its query string."""
    return "{} page {}".format(ctx["path"], page)


# Statuses worth a second attempt before a page is declared failed. Raw
# http.get is required here (the body is XML), so the shared helper's built-in
# retry is unavailable; this list is its transient subset. 500 is deliberately
# absent: a live Miradore site answers 500 -- not 400 -- to a query whose
# syntax it dislikes, and that failure belongs to the select ladder below, not
# to a retry loop.
TRANSIENT_STATUSES = [408, 425, 429, 502, 503, 504]
TRANSIENT_RETRIES = 3


def http_get_transient(url, **options):
    """GET with retries for transient statuses and no-response transport errors.

    A single 502 blip on page 40 of a long walk used to end the run with a
    truncated import; retrying with backoff rides out the blip. Every other
    status is returned to the caller untouched on the first attempt.
    """
    resp = None
    for attempt in range(TRANSIENT_RETRIES + 1):
        if attempt:
            # 1s, 2s, 4s. Starlark has no ** operator; shift instead.
            sleep("{}s".format(1 << (attempt - 1)))
        resp = http_get(url, **options)
        if resp != None and resp.status_code not in TRANSIENT_STATUSES:
            return resp
        if attempt < TRANSIENT_RETRIES:
            # The URL is never logged: the v1 key travels in its query string.
            print("miradore: transient failure ({}); retrying".format(
                "no response" if resp == None else "status {}".format(resp.status_code)))
    return resp


def fetch_page(ctx, page):
    """Fetch one page of devices and return (elements, total, err, retryable).

    `total` is the count of devices matching the query across all pages, or -1
    when the server did not report one.

    `retryable` says whether a narrower select could plausibly fix the failure.
    Only a request the server actively rejected qualifies -- a 400, or a v1
    <Error> envelope. A refused key, an unreachable server, and a 5xx are all
    failures no attribute list can repair, and retrying them would spend a second
    request and log a misleading cause.
    """
    resp = http_get_transient(ctx["url"] + ctx["path"] + "?" + build_query(ctx, page), **ctx["http_options"])
    if resp == None:
        return [], -1, "no response from the Miradore server", False
    if resp.status_code == 401:
        return [], -1, "status 401: the authentication key was rejected", False
    if resp.status_code != 200:
        # v1 reports failures in the body as well as the status line, and the
        # description is the only thing that distinguishes a bad attribute name
        # from a bad site.
        detail = error_detail(resp.body)
        # 400 is the documented "bad request". 500 is included because a live
        # Miradore Online site answers 500 -- not 400 -- to a query whose syntax
        # it dislikes, so treating it as fatal would strand an import that a
        # narrower attribute list would have completed.
        retryable = resp.status_code == 400 or resp.status_code == 500
        if detail:
            return [], -1, "status {}: {}".format(resp.status_code, detail), retryable
        return [], -1, "status {}".format(resp.status_code), retryable

    doc = xml_parse(resp.body)
    if doc == None or doc.tag != "Content":
        return [], -1, "the response was not a Miradore API document", False
    failure = doc.find("Error")
    if failure != None:
        description = failure.find("Description")
        return [], -1, as_text(description.text).strip() if description != None else "unspecified API error", True

    # The count attribute sits on Items in most responses and on Content in
    # others; both spellings appear in the specification's own examples.
    items = doc.find("Items")
    total = -1
    for holder in [items, doc]:
        if holder == None:
            continue
        raw = holder.get("count", "")
        if raw and raw.isdigit():
            total = int(raw)
            break

    return doc.find_all("Items/Device"), total, None, False


def error_detail(body):
    """Description out of a v1 <Error> envelope, or "" if the body is not one."""
    doc = xml_parse(body)
    if doc == None:
        return ""
    node = doc.find("Error/Description")
    if node == None:
        return ""
    return as_text(node.text).strip()


def local_ip(device):
    """The device's local address.

    Appendix 2 of the specification spells this attribute "LocalIpAddress" and
    `select` accepts that spelling, but the element that comes back is
    "LocalIPAddress". Both are read so the value is not lost to a capital letter.
    """
    return first_text(device, ["LocalIPAddress", "LocalIpAddress"])


def device_macs(device):
    """Every MAC the device reports, de-duplicated in reporting order."""
    macs = []
    seen = {}
    for path in ["MACAddress", "InvDevice/WiFiMAC", "InvDevice/BluetoothMAC"]:
        value = el_text(device, path)
        if not value:
            continue
        canonical = normalize_mac(value)
        if canonical == None:
            continue
        if canonical in seen:
            continue
        seen[canonical] = True
        macs.append(value)
    return macs


def device_networks(device):
    """One interface per reported MAC.

    Miradore reports addresses and MACs at the device level with no pairing
    between them, so the addresses go on the first interface and the remaining
    MACs are carried as address-less interfaces -- which is what lets a phone
    still match on its Wi-Fi MAC after its lease has changed.

    routable_ips drops loopback, link-local, and unspecified addresses. That
    filter matters more than it looks: an agent that reports 127.0.0.1 as a
    device's only address would otherwise give every such device the same
    address and merge them onto one asset.
    """
    ips = routable_ips([el_text(device, "IPAddress"), local_ip(device)])
    macs = device_macs(device)

    interfaces = []
    pending = ips
    for mac in macs[:MAX_INTERFACES]:
        nic = network_interface(ips=pending, mac=mac)
        pending = []
        if nic != None:
            interfaces.append(nic)
    if not interfaces and pending:
        nic = network_interface(ips=pending)
        if nic != None:
            interfaces.append(nic)
    return interfaces


def device_software(device):
    """Installed applications, when they were requested and the device has any."""
    software = []
    for entry in device.find_all(APPLICATIONS_PATH):
        product = el_text(entry, "Name")
        if not product:
            continue
        # Software requires an id -- omitting it fails the whole record with
        # "missing argument for id", which on a live site is most rows: many
        # InvApplication entries carry no Identifier at all. The bundle or
        # package identifier is the stable key where it exists; the display name
        # is the fallback, which is at least stable for the same product.
        identifier = el_text(entry, "Identifier") or product
        params = {"id": identifier[:255], "product": product[:255]}
        version = el_text(entry, "Version")
        if version:
            params["version"] = version[:255]
        software.append(Software(**params))
        if len(software) >= MAX_CHILDREN:
            break
    return software


def device_os(device):
    """(os, osVersion) for the device, or ("", "") when the platform is unknown."""
    platform = first_text(device, ["InvOS/Platform", "Platform"]).lower()
    os_name = PLATFORM_OS.get(platform, "")
    version = first_text(device, ["InvOS/Version", "OSVersionName"])
    return os_name, version


def device_type(device):
    """runZero device type, or "" to leave the fingerprint in charge."""
    model = (first_text(device, ["InvDevice/MarketingName", "InvDevice/Model", "InvDevice/ProductName"])
             .lower().replace(" ", "").replace("-", ""))
    for prefix, kind in MODEL_DEVICE_TYPES:
        if prefix in model:
            return kind
    return PLATFORM_DEVICE_TYPES.get(first_text(device, ["InvOS/Platform", "Platform"]).lower(), "")


def owner_name(device):
    """The assigned user's display name, falling back to first/last."""
    name = el_text(device, "User/Name")
    if name:
        return name
    parts = [el_text(device, "User/Firstname"), el_text(device, "User/Lastname")]
    return " ".join([p for p in parts if p]).strip()


def build_asset(ctx, device):
    """One Miradore device as an ImportAsset, or None if it cannot be imported."""
    device_id = el_text(device, "ID")
    if not device_id:
        print("miradore: skipping a device with no ID")
        return None

    status = el_text(device, "Status")
    if not ctx["include_deleted"] and status and status.lower() not in ACTIVE_STATUSES:
        return None

    display_name = el_text(device, "InvDevice/DeviceName")
    os_name, os_version = device_os(device)
    manufacturer = first_text(device, ["InvDevice/Manufacturer", "BIOS/Manufacturer"])
    model = first_text(device, ["InvDevice/MarketingName", "InvDevice/Model", "InvDevice/ProductName"])
    serial = first_text(device, ["InvDevice/SerialNumber", "InvDevice/HardwareSerialNumber", "BIOS/SerialNumber"])

    attrs = {
        "miradore_device_id": device_id,
        # Kept raw: hostnames below drops anything that is not DNS-valid, and on
        # an MDM fleet that is most of them ("John's iPhone").
        "miradore_device_name": display_name,
        "miradore_status": status,
        "miradore_online_status": el_text(device, "OnlineStatus"),
        "miradore_platform": first_text(device, ["InvOS/Platform", "Platform"]),
        "miradore_os_build": el_text(device, "InvOS/Build"),
        "miradore_os_language": el_text(device, "InvOS/Language"),
        "miradore_device_type": el_text(device, "InvDevice/DeviceType"),
        "miradore_serial_number": serial,
        "miradore_imei": el_text(device, "InvDevice/IMEI"),
        "miradore_udid": el_text(device, "InvDevice/UDID"),
        "miradore_android_id": el_text(device, "AndroidID"),
        "miradore_user_email": el_text(device, "User/Email"),
        "miradore_user_name": owner_name(device),
        "miradore_user_phone": el_text(device, "User/PhoneNumber"),
        "miradore_location": el_text(device, "Location/Name"),
        "miradore_location_full": el_text(device, "Location/FullName"),
        "miradore_organization": el_text(device, "Organization/Name"),
        "miradore_organization_full": el_text(device, "Organization/FullName"),
        "miradore_category": el_text(device, "Category/Name"),
        "miradore_client_version": el_text(device, "Client/Version"),
        "miradore_management_type": el_text(device, "Client/ManagementType"),
        "miradore_bios_version": first_text(device, ["BIOS/Version", "BIOS/SMBIOSBIOSVersion"]),
        # The addresses exactly as reported, including any this script filtered
        # out of the interfaces above.
        "miradore_ip_address": el_text(device, "IPAddress"),
        "miradore_local_ip_address": local_ip(device),
        "miradore_mac_address": el_text(device, "MACAddress"),
        "miradore_wifi_mac": el_text(device, "InvDevice/WiFiMAC"),
        "miradore_bluetooth_mac": el_text(device, "InvDevice/BluetoothMAC"),
        # Raw stamps, so an operator can still see a value this script declined
        # to parse or clamped.
        "miradore_last_reported": el_text(device, "LastReported"),
        "miradore_created": el_text(device, "Created"),
        "miradore_modified": el_text(device, "Modified"),
        "miradore_purchase_date": el_text(device, "PurchaseDate"),
        "miradore_warranty_end_date": el_text(device, "WarrantyEndDate"),
    }

    tags = el_texts(device, TAGS_PATH, "Name")
    if tags:
        attrs["miradore_tags"] = ",".join(tags)[:MAX_VALUE_LEN]

    volumes = []
    for volume in device.find_all(STORAGE_PATH)[:MAX_CHILDREN]:
        # Real rows carry Type/TotalSpace/FreeSpace and no Volume at all, so the
        # label falls back to the storage type rather than leaving a bare colon.
        label = el_text(volume, "Volume") or el_text(volume, "Type")
        total = el_text(volume, "TotalSpace")
        free = el_text(volume, "FreeSpace")
        if label or total:
            volumes.append("{}:{}/{}".format(label, free, total))
    if volumes:
        attrs["miradore_storage"] = ",".join(volumes)[:MAX_VALUE_LEN]

    params = {
        # <slug>:<scope>:<vendor id>. Miradore numbers devices per site starting
        # at 1, so the bare number is not unique across two Miradore sites and
        # would merge unrelated devices onto one asset. The slug is not
        # redundant with the source: the id text is what keeps this integration
        # from colliding with another that also namespaces by site.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], device_id),
        "networkInterfaces": device_networks(device),
        "customAttributes": to_custom_attributes(
            {k: v for k, v in attrs.items() if v}
        ),
    }

    names = clean_hostnames([display_name])
    if names:
        params["hostnames"] = names
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    kind = device_type(device)
    if kind:
        params["deviceType"] = kind

    first_ts = parse_reported_ts(el_text(device, "Created"), ctx["now"])
    if first_ts != None:
        params["firstSeenTS"] = first_ts
    # LastReported is when the device last checked in with Miradore, which is a
    # real observation. Modified only tracks when the database row changed.
    last_ts = parse_reported_ts(el_text(device, "LastReported"), ctx["now"])
    if last_ts != None:
        params["lastSeenTS"] = last_ts

    if ctx["include_software"]:
        software = device_software(device)
        if software:
            params["software"] = software

    return ImportAsset(**params)


def main(*args, **kwargs):
    require(kwargs, "url", "api_key", "site_name")
    base_url = get_url_base(kwargs)
    api_key = get_string(kwargs, "api_key")
    site_name = get_string(kwargs, "site_name").strip().strip("/")
    # The id scope is case-folded so that "Acme" and "acme" cannot produce two
    # sets of ids for one site. The request path keeps the operator's spelling
    # and falls back to the folded form, since only the URL is case-sensitive.
    scope = site_name.lower()
    # CONFIG defaults are applied by the console but not on the plain
    # --kwargs path, so each default is repeated here.
    page_size = get_int(kwargs, "page_size", default=100)
    if page_size < 1:
        page_size = 100
    include_software = get_bool(kwargs, "include_software", default=True)
    include_deleted = get_bool(kwargs, "include_deleted", default=False)
    if include_software and page_size > SOFTWARE_PAGE_LIMIT:
        # Say it rather than silently ignoring the configured value: a run that
        # quietly pages differently than asked is hard to reason about, and the
        # reason is worth knowing when tuning.
        print("miradore: lowering the page size from {} to {} because application inventory is enabled; turn it off to page in larger chunks".format(
            page_size, SOFTWARE_PAGE_LIMIT))
        page_size = SOFTWARE_PAGE_LIMIT

    # The attribute ladder, widest first. Each rung is tried on page 1 only; the
    # rung that works is used for the whole walk. The last rung sends no select
    # at all, which makes the API return its own default attribute set -- less
    # detail, but a query no site can reject on its attribute list.
    full = SELECT_CORE + SELECT_EXTRA
    if include_software:
        full = full + SELECT_SOFTWARE
    stages = [("full attribute set", full),
              ("core attribute set", SELECT_CORE),
              ("the API's default attribute set", [])]

    ctx = {
        "url": base_url,
        # Replaced by choose_path below, which settles the site segment against
        # the live site rather than assuming it.
        "path": ITEM_PATH,
        # Two different things: the name as the operator typed it builds the
        # request path (the URL is case-sensitive), and the case-folded form
        # scopes asset ids (so one site typed two ways is still one set of ids).
        "site_name": site_name,
        "scope": scope,
        "api_key": api_key,
        "select": stages[0][1],
        "page_size": page_size,
        "include_software": include_software,
        "include_deleted": include_deleted,
        "now": now(),
        "http_options": get_http_options(kwargs, headers={"Accept": "application/xml"}),
    }

    path_err = choose_path(ctx)
    if path_err != None:
        print("miradore: could not read the device list: {}".format(path_err))
        if "401" not in path_err:
            # The API answers 500 both for a site that does not exist and for a
            # site name in the wrong case, so this is the first thing to check
            # and the error itself never says so.
            print("miradore: check the site name. It is the segment in your console URL " +
                  "(https://<server>/<site name>/) and it is case-sensitive; the API answers " +
                  "500 rather than 404 when it does not match.")
        return None

    reported = 0
    skipped = 0
    seen_total = -1
    previous = None
    stage = 0

    p = pager("devices")
    while p.next():
        devices, total, err, retryable = fetch_page(ctx, p.page)
        # A site that rejects the query fails it whole, which would otherwise
        # cost the entire import for one unsupported attribute. Walk down the
        # ladder on page 1 until a query is accepted.
        for _ in range(len(stages)):
            if err == None or not retryable or p.page != 1 or stage + 1 >= len(stages):
                break
            stage += 1
            print("miradore: {} failed ({}); retrying with {}".format(
                safe_label(ctx, p.page), err, stages[stage][0]))
            ctx["select"] = stages[stage][1]
            # Software only arrives when InvApplication was asked for, and no
            # rung below the first asks for it.
            ctx["include_software"] = False
            devices, total, err, retryable = fetch_page(ctx, p.page)
        if err != None:
            print("miradore: {} failed: {}".format(safe_label(ctx, p.page), err))
            break
        if not devices:
            break
        if total >= 0:
            seen_total = total

        # A server that ignores the page option -- or a proxy replaying one
        # response -- would otherwise be paged forever. Comparing the ids on
        # consecutive pages catches that on the first repeat.
        signature = ",".join([el_text(device, "ID") for device in devices])
        if signature == previous:
            print("miradore: {} repeated the previous page; stopping".format(safe_label(ctx, p.page)))
            break
        previous = signature

        for device in devices:
            asset = build_asset(ctx, device)
            if asset == None:
                skipped += 1
                continue
            reported += report_asset(asset)

        if len(devices) < page_size:
            break
        if seen_total >= 0 and p.page * page_size >= seen_total:
            break

    if stage > 0:
        print("miradore: ran with {}; some inventory detail was not imported".format(stages[stage][0]))
    if skipped:
        print("miradore: skipped {} devices (deleted, auto-generated, or missing an ID)".format(skipped))
    if seen_total >= 0:
        print("miradore: reported {} of {} devices matched by the query".format(reported, seen_total))
    else:
        print("miradore: reported {} devices".format(reported))
    return None

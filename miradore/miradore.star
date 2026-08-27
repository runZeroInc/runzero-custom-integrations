# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-miradore",
    "name": "Miradore",
    "type": "inbound",
    "description": "Imports managed devices, hardware, OS, installed software, owners, and network addresses from Miradore.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Device.ID is the site's database key for the enrollment: stable across runs
    # and one per device, so id matching stays authoritative. Everything else
    # churns on an MDM fleet -- phones roam, take new leases, get renamed -- and
    # these flags stop that drift blocking a merge. See README "Asset identity".
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
            "label": "API authentication key",
            "description": "Authentication key generated in the Miradore console under System > Infrastructure diagram. The same key authenticates both API versions. Its leading number does not select the site -- name the site separately below.",
            "type": "secret",
            "required": True,
        },
        {
            "key": "site_name",
            "label": "Miradore site name",
            "description": "The site name shown in the Miradore console. Both APIs need it -- v1 in the request path, v2 in the X-Instance-Name header -- and it also scopes imported asset IDs, because Miradore numbers devices per site and every site has a device 1.",
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
        {
            "key": "include_v2_details",
            "label": "Add API v2 detail",
            "description": "Adds the per-device custom attribute values and the suspended-device list from Miradore API v2, which API v1 does not expose. Costs one extra request per device.",
            "type": "bool",
            "default": True,
        },
        {
            "key": "include_v2_location",
            "label": "Add the last reported location",
            "description": "Adds each device's most recent reported coordinates from API v2. This is employee-device geolocation, so it is separately switchable; it costs a second extra request per device.",
            "type": "bool",
            "default": True,
            "dependsOn": "include_v2_details",
        },
        {
            "key": "v2_detail_limit",
            "label": "Maximum devices to detail",
            "description": "Upper bound on how many devices the per-device v2 requests are made for. The v1 walk still imports the whole estate; devices past this bound are imported without their v2 detail rather than letting a large fleet spend the run on per-device requests.",
            "type": "int",
            "default": 5000,
            "min": 0,
            "max": 100000,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

# Miradore has two APIs and only v1 can enumerate devices, so this reads both:
# v1 lists the estate, v2 adds the per-device custom attributes and locations v1
# does not carry. v2 is a management API, its Device schema is request-only, and
# the two routes that look like enumeration (/Devices, /Device/SuspendedDevices)
# answer 401 to every credential. See the README for the probe results.
#
# Two properties of v1 shape the code: it answers XML, so this uses raw http.get
# plus xml.parse, which carries no retry budget (see http_get_transient); and it
# authenticates with the key in the query string, so a v1 URL is a secret and is
# never logged (see safe_label). v2 takes the same key in an X-API-Key header, so
# its URLs are logged. v1's contract is the "Miradore API Specification" PDF
# v1.14; every attribute in the select lists below is from its Appendix 2.

load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('http', http_get='get', 'get_json', 'url_encode')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames', 'normalize_mac')
load('xml', xml_parse='parse')
load('time', 'now', 'parse_ts', 'sleep')
load('re', re_match='match')
load('coerce', 'as_text', 'as_dict', 'as_list', 'as_int')

VENDOR = "miradore"

# The Device item is the only one this script reads. Everything else it needs is
# reachable as a child item of Device, so one paged walk covers the whole import.
ITEM_PATH = "/API/Device"

# v2 lives at the server root, not under the site path segment: the site is named
# in the X-Instance-Name header instead. Verified against the live service.
V2_SUSPENDED_PATH = "/api/v2/Device/SuspendedDevices"
V2_DEVICE_PREFIX = "/api/v2/Device/"

# Attributes are requested explicitly because v1 otherwise returns only a small
# default set. The list is split into groups so that one unrecognized attribute
# cannot cost the whole import: v1 fails a query whole, so the ladder in main()
# drops one group at a time until the site accepts the query.
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

# The two child items carrying management posture: encryption, passcode and
# jailbreak state, and enrollment. Requested as `Item.*` wildcards and flattened
# under whatever names the site returns, so the script is not pinned to one
# site's schema. Both are accepted by Miradore Online; they still get their own
# rung of the ladder in main() so a site that rejects them loses only posture.
SELECT_POSTURE = [
    "Security.*",
    "Enrollment.*",
]

# InvApplication has exactly six properties: Name, Version, Identifier, Size,
# OSCategory and InventoryTime. There is NO Vendor property, despite Appendix 2
# implying one. Do not add it, or anything else unverified, to this list: asking
# for InvApplication.Vendor 400s the whole query, the ladder steps past both
# software rungs, and the run imports zero software estate-wide while still
# reporting assets and looking healthy. software_vendor() derives the vendor from
# the bundle identifier instead. OSCategory and InventoryTime are omitted because
# a device reports hundreds of applications; see SOFTWARE_PAGE_LIMIT.
SELECT_SOFTWARE = [
    "InvApplication.Name",
    "InvApplication.Version",
    "InvApplication.Identifier",
    "InvApplication.Size",
]

# v1 renders DateTime as "dd.MM.yyyy HH:mm:ss" by default, and year-first when a
# dateformat option is in play. Reading both means the query never has to ask for
# one. A value matching neither yields no timestamp rather than risking a
# transposed day and month.
TS_PATTERN_DAY_FIRST = "^[0-9]{2}\\.[0-9]{2}\\.[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$"
TS_PATTERN_YEAR_FIRST = "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$"

# Device.ID as the v1 specification documents it: an integer. Checked before the
# value is spliced into a v2 request path.
ID_PATTERN = "^[0-9]+$"

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
# is claimed as a laptop before "Mac Pro" sees it. Order is load-bearing: "tab"
# must stay last because it is the loosest match, there to catch Android tablets
# that PLATFORM_DEVICE_TYPES would otherwise type as phones. Moved up, it would
# steal an iPad or a ThinkPad.
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

# Only platforms where the form factor follows from the platform alone. macOS
# and WindowsDesktop are absent because each covers laptops and desktops both:
# macOS is settled by the model list above, while Windows is left unset for
# runZero to fingerprint rather than guessed at from OEM laptop names.
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

# Applications are ~97% of the response: measured live, a device costs 1.5 KB
# without them and 40.1 KB with. The Explorer's memory ceiling applies to the
# parsed XML, which expands ~70x over the wire, so one 186-device page with
# applications (8.4 MB of XML) needed 578 MB against a 512 MB limit and was
# killed mid-walk, reporting nothing. The bound is therefore per PAGE, not per
# estate: at 25 rows a fleet ten times larger costs ten times the requests at the
# same peak. The cap applies only when applications are requested; without them a
# page of 500 stays well under 1 MB and the operator's page size stands.
SOFTWARE_PAGE_LIMIT = 25

# Software rows per device. Managed Macs average ~350 applications, so a cap of
# 99 would discard two thirds of the inventory. Raising it is nearly free: the
# page is parsed either way and assets stream out one at a time, so this bounds
# one asset, not the run.
MAX_CHILDREN = 999
MAX_INTERFACES = 32
MAX_VALUE_LEN = 1024   # custom attribute values are truncated at this length

# Ceiling on keys from any open-ended source: the Security and Enrollment
# wildcards, v2 custom attribute values, and a v2 location record. All are named
# by the site rather than a specification, so none has a length this script knows.
MAX_FLAT_ATTRIBUTES = 32


def el_text(element, path):
    """Text of the first child at `path`, or "" when absent."""
    if element == None:
        return ""
    node = element.find(path)
    if node == None:
        return ""
    return as_text(node.text).strip()


# List-typed attributes are requested by singular name in `select` ("Tag.Name",
# "InvApplication.Name") but come back wrapped in a plural container:
# <Tags><Tag>...</Tag></Tags>. The specification documents only the singular, so
# this is visible only against a live site. Reading the singular as a direct
# child of <Device> matches nothing and silently loses all software, tags and
# storage.
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

    The ordering is settled from the shape before parsing so day and month are
    never transposed, and the value is pinned to UTC because v1 stamps carry no
    zone. The clamp to `ceiling` matters most: runZero rejects an ImportAsset
    with a future timestamp by discarding the whole record, not the field, so a
    site whose clock runs ahead of the Explorer would import nothing at all.
    The raw string is kept as a custom attribute either way.
    """
    if not value:
        return None
    if re_match(TS_PATTERN_DAY_FIRST, value) != None:
        # dd.MM.yyyy HH:mm:ss -> yyyy-MM-ddTHH:mm:ssZ. The pattern fixed every
        # offset, so these slices cannot land mid-field.
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

    Deliberately the plainest query the specification documents: auth, select and
    the rows/page options. dateformat and orderby are accepted by a live site but
    neither is sent, since timestamps are read in either rendering and the
    no-progress guard in main covers a source that never advances.

    Each key is encoded separately. That escaping is required, not cosmetic: real
    Miradore keys contain braces and commas, which are significant in a query
    string, and an unencoded key is rejected before it reaches the API.
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

    Miradore Online serves each site under its own /<site>/ path segment; the
    site-less form is kept as a fallback for a deployment serving the API at the
    root. The segment is skipped when the base URL already ends with it, so a
    base URL naming the site is not doubled.
    """
    paths = []
    for name in [site_name, site_name.lower()]:
        # The segment is case-sensitive: a live site answers 200 to /acme/ and
        # 500 to every other casing, the same answer it gives for a site that
        # does not exist. A console site name is not always written the way the
        # URL wants it, so the lower-case form is tried rather than leaving the
        # operator to work that out from a 500.
        candidate = "/" + name + ITEM_PATH
        if name and not base_url.endswith("/" + name) and candidate not in paths:
            paths.append(candidate)
    paths.append(ITEM_PATH)
    return paths


def site_from_path(path, fallback):
    """The site segment out of a chosen request path.

    choose_path settles the casing the server accepts; this recovers it for the
    v2 instance header. The site-less path has no segment, so `fallback` stands.
    """
    trimmed = path.strip("/")
    if trimmed.endswith(ITEM_PATH.strip("/")):
        trimmed = trimmed[:len(trimmed) - len(ITEM_PATH.strip("/"))].strip("/")
    return trimmed if trimmed else fallback


def choose_path(ctx):
    """Pick the request path, returning an error string when none answered.

    Each candidate is tried with the cheapest query the API accepts, no select
    and one row, so this cannot fail for any reason except the endpoint itself.
    It has to happen at runtime: a site wanting the segment answers 500 rather
    than 404 to the form without it, so only a real request tells the forms
    apart. (The specification's third form, https://<site>.online.miradore.com/,
    no longer resolves and is not tried.)
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
            # The endpoint is right and the credential is not, so no other path
            # does better. Report this rather than blaming the last one tried.
            ctx["path"] = path
            return err
        print("miradore: {} did not answer ({})".format(path, err))
        last = err
    return last


def safe_label(ctx, page):
    """A log label for a request. The URL itself is never logged: the v1
    authentication key travels in its query string."""
    return "{} page {}".format(ctx["path"], page)


# Statuses worth a second attempt before a page is declared failed. The body is
# XML, so raw http.get is required and the shared helper's retry is unavailable;
# this is its transient subset. 500 is deliberately absent: a live site answers
# 500 for a site name it cannot resolve, which no retry repairs.
TRANSIENT_STATUSES = [408, 425, 429, 502, 503, 504]
TRANSIENT_RETRIES = 3


def http_get_transient(url, **options):
    """GET with retries for transient statuses and no-response transport errors.

    Backoff rides out a single proxy blip mid-walk, which would otherwise
    truncate the import. Every other status is returned to the caller untouched
    on the first attempt.
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
    Only a request the server actively rejected qualifies: a 400, or a v1 <Error>
    envelope. A refused key or an unreachable server is not something an
    attribute list repairs, and retrying would log a misleading cause.
    """
    resp = http_get_transient(ctx["url"] + ctx["path"] + "?" + build_query(ctx, page), **ctx["http_options"])
    if resp == None:
        return [], -1, "no response from the Miradore server", False
    if resp.status_code == 401:
        return [], -1, "status 401: the authentication key was rejected", False
    if resp.status_code != 200:
        # v1 reports failures in the body as well as the status line, and the
        # description is the only thing separating a bad attribute name from a
        # bad site: a 400 body names it, as in "Entity 'InvApplication' does not
        # have property 'Vendor'". 500 stays retryable too, since one narrower
        # attempt is all it costs.
        detail = error_detail(resp.body)
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


LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"


def attr_key(name):
    """A custom-attribute-safe key from a vendor-supplied name.

    Callers pass names the site chose, not ones from a specification, so this has
    to survive spaces, punctuation and any casing. It also has to be stable: the
    same source name must always yield the same key, or an attribute renames
    itself between runs.
    """
    out = ""
    for i in range(len(name)):
        ch = name[i]
        if ch in UPPER:
            # camelCase and PascalCase both become snake_case, but only at a
            # genuine word boundary, so "IMEI" stays "imei" and does not become
            # "i_m_e_i".
            if out and (name[i - 1] in LOWER or name[i - 1] in DIGITS):
                out += "_"
            out += ch.lower()
        elif ch in LOWER or ch in DIGITS:
            out += ch
        elif out and not out.endswith("_"):
            out += "_"
    return out.strip("_")


def flatten_children(device, tag, prefix, attrs):
    """Copy the leaf children of one v1 child item into attrs.

    Security and Enrollment are wildcards, so their field names are whatever the
    site returns. One level deep is the whole shape of both, and stopping there
    also bounds the walk against an arbitrarily deep document.
    """
    node = device.find(tag)
    if node == None:
        return
    added = 0
    for child in node.children:
        if added >= MAX_FLAT_ATTRIBUTES:
            break
        value = as_text(child.text).strip()
        key = attr_key(as_text(child.tag))
        if not value or not key:
            continue
        attrs[prefix + key] = value[:MAX_VALUE_LEN]
        added += 1


def v2_url(base_url, site_name):
    """The base URL for v2 requests.

    v2 is served from the server root and names the site in a header, so a base
    URL carrying the site path segment must have it stripped; otherwise the
    request goes to /<site>/api/v2/... and 404s.
    """
    trimmed = base_url.rstrip("/")
    for name in [site_name, site_name.lower()]:
        if name and trimmed.lower().endswith("/" + name.lower()):
            return trimmed[:len(trimmed) - len(name) - 1].rstrip("/")
    return trimmed


def v2_get(ctx, path, what):
    """GET one v2 JSON endpoint, returning the decoded body or None.

    Every v2 read is enrichment: the device is built from v1 and imported whether
    or not this succeeds, so a failure is logged once per run rather than once
    per device. Retries are cut to one because these are two requests per device,
    and a site answering 5xx would otherwise spend the run in backoff.
    """
    data, err = get_json(ctx["v2_url"] + path, retries=1, **ctx["v2_options"])
    if err != None:
        if what not in ctx["v2_failures"]:
            ctx["v2_failures"][what] = True
            print("miradore: v2 {} unavailable ({}); continuing without it".format(what, err))
        return None
    return data


def v2_suspended_ids(ctx):
    """Device ids Miradore currently has suspended, as a set.

    One request for the estate, and the only device state v1 does not report at
    all: a suspended device still comes back from v1 as "Active". The OpenAPI
    document declares a 200 with no schema, so both plausible shapes are
    accepted, a bare list of ids and a list of objects carrying one. On Miradore
    Online the route 401s to every credential, so this usually returns an empty
    set and logs once; it is kept because the failure is free and a deployment
    that does serve it gets the attribute.
    """
    suspended = {}
    data = v2_get(ctx, V2_SUSPENDED_PATH, "suspended device list")
    if data == None:
        return suspended
    for entry in as_list(data):
        value = ""
        row = as_dict(entry)
        if row:
            for key in ["id", "deviceId", "deviceID", "Id", "ID", "DeviceId"]:
                value = as_text(row.get(key, "")).strip()
                if value:
                    break
        else:
            value = as_text(entry).strip()
        if value:
            suspended[value] = True
    if suspended:
        print("miradore: v2 reports {} suspended device(s)".format(len(suspended)))
    return suspended


def v2_custom_attributes(ctx, device_id, attrs):
    """Fold a device's v2 custom attribute values into attrs.

    These are the operator's own fields (asset tag, cost centre, owner) and v1
    does not carry them at all, which is the largest thing v2 adds. Identifier is
    preferred over Name because a site can rename an attribute without changing
    its identifier, and a key that moves when a label is edited makes the
    imported attribute look like a new one.
    """
    data = v2_get(ctx, V2_DEVICE_PREFIX + device_id + "/CustomAttribute", "device custom attributes")
    if data == None:
        return
    added = 0
    for entry in as_list(data):
        if added >= MAX_FLAT_ATTRIBUTES:
            break
        row = as_dict(entry)
        if not row:
            continue
        key = attr_key(as_text(row.get("identifier", "")) or as_text(row.get("name", "")))
        value = as_text(row.get("value", "")).strip()
        if not key or not value:
            continue
        attrs["miradore_attr_" + key] = value[:MAX_VALUE_LEN]
        added += 1


def v2_location(ctx, device_id, attrs):
    """Fold a device's most recently reported location into attrs.

    The endpoint returns history over a range and only the newest entry is
    wanted, so the window is deliberately wide and both bounds are whole dates
    off the current year, leaving no timezone difference able to clip it.

    Named `miradore_geo_*` rather than `miradore_location_*` because v1 already
    has a Location item, the site's organizational unit, unrelated to coordinates.
    """
    query = url_encode({
        "startDate": "{}-01-01T00:00:00Z".format(ctx["now"].year - 1),
        "endDate": "{}-12-31T23:59:59Z".format(ctx["now"].year),
    })
    data = v2_get(ctx, V2_DEVICE_PREFIX + device_id + "/Location?" + query, "device locations")
    if data == None:
        return

    latest = None
    latest_stamp = ""
    for entry in as_list(data):
        row = as_dict(entry)
        if not row:
            continue
        # Entries are not documented as ordered. These timestamps are ISO
        # strings, which sort chronologically as text, so the newest is the
        # largest; an entry with no timestamp wins only if nothing else did.
        stamp = as_text(row.get("timestamp", "")) or as_text(row.get("time", ""))
        if latest == None or stamp > latest_stamp:
            latest = row
            latest_stamp = stamp
    if latest == None:
        return

    added = 0
    for key, raw in latest.items():
        if added >= MAX_FLAT_ATTRIBUTES:
            break
        name = attr_key(as_text(key))
        value = as_text(raw).strip()
        if not name or not value:
            continue
        attrs["miradore_geo_" + name] = value[:MAX_VALUE_LEN]
        added += 1


def v2_enrich(ctx, device_id, attrs):
    """Add every v2 detail this run is configured for to one device.

    The bound counts devices detailed, not elapsed time, because these are
    per-device requests: a fifty-thousand-device estate would otherwise spend the
    whole task window here. Past the bound the v1 import continues untouched.
    """
    if not ctx["include_v2_details"]:
        return
    # The id is spliced into a request path, so it is checked rather than
    # escaped: Device.ID is documented as an integer, and anything else is a
    # response this script cannot safely build a URL from. The device is still
    # imported from v1 either way.
    if re_match(ID_PATTERN, device_id) == None:
        return
    if ctx["detailed"] >= ctx["v2_detail_limit"]:
        if not ctx["detail_limit_logged"]:
            ctx["detail_limit_logged"] = True
            print("miradore: reached the v2 detail limit of {} devices; the rest are imported without v2 detail".format(
                ctx["v2_detail_limit"]))
        return
    ctx["detailed"] += 1
    v2_custom_attributes(ctx, device_id, attrs)
    if ctx["include_v2_location"]:
        v2_location(ctx, device_id, attrs)


def local_ip(device):
    """The device's local address.

    Appendix 2 spells the attribute "LocalIpAddress" and `select` accepts that,
    but the element that comes back is "LocalIPAddress". Both are read so the
    value is not lost to a capital letter.
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

    Addresses and MACs are reported at the device level with no pairing, so the
    addresses go on the first interface and the remaining MACs become
    address-less ones, letting a phone still match on its Wi-Fi MAC after a lease
    change.

    Only LocalIPAddress becomes an asset address. Do not add IPAddress: it is the
    egress address the service saw, identical for every device behind one NAT,
    and importing it would hand a whole office one address to correlate on. The
    routable_ips filter guards the same failure for 127.0.0.1.
    """
    ips = routable_ips([local_ip(device)])
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


def software_vendor(entry, identifier):
    """The application's vendor, derived from its identifier.

    InvApplication has no vendor property, so the bundle identifier is the only
    source: a reverse DNS name like com.apple.Safari names apple in its second
    label. Nothing is inferred from a name that is not reverse DNS, since a bare
    "Safari" would make "Safari" the vendor; those go to runZero's own software
    normalization. The element is still read first for a schema that has one.
    """
    vendor = el_text(entry, "Vendor")
    if vendor:
        return vendor
    parts = identifier.split(".")
    if len(parts) >= 3 and parts[0].lower() in ["com", "org", "net", "io", "co", "edu", "gov"]:
        return parts[1]
    return ""


def device_software(device):
    """Installed applications, when they were requested and the device has any."""
    software = []
    for entry in device.find_all(APPLICATIONS_PATH):
        product = el_text(entry, "Name")
        if not product:
            continue
        # Software requires an id, and many InvApplication entries carry no
        # Identifier at all, so the display name is the fallback. Without it
        # those rows fail with "missing argument for id", which on a live site
        # is most of them.
        identifier = el_text(entry, "Identifier")
        params = {"id": (identifier or product)[:255], "product": product[:255]}
        version = el_text(entry, "Version")
        if version:
            params["version"] = version[:255]
        vendor = software_vendor(entry, identifier)
        if vendor:
            params["vendor"] = vendor[:255]
        # as_int yields 0 for anything unparseable, so a string cannot reach
        # installedSize. Zero is dropped with it: it means the site reported no
        # size, not that the application occupies none.
        size = as_int(el_text(entry, "Size"))
        if size > 0:
            params["installedSize"] = size
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
        # Kept raw: hostnames below drops anything not DNS-valid, and on an MDM
        # fleet that is most of them ("John's iPhone").
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
        # The firmware or baseband revision, distinct from the OS version above.
        "miradore_software_version": el_text(device, "InvDevice/SoftwareVersion"),
        "miradore_client_version": el_text(device, "Client/Version"),
        "miradore_management_type": el_text(device, "Client/ManagementType"),
        "miradore_bios_version": first_text(device, ["BIOS/Version", "BIOS/SMBIOSBIOSVersion"]),
        # The addresses as reported, including any filtered out of the interfaces
        # above. IPAddress is the egress address the Miradore service saw, not an
        # address of the device, so it is named for what it is.
        "miradore_public_ip": el_text(device, "IPAddress"),
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

    if device_id in ctx["suspended"]:
        # Suspended is a v2 concept; v1 still reports such a device as Active, so
        # without this the asset looks managed when Miradore has stopped managing
        # it.
        attrs["miradore_suspended"] = "true"

    # Whatever the wildcards returned, under the names the site used. Nothing
    # here assumes a field is present.
    flatten_children(device, "Security", "miradore_security_", attrs)
    flatten_children(device, "Enrollment", "miradore_enrollment_", attrs)

    # Last, so a device already skipped above (no ID, or filtered by status)
    # never costs a request.
    v2_enrich(ctx, device_id, attrs)

    tags = el_texts(device, TAGS_PATH, "Name")
    if tags:
        attrs["miradore_tags"] = ",".join(tags)[:MAX_VALUE_LEN]

    volumes = []
    for volume in device.find_all(STORAGE_PATH)[:MAX_CHILDREN]:
        # Real rows carry Type/TotalSpace/FreeSpace and no Volume, so the label
        # falls back to the storage type rather than leaving a bare colon.
        label = el_text(volume, "Volume") or el_text(volume, "Type")
        total = el_text(volume, "TotalSpace")
        free = el_text(volume, "FreeSpace")
        if label or total:
            volumes.append("{}:{}/{}".format(label, free, total))
    if volumes:
        attrs["miradore_storage"] = ",".join(volumes)[:MAX_VALUE_LEN]

    params = {
        # <slug>:<scope>:<vendor id>. Miradore numbers devices per site starting
        # at 1, so a bare number is not unique across sites and would merge
        # unrelated devices onto one asset. The slug keeps this from colliding
        # with another integration that also namespaces by site.
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
    # LastReported is when the device last checked in, a real observation.
    # Modified only tracks when the database row changed.
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
    # Case-folded so "Acme" and "acme" cannot produce two sets of ids for one
    # site. The request path keeps the operator's spelling, since only the URL
    # is case-sensitive.
    scope = site_name.lower()
    # CONFIG defaults are applied by the console but not on the plain --kwargs
    # path, so each default is repeated here.
    page_size = get_int(kwargs, "page_size", default=100)
    if page_size < 1:
        page_size = 100
    include_software = get_bool(kwargs, "include_software", default=True)
    include_deleted = get_bool(kwargs, "include_deleted", default=False)
    include_v2_details = get_bool(kwargs, "include_v2_details", default=True)
    include_v2_location = get_bool(kwargs, "include_v2_location", default=True)
    v2_detail_limit = get_int(kwargs, "v2_detail_limit", default=5000)
    if v2_detail_limit < 0:
        v2_detail_limit = 0
    if include_software and page_size > SOFTWARE_PAGE_LIMIT:
        # Said aloud rather than silently ignoring the configured value: a run
        # that quietly pages differently than asked is hard to reason about.
        print("miradore: lowering the page size from {} to {} because application inventory is enabled; turn it off to page in larger chunks".format(
            page_size, SOFTWARE_PAGE_LIMIT))
        page_size = SOFTWARE_PAGE_LIMIT

    # The attribute ladder, widest first. Each rung is tried on page 1 only and
    # the one that works is used for the whole walk. Rungs step down a single
    # group at a time because v1 fails a query whole and never says which
    # attribute it objected to, so dropping one group per attempt is the only way
    # to keep what the site does support. The wildcards go first as the likeliest
    # refusal, applications next. The last rung sends no select at all, which no
    # site can reject on its attribute list. Each rung carries whether it still
    # asks for applications, so a fallback keeping them still parses them.
    base = SELECT_CORE + SELECT_EXTRA
    stages = []
    if include_software:
        stages.append(("the full attribute set", base + SELECT_POSTURE + SELECT_SOFTWARE, True))
        stages.append(("the inventory and application attributes", base + SELECT_SOFTWARE, True))
    else:
        stages.append(("the full attribute set", base + SELECT_POSTURE, False))
    stages.append(("the inventory attributes alone", base, False))
    stages.append(("the core attribute set", SELECT_CORE, False))
    stages.append(("the API's default attribute set", [], False))

    ctx = {
        "url": base_url,
        # Replaced by choose_path below, which settles the site segment against
        # the live site rather than assuming it.
        "path": ITEM_PATH,
        # The typed name builds the request path (the URL is case-sensitive);
        # the folded form scopes asset ids.
        "site_name": site_name,
        "scope": scope,
        "api_key": api_key,
        "select": stages[0][1],
        "page_size": page_size,
        "include_software": include_software,
        "include_deleted": include_deleted,
        "include_v2_details": include_v2_details,
        "include_v2_location": include_v2_location,
        "v2_detail_limit": v2_detail_limit,
        # Devices detailed so far, and whether the limit has been announced:
        # once per run, not once per device past it.
        "detailed": 0,
        "detail_limit_logged": False,
        # v2 endpoints that already failed, so an unavailable one is reported
        # once rather than for every device in the estate.
        "v2_failures": {},
        "suspended": {},
        "now": now(),
        "http_options": get_http_options(kwargs, headers={"Accept": "application/xml"}),
        # v2 is served from the server root and takes the key in a header, so it
        # needs its own base URL and header set. get_http_options snapshots the
        # headers it is given, so these are built separately rather than by
        # copying the v1 options.
        "v2_url": v2_url(base_url, site_name),
        # Filled in below, once choose_path has settled which spelling of the
        # site name the server accepts.
        "v2_options": None,
    }

    path_err = choose_path(ctx)
    if path_err != None:
        print("miradore: could not read the device list: {}".format(path_err))
        if "401" not in path_err:
            # The API answers 500 both for a site that does not exist and for one
            # in the wrong case, and the error never says which.
            print("miradore: check the site name. It is the segment in your console URL " +
                  "(https://<server>/<site name>/) and it is case-sensitive; the API answers " +
                  "500 rather than 404 when it does not match.")
        return None

    # X-Instance-Name is case-sensitive and answers a wrong casing with 403 where
    # v1's path answers 500: two different errors for one mistake. v1 has just
    # proved which spelling the server accepts, so reuse it rather than asking
    # the operator for the site name twice.
    ctx["v2_options"] = get_http_options(kwargs, headers={
        "Accept": "application/json",
        "X-API-Key": api_key,
        "X-Instance-Name": site_from_path(ctx["path"], site_name),
    })
    if include_v2_details:
        ctx["suspended"] = v2_suspended_ids(ctx)

    reported = 0
    skipped = 0
    seen_total = -1
    previous = None
    stage = 0

    p = pager("devices")
    while p.next():
        devices, total, err, retryable = fetch_page(ctx, p.page)
        # A rejected query fails whole, which would cost the entire import for
        # one unsupported attribute. Walk down the ladder on page 1 until a
        # query is accepted.
        for _ in range(len(stages)):
            if err == None or not retryable or p.page != 1 or stage + 1 >= len(stages):
                break
            stage += 1
            print("miradore: {} failed ({}); retrying with {}".format(
                safe_label(ctx, p.page), err, stages[stage][0]))
            ctx["select"] = stages[stage][1]
            # Rungs differ on whether they still ask for InvApplication.
            ctx["include_software"] = stages[stage][2]
            devices, total, err, retryable = fetch_page(ctx, p.page)
        if err != None:
            print("miradore: {} failed: {}".format(safe_label(ctx, p.page), err))
            break
        # Recorded before the empty check, so a site matching nothing still ends
        # the run saying "0 of 0" rather than leaving it ambiguous whether the
        # query was answered at all.
        if total >= 0:
            seen_total = total
        if not devices:
            break

        # A server ignoring the page option, or a proxy replaying one response,
        # would otherwise be paged forever. Comparing the ids on consecutive
        # pages catches that on the first repeat.
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

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-aruba-clearpass",
    "name": "HPE Aruba ClearPass",
    "type": "inbound",
    "description": "Imports endpoints, device profiles, and optional RADIUS session context from an HPE Aruba ClearPass Policy Manager appliance.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # ClearPass is an access-control system, not an asset inventory. The id
    # is derived from the MAC rather than issued by the source, so it must
    # not drive or block matching; correlation falls back to the MAC, the
    # profiled addresses, and the profiled hostname.
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "ClearPass URL",
            "type": "url",
            "required": True,
            "placeholder": "https://cppm.example.com",
            "description": "Base URL of the ClearPass Policy Manager publisher or a node that serves the API. The /api path is appended automatically.",
        },
        {
            "key": "client_id",
            "label": "API client ID",
            "type": "string",
            "required": True,
            "description": "Client ID of an API client created under Guest > Administration > API Services > API Clients, with the client_credentials grant enabled.",
        },
        {
            "key": "client_secret",
            "label": "API client secret",
            "type": "secret",
            "required": True,
            "description": "Client secret for the API client. Shown only once when the client is created.",
        },
        {
            "key": "status_filter",
            "label": "Endpoint status",
            "type": "enum",
            "required": False,
            "default": "any",
            "options": ["any", "known", "unknown", "disabled"],
            "caseInsensitive": True,
            "description": "Import only endpoints with this status. any imports every endpoint in the database.",
        },
        {
            "key": "include_sessions",
            "label": "Join active RADIUS sessions",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Join the active session table onto endpoints by MAC for the live client IP, NAS address and port, SSID, and assigned role. Sessions are transient; an IP taken from one can be wrong by the time the task runs.",
        },
        {
            "key": "max_profile_age_days",
            "label": "Maximum profile age (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "max": 3650,
            "description": "Drop the profiled IP addresses of any endpoint last profiled more than this many days ago, keeping the asset MAC-only. 0 imports profiled addresses regardless of age.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 1000,
            "description": "Value sent as limit on every paged read. The API caps this at 1000.",
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
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ip')
load('http', 'get_json', 'post_json', 'bearer', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('json', json_encode='encode')

load('time', 'now', 'parse_ts')

load('coerce', 'as_dict')
OAUTH_PATH = "/api/oauth"
ENDPOINT_PATH = "/api/endpoint"
SESSION_PATH = "/api/session"

DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 1000

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so every page ceiling is that target
# divided by the page size. At the 500-endpoint default that is
# ceil(10,000,000 / 500) = 20,000 pages, which is the declared max_pages default.
#
# The ceiling is a BACKSTOP, not the working guard. The working guard is the
# repeated-page check in each walk: an appliance that ignores `offset` re-serves
# one page forever, and against that failure the ceiling IS the request count --
# no cap derived from a record target can be small enough to catch it quickly
# without truncating a real endpoint database. Either stop is logged, because a
# truncated import that says nothing looks exactly like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = 20000
MAX_TAG_LENGTH = 64

# The enum value that means "do not filter on status at all".
STATUS_ANY = "any"

# The endpoint status enum is declared in lower case so the value is easy to
# type, but ClearPass matches the filter against its own capitalization.
STATUS_FILTER_VALUES = {
    "known": "Known",
    "unknown": "Unknown",
    "disabled": "Disabled",
}

# ClearPass takes `filter` as a JSON-encoded string rather than as repeated
# query parameters, so an unfiltered read still has to send a literal "{}".
EMPTY_FILTER = "{}"

# ClearPass publishes no rate limit, and a Policy Manager appliance answers the
# API from the same node that authenticates the network. Back off generously
# rather than racing it; the retry budget itself is on by default.
HTTP_RETRY_BACKOFF = 2.0

# An API client whose token expires this quickly cannot outlive a full walk of
# a large endpoint database, so it is worth warning about.
SHORT_TOKEN_LIFETIME = 900

# Only sessions in this state contribute an address. `stale` and `closed` rows
# describe where a device used to be, and importing their IP is worse than
# importing no IP at all.
SESSION_ACTIVE_STATE = "active"

# Fields copied off a joined session. This is a deliberate allowlist, not a
# blocklist: the session table is the guest registration store as well as the
# RADIUS accounting store, and visitor_name, visitor_company, visitor_carrier,
# visitor_phone, sponsor_name, sponsor_email, and sponsor_profile_name are
# personal contact details that have no place in an asset inventory.
SESSION_FIELDS = [
    "id",
    "acctsessionid",
    "state",
    "username",
    "nasipaddress",
    "nas_name",
    "nasportid",
    "nasporttype",
    "calledstationid",
    "callingstationid",
    "framedipaddress",
    "ssid",
    "ap_name",
    "servicetype",
    "tipsrole",
    "arubauserrole",
    "arubauservlan",
    "role_name",
    "acctstarttime",
    "acctsessiontime",
    "updated_at",
    "cppm_uuid",
]

OFFSET_RE = r"([Zz]|[+-]\d{2}:?\d{2})$"

# profile.device_category is ClearPass Profile's broadest classification of a
# device. Only the categories that name a runZero device type outright are
# promoted; "Computer" is deliberately absent because runZero separates server,
# desktop, and laptop and the category cannot tell them apart. Everything is
# kept as a custom attribute and a tag regardless.
DEVICE_CATEGORY_TYPES = {
    "PRINTER": "Printer",
    "ACCESS POINT": "Wireless Access Point",
    "ACCESSPOINT": "Wireless Access Point",
    "ROUTER": "Router",
    "SWITCH": "Switch",
    "FIREWALL": "Firewall",
    "VOIP": "IP Phone",
    "IP PHONE": "IP Phone",
    "IPPHONE": "IP Phone",
    "IP CAMERA": "IP Camera",
    "IPCAMERA": "IP Camera",
    "SMARTDEVICE": "Mobile Device",
    "SMART DEVICE": "Mobile Device",
    "SERVER": "Server",
    "STORAGE": "Storage",
    "GAME CONSOLE": "Game Console",
    "GAMECONSOLE": "Game Console",
    "SCANNER": "Scanner",
    "UPS": "UPS",
    "VIRTUAL MACHINE": "Virtual Machine",
    "VIRTUALMACHINE": "Virtual Machine",
}

# Device Insight tags are free-form labels, so they are only consulted when the
# profile carries no category, and only for substrings that name a device class
# outright. The same conservative rule the DHCP-fingerprint mapping follows.
INSIGHT_TAG_DEVICE_TYPES = [
    ("printer", "Printer"),
    ("ip camera", "IP Camera"),
    ("ip phone", "IP Phone"),
    ("voip", "IP Phone"),
    ("access point", "Wireless Access Point"),
    ("firewall", "Firewall"),
    ("router", "Router"),
    ("switch", "Switch"),
]

def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()
def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    The shared normalize_mac helper is deliberately not used here. It clears the
    locally-administered bit of the first octet, so aa:bb:cc:dd:ee:ff and
    a8:bb:cc:dd:ee:ff both normalize to a8:bb:cc:dd:ee:ff and two genuinely
    different endpoints would collapse onto one imported id. Every randomized
    client MAC carries that bit, and ClearPass sees a great many of them.
    """
    text = _clean(value).lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in "0123456789abcdef":
            return ""
    octets = []
    for index in range(6):
        octets.append(text[index * 2:index * 2 + 2])
    return ":".join(octets)

def _cppm_host(base_url):
    """Return the ClearPass hostname, which is the scope every imported id sits under.

    The scheme and port are dropped so that reaching the same appliance on a
    different port does not change the identity of already-imported assets.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1]
def _insight_tags(value):
    """Return device_insight_tags as a list.

    The schema types the field as a string while the appliance and Aruba's own
    clients treat it as a list of tag names, so both shapes are accepted and a
    string is split on commas.
    """
    tags = []
    if type(value) == "list":
        for entry in value:
            entry = _clean(entry)
            if entry:
                tags.append(entry)
        return tags
    for entry in _clean(value).split(","):
        entry = _clean(entry)
        if entry:
            tags.append(entry)
    return tags

def _device_type(category, insight_tags):
    """Return a runZero device type for the classifications that name one outright."""
    mapped = DEVICE_CATEGORY_TYPES.get(category.upper(), "")
    if mapped:
        return mapped
    for tag in insight_tags:
        lowered = tag.lower()
        for entry in INSIGHT_TAG_DEVICE_TYPES:
            if entry[0] in lowered:
                return entry[1]
    return ""

def _endpoint_filter(status):
    """Build the JSON filter expression sent as the endpoint read's filter param.

    The API takes filter as a JSON-encoded string, so the expression is encoded
    here and the result becomes a single query parameter value.
    """
    value = STATUS_FILTER_VALUES.get(_clean(status).lower(), "")
    if value:
        return json_encode({"status": value})
    return EMPTY_FILTER

def _page_params(filter_expression, sort, offset, page_size):
    """Build the query for one paged read."""
    return {
        "filter": filter_expression,
        "sort": sort,
        "offset": str(offset),
        "limit": str(page_size),
        # Counting the whole table on every page is an expensive scan on the
        # appliance and nothing here needs the total.
        "calculate_count": "false",
    }

def retrieved_of(reported, total):
    """The retrieved/available half of a truncation message.

    A bare count says nothing about whether the import is nearly complete or
    stopped at the first percent, so pair it with whatever total the API
    reported. ClearPass only counts the whole table when asked, and the walk
    deliberately sends calculate_count=false because that count is a full scan
    on an appliance that is also authenticating the network -- so this always
    takes the second branch. Say that plainly rather than printing a bare slash
    or inventing a denominator.
    """
    if type(total) == "int" and total > 0:
        return "retrieved {}/{} available assets".format(reported, total)
    return "retrieved {} assets, total not reported".format(reported)

def page_ceiling(config_kwargs, page_size):
    """The paging ceiling for one walk.

    An explicit max_pages wins. Otherwise the ceiling is the repo-wide ten
    million record target divided by the page size actually in use: the declared
    CONFIG default is that arithmetic at the 500-row default page, and an
    operator who shrinks the page size should still reach the same record target
    rather than a fraction of it.
    """
    requested = get_int(config_kwargs, "max_pages", default=MAX_PAGES)
    if requested != MAX_PAGES:
        return requested
    if page_size > 0:
        return (MAX_RECORDS + page_size - 1) // page_size
    return MAX_PAGES

def _page_signature(items):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the appliance re-served
    one page rather than honouring `offset`. Comparing the ends rather than
    every row keeps this O(1) per page, and it is enough for the failure it
    guards against: a ClearPass that ignores `offset` returns the identical
    response, not a rearrangement of one.
    """
    if not items:
        return "empty"
    first = items[0]
    last = items[-1]
    first_id = str(first.get("id", "")) if type(first) == "dict" else ""
    last_id = str(last.get("id", "")) if type(last) == "dict" else ""
    return "{}|{}|{}".format(len(items), first_id, last_id)

def _get_page(url, http_options, params):
    """Fetch one page and return (items, has_next, err).

    Responses are HAL+JSON: the rows live under _embedded.items and _links
    carries a next reference on every page but the last.
    """
    options = dict(http_options)
    options["params"] = params
    data, err = get_json(url, **options)
    if err:
        return [], False, err
    data = data or {}
    if type(data) != "dict":
        return [], False, "unexpected response of type " + type(data)
    items = as_dict(data.get("_embedded")).get("items", [])
    if type(items) != "list":
        return [], False, "unexpected items of type " + type(items)
    return items, bool(as_dict(data.get("_links")).get("next")), None

def _auth_hint(err):
    """Print a credential hint for the statuses that mean ClearPass rejected the client."""
    if err.startswith("status 401") or err.startswith("status 403"):
        print("aruba-clearpass: check that the API client is enabled and its operator profile grants read access")

def _session_rank(record):
    """Rank a session so the most recent one wins when a MAC has several.

    Ranking on the accounting start time keeps the choice deterministic even if
    the appliance ignores the requested sort order; the accounting id breaks a
    tie between two rows that start in the same second.
    """
    started = parse_ts(record.get("acctstarttime"))
    stamp = started.unix if started else 0
    return (stamp, _clean(record.get("id")))

def build_asset(record, cppm_host, session, max_profile_age_hours):
    """Build one ImportAsset from an endpoint row and its optional session join."""
    mac = _mac_key(record.get("mac_address"))
    profile = as_dict(record.get("profile"))
    nad = as_dict(record.get("nad_detail"))
    insight_tags = _insight_tags(record.get("device_insight_tags"))
    status = _clean(record.get("status"))

    # A profiled address is ClearPass's own record of where the endpoint was
    # last seen, not a live observation, so an operator can require it to be
    # recent before it is allowed to act as a merge signal.
    last_profiled = parse_ts(profile.get("last_profiled_at"))
    stale_profile = False
    if max_profile_age_hours > 0 and last_profiled:
        if (now() - last_profiled).hours > max_profile_age_hours:
            stale_profile = True

    ips = []
    if not stale_profile:
        for value in [profile.get("ipv4_address"), profile.get("ipv6_address")]:
            address = routable_ip(value)
            if address:
                ips.append(address)
    if session:
        address = routable_ip(session.get("framedipaddress"))
        if address:
            ips.append(address)

    nic = network_interface(mac=mac, ips=ips)
    netifs = [nic] if nic else []

    attrs = {
        # The numeric endpoint id is recorded so an operator can follow an asset
        # back into Policy Manager, but it is not used as the imported id: it is
        # allocated by one cluster's publisher and means nothing outside it.
        "endpoint_id": record.get("id", ""),
        "mac_address": _clean(record.get("mac_address")),
        "status": status,
        "description": record.get("description", ""),
        "randomized_mac": record.get("randomized_mac", False),
        "device_insight_tags": insight_tags,
        "added_at": record.get("added_at", ""),
        "updated_at": record.get("updated_at", ""),
        # The endpoint's free-form attribute map. ClearPass stores whatever the
        # profiler, an operator, or a policy wrote here, so it is flattened
        # verbatim rather than cherry-picked.
        "attributes": as_dict(record.get("attributes")),
    }

    if profile:
        attrs["profile"] = {
            "ipv4_address": profile.get("ipv4_address", ""),
            "ipv6_address": profile.get("ipv6_address", ""),
            "static_ip": profile.get("static_ip", False),
            "host_name": profile.get("host_name", ""),
            "device_category": profile.get("device_category", ""),
            "device_os_family": profile.get("device_os_family", ""),
            "device_name": profile.get("device_name", ""),
            "profiled_by": profile.get("profiled_by", ""),
            "first_profiled_at": profile.get("first_profiled_at", ""),
            "last_profiled_at": profile.get("last_profiled_at", ""),
        }

    if nad:
        attrs["nad_ip"] = nad.get("nad_ip", "")
        attrs["nad_port"] = nad.get("nad_port", "")

    if session:
        picked = {}
        for field in SESSION_FIELDS:
            if field in session:
                picked[field] = session.get(field, "")
        attrs["session"] = picked

    tags = ["aruba-clearpass"]
    if status:
        tags.append("status:" + status.lower())
    for tag in insight_tags:
        tags.append("device-insight:" + tag[:MAX_TAG_LENGTH])

    category = _clean(profile.get("device_category"))
    if category:
        tags.append("device-category:" + category.lower()[:MAX_TAG_LENGTH])
    os_family = _clean(profile.get("device_os_family"))
    if os_family:
        tags.append("device-os-family:" + os_family.lower()[:MAX_TAG_LENGTH])
    device_name = _clean(profile.get("device_name"))
    if device_name:
        tags.append("device-name:" + device_name.lower()[:MAX_TAG_LENGTH])

    # A randomized MAC is a per-network private address the client invented, so
    # it correlates with what runZero sees on the wire but says nothing durable
    # about the hardware. Flagging it keeps that visible in search.
    if record.get("randomized_mac", False):
        tags.append("aruba-clearpass-randomized-mac")
    if stale_profile:
        tags.append("aruba-clearpass-stale-profile")
    if session:
        tags.append("aruba-clearpass-active-session")
        ssid = _clean(session.get("ssid"))
        if ssid:
            tags.append("ssid:" + ssid[:MAX_TAG_LENGTH])

    asset_args = {
        # The MAC is the natural key of the endpoint database and the only part
        # of the record that means anything outside this cluster, so it, not the
        # numeric id, carries the identity. It is normalized first so a change
        # in the appliance's formatting cannot fork one endpoint into two.
        "id": "aruba-clearpass:{}:{}".format(cppm_host, mac),
        "hostnames": [_clean(profile.get("host_name"))],
        "networkInterfaces": netifs,
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix="aruba_clearpass", separator="_"),    }

    device_type = _device_type(category, insight_tags)
    if device_type:
        asset_args["deviceType"] = device_type

    first_seen = parse_ts(record.get("added_at"))
    if not first_seen:
        first_seen = parse_ts(profile.get("first_profiled_at"))
    first_seen = first_seen
    if first_seen:
        asset_args["firstSeenTS"] = first_seen

    last_seen = parse_ts(record.get("updated_at"))
    if not last_seen:
        last_seen = last_profiled
    last_seen = last_seen

    asset = ImportAsset(**asset_args)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_access_token(base_url, client_id, client_secret, config_kwargs):
    """Exchange the API client credentials for a bearer token.

    ClearPass documents this grant with a JSON request body rather than the
    form encoding the OAuth2 spec defaults to, so the exchange is issued
    directly instead of through the shared oauth2_token helper.
    """
    options = get_http_options(config_kwargs, headers={"Accept": "application/json"})
    options["retry_backoff"] = HTTP_RETRY_BACKOFF

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    data, err = post_json(base_url + OAUTH_PATH, json=payload, **options)
    if err:
        print("aruba-clearpass: failed to obtain an access token:", err)
        _auth_hint(err)
        return ""

    data = data or {}
    token = _clean(data.get("access_token"))
    if not token:
        print("aruba-clearpass: token response contained no access_token")
        return ""

    lifetime = data.get("expires_in", 0)
    if type(lifetime) == "int" and lifetime > 0 and lifetime < SHORT_TOKEN_LIFETIME:
        print("aruba-clearpass: access token expires in {}s; raise the API client's token lifetime if a large import fails partway".format(lifetime))
    return token

def fetch_session_index(base_url, http_options, page_size, max_pages):
    """Index the active RADIUS sessions by client MAC.

    The session table holds one row per accounting record, so a device that has
    reauthenticated has several; the most recently started active row wins.
    """
    sessions = {}
    skipped = 0
    url = base_url + SESSION_PATH
    # The state filter is applied server-side to keep closed accounting history
    # off the wire, and re-checked below so an appliance that ignores it still
    # cannot contribute a stale address.
    filter_expression = json_encode({"state": SESSION_ACTIVE_STATE})
    offset = 0
    pages = 0
    capped = True
    last_signature = ""

    for _page in range(0, max_pages):
        items, has_next, err = _get_page(url, http_options,
                                         _page_params(filter_expression, "-id", offset, page_size))
        if err:
            print("aruba-clearpass: failed to fetch active sessions:", err)
            _auth_hint(err)
            return sessions
        pages += 1
        if not items:
            capped = False
            break

        # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it means
        # the appliance ignored `offset`, so the walk is not advancing and every
        # further request can only re-read rows already indexed. Checked before
        # the rows are merged, and it can never truncate genuine data: it only
        # fires on a page that adds nothing.
        signature = _page_signature(items)
        if signature == last_signature:
            print("aruba-clearpass: paging stopped after {} pages (API returned the same page twice walking sessions, {})".format(
                pages, retrieved_of(len(sessions), None)))
            capped = False
            break
        last_signature = signature

        for record in items:
            if type(record) != "dict":
                skipped += 1
                continue
            if _clean(record.get("state")).lower() != SESSION_ACTIVE_STATE:
                skipped += 1
                continue
            mac = _mac_key(record.get("mac_address"))
            if not mac:
                mac = _mac_key(record.get("callingstationid"))
            if not mac:
                skipped += 1
                continue
            existing = sessions.get(mac)
            if existing and _session_rank(existing) >= _session_rank(record):
                continue
            sessions[mac] = record

        if len(items) < page_size or not has_next:
            capped = False
            break
        offset += page_size

    if capped:
        print("aruba-clearpass: page limit of {} hit (integration safety limit, walking sessions, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(len(sessions), None)))

    print("aruba-clearpass: indexed {} active sessions ({} rows ignored)".format(len(sessions), skipped))
    return sessions

def fetch_and_report_endpoints(base_url, http_options, page_size, cppm_host, status,
                               session_index, max_profile_age_hours, max_pages):
    """Fetch and stream endpoints one page at a time so the whole endpoint
    database is never held in memory at once."""
    reported = 0
    skipped = 0
    url = base_url + ENDPOINT_PATH
    filter_expression = _endpoint_filter(status)
    offset = 0
    pages = 0
    capped = True
    last_signature = ""

    for _page in range(0, max_pages):
        items, has_next, err = _get_page(url, http_options,
                                         _page_params(filter_expression, "+id", offset, page_size))
        if err:
            print("aruba-clearpass: failed to fetch endpoints at offset {}:".format(offset), err)
            _auth_hint(err)
            return reported, skipped
        pages += 1
        if not items:
            capped = False
            break

        # THE PRIMARY RUNAWAY GUARD. See fetch_session_index: a repeated page
        # means `offset` was ignored, and reporting it again would only
        # re-import endpoints already sent.
        signature = _page_signature(items)
        if signature == last_signature:
            print("aruba-clearpass: paging stopped after {} pages (API returned the same page twice walking endpoints, {})".format(
                pages, retrieved_of(reported, None)))
            capped = False
            break
        last_signature = signature

        assets = []
        for record in items:
            if type(record) != "dict":
                skipped += 1
                continue
            mac = _mac_key(record.get("mac_address"))
            if not mac:
                skipped += 1
                print("aruba-clearpass: skipping endpoint with no usable mac_address: id={}".format(
                    record.get("id", "")))
                continue
            assets.append(build_asset(record, cppm_host, session_index.get(mac),
                                      max_profile_age_hours))
        if assets:
            reported += report_assets(assets)

        if len(items) < page_size or not has_next:
            capped = False
            break
        offset += page_size

    if capped:
        print("aruba-clearpass: page limit of {} hit (integration safety limit, walking endpoints, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(reported, None)))

    return reported, skipped

def main(**kwargs):
    base_url = get_url_base(kwargs)
    cppm_host = _cppm_host(base_url)
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    status = get_string(kwargs, "status_filter", default=STATUS_ANY)
    include_sessions = get_bool(kwargs, "include_sessions", default=False)
    max_profile_age_days = get_int(kwargs, "max_profile_age_days", default=0)
    if max_profile_age_days < 0:
        max_profile_age_days = 0
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    token = fetch_access_token(base_url, client_id, client_secret, kwargs)
    if not token:
        return None

    http_options = get_http_options(kwargs, headers={
        "Authorization": bearer(token),
        "Accept": "application/json",
    })
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    max_pages = page_ceiling(kwargs, page_size)

    session_index = {}
    if include_sessions:
        session_index = fetch_session_index(base_url, http_options, page_size, max_pages)

    reported, skipped = fetch_and_report_endpoints(base_url, http_options, page_size,
                                                   cppm_host, status, session_index,
                                                   max_profile_age_days * 24, max_pages)
    print("aruba-clearpass: reported {} endpoints from {}".format(reported, cppm_host))
    if skipped:
        print("aruba-clearpass: skipped {} records with no usable mac_address".format(skipped))
    if not reported:
        print("aruba-clearpass: no assets retrieved")
    return None

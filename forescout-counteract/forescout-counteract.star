# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-forescout-counteract",
    "name": "Forescout CounterACT",
    "type": "inbound",
    "description": "Imports endpoints, classification properties, open port services, installed software, and CVE findings from Forescout CounterACT.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The paginated walk stops when the Enterprise Manager stops handing back a
    # next_link. This is the backstop for an appliance that keeps handing one
    # back forever. At the default page size of 1000 it bounds the run at a
    # million endpoints, which is also roughly what 20 requests per minute can
    # move inside a task's wall clock.
    "maxPages": 1000,
    # The CounterACT object id is the endpoint's IPv4 address packed into a
    # 32-bit integer, so it identifies an address rather than a device: it
    # changes on re-addressing and is handed to whatever takes the address
    # over. Kept as a namespaced record key, never a merge key; correlation
    # falls back to MAC, IP, and name. See README "Asset identity".
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Enterprise Manager URL",
            "type": "url",
            "required": True,
            "placeholder": "https://enterprise-manager.example.com",
            "description": "Base URL of the Forescout Enterprise Manager or standalone Appliance. The /api/ paths are appended automatically.",
        },
        {
            "key": "username",
            "label": "Web API username",
            "type": "string",
            "required": True,
            "description": "Web API user created under Tools > Options > Web API > User Settings. This is not a console operator account.",
        },
        {
            "key": "password",
            "label": "Web API password",
            "type": "secret",
            "required": True,
            "description": "Password for the Web API user.",
        },
        {
            "key": "match_rule_ids",
            "label": "Policy or rule IDs",
            "type": "string",
            "required": False,
            "description": "Optional comma-separated Forescout policy or sub-rule IDs. Only hosts selected by all of them are imported. Use this to scope a large Enterprise Manager.",
        },
        {
            "key": "host_filter",
            "label": "Host property filter",
            "type": "string",
            "required": False,
            "placeholder": "online=true&onsite=true",
            "description": "Optional host field filter in the Web API's own format, for example online=true. Appended to the host index query verbatim.",
        },
        {
            "key": "include_details",
            "label": "Import classification, services, and software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request host properties alongside each endpoint. Disable it to import the IP and MAC list only.",
        },
        {
            "key": "page_size",
            "label": "Endpoints per page",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 50,
            "max": 5000,
            "description": "Endpoints returned per paginated request. The Web API accepts 50 to 5000. Lower it if a large Enterprise Manager truncates a page on an internal timeout.",
        },
        {
            "key": "since_days",
            "label": "Only import endpoints updated in the last N days",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Incremental sync. Sends the paginated walk a sinceTime of this many days ago, so the Enterprise Manager answers only with endpoints updated since then. 0 imports the whole estate. Ignored on the legacy path, which has no equivalent.",
        },
        {
            "key": "detail_limit",
            "label": "Detail enrichment limit (legacy path only)",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Caps the one-request-per-host enrichment used only when the Enterprise Manager is too old for the paginated endpoint. Hosts past the limit are still imported with their IP and MAC. 0 removes the cap. The paginated path selects properties inline and ignores this.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac', 'routable_ip', 'clean_hostnames')
load('http', 'get_json', 'post_json', http_post='post', 'url_encode', 'url_parse')
load('json', json_encode='encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('re', re_find_all='find_all', re_match='match')
load('time', 'now', 'sleep', 'parse_ts')

load('coerce', 'as_text', 'as_float', 'dedupe')
VENDOR = "forescout-counteract"
ATTR_PREFIX = "forescout_counteract"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
LOGIN_PATH = "/api/login"
HOSTS_PATH = "/api/hosts"
DISCOVERY_PATH = "/api/hosts/discovery"
HOSTFIELDS_PATH = "/api/hostfields"
CHUNK_SIZE = 100         # index rows converted per batch on the legacy path
MAX_CHILDREN = 99
MAX_INTERFACES = 32
# The paginated endpoint accepts "up to 50 different fields" in its request
# body, so 50 is a protocol ceiling and not a comfort limit. The same list is
# reused on the legacy path's ?fields= query string.
MAX_FIELDS = 50
MAX_DISCOVERED = 8       # discovered software / CVE properties requested per host
DEFAULT_PAGE_SIZE = 1000
MIN_PAGE_SIZE = 50       # the Web API accepts 50-5000 endpoints per page
MAX_PAGE_SIZE = 5000
SECONDS_PER_DAY = 86400
DEFAULT_TRANSPORT = "tcp"
DIGITS = "0123456789"
TRANSPORTS = ["tcp", "udp", "sctp"]
FIELD_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
# A host key that is neither an integer nor an address still has to be safe to
# put in a URL path and in a foreign id.
HOST_KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
CVE_PATTERN = r"CVE-[0-9]{4}-[0-9]{4,19}"
# Vulnerability.cve is validated against this anchored form and is NOT
# upper-cased on the way in, so every candidate is upper-cased and matched
# here before it is set. A value that fails rejects the whole record.
CVE_STRICT = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# The IP and MAC columns of the host index are documented to carry the literal
# string "undefined" when the endpoint has neither, which is not an address.
UNDEFINED_VALUES = ["undefined", "null", "none", "-"]
# What the classification engine returns when it reached no conclusion.
UNCLASSIFIED_VALUES = ["unknown", "unclassified", "n/a", "none", "-", "other"]

# The Web API mints a JWT whose default validity is five minutes, so the token is
# refreshed well inside that window rather than waiting for the first 401.
TOKEN_TTL_SECONDS = 240

# The login POST stays a raw http_post (the token comes back as a bare body, not
# JSON), and the raw builtin has no retries kwarg, so transient failures are
# retried by hand. Only statuses that mean the request was rejected unprocessed
# are retried, matching what get_json retries elsewhere in the run.
LOGIN_ATTEMPTS = 4
LOGIN_RETRY_STATUSES = [408, 425, 429, 500, 502, 503, 504]

EXCLUDED_MACS = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]

# Host properties this integration knows how to map, requested only when
# GET /api/hostfields reports the deployment actually exposes them. Plugins add
# and remove properties, so no name here is assumed to exist.
#
# hostname_calculated and otsm_details_host_name lead deliberately: they are
# the only hostnames the one captured live property document carries, so a
# deployment shaped like that imports nothing from the plugin-specific names.
HOSTNAME_FIELDS = [
    "hostname_calculated", "otsm_details_host_name", "hostname",
    "dhcp_hostname_v2", "dhcp_hostname", "nbthost", "linux_hostname",
    "mac_hostname", "vmware_guest_host", "aws_instance_public_dns",
]
DOMAIN_FIELDS = ["nbtdomain"]
PORT_FIELDS = ["openports"]
# Every property that can contribute a MAC. macs is the canonical list;
# mac_calculated and the eyeInspect-forwarded list appear on deployments that
# do not publish macs.
MAC_FIELDS = ["macs", "mac", "mac_calculated", "otsm_details_host_mac_addresses"]
# eyeSight's own segmentation. Worth carrying as attributes: a segment name is
# how an operator recognises where in the plant an OT endpoint sits.
SEGMENT_FIELDS = ["segment_name_calculated", "segment_path_calculated"]
# The classification engine is the reason to import CounterACT at all: these are
# the properties its profiling produces.
CLASSIFICATION_FIELDS = [
    "os_classification", "prim_classification", "vendor_classification",
    "model_classification", "manufacturer_classification", "firmware_classification",
    "classification_source_os", "classification_source_func", "cl_type", "cl_rule",
    "mac_vendor_string", "vendor", "dhcp_class", "dhcp_os", "user_def_fp",
    "fingerprint", "matched_fingerprints", "nmap_def_fp7", "nmap_def_fp5",
    "nmap_netfunc7", "va_netfunc", "dhcp_req_fingerprint", "dhcp_opt_fingerprint",
    "otsm_details_manufacturer", "otsm_details_model", "otsm_details_firmware_version",
    "otsm_details_purdue_level", "otsm_details_role", "is_iot", "device_role",
]
# The classification properties that carry the most import value, so they
# survive the 50-field ceiling on a deployment that advertises hundreds.
PRIMARY_CLASSIFICATION_FIELDS = [
    "prim_classification", "os_classification", "vendor_classification",
    "model_classification", "manufacturer_classification", "mac_vendor_string",
]
# Date-typed host properties, best first. The first one that parses becomes a
# lastSeenTS candidate. ipv4_report_time is deliberately LAST despite its name:
# a live property document returns it as {"value": "true"}, a boolean, while
# last_nbt_report_time alongside it carries a real epoch.
LAST_SEEN_FIELDS = ["otsm_details_last_seen", "last_nbt_report_time", "ipv4_report_time"]

# First-discovery is not published as a plain Web API property, but a
# deployment running the OT module forwards eyeInspect's own value. It is the
# only first-seen source the Web API has.
FIRST_SEEN_FIELDS = ["otsm_details_first_seen"]
# Properties whose own update time is a direct statement about the endpoint
# being reachable, so their value wrapper's timestamp is the best last-seen
# any deployment can offer regardless of which plugins are installed.
LIVENESS_FIELDS = ["online", "engine_seen_packet"]
STATE_FIELDS = [
    "online", "onsite", "engine_seen_packet", "manage_agent", "agent_version",
    "agent_install_mode", "agent_visible_mode", "gst_signed_in_stat", "adm", "misc",
    "access_ip", "ipv4_calculated", "mac_prefix32", "switch_port_name", "sw_hostname",
    "compliance_state", "rem_category",
]
# Substrings used to discover installed-software and vulnerability properties,
# whose names differ between deployments depending on the plugins installed.
SOFTWARE_FIELD_HINTS = ["application", "installed_program", "installed_software", "packages"]
VULN_FIELD_HINTS = ["cve", "vulnerab"]

# Sub-field names seen in the composite CVE properties CounterACT publishes.
# The eyeInspect forwarder (otsm_details_cves) and the risk plugin
# (cysiv_risk_cve_list) name the same facts differently, so both spellings are
# read and anything unrecognised falls back to scraping identifiers out of the
# value with a regex.
CVE_ID_KEYS = ["cve_id", "cysiv_cve_id", "cve", "id", "cve_name"]
CVE_SCORE_KEYS = ["cvss_score", "cysiv_cve_cvss_score", "cvss_base_score"]
CVE_TEMPORAL_KEYS = ["cvss_temporal_score", "cysiv_cve_cvss_temporal_score"]
CVE_TITLE_KEYS = ["title", "name", "summary", "description"]
CVSS_IMPACT_KEYS = [
    "cvss_confidentiality_impact", "cvss_integrity_impact", "cvss_availability_impact",
]
CVSS2_MARKER_KEYS = ["cvss_authentication", "cvss_access_vector", "cvss_access_complexity"]
CVSS2_IMPACTS = ["PARTIAL", "COMPLETE"]
CVE_ATTR_KEYS = [
    "icsa_id", "matching_confidence", "vendor_specific_id", "cvss_remediation_level",
    "cvss_reporting_confidence", "cvss_exploitability", "cvss_access_vector",
    "cysiv_cve_exploitability_level", "cysiv_cve_exploitability_percentile",
    "cysiv_cve_cisa",
]

# Forescout's Function classification, mapped onto the device type vocabulary
# runZero already uses. Unmapped values survive verbatim, so a deployment with a
# custom classification tree still gets a device type.
DEVICE_TYPES = {
    "desktop": "Desktop",
    "workstation": "Desktop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "server": "Server",
    "thin client": "Thin Client",
    "printer": "Printer",
    "multifunction printer": "Printer",
    "scanner": "Scanner",
    "ip camera": "IP Camera",
    "camera": "IP Camera",
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "access point": "Wireless Access Point",
    "wireless access point": "Wireless Access Point",
    "wireless controller": "Wireless Controller",
    "network device": "Network Device",
    "voip": "VoIP Phone",
    "voip phone": "VoIP Phone",
    "ip phone": "VoIP Phone",
    "mobile": "Mobile Device",
    "smartphone": "Mobile Device",
    "tablet": "Mobile Device",
    "hypervisor": "Hypervisor",
    "virtual machine": "Virtual Machine",
    "storage": "Storage",
    "nas": "Storage",
    "ups": "UPS",
    "game console": "Game Console",
    "smart tv": "TV",
    "medical device": "Medical Device",
    "plc": "Industrial Control System",
    "rtu": "Industrial Control System",
    "hmi": "Industrial Control System",
    "industrial device": "Industrial Control System",
}
def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is not numeric."""
    if type(value) == "int":
        return value
    text = str(value).strip()
    if not text or len(text) > 10:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)
def _ipv4_to_int(text):
    """Pack a dotted-quad IPv4 string into a 32-bit integer, or -1."""
    parts = text.split(".")
    if len(parts) != 4:
        return -1
    packed = 0
    for index in range(4):
        octet = _to_int(parts[index])
        if octet < 0 or octet > 255:
            return -1
        packed = packed * 256 + octet
    return packed

def _host_key(value):
    """Canonicalise a CounterACT host key so both walks agree on one value.

    This is the whole of the asset's foreign id, so it MUST NOT depend on which
    endpoint produced the record. The index returns an integer hostId; the
    paginated endpoint calls it id and may return the address form. The two are
    the same number -- 10.42.1.156 packed big-endian IS 170525084 -- so an
    address-shaped id is converted to the integer the index would have given.
    Any other key is screened and passed through identically on both walks.
    See README "One id, two endpoints"."""
    if value == None:
        return ""
    text = as_text(value, join=",").strip()
    if not text or text.lower() in UNDEFINED_VALUES:
        return ""
    numeric = _to_int(text)
    if numeric >= 0:
        return str(numeric)
    packed = _ipv4_to_int(text)
    if packed >= 0:
        return str(packed)
    if len(text) > 128:
        return ""
    for index in range(len(text)):
        if text[index] not in HOST_KEY_CHARS:
            return ""
    return text

def _report_time(value):
    """Parse a CounterACT date property, detecting epoch milliseconds by width.

    A seconds epoch is 10 digits until 2286, so 12 or more digits is
    milliseconds, which parse_ts reads as None unless the unit is named. A
    value under 10 digits is REFUSED rather than parsed: date-named properties
    do not always carry dates (a live document returns ipv4_report_time as
    {"value": "true"}), and a "1" would parse to epoch 1, which the unix <= 0
    guard does not catch.
    """
    text = str(value or "").strip()
    if not text:
        return None
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return _reject_never(parse_ts(text))
    if len(text) >= 12:
        return _reject_never(parse_ts(text, unit="ms"))
    if len(text) < 10:
        return None
    return _reject_never(parse_ts(text))

def _reject_never(ts):
    """Drop the "never" sentinels parse_ts happily returns as real times.

    An ISO year-1 value (Go's zero time) parses to unix=-62135596800 and any
    1970-01-01 value to unix=0. Both survive a `!= None` check and epoch 0
    survives a plain truth test, so an unguarded parse dates a never-seen host
    instead of leaving it unknown."""
    if ts == None or ts.unix <= 0:
        return None
    return ts
def _usable_mac(value):
    """Return the canonical form of a MAC that is a real merge signal, or None.
    CounterACT emits 000000000000 for hosts it has never resolved a MAC for."""
    if not value:
        return None
    mac = normalize_mac(str(value).strip())
    if mac == None or mac in EXCLUDED_MACS:
        return None
    return mac

def _classified(value):
    """Return a classification value, or "" when it is the vendor's way of
    saying it did not classify the endpoint. A live document returns
    os_classification as "Unknown", and importing that as the OS states
    something the classification engine explicitly did not conclude."""
    text = value.strip()
    if text.lower() in UNCLASSIFIED_VALUES:
        return ""
    return text

def _leaf(value):
    """Return the most specific segment of a Forescout tree-path classification
    value. The classification properties are typed tree_path and serialize as
    "Computer/Windows Machine/Desktop", so the leaf is the specific answer."""
    text = as_text(value, join=",").strip()
    if "/" not in text:
        return text
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if not parts:
        return ""
    return parts[-1]

def _root(value):
    """Return the least specific segment of a tree-path classification value."""
    text = as_text(value, join=",").strip()
    if "/" not in text:
        return text
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if not parts:
        return ""
    return parts[0]

def _entries(fields, name):
    """Return one host property's raw value wrappers as a list.

    The Web API wraps every property value as {"timestamp": ..., "value": ...}
    and repeats that wrapper in a list when the property is multi-valued, so
    both shapes normalise to a list of wrappers here. The wrapper is kept
    rather than unwrapped because its timestamp is the only per-value
    freshness the Web API publishes."""
    if type(fields) != "dict":
        return []
    entry = fields.get(name)
    if entry == None:
        return []
    if type(entry) == "list":
        return [item for item in entry if item != None]
    return [entry]

def _values(fields, name):
    """Read one host property as a plain list of values, wrappers removed.
    A dict that is not a wrapper is passed through rather than dropped."""
    out = []
    for item in _entries(fields, name):
        if type(item) == "dict" and "value" in item:
            value = item.get("value")
            if value != None:
                out.append(value)
        elif item != None:
            out.append(item)
    return out

def _stamps(fields, name):
    """Return the wrapper timestamps carried alongside one property's values.

    The guide states that "the timestamp field indicates how recently the value
    was updated in eyeSight", which makes it a per-property freshness signal
    that exists on every deployment. A zero is discarded: the in-group property
    on a live document stamps every value 0, meaning never rather than 1970."""
    out = []
    for item in _entries(fields, name):
        if type(item) != "dict":
            continue
        stamp = _to_int(item.get("timestamp"))
        if stamp > 0:
            out.append(stamp)
    return out

def _freshest_stamp(fields):
    """Return the newest wrapper timestamp anywhere in a property document, or
    0. This is an upper bound on when eyeSight last learned anything about the
    endpoint, and it is the last-seen of last resort."""
    if type(fields) != "dict":
        return 0
    newest = 0
    for name in fields:
        for stamp in _stamps(fields, name):
            if stamp > newest:
                newest = stamp
    return newest

def _derive_last_seen(fields):
    """Choose a lastSeenTS for one endpoint and name where it came from.

    Preference order, best first:
      1. The wrapper timestamp on a liveness property: it says when eyeSight
         last decided whether the endpoint was up, and it needs no plugin.
      2. An explicitly date-typed property, where a plugin publishes one.
      3. The newest wrapper timestamp anywhere in the document, which
         guarantees an answer on any deployment at all."""
    for name in LIVENESS_FIELDS:
        for stamp in _stamps(fields, name):
            seen = _report_time(stamp)
            if seen != None:
                return seen, name
    for name in LAST_SEEN_FIELDS:
        seen = _report_time(_value(fields, name))
        if seen != None:
            return seen, name
    newest = _freshest_stamp(fields)
    if newest:
        seen = _report_time(newest)
        if seen != None:
            return seen, "freshest property update"
    return None, ""

def _value(fields, name):
    """Read one host property as a single trimmed string."""
    values = _values(fields, name)
    if not values:
        return ""
    return as_text(values[0], join=",").strip()

def _is_true(fields, name):
    """Read a boolean host property. The Web API serializes these as strings."""
    return _value(fields, name).lower() in ("true", "yes", "1")

def _safe_field(name):
    """Return a property name that is safe to append to a query string, or an
    empty string. Property names are discovered from the deployment, so they are
    screened rather than trusted."""
    text = as_text(name, join=",").strip()
    if not text or len(text) > 128:
        return ""
    for index in range(len(text)):
        if text[index] not in FIELD_NAME_CHARS:
            return ""
    return text

def _extract_cves(values):
    """Pull CVE identifiers out of arbitrary property values. Identifiers are
    upper-cased before matching because Vulnerability.cve is validated against a
    strict upper-case pattern and a lower-case value fails the whole record."""
    text = ""
    for value in values:
        if type(value) == "string":
            text += " " + value
        else:
            text += " " + json_encode(value)
    if not text.strip():
        return []
    return dedupe(re_find_all(CVE_PATTERN, text.upper()))

def _cvss_version(entry):
    """Decide which CVSS revision a CounterACT CVE record is scored under.

    The records name no version; vocabulary is what separates them. v2 scores
    the three impacts as NONE/PARTIAL/COMPLETE and carries Access Vector,
    Access Complexity and Authentication sub-scores, while v3 scores them as
    NONE/LOW/HIGH. A live document carried both forms inside one property, so
    this is decided per record rather than per deployment."""
    for key in CVSS2_MARKER_KEYS:
        if as_text(entry.get(key), join=",").strip():
            return 2
    for key in CVSS_IMPACT_KEYS:
        if as_text(entry.get(key), join=",").strip().upper() in CVSS2_IMPACTS:
            return 2
    return 3

def _cve_detail(entry):
    """Read a structured CVE record into a normalised dict, or None when the
    value is not one.

    CounterACT publishes CVEs through plugin-specific composite properties
    whose sub-field names differ: the eyeInspect forwarder writes cve_id,
    cvss_score, cvss_temporal_score, title, and icsa_id, while the risk plugin
    prefixes everything with cysiv_cve_. Both carry a CVSS score."""
    if type(entry) != "dict":
        return None

    cve = ""
    for key in CVE_ID_KEYS:
        candidate = as_text(entry.get(key), join=",").strip().upper()
        # Vulnerability.cve is validated and is not upper-cased for us, so the
        # candidate is upper-cased and then matched against the anchored form
        # the platform enforces. A value that would fail is not set at all.
        if re_match(CVE_STRICT, candidate):
            cve = candidate
            break
    if not cve:
        return None

    detail = {"cve": cve, "suppressed": False, "attrs": {}}
    if as_text(entry.get("suppressed"), join=",").strip().lower() == "true":
        detail["suppressed"] = True

    for key in CVE_TITLE_KEYS:
        title = as_text(entry.get(key), join=",").strip()
        # The eyeInspect shape repeats the identifier in "id", so a title that
        # is just the CVE again is no better than the name already set.
        if title and title.upper() != cve:
            detail["title"] = title[:255]
            break

    detail["version"] = _cvss_version(entry)
    for key in CVE_SCORE_KEYS:
        score = as_float(entry.get(key), default=-1.0)
        if score > 0:
            detail["score"] = score
            break
    for key in CVE_TEMPORAL_KEYS:
        temporal = as_float(entry.get(key), default=-1.0)
        if temporal > 0:
            detail["temporal"] = temporal
            break

    detail["published"] = _report_time(as_text(entry.get("cysiv_cve_reported_time"), join=","))
    for key in CVE_ATTR_KEYS:
        value = as_text(entry.get(key), join=",").strip()
        if value:
            detail["attrs"][key] = value
    return detail

def _apply_cve_detail(params, attrs, detail):
    """Fold a normalised CVE record's score and prose onto a Vulnerability."""
    if detail.get("title"):
        params["name"] = detail["title"]
    score = detail.get("score", 0.0)
    if score > 0:
        if detail.get("version") == 2:
            params["cvss2BaseScore"] = float(score)
        else:
            params["cvss3BaseScore"] = float(score)
        # CounterACT publishes no severity of its own for these, so the base
        # score is what ranks them, on the same thresholds the runZero console
        # uses for CVSS elsewhere.
        rank = 4
        if score < 4.0:
            rank = 1
        elif score < 7.0:
            rank = 2
        elif score < 9.0:
            rank = 3
        params["severityRank"] = rank
        params["severityScore"] = float(score)
        params["riskRank"] = rank
        params["riskScore"] = float(score)
    temporal = detail.get("temporal", 0.0)
    if temporal > 0:
        if detail.get("version") == 2:
            params["cvss2TemporalScore"] = float(temporal)
        else:
            params["cvss3TemporalScore"] = float(temporal)
    if detail.get("published") != None:
        params["publishedTS"] = detail["published"]
    for key in detail.get("attrs", {}):
        attrs["cve_" + key] = detail["attrs"][key]

def _parse_open_port(entry):
    """Extract (port, transport) from one openports entry. Transport is an empty
    string when the entry does not name one."""
    if type(entry) == "dict":
        port = _to_int(entry.get("port", entry.get("number", -1)))
        transport = ""
        for key in ("transport", "protocol", "proto", "l4_proto"):
            named = entry.get(key)
            if named:
                transport = str(named).strip().lower()
                break
        if transport not in TRANSPORTS:
            transport = ""
        return port, transport

    if type(entry) == "int":
        return entry, ""

    text = str(entry).lower()
    for separator in ("/", ":", "(", ")", ",", ";", "\t"):
        text = text.replace(separator, " ")
    port = -1
    transport = ""
    for token in text.split(" "):
        if not token:
            continue
        if token in TRANSPORTS:
            if not transport:
                transport = token
            continue
        if port < 0:
            candidate = _to_int(token)
            if candidate >= 0:
                port = candidate
    return port, transport

def _split_product_version(text):
    """Split an application string such as "7-Zip 23.01" into (product,
    version). Only a trailing token that starts with a digit is treated as a
    version; everything else stays in the product name."""
    parts = text.split(" ")
    if len(parts) < 2:
        return text, ""
    tail = parts[-1]
    if tail and tail[0] in DIGITS:
        return " ".join(parts[:-1]).strip(), tail.strip()
    return text, ""

def login(ctx):
    """Exchange the Web API credentials for a JWT and install it on the shared
    request headers. The token is returned as the plain-text response body, not
    as JSON and not in a response header, so this is a raw http.post: get_json
    would try to decode a bare JWT as a document."""
    # The shared options carry the configured User-Agent and TLS settings, so
    # the login request reuses them with its own content type and without the
    # Authorization header it is about to replace.
    headers = dict(ctx["headers"])
    headers.pop("Authorization", None)
    headers.pop("Accept", None)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    options = dict(ctx["http_options"])
    options["headers"] = headers

    body = url_encode({"username": ctx["username"], "password": ctx["password"]})
    resp = None
    for attempt in range(LOGIN_ATTEMPTS):
        if attempt:
            sleep("{}s".format(attempt))
        resp = http_post(ctx["base_url"] + LOGIN_PATH, body=bytes(body), **options)
        if resp != None and resp.status_code not in LOGIN_RETRY_STATUSES:
            break
        print("forescout-counteract: transient Web API login failure (attempt {} of {}): {}".format(
            attempt + 1, LOGIN_ATTEMPTS, resp.status_code if resp != None else "no response"))
    if resp == None:
        print("forescout-counteract: no response from the Web API login endpoint")
        return False
    if resp.status_code != 200:
        print("forescout-counteract: Web API login failed with status {}".format(resp.status_code))
        return False

    token = as_text(resp.body, join=",").strip()
    # A JWT is three dot-separated segments. Anything else is an error page that
    # must not be installed as a credential.
    if len(token) < 16 or token.count(".") != 2:
        print("forescout-counteract: Web API login returned an unexpected body instead of a token")
        return False

    ctx["headers"]["Authorization"] = token
    ctx["token_at"] = now()
    return True

def api_get(ctx, url, label):
    """GET one Web API resource, refreshing the JWT before it expires and once
    more if the Enterprise Manager rejects it anyway. Returns (data, err)."""
    if ctx["token_at"] == None or (now() - ctx["token_at"]).seconds >= TOKEN_TTL_SECONDS:
        if not login(ctx):
            return None, "login failed"

    data, err = get_json(url, **ctx["http_options"])
    if err and err.startswith("status 401"):
        # The token expired earlier than its advertised validity, or the
        # Enterprise Manager was restarted. Re-authenticate once and retry.
        print("forescout-counteract: re-authenticating after a rejected token while fetching {}".format(label))
        if not login(ctx):
            return None, err
        data, err = get_json(url, **ctx["http_options"])
    return data, err

def api_post(ctx, url, body, label):
    """POST one Web API resource with a JSON body, refreshing the JWT the same
    way api_get does. Returns (data, err).

    The transaction is rate limited to 20 requests per minute; post_json
    already retries 429 honouring Retry-After, so nothing is backed off by hand
    here. The request selects endpoints rather than changing them, so leaving
    the default retries on is safe."""
    if ctx["token_at"] == None or (now() - ctx["token_at"]).seconds >= TOKEN_TTL_SECONDS:
        if not login(ctx):
            return None, "login failed"

    data, err = post_json(url, json=body, **ctx["http_options"])
    if err and err.startswith("status 401"):
        print("forescout-counteract: re-authenticating after a rejected token while fetching {}".format(label))
        if not login(ctx):
            return None, err
        data, err = post_json(url, json=body, **ctx["http_options"])
    return data, err

def build_field_list(ctx):
    """Ask the Enterprise Manager which host properties it exposes and build the
    fields= list from the intersection with what this integration can map.
    Property sets vary per deployment because every plugin contributes its own,
    so nothing is requested that the deployment has not advertised."""
    data, err = api_get(ctx, ctx["base_url"] + HOSTFIELDS_PATH, "host fields")
    if err:
        print("forescout-counteract: failed to fetch the host field index, importing the IP and MAC index only:", err)
        return

    data = data or {}
    entries = data.get("hostFields", []) if type(data) == "dict" else []
    if type(entries) != "list":
        entries = []

    available = []
    for entry in entries:
        if type(entry) != "dict":
            continue
        name = _safe_field(entry.get("name"))
        if name:
            available.append(name)
    if not available:
        print("forescout-counteract: the host field index named no host properties, importing the IP and MAC index only")
        return

    # Installed-software and vulnerability property names are plugin-specific,
    # so they are discovered from the index rather than assumed.
    software = []
    vulns = []
    for name in available:
        lowered = name.lower()
        for hint in SOFTWARE_FIELD_HINTS:
            if hint in lowered and name not in software and len(software) < MAX_DISCOVERED:
                software.append(name)
        for hint in VULN_FIELD_HINTS:
            if hint in lowered and name not in vulns and len(vulns) < MAX_DISCOVERED:
                vulns.append(name)

    # MAX_FIELDS is a protocol ceiling, not a comfort limit, and a deployment
    # can advertise several hundred properties. The request is assembled in
    # tiers so the cap falls on the least valuable names: identity and
    # child-record properties first, then classification detail, then the rest.
    tiers = [
        HOSTNAME_FIELDS + MAC_FIELDS + PORT_FIELDS + DOMAIN_FIELDS,
        LIVENESS_FIELDS + LAST_SEEN_FIELDS + FIRST_SEEN_FIELDS,
        software + vulns,
        PRIMARY_CLASSIFICATION_FIELDS,
        SEGMENT_FIELDS,
        CLASSIFICATION_FIELDS,
        STATE_FIELDS,
    ]
    wanted = []
    for tier in tiers:
        for name in tier:
            if name in available and name not in wanted and len(wanted) < MAX_FIELDS:
                wanted.append(name)

    # A property that did not fit must not be read back either, or the
    # software and CVE builders walk names that were never requested.
    ctx["software_fields"] = [name for name in software if name in wanted]
    ctx["vuln_fields"] = [name for name in vulns if name in wanted]
    ctx["fields"] = wanted
    if not ctx["fields"]:
        print("forescout-counteract: none of the {} host properties this deployment exposes are mappable, importing the IP and MAC list only".format(len(available)))
        return
    print("forescout-counteract: the deployment exposes {} host properties, requesting {} per endpoint ({} software, {} vulnerability)".format(
        len(available), len(ctx["fields"]), len(ctx["software_fields"]), len(ctx["vuln_fields"])))

def fetch_host_detail(ctx, host_id):
    """Fetch the property document for one host. A failure is reported and
    treated as an empty document so a single unreadable host cannot end the run.
    The fields list is appended verbatim rather than passed as params so the
    comma separators reach the Enterprise Manager unencoded."""
    url = ctx["base_url"] + HOSTS_PATH + "/" + str(host_id)
    if ctx["fields"]:
        url += "?fields=" + ",".join(ctx["fields"])

    data, err = api_get(ctx, url, "host {}".format(host_id))
    if err:
        print("forescout-counteract: failed to fetch properties for host {}: {}".format(host_id, err))
        return {}
    data = data or {}
    if type(data) != "dict":
        return {}
    host = data.get("host", {})
    if type(host) != "dict":
        return {}
    return host

def _build_vulnerability(ctx, host_id, name, cve, detail):
    """Assemble one CVE finding, scored when the property carried a score."""
    params = {
        "id": "{}:{}:{}:cve:{}".format(VENDOR, ctx["scope"], host_id, cve),
        "name": cve,
        "cve": cve,
        "category": "CVE",
    }
    attrs = {"cve": cve, "cve_source_property": name}
    if detail != None:
        _apply_cve_detail(params, attrs, detail)
    if params.get("severityScore"):
        ctx["cve_scored"] += 1
    ctx["cve_total"] += 1
    params["customAttributes"] = to_custom_attributes(
        attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return Vulnerability(**params)

def build_vulnerabilities(ctx, host_id, fields):
    """Convert the CVEs a deployment records against a host into findings.

    The vulnerability properties are composite, carrying a CVSS base score, a
    temporal score, a title and an ICS advisory id per entry, so they are read
    structurally and the finding arrives scored. The property names are
    plugin-specific and undocumented, so a shape that is not recognised still
    has its identifiers scraped out with the regex."""
    vulns = []
    seen = []
    suppressed = 0
    for name in ctx["vuln_fields"]:
        for entry in _values(fields, name):
            detail = _cve_detail(entry)
            if detail != None:
                # eyeInspect marks a CVE the operator has dismissed for this
                # endpoint. Importing it would re-raise a finding they closed.
                if detail["suppressed"]:
                    suppressed += 1
                    continue
                if detail["cve"] in seen:
                    continue
                seen.append(detail["cve"])
                vulns.append(_build_vulnerability(ctx, host_id, name, detail["cve"], detail))
                continue
            for cve in _extract_cves([entry]):
                if cve in seen:
                    continue
                seen.append(cve)
                vulns.append(_build_vulnerability(ctx, host_id, name, cve, None))
    ctx["cve_suppressed"] += suppressed
    return vulns

def build_software(ctx, host_id, address, fields):
    """Convert the installed-application properties into Software records. The
    property names are discovered per deployment and their element shape is not
    published, so dicts, "Product Version" strings, and bare names are all
    accepted. CounterACT emits no CPE, so cpe23 is left unset rather than
    synthesized."""
    software = []
    seen = []
    for name in ctx["software_fields"]:
        for entry in _values(fields, name):
            vendor = ""
            version = ""
            raw = ""
            if type(entry) == "dict":
                product = ""
                # app_name / app_version are the sub-field names the guide's
                # own composite example uses for Applications Installed.
                for key in ("app_name", "name", "product", "display_name", "application", "title"):
                    product = as_text(entry.get(key), join=",").strip()
                    if product:
                        break
                for key in ("app_version", "version", "display_version", "product_version"):
                    version = as_text(entry.get(key), join=",").strip()
                    if version:
                        break
                for key in ("vendor", "publisher", "manufacturer"):
                    vendor = as_text(entry.get(key), join=",").strip()
                    if vendor:
                        break
                if not version:
                    product, version = _split_product_version(product)
            else:
                raw = as_text(entry, join=",").strip()
                if not raw:
                    continue
                product, version = _split_product_version(raw)

            if not product:
                continue
            key = product + "|" + version
            if key in seen:
                continue
            seen.append(key)

            params = {
                "id": "{}:{}:{}:software:{}".format(VENDOR, ctx["scope"], host_id, key),
                "product": product,
                "serviceAddress": address or "127.0.0.1",
                "customAttributes": to_custom_attributes({
                    "software_source_property": name,
                    "software_raw": raw,
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            }
            if vendor:
                params["vendor"] = vendor
            if version:
                params["version"] = version
            software.append(Software(**params))
    return software

def build_services(ctx, address, fields):
    """Build Service objects from the host open-port properties. Only concrete
    port numbers become services: the classification properties name an OS or a
    function without a port and are never turned into one. Entries that name no
    transport are recorded as tcp and flagged."""
    if not address:
        return []

    services = []
    seen = []
    for name in PORT_FIELDS:
        for entry in _values(fields, name):
            port, transport = _parse_open_port(entry)
            if port < 1 or port > 65535:
                continue
            assumed = transport == ""
            if assumed:
                transport = DEFAULT_TRANSPORT
            key = "{}/{}".format(port, transport)
            if key in seen:
                continue
            seen.append(key)
            services.append(Service(
                address=address,
                port=int(port),
                transport=transport,
                customAttributes=to_custom_attributes({
                    "service_source": name,
                    "transport_source": "assumed" if assumed else "reported",
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            ))
    return services

def build_asset(ctx, host_id, index_ip, index_mac, fields, enriched, source):
    """Convert one CounterACT endpoint into a runZero asset.

    Both walks land here with the same four inputs -- a canonical host key, the
    endpoint's IP and MAC, and a property document -- so the asset an endpoint
    produces does not depend on which endpoint produced the record. Returns
    None when the host carries no address, MAC, or name, because the host key
    cannot be used as a merge key and such a record has nothing to correlate
    on."""
    address = routable_ip(index_ip)
    if not address:
        # The paginated walk answers with a bare id for an endpoint whose
        # address eyeSight only knows as a property.
        for name in ("ipv4_calculated", "access_ip"):
            address = routable_ip(_value(fields, name))
            if address:
                break

    macs = []
    usable = _usable_mac(index_mac)
    if usable:
        macs.append(usable)
    for name in MAC_FIELDS:
        for value in _values(fields, name):
            mac = _usable_mac(value)
            if mac and mac not in macs:
                macs.append(mac)

    netifs = []
    if macs:
        for index in range(len(macs[:MAX_INTERFACES])):
            ips = [address] if (index == 0 and address) else []
            nic = network_interface(mac=macs[index], ips=ips)
            if nic:
                netifs.append(nic)
    elif address:
        nic = network_interface(ips=[address])
        if nic:
            netifs.append(nic)

    # NBT/DHCP-derived names carry placeholders ("UNKNOWN", bare IPs) that every
    # unresolved host shares, so they are screened before import: one shared
    # name across an estate is a merge hazard, not an identity.
    hostnames = clean_hostnames([_value(fields, name) for name in HOSTNAME_FIELDS])

    if not netifs and not hostnames:
        print("forescout-counteract: skipping host {} with no address, MAC, or name to correlate on".format(host_id))
        return None

    os_class = _classified(_value(fields, "os_classification"))
    function = _classified(_value(fields, "prim_classification"))
    vendor_class = _classified(_value(fields, "vendor_classification"))
    nic_vendor = _classified(_value(fields, "mac_vendor_string"))

    tags = [VENDOR, "nac"]
    leaf_function = _leaf(function)
    if leaf_function:
        tags.append("function:" + leaf_function)
    if vendor_class:
        tags.append("vendor-model:" + _leaf(vendor_class))
    cl_type = _value(fields, "cl_type")
    if cl_type:
        tags.append("classified-by:" + cl_type)
    if _is_true(fields, "online"):
        tags.append("online")
    if _is_true(fields, "onsite"):
        tags.append("onsite")
    if _is_true(fields, "manage_agent"):
        tags.append("secureconnector")

    services = build_services(ctx, address, fields)
    software = build_software(ctx, host_id, address, fields)
    vulns = build_vulnerabilities(ctx, host_id, fields)

    attrs = {
        "host_id": host_id,
        "enterprise_manager": ctx["scope"],
        "index_ip": index_ip,
        "index_mac": as_text(index_mac, join=","),
        "mac_addresses": macs,
        "detail_enriched": "true" if enriched else "false",
        # Which of the two walks produced this record. The foreign id is
        # identical either way, so this is the only way to tell from the
        # imported asset which endpoint the Enterprise Manager answered on.
        "source_endpoint": source,
    }
    for name in CLASSIFICATION_FIELDS + STATE_FIELDS + DOMAIN_FIELDS + PORT_FIELDS + SEGMENT_FIELDS + LAST_SEEN_FIELDS + FIRST_SEEN_FIELDS:
        values = _values(fields, name)
        if values:
            attrs[name] = values if len(values) > 1 else values[0]
    if enriched:
        attrs["service_count"] = len(services)
        attrs["software_count"] = len(software)
        attrs["vulnerability_count"] = len(vulns)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], host_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "services": services[:MAX_CHILDREN],
        "software": software[:MAX_CHILDREN],
        "vulnerabilities": vulns[:MAX_CHILDREN],    }

    leaf_os = _leaf(os_class)
    if leaf_os:
        params["os"] = leaf_os
    if leaf_function:
        params["deviceType"] = DEVICE_TYPES.get(leaf_function.lower(), leaf_function)
    # The Vendor and Model classification is a tree whose root is the vendor and
    # whose leaf is the model. A deployment that publishes it as a flat string
    # yields a manufacturer and no model, which is why the leaf is only used
    # when the value actually has more than one segment.
    manufacturer = (_root(vendor_class)
                    or _classified(_value(fields, "manufacturer_classification"))
                    or _classified(_value(fields, "otsm_details_manufacturer")) or nic_vendor)
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = ""
    if vendor_class and "/" in vendor_class:
        model = _leaf(vendor_class)
    model = (model or _classified(_value(fields, "model_classification"))
             or _classified(_value(fields, "otsm_details_model")))
    if model:
        params["model"] = model
    domain = _value(fields, "nbtdomain")
    if domain:
        params["domain"] = domain

    # parse_ts rather than parse_time: it returns None on anything it cannot
    # read instead of aborting the script, and clamps a future value to now, so
    # a fast Enterprise Manager clock cannot drop the record.
    last_seen, last_seen_source = _derive_last_seen(fields)
    if last_seen != None:
        params["lastSeenTS"] = last_seen
        attrs["last_seen_source"] = last_seen_source
    for name in FIRST_SEEN_FIELDS:
        first_seen = _report_time(_value(fields, name))
        if first_seen != None:
            params["firstSeenTS"] = first_seen
            attrs["first_seen_source"] = name
            break

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)

def _claim(ctx, record, id_key):
    """Screen one endpoint record and return its canonical host key, or "".
    An endpoint already imported this run returns "" as well, so the two walks
    can be run one after the other without double-reporting anything."""
    if type(record) != "dict":
        # A string where an object is documented. There is nothing to name it
        # by, so it is counted in the summary rather than logged per record.
        ctx["skipped_no_id"] += 1
        return ""
    host_id = _host_key(record.get(id_key))
    if not host_id:
        ctx["skipped_no_id"] += 1
        print("forescout-counteract: skipping host with no object id: ip=" + as_text(record.get("ip"), join=","))
        return ""
    if host_id in ctx["seen"]:
        return ""
    ctx["seen"][host_id] = True
    return host_id

def build_assets(ctx, records):
    """Convert a chunk of CounterACT host index rows into runZero assets.
    Only the legacy walk reaches this: it is where the per-host N+1 lives."""
    assets = []
    for record in records:
        host_id = _claim(ctx, record, "hostId")
        if not host_id:
            continue

        fields = {}
        enriched = False
        if ctx["fields"]:
            if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
                ctx["detail_skipped"] += 1
            else:
                ctx["detail_used"] += 1
                enriched = True
                candidate = fetch_host_detail(ctx, host_id).get("fields", {})
                if type(candidate) == "dict":
                    fields = candidate

        asset = build_asset(ctx, host_id, as_text(record.get("ip"), join=",").strip(),
                            record.get("mac"), fields, enriched, "index")
        if asset:
            assets.append(asset)
    return assets

def discovery_query(ctx, page, node_id):
    """Build the query string for one paginated request. It is appended to the
    URL rather than passed as params= because params= replaces a URL's whole
    query string, and the same helper builds the follow-up pages."""
    query = ["page=" + str(page), "pageSize=" + str(ctx["page_size"]), "nodeId=" + node_id]
    if ctx["since_time"]:
        query.append("sinceTime=" + str(ctx["since_time"]))
    return "?" + "&".join(query)

def _node_id(value):
    """Screen an appliance node id. It reaches a query string and comes from a
    response body, so it is checked rather than trusted. The ids are decimal
    and can be wider than a 32-bit integer -- 5934747350691673071 in the
    guide's own example -- so they are kept as text."""
    text = as_text(value, join=",").strip()
    if not text or len(text) > 64:
        return ""
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return ""
    return text

def next_page_ref(data):
    """Read the next page and node out of a response's next_link.

    Only page and nodeId are taken from it; the URL is rebuilt against the
    configured Enterprise Manager rather than dialled as given. On a
    multi-appliance deployment next_link names the appliance holding the next
    node, which the scanner may have no route to and no credential for.

    Returns (page, node_id) or (-1, "") when the walk is over."""
    metadata = data.get("metadata") if type(data) == "dict" else None
    if type(metadata) != "dict":
        return -1, ""
    link = as_text(metadata.get("next_link"), join=",").strip()
    if not link:
        return -1, ""
    parsed = url_parse(link)
    if parsed == None:
        print("forescout-counteract: the paginated walk returned a next_link that could not be parsed; stopping")
        return -1, ""
    query = parsed.query if type(parsed.query) == "dict" else {}
    page = _to_int(as_text(query.get("page"), join=","))
    node_id = _node_id(query.get("nodeId"))
    if page < 0 or not node_id:
        print("forescout-counteract: the paginated walk returned a next_link naming no page or node; stopping")
        return -1, ""
    return page, node_id

def discovery_walk(ctx):
    """Walk POST /api/hosts/discovery, reporting each page as it arrives.

    This is the endpoint to use where the Web API plugin has it: properties are
    selected inline in the request body, so an estate costs one request per
    page instead of one request per endpoint. Returns (reported, degrade),
    where degrade asks the caller to fall back because the first request never
    landed."""
    body = {"fields": ctx["fields"]}
    page = 0
    node_id = "0"      # the guide recommends starting here and following next_link
    visited = {"0/0": True}
    reported = 0
    requests = 0

    p = pager("discovery pages")
    while p.next():
        url = ctx["base_url"] + DISCOVERY_PATH + discovery_query(ctx, page, node_id)
        data, err = api_post(ctx, url, body, "the paginated endpoint list")
        if err:
            if not requests:
                return 0, err
            print("forescout-counteract: the paginated walk failed at page {} after {} assets: {}".format(
                p.page, reported, err))
            return reported, ""
        requests += 1

        data = data or {}
        hosts = data.get("hosts", []) if type(data) == "dict" else []
        if type(hosts) != "list":
            hosts = []
        for record in hosts:
            host_id = _claim(ctx, record, "id")
            if not host_id:
                continue
            fields = record.get("fields", {})
            if type(fields) != "dict":
                fields = {}
            asset = build_asset(ctx, host_id, as_text(record.get("ip"), join=",").strip(),
                                record.get("mac"), fields, len(ctx["fields"]) > 0, "discovery")
            if asset != None:
                reported += report_asset(asset)

        page, node_id = next_page_ref(data)
        if page < 0:
            break
        # The documented terminator is the absence of a next_link, so an
        # Enterprise Manager that keeps serving one already visited would spin
        # until pager() raises at maxPages and reported a finished run as
        # incomplete. Treat a repeat as the end of the walk.
        step = "{}/{}".format(node_id, page)
        if step in visited:
            print("forescout-counteract: the paginated walk repeated page {} of node {}; stopping".format(page, node_id))
            break
        visited[step] = True

    print("forescout-counteract: imported {} assets from the paginated endpoint over {} request(s)".format(
        reported, requests))
    return reported, ""

def legacy_walk(ctx):
    """Fetch the whole host index and stream it in chunks.

    This is the pre-discovery path, kept for a Web API plugin too old to have
    the paginated endpoint. GET /api/hosts publishes no pagination -- it
    answers with the entire index in one response, which the guide warns may
    be truncated when an internal timeout is exceeded -- so the request cannot
    be split, and every property costs one extra request per host."""
    url = ctx["base_url"] + HOSTS_PATH
    query = []
    if ctx["match_rule_ids"]:
        query.append("matchRuleId=" + ctx["match_rule_ids"])
    if ctx["host_filter"]:
        query.append(ctx["host_filter"])
    if query:
        url += "?" + "&".join(query)

    data, err = api_get(ctx, url, "the host index")
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("forescout-counteract: the Enterprise Manager rejected the Web API user:", err)
        else:
            print("forescout-counteract: failed to fetch the host index:", err)
        return 0

    data = data or {}
    hosts = data.get("hosts", []) if type(data) == "dict" else []
    if type(hosts) != "list":
        hosts = []
    total = len(hosts)
    if not total:
        return 0
    print("forescout-counteract: the host index returned {} hosts".format(total))

    reported = 0
    for start in range(0, total, CHUNK_SIZE):
        reported += report_assets(build_assets(ctx, hosts[start:start + CHUNK_SIZE]))

    print("forescout-counteract: reported {} assets".format(reported))
    if ctx["detail_skipped"]:
        print("forescout-counteract: detail limit of {} reached; classification, services, and software were not imported for {} of {} hosts".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("forescout-counteract: could not determine the Enterprise Manager host from the configured URL")
        return None

    http_options = get_http_options(kwargs, headers={"Accept": "application/hal+json"})
    # The JWT is installed on the collected headers dict in place, so every
    # later request picks up the current token without rebuilding the option
    # set. The dict has to be the one get_http_options returned, because that is
    # the one carrying the configured User-Agent.
    headers = http_options.get("headers", {})

    # The CONFIG defaults are not applied on the script --kwargs path, so every
    # default is repeated here or the integration behaves differently when it
    # is driven from the command line.
    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < MIN_PAGE_SIZE:
        page_size = MIN_PAGE_SIZE
    elif page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    # sinceTime is a UNIX timestamp, which is not a thing an operator wants to
    # type, so the parameter is a window in days and the epoch is computed
    # from it. 0 means the whole estate, which is also the Web API's own
    # default, and the parameter is then left off the request entirely.
    since_days = get_int(kwargs, "since_days", default=0)
    since_time = 0
    if since_days > 0:
        since_time = now().unix - (since_days * SECONDS_PER_DAY)
        if since_time < 0:
            since_time = 0

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "username": get_string(kwargs, "username"),
        "password": get_string(kwargs, "password"),
        "headers": headers,
        "http_options": http_options,
        "match_rule_ids": get_string(kwargs, "match_rule_ids", default="").strip(),
        "host_filter": get_string(kwargs, "host_filter", default="").strip(),
        "include_details": get_bool(kwargs, "include_details", default=True),
        "detail_limit": detail_limit,
        "page_size": page_size,
        "since_time": since_time,
        "detail_used": 0,
        "detail_skipped": 0,
        "skipped_no_id": 0,
        "cve_suppressed": 0,
        "cve_total": 0,
        "cve_scored": 0,
        "fields": [],
        "software_fields": [],
        "vuln_fields": [],
        "seen": {},
        "token_at": None,
    }

    if not login(ctx):
        return None

    if ctx["include_details"]:
        build_field_list(ctx)

    if ctx["since_time"]:
        print("forescout-counteract: incremental sync, asking for endpoints updated in the last {} day(s)".format(since_days))

    # The paginated endpoint is preferred: it selects properties inline, so it
    # replaces one request per endpoint with one request per page. A plugin
    # predating it answers 404 or 400, and any other failure of the very first
    # request degrades the same way rather than importing nothing.
    reported, degrade = discovery_walk(ctx)
    if degrade:
        print("forescout-counteract: the paginated endpoint is unavailable ({}); falling back to the host index and per-host properties".format(degrade))
        reported = legacy_walk(ctx)

    if ctx["skipped_no_id"]:
        print("forescout-counteract: skipped {} endpoint(s) carrying no usable object id".format(ctx["skipped_no_id"]))
    if ctx["cve_total"]:
        print("forescout-counteract: imported {} CVE finding(s), {} of them carrying a CVSS score".format(
            ctx["cve_total"], ctx["cve_scored"]))
    if ctx["cve_suppressed"]:
        print("forescout-counteract: skipped {} CVE record(s) the deployment has marked suppressed".format(ctx["cve_suppressed"]))
    if not reported:
        print("forescout-counteract: no assets retrieved")
    return None

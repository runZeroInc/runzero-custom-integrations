# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-claroty-xdome",
    "name": "Claroty xDome",
    "type": "inbound",
    "description": "Imports devices and vulnerabilities from Claroty xDome (formerly Medigate).",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # matchBehavior is deliberately absent, so all four dimensions match and
    # break. uid is an opaque per-device UUID that survives rename, readdress,
    # and NIC changes, so id matching needs no relaxing. The break flags stay on
    # because xDome retains historical addressing on the same row, so a record
    # can carry an address that now belongs to another host; refusing that first
    # merge creates a separate asset, which is the recoverable mistake.
    # See README "Asset identity".
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "xDome API URL",
            "type": "url",
            "required": True,
            "default": "https://api.claroty.com",
            "placeholder": "https://api.claroty.com",
            "description": "Regional xDome API host. US is https://api.claroty.com, EU is https://eu.api.claroty.com, and legacy Medigate tenants use https://api.medigate.io. The /api/v1 path is appended automatically.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Token generated for an xDome API user. Sent as an Authorization: Bearer header.",
        },
        {
            "key": "import_vulnerabilities",
            "label": "Import vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch device-vulnerability relations and attach the findings to their devices. This is a second full pagination pass over the tenant, so turn it off to import the inventory alone.",
        },
        {
            "key": "include_retired",
            "label": "Include retired devices",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "xDome returns retired devices by default. Leave this off to filter them out server-side, or the runZero inventory accumulates decommissioned assets forever.",
        },
        {
            "key": "include_irrelevant_vulnerabilities",
            "label": "Include irrelevant vulnerabilities",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import findings xDome marks Irrelevant as well as Confirmed and Potentially Relevant. Irrelevant findings badly inflate CVE counts on OT gear.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 1,
            "max": 5000,
            "description": "Rows per request. The documented maximum is 5000 and the API default is 100.",
        },
        {
            "key": "device_fields",
            "label": "Device fields",
            "type": "string",
            "required": False,
            "description": "Comma-separated override for the device field list requested from /api/v1/devices/. Leave blank for the built-in set. Set it only to work around an HTTP 422, or to add a tenant-specific custom_attribute_* field. uid is always requested.",
        },
        {
            "key": "vulnerability_fields",
            "label": "Vulnerability fields",
            "type": "string",
            "required": False,
            "description": "Comma-separated override for the field list requested from /api/v1/device_vulnerability_relations/. Leave blank for the built-in set. device_uid is always requested.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'ip_address', 'clean_hostnames')
load('http', 'post_json', 'bearer')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool', 'get_list')
load('coerce', 'as_text', 'as_list', 'as_float', 'dedupe')
load('time', 'parse_ts')
load('re', re_match='match')

# Every xDome endpoint is a POST carrying a JSON body. There are no GET routes
# and no query-string parameters, and the trailing slash on a collection path is
# part of the documented path.
DEVICE_PATH = "/api/v1/devices/"
VULNERABILITY_PATH = "/api/v1/device_vulnerability_relations/"

# maximum: 5000 in the request schema, confirmed by four vendor-partner
# connectors. The API's own default is 100, which is why limit is always sent.
MAX_PAGE_SIZE = 5000
DEFAULT_PAGE_SIZE = 5000

MAX_VULNS_PER_ASSET = 99
# The relation endpoint is devices x vulnerabilities, so it is the one response
# set that can grow without bound on a large tenant. The per-device cap bounds
# each bucket but not the device count, and the index is held in Explorer memory
# for the whole device walk, so the walk stops here and says so.
MAX_VULNERABILITY_ROWS = 50000
ATTR_PREFIX = "claroty_xdome"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# Vulnerability.cve is validated against this shape and is NOT upper-cased for
# the script, so a value is folded and checked before it is ever assigned.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# Hostnames that identify nothing. Every device whose name a sensor never
# learned carries the same one, so importing them merges unrelated assets.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none",
                     "null", "-", "n/a", "*"]

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "VERY LOW": 1}
RANK_SCORE = {4: 10.0, 3: 8.0, 2: 5.0, 1: 2.0, 0: 0.0}

# The fields requested from POST /api/v1/devices/.
#
# `fields` is REQUIRED and validated against an enum, so one unsupported name is
# rejected with a 422 that fails the whole request: zero assets, not a missing
# column. Field availability varies by tenant release and licensing, so the list
# is conservative -- every name is in the vendor's per-field table and nothing is
# requested that the script does not map. A tenant that still rejects it can be
# narrowed or extended through the device_fields parameter.
DEVICE_FIELDS = [
    "uid",
    "asset_id",
    "device_name",
    "local_name",
    "windows_last_seen_hostname",
    "dhcp_last_seen_hostname",
    "http_last_seen_hostname",
    "snmp_last_seen_hostname",
    "other_hostnames",
    "domains",
    "ip_list",
    "mac_list",
    "mac_oui_list",
    "ip_assignment_list",
    "number_of_nics",
    "network_list",
    "network_scope_list",
    "vlan_list",
    "vlan_name_list",
    "device_category",
    "device_subcategory",
    "device_type",
    "device_type_family",
    "manufacturer",
    "model",
    "serial_number",
    "hw_version",
    "software_or_firmware_version",
    "endpoint_security_names",
    "management_services",
    "machine_type",
    "os_name",
    "os_version",
    "os_revision",
    "combined_os",
    "os_category",
    "os_subcategory",
    "os_eol_date",
    "site_name",
    "purdue_level",
    "labels",
    "assignees",
    "risk_score",
    "risk_score_points",
    "known_vulnerabilities",
    "insecure_protocols",
    "is_online",
    "retired",
    "retired_since",
    "first_seen_list",
    "last_seen_list",
    # Topology: the per-NIC switch, wireless, and directory columns. The switch
    # and port a device is cabled to is the one fact a network scan cannot
    # recover. These index-align with mac_list and ip_list like every other
    # _list field, so entry i describes the interface built from mac_list[i].
    "switch_ip_list",
    "switch_name_list",
    "switch_port_list",
    "switch_mac_list",
    "switch_location_list",
    "connection_type_list",
    "ssid_list",
    "bssid_list",
    "ap_name_list",
    "ad_distinguished_name",
    "dhcp_fingerprint",
    "last_domain_user",
    "ae_titles",
    "note",
    "internet_communication",
    "last_scan_time",
]

# The relation endpoint exposes the same device columns with a `device` prefix,
# so `uid` is `device_uid` here. The two spellings must never be mixed: each
# endpoint rejects the other's enum values.
VULNERABILITY_FIELDS = [
    "device_uid",
    "device_asset_id",
    "vulnerability_id",
    "vulnerability_name",
    "vulnerability_type",
    "vulnerability_cve_ids",
    "vulnerability_cvss_v2_score",
    "vulnerability_cvss_v3_score",
    "vulnerability_adjusted_vulnerability_score",
    "vulnerability_adjusted_vulnerability_score_level",
    "vulnerability_epss_score",
    "vulnerability_is_known_exploited",
    "vulnerability_exploits_count",
    "vulnerability_relevance",
    "vulnerability_published_date",
    "vulnerability_recommendations",
    "device_vulnerability_detection_date",
    "device_vulnerability_resolution_date",
]

# Hostname sources, best first. device_name is NOT among them: the vendor
# documents it as "the device's IP, hostname, etc.", it is user-editable, and
# both published samples show it holding a bare IP address.
HOSTNAME_FIELDS = [
    "windows_last_seen_hostname",
    "dhcp_last_seen_hostname",
    "http_last_seen_hostname",
    "snmp_last_seen_hostname",
    "local_name",
]

# Device attributes copied verbatim into custom attributes.
DEVICE_ATTR_FIELDS = [
    "asset_id",
    "device_name",
    "device_category",
    "device_subcategory",
    "device_type",
    "device_type_family",
    "site_name",
    "purdue_level",
    "network_list",
    "network_scope_list",
    "vlan_list",
    "vlan_name_list",
    "mac_oui_list",
    "ip_assignment_list",
    "number_of_nics",
    "domains",
    "combined_os",
    "os_category",
    "os_subcategory",
    "os_eol_date",
    "serial_number",
    "hw_version",
    "software_or_firmware_version",
    "endpoint_security_names",
    "management_services",
    "machine_type",
    "is_online",
    "retired",
    "retired_since",
    "risk_score",
    "risk_score_points",
    "known_vulnerabilities",
    "insecure_protocols",
    "assignees",
    "first_seen_list",
    "last_seen_list",
    # The topology group. Kept as attributes rather than mapped onto anything:
    # runZero has no first-class switch-port field, and the per-NIC alignment is
    # only meaningful read next to the interface list, which the attributes
    # preserve in order.
    "switch_ip_list",
    "switch_name_list",
    "switch_port_list",
    "switch_mac_list",
    "switch_location_list",
    "connection_type_list",
    "ssid_list",
    "bssid_list",
    "ap_name_list",
    "ad_distinguished_name",
    "dhcp_fingerprint",
    "last_domain_user",
    "ae_titles",
    "note",
    "internet_communication",
    "last_scan_time",
]

def _hostname(value):
    """Return a value fit to import as a hostname, or "".

    An IP-as-hostname is a merge hazard: the same string lands on whichever
    device holds the address next.
    """
    text = as_text(value).rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text

def _address(value):
    """Return the bare address from an UNANNOTATED ip_list entry, or "".

    An entry may be suffixed by " / (annotation)", where the annotation is a
    child device ID or "(Last Known IP)". Either way the address is NOT this
    device's current one: it is historical, or it belongs to a child device with
    its own row in the same response. Importing it would assert the opposite and
    let two assets from one import claim the same address, so an annotated entry
    yields nothing here and _annotation keeps the raw value for the record.
    """
    text = as_text(value)
    if text.find("/") >= 0:
        return ""
    return text.strip()

def _annotation(value):
    """Return an annotated ip_list entry verbatim, or "" when it is unannotated."""
    text = as_text(value)
    if text.find("/") >= 0:
        return text.strip()
    return ""

def _bound_ts(values, newest):
    """Return the earliest or latest parseable timestamp in a per-NIC list."""
    best = None
    for entry in as_list(values):
        stamp = _seen_ts(entry)
        if stamp == None:
            continue
        if best == None:
            best = stamp
        elif newest and stamp.unix > best.unix:
            best = stamp
        elif not newest and stamp.unix < best.unix:
            best = stamp
    return best

def build_interfaces(device):
    """Zip the per-NIC arrays by index into one interface each.

    Fields ending in `_list` carry one entry per interface at corresponding
    indexes, so ip_list[i] and mac_list[i] are one NIC and a cross-product would
    invent interfaces the device does not have. Equal lengths are never
    promised, so a ragged pair yields an address-only or MAC-only interface
    rather than being dropped.
    """
    macs = as_list(device.get("mac_list"))
    addresses = as_list(device.get("ip_list"))
    netifs = []
    for index in range(max(len(macs), len(addresses))):
        mac = as_text(macs[index]) if index < len(macs) else ""
        found = []
        if index < len(addresses):
            address = _address(addresses[index])
            if address:
                found.append(address)
        # routable_ips drops loopback, unspecified, and link-local values: an
        # APIPA address a device invents when DHCP fails identifies nothing and
        # would correlate unrelated hosts to each other.
        nic = network_interface(mac=mac, ips=routable_ips(found))
        # network_interface returns None when nothing usable survived, and a
        # None in networkInterfaces aborts the whole run.
        if nic:
            netifs.append(nic)
    return netifs

def build_hostnames(device):
    """Collect the protocol-derived hostnames, best first."""
    names = []
    for key in HOSTNAME_FIELDS:
        names.append(_hostname(device.get(key)))
    for entry in as_list(device.get("other_hostnames")):
        names.append(_hostname(entry))
    return clean_hostnames(names)

def build_tags(device):
    """Tag the operational groupings an operator searches by."""
    tags = []
    site = as_text(device.get("site_name"))
    if site:
        tags.append("site:" + site)
    risk = as_text(device.get("risk_score"))
    if risk:
        tags.append("risk:" + risk)
    purdue = as_text(device.get("purdue_level"))
    if purdue:
        tags.append("purdue:" + purdue)
    for label in as_list(device.get("labels")):
        text = as_text(label)
        if text:
            tags.append(text)
    return dedupe(tags)

def _severity(row):
    """Return the (rank, score) pair for one relation row.

    xDome publishes a CVSS base score and, separately, its own adjusted score
    level. The CVSS score is the comparable number, so it drives the score; the
    adjusted level drives the rank, and each falls back to the other.
    """
    level = as_text(row.get("vulnerability_adjusted_vulnerability_score_level")).upper()
    rank = SEVERITY_RANK.get(level, 0)

    score = as_float(row.get("vulnerability_cvss_v3_score"))
    if score <= 0.0:
        score = as_float(row.get("vulnerability_cvss_v2_score"))
    if score <= 0.0:
        return rank, RANK_SCORE.get(rank, 0.0)

    if rank == 0:
        rank = 1
        if score >= 9.0:
            rank = 4
        elif score >= 7.0:
            rank = 3
        elif score >= 4.0:
            rank = 2
    return rank, score

def build_vulnerability(row, vuln_id, cve, claroty_id, name):
    """Convert one (device, CVE) pair into a runZero Vulnerability."""
    rank, score = _severity(row)

    params = {
        "id": vuln_id[:255],
        "name": name or claroty_id,
        "severityRank": rank,
        "severityScore": float(score),
        "riskRank": rank,
        "riskScore": float(score),
        "customAttributes": to_custom_attributes({
            "vulnerability_id": claroty_id,
            "vulnerability_name": name,
            "vulnerability_type": row.get("vulnerability_type"),
            "vulnerability_relevance": row.get("vulnerability_relevance"),
            "vulnerability_cve_ids": row.get("vulnerability_cve_ids"),
            "vulnerability_cvss_v2_score": row.get("vulnerability_cvss_v2_score"),
            "vulnerability_cvss_v3_score": row.get("vulnerability_cvss_v3_score"),
            "vulnerability_adjusted_score": row.get("vulnerability_adjusted_vulnerability_score"),
            "vulnerability_adjusted_score_level": row.get("vulnerability_adjusted_vulnerability_score_level"),
            "vulnerability_epss_score": row.get("vulnerability_epss_score"),
            "vulnerability_exploits_count": row.get("vulnerability_exploits_count"),
            "vulnerability_resolution_date": row.get("device_vulnerability_resolution_date"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    if cve:
        params["cve"] = cve
    if row.get("vulnerability_is_known_exploited") == True:
        params["exploitable"] = True

    recommendation = as_text(row.get("vulnerability_recommendations"))
    if recommendation:
        params["solution"] = recommendation[:1024]

    published = parse_ts(row.get("vulnerability_published_date"))
    if published:
        params["publishedTS"] = published
    detected = parse_ts(row.get("device_vulnerability_detection_date"))
    if detected:
        params["firstDetectedTS"] = detected

    return Vulnerability(**params)

def build_vulnerabilities(rows):
    """Convert every relation row for one device into Vulnerability objects.

    One Claroty vulnerability_id can carry many CVEs, so a row fans out to one
    finding per CVE rather than collapsing into a record that names only the
    advisory. A row with no usable CVE still produces one finding under
    Claroty's own id, so an advisory tracked outside the CVE system is kept.
    """
    vulns = []
    seen = {}
    for row in rows:
        claroty_id = as_text(row.get("vulnerability_id"))
        name = as_text(row.get("vulnerability_name"))
        if not claroty_id and not name:
            continue

        cves = []
        for entry in as_list(row.get("vulnerability_cve_ids")):
            cve = as_text(entry).upper()
            if re_match(CVE_PATTERN, cve):
                cves.append(cve)
        cves = dedupe(cves)

        for cve in (cves or [""]):
            vuln_id = claroty_id or name
            if cve:
                vuln_id = "{}:{}".format(vuln_id, cve)
            if vuln_id in seen:
                continue
            seen[vuln_id] = True
            vulns.append(build_vulnerability(row, vuln_id, cve, claroty_id, name))
            if len(vulns) >= MAX_VULNS_PER_ASSET:
                return vulns
    return vulns

def _seen_ts(value):
    """Parse a vendor timestamp, rejecting the "never" sentinels.

    parse_ts does NOT return None for every empty-ish value: Go's zero time
    parses to unix=-62135596800 and 1970-01-01 to unix=0. Both survive a
    `!= None` check, so an unguarded parse stamps a never-seen asset with an
    ancient date instead of leaving it unknown.
    """
    ts = parse_ts(value)
    if ts == None or ts.unix <= 0:
        return None
    return ts

def build_asset(device, vulns):
    """Convert one xDome device row into a runZero ImportAsset."""
    uid = as_text(device.get("uid"))
    if not uid:
        return None

    attrs = {}
    for key in DEVICE_ATTR_FIELDS:
        attrs[key] = device.get(key)
    if vulns:
        attrs["vulnerability_count"] = len(vulns)
    # Annotated ip_list entries are deliberately not imported as addresses --
    # they are historical or belong to a child device -- but the operator still
    # wants to see them, so they are kept verbatim here.
    annotated = []
    for entry in as_list(device.get("ip_list")):
        found = _annotation(entry)
        if found:
            annotated.append(found)
    if annotated:
        attrs["ip_list_annotated"] = annotated

    params = {
        # uid is a per-device UUID, so the slug alone is scope enough. The API
        # host would be misleading: api.claroty.com is shared by every US tenant
        # and so distinguishes nothing.
        "id": "claroty-xdome:" + uid,
        "hostnames": build_hostnames(device),
        "networkInterfaces": build_interfaces(device),
        "tags": build_tags(device),
        "vulnerabilities": vulns[:MAX_VULNS_PER_ASSET],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    domains = dedupe([as_text(entry) for entry in as_list(device.get("domains"))])
    if domains:
        params["domain"] = domains[0]

    os_name = as_text(device.get("os_name"))
    os_version = as_text(device.get("os_version"))
    revision = as_text(device.get("os_revision"))
    if revision:
        os_version = (os_version + " " + revision).strip()
    if not os_name:
        # combined_os aggregates name, version and revision into one string and
        # is the only OS value some rows carry.
        os_name = as_text(device.get("combined_os"))
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version

    manufacturer = as_text(device.get("manufacturer"))
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = as_text(device.get("model"))
    if model:
        params["model"] = model

    # device_type is the specific classification ("SCADA Server", "Patient
    # Monitor"); the two category fields are the coarse fallbacks.
    device_type = as_text(device.get("device_type"))
    if not device_type:
        device_type = as_text(device.get("device_subcategory"))
    if not device_type:
        device_type = as_text(device.get("device_category"))
    if device_type:
        params["deviceType"] = device_type

    first_seen = _bound_ts(device.get("first_seen_list"), False)
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = _bound_ts(device.get("last_seen_list"), True)
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def _device_filter(include_retired):
    """Exclude retired devices unless the operator asked for them.

    The operation is `in` over a single-element array rather than `equals` over
    a scalar: both are listed for `retired`, but only `in` is in the spec's
    conventions table and it is what the vendor's own client sends. A rejected
    filter is a failed request, not a degraded import, so the run would end with
    zero assets.
    """
    if include_retired:
        return None
    return {"field": "retired", "operation": "in", "value": [False]}

def _vulnerability_filter(include_retired, include_irrelevant):
    """Constrain the relation walk the way the vendor's own clients do."""
    operands = []
    if not include_retired:
        operands.append({"field": "device_retired", "operation": "in", "value": [False]})
    if not include_irrelevant:
        operands.append({
            "field": "vulnerability_relevance",
            "operation": "in",
            "value": ["Confirmed", "Potentially Relevant"],
        })
    if not operands:
        return None
    if len(operands) == 1:
        return operands[0]
    return {"operation": "and", "operands": operands}

def _page_body(fields, offset, limit, sort_fields, filter_by):
    """Build one request body.

    Offset pagination over a live table can skip or duplicate rows when the
    server's ordering is not deterministic, so the sort is sent explicitly on
    a unique key rather than left to the endpoint default.
    """
    body = {
        "fields": fields,
        "offset": offset,
        "limit": limit,
        "sort_by": [{"field": name, "order": "asc"} for name in sort_fields],
    }
    if filter_by:
        body["filter_by"] = filter_by
    return body

def fetch_page(ctx, path, body, label, tunable):
    """POST one page, translating the two failures an operator can act on.

    A 422 is the failure mode that matters here. `fields` is enum-validated, so
    one name this tenant's API version does not know rejects the entire request
    and the import ends with zero assets rather than one missing column. The
    response body is not echoed: it is a FastAPI validation dump that can carry
    the whole request back.
    """
    data, err = post_json(ctx["base_url"] + path, json=body, **ctx["http_options"])
    if not err:
        return data, None

    if err.startswith("status 422"):
        print(("claroty-xdome: {} rejected the request with HTTP 422. The likely cause is a" +
               " requested field this tenant's API version does not support; set the {}" +
               " parameter to a narrower list and retry.").format(label, tunable))
        return None, "field list rejected"
    if err.startswith("status 401") or err.startswith("status 403"):
        print("claroty-xdome: the API rejected the token. xDome tokens expire on the date" +
              " chosen when they were generated and cannot be refreshed, so generate a new" +
              " one and confirm the API user still holds the Read-Only role and its site" +
              " permissions.")
        return None, "token rejected"
    return None, err

def _rows(data, key, label):
    """Return the row array from a response envelope, or None to stop.

    A real tenant answers an exhausted page with `"devices": null` rather than
    an empty array, which the response schema does not allow for, so null is
    treated as end-of-data and anything else unexpected ends the walk cleanly.
    """
    raw = (data or {}).get(key)
    if raw == None:
        return []
    if type(raw) != "list":
        print("claroty-xdome: unexpected {} payload, ending the {} walk".format(key, label))
        return None
    return raw

def fetch_vulnerability_index(ctx):
    """Index relation rows by device_uid so each device's findings are ready
    before its inventory page is built."""
    index = {}
    rows_seen = 0
    offset = 0
    filter_by = _vulnerability_filter(ctx["include_retired"], ctx["include_irrelevant"])

    p = pager("vulnerabilities")
    while p.next():
        body = _page_body(ctx["vulnerability_fields"], offset, ctx["page_size"],
                          ["device_uid", "vulnerability_id"], filter_by)
        data, err = fetch_page(ctx, VULNERABILITY_PATH, body,
                               "device_vulnerability_relations", "vulnerability_fields")
        if err:
            print("claroty-xdome: failed to fetch device-vulnerability relations:", err)
            return index

        rows = _rows(data, "devices_vulnerabilities", "vulnerability")
        if rows == None:
            return index
        if not rows:
            break

        for row in rows:
            if type(row) != "dict":
                continue
            device_uid = as_text(row.get("device_uid"))
            if not device_uid:
                continue
            kept = index.setdefault(device_uid, [])
            # One row can still fan out to several CVEs, so this bound is on
            # memory rather than on the child cap the asset applies later.
            if len(kept) >= MAX_VULNS_PER_ASSET:
                continue
            kept.append(row)
            rows_seen += 1

        if rows_seen >= MAX_VULNERABILITY_ROWS:
            print("claroty-xdome: stopping the vulnerability walk at {} indexed relations".format(
                rows_seen))
            break
        if len(rows) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    print("claroty-xdome: indexed {} vulnerability relations across {} devices".format(
        rows_seen, len(index)))
    return index

def fetch_and_report_devices(ctx, vuln_index):
    """Page the inventory, streaming each asset so the whole tenant is never
    held in memory at once."""
    reported = 0
    skipped = 0
    offset = 0
    filter_by = _device_filter(ctx["include_retired"])

    p = pager("devices")
    while p.next():
        body = _page_body(ctx["device_fields"], offset, ctx["page_size"], ["uid"], filter_by)
        data, err = fetch_page(ctx, DEVICE_PATH, body, "devices", "device_fields")
        if err:
            print("claroty-xdome: failed to fetch devices:", err)
            return reported, skipped

        devices = _rows(data, "devices", "device")
        if devices == None:
            return reported, skipped
        if not devices:
            break

        for device in devices:
            if type(device) != "dict":
                skipped += 1
                continue
            uid = as_text(device.get("uid"))
            rows = vuln_index.pop(uid, []) if uid else []
            asset = build_asset(device, build_vulnerabilities(rows))
            if not asset:
                skipped += 1
                continue
            reported += report_asset(asset)

        # The documented termination rule is "until less than `limit` results
        # are returned", not until an empty page arrives.
        if len(devices) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    return reported, skipped

def main(**kwargs):
    require(kwargs, "api_token")
    base_url = get_url_base(kwargs)
    token = get_string(kwargs, "api_token")

    # CONFIG defaults are not applied on the `script --kwargs` path, so every
    # default is repeated here.
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    include_retired = get_bool(kwargs, "include_retired", default=False)
    include_irrelevant = get_bool(kwargs, "include_irrelevant_vulnerabilities", default=False)
    import_vulnerabilities = get_bool(kwargs, "import_vulnerabilities", default=True)

    # A response carries only the fields the request asked for, so uid and
    # device_uid are forced into an operator's override: without them no record
    # has an identity and the whole run would be skipped.
    device_fields = get_list(kwargs, "device_fields", default=[]) or DEVICE_FIELDS
    if "uid" not in device_fields:
        device_fields = ["uid"] + device_fields
    vulnerability_fields = get_list(kwargs, "vulnerability_fields", default=[]) or VULNERABILITY_FIELDS
    if "device_uid" not in vulnerability_fields:
        vulnerability_fields = ["device_uid"] + vulnerability_fields

    ctx = {
        "base_url": base_url,
        "page_size": page_size,
        "include_retired": include_retired,
        "include_irrelevant": include_irrelevant,
        "device_fields": device_fields,
        "vulnerability_fields": vulnerability_fields,
        # get_http_options already carries the header map, so headers are built
        # into it rather than passed alongside the request.
        "http_options": get_http_options(kwargs, headers={
            "Authorization": bearer(token),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }),
    }

    vuln_index = {}
    if import_vulnerabilities:
        vuln_index = fetch_vulnerability_index(ctx)

    reported, skipped = fetch_and_report_devices(ctx, vuln_index)
    if skipped:
        print("claroty-xdome: skipped {} device records with no uid".format(skipped))
    # Relations whose device never appeared in the inventory are dropped rather
    # than turned into assets: the relation endpoint is a different grain, and
    # building inventory from it would resurrect the retired devices the device
    # filter just excluded.
    if vuln_index:
        print("claroty-xdome: dropped findings for {} devices absent from the inventory".format(
            len(vuln_index)))
    if not reported:
        print("claroty-xdome: no assets retrieved")
    else:
        print("claroty-xdome: reported {} devices".format(reported))
    return None

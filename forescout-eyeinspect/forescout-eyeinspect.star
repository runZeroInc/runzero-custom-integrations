# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-forescout-eyeinspect",
    "name": "Forescout eyeInspect",
    "type": "inbound",
    "description": "Imports OT hosts, open port services, and alert findings from Forescout eyeInspect.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # main_name is inferred from protocol traffic and churns as eyeInspect
    # re-observes a host, so name-break is relaxed. mac-break and ip-break stay
    # ON: ip_reuse_domain_id lets one address belong to several hosts, and a
    # host behind a router or serial gateway presents the gateway's MAC, so
    # those breaks are the only thing separating such devices before the host
    # id has matched. See README "Asset identity".
    "matchBehavior": "no-name-break",
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "eyeInspect Command Center URL",
            "type": "url",
            "required": True,
            "placeholder": "https://eyeinspect.example.com",
            "description": "Base URL of the eyeInspect Command Center. The /api/v1/ path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Command Center user with read access to the hosts, alerts, and CVE APIs.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the Command Center user.",
        },
        {
            "key": "last_seen_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import hosts last seen within this many days. 0 imports every host.",
        },
        {
            "key": "full_host_details",
            "label": "Request full host records",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Send full=true on the hosts request, which returns the Full-only host properties (installed software, patches, open ports, CVE matches, role, purdue level, criticality, vendor model, firmware version, risk scores). Turn off if an older Command Center rejects the parameter.",
        },
        {
            "key": "include_alerts",
            "label": "Import alerts as vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Attach eyeInspect alerts to their host as findings. Costs one alerts request per host, with no way to skip a host that has none.",
        },
        {
            "key": "include_cve_details",
            "label": "Enrich CVEs from eyeInspect",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Look up CVE detail for every CVE referenced by a host or alert. Host CVEs are looked up in bulk, one request per page; anything else costs one request per distinct CVE.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'ServiceProtocolData', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'clean_hostname')
load('http', 'get_json', 'post_json', 'basic', 'url_parse')
load('json', json_encode='encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_duration', 'parse_ts')
load('re', re_find_all='find_all')

load('coerce', 'as_text', 'dicts', 'dedupe')
VENDOR = "forescout-eyeinspect"
ATTR_PREFIX = "forescout_eyeinspect"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
API_PATH = "/api/v1/"
# The guide documents limit as a default of 100 and states no maximum. 100 is
# kept anyway: the walk stops on a page shorter than the requested limit, so a
# Command Center that silently capped a larger request would end the walk on
# its first page.
PAGE_SIZE = 100
ALERT_LIMIT = 100        # alerts attached per host, same documented default
# POST /cve_info/list documents "The size of the given list is limited to 1000
# by default", so a page's lookups are chunked at that size.
CVE_BULK_LIMIT = 1000
HTTP_RETRIES = 3
MAX_INTERFACES = 32
MAX_CHILDREN = 99
DEFAULT_TRANSPORT = "tcp"
LOOPBACK = "127.0.0.1"
DIGITS = "0123456789"
TRANSPORTS = ["tcp", "udp", "sctp"]
CVE_PATTERN = r"CVE-[0-9]{4}-[0-9]{4,7}"
# purdue_level is a string enum, not a number. UNDEFINED means "not set" and is
# deliberately not turned into a tag.
PURDUE_LEVELS = ["LEVEL0", "LEVEL1", "LEVEL2", "LEVEL3", "LEVEL35", "LEVEL4", "LEVEL5"]
# criticality is an integer in [0-5], not a word like "high".
MAX_CRITICALITY = 5
# eyeInspect alert severity is a 0-5 scale; runZero ranks are 0-4.
ALERT_SEVERITY_RANK = {"0": 0, "1": 0, "2": 1, "3": 2, "4": 3, "5": 4}
RANK_SCORE = {0: 0.0, 1: 2.5, 2: 5.0, 3: 7.5, 4: 10.0}
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
def _first(record, keys):
    """First populated value among alternate vendor spellings of one property.

    The eyeInspect API Guide's sort_field vocabulary and its Host record
    vocabulary are not the same list: sorting on `name` returns `main_name`,
    and the same holds for role and vendor_model. The plain spellings are kept
    as fallbacks so a Command Center that does publish them still maps.
    """
    for key in keys:
        value = record.get(key)
        if value != None and value != "":
            return value
    return None

def _results(data):
    """Unwrap the {total_count, results} envelope returned by the list endpoints."""
    if type(data) == "list":
        return data
    if type(data) == "dict":
        results = data.get("results", [])
        if type(results) == "list":
            return results
    return []

def _list(value):
    """Coerce a field documented as a list into one, so a scalar cannot abort the
    run. A comma-separated string is split, since eyeInspect types several of
    these list fields as strings."""
    if value == None:
        return []
    if type(value) == "list":
        return value
    if type(value) == "string" and "," in value:
        return [item.strip() for item in value.split(",")]
    return [value]
def _extract_cves(value):
    """Pull CVE identifiers out of an arbitrary value. eyeInspect does not publish
    a CVE field on alerts, so alert text and the host complex_cves field are
    scanned instead."""
    if value == None:
        return []
    if type(value) == "string":
        text = value
    else:
        text = json_encode(value)
    return dedupe(re_find_all(CVE_PATTERN, text.upper()))

def _parse_open_port(entry):
    """Extract (port, transport, app) from one open_ports entry.

    OpenPortsInfo is {port, l4_protocol, app}, all typed as strings, where app is
    "The service/application running on the port. Example: HTTP". Transport is an
    empty string when the entry does not name one, and app is empty for every
    shape that is not the documented object.
    """
    if type(entry) == "dict":
        port = _to_int(entry.get("port", entry.get("number", -1)))
        transport = ""
        for key in ("l4_protocol", "transport", "protocol", "proto", "l4_proto"):
            named = entry.get(key)
            if named:
                transport = str(named).strip().lower()
                break
        if transport not in TRANSPORTS:
            transport = ""
        return port, transport, as_text(entry.get("app"), join=",").strip()

    if type(entry) == "int":
        return entry, "", ""

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
    return port, transport, ""

def fetch_cve_detail(ctx, lookup_id):
    """Look up one vulnerability record in the eyeInspect CVE database, caching
    every lookup so an advisory seen on many hosts costs a single request.

    The path parameter is the CVEInfo `id`, which for an NVD-sourced record is
    the CVE id itself and for an ICS-CERT or vendor advisory is that repository's
    own identifier.
    """
    cache = ctx["cve_cache"]
    if lookup_id in cache:
        return cache[lookup_id]
    url = ctx["base_url"] + API_PATH + "cve_info/" + lookup_id
    data, err = get_json(url, **ctx["http_options"])
    if err:
        print("forescout-eyeinspect: failed to fetch CVE {}: {}".format(lookup_id, err))
        cache[lookup_id] = {}
        return cache[lookup_id]
    if type(data) != "dict":
        data = {}
    cache[lookup_id] = data
    return data

def warm_cve_cache(ctx, hosts):
    """Pre-load the CVE cache for one page of hosts with a single bulk request.

    POST /cve_info/list takes up to 1000 ids per call and returns the same
    CVEInfo records as the per-id GET, collapsing the N+1 include_cve_details
    otherwise costs. The guide lists X-CSRF-Token among its required headers
    and that nonce needs a cookie session the JSON helpers do not expose, so
    the call is attempted and a rejection turns bulk off for the rest of the
    run. Only host CVEs are pre-loaded; an alert's are not known until its
    alerts request has been made and fall through to the cached GET.
    """
    if not ctx["include_cve_details"] or not ctx["cve_bulk"]:
        return

    wanted = []
    for host in hosts:
        for entry in _host_cves(host):
            key = entry["key"]
            if key and key not in ctx["cve_cache"] and key not in wanted:
                wanted.append(key)
    if not wanted:
        return

    url = ctx["base_url"] + API_PATH + "cve_info/list"
    options = dict(ctx["http_options"])
    headers = dict(options.get("headers", {}))
    headers["Content-Type"] = "application/json"
    options["headers"] = headers

    for start in range(0, len(wanted), CVE_BULK_LIMIT):
        chunk = wanted[start:start + CVE_BULK_LIMIT]
        data, err = post_json(url, body=bytes(json_encode(chunk)), **options)
        if err:
            print("forescout-eyeinspect: bulk CVE lookup unavailable, falling back to per-CVE lookups:", err)
            ctx["cve_bulk"] = False
            return
        for record in dicts(_results(data or [])):
            for key in (as_text(record.get("id"), join=","), as_text(record.get("cve_id"), join=",")):
                if key:
                    ctx["cve_cache"][key] = record
        # An id the Command Center does not know is simply absent from the
        # response. Recording it as a miss stops the GET fallback from asking
        # again for something the bulk call already answered.
        for key in chunk:
            if key not in ctx["cve_cache"]:
                ctx["cve_cache"][key] = {}

def fetch_host_alerts(ctx, host_id):
    """Fetch one page of alerts for a single host. The Command Center resolves
    host_id against both the IP and the MAC addresses of the host, which is more
    precise than correlating alert src_ip/dst_ip locally."""
    url = ctx["base_url"] + API_PATH + "alerts"
    params = {"host_id": str(host_id), "offset": "0", "limit": str(ALERT_LIMIT)}
    data, err = get_json(url, params=params, **ctx["http_options"])
    if err:
        print("forescout-eyeinspect: failed to fetch alerts for host {}: {}".format(host_id, err))
        return []
    return _results(data or {})

def apply_cve_detail(ctx, params, attrs, lookup_id, rank_from_cvss):
    """Fold an eyeInspect cve_info record into a Vulnerability. The CVSS scores
    only drive the rank for findings that have no severity of their own; an alert
    keeps the severity the sensor assigned it."""
    if not ctx["include_cve_details"]:
        return

    detail = fetch_cve_detail(ctx, lookup_id)
    if not detail:
        return

    title = as_text(detail.get("title"), join=",")
    if title and rank_from_cvss:
        params["name"] = title[:255]
    summary = as_text(detail.get("summary"), join=",")
    if summary and not params.get("description"):
        params["description"] = summary[:1024]
    solution = as_text(detail.get("solution"), join=",")
    if solution:
        params["solution"] = solution[:1024]

    version = as_text(detail.get("cvss_version"), join=",").upper()
    score = detail.get("cvss_score")
    if type(score) in ("int", "float") and score > 0:
        if version.endswith("2"):
            params["cvss2BaseScore"] = float(score)
        else:
            params["cvss3BaseScore"] = float(score)
        if rank_from_cvss:
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

    temporal = detail.get("cvss_temporal_score")
    if type(temporal) in ("int", "float") and temporal > 0:
        if version.endswith("2"):
            params["cvss2TemporalScore"] = float(temporal)
        else:
            params["cvss3TemporalScore"] = float(temporal)

    published = parse_ts(detail.get("published_date"))
    if published:
        params["publishedTS"] = published

    attrs["cve_vendor"] = detail.get("vendor")
    attrs["cve_icsa_id"] = detail.get("icsa_id")
    attrs["cve_vendor_specific_id"] = detail.get("vendor_specific_id")
    attrs["cve_remediation_level"] = detail.get("cvss_remediation_level")

def build_cve_vulnerability(ctx, vuln_id, cve_id, lookup_id, category, base_attrs):
    """Build a CVE-backed Vulnerability, enriched from cve_info when enabled.

    `cve_id` is the NVD identifier the finding reports; `lookup_id` is the
    CVEInfo record id the enrichment is fetched under, which differs whenever
    the match came from an ICS-CERT or vendor advisory.
    """
    params = {
        "id": vuln_id,
        "name": cve_id,
        "cve": cve_id,
        "category": category,
    }
    attrs = dict(base_attrs)
    apply_cve_detail(ctx, params, attrs, lookup_id, True)
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return Vulnerability(**params)

def build_alert_vulnerability(ctx, host_ip, alert):
    """Convert one eyeInspect alert into a Vulnerability on its host."""
    alert_id = alert.get("alert_id")
    if alert_id == None:
        return None

    names = alert.get("event_type_names", []) or []
    name = as_text(names, join=",") or as_text(alert.get("event_type_ids"), join=",") or "eyeInspect alert {}".format(alert_id)
    rank = ALERT_SEVERITY_RANK.get(str(alert.get("severity", "")).strip(), 0)

    params = {
        "id": "{}:{}:alert:{}".format(VENDOR, ctx["scope"], alert_id),
        "name": name[:255],
        "category": as_text(alert.get("engine"), join=",") or "eyeInspect alert",
        "description": as_text(alert.get("description"), join=",")[:1024],
        "severityRank": rank,
        "severityScore": RANK_SCORE[rank],
        "riskRank": rank,
        "riskScore": RANK_SCORE[rank],
    }

    detected = parse_ts(alert.get("timestamp"))
    if detected:
        params["firstDetectedTS"] = detected
        params["lastDetectedTS"] = detected

    # Only bind the finding to a port when the alert names this host as the
    # destination of the traffic that produced it.
    dst_port = _to_int(alert.get("dst_port", -1))
    transport = as_text(alert.get("l4_proto"), join=",").lower()
    if host_ip and as_text(alert.get("dst_ip"), join=",") == host_ip and dst_port > 0 and transport in TRANSPORTS:
        params["serviceAddress"] = host_ip
        params["servicePort"] = int(dst_port)
        params["serviceTransport"] = transport

    cves = _extract_cves(" ".join([
        as_text(alert.get("event_type_ids"), join=","),
        as_text(alert.get("event_type_names"), join=","),
        as_text(alert.get("description"), join=","),
        as_text(alert.get("notes"), join=","),
    ]))
    attrs = {
        "alert_id": alert_id,
        "alert_status": alert.get("status"),
        "alert_severity": alert.get("severity"),
        "alert_timestamp": alert.get("timestamp"),
        "alert_engine": alert.get("engine"),
        "alert_profile_module": alert.get("profile_module_name"),
        "alert_sensor_id": alert.get("sensor_id"),
        "alert_sensor_name": alert.get("sensor_name"),
        "alert_event_type_ids": alert.get("event_type_ids"),
        "alert_l4_proto": alert.get("l4_proto"),
        "alert_l7_proto": alert.get("l7_proto"),
        "alert_src_ip": alert.get("src_ip"),
        "alert_dst_ip": alert.get("dst_ip"),
        "alert_cves": cves,
    }

    if cves:
        params["cve"] = cves[0]
        apply_cve_detail(ctx, params, attrs, cves[0], False)

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return Vulnerability(**params)

def build_vulnerabilities(ctx, host, host_ip, alerts):
    """Build the findings for one host: every alert the Command Center ties to it,
    plus any CVE the host record itself carries."""
    vulns = []

    for alert in alerts:
        if type(alert) != "dict":
            continue
        vuln = build_alert_vulnerability(ctx, host_ip, alert)
        if vuln:
            vulns.append(vuln)

    host_id = host.get("id")
    for entry in _host_cves(host):
        vulns.append(build_cve_vulnerability(
            ctx,
            "{}:{}:host:{}:cve:{}".format(VENDOR, ctx["scope"], host_id, entry["cve"]),
            entry["cve"],
            entry["key"],
            "CVE",
            {
                "host_id": host_id,
                "cve_source": entry["source"],
                "cve_record_id": entry["key"],
                "cve_matching_confidence": entry.get("matching_confidence"),
                "cve_icsa_id": entry.get("icsa_id"),
                "cve_vendor_specific_id": entry.get("vendor_specific_id"),
            },
        ))

    return vulns

def _host_cves(host):
    """Host CVE matches, as {cve, key, source, ...} records.

    The response property is `cves`, a HostCVEInfo array; the comma-joined
    `complex_cves` belongs to the sort_field vocabulary and is a fallback only.
    A suppressed match is an operator dismissal and must not become a finding;
    an ICS-CERT-only advisory carries an empty cve_id. `cve` is the NVD
    identifier the finding reports, while `key` is HostCVEInfo.id, what the CVE
    database is keyed on: a vendor advisory carries that repository's id
    instead, and looking it up by CVE id would miss it.
    """
    out = []
    seen = {}
    for entry in _list(host.get("cves")):
        if type(entry) != "dict":
            continue
        if entry.get("suppressed") == True:
            continue
        cve_id = as_text(entry.get("cve_id"), join=",").strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen[cve_id] = True
        out.append({
            "cve": cve_id,
            "key": as_text(entry.get("id"), join=",").strip() or cve_id,
            "source": "cves",
            "matching_confidence": entry.get("matching_confidence"),
            "icsa_id": entry.get("icsa_id"),
            "vendor_specific_id": entry.get("vendor_specific_id"),
        })
    for cve_id in _extract_cves(host.get("complex_cves")):
        if cve_id in seen:
            continue
        seen[cve_id] = True
        out.append({"cve": cve_id, "key": cve_id, "source": "complex_cves"})
    return out

def _software_row(ctx, host_id, address, kind, suffix, params, attrs):
    """Assemble one Software record.

    Software REQUIRES an id -- omitting it fails validation for the whole run,
    not just the row -- and the product name field is `product`, never `name`.
    Both are easy to get wrong because SoftwareInfo itself calls the product
    `name`.
    """
    attrs["software_kind"] = kind
    params["id"] = "{}:{}:host:{}:{}".format(VENDOR, ctx["scope"], host_id, suffix)[:255]
    params["serviceAddress"] = address
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return Software(**params)

def build_software(ctx, host, host_ip):
    """Build the Software rows for one host: installed applications, OS patches,
    and a firmware row for embedded devices.

    `software` (SoftwareInfo[]) and `patches` (PatchesInfo[]) are Full-only Host
    properties, so without full=true this returns the firmware row alone, or
    nothing. Both are documented non-nullable, so an unknown value is an empty
    string rather than null.
    """
    rows = []
    seen = {}
    host_id = host.get("id")
    address = host_ip or LOOPBACK
    source = as_text(host.get("software_source"), join=",").strip().upper()

    for entry in dicts(host.get("software")):
        product = as_text(entry.get("name"), join=",").strip()
        if not product:
            continue
        version = as_text(entry.get("version"), join=",").strip()
        label = (product + "@" + version).lower()
        if label in seen:
            continue
        seen[label] = True
        params = {"product": product[:255]}
        vendor = as_text(entry.get("vendor"), join=",").strip()
        if vendor:
            params["vendor"] = vendor[:255]
        if version:
            params["version"] = version[:255]
        rows.append(_software_row(ctx, host_id, address, "software", "software:" + label, params, {
            "software_install_date": entry.get("install_date"),
            # software_source is how eyeInspect learned of the software
            # (PASSIVE, ACTIVE_WMI, EDITED...), not where it was installed from,
            # so it stays an attribute rather than becoming installedFrom.
            "software_source": source,
        }))

    for entry in dicts(host.get("patches")):
        hot_fix = as_text(entry.get("hot_fix_id"), join=",").strip()
        if not hot_fix:
            continue
        label = hot_fix.lower()
        if label in seen:
            continue
        seen[label] = True
        rows.append(_software_row(ctx, host_id, address, "patch", "patch:" + label, {
            "product": hot_fix[:255],
        }, {
            "patch_installed_by": entry.get("installed_by"),
            "patch_install_date": entry.get("install_date"),
            "patch_service_pack": entry.get("service_pack"),
        }))

    # The firmware row is synthetic: eyeInspect reports firmware and vendor/model
    # as host properties rather than as a software entry, and an embedded device
    # has no installed-application list at all.
    vendor_model = as_text(_first(host, ["main_vendor_model", "vendor_model"]), join=",").strip()
    firmware = as_text(host.get("firmware_version"), join=",").strip()
    if vendor_model or firmware:
        params = {"product": (vendor_model or "Firmware")[:255]}
        if firmware:
            params["version"] = firmware[:255]
        rows.append(_software_row(ctx, host_id, address, "firmware", "firmware", params, {
            "hardware_version": host.get("hardware_version"),
            "serial_number": host.get("serial_number"),
            "project": host.get("project"),
        }))

    return rows

def build_services(host_ip, open_ports):
    """Build Service objects from the host open_ports list.

    The documented element is an OpenPortsInfo object, {port, l4_protocol, app}.
    Older Command Centers hand back bare port strings instead, so ints, "443",
    "502/tcp" and {port, protocol} dicts are accepted as well. An entry naming
    no transport is recorded as tcp and flagged. `app` ("HTTP", "MODBUS")
    becomes the service's protocol name.
    """
    if not host_ip or type(open_ports) != "list":
        return []

    services = []
    seen = []
    for entry in open_ports:
        port, transport, app = _parse_open_port(entry)
        if port < 1 or port > 65535:
            continue
        assumed = transport == ""
        if assumed:
            transport = DEFAULT_TRANSPORT
        key = "{}/{}".format(port, transport)
        if key in seen:
            continue
        seen.append(key)
        params = {
            "address": host_ip,
            "port": int(port),
            "transport": transport,
            "customAttributes": to_custom_attributes({
                "service_source": "open_ports",
                "transport_source": "assumed" if assumed else "reported",
                "app": app,
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        if app:
            params["protocolData"] = [ServiceProtocolData(name=app.lower()[:128])]
        services.append(Service(**params))
    return services

def _host_macs(host):
    """Every MAC on a host record, flattened to strings.

    `mac_addresses` is a plain string[], but the host-owned set is a
    HostMacAddress[] of {mac_address, last_seen} objects, spelled
    `host_mac_address` on Host and `host_mac_addresses` on AssetBaselineHost.
    Both spellings are read, and a dict element is unwrapped: handing the
    object itself to network_interface yields no interface at all.
    """
    values = []
    for key in ("mac_addresses", "host_mac_address", "host_mac_addresses"):
        for entry in _list(host.get(key)):
            if type(entry) == "dict":
                values.append(as_text(entry.get("mac_address"), join=","))
            else:
                values.append(as_text(entry, join=","))
    return dedupe(values)

def _purdue_tag(value):
    """Tag value for purdue_level, or "" when it is not a documented level.

    purdue_level is a string enum (LEVEL0..LEVEL5, LEVEL35, UNDEFINED), not a
    number. UNDEFINED means the level was never set, so it is not worth a tag,
    and neither is a value from outside the enum.
    """
    level = value.upper()
    if level in PURDUE_LEVELS:
        return "purdue-level:" + level
    return ""

def _criticality_tag(value):
    """Tag value for criticality, or "" when it is out of the documented domain.

    criticality is an integer in [0-5] derived from the host's role, not a
    severity word. A legacy or hand-edited value that is not in that range stays
    in the custom attribute but does not become a tag.
    """
    level = _to_int(value)
    if level < 0 or level > MAX_CRITICALITY:
        return ""
    return "criticality:{}".format(level)

def _seen_ts(value):
    """Parse a vendor timestamp, rejecting the "never" sentinels.

    parse_ts does NOT return None for every empty-ish value: an ISO year-1
    value (Go's zero time) parses to unix=-62135596800 and any 1970-01-01 value
    to unix=0. Both survive a `!= None` check and epoch 0 survives a plain
    truth test, so an unguarded parse dates a never-seen asset instead of
    leaving it unknown.
    """
    ts = parse_ts(value)
    if ts == None or ts.unix <= 0:
        return None
    return ts

def build_asset(ctx, host):
    """Convert one eyeInspect host record into a runZero asset."""
    host_id = host.get("id")
    host_ip = as_text(host.get("ip"), join=",").strip()

    macs = _host_macs(host)
    netifs = []
    if macs:
        for index in range(len(macs[:MAX_INTERFACES])):
            ips = [host_ip] if (index == 0 and host_ip) else []
            nic = network_interface(mac=macs[index], ips=ips)
            if nic:
                netifs.append(nic)
    elif host_ip:
        nic = network_interface(ips=[host_ip])
        if nic:
            netifs.append(nic)

    # Unconditional when include_alerts is on. alert_count is a sort_field, not
    # a Host record field, so there is no alert-volume property to skip a quiet
    # host on and any short-circuit keyed on it never fires.
    alerts = []
    if ctx["include_alerts"]:
        alerts = fetch_host_alerts(ctx, host_id)

    tags = [VENDOR, "ot"]
    role = as_text(_first(host, ["main_role", "role"]), join=",").strip()
    if role:
        tags.append("role:" + role)
    # The typo spellings are the guide's own: the Host record table prints
    # `critically` and `sercurity_risk` where the sort_field vocabulary spells
    # both correctly, so both are read.
    purdue = as_text(host.get("purdue_level"), join=",").strip()
    purdue_tag = _purdue_tag(purdue)
    if purdue_tag:
        tags.append(purdue_tag)
    criticality = as_text(_first(host, ["criticality", "critically"]), join=",").strip()
    criticality_tag = _criticality_tag(criticality)
    if criticality_tag:
        tags.append(criticality_tag)

    attrs = {
        "host_id": host_id,
        "command_center": ctx["scope"],
        "ip": host_ip,
        "vlan": host.get("vlan"),
        "nested_address": host.get("nested_address"),
        "ip_reuse_domain_id": host.get("ip_reuse_domain_id"),
        # The Host record spells this sensors_ids; the sort_field vocabulary
        # spells it sensor_ids.
        "sensor_ids": _first(host, ["sensors_ids", "sensor_ids"]),
        "description": host.get("description"),
        "main_name": host.get("main_name"),
        "role": role,
        # A host observed in several roles or matching several device
        # fingerprints reports the winning one in role/vendor_model and the
        # full set in these, so both are kept.
        "all_roles": host.get("all_roles"),
        "all_vendors_models": host.get("all_vendors_models"),
        "purdue_level": purdue,
        "criticality": criticality,
        "labels": host.get("labels"),
        "serial_number": host.get("serial_number"),
        "hardware_version": host.get("hardware_version"),
        "firmware_version": host.get("firmware_version"),
        "vendor_model": _first(host, ["main_vendor_model", "vendor_model"]),
        "project": host.get("project"),
        # Both risk scores are floats in [0-10], not severity words.
        "security_risk": _first(host, ["security_risk", "sercurity_risk"]),
        "operational_risk": host.get("operational_risk"),
        "software_source": host.get("software_source"),
        "os_version_source": host.get("os_version_source"),
        "mac_addresses": macs,
        "alerts_fetched": len(alerts),
    }

    # main_name is inferred from traffic, so placeholders ("unknown", bare
    # IPs) are screened out; every unresolved host would share one name.
    main_name = clean_hostname(as_text(host.get("main_name"), join=",").strip())
    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], host_id),
        "hostnames": [main_name] if main_name else [],
        "networkInterfaces": netifs,
        "tags": tags,
        "services": build_services(host_ip, _list(host.get("open_ports")))[:MAX_CHILDREN],
        "software": build_software(ctx, host, host_ip)[:MAX_CHILDREN],
        "vulnerabilities": build_vulnerabilities(ctx, host, host_ip, alerts)[:MAX_CHILDREN],    }

    os_version = as_text(host.get("os_version"), join=",").strip()
    if os_version:
        params["os"] = os_version
    if role:
        params["deviceType"] = role

    # The raw strings are always recorded, not just when they fail to parse: a
    # future timestamp is clamped to now, so the attribute is the only place
    # the value the sensor actually reported survives.
    first_ts = _seen_ts(host.get("first_seen"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    attrs["first_seen"] = host.get("first_seen")
    last_ts = _seen_ts(host.get("last_seen"))
    attrs["last_seen"] = host.get("last_seen")

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset

def build_assets(ctx, hosts, id_floor):
    """Convert a page of eyeInspect hosts into runZero assets.

    Returns the assets and the highest numeric host id on the page, which is the
    check-point the next request pages from. A host at or below id_floor was
    already reported on the previous page and is dropped.
    """
    usable = []
    max_id = -1
    for host in hosts:
        if type(host) != "dict":
            continue
        host_id = host.get("id")
        if host_id == None or str(host_id).strip() == "":
            print("forescout-eyeinspect: skipping host with no id: ip=" + as_text(host.get("ip"), join=","))
            continue
        numeric = _to_int(host_id)
        if numeric >= 0:
            if numeric > max_id:
                max_id = numeric
            # id_min reads as inclusive, so the floor is passed as the last id
            # seen rather than one past it: correct whether the Command Center
            # treats it as >= or >, at the cost of dropping one duplicate here.
            if id_floor >= 0 and numeric <= id_floor:
                continue
        usable.append(host)

    warm_cve_cache(ctx, usable)
    return [build_asset(ctx, host) for host in usable], max_id

def fetch_and_report_hosts(ctx):
    """Fetch and stream hosts one page at a time so the full inventory is never
    held in memory at once."""
    url = ctx["base_url"] + API_PATH + "hosts"
    reported = 0
    offset = 0
    id_min = -1
    p = pager("hosts")
    while p.next():
        params = {"limit": str(PAGE_SIZE)}
        # id_min walks the table by primary key rather than by position, so an
        # insert behind the cursor cannot shift a row past it. offset is only
        # the first page and the fallback for a page with no numeric id.
        #
        # sort_field is deliberately NOT sent: `id` is not one of its accepted
        # values, and omitting it gives the ID-ascending order id_min needs.
        if id_min >= 0:
            params["id_min"] = str(id_min)
        else:
            params["offset"] = str(offset)
        # full=true asks for the enrichment properties rather than the compact
        # host record: software, patches, open_ports, cves, purdue_level,
        # criticality, firmware and the risk scores are all Full-only. Operator
        # disablable in case an older Command Center rejects the parameter.
        if ctx["full_host_details"]:
            params["full"] = "true"
        if ctx["last_seen"]:
            params["last_seen"] = ctx["last_seen"]

        data, err = get_json(url, params=params, **ctx["http_options"])
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("forescout-eyeinspect: authentication to the Command Center failed:", err)
            else:
                print("forescout-eyeinspect: failed to fetch hosts:", err)
            return reported

        hosts = _results(data or {})
        if not hosts:
            break

        assets, page_max = build_assets(ctx, hosts, id_min)
        reported += report_assets(assets)
        offset += len(hosts)

        # A page shorter than the limit is the last page. This holds only while
        # the Command Center honors the requested limit, which is why PAGE_SIZE
        # stays at the documented default.
        if len(hosts) < PAGE_SIZE:
            break
        if page_max < 0:
            continue
        if id_min >= 0 and page_max <= id_min:
            print("forescout-eyeinspect: host walk stopped, id_min did not advance past {}".format(id_min))
            break
        id_min = page_max

    print("forescout-eyeinspect: reported {} assets".format(reported))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        fail("forescout-eyeinspect: could not determine the Command Center host from the configured URL")

    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(get_string(kwargs, "username"), get_string(kwargs, "password")),
        "Accept": "application/json",
    })
    # get_json retries the transient statuses (408/425/429/5xx) with backoff and
    # honors Retry-After. Three retries is the built-in default; it is set
    # explicitly here so the count is visible next to the other tuning.
    http_options["retries"] = HTTP_RETRIES

    last_seen = ""
    last_seen_days = get_int(kwargs, "last_seen_days", default=0)
    if last_seen_days > 0:
        cutoff = now() + parse_duration("-{}h".format(last_seen_days * 24))
        last_seen = cutoff.format("2006-01-02T15:04:05Z07:00")

    ctx = {
        "base_url": base_url,
        "http_options": http_options,
        "scope": scope,
        "last_seen": last_seen,
        # CONFIG defaults are not applied on the script --kwargs path, so every
        # default is repeated here.
        "full_host_details": get_bool(kwargs, "full_host_details", default=True),
        "include_alerts": get_bool(kwargs, "include_alerts", default=True),
        "include_cve_details": get_bool(kwargs, "include_cve_details", default=False),
        "cve_cache": {},
        # Turned off for the rest of the run the first time the Command Center
        # rejects POST /cve_info/list, so a CSRF-enforcing deployment pays for
        # one failed request rather than one per page.
        "cve_bulk": True,
    }

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("forescout-eyeinspect: no assets retrieved")
    return None

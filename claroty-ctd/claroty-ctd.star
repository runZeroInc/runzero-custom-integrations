# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-claroty-ctd",
    "name": "Claroty CTD",
    "type": "inbound",
    "description": "Imports OT, IoT, and IT assets and their confirmed CVE findings from a Claroty Continuous Threat Detection (CTD) appliance or Enterprise Management Console (EMC).",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # resource_id is a per-asset primary key with no address input, so default
    # id matching is kept. name-break is relaxed: CTD learns names passively
    # from OT traffic, so its label routinely disagrees with an authoritative
    # FQDN, and on first contact that would split one device into two assets
    # that never reconcile. mac-break and ip-break stay on, because overlapping
    # site address plans and shared gateway MACs are what they separate.
    # See README "Asset identity".
    "matchBehavior": "no-name-break",
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "Claroty CTD or EMC URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ctd.example.com",
            "description": "Base URL of the CTD appliance or, preferably, the EMC that aggregates them. The /auth/ and /ranger/ paths are appended automatically. Include the port if the appliance is not on 443 (older deployments answer on 5000).",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "CTD or EMC user with the Visibility and the Risk and Vulnerabilities RBAC permissions.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for that user.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import CVE findings",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Also walk the asset-vulnerabilities join table and attach confirmed CVEs to their asset. Costs one extra paged walk of that table.",
        },
        {
            "key": "last_updated_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import assets whose record changed within this many days, using the last_updated__gt cursor. 0 imports the whole inventory.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames')
load('http', 'get_json', 'post_json', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_duration', 'parse_ts')
load('re', re_match='match')
load('coerce', 'as_text', 'as_dict', 'as_int', 'as_float', 'as_bool', 'as_list', 'dicts', 'dedupe')

VENDOR = "claroty-ctd"
ATTR_PREFIX = "claroty_ctd"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

AUTH_PATH = "/auth/authenticate"
ASSET_PATH = "/ranger/assets"
VULNERABILITY_PATH = "/ranger/asset-vulnerabilities"

# No server-side per_page ceiling is documented. 500 is the best-attested
# value: it is what Claroty's own asset scripts send and what Elastic's
# shipping CTD integration uses as its batch size.
PAGE_SIZE = 500
# get_json retries the transient statuses (408/425/429/5xx) with backoff and
# honors Retry-After. Claroty documents no rate limit, so this is defensive;
# the built-in default is set explicitly to keep it visible beside the tuning.
HTTP_RETRIES = 3

MAX_INTERFACES = 32
MAX_CHILDREN = 99
MAX_TAGS = 40
MAX_SLOTS = 16
MAX_INFO_ENTRIES = 32
# The join table is assets x CVEs, so it is the one response set that can grow
# without bound on a large EMC. The walk stops here and says so rather than
# holding an unbounded index in Explorer memory.
MAX_VULNERABILITY_ROWS = 50000

# Vulnerability.cve is validated against this pattern by the platform and a
# malformed id fails the WHOLE record, so values are screened before assignment.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# class_type is a string in responses ("OT"/"IT"/"IoT") and an int in filters.
CLASS_TYPE = {0: "OT", 1: "IT", 2: "IoT"}
CRITICALITY = {0: "Low", 1: "Medium", 2: "High"}
RISK_LEVEL = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
# special_hint 0 is a real unicast asset; 1-4 are the broadcast, multicast,
# out-of-scope, and external pseudo-assets CTD keeps for traffic accounting.
SPECIAL_HINT = {0: "Unicast", 1: "Broadcast", 2: "Multicast", 3: "Out of scope", 4: "External"}
# asset_type drives deviceType, so its fallback table is carried in full: a
# response projecting asset_type without asset_type__ would otherwise leave
# every asset untyped. Values are stored exactly as _enum_label yields them,
# stripped of the "e" prefix with the CamelCase runs intact, because _labelled
# returns a table hit verbatim and both paths must agree on the deviceType.
ASSET_TYPE = {
    0: "PLC", 1: "HMI", 2: "Endpoint",
    3: "Networking", 4: "Broadcast", 5: "DomainController",
    6: "Printer", 7: "SCADAClient", 8: "SCADAServer",
    9: "Historian", 10: "FileServer", 11: "Router",
    12: "Switch", 13: "RemoteIO", 14: "EngineeringStation",
    15: "Gateway", 16: "OPCServer", 17: "OT",
    18: "RTU", 19: "IED", 20: "Controller",
    21: "NTPServer", 22: "UserConsole", 23: "UserWorkstation",
    24: "TerminalServer", 25: "SyslogServer", 26: "FrontEndProcessor",
    27: "Modem", 28: "ProxyServer", 29: "ReverseProxyServer",
    30: "NetworkAccessStorage", 31: "Firewall", 32: "AVServer",
    33: "ADServer", 34: "WebServer", 35: "DBServer",
    36: "StorageArray", 37: "GPSClock", 38: "SCADAMaster",
    39: "VoipPhone", 40: "TVScreen", 41: "BluetoothDevice",
    42: "Camera", 43: "VendingMachine", 44: "SmartPhone",
    45: "SmartWatch", 46: "InfusionPump", 47: "MedicalDevice",
    48: "BarcodeScanner", 49: "Microscope", 50: "AccessControl",
    51: "SmartLight", 52: "Streamer", 53: "HomeAssistant",
    54: "MediaServer", 55: "CleaningDevice", 56: "VoipServer",
    57: "Robot", 58: "AutonomousVehicle", 59: "WirelessLanController",
    60: "AccessPoint", 61: "AAAServer", 62: "GPSDevice",
    63: "UPS", 64: "VideoRecorder", 65: "VirtualizationServer",
    66: "DataLogger", 67: "Sensor", 68: "ElectricalDrive",
    69: "MotorStarter", 70: "VulnerabilityScanner", 71: "VOIPAccessPoint",
    72: "SNMPServer", 73: "SNMPScanner", 74: "BiometricScanner",
    75: "DNSServer", 76: "VisionCamera", 77: "BarcodeReader",
    78: "VisionController", 79: "VisionSensor", 80: "RTLS",
    81: "CNC", 82: "CNCMill", 83: "CNCLathe",
    84: "AnalysisStation", 85: "WeightSensor", 86: "XRayCargoScanner",
}

SEVERITY_BAND = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
RANK_SCORE = {0: 0.0, 1: 2.5, 2: 5.0, 3: 7.5, 4: 10.0}

def _enum_label(value):
    """Return the human half of one of CTD's e-prefixed enum labels.

    asset_type__, criticality__, and special_hint__ all carry a label of the
    form "ePLC" or "eMedium". Only a leading "e" followed by an upper-case
    letter is stripped, so a label that does not use the convention survives
    untouched."""
    text = as_text(value).strip()
    if len(text) > 1 and text[0] == "e" and text[1] in UPPER:
        return text[1:]
    return text

def _labelled(record, field, table):
    """Read one of CTD's paired enum fields, preferring the label the appliance
    already supplied over the local integer table."""
    label = _enum_label(record.get(field + "__"))
    if label:
        return label
    value = record.get(field)
    if type(value) == "int":
        return table.get(value, "")
    return as_text(value).strip()

def _class_type(value):
    """Normalize class_type, which responses type as a string and filters type
    as an integer."""
    if type(value) == "int":
        return CLASS_TYPE.get(value, "")
    return as_text(value).strip()

def _strings(value):
    """Coerce a field documented as a list of strings into one. Several of
    these fields are absent entirely on a given asset, and a projected or
    single-element response can collapse the array to a scalar."""
    return dedupe([as_text(item) for item in as_list(value)])

def _attr_key(value):
    """Turn a CTD-supplied label into a custom attribute key fragment.

    custom_informations and custom_attributes are keyed by free text the
    appliance or an operator wrote ("Mode (Card 0)"), so the spacing and case
    are normalized before the key reaches a runZero attribute name."""
    text = as_text(value).strip().lower()
    for separator in (" ", "(", ")", "/", "\\", ".", ",", ":"):
        text = text.replace(separator, "_")
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")[:64]

def _more_pages(envelope, page_rows, seen):
    """Decide whether another page of a {count_filtered, count_total, objects}
    envelope is due.

    A FULL page always earns another request: trusting a count over a visibly
    full page is what truncates an import silently. On a SHORT page the count
    decides, and count_filtered is the one that matches this walk, because every
    request carries a filter and count_total is the pre-filter total.
    count_total is the fallback when the filtered count is absent. Keeping a
    count in play covers an appliance that clamps per_page, where an early short
    page would otherwise end the import without an error."""
    if page_rows >= PAGE_SIZE:
        return True
    total = as_int(envelope.get("count_filtered"))
    if total <= 0:
        total = as_int(envelope.get("count_total"))
    return total > 0 and seen < total

def authenticate(ctx):
    """Exchange the username and password for a CTD session token.

    The response is a 200 in three situations: a real token, an expired password
    that must be rotated before the API is usable, and a refusal carrying an
    error key. All three are distinguished so the operator gets a message that
    names the actual problem."""
    data, err = post_json(ctx["base_url"] + AUTH_PATH,
                          json={"username": ctx["username"], "password": ctx["password"]},
                          **ctx["auth_options"])
    if err:
        print("claroty-ctd: authentication failed:", err)
        return ""

    payload = as_dict(data)
    if as_bool(payload.get("password_expired")):
        print("claroty-ctd: the API account's password has expired; rotate it in the CTD console before this integration can read any data")
        return ""

    token = as_text(payload.get("token"))
    if not token:
        message = as_text(payload.get("error")) or as_text(payload.get("message"))
        if message:
            print("claroty-ctd: authentication was refused: " + message[:200])
        else:
            print("claroty-ctd: the authentication response carried no token")
    return token

def _api_options(config_kwargs, token):
    """Collect the HTTP options used for every /ranger/ call under one token.

    get_http_options SNAPSHOTS the header map it is given, so a token minted
    mid-run needs the whole options dict rebuilt rather than the existing
    header dict mutated in place."""
    options = get_http_options(config_kwargs, headers={
        # Claroty takes the raw token. A "Bearer " prefix is rejected: every
        # shipping client for this API sends the bare value.
        "Authorization": token,
        "Accept": "application/json",
    })
    options["retries"] = HTTP_RETRIES
    return options

def fetch_json(ctx, url, params):
    """GET one API page, re-authenticating once on a 401.

    Claroty documents no token lifetime, only that tokens expire and 401 is the
    signal. A full walk of a large EMC can outlive its first token, so a 401
    mid-run is treated as an aged-out session rather than a bad credential."""
    for attempt in range(2):
        data, err = get_json(url, params=params, **ctx["http_options"])
        if not err:
            return data, None
        if err.startswith("status 401") and attempt == 0:
            print("claroty-ctd: session token rejected mid-run, authenticating again")
            token = authenticate(ctx)
            if token:
                ctx["http_options"] = _api_options(ctx["kwargs"], token)
                continue
        return None, err
    return None, "unreachable"

def build_vulnerability(ctx, row):
    """Convert one asset-vulnerabilities match record into a Vulnerability."""
    row_id = as_text(row.get("resource_id"))
    asset_key = as_text(row.get("asset_id"))
    cve = as_text(row.get("cve_id")).upper()
    if not row_id and not cve:
        return None

    params = {
        "id": "{}:{}:vuln:{}".format(VENDOR, ctx["scope"], row_id or (asset_key + ":" + cve)),
        "name": (cve or as_text(row.get("vulnerability_type")) or "Claroty CTD finding")[:255],
        "description": as_text(row.get("description"))[:1024],
        "category": as_text(row.get("vulnerability_type")),
    }
    # The platform does not upper-case this field for you and a value that
    # misses the pattern fails the whole record, so it is checked first.
    if re_match(CVE_RE, cve):
        params["cve"] = cve

    # cvss_v3_score is documented as an object {value, label}, not a scalar.
    # A build that reports a bare number instead still parses, because
    # as_dict yields {} for it and the raw value is read directly.
    cvss = as_dict(row.get("cvss_v3_score"))
    if cvss:
        score = as_float(cvss.get("value"), default=-1.0)
        band = as_text(cvss.get("label")).upper()
    else:
        score = as_float(row.get("cvss_v3_score"), default=-1.0)
        band = ""

    rank = SEVERITY_BAND.get(band, 0)
    if score > 0.0:
        params["cvss3BaseScore"] = score
        rank = 4
        if score < 4.0:
            rank = 1
        elif score < 7.0:
            rank = 2
        elif score < 9.0:
            rank = 3
        params["severityScore"] = score
        params["riskScore"] = score
    else:
        params["severityScore"] = RANK_SCORE[rank]
        params["riskScore"] = RANK_SCORE[rank]
    params["severityRank"] = rank
    params["riskRank"] = rank

    # epss_score is the second nested object on this record.
    epss = as_dict(row.get("epss_score"))
    epss_value = epss.get("value") if epss else row.get("epss_score")

    exploited = as_bool(row.get("actively_exploited"))
    if exploited:
        params["exploitable"] = True

    detected = parse_ts(row.get("detection_date"))
    if detected:
        params["firstDetectedTS"] = detected

    params["customAttributes"] = to_custom_attributes({
        "vuln_resource_id": row_id,
        "vuln_asset_id": asset_key,
        "vuln_asset_name": row.get("asset_name"),
        # The raw value as the appliance reported it, kept even when it was not
        # well-formed enough to assert as the cve field.
        "cve_id": row.get("cve_id"),
        "cvss_v3_score": score if score > 0.0 else "",
        "cvss_v3_label": band,
        "epss_score": epss_value,
        "actively_exploited": exploited,
        "advisory_names": row.get("advisory_names"),
        "vulnerability_type": row.get("vulnerability_type"),
        "relevance": row.get("relevance__"),
        "status": row.get("status__"),
        "detection_date": row.get("detection_date"),
    }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return Vulnerability(**params)

def _vuln_key(row):
    """Canonicalise a vulnerability row's asset reference to the resource-id form.

    A row that already carries "<id>-<site id>" is used verbatim. A bare numeric
    id is only meaningful alongside its site, so it is combined with the row's
    own site_id; with no site_id the bare value is used, which is correct on a
    single-site CTD and is the only option when the field is omitted.
    """
    key = as_text(row.get("asset_id")).strip()
    if not key or key.find("-") >= 0:
        return key
    site = as_text(row.get("site_id")).strip()
    if site:
        return "{}-{}".format(key, site)
    return key

def fetch_vulnerability_index(ctx):
    """Index confirmed CVE matches by the asset key they join on.

    relevance__exact=1 restricts the walk to CONFIRMED matches, not the
    vendor/model-inferred "potentially relevant" ones. asset_id may carry either
    the numeric id or the "<id>-<site id>" resource id, so every row is
    CANONICALISED to the resource-id form at index time. Matching both spellings
    at lookup would over-join on an EMC: the bare id is site-scoped, so asset 30
    at site 1 and at site 2 would share the key "30"."""
    index = {}
    kept = 0
    seen = 0

    p = pager("asset-vulnerabilities")
    while p.next():
        params = {
            "page": str(p.page),
            "per_page": str(PAGE_SIZE),
            "relevance__exact": "1",
        }
        data, err = fetch_json(ctx, ctx["base_url"] + VULNERABILITY_PATH, params)
        if err:
            print("claroty-ctd: failed to fetch asset vulnerabilities:", err)
            return index

        envelope = as_dict(data)
        rows = dicts(envelope.get("objects"))
        if not rows:
            break

        for row in rows:
            key = _vuln_key(row)
            if not key:
                continue
            vuln = build_vulnerability(ctx, row)
            if not vuln:
                continue
            bucket = index.get(key)
            if bucket == None:
                bucket = []
                index[key] = bucket
            if len(bucket) < MAX_CHILDREN:
                bucket.append(vuln)
                kept += 1

        seen += len(rows)
        if not _more_pages(envelope, len(rows), seen):
            break
        if seen >= MAX_VULNERABILITY_ROWS:
            print("claroty-ctd: stopping the vulnerability walk at {} rows".format(seen))
            break

    print("claroty-ctd: indexed {} vulnerabilities across {} assets".format(kept, len(index)))
    return index

def build_software(ctx, record, resource_id, primary_ip):
    """Build a firmware Software record from the hardware properties the asset
    row carries. Nothing is emitted when CTD never determined any of them,
    which is normal for passively observed IT endpoints."""
    vendor = as_text(record.get("vendor"))
    model = as_text(record.get("model"))
    firmware = as_text(record.get("firmware"))
    if not vendor and not model and not firmware:
        return []

    params = {
        # Software REQUIRES an id, and the field for the name is product.
        "id": "{}:{}:asset:{}:firmware".format(VENDOR, ctx["scope"], resource_id),
        "product": model or "Firmware",
        "vendor": vendor,
        "version": firmware,
        "customAttributes": to_custom_attributes({
            "serial_number": record.get("serial_number"),
            "model": model,
            "firmware": firmware,
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    # An asset with no address gets a firmware record with no serviceAddress
    # rather than a loopback placeholder, which is identical on every host.
    if primary_ip:
        params["serviceAddress"] = primary_ip
    # cpe23 is deliberately unset: CTD publishes no CPE on the asset row, and
    # Software.cpe23 only accepts the CPE 2.2 "cpe:/a:" binding.
    return [Software(**params)]

def _collect_attributes(record, attrs):
    """Fold CTD's three nested detail structures into flat custom attributes.

    plc_slots, project_parsed, custom_informations, and custom_attributes are
    where the OT-specific value of this source lives, and none of them survives
    a plain list join, so each is expanded into explicit keys."""
    # A plc_slots entry is not a flat card record: its only key is
    # PLCSlotInformation, whose `value` holds the PLCInformation object, so the
    # card fields are two levels down. The key uses the wrapper's own slot
    # number, not the array index; a chassis populated at slots 0, 1, 2, 5, 6
    # would otherwise report slot 5's card as plc_slot_3.
    slots = dicts(record.get("plc_slots"))
    for index in range(len(slots[:MAX_SLOTS])):
        wrapper = as_dict(slots[index].get("PLCSlotInformation"))
        if not wrapper:
            # A deployment that publishes the flat form is still read.
            wrapper = slots[index]
            info = slots[index]
            number = as_text(wrapper.get("slot")) or str(index)
        else:
            info = as_dict(as_dict(wrapper.get("value")).get("PLCInformation"))
            number = as_text(wrapper.get("slot"))
            if number == "":
                number = str(index)
        if not info:
            continue
        key = "plc_slot_{}_".format(number)
        attrs[key + "name"] = info.get("name")
        attrs[key + "vendor"] = info.get("vendor")
        attrs[key + "product"] = info.get("product")
        attrs[key + "order_number"] = info.get("order_number")
        attrs[key + "firmware_version"] = info.get("firmware_version")
        attrs[key + "serial_number"] = info.get("serial_number")
        attrs[key + "address"] = info.get("address")
        attrs[key + "description"] = wrapper.get("description")

    project = as_dict(record.get("project_parsed"))
    attrs["project_name"] = project.get("name")
    attrs["project_description"] = project.get("description")
    attrs["project_builder_hostname"] = project.get("builder_hostname")
    attrs["project_creation_ver"] = project.get("creation_ver")
    attrs["project_ver"] = project.get("project_ver")

    for entry in dicts(record.get("custom_informations"))[:MAX_INFO_ENTRIES]:
        key = _attr_key(entry.get("display_key")) or _attr_key(entry.get("key"))
        if key:
            attrs["info_" + key] = entry.get("val")

    for entry in dicts(record.get("custom_attributes"))[:MAX_INFO_ENTRIES]:
        key = _attr_key(as_dict(entry.get("category")).get("name"))
        if key:
            attrs["attr_" + key] = entry.get("value")

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

# DNS-shaped names observed on more than one asset in a real CTD export, plus
# the usual placeholders. clean_hostnames cannot catch these -- they are valid
# hostnames, they just do not identify a device.
PLACEHOLDER_NAMES = [
    "untitled", "unknown", "none", "null", "n/a", "-", "*",
    "localhost", "localhost.localdomain",
    "scada-server", "windows7", "desktop", "workstation",
]

def _hostname(value):
    """Return a value fit to import as a hostname, or "".

    Rejects the shared placeholder names above. A name that identifies nothing
    is worse than no name at all here, because it is a live merge signal.
    """
    text = as_text(value).strip()
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    return text

def build_asset(ctx, record, resource_id):
    """Convert one top-level CTD asset row into a runZero asset."""
    # ipv4, ipv6, and mac are lists when present and any of them can be absent:
    # MAC-only L2 devices, IP-only remote endpoints, and backplane cards
    # addressed by slot all occur naturally. routable_ips drops loopback,
    # link-local, multicast, and unspecified values, which correlate unrelated
    # hosts onto one asset.
    ips = routable_ips(_strings(record.get("ipv4")) + _strings(record.get("ipv6")))
    macs = _strings(record.get("mac"))
    primary_ip = ips[0] if ips else ""

    # OT gear is routinely multi-homed and the two arrays are not positionally
    # paired, so every MAC becomes an interface and the addresses ride on the
    # first one. network_interface returns None when nothing usable survives,
    # and a None inside networkInterfaces aborts the whole run.
    netifs = []
    if macs:
        for index in range(len(macs[:MAX_INTERFACES])):
            nic = network_interface(mac=macs[index], ips=ips if index == 0 else [])
            if nic:
                netifs.append(nic)
    elif ips:
        nic = network_interface(ips=ips)
        if nic:
            netifs.append(nic)

    # name and display_name fall back to an address string when CTD never
    # learned a real name; clean_hostnames rejects those and the bus addresses
    # ("10.1.30.1:Card 2 \ Addr 255"). It does NOT reject a DNS-shaped name
    # shared by many assets (SCADA-SERVER, Windows7), which _hostname screens:
    # name-match is on, and for an address-less row a shared name is the only
    # merge dimension there is.
    names = clean_hostnames([
        _hostname(record.get("hostname")),
        _hostname(record.get("display_name")),
        _hostname(record.get("name")),
    ])

    asset_type = _labelled(record, "asset_type", ASSET_TYPE)
    class_type = _class_type(record.get("class_type"))
    criticality = _labelled(record, "criticality", CRITICALITY)
    risk_level = _labelled(record, "risk_level", RISK_LEVEL)
    purdue = as_text(record.get("purdue_level")).strip()
    zone = as_text(record.get("virtual_zone_name"))
    site = as_text(record.get("site_name"))
    protocols = _strings(record.get("protocol"))
    insights = _strings(record.get("insight_names"))

    tags = [VENDOR]
    if class_type:
        tags.append("class:" + class_type)
    if asset_type:
        tags.append("type:" + asset_type)
    if purdue:
        tags.append("purdue-level:" + purdue)
    if zone:
        tags.append("zone:" + zone)
    if criticality:
        tags.append("criticality:" + criticality)
    if risk_level:
        tags.append("risk:" + risk_level)
    if site:
        tags.append("site:" + site)
    for protocol in protocols:
        tags.append("protocol:" + protocol)
    for insight in insights:
        tags.append("insight:" + insight)

    # children[] holds complete nested asset objects, each of which is ALSO
    # returned as its own top-level row. Only the child's resource_id is kept,
    # as a parent/child relationship attribute; recursing into the array would
    # import every backplane card twice.
    children = dedupe([as_text(child.get("resource_id")) for child in dicts(record.get("children"))])

    network = as_dict(record.get("network"))
    # The resource-id key is exact. A bare numeric asset_id with no site_id
    # could not be canonicalised at index time, so it is claimed here by the
    # first matching asset and then REMOVED: without the pop, asset 30 at site 1
    # and asset 30 at site 2 on an EMC would each take the other's findings.
    vulns = ctx["vulns"].get(resource_id, [])
    if not vulns:
        vulns = ctx["vulns"].pop(as_text(record.get("id")).strip(), [])

    attrs = {
        "appliance": ctx["scope"],
        "resource_id": resource_id,
        "asset_id": record.get("id"),
        "site_id": record.get("site_id"),
        "site_name": site,
        "name": record.get("name"),
        "display_name": record.get("display_name"),
        "hostname": record.get("hostname"),
        "domain_workgroup": record.get("domain_workgroup"),
        "ipv4": _strings(record.get("ipv4")),
        "ipv6": _strings(record.get("ipv6")),
        "mac": macs,
        # Previously observed addresses. CTD appends rather than forking the
        # record, which is the direct evidence that resource_id survives a
        # readdress, so the history is worth keeping as identity evidence.
        "old_ips": _strings(record.get("old_ips")),
        "vlan": _strings(record.get("vlan")),
        # Non-IP bus or backplane address, e.g. "10.1.30.1:Card 2 \ Addr 255".
        "address": _strings(record.get("address")),
        "default_gateway": as_text(record.get("default_gateway")) or as_text(record.get("gateway")),
        "network_id": record.get("network_id"),
        "network_name": network.get("name"),
        "network_resource_id": network.get("resource_id"),
        "subnet_id": record.get("subnet_id"),
        "subnet": as_dict(record.get("subnet")).get("name"),
        "subnet_type": record.get("subnet_type"),
        "has_interfaces": record.get("has_interfaces"),
        # Protocol names only: CTD records which protocols it observed but
        # never the ports they ran on, so no Service is built.
        "protocol": protocols,
        "asset_type": record.get("asset_type"),
        "asset_type_label": asset_type,
        "class_type": class_type,
        "criticality": record.get("criticality"),
        "criticality_label": criticality,
        "risk_level": record.get("risk_level"),
        "risk_level_label": risk_level,
        "risk_score": record.get("risk_score"),
        "purdue_level": purdue,
        "virtual_zone_id": record.get("virtual_zone_id"),
        "virtual_zone_name": zone,
        "insight_names": insights,
        "num_alerts": record.get("num_alerts"),
        "vendor": record.get("vendor"),
        "model": record.get("model"),
        "firmware": record.get("firmware"),
        "serial_number": record.get("serial_number"),
        "os": record.get("os"),
        "os_build": record.get("os_build"),
        "os_architecture": record.get("os_architecture"),
        "os_service_pack": record.get("os_service_pack"),
        "os_revision": record.get("os_revision"),
        "installed_antivirus": record.get("installed_antivirus"),
        "installed_programs_count": record.get("installed_programs_count"),
        "patch_count": record.get("patch_count"),
        "usb_devices_count": record.get("usb_devices_count"),
        "special_hint": record.get("special_hint"),
        "special_hint_label": _labelled(record, "special_hint", SPECIAL_HINT),
        "ghost": record.get("ghost"),
        "valid": record.get("valid"),
        "approved": record.get("approved"),
        "parsed": record.get("parsed"),
        "state": record.get("state"),
        "edge_id": record.get("edge_id"),
        "edge_last_run": record.get("edge_last_run"),
        # The raw strings are recorded alongside the parsed timestamps, not
        # only when parsing fails: parse_ts caps a future value at now, so the
        # attribute is the only place the appliance's own value survives.
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "last_entity_seen": record.get("last_entity_seen"),
        "last_updated": record.get("last_updated"),
        "timestamp": record.get("timestamp"),
        "children_resource_ids": children,
        "children_count": len(children),
        "vulnerability_count": len(vulns),
    }
    _collect_attributes(record, attrs)

    return ImportAsset(
        id="{}:{}:{}".format(VENDOR, ctx["scope"], resource_id),
        hostnames=names,
        networkInterfaces=netifs,
        tags=tags[:MAX_TAGS],
        os=as_text(record.get("os")),
        osVersion=as_text(record.get("os_build")) or as_text(record.get("os_revision")),
        manufacturer=as_text(record.get("vendor")),
        model=as_text(record.get("model")),
        deviceType=asset_type,
        domain=as_text(record.get("domain_workgroup")),
        software=build_software(ctx, record, resource_id, primary_ip)[:MAX_CHILDREN],
        vulnerabilities=vulns[:MAX_CHILDREN],
        firstSeenTS=_seen_ts(record.get("first_seen")),
        lastSeenTS=_seen_ts(record.get("last_seen")),
        customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    )

def report_page(ctx, rows):
    """Convert and report one page of asset rows, dropping the ones that cannot
    be imported. Each asset is streamed as it is built, so no page of the
    inventory is ever buffered. Returns (reported, skipped)."""
    reported = 0
    skipped = 0
    for row in rows:
        resource_id = as_text(row.get("resource_id")).strip()
        if not resource_id:
            # id alone is site-scoped and collides across the sites an EMC
            # aggregates, so there is no safe fallback: the row is dropped.
            skipped += 1
            print("claroty-ctd: skipping asset with no resource_id: id=" + as_text(row.get("id")))
            continue
        # Belt and braces against the server-side filters: a ghost is a
        # placeholder for an address CTD inferred but never confirmed, and it
        # can shadow the real asset. special_hint 1-4 are pseudo-assets.
        if as_bool(row.get("ghost")) or as_int(row.get("special_hint")) != 0:
            skipped += 1
            continue
        reported += report_asset(build_asset(ctx, row, resource_id))
    return reported, skipped

def fetch_and_report_assets(ctx):
    """Fetch and stream assets one page at a time so the full inventory is
    never held in memory at once.

    The walk ends on whichever documented condition comes first: the running
    count reaching count_total, a short page, or an empty objects array. Taking
    all three means a missing or malformed count cannot spin the loop."""
    reported = 0
    skipped = 0
    seen = 0

    p = pager("assets")
    while p.next():
        params = {
            "page": str(p.page),
            "per_page": str(PAGE_SIZE),
            "ghost__exact": "false",
        }
        if ctx["last_updated"]:
            params["last_updated__gt"] = ctx["last_updated"]
        # The fields projection is deliberately never sent. Its delimiter is
        # the literal three-character sequence ",;$", and omitting the
        # parameter is what guarantees resource_id is on every row.
        data, err = fetch_json(ctx, ctx["base_url"] + ASSET_PATH, params)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("claroty-ctd: the API account was refused access to the asset inventory:", err)
            else:
                print("claroty-ctd: failed to fetch assets:", err)
            return reported

        envelope = as_dict(data)
        rows = dicts(envelope.get("objects"))
        if not rows:
            break

        page_reported, page_skipped = report_page(ctx, rows)
        reported += page_reported
        skipped += page_skipped
        seen += len(rows)
        if not _more_pages(envelope, len(rows), seen):
            break

    if skipped:
        print("claroty-ctd: skipped {} rows with no resource_id, or flagged ghost or non-unicast".format(skipped))
    print("claroty-ctd: reported {} assets".format(reported))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    # The id namespace is the hostname ALONE, with any port stripped. A port is
    # a deployment detail that changes when an appliance moves behind a proxy;
    # baking it into the foreign id would rewrite the id of every asset.
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("claroty-ctd: could not determine the appliance host from the configured URL")
        return None

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "kwargs": kwargs,
        "username": get_string(kwargs, "username"),
        "password": get_string(kwargs, "password"),
        "auth_options": get_http_options(kwargs, headers={"Accept": "application/json"}),
        "http_options": {},
        "last_updated": "",
        "vulns": {},
    }

    # CONFIG defaults are not applied on the script --kwargs path, so every
    # default is repeated here.
    last_updated_days = get_int(kwargs, "last_updated_days", default=0)
    if last_updated_days > 0:
        cutoff = now() + parse_duration("-{}h".format(last_updated_days * 24))
        # CTD emits and accepts the offset form, e.g. 2024-07-16T09:59:10+00:00.
        ctx["last_updated"] = cutoff.format("2006-01-02T15:04:05-07:00")

    token = authenticate(ctx)
    if not token:
        return None
    ctx["http_options"] = _api_options(kwargs, token)

    if get_bool(kwargs, "include_vulnerabilities", default=True):
        ctx["vulns"] = fetch_vulnerability_index(ctx)

    reported = fetch_and_report_assets(ctx)
    if not reported:
        print("claroty-ctd: no assets retrieved")
    return None

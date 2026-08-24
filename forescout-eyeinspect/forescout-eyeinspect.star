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
    # re-observes a host, so name-break is relaxed. mac-break and ip-break
    # are deliberately kept on, because this source has two documented ways
    # of giving different devices the same identifier: ip_reuse_domain_id
    # means one address can legitimately belong to several hosts in
    # different reuse domains, and hosts reached through a router or serial
    # gateway present the gateway's MAC. Those breaks are the only thing
    # separating such devices when the host id has not yet matched, so
    # relaxing them would let the collisions this source is known to
    # produce merge unrelated OT assets.
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
            "key": "include_alerts",
            "label": "Import alerts as vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Attach eyeInspect alerts to their host as findings. Costs one alerts request per host.",
        },
        {
            "key": "include_cve_details",
            "label": "Enrich CVEs from eyeInspect",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Look up CVE detail for every CVE referenced by a host or alert. Costs one request per distinct CVE.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'clean_hostname')
load('http', 'get_json', 'basic', 'url_parse')
load('json', json_encode='encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_time', 'parse_duration', 'parse_ts')
load('re', re_find_all='find_all')

load('coerce', 'as_text', 'dedupe')
VENDOR = "forescout-eyeinspect"
ATTR_PREFIX = "forescout_eyeinspect"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
API_PATH = "/api/v1/"
PAGE_SIZE = 100          # MAX_LIMIT documented for every paged eyeInspect endpoint
ALERT_LIMIT = 100        # alerts attached per host, bounded by the same MAX_LIMIT
HTTP_RETRIES = 3
MAX_INTERFACES = 32
MAX_CHILDREN = 99
DEFAULT_TRANSPORT = "tcp"
DIGITS = "0123456789"
TRANSPORTS = ["tcp", "udp", "sctp"]
CVE_PATTERN = r"CVE-[0-9]{4}-[0-9]{4,7}"
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
    """Extract (port, transport) from one open_ports entry. Transport is an empty
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


def fetch_cve_detail(ctx, cve_id):
    """Look up one CVE in the eyeInspect CVE database, caching every lookup so a
    CVE seen on many hosts costs a single request."""
    cache = ctx["cve_cache"]
    if cve_id in cache:
        return cache[cve_id]
    url = ctx["base_url"] + API_PATH + "cve_info/" + cve_id
    data, err = get_json(url, **ctx["http_options"])
    if err:
        print("forescout-eyeinspect: failed to fetch CVE {}: {}".format(cve_id, err))
        cache[cve_id] = {}
        return cache[cve_id]
    if type(data) != "dict":
        data = {}
    cache[cve_id] = data
    return data


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


def apply_cve_detail(ctx, params, attrs, cve_id, rank_from_cvss):
    """Fold an eyeInspect cve_info record into a Vulnerability. The CVSS scores
    only drive the rank for findings that have no severity of their own; an alert
    keeps the severity the sensor assigned it."""
    if not ctx["include_cve_details"]:
        return

    detail = fetch_cve_detail(ctx, cve_id)
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


def build_cve_vulnerability(ctx, vuln_id, cve_id, category, base_attrs):
    """Build a CVE-backed Vulnerability, enriched from cve_info when enabled."""
    params = {
        "id": vuln_id,
        "name": cve_id,
        "cve": cve_id,
        "category": category,
    }
    attrs = dict(base_attrs)
    apply_cve_detail(ctx, params, attrs, cve_id, True)
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
    for cve_id in _extract_cves(host.get("complex_cves")):
        vulns.append(build_cve_vulnerability(
            ctx,
            "{}:{}:host:{}:cve:{}".format(VENDOR, ctx["scope"], host_id, cve_id),
            cve_id,
            "CVE",
            {"host_id": host_id, "cve_source": "complex_cves"},
        ))

    return vulns


def build_software(ctx, host, host_ip):
    """Build a firmware Software record, but only when the host record actually
    carries vendor/model or firmware detail. eyeInspect documents these as host
    properties without publishing them in the host response contract, so nothing
    is emitted when they are absent."""
    vendor_model = as_text(host.get("vendor_model"), join=",").strip()
    firmware = as_text(host.get("firmware_version"), join=",").strip()
    if not vendor_model and not firmware:
        return []

    params = {
        "id": "{}:{}:host:{}:firmware".format(VENDOR, ctx["scope"], host.get("id")),
        "product": vendor_model or "Firmware",
        "serviceAddress": host_ip or "127.0.0.1",
        "customAttributes": to_custom_attributes({
            "hardware_version": host.get("hardware_version"),
            "serial_number": host.get("serial_number"),
            "project": host.get("project"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if firmware:
        params["version"] = firmware
    return [Software(**params)]


def build_services(host_ip, open_ports):
    """Build Service objects from the host open_ports list. eyeInspect documents
    the field as the open TCP and UDP ports of the host but does not publish the
    element shape, so ints, "443", "502/tcp" strings, and {port, protocol} dicts
    are all accepted. Entries that name no transport are recorded as tcp and
    flagged with a custom attribute."""
    if not host_ip or type(open_ports) != "list":
        return []

    services = []
    seen = []
    for entry in open_ports:
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
            address=host_ip,
            port=int(port),
            transport=transport,
            customAttributes=to_custom_attributes({
                "service_source": "open_ports",
                "transport_source": "assumed" if assumed else "reported",
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        ))
    return services


def build_asset(ctx, host):
    """Convert one eyeInspect host record into a runZero asset."""
    host_id = host.get("id")
    host_ip = as_text(host.get("ip"), join=",").strip()

    macs = dedupe(_list(host.get("mac_addresses")) + _list(host.get("host_mac_addresses")))
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

    alerts = []
    if ctx["include_alerts"] and _to_int(host.get("alert_count", -1)) != 0:
        alerts = fetch_host_alerts(ctx, host_id)

    tags = [VENDOR, "ot"]
    role = as_text(host.get("role"), join=",").strip()
    if role:
        tags.append("role:" + role)
    purdue = as_text(host.get("purdue_level"), join=",").strip()
    if purdue:
        tags.append("purdue-level:" + purdue)
    criticality = as_text(host.get("criticality"), join=",").strip()
    if criticality:
        tags.append("criticality:" + criticality)

    attrs = {
        "host_id": host_id,
        "command_center": ctx["scope"],
        "ip": host_ip,
        "vlan": host.get("vlan"),
        "nested_address": host.get("nested_address"),
        "ip_reuse_domain_id": host.get("ip_reuse_domain_id"),
        "sensor_ids": host.get("sensor_ids"),
        "description": host.get("description"),
        "main_name": host.get("main_name"),
        "role": role,
        "purdue_level": purdue,
        "criticality": criticality,
        "labels": host.get("labels"),
        "serial_number": host.get("serial_number"),
        "hardware_version": host.get("hardware_version"),
        "firmware_version": host.get("firmware_version"),
        "vendor_model": host.get("vendor_model"),
        "project": host.get("project"),
        "ip_type": host.get("ip_type"),
        "monitored_networks": host.get("monitored_networks"),
        "alert_count": host.get("alert_count"),
        "security_risk": host.get("security_risk"),
        "operational_risk": host.get("operational_risk"),
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

    # The raw strings are always recorded, not just when they fail to parse:
    # _parse_ts caps a future timestamp at now, so the attribute is the only
    # place the value the sensor actually reported survives.
    first_ts = parse_ts(host.get("first_seen"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    attrs["first_seen"] = host.get("first_seen")
    last_ts = parse_ts(host.get("last_seen"))
    attrs["last_seen"] = host.get("last_seen")

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset


def build_assets(ctx, hosts):
    """Convert a page of eyeInspect hosts into runZero assets."""
    assets = []
    for host in hosts:
        if type(host) != "dict":
            continue
        host_id = host.get("id")
        if host_id == None or str(host_id).strip() == "":
            print("forescout-eyeinspect: skipping host with no id: ip=" + as_text(host.get("ip"), join=","))
            continue
        assets.append(build_asset(ctx, host))
    return assets


def fetch_and_report_hosts(ctx):
    """Fetch and stream hosts one page at a time so the full inventory is never
    held in memory at once."""
    url = ctx["base_url"] + API_PATH + "hosts"
    reported = 0
    offset = 0
    p = pager("hosts")
    while p.next():
        params = {"offset": str(offset), "limit": str(PAGE_SIZE), "sort_field": "id", "sort_ascending": "true"}
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

        reported += report_assets(build_assets(ctx, hosts))
        if len(hosts) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    print("forescout-eyeinspect: reported {} assets".format(reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("forescout-eyeinspect: could not determine the Command Center host from the configured URL")
        return None

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
        "include_alerts": get_bool(kwargs, "include_alerts", default=True),
        "include_cve_details": get_bool(kwargs, "include_cve_details", default=False),
        "cve_cache": {},
    }

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("forescout-eyeinspect: no assets retrieved")
    return None

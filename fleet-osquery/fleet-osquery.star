# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-fleet-osquery",
    "name": "Fleet (osquery)",
    "type": "inbound",
    # Software, labels, and policy results are on by default; CVE findings,
    # per-host detail, and listening services are opt-in, and the last of those
    # additionally needs a Fleet additional_query to be named. The description
    # used to advertise services and CVEs as if they were part of a default run.
    "description": "Imports hosts from Fleet with their software, labels, and policy results; CVE findings and listening services are optional.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The Fleet host id is authoritative for the server, but Fleet publishes
    # only one address and one MAC per host and both are re-derived on every
    # detail refresh, so network churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Fleet server URL",
            "type": "url",
            "required": True,
            "placeholder": "https://fleet.example.com",
            "description": "Base URL of the Fleet server. The /api/v1/fleet/ path is appended automatically.",
        },
        {
            "key": "email",
            "label": "Fleet user email",
            "type": "string",
            "required": False,
            "description": "Email of an API-only Fleet user. Only needed when no API token is supplied; the script then logs in to mint a fresh token for each run.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": False,
            "description": "Fleet API token for an API-only user. Preferred. Fleet expires tokens after the server session_duration (5 days by default), so use the email and password fields instead for schedules longer than that.",
        },
        {
            "key": "password",
            "label": "Fleet user password",
            "type": "secret",
            "required": False,
            "description": "Password for the Fleet user above. Used only to call the login endpoint when no API token is supplied.",
        },
        {
            "key": "include_software",
            "label": "Import software inventory",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request populate_software on the host list. Fleet documents this as expensive; disable it to import inventory only.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import CVE findings",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Map the CVEs Fleet matches against installed software. Requires software import. CVSS scores and exploit flags are Fleet Premium only.",
        },
        {
            "key": "include_labels",
            "label": "Import label and team membership",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request populate_labels on the host list and tag hosts with their user-created labels.",
        },
        {
            "key": "include_policies",
            "label": "Import policy results",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request populate_policies on the host list and record which policies each host passes and fails.",
        },
        {
            "key": "listening_ports_query",
            "label": "Listening ports additional query name",
            "type": "string",
            "required": False,
            "description": "Name of a Fleet additional query that selects from the listening_ports osquery table. Leave blank to skip services. The query must already exist in features.additional_queries on the Fleet server.",
        },
        {
            "key": "include_host_detail",
            "label": "Fetch per-host detail",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Issue one extra request per host to collect disk encryption state, MDM profile status, and agent versions. Off by default because it is one request per host.",
        },
        {
            "key": "detail_limit",
            "label": "Per-host detail limit",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "description": "Maximum number of hosts to enrich with per-host detail. Hosts past the limit are still imported without it. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Hosts per page",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 500,
            "description": "Hosts requested per page. Fleet recommends 50 or fewer when software is also being populated.",
        },
    ],
    "atLeastOneOf": [["api_token", "password"]],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'ServiceProtocolData', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'post_json', 'bearer', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "fleet-osquery"
ATTR_PREFIX = "fleet"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

API_BASE = "/api/v1/fleet"
LOGIN_PATH = "/api/v1/fleet/login"
HOSTS_PATH = "/api/v1/fleet/hosts"

MAX_PAGES = 100000
MAX_CHILDREN = 99
MAX_POLICY_NAMES = 25

# Fleet numbers host list pages from zero.
FIRST_PAGE = 0

# Only the tokens Fleet publishes on a Vulnerability are trusted. runZero
# validates cve against this exact pattern and rejects the whole finding when it
# does not match, so anything else is dropped rather than guessed at.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# A dotted numeric token, used to find where an OS name stops and its version
# starts in Fleet's combined os_version string.
VERSION_RE = r"^[0-9]+(\.[0-9]+)*$"

# Software.cpe23 is validated against ^cpe:/a:.*, the CPE 2.2 URI binding for
# applications. Fleet's generated_cpe is the CPE 2.3 formatted string
# ("cpe:2.3:a:gnu:glibc:2.12:*:*:*:*:*:*:*"), which does not match, so the
# prefix is checked at runtime and anything else becomes a custom attribute.
CPE22_APP_PREFIX = "cpe:/a:"
CPE23_APP_PREFIX = "cpe:2.3:a:"

# listening_ports.protocol is the IANA IP protocol number, not a name.
TRANSPORTS = {
    "6": "tcp",
    "17": "udp",
    "132": "sctp",
    "tcp": "tcp",
    "udp": "udp",
    "sctp": "sctp",
}

# Addresses osquery reports for a wildcard bind, which are not usable as a
# runZero service address on their own.
WILDCARD_ADDRESSES = ["", "*", "0.0.0.0", "::", "[::]"]

# osquery reports an all-zero MAC for an interface it could not read. Every host
# in that state would share one MAC, so it is dropped like loopback is.
EMPTY_MAC = "00:00:00:00:00:00"

# Fleet's platform values that identify a phone or tablet rather than a
# general purpose computer. Every other platform is left unmapped so runZero's
# own fingerprinting decides.
MOBILE_PLATFORMS = ["ios", "ipados", "android"]

# Query parameters that older Fleet releases do not understand. They are
# dropped together after a rejected page so the import still runs.
OPTIONAL_PARAMS = ["populate_software", "populate_policies", "populate_labels", "additional_info_filters"]

# Statuses that mean Fleet rejected the request itself rather than the caller.
# Only these justify dropping the optional parameters and trying again: a 401
# or 403 is a credential problem, and a 429 or 5xx is transient and has already
# been retried with backoff by the shared HTTP helper.
PARAM_REJECTED = ["status 400", "status 404", "status 422"]
def _to_int(value):
    """Coerce a numeric value to an int, or -1 when it is not one. int() on a
    non-numeric string is a fatal error in Starlark, so the shape is checked
    first; JSON numbers can arrive as 6 or 6.0 depending on the column type."""
    if type(value) == "int":
        return value
    matched = re_match(r"^([0-9]+)(\.0+)?$", str(value).strip())
    if not matched:
        return -1
    return int(matched.groups[1])


def _to_float(value):
    """Return a numeric value as a float, or -1.0 when it is absent or not a
    number. Fleet serializes an unset score as null."""
    if type(value) in ("int", "float"):
        return float(value)
    return -1.0
def _score_rank(score):
    """Convert a CVSS score to a runZero 0-4 rank using the standard bands."""
    if score < 0.1:
        return 0
    if score < 4.0:
        return 1
    if score < 7.0:
        return 2
    if score < 9.0:
        return 3
    return 4


def split_os_version(os_version, platform):
    """Split Fleet's combined os_version string into an OS name and a version.

    Fleet builds this field itself: non-Windows hosts get "<name> <version>",
    for example "macOS 15.2" or "Ubuntu 20.04.6 LTS", so the first dotted
    numeric token starts the version. Windows hosts get
    "<name> <display version> <build>", and Fleet's own host filters document
    the name as everything except the trailing build number."""
    text = as_text(os_version, join=",").strip()
    parts = [part for part in text.split(" ") if part]
    if len(parts) < 2:
        return text, ""
    if platform == "windows":
        return " ".join(parts[:-1]), parts[-1]
    for index in range(1, len(parts)):
        if re_match(VERSION_RE, parts[index]):
            return " ".join(parts[:index]), " ".join(parts[index:])
    return text, ""


def build_vulnerabilities(ctx, host_id, entry, software_id):
    """Convert the CVEs Fleet matched against one installed software version
    into runZero findings. Fleet does not tie a CVE to a port, so no service
    fields are set. Returns a list of (rank, Vulnerability) pairs."""
    findings = []
    for item in dicts(entry.get("vulnerabilities")):
        cve = as_text(item.get("cve"), join=",").strip().upper()
        if not re_match(CVE_RE, cve):
            continue

        params = {
            "id": "{}:{}:{}:{}:{}".format(VENDOR, ctx["scope"], host_id, software_id, cve),
            "name": cve,
            "cve": cve,
            "category": "CVE",
        }

        description = as_text(item.get("cve_description"), join=",").strip()
        if description:
            params["description"] = description[:1024]

        # Fleet's cvss_score is the NVD CVSS 3.x base score; its own
        # min_cvss_score filter is documented against "CVSS version 3.x base
        # score", so it is recorded as such rather than as a generic severity.
        score = _to_float(item.get("cvss_score"))
        if score >= 0:
            params["cvss3BaseScore"] = score
            params["severityScore"] = score
            params["severityRank"] = _score_rank(score)
            params["riskScore"] = score
            params["riskRank"] = _score_rank(score)

        if item.get("cisa_known_exploit") == True:
            params["exploitable"] = True

        published = parse_ts(item.get("cve_published"))
        if published:
            params["publishedTS"] = published

        resolved = as_text(item.get("resolved_in_version"), join=",").strip()
        product = as_text(entry.get("name"), join=",").strip()
        if resolved and product:
            params["solution"] = "Update {} to {}".format(product, resolved)[:1024]
        elif resolved:
            params["solution"] = "Update to {}".format(resolved)[:1024]

        params["customAttributes"] = to_custom_attributes({
            "details_link": item.get("details_link"),
            "epss_probability": item.get("epss_probability"),
            "cisa_known_exploit": item.get("cisa_known_exploit"),
            "resolved_in_version": resolved,
            "software_name": product,
            "software_version": entry.get("version"),
            "software_source": entry.get("source"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)

        rank = params.get("severityRank", 0)
        findings.append((rank, Vulnerability(**params)))
    return findings


def build_software(ctx, host_id, address, host):
    """Convert the software inventory Fleet collected for one host into
    Software records, and collect the CVEs attached to each entry.

    Returns (software, vulnerabilities). Findings are bucketed by severity rank
    so that the most severe survive the per-asset child cap."""
    software = []
    buckets = [[], [], [], [], []]
    seen = []

    for entry in dicts(host.get("software")):
        product = as_text(entry.get("name"), join=",").strip()
        if not product:
            continue
        version = as_text(entry.get("version"), join=",").strip()
        source = as_text(entry.get("source"), join=",").strip()
        software_id = as_text(entry.get("id"), join=",").strip()

        key = "{}|{}|{}".format(source, product, version)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:software:{}".format(VENDOR, ctx["scope"], software_id or key)[:255],
            "product": product[:255],
            "serviceAddress": address or "127.0.0.1",
        }
        if version:
            params["version"] = version[:255]

        attrs = {
            "software_id": software_id,
            "source": source,
            "bundle_identifier": entry.get("bundle_identifier"),
            "extension_for": entry.get("extension_for"),
            "browser": entry.get("browser"),
            "last_opened_at": entry.get("last_opened_at"),
            "installed_paths": entry.get("installed_paths"),
        }

        # Fleet publishes the CPE 2.3 formatted string, which fails runZero's
        # ^cpe:/a:.* check on Software.cpe23, so only a genuine 2.2 application
        # URI is assigned and everything else is kept as an attribute. The 2.3
        # form still yields a real vendor token, which is the only vendor Fleet
        # exposes for an installed package.
        cpe = as_text(entry.get("generated_cpe"), join=",").strip()
        if cpe:
            attrs["cpe"] = cpe
            if cpe.startswith(CPE22_APP_PREFIX):
                params["cpe23"] = cpe
            if cpe.startswith(CPE23_APP_PREFIX):
                fields = cpe.split(":")
                if len(fields) > 3 and fields[3] not in ("", "*", "-"):
                    params["vendor"] = fields[3].replace("_", " ")[:255]

        paths = entry.get("installed_paths")
        if type(paths) == "list" and paths and as_text(paths[0], join=",").strip():
            params["installedFrom"] = as_text(paths[0], join=",").strip()[:255]

        params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))

        if ctx["vulnerabilities"]:
            for rank, finding in build_vulnerabilities(ctx, host_id, entry, software_id or key):
                buckets[rank].append(finding)

    vulns = []
    for rank in [4, 3, 2, 1, 0]:
        vulns.extend(buckets[rank])
    return software, vulns


def build_services(ctx, address, host):
    """Build Service objects from the listening_ports rows Fleet collected
    through its additional-query mechanism. Fleet stores each additional query
    result as the raw osquery rows under host.additional[<query name>]."""
    rows = dicts(as_dict(host.get("additional")).get(ctx["ports_query"]))
    if not rows:
        return []

    services = []
    seen = []
    for row in rows:
        transport = TRANSPORTS.get(as_text(row.get("protocol"), join=",").strip().lower())
        if not transport:
            continue
        port = _to_int(row.get("port"))
        if port < 1 or port > 65535:
            continue

        # osquery reports a wildcard bind as 0.0.0.0 or ::, which is not a
        # usable service address, so the host's primary address stands in.
        bound = as_text(row.get("address"), join=",").strip()
        listen = address if bound in WILDCARD_ADDRESSES else routable_ip(bound)
        if not listen:
            continue

        key = "{}|{}|{}".format(listen, port, transport)
        if key in seen:
            continue
        seen.append(key)

        services.append(Service(
            address=listen,
            port=int(port),
            transport=transport,
            protocolData=[ServiceProtocolData(name="osquery", attributes={
                "pid": as_text(row.get("pid"), join=","),
                "path": as_text(row.get("path"), join=","),
                "family": as_text(row.get("family"), join=","),
                "bound_address": bound,
            })],
        ))
    return services


def build_policy_state(host):
    """Summarize the host's policy results into (tags, attrs)."""
    failing = []
    passing = 0
    critical_failing = 0
    for policy in dicts(host.get("policies")):
        name = as_text(policy.get("name"), join=",").strip()
        response = as_text(policy.get("response"), join=",").strip().lower()
        if response == "pass":
            passing += 1
        elif response == "fail" and name:
            failing.append(name)
            if policy.get("critical") == True:
                critical_failing += 1

    tags = []
    if failing:
        tags.append("policy:failing")
    attrs = {
        "policies_failing": failing[:MAX_POLICY_NAMES],
        "policies_failing_count": len(failing),
        "policies_passing_count": passing,
        "policies_critical_failing_count": critical_failing,
    }
    return tags, attrs


def build_label_state(host):
    """Summarize the host's label membership into (tags, attrs). Only the
    user-created labels become tags; Fleet's builtin labels are membership
    bookkeeping such as "All Hosts" and would be noise on every asset."""
    names = []
    tags = []
    for label in dicts(host.get("labels")):
        name = as_text(label.get("name"), join=",").strip()
        if not name:
            continue
        names.append(name)
        if as_text(label.get("label_type"), join=",").strip().lower() == "regular":
            tags.append("label:" + name)
    return tags, {"labels": dedupe(names)}


def fetch_host_detail(ctx, host_id):
    """Fetch one per-host detail document. Software is excluded because the
    list response already carries it. A failure is reported and treated as an
    empty document so a single unreadable host cannot end the run."""
    url = "{}{}/{}".format(ctx["base_url"], HOSTS_PATH, host_id)
    data, err = get_json(url, params={"exclude_software": "true"}, **ctx["http_options"])
    if err:
        print("fleet-osquery: failed to fetch detail for host {}: {}".format(host_id, err))
        return {}
    return as_dict(as_dict(data).get("host"))


def build_asset(ctx, record):
    """Convert one Fleet host record into a runZero asset."""
    host_id = record.get("id")

    host = record
    enriched = False
    if ctx["host_detail"]:
        if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        else:
            ctx["detail_used"] += 1
            detail = fetch_host_detail(ctx, host_id)
            if detail:
                enriched = True
                host = dict(record)
                # The detail response omits software when exclude_software is
                # set, so the list response's inventory must survive the merge.
                detail.pop("software", None)
                host.update(detail)

    platform = as_text(host.get("platform"), join=",").strip().lower()
    os_name, os_version = split_os_version(host.get("os_version"), platform)

    primary_ip = routable_ip(host.get("primary_ip"))
    primary_mac = as_text(host.get("primary_mac"), join=",").strip()
    if normalize_mac(primary_mac) == EMPTY_MAC:
        primary_mac = ""
    nic = network_interface(mac=primary_mac, ips=[primary_ip] if primary_ip else [])
    netifs = [nic] if nic else []

    hostnames = dedupe([
        host.get("hostname"),
        host.get("computer_name"),
        host.get("display_name"),
    ])

    serial = as_text(host.get("hardware_serial"), join=",").strip()
    team = as_text(host.get("team_name"), join=",").strip() or as_text(host.get("fleet_name"), join=",").strip()
    mdm = as_dict(host.get("mdm"))
    issues = as_dict(host.get("issues"))
    geo = as_dict(host.get("geolocation"))

    software = []
    vulns = []
    if ctx["software"]:
        software, vulns = build_software(ctx, host_id, primary_ip, host)
    services = build_services(ctx, primary_ip, host) if ctx["ports_query"] else []

    tags = [VENDOR]
    if platform:
        tags.append("platform:" + platform)
    if team:
        tags.append("team:" + team)
    if serial:
        tags.append("serial:" + serial)

    attrs = {
        "host_id": host_id,
        "uuid": host.get("uuid"),
        "hardware_serial": serial,
        "hardware_model": host.get("hardware_model"),
        "hardware_vendor": host.get("hardware_vendor"),
        "hardware_version": host.get("hardware_version"),
        "computer_name": host.get("computer_name"),
        "display_name": host.get("display_name"),
        "platform": platform,
        "platform_like": host.get("platform_like"),
        "os_version": host.get("os_version"),
        "build": host.get("build"),
        "code_name": host.get("code_name"),
        "osquery_version": host.get("osquery_version"),
        "orbit_version": host.get("orbit_version"),
        "fleet_desktop_version": host.get("fleet_desktop_version"),
        "scripts_enabled": host.get("scripts_enabled"),
        "status": host.get("status"),
        "team_id": host.get("team_id"),
        "team_name": team,
        "primary_ip": host.get("primary_ip"),
        "primary_mac": host.get("primary_mac"),
        # public_ip is the NAT egress address the host was last seen from. It is
        # recorded but never becomes an interface: an entire office shares it.
        "public_ip": host.get("public_ip"),
        "cpu_type": host.get("cpu_type"),
        "cpu_brand": host.get("cpu_brand"),
        "cpu_physical_cores": host.get("cpu_physical_cores"),
        "cpu_logical_cores": host.get("cpu_logical_cores"),
        "memory": host.get("memory"),
        "uptime": host.get("uptime"),
        "gigs_total_disk_space": host.get("gigs_total_disk_space"),
        "gigs_disk_space_available": host.get("gigs_disk_space_available"),
        "percent_disk_space_available": host.get("percent_disk_space_available"),
        "disk_encryption_enabled": host.get("disk_encryption_enabled"),
        "created_at": host.get("created_at"),
        "updated_at": host.get("updated_at"),
        "seen_time": host.get("seen_time"),
        "detail_updated_at": host.get("detail_updated_at"),
        "software_updated_at": host.get("software_updated_at"),
        "policy_updated_at": host.get("policy_updated_at"),
        "label_updated_at": host.get("label_updated_at"),
        "last_enrolled_at": host.get("last_enrolled_at"),
        "last_restarted_at": host.get("last_restarted_at"),
        "mdm_enrollment_status": mdm.get("enrollment_status"),
        "mdm_name": mdm.get("name"),
        "mdm_server_url": mdm.get("server_url"),
        "mdm_connected_to_fleet": mdm.get("connected_to_fleet"),
        "mdm_encryption_key_available": mdm.get("encryption_key_available"),
        "mdm_device_status": mdm.get("device_status"),
        "mdm_disk_encryption": as_dict(as_dict(mdm.get("os_settings")).get("disk_encryption")).get("status"),
        "failing_policies_count": issues.get("failing_policies_count"),
        "critical_vulnerabilities_count": issues.get("critical_vulnerabilities_count"),
        "total_issues_count": issues.get("total_issues_count"),
        "geolocation_country_iso": geo.get("country_iso"),
        "geolocation_city_name": geo.get("city_name"),
        "software_count": len(software),
        "service_count": len(services),
        "vulnerability_count": len(vulns),
        "detail_enriched": "true" if enriched else "false",
    }

    if host.get("disk_encryption_enabled") == True:
        tags.append("disk-encryption:on")
    elif host.get("disk_encryption_enabled") == False:
        tags.append("disk-encryption:off")

    enrollment = as_text(mdm.get("enrollment_status"), join=",").strip()
    if enrollment:
        tags.append("mdm:" + enrollment)

    if ctx["labels"]:
        label_tags, label_attrs = build_label_state(host)
        tags.extend(label_tags)
        attrs.update(label_attrs)
    if ctx["policies"]:
        policy_tags, policy_attrs = build_policy_state(host)
        tags.extend(policy_tags)
        attrs.update(policy_attrs)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], host_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
        "services": services[:MAX_CHILDREN],
        "vulnerabilities": vulns[:MAX_CHILDREN],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),    }
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    manufacturer = as_text(host.get("hardware_vendor"), join=",").strip()
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = as_text(host.get("hardware_model"), join=",").strip()
    if model:
        params["model"] = model
    if platform in MOBILE_PLATFORMS:
        params["deviceType"] = "Mobile Device"
    elif "server" in as_text(host.get("os_version"), join=",").lower():
        params["deviceType"] = "Server"

    first_seen = parse_ts(host.get("created_at"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = parse_ts(host.get("seen_time")) or parse_ts(host.get("detail_updated_at"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(ctx, records):
    """Convert a page of Fleet host records into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        host_id = record.get("id")
        if host_id == None or as_text(host_id, join=",").strip() == "":
            print("fleet-osquery: skipping host with no id: hostname=" + as_text(record.get("hostname"), join=","))
            continue
        assets.append(build_asset(ctx, record))
    return assets


def list_params(ctx, page):
    """Build the query parameters for one page of the host list."""
    params = {
        "page": str(page),
        "per_page": str(ctx["page_size"]),
        "order_key": "id",
        "order_direction": "asc",
    }
    if ctx["reduced"]:
        return params
    if ctx["software"]:
        # "true" adds the CVSS score, publication date, and description that
        # Fleet Premium attaches to each CVE; the cheaper form still lists which
        # CVEs apply, so it is used whenever findings are not being imported.
        params["populate_software"] = "true" if ctx["vulnerabilities"] else "without_vulnerability_details"
    if ctx["policies"]:
        params["populate_policies"] = "true"
    if ctx["labels"]:
        params["populate_labels"] = "true"
    if ctx["ports_query"]:
        params["additional_info_filters"] = ctx["ports_query"]
    return params


def _param_rejected(err):
    """Report whether the error means Fleet refused a query parameter."""
    for prefix in PARAM_REJECTED:
        if err.startswith(prefix):
            return True
    return False


def fetch_hosts_page(ctx, page):
    """Fetch one page of hosts, returning (records, err).

    Fleet is self-hosted, so a server can predate the populate_* parameters.
    A request rejected as invalid is retried once without the optional
    parameters, and the rest of the run then stays on the reduced set. A
    transient or credential failure is passed straight back instead."""
    url = ctx["base_url"] + HOSTS_PATH
    data, err = get_json(url, params=list_params(ctx, page), **ctx["http_options"])
    if err and not ctx["reduced"] and _param_rejected(err):
        ctx["reduced"] = True
        print("fleet-osquery: the server rejected {}, retrying without them: {}".format(
            ",".join(OPTIONAL_PARAMS), err))
        data, err = get_json(url, params=list_params(ctx, page), **ctx["http_options"])
    if err:
        return [], err
    return dicts(as_dict(data).get("hosts")), None


def fetch_and_report_hosts(ctx):
    """Fetch and stream hosts one page at a time so the full inventory is never
    held in memory at once. Fleet numbers pages from zero and returns no total,
    so paging stops on the first short or empty page."""
    reported = 0
    for page in range(FIRST_PAGE, FIRST_PAGE + MAX_PAGES):
        records, err = fetch_hosts_page(ctx, page)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("fleet-osquery: authentication to the Fleet server failed:", err)
            else:
                print("fleet-osquery: failed to fetch hosts:", err)
            return reported
        if not records:
            break

        reported += report_assets(build_assets(ctx, records))
        print("fleet-osquery: reported {} assets so far".format(reported))
        if len(records) < ctx["page_size"]:
            break

    if ctx["detail_skipped"]:
        print("fleet-osquery: detail limit of {} reached; disk encryption and MDM detail were not imported for {} of {} hosts".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    return reported


def login(base_url, http_options, email, password):
    """Exchange Fleet user credentials for a session token."""
    # A retried login mints an extra session, so only the statuses that mean the
    # request was rejected unprocessed are retried. Fleet rate limits this
    # endpoint and returns retry-after, which the helper honors.
    data, err = post_json(base_url + LOGIN_PATH, json={"email": email, "password": password},
                          retry_on=[429, 503], **http_options)
    if err:
        print("fleet-osquery: login failed:", err)
        return ""
    return as_text(as_dict(data).get("token"), join=",").strip()


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("fleet-osquery: could not determine the Fleet server host from the configured URL")
        return None

    headers = {"Accept": "application/json"}
    token = get_string(kwargs, "api_token", default="").strip()
    if not token:
        email = get_string(kwargs, "email", default="").strip()
        password = get_string(kwargs, "password", default="")
        if not email or not password:
            print("fleet-osquery: supply either an API token or a Fleet user email and password")
            return None
        token = login(base_url, get_http_options(kwargs, headers=headers), email, password)
        if not token:
            return None
    headers["Authorization"] = bearer(token)

    detail_limit = get_int(kwargs, "detail_limit", default=500)
    if detail_limit < 0:
        detail_limit = 0

    software = get_bool(kwargs, "include_software", default=True)
    vulnerabilities = get_bool(kwargs, "include_vulnerabilities", default=False)
    if vulnerabilities and not software:
        print("fleet-osquery: CVE findings are attached to installed software, enabling software import")
        software = True

    ctx = {
        "base_url": base_url,
        "http_options": get_http_options(kwargs, headers=headers),
        "scope": scope,
        "page_size": get_int(kwargs, "page_size", default=100),
        "software": software,
        "vulnerabilities": vulnerabilities,
        "labels": get_bool(kwargs, "include_labels", default=True),
        "policies": get_bool(kwargs, "include_policies", default=True),
        "ports_query": get_string(kwargs, "listening_ports_query", default="").strip(),
        "host_detail": get_bool(kwargs, "include_host_detail", default=False),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "reduced": False,
    }

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("fleet-osquery: no assets retrieved")
    return None

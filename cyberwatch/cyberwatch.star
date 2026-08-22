# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cyberwatch",
    "name": "Cyberwatch",
    "type": "inbound",
    "description": "Imports IT and OT assets, installed software, listening services, and CVE findings from Cyberwatch.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The Cyberwatch server id is authoritative for the appliance, but the
    # API publishes no MAC at all, and IPs and names only arrive through the
    # optional detail call, so network churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Cyberwatch master scanner URL",
            "type": "url",
            "required": True,
            "placeholder": "https://192.168.0.1",
            "description": "Base URL of the Cyberwatch master scanner. The /api/v3/ path is appended automatically.",
        },
        {
            "key": "api_access_key",
            "label": "API access key",
            "type": "string",
            "required": True,
            "description": "Cyberwatch API access key, generated from the profile page of an administrator account.",
        },
        {
            "key": "api_secret_key",
            "label": "API secret key",
            "type": "secret",
            "required": True,
            "description": "Cyberwatch API secret key issued alongside the access key.",
        },
        {
            "key": "include_details",
            "label": "Import software, services, and CVEs",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch the two per-asset detail endpoints. Costs two extra requests per asset; disable it to import inventory only.",
        },
        {
            "key": "detail_limit",
            "label": "Detail enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of assets to enrich with detail. Assets past the limit are still imported, without software, services, or CVEs. 0 removes the cap.",
        },
        {
            "key": "category",
            "label": "Asset category filter",
            "type": "string",
            "required": False,
            "description": "Optional Cyberwatch category to restrict the import to, for example industrial_device. Leave blank to import every category.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_time', 'now', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "cyberwatch"
ATTR_PREFIX = "cyberwatch"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
VULN_PATH = "/api/v3/vulnerabilities/servers"
ASSET_PATH = "/api/v3/assets/servers"
PAGE_SIZE = 500         # per_page defaults to 30 server-side; the maximum is undocumented
HTTP_RETRIES = 3
MAX_CHILDREN = 99
DIGITS = "0123456789"
TRANSPORTS = ["tcp", "udp", "sctp"]
# Vulnerability.cve is validated against this pattern by the platform and a
# value that misses it fails the whole ImportAsset, which aborts the run and
# loses every asset already parsed. Cyberwatch files vendor bulletins and its
# own CW- identifiers in cve_announcements alongside real CVEs, so a code is
# screened before it is assigned.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# Cyberwatch asset categories, mapped onto the device type vocabulary runZero
# already uses. Categories with no faithful equivalent are left unmapped and
# survive as the cyberwatch_category custom attribute.
DEVICE_TYPES = {
    "server": "Server",
    "desktop": "Desktop",
    "hypervisor": "Hypervisor",
    "network_device": "Network Device",
    "industrial_device": "Industrial Control System",
    "docker_image": "Container",
    "mobile": "Mobile Device",
}

# A Windows KB is a patch rather than an application, so KB packages are sorted
# behind the real applications and only fill whatever room is left under the
# per-asset child cap.
PATCH_PACKAGE_TYPES = ["Packages::Kb"]

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


def _to_float(value):
    """Return a positive numeric value as a float, or -1.0 when it is absent or
    not a number. Cyberwatch serializes an unset score as null."""
    if type(value) in ("int", "float"):
        return float(value)
    return -1.0
def _base_url(kwargs):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used: it keeps only the scheme and host and
    discards the path -- verified against the scanner, https://proxy/cyberwatch
    comes back as https://proxy. Cyberwatch's master node is regularly published
    through a reverse proxy under a path prefix, and dropping it would send every
    /api/v3 request to the wrong place on those installs. librenms, netdisco and
    slurpit avoid it for the same reason.
    """
    return get_string(kwargs, "url", default="").strip().rstrip("/")
def split_addresses(addresses):
    """Split the untyped Cyberwatch addresses list into (ips, hostnames). The
    field mixes both — ["WIN-GNVEC8UIKUD", "127.0.0.1"] is a real sample — so
    every element is sniffed with ip_address(). Loopback and link-local
    addresses are dropped from the IP side but stay in the raw attribute."""
    ips = []
    hostnames = []
    for entry in addresses if type(addresses) == "list" else []:
        text = as_text(entry, join=",").strip()
        if not text:
            continue
        if ip_address(text) != None:
            routable = routable_ip(text)
            if routable:
                ips.append(routable)
            continue
        hostnames.append(text)
    return dedupe(ips), dedupe(hostnames)


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


def build_update_index(updates):
    """Index the asset's pending updates by CVE code so each finding can carry
    the remediation Cyberwatch already knows about. One update commonly fixes
    several CVEs, and one CVE can be fixed by several updates."""
    index = {}
    for update in dicts(updates):
        target = update.get("target")
        if type(target) != "dict":
            continue
        product = as_text(target.get("product"), join=",").strip()
        if not product:
            continue
        current = update.get("current")
        from_version = ""
        if type(current) == "dict":
            from_version = as_text(current.get("version"), join=",").strip()
        to_version = as_text(target.get("version"), join=",").strip()
        if from_version and to_version:
            fix = "Update {} from {} to {}".format(product, from_version, to_version)
        elif to_version:
            fix = "Install {} {}".format(product, to_version)
        else:
            fix = "Install {}".format(product)
        if update.get("patchable") == False:
            fix += " (no patch published by the vendor yet)"
        for code in update.get("cve_announcements", []) or []:
            key = as_text(code, join=",").strip().upper()
            if not key:
                continue
            if key not in index:
                index[key] = []
            if fix not in index[key]:
                index[key].append(fix)
    return index


def build_vulnerabilities(ctx, server_id, detail):
    """Convert the CVE announcements Cyberwatch records against one asset into
    runZero findings. Remediated announcements are skipped: they carry a
    fixed_at date or active=false, and importing them would show closed
    findings as open. Cyberwatch cannot tie a CVE to a port, so no service
    fields are set on the finding."""
    announcements = dicts(detail.get("cve_announcements"))
    if not announcements:
        return [], 0

    fixes = build_update_index(detail.get("updates"))
    last_detected = parse_ts(detail.get("analyzed_at")) or parse_ts(detail.get("last_communication"))

    vulns = []
    fixed = 0
    for entry in announcements:
        code = as_text(entry.get("cve_code"), join=",").strip().upper()
        if not code:
            continue
        if entry.get("active") == False or as_text(entry.get("fixed_at"), join=",").strip():
            fixed += 1
            continue

        params = {
            "id": "{}:{}:{}:cve:{}".format(VENDOR, ctx["scope"], server_id, code),
            "name": code,
            "category": "CVE",
        }
        # Only a value the platform will accept reaches the cve field. The
        # finding is still imported either way: it keeps the raw code as its
        # name and as the cyberwatch_cve_code attribute below.
        if re_match(CVE_RE, code):
            params["cve"] = code

        # The per-asset announcement carries a single merged "score" with no
        # CVSS version attached — only the CVE catalog endpoint splits it into
        # score_v2 and score_v3 — so it drives severity rather than being
        # guessed into cvss3BaseScore.
        score = _to_float(entry.get("score"))
        if score >= 0:
            params["severityScore"] = score
            params["severityRank"] = _score_rank(score)

        # Cyberwatch's environmental score is the CVSS environmental metric
        # recomputed against the asset's declared C/I/A requirements, which is
        # exactly runZero's notion of risk: severity in context.
        environmental = _to_float(entry.get("environmental_score"))
        risk = environmental if environmental >= 0 else score
        if risk >= 0:
            params["riskScore"] = risk
            params["riskRank"] = _score_rank(risk)

        published = parse_ts(entry.get("published"))
        if published:
            params["publishedTS"] = published
        detected = parse_ts(entry.get("detected_at"))
        if detected:
            params["firstDetectedTS"] = detected
        if last_detected:
            params["lastDetectedTS"] = last_detected

        solutions = fixes.get(code, [])
        if solutions:
            params["solution"] = "\n".join(solutions)[:1024]

        params["customAttributes"] = to_custom_attributes({
            "cve_code": code,
            "score": entry.get("score"),
            "environmental_score": entry.get("environmental_score"),
            "epss": entry.get("epss"),
            "comment": entry.get("comment"),
            "prioritized": entry.get("prioritized"),
            "ignored": entry.get("ignored"),
            "active": entry.get("active"),
            "detected_at": entry.get("detected_at"),
            "published": entry.get("published"),
            "patch_available": "true" if solutions else "false",
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        vulns.append(Vulnerability(**params))

    return vulns, fixed


def build_software(ctx, server_id, address, detail):
    """Convert the installed packages Cyberwatch inventories on one asset into
    Software records. Applications are emitted first so that Windows KB
    entries, which are patches rather than applications, only consume whatever
    room is left under the per-asset child cap."""
    applications = []
    patches = []
    for package in dicts(detail.get("packages")):
        product = as_text(package.get("product"), join=",").strip()
        if not product:
            continue
        package_type = as_text(package.get("type"), join=",").strip()
        version = as_text(package.get("version"), join=",").strip()

        params = {
            "id": "{}:{}:{}:package:{}:{}".format(VENDOR, ctx["scope"], server_id, package_type, product),
            "product": product,
            "serviceAddress": address or "127.0.0.1",
        }
        vendor = as_text(package.get("vendor"), join=",").strip()
        if vendor:
            params["vendor"] = vendor
        if version:
            params["version"] = version
        # Cyberwatch publishes no CPE on a package, so cpe23 is deliberately
        # left unset rather than synthesized.
        params["customAttributes"] = to_custom_attributes({
            "package_type": package_type,
            "package_active": package.get("active"),
            # paths carries the dpkg selection state ("ii") for Debian packages,
            # not a filesystem path, so it is recorded rather than mapped.
            "package_paths": package.get("paths"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)

        if package_type in PATCH_PACKAGE_TYPES:
            patches.append(Software(**params))
        else:
            applications.append(Software(**params))

    return applications + patches


def _port_entry(entry):
    """Extract (port, transport, product, version) from one ports[] element.
    The documented shape is {port, protocol, package}, where package is the
    full package object that owns the socket. Other element types are still
    accepted because the published contract predates the current release."""
    if type(entry) == "int":
        return entry, "", "", ""

    if type(entry) != "dict":
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
        return port, transport, "", ""

    port = -1
    for key in ("port", "number", "port_number"):
        candidate = _to_int(entry.get(key, -1))
        if candidate >= 0:
            port = candidate
            break

    transport = ""
    for key in ("protocol", "transport", "proto"):
        named = entry.get(key)
        if named:
            transport = str(named).strip().lower()
            break
    if transport not in TRANSPORTS:
        transport = ""

    # ports[] carries a back-reference to the full package object that owns the
    # socket, which is the best available name for the listener.
    product = ""
    version = ""
    package = entry.get("package")
    if type(package) == "dict":
        product = as_text(package.get("product"), join=",").strip()
        version = as_text(package.get("version"), join=",").strip()
    elif package != None:
        product = as_text(package, join=",").strip()
    if not product:
        for key in ("name", "product", "service"):
            named = as_text(entry.get(key), join=",").strip()
            if named:
                product = named
                break

    return port, transport, product, version


def build_service_states(detail):
    """Summarize the asset's system services. Cyberwatch's services[] holds
    operating system service units — {name, status, updated_at} — with no port
    and no protocol, so they are not network services and cannot become Service
    objects. They are recorded as "name:status" pairs instead."""
    states = []
    for entry in detail.get("services") if type(detail.get("services")) == "list" else []:
        if type(entry) != "dict":
            states.append(as_text(entry, join=",").strip())
            continue
        name = as_text(entry.get("name"), join=",").strip()
        if not name:
            continue
        status = as_text(entry.get("status"), join=",").strip()
        states.append("{}:{}".format(name, status) if status else name)
    return dedupe(states)


def build_services(address, detail):
    """Build Service objects from the asset's open ports. Entries that name no
    transport are recorded as tcp and flagged, and an entry that resolves to no
    usable port is skipped rather than guessed at. A services[] element is
    considered too, but only in case a future release starts publishing a port
    there; today it never carries one."""
    if not address:
        return []

    raw = detail.get("ports") if type(detail.get("ports")) == "list" else []
    if type(detail.get("services")) == "list":
        raw = raw + detail.get("services")

    services = []
    seen = []
    for entry in raw:
        port, transport, product, version = _port_entry(entry)
        if port < 1 or port > 65535:
            continue
        assumed = transport == ""
        if assumed:
            transport = "tcp"
        key = "{}/{}".format(port, transport)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "address": address,
            "port": int(port),
            "transport": transport,
            "customAttributes": to_custom_attributes({
                "transport_source": "assumed" if assumed else "reported",
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        if product:
            params["product"] = product
        if version:
            params["version"] = version
        services.append(Service(**params))

    return services


def fetch_detail(ctx, path, server_id):
    """Fetch one per-asset detail document. A failure is reported and treated as
    an empty document so a single unreadable asset cannot end the run."""
    url = ctx["base_url"] + path + "/" + str(server_id)
    data, err = get_json(url, **ctx["http_options"])
    if err:
        print("cyberwatch: failed to fetch {} for asset {}: {}".format(path, server_id, err))
        return {}
    if type(data) != "dict":
        return {}
    return data


def build_asset(ctx, record):
    """Convert one Cyberwatch server record into a runZero asset, optionally
    enriched from the two per-asset detail endpoints."""
    server_id = record.get("id")

    detail = {}
    enriched = False
    if ctx["include_details"]:
        if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        else:
            ctx["detail_used"] += 1
            enriched = True
            # The vulnerability view carries addresses, CVE announcements, and
            # pending updates; the asset view carries packages, ports, services,
            # and hardware metadata. Neither is a superset of the other.
            detail = dict(record)
            detail.update(fetch_detail(ctx, VULN_PATH, server_id))
            detail.update(fetch_detail(ctx, ASSET_PATH, server_id))
    if not detail:
        detail = record

    addresses = detail.get("addresses")
    ips, extra_hostnames = split_addresses(addresses)
    nic = network_interface(ips=ips)
    netifs = [nic] if nic else []
    address = ips[0] if ips else ""

    hostname = as_text(record.get("hostname"), join=",").strip()
    hostnames = dedupe([hostname] + extra_hostnames)

    category = as_text(record.get("category"), join=",").strip()
    groups = [as_text(group.get("name"), join=",").strip() for group in dicts(record.get("groups"))]
    environment = record.get("environment") if type(record.get("environment")) == "dict" else {}
    os_info = record.get("os") if type(record.get("os")) == "dict" else {}
    connector = detail.get("connector") if type(detail.get("connector")) == "dict" else {}

    tags = [VENDOR]
    if category:
        tags.append("category:" + category)
    if category == "industrial_device":
        # OT assets are the reason a Cyberwatch import is interesting alongside
        # runZero's own discovery, so they are tagged for direct search.
        tags.append("ot")
        tags.append("industrial-device")
    environment_name = as_text(environment.get("name"), join=",").strip()
    if environment_name:
        tags.append("environment:" + environment_name)
    for group in groups:
        if group:
            tags.append("group:" + group)

    vulns = []
    fixed_count = 0
    software = []
    services = []
    service_states = []
    if enriched:
        vulns, fixed_count = build_vulnerabilities(ctx, server_id, detail)
        software = build_software(ctx, server_id, address, detail)
        services = build_services(address, detail)
        service_states = build_service_states(detail)

    attrs = {
        "server_id": server_id,
        "scanner": ctx["scope"],
        "category": category,
        "description": record.get("description"),
        "status": record.get("status"),
        "reboot_required": record.get("reboot_required"),
        "boot_at": record.get("boot_at"),
        "analyzed_at": record.get("analyzed_at"),
        "last_communication": record.get("last_communication"),
        "created_at": record.get("created_at"),
        "addresses": addresses,
        "os_key": os_info.get("key"),
        "os_arch": os_info.get("arch"),
        "os_short_name": os_info.get("short_name"),
        "os_type": os_info.get("type"),
        "os_eol": os_info.get("eol"),
        "environment": environment_name,
        "environment_confidentiality": environment.get("confidentiality_requirement"),
        "environment_integrity": environment.get("integrity_requirement"),
        "environment_availability": environment.get("availability_requirement"),
        "groups": groups,
        # The list view names this compliance_groups and the detail view names
        # it compliance_repositories; both hold the same catalogue names.
        "compliance_repositories": [as_text(item.get("name"), join=",").strip() for item in dicts(detail.get("compliance_repositories"))],
        "compliance_groups": [as_text(item.get("name"), join=",").strip() for item in dicts(record.get("compliance_groups"))],
        "cve_announcements_count": record.get("cve_announcements_count"),
        "prioritized_cve_announcements_count": record.get("prioritized_cve_announcements_count"),
        "updates_count": record.get("updates_count"),
        "detail_enriched": "true" if enriched else "false",
    }
    if enriched:
        attrs["cve_fixed_count"] = fixed_count
        attrs["package_count"] = len(software)
        attrs["port_count"] = len(services)
        attrs["connector_type"] = connector.get("type")
        attrs["connector_id"] = connector.get("id")
        for item in dicts(detail.get("metadata")):
            key = as_text(item.get("key"), join=",").strip().replace("-", "_")
            if key:
                attrs["metadata_" + key] = item.get("value")
        for issue in dicts(detail.get("security_issues")):
            sid = as_text(issue.get("sid"), join=",").strip()
            if sid:
                tags.append("security-issue:" + sid)
        if service_states:
            attrs["service_count"] = len(service_states)
            attrs["services"] = service_states

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], server_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
        "services": services[:MAX_CHILDREN],
        "vulnerabilities": vulns[:MAX_CHILDREN],    }

    os_name = as_text(os_info.get("name"), join=",").strip() or as_text(os_info.get("short_name"), join=",").strip()
    if os_name:
        params["os"] = os_name
    device_type = DEVICE_TYPES.get(category, "")
    if device_type:
        params["deviceType"] = device_type

    first_ts = parse_ts(record.get("created_at"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    last_ts = parse_ts(record.get("last_communication"))

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset


def build_assets(ctx, records):
    """Convert a page of Cyberwatch server records into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        server_id = record.get("id")
        if server_id == None or str(server_id).strip() == "":
            print("cyberwatch: skipping server with no id: hostname=" + as_text(record.get("hostname"), join=","))
            continue
        assets.append(build_asset(ctx, record))
    return assets


def fetch_and_report_servers(ctx):
    """Fetch and stream servers one page at a time so the full inventory is
    never held in memory at once. Cyberwatch reports the result count in the
    x-total and x-per-page response headers, but get_json does not expose
    response headers, so paging instead stops on the first short or empty page.
    The page size is learned from the first response rather than assumed to be
    the requested per_page, so a server-side cap cannot truncate the import."""
    url = ctx["base_url"] + VULN_PATH
    reported = 0
    page_size = 0
    _pager = pager("cyberwatch")
    while _pager.next():
        page = _pager.page
        params = {"page": str(page), "per_page": str(PAGE_SIZE)}
        if ctx["category"]:
            params["category"] = ctx["category"]

        data, err = get_json(url, params=params, **ctx["http_options"])
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("cyberwatch: authentication to the master scanner failed:", err)
            else:
                print("cyberwatch: failed to fetch servers:", err)
            return reported

        records = data if type(data) == "list" else []
        if not records:
            break

        reported += report_assets(build_assets(ctx, records))
        if page_size == 0:
            page_size = len(records)
        if len(records) < page_size:
            break

    print("cyberwatch: reported {} assets".format(reported))
    if ctx["detail_skipped"]:
        print("cyberwatch: detail limit of {} reached; software, services, and CVEs were not imported for {} of {} assets".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    return reported


def main(**kwargs):
    base_url = _base_url(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("cyberwatch: could not determine the master scanner host from the configured URL")
        return None

    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(get_string(kwargs, "api_access_key"), get_string(kwargs, "api_secret_key")),
        "Accept": "application/json",
    })
    # get_json retries the transient statuses (408/425/429/5xx) with backoff and
    # honors Retry-After. Three retries is the built-in default; it is set
    # explicitly here so the count is visible next to the other tuning.
    http_options["retries"] = HTTP_RETRIES

    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "base_url": base_url,
        "http_options": http_options,
        "scope": scope,
        "category": get_string(kwargs, "category", default="").strip(),
        "include_details": get_bool(kwargs, "include_details", default=True),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
    }

    reported = fetch_and_report_servers(ctx)
    if not reported:
        print("cyberwatch: no assets retrieved")
    return None

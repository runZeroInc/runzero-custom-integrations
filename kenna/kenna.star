# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-kenna",
    "name": "Kenna Security",
    "type": "inbound",
    "description": "Imports assets, services, and vulnerabilities from Kenna Security (Cisco Vulnerability Management).",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Kenna's asset id is stable and authoritative, but its MAC, IP, and
    # hostname are second-hand: they are whatever the last upstream
    # connector reported, they are frequently null, and they can be months
    # stale. They should corroborate a merge, never disqualify one.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Kenna API URL",
            "type": "url",
            "required": True,
            "default": "https://api.kennasecurity.com",
            "placeholder": "https://api.kennasecurity.com",
            "description": "Base URL of the Kenna API. Regional instances use their own hostname; match the subdomain of your Kenna UI.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Kenna API key, sent as the X-Risk-Token header. Generated under Settings then API Keys.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch the vulnerabilities for each page of assets and attach them to the matching asset.",
        },
        {
            "key": "asset_status",
            "label": "Asset status",
            "type": "enum",
            "required": False,
            "options": ["active", "inactive", "all"],
            "default": "active",
            "description": "Which Kenna asset statuses to import. Inactive assets are ones Kenna no longer considers part of the estate.",
        },
        {
            "key": "min_risk_meter_score",
            "label": "Minimum asset risk meter score",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "max": 1000,
            "description": "Only import assets scoring at or above this value on Kenna's 0-1000 asset risk meter. Zero imports every asset.",
        },
        {
            "key": "include_non_network_assets",
            "label": "Import non-network assets",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import assets whose primary locator is a URL, file, database, or application. These are not network hosts.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 5000,
            "description": "Records requested per page. Kenna serves at most 20 pages per search, so raise this to reach a larger inventory.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'ServiceProtocolData', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'ip_address', 'ip_in_network', 'normalize_mac')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_text')
ASSETS_SEARCH_PATH = "/assets/search"
VULNERABILITIES_SEARCH_PATH = "/vulnerabilities/search"

# Every Kenna search endpoint stops at 20 pages, whatever the page size.
MAX_PAGES = 20
DEFAULT_PAGE_SIZE = 500

# /assets/search allows 50000 per page and /vulnerabilities/search allows 5000.
# One page size drives both, so the smaller ceiling is the one that applies.
MAX_PAGE_SIZE = 5000

# Asset ids sent in a single asset[id][] vulnerability query. One hundred ids
# keeps the generated query string near two kilobytes.
VULN_BATCH = 100

CHILD_LIMIT = 99

# primary_locator names the field Kenna itself treats as an asset's identity.
# These four values describe something that is not a network host at all.
NON_NETWORK_LOCATORS = ["url", "file", "database", "application"]

# Addresses that must never reach a NetworkInterface. Kenna's own documented
# asset example carries ip_address 127.0.0.1, so this is not a hypothetical.
UNUSABLE_NETWORKS = [
    "127.0.0.0/8",
    "0.0.0.0/32",
    "169.254.0.0/16",
    "::1/128",
    "::/128",
    "fe80::/10",
]

# Vulnerability.cve is validated against this before the type sees it, so a
# value that does not match is dropped rather than failing the whole record.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# Kenna publishes no rate limit, so the built-in backoff is widened instead.
HTTP_RETRY_BACKOFF = 2.0
def _number(value):
    """Return a float for a numeric JSON value, or None for anything else."""
    if type(value) == "int" or type(value) == "float":
        return float(value)
    return None

def _tenant_host(base_url):
    """Return the Kenna API hostname, which is the tenant scope for asset ids.

    The scheme is dropped so that switching the configured URL between http and
    https does not change the identity of already-imported assets.
    """
    return base_url.split("://")[-1]
def _cve(value):
    """Return the upper-cased CVE identifier, or "" when the value is not one.

    Vulnerability.cve is checked against ^CVE-[0-9]{4}-[0-9]{4,19}$ before the
    type normalizes case, so a lower-case identifier fails the whole record.
    Kenna's cve_id is nullable and carries scanner-supplied text on findings
    with no CVE, which is why the format is verified rather than assumed.
    """
    cve = as_text(value).strip().upper()
    if not re_match(CVE_RE, cve):
        return ""
    return cve

def _usable_addresses(values):
    """Return the addresses that are safe to place on a NetworkInterface.

    Loopback, unspecified, and link-local addresses are removed. Kenna is an
    aggregator, and a connector that cannot resolve a real address commonly
    reports 127.0.0.1 for every asset it feeds in; letting that reach an
    interface would give the whole estate one address and merge it onto a
    single runZero asset.
    """
    usable = []
    seen = {}
    for value in values:
        text = as_text(value).strip()
        if not text or seen.get(text, False):
            continue
        seen[text] = True
        if ip_address(text) == None:
            continue
        skip = False
        for cidr in UNUSABLE_NETWORKS:
            if ip_in_network(text, cidr):
                skip = True
                break
        if skip:
            continue
        usable.append(text)
    return usable

def _hostnames(record):
    """Return hostname, fqdn, and netbios, de-duplicated case-insensitively."""
    names = []
    seen = {}
    for key in ["hostname", "fqdn", "netbios"]:
        value = record.get(key)
        if type(value) != "string":
            continue
        value = value.strip()
        if not value or seen.get(value.lower(), False):
            continue
        seen[value.lower()] = True
        names.append(value)
    return names

def _mac(record):
    """Return the normalized MAC address, or "" when the value is unusable."""
    mac = normalize_mac(as_text(record.get("mac_address")).strip())
    if mac == None:
        return ""
    return mac

def _network_ports(record):
    """Return network_ports as a list of dicts.

    The vendor schema documents an array, but the search-assets response
    example shows a single bare object, so both shapes are accepted.
    """
    ports = record.get("network_ports")
    if type(ports) == "dict":
        return [ports]
    if type(ports) != "list":
        return []
    entries = []
    for entry in ports:
        if type(entry) == "dict":
            entries.append(entry)
    return entries

def _port_transports(record):
    """Return a port number to transport map built from the asset's open ports."""
    transports = {}
    for entry in _network_ports(record):
        port = entry.get("port_number")
        transport = as_text(entry.get("protocol")).strip().lower()
        if type(port) != "int":
            continue
        if transport == "tcp" or transport == "udp":
            transports[port] = transport
    return transports

def _vulnerability_ports(record):
    """Return the distinct ports a finding was observed on.

    scanner_vulnerabilities[].port is nullable and frequently null, and the
    top-level port array can be empty, so both are read and anything that is
    not a real port number is discarded.
    """
    ports = []
    seen = {}
    for source in [record.get("scanner_vulnerabilities"), record.get("port")]:
        if type(source) != "list":
            continue
        for item in source:
            value = item
            if type(item) == "dict":
                value = item.get("port")
            if type(value) != "int" or value < 1 or value > 65535:
                continue
            if seen.get(value, False):
                continue
            seen[value] = True
            ports.append(value)
    return ports

def _severity_score(record):
    """Return the 0-10 score that drives severityRank.

    CVSS is preferred because its scale is published; Kenna's own severity
    integer is the fallback and is assumed to share the same 0-10 axis.
    """
    for key in ["cvss_v3", "cvss_v2"]:
        block = record.get(key)
        if type(block) == "dict":
            score = _number(block.get("score"))
            if score != None:
                return score
    return _number(record.get("severity"))

def _severity_rank(score):
    """Map a 0-10 CVSS-style score onto runZero's 0-4 severity rank."""
    if score == None:
        return 0
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return 0

def _risk_rank(score):
    """Map Kenna's 0-100 vulnerability risk meter score onto a runZero rank.

    Kenna colours the vulnerability score in thirds - 0-33 green, 34-66 amber,
    67-100 red - so the mapping stops at 3 (High) rather than claiming a
    Critical band that Kenna's scale does not define.
    """
    if score == None:
        return 0
    if score >= 67:
        return 3
    if score >= 34:
        return 2
    if score > 0:
        return 1
    return 0

def _connector_field(record, key):
    """Return one field from every connector that reported a finding."""
    values = []
    connectors = record.get("connectors")
    if type(connectors) != "list":
        return values
    for connector in connectors:
        if type(connector) != "dict":
            continue
        value = as_text(connector.get(key)).strip()
        if value:
            values.append(value)
    return values

def _last_page(data, page, count, page_size):
    """Report whether `page` was the final page of a Kenna search response.

    Every search response carries meta.pages, so that is the termination
    condition; a short page is the fallback for a response that omits meta.
    """
    meta = data.get("meta")
    if type(meta) == "dict":
        pages = meta.get("pages")
        if type(pages) == "int" and pages > 0:
            return page >= pages
    return count < page_size

def _asset_id_query(asset_ids):
    """Return the asset[id][] query string for one batch of asset ids.

    get_json builds its query from the `params` dict, and a Starlark dict
    cannot hold the repeated asset[id][] key Kenna's array filter needs, so the
    query is assembled here and appended to the URL instead. The brackets are
    percent-encoded, which is what the vendor's own reference client sends.
    """
    parts = []
    for asset_id in asset_ids:
        parts.append("asset%5Bid%5D%5B%5D=" + asset_id)
    return "&".join(parts)

def build_vulnerability(record, tenant_host, address, port_transports):
    """Convert one Kenna vulnerability record into a Vulnerability object."""
    vuln_id = record.get("id")
    if vuln_id == None or vuln_id == "":
        return None

    cve = _cve(record.get("cve_id"))
    identifiers = record.get("identifiers")
    name = cve
    if not name and type(identifiers) == "list" and identifiers:
        name = as_text(identifiers[0]).strip()

    description = as_text(record.get("cve_description")).strip()
    if not description:
        description = as_text(record.get("description")).strip()

    severity_score = _severity_score(record)
    risk_score = _number(record.get("risk_meter_score"))
    ports = _vulnerability_ports(record)

    attrs = {
        "vuln_id": vuln_id,
        "status": record.get("status"),
        "severity": record.get("severity"),
        "threat": record.get("threat"),
        # scanner_score is the upstream scanner's own grade. Kenna does not
        # document its range and it is not comparable across connectors
        # (a Nessus 3 is not a Qualys 3), so it is recorded but not scored.
        "scanner_score": record.get("scanner_score"),
        "risk_meter_score": record.get("risk_meter_score"),
        "priority": record.get("priority"),
        "top_priority": record.get("top_priority"),
        "due_date": record.get("due_date"),
        "closed_at": record.get("closed_at"),
        "fix_id": record.get("fix_id"),
        "patch_available": record.get("patch"),
        "patch_published_at": record.get("patch_published_at"),
        "identifiers": identifiers,
        "platform_types": record.get("platform_types"),
        "ports": ports,
        "remote_code_execution": record.get("remote_code_execution"),
        "predicted_exploitable": record.get("predicted_exploitable"),
        "popular_target": record.get("popular_target"),
        "wasc_id": record.get("wasc_id"),
        # Which upstream scanner fed this finding into Kenna is the single most
        # useful thing an aggregator can tell runZero about a record's origin.
        "connector_names": _connector_field(record, "name"),
        "connector_vendors": _connector_field(record, "vendor"),
        "connector_definitions": _connector_field(record, "connector_definition_name"),
    }

    vuln_args = {
        "id": "kenna:{}:{}".format(tenant_host, vuln_id),
        "name": name[:255],
        "description": description[:1024],
        "solution": as_text(record.get("solution")).strip()[:1024],
        "severityRank": _severity_rank(severity_score),
        "riskRank": _risk_rank(risk_score),
        # easily_exploitable, malware_exploitable, and active_internet_breach
        # each assert that exploit code or in-the-wild activity exists.
        # remote_code_execution describes impact and predicted_exploitable is a
        # forecast, so neither contributes to this flag.
        "exploitable": (record.get("easily_exploitable", False) == True or
                        record.get("malware_exploitable", False) == True or
                        record.get("active_internet_breach", False) == True),
        "customAttributes": to_custom_attributes(attrs, prefix="kenna", separator="_"),
    }

    if cve:
        vuln_args["cve"] = cve
    if severity_score != None:
        vuln_args["severityScore"] = severity_score
    if risk_score != None:
        vuln_args["riskScore"] = risk_score

    for key, base_field, temporal_field in [
        ("cvss_v2", "cvss2BaseScore", "cvss2TemporalScore"),
        ("cvss_v3", "cvss3BaseScore", "cvss3TemporalScore"),
    ]:
        block = record.get(key)
        if type(block) != "dict":
            continue
        base = _number(block.get("score"))
        if base != None:
            vuln_args[base_field] = base
        temporal = _number(block.get("temporal_score"))
        if temporal != None:
            vuln_args[temporal_field] = temporal

    # A finding is only tied to a socket when Kenna reports exactly one port
    # for it. The POODLE example in the vendor documentation carries ports 443
    # and 5003 on one record, and picking either would be arbitrary, so those
    # keep their ports as a custom attribute and no service fields. The
    # transport is only set when the asset's own open-port list names it,
    # because scanner_vulnerabilities carries a port and nothing else.
    if len(ports) == 1 and address:
        vuln_args["serviceAddress"] = address
        vuln_args["servicePort"] = int(ports[0])
        transport = port_transports.get(ports[0], "")
        if transport:
            vuln_args["serviceTransport"] = transport

    published = parse_ts(record.get("cve_published_at"))
    if published:
        vuln_args["publishedTS"] = published
    first_detected = parse_ts(record.get("first_found_on"))
    if first_detected:
        vuln_args["firstDetectedTS"] = first_detected
    last_detected = parse_ts(record.get("last_seen_time"))
    if last_detected:
        vuln_args["lastDetectedTS"] = last_detected

    return Vulnerability(**vuln_args)

def build_vulnerabilities(records, tenant_host, address, port_transports):
    """Build the Vulnerability objects for one asset."""
    vulns = []
    for record in records:
        vuln = build_vulnerability(record, tenant_host, address, port_transports)
        if vuln:
            vulns.append(vuln)
    return vulns

def build_services(record, address):
    """Build Service objects from an asset's network_ports entries.

    Service.address is required and there is no meaningful placeholder for it,
    so an asset with no routable address contributes no services.
    """
    services = []
    if not address:
        return services
    for entry in _network_ports(record):
        port = entry.get("port_number")
        transport = as_text(entry.get("protocol")).strip().lower()
        if type(port) != "int" or port < 1 or port > 65535:
            continue
        if transport != "tcp" and transport != "udp":
            continue
        state = as_text(entry.get("state")).strip().lower()
        if state and state != "running" and state != "open":
            continue
        service_args = {
            "address": address,
            "port": int(port),
            "transport": transport,
        }
        product = as_text(entry.get("product")).strip()
        if product:
            service_args["product"] = product
        version = as_text(entry.get("version")).strip()
        if version:
            service_args["version"] = version
        name = as_text(entry.get("name")).strip().lower()
        if name:
            service_args["protocolData"] = [ServiceProtocolData(name=name)]
        services.append(Service(**service_args))
    return services

def build_asset(record, asset_id, tenant_host, vuln_records):
    """Build a single ImportAsset from one Kenna asset record."""
    addresses = _usable_addresses([record.get("ip_address"), record.get("ipv6")])
    nic = network_interface(mac=_mac(record), ips=addresses)
    netifs = [nic] if nic else []
    address = ""
    if addresses:
        address = addresses[0]

    services = build_services(record, address)
    vulns = build_vulnerabilities(vuln_records, tenant_host, address,
                                  _port_transports(record))

    groups = []
    asset_groups = record.get("asset_groups")
    if type(asset_groups) == "list":
        for group in asset_groups:
            if type(group) == "dict":
                name = as_text(group.get("name")).strip()
                if name:
                    groups.append(name)

    tags = ["kenna"]
    source_tags = record.get("tags")
    if type(source_tags) == "list":
        for tag in source_tags:
            value = as_text(tag).strip()
            if value:
                tags.append(value)

    attrs = {
        "asset_id": asset_id,
        "external_id": record.get("external_id"),
        # primary_locator is Kenna's own statement of which field identifies
        # this asset. It is kept so an operator can see whether a record was
        # identified by address, by name, or by something else entirely.
        "primary_locator": record.get("primary_locator"),
        "locator": record.get("locator"),
        "status": record.get("status"),
        "status_set_manually": record.get("status_set_manually"),
        "inactive_at": record.get("inactive_at"),
        "risk_meter_score": record.get("risk_meter_score"),
        "priority": record.get("priority"),
        "vulnerabilities_count": record.get("vulnerabilities_count"),
        "owner": record.get("owner"),
        "notes": record.get("notes"),
        "asset_groups": groups,
        "last_booted_at": record.get("last_booted_at"),
        "created_at": record.get("created_at"),
        "last_seen_time": record.get("last_seen_time"),
        # The addresses as Kenna reported them, before the loopback filter.
        "reported_ip_address": record.get("ip_address"),
        "reported_ipv6": record.get("ipv6"),
        "reported_mac_address": record.get("mac_address"),
    }

    asset_args = {
        "id": "kenna:{}:{}".format(tenant_host, asset_id),
        "hostnames": _hostnames(record),
        "networkInterfaces": netifs,
        "os": as_text(record.get("operating_system")).strip(),
        "osVersion": as_text(record.get("os_version")).strip(),
        "tags": tags,
        "services": services[:CHILD_LIMIT],
        "vulnerabilities": vulns[:CHILD_LIMIT],
        "customAttributes": to_custom_attributes(attrs, prefix="kenna", separator="_"),    }

    first_seen = parse_ts(record.get("created_at"))
    if first_seen:
        asset_args["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_args)

    last_seen = parse_ts(record.get("last_seen_time"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def build_assets(records, tenant_host, vuln_map):
    """Build one page of ImportAssets, attaching each asset's vulnerabilities."""
    assets = []
    for record in records:
        asset_id = as_text(record.get("id"))
        assets.append(build_asset(record, asset_id, tenant_host,
                                  vuln_map.get(asset_id, [])))
    return assets

def select_assets(records, include_non_network, min_risk, skipped):
    """Return the records that can become runZero assets, counting the rest.

    Kenna aggregates other scanners, so most of its assets are machines runZero
    already knows from the original source. A record with no MAC, no hostname,
    and no routable address cannot merge onto that machine and would sit beside
    it as a permanent duplicate carrying nothing but a Kenna id, so it is
    dropped rather than imported.
    """
    kept = []
    for record in records:
        if type(record) != "dict":
            skipped["malformed"] = skipped["malformed"] + 1
            continue
        asset_id = record.get("id")
        if asset_id == None or asset_id == "":
            print("kenna: skipping asset with no id: locator=" + as_text(record.get("locator")))
            skipped["no_id"] = skipped["no_id"] + 1
            continue
        locator = as_text(record.get("primary_locator")).strip().lower()
        if not include_non_network and locator in NON_NETWORK_LOCATORS:
            skipped["non_network"] = skipped["non_network"] + 1
            continue
        # The min_risk_meter_score query parameter is also sent to the server,
        # but it is not a documented /assets/search filter, so it cannot be
        # relied on alone: a server that ignores it would import the whole
        # estate despite the operator's threshold. This client-side check makes
        # the threshold hold either way. A record with no numeric score is kept
        # rather than guessed at.
        if min_risk > 0:
            score = _number(record.get("risk_meter_score"))
            if score != None and score < min_risk:
                skipped["below_risk"] = skipped["below_risk"] + 1
                continue
        if not _usable_addresses([record.get("ip_address"), record.get("ipv6")]):
            if not _hostnames(record) and not _mac(record):
                skipped["no_correlator"] = skipped["no_correlator"] + 1
                continue
        kept.append(record)
    return kept

def fetch_vulnerability_map(base_url, http_options, asset_ids, page_size):
    """Fetch the vulnerabilities for one page of assets, indexed by asset id.

    The flat /vulnerabilities/search endpoint is filtered down to the asset ids
    on the current page rather than walked whole. That keeps the response
    joinable on asset_id, bounds memory to one page of assets, and sidesteps
    Kenna's 20-page ceiling, which would otherwise cap a whole tenant's
    findings at twenty pages no matter how many assets it has.
    """
    vuln_map = {}
    total = 0
    # One pager bounds the whole join, not one per batch: a fresh guard per
    # 100-id batch would reset the page budget every batch and let the walk
    # grow unbounded with the estate. Kenna numbers pages per search, so the
    # page parameter restarts at 1 for each batch while the guard accumulates.
    p = pager("kenna-vulnerabilities")
    for start in range(0, len(asset_ids), VULN_BATCH):
        query = _asset_id_query(asset_ids[start:start + VULN_BATCH])
        page = 0
        while p.next():
            page += 1
            url = "{}{}?{}&page={}&per_page={}".format(
                base_url, VULNERABILITIES_SEARCH_PATH, query, page, page_size)
            # The query is already in the URL; passing params= would replace it.
            data, err = get_json(url, **http_options)
            if err:
                print("kenna: failed to fetch vulnerabilities:", err)
                if err.startswith("status 401") or err.startswith("status 403"):
                    print("kenna: check the API token")
                    return vuln_map
                break
            data = data or {}
            records = data.get("vulnerabilities", []) or []
            if not records:
                break
            for record in records:
                if type(record) != "dict":
                    continue
                key = as_text(record.get("asset_id"))
                if not key:
                    continue
                existing = vuln_map.get(key, [])
                if len(existing) >= CHILD_LIMIT:
                    continue
                existing.append(record)
                vuln_map[key] = existing
                total += 1
            if _last_page(data, page, len(records), page_size):
                break

    print("kenna: indexed {} vulnerabilities across {} assets".format(total, len(vuln_map)))
    return vuln_map

def fetch_and_report_assets(base_url, http_options, params, page_size,
                            include_vulnerabilities, include_non_network,
                            min_risk):
    """Fetch and stream assets one page at a time so the full set is never
    held in memory at once."""
    reported = 0
    truncated = False
    tenant_host = _tenant_host(base_url)
    url = base_url + ASSETS_SEARCH_PATH
    skipped = {"malformed": 0, "no_id": 0, "non_network": 0, "no_correlator": 0,
               "below_risk": 0}

    p = pager("kenna-assets")

    while p.next():

        page = p.page
        page_params = dict(params)
        page_params["page"] = page
        page_params["per_page"] = page_size

        data, err = get_json(url, params=page_params, **http_options)
        if err:
            print("kenna: failed to fetch assets:", err)
            if err.startswith("status 401") or err.startswith("status 403"):
                print("kenna: check the API token")
            break
        data = data or {}
        records = data.get("assets", []) or []
        if not records:
            break

        kept = select_assets(records, include_non_network, min_risk, skipped)
        if kept:
            vuln_map = {}
            if include_vulnerabilities:
                asset_ids = []
                for record in kept:
                    asset_ids.append(as_text(record.get("id")))
                vuln_map = fetch_vulnerability_map(base_url, http_options,
                                                   asset_ids, page_size)
            reported += report_assets(build_assets(kept, tenant_host, vuln_map))

        if _last_page(data, page, len(records), page_size):
            break
        truncated = page == MAX_PAGES

    if truncated:
        print("kenna: stopped at Kenna's {}-page search limit; raise the page size or the minimum risk meter score to reach the rest of the inventory".format(MAX_PAGES))
    if skipped["no_correlator"]:
        print("kenna: skipped {} assets with no usable MAC, hostname, or routable address".format(skipped["no_correlator"]))
    if skipped["non_network"]:
        print("kenna: skipped {} assets whose primary locator is not a network host".format(skipped["non_network"]))
    if skipped["below_risk"]:
        print("kenna: skipped {} assets below the configured minimum risk meter score".format(skipped["below_risk"]))
    if skipped["malformed"]:
        print("kenna: skipped {} malformed asset records".format(skipped["malformed"]))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    api_token = get_string(kwargs, "api_token")
    include_vulnerabilities = get_bool(kwargs, "include_vulnerabilities", default=True)
    include_non_network = get_bool(kwargs, "include_non_network_assets", default=False)
    asset_status = get_string(kwargs, "asset_status", default="active")
    min_risk_meter_score = get_int(kwargs, "min_risk_meter_score", default=0)
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    params = {}
    if asset_status == "active" or asset_status == "inactive":
        params["status[]"] = asset_status
    if min_risk_meter_score > 0:
        params["min_risk_meter_score"] = min_risk_meter_score

    http_options = get_http_options(kwargs, headers={
        "X-Risk-Token": api_token,
        "Accept": "application/json",
    })
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    reported = fetch_and_report_assets(base_url, http_options, params, page_size,
                                       include_vulnerabilities, include_non_network,
                                       min_risk_meter_score)
    if not reported:
        print("kenna: no assets retrieved")
    return None

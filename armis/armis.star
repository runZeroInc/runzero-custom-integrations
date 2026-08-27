# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-armis",
    "name": "Armis Centrix",
    "type": "inbound",
    "description": "Imports devices, addresses, classification, and optional CVE findings from an Armis Centrix tenant.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Armis ids may be recycled; the evidence is one uncorroborated field
    # report, so this is conservative rather than proven. A foreign-id match
    # cannot be vetoed by a conflicting MAC, IP, or name, so a recycled id
    # would merge unrelated devices with nothing able to stop it. Correlate on
    # the addresses instead. Cost: a record with none of the three is skipped.
    # See README "Asset identity".
    "matchBehavior": "no-id-match no-id-break",
    "ownershipAttributes": ["armis_user"],
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "Armis tenant URL",
            "type": "url",
            "required": True,
            "placeholder": "https://example.armis.com",
            "description": "Base URL of the Armis Centrix tenant. The /api/v1 paths are appended automatically.",
        },
        {
            "key": "secret_key",
            "label": "API secret key",
            "type": "secret",
            "required": True,
            "description": "Secret key created under Settings > API Management. Armis prohibits sharing one secret key across concurrent tasks, so use a dedicated key for this integration.",
        },
        {
            "key": "device_filter",
            "label": "Additional ASQ filter",
            "type": "string",
            "required": False,
            "placeholder": "timeFrame:\"30 Days\"",
            "description": "Optional ASQ tokens appended to in:devices and AND-ed with it, for example timeFrame:\"30 Days\" or riskLevel:Medium,High. Leave empty to import the whole inventory.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 10000,
            "description": "Rows requested per search page. Armis does not document a ceiling; 10000 is the largest value any reference client uses and roughly 5000 is the largest observed in production. Lower this if the tenant answers 502 or returns truncated JSON.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import vulnerabilities",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Also resolve CVE findings onto devices. This costs two extra endpoints and requires an Armis ViPR licence, so it is off by default.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames')
load('http', 'get_json', 'post_json', 'url_encode', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('coerce', 'as_text', 'as_dict', 'as_list', 'as_int', 'as_float', 'dicts', 'dedupe')
load('time', 'parse_ts')
load('re', re_match='match')

TOKEN_PATH = "/api/v1/access_token/"
SEARCH_PATH = "/api/v1/search/"
VULNERABILITY_MATCH_PATH = "/api/v1/vulnerability-match/"

# ASQ collection selectors. The selector is always the first token; operator
# filters are space-joined onto it and AND-ed together.
DEVICE_QUERY = "in:devices"
VULNERABILITY_QUERY = "in:vulnerabilities"

# vulnerability_ids travels in the query string, so a large batch trips the
# 414 that Armis integrations report on this endpoint. A CVE id is ~15 bytes,
# which keeps a batch of this size well inside any URL limit.
CVE_BATCH_SIZE = 100

# Sanity cap so a malformed macAddress array cannot fan out interfaces. Matches
# the value the rest of this repo uses; no vendor limit is documented.
MAX_INTERFACES = 32
MAX_VULNS_PER_ASSET = 99

ATTR_PREFIX = "armis"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# Vulnerability.cve is validated against this and is NOT upper-cased for the
# script, and a rejected value fails the whole record rather than the field.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# The only in:vulnerabilities fields build_vulnerability reads. The index is
# held for the length of the device walk, so nothing else is kept.
CVE_INDEX_FIELDS = [
    "commonName", "description", "severity", "cvssScore", "avmRating",
    "epssScore", "isWeaponized", "hasRansomware", "threatTags",
]

# Device fields copied verbatim into custom attributes, vendor name to
# attribute name. Nested and list-valued fields are projected separately
# below, because to_custom_attributes would otherwise join a list of objects
# into one unreadable string.
DEVICE_ATTR_FIELDS = {
    "category": "category",
    "type": "type",
    "typeEnum": "type_enum",
    "riskLevel": "risk_level",
    "purdueLevel": "purdue_level",
    "businessImpact": "business_impact",
    "visibility": "visibility",
    "boundaries": "boundaries",
    "displayTitle": "display_title",
    "accessSwitch": "access_switch",
    "user": "user",
    "names": "names",
    "firstSeen": "first_seen",
    "lastSeen": "last_seen",
}

def _values(value):
    """Return a vendor field as a list of strings, scalar or array.

    v1 documents ipAddress and macAddress as scalars while v3 uses arrays, so
    both shapes reach this parser. A v1 scalar is not always single-valued:
    Armis comma-joins multiple addresses into the one string, and an unsplit
    "10.1.1.5, 10.1.1.6" is rejected outright by routable_ips and
    network_interface, costing the device every address and MAC at once.
    """
    out = []
    for entry in as_list(value):
        text = as_text(entry)
        if not text:
            continue
        # Only strings can carry the joined form; an array member is taken whole.
        if type(entry) == "string" and "," in text:
            for part in text.split(","):
                part = part.strip()
                if part:
                    out.append(part)
            continue
        out.append(text)
    return out

def _time_bound(device_filter):
    """Return the ASQ timeFrame value out of the device filter, or "".

    ASQ writes the bound as timeFrame:"30 Days" when the value contains a space
    and timeFrame:7Days when it does not, so both shapes are read. It is the one
    filter token that transfers to in:vulnerabilities, which carries
    lastDetected but has no site or riskLevel field."""
    marker = "timeFrame:"
    start = device_filter.find(marker)
    if start < 0:
        return ""
    rest = device_filter[start + len(marker):]
    if rest.startswith("\""):
        end = rest.find("\"", 1)
        if end < 1:
            return ""
        return rest[1:end]
    end = rest.find(" ")
    if end < 0:
        return rest
    return rest[:end]

def _scope(base_url):
    """Return the tenant hostname used to namespace asset ids.

    Armis ids are unique only inside one tenant and the tenant is the host. The
    port is excluded on purpose: including it would re-key an entire estate the
    day someone moves the console behind a different port."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]

def _named_values(entries, key):
    """Pull one field out of a list of objects, deduplicated and in order."""
    out = []
    for entry in dicts(entries):
        out.append(as_text(entry.get(key)))
    return dedupe(out)

def _interfaces(device):
    """Build the network interfaces for one device row.

    routable_ips drops loopback, unspecified, and link-local addresses. v1 rows
    routinely carry an fe80:: address in ipv6, which identifies nothing and
    would correlate every host reporting one onto a single asset."""
    addresses = routable_ips(_values(device.get("ipAddress")) + _values(device.get("ipv6")))
    macs = _values(device.get("macAddress"))[:MAX_INTERFACES]

    nic = network_interface(mac=macs[0] if macs else "", ips=addresses)
    netifs = [nic] if nic else []
    # v1 has only ever been observed returning a scalar macAddress, but a
    # tenant that returns the v3-style array must not silently lose the rest.
    for mac in macs[1:]:
        extra = network_interface(mac=mac, ips=[])
        if extra:
            netifs.append(extra)
    return netifs

def build_vulnerability(match, cve):
    """Convert one vulnerability-match row into a runZero Vulnerability.

    The match row says which device a CVE was found on and how confident Armis
    is; the CVE row from in:vulnerabilities carries the score and the prose.
    Everything Armis rates itself (avmRating, EPSS, weaponization) is kept as a
    custom attribute rather than being folded into the runZero severity."""
    uid = as_text(match.get("cveUid")).upper()
    if not uid:
        return None

    severity = as_text(cve.get("severity"))
    score = as_float(cve.get("cvssScore"), default=0.0)
    rank = SEVERITY_RANK.get(severity.upper(), 0)
    params = {
        "id": uid,
        "name": as_text(cve.get("commonName")) or uid,
        # Armis publishes one severity and one CVSS score per CVE, with nothing
        # separating exploitability from impact, so the risk pair repeats the
        # severity pair rather than being left unset.
        "severityRank": rank,
        "severityScore": score,
        "riskRank": rank,
        "riskScore": score,
        "customAttributes": to_custom_attributes({
            "cve_uid": uid,
            "status": match.get("status"),
            "status_source": match.get("statusSource"),
            "status_change_reason": match.get("statusChangeReason"),
            "match_criteria": match.get("matchCriteriaString"),
            "confidence_level": match.get("confidenceLevel"),
            "advisory_id": match.get("advisoryId"),
            "remediation_types": match.get("remediationTypes"),
            "avm_rating": cve.get("avmRating"),
            "cvss_score": cve.get("cvssScore"),
            "epss_score": cve.get("epssScore"),
            "severity": severity,
            "is_weaponized": cve.get("isWeaponized"),
            "has_ransomware": cve.get("hasRansomware"),
            "threat_tags": as_list(cve.get("threatTags")),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    # Only a value the platform accepts reaches the cve field. The finding is
    # still imported either way, keeping the identifier as its name and as the
    # armis_cve_uid attribute, so an advisory Armis tracks under a non-CVE id
    # is not silently dropped along with the whole record.
    if re_match(CVE_PATTERN, uid):
        params["cve"] = uid

    description = as_text(cve.get("description"))
    if description:
        params["description"] = description[:1024]
    solution = as_text(match.get("recommendedSteps"))
    if solution:
        params["solution"] = solution[:1024]

    first_detected = parse_ts(match.get("firstDetected"))
    if first_detected:
        params["firstDetectedTS"] = first_detected
    # lastDetected is documented as sometimes null on this endpoint.
    last_detected = parse_ts(match.get("lastDetected"))
    if last_detected:
        params["lastDetectedTS"] = last_detected

    return Vulnerability(**params)

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

def build_asset(device, vulns, scope, stats):
    """Convert one in:devices row into a runZero ImportAsset."""
    device_id = as_text(device.get("id"))
    if not device_id:
        stats["no_id"] += 1
        print("armis: skipping device record with no id, name=" + as_text(device.get("name")))
        return None

    netifs = _interfaces(device)
    hostnames = clean_hostnames(_values(device.get("name")) + _values(device.get("names")))
    # The id is barred from matching, so a record with no address and no name
    # has nothing to correlate on and would create a fresh orphan asset on every
    # poll. The count is reported once at the end, not per record.
    if not netifs and not hostnames:
        stats["no_correlator"] += 1
        return None

    site = as_dict(device.get("site"))
    sensor = as_dict(device.get("sensor"))

    attrs = {}
    for source, target in DEVICE_ATTR_FIELDS.items():
        attrs[target] = device.get(source)
    attrs["site_name"] = site.get("name")
    attrs["site_location"] = site.get("location")
    attrs["sensor_name"] = sensor.get("name")
    attrs["sensor_type"] = sensor.get("type")
    attrs["ipv6"] = _values(device.get("ipv6"))
    attrs["user_ids"] = [as_text(entry) for entry in as_list(device.get("userIds"))]
    # dataSources names which Armis connectors and sensors contributed the
    # record, which is the provenance an operator needs to judge it.
    attrs["data_sources"] = _named_values(device.get("dataSources"), "name")
    attrs["protections"] = _named_values(device.get("protections"), "protectionName")
    for key, value in as_dict(device.get("customProperties")).items():
        attrs["custom_" + as_text(key)] = value
    if vulns:
        attrs["vulnerability_count"] = len(vulns)

    tags = dedupe(_values(device.get("tags")))
    site_name = as_text(site.get("name"))
    if site_name:
        tags.append("site:" + site_name)

    params = {
        "id": "armis:{}:{}".format(scope, device_id),
        # clean_hostnames rejects placeholder names and values that are really
        # IP addresses, and de-duplicates name against the differently-spelled
        # names field.
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if vulns:
        params["vulnerabilities"] = vulns[:MAX_VULNS_PER_ASSET]

    os_name = as_text(device.get("operatingSystem"))
    if os_name:
        params["os"] = os_name
    os_version = as_text(device.get("operatingSystemVersion"))
    if os_version:
        params["osVersion"] = os_version
    manufacturer = as_text(device.get("manufacturer"))
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = as_text(device.get("model"))
    if model:
        params["model"] = model
    # type is Armis' device taxonomy ("Laptops", "Servers"), which is the grain
    # runZero's device type expects. category is a much coarser grouping
    # ("Computers") and stays an attribute. typeEnum is the machine-readable
    # spelling of type and only stands in when type itself is absent.
    device_type = as_text(device.get("type")) or as_text(device.get("typeEnum"))
    if device_type:
        params["deviceType"] = device_type

    # firstSeen is emitted so that an id whose device history restarts -- the
    # signature of a recycled or merged-away id -- is at least visible.
    first_seen = _seen_ts(device.get("firstSeen"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = _seen_ts(device.get("lastSeen"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_access_token(base_url, secret_key, config_kwargs):
    """Exchange the tenant secret key for a short-lived v1 access token.

    The secret goes in a form-encoded body rather than the query string so it
    does not reach proxy and access logs. The response's expiration_utc is
    unused on purpose: parse_ts clamps future values to now, so treating it as
    an expiry would make every fresh token look expired. Expiry is handled
    where it is observable, on the 401 in fetch_json."""
    options = get_http_options(config_kwargs, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })

    body = url_encode({"secret_key": secret_key})
    data, err = post_json(base_url + TOKEN_PATH, body=bytes(body), **options)
    if err:
        print("armis: failed to obtain an access token:", err)
        return ""

    token = as_text(as_dict(as_dict(data).get("data")).get("access_token"))
    if not token:
        print("armis: token response contained no access_token")
    return token

def _api_options(config_kwargs, token):
    """Collect the HTTP options used for every call under a given token.

    Armis v1 takes the token bare: `Authorization: <token>`, no `Bearer` prefix.
    get_http_options snapshots the header map, so a refreshed token needs these
    options rebuilt rather than the returned dict mutated."""
    return get_http_options(config_kwargs, headers={
        "Authorization": token,
        "Accept": "application/json",
    })

def fetch_json(ctx, url, params):
    """GET one API page, re-minting the access token once on a 401.

    An Armis v1 token lives 30 minutes and a large tenant takes longer than that
    to walk, so a 401 mid-run is the token ageing out rather than a bad
    credential, and the fix is a new token instead of a retry. Rate limiting is
    left to get_json, which already retries 429 and 5xx and honors
    Retry-After."""
    for attempt in range(2):
        data, err = get_json(url, params=params, **ctx["http_options"])
        if not err:
            return data, None
        if err.startswith("status 401") and attempt == 0:
            print("armis: access token rejected mid-run, requesting a new one")
            token = fetch_access_token(ctx["base_url"], ctx["secret_key"], ctx["kwargs"])
            if token:
                ctx["http_options"] = _api_options(ctx["kwargs"], token)
                continue
        return None, err
    return None, "unreachable"

def _search_page(ctx, aql, order_by, offset):
    """Run one /search/ page and return (rows, next offset, error).

    The envelope is {data: {count, next, prev, results, total}} and data.next
    is an absolute row offset to feed back as `from`, not an opaque cursor.
    includeTotal=false skips the count Armis would otherwise compute per page."""
    params = {
        "aql": aql,
        "length": ctx["page_size"],
        "from": offset,
        "orderBy": order_by,
        "includeTotal": "false",
    }
    data, err = fetch_json(ctx, ctx["base_url"] + SEARCH_PATH, params)
    if err:
        return [], None, err

    page = as_dict(as_dict(data).get("data"))
    return dicts(page.get("results")), page.get("next"), None

def _advance(offset, next_offset, rows):
    """Return the next offset, or None when the walk is finished.

    Armis ends a walk with a null next. An empty page and a next that fails to
    move forward are both guarded as well, because either would otherwise spin
    the loop against the same offset until the page ceiling stopped it."""
    if not rows or next_offset == None:
        return None
    following = as_int(next_offset)
    if following <= offset:
        return None
    return following

def fetch_cve_index(ctx):
    """Index the tenant's vulnerabilities by CVE id.

    in:vulnerabilities returns one row per CVE, not per device finding, so this
    pass only collects the scores and prose. Which devices are affected comes
    from the separate vulnerability-match endpoint below. The query carries the
    device filter's time bound when it has one, which keeps the pass
    proportionate to the run rather than to the whole CVE catalogue."""
    index = {}
    offset = 0

    p = pager("vulnerabilities")
    while p.next():
        rows, next_offset, err = _search_page(ctx, ctx["vulnerability_query"], "lastDetected", offset)
        if err:
            print("armis: failed to fetch vulnerabilities:", err)
            return index

        for row in rows:
            # The row id and cveUid are the same value; either identifies it.
            uid = as_text(row.get("cveUid")) or as_text(row.get("id"))
            if not uid:
                continue
            kept = {}
            for field in CVE_INDEX_FIELDS:
                value = row.get(field)
                if value != None:
                    kept[field] = value
            index[uid.upper()] = kept

        offset = _advance(offset, next_offset, rows)
        if offset == None:
            break

    return index

def _batch_uids(cve_index):
    """Order the indexed CVE ids worst-first and cut them into request batches.

    The per-device cap is applied as match rows arrive, so batch order decides
    which findings survive it. Sorting by severity rank and then CVSS score,
    both descending, makes the kept findings the worst ones. The id is the final
    tiebreak so the walk stays deterministic."""
    ranked = []
    for uid in cve_index.keys():
        row = as_dict(cve_index[uid])
        ranked.append((
            -SEVERITY_RANK.get(as_text(row.get("severity")).upper(), 0),
            -as_float(row.get("cvssScore"), default=0.0),
            uid,
        ))

    ordered = sorted(ranked)
    batches = []
    for start in range(0, len(ordered), CVE_BATCH_SIZE):
        batch = []
        for entry in ordered[start:start + CVE_BATCH_SIZE]:
            batch.append(entry[2])
        batches.append(batch)
    return batches

def fetch_vulnerability_index(ctx, cve_index):
    """Resolve the indexed CVEs onto the devices they were found on.

    /vulnerability-match/ takes a comma-separated list of CVE ids and answers
    with a different envelope from every other v1 endpoint: data.sample rather
    than data.results, and data.paging.next rather than data.next."""
    index = {}
    kept = 0

    # Worst-first, because the per-device cap keeps whatever arrives first.
    batches = _batch_uids(cve_index)

    # One guard across every batch, so the page budget bounds the whole pass
    # rather than resetting each time a new batch of CVE ids starts.
    p = pager("vulnerability-matches")
    for batch in batches:
        offset = 0
        while p.next():
            params = {
                "vulnerability_ids": ",".join(batch),
                "length": ctx["page_size"],
                "from": offset,
            }
            data, err = fetch_json(ctx, ctx["base_url"] + VULNERABILITY_MATCH_PATH, params)
            if err:
                print("armis: failed to resolve vulnerability matches:", err)
                return index

            page = as_dict(as_dict(data).get("data"))
            rows = dicts(page.get("sample"))
            for row in rows:
                device_id = as_text(row.get("deviceId"))
                if not device_id:
                    continue
                cve = as_dict(cve_index.get(as_text(row.get("cveUid")).upper()))
                vuln = build_vulnerability(row, cve)
                if not vuln:
                    continue
                findings = index.get(device_id)
                if findings == None:
                    findings = []
                    index[device_id] = findings
                if len(findings) < MAX_VULNS_PER_ASSET:
                    findings.append(vuln)
                    kept += 1

            offset = _advance(offset, as_dict(page.get("paging")).get("next"), rows)
            if offset == None:
                break

    print("armis: indexed {} vulnerabilities across {} devices".format(kept, len(index)))
    return index

def fetch_and_report_devices(ctx, vuln_index, stats):
    """Walk the device inventory, streaming each page so the whole tenant is
    never held in memory at once."""
    reported = 0
    offset = 0

    p = pager("devices")
    while p.next():
        # orderBy=lastSeen is what every reference client uses. It is not a
        # stable key for an offset walk of a live inventory, so a device whose
        # lastSeen advances mid-walk can shift position; runZero reconciles the
        # duplicate on the next poll.
        rows, next_offset, err = _search_page(ctx, ctx["device_query"], "lastSeen", offset)
        if err:
            print("armis: failed to fetch devices:", err)
            return reported

        for row in rows:
            device_id = as_text(row.get("id"))
            findings = vuln_index.pop(device_id, []) if device_id else []
            reported += report_asset(build_asset(row, findings, ctx["scope"], stats))

        offset = _advance(offset, next_offset, rows)
        if offset == None:
            break

    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    secret_key = get_string(kwargs, "secret_key")
    device_filter = get_string(kwargs, "device_filter", default="")
    page_size = get_int(kwargs, "page_size", default=1000)
    include_vulnerabilities = get_bool(kwargs, "include_vulnerabilities", default=False)

    token = fetch_access_token(base_url, secret_key, kwargs)
    if not token:
        return None

    device_query = DEVICE_QUERY
    vulnerability_query = VULNERABILITY_QUERY
    if device_filter:
        device_query = DEVICE_QUERY + " " + device_filter
        # in:vulnerabilities is tenant-wide and knows nothing about sites or
        # device risk, so only the filter's time bound transfers to it, as
        # lastDetected. Without it a narrow device scope still walks and joins
        # the whole CVE catalogue against the 200-per-5-minutes budget.
        bound = _time_bound(device_filter)
        if bound:
            vulnerability_query = VULNERABILITY_QUERY + (" lastDetected:\"{}\"".format(bound))

    ctx = {
        "base_url": base_url,
        "secret_key": secret_key,
        "kwargs": kwargs,
        "scope": _scope(base_url),
        "page_size": page_size,
        "device_query": device_query,
        "vulnerability_query": vulnerability_query,
        "http_options": _api_options(kwargs, token),
    }

    vuln_index = {}
    if include_vulnerabilities:
        vuln_index = fetch_vulnerability_index(ctx, fetch_cve_index(ctx))

    stats = {"no_id": 0, "no_correlator": 0}
    reported = fetch_and_report_devices(ctx, vuln_index, stats)

    if stats["no_correlator"]:
        print("armis: skipped {} devices with no MAC, IP, or hostname to correlate on".format(stats["no_correlator"]))
    if vuln_index:
        # A vulnerability-match row carries only a deviceId, so a finding for a
        # device the inventory query did not return cannot be turned into an
        # asset -- there is nothing to correlate it with.
        print("armis: dropped findings for {} devices absent from the inventory query".format(len(vuln_index)))
    if not reported:
        print("armis: no assets retrieved")
    return None

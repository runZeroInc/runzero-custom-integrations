# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-nozomi-networks",
    "name": "Nozomi Networks",
    "type": "inbound",
    "description": "Imports OT, IoT, and IT assets and their CVE findings from a Nozomi Networks Guardian or CMC appliance via the on-premise N2OS Open API.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The asset id is authoritative for the appliance, but passive OT
    # monitoring re-observes addresses constantly and one MAC legitimately
    # backs several assets, so network churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Nozomi Networks URL",
            "type": "url",
            "required": True,
            "placeholder": "https://guardian.example.com",
            "description": "Base URL of the Guardian or CMC appliance. The /api/open/ paths are appended automatically; they are the on-premise N2OS Open API, which Vantage (SaaS) does not serve.",
        },
        {
            "key": "key_name",
            "label": "API key name",
            "type": "string",
            "required": True,
            "description": "The key_name half of a Nozomi Open API key pair.",
        },
        {
            "key": "key_token",
            "label": "API key token",
            "type": "secret",
            "required": True,
            "description": "The key_token half of the Open API key pair.",
        },
        {
            "key": "asset_filter",
            "label": "Asset query filter",
            "type": "string",
            "required": False,
            "placeholder": "where level == 4",
            "description": "Optional N2OS filter appended to the assets query, for example 'where level == 4'. Leave blank to import every asset.",
        },
        {
            "key": "include_cves",
            "label": "Import CVE findings",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Also query the asset_cves table and attach unresolved CVEs to their asset. Skipped automatically when the credential is not permitted to query that table.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface')
load('http', http_post='post', 'get_json', 'basic', 'url_encode', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_bool')
load('time', 'from_timestamp')
load('re', re_match='match')

load('coerce', 'as_text', 'dedupe')
VENDOR = "nozomi-networks"
ATTR_PREFIX = "nozomi"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
SIGN_IN_PATH = "/api/open/sign_in"
QUERY_PATH = "/api/open/query/do"
# The Open API caps "count" at 10000 and recommends staying under 1000; "page"
# is rejected past 1000, at which point the vendor's own guidance is to pivot
# past the last record seen and restart at page 1.
PAGE_SIZE = 500
MAX_PAGE = 1000
# /api/open/ is throttled to 60 requests per minute per client IP and answers
# 429 with a Retry-After header. The helper's default retry count covers that;
# the backoff factor is widened below.
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0
MAX_SIGN_IN_ATTEMPTS = 3
MAX_INTERFACES = 32
MAX_CHILDREN = 99
MAX_TAGS = 40
MAX_CVE_ROWS = 20000
# Vulnerability.cve is validated against this pattern by the platform and a
# malformed id fails the WHOLE record, so values are screened before assignment.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
DIGITS = "0123456789"
# The assets table uses "-" where a property was never determined.
UNKNOWN = ["", "-", "n/a", "unknown", "none"]
# Properties the assets table annotates with a "<field>:info" object recording
# whether the value was observed passively or collected by active polling.
SOURCED_FIELDS = ["vendor", "firmware_version", "product_name", "serial_number", "type"]

RANK_SCORE = {0: 0.0, 1: 2.5, 2: 5.0, 3: 7.5, 4: 10.0}
def _list(value):
    """Coerce a field documented as an array into one. The assets table types
    ip, mac_address, protocols, and zones as arrays, but a projected or
    filtered query can collapse a single-element array to a scalar."""
    if value == None:
        return []
    if type(value) == "list":
        return value
    return [value]
def _clean(value):
    """Return the trimmed text of a property, or an empty string when the
    appliance filled it with one of its not-determined placeholders."""
    text = as_text(value, join=",").strip()
    if text.lower() in UNKNOWN:
        return ""
    return text


def _is_ip(text):
    """Report whether a string is an IP literal. The assets table falls back to
    the address when a node has no resolved name, and an address must not be
    imported as a hostname. network_interface is used as the test because it
    returns None rather than failing on unparseable input."""
    if not text:
        return False
    return network_interface(ips=[text]) != None


def _number(value):
    """Return a float for a numeric field, or -1.0 when it is not numeric."""
    if type(value) in ("int", "float"):
        return float(value)
    text = as_text(value, join=",").strip()
    if not text or len(text) > 12:
        return -1.0
    seen_dot = False
    for index in range(len(text)):
        char = text[index]
        if char == ".":
            if seen_dot:
                return -1.0
            seen_dot = True
        elif char not in DIGITS:
            return -1.0
    if text == "." or not text:
        return -1.0
    return float(text)


def _epoch_ms(value):
    """Convert a Nozomi millisecond epoch to a time value, or None when the
    field is absent or not numeric. Every timestamp the Open API returns uses
    this encoding."""
    if type(value) == "float":
        value = int(value)
    if type(value) != "int":
        text = as_text(value, join=",").strip()
        if not text or len(text) > 16:
            return None
        for index in range(len(text)):
            if text[index] not in DIGITS:
                return None
        value = int(text)
    if value <= 0:
        return None
    return from_timestamp(value // 1000)


def _truthy(value):
    """Report whether a documented boolean column is set, tolerating the string
    spellings a projected query can return."""
    if type(value) == "bool":
        return value
    return as_text(value, join=",").strip().lower() in ("true", "1", "yes")


def _first_header(headers, name):
    """Read one response header. The http module exposes response headers as a
    dict of canonically cased names to a list of values."""
    if type(headers) != "dict":
        return ""
    values = headers.get(name)
    if type(values) == "list":
        if not values:
            return ""
        return str(values[0]).strip()
    if values == None:
        return ""
    return str(values).strip()


def _envelope(data):
    """Unwrap the {result, header, error, total} envelope every query/do
    response carries. A rejected query still answers 200 with the reason in
    "error", so the body has to be inspected and not just the status."""
    if type(data) != "dict":
        return [], ""
    rows = data.get("result")
    if type(rows) != "list":
        rows = []
    error = data.get("error")
    if error == None or as_text(error, join=",").strip() == "":
        return rows, ""
    return rows, as_text(error, join=",").strip()


def _query_url(base_url, query, page, count):
    """Build a query/do URL. url_encode is Go's url.Values encoder, which emits
    "+" for a space; the Nozomi clients send "%20", so encoded spaces are
    rewritten. A literal plus in the query is already %2B by this point, so
    only spaces are affected."""
    encoded = url_encode({"query": query, "page": str(page), "count": str(count)})
    return base_url + QUERY_PATH + "?" + encoded.replace("+", "%20")


def sign_in(ctx):
    """Exchange the Open API key pair for a bearer token and install it on the
    request options. Nozomi returns the token in the Authorization response
    header rather than the body, so this uses raw http.post; the value is
    reused verbatim because it already carries whatever scheme prefix the
    appliance chose. Falls back to HTTP Basic, which the Open API also accepts
    for the same key pair. Returns True when a bearer token was installed."""
    if ctx["sign_in_attempts"] >= MAX_SIGN_IN_ATTEMPTS:
        return False
    ctx["sign_in_attempts"] += 1

    token = ""
    resp = http_post(
        ctx["base_url"] + SIGN_IN_PATH,
        json={"key_name": ctx["key_name"], "key_token": ctx["key_token"]},
        **ctx["post_options"]
    )
    if not resp:
        print("nozomi-networks: no response from sign_in, falling back to basic authentication")
    elif resp.status_code != 200:
        print("nozomi-networks: sign_in returned status {}, falling back to basic authentication".format(resp.status_code))
    else:
        token = _first_header(resp.headers, "Authorization")
        if not token:
            print("nozomi-networks: sign_in returned no Authorization header, falling back to basic authentication")

    if token:
        ctx["http_options"]["headers"] = dict(ctx["headers"], Authorization=token)
        return True
    ctx["http_options"]["headers"] = dict(ctx["headers"], Authorization=basic(ctx["key_name"], ctx["key_token"]))
    return False


def run_query(ctx, query, page, count):
    """Run one N2OS pipeline and return (rows, error). The bearer token issued
    by sign_in expires after 30 minutes, which a large inventory walk can
    outlive, so a rejected token is refreshed once and the page re-requested."""
    url = _query_url(ctx["base_url"], query, page, count)
    data, err = get_json(url, **ctx["http_options"])
    if err and (err.startswith("status 401") or err.startswith("status 403")) and ctx["token_auth"]:
        print("nozomi-networks: the Open API rejected the bearer token, signing in again")
        ctx["token_auth"] = sign_in(ctx)
        data, err = get_json(url, **ctx["http_options"])
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            return [], "authentication to the Open API failed: " + err
        return [], err
    return _envelope(data or {})


def fetch_cves(ctx):
    """Fetch the asset_cves table and index the unresolved rows by the asset
    they belong to. The table is documented but the per-table query permissions
    are not, so a rejected query is reported and the run continues with assets
    alone."""
    index = {}
    rows, err = run_query(ctx, "asset_cves | sort id", 1, 1)
    if err:
        print("nozomi-networks: CVE findings are unavailable on this appliance:", err)
        return index

    fetched = 0
    kept = 0
    pivot_id = ""
    page = 1
    for _request in range(1, 100001):
        query = "asset_cves | sort id"
        if pivot_id:
            query += " | where id > " + pivot_id

        rows, err = run_query(ctx, query, page, PAGE_SIZE)
        if err:
            print("nozomi-networks: failed to fetch CVE findings:", err)
            break
        if not rows:
            break

        last_id = ""
        for row in rows:
            if type(row) != "dict":
                continue
            last_id = as_text(row.get("id"), join=",").strip()
            # Nozomi keeps resolved findings in the table; importing them would
            # report vulnerabilities the asset no longer has.
            if _truthy(row.get("resolved")):
                continue
            asset_id = as_text(row.get("asset_id"), join=",").strip()
            if not asset_id:
                continue
            if asset_id not in index:
                index[asset_id] = []
            index[asset_id].append(row)
            kept += 1

        fetched += len(rows)
        if len(rows) < PAGE_SIZE:
            break
        if fetched >= MAX_CVE_ROWS:
            # A full final page means the table likely holds more; say so
            # loudly, because a silent cap looks exactly like a complete import.
            print("nozomi-networks: CVE ingestion stopped at the {}-row cap; findings beyond it were NOT imported".format(MAX_CVE_ROWS))
            break
        if page < MAX_PAGE:
            page += 1
            continue
        if not last_id or last_id == pivot_id:
            break
        pivot_id = last_id
        page = 1

    print("nozomi-networks: indexed {} unresolved CVE findings across {} assets".format(kept, len(index)))
    return index


def build_vulnerabilities(ctx, rows):
    """Convert the asset_cves rows that belong to one asset into findings."""
    vulns = []
    for row in rows:
        row_id = as_text(row.get("id"), join=",").strip()
        cve = as_text(row.get("cve"), join=",").strip()
        if not row_id and not cve:
            continue

        # A value that is not shaped like a CVE id -- a vendor advisory id, a
        # joined list, a typo in the appliance data -- would raise inside the
        # Vulnerability constructor and abort the task mid-stream. Screen it:
        # only a well-formed id is asserted as cve, and anything else still
        # travels as the finding's name and as an attribute.
        cve_id = cve.upper()
        if not re_match(CVE_RE, cve_id):
            cve_id = ""

        params = {
            "id": "{}:{}:cve:{}".format(VENDOR, ctx["scope"], row_id or cve),
            "name": (_clean(row.get("name")) or cve or row_id)[:255],
            "category": "CVE",
        }
        if cve_id:
            params["cve"] = cve_id

        summary = _clean(row.get("summary"))
        if summary:
            params["description"] = summary[:1024]

        # asset_cves names the first and the minimum fixed release rather than
        # carrying remediation prose.
        latest = _clean(row.get("latest_hotfix"))
        minimum = _clean(row.get("minimum_hotfix"))
        if minimum or latest:
            solution = "Minimum fixed version: {}".format(minimum) if minimum else ""
            if latest:
                if solution:
                    solution += ". "
                solution += "Latest fixed version: {}".format(latest)
            params["solution"] = solution[:1024]

        # "score" is the NVD severity score, but asset_cves does not publish
        # which CVSS version produced it, so it drives the severity and risk
        # ranks instead of being asserted as a cvss2 or cvss3 base score.
        score = _number(row.get("score"))
        rank = 0
        if score > 0.0:
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

        # A CISA known-exploited CVE is exploitable by definition.
        if _truthy(row.get("is_kev")):
            params["exploitable"] = True

        # Vulnerability.cpe23 accepts any "cpe:" binding, unlike Software.cpe23
        # which only accepts the CPE 2.2 "cpe:/a:" form. Nozomi does not
        # document which binding matching_cpes uses, so the value is checked
        # before it is assigned and otherwise kept as an attribute.
        cpes = dedupe(_list(row.get("matching_cpes")))
        if cpes and cpes[0].startswith("cpe:"):
            params["cpe23"] = cpes[0]

        published = _epoch_ms(row.get("creation_time"))
        if published:
            params["publishedTS"] = published
        detected = _epoch_ms(row.get("time"))
        if detected:
            params["firstDetectedTS"] = detected
        updated = _epoch_ms(row.get("update_time"))
        if updated:
            params["lastDetectedTS"] = updated

        params["customAttributes"] = to_custom_attributes({
            "cve_row_id": row_id,
            # The raw value as the appliance reported it, kept even when it was
            # not well-formed enough to assert as the cve field.
            "cve_id": cve,
            "cve_score": row.get("score"),
            "cve_epss_score": row.get("epss_score"),
            "cve_is_kev": row.get("is_kev"),
            "cve_likelihood": row.get("likelihood"),
            "cve_source": row.get("source"),
            "cve_cwe_id": row.get("cwe_id"),
            "cve_cwe_name": row.get("cwe_name"),
            "cve_matching_cpes": cpes,
            "cve_nodes": row.get("nodes"),
            "cve_references": row.get("references"),
            "cve_latest_hotfix": latest,
            "cve_minimum_hotfix": minimum,
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        vulns.append(Vulnerability(**params))
    return vulns


def build_software(ctx, asset, primary_ip):
    """Build a firmware Software record from the vendor, product, and firmware
    properties the assets table carries. Nothing is emitted when the appliance
    never determined any of them, which is common for passively observed gear."""
    vendor = _clean(asset.get("vendor"))
    product = _clean(asset.get("product_name"))
    firmware = _clean(asset.get("firmware_version"))
    if not vendor and not product and not firmware:
        return []

    params = {
        "id": "{}:{}:asset:{}:firmware".format(VENDOR, ctx["scope"], asset.get("id")),
        "product": product or "Firmware",
    }
    # An asset with no IP gets a firmware record with no serviceAddress rather
    # than a loopback placeholder, which is identical on every host.
    if primary_ip:
        params["serviceAddress"] = primary_ip
    if vendor:
        params["vendor"] = vendor
    if firmware:
        params["version"] = firmware
    # cpe23 is deliberately unset: the assets table publishes no CPE, and
    # Software.cpe23 only accepts the CPE 2.2 "cpe:/a:" binding.
    params["customAttributes"] = to_custom_attributes({
        "serial_number": _clean(asset.get("serial_number")),
        "os_or_firmware": _clean(asset.get("os_or_firmware")),
    }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return [Software(**params)]


def build_asset(ctx, asset):
    """Convert one row of the Nozomi assets table into a runZero asset."""
    asset_id = as_text(asset.get("id"), join=",").strip()
    ips = dedupe(_list(asset.get("ip")))
    macs = dedupe(_list(asset.get("mac_address")))
    primary_ip = ips[0] if ips else ""

    # OT gear is routinely multi-homed and the two arrays are not positionally
    # paired, so every MAC becomes an interface and the addresses ride on the
    # first one, matching how the eyeInspect import handles the same shape.
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

    name = _clean(asset.get("name"))
    hostnames = []
    if name and not _is_ip(name):
        hostnames = [name]

    level = _clean(asset.get("level"))
    zones = dedupe(_list(asset.get("zones")))
    roles = dedupe(_list(asset.get("roles")))
    protocols = dedupe(_list(asset.get("protocols")))

    tags = [VENDOR, "ot"]
    if level:
        tags.append("purdue-level:" + level)
    for zone in zones:
        tags.append("zone:" + zone)
    for role in roles:
        tags.append("role:" + role)
    for protocol in protocols:
        tags.append("protocol:" + protocol)

    attrs = {
        "asset_id": asset_id,
        "appliance": ctx["scope"],
        "appliance_hosts": asset.get("appliance_hosts"),
        "capture_device": asset.get("capture_device"),
        "capture_devices": asset.get("capture_devices"),
        "device_id": asset.get("device_id"),
        "is_ai_enriched": asset.get("is_ai_enriched"),
        "name": name,
        "level": level,
        "zones": zones,
        "roles": roles,
        # Protocol names only: the assets table records which protocols were
        # observed but never the ports they ran on, so no Service is built.
        "protocols": protocols,
        "nodes": asset.get("nodes"),
        "ip": ips,
        "mac_address": macs,
        "mac_vendor": asset.get("mac_vendor"),
        "mac_address_level": asset.get("mac_address_level"),
        "vlan_id": asset.get("vlan_id"),
        "type": _clean(asset.get("type")),
        "os": _clean(asset.get("os")),
        "os_or_firmware": _clean(asset.get("os_or_firmware")),
        "vendor": _clean(asset.get("vendor")),
        "product_name": _clean(asset.get("product_name")),
        "firmware_version": _clean(asset.get("firmware_version")),
        "serial_number": _clean(asset.get("serial_number")),
        "custom_fields": asset.get("custom_fields"),
    }
    # Nozomi records whether each property was observed passively or polled
    # actively; that provenance matters for OT change control.
    for field in SOURCED_FIELDS:
        info = asset.get(field + ":info")
        if type(info) == "dict":
            attrs[field + "_source"] = info.get("source")

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], asset_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags[:MAX_TAGS],
        "software": build_software(ctx, asset, primary_ip)[:MAX_CHILDREN],
        "vulnerabilities": build_vulnerabilities(ctx, ctx["cves"].get(asset_id, []))[:MAX_CHILDREN],        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    os_name = _clean(asset.get("os"))
    if os_name:
        params["os"] = os_name
    device_type = _clean(asset.get("type"))
    if device_type:
        params["deviceType"] = device_type
    manufacturer = _clean(asset.get("vendor"))
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = _clean(asset.get("product_name"))
    if model:
        params["model"] = model

    # The assets table publishes no first-seen or last-seen column, so neither
    # timestamp is set here.
    return ImportAsset(**params)


def build_assets(ctx, rows):
    """Convert a page of assets rows into runZero assets, skipping any row that
    carries no asset id."""
    assets = []
    for row in rows:
        if type(row) != "dict":
            continue
        asset_id = as_text(row.get("id"), join=",").strip()
        if not asset_id:
            print("nozomi-networks: skipping asset with no id: name=" + _clean(row.get("name")))
            continue
        assets.append(build_asset(ctx, row))
    return assets


def fetch_and_report_assets(ctx):
    """Fetch and stream assets one page at a time so the full inventory is
    never held in memory at once. Paging uses the documented page and count
    parameters over an id-sorted query; when the documented page ceiling is
    reached the query pivots past the last id seen and restarts at page 1,
    which is the pattern Nozomi prescribes for walking past that ceiling."""
    base_query = "assets | sort id"
    if ctx["asset_filter"]:
        base_query += " | " + ctx["asset_filter"]

    reported = 0
    pivot_id = ""
    page = 1
    for _request in range(1, 100001):
        query = base_query
        if pivot_id:
            query += " | where id > " + pivot_id

        rows, err = run_query(ctx, query, page, PAGE_SIZE)
        if err:
            print("nozomi-networks: failed to fetch assets:", err)
            return reported
        if not rows:
            break

        reported += report_assets(build_assets(ctx, rows))

        if len(rows) < PAGE_SIZE:
            break
        if page < MAX_PAGE:
            page += 1
            continue

        last_id = as_text(rows[-1].get("id"), join=",").strip() if type(rows[-1]) == "dict" else ""
        if not last_id or last_id == pivot_id:
            print("nozomi-networks: stopping, the assets query stopped advancing past id " + pivot_id)
            break
        pivot_id = last_id
        page = 1

    print("nozomi-networks: reported {} assets".format(reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        fail("nozomi-networks: could not determine the appliance host from the configured URL")

    headers = {"Accept": "application/json"}
    # The sign-in call needs the raw http.post builtin so it can read a
    # response header, and that builtin does not accept the retry keywords, so
    # the two option sets are built separately.
    post_options = get_http_options(kwargs, headers=headers)
    http_options = get_http_options(kwargs, headers=headers)
    # get_json retries the transient statuses (408/425/429/5xx) with backoff
    # and honors Retry-After. Three retries is the built-in default; it is set
    # explicitly here so the count is visible next to the backoff factor.
    http_options["retries"] = HTTP_RETRIES
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    asset_filter = get_string(kwargs, "asset_filter", default="").strip()
    if asset_filter.startswith("|"):
        asset_filter = asset_filter.lstrip("| ")

    ctx = {
        "base_url": base_url,
        "scope": scope,
        # Reuse the header set get_http_options built, so an Explorer-configured
        # User-Agent survives being re-stamped with the Authorization value.
        "headers": dict(http_options.get("headers", headers)),
        "post_options": post_options,
        "http_options": http_options,
        "key_name": get_string(kwargs, "key_name"),
        "key_token": get_string(kwargs, "key_token"),
        "sign_in_attempts": 0,
        "token_auth": False,
        "asset_filter": asset_filter,
        "cves": {},
    }
    ctx["token_auth"] = sign_in(ctx)

    if get_bool(kwargs, "include_cves", default=True):
        ctx["cves"] = fetch_cves(ctx)

    reported = fetch_and_report_assets(ctx)
    if not reported:
        print("nozomi-networks: no assets retrieved")
    return None

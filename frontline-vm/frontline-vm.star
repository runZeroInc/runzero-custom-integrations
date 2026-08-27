# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-frontline-vm",
    "name": "Frontline VM",
    "type": "inbound",
    "description": "Imports scanned hosts and their vulnerabilities from Fortra Frontline VM.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Frontline VM URL",
            "type": "url",
            "required": True,
            "default": "https://vm.frontline.cloud",
            "placeholder": "https://vm.frontline.cloud",
            "description": "Base URL of the Frontline.Cloud instance. Leave the default unless Fortra assigned a dedicated hostname.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Frontline.Cloud API token, sent as the Authorization: Token header.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch active-view vulnerabilities and attach them to the matching hosts.",
        },
        {
            "key": "min_vuln_severity",
            "label": "Minimum vulnerability severity",
            "type": "enum",
            "required": False,
            "options": ["critical", "high", "medium", "low", "trivial", "info"],
            "description": "Only import vulnerabilities at or above this DDI severity. Leave unset to import every severity.",
        },
        {
            "key": "max_days_since_scan",
            "label": "Maximum days since scan",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import hosts whose active-view record was created within this many days. Zero imports every host.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_duration', 'parse_ts')
load('re', re_find_all='find_all')

HOSTS_PATH = "/api/scanresults/active/hosts/"
VULNERABILITIES_PATH = "/api/scanresults/active/vulnerabilities/"

# Frontline grades findings on its own DDI scale rather than on CVSS bands.
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "TRIVIAL": 0,
    "INFO": 0,
}

# Frontline does not publish a CVE field on the vulnerability record, so the
# identifier is recovered by an exact-format scan of the title and data blob.
CVE_RE = r"(?i)CVE-[0-9]{4}-[0-9]{4,7}"

CHILD_LIMIT = 99
# get_json retries the transient statuses and honors Retry-After on its own;
# three retries is its default. Only the backoff factor is widened here.
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0

def _tenant_host(base_url):
    """Return the Frontline hostname, which is the tenant scope for host ids.

    The scheme is dropped so that switching the configured URL between http and
    https does not change the identity of already-imported assets.
    """
    return base_url.split("://")[-1]

def _index_filters(filters):
    """Rewrite filter keys into the positional _<n>_<key> form Frontline requires.

    The API silently ignores any filter parameter that is not prefixed with its
    ordinal position, so every filter must be built through this function or it
    will no-op without returning an error.
    """
    indexed = {}
    position = 0
    for key in filters:
        indexed["_{}_{}".format(position, key)] = filters[key]
        position += 1
    return indexed

def _get_page(url, http_options, params):
    """Fetch one page, omitting `params` entirely when there is nothing to send.

    Frontline's `next` cursor is an absolute URL that already carries the query
    string. Passing `params` replaces that query rather than merging into it, so
    an empty dict would silently restart pagination at the first page.
    """
    options = dict(http_options)
    if params:
        options["params"] = params
    return get_json(url, **options)
def _cutoff_date(days):
    """Return the UTC RFC 3339 timestamp `days` in the past, for date filters."""
    cutoff = now() - parse_duration("{}h".format(days * 24))
    return cutoff.in_location("UTC").format("2006-01-02T15:04:05Z")

def _first_cve(title, info):
    """Return the first CVE identifier present in the title or data blob.

    Only the exact CVE-YYYY-NNNN format is matched; nothing else is inferred
    from Frontline's free-form vulnerability text. The result is upper-cased
    because Vulnerability.cve is validated against ^CVE-[0-9]{4}-[0-9]{4,19}$
    before the type normalizes it, so a lower-case match fails the record.
    """
    matches = re_find_all(CVE_RE, title)
    if not matches and type(info) == "string":
        matches = re_find_all(CVE_RE, info)
    if not matches:
        return ""
    return matches[0].upper()

def _vulnerability_key(record):
    """Return the single join key a vulnerability record is indexed under.

    The active-view vulnerability record exposes no host id, so IP address and
    hostname are the only available join points. A finding is indexed under its
    IP alone when it has one: indexing under both would attach it to every host
    sharing the hostname, which Frontline allows across different addresses.
    """
    ip = str(record.get("ip_address", "") or "")
    if ip:
        return "ip:" + ip
    hostname = str(record.get("hostname", "") or "")
    if hostname:
        return "name:" + hostname.lower()
    return ""

def _host_keys(record):
    """Return the join keys for a host, most specific first."""
    keys = []
    ip = str(record.get("ip_address", "") or "")
    if ip:
        keys.append("ip:" + ip)
    for name in [record.get("hostname", ""), record.get("dns_name", "")]:
        name = str(name or "")
        if name:
            keys.append("name:" + name.lower())
    return keys

def _hostnames(record):
    """Return the host and DNS names, de-duplicated case-insensitively."""
    names = []
    seen = {}
    for value in [record.get("hostname", ""), record.get("dns_name", "")]:
        value = str(value or "")
        if not value:
            continue
        if seen.get(value.lower(), False):
            continue
        seen[value.lower()] = True
        names.append(value)
    return names

def _severity_counts(record):
    """Return the weighted DDI severity count map from an active-view host record."""
    counts = record.get("active_view_vulnerability_severity_counts", {})
    for key in ["weighted", "ddi", "counts"]:
        if type(counts) != "dict":
            return {}
        counts = counts.get(key, {})
    if type(counts) != "dict":
        return {}
    return counts

def build_vulnerability(record):
    """Convert one active-view vulnerability record into a Vulnerability object."""
    vuln_id = record.get("id")
    if vuln_id == None or vuln_id == "":
        return None

    title = str(record.get("title", "") or "")
    severities = record.get("severities", {})
    if type(severities) != "dict":
        severities = {}
    severity = str(severities.get("ddi", "") or "")

    # Frontline exposes one qualitative DDI grade and no numeric score, so the
    # same rank drives both severity and risk and the score fields stay unset.
    rank = SEVERITY_RANK.get(severity.upper(), 0)

    info = record.get("data")
    description = ""
    if type(info) == "string":
        description = info

    attrs = {
        "vuln_id": vuln_id,
        "severity_ddi": severity,
        "hostname": record.get("hostname", ""),
        "ip_address": record.get("ip_address", ""),
        "date_created": record.get("active_view_date_created", ""),
        "data": info,
    }

    # The vulnerability record ties a finding to a host, not to a socket: no
    # documented port, transport, or protocol field exists on it, so the
    # Vulnerability service fields are deliberately left unset.
    vuln_args = {
        "id": str(vuln_id)[:255],
        "name": title[:255],
        "description": description[:1024],
        "severityRank": rank,
        "riskRank": rank,
        "customAttributes": to_custom_attributes(attrs, prefix="frontline_vm", separator="_"),
    }

    cve = _first_cve(title, info)
    if cve:
        vuln_args["cve"] = cve

    detected = parse_ts(record.get("active_view_date_created"))
    if detected:
        vuln_args["firstDetectedTS"] = detected

    return Vulnerability(**vuln_args)

def build_asset(record, host_id, tenant_host, vulns):
    """Build a single ImportAsset from one active-view host record."""
    nic = network_interface(mac=str(record.get("mac_address", "") or ""),
                            ips=[str(record.get("ip_address", "") or "")])
    netifs = [nic] if nic else []

    counts = _severity_counts(record)

    attrs = {
        "host_id": host_id,
        "dns_name": record.get("dns_name", ""),
        # os_type is Frontline's operating-system family ("Windows", "Linux"),
        # not a device classification, so it is not mapped to deviceType.
        "os_type": record.get("os_type", ""),
        "date_created": record.get("date_created", ""),
        "vuln_counts": counts,
    }

    asset_args = {
        "id": "frontline-vm:{}:{}".format(tenant_host, host_id),
        "hostnames": _hostnames(record),
        "networkInterfaces": netifs,
        "os": str(record.get("os", "") or ""),
        "tags": ["frontline-vm"],
        "vulnerabilities": vulns[:CHILD_LIMIT],
        "customAttributes": to_custom_attributes(attrs, prefix="frontline_vm", separator="_"),
        # matchBehavior is deliberately left at the default. The active-view
        # host id is stable, and every record also carries a scanner-observed
        # MAC, IP, and hostname, so the network dimensions are corroborating
        # evidence rather than churn that needs to be suppressed.
    }

    # date_created is when the host entered the active view, which is the only
    # lifecycle timestamp on the record; Frontline exposes no last-seen field,
    # so lastSeenTS is left unset rather than filled with the same value.
    first_seen = parse_ts(record.get("date_created"))
    if first_seen:
        asset_args["firstSeenTS"] = first_seen

    return ImportAsset(**asset_args)

def build_assets(records, tenant_host, vuln_map):
    """Build one page of ImportAssets, attaching each host's vulnerabilities."""
    assets = []
    for record in records:
        if type(record) != "dict":
            print("frontline-vm: skipping malformed host record")
            continue
        host_id = record.get("id")
        if host_id == None or host_id == "":
            print("frontline-vm: skipping host with no id: ip=" + str(record.get("ip_address", "")))
            continue
        host_id = str(host_id)

        vulns = []
        for key in _host_keys(record):
            vulns = vuln_map.get(key, [])
            if vulns:
                break

        assets.append(build_asset(record, host_id, tenant_host, vulns))
    return assets

def fetch_vulnerability_map(base_url, http_options, min_severity):
    """Fetch active-view vulnerabilities and index them by host IP and hostname.

    Frontline exposes per-host findings only through a /hosts/<id>/vulnerabilities/
    sub-resource, so the flat list is fetched once and joined locally instead of
    issuing one request per host.
    """
    vuln_map = {}
    total = 0
    unjoinable = 0
    url = base_url + VULNERABILITIES_PATH
    params = {}
    if min_severity:
        # lte on the DDI scale selects everything at or above the named
        # severity, matching the vendor client's "minimum severity" filter.
        params = _index_filters({"lte_vuln_severity_ddi": min_severity})

    _pager1 = pager("frontline-vm-1")

    while _pager1.next():
        data, err = _get_page(url, http_options, params)
        if err:
            print("frontline-vm: failed to fetch vulnerabilities:", err)
            if err.startswith("status 401") or err.startswith("status 403"):
                print("frontline-vm: check the API token")
            return vuln_map
        data = data or {}
        records = data.get("results", []) or []
        for record in records:
            if type(record) != "dict":
                continue
            key = _vulnerability_key(record)
            if not key:
                unjoinable += 1
                continue
            vuln = build_vulnerability(record)
            if not vuln:
                continue
            existing = vuln_map.get(key, [])
            if len(existing) >= CHILD_LIMIT:
                continue
            existing.append(vuln)
            vuln_map[key] = existing
            total += 1

        # The cursor is an absolute URL that already carries the filter query,
        # so it is followed verbatim and no parameters are re-sent.
        url = str(data.get("next", "") or "")
        if not url:
            break
        params = {}

    print("frontline-vm: indexed {} vulnerabilities across {} hosts".format(total, len(vuln_map)))
    if unjoinable:
        print("frontline-vm: dropped {} vulnerabilities with no IP or hostname to join on".format(unjoinable))
    return vuln_map

def fetch_and_report_assets(base_url, http_options, max_days_since_scan, vuln_map):
    """Fetch and stream hosts one page at a time so the full set is never held
    in memory at once."""
    reported = 0
    url = base_url + HOSTS_PATH
    tenant_host = _tenant_host(base_url)
    params = {}
    if max_days_since_scan > 0:
        params = _index_filters({"gte_host_date_created": _cutoff_date(max_days_since_scan)})

    _pager2 = pager("frontline-vm-2")

    while _pager2.next():
        data, err = _get_page(url, http_options, params)
        if err:
            print("frontline-vm: failed to fetch hosts:", err)
            if err.startswith("status 401") or err.startswith("status 403"):
                print("frontline-vm: check the API token")
            return reported
        data = data or {}
        records = data.get("results", []) or []
        if records:
            assets = build_assets(records, tenant_host, vuln_map)
            if assets:
                reported += report_assets(assets)

        url = str(data.get("next", "") or "")
        if not url:
            break
        params = {}

    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    api_token = get_string(kwargs, "api_token")
    include_vulnerabilities = get_bool(kwargs, "include_vulnerabilities", default=True)
    min_severity = get_string(kwargs, "min_vuln_severity", default="")
    max_days_since_scan = get_int(kwargs, "max_days_since_scan", default=0)

    http_options = get_http_options(kwargs, headers={
        "Authorization": "Token " + api_token,
        "Accept": "application/json",
    })
    http_options["retries"] = HTTP_RETRIES
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF

    vuln_map = {}
    if include_vulnerabilities:
        vuln_map = fetch_vulnerability_map(base_url, http_options, min_severity)

    reported = fetch_and_report_assets(base_url, http_options, max_days_since_scan, vuln_map)
    if not reported:
        print("frontline-vm: no assets retrieved")
    return None

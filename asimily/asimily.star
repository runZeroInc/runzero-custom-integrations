# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-asimily",
    "name": "Asimily",
    "type": "inbound",
    "description": "Imports devices, open CVEs, and installed software from Asimily Insight.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # deviceID is authoritative and stable, but clinical devices are
    # regularly re-addressed and moved between facilities, so network
    # identifier churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Asimily portal URL",
            "type": "url",
            "required": True,
            "placeholder": "https://customer-portal.asimily.com",
            "description": "Base URL of the Asimily Insight portal.",
        },
        {
            "key": "username",
            "label": "API username",
            "type": "string",
            "required": True,
            "description": "Asimily Insight API user created under Settings > Users.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Password or API key for the Asimily Insight API user.",
        },
        {
            "key": "source",
            "label": "Source header",
            "type": "string",
            "required": False,
            "default": "runzero",
            "pattern": "[A-Za-z]+",
            "description": "Client identifier sent in Asimily's mandatory source header. Alphabetic characters only (A-Z, a-z): no spaces, digits, dots, hyphens, or underscores. Leave this at runzero unless Asimily has assigned your organization a different identifier.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import open CVEs",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch unfixed device CVEs and attach them to the matching assets.",
        },
        {
            "key": "include_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch installed applications. Asimily keys this endpoint on MAC address, so it costs one extra request per device and is slow on large inventories.",
        },
        {
            "key": "software_device_limit",
            "label": "Software device limit",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "description": "Maximum number of devices to query for installed software. Devices beyond this limit are imported without software and the skipped count is logged.",
        },
        {
            "key": "page_size",
            "label": "Asset page size",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 500,
            "description": "Devices requested per asset page. Lower this if the portal times out.",
        },
        {
            "key": "request_timeout",
            "label": "Request timeout (seconds)",
            "type": "int",
            "required": False,
            "default": 180,
            "min": 30,
            "description": "Per-request timeout. The Asimily API is slow; the reference client uses 180 seconds.",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 50000,
            "min": 1,
            "description": "Safety ceiling on the paging walk. Raise it if a run reports hitting the limit.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'post_json', 'basic')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_ts')
load('re', re_match='match')

ASSETS_PATH = "/api/extapi/assets"
APPLICATIONS_PATH = "/api/extapi/assets/application"
DEVICE_CVES_PATH = "/api/extapi/assets/device-cves"

# The device-cves endpoint returns one row per device with a nested cves array,
# so its pages are far heavier than asset pages and use a smaller size.
CVE_PAGE_SIZE = 50
CVE_SORT = "deviceInfoId"

# Asimily encodes fix state as a sentinel integer rather than a boolean.
CVE_STATE_FIXED = 55
CVE_STATE_NOT_FIXED = 56

# Asimily prioritized CVE score bands, taken from the reference client
# (high >= 7.5, medium >= 3.5). Critical is a runZero-side extension.
ASIMILY_RISK_CRITICAL = 9.0
ASIMILY_RISK_HIGH = 7.5
ASIMILY_RISK_MEDIUM = 3.5

# Standard CVSS v3 qualitative severity bands.
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

CHILD_LIMIT = 99

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so every page ceiling is that target
# divided by the page size. At the 200-device default asset page that is
# ceil(10,000,000 / 200) = 50,000 pages, which is the declared max_pages
# default; the heavier CVE page of 50 derives 200,000 from the same target.
#
# The ceiling is a BACKSTOP, not the working guard. The working guard is the
# repeated-page check in each walk: Asimily's own exit is `page + 1 >=
# totalPages`, and a portal that answers every `page` with the same rows while
# reporting a large totalPages never reaches it -- against that failure the
# ceiling IS the request count. Either stop is logged, because a truncated
# import that says nothing looks exactly like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = 50000

# get_json / post_json retry the transient statuses with backoff by default
# (3 retries). The Asimily API is slow and rate limited, so every call is
# raised to the budget the reference client uses (4 retries, 7.5 second backoff
# factor). Retry-After is honored by the helper.
HTTP_RETRIES = 4
HTTP_RETRY_BACKOFF = 7.5
HTTP_RETRY_MAX_BACKOFF = 120.0

# Vulnerability.cve is validated against this pattern by the platform and a
# value that misses it fails the whole ImportAsset, which aborts the run and
# loses every device already parsed. Asimily's cveName is not guaranteed to be
# a CVE id -- it carries lower-case spellings and vendor advisory ids -- so a
# candidate is screened before it is assigned.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

EPOCH_MILLIS_FLOOR = 100000000000

# Asimily requires a `source` header on EVERY REST call, carrying an identifier
# for "the client or organization making the request". Its stated rule is that
# only alphabetic characters are permitted -- "Spaces, commas, dots, hyphens,
# underscores, numbers, and any other non-alphabetic characters are strictly
# forbidden" -- with a mandatory enforcement date of 1 May 2026, after which a
# request carrying no compliant value "will be rejected by the Asimily API".
# A bad value therefore fails every request in the run rather than one, so it is
# screened once before the first call instead of being discovered N failures in.
SOURCE_RE = r"^[A-Za-z]+$"

# runZero is the client making the call, which is what the header identifies.
# The value is self-declared -- nothing in Asimily's published material issues,
# registers, or validates a per-customer identifier, and the vendor's own sample
# client just hardcodes one -- so this default is compliant by itself and only
# needs overriding if an Asimily representative assigns a specific value.
DEFAULT_SOURCE = "runzero"

def _device_key(record):
    """Return the Asimily device id as a string, accepting either spelling.

    The asset payload spells the field deviceID while the device-cves and
    anomalies payloads spell it deviceId. This function is the join point
    between the two endpoints, so both spellings are normalized here.
    """
    value = record.get("deviceID", None)
    if value == None:
        value = record.get("deviceId", None)
    if value == None:
        return ""
    return str(value)

def _score(value):
    """Coerce a vendor score to float, returning 0.0 for missing or non-numeric input."""
    if type(value) == "int" or type(value) == "float":
        return float(value)
    return 0.0

def _rank(score, critical, high, medium):
    """Map a 0-10 score onto the runZero 0-4 severity/risk rank."""
    if score >= critical:
        return 4
    if score >= high:
        return 3
    if score >= medium:
        return 2
    if score > 0:
        return 1
    return 0
def _portal_host(base_url):
    """Return the portal hostname, which is the tenant scope for device ids.

    The scheme is dropped so that switching the configured URL between http and
    https does not change the identity of already-imported assets.
    """
    return base_url.split("://")[-1]

def _string_list(value):
    """Return a list of non-empty strings from a value that may be a list or scalar."""
    if value == None:
        return []
    if type(value) != "list":
        if value == "":
            return []
        return [str(value)]
    out = []
    for item in value:
        if item == None or item == "":
            continue
        out.append(str(item))
    return out

def build_vulnerabilities(device_row):
    """Convert the cves array on one device-cves row into Vulnerability objects."""
    vulns = []
    seen = {}
    duplicates = 0
    for cve in device_row.get("cves", []) or []:
        if type(cve) != "dict":
            continue
        cve_name = str(cve.get("cveName", "") or "")
        if not cve_name:
            continue
        product_name = str(cve.get("productName", "") or "")
        # One device can carry the same CVE against more than one product, so
        # the product qualifies the vulnerability id.
        vuln_id = cve_name
        if product_name:
            vuln_id = "{}:{}".format(cve_name, product_name)
        vuln_id = vuln_id[:255]

        # A repeated cveName:productName pair on one device would emit two
        # Vulnerability children with the same id; the first entry wins.
        if vuln_id in seen:
            duplicates += 1
            continue
        seen[vuln_id] = True

        asimily_score = _score(cve.get("score"))
        cvss_base = _score(cve.get("cvssBaseScore"))

        attrs = {
            "cve_title": cve.get("cveTitle", ""),
            "product_name": product_name,
            "product_type": cve.get("productType", ""),
            "score": cve.get("score"),
            "cvss_base_score": cve.get("cvssBaseScore"),
            "is_fixed": cve.get("isFixed") == CVE_STATE_FIXED,
            "oem_patched": cve.get("oemPatched"),
            "is_muted": cve.get("isCveMuted"),
            "exploitable_in_wild": cve.get("exploitableInWild"),
            "nvd_publish_date": cve.get("nvdPublishDate", ""),
            "open_date": cve.get("openDate", ""),
            "fixed_date": cve.get("fixedDate", ""),
            # Kept so a value the platform pattern rejects is still searchable
            # after it has been dropped from the cve field below.
            "cve_name": cve_name,
        }

        # No port, transport, or address is available from this endpoint, so
        # the Vulnerability service fields are deliberately left unset.
        vuln_args = {
            "id": vuln_id,
            "name": cve_name,
            "description": str(cve.get("description", "") or "")[:1024],
            "solution": str(cve.get("fixedBy", "") or "")[:1024],
            "cvss3BaseScore": cvss_base,
            "severityScore": cvss_base,
            "severityRank": _rank(cvss_base, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM),
            "riskScore": asimily_score,
            "riskRank": _rank(asimily_score, ASIMILY_RISK_CRITICAL, ASIMILY_RISK_HIGH, ASIMILY_RISK_MEDIUM),
            "exploitable": cve.get("exploitableInWild") == True,
            "customAttributes": to_custom_attributes(attrs, prefix="asimily", separator="_"),
        }

        # Only a value the platform will accept reaches the cve field. The
        # finding is still imported either way: it keeps cveName as its name and
        # as the asimily_cve_name attribute, so an advisory Asimily tracks under
        # a non-CVE id is not silently lost.
        if re_match(CVE_RE, cve_name):
            vuln_args["cve"] = cve_name

        published = parse_ts(cve.get("nvdPublishDate"))
        if published:
            vuln_args["publishedTS"] = published
        opened = parse_ts(cve.get("openDate"))
        if opened:
            vuln_args["firstDetectedTS"] = opened

        vulns.append(Vulnerability(**vuln_args))
        if len(vulns) >= CHILD_LIMIT:
            break
    if duplicates:
        print("asimily: skipped {} duplicate CVE entries for device {}".format(
            duplicates, _device_key(device_row)))
    return vulns

def build_software(applications):
    """Convert the applications array for one device into Software objects."""
    software = []
    for entry in applications:
        if type(entry) != "dict":
            continue
        name = entry.get("application", "")
        version = str(entry.get("version", "") or "")
        # Observed responses carry a plain application name string, but tolerate
        # a nested object as well.
        if type(name) == "dict":
            version = str(name.get("version", version) or "")
            name = name.get("application", "") or name.get("name", "")
        name = str(name or "")
        if not name:
            continue
        if version == "*":
            version = ""
        software.append(Software(
            id=name[:255],
            product=name[:255],
            version=version[:255],
            serviceAddress="127.0.0.1",
        ))
        if len(software) >= CHILD_LIMIT:
            break
    return software

def fetch_software(base_url, http_options, mac):
    """Fetch installed applications for one device, keyed on its MAC address."""
    data, err = get_json(base_url + APPLICATIONS_PATH, params={"macAddr": mac},
                         **http_options)
    if err:
        print("asimily: failed to fetch applications for one device:", err)
        return []
    data = data or []
    if type(data) != "list" or not data:
        return []
    first = data[0]
    if type(first) != "dict":
        return []
    return build_software(first.get("applications", []) or [])

def build_asset(record, device_id, base_url, portal_host, vulns, software):
    """Build a single ImportAsset from one Asimily asset record."""
    ips = _string_list(record.get("v4IpAddrs")) + _string_list(record.get("v6IpAddrs"))
    nic = network_interface(mac=str(record.get("macAddr", "") or ""), ips=ips)
    netifs = [nic] if nic else []

    device_class = str(record.get("deviceClass", "") or "")
    facility = str(record.get("facility", "") or "")
    department = str(record.get("department", "") or "")

    tags = ["asimily"]
    if facility:
        tags.append("facility:" + facility)
    if department:
        tags.append("department:" + department)
    if device_class:
        tags.append("class:" + device_class)

    attrs = {
        "device_id": device_id,
        "device_class": device_class,
        "device_families": record.get("deviceFamilies", ""),
        "device_master_family": record.get("deviceMasterFamily", ""),
        "device_tag": record.get("deviceTag", ""),
        "serial_number": record.get("serialNumber", ""),
        "hardware_architecture": record.get("hardwareArchitecture", ""),
        "software_version": record.get("softwareVersion", ""),
        "location": record.get("location", ""),
        "facility": facility,
        "department": department,
        "region": record.get("region", ""),
        "risk_score": record.get("riskScore"),
        "likelihood": record.get("likelihood"),
        "impact": record.get("impact"),
        "is_connected": record.get("isConnected"),
        "is_wireless": record.get("isWireless"),
        "is_networking_device": record.get("isNetworkingDevice"),
        "is_currently_in_use": record.get("isCurrentlyInUse"),
        "managed_by": record.get("managedBy", ""),
        "anomaly_present": record.get("anomalyPresent"),
        "discovery_source": record.get("discoverySourceValue", ""),
        "mds2": record.get("mds2", ""),
        "stores_ephi": record.get("storesEphi"),
        "transmits_ephi": record.get("transmitEphi"),
        "uses_endpoint_security": record.get("isUsingEndpointSecurity"),
        "cmms_id": record.get("cmmsId", ""),
        "last_discovered_at": record.get("lastDiscoveredAt", ""),
        "portal_url": "{}/index.html#/asset/1/{}".format(base_url, device_id),
    }

    asset_args = {
        "id": "asimily:{}:{}".format(portal_host, device_id),
        "hostnames": [str(record.get("hostName", "") or "")],
        "networkInterfaces": netifs,
        "os": str(record.get("os", "") or ""),
        "osVersion": str(record.get("osVersion", "") or ""),
        "manufacturer": str(record.get("manufacturer", "") or ""),
        "model": str(record.get("deviceModel", "") or ""),
        # deviceType is the specific clinical/IT device type ("Infusion Pump");
        # deviceClass is the broader grouping and is carried as a tag instead.
        "deviceType": str(record.get("deviceType", "") or "") or device_class,
        "tags": tags,
        "software": software[:CHILD_LIMIT],
        "vulnerabilities": vulns[:CHILD_LIMIT],
        "customAttributes": to_custom_attributes(attrs, prefix="asimily", separator="_"),    }

    asset = ImportAsset(**asset_args)

    last_seen = parse_ts(record.get("lastDiscoveredAt"))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def build_assets(records, base_url, portal_host, http_options, vuln_map,
                 include_software, software_state):
    """Build one page of ImportAssets, attaching CVEs and optional software."""
    assets = []
    for record in records:
        if type(record) != "dict":
            print("asimily: skipping malformed device record")
            continue
        device_id = _device_key(record)
        if not device_id:
            print("asimily: skipping device with no deviceID: mac=" + str(record.get("macAddr", "")))
            continue

        vulns = vuln_map.get(device_id, [])

        software = []
        mac = str(record.get("macAddr", "") or "")
        if include_software and mac:
            if software_state["fetched"] < software_state["limit"]:
                software_state["fetched"] += 1
                software = fetch_software(base_url, http_options, mac)
            else:
                software_state["skipped"] += 1

        assets.append(build_asset(record, device_id, base_url, portal_host, vulns, software))
    return assets

def retrieved_of(reported, total):
    """The retrieved/available half of a truncation message.

    A bare count says nothing about whether the import is nearly complete or
    stopped at the first percent, so pair it with the total Asimily reports
    alongside every page (`totalElements`). Where a response omits it, say so
    plainly rather than printing a bare slash or inventing a denominator.
    """
    if type(total) == "int" and total > 0:
        return "retrieved {}/{} available assets".format(reported, total)
    return "retrieved {} assets, total not reported".format(reported)

def page_ceiling(config_kwargs, page_size):
    """The paging ceiling for one walk.

    An explicit max_pages wins. Otherwise the ceiling is the repo-wide ten
    million record target divided by the page size actually in use, so the
    heavier CVE page and the lighter asset page reach the same record target
    rather than the same page count.
    """
    requested = get_int(config_kwargs, "max_pages", default=MAX_PAGES)
    if requested != MAX_PAGES:
        return requested
    if page_size > 0:
        return (MAX_RECORDS + page_size - 1) // page_size
    return MAX_PAGES

def _page_signature(rows):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the portal re-served one
    page rather than honouring `page`. Comparing the ends rather than every row
    keeps this O(1) per page, and it is enough for the failure it guards
    against: a portal that ignores `page` returns the identical response, not a
    rearrangement of one.

    The ids go through _device_key because the two endpoints spell the field
    differently. Reading a key neither payload has would leave every full page
    with the same fingerprint of length-and-two-blanks, and the guard would then
    fire on the second page of a perfectly healthy walk and truncate it.
    """
    if not rows:
        return "empty"
    first = rows[0]
    last = rows[-1]
    first_id = _device_key(first) if type(first) == "dict" else ""
    last_id = _device_key(last) if type(last) == "dict" else ""
    return "{}|{}|{}".format(len(rows), first_id, last_id)

def _total_elements(data):
    """Asimily's count of everything the query matched, or None when absent."""
    value = data.get("totalElements")
    if type(value) == "int" and value >= 0:
        return value
    return None

def fetch_vulnerability_map(base_url, http_options, max_pages):
    """Fetch open device CVEs and index the Vulnerability objects by device id.

    The CVE endpoint returns one row per device with a nested cves array, so the
    map is built before assets are streamed and only the finished Vulnerability
    objects are retained.
    """
    vuln_map = {}
    total = 0
    url = base_url + DEVICE_CVES_PATH
    # 56 is the Asimily sentinel for "not fixed"; the reference client always
    # applies this filter so only open findings are imported.
    body = {"filters": {"isFixed": [{"operator": ":", "value": CVE_STATE_NOT_FIXED}]}}

    capped = True
    pages = 0
    last_signature = ""
    total_count = None

    for page in range(0, max_pages):
        data, err = post_json(url, json=body,
                              params={"page": page, "size": CVE_PAGE_SIZE, "sort": CVE_SORT},
                              **http_options)
        if err:
            print("asimily: failed to fetch device CVEs on page {}: {}".format(page, err))
            if err.startswith("status 401") or err.startswith("status 403"):
                print("asimily: check the API username and key")
            return vuln_map
        data = data or {}
        pages += 1
        reported_total = _total_elements(data)
        if reported_total != None:
            total_count = reported_total
        rows = data.get("content", []) or []
        if not rows:
            capped = False
            break

        # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it means
        # the portal ignored `page`, so the walk is not advancing and every
        # further request can only re-index findings already indexed. Checked
        # before the rows are merged, and it can never truncate genuine data: it
        # only fires on a page that adds nothing.
        signature = _page_signature(rows)
        if signature == last_signature:
            print("asimily: paging stopped after {} pages (API returned the same page twice walking device CVEs, {})".format(
                pages, retrieved_of(len(vuln_map), total_count)))
            capped = False
            break
        last_signature = signature

        for row in rows:
            if type(row) != "dict":
                continue
            device_id = _device_key(row)
            if not device_id:
                continue
            existing = vuln_map.get(device_id, [])
            for vuln in build_vulnerabilities(row):
                if len(existing) >= CHILD_LIMIT:
                    break
                existing.append(vuln)
                total += 1
            if existing:
                vuln_map[device_id] = existing
        total_pages = data.get("totalPages", 0) or 0
        if page + 1 >= total_pages:
            capped = False
            break

    if capped:
        print("asimily: page limit of {} hit (integration safety limit, walking device CVEs, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(len(vuln_map), total_count)))

    print("asimily: indexed {} open CVEs across {} devices".format(total, len(vuln_map)))
    return vuln_map

def fetch_and_report_assets(base_url, http_options, page_size, vuln_map,
                            include_software, software_state, max_pages):
    """Fetch and stream devices one page at a time so the full inventory is never
    held in memory at once."""
    reported = 0
    url = base_url + ASSETS_PATH
    portal_host = _portal_host(base_url)

    capped = True
    pages = 0
    last_signature = ""
    total_count = None

    for page in range(0, max_pages):
        data, err = get_json(url, params={"page": page, "size": page_size},
                             **http_options)
        if err:
            print("asimily: failed to fetch devices on page {}: {}".format(page, err))
            if err.startswith("status 401") or err.startswith("status 403"):
                print("asimily: check the API username and key")
            return reported
        data = data or {}
        pages += 1
        reported_total = _total_elements(data)
        if reported_total != None:
            total_count = reported_total
        records = data.get("content", []) or []
        if not records:
            capped = False
            break

        # THE PRIMARY RUNAWAY GUARD. See fetch_vulnerability_map: a repeated
        # page means `page` was ignored, and reporting it again would only
        # re-import devices already sent -- and, with include_software on,
        # re-issue a per-device software call for each of them.
        signature = _page_signature(records)
        if signature == last_signature:
            print("asimily: paging stopped after {} pages (API returned the same page twice walking devices, {})".format(
                pages, retrieved_of(reported, total_count)))
            capped = False
            break
        last_signature = signature

        assets = build_assets(records, base_url, portal_host, http_options, vuln_map,
                              include_software, software_state)
        if assets:
            reported += report_assets(assets)
        total_pages = data.get("totalPages", 0) or 0
        if page + 1 >= total_pages:
            capped = False
            break

    if capped:
        print("asimily: page limit of {} hit (integration safety limit, walking devices, {}) - raise the max_pages parameter to import the rest".format(
            max_pages, retrieved_of(reported, total_count)))

    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    username = get_string(kwargs, "username")
    api_key = get_string(kwargs, "api_key")
    include_vulnerabilities = get_bool(kwargs, "include_vulnerabilities", default=True)
    include_software = get_bool(kwargs, "include_software", default=False)
    software_device_limit = get_int(kwargs, "software_device_limit", default=100)
    page_size = get_int(kwargs, "page_size", default=200)
    timeout = get_int(kwargs, "request_timeout", default=180)

    # Screened before the first request: a non-compliant value is rejected by
    # Asimily on every call, so one legible message beats a run's worth of
    # identical failures. See SOURCE_RE.
    source = get_string(kwargs, "source", default=DEFAULT_SOURCE)
    if not re_match(SOURCE_RE, source):
        print(("asimily: not starting: the source header value must be alphabetic characters " +
               "only (A-Z, a-z), with no spaces, digits, dots, hyphens or underscores; got '{}'").format(source))
        fail("asimily: Asimily rejects requests carrying a non-compliant source value, so every request in this run would fail")

    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(username, api_key),
        "Accept": "application/json",
        "source": source,
    })
    http_options["timeout"] = timeout
    http_options["retries"] = HTTP_RETRIES
    http_options["retry_backoff"] = HTTP_RETRY_BACKOFF
    http_options["retry_max_backoff"] = HTTP_RETRY_MAX_BACKOFF

    vuln_map = {}
    if include_vulnerabilities:
        vuln_map = fetch_vulnerability_map(base_url, http_options,
                                           page_ceiling(kwargs, CVE_PAGE_SIZE))

    software_state = {"fetched": 0, "skipped": 0, "limit": software_device_limit}
    reported = fetch_and_report_assets(base_url, http_options, page_size, vuln_map,
                                       include_software, software_state,
                                       page_ceiling(kwargs, page_size))

    if include_software:
        print("asimily: fetched software for {} devices".format(software_state["fetched"]))
        if software_state["skipped"]:
            print("asimily: skipped software for {} devices; raise the software device limit ({}) to cover more".format(
                software_state["skipped"], software_device_limit))
    if not reported:
        print("asimily: no assets retrieved")
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cisco-secure-endpoint",
    "name": "Cisco Secure Endpoint",
    "type": "inbound",
    "description": "Imports connector-managed computers and vulnerable application findings from Cisco Secure Endpoint.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # connector_guid identifies a connector installation, not a machine, and
    # Cisco documents it failing in both directions: a full uninstall and
    # reinstall registers a new GUID for an unchanged host, while a golden
    # image built with a populated local.xml hands one GUID to every clone.
    # So id-break is turned off, letting a reinstalled connector land on the
    # existing asset instead of forking it, while mac-break and name-break
    # stay on so a shared golden-image GUID cannot collapse a fleet onto one
    # asset. Only ip-break is relaxed alongside it: these endpoints roam and
    # a stale DHCP address is not evidence of a different machine.
    "matchBehavior": "no-id-break no-ip-break",
    "params": [
        {
            "key": "api_host",
            "label": "Secure Endpoint API host",
            "type": "url",
            "required": True,
            "default": "https://api.amp.cisco.com",
            "description": "Regional API endpoint that matches the console your business is provisioned in. North America https://api.amp.cisco.com, Europe https://api.eu.amp.cisco.com, Asia Pacific/Japan/China https://api.apjc.amp.cisco.com, consumer https://api.consumer.amp.cisco.com.",
        },
        {
            "key": "client_id",
            "label": "3rd Party API Client ID",
            "type": "string",
            "required": True,
            "description": "Client ID issued with the API credential under Accounts > API Credentials.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "API key issued alongside the Client ID. Read-only scope is sufficient.",
        },
        {
            "key": "import_vulnerabilities",
            "label": "Import vulnerable application findings",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Make one extra request per computer to attach the CVEs Secure Endpoint observed on it. Off by default because it costs one request per computer against a 3000 request per hour budget.",
        },
        {
            "key": "vulnerability_limit",
            "label": "Vulnerability enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of computers to enrich with findings. Computers past the limit are still imported, without vulnerabilities. 0 removes the cap.",
        },
        {
            "key": "active_only",
            "label": "Only import active connectors",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Skip computers the console reports as inactive.",
        },
        {
            "key": "include_demo",
            "label": "Include demo computers",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import the sample computers Cisco seeds into evaluation businesses. These are fabricated hosts and are excluded by default.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 500,
            "description": "Records requested per page. The API caps this at 500.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_time', 'parse_ts')
load('re', re_match='match', re_sub='sub')

load('coerce', 'dicts')
VENDOR = "cisco-secure-endpoint"
# to_custom_attributes joins prefix to each key with separator, so the prefix
# carries underscores to keep the emitted attribute names consistent.
ATTR_PREFIX = "cisco_secure_endpoint"

COMPUTERS_PATH = "/v1/computers"

MAX_PAGE_SIZE = 500
MAX_VULNS_PER_ASSET = 99
# One page of vulnerable applications per computer is plenty to fill the
# per-asset child cap, and keeps the enrichment pass at exactly one request
# per computer.
VULN_PAGE_SIZE = 100

# Secure Endpoint allows 3000 requests per hour per business and answers 429
# once that budget is spent, so back off generously instead of racing it.
HTTP_RETRY_BACKOFF = 2.0

# Vulnerability.cve is validated against this pattern by the platform and a
# value that misses it fails the whole record, so candidates are screened.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# operating_system is a free-form display string with no documented format, and
# its shape varies by connector generation: "Windows 10", "Windows 10, SP 0.0",
# "Windows 10 (Build 19044.1466)", "Windows Server 2019 Datacenter",
# "OS X 10.14.6". Only these two confirmed suffixes are trimmed; anything else
# is left exactly as reported and the raw value is kept as an attribute.
OS_SUFFIX_RE = r"(,\s*SP\s*[0-9.]+|\s*\(Build\s+[0-9.]+\))$"

# The documented "healthy" isolation state. Anything else is worth a tag.
ISOLATION_NORMAL = "not_isolated"

# Distributions that ship only as a server platform. The Linux connector often
# reports a bare "Linux", which says nothing, but the tenants that report the
# distribution name are worth reading. Ubuntu and Debian are deliberately
# absent: each is as often a workstation as a server. So is SUSE Linux
# Enterprise *Desktop*, which is why the list carries sles and not a bare
# "suse" substring.
SERVER_OS_NAMES = [
    "red hat enterprise", "rhel", "centos", "rocky linux", "almalinux",
    "amazon linux", "oracle linux", "suse linux enterprise server", "sles",
]


def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    return str(value or "").strip()
def _to_float(value):
    """Return a numeric score as a float, or -1.0 when it is absent or not a
    number. The API serializes an unscored CVE as null."""
    if type(value) in ("int", "float"):
        return float(value)
    text = _clean(value)
    if not text:
        return -1.0
    seen_dot = False
    for index in range(len(text)):
        char = text[index]
        if char == ".":
            if seen_dot:
                return -1.0
            seen_dot = True
        elif char not in "0123456789":
            return -1.0
    return float(text)
def _score_rank(score):
    """Convert a CVSS base score to a runZero 0-4 rank using the standard bands."""
    if score < 0.1:
        return 0
    if score < 4.0:
        return 1
    if score < 7.0:
        return 2
    if score < 9.0:
        return 3
    return 4


def _scope(base_url):
    """Return the regional API hostname used to namespace asset ids."""
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url


def split_os(operating_system, os_version):
    """Split the reported OS strings into a product name and a version.

    `operating_system` is a free-form product name that carries a Windows
    service pack or build suffix ("Windows 10, SP 0.0", "Windows 10 (Build
    19044.1466)") and, on macOS, repeats the release already present in
    `os_version` ("OS X 10.14.6"). `os_version` is the precise build
    ("10.0.19044.1466"), so it wins as the version and its text is trimmed off
    the tail of the name when it is duplicated there. Nothing else is parsed
    out of the name, because the format is undocumented and varies by
    connector generation.
    """
    name = re_sub(OS_SUFFIX_RE, "", _clean(operating_system)).strip()
    version = _clean(os_version)
    if version and name.endswith(" " + version):
        name = name[:len(name) - len(version)].strip()
    return name, version


def _device_type(os_name):
    """Return a runZero device type for one computer record, or "".

    The computer object names no chassis -- there is no model, no manufacturer
    and no asset class anywhere in it, and this integration reports none -- so
    the only genuine statement of role is an OS that says what it is. "Windows
    Server 2019 Datacenter" and the server-only distributions above are
    unambiguous.

    A bare "Windows 10", "OS X 10.14.6" or "Linux" stays unset: it is a desktop
    or a laptop and the record cannot say which, and a wrong hint is worse than
    none.

    This is only a hint, and runZero prefers anything it can derive from the
    hardware or from its own scan. Since nothing here feeds the hardware
    fingerprinter, for an endpoint runZero has never reached this is the only
    type it will have.
    """
    text = os_name.lower()
    if "server" in text:
        return "Server"
    for name in SERVER_OS_NAMES:
        if name in text:
            return "Server"
    return ""


def build_vulnerabilities(scope, connector_guid, records):
    """Convert the vulnerable applications observed on one computer into runZero
    findings. Secure Endpoint reports a vulnerable file, not a listening socket,
    so no service fields are set on the finding."""
    vulns = []
    seen = {}
    for record in records:
        application = _clean(record.get("application"))
        version = _clean(record.get("version"))
        file_info = record.get("file", {})
        if type(file_info) != "dict":
            file_info = {}
        identity = file_info.get("identity", {})
        if type(identity) != "dict":
            identity = {}
        sha256 = _clean(identity.get("sha256")).lower()
        filename = _clean(file_info.get("filename"))
        detected = parse_ts(record.get("latest_date"))

        for entry in dicts(record.get("cves")):
            # The platform validates cve against a strict upper-case pattern and
            # rejects the whole record on a miss, so screen before assigning.
            cve = _clean(entry.get("id")).upper()
            if not re_match(CVE_RE, cve):
                continue
            key = "{}:{}".format(sha256 or application, cve)
            if key in seen:
                continue
            seen[key] = True

            params = {
                "id": "{}:{}:{}:{}:{}".format(VENDOR, scope, connector_guid, cve,
                                              sha256 or application),
                "name": cve,
                "cve": cve,
                "category": "CVE",
            }
            description = " ".join([part for part in [application, version] if part])
            if description:
                params["description"] = description

            # The feed publishes one unlabelled "cvss" number per CVE with no
            # version attached, so it drives severity and risk rather than being
            # guessed into cvss2BaseScore or cvss3BaseScore.
            score = _to_float(entry.get("cvss"))
            if score >= 0:
                params["severityScore"] = score
                params["severityRank"] = _score_rank(score)
                params["riskScore"] = score
                params["riskRank"] = _score_rank(score)
            if detected:
                params["lastDetectedTS"] = detected

            attrs = {
                "application": application,
                "application_version": version,
                "file_name": filename,
                "file_sha256": sha256,
                "reference": _clean(entry.get("link")),
            }
            params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                              separator="_")
            vulns.append(Vulnerability(**params))
    return vulns


def build_network_interfaces(computer):
    """Build one interface per reported MAC/IP pair, falling back to the bare
    internal address list when the connector reported no adapters."""
    netifs = []
    covered = {}
    for address in dicts(computer.get("network_addresses")):
        mac = _clean(address.get("mac"))
        ips = []
        routable = routable_ip(address.get("ip"))
        if routable:
            ips.append(routable)
            covered[routable] = True
        # network_interface returns None when neither the MAC nor any address
        # survived, which is what a loopback-only adapter reduces to.
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            netifs.append(nic)

    # internal_ips is the same address set without the MAC pairing, so it only
    # contributes what the adapter list missed.
    leftovers = []
    internal = computer.get("internal_ips")
    for value in internal if type(internal) == "list" else []:
        routable = routable_ip(value)
        if routable and routable not in covered:
            leftovers.append(routable)
            covered[routable] = True
    if leftovers:
        nic = network_interface(ips=leftovers)
        if nic:
            netifs.append(nic)

    # external_ip is deliberately excluded: it is the NAT egress address shared
    # by every connector behind one gateway, and attaching it to an interface
    # would invite unrelated endpoints to merge together.
    return netifs


def build_asset(scope, computer):
    """Convert one computer record into an ImportAsset."""
    connector_guid = _clean(computer.get("connector_guid"))
    if not connector_guid:
        print("cisco-secure-endpoint: skipping computer with no connector_guid: hostname=" +
              _clean(computer.get("hostname")))
        return None

    policy = computer.get("policy", {})
    if type(policy) != "dict":
        policy = {}
    isolation = computer.get("isolation", {})
    if type(isolation) != "dict":
        isolation = {}
    orbital = computer.get("orbital", {})
    if type(orbital) != "dict":
        orbital = {}

    group_guid = _clean(computer.get("group_guid"))
    policy_name = _clean(policy.get("name"))
    group_names = [_clean(group.get("name")) for group in dicts(computer.get("groups"))]
    group_names = [name for name in group_names if name]

    os_name, os_version = split_os(computer.get("operating_system"),
                                   computer.get("os_version"))

    av_definitions = computer.get("av_update_definitions", {})
    if type(av_definitions) != "dict":
        av_definitions = {}
    host_firewall = computer.get("host_firewall", {})
    if type(host_firewall) != "dict":
        host_firewall = {}

    internal = computer.get("internal_ips")
    isolation_status = _clean(isolation.get("status")).lower().replace(" ", "_")
    attrs = {
        "active": computer.get("active"),
        "av_definitions_status": _clean(av_definitions.get("status")),
        "av_detection_engine": _clean(av_definitions.get("detection_engine")),
        "connector_guid": connector_guid,
        "connector_version": _clean(computer.get("connector_version")),
        "csc_id": _clean(computer.get("csc_id")),
        "demo": computer.get("demo"),
        "external_ip": _clean(computer.get("external_ip")),
        "faults": [_clean(fault) for fault in computer.get("faults") or []
                   if type(fault) == "string"],
        "group_guid": group_guid,
        "group_names": group_names,
        "host_firewall_status": _clean(host_firewall.get("status")),
        "install_date": _clean(computer.get("install_date")),
        "internal_ips": internal if type(internal) == "list" else [],
        "is_compromised": computer.get("is_compromised"),
        "isolation_available": isolation.get("available"),
        "isolation_status": _clean(isolation.get("status")),
        "last_seen": _clean(computer.get("last_seen")),
        # Windows connectors report windows_processor_id; macOS connectors
        # report mac_hardware_id in its place.
        "mac_hardware_id": _clean(computer.get("mac_hardware_id")),
        "operating_system": _clean(computer.get("operating_system")),
        "orbital_status": _clean(orbital.get("status")),
        "os_version": _clean(computer.get("os_version")),
        "policy_guid": _clean(policy.get("guid")),
        "policy_name": policy_name,
        "risk_score": computer.get("risk_score"),
        "windows_processor_id": _clean(computer.get("windows_processor_id")),
    }

    tags = ["cisco-secure-endpoint"]
    if policy_name:
        tags.append("policy:" + policy_name)
    if group_guid:
        tags.append("group:" + group_guid)
    if isolation_status and isolation_status != ISOLATION_NORMAL:
        tags.append("isolation:" + isolation_status)
    if computer.get("demo") == True:
        tags.append("demo")
    if computer.get("is_compromised") == True:
        tags.append("compromised")

    params = {
        "id": "{}:{}:{}".format(VENDOR, scope, connector_guid),
        "hostnames": [_clean(computer.get("hostname"))],
        "networkInterfaces": build_network_interfaces(computer),
        "tags": tags,        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                 separator="_"),
    }

    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version

    # Omitted rather than set to "" when the OS names no role: an empty
    # deviceType is still a value and displaces the type runZero would
    # otherwise derive for itself.
    device_type = _device_type(os_name)
    if device_type:
        params["deviceType"] = device_type

    first_seen = parse_ts(computer.get("install_date"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = parse_ts(computer.get("last_seen"))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(scope, computers):
    """Convert one page of computer records into ImportAsset objects."""
    assets = []
    for computer in computers:
        asset = build_asset(scope, computer)
        if asset:
            assets.append(asset)
    return assets


def build_vulnerability_asset(scope, connector_guid, records):
    """Build an enrichment asset carrying one computer's vulnerable applications."""
    vulns = build_vulnerabilities(scope, connector_guid, records)
    if not vulns:
        return None
    return ImportAsset(
        id="{}:{}:{}".format(VENDOR, scope, connector_guid),
        vulnerabilities=vulns[:MAX_VULNS_PER_ASSET],
    )


def keep_computer(computer, active_only, include_demo):
    """Report whether a computer record survives the configured filters."""
    if active_only and computer.get("active") != True:
        return False
    if not include_demo and computer.get("demo") == True:
        return False
    return True


def fetch_vulnerabilities(base_url, http_options, connector_guid):
    """Fetch the vulnerable applications observed on one computer."""
    url = "{}{}/{}/vulnerabilities".format(base_url, COMPUTERS_PATH, connector_guid)
    data, err = get_json(url, params={"limit": VULN_PAGE_SIZE, "offset": 0},
                         retry_backoff=HTTP_RETRY_BACKOFF, **http_options)
    if err:
        return [], err
    data = data or {}
    payload = data.get("data", {})
    if type(payload) != "dict":
        return [], "unexpected data shape"
    return dicts(payload.get("vulnerabilities")), None


def report_page_vulnerabilities(base_url, http_options, scope, computers, budget):
    """Enrich up to `budget` computers from one page with their findings.

    Returns the number of computers enriched. A single failing computer is
    logged and skipped rather than abandoning the run, because one connector
    with no vulnerability history should not cost the whole import.
    """
    enriched = 0
    for computer in computers:
        if budget != None and enriched >= budget:
            break
        connector_guid = _clean(computer.get("connector_guid"))
        if not connector_guid:
            continue
        records, err = fetch_vulnerabilities(base_url, http_options, connector_guid)
        if err:
            print("cisco-secure-endpoint: failed to fetch vulnerabilities for {}: {}".format(
                connector_guid, err))
            enriched += 1
            continue
        enriched += 1
        asset = build_vulnerability_asset(scope, connector_guid, records)
        if asset:
            report_assets(asset)
    return enriched


def fetch_and_report_computers(base_url, http_options, scope, page_size, active_only,
                               include_demo, import_vulnerabilities, vulnerability_limit):
    """Fetch and stream computers one page at a time so the full set is never
    held in memory at once, optionally enriching each page with findings."""
    reported = 0
    enriched = 0
    offset = 0
    total = -1
    _pager = pager("cisco-secure-endpoint")
    while _pager.next():
        data, err = get_json(base_url + COMPUTERS_PATH,
                             params={"limit": page_size, "offset": offset},
                             retry_backoff=HTTP_RETRY_BACKOFF, **http_options)
        if err:
            print("cisco-secure-endpoint: failed to fetch computers:", err)
            return reported, enriched
        data = data or {}
        rows = data.get("data", [])
        if type(rows) != "list":
            print("cisco-secure-endpoint: stopping: unexpected data shape at offset", offset)
            return reported, enriched
        if not rows:
            break

        if total < 0:
            results = (data.get("metadata", {}) or {}).get("results", {}) or {}
            if type(results.get("total")) == "int":
                total = results["total"]
                print("cisco-secure-endpoint: {} computers reported by the API".format(total))

        computers = [row for row in rows if type(row) == "dict" and
                     keep_computer(row, active_only, include_demo)]
        reported += report_assets(build_assets(scope, computers))

        if import_vulnerabilities:
            budget = None
            if vulnerability_limit > 0:
                budget = vulnerability_limit - enriched
                if budget <= 0:
                    import_vulnerabilities = False
            if import_vulnerabilities:
                enriched += report_page_vulnerabilities(base_url, http_options, scope,
                                                        computers, budget)

        if len(rows) < page_size:
            break
        offset += page_size
    return reported, enriched


def main(**kwargs):
    require(kwargs, "api_host", "client_id", "api_key")
    base_url = get_url_base(kwargs, "api_host")
    client_id = get_string(kwargs, "client_id")
    api_key = get_string(kwargs, "api_key")
    import_vulnerabilities = get_bool(kwargs, "import_vulnerabilities", default=False)
    vulnerability_limit = get_int(kwargs, "vulnerability_limit", default=1000)
    active_only = get_bool(kwargs, "active_only", default=False)
    include_demo = get_bool(kwargs, "include_demo", default=False)
    page_size = get_int(kwargs, "page_size", default=MAX_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE
    if vulnerability_limit < 0:
        vulnerability_limit = 0

    # The v1 API authenticates with HTTP Basic, using the 3rd Party API Client
    # ID as the username and the API key as the password.
    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(client_id, api_key),
        "Accept": "application/json",
    })
    scope = _scope(base_url)

    reported, enriched = fetch_and_report_computers(
        base_url, http_options, scope, page_size, active_only, include_demo,
        import_vulnerabilities, vulnerability_limit)
    print("cisco-secure-endpoint: reported {} computers".format(reported))
    if import_vulnerabilities:
        print("cisco-secure-endpoint: checked {} computers for vulnerabilities".format(enriched))
    if not reported:
        print("cisco-secure-endpoint: no assets retrieved")
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-uptycs",
    "name": "Uptycs",
    "type": "inbound",
    "description": "Imports assets, software, services, and vulnerabilities from Uptycs.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Uptycs URL",
            "type": "url",
            "required": True,
            "placeholder": "https://tenant.uptycs.io",
            "description": "Uptycs tenant URL built from the domain field of the downloaded API key file.",
        },
        {
            "key": "customer_id",
            "label": "Customer ID",
            "type": "string",
            "required": True,
            "description": "Uptycs customer (tenant) identifier from the API key file.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "The key value from the Uptycs API key file. Used as the JWT issuer claim.",
        },
        {
            "key": "api_secret",
            "label": "API secret",
            "type": "secret",
            "required": True,
            "description": "The secret value from the Uptycs API key file. Used to sign the JWT.",
        },
        {
            "key": "include_host_details",
            "label": "Import MAC addresses, IP addresses, and serials",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Query the interface_details, interface_addresses, and system_info osquery tables.",
        },
        {
            "key": "include_software",
            "label": "Import software inventory",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Query the programs, apps, deb_packages, and rpm_packages osquery tables.",
        },
        {
            "key": "include_services",
            "label": "Import listening services",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Query the listening_ports osquery table. This can return a large number of rows.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import vulnerabilities",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Query the vulnerability table named below. Off by default because the table name is tenant specific.",
        },
        {
            "key": "vulnerability_table",
            "label": "Vulnerability table name",
            "type": "string",
            "required": False,
            "default": "upt_vulnerabilities_state",
            "description": "Data lake table queried when vulnerability import is enabled.",
        },
        {
            "key": "lookback_days",
            "label": "Enrichment lookback (days)",
            "type": "int",
            "required": False,
            "default": 3,
            "min": 1,
            "max": 90,
            "description": "How many days of the upt_day partition to scan for software, service, and interface rows.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'Service', 'ServiceProtocolData', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'post_json', 'bearer')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_bool', 'get_int')
load('time', 'now', 'parse_time', 'parse_duration', 'parse_ts')
load('jwt', jwt_encode='encode')
load('re', re_sub='sub', re_match='match')

QUERY_PATH = "/public/api/customers/{}/query"

# Assets are paged with LIMIT/OFFSET. Every enrichment table is then queried
# once per asset page with a WHERE upt_asset_id IN (...) filter, so the SQL
# text and the row count both stay bounded by the page size.
ASSET_PAGE_SIZE = 200
ROW_PAGE_SIZE = 2000
MAX_TABLE_ROWS = 20000
MAX_CHILDREN = 99

# The shared HTTP helper applies exponential backoff and honors Retry-After.
# Three retries is its default, restated here so the bound is visible.
HTTP_RETRIES = 3

# Uptycs signs requests with a locally-minted HS256 JWT; there is no token
# exchange endpoint. A fresh token is minted for each asset page so a long run
# never presents an expired assertion.
TOKEN_LIFETIME = "1h"
RFC1123 = "Mon, 02 Jan 2006 15:04:05 GMT"

# Custom attribute namespace. to_custom_attributes joins the prefix to each key
# with the separator, so these two together produce "uptycs_<key>".
ATTR_PREFIX = "uptycs"
ATTR_SEPARATOR = "_"

# osquery software tables, normalized onto a common alias shape so one builder
# handles all of them. Only the tables that exist for a platform return rows.
SOFTWARE_TABLES = [
    {"table": "programs", "product": "name", "version": "version", "vendor": "publisher", "extra": "install_location"},
    {"table": "apps", "product": "name", "version": "bundle_short_version", "vendor": "bundle_identifier", "extra": "path"},
    {"table": "deb_packages", "product": "name", "version": "version", "vendor": "maintainer", "extra": "arch"},
    {"table": "rpm_packages", "product": "name", "version": "version", "vendor": "vendor", "extra": "arch"},
]

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
SKIP_ADDRESSES = ["", "0.0.0.0", "127.0.0.1", "::", "::1"]
EMPTY_MAC = "00:00:00:00:00:00"

# osquery reports every interface on a host, including the container, VPN, and
# hypervisor adapters that the OS itself created. Those must not become network
# interfaces: a container bridge such as docker0 carries the same deterministic
# MAC on every host that runs Docker, and a virtual switch address is shared by
# every guest on a hypervisor, so importing them attaches one host's adapters to
# unrelated assets. Matched case-insensitively against the osquery interface
# name, as a prefix for the numbered families and exactly otherwise.
VIRTUAL_INTERFACE_PREFIXES = [
    "lo", "docker", "veth", "virbr", "vmnet", "vboxnet", "br-", "cni",
    "flannel", "cali", "tun", "tap", "utun", "wg", "zt", "tailscale",
    "vethernet", "awdl", "llw", "bridge", "gpd", "nordlynx", "ham",
]


def _is_virtual_interface(name):
    """Report whether an osquery interface name is a virtual adapter."""
    lowered = name.strip().lower()
    if not lowered:
        return True
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix):
            # Guard the short prefixes against swallowing real adapters: "lo"
            # must not match "lom1", and "tun"/"tap" must not match a vendor
            # name. A real virtual adapter is the bare prefix or the prefix
            # followed by a digit, a separator, or a parenthesised label.
            rest = lowered[len(prefix):]
            if not rest:
                return True
            if rest[0] in "0123456789-_. (":
                return True
    return False

# Vulnerability.cve is validated against this pattern by the platform and a
# value that misses it fails the whole ImportAsset, which aborts the run and
# loses every asset already parsed. cve_list is plural -- a row covering several
# CVEs returns an array that str() renders as '["CVE-...", "CVE-..."]' -- and a
# tenant may file its own advisory ids there, so it is screened before use.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": 0}
SEVERITY_SCORE = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0, "NONE": 0.0}

# upt_vulnerabilities_state spells these cve_list / uptycs_severity /
# cvss_score / package_name, but the exact table exposed varies by tenant, so
# findings are read from the first alias that is present.
VULN_ALIASES = {
    "cve": ["cve_list", "cve", "cve_id", "cveid", "vulnerability_id"],
    "title": ["title", "name", "summary", "vulnerability_name"],
    "description": ["description", "vuln_desc", "details", "synopsis"],
    "severity": ["uptycs_severity", "severity", "severity_level", "cve_severity"],
    "score": ["cvss_score", "uptycs_score", "cvss3_score", "cvss_base_score", "base_score"],
    "solution": ["solution", "remediation", "fix_version"],
    "package": ["package_name", "software_name", "affected_package", "product"],
    "package_version": ["package_version", "installed_version"],
}


def _auth_headers(api_key, api_secret):
    """Mint a short-lived HS256 JWT and return the Uptycs request headers."""
    issued = now().in_location("UTC")
    expires = issued + parse_duration(TOKEN_LIFETIME)
    token = jwt_encode({"iss": api_key, "exp": expires.unix}, api_secret, algorithm="HS256")
    return {
        "Authorization": bearer(token),
        "date": issued.format(RFC1123),
        "Accept": "application/json",
    }


def _sql_id_list(values):
    """Render ids as a SQL IN list, dropping any character outside the Uptycs id
    alphabet so API data can never alter the shape of a query."""
    quoted = []
    for value in values:
        clean = re_sub(r"[^0-9A-Za-z_.-]", "", str(value))
        if clean:
            quoted.append("'" + clean + "'")
    return ",".join(quoted)


def _run_query(query_url, http_options, sql):
    """Run one global SQL query and return (items, err). Callers treat a
    non-nil err as a missing or unauthorized table and continue without it."""
    data, err = post_json(query_url, json={"query": sql, "queryType": "global"},
                          retries=HTTP_RETRIES, **http_options)
    if err:
        return [], err
    data = data or {}
    return data.get("items", []) or [], None


def _collect_rows(query_url, http_options, label, select_sql, order_sql):
    """Page one data lake table with LIMIT/OFFSET and return (rows, err).

    The pager label is the table being walked, so a bound failure names the
    collection that did not terminate. MAX_TABLE_ROWS exits the walk long
    before the CONFIG page bound in practice.
    """
    rows = []
    offset = 0
    p = pager(label)
    while p.next():
        sql = "{} ORDER BY {} LIMIT {} OFFSET {}".format(select_sql, order_sql, ROW_PAGE_SIZE, offset)
        items, err = _run_query(query_url, http_options, sql)
        if err:
            return rows, err
        rows.extend(items)
        if len(items) < ROW_PAGE_SIZE:
            return rows, None
        if len(rows) >= MAX_TABLE_ROWS:
            print("uptycs: capped {} at {} rows for this asset page".format(label, MAX_TABLE_ROWS))
            return rows, None
        offset += ROW_PAGE_SIZE
    return rows, None


def _collect_osquery_rows(query_url, http_options, table, select_clause, order_sql, asset_ids, day_min):
    """Collect distinct rows from one osquery table for a page of assets.

    Uptycs re-collects these tables every few hours, so the query is bounded by
    the upt_day partition and de-duplicated by the engine. upt_day is injected
    into osquery tables by the Uptycs agent pipeline rather than defined by
    osquery, so a table that rejects the predicate is retried without it."""
    base = "SELECT DISTINCT {} FROM {} WHERE upt_asset_id IN ({})".format(
        select_clause, table, _sql_id_list(asset_ids))

    rows, err = _collect_rows(query_url, http_options, table,
                              "{} AND upt_day >= {}".format(base, day_min), order_sql)
    if not err:
        return rows, None

    rows, retry_err = _collect_rows(query_url, http_options, table, base, order_sql)
    if retry_err:
        return rows, retry_err
    print("uptycs: {} rejected the upt_day filter, queried without a time bound".format(table))
    return rows, None


def _first_value(row, names):
    """Return the first non-empty value among the candidate column names."""
    for name in names:
        value = row.get(name)
        if value != None and str(value) != "":
            return value
    return ""
def _partition_day(lookback_days):
    """Return the upt_day partition value (YYYYMMDD) for the lookback window."""
    cutoff = now().in_location("UTC") - parse_duration("{}h".format(lookback_days * 24))
    return int(cutoff.format("20060102"))


def _to_float(value):
    """Coerce a score to a float, returning None for anything non-numeric."""
    text = str(value).strip()
    if not text:
        return None
    if not re_match(r"^-?[0-9]+(\.[0-9]+)?$", text):
        return None
    return float(text)


def _to_int(value):
    """Coerce a numeric column to an int, returning None when it is not one.

    JSON numbers can arrive as either 6 or 6.0 depending on the column type, so
    a trailing fractional zero is tolerated and anything else is rejected --
    int() on a non-numeric string is a fatal error in Starlark."""
    text = str(value).strip()
    matched = re_match(r"^([0-9]+)(\.0+)?$", text)
    if not matched:
        return None
    return int(matched.groups[1])


def build_vulnerabilities(query_url, http_options, asset_ids, table):
    """Collect vulnerability findings keyed by Uptycs asset id."""
    findings = {}
    clean_table = re_sub(r"[^0-9A-Za-z_]", "", str(table))
    if not clean_table:
        print("uptycs: vulnerability table name is empty, skipping vulnerabilities")
        return findings

    select_sql = "SELECT * FROM {} WHERE upt_asset_id IN ({})".format(clean_table, _sql_id_list(asset_ids))
    rows, err = _collect_rows(query_url, http_options, clean_table, select_sql, "upt_asset_id")
    if err:
        print("uptycs: skipping vulnerabilities from {}: {}".format(clean_table, err))
        return findings

    seen = {}
    for row in rows:
        asset_id = str(row.get("upt_asset_id", ""))
        if not asset_id:
            continue
        cve = str(_first_value(row, VULN_ALIASES["cve"]))
        title = str(_first_value(row, VULN_ALIASES["title"]))
        package = str(_first_value(row, VULN_ALIASES["package"]))
        package_version = str(_first_value(row, VULN_ALIASES["package_version"]))
        name = title or cve
        if not name:
            continue

        severity = str(_first_value(row, VULN_ALIASES["severity"])).upper()
        rank = SEVERITY_RANK.get(severity, 0)
        score = SEVERITY_SCORE.get(severity, 0.0)
        raw_score = _to_float(_first_value(row, VULN_ALIASES["score"]))
        if raw_score != None:
            score = raw_score
            if severity not in SEVERITY_RANK:
                if score >= 9.0:
                    rank = 4
                elif score >= 7.0:
                    rank = 3
                elif score >= 4.0:
                    rank = 2
                elif score > 0.0:
                    rank = 1

        key = "{}|{}|{}".format(asset_id, cve or name, package)
        if key in seen:
            continue
        seen[key] = True

        vuln_id = cve or name
        if package:
            vuln_id = "{}:{}".format(vuln_id, package)
        params = {
            "id": vuln_id[:255],
            "name": name[:255],
            "description": str(_first_value(row, VULN_ALIASES["description"]))[:1024],
            "solution": str(_first_value(row, VULN_ALIASES["solution"]))[:1024],
            "severityRank": rank,
            "severityScore": float(score),
            "riskRank": rank,
            "riskScore": float(score),
            "customAttributes": to_custom_attributes({
                "table": clean_table,
                "package": package,
                "package_version": package_version,
                "severity": severity,
                # Kept so a value the platform pattern rejects -- a multi-CVE
                # array, or a tenant-local advisory id -- is still searchable.
                "cve_list": cve,
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        # Only a value the platform will accept reaches the cve field; the
        # finding is imported either way, identified by cve_list above. The
        # pattern already bounds the value at 29 characters, so the previous
        # [:20] truncation is gone -- it could only turn a good id into a bad one.
        if re_match(CVE_RE, cve):
            params["cve"] = cve
        finding = Vulnerability(**params)
        if asset_id not in findings:
            findings[asset_id] = []
        findings[asset_id].append(finding)

    return findings


def build_software(query_url, http_options, asset_ids, day_min):
    """Collect installed software keyed by Uptycs asset id."""
    installed = {}
    seen = {}
    for spec in SOFTWARE_TABLES:
        table = spec["table"]
        select_clause = "upt_asset_id AS asset_id, {} AS product, {} AS version, {} AS vendor, {} AS extra".format(
            spec["product"], spec["version"], spec["vendor"], spec["extra"])
        order_sql = "upt_asset_id, {}".format(spec["product"])

        rows, err = _collect_osquery_rows(query_url, http_options, table, select_clause,
                                          order_sql, asset_ids, day_min)
        if err:
            print("uptycs: skipping software from {}: {}".format(table, err))
            continue

        for row in rows:
            asset_id = str(row.get("asset_id", ""))
            product = str(row.get("product", "") or "")
            if not asset_id or not product:
                continue
            version = str(row.get("version", "") or "")
            key = "{}|{}|{}".format(asset_id, product, version)
            if key in seen:
                continue
            seen[key] = True

            if asset_id not in installed:
                installed[asset_id] = []
            if len(installed[asset_id]) >= MAX_CHILDREN:
                continue
            installed[asset_id].append(Software(
                id="{}:{}:{}".format(table, product, version)[:255],
                product=product[:255],
                version=version[:255],
                vendor=str(row.get("vendor", "") or "")[:255],
                installedFrom=str(row.get("extra", "") or "")[:255],
                serviceAddress="127.0.0.1",
                customAttributes=to_custom_attributes({"table": table},
                                                      prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            ))

    return installed


def build_services(query_url, http_options, asset_ids, primary_ips, day_min):
    """Collect listening ports as runZero services keyed by Uptycs asset id."""
    listening = {}
    select_clause = ("upt_asset_id AS asset_id, address AS address, port AS port, " +
                     "protocol AS protocol, pid AS pid, path AS path")

    rows, err = _collect_osquery_rows(query_url, http_options, "listening_ports", select_clause,
                                      "upt_asset_id, port", asset_ids, day_min)
    if err:
        print("uptycs: skipping services from listening_ports:", err)
        return listening

    seen = {}
    for row in rows:
        asset_id = str(row.get("asset_id", ""))
        if not asset_id:
            continue
        protocol = _to_int(row.get("protocol", ""))
        if protocol == None:
            transport = TRANSPORTS.get(str(row.get("protocol", "")).lower())
        else:
            transport = TRANSPORTS.get(str(protocol))
        if not transport:
            continue
        port = _to_int(row.get("port", ""))
        if port == None or port <= 0 or port > 65535:
            continue

        address = str(row.get("address", "") or "").strip()
        if address in WILDCARD_ADDRESSES:
            address = primary_ips.get(asset_id, "")
        if not address or address in SKIP_ADDRESSES:
            continue

        key = "{}|{}|{}|{}".format(asset_id, address, port, transport)
        if key in seen:
            continue
        seen[key] = True

        if asset_id not in listening:
            listening[asset_id] = []
        if len(listening[asset_id]) >= MAX_CHILDREN:
            continue
        listening[asset_id].append(Service(
            address=address,
            port=port,
            transport=transport,
            protocolData=[ServiceProtocolData(name="osquery", attributes={
                "pid": str(row.get("pid", "") or ""),
                "path": str(row.get("path", "") or ""),
            })],
        ))

    return listening


def build_interfaces(query_url, http_options, asset_ids, day_min):
    """Collect MACs and IPs per interface, keyed by Uptycs asset id."""
    interfaces = {}

    mac_rows, err = _collect_osquery_rows(
        query_url, http_options, "interface_details",
        "upt_asset_id AS asset_id, interface AS interface, mac AS mac",
        "upt_asset_id, interface", asset_ids, day_min)
    if err:
        print("uptycs: skipping MAC addresses from interface_details:", err)
        mac_rows = []

    addr_rows, err = _collect_osquery_rows(
        query_url, http_options, "interface_addresses",
        "upt_asset_id AS asset_id, interface AS interface, address AS address",
        "upt_asset_id, interface", asset_ids, day_min)
    if err:
        print("uptycs: skipping IP addresses from interface_addresses:", err)
        addr_rows = []

    for row in mac_rows:
        asset_id = str(row.get("asset_id", ""))
        name = str(row.get("interface", "") or "")
        mac = str(row.get("mac", "") or "").strip().lower()
        if not asset_id or not name or not mac or mac == EMPTY_MAC:
            continue
        if _is_virtual_interface(name):
            continue
        if asset_id not in interfaces:
            interfaces[asset_id] = {}
        if name not in interfaces[asset_id]:
            interfaces[asset_id][name] = {"mac": "", "ips": []}
        interfaces[asset_id][name]["mac"] = mac

    for row in addr_rows:
        asset_id = str(row.get("asset_id", ""))
        name = str(row.get("interface", "") or "")
        address = str(row.get("address", "") or "").strip()
        if not asset_id or not name or address in SKIP_ADDRESSES:
            continue
        if _is_virtual_interface(name):
            continue
        if asset_id not in interfaces:
            interfaces[asset_id] = {}
        if name not in interfaces[asset_id]:
            interfaces[asset_id][name] = {"mac": "", "ips": []}
        if address not in interfaces[asset_id][name]["ips"]:
            interfaces[asset_id][name]["ips"].append(address)

    return interfaces


def build_system_info(query_url, http_options, asset_ids, day_min):
    """Collect hardware serials and system UUIDs keyed by Uptycs asset id."""
    details = {}
    select_clause = ("upt_asset_id AS asset_id, hardware_serial AS hardware_serial, " +
                     "uuid AS system_uuid, computer_name AS computer_name")

    rows, err = _collect_osquery_rows(query_url, http_options, "system_info", select_clause,
                                      "upt_asset_id", asset_ids, day_min)
    if err:
        print("uptycs: skipping serials from system_info:", err)
        return details

    for row in rows:
        asset_id = str(row.get("asset_id", ""))
        if not asset_id or asset_id in details:
            continue
        details[asset_id] = {
            "hardware_serial": str(row.get("hardware_serial", "") or ""),
            "system_uuid": str(row.get("system_uuid", "") or ""),
            "computer_name": str(row.get("computer_name", "") or ""),
        }

    return details


def primary_ip_map(interfaces):
    """Pick one routable IPv4-looking address per asset for service addresses."""
    primary = {}
    for asset_id, by_interface in interfaces.items():
        for _name, detail in by_interface.items():
            for address in detail["ips"]:
                if "." in address and asset_id not in primary:
                    primary[asset_id] = address
    return primary


# os_flavor is osquery's platform value, which on Linux is the os-release ID.
# These distributions ship only as server platforms, so the flavor alone is a
# fair statement of role. Deliberately absent are ubuntu, debian, fedora, arch,
# opensuse and darwin, which are as often a workstation as a server, and sled
# (SUSE Linux Enterprise *Desktop*), which is the desktop half of sles.
SERVER_OS_FLAVORS = [
    "rhel", "redhat", "centos", "rocky", "almalinux", "alma",
    "amzn", "ol", "oraclelinux", "sles",
]


def _device_type(item):
    """Return a runZero device type for one upt_assets row, or "".

    upt_assets has no asset-class column -- the record is host_name, os,
    os_version, os_flavor, hardware_vendor, hardware_model and telemetry, and
    nothing in it names a chassis -- so the only genuine type signal is an OS
    that says what it is. A product name carrying "server" ("Windows Server
    2022", "SUSE Linux Enterprise Server") and the server-only distributions
    above are unambiguous. A bare "Windows", "Ubuntu" or "Mac OS X" is not: it
    is a desktop or a laptop and the record cannot say which, so it is left
    unset rather than guessed at.

    This is a hint. runZero prefers anything it can derive from the hardware or
    from its own scan and only falls back to this, which is exactly the case
    for a cloud instance whose model is "Virtual Machine" and which no scan has
    ever reached.
    """
    flavor = str(item.get("os_flavor", "") or "").strip().lower()
    text = "{} {} {}".format(item.get("os", "") or "",
                             item.get("os_version", "") or "", flavor).lower()
    if "server" in text:
        return "Server"
    if flavor in SERVER_OS_FLAVORS:
        return "Server"
    return ""


def build_asset(item, customer_id, extras):
    """Build one ImportAsset from an upt_assets row plus its enrichment rows."""
    source_id = item.get("id")
    if not source_id:
        print("uptycs: skipping asset with no id: host_name=" + str(item.get("host_name", "")))
        return None
    source_id = str(source_id)

    netifs = []
    for _name, detail in extras["interfaces"].get(source_id, {}).items():
        nic = network_interface(mac=detail["mac"], ips=detail["ips"])
        if nic:
            netifs.append(nic)

    system = extras["system_info"].get(source_id, {})
    hostnames = []
    for name in [str(item.get("host_name", "") or ""), system.get("computer_name", "")]:
        if name and name not in hostnames:
            hostnames.append(name)

    attrs = {
        "asset_id": source_id,
        "host_name": item.get("host_name", ""),
        "os_flavor": item.get("os_flavor", ""),
        "osquery_version": item.get("osquery_version", ""),
        "status": item.get("status", ""),
        "live": item.get("live", ""),
        "deleted_at": item.get("deleted_at", ""),
        "location": item.get("location", ""),
        "latitude": item.get("latitude", ""),
        "longitude": item.get("longitude", ""),
        "gateway": item.get("gateway", ""),
        "cores": item.get("cores", ""),
        "memory_mb": item.get("memory_mb", ""),
        "cpu_brand": item.get("cpu_brand", ""),
        "object_group_id": item.get("object_group_id", ""),
        "created_at": item.get("created_at", ""),
        "last_enrolled_at": item.get("last_enrolled_at", ""),
        "last_activity_at": item.get("last_activity_at", ""),
        "hardware_serial": system.get("hardware_serial", ""),
        "system_uuid": system.get("system_uuid", ""),
        "computer_name": system.get("computer_name", ""),
    }

    asset_params = {
        "id": "uptycs:{}:{}".format(customer_id, source_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "os": str(item.get("os", "") or ""),
        "osVersion": str(item.get("os_version", "") or ""),
        "manufacturer": str(item.get("hardware_vendor", "") or ""),
        "model": str(item.get("hardware_model", "") or ""),
        "tags": ["uptycs"],
        "software": extras["software"].get(source_id, [])[:MAX_CHILDREN],
        "services": extras["services"].get(source_id, [])[:MAX_CHILDREN],
        "vulnerabilities": extras["vulnerabilities"].get(source_id, [])[:MAX_CHILDREN],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    # Omitted rather than set to "" when the OS says nothing about the role: an
    # empty deviceType is still a value and displaces the type runZero would
    # otherwise derive for itself.
    device_type = _device_type(item)
    if device_type:
        asset_params["deviceType"] = device_type

    first_seen = parse_ts(item.get("created_at", ""))
    if first_seen:
        asset_params["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_params)

    last_seen = parse_ts(item.get("last_activity_at", ""))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(items, customer_id, extras):
    """Build the ImportAssets for one page of upt_assets rows."""
    assets = []
    for item in items:
        asset = build_asset(item, customer_id, extras)
        if asset:
            assets.append(asset)
    return assets


def collect_extras(query_url, http_options, asset_ids, options):
    """Run the enabled enrichment queries for one page of asset ids. Every
    table is queried independently so one missing table never stops the run."""
    extras = {"interfaces": {}, "system_info": {}, "software": {}, "services": {}, "vulnerabilities": {}}
    if not asset_ids:
        return extras

    day_min = options["day_min"]
    if options["host_details"]:
        extras["interfaces"] = build_interfaces(query_url, http_options, asset_ids, day_min)
        extras["system_info"] = build_system_info(query_url, http_options, asset_ids, day_min)
    if options["software"]:
        extras["software"] = build_software(query_url, http_options, asset_ids, day_min)
    if options["services"]:
        extras["services"] = build_services(query_url, http_options, asset_ids,
                                            primary_ip_map(extras["interfaces"]), day_min)
    if options["vulnerabilities"]:
        extras["vulnerabilities"] = build_vulnerabilities(query_url, http_options, asset_ids,
                                                          options["vulnerability_table"])
    return extras


def fetch_and_report_assets(query_url, config_kwargs, api_key, api_secret, customer_id, options):
    """Fetch and stream upt_assets one page at a time so the full inventory is
    never held in memory at once."""
    reported = 0
    offset = 0
    p = pager("uptycs-assets")
    while p.next():
        http_options = get_http_options(config_kwargs, headers=_auth_headers(api_key, api_secret))
        sql = "SELECT * FROM upt_assets ORDER BY id LIMIT {} OFFSET {}".format(ASSET_PAGE_SIZE, offset)
        items, err = _run_query(query_url, http_options, sql)
        if err:
            print("uptycs: failed to fetch assets:", err)
            return reported
        if not items:
            break

        asset_ids = []
        for item in items:
            source_id = item.get("id")
            if source_id:
                asset_ids.append(str(source_id))

        extras = collect_extras(query_url, http_options, asset_ids, options)
        reported += report_assets(build_assets(items, customer_id, extras))
        print("uptycs: reported {} assets so far".format(reported))

        if len(items) < ASSET_PAGE_SIZE:
            break
        offset += ASSET_PAGE_SIZE
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    customer_id = get_string(kwargs, "customer_id")
    api_key = get_string(kwargs, "api_key")
    api_secret = get_string(kwargs, "api_secret")

    options = {
        "host_details": get_bool(kwargs, "include_host_details", default=True),
        "software": get_bool(kwargs, "include_software", default=True),
        "services": get_bool(kwargs, "include_services", default=False),
        "vulnerabilities": get_bool(kwargs, "include_vulnerabilities", default=False),
        "vulnerability_table": get_string(kwargs, "vulnerability_table", default="upt_vulnerabilities_state"),
        "day_min": _partition_day(get_int(kwargs, "lookback_days", default=3)),
    }

    query_url = base_url + QUERY_PATH.format(customer_id)
    reported = fetch_and_report_assets(query_url, kwargs, api_key, api_secret, customer_id, options)
    if not reported:
        print("uptycs: no assets retrieved")
    return None

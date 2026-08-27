# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-tenable-ot-security",
    "name": "Tenable OT Security",
    "type": "inbound",
    "description": "Imports OT and IT assets, plugin findings, OS hotfixes, and open ports from a Tenable OT Security console.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Asset.id is a console-assigned UUID that survives rename, readdress, and
    # reclassification, so default id matching stays on. Only name breaking is
    # relaxed: the console names most assets synthetically ("OT Device #966"),
    # so a name disagreement is no evidence against a first-contact merge.
    # mac-break and ip-break are kept. See README "Asset identity".
    "matchBehavior": "no-name-break",
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "OT Security console URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ot.example.com",
            "description": "Base URL of the Tenable OT Security console. The /graphql path is appended automatically.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Key generated under Local Settings > System Configuration > API Keys. Sent as X-APIKeys: key=<value>.",
        },
        {
            "key": "page_size",
            "label": "Assets per page",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 1000,
            "description": "Value of the GraphQL first argument. pyTenable uses 200, Elastic uses 1000.",
        },
        {
            "key": "lookback_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Only import assets created or updated within this many days. 0 imports the whole inventory.",
        },
        {
            "key": "include_hidden",
            "label": "Include hidden assets",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import assets an operator has hidden in the console. Hidden assets are excluded by default, as in pyTenable.",
        },
        {
            "key": "import_vulnerabilities",
            "label": "Import plugin findings",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Select each asset's plugins in the same query and attach them as vulnerabilities. Makes the console do more work per page.",
        },
        {
            "key": "import_software",
            "label": "Import OS hotfixes as software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Select osDetails.hotFixes and attach each installed hotfix as software. Makes the console do more work per page.",
        },
        {
            "key": "import_services",
            "label": "Import open ports as services",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Select the open ports recorded against each direct interface address. This is the deepest selection in the document -- interface, then address, then port -- so it is off by default.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames', 'mac_key')
load('http', 'post_json', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('coerce', 'as_text', 'as_dict', 'as_list', 'dicts', 'as_int', 'as_float', 'as_bool', 'dedupe')
load('time', 'now', 'parse_duration', 'parse_ts')
load('re', re_match='match')

VENDOR = "tenable-ot-security"
ATTR_PREFIX = "tenable_ot_security"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# The whole API is one endpoint: "Tenable OT Exposure uses a GraphQL API
# instead of a REST API so querying data ... is handled via a single API
# endpoint (/graphql)".
GRAPHQL_PATH = "/graphql"

# Most of these double as the server-side `first:` bound on the matching nested
# connection, so the console never materializes rows this script would throw
# away. MAX_HOSTNAMES and MAX_SERVICES_PER_ASSET are totals gathered across
# several connections, so no single `first:` expresses them; they stay
# client-side.
MAX_VULNS_PER_ASSET = 99
MAX_SOFTWARE_PER_ASSET = 99
MAX_SERVICES_PER_ASSET = 99
MAX_INTERFACES_PER_ASSET = 20
MAX_IPS_PER_INTERFACE = 16
MAX_PORTS_PER_IP = 32
MAX_ADDRESSES = 64
MAX_DNS_NAMES = 8
MAX_HOSTNAMES = 8
MAX_SEGMENT_TAGS = 10

# Vulnerability.cve is validated against this shape and a miss fails the WHOLE
# record, not just the field, so every candidate is checked before it is set.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# The sentinel members of PurdueLevel and Criticality. They mean "nobody has
# classified this" rather than naming a level, so they are dropped instead of
# becoming a tag every unclassified asset shares. The criticality sentinel is
# spelled here as it reads after the redundant suffix is stripped.
PURDUE_UNKNOWN = "UnknownLevel"
CRITICALITY_NONE = "None"

# runZero severity ranks run 0-4. Lookups are done on the upper-cased value
# with a trailing SEVERITY or CRITICALITY stripped, so the suffixed spelling
# the sibling Criticality enum uses (MediumCriticality) also resolves. An
# unrecognized value ranks 0 rather than failing the record.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
                 "INFORMATIONAL": 0, "NONE": 0}

# The last-resort stand-in for severityScore. plugin_score prefers a real CVSS
# base score wherever the plugin publishes one; this only fills in for a plugin
# that carries none, so the finding still sorts against the rest of the estate.
SEVERITY_SCORE = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0,
                  "INFO": 0.0, "INFORMATIONAL": 0.0, "NONE": 0.0}

# OpenPorts publishes a port and the protocol most likely spoken on it, but no
# transport, so one is assumed and the assumption is recorded on the service.
DEFAULT_TRANSPORT = "tcp"

# pyTenable's documented default sort. Sorting on the immutable id rather than
# on lastUpdate keeps the cursor walk stable while assets are being updated
# underneath it.
ASSET_SORT = [{"field": "id", "direction": "DescNullLast"}]

# pyTenable's default filter. Hidden assets are ones an operator has explicitly
# suppressed in the console.
HIDDEN_FILTER = {"op": "Equal", "field": "hidden", "values": "false"}

QUERY_HEAD = """query getAssets($first: Int, $after: String, $filter: AssetExpressionsParams, $sort: [AssetSortParams!]) {
  assets(first: $first, after: $after, filter: $filter, sort: $sort) {
    nodes {
"""

QUERY_TAIL = """    }
    pageInfo { hasNextPage endCursor }
  }
}"""

# Everything pyTenable's ASSETS_QUERY adds on top of the Elastic-verified set.
# These come from the vendor's own client rather than from a console capture,
# so a release that does not publish one of them fails GraphQL validation for
# the whole document, which is why the minimal fallback exists.
EXTRA_FIELDS = """      vendor
      model
      serial
      family
      location
      slot
      firmwareVersion
      os
      description
      backplane { id name size }
      customField1
      customField2
      customField3
      customField4
      customField5
      customField6
      customField7
      customField8
      customField9
      customField10
"""


def bound(name, limit):
    """Render a Relay connection field with its server-side `first:` bound.

    Every nested connection here is truncated client-side anyway, so an
    unbounded selection makes the console assemble rows this script immediately
    discards, once per asset, 200 assets to the page.
    """
    return name + "(first: " + str(limit) + ")"


def address_fields():
    """The flat address lists.

    These stay selected even though directNetworkInterfaces supersedes them for
    interface building: they are the only address source in the minimal
    document, the fallback when the console returns no interface connection,
    and both full lists are kept as attributes.
    """
    limit = MAX_ADDRESSES
    return ("      " + bound("ips", limit) + " { nodes }\n" +
            "      " + bound("macs", limit) + " { nodes }\n" +
            "      " + bound("directIps", limit) + " { nodes }\n" +
            "      " + bound("directMacs", limit) + " { nodes }\n")


def minimal_fields():
    """The field set Elastic's shipping tenable_ot_security package selects.

    It is the one selection confirmed against a real console, so it is what the
    script falls back to if the wider selection is rejected.
    """
    return ("""      id
      name
      firstSeen
      lastSeen
      lastHit
      lastUpdate
      type
      superType
      category
      purdueLevel
      criticality
      hidden
      runStatus
      runStatusTime
      risk { totalRisk }
""" + address_fields() +
            "      " + bound("segments", MAX_SEGMENT_TAGS) + " { nodes { id name type } }\n")


def interfaces_block(include_services):
    """Select the direct network interfaces, their DNS names, and their ports.

    directNetworkInterfaces rather than networkInterfaces: a NetworkInterface
    carries `directAsset`, so the associated connection includes interfaces
    belonging to a sibling backplane module or a fronting gateway. dnsNames is
    the only real hostname source the console has, since Asset.name is usually
    synthetic. openPorts is only asked for when services are wanted.
    """
    ip_fields = "ip " + bound("dnsNames", MAX_DNS_NAMES) + " { nodes }"
    if include_services:
        ip_fields += (" openPorts { " + bound("ports", MAX_PORTS_PER_IP) +
                      " { nodes { port scanTime source name description } } }")
    return ("      " + bound("directNetworkInterfaces", MAX_INTERFACES_PER_ASSET) +
            " { nodes { mac " + bound("dnsNames", MAX_DNS_NAMES) + " { nodes } " +
            bound("ips", MAX_IPS_PER_INTERFACE) + " { nodes { " + ip_fields + " } } } }\n")


def os_details_block(include_software):
    """Select the OS, adding the hotfix inventory when software is wanted."""
    if not include_software:
        return "      osDetails { name architecture version }\n"
    return ("      osDetails { name architecture version " +
            bound("hotFixes", MAX_SOFTWARE_PER_ASSET) +
            " { nodes { name installDate description } } }\n")


def plugins_block():
    """Select the plugin findings, worst first.

    Vulnerabilities hang off the asset, so selecting them here joins on Asset.id
    without a second pagination loop. The connection is sorted server-side on
    severity descending before the `first:` bound applies, so the cap keeps the
    findings worth keeping rather than whichever the console listed first.
    details is non-null on Plugin and carries the CVEs, the CPEs, the prose, and
    the published CVSS base scores.
    """
    sort = "sort: [{field: severity, direction: DescNullLast}]"
    return ("      plugins(first: " + str(MAX_VULNS_PER_ASSET) + ", " + sort + ")" +
            " { nodes { id name source family severity vprScore cvss3Score comment" +
            " totalAffectedAssets" +
            " details { cves cpes description solution cvssV3BaseScore cvssBaseScore } } }\n")


def build_assets_query(rich, include_vulns, include_software, include_services):
    """Assemble the assets document for the requested selection depth."""
    if not rich:
        return QUERY_HEAD + minimal_fields() + QUERY_TAIL
    query = QUERY_HEAD + minimal_fields() + EXTRA_FIELDS
    query += interfaces_block(include_services)
    query += os_details_block(include_software)
    if include_vulns:
        query += plugins_block()
    return query + QUERY_TAIL


def graphql_error_message(errors):
    """Return the first GraphQL error's message as printable text.

    The spec says each entry is an object carrying `message`, but a bare string
    here would abort the script at .get, so the shape is checked.
    """
    if not errors:
        return ""
    entry = errors[0]
    if type(entry) == "dict":
        return as_text(entry.get("message"))[:200]
    return as_text(entry)[:200]


def connection_values(value):
    """Return the string members of a GraphQL {nodes: [...]} connection.

    ips, macs, directIps, and directMacs are all StringConnection!; a console
    that answers with a bare string would abort a plain .get("nodes"), so the
    shape is coerced rather than assumed.
    """
    out = []
    for entry in as_list(as_dict(value).get("nodes")):
        text = as_text(entry)
        if text:
            out.append(text)
    return dedupe(out)


def connection_nodes(value):
    """Return the dict members of a GraphQL {nodes: [...]} connection."""
    return dicts(as_dict(value).get("nodes"))


def timestamp(value):
    """parse_ts, rejecting the Go zero time the console emits for "never".

    runStatusTime and the other optional Time fields arrive as
    0001-01-01T00:00:00Z rather than null, and parse_ts parses that happily,
    stamping a year-1 first-seen date onto every asset that never ran.
    """
    parsed = parse_ts(value)
    if parsed == None or parsed.unix <= 0:
        return None
    return parsed


def strip_suffix(value, suffix):
    """Drop an enum's redundant tail: MediumCriticality -> Medium."""
    if value.endswith(suffix) and len(value) > len(suffix):
        return value[:-len(suffix)]
    return value


def severity_key(value):
    """Normalize a Tenable severity enum into a SEVERITY_RANK lookup key."""
    key = strip_suffix(as_text(value).upper(), "SEVERITY")
    return strip_suffix(key, "CRITICALITY")


def direct_interfaces(node):
    """Return the asset's own network interface nodes, capped."""
    return connection_nodes(node.get("directNetworkInterfaces"))[:MAX_INTERFACES_PER_ASSET]


def interface_ips(iface):
    """Return the routable addresses on one NetworkInterface.

    IpDetails.ip is a single String!, not a list. routable_ips drops loopback,
    unspecified, and link-local values: an APIPA address a device invents when
    DHCP fails identifies nothing and would correlate unrelated hosts.
    """
    addresses = []
    for details in connection_nodes(iface.get("ips"))[:MAX_IPS_PER_INTERFACE]:
        address = as_text(details.get("ip"))
        if address:
            addresses.append(address)
    return routable_ips(dedupe(addresses))


def build_flat_interfaces(node):
    """Build interfaces from the flat address lists.

    The fallback for the minimal document, which has no interface connection,
    and for a console that returns an empty one. It cannot pair a MAC with its
    own addresses, so the first interface carries the primary MAC together with
    every address and each remaining MAC becomes an address-less interface. The
    associated lists back up the direct ones, which a recorded sample returns
    empty with the real MAC only in macs.
    """
    ips = routable_ips(dedupe(connection_values(node.get("directIps"))))
    if not ips:
        ips = routable_ips(dedupe(connection_values(node.get("ips"))))

    # mac_key is the "is this a real MAC" gate: it rejects the all-zero and
    # broadcast placeholders as well as anything unparseable. Only the gate is
    # used; the source's own spelling is what reaches the interface.
    candidates = dedupe(connection_values(node.get("directMacs")))
    if not candidates:
        candidates = dedupe(connection_values(node.get("macs")))
    macs = []
    for value in candidates:
        if mac_key(value):
            macs.append(value)

    if not macs:
        nic = network_interface(mac="", ips=ips)
        return [nic] if nic else []

    nics = []
    primary = network_interface(mac=macs[0], ips=ips)
    if primary:
        nics.append(primary)
    for mac in macs[1:MAX_INTERFACES_PER_ASSET]:
        extra = network_interface(mac=mac, ips=[])
        if extra:
            nics.append(extra)
    return nics


def build_interfaces(node):
    """Build the network interfaces for one asset.

    Only the asset's OWN addresses become interfaces: ips is "All associated
    IPs", which includes a chassis module's siblings and a fronting gateway.
    Those would make every module in a rack advertise the same addresses, so
    ip-match forks and thrashes instead of merging. directNetworkInterfaces
    pairs each MAC with its own addresses, so it is preferred, with the flat
    lists as fallback. network_interface returns None when nothing usable
    survives, and passing None to ImportAsset aborts the run.
    """
    nics = []
    for iface in direct_interfaces(node):
        # A NetworkInterface with no MAC is still worth keeping for its
        # addresses, so an unusable value becomes empty rather than a skip.
        mac = as_text(iface.get("mac"))
        if not mac_key(mac):
            mac = ""
        nic = network_interface(mac=mac, ips=interface_ips(iface))
        if nic:
            nics.append(nic)
    if nics:
        return nics
    return build_flat_interfaces(node)


def build_hostnames(node):
    """Collect the names fit to import as hostnames for one asset.

    dnsNames is the real hostname source: the console's own `name` is usually
    synthetic ("OT Device #966"), which clean_hostnames rightly refuses along
    with placeholders and bare IP addresses. The schema publishes dnsNames on
    both NetworkInterface and IpDetails, so both are read, with the console name
    last as a fallback. The raw console name is kept as an attribute either way.
    """
    candidates = []
    for iface in direct_interfaces(node):
        candidates.extend(connection_values(iface.get("dnsNames")))
        for details in connection_nodes(iface.get("ips"))[:MAX_IPS_PER_INTERFACE]:
            candidates.extend(connection_values(details.get("dnsNames")))
    candidates.append(as_text(node.get("name")))
    return clean_hostnames(dedupe(candidates))[:MAX_HOSTNAMES]


def build_services(node):
    """Convert the open ports recorded against each direct address.

    The ports hang off one IpDetails, so every service lands on the address the
    console actually saw it on rather than on a guessed primary. OpenPorts
    publishes no transport, so tcp is assumed and the assumption is recorded
    rather than presented as reported fact.
    """
    services = []
    seen = []
    for iface in direct_interfaces(node):
        for details in connection_nodes(iface.get("ips"))[:MAX_IPS_PER_INTERFACE]:
            address = as_text(details.get("ip"))
            if not address or not routable_ips([address]):
                continue
            open_ports = as_dict(details.get("openPorts"))
            for entry in connection_nodes(open_ports.get("ports"))[:MAX_PORTS_PER_IP]:
                port = as_int(entry.get("port"))
                if port < 1 or port > 65535:
                    continue
                key = address + "/" + str(port)
                if key in seen:
                    continue
                seen.append(key)
                services.append(Service(
                    address=address,
                    port=port,
                    transport=DEFAULT_TRANSPORT,
                    customAttributes=to_custom_attributes({
                        "service_protocol": entry.get("name"),
                        "service_description": entry.get("description"),
                        "service_source": entry.get("source"),
                        "service_scan_time": entry.get("scanTime"),
                        "transport_source": "assumed",
                    }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
                ))
                if len(services) >= MAX_SERVICES_PER_ASSET:
                    return services
    return services


def build_tags(node, segments):
    """Collect the console classifications worth searching on in runZero.

    The "not classified" members of each enum are dropped rather than tagged: a
    tag shared by every unclassified asset on the console narrows nothing.
    """
    tags = []
    asset_type = as_text(node.get("type"))
    if asset_type:
        tags.append("type:" + asset_type)
    purdue = as_text(node.get("purdueLevel"))
    if purdue and purdue != PURDUE_UNKNOWN:
        tags.append("purdue:" + purdue)
    criticality = strip_suffix(as_text(node.get("criticality")), "Criticality")
    if criticality and criticality != CRITICALITY_NONE:
        tags.append("criticality:" + criticality)
    run_status = as_text(node.get("runStatus"))
    if run_status and run_status != "Unknown":
        tags.append("run-status:" + run_status)
    for segment in segments[:MAX_SEGMENT_TAGS]:
        name = as_text(segment.get("name"))
        if name:
            tags.append("segment:" + name)
    return dedupe(tags)


def plugin_score(plugin, details):
    """Return the best CVSS base score the plugin publishes, or 0.0.

    Plugin.cvss3Score is already a Float and is preferred for that reason.
    PluginDetails publishes the same v3 base score as a String, and the v2 base
    score behind it, so both are read before falling back on the severity
    stand-in.
    """
    score = as_float(plugin.get("cvss3Score"))
    if score > 0.0:
        return score
    score = as_float(details.get("cvssV3BaseScore"))
    if score > 0.0:
        return score
    return as_float(details.get("cvssBaseScore"))


def plugin_cve(details, name):
    """Return the first publishable CVE for a plugin, or "".

    PluginDetails.cves is the real source; a plugin whose entire name is a CVE
    is the fallback for a console that publishes no details. Vulnerability.cve
    is NOT upper-cased for us and a miss fails the ENTIRE record rather than the
    field, so every candidate is upper-cased and checked against CVE_PATTERN.
    """
    for entry in as_list(details.get("cves")):
        candidate = as_text(entry).upper()
        if re_match(CVE_PATTERN, candidate):
            return candidate
    candidate = name.upper()
    if re_match(CVE_PATTERN, candidate):
        return candidate
    return ""


def build_vulnerability(plugin):
    """Convert one plugin node into a runZero Vulnerability.

    A finding with no CVE is still imported. Most OT plugins are configuration
    and protocol checks that have no CVE at all, and dropping them would hide
    the findings the product exists to report.
    """
    plugin_id = as_text(plugin.get("id"))
    name = as_text(plugin.get("name"))
    if not plugin_id and not name:
        return None

    details = as_dict(plugin.get("details"))
    key = severity_key(plugin.get("severity"))
    rank = SEVERITY_RANK.get(key, 0)
    score = plugin_score(plugin, details)
    if score <= 0.0:
        score = SEVERITY_SCORE.get(key, 0.0)
    # VPR is published on the same 0-10 scale as CVSS, so it is the better risk
    # score when the plugin carries one; severity drives the ranks either way.
    vpr = as_float(plugin.get("vprScore"))

    params = {
        "id": (plugin_id or name)[:255],
        "name": name or plugin_id,
        "severityRank": rank,
        "severityScore": score,
        "riskRank": rank,
        "riskScore": vpr if vpr > 0.0 else score,
        "customAttributes": to_custom_attributes({
            "plugin_id": plugin_id,
            "plugin_source": plugin.get("source"),
            "plugin_family": plugin.get("family"),
            "plugin_severity": plugin.get("severity"),
            "plugin_vpr_score": plugin.get("vprScore"),
            "plugin_cvss3_score": plugin.get("cvss3Score"),
            "plugin_cvss_v3_base_score": details.get("cvssV3BaseScore"),
            "plugin_cvss_base_score": details.get("cvssBaseScore"),
            "plugin_cves": ",".join(dedupe([as_text(c) for c in as_list(details.get("cves"))])),
            "plugin_total_affected_assets": plugin.get("totalAffectedAssets"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    # The plugin's own prose beats the operator comment, which is a local note
    # rather than a description of the finding.
    description = as_text(details.get("description")) or as_text(plugin.get("comment"))
    if description:
        params["description"] = description[:1024]
    solution = as_text(details.get("solution"))
    if solution:
        params["solution"] = solution[:1024]

    cve = plugin_cve(details, name)
    if cve:
        params["cve"] = cve

    # Vulnerability.cpe23 accepts any "cpe:" binding, unlike Software.cpe23
    # which takes only the CPE 2.2 "cpe:/a:" form, so a 2.3 string is fine here.
    for entry in as_list(details.get("cpes")):
        candidate = as_text(entry)
        if candidate.startswith("cpe:"):
            params["cpe23"] = candidate
            break

    return Vulnerability(**params)


def build_vulnerabilities(node):
    """Convert an asset's plugin connection into ranked Vulnerabilities.

    Returns the findings, the CVEs they name, and the highest CVSS base score
    any of them publishes. The rollups become asset attributes because a
    vulnerability's own fields are not searchable from the asset. The cap makes
    order matter, so the findings are re-sorted on severity then CVSS score,
    with a position tiebreak that makes the result identical on every run.
    """
    ranked = []
    position = 0
    for plugin in connection_nodes(node.get("plugins")):
        details = as_dict(plugin.get("details"))
        rank = SEVERITY_RANK.get(severity_key(plugin.get("severity")), 0)
        ranked.append((-rank, -plugin_score(plugin, details), position, plugin))
        position += 1

    vulns = []
    cves = []
    top_score = 0.0
    for entry in sorted(ranked):
        plugin = entry[3]
        vuln = build_vulnerability(plugin)
        if not vuln:
            continue
        vulns.append(vuln)
        details = as_dict(plugin.get("details"))
        cve = plugin_cve(details, as_text(plugin.get("name")))
        if cve:
            cves.append(cve)
        # The published score only, never the severity stand-in: a rollup that
        # mixed the two would report a CVSS the vendor never assigned.
        score = plugin_score(plugin, details)
        if score > top_score:
            top_score = score
        if len(vulns) >= MAX_VULNS_PER_ASSET:
            break
    return vulns, dedupe(cves), top_score


def build_software(os_details):
    """Convert installed OS hotfixes into runZero Software.

    osDetails.hotFixes is the only installed-software inventory in the asset
    schema; there is no general package list.
    """
    software = []
    for hotfix in connection_nodes(os_details.get("hotFixes"))[:MAX_SOFTWARE_PER_ASSET]:
        name = as_text(hotfix.get("name"))
        if not name:
            continue
        params = {
            # Software REQUIRES an id; the hotfix identifier is its name.
            "id": name[:255],
            "product": name,
        }
        description = as_text(hotfix.get("description"))
        if description:
            params["customAttributes"] = to_custom_attributes({
                "hotfix_description": description,
                "hotfix_install_date": hotfix.get("installDate"),
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        installed = timestamp(hotfix.get("installDate"))
        if installed:
            params["installedAt"] = installed
        software.append(Software(**params))
    return software


def build_asset(node, scope, include_services):
    """Convert one assets node into a runZero ImportAsset."""
    asset_id = as_text(node.get("id"))
    if not asset_id:
        print("{}: skipping asset with no id: name={}".format(VENDOR, as_text(node.get("name"))))
        return None

    segments = connection_nodes(node.get("segments"))[:MAX_SEGMENT_TAGS]
    os_details = as_dict(node.get("osDetails"))
    risk = as_dict(node.get("risk"))
    backplane = as_dict(node.get("backplane"))
    name = as_text(node.get("name"))
    hostnames = build_hostnames(node)

    attrs = {
        "asset_id": asset_id,
        "name": name,
        "type": node.get("type"),
        "super_type": node.get("superType"),
        "category": node.get("category"),
        "purdue_level": node.get("purdueLevel"),
        "criticality": node.get("criticality"),
        "hidden": node.get("hidden"),
        "run_status": node.get("runStatus"),
        "run_status_time": node.get("runStatusTime"),
        # totalRisk arrives as a STRING, not a number.
        "total_risk": risk.get("totalRisk"),
        "family": node.get("family"),
        "location": node.get("location"),
        "slot": node.get("slot"),
        "serial": node.get("serial"),
        "firmware_version": node.get("firmwareVersion"),
        "description": node.get("description"),
        "os_architecture": os_details.get("architecture"),
        "backplane_id": backplane.get("id"),
        "backplane_name": backplane.get("name"),
        "backplane_size": backplane.get("size"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
        "last_hit": node.get("lastHit"),
        "last_update": node.get("lastUpdate"),
        "direct_ips": ",".join(connection_values(node.get("directIps"))),
        "direct_macs": ",".join(connection_values(node.get("directMacs"))),
        "dns_names": ",".join(hostnames),
        "segment_ids": ",".join([as_text(s.get("id")) for s in segments]),
        "segment_names": ",".join([as_text(s.get("name")) for s in segments]),
    }
    for index in range(1, 11):
        attrs["custom_field_{}".format(index)] = node.get("customField{}".format(index))

    params = {
        "id": "{}:{}:{}".format(VENDOR, scope, asset_id),
        "hostnames": hostnames,
        "networkInterfaces": build_interfaces(node),
        "tags": build_tags(node, segments),
    }

    asset_type = as_text(node.get("type"))
    if asset_type:
        params["deviceType"] = asset_type
    vendor = as_text(node.get("vendor"))
    if vendor:
        params["manufacturer"] = vendor
    model = as_text(node.get("model"))
    if model:
        params["model"] = model
    os_name = as_text(node.get("os")) or as_text(os_details.get("name"))
    if os_name:
        params["os"] = os_name
    os_version = as_text(os_details.get("version"))
    if os_version:
        params["osVersion"] = os_version

    first_seen = timestamp(node.get("firstSeen"))
    if first_seen:
        params["firstSeenTS"] = first_seen
    # lastSeen ONLY. lastHit and lastUpdate record a console-side touch, a
    # plugin re-evaluation or an operator edit, not a sighting on the wire.
    # lastSeen is nullable while lastUpdate is Time!, so a fallback chain would
    # fire on exactly the assets the console says were never seen and stamp
    # them as freshly seen. Both survive as attributes.
    last_seen = timestamp(node.get("lastSeen"))
    if last_seen:
        params["lastSeenTS"] = last_seen

    vulns, cves, top_score = build_vulnerabilities(node)
    if vulns:
        params["vulnerabilities"] = vulns
        attrs["plugin_count"] = len(vulns)
        attrs["plugin_cves"] = ",".join(cves)
        if top_score > 0.0:
            attrs["plugin_max_cvss"] = top_score

    software = build_software(os_details)
    if software:
        params["software"] = software
        attrs["hotfix_count"] = len(software)

    if include_services:
        services = build_services(node)
        if services:
            params["services"] = services
            attrs["service_count"] = len(services)

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                      separator=ATTR_SEPARATOR)
    return ImportAsset(**params)


def build_filter(lookback_days, include_hidden):
    """Build the AssetExpressionsParams for the requested scope.

    Two expression shapes are combined here: pyTenable's hidden equality and
    Elastic's Or over lastUpdate/firstSeen. Nesting the Or inside an And is the
    documented way to ask for both, which keeps hidden filtering server-side
    instead of transferring suppressed assets and dropping them on arrival. The
    client-side drop stays as a guard, which is why `hidden` is always selected.
    """
    expressions = []
    if not include_hidden:
        expressions.append(HIDDEN_FILTER)
    if lookback_days > 0:
        cutoff = now() + parse_duration("-{}h".format(lookback_days * 24))
        since = cutoff.format("2006-01-02T15:04:05Z07:00")
        expressions.append({"op": "Or", "expressions": [
            {"field": "lastUpdate", "op": "GreaterEqual", "values": since},
            {"field": "firstSeen", "op": "GreaterEqual", "values": since},
        ]})

    if not expressions:
        return None
    if len(expressions) == 1:
        return expressions[0]
    return {"op": "And", "expressions": expressions}


def post_assets(ctx, variables):
    """POST one assets document and return (connection, error text)."""
    data, err = post_json(ctx["endpoint"], json={"query": ctx["query"], "variables": variables},
                          **ctx["http_options"])
    if err:
        return {}, err

    data = as_dict(data)
    connection = as_dict(as_dict(data.get("data")).get("assets"))
    errors = as_list(data.get("errors"))
    # A partial response carries both nodes and errors; the nodes are still
    # worth importing, so errors only end the walk when nothing came back.
    if errors and not connection:
        return {}, "graphql: " + graphql_error_message(errors)
    if errors:
        print("{}: the console returned a partial page: {}".format(VENDOR, graphql_error_message(errors)))
    return connection, None


def fetch_page(ctx, cursor):
    """Fetch one page, falling back once to the Elastic-verified field set.

    The wider selection comes from pyTenable rather than a console capture, and
    GraphQL validates the whole document, so a console that does not publish one
    of those fields would otherwise return nothing at all.
    """
    variables = {"first": ctx["page_size"], "sort": ASSET_SORT}
    if cursor:
        variables["after"] = cursor
    if ctx["filter"]:
        variables["filter"] = ctx["filter"]

    connection, err = post_assets(ctx, variables)
    if not err:
        return connection, None
    if not ctx["rich"]:
        return {}, err

    ctx["rich"] = False
    ctx["query"] = build_assets_query(False, False, False, False)
    print("{}: the console rejected the extended field selection, retrying with the minimal field set".format(VENDOR))
    return post_assets(ctx, variables)


def log_fetch_error(err):
    """Report a failed page, naming the cause for the credential statuses."""
    if err.startswith("status 401") or err.startswith("status 403"):
        print("{}: the console rejected the API key; regenerate it under Local Settings > System Configuration > API Keys".format(VENDOR))
    print("{}: failed to fetch assets: {}".format(VENDOR, err))


def fetch_and_report_assets(ctx):
    """Walk the Relay cursor and stream each page so the full inventory is
    never held in memory at once."""
    reported = 0
    skipped = 0
    hidden = 0
    cursor = None

    p = pager("assets")
    while p.next():
        connection, err = fetch_page(ctx, cursor)
        if err:
            log_fetch_error(err)
            break

        nodes = connection_nodes(connection)
        for node in nodes:
            if not ctx["include_hidden"] and as_bool(node.get("hidden")):
                hidden += 1
                continue
            asset = build_asset(node, ctx["scope"], ctx["include_services"])
            if not asset:
                skipped += 1
                continue
            reported += report_asset(asset)

        # The documented termination condition: Elastic's CEL program keeps
        # paging on exactly "body.data.assets.pageInfo.hasNextPage". A missing
        # or repeated cursor also stops the walk, so a console that reports
        # hasNextPage forever cannot spin.
        page_info = as_dict(connection.get("pageInfo"))
        if not as_bool(page_info.get("hasNextPage")):
            break
        next_cursor = as_text(page_info.get("endCursor"))
        if not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor

    if hidden:
        print("{}: excluded {} hidden assets".format(VENDOR, hidden))
    if skipped:
        print("{}: skipped {} assets with no id".format(VENDOR, skipped))
    print("{}: reported {} assets".format(VENDOR, reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    # The console is a per-customer on-premise appliance with no shared SaaS
    # hostname, so its host is the id namespace. The port is deliberately not
    # part of it: one console reached on two ports is one console.
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("{}: could not determine the console host from the configured URL".format(VENDOR))
        return None

    api_key = get_string(kwargs, "api_key")
    # The documented header is X-APIKeys with a "key=" prefix and no bearer
    # scheme; pyTenable and Elastic both send exactly this.
    http_options = get_http_options(kwargs, headers={
        "X-APIKeys": "key=" + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })

    include_hidden = get_bool(kwargs, "include_hidden", default=False)
    include_vulns = get_bool(kwargs, "import_vulnerabilities", default=True)
    include_software = get_bool(kwargs, "import_software", default=True)
    include_services = get_bool(kwargs, "import_services", default=False)
    lookback_days = get_int(kwargs, "lookback_days", default=0)

    ctx = {
        "endpoint": base_url + GRAPHQL_PATH,
        "http_options": http_options,
        "scope": scope,
        "page_size": get_int(kwargs, "page_size", default=200),
        "filter": build_filter(lookback_days, include_hidden),
        "include_hidden": include_hidden,
        "include_services": include_services,
        "rich": True,
        "query": build_assets_query(True, include_vulns, include_software, include_services),
    }

    if not fetch_and_report_assets(ctx):
        print("{}: no assets retrieved".format(VENDOR))
    return None

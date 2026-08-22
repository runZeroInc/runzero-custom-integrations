# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-trellix-epo",
    "name": "Trellix ePolicy Orchestrator",
    "type": "inbound",
    "description": "Imports managed and unmanaged systems from the Trellix ePolicy Orchestrator System Tree.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # ePO is an endpoint protection console, so its addresses are reported
    # by the agent rather than observed on the wire: they are frequently
    # absent, stale, or a VPN lease. The System Tree node id is
    # authoritative, so network churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "ePolicy Orchestrator URL",
            "type": "url",
            "required": True,
            "placeholder": "https://epo.example.com:8443",
            "description": "Base URL of the ePO console. The remote command interface is served from /remote/ on the console port, which defaults to 8443.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "ePO user account. A permission set granting System Tree read access is sufficient.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the ePO user account, sent with HTTP Basic authentication.",
        },
        {
            "key": "collection_mode",
            "label": "Collection mode",
            "type": "enum",
            "required": False,
            "options": ["search", "system-tree"],
            "default": "search",
            "caseInsensitive": True,
            "description": "search runs one system.find call and returns every matching system in a single response. system-tree walks each System Tree group with epogroup.findSystems, which keeps each response small on large estates.",
        },
        {
            "key": "search_text",
            "label": "Search text",
            "type": "string",
            "required": False,
            "description": "Substring filter applied by system.find in search mode. Leave blank to return every system. Ignored in system-tree mode.",
        },
        {
            "key": "include_unmanaged",
            "label": "Import unmanaged systems",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import System Tree entries that have no ePO agent installed. They carry little detail beyond a name, but they are what makes an endpoint protection coverage gap visible.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', http_get='get', 'basic', 'url_encode', 'url_parse')
load('json', json_decode='decode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_bool')
load('time', 'parse_time', 'parse_ts')
load('re', re_match='match')

# Every ePO remote command is an RPC name used as a path segment under /remote/.
REMOTE_PATH = "/remote/"
FIND_SYSTEMS_COMMAND = "system.find"
FIND_GROUPS_COMMAND = "system.findGroups"
GROUP_SYSTEMS_COMMAND = "epogroup.findSystems"

MODE_SYSTEM_TREE = "system-tree"

# Result rows are flat dicts keyed by "<ePO table>.<column>", so every lookup
# carries the table prefix the column actually belongs to.
PROPS = "EPOComputerProperties."
LEAF = "EPOLeafNode."
BRANCH = "EPOBranchNode."

# IPV4x is stored biased by 2^31 so that addresses sort correctly as signed
# 32-bit integers in the backing SQL Server column: the dotted quad is
# recovered by adding 2^31 back and splitting the result into four octets.
# 10.0.0.0/8 therefore arrives negative while 192.168.0.0/16 arrives positive.
IPV4X_BIAS = 2147483648
IPV4X_MIN = -2147483648
IPV4X_MAX = 2147483647

# ePO writes these literal placeholders into string columns it has no value for.
PLACEHOLDER_VALUES = ["N/A", "(none)", "<null>"]

# OSPlatform is a device class rather than an operating system family. Only the
# values ePO documents are translated; anything else leaves deviceType unset.
DEVICE_TYPES = {
    "SERVER": "Server",
    "WORKSTATION": "Desktop",
    "LAPTOP": "Laptop",
}

TAG_LIMIT = 99

def _text(value):
    """Return a trimmed string, treating ePO's placeholder values as empty."""
    if value == None:
        return ""
    text = str(value).strip()
    if text in PLACEHOLDER_VALUES:
        return ""
    return text


def _int(value):
    """Return an integer column, or None when the column is unset or non-numeric."""
    if type(value) != "int":
        return None
    return value


def _count(value):
    """Return a hardware counter column, dropping the zero ePO uses for unknown."""
    number = _int(value)
    if not number:
        return ""
    return number
def _appliance_scope(base_url):
    """Return the ePO hostname, which is the uniqueness scope for system ids.

    Scheme and port are dropped so that editing the configured URL between http
    and https, or off the default console port, does not change the identity of
    systems that were already imported.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return str(parsed.hostname).lower()
    return base_url.split("://")[-1].split("/")[0].split(":")[0].lower()


def _ipv4_from_column(value):
    """Convert the biased signed IPV4x column into a dotted quad."""
    packed = _int(value)
    if packed == None or packed < IPV4X_MIN or packed > IPV4X_MAX:
        return ""
    # ePO reports an absent address as null, and a literal 0 would decode to
    # the network address 128.0.0.0, so a zero column is treated as unset
    # rather than injected as an address shared by every affected system.
    if packed == 0:
        return ""
    packed = packed + IPV4X_BIAS
    quad = "{}.{}.{}.{}".format((packed // 16777216) % 256, (packed // 65536) % 256,
                                (packed // 256) % 256, packed % 256)
    if quad == "0.0.0.0":
        return ""
    return quad


def _parse_envelope(body):
    """Split ePO's status line off the response body, returning (payload, err).

    Every remote command answers with a status line terminated by a colon and a
    CRLF before the JSON document, so the response is not valid JSON until that
    prefix is removed. A successful command answers "OK:"; a failed one answers
    "Error <code>:" followed by a plain-text message instead of a document.
    """
    marker = body.find(":")
    if marker < 0:
        return "", "unrecognized response envelope"
    status = body[:marker]
    payload = body[marker + 1:].strip()
    if status.split(" ")[0] != "OK":
        return "", "{}: {}".format(status.strip(), payload[:200])
    return payload, None


def _decode_rows(payload):
    """Decode an ePO result array, rejecting any payload that is not one.

    json_decode aborts the script on malformed input, so the payload is checked
    for the opening bracket of an array first. A command that succeeds without
    matching anything answers with an empty payload rather than `[]`.
    """
    if not payload:
        return [], None
    if not payload.startswith("["):
        return [], "expected a JSON array, got: " + payload[:120]
    rows = json_decode(payload)
    if type(rows) != "list":
        return [], "expected a JSON array"
    return rows, None


def _command_url(base_url, command, params):
    """Build a remote command URL with `:output=json` written in literally.

    The leading colon belongs to ePO's parameter name and every ePO client
    sends it unencoded, so it is concatenated rather than handed to url_encode,
    which would emit `%3Aoutput`. The remaining values are encoded, and the "+"
    that url_encode emits for a space is rewritten to "%20" so that a search
    string containing spaces reaches the console intact; a literal plus is
    already "%2B" by that point and is unaffected.
    """
    query = ":output=json"
    if params:
        encoded = {}
        for key in params:
            encoded[key] = str(params[key])
        query = query + "&" + url_encode(encoded).replace("+", "%20")
    return "{}{}{}?{}".format(base_url, REMOTE_PATH, command, query)


def run_command(base_url, command, params, http_options):
    """Run one ePO remote command and return its decoded rows as (rows, err).

    get_json cannot be used here because the response body is prefixed with a
    status line and therefore does not decode as JSON. That also means the
    retry budget get_json exposes is unavailable on this transport: the raw
    http.get builtin rejects a `retries` argument outright. The query string is
    built into the URL, so no `params` argument is passed alongside it.
    """
    response = http_get(_command_url(base_url, command, params), **http_options)
    if not response:
        return [], "no response from " + command
    if response.status_code != 200:
        return [], "status {}".format(response.status_code)

    payload, err = _parse_envelope(str(response.body))
    if err:
        return [], err
    return _decode_rows(payload)


def build_hostnames(row):
    """Collect the distinct names ePO reports for one system."""
    names = []
    for key in ["ComputerName", "IPHostName"]:
        name = _text(row.get(PROPS + key, ""))
        if name and name not in names:
            names.append(name)
    return names


def build_os_version(row):
    """Compose an OS version from ePO's separate version, build, and pack columns."""
    version = _text(row.get(PROPS + "OSVersion", ""))
    if not version:
        return ""
    build = _int(row.get(PROPS + "OSBuildNum", 0))
    if build:
        version = "{}.{}".format(version, build)
    service_pack = _text(row.get(PROPS + "OSServicePackVer", ""))
    if service_pack:
        version = "{} {}".format(version, service_pack)
    return version


def build_tags(row, group_path, managed):
    """Build the runZero tag list from ePO's comma-joined tag column."""
    tags = ["trellix-epo"]
    if managed:
        tags.append("managed:true")
    else:
        tags.append("managed:false")
    if group_path:
        tags.append("group:" + group_path)
    for name in _text(row.get(LEAF + "Tags", "")).split(","):
        name = name.strip()
        if name and name not in tags:
            tags.append(name)
    return tags[:TAG_LIMIT]


def build_asset(row, scope, node_id, group_paths):
    """Convert one EPOComputerProperties result row into an ImportAsset."""
    group_id = _int(row.get(BRANCH + "AutoID", None))
    group_path = ""
    if group_id != None:
        group_path = group_paths.get(group_id, "")

    # NetAddress is the MAC as unpunctuated hex; network_interface normalizes
    # that form directly, so no separators are inserted by hand.
    ips = []
    for candidate in [_ipv4_from_column(row.get(PROPS + "IPV4x", None)),
                      _text(row.get(PROPS + "IPAddress", "")),
                      _text(row.get(PROPS + "IPV6", ""))]:
        if candidate and candidate not in ips:
            ips.append(candidate)
    nic = network_interface(mac=_text(row.get(PROPS + "NetAddress", "")), ips=ips)
    netifs = [nic] if nic else []

    managed = _int(row.get(LEAF + "ManagedState", 0)) == 1

    attrs = {
        "node_id": node_id,
        "agent_guid": _text(row.get(LEAF + "AgentGUID", "")),
        "agent_version": _text(row.get(LEAF + "AgentVersion", "")),
        "managed_state": row.get(LEAF + "ManagedState", ""),
        "group_id": group_id,
        "group_path": group_path,
        "excluded_tags": _text(row.get(LEAF + "ExcludedTags", "")),
        "last_update": _text(row.get(LEAF + "LastUpdate", "")),
        "computer_name": _text(row.get(PROPS + "ComputerName", "")),
        "ip_host_name": _text(row.get(PROPS + "IPHostName", "")),
        "domain_name": _text(row.get(PROPS + "DomainName", "")),
        "os_type": _text(row.get(PROPS + "OSType", "")),
        "os_platform": _text(row.get(PROPS + "OSPlatform", "")),
        "os_version": _text(row.get(PROPS + "OSVersion", "")),
        "os_build_num": _count(row.get(PROPS + "OSBuildNum", None)),
        "os_service_pack": _text(row.get(PROPS + "OSServicePackVer", "")),
        "os_oem_id": _text(row.get(PROPS + "OSOEMID", "")),
        "cpu_type": _text(row.get(PROPS + "CPUType", "")),
        "cpu_speed_mhz": _count(row.get(PROPS + "CPUSpeed", None)),
        "num_of_cpu": _count(row.get(PROPS + "NumOfCPU", None)),
        "total_physical_memory": _count(row.get(PROPS + "TotalPhysicalMemory", None)),
        "total_disk_space": _count(row.get(PROPS + "TotalDiskSpace", None)),
        "free_disk_space": _count(row.get(PROPS + "FreeDiskSpace", None)),
        "subnet_address": _text(row.get(PROPS + "SubnetAddress", "")),
        "subnet_mask": _text(row.get(PROPS + "SubnetMask", "")),
        "ipx_address": _text(row.get(PROPS + "IPXAddress", "")),
        "user_name": _text(row.get(PROPS + "UserName", "")),
        "time_zone": _text(row.get(PROPS + "TimeZone", "")),
        "system_description": _text(row.get(PROPS + "SystemDescription", "")),
        "description": _text(row.get(PROPS + "Description", "")),
        "user_property_1": _text(row.get(PROPS + "UserProperty1", "")),
        "user_property_2": _text(row.get(PROPS + "UserProperty2", "")),
        "user_property_3": _text(row.get(PROPS + "UserProperty3", "")),
        "user_property_4": _text(row.get(PROPS + "UserProperty4", "")),
    }

    asset_params = {
        "id": "trellix-epo:{}:{}".format(scope, node_id),
        "hostnames": build_hostnames(row),
        "networkInterfaces": netifs,
        "tags": build_tags(row, group_path, managed),        # prefix is joined to each key with separator, so this yields
        # "trellix_epo_node_id" rather than "trellix_epo_.node_id".
        "customAttributes": to_custom_attributes(attrs, prefix="trellix_epo", separator="_"),
    }

    domain = _text(row.get(PROPS + "DomainName", ""))
    if domain:
        asset_params["domain"] = domain
    os_type = _text(row.get(PROPS + "OSType", ""))
    if os_type:
        asset_params["os"] = os_type
    os_version = build_os_version(row)
    if os_version:
        asset_params["osVersion"] = os_version
    device_type = DEVICE_TYPES.get(_text(row.get(PROPS + "OSPlatform", "")).upper(), "")
    if device_type:
        asset_params["deviceType"] = device_type

    # ePO records no discovery date on the system, so only the last agent
    # check-in is available and firstSeenTS is left unset.
    asset = ImportAsset(**asset_params)

    # lastSeenTS is settable as an attribute but is not a constructor keyword.
    last_update = parse_ts(row.get(LEAF + "LastUpdate", ""))

    if last_update != None:
        asset.lastSeenTS = last_update
    return asset


def build_assets(rows, scope, group_paths, include_unmanaged):
    """Convert one batch of ePO result rows into ImportAsset objects."""
    assets = []
    for row in rows:
        if type(row) != "dict":
            print("trellix-epo: skipping malformed system record")
            continue

        # ParentID is the EPOLeafNode row that owns these properties: it is the
        # System Tree identity of the machine and is present on every row, while
        # AgentGUID is null until an agent reports in.
        node_id = _int(row.get(PROPS + "ParentID", None))
        if node_id == None:
            print("trellix-epo: skipping system with no node id: name=" +
                  _text(row.get(PROPS + "ComputerName", "")))
            continue

        if not include_unmanaged and _int(row.get(LEAF + "ManagedState", 0)) != 1:
            continue

        assets.append(build_asset(row, scope, node_id, group_paths))
    return assets


def fetch_group_paths(base_url, http_options):
    """Fetch the System Tree as a {group id: group path} map.

    The map is small, one entry per group rather than per system, and it turns
    the bare group id on each system row into a readable tree location.
    """
    group_paths = {}
    rows, err = run_command(base_url, FIND_GROUPS_COMMAND, {}, http_options)
    if err:
        print("trellix-epo: failed to fetch the System Tree:", err)
        if err.startswith("status 401") or err.startswith("status 403"):
            print("trellix-epo: check the username and password")
        return group_paths
    for row in rows:
        if type(row) != "dict":
            continue
        group_id = _int(row.get("groupId", None))
        if group_id == None:
            continue
        group_paths[group_id] = _text(row.get("groupPath", ""))
    return group_paths


def fetch_and_report_search(base_url, http_options, search_text, scope, group_paths,
                            include_unmanaged):
    """Fetch every matching system with a single system.find call.

    ePO returns the whole result set in one response and offers no paging
    arguments, so this path holds one copy of the estate in memory. The
    system-tree collection mode exists to break that up by group.
    """
    rows, err = run_command(base_url, FIND_SYSTEMS_COMMAND, {"searchText": search_text},
                            http_options)
    if err:
        print("trellix-epo: failed to search for systems:", err)
        if err.startswith("status 401") or err.startswith("status 403"):
            print("trellix-epo: check the username and password")
        return 0
    assets = build_assets(rows, scope, group_paths, include_unmanaged)
    if not assets:
        return 0
    return report_assets(assets)


def fetch_and_report_tree(base_url, http_options, scope, group_paths, include_unmanaged):
    """Fetch and stream the System Tree one group at a time so the full estate
    is never held in memory at once."""
    reported = 0
    for group_id in sorted(group_paths.keys()):
        rows, err = run_command(base_url, GROUP_SYSTEMS_COMMAND, {"groupId": group_id},
                                http_options)
        if err:
            # One unreadable group must not abandon the rest of the tree.
            print("trellix-epo: failed to fetch systems in group {}: {}".format(group_id, err))
            continue
        assets = build_assets(rows, scope, group_paths, include_unmanaged)
        if assets:
            reported += report_assets(assets)
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    collection_mode = get_string(kwargs, "collection_mode", default="search")
    search_text = get_string(kwargs, "search_text", default="")
    include_unmanaged = get_bool(kwargs, "include_unmanaged", default=True)

    http_options = get_http_options(kwargs, headers={
        "Authorization": basic(username, password),
        "Accept": "application/json",
    })

    scope = _appliance_scope(base_url)
    group_paths = fetch_group_paths(base_url, http_options)

    if collection_mode == MODE_SYSTEM_TREE:
        if not group_paths:
            print("trellix-epo: no System Tree groups available to walk")
            return None
        reported = fetch_and_report_tree(base_url, http_options, scope, group_paths,
                                         include_unmanaged)
    else:
        reported = fetch_and_report_search(base_url, http_options, search_text, scope,
                                           group_paths, include_unmanaged)

    if not reported:
        print("trellix-epo: no assets retrieved")
    return None

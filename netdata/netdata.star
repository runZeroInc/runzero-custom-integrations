# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-netdata",
    "name": "Netdata",
    "type": "inbound",
    "description": "Imports monitored nodes from a Netdata Agent or Parent.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The machine GUID is written once to disk and documented as permanent
    # for the life of the node, so it is a stable foreign id. It is still
    # only Netdata's opinion of a machine, and Netdata supplies no address
    # to corroborate it, so the id must not disqualify a merge that runZero
    # would otherwise make on hostname.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Netdata Agent URL",
            "type": "url",
            "required": True,
            "placeholder": "https://netdata-parent.example.com:19999",
            "description": "Base URL of the Netdata Agent. Point this at a Parent to inventory every child that streams to it.",
        },
        {
            "key": "api_token",
            "label": "Bearer token",
            "type": "secret",
            "required": False,
            "description": "Only needed when bearer protection is enabled on the agent. Leave blank on an agent that serves its dashboard without authentication.",
        },
        {
            "key": "api_version",
            "label": "API version",
            "type": "enum",
            "required": False,
            "default": "auto",
            "options": ["auto", "v3", "v2"],
            "description": "auto tries /api/v3/nodes first and falls back to /api/v2/nodes on older agents.",
        },
        {
            "key": "collect_node_details",
            "label": "Collect per-node system detail",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Issue one extra request per node for OS, kernel, architecture, virtualization, and host labels. This is an N+1 call.",
        },
        {
            "key": "max_detail_nodes",
            "label": "Maximum nodes to enrich",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "max": 20000,
            "description": "Cap on the per-node detail requests. Nodes past the cap are still imported, without system detail.",
        },
        {
            "key": "include_unreachable_nodes",
            "label": "Import stale and offline nodes",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "A Parent remembers children that have stopped streaming. Disable to import only nodes currently reachable.",
        },
        {
            "key": "attach_agent_address",
            "label": "Attach the configured address to the local agent",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "When the Netdata URL is a literal IP address, place it on the node the agent runs on (hops 0). Leave off when a reverse proxy or load balancer fronts the agent.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# Netdata -> runZero ImportAsset integration
#
# Netdata is a metrics agent, not an inventory system. What it does publish
# about the machines it watches is a machine GUID, a hostname, and -- through a
# second request per node -- the operating system, kernel, architecture,
# virtualization, and container runtime. It publishes no IP address and no MAC
# address for any node, so every asset this integration emits correlates on
# hostname alone. Read the "Asset identity" section of the README before
# deciding whether that is worth importing in a given environment.
#
# The value is concentrated in one deployment shape: a Netdata Parent that many
# children stream to. Pointed at a Parent, /api/v3/nodes returns the whole
# fleet in one request. Pointed at a standalone agent it returns exactly one
# node, which is rarely worth a scheduled task.

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "network_interface", "ip_address")
load("http", "get_json", "bearer", "url_parse")
load("kwargs", "get_bool", "get_int", "get_string", "get_http_options")
load("runzero.progress", progress_info="info")

load('coerce', 'as_dict')
DEFAULT_API_VERSION = "auto"
DEFAULT_COLLECT_NODE_DETAILS = True
DEFAULT_MAX_DETAIL_NODES = 500
DEFAULT_INCLUDE_UNREACHABLE = True
DEFAULT_ATTACH_AGENT_ADDRESS = False

# Netdata's default listen port, used only to build the placeholder and the
# README examples. Nothing in the script assumes it.
NETDATA_DEFAULT_PORT = 19999

# A machine GUID is a UUID written to netdata.public.unique.id on first start.
# Screening against this shape keeps a truncated or placeholder value from
# becoming a foreign id.
GUID_RE = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

# A hostname that identifies nothing. Netdata reports the kernel's idea of the
# hostname, and an unconfigured container or appliance reports one of these.
# The platform's own placeholder check rejects them, and an asset carrying only
# such a name would merge with every other one, so the node is skipped instead.
PLACEHOLDER_HOSTNAMES = [
    "localhost", "localhost.localdomain", "unknown", "none", "null",
    "(none)", "nodename", "netdata", "default", "n/a", "-",
]

# Node states reported by /api/vN/nodes. "reachable" means the node is
# currently streaming (or is the agent itself); the others are remembered
# children.
REACHABLE_STATES = ["reachable"]

# Host labels Netdata sets itself. They are worth importing as attributes but
# must not be confused with operator-assigned labels, so both are kept under
# distinct prefixes.
AUTO_LABEL_PREFIX = "_"


def _log(msg):
    print("netdata: " + msg)


def _clean(value):
    """Return a value as a trimmed string, or "" for anything unusable."""
    if value == None:
        return ""
    if type(value) == "string":
        return value.strip()
    if type(value) in ("int", "float", "bool"):
        return str(value)
    return ""
def _is_guid(value):
    """Report whether a value has the shape of a Netdata machine GUID."""
    text = _clean(value)
    if len(text) != 36:
        return False
    for index in range(36):
        char = text[index]
        if index in (8, 13, 18, 23):
            if char != "-":
                return False
        elif char not in "0123456789abcdefABCDEF":
            return False
    return True


def _usable_hostname(value):
    """Return a hostname worth importing, or "" when it identifies nothing."""
    text = _clean(value)
    if not text:
        return ""
    if text.lower() in PLACEHOLDER_HOSTNAMES:
        return ""
    # A bare address is not a name. runZero rejects one imported as a hostname,
    # and Netdata does report the address when the kernel hostname is unset.
    if ip_address(text) != None:
        return ""
    return text


def _agent_host(base_url):
    """Return the hostname the ids are scoped under, and the parsed URL.

    Two Netdata Parents polled into one organization must not collide, and a
    machine GUID is per-node rather than per-fleet, so the id carries the agent
    host. The port is deliberately dropped: reaching the same agent on a
    different port must not re-identify everything it reports.
    """
    parsed = url_parse(base_url)
    if parsed == None:
        return "", None
    if not parsed.scheme or not parsed.hostname:
        return "", None
    return parsed.hostname, parsed


def _get(base_url, path, options):
    """GET a Netdata path, returning (data, err)."""
    return get_json(base_url + path, **options)


def _fetch_nodes(base_url, api_version, options):
    """Return (nodes, api_path_used, err).

    /api/v3/nodes is the current endpoint; /api/v2/nodes is marked deprecated
    in Netdata's own OpenAPI document but is what agents before Netdata v2
    serve. Both return the same body, so "auto" tries v3 and falls back on any
    error rather than trying to version-detect the agent first.
    """
    order = ["/api/v3/nodes", "/api/v2/nodes"]
    if api_version == "v3":
        order = ["/api/v3/nodes"]
    elif api_version == "v2":
        order = ["/api/v2/nodes"]

    last_err = "no endpoint attempted"
    for path in order:
        data, err = _get(base_url, path, options)
        if err:
            last_err = err
            _log("{} did not answer ({}); trying the next endpoint".format(path, err))
            continue
        body = as_dict(data)
        nodes = body.get("nodes")
        if type(nodes) != "list":
            last_err = "{} returned no nodes array".format(path)
            _log(last_err)
            continue
        return nodes, path, None
    return [], "", last_err


def _fetch_node_info(base_url, hostname, is_local, options):
    """Return the /api/v1/info body for one node, or None.

    A Parent serves any child's own info under /host/<hostname>/api/v1/..., which
    is how the OS and kernel detail is reached for a node that is not the agent
    being queried. The agent itself answers on the unprefixed path.
    """
    if is_local:
        path = "/api/v1/info"
    else:
        # The node name is a hostname, which cannot contain a path separator or
        # a query delimiter. Refuse anything that does rather than building a
        # request that would escape the /host/ prefix.
        for bad in ["/", "?", "#", "\\", " "]:
            if bad in hostname:
                _log("node name {} is not usable in a /host/ path; skipping detail".format(hostname))
                return None
        path = "/host/" + hostname + "/api/v1/info"
    data, err = _get(base_url, path, options)
    if err:
        _log("no system detail for {} ({})".format(hostname, err))
        return None
    return as_dict(data)


def _labels_attributes(labels):
    """Split Netdata host labels into automatic and operator-assigned sets."""
    auto = {}
    custom = {}
    for key, value in as_dict(labels).items():
        name = _clean(key)
        if not name:
            continue
        if name.startswith(AUTO_LABEL_PREFIX):
            auto[name[len(AUTO_LABEL_PREFIX):]] = value
        else:
            custom[name] = value
    return auto, custom


def _node_asset(node, agent_host, base_url, options, detail_budget, local_ip):
    """Build one ImportAsset from a /api/vN/nodes entry.

    Returns (asset, detail_used). asset is None when the node carries nothing
    that can identify it.
    """
    record = as_dict(node)

    guid = _clean(record.get("mg"))
    if not _is_guid(guid):
        _log("skipping node with no usable machine guid (field mg)")
        return None, False

    hostname = _usable_hostname(record.get("nm"))
    if not hostname:
        _log("skipping node {} with no usable hostname (field nm)".format(guid))
        return None, False

    guid = guid.lower()
    state = _clean(record.get("state")).lower()
    hops = record.get("hops")
    is_local = (hops == 0)

    status = as_dict(record.get("st"))

    attrs = {
        "netdata.machine_guid": guid,
        "netdata.node_name": hostname,
        "netdata.cloud_node_id": record.get("nd"),
        "netdata.agent_version": record.get("version"),
        "netdata.hops": hops,
        "netdata.state": state,
        "netdata.status_code": status.get("code"),
        "netdata.status_message": status.get("msg"),
        "netdata.collected_from": agent_host,
        "netdata.role": "parent-or-standalone" if is_local else "child",
    }

    os_name = ""
    os_version = ""
    detail_used = False

    if detail_budget > 0:
        info = _fetch_node_info(base_url, hostname, is_local, options)
        if info != None:
            detail_used = True
            os_name = _clean(info.get("os_name"))
            os_version = _clean(info.get("os_version"))
            auto_labels, custom_labels = _labels_attributes(info.get("labels"))
            attrs["netdata.os_id"] = info.get("os_id")
            attrs["netdata.os_id_like"] = info.get("os_id_like")
            attrs["netdata.os_version_id"] = info.get("os_version_id")
            attrs["netdata.os_detection"] = info.get("os_detection")
            attrs["netdata.kernel_name"] = info.get("kernel_name")
            attrs["netdata.kernel_version"] = info.get("kernel_version")
            attrs["netdata.architecture"] = info.get("architecture")
            attrs["netdata.virtualization"] = info.get("virtualization")
            attrs["netdata.virt_detection"] = info.get("virt_detection")
            attrs["netdata.container"] = info.get("container")
            attrs["netdata.container_detection"] = info.get("container_detection")
            attrs["netdata.is_k8s_node"] = info.get("is_k8s_node")
            attrs["netdata.agent_uid"] = info.get("uid")
            for key, value in auto_labels.items():
                attrs["netdata.label_auto." + key] = value
            for key, value in custom_labels.items():
                attrs["netdata.label." + key] = value

    # Netdata publishes no address for any node. The one exception the operator
    # can opt into is the agent's own host, whose address is the one the task
    # was pointed at -- and only when that was written as a literal IP, because
    # a name may resolve to a proxy rather than to the machine.
    ips = []
    if is_local and local_ip:
        ips.append(local_ip)
        attrs["netdata.address_source"] = "integration url"
    nic = network_interface(ips=ips)
    nics = [nic] if nic else []

    tags = ["netdata"]
    if is_local:
        tags.append("netdata-agent-host")
    else:
        tags.append("netdata-child")
    if state and state not in REACHABLE_STATES:
        tags.append("netdata-" + state)

    return ImportAsset(
        id="netdata:{}:{}".format(agent_host, guid),
        hostnames=[hostname],
        networkInterfaces=nics,
        os=os_name,
        osVersion=os_version,
        deviceType="",
        tags=tags,        customAttributes=to_custom_attributes(attrs, list_join="json"),
    ), detail_used


def main(*args, **kwargs):
    base_url = _clean(kwargs.get("url"))
    if not base_url:
        _log("url (Netdata Agent URL) is required")
        return None
    base_url = base_url.rstrip("/")

    # http.get raises on a transport error rather than returning nil, and a URL
    # with no scheme or no host is a transport error, so the URL is parsed
    # before anything is fetched.
    agent_host, parsed = _agent_host(base_url)
    if not agent_host:
        _log("url must be an absolute URL with a scheme and a host, for example https://netdata.example.com:19999")
        return None

    api_version = get_string(kwargs, "api_version", DEFAULT_API_VERSION)
    collect_details = get_bool(kwargs, "collect_node_details", DEFAULT_COLLECT_NODE_DETAILS)
    max_detail = get_int(kwargs, "max_detail_nodes", DEFAULT_MAX_DETAIL_NODES)
    include_unreachable = get_bool(kwargs, "include_unreachable_nodes", DEFAULT_INCLUDE_UNREACHABLE)
    attach_address = get_bool(kwargs, "attach_agent_address", DEFAULT_ATTACH_AGENT_ADDRESS)

    headers = {"Accept": "application/json"}
    token = _clean(kwargs.get("api_token"))
    if token:
        headers["Authorization"] = bearer(token)
    options = get_http_options(kwargs, "http_", "tls_", headers)

    local_ip = ""
    if attach_address:
        candidate = ip_address(parsed.hostname)
        if candidate != None:
            local_ip = str(candidate)
        else:
            _log("attach_agent_address is on but the URL host is a name, not an address; no address will be attached")

    nodes, path_used, err = _fetch_nodes(base_url, api_version, options)
    if err:
        _log("could not list nodes: " + err)
        return None
    _log("listed {} node(s) from {}".format(len(nodes), path_used))
    progress_info("netdata: {} node(s) reported by {}".format(len(nodes), agent_host))

    if not collect_details:
        max_detail = 0

    skipped_unreachable = 0
    skipped_invalid = 0
    detail_remaining = max_detail
    detail_skipped = 0

    for node in nodes:
        record = as_dict(node)
        state = _clean(record.get("state")).lower()
        if not include_unreachable and state and state not in REACHABLE_STATES:
            skipped_unreachable += 1
            continue

        budget = detail_remaining
        if budget <= 0 and max_detail > 0:
            detail_skipped += 1
        asset, detail_used = _node_asset(record, agent_host, base_url, options, budget, local_ip)
        if asset == None:
            skipped_invalid += 1
            continue
        if detail_used:
            detail_remaining -= 1
        report_asset(asset)

        # Stream in pages so a Parent with a large fleet never holds the whole
        # inventory in memory at once.

    if skipped_unreachable:
        _log("skipped {} node(s) that are not currently reachable".format(skipped_unreachable))
    if skipped_invalid:
        _log("skipped {} node(s) with no usable identity".format(skipped_invalid))
    if detail_skipped:
        _log("system detail capped: {} node(s) imported without OS detail (raise max_detail_nodes to include them)".format(detail_skipped))
    _log("import complete")
    return None

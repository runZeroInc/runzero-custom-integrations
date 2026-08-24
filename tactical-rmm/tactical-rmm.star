# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-tactical-rmm",
    "name": "Tactical RMM",
    "type": "inbound",
    "description": "Imports agent endpoints, hardware inventory, and installed software from a Tactical RMM server.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The agent id is issued by the server at registration and replayed by
    # the agent afterwards, so it survives rename, address change, and
    # reboot. Differing MACs, addresses, and hostnames must not disqualify
    # a merge against an existing asset.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Tactical RMM API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://api.example.com",
            "description": "Base URL of the Tactical RMM backend. This is the 'api.' subdomain of a standard install, not the 'rmm.' dashboard and not the 'mesh.' MeshCentral host. The REST resources are mounted at the root of that host, so the URL carries no path.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Created under Settings > Global Settings > API Keys. The key inherits the permissions of the user it is issued to, so that user must be a superuser or hold a role granting can_list_agents (and can_list_software when software import is enabled).",
        },
        {
            "key": "monitoring_type",
            "label": "Agent type",
            "type": "enum",
            "required": False,
            "default": "all",
            "options": ["all", "server", "workstation"],
            "description": "Restrict the import to servers or to workstations. 'all' imports every agent the key can see.",
        },
        {
            "key": "extract_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch the installed-software list for each agent. This is one extra request per agent, so it is off by default and bounded by the limit below. Tactical RMM only collects software from Windows agents.",
        },
        {
            "key": "software_agent_limit",
            "label": "Maximum agents to query for software",
            "type": "int",
            "required": False,
            "default": 250,
            "min": 1,
            "max": 5000,
            "description": "Upper bound on the per-agent software requests made in one run. Agents beyond the limit are imported without software and the number skipped is logged.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "Software", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", http_get="get", "url_parse")
load("kwargs", "require", "get_url_base", "get_http_options", "get_string", "get_bool", "get_int")
load("jsonstream", "iter_array")
load("time", "now", "parse_time", "from_timestamp", "sleep")
load("re", re_match="match", re_search="search", re_find_all="find_all")

load('coerce', 'as_dict')
VENDOR = "tacticalrmm"
ATTR_PREFIX = "tacticalrmm"
ATTR_SEPARATOR = "_"

AGENTS_PATH = "/agents/"
SOFTWARE_PATH = "/software/{}/"

MAX_CHILDREN = 99

# parse_time aborts the whole script -- Starlark has no exceptions -- on any
# string it cannot read, so last_seen is screened against the shape Django REST
# Framework actually emits before it is parsed.
TIMESTAMP_RE = r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})$"

# iter_array aborts the entire run when the body is not a JSON array. An HTML
# error page or a DRF error object would both end the import, so the body is
# checked for a leading '[' before the iterator is built.
JSON_ARRAY_RE = r"^\s*\["

# Values the agent sends in place of data it could not read. Every one of these
# is a sentinel, not an observation, and importing any of them as a fact would
# put the same false model or the same false address on every affected asset.
SENTINELS = [
    "error",
    "error getting local ips",
    "error getting make/model",
    "unknown make/model",
    "unknown cpu model",
    "unknown disk",
    "no graphics cards",
    "graphics info requires agent v1.4.14",
    "n/a",
    "-",
    "unknown",
]

# Tactical RMM records monitoring_type per agent and nothing finer, so this is
# the whole device-type signal the source carries.
DEVICE_TYPES = {
    "server": "Server",
    "workstation": "Desktop",
}

PLATFORM_NAMES = {
    "windows": "Windows",
    "linux": "Linux",
    "darwin": "macOS",
}


def _text(value):
    """Return a value as a string, with bytes decoded, or "" for anything else."""
    if type(value) == "string":
        return value
    if type(value) == "bytes":
        return str(value)
    return ""


def _clean(value):
    """Return a trimmed string for a scalar, or "" when the value carries nothing.

    Booleans are excluded deliberately: str(False) is "False", which is a
    perfectly good custom attribute but a terrible hostname or model.
    """
    if type(value) == "string":
        return value.strip()
    if type(value) == "int" or type(value) == "float":
        return str(value)
    return ""


def _real(value):
    """Return a cleaned string, or "" when the agent sent one of its sentinels."""
    text = _clean(value)
    if not text:
        return ""
    if text.lower() in SENTINELS:
        return ""
    return text


def _real_list(value):
    """Return a list of real strings from a field the API types as a list.

    cpu_model, physical_disks, and graphics all carry a sentinel list rather
    than an empty one when the agent could not read the hardware.
    """
    items = []
    if type(value) == "list":
        for entry in value:
            text = _real(entry)
            if text:
                items.append(text)
        return items
    text = _real(value)
    if text:
        items.append(text)
    return items
def _local_ips(value):
    """Return the routable addresses from the agent's local_ips field.

    local_ips is a STRING on every agent version, not a list: the serializer
    joins the addresses with ", ". A list is accepted anyway because that is
    what a reader would expect from the field name and it costs one branch.
    """
    raw = []
    if type(value) == "list":
        for entry in value:
            raw.append(_clean(entry))
    else:
        for entry in _real(value).split(","):
            raw.append(entry.strip())

    addresses = []
    for entry in raw:
        canonical = routable_ip(entry)
        if canonical and canonical not in addresses:
            addresses.append(canonical)
    return addresses


def _hostname(record):
    """Return the agent hostname, or "" when it is a placeholder.

    A bare address imported as a hostname is worse than no hostname: it merges
    on an attribute that already merges, and it survives the lease that made it
    true.
    """
    text = _real(record.get("hostname"))
    if not text:
        return ""
    if text.lower() in ["localhost", "localhost.localdomain"]:
        return ""
    if ip_address(text) != None:
        return ""
    return text


def _os(record):
    """Split operating_system into an OS name and a version.

    The agent builds this string itself and the two platforms build it
    differently:

      windows -> "Windows 10 Pro, 64 bit v22H2 (build 19045.3324)"
      posix   -> "Debian 11.5 x86_64 5.10.0-19-amd64"

    The raw string is always kept as an attribute, so a format this does not
    recognise costs the split and nothing else.
    """
    raw = _real(record.get("operating_system"))
    if not raw:
        return "", ""

    plat = _real(record.get("plat")).lower()
    if plat == "windows" or raw.lower().startswith("windows") or raw.lower().startswith("microsoft windows"):
        name = raw.split(",")[0].strip()
        version = ""
        # re match structs expose groups[0] as the WHOLE match; the first
        # capture group is groups[1].
        build = re_search(r"build ([0-9][0-9.]*)", raw)
        release = re_search(r"\sv([0-9][0-9A-Za-z.]*)", raw)
        if release:
            version = release.groups[1]
        if build:
            if version:
                version = version + " (build " + build.groups[1] + ")"
            else:
                version = "build " + build.groups[1]
        return name, version

    # posix: "<platform> <platformVersion> <kernelArch> <kernelVersion>". The
    # platform name is not always one word -- "Rocky Linux 9.3 x86_64 ..." and
    # "Red Hat Enterprise Linux 9.3 ..." are both real -- so the split is made
    # at the first token that looks like a version rather than at the first
    # space. Only the leading tokens are considered, so the kernel version at
    # the end can never be mistaken for the distribution version.
    parts = raw.split(" ")
    limit = len(parts) if len(parts) < 5 else 5
    for index in range(1, limit):
        if re_match(r"^[0-9][0-9A-Za-z.\-]*$", parts[index]):
            return " ".join(parts[:index]), parts[index]
    return raw, ""


def _timestamp(value, ceiling):
    """Return a parsed timestamp clamped to now, or None.

    A timestamp in the future does not fail the field, it fails the ENTIRE
    ImportAsset, so a server whose clock runs fast would import nothing at all.
    Clamping costs accuracy on one field instead of costing the asset.
    """
    text = _clean(value)
    if not text or not re_match(TIMESTAMP_RE, text):
        return None
    parsed = parse_time(text)
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed


def _boot_time(value, ceiling):
    """Return boot_time -- a float of epoch SECONDS -- as a clamped time, or None."""
    if type(value) != "int" and type(value) != "float":
        return None
    seconds = int(value)
    if seconds <= 0:
        return None
    parsed = from_timestamp(seconds)
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed


def _software(payload, agent_id):
    """Return the Software records for one agent.

    The endpoint is polymorphic and both shapes are real: an agent with a
    software record answers with {"id", "agent", "software": [...]}, and an
    agent with none answers 200 with a bare [] -- asserted by Tactical RMM's own
    test suite. Anything else is ignored rather than guessed at.
    """
    rows = []
    if type(payload) == "list":
        rows = payload
    elif type(payload) == "dict":
        entries = payload.get("software")
        if type(entries) == "list":
            rows = entries

    records = []
    for row in rows:
        if type(row) != "dict":
            continue
        name = _clean(row.get("name"))
        if not name:
            continue
        if len(records) >= MAX_CHILDREN:
            print("{}: software list for agent {} exceeds {} records, truncating".format(
                VENDOR, agent_id, MAX_CHILDREN))
            break
        records.append(Software(
            id="{}:{}:{}".format(agent_id, name, _clean(row.get("version"))),
            vendor=_clean(row.get("publisher")),
            product=name,
            version=_clean(row.get("version")),
            # cpe23 is deliberately unset. Software.cpe23 only accepts the CPE
            # 2.2 application URI binding (^cpe:/a:) and Tactical RMM publishes
            # no CPE of any kind, so there is nothing to put there that would
            # not be invented.
        ))
    return records


def _attrs(record, os_raw, addresses):
    """Return the custom attributes for one agent."""
    checks = as_dict(record.get("checks"))
    raw = {
        "agent_id": _clean(record.get("agent_id")),
        "client": _real(record.get("client_name")),
        "site": _real(record.get("site_name")),
        "monitoring_type": _real(record.get("monitoring_type")),
        "description": _real(record.get("description")),
        "status": _real(record.get("status")),
        "agent_version": _real(record.get("version")),
        "operating_system": os_raw,
        "platform": _real(record.get("plat")),
        "arch": _real(record.get("goarch")),
        "public_ip": _real(record.get("public_ip")),
        "local_ips": ", ".join(addresses),
        "make_model": _real(record.get("make_model")),
        "cpu_model": ", ".join(_real_list(record.get("cpu_model"))),
        "physical_disks": ", ".join(_real_list(record.get("physical_disks"))),
        "graphics": ", ".join(_real_list(record.get("graphics"))),
        "serial_number": _real(record.get("serial_number")),
        "logged_username": _real(record.get("logged_username")),
        "needs_reboot": record.get("needs_reboot"),
        "patches_pending": record.get("has_patches_pending"),
        "maintenance_mode": record.get("maintenance_mode"),
        "pending_actions": record.get("pending_actions_count"),
        "checks_total": checks.get("total"),
        "checks_failing": checks.get("failing"),
        "checks_warning": checks.get("warning"),
        "last_seen": _clean(record.get("last_seen")),
    }
    return to_custom_attributes(raw, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)


def build_asset(record, namespace, ceiling, software):
    """Convert one agent row into an ImportAsset, or None when it has no identity."""
    if type(record) != "dict":
        print("{}: skipping agent row that is not an object".format(VENDOR))
        return None

    agent_id = _clean(record.get("agent_id"))
    if not agent_id:
        print("{}: skipping agent with no agent_id".format(VENDOR))
        return None

    addresses = _local_ips(record.get("local_ips"))
    hostname = _hostname(record)

    # public_ip is the address the NAT gateway presents, which every agent
    # behind one shares. It is kept as an attribute and deliberately never put
    # on an interface, because doing so would correlate an entire office onto
    # one asset.
    nic = network_interface(ips=addresses)
    interfaces = [nic] if nic else []

    if not interfaces and not hostname:
        print("{}: skipping agent {} with no hostname and no routable address".format(
            VENDOR, agent_id))
        return None

    os_name, os_version = _os(record)
    os_raw = _real(record.get("operating_system"))

    tags = []
    serial = _real(record.get("serial_number"))
    if serial:
        tags.append("serial:" + serial)

    asset = ImportAsset(
        id="{}:{}:{}".format(VENDOR, namespace, agent_id),
        hostnames=[hostname],
        networkInterfaces=interfaces,
        os=os_name,
        osVersion=os_version,
        manufacturer=_real(record.get("make_model")).split(" ")[0] if _real(record.get("make_model")) else "",
        model=_real(record.get("make_model")),
        deviceType=DEVICE_TYPES.get(_real(record.get("monitoring_type")).lower(), ""),
        tags=tags,
        software=software,
        customAttributes=_attrs(record, os_raw, addresses),    )

    # The ImportAsset constructor accepts firstSeenTS but rejects lastSeenTS, so
    # the attribute is assigned after construction.
    last_seen = _timestamp(record.get("last_seen"), ceiling)
    if last_seen != None:
        asset.lastSeenTS = last_seen

    boot = _boot_time(record.get("boot_time"), ceiling)
    if boot != None:
        asset.customAttributes["tacticalrmm_boot_time"] = boot.format("2006-01-02T15:04:05Z07:00")

    return asset


def fetch_software(ctx, agent_id):
    """Return the Software records for one agent, or [] on any failure.

    A software request that fails costs that agent its software list and
    nothing else -- the agent is still imported.
    """
    url = ctx["base_url"] + SOFTWARE_PATH.format(agent_id)
    payload, err = get_json(url, **ctx["http_options"])
    if err:
        print("{}: software request for agent {} failed: {}".format(VENDOR, agent_id, err))
        return []
    return _software(payload, agent_id)


def stream_agents(ctx):
    """Return an iterator over the agent rows, and an error string.

    GET /agents/ is completely unpaginated: Django REST Framework is configured
    with no default pagination class and the view returns one flat array of
    every agent the key can see, which on an MSP install is tens of megabytes.
    The body is therefore streamed rather than decoded whole, so only one agent
    row is a live Starlark value at a time.

    The raw http builtin is used because iter_array needs the body itself. Raw
    http.get takes no retries kwarg -- that is a get_json/post_json parameter --
    so the bounded retry below is hand-rolled: this is the only load-bearing
    request in the run, and one transient 502 used to turn the whole run into a
    green zero-asset import. A GET is safe to repeat; only transient statuses
    and missing responses are retried, and a 4xx is returned immediately.
    """
    url = ctx["base_url"] + AGENTS_PATH
    query = []
    if ctx["monitoring_type"]:
        query.append("monitoring_type=" + ctx["monitoring_type"])
    if query:
        url = url + "?" + "&".join(query)

    resp = None
    for attempt in range(3):
        if attempt:
            sleep("{}s".format(attempt))
        resp = http_get(url, **ctx["http_options"])
        if resp != None and resp.status_code not in [408, 425, 429, 500, 502, 503, 504]:
            break
    if resp == None:
        return None, "no response"
    if resp.status_code != 200:
        return None, "status {}: {}".format(resp.status_code, _text(resp.body[:200]))

    body = resp.body
    # Only the first bytes are needed to check for a leading '[': stringifying
    # the whole body here would momentarily double the memory of a
    # tens-of-megabytes response just to look at one character.
    if not re_search(JSON_ARRAY_RE, _text(body[:64])):
        # iter_array aborts the entire script when the body does not hold an
        # array, so an HTML error page or a DRF error object has to be caught
        # here rather than by the iterator.
        return None, "response was not a JSON array: {}".format(_text(body[:200]))
    return iter_array(body), None


def main(*args, **kwargs):
    require(kwargs, "url", "api_key")

    base_url = get_url_base(kwargs, "url")
    api_key = get_string(kwargs, "api_key")
    monitoring_type = get_string(kwargs, "monitoring_type", default="all").lower()
    if monitoring_type == "all":
        monitoring_type = ""
    extract_software = get_bool(kwargs, "extract_software", default=False)
    software_limit = get_int(kwargs, "software_agent_limit", default=250)

    parsed = url_parse(base_url)
    namespace = parsed.hostname.lower() if parsed and parsed.hostname else base_url

    headers = {
        "X-API-KEY": api_key,
        "Accept": "application/json",
    }
    ctx = {
        "base_url": base_url,
        "monitoring_type": monitoring_type,
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
    }

    stream, err = stream_agents(ctx)
    if err:
        print("{}: failed to list agents: {}".format(VENDOR, err))
        return None

    ceiling = now()
    reported = 0
    skipped = 0
    software_queried = 0
    software_skipped = 0
    seen = {}

    for entry in stream:
        record = entry if type(entry) == "dict" else None
        if record == None:
            skipped += 1
            print("{}: skipping agent row that is not an object".format(VENDOR))
            continue

        agent_id = _clean(record.get("agent_id"))
        software = []
        if extract_software and agent_id:
            if software_queried < software_limit:
                software = fetch_software(ctx, agent_id)
                software_queried += 1
            else:
                software_skipped += 1

        asset = build_asset(record, namespace, ceiling, software)
        if asset == None:
            skipped += 1
            continue
        if asset.id in seen:
            skipped += 1
            print("{}: skipping duplicate agent_id {}".format(VENDOR, agent_id))
            continue
        seen[asset.id] = True
        reported += report_asset(asset)


    if software_skipped:
        print("{}: software limit of {} reached, {} agents imported without software".format(
            VENDOR, software_limit, software_skipped))
    print("{}: reported {} assets, skipped {}".format(VENDOR, reported, skipped))
    # Assets are streamed with report_assets, so nothing is buffered here.
    return None

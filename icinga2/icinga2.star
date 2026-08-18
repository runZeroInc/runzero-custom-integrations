# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-icinga2",
    "name": "Icinga 2",
    "type": "inbound",
    "description": "Imports monitored hosts from the Icinga 2 API, with their addresses, host groups, and custom variables.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Icinga 2 API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://icinga.example.com:5665",
            "description": "Base URL of the Icinga 2 API listener. The default port is 5665 and the API is always TLS.",
        },
        {
            "key": "username",
            "label": "API user",
            "type": "string",
            "required": True,
            "description": "Name of the Icinga 2 ApiUser object, for example the object name in /etc/icinga2/conf.d/api-users.conf.",
        },
        {
            "key": "password",
            "label": "API password",
            "type": "secret",
            "required": True,
            "description": "Password attribute of that ApiUser object.",
        },
        {
            "key": "host_group",
            "label": "Host group",
            "type": "string",
            "required": False,
            "description": "Import only hosts in this host group. Sent as a parameterized filter variable, so the group name is never interpolated into the filter expression.",
        },
        {
            "key": "host_filter",
            "label": "Host filter expression",
            "type": "string",
            "required": False,
            "placeholder": "host.vars.site == \"dc1\"",
            "description": "Raw Icinga DSL filter, evaluated server-side against every host. Combined with the host group filter when both are set.",
        },
        {
            "key": "include_check_output",
            "label": "Import last check output",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Request last_check_result and keep its plugin output. This attribute carries performance data and the full command line, so it multiplies the response size.",
        },
        {
            "key": "include_checks",
            "label": "Summarize service checks",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch the Service objects and record per-host check counts and check names as custom attributes. Checks are never imported as runZero services; see the README.",
        },
        {
            "key": "max_check_names",
            "label": "Check names per host",
            "type": "int",
            "required": False,
            "default": 40,
            "min": 0,
            "description": "Maximum number of service check names recorded per host when service checks are summarized.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', http_post='post', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('json', json_encode='encode')
load('jsonstream', 'iter_array')
load('time', 'now', 'from_timestamp')

load('coerce', 'as_dict', 'as_text')
VENDOR = "icinga2"
ATTR_PREFIX = "icinga"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix to the key with the separator
MAX_CHECK_NAMES = 200  # hard ceiling on the per-host check-name list, whatever the option says

# Attributes requested for every Host object. Icinga returns every attribute of
# every object when attrs is omitted, and a Host carries well over a hundred of
# them, so the list is explicit: it is the difference between a few hundred
# bytes and several kilobytes per host on an install with tens of thousands.
HOST_ATTRS = [
    "name", "display_name", "address", "address6", "groups", "vars",
    "state", "state_type", "last_check", "last_state_change", "check_command",
    "zone", "command_endpoint", "notes", "notes_url", "action_url", "templates",
    "max_check_attempts", "check_interval", "enable_notifications",
    "acknowledgement", "downtime_depth", "flapping", "active", "paused",
]
SERVICE_ATTRS = ["host_name", "name", "display_name", "state", "check_command"]

# Host.state and Service.state, from the Host and Service runtime attribute
# tables in the object types reference.
HOST_STATES = {0: "UP", 1: "DOWN"}
SERVICE_STATES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
STATE_TYPES = {0: "SOFT", 1: "HARD"}
ACK_STATES = {0: "NONE", 1: "NORMAL", 2: "STICKY"}

# Custom variable names that conventionally hold a MAC address. Icinga has no
# MAC attribute of its own, so this is the only place one can appear.
MAC_VARS = ["mac", "mac_address", "macaddress", "mac_addr", "hwaddr", "hw_address"]

# Custom variable names that conventionally hold the operating system. vars.os
# is set by the host template that ships in Icinga's own example configuration.
OS_VARS = ["os", "operating_system", "osfamily"]

# Names that identify nothing. Icinga host objects are frequently named for a
# role rather than a machine, and an object named "localhost" ships in the
# default configuration of every install.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "n/a", "none", "-"]

# The character set a value has to stay inside to be treated as a hostname.
HOSTNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
def _str_list(value):
    """Coerce an Icinga array attribute into a list of non-empty strings."""
    if type(value) != "list":
        return []
    out = []
    for item in value:
        text = as_text(item)
        if text:
            out.append(text)
    return out
def _num(value):
    """Return an Icinga numeric attribute as an int, or None when it is not a
    number at all.

    Every number Icinga emits is a JSON float, including the ones documented as
    Number enumerations: a host that is UP serializes as "state": 0.0 and a
    check with three attempts as "max_check_attempts": 3.0. Reading those with
    an int-only type test silently drops every state, so the float has to be
    accepted and truncated."""
    kind = type(value)
    if kind == "int":
        return value
    if kind == "float":
        return int(value)
    return None


def _epoch(value, ceiling):
    """Convert an Icinga timestamp into a time value, clamped to the current
    time. Icinga serializes timestamps as a Unix epoch with fractional seconds
    (1443019345.093372), and from_timestamp rejects a float outright with an
    error that would abort the whole script, so the value is truncated to a
    whole second first. runZero rejects an asset whose first- or last-seen time
    is in the future and drops the entire record, so a clock skew between the
    Icinga server and the Explorer must not be allowed through."""
    if type(value) != "int" and type(value) != "float":
        return None
    seconds = int(value)
    # Icinga writes a NEGATIVE sentinel for "never checked" rather than omitting
    # the attribute: 2.16.4 writes -1, verified against the real server in the
    # container scenario, where every seeded host reports last_check = -1. The
    # test is `<= 0` rather than `== -1` deliberately -- it covers 0 as well, so
    # a build that spells the sentinel differently is still handled -- and it
    # must stay that way. A future `== 0` would let -1 through and produce a
    # 1969 timestamp on every unchecked object.
    if seconds <= 0:
        return None
    if seconds > ceiling.unix:
        return ceiling
    return from_timestamp(seconds)
def _hostname(value):
    """Return a value fit to be imported as a hostname, or an empty string.

    Icinga's host object name and display_name are free text. The name is
    usually an FQDN, but it is just as often a bare IP address or a role label,
    and display_name is a human caption - "Core switch 01" - far more often than
    it is a name. A bare IP is not a name and correlates nothing, a placeholder
    correlates unrelated hosts to each other, and a caption with a space in it
    is not resolvable, so all three are rejected."""
    text = as_text(value)
    if not text or len(text) > 253:
        return ""
    if text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    # Starlark strings are not iterable, so the scan is by index.
    numeric = True
    for index in range(len(text)):
        if text[index] not in HOSTNAME_CHARS:
            return ""
        if text[index] not in "0123456789.":
            numeric = False
    # A value made only of digits and dots is a malformed address - "192.0.2..300"
    # is what a typo in the address attribute looks like - not a name. The
    # platform rejects a well-formed bare IP as a hostname on its own; this
    # catches the near misses it cannot recognize.
    if numeric:
        return ""
    return text


def _array_at(body, key):
    """Report whether the body is a JSON object with an array at the given
    top-level key.

    iter_array aborts the entire script - there is no way to recover - when the
    body is not JSON, when the path is absent, or when the value at the path is
    not an array. Icinga answers an authentication failure or a missing
    permission with an object that has no results key at all, and a reverse
    proxy in front of the API answers with HTML, so the shape has to be checked
    before the parser is handed the body."""
    if type(body) != "string":
        return False
    text = body.lstrip()
    if not text.startswith("{"):
        return False
    marker = '"' + key + '"'
    index = text.find(marker)
    if index < 0:
        return False
    rest = text[index + len(marker):].lstrip()
    if not rest.startswith(":"):
        return False
    return rest[1:].lstrip().startswith("[")


def _query(ctx, path, payload, what):
    """Run one Icinga object query and return the raw response body.

    The query is sent as a POST carrying X-HTTP-Method-Override: GET, which the
    API documents as the way to give a read a request body. That is required
    rather than convenient: attrs and joins are repeated query parameters in URL
    form (attrs=name&attrs=address), and the runtime's params= dict cannot hold
    a duplicate key, so the only way to ask for a trimmed attribute set is the
    JSON body. The body form also keeps the filter expression out of the URL.

    The raw verb is used instead of post_json because the response is a single
    unpaginated array of every host, which on a large install is measured in
    megabytes; handing the undecoded body to jsonstream keeps the decoded
    document from ever existing. The cost is that the raw verbs take no retry
    budget, so this request gets one attempt."""
    # The raw verbs take the body as bytes; a str is rejected outright.
    resp = http_post(ctx["api_url"] + path, body=bytes(json_encode(payload)), **ctx["http_options"])
    if resp == None:
        return "", "no response from the Icinga 2 API"
    if resp.status_code == 401:
        return "", "status 401: the ApiUser name or password was rejected"
    if resp.status_code == 404:
        # A query that matched nothing and a query the ApiUser may not run are
        # both reported in the 400 range, so the message names both rather than
        # guessing which one happened.
        return "", "status 404: no {} matched, or the ApiUser lacks the objects/query permission".format(what)
    if resp.status_code < 200 or resp.status_code >= 300:
        return "", "status {}: {}".format(resp.status_code, as_text(resp.body)[:200])
    return resp.body, None


def build_check_summary(ctx):
    """Index the Service objects by the host they are attached to.

    An Icinga service is a check - "disk space on web01", "http on api02" - and
    not a listening port, so these never become runZero services. What they are
    worth is a description of how a host is monitored, which is recorded as
    counts and names on the host's own asset. Only the counts and a capped list
    of names are kept, so the map stays bounded on an install with a hundred
    checks per host."""
    summary = {}
    payload = {"attrs": SERVICE_ATTRS}
    body, err = _query(ctx, "/v1/objects/services", payload, "service")
    if err:
        print("icinga2: failed to fetch service checks:", err)
        return summary
    if not _array_at(body, "results"):
        print("icinga2: the service query returned no results array; skipping check summaries")
        return summary

    total = 0
    for entry in iter_array(body, path="results"):
        if type(entry) != "dict":
            continue
        attrs = as_dict(entry.get("attrs"))
        host = as_text(attrs.get("host_name"))
        if not host:
            continue
        total += 1
        record = summary.get(host)
        if record == None:
            record = {"count": 0, "names": [], "problems": 0}
            summary[host] = record
        record["count"] += 1
        state = _num(attrs.get("state"))
        if state != None and state != 0:
            record["problems"] += 1
        name = as_text(attrs.get("display_name")) or as_text(attrs.get("name"))
        if name and len(record["names"]) < ctx["max_check_names"]:
            record["names"].append(name)

    print("icinga2: summarized {} service checks across {} hosts".format(total, len(summary)))
    return summary


def collect_addresses(attrs):
    """Split the address attributes into routable IPs and hostnames.

    address and address6 are documented as the host's IPv4 and IPv6 address, but
    they are plain string attributes that Icinga never validates, and filling
    them with a DNS name is common enough to be the norm on installs that let
    DNS do the resolving. Each value is therefore classified by what it actually
    is rather than by which attribute it arrived in."""
    ips = []
    names = []
    for key in ["address", "address6"]:
        value = as_text(attrs.get(key))
        if not value:
            continue
        routable = routable_ip(value)
        if routable:
            if routable not in ips:
                ips.append(routable)
            continue
        if ip_address(value) != None:
            # A real address that identifies nothing - loopback or APIPA.
            continue
        name = _hostname(value)
        if name and name not in names:
            names.append(name)
    return ips, names


def find_mac(variables):
    """Recover a MAC address from the host's custom variables, returning the
    value and the variable it came from.

    Icinga models no hardware at all, so a MAC only ever appears where an
    operator put one. Rather than sniff every variable, a short list of
    conventional names is checked and the value is accepted only when it parses
    as a MAC, which keeps a variable holding a serial number or an asset tag
    from being read as hardware addressing."""
    for key in MAC_VARS:
        for candidate in [key, key.upper()]:
            value = as_text(variables.get(candidate))
            if value and normalize_mac(value) != None:
                return value, candidate
    return "", ""


def build_asset(ctx, entry, name, checks):
    """Convert one Icinga Host object into a runZero asset, or None when the
    object carries nothing runZero could ever correlate on.

    An Icinga host whose only address is 127.0.0.1 and whose only name is
    "localhost" - the object that ships in the default configuration of every
    install - has no MAC, no routable address, and no usable hostname. Importing
    it produces an asset that can never merge with anything and that clutters
    the inventory of every runZero account that adds a second Icinga server, so
    it is skipped instead."""
    attrs = as_dict(entry.get("attrs"))

    ips, address_names = collect_addresses(attrs)
    variables = as_dict(attrs.get("vars"))
    mac, mac_var = find_mac(variables)
    nic = network_interface(mac=mac, ips=ips)

    hostnames = []
    for candidate in [_hostname(name), _hostname(attrs.get("display_name"))] + address_names:
        if candidate and candidate not in hostnames:
            hostnames.append(candidate)

    if not hostnames and nic == None:
        print("icinga2: skipping host {}: no MAC, routable address, or usable hostname".format(name))
        return None

    groups = _str_list(attrs.get("groups"))
    state = _num(attrs.get("state"))
    state_label = HOST_STATES.get(state, "") if state != None else ""

    tags = [VENDOR]
    for group in groups:
        tags.append("hostgroup:" + group)
    if state_label:
        tags.append("state:" + state_label.lower())

    check_record = checks.get(name, {})

    attributes = {
        "object_name": name,
        "server": ctx["scope"],
        "display_name": as_text(attrs.get("display_name")),
        "address": as_text(attrs.get("address")),
        "address6": as_text(attrs.get("address6")),
        "state": state_label,
        "state_code": state,
        "state_type": STATE_TYPES.get(_num(attrs.get("state_type")), ""),
        "acknowledgement": ACK_STATES.get(_num(attrs.get("acknowledgement")), ""),
        "downtime_depth": _num(attrs.get("downtime_depth")),
        "flapping": attrs.get("flapping"),
        "check_command": as_text(attrs.get("check_command")),
        "check_interval": _num(attrs.get("check_interval")),
        "max_check_attempts": _num(attrs.get("max_check_attempts")),
        "notifications_enabled": attrs.get("enable_notifications"),
        "active": attrs.get("active"),
        "paused": attrs.get("paused"),
        "zone": as_text(attrs.get("zone")),
        "command_endpoint": as_text(attrs.get("command_endpoint")),
        "groups": groups,
        "templates": _str_list(attrs.get("templates")),
        "notes": as_text(attrs.get("notes")),
        "notes_url": as_text(attrs.get("notes_url")),
        "action_url": as_text(attrs.get("action_url")),
        # Truncated to whole seconds: these arrive as floats with microsecond
        # fractions, which would otherwise be stringified in exponent form.
        "last_check_epoch": _num(attrs.get("last_check")),
        "last_state_change_epoch": _num(attrs.get("last_state_change")),
        "check_count": check_record.get("count", 0) if check_record else "",
        "check_problem_count": check_record.get("problems", 0) if check_record else "",
        "check_names": check_record.get("names", []) if check_record else [],
    }
    if mac:
        attributes["mac"] = mac
        attributes["mac_source_var"] = mac_var
    if ctx["include_check_output"]:
        result = as_dict(attrs.get("last_check_result"))
        attributes["last_check_output"] = as_text(result.get("output"))[:1000]
        attributes["last_check_exit_status"] = _num(result.get("exit_status"))

    params = {
        # The Icinga object name is the primary key of the configuration: Icinga
        # refuses two Host objects with the same name, and every other API call
        # addresses a host by it.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], name),
        "hostnames": hostnames,
        # network_interface returns None when neither a usable address nor a MAC
        # survived, and a networkInterfaces list holding None aborts the run.
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
    }

    for key in OS_VARS:
        os_name = as_text(variables.get(key))
        if os_name:
            params["os"] = os_name
            break

    last_seen = _epoch(attrs.get("last_check"), ctx["now"])
    params["customAttributes"] = to_custom_attributes(
        attributes, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    # vars is where every site stashes the data Icinga itself has no field for -
    # owner, location, serial, environment, application - so it is flattened
    # under its own prefix rather than folded in with the object's attributes.
    variable_attrs = to_custom_attributes(
        variables, prefix=ATTR_PREFIX + ATTR_SEPARATOR + "var", separator=ATTR_SEPARATOR)
    for key in variable_attrs:
        if key not in params["customAttributes"]:
            params["customAttributes"][key] = variable_attrs[key]

    asset = ImportAsset(**params)
    # There is no first-seen equivalent in Icinga: an object exists from the
    # moment it is configured, and last_state_change is not when the host was
    # first seen.
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_filter(kwargs):
    """Build the server-side filter expression and its variables.

    A host group name is passed through filter_vars rather than pasted into the
    expression, which is what the API reference recommends and what keeps a
    group name containing a quote from changing the meaning of the filter."""
    expressions = []
    variables = {}

    group = get_string(kwargs, "host_group", default="").strip()
    if group:
        expressions.append("group in host.groups")
        variables["group"] = group

    raw = get_string(kwargs, "host_filter", default="").strip()
    if raw:
        expressions.append("(" + raw + ")")

    if not expressions:
        return "", {}
    return " && ".join(expressions), variables


def fetch_and_report_hosts(ctx, host_filter, filter_vars):
    """Stream the host inventory into runZero.

    /v1/objects/hosts does not paginate: it answers with every matching object
    in a single results array, which is why the response is streamed element by
    element and reported in batches instead of being decoded into one list."""
    payload = {"attrs": ctx["host_attrs"]}
    if host_filter:
        payload["filter"] = host_filter
        if filter_vars:
            payload["filter_vars"] = filter_vars

    body, err = _query(ctx, "/v1/objects/hosts", payload, "host")
    if err:
        print("icinga2: failed to fetch hosts:", err)
        return 0
    if not _array_at(body, "results"):
        print("icinga2: the host query returned no results array; nothing was imported")
        return 0

    reported = 0
    skipped = 0
    seen = {}
    for entry in iter_array(body, path="results"):
        if type(entry) != "dict":
            skipped += 1
            continue
        attrs = as_dict(entry.get("attrs"))
        name = as_text(entry.get("name")) or as_text(attrs.get("name"))
        if not name:
            skipped += 1
            print("icinga2: skipping host object with no name: check_command={}".format(
                as_text(attrs.get("check_command"))))
            continue
        if name in seen:
            continue
        seen[name] = True

        asset = build_asset(ctx, entry, name, ctx["checks"])
        if asset == None:
            skipped += 1
            continue
        reported += report_asset(asset)
    if skipped:
        print("icinga2: skipped {} host records with no name or nothing to correlate on".format(skipped))
    print("icinga2: reported {} assets".format(reported))
    return reported


def fetch_version(ctx):
    """Read the Icinga version so every asset records which server it came from.
    This one is small enough to go through the JSON helper, which brings the
    retry budget the streamed calls give up."""
    data, err = get_json(ctx["api_url"] + "/v1/status/IcingaApplication", **ctx["http_options"])
    if err:
        print("icinga2: could not read the application status:", err)
        return ""
    if type(data) != "dict":
        return ""
    results = data.get("results")
    if type(results) != "list" or not results:
        return ""
    status = as_dict(as_dict(results[0]).get("status"))
    app = as_dict(as_dict(status.get("icingaapplication")).get("app"))
    return as_text(app.get("version"))


def main(**kwargs):
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("icinga2: no Icinga 2 API URL was configured")
        return None

    parsed = url_parse(url)
    if parsed == None or not parsed.hostname:
        print("icinga2: could not determine the Icinga host from the configured URL")
        return None
    # The hostname alone, without the port, so that moving the API listener off
    # the default 5665 does not re-key every asset the previous runs created.
    scope = parsed.hostname

    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")
    if not username or not password:
        print("icinga2: an ApiUser name and password are both required")
        return None

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": basic(username, password),
        # The API rejects a body on a GET, so a read that needs one is sent as a
        # POST carrying this header. Without it the request would be treated as
        # an object creation and rejected for lacking objects/create.
        "X-HTTP-Method-Override": "GET",
    }

    max_check_names = get_int(kwargs, "max_check_names", default=40)
    if max_check_names < 0:
        max_check_names = 0
    if max_check_names > MAX_CHECK_NAMES:
        max_check_names = MAX_CHECK_NAMES

    host_attrs = list(HOST_ATTRS)
    include_check_output = get_bool(kwargs, "include_check_output", default=False)
    if include_check_output:
        host_attrs.append("last_check_result")

    ctx = {
        "api_url": url,
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
        "now": now(),
        "scope": scope,
        "host_attrs": host_attrs,
        "include_check_output": include_check_output,
        "max_check_names": max_check_names,
        "checks": {},
    }

    version = fetch_version(ctx)
    if version:
        print("icinga2: connected to Icinga", version)

    if get_bool(kwargs, "include_checks", default=False):
        ctx["checks"] = build_check_summary(ctx)

    host_filter, filter_vars = build_filter(kwargs)
    if host_filter:
        print("icinga2: applying host filter:", host_filter)

    if not fetch_and_report_hosts(ctx, host_filter, filter_vars):
        print("icinga2: no assets retrieved")
    return None

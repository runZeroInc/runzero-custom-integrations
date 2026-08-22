# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cybereason",
    "name": "Cybereason",
    "type": "inbound",
    "description": "Imports sensor-managed endpoints, and optionally their inbound network connections, from a Cybereason tenant.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The sensor id is authoritative for a sensor installation, but only a
    # single last-known internal address is published, so ip-break is
    # relaxed to keep a roaming endpoint from fragmenting. mac-break is
    # deliberately left on: the MAC here is recovered from an undocumented
    # pylumId format, so if that recovery is ever wrong the right outcome is
    # a separate asset rather than a confident merge onto the wrong one.
    # name-break is left on as well, guarding against a sensor id that a
    # cloned golden image duplicated across a fleet collapsing that fleet
    # onto one asset. See the README.
    "matchBehavior": "no-ip-break",
    "params": [
        {
            "key": "url",
            "label": "Cybereason URL",
            "type": "url",
            "required": True,
            "placeholder": "https://tenant.cybereason.net:443",
            "description": "Base URL of the Cybereason console, including the port. Cybereason publishes tenants on port 443 or 8443 depending on the deployment.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Cybereason console user, normally an email address. A role with read access to System > Sensors is sufficient.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the console user. Accounts with two-factor authentication enabled cannot be used, because the form login has no second-factor step.",
        },
        {
            "key": "import_connections",
            "label": "Import inbound network connections as services",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Run one investigation graph query per sensor to look for connections the endpoint accepted, and record those as services. Off by default because it costs one extra request per sensor.",
        },
        {
            "key": "connection_limit",
            "label": "Connection enrichment limit",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "description": "Maximum number of sensors to query for connections. Sensors past the limit are still imported, without services. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Sensors per page",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 1000,
            "description": "Sensor records requested per call. Cybereason defaults to 50 when no limit is sent.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', 'post_json', 'url_encode', 'url_parse')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('requests', 'Session')
load('time', 'now', 'from_timestamp')

VENDOR = "cybereason"
# to_custom_attributes joins the prefix to each key with the separator, so the
# separator has to be passed too or every attribute is named cybereason.<key>.
ATTR_PREFIX = "cybereason"
ATTR_SEPARATOR = "_"

LOGIN_PATH = "/login.html"
SENSORS_PATH = "/rest/sensors/query"
VISUALSEARCH_PATH = "/rest/visualsearch/query/simple"

# Cybereason's own clients treat a session as good for 28000 seconds. The
# refresh happens a little early so a long page never expires mid-flight.
SESSION_LIFETIME_SECONDS = 28000
SESSION_REFRESH_MARGIN_SECONDS = 300
SESSION_COOKIE = "JSESSIONID"

DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000
MAX_SERVICES = 99

# The investigation graph is a general query language; these are the only knobs
# that matter for a single machine's connections. queryTimeout is milliseconds
# and is the server-side budget, not the HTTP timeout.
CONNECTION_QUERY_TIMEOUT_MS = 120000
CONNECTION_RESULT_LIMIT = 200
CONNECTION_FIELDS = ["elementDisplayName", "direction", "serverAddress", "serverPort",
                     "portType"]

# Cybereason records a connection's direction from the point of view of the
# machine that owns it, so only an inbound connection describes a port that was
# open on the endpoint itself.
DIRECTION_INBOUND = "INCOMING"

DIGITS = "0123456789"
# Indexing into this doubles as a hex digit's value, which is how the multicast
# bit is read out of a pylumId MAC token.
HEX_DIGITS = "0123456789abcdef"

# osType is a small platform enum. Anything outside it is title-cased as-is and
# the raw value is kept as an attribute either way.
OS_TYPES = {
    "WINDOWS": "Windows",
    "OSX": "macOS",
    "MACOS": "macOS",
    "MAC": "macOS",
    "LINUX": "Linux",
    "UNKNOWN": "",
}

# deviceType is null on every sensor in the only captured response available, so
# the enum is unverified. Only spellings whose meaning is unambiguous are
# mapped; everything else leaves deviceType unset and survives as the
# cybereason_device_type attribute rather than being guessed into a runZero
# type that search and reporting would then treat as authoritative.
DEVICE_TYPES = {
    "server": "Server",
    "domain controller": "Server",
    "workstation": "Desktop",
    "desktop": "Desktop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "portable": "Laptop",
    "tablet": "Tablet",
    "mobile": "Mobile Device",
    "phone": "Mobile Device",
    "virtual machine": "Virtual Machine",
}

# Sensor fields copied verbatim onto every asset. The rest of the record is
# per-component feature switches (document protection modes, static analysis
# origins) that would only crowd the attribute list.
SENSOR_ATTRS = [
    "amStatus", "antiMalwareStatus", "avDbLastUpdateTime", "avDbVersion",
    "collectionStatus", "collectiveUuid", "compliance", "consoleVersion",
    "criticalAsset", "customTags", "department", "deviceModel", "deviceType",
    "disconnected", "disconnectionTime", "externalIpAddress", "firstSeenTime",
    "fqdn", "groupId", "groupName", "guid", "internalIpAddress", "isolated",
    "lastPylumInfoMsgUpdateTime", "lastPylumUpdateTimestampMs", "lastStatusAction",
    "lastUpgradeResult", "location", "machineName", "offlineTimeMS", "onlineTimeMS",
    "organization", "organizationalUnit", "osType", "osVersionType", "outdated",
    "policyId", "policyName", "preventionStatus", "privateServerIp", "proxyAddress",
    "pylumId", "ransomwareStatus", "sensorId", "serialNumber", "serverId",
    "serverIp", "serverName", "serviceStatus", "siteId", "siteName", "staleTimeMS",
    "status", "upTime", "version",
]


def _clean(value):
    """Return a trimmed string, or an empty string when there is nothing usable."""
    if value == None:
        return ""
    if type(value) == "list":
        return ",".join([_clean(item) for item in value if item != None])
    if type(value) == "dict":
        return ""
    return str(value).strip()


def _is_true(value):
    """Read a flag that the API serializes as either a bool or a quoted bool.

    isolated arrives as false in one captured response and as "false" in
    another, so neither spelling can be trusted on its own.
    """
    if type(value) == "bool":
        return value
    return _clean(value).lower() == "true"


def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is neither."""
    if type(value) == "int":
        return value
    if type(value) == "float":
        return int(value)
    text = _clean(value)
    if not text or len(text) > 18:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _timestamp(value, ceiling):
    """Convert an epoch-milliseconds field to a time, or None when it is absent.

    Cybereason writes 0 for "never" (a sensor that has not disconnected, a
    machine with no recorded first-seen time), and runZero rejects an
    ImportAsset whose first- or last-seen time is ahead of now by failing the
    whole record, so a clock-skewed value is capped at the current time rather
    than allowed to drop the asset. The raw milliseconds are kept as a custom
    attribute either way.
    """
    millis = _to_int(value)
    if millis <= 0:
        return None
    parsed = from_timestamp(millis // 1000)
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed
def _hostnames(sensor):
    """Return the sensor's names, de-duplicated case-insensitively.

    fqdn is frequently the short name repeated rather than a qualified name,
    which is what the captured response shows, so the two fields collapse to one
    hostname more often than not.
    """
    names = []
    seen = {}
    for value in [_clean(sensor.get("machineName")), _clean(sensor.get("fqdn"))]:
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen[key] = True
        names.append(value)
    return names


def _pylum_mac(sensor):
    """Recover the endpoint MAC that Cybereason embeds in pylumId, or "".

    Cybereason publishes no MAC field, but pylumId is built as
    PYLUMCLIENT_<realm>_<machine name>_<12 hex digits>, and the trailing token
    is the endpoint's MAC:

        PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F  -> 08:00:27:...
        PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5  -> 12:3c:c9:...

    The format is undocumented, so rather than trust the shape of the string on
    its own, the field layout is re-confirmed against this record: the token
    before the last one has to be the machine's own name. That is what makes a
    misparse of some future pylumId variant fall out as a skip instead of as a
    plausible-looking wrong MAC, which would merge unrelated assets.

    The address itself is then required to be a 12-digit hex unicast station
    address. Locally administered addresses are kept: the second example above
    has the LAA bit set because AWS assigns EC2 interfaces out of that space,
    and dropping those would discard the MAC for every cloud-hosted endpoint.
    """
    pylum = _clean(sensor.get("pylumId"))
    parts = pylum.split("_")
    if len(parts) < 2:
        return ""

    # Re-confirm the field layout against this record before reading the token.
    name = parts[len(parts) - 2].lower()
    if not name:
        return ""
    matched = False
    for candidate in _hostnames(sensor):
        candidate = candidate.lower()
        if candidate == name or candidate.startswith(name + "."):
            matched = True
            break
    if not matched:
        return ""

    token = parts[len(parts) - 1].lower()
    if len(token) != 12:
        return ""
    for index in range(len(token)):
        if token[index] not in HEX_DIGITS:
            return ""

    # An all-zero address is a placeholder, and the low bit of the first octet
    # marks a multicast address, which no station ever owns.
    if token == "000000000000":
        return ""
    if (HEX_DIGITS.find(token[1]) % 2) == 1:
        return ""

    octets = []
    for index in range(6):
        octets.append(token[index * 2:index * 2 + 2])
    return ":".join(octets)


def _domain(sensor):
    """Return the DNS domain when fqdn is genuinely qualified."""
    fqdn = _clean(sensor.get("fqdn"))
    if "." not in fqdn:
        return ""
    return fqdn[fqdn.find(".") + 1:].strip(".")


def split_os(sensor):
    """Split osType and osVersionType into an OS name and, when one is really
    present, a version.

    osType is the platform family ("WINDOWS") and osVersionType is the product
    name with underscores for spaces ("Windows_10"), so the product name is the
    better `os` value. osVersionType is a release family rather than a build
    number, so a version is only emitted when what remains after trimming the
    family name is numeric: "Windows_10" yields 10, while
    "Windows_Server_2019" yields no version at all rather than the nonsense
    string "Server 2019".
    """
    family = OS_TYPES.get(_clean(sensor.get("osType")).upper())
    if family == None:
        family = _clean(sensor.get("osType")).title()
    product = _clean(sensor.get("osVersionType")).replace("_", " ").strip()
    name = product if product else family
    version = ""
    if family and product.startswith(family + " "):
        remainder = product[len(family) + 1:].strip()
        numeric = remainder != ""
        for index in range(len(remainder)):
            if remainder[index] not in DIGITS and remainder[index] != ".":
                numeric = False
                break
        if numeric:
            version = remainder
    return name, version


def _custom_tags(value):
    """Coerce the customTags field into a list of strings.

    It is null on every sensor in the captured response, so whether Cybereason
    publishes a list or a delimited string is unconfirmed; both are handled.
    """
    tags = []
    if type(value) == "list":
        candidates = [_clean(item) for item in value]
    else:
        candidates = _clean(value).split(",")
    for candidate in candidates:
        text = candidate.strip()
        if text and text not in tags:
            tags.append(text)
    return tags


def _simple_value(element, name):
    """Read one scalar out of an investigation graph element.

    Every field in a graph result is wrapped as
    {"simpleValues": {"<field>": {"values": ["<value>"], "totalValues": 1}}},
    so a plain dict lookup returns the wrapper rather than the value.
    """
    simple = element.get("simpleValues")
    if type(simple) != "dict":
        return ""
    field = simple.get(name)
    if type(field) != "dict":
        return ""
    values = field.get("values")
    if type(values) != "list" or not values:
        return ""
    return _clean(values[0])


def build_services(elements, addresses):
    """Build Service objects from the connections an endpoint accepted.

    A Cybereason Connection element describes a conversation, not a listening
    socket, and serverAddress/serverPort name the server side of it. For an
    outbound connection that is the remote peer, so recording it would attach
    another host's ports to this asset. Only a connection whose direction is
    inbound *and* whose server address is one of this endpoint's own addresses
    is evidence that this endpoint was listening on that port, and that is the
    only case that produces a Service. Everything else is counted and dropped.

    No transport is published for a connection, so tcp is recorded and flagged
    as assumed; a UDP service such as NetBIOS will be reported as tcp.
    """
    services = []
    seen = {}
    inbound = 0
    skipped = 0
    for element in elements:
        if type(element) != "dict":
            continue
        direction = _simple_value(element, "direction").upper()
        if direction != DIRECTION_INBOUND:
            skipped += 1
            continue
        inbound += 1
        address = routable_ip(_simple_value(element, "serverAddress"))
        if not address or address not in addresses:
            # An inbound connection whose server side is not this endpoint is
            # either a relayed record or an address the sensor never reported,
            # and guessing which would put a port on the wrong asset.
            skipped += 1
            continue
        port = _to_int(_simple_value(element, "serverPort"))
        if port < 1 or port > 65535:
            skipped += 1
            continue
        key = "{}:{}".format(address, port)
        if key in seen:
            continue
        seen[key] = True
        services.append(Service(
            address=address,
            port=int(port),
            transport="tcp",
            customAttributes=to_custom_attributes({
                "connection_direction": direction,
                "connection_port_type": _simple_value(element, "portType"),
                "transport_source": "assumed",
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        ))
    return services, inbound, skipped


def build_asset(ctx, sensor):
    """Convert one Cybereason sensor record into a runZero asset."""
    sensor_id = _clean(sensor.get("sensorId"))

    # internalIpAddress is the only address that describes the endpoint.
    # externalIpAddress is the NAT egress address shared by everything behind
    # one gateway, and serverIp/privateServerIp are addresses of the Cybereason
    # server the sensor reports to, so none of the three can become an interface
    # address without inviting unrelated endpoints to merge together. All three
    # are kept as custom attributes.
    addresses = []
    internal = routable_ip(sensor.get("internalIpAddress"))
    if internal:
        addresses.append(internal)

    # Cybereason exposes no MAC field; this one is recovered from pylumId, so it
    # is only present for records whose layout could be re-confirmed. An
    # endpoint with a MAC and no usable address still earns an interface.
    mac = _pylum_mac(sensor)
    nic = network_interface(mac=mac, ips=addresses) if mac else network_interface(ips=addresses)
    netifs = [nic] if nic else []

    services = []
    if ctx["import_connections"]:
        if ctx["connection_limit"] and ctx["connection_used"] >= ctx["connection_limit"]:
            ctx["connection_skipped"] += 1
        else:
            ctx["connection_used"] += 1
            elements = fetch_connections(ctx, _clean(sensor.get("machineName")))
            services, inbound, dropped = build_services(elements, addresses)
            ctx["connections_seen"] += len(elements)
            ctx["connections_inbound"] += inbound
            ctx["connections_dropped"] += dropped

    site = _clean(sensor.get("siteName"))
    group = _clean(sensor.get("groupName"))
    policy = _clean(sensor.get("policyName"))
    status = _clean(sensor.get("status"))
    serial = _clean(sensor.get("serialNumber"))

    tags = [VENDOR]
    if site:
        tags.append("site:" + site)
    if group:
        tags.append("group:" + group)
    if policy:
        tags.append("policy:" + policy)
    if status:
        tags.append("status:" + status.lower())
    if serial:
        tags.append("serial:" + serial)
    if _is_true(sensor.get("isolated")):
        tags.append("isolated")
    if _is_true(sensor.get("outdated")):
        tags.append("outdated-sensor")
    for tag in _custom_tags(sensor.get("customTags")):
        tags.append("tag:" + tag)

    attrs = {"tenant": ctx["host"]}
    for name in SENSOR_ATTRS:
        if name in sensor:
            attrs[name] = sensor[name]
    if ctx["import_connections"]:
        attrs["service_count"] = len(services)
    if mac:
        # network_interface clears the locally administered bit so that MACs
        # match across sources, which rewrites an EC2 address such as
        # 12:3c:... to 10:3c:.... Keeping the recovered value verbatim leaves
        # the address the cloud console shows visible on the asset.
        attrs["pylum_mac"] = mac

    os_name, os_version = split_os(sensor)
    model = _clean(sensor.get("deviceModel"))
    device_type = DEVICE_TYPES.get(
        _clean(sensor.get("deviceType")).lower().replace("_", " ").replace("-", " "), "")

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["host"], sensor_id),
        "hostnames": _hostnames(sensor),
        "networkInterfaces": netifs,
        "services": services[:MAX_SERVICES],
        "tags": tags,    }

    domain = _domain(sensor)
    if domain:
        params["domain"] = domain
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    if model:
        params["model"] = model
    if device_type:
        params["deviceType"] = device_type

    first_seen = _timestamp(sensor.get("firstSeenTime"), ctx["now"])
    if first_seen:
        params["firstSeenTS"] = first_seen

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                      separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)

    # lastPylumUpdateTimestampMs is the last message the sensor sent, which is
    # the closest thing Cybereason records to an observation of the endpoint.
    # lastPylumInfoMsgUpdateTime only moves when a full inventory message
    # arrives, so it is the fallback rather than the first choice.
    # lastSeenTS is settable as an attribute but is not a constructor keyword.
    last_seen = (_timestamp(sensor.get("lastPylumUpdateTimestampMs"), ctx["now"]) or
                 _timestamp(sensor.get("lastPylumInfoMsgUpdateTime"), ctx["now"]))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(ctx, sensors):
    """Convert one page of sensor records into runZero assets."""
    assets = []
    for sensor in sensors:
        if type(sensor) != "dict":
            print("cybereason: skipping non-object sensor record")
            continue
        if not _clean(sensor.get("sensorId")):
            # The machine name is not logged: it is operator-visible personal
            # data on a laptop fleet, and the opaque graph guid identifies the
            # record just as well.
            print("cybereason: skipping sensor with no sensorId: guid=" +
                  _clean(sensor.get("guid")))
            continue
        assets.append(build_asset(ctx, sensor))
    return assets


def login(ctx):
    """Log in with the form login and capture the session cookie.

    Cybereason answers /login.html with a redirect rather than a body, and the
    JSESSIONID cookie is set on that redirect. The HTTP client follows
    redirects and carries no cookie jar, so reading Set-Cookie off the response
    returns the *unauthenticated* cookie the login page sets on the last hop.
    A requests.Session has a real cookie jar, follows the chain with the cookie
    attached, and ends up holding the authenticated session, so the login runs
    there and every later call replays the cookie as a plain header.
    """
    session = Session(insecure_skip_verify=ctx["insecure"])
    # The connection options collected from CONFIG carry the configured
    # User-Agent, which the login has to send too.
    headers = dict(ctx["base_options"].get("headers", {}))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    body = url_encode({"username": ctx["username"], "password": ctx["password"]})
    resp = session.post(ctx["base_url"] + LOGIN_PATH, headers=headers, body=bytes(body))
    if resp == None:
        print("cybereason: no response from the login endpoint")
        return False
    if resp.status_code >= 400:
        print("cybereason: login failed with status {}".format(resp.status_code))
        return False

    token = ""
    cookies = session.cookies.get(ctx["base_url"])
    for cookie in cookies if type(cookies) == "list" else []:
        if cookie.name == SESSION_COOKIE:
            token = cookie.value
    if not token:
        print("cybereason: the login response set no {} cookie".format(SESSION_COOKIE))
        return False

    headers = dict(ctx["base_options"].get("headers", {}))
    headers["Cookie"] = "{}={}".format(SESSION_COOKIE, token)
    # Cybereason's own client closes the connection after every call; the
    # console is fronted by a load balancer that does not always honor
    # keep-alive on the REST paths.
    headers["Connection"] = "close"
    http_options = dict(ctx["base_options"])
    http_options["headers"] = headers
    ctx["http_options"] = http_options
    ctx["session_expires"] = (now().unix + SESSION_LIFETIME_SECONDS -
                              SESSION_REFRESH_MARGIN_SECONDS)
    return True


def _auth_failure(err):
    """Report whether a request error means the session is no longer good.

    An expired Cybereason session does not answer 401 on the REST paths: it
    redirects to the login page, which returns 200 with an HTML body. That
    surfaces here as a JSON decode failure on a 200, which is a far more
    reliable signal than the redirect-URL sniff Cybereason's own clients use,
    because the response struct exposes no final URL to sniff.
    """
    if err.startswith("status 401") or err.startswith("status 403"):
        return True
    return err.startswith("status 200") and "invalid JSON" in err


def _post(ctx, path, payload):
    """POST one JSON request, refreshing the session when it has aged out and
    retrying once when the answer shows it expired early. Returns (data, err)."""
    if now().unix >= ctx["session_expires"]:
        print("cybereason: session lifetime reached, logging in again")
        if not login(ctx):
            return None, "login failed"

    for attempt in range(2):
        data, err = post_json(ctx["base_url"] + path, json=payload, **ctx["http_options"])
        if not err:
            return data or {}, None
        if _auth_failure(err):
            if attempt == 0:
                print("cybereason: session rejected, logging in again")
                if not login(ctx):
                    return None, err
                continue
            # A wrong password still produces a session cookie, because the
            # form login answers with a redirect either way, so bad credentials
            # only surface here. Say so rather than passing on the JSON decode
            # error that the returned login page produces.
            return None, "authentication rejected, check the username and password"
        return None, err
    return None, "request failed"


def fetch_connections(ctx, machine_name):
    """Fetch the connections the investigation graph holds for one machine.

    This is one request per sensor, which is why it is optional and capped. A
    failure is logged and treated as no connections so a single unreadable
    machine cannot end the run.
    """
    if not machine_name:
        return []
    payload = {
        "customFields": CONNECTION_FIELDS,
        "perFeatureLimit": 100,
        "perGroupLimit": CONNECTION_RESULT_LIMIT,
        "queryPath": [
            {
                "requestedType": "Connection",
                "filters": [],
                "connectionFeature": {
                    "elementInstanceType": "Connection",
                    "featureName": "ownerMachine",
                },
                "isResult": True,
            },
            {
                "requestedType": "Machine",
                "filters": [{
                    "facetName": "elementDisplayName",
                    "values": [machine_name],
                    "filterType": "Equals",
                }],
            },
        ],
        "queryTimeout": CONNECTION_QUERY_TIMEOUT_MS,
        "templateContext": "SPECIFIC",
        "totalResultLimit": CONNECTION_RESULT_LIMIT,
    }
    data, err = _post(ctx, VISUALSEARCH_PATH, payload)
    if err:
        print("cybereason: failed to fetch connections for a sensor: {}".format(err))
        return []
    if type(data) != "dict":
        return []
    payload_data = data.get("data")
    if type(payload_data) != "dict":
        return []
    elements = payload_data.get("resultIdToElementDataMap")
    if type(elements) != "dict":
        return []
    return [elements[key] for key in elements]


def fetch_and_report_sensors(ctx):
    """Fetch and stream sensors one page at a time so the whole fleet is never
    held in memory at once."""
    reported = 0
    offset = 0
    total = -1
    previous = ""
    _pager = pager("cybereason")
    while _pager.next():
        data, err = _post(ctx, SENSORS_PATH,
                          {"filters": [], "limit": ctx["page_size"], "offset": offset})
        if err:
            print("cybereason: failed to fetch sensors at offset {}: {}".format(offset, err))
            return reported
        if type(data) != "dict":
            print("cybereason: stopping: unexpected response shape at offset", offset)
            return reported
        sensors = data.get("sensors")
        if type(sensors) != "list":
            print("cybereason: stopping: no sensor list at offset", offset)
            return reported
        if not sensors:
            break

        if total < 0:
            total = _to_int(data.get("totalResults"))
            if total > 0:
                print("cybereason: {} sensors reported by the tenant".format(total))

        # A deployment that ignored the offset would serve the same first record
        # forever; a repeated leading id ends the run instead.
        marker = _clean(sensors[0].get("sensorId")) if type(sensors[0]) == "dict" else ""
        if marker and marker == previous:
            print("cybereason: the tenant repeated the page at offset {}, stopping".format(offset))
            break
        previous = marker

        reported += report_assets(build_assets(ctx, sensors))

        # hasMoreResults is the tenant's own statement about paging; the page
        # length is only the fallback for a release that omits it.
        if data.get("hasMoreResults") == False:
            break
        if len(sensors) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    print("cybereason: reported {} sensors from {}".format(reported, ctx["host"]))
    return reported


def main(**kwargs):
    require(kwargs, "url", "username", "password")
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    host = parsed.hostname if parsed else ""
    if not host:
        print("cybereason: could not determine the tenant host from the configured URL")
        return None

    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE
    connection_limit = get_int(kwargs, "connection_limit", default=500)
    if connection_limit < 0:
        connection_limit = 0

    base_options = get_http_options(kwargs, headers={"Accept": "application/json"})
    ctx = {
        "base_options": base_options,
        "base_url": base_url,
        "host": host,
        "now": now(),
        "username": get_string(kwargs, "username"),
        "password": get_string(kwargs, "password"),
        # A requests.Session takes only this one TLS control, so a tenant using
        # a private CA or a client certificate cannot have those settings
        # applied to the login hop; see the README.
        "insecure": base_options.get("tls", {}).get("insecure", False) == True,
        "import_connections": get_bool(kwargs, "import_connections", default=False),
        "connection_limit": connection_limit,
        "page_size": page_size,
        "http_options": {},
        "session_expires": 0,
        "connection_used": 0,
        "connection_skipped": 0,
        "connections_seen": 0,
        "connections_inbound": 0,
        "connections_dropped": 0,
    }

    if not login(ctx):
        return None

    reported = fetch_and_report_sensors(ctx)
    if ctx["import_connections"]:
        print("cybereason: queried {} sensors for connections: {} connections, {} inbound, {} not attributable to the endpoint".format(
            ctx["connection_used"], ctx["connections_seen"], ctx["connections_inbound"],
            ctx["connections_dropped"]))
        if ctx["connection_skipped"]:
            print("cybereason: connection enrichment capped at {}, {} sensors imported without services".format(
                ctx["connection_limit"], ctx["connection_skipped"]))
    if not reported:
        print("cybereason: no assets retrieved")
    return None

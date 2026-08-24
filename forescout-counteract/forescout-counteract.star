# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-forescout-counteract",
    "name": "Forescout CounterACT",
    "type": "inbound",
    "description": "Imports endpoints, classification properties, open port services, installed software, and CVE findings from Forescout CounterACT.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The CounterACT object id is derived from the endpoint's IPv4 address,
    # so it identifies an address rather than a device: it changes when the
    # host is re-addressed and is handed to whatever device takes the
    # address over. It is kept as a stable, namespaced record key but must
    # not drive or block merging, which falls back to MAC, IP, and name.
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Enterprise Manager URL",
            "type": "url",
            "required": True,
            "placeholder": "https://enterprise-manager.example.com",
            "description": "Base URL of the Forescout Enterprise Manager or standalone Appliance. The /api/ paths are appended automatically.",
        },
        {
            "key": "username",
            "label": "Web API username",
            "type": "string",
            "required": True,
            "description": "Web API user created under Tools > Options > Web API > User Settings. This is not a console operator account.",
        },
        {
            "key": "password",
            "label": "Web API password",
            "type": "secret",
            "required": True,
            "description": "Password for the Web API user.",
        },
        {
            "key": "match_rule_ids",
            "label": "Policy or rule IDs",
            "type": "string",
            "required": False,
            "description": "Optional comma-separated Forescout policy or sub-rule IDs. Only hosts selected by all of them are imported. Use this to scope a large Enterprise Manager.",
        },
        {
            "key": "host_filter",
            "label": "Host property filter",
            "type": "string",
            "required": False,
            "placeholder": "online=true&onsite=true",
            "description": "Optional host field filter in the Web API's own format, for example online=true. Appended to the host index query verbatim.",
        },
        {
            "key": "include_details",
            "label": "Import classification, services, and software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch the per-host property document. Costs one extra request per host; disable it to import the IP and MAC index only.",
        },
        {
            "key": "detail_limit",
            "label": "Detail enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of hosts to enrich with properties. Hosts past the limit are still imported from the index, with only their IP and MAC. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac', 'routable_ip', 'clean_hostnames')
load('http', 'get_json', http_post='post', 'url_encode', 'url_parse')
load('json', json_encode='encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('re', re_find_all='find_all')
load('time', 'now', 'sleep')

load('coerce', 'as_text', 'dedupe')
VENDOR = "forescout-counteract"
ATTR_PREFIX = "forescout_counteract"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
LOGIN_PATH = "/api/login"
HOSTS_PATH = "/api/hosts"
HOSTFIELDS_PATH = "/api/hostfields"
CHUNK_SIZE = 100         # assets built and streamed per report_assets call
MAX_CHILDREN = 99
MAX_INTERFACES = 32
MAX_FIELDS = 64          # properties requested per host, to keep the query string sane
MAX_DISCOVERED = 8       # discovered software / CVE properties requested per host
DEFAULT_TRANSPORT = "tcp"
DIGITS = "0123456789"
TRANSPORTS = ["tcp", "udp", "sctp"]
FIELD_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
CVE_PATTERN = r"CVE-[0-9]{4}-[0-9]{4,19}"

# The Web API mints a JWT whose default validity is five minutes, so the token is
# refreshed well inside that window rather than waiting for the first 401.
TOKEN_TTL_SECONDS = 240

# The login POST stays a raw http_post (the token comes back as a bare body, not
# JSON), and the raw builtin has no retries kwarg, so transient failures are
# retried by hand. Only statuses that mean the request was rejected unprocessed
# are retried, matching what get_json retries elsewhere in the run.
LOGIN_ATTEMPTS = 4
LOGIN_RETRY_STATUSES = [408, 425, 429, 500, 502, 503, 504]

EXCLUDED_MACS = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]

# Host properties this integration knows how to map, requested only when
# GET /api/hostfields reports the deployment actually exposes them. Plugins add
# and remove properties, so no name here is assumed to exist.
HOSTNAME_FIELDS = [
    "hostname", "nbthost", "dhcp_hostname", "linux_hostname", "mac_hostname",
    "vmware_guest_host", "aws_instance_public_dns",
]
DOMAIN_FIELDS = ["nbtdomain"]
PORT_FIELDS = ["openports"]
# The classification engine is the reason to import CounterACT at all: these are
# the properties its profiling produces.
CLASSIFICATION_FIELDS = [
    "os_classification", "prim_classification", "vendor_classification",
    "classification_source_os", "classification_source_func", "cl_type", "cl_rule",
    "mac_vendor_string", "vendor", "dhcp_class", "dhcp_os", "user_def_fp",
    "fingerprint", "matched_fingerprints", "nmap_def_fp7", "nmap_def_fp5",
    "nmap_netfunc7", "va_netfunc", "dhcp_req_fingerprint", "dhcp_opt_fingerprint",
]
STATE_FIELDS = [
    "online", "onsite", "engine_seen_packet", "manage_agent", "agent_version",
    "agent_install_mode", "agent_visible_mode", "gst_signed_in_stat", "adm", "misc",
    "access_ip", "macs", "mac_prefix32", "ipv4_report_time", "last_nbt_report_time",
    "switch_port_name", "sw_hostname",
]
# Substrings used to discover installed-software and vulnerability properties,
# whose names differ between deployments depending on the plugins installed.
SOFTWARE_FIELD_HINTS = ["application", "installed_program", "installed_software", "packages"]
VULN_FIELD_HINTS = ["cve", "vulnerab"]

# Forescout's Function classification, mapped onto the device type vocabulary
# runZero already uses. Unmapped values survive verbatim, so a deployment with a
# custom classification tree still gets a device type.
DEVICE_TYPES = {
    "desktop": "Desktop",
    "workstation": "Desktop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "server": "Server",
    "thin client": "Thin Client",
    "printer": "Printer",
    "multifunction printer": "Printer",
    "scanner": "Scanner",
    "ip camera": "IP Camera",
    "camera": "IP Camera",
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "access point": "Wireless Access Point",
    "wireless access point": "Wireless Access Point",
    "wireless controller": "Wireless Controller",
    "network device": "Network Device",
    "voip": "VoIP Phone",
    "voip phone": "VoIP Phone",
    "ip phone": "VoIP Phone",
    "mobile": "Mobile Device",
    "smartphone": "Mobile Device",
    "tablet": "Mobile Device",
    "hypervisor": "Hypervisor",
    "virtual machine": "Virtual Machine",
    "storage": "Storage",
    "nas": "Storage",
    "ups": "UPS",
    "game console": "Game Console",
    "smart tv": "TV",
    "medical device": "Medical Device",
    "plc": "Industrial Control System",
    "rtu": "Industrial Control System",
    "hmi": "Industrial Control System",
    "industrial device": "Industrial Control System",
}
def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is not numeric."""
    if type(value) == "int":
        return value
    text = str(value).strip()
    if not text or len(text) > 10:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)
def _usable_mac(value):
    """Return the canonical form of a MAC that is a real merge signal, or None.
    CounterACT emits 000000000000 for hosts it has never resolved a MAC for."""
    if not value:
        return None
    mac = normalize_mac(str(value).strip())
    if mac == None or mac in EXCLUDED_MACS:
        return None
    return mac

def _leaf(value):
    """Return the most specific segment of a Forescout tree-path classification
    value. The classification properties are typed tree_path and serialize as
    "Computer/Windows Machine/Desktop", so the leaf is the specific answer."""
    text = as_text(value, join=",").strip()
    if "/" not in text:
        return text
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if not parts:
        return ""
    return parts[-1]

def _root(value):
    """Return the least specific segment of a tree-path classification value."""
    text = as_text(value, join=",").strip()
    if "/" not in text:
        return text
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if not parts:
        return ""
    return parts[0]

def _values(fields, name):
    """Read one host property out of the per-host document. The Web API wraps
    every property value as {"value": ...} and repeats it in a list when the
    property is multi-valued, so both shapes are unwrapped to a plain list.
    Anything else is passed through rather than dropped."""
    if type(fields) != "dict":
        return []
    entry = fields.get(name)
    if entry == None:
        return []
    if type(entry) == "dict":
        if "value" in entry:
            value = entry.get("value")
            return [] if value == None else [value]
        return [entry]
    if type(entry) == "list":
        out = []
        for item in entry:
            if type(item) == "dict" and "value" in item:
                value = item.get("value")
                if value != None:
                    out.append(value)
            elif item != None:
                out.append(item)
        return out
    return [entry]

def _value(fields, name):
    """Read one host property as a single trimmed string."""
    values = _values(fields, name)
    if not values:
        return ""
    return as_text(values[0], join=",").strip()

def _is_true(fields, name):
    """Read a boolean host property. The Web API serializes these as strings."""
    return _value(fields, name).lower() in ("true", "yes", "1")

def _safe_field(name):
    """Return a property name that is safe to append to a query string, or an
    empty string. Property names are discovered from the deployment, so they are
    screened rather than trusted."""
    text = as_text(name, join=",").strip()
    if not text or len(text) > 128:
        return ""
    for index in range(len(text)):
        if text[index] not in FIELD_NAME_CHARS:
            return ""
    return text

def _extract_cves(values):
    """Pull CVE identifiers out of arbitrary property values. Identifiers are
    upper-cased before matching because Vulnerability.cve is validated against a
    strict upper-case pattern and a lower-case value fails the whole record."""
    text = ""
    for value in values:
        if type(value) == "string":
            text += " " + value
        else:
            text += " " + json_encode(value)
    if not text.strip():
        return []
    return dedupe(re_find_all(CVE_PATTERN, text.upper()))

def _parse_open_port(entry):
    """Extract (port, transport) from one openports entry. Transport is an empty
    string when the entry does not name one."""
    if type(entry) == "dict":
        port = _to_int(entry.get("port", entry.get("number", -1)))
        transport = ""
        for key in ("transport", "protocol", "proto", "l4_proto"):
            named = entry.get(key)
            if named:
                transport = str(named).strip().lower()
                break
        if transport not in TRANSPORTS:
            transport = ""
        return port, transport

    if type(entry) == "int":
        return entry, ""

    text = str(entry).lower()
    for separator in ("/", ":", "(", ")", ",", ";", "\t"):
        text = text.replace(separator, " ")
    port = -1
    transport = ""
    for token in text.split(" "):
        if not token:
            continue
        if token in TRANSPORTS:
            if not transport:
                transport = token
            continue
        if port < 0:
            candidate = _to_int(token)
            if candidate >= 0:
                port = candidate
    return port, transport

def _split_product_version(text):
    """Split an application string such as "7-Zip 23.01" into (product,
    version). Only a trailing token that starts with a digit is treated as a
    version; everything else stays in the product name."""
    parts = text.split(" ")
    if len(parts) < 2:
        return text, ""
    tail = parts[-1]
    if tail and tail[0] in DIGITS:
        return " ".join(parts[:-1]).strip(), tail.strip()
    return text, ""

def login(ctx):
    """Exchange the Web API credentials for a JWT and install it on the shared
    request headers. The token is returned as the plain-text response body, not
    as JSON and not in a response header, so this is a raw http.post: get_json
    would try to decode a bare JWT as a document."""
    # The shared options carry the configured User-Agent and TLS settings, so
    # the login request reuses them with its own content type and without the
    # Authorization header it is about to replace.
    headers = dict(ctx["headers"])
    headers.pop("Authorization", None)
    headers.pop("Accept", None)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    options = dict(ctx["http_options"])
    options["headers"] = headers

    body = url_encode({"username": ctx["username"], "password": ctx["password"]})
    resp = None
    for attempt in range(LOGIN_ATTEMPTS):
        if attempt:
            sleep("{}s".format(attempt))
        resp = http_post(ctx["base_url"] + LOGIN_PATH, body=bytes(body), **options)
        if resp != None and resp.status_code not in LOGIN_RETRY_STATUSES:
            break
        print("forescout-counteract: transient Web API login failure (attempt {} of {}): {}".format(
            attempt + 1, LOGIN_ATTEMPTS, resp.status_code if resp != None else "no response"))
    if resp == None:
        print("forescout-counteract: no response from the Web API login endpoint")
        return False
    if resp.status_code != 200:
        print("forescout-counteract: Web API login failed with status {}".format(resp.status_code))
        return False

    token = as_text(resp.body, join=",").strip()
    # A JWT is three dot-separated segments. Anything else is an error page that
    # must not be installed as a credential.
    if len(token) < 16 or token.count(".") != 2:
        print("forescout-counteract: Web API login returned an unexpected body instead of a token")
        return False

    ctx["headers"]["Authorization"] = token
    ctx["token_at"] = now()
    return True

def api_get(ctx, url, label):
    """GET one Web API resource, refreshing the JWT before it expires and once
    more if the Enterprise Manager rejects it anyway. Returns (data, err)."""
    if ctx["token_at"] == None or (now() - ctx["token_at"]).seconds >= TOKEN_TTL_SECONDS:
        if not login(ctx):
            return None, "login failed"

    data, err = get_json(url, **ctx["http_options"])
    if err and err.startswith("status 401"):
        # The token expired earlier than its advertised validity, or the
        # Enterprise Manager was restarted. Re-authenticate once and retry.
        print("forescout-counteract: re-authenticating after a rejected token while fetching {}".format(label))
        if not login(ctx):
            return None, err
        data, err = get_json(url, **ctx["http_options"])
    return data, err

def build_field_list(ctx):
    """Ask the Enterprise Manager which host properties it exposes and build the
    fields= list from the intersection with what this integration can map.
    Property sets vary per deployment because every plugin contributes its own,
    so nothing is requested that the deployment has not advertised."""
    data, err = api_get(ctx, ctx["base_url"] + HOSTFIELDS_PATH, "host fields")
    if err:
        print("forescout-counteract: failed to fetch the host field index, importing the IP and MAC index only:", err)
        return

    data = data or {}
    entries = data.get("hostFields", []) if type(data) == "dict" else []
    if type(entries) != "list":
        entries = []

    available = []
    for entry in entries:
        if type(entry) != "dict":
            continue
        name = _safe_field(entry.get("name"))
        if name:
            available.append(name)
    if not available:
        print("forescout-counteract: the host field index named no host properties, importing the IP and MAC index only")
        return

    known = HOSTNAME_FIELDS + DOMAIN_FIELDS + CLASSIFICATION_FIELDS + STATE_FIELDS + PORT_FIELDS
    wanted = [name for name in known if name in available]

    # Installed-software and vulnerability property names are plugin-specific,
    # so they are discovered from the index rather than assumed.
    software = []
    vulns = []
    for name in available:
        lowered = name.lower()
        for hint in SOFTWARE_FIELD_HINTS:
            if hint in lowered and name not in software and len(software) < MAX_DISCOVERED:
                software.append(name)
        for hint in VULN_FIELD_HINTS:
            if hint in lowered and name not in vulns and len(vulns) < MAX_DISCOVERED:
                vulns.append(name)

    ctx["software_fields"] = software
    ctx["vuln_fields"] = vulns
    ctx["fields"] = dedupe(wanted + software + vulns)[:MAX_FIELDS]
    if not ctx["fields"]:
        print("forescout-counteract: none of the {} host properties this deployment exposes are mappable, importing the IP and MAC index only".format(len(available)))
        return
    print("forescout-counteract: the deployment exposes {} host properties, requesting {} per host ({} software, {} vulnerability)".format(
        len(available), len(ctx["fields"]), len(software), len(vulns)))

def fetch_host_detail(ctx, host_id):
    """Fetch the property document for one host. A failure is reported and
    treated as an empty document so a single unreadable host cannot end the run.
    The fields list is appended verbatim rather than passed as params so the
    comma separators reach the Enterprise Manager unencoded."""
    url = ctx["base_url"] + HOSTS_PATH + "/" + str(host_id)
    if ctx["fields"]:
        url += "?fields=" + ",".join(ctx["fields"])

    data, err = api_get(ctx, url, "host {}".format(host_id))
    if err:
        print("forescout-counteract: failed to fetch properties for host {}: {}".format(host_id, err))
        return {}
    data = data or {}
    if type(data) != "dict":
        return {}
    host = data.get("host", {})
    if type(host) != "dict":
        return {}
    return host

def build_vulnerabilities(ctx, host_id, fields):
    """Convert any CVE identifier the deployment records against a host into a
    finding. CounterACT only carries these when a vulnerability assessment
    plugin is installed, and it publishes no CVSS score alongside them, so the
    findings deliberately carry no severity or risk rank of their own."""
    vulns = []
    seen = []
    for name in ctx["vuln_fields"]:
        for cve in _extract_cves(_values(fields, name)):
            if cve in seen:
                continue
            seen.append(cve)
            vulns.append(Vulnerability(
                id="{}:{}:{}:cve:{}".format(VENDOR, ctx["scope"], host_id, cve),
                name=cve,
                cve=cve,
                category="CVE",
                customAttributes=to_custom_attributes({
                    "cve": cve,
                    "cve_source_property": name,
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            ))
    return vulns

def build_software(ctx, host_id, address, fields):
    """Convert the installed-application properties into Software records. The
    property names are discovered per deployment and their element shape is not
    published, so dicts, "Product Version" strings, and bare names are all
    accepted. CounterACT emits no CPE, so cpe23 is left unset rather than
    synthesized."""
    software = []
    seen = []
    for name in ctx["software_fields"]:
        for entry in _values(fields, name):
            vendor = ""
            version = ""
            raw = ""
            if type(entry) == "dict":
                product = ""
                for key in ("name", "product", "display_name", "application", "title"):
                    product = as_text(entry.get(key), join=",").strip()
                    if product:
                        break
                for key in ("version", "display_version", "product_version"):
                    version = as_text(entry.get(key), join=",").strip()
                    if version:
                        break
                for key in ("vendor", "publisher", "manufacturer"):
                    vendor = as_text(entry.get(key), join=",").strip()
                    if vendor:
                        break
                if not version:
                    product, version = _split_product_version(product)
            else:
                raw = as_text(entry, join=",").strip()
                if not raw:
                    continue
                product, version = _split_product_version(raw)

            if not product:
                continue
            key = product + "|" + version
            if key in seen:
                continue
            seen.append(key)

            params = {
                "id": "{}:{}:{}:software:{}".format(VENDOR, ctx["scope"], host_id, key),
                "product": product,
                "serviceAddress": address or "127.0.0.1",
                "customAttributes": to_custom_attributes({
                    "software_source_property": name,
                    "software_raw": raw,
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            }
            if vendor:
                params["vendor"] = vendor
            if version:
                params["version"] = version
            software.append(Software(**params))
    return software

def build_services(ctx, address, fields):
    """Build Service objects from the host open-port properties. Only concrete
    port numbers become services: the classification properties name an OS or a
    function without a port and are never turned into one. Entries that name no
    transport are recorded as tcp and flagged."""
    if not address:
        return []

    services = []
    seen = []
    for name in PORT_FIELDS:
        for entry in _values(fields, name):
            port, transport = _parse_open_port(entry)
            if port < 1 or port > 65535:
                continue
            assumed = transport == ""
            if assumed:
                transport = DEFAULT_TRANSPORT
            key = "{}/{}".format(port, transport)
            if key in seen:
                continue
            seen.append(key)
            services.append(Service(
                address=address,
                port=int(port),
                transport=transport,
                customAttributes=to_custom_attributes({
                    "service_source": name,
                    "transport_source": "assumed" if assumed else "reported",
                }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            ))
    return services

def build_asset(ctx, record):
    """Convert one CounterACT host index row into a runZero asset, optionally
    enriched with the per-host property document. Returns None when the host
    carries no address, MAC, or name, because the host id cannot be used as a
    merge key and such a record has nothing to correlate on."""
    host_id = record.get("hostId")

    fields = {}
    enriched = False
    if ctx["fields"]:
        if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        else:
            ctx["detail_used"] += 1
            enriched = True
            detail = fetch_host_detail(ctx, host_id)
            candidate = detail.get("fields", {})
            if type(candidate) == "dict":
                fields = candidate

    index_ip = as_text(record.get("ip"), join=",").strip()
    address = routable_ip(index_ip)
    macs = []
    index_mac = _usable_mac(record.get("mac"))
    if index_mac:
        macs.append(index_mac)
    for value in _values(fields, "macs"):
        mac = _usable_mac(value)
        if mac and mac not in macs:
            macs.append(mac)

    netifs = []
    if macs:
        for index in range(len(macs[:MAX_INTERFACES])):
            ips = [address] if (index == 0 and address) else []
            nic = network_interface(mac=macs[index], ips=ips)
            if nic:
                netifs.append(nic)
    elif address:
        nic = network_interface(ips=[address])
        if nic:
            netifs.append(nic)

    # NBT/DHCP-derived names carry placeholders ("UNKNOWN", bare IPs) that every
    # unresolved host shares, so they are screened before import: one shared
    # name across an estate is a merge hazard, not an identity.
    hostnames = clean_hostnames([_value(fields, name) for name in HOSTNAME_FIELDS])

    if not netifs and not hostnames:
        print("forescout-counteract: skipping host {} with no address, MAC, or name to correlate on".format(host_id))
        return None

    os_class = _value(fields, "os_classification")
    function = _value(fields, "prim_classification")
    vendor_class = _value(fields, "vendor_classification")
    nic_vendor = _value(fields, "mac_vendor_string")

    tags = [VENDOR, "nac"]
    leaf_function = _leaf(function)
    if leaf_function:
        tags.append("function:" + leaf_function)
    if vendor_class:
        tags.append("vendor-model:" + _leaf(vendor_class))
    cl_type = _value(fields, "cl_type")
    if cl_type:
        tags.append("classified-by:" + cl_type)
    if _is_true(fields, "online"):
        tags.append("online")
    if _is_true(fields, "onsite"):
        tags.append("onsite")
    if _is_true(fields, "manage_agent"):
        tags.append("secureconnector")

    services = build_services(ctx, address, fields)
    software = build_software(ctx, host_id, address, fields)
    vulns = build_vulnerabilities(ctx, host_id, fields)

    attrs = {
        "host_id": host_id,
        "enterprise_manager": ctx["scope"],
        "index_ip": index_ip,
        "index_mac": as_text(record.get("mac"), join=","),
        "mac_addresses": macs,
        "detail_enriched": "true" if enriched else "false",
    }
    for name in CLASSIFICATION_FIELDS + STATE_FIELDS + DOMAIN_FIELDS + PORT_FIELDS:
        values = _values(fields, name)
        if values:
            attrs[name] = values if len(values) > 1 else values[0]
    if enriched:
        attrs["service_count"] = len(services)
        attrs["software_count"] = len(software)
        attrs["vulnerability_count"] = len(vulns)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], host_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "services": services[:MAX_CHILDREN],
        "software": software[:MAX_CHILDREN],
        "vulnerabilities": vulns[:MAX_CHILDREN],    }

    leaf_os = _leaf(os_class)
    if leaf_os:
        params["os"] = leaf_os
    if leaf_function:
        params["deviceType"] = DEVICE_TYPES.get(leaf_function.lower(), leaf_function)
    # The Vendor and Model classification is a tree whose root is the vendor and
    # whose leaf is the model. A deployment that publishes it as a flat string
    # yields a manufacturer and no model, which is why the leaf is only used
    # when the value actually has more than one segment.
    manufacturer = _root(vendor_class) or nic_vendor
    if manufacturer:
        params["manufacturer"] = manufacturer
    if vendor_class and "/" in vendor_class:
        params["model"] = _leaf(vendor_class)
    domain = _value(fields, "nbtdomain")
    if domain:
        params["domain"] = domain

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)

def build_assets(ctx, records):
    """Convert a chunk of CounterACT host index rows into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        host_id = record.get("hostId")
        if host_id == None or str(host_id).strip() == "":
            print("forescout-counteract: skipping host with no object id: ip=" + as_text(record.get("ip"), join=","))
            continue
        key = str(host_id)
        if key in ctx["seen"]:
            continue
        ctx["seen"][key] = True
        asset = build_asset(ctx, record)
        if asset:
            assets.append(asset)
    return assets

def fetch_and_report_hosts(ctx):
    """Fetch the host index and stream it in chunks. The Web API publishes no
    pagination for GET /api/hosts — it answers with the whole index in one
    response — so the request cannot be split; assets are still built and
    reported a chunk at a time so the ImportAsset set never accumulates."""
    url = ctx["base_url"] + HOSTS_PATH
    query = []
    if ctx["match_rule_ids"]:
        query.append("matchRuleId=" + ctx["match_rule_ids"])
    if ctx["host_filter"]:
        query.append(ctx["host_filter"])
    if query:
        url += "?" + "&".join(query)

    data, err = api_get(ctx, url, "the host index")
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("forescout-counteract: the Enterprise Manager rejected the Web API user:", err)
        else:
            print("forescout-counteract: failed to fetch the host index:", err)
        return 0

    data = data or {}
    hosts = data.get("hosts", []) if type(data) == "dict" else []
    if type(hosts) != "list":
        hosts = []
    total = len(hosts)
    if not total:
        return 0
    print("forescout-counteract: the host index returned {} hosts".format(total))

    reported = 0
    for start in range(0, total, CHUNK_SIZE):
        reported += report_assets(build_assets(ctx, hosts[start:start + CHUNK_SIZE]))

    print("forescout-counteract: reported {} assets".format(reported))
    if ctx["detail_skipped"]:
        print("forescout-counteract: detail limit of {} reached; classification, services, and software were not imported for {} of {} hosts".format(
            ctx["detail_limit"], ctx["detail_skipped"], reported))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("forescout-counteract: could not determine the Enterprise Manager host from the configured URL")
        return None

    http_options = get_http_options(kwargs, headers={"Accept": "application/hal+json"})
    # The JWT is installed on the collected headers dict in place, so every
    # later request picks up the current token without rebuilding the option
    # set. The dict has to be the one get_http_options returned, because that is
    # the one carrying the configured User-Agent.
    headers = http_options.get("headers", {})

    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "username": get_string(kwargs, "username"),
        "password": get_string(kwargs, "password"),
        "headers": headers,
        "http_options": http_options,
        "match_rule_ids": get_string(kwargs, "match_rule_ids", default="").strip(),
        "host_filter": get_string(kwargs, "host_filter", default="").strip(),
        "include_details": get_bool(kwargs, "include_details", default=True),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "fields": [],
        "software_fields": [],
        "vuln_fields": [],
        "seen": {},
        "token_at": None,
    }

    if not login(ctx):
        return None

    if ctx["include_details"]:
        build_field_list(ctx)

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("forescout-counteract: no assets retrieved")
    return None

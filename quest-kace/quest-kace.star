# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-quest-kace",
    "name": "Quest KACE SMA",
    "type": "inbound",
    "description": "Imports managed devices, hardware inventory, and installed software from a Quest KACE Systems Management Appliance.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The machine id is authoritative within the appliance and organization,
    # while KACE only reports one primary MAC and one primary IP per device,
    # both of which churn with DHCP and docking stations.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "KACE SMA URL",
            "type": "url",
            "required": True,
            "placeholder": "https://kace.example.com",
            "description": "Base URL of the KACE Systems Management Appliance. The /api and /ams paths are appended automatically.",
        },
        {
            "key": "organization",
            "label": "Organization name",
            "type": "string",
            "required": False,
            "description": "Organization to log into on a multi-org appliance, for example Default. Leave blank to use the account's default organization.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "KACE SMA user with the Administrator or Read-only administrator role.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for the KACE SMA user. Accounts with two-factor authentication enabled cannot be used.",
        },
        {
            "key": "import_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request the software sub-entity alongside each machine. Adds the installed software list to every asset and makes each page considerably larger.",
        },
        {
            "key": "import_assets",
            "label": "Enrich from the asset CMDB",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /api/asset/assets and attach the matching CMDB record (owner, status, asset type, custom fields) to each machine.",
        },
        {
            "key": "page_size",
            "label": "Records per page",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Records requested per API call. The appliance defaults to 50 when no paging is requested.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'routable_ip')
load('http', http_post='post', 'get_json', 'url_encode', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('json', json_encode='encode')
load('time', 'now', 'parse_ts')

load('coerce', 'as_text')
VENDOR = "quest-kace"
ATTR_PREFIX = "quest_kace"
ATTR_SEPARATOR = "_"        # to_custom_attributes joins the prefix with the separator

LOGIN_PATH = "/ams/shared/api/security/login"
MACHINES_PATH = "/api/inventory/machines"
ASSETS_PATH = "/api/asset/assets"

# The appliance dropped the x-kace-csrf-token requirement in 12.1 and now only
# needs a version header, but 12.0 and older still reject an unversioned request
# and issue the token in the Dell-branded header. Both spellings are sent so one
# script covers both generations; the appliance ignores the one it does not know.
API_VERSION = "5"
VERSION_HEADERS = ["x-dell-api-version", "x-kace-api-version"]
CSRF_HEADERS = ["x-dell-csrf-token", "x-kace-csrf-token"]

# Go canonicalizes response header names, so a lookup has to use that spelling.
# Every value is a list, never a string.
CSRF_RESPONSE_HEADERS = ["X-Dell-Csrf-Token", "X-Kace-Csrf-Token"]
SET_COOKIE_HEADER = "Set-Cookie"

# Session cookies the appliance sets at login. All five are replayed on every
# later request; the CSRF token is also read out of KACE_CSRF_TOKEN when the
# appliance does not return it as a response header.
CSRF_COOKIE = "KACE_CSRF_TOKEN"
ORG_COOKIE = "KACE_LAST_ORG_SECURE"

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
MAX_CHILDREN = 99
MAX_ASSET_INDEX = 50000
HTTP_RETRIES = 3

DIGITS = "0123456789"
# The zeroed MySQL datetime KACE writes for a value it never recorded.
NULL_TIMESTAMP = "0000-00-00 00:00:00"

# Hostnames that identify nothing; a shared placeholder merges unrelated assets.
PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none",
                     "null", "-", "n/a", "*"]
# Chassis_Type carries the SMBIOS chassis description. Only the values with a
# faithful runZero equivalent are mapped; anything else survives as the
# quest_kace_chassis_type custom attribute.
DEVICE_TYPES = {
    "desktop": "Desktop",
    "low profile desktop": "Desktop",
    "tower": "Desktop",
    "mini tower": "Desktop",
    "space-saving": "Desktop",
    "all in one": "Desktop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "sub notebook": "Laptop",
    "portable": "Laptop",
    "convertible": "Laptop",
    "detachable": "Laptop",
    "rack mount chassis": "Server",
    "main server chassis": "Server",
    "blade": "Server",
    "blade enclosure": "Server",
    "tablet": "Tablet",
    "hand held": "Mobile Device",
    "handheld": "Mobile Device",
}

# Fields copied verbatim onto every asset. The rest of the "machine all" payload
# (pagefile sizes, registry sizes, sound devices) is inventory trivia that would
# only crowd the attribute list.
MACHINE_ATTRS = [
    "asset_tag", "bios_description", "bios_identification_code", "bios_manufacturer",
    "bios_name", "bios_serial_number", "bios_version", "chassis_type", "client_version",
    "cpu_name", "created", "cs_domain", "cs_manufacturer", "cs_model", "csp_id_number",
    "custom_field_value0", "custom_field_value1", "custom_field_value2",
    "custom_field_value3", "custom_field_value4", "custom_field_value5",
    "domain", "ip", "ipv6", "kuid", "last_inventory", "last_reboot", "last_shutdown",
    "last_sync", "last_user", "mac", "manual_entry", "manufacturer_product_number",
    "modified", "netmask", "notes", "os_arch", "os_build", "os_family",
    "os_installed_date", "os_name", "os_number", "os_release", "os_version",
    "ownership", "physical_cores", "physical_processors", "ram_max", "ram_total",
    "ram_used", "service_pack", "sys_arch", "system_description", "uptime",
    "user", "user_domain", "user_fullname", "user_logged", "user_name", "virtual",
]

# CMDB columns worth attaching to the machine they are mapped to.
ASSET_ATTRS = [
    "id", "name", "asset_class_id", "asset_data_id", "asset_status_id", "asset_type_id",
    "asset_type_name", "archive", "created", "modified", "owner_id", "mapped_id",
    "location", "location_name", "owner_name", "asset_status_name",
]
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

def _fields(record):
    """Normalize one API record's keys to lower_snake_case.

    The appliance is not consistent about the casing of its own field names:
    the API guide documents the inventory Machine entity as Cs_Manufacturer and
    Bios_Serial_Number, live 10.x appliances answer with Os_name and
    Last_inventory, the asset API spells the same columns cs_manufacturer, and
    at least one field ("Ram Total") is separated by a space. Folding every key
    once means the mapping below can be written against a single spelling.
    """
    fields = {}
    for key in record:
        fields[str(key).strip().lower().replace(" ", "_")] = record[key]
    return fields

def _string(fields, name):
    """Read one normalized field as a trimmed string."""
    return as_text(fields.get(name), join=",").strip()

def _first(fields, names):
    """Read the first of several normalized fields that holds a value."""
    for name in names:
        value = _string(fields, name)
        if value:
            return value
    return ""

def _ts(value):
    """parse_ts with KACE's zeroed never-set MySQL datetime filtered first."""
    if as_text(value, join=",").strip() == NULL_TIMESTAMP:
        return None
    return parse_ts(value)

def _hostname(value):
    """Return a value fit to import as a hostname, or "".

    A machine name that is a placeholder or really an IP address is a merge
    hazard: every record carrying the same one would correlate to each other.
    """
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text

def _sub_records(value):
    """Coerce a sub-entity field documented as a list of objects into one,
    dropping any element that is not a dict so a scalar cannot abort the run."""
    if type(value) != "list":
        return []
    return [item for item in value if type(item) == "dict"]
def _query(pairs):
    """Encode a KACE query string.

    The query DSL is built out of spaces ("paging=offset 0 limit 100"), and
    url_encode emits "+" for a space. The substitution to %20 matches what the
    appliance's own documented examples send and is safe because a literal plus
    is already %2B by this point. The result is appended to the URL rather than
    passed as params= so nothing can re-encode it.
    """
    return url_encode(pairs).replace("+", "%20")

def _header_values(headers, name):
    """Read one response header as a list of values.

    Response headers are a dict of canonicalized name to a list of strings, so a
    lowercase lookup silently returns None and a caller expecting a string gets
    a list.
    """
    value = headers.get(name)
    if value == None:
        return []
    if type(value) == "list":
        return [str(item) for item in value]
    return [str(value)]

def parse_cookies(headers):
    """Assemble the session cookies out of the login response.

    The appliance sets five cookies (KACE_LAST_USER_SECURE, KACE_LAST_ORG_SECURE,
    kboxid, x-dell-auth-jwt, KACE_CSRF_TOKEN) and rejects any later request that
    does not replay all of them. Every Set-Cookie value is kept, not just those
    five, so a release that adds a sixth still works.
    """
    names = []
    values = {}
    for header in _header_values(headers, SET_COOKIE_HEADER):
        pair = header.split(";")[0].strip()
        if "=" not in pair:
            continue
        name = pair.split("=")[0].strip()
        value = pair[len(name) + 1:].strip()
        if not name:
            continue
        if name not in names:
            names.append(name)
        values[name] = value
    return names, values

def build_software(scope, machine_id, address, entries):
    """Convert the software sub-entity of one machine into Software records.

    The appliance publishes no CPE for an inventoried title, so cpe23 is left
    unset rather than synthesized: Software.cpe23 only accepts the CPE 2.2
    application URI binding and a wrong guess fails the whole record.

    A Software record that fails validation fails the asset carrying it, so the
    install time goes through _ts: the zeroed never-set sentinel is dropped and
    a future value is clamped by parse_ts.
    """
    software = []
    seen = {}
    for entry in entries:
        fields = _fields(entry)
        product = _first(fields, ["display_name", "name"])
        if not product:
            continue
        version = _first(fields, ["display_version", "version"])
        title_id = _string(fields, "id")
        key = title_id if title_id else "{}:{}".format(product, version)
        if key in seen:
            continue
        seen[key] = True

        params = {
            "id": "{}:{}:{}:software:{}".format(VENDOR, scope, machine_id, key)[:255],
            "product": product,
            # An inventoried title has no socket of its own.
            "serviceAddress": address if address else "127.0.0.1",
        }
        if version:
            params["version"] = version
        publisher = _string(fields, "publisher")
        if publisher:
            params["vendor"] = publisher
        installed_at = _ts(fields.get("install_date"))
        if installed_at:
            params["installedAt"] = installed_at
        params["customAttributes"] = to_custom_attributes({
            "title_id": title_id,
            "category": fields.get("category"),
            "is_patch": fields.get("is_patch"),
            "is_manual": fields.get("is_manual"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software

def build_asset(ctx, record):
    """Convert one KACE machine record into a runZero asset."""
    fields = _fields(record)
    machine_id = _string(fields, "id")

    ips = []
    for value in [fields.get("ip"), fields.get("ipv6")]:
        routable = routable_ip(value)
        if routable and routable not in ips:
            ips.append(routable)
    nic = network_interface(mac=_string(fields, "mac"), ips=ips)
    netifs = [nic] if nic else []
    address = ips[0] if ips else ""

    software = []
    if ctx["import_software"]:
        titles = _sub_records(fields.get("software")) + _sub_records(fields.get("softwares"))
        software = build_software(ctx["scope"], machine_id, address, titles)

    serial = _string(fields, "bios_serial_number")
    virtual = _string(fields, "virtual")
    tags = [VENDOR, "org:" + ctx["org"]]
    if serial:
        tags.append("serial:" + serial)
    if virtual and virtual.lower() not in ("0", "false", "no", "none"):
        tags.append("virtual")

    attrs = {"machine_id": machine_id, "appliance": ctx["host"], "organization": ctx["org"]}
    for name in MACHINE_ATTRS:
        if name in fields:
            attrs[name] = fields[name]
    if ctx["import_software"]:
        attrs["software_count"] = len(software)

    cmdb = ctx["assets"].get(machine_id)
    if cmdb:
        for name in cmdb:
            attrs["asset_" + name] = cmdb[name]
        asset_type = cmdb.get("asset_type_name", "")
        if asset_type:
            tags.append("asset-type:" + asset_type)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], machine_id),
        # _hostname drops placeholder names and values that are really IPs.
        "hostnames": [_hostname(fields.get("name"))],
        "networkInterfaces": netifs,
        "software": software[:MAX_CHILDREN],
        "tags": tags,    }

    domain = _first(fields, ["cs_domain", "domain"])
    if domain:
        params["domain"] = domain
    manufacturer = _string(fields, "cs_manufacturer")
    if manufacturer:
        params["manufacturer"] = manufacturer
    model = _string(fields, "cs_model")
    if model:
        params["model"] = model
    os_name = _string(fields, "os_name")
    if os_name:
        params["os"] = os_name
    os_version = _first(fields, ["os_number", "os_version", "os_build"])
    if os_version:
        params["osVersion"] = os_version
    device_type = DEVICE_TYPES.get(_string(fields, "chassis_type").lower(), "")
    if device_type:
        params["deviceType"] = device_type

    first_seen = _ts(fields.get("created"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                      separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)

    # Last_sync is the last agent check-in, which is the closest thing the
    # appliance records to an observation of the device. Last_inventory only
    # moves when a full inventory upload succeeds, and Modified also moves when
    # an administrator edits the record, so it would overstate presence.
    # lastSeenTS is settable as an attribute but is not a constructor keyword.
    last_seen = (_ts(fields.get("last_sync")) or _ts(fields.get("last_inventory")) or
                 _ts(fields.get("modified")))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def build_assets(ctx, records):
    """Convert one page of machine records into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            print("quest-kace: skipping non-object machine record")
            continue
        fields = _fields(record)
        machine_id = _string(fields, "id")
        if not machine_id:
            print("quest-kace: skipping machine with no id: name=" + _string(fields, "name"))
            continue
        assets.append(build_asset(ctx, record))
    return assets

def login(ctx):
    """Log in and refresh the session headers.

    The response carries the session as Set-Cookie headers plus, on appliances
    older than 12.1, a CSRF token that has to be echoed back on every later
    request. Nothing in the helper layer exposes response headers, so the login
    is a raw POST and the cookie jar is assembled by hand.
    """
    body = {"userName": ctx["username"], "password": ctx["password"]}
    if ctx["organization"]:
        body["organizationName"] = ctx["organization"]

    # The connection options collected from CONFIG carry the TLS settings and
    # the configured User-Agent, both of which the login has to honor too.
    options = dict(ctx["base_options"])
    headers = dict(options.get("headers", {}))
    options.pop("headers", None)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    for name in VERSION_HEADERS:
        headers[name] = API_VERSION

    resp = http_post(ctx["base_url"] + LOGIN_PATH, headers=headers,
                     body=bytes(json_encode(body)), **options)
    if resp == None:
        print("quest-kace: no response from the login endpoint")
        return False
    if resp.status_code != 200:
        if resp.status_code == 401:
            print("quest-kace: login rejected, check the username, password, and organization")
        else:
            print("quest-kace: login failed with status {}".format(resp.status_code))
        return False

    names, values = parse_cookies(resp.headers)
    if not names:
        print("quest-kace: the login response set no session cookies")
        return False

    token = ""
    for name in CSRF_RESPONSE_HEADERS:
        found = _header_values(resp.headers, name)
        if found:
            token = found[0]
            break
    if not token:
        token = values.get(CSRF_COOKIE, "")

    session = dict(ctx["base_options"].get("headers", {}))
    session["Accept"] = "application/json"
    session["Cookie"] = "; ".join(["{}={}".format(name, values[name]) for name in names])
    for name in VERSION_HEADERS:
        session[name] = API_VERSION
    if token:
        for name in CSRF_HEADERS:
            session[name] = token

    http_options = dict(ctx["base_options"])
    http_options["headers"] = session
    # get_json already retries transient statuses by default; the budget is
    # pinned here so the walk's retry behavior does not drift with the helper.
    http_options["retries"] = HTTP_RETRIES
    ctx["http_options"] = http_options

    # The organization is part of every asset id, so it is taken from the
    # appliance's own statement of the session organization when it publishes
    # one, and only then from the configured name.
    org = values.get(ORG_COOKIE, "").strip()
    ctx["org"] = (org or ctx["organization"] or "default").lower()
    ctx["scope"] = "{}:{}".format(ctx["host"], ctx["org"])
    return True

def fetch_page(ctx, path, wrapper, shaping, offset):
    """Fetch one page of a KACE collection, re-authenticating once if the
    session has expired. The wrapper name is given in lower case because the
    response keys are folded before the collection is read. Returns
    (records, ok)."""
    query = _query({
        "shaping": shaping,
        "paging": "offset {} limit {}".format(offset, ctx["page_size"]),
        # The count costs the appliance a second query and the field it lands in
        # is not part of the published schema, so it is switched off.
        "use_count": "false",
    })
    url = ctx["base_url"] + path + "?" + query

    for attempt in range(2):
        data, err = get_json(url, **ctx["http_options"])
        if not err:
            data = data or {}
            if type(data) != "dict":
                print("quest-kace: unexpected response shape from {}".format(path))
                return [], False
            records = _fields(data).get(wrapper, [])
            # Malformed elements are left in place: the page length is what ends
            # pagination, so filtering here would cut the import short.
            if type(records) != "list":
                return [], True
            return records, True
        if err.startswith("status 401") and attempt == 0:
            print("quest-kace: session expired, logging in again")
            if login(ctx):
                continue
            return [], False
        print("quest-kace: failed to fetch {} at offset {}: {}".format(path, offset, err))
        return [], False
    return [], False

def fetch_assets(ctx):
    """Index the asset CMDB by the inventory machine each record is mapped to.

    Only device assets carry a mapped_id, so licence, location, and software
    asset types are skipped here; they describe no device and would have nothing
    to merge onto.
    """
    index = {}
    offset = 0
    collisions = 0
    _pager1 = pager("quest-kace-1")
    while _pager1.next():
        records, ok = fetch_page(ctx, ASSETS_PATH, "assets", "asset all", offset)
        if not ok:
            break
        if not records:
            break
        for record in records:
            if type(record) != "dict":
                continue
            fields = _fields(record)
            mapped = _to_int(fields.get("mapped_id", -1))
            if mapped < 1:
                continue
            asset_type = _string(fields, "asset_type_name")
            if asset_type and asset_type.lower() != "device":
                continue
            key = str(mapped)
            if key in index:
                collisions += 1
                continue
            if len(index) >= MAX_ASSET_INDEX:
                print("quest-kace: asset index capped at {} records".format(MAX_ASSET_INDEX))
                return index
            entry = {}
            for name in ASSET_ATTRS:
                if name in fields:
                    entry[name] = as_text(fields[name], join=",")
            index[key] = entry
        if len(records) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    print("quest-kace: indexed {} CMDB assets mapped to inventory machines".format(len(index)))
    if collisions:
        print("quest-kace: {} extra CMDB assets map to a machine that already has one".format(collisions))
    return index

def fetch_and_report_machines(ctx):
    """Fetch and stream machines one page at a time so the full inventory is
    never held in memory at once.

    Shaping has to be requested explicitly: the default STANDARD level omits the
    MAC address, the serial numbers, the manufacturer and model, and the
    software list, which is most of what makes this import worth running.
    """
    shaping = "machine all"
    if ctx["import_software"]:
        shaping = "machine all,software all"

    reported = 0
    offset = 0
    previous = ""
    _pager2 = pager("quest-kace-2")
    while _pager2.next():
        records, ok = fetch_page(ctx, MACHINES_PATH, "machines", shaping, offset)
        if not ok:
            return reported
        if not records:
            break

        # An appliance that ignores paging would serve the same first record
        # forever; a repeated leading id ends the run instead.
        marker = _string(_fields(records[0]), "id") if type(records[0]) == "dict" else ""
        if marker and marker == previous:
            print("quest-kace: the appliance repeated the page starting at offset {}, stopping".format(offset))
            break
        previous = marker

        reported += report_assets(build_assets(ctx, records))
        if len(records) < ctx["page_size"]:
            break
        offset += ctx["page_size"]

    print("quest-kace: reported {} assets from organization {}".format(reported, ctx["org"]))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    host = parsed.hostname if parsed else ""
    if not host:
        fail("quest-kace: could not determine the appliance host from the configured URL")

    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    ctx = {
        "base_options": get_http_options(kwargs, headers={"Accept": "application/json"}),
        "base_url": base_url,
        "host": host,
        "username": get_string(kwargs, "username"),
        "password": get_string(kwargs, "password"),
        "organization": get_string(kwargs, "organization", default="").strip(),
        "import_software": get_bool(kwargs, "import_software", default=True),
        "import_assets": get_bool(kwargs, "import_assets", default=True),
        "page_size": page_size,
        "http_options": {},
        "org": "default",
        "scope": host,
        "assets": {},
    }

    if not login(ctx):
        return None

    if ctx["import_assets"]:
        ctx["assets"] = fetch_assets(ctx)

    reported = fetch_and_report_machines(ctx)
    if not reported:
        print("quest-kace: no assets retrieved")
    return None

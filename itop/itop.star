# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-itop",
    "name": "iTop",
    "type": "inbound",
    "description": "Imports configuration items from the iTop CMDB, with their serial numbers, models, operating systems, and network interfaces.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "iTop URL",
            "type": "url",
            "required": True,
            "placeholder": "https://itop.example.com",
            "description": "Base URL of the iTop instance, including any subdirectory. The /webservices/rest.php path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": False,
            "description": "iTop user holding the REST Services User profile. Leave blank when an authentication token is supplied.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": False,
            "description": "Password for that user, sent with HTTP Basic authentication.",
        },
        {
            "key": "auth_token",
            "label": "Authentication token",
            "type": "secret",
            "required": False,
            "description": "Application or personal token, sent in the Auth-Token header. Requires the authent-token module (iTop 3.1 and later) and is preferred over a password.",
        },
        {
            "key": "classes",
            "label": "CI classes",
            "type": "string",
            "required": False,
            "default": "Server,VirtualMachine,NetworkDevice,PC",
            "description": "Comma-separated iTop classes to import. An abstract class such as PhysicalDevice collects every subclass in one query.",
        },
        {
            "key": "oql_filter",
            "label": "OQL filter",
            "type": "string",
            "required": False,
            "placeholder": "status != 'obsolete'",
            "description": "Appended to every query as an OQL WHERE clause. It is evaluated server-side against each class, so it may only reference attributes every selected class has.",
        },
        {
            "key": "api_version",
            "label": "REST API version",
            "type": "string",
            "required": False,
            "default": "1.4",
            "description": "Value sent as the version parameter. Pagination needs 1.4; iTop accepts 1.0 through 1.4.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "description": "Objects requested per page, sent as the limit field of each core/get.",
        },
        {
            "key": "include_interfaces",
            "label": "Import network interfaces",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read the PhysicalInterface and LogicalInterface classes once and attach each interface to the CI that owns it.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'post_json', 'basic', 'url_encode', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool', 'get_list')
load('json', json_encode='encode')
load('time', 'now', 'parse_time')

load('coerce', 'as_dict', 'as_text')
VENDOR = "itop"
ATTR_PREFIX = "itop"
ATTR_SEPARATOR = "_"
API_SUFFIX = "/webservices/rest.php"
# Attributes defined on FunctionalCI, the root of every configuration item
# class. Requesting only these is always safe, whatever class was asked for.
BASE_FIELDS = ["id", "name", "description", "organization_name", "business_criticity", "move2production"]

# Attributes added by PhysicalDevice, the parent of every tangible CI.
PHYSICAL_FIELDS = ["serialnumber", "location_name", "status", "brand_name", "model_name",
                   "asset_number", "purchase_date", "end_of_warranty"]

# Attributes added by DatacenterDevice, which is where managementip lives. A PC
# or a Printer is a ConnectableCI and has no managementip at all.
DATACENTER_FIELDS = ["managementip", "rack_name", "enclosure_name", "nb_u"]

OS_FIELDS = ["osfamily_name", "osversion_name"]

# Per-class attribute sets, keyed on the class named in the query. Requesting an
# attribute a class does not define is an error rather than an omission, so an
# unlisted class falls back to BASE_FIELDS, which every CI class has.
CLASS_FIELDS = {
    "FunctionalCI": [],
    "PhysicalDevice": PHYSICAL_FIELDS,
    "ConnectableCI": PHYSICAL_FIELDS,
    "DatacenterDevice": PHYSICAL_FIELDS + DATACENTER_FIELDS,
    "Server": PHYSICAL_FIELDS + DATACENTER_FIELDS + OS_FIELDS + ["oslicence_name", "cpu", "ram"],
    "NetworkDevice": PHYSICAL_FIELDS + DATACENTER_FIELDS + ["networkdevicetype_name", "iosversion_name", "ram"],
    "PC": PHYSICAL_FIELDS + OS_FIELDS + ["cpu", "ram", "type"],
    "Printer": PHYSICAL_FIELDS,
    "Tablet": PHYSICAL_FIELDS,
    "Peripheral": PHYSICAL_FIELDS,
    "TelephonyCI": PHYSICAL_FIELDS + ["phonenumber"],
    "Phone": PHYSICAL_FIELDS + ["phonenumber"],
    "IPPhone": PHYSICAL_FIELDS + ["phonenumber"],
    "MobilePhone": PHYSICAL_FIELDS + ["phonenumber", "imei"],
    # The virtualization branch descends from VirtualDevice, not PhysicalDevice,
    # so it has status but none of the serial or model attributes.
    "VirtualDevice": ["status"],
    "VirtualMachine": ["status", "managementip", "virtualhost_name", "oslicence_name", "cpu", "ram"] + OS_FIELDS,
    "VirtualHost": ["status"],
    "Hypervisor": ["status", "server_name", "farm_name"],
    "Farm": ["status"],
}

# The runZero device type each iTop class describes. Classes that say nothing
# about form factor are deliberately absent.
DEVICE_TYPES = {
    "Server": "Server",
    "NetworkDevice": "Network Device",
    "Printer": "Printer",
    "VirtualMachine": "Virtual Machine",
    "Hypervisor": "Hypervisor",
    "Tablet": "Tablet",
    "MobilePhone": "Mobile Device",
    "IPPhone": "IP Phone",
    "Phone": "IP Phone",
}
# PC.type is an enumeration with exactly these two values.
PC_TYPES = {"laptop": "Laptop", "desktop": "Desktop"}

# The two IPInterface subclasses, with the external key that names the CI each
# one belongs to. Reading the interface classes directly is what keeps the CI
# queries from having to ask for physicalinterface_list, which iTop's own
# documentation warns against because a link set pulls every linked object and
# can exhaust the server's memory limit.
INTERFACE_CLASSES = [
    ("PhysicalInterface", "connectableci_id"),
    ("LogicalInterface", "virtualmachine_id"),
]
INTERFACE_FIELDS = ["id", "name", "ipaddress", "macaddress", "speed"]

# iTop's own REST error codes, from RestResult in core/restservices.class.inc.php.
ERROR_CODES = {
    0: "OK",
    1: "UNAUTHORIZED",
    2: "MISSING_VERSION",
    3: "MISSING_JSON",
    4: "INVALID_JSON",
    5: "MISSING_AUTH_USER",
    6: "MISSING_AUTH_PWD",
    10: "UNSUPPORTED_VERSION",
    11: "UNKNOWN_OPERATION",
    12: "UNSAFE",
    100: "INTERNAL_ERROR",
}

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "n/a", "none", "-", "undefined"]
HOSTNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
DIGITS = "0123456789"
MONTH_DAYS = {1: 31, 2: 28, 3: 31, 4: 30, 5: 31, 6: 30, 7: 31, 8: 31, 9: 30, 10: 31, 11: 30, 12: 31}
def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1."""
    if type(value) == "int":
        return value
    text = as_text(value)
    if not text or len(text) > 10:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _parse_date(value, ceiling):
    """Parse an iTop date or datetime, clamped to the current time.

    iTop serializes AttributeDate as "2024-03-11" and AttributeDateTime as
    "2024-03-11 08:21:38", neither of which carries a timezone, and parse_time
    rejects both with an error that aborts the whole script. Each is therefore
    validated field by field before a Z is appended. iTop stores these in the
    timezone configured on the server and publishes no offset, so they are read
    as UTC; the clamp keeps a server east of UTC from producing timestamps that
    read as the future, which runZero rejects by dropping the whole record."""
    text = as_text(value).replace("T", " ")
    if len(text) == 10:
        text = text + " 00:00:00"
    if len(text) < 19 or text[4] != "-" or text[7] != "-" or text[10] != " ":
        return None
    if text[13] != ":" or text[16] != ":":
        return None
    year = _to_int(text[0:4])
    month = _to_int(text[5:7])
    day = _to_int(text[8:10])
    hour = _to_int(text[11:13])
    minute = _to_int(text[14:16])
    second = _to_int(text[17:19])
    if year < 1971 or month < 1 or month > 12 or day < 1:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59 or second < 0 or second > 60:
        return None
    max_day = MONTH_DAYS[month]
    if month == 2 and year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        max_day = 29
    if day > max_day:
        return None
    parsed = parse_time(text[0:10] + "T" + text[11:19] + "Z")
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed
def _hostname(value):
    """Return a value fit to be imported as a hostname, or an empty string.

    A CI name in iTop is free text maintained by hand, so it is a hostname on
    some installs, an inventory label with spaces on others, and occasionally an
    IP address."""
    text = as_text(value)
    if not text or len(text) > 253:
        return ""
    if text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    numeric = True
    for index in range(len(text)):
        if text[index] not in HOSTNAME_CHARS:
            return ""
        if text[index] not in "0123456789.":
            numeric = False
    if numeric:
        return ""
    return text


def _fields_for(class_name):
    """Return the attribute list to request for a class."""
    return BASE_FIELDS + CLASS_FIELDS.get(class_name, [])


def call(ctx, payload, what):
    """Run one core/get and return the decoded response.

    Every iTop operation goes to the same endpoint as a form POST: version and
    json_data are ordinary form fields, which is what the REST/JSON reference's
    own curl examples send. The credential travels in a header instead, because
    the auth_user and auth_pwd body fields belong to iTop's "url" login type,
    and the shipped default for allowed_login_types is form|external|basic|token
    - so on an untouched install those two fields are rejected while HTTP Basic
    is accepted."""
    form = url_encode({"version": ctx["api_version"], "json_data": json_encode(payload)})
    data, err = post_json(ctx["api_url"], body=bytes(form), **ctx["http_options"])
    if err:
        return None, "{}: {}".format(what, err)
    if type(data) != "dict":
        # An HTML login page or a PHP fatal error reaches this point as a decode
        # failure inside the helper, so anything else that is not an object is
        # a response iTop did not produce.
        return None, "{}: the response was not a JSON object".format(what)
    code = data.get("code")
    if code != 0:
        label = ERROR_CODES.get(code, "code {}".format(code))
        return None, "{}: {} - {}".format(what, label, as_text(data.get("message")))
    return data, None


def build_interface_map(ctx):
    """Index every IPInterface by the id of the CI that owns it.

    PhysicalInterface hangs off a ConnectableCI and LogicalInterface off a
    VirtualMachine, but iTop allocates object ids from the root of the class
    hierarchy, so a single map keyed on the owner id serves both without a
    collision."""
    interfaces = {}
    for class_name, owner_key in INTERFACE_CLASSES:
        fields = INTERFACE_FIELDS + [owner_key]
        count = 0
        _pager1 = pager("itop-1")
        while _pager1.next():
            page = _pager1.page
            payload = {
                "operation": "core/get",
                "class": class_name,
                "key": "SELECT " + class_name,
                "output_fields": ",".join(fields),
                "limit": ctx["page_size"],
                "page": page,
            }
            data, err = call(ctx, payload, "fetching " + class_name)
            if err:
                # A CMDB without the datacenter or virtualization module simply
                # has no such class; that is not a reason to end the run.
                print("itop:", err)
                break
            objects = as_dict(data.get("objects"))
            if not objects:
                break
            for key in objects:
                entry = as_dict(objects[key])
                row = as_dict(entry.get("fields"))
                owner = as_text(row.get(owner_key))
                if not owner or owner == "0":
                    continue
                record = {
                    "name": as_text(row.get("name")),
                    "ip": as_text(row.get("ipaddress")),
                    "mac": as_text(row.get("macaddress")),
                    "speed": as_text(row.get("speed")),
                    "class": class_name,
                }
                if owner not in interfaces:
                    interfaces[owner] = []
                if len(interfaces[owner]) < 99:
                    interfaces[owner].append(record)
                count += 1
            if len(objects) < ctx["page_size"]:
                break
        if count:
            print("itop: indexed {} {} records".format(count, class_name))
    return interfaces


def build_interfaces(records):
    """Build one runZero interface per iTop interface record.

    iTop models an interface as a single address and a single MAC, so a host
    with several NICs keeps them apart instead of being collapsed into one."""
    nics = []
    for record in records:
        ips = []
        address = routable_ip(record["ip"])
        if address:
            ips.append(address)
        mac = record["mac"]
        if mac and normalize_mac(mac) == None:
            mac = ""
        nic = network_interface(mac=mac, ips=ips)
        if nic:
            nics.append(nic)
    return nics


def build_asset(ctx, class_name, object_id, fields, records):
    """Convert one iTop CI into a runZero asset, or None when it carries nothing
    runZero could correlate on."""
    name = as_text(fields.get("name"))
    management_ip = routable_ip(fields.get("managementip"))

    nics = build_interfaces(records)
    if management_ip:
        covered = False
        for record in records:
            if routable_ip(record["ip"]) == management_ip:
                covered = True
                break
        if not covered:
            # The management address is an attribute of the CI rather than of
            # any modelled interface, so it becomes an interface of its own only
            # when no interface already carries it.
            nic = network_interface(ips=[management_ip])
            if nic:
                nics.append(nic)

    hostnames = []
    hostname = _hostname(name)
    if hostname:
        hostnames.append(hostname)

    if not hostnames and not nics:
        print("itop: skipping {} {}: no address, MAC, or usable name".format(class_name, object_id))
        return None

    status = as_text(fields.get("status"))
    serial = as_text(fields.get("serialnumber"))
    organization = as_text(fields.get("organization_name"))

    tags = [VENDOR, "class:" + class_name]
    if status:
        tags.append("status:" + status)
    if organization:
        tags.append("org:" + organization)

    attributes = {
        "object_id": object_id,
        "class": class_name,
        "server": ctx["scope"],
        "name": name,
        "description": as_text(fields.get("description")),
        "organization": organization,
        "business_criticity": as_text(fields.get("business_criticity")),
        "status": status,
        "serialnumber": serial,
        "asset_number": as_text(fields.get("asset_number")),
        "location": as_text(fields.get("location_name")),
        "brand": as_text(fields.get("brand_name")),
        "model": as_text(fields.get("model_name")),
        "os_family": as_text(fields.get("osfamily_name")),
        "os_version": as_text(fields.get("osversion_name")),
        "os_licence": as_text(fields.get("oslicence_name")),
        "cpu": as_text(fields.get("cpu")),
        "ram": as_text(fields.get("ram")),
        "managementip": as_text(fields.get("managementip")),
        "rack": as_text(fields.get("rack_name")),
        "enclosure": as_text(fields.get("enclosure_name")),
        "nb_u": fields.get("nb_u"),
        "network_device_type": as_text(fields.get("networkdevicetype_name")),
        "ios_version": as_text(fields.get("iosversion_name")),
        "virtual_host": as_text(fields.get("virtualhost_name")),
        "hypervisor_server": as_text(fields.get("server_name")),
        "hypervisor_farm": as_text(fields.get("farm_name")),
        "pc_type": as_text(fields.get("type")),
        "phone_number": as_text(fields.get("phonenumber")),
        "imei": as_text(fields.get("imei")),
        "purchase_date": as_text(fields.get("purchase_date")),
        "end_of_warranty": as_text(fields.get("end_of_warranty")),
        "move2production": as_text(fields.get("move2production")),
        "interface_count": len(records),
        "interface_names": [record["name"] for record in records if record["name"]],
    }

    params = {
        # iTop allocates object ids from a MySQL auto-increment column on the
        # root of each class hierarchy, so an id is unique across every CI class
        # at once; the class is kept in the key so an id can be read back to the
        # object it names.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], class_name, object_id),
        "hostnames": hostnames,
        "networkInterfaces": nics[:99],
        "tags": tags,
    }
    brand = as_text(fields.get("brand_name"))
    if brand:
        params["manufacturer"] = brand
    model = as_text(fields.get("model_name"))
    if model:
        params["model"] = model

    device_type = DEVICE_TYPES.get(class_name, "")
    if class_name == "PC":
        device_type = PC_TYPES.get(as_text(fields.get("type")).lower(), "Desktop")
    if device_type:
        params["deviceType"] = device_type

    os_family = as_text(fields.get("osfamily_name"))
    if os_family:
        params["os"] = os_family
    os_version = as_text(fields.get("osversion_name"))
    if os_version:
        params["osVersion"] = os_version

    # move2production is the date the CI entered service, which is the closest
    # thing iTop keeps to a first-seen time. There is no last-seen equivalent: a
    # CMDB row records what should exist, not when it was last observed, so
    # lastSeenTS is deliberately left unset rather than filled with the date the
    # record was edited.
    first_seen = _parse_date(fields.get("move2production"), ctx["now"])
    if first_seen:
        params["firstSeenTS"] = first_seen

    params["customAttributes"] = to_custom_attributes(
        attributes, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)


def fetch_and_report_class(ctx, class_name):
    """Page through one iTop class and stream each page into runZero."""
    fields = _fields_for(class_name)
    oql = "SELECT " + class_name
    if ctx["oql_filter"]:
        oql += " WHERE " + ctx["oql_filter"]

    reported = 0
    previous_keys = ""
    _pager2 = pager("itop-2")
    while _pager2.next():
        page = _pager2.page
        payload = {
            "operation": "core/get",
            "class": class_name,
            "key": oql,
            "output_fields": ",".join(fields),
            "limit": ctx["page_size"],
            "page": page,
        }
        data, err = call(ctx, payload, "fetching " + class_name)
        if err:
            print("itop:", err)
            return reported

        # iTop answers a query that matched nothing with objects: null rather
        # than an empty object, which is the end of the pages.
        objects = as_dict(data.get("objects"))
        if not objects:
            break

        # An iTop older than the release that added limit and page ignores both
        # and returns the whole result set on every request. Each page then
        # looks full, so paging would continue forever. The check compares the
        # page's own object keys rather than counting new objects, because two
        # overlapping classes - PhysicalDevice after Server - legitimately
        # produce a page of already-seen objects that must not stop the walk.
        page_keys = ",".join(sorted(objects.keys()))
        if page_keys == previous_keys:
            print("itop: page {} of {} repeated the previous page; the server appears to ignore limit and page".format(
                page, class_name))
            break
        previous_keys = page_keys

        assets = []
        for key in objects:
            entry = as_dict(objects[key])
            if entry.get("code") != None and entry.get("code") != 0:
                print("itop: skipping {}: {}".format(key, as_text(entry.get("message"))))
                continue
            row = as_dict(entry.get("fields"))
            # The concrete class is reported per object, so querying an abstract
            # class such as PhysicalDevice still yields Server, PC, and Printer
            # under their own names, and an id built from it is stable whichever
            # class the operator asked for.
            concrete = as_text(entry.get("class")) or class_name
            object_id = as_text(entry.get("key")) or as_text(row.get("id"))
            if not object_id or object_id == "0":
                print("itop: skipping {} with no key: name={}".format(concrete, as_text(row.get("name"))))
                continue
            unique = concrete + ":" + object_id
            if unique in ctx["seen"]:
                continue
            ctx["seen"][unique] = True

            asset = build_asset(ctx, concrete, object_id, row, ctx["interfaces"].get(object_id, []))
            if asset != None:
                assets.append(asset)

        if assets:
            reported += report_assets(assets)
        if len(objects) < ctx["page_size"]:
            break

    print("itop: reported {} assets from {}".format(reported, class_name))
    return reported


def main(**kwargs):
    # get_url_base would drop the path, and iTop is very often installed in a
    # subdirectory such as https://itsm.example.com/itop.
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("itop: no iTop URL was configured")
        return None
    api_url = url if url.endswith(API_SUFFIX) else url + API_SUFFIX

    parsed = url_parse(url)
    if parsed == None or not parsed.hostname:
        print("itop: could not determine the iTop host from the configured URL")
        return None
    scope = parsed.hostname

    token = get_string(kwargs, "auth_token", default="").strip()
    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")

    headers = {
        "Accept": "application/json",
        # json_data and version are form fields, not a JSON document.
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if token:
        headers["Auth-Token"] = token
    elif username and password:
        headers["Authorization"] = basic(username, password)
    else:
        print("itop: configure either an authentication token or a username and password")
        return None

    page_size = get_int(kwargs, "page_size", default=200)
    if page_size < 1:
        page_size = 1

    classes = get_list(kwargs, "classes", default=[])
    selected = []
    for class_name in classes:
        name = as_text(class_name)
        if name and name not in selected:
            selected.append(name)
    if not selected:
        selected = ["Server", "VirtualMachine", "NetworkDevice", "PC"]

    ctx = {
        "api_url": api_url,
        "http_options": get_http_options(kwargs, "http_", "tls_", headers),
        "now": now(),
        "scope": scope,
        "api_version": get_string(kwargs, "api_version", default="1.4").strip() or "1.4",
        "page_size": page_size,
        "oql_filter": get_string(kwargs, "oql_filter", default="").strip(),
        "interfaces": {},
        "seen": {},
    }

    if get_bool(kwargs, "include_interfaces", default=True):
        ctx["interfaces"] = build_interface_map(ctx)

    reported = 0
    for class_name in selected:
        reported += fetch_and_report_class(ctx, class_name)

    if not reported:
        print("itop: no assets retrieved")
    return None

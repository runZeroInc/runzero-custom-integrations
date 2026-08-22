# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-glpi",
    "name": "GLPI",
    "type": "inbound",
    "description": "Imports computers, network equipment, printers, their network ports, and installed software from GLPI.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "GLPI URL",
            "type": "url",
            "required": True,
            "placeholder": "https://glpi.example.com",
            "description": "Base URL of the GLPI instance, including any subdirectory. The /apirest.php path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": False,
            "description": "GLPI username, for password login. Leave blank when a user API token is supplied.",
        },
        {
            "key": "app_token",
            "label": "Application token",
            "type": "secret",
            "required": False,
            "description": "App-Token of the GLPI API client. Required whenever the matching API client defines one.",
        },
        {
            "key": "user_token",
            "label": "User API token",
            "type": "secret",
            "required": False,
            "description": "Personal API token of a GLPI user. Preferred over username and password.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": False,
            "description": "GLPI password, used only with the username field.",
        },
        {
            "key": "include_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch the per-computer software inventory. Costs one extra request per computer.",
        },
        {
            "key": "detail_limit",
            "label": "Software enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of computers to enrich with software. Computers past the limit are still imported, without software. 0 removes the cap.",
        },
        {
            "key": "include_network_devices",
            "label": "Import network equipment and printers",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Also import the NetworkEquipment and Printer item types alongside Computer.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_time', 'parse_ts')

load('coerce', 'dicts')
VENDOR = "glpi"
ATTR_PREFIX = "glpi"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
API_SUFFIX = "/apirest.php"
PAGE_SIZE = 200         # Accept-Range advertises a server maximum of 1000
SIDE_PAGE_SIZE = 500    # side tables carry narrow rows, so they page in larger chunks
MAX_CHILDREN = 99
DIGITS = "0123456789"
# The GLPI item types worth importing, in the order they are fetched. Every one
# of these is a network-addressable asset that carries a serial number and can
# own network ports, which is what makes it mergeable with runZero discovery.
# The model and type dropdowns are named after the item type, so each needs its
# own field names. Monitor and Phone are deliberately absent: see the README.
ITEM_ORDER = ["Computer", "NetworkEquipment", "Printer"]
ITEM_TYPES = {
    "Computer": {"model": "computermodels_id", "type": "computertypes_id", "device_type": ""},
    "NetworkEquipment": {"model": "networkequipmentmodels_id", "type": "networkequipmenttypes_id", "device_type": "Network Device"},
    "Printer": {"model": "printermodels_id", "type": "printertypes_id", "device_type": "Printer"},
}

# GLPI computer types are a free-text dropdown, but these values ship in the
# default install and are what the native inventory writes from the SMBIOS
# chassis type. Anything else survives as the glpi_item_type attribute.
DEVICE_TYPES = {
    "laptop": "Laptop",
    "desktop": "Desktop",
    "server": "Server",
    "virtual machine": "Virtual Machine",
    "tablet": "Tablet",
    "smartphone": "Mobile Device",
    "phone": "IP Phone",
    "printer": "Printer",
    "storage": "Storage",
}

# NetworkPortLocal is the loopback port GLPI creates for "lo", so it never
# describes a routable interface and is dropped before interfaces are built.
SKIP_PORT_CLASSES = ["NetworkPortLocal"]

# The port class alone is not enough to recognize a software device. GLPI files
# docker0 and veth pairs under NetworkPortEthernet, exactly like a real NIC, so
# only the port name distinguishes them. This matters more here than it looks:
# the docker0 bridge MAC is derived from a fixed vendor prefix, so once runZero
# clears the locally-administered bit it is byte-for-byte identical on every
# Docker host on earth, and importing it merges unrelated estates onto one
# asset. Kernel-assigned names are matched as prefixes because they carry a
# generated suffix (veth1a2b3c4, br-9f3c2e1a0b7d).
VIRTUAL_PORT_PREFIXES = [
    "docker", "veth", "virbr", "br-", "vnet", "vmnet", "tap", "tun", "wg",
    "zt", "cali", "flannel", "cni", "kube-bridge", "nerdctl", "podman",
]

# Windows names the adapter by its product description rather than by a kernel
# device name, so those are matched as substrings anywhere in the name.
VIRTUAL_PORT_HINTS = [
    "vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "vmnet", "docker",
    "wan miniport", "wi-fi direct virtual", "kernel debug network",
    "loopback", "tap-windows", "tap adapter", "teredo tunneling", "isatap",
    "bluetooth device (personal area network)", "openvpn", "wintun",
    "tailscale", "zerotier", "virtual ethernet", "virtual adapter",
    "pppoe", "6to4 adapter",
]

# GLPI stores text through its legacy input sanitizer, so a value round-trips
# out of the API with HTML entities in place of the original punctuation. A
# location reads "HQ &#62; Floor 2" rather than "HQ > Floor 2".
ENTITIES = [
    ("&#60;", "<"), ("&lt;", "<"),
    ("&#62;", ">"), ("&gt;", ">"),
    ("&#34;", '"'), ("&quot;", '"'),
    ("&#39;", "'"), ("&#039;", "'"), ("&apos;", "'"),
    ("&#38;", "&"), ("&amp;", "&"),
]


def _text(value):
    """Flatten a scalar or list into a plain string, decoding the HTML entities
    GLPI leaves in every text field."""
    if value == None:
        return ""
    if type(value) == "list":
        return ",".join([_text(item) for item in value if item != None])
    text = str(value)
    for entity, char in ENTITIES:
        if entity in text:
            text = text.replace(entity, char)
    return text


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
def _dropdown(value):
    """Return an expanded dropdown as text. GLPI writes 0 when the dropdown is
    unset and the resolved name once expand_dropdowns has been applied, so a
    bare integer means "none" rather than a usable value."""
    if value == None or type(value) == "int":
        return ""
    return _text(value).strip()
def build_software(ctx, item_type, item_id, entries):
    """Convert the software installations GLPI records against one computer into
    Software records. With expand_dropdowns applied the installation row carries
    the product and version as names rather than ids, but never the publisher,
    so the vendor is filled in from the software catalog fetched once up front.
    GLPI publishes no CPE for an installation, so cpe23 is left unset rather
    than synthesized."""
    software = []
    seen = []
    for entry in dicts(entries):
        product = _dropdown(entry.get("softwares_id"))
        if not product:
            continue
        version = _dropdown(entry.get("softwareversions_id"))
        key = "{}:{}".format(product, version)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:{}:{}:software:{}".format(VENDOR, ctx["scope"], item_type, item_id, key),
            "product": product,
            "serviceAddress": "127.0.0.1",
        }
        if version:
            params["version"] = version
        publisher = ctx["publishers"].get(product, "")
        if publisher:
            params["vendor"] = publisher
        params["customAttributes"] = to_custom_attributes({
            "software_category": _dropdown(entry.get("softwarecategories_id")),
            "software_dynamic": entry.get("is_dynamic"),
            "software_valid": entry.get("is_valid"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software


def _is_virtual_port(name):
    """Decide whether a network port is a software device rather than real
    hardware. An agent on a container or hypervisor host reports these under the
    same port class as a physical NIC, and their MACs are either shared across
    every host running the same software or regenerated on each boot, so neither
    spelling belongs on an asset."""
    lowered = name.lower()
    if not lowered:
        return False
    for prefix in VIRTUAL_PORT_PREFIXES:
        if lowered.startswith(prefix):
            return True
    for hint in VIRTUAL_PORT_HINTS:
        if hint in lowered:
            return True
    return False


def collect_ports(networkports):
    """Flatten the _networkports expansion into one entry per port. GLPI keys the
    expansion by port class - NetworkPortEthernet, NetworkPortWifi,
    NetworkPortAggregate, NetworkPortAlias, NetworkPortDialup, NetworkPortLocal,
    NetworkPortFiberchannel - and hangs the addresses off the port's NetworkName
    as NetworkName.IPAddress[].name. Loopback ports and loopback addresses are
    dropped, virtual adapters are dropped by name, and a port with neither a MAC
    nor a routable address is skipped so it cannot become an empty interface."""
    ports = []
    if type(networkports) != "dict":
        return ports
    for port_class in networkports:
        if port_class in SKIP_PORT_CLASSES:
            continue
        for port in dicts(networkports[port_class]):
            port_name = _text(port.get("name")).strip()
            if _is_virtual_port(port_name):
                continue
            mac = _text(port.get("mac")).strip()
            ips = []
            network_name = port.get("NetworkName")
            if type(network_name) == "dict":
                for address in dicts(network_name.get("IPAddress")):
                    routable = routable_ip(_text(address.get("name")).strip())
                    if routable and routable not in ips:
                        ips.append(routable)
            if not mac and not ips:
                continue
            ports.append({
                "class": port_class,
                "name": port_name,
                "mac": mac,
                "ips": ips,
            })
    return ports


def build_interfaces(ports):
    """Build one runZero network interface per GLPI network port. GLPI models a
    MAC and its addresses on each port individually, so a multi-homed host keeps
    its per-NIC addressing instead of being collapsed into one interface."""
    interfaces = []
    for port in ports:
        nic = network_interface(mac=port["mac"], ips=port["ips"])
        if nic:
            interfaces.append(nic)
    return interfaces


def build_asset(ctx, item_type, record, software):
    """Convert one GLPI inventory record into a runZero asset."""
    item_id = record.get("id")
    fields = ITEM_TYPES[item_type]

    ports = collect_ports(record.get("_networkports"))
    netifs = build_interfaces(ports)

    name = _text(record.get("name")).strip()
    serial = _text(record.get("serial")).strip()
    otherserial = _text(record.get("otherserial")).strip()
    entity = _dropdown(record.get("entities_id"))
    state = _dropdown(record.get("states_id"))
    location = _dropdown(record.get("locations_id"))
    manufacturer = _dropdown(record.get("manufacturers_id"))
    model = _dropdown(record.get(fields["model"]))
    item_category = _dropdown(record.get(fields["type"]))

    tags = [VENDOR, "itemtype:" + item_type]
    if serial:
        tags.append("serial:" + serial)
    if entity:
        tags.append("entity:" + entity)
    if state:
        tags.append("state:" + state)

    operating_system = ctx["os_map"].get("{}:{}".format(item_type, item_id), {})

    attrs = {
        "item_id": item_id,
        "item_type": item_type,
        "server": ctx["scope"],
        "name": name,
        "serial": serial,
        "inventory_number": otherserial,
        "uuid": record.get("uuid"),
        "entity": entity,
        "location": location,
        "state": state,
        "user": _dropdown(record.get("users_id")),
        "group": _dropdown(record.get("groups_id")),
        "tech_user": _dropdown(record.get("users_id_tech")),
        "tech_group": _dropdown(record.get("groups_id_tech")),
        "contact": _text(record.get("contact")).strip(),
        "contact_num": _text(record.get("contact_num")).strip(),
        "comment": _text(record.get("comment")).strip(),
        "network": _dropdown(record.get("networks_id")),
        "item_category": item_category,
        "manufacturer": manufacturer,
        "model": model,
        "is_dynamic": record.get("is_dynamic"),
        "is_recursive": record.get("is_recursive"),
        "autoupdatesystem": _dropdown(record.get("autoupdatesystems_id")),
        "date_creation": record.get("date_creation"),
        "date_mod": record.get("date_mod"),
        "last_inventory_update": record.get("last_inventory_update"),
        "ticket_tco": record.get("ticket_tco"),
        "port_count": len(ports),
        "port_names": [port["name"] for port in ports if port["name"]],
        # The port class distinguishes a wired NIC from wifi, a link aggregate,
        # or a fiber channel port, which GLPI records nowhere else.
        "port_classes": [port["class"] for port in ports],
        "os_architecture": operating_system.get("architecture", ""),
        "os_kernel_version": operating_system.get("kernel", ""),
        "os_install_date": operating_system.get("install_date", ""),
        "software_count": len(software),
        "software_enriched": "true" if ctx["enriched"] else "false",
    }
    # sysdescr is the SNMP description string on the network-scanned item types
    # and is absent on Computer.
    sysdescr = _text(record.get("sysdescr")).strip()
    if sysdescr:
        attrs["sysdescr"] = sysdescr

    params = {
        # The GLPI item id is authoritative for the instance, but a GLPI record
        # is routinely renamed by hand and can carry stale or no addressing at
        # all, so network churn must not disqualify a merge.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], item_type, item_id),
        "hostnames": [name],
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model

    device_type = fields["device_type"] or DEVICE_TYPES.get(item_category.lower(), "")
    if device_type:
        params["deviceType"] = device_type

    os_name = operating_system.get("name", "")
    if os_name:
        params["os"] = os_name
    os_version = operating_system.get("version", "")
    if os_version:
        params["osVersion"] = os_version

    first_ts = parse_ts(record.get("date_creation"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    # last_inventory_update is written by the GLPI agent and is the closest thing
    # to a real last-seen time; date_mod only tracks the database row.
    last_ts = parse_ts(record.get("last_inventory_update")) or parse_ts(record.get("date_mod"))
    last_ts = last_ts

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset


def fetch_software(ctx, item_id):
    """Fetch the software installed on one computer. Only the single-item
    endpoint honors with_softwares, so this is one request per computer; the
    caller caps how many are made. A failure is reported and treated as an empty
    inventory so one unreadable computer cannot end the run."""
    url = "{}/Computer/{}".format(ctx["api_url"], item_id)
    params = {"expand_dropdowns": "true", "get_hateoas": "false", "with_softwares": "true"}
    data, err = get_json(url, params=params, **ctx["http_options"])
    if err:
        print("glpi: failed to fetch software for Computer {}: {}".format(item_id, err))
        return []
    data = data or {}
    if type(data) != "dict":
        return []
    return data.get("_softwares", [])


def build_assets(ctx, item_type, records):
    """Convert a page of GLPI records into runZero assets, enriching computers
    with their software inventory until the detail limit is reached."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        item_id = record.get("id")
        if item_id == None or str(item_id).strip() == "":
            print("glpi: skipping {} with no id: name={}".format(item_type, _text(record.get("name"))))
            continue
        # Templates are blueprints for creating items, not inventory.
        if record.get("is_template"):
            continue

        software = []
        ctx["enriched"] = False
        if item_type == "Computer" and ctx["include_software"]:
            if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
                ctx["detail_skipped"] += 1
            else:
                ctx["detail_used"] += 1
                ctx["enriched"] = True
                software = build_software(ctx, item_type, item_id, fetch_software(ctx, item_id))

        assets.append(build_asset(ctx, item_type, record, software))
    return assets


def fetch_page(ctx, path, params, offset, page_size):
    """Fetch one range of a GLPI collection. GLPI answers a range whose first
    index is past the total with 400 ERROR_RANGE_EXCEED_TOTAL rather than an
    empty list, so that response is reported as a clean end of data."""
    query = dict(params)
    query["range"] = "{}-{}".format(offset, offset + page_size - 1)
    data, err = get_json(ctx["api_url"] + path, params=query, **ctx["http_options"])
    if err:
        if "ERROR_RANGE_EXCEED_TOTAL" in err:
            return [], None
        return [], err
    data = data or []
    if type(data) != "list":
        return [], "unexpected response type {}".format(type(data))
    return data, None


def fetch_publishers(ctx):
    """Index the software catalog by product name so each installation can carry
    its publisher. The installation rows returned by with_softwares name the
    product and version but never the publisher, and GLPI keeps software names
    unique, so one paged pass over the catalog replaces a per-title lookup."""
    publishers = {}
    params = {"expand_dropdowns": "true", "get_hateoas": "false"}
    offset = 0
    _pager1 = pager("glpi-1")
    while _pager1.next():
        records, err = fetch_page(ctx, "/Software", params, offset, SIDE_PAGE_SIZE)
        if err:
            print("glpi: failed to fetch the software catalog:", err)
            return publishers
        if not records:
            break
        for record in records:
            if type(record) != "dict":
                continue
            name = _text(record.get("name")).strip()
            publisher = _dropdown(record.get("manufacturers_id"))
            if name and publisher and name not in publishers:
                publishers[name] = publisher
        offset += len(records)
        if len(records) < SIDE_PAGE_SIZE:
            break
    return publishers


def fetch_operating_systems(ctx):
    """Index the operating system assigned to every inventory item. GLPI 10 does
    not keep an operatingsystems_id column on Computer; the OS lives in the
    Item_OperatingSystem relation, so one paged pass over that table replaces a
    per-item lookup. expand_dropdowns cannot be used here because it would
    rewrite items_id from the numeric item id to the item's name and destroy the
    join key, so add_keys_names is used to resolve the dropdowns alongside the
    numeric ids instead."""
    os_map = {}
    params = {
        "get_hateoas": "false",
        "add_keys_names[0]": "operatingsystems_id",
        "add_keys_names[1]": "operatingsystemversions_id",
        "add_keys_names[2]": "operatingsystemarchitectures_id",
        "add_keys_names[3]": "operatingsystemkernelversions_id",
    }
    offset = 0
    _pager2 = pager("glpi-2")
    while _pager2.next():
        records, err = fetch_page(ctx, "/Item_OperatingSystem", params, offset, SIDE_PAGE_SIZE)
        if err:
            print("glpi: failed to fetch operating systems:", err)
            return os_map
        if not records:
            break
        for record in records:
            if type(record) != "dict":
                continue
            if record.get("is_deleted"):
                continue
            names = record.get("_keys_names")
            if type(names) != "dict":
                names = {}
            key = "{}:{}".format(_text(record.get("itemtype")).strip(), record.get("items_id"))
            os_map[key] = {
                "name": _dropdown(names.get("operatingsystems_id")),
                "version": _dropdown(names.get("operatingsystemversions_id")),
                "architecture": _dropdown(names.get("operatingsystemarchitectures_id")),
                "kernel": _dropdown(names.get("operatingsystemkernelversions_id")),
                "install_date": _text(record.get("install_date")).strip(),
            }
        offset += len(records)
        if len(records) < SIDE_PAGE_SIZE:
            break
    return os_map


def fetch_and_report_items(ctx, item_type):
    """Fetch and stream one GLPI item type a page at a time so the full inventory
    is never held in memory at once. with_networkports is honored on the
    collection endpoint, so every port, MAC, and address on a page arrives with
    the page rather than costing a request per item."""
    params = {
        "expand_dropdowns": "true",
        "get_hateoas": "false",
        "with_networkports": "true",
        "is_deleted": "false",
    }
    reported = 0
    offset = 0
    _pager3 = pager("glpi-3")
    while _pager3.next():
        records, err = fetch_page(ctx, "/" + item_type, params, offset, PAGE_SIZE)
        if err:
            if err.startswith("status 401") or "ERROR_SESSION_TOKEN" in err or "ERROR_NOT_ALLOWED_IP" in err:
                print("glpi: the API session was rejected while fetching {}: {}".format(item_type, err))
            else:
                print("glpi: failed to fetch {}: {}".format(item_type, err))
            return reported
        if not records:
            break
        reported += report_assets(build_assets(ctx, item_type, records))
        offset += len(records)
        if len(records) < PAGE_SIZE:
            break

    print("glpi: reported {} assets from {}".format(reported, item_type))
    return reported


def open_session(api_url, http_options):
    """Exchange the application token and the user credential for a session
    token. Every other endpoint requires the session token, so a failure here
    ends the run."""
    data, err = get_json(api_url + "/initSession", **http_options)
    if err:
        print("glpi: failed to open an API session:", err)
        return ""
    data = data or {}
    if type(data) != "dict":
        return ""
    return _text(data.get("session_token")).strip()


def close_session(ctx):
    """Release the GLPI session. A session left open holds server-side state
    until it expires, so it is closed even when the import failed."""
    data, err = get_json(ctx["api_url"] + "/killSession", **ctx["http_options"])
    if err:
        print("glpi: failed to close the API session:", err)


def main(**kwargs):
    # get_url_base would drop the path, and GLPI is very often installed in a
    # subdirectory such as https://itsm.example.com/glpi, so the configured URL
    # is used as written.
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("glpi: no GLPI URL was configured")
        return None
    api_url = url if url.endswith(API_SUFFIX) else url + API_SUFFIX

    parsed = url_parse(url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("glpi: could not determine the GLPI host from the configured URL")
        return None

    app_token = get_string(kwargs, "app_token", default="").strip()
    user_token = get_string(kwargs, "user_token", default="").strip()
    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")

    # GLPI accepts either a personal API token or a password login on
    # initSession, and the choice is made per credential rather than per
    # instance, so exactly one of them has to be configured.
    if user_token:
        authorization = "user_token " + user_token
    elif username and password:
        authorization = basic(username, password)
    else:
        print("glpi: configure either a user API token or a username and password")
        return None

    auth_header = {"Accept": "application/json", "Authorization": authorization}
    if app_token:
        auth_header["App-Token"] = app_token

    session_token = open_session(api_url, get_http_options(kwargs, headers=auth_header))
    if not session_token:
        return None

    session_header = {"Accept": "application/json", "Session-Token": session_token}
    if app_token:
        session_header["App-Token"] = app_token
    http_options = get_http_options(kwargs, headers=session_header)

    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "api_url": api_url,
        "http_options": http_options,
        "now": now(),
        "scope": scope,
        "include_software": get_bool(kwargs, "include_software", default=True),
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "enriched": False,
        "os_map": {},
        "publishers": {},
    }

    ctx["os_map"] = fetch_operating_systems(ctx)
    if ctx["include_software"]:
        ctx["publishers"] = fetch_publishers(ctx)

    item_types = ITEM_ORDER if get_bool(kwargs, "include_network_devices", default=False) else ["Computer"]
    reported = 0
    for item_type in item_types:
        reported += fetch_and_report_items(ctx, item_type)

    if ctx["detail_skipped"]:
        print("glpi: software enrichment limit of {} reached; software was not imported for {} computers".format(
            ctx["detail_limit"], ctx["detail_skipped"]))
    if not reported:
        print("glpi: no assets retrieved")

    close_session(ctx)
    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-ocs-inventory",
    "name": "OCS Inventory NG",
    "type": "inbound",
    "description": "Imports computers, their network adapters, hardware inventory, and installed software from OCS Inventory NG.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "OCS Inventory URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ocs.example.com",
            "description": "Base URL of the OCS Inventory server. The /ocsapi/v1 REST path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": False,
            "description": "HTTP Basic user for the /ocsapi location. Leave blank when the server authorizes the Explorer by IP address instead.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": False,
            "description": "HTTP Basic password, used only together with the username field.",
        },
        {
            "key": "include_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch the per-computer software inventory. Costs one extra request per computer and a Windows host reports hundreds of titles.",
        },
        {
            "key": "software_limit",
            "label": "Software enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of computers to enrich with software. Computers past the limit are still imported, without software. 0 removes the cap.",
        },
        {
            "key": "stale_days",
            "label": "Ignore computers not seen in (days)",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Skip computers whose last agent contact is older than this many days. 0 imports every computer, including abandoned records left behind by a reimage.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'now', 'parse_ts')

load('coerce', 'dicts')
VENDOR = "ocs-inventory"
ATTR_PREFIX = "ocs_inventory"
ATTR_SEPARATOR = "_"    # to_custom_attributes joins the prefix with the separator
API_SUFFIX = "/ocsapi/v1"
# Every computer in a page drags its whole inventory with it - one SQL query per
# section per computer, roughly thirty of them - so the page stays small.
PAGE_SIZE = 50
MAX_CHILDREN = 99
MAX_LIST_VALUES = 20
DAY_SECONDS = 86400
DIGITS = "0123456789"
# OCS stores its computer groups as rows in the same hardware table as real
# computers and marks them with these reserved device identifiers. The REST
# collection routes do not filter them, so a group would otherwise be imported
# as an asset with a name and no addressing at all.
GROUP_DEVICEIDS = ["_SYSTEMGROUP_", "_DOWNLOADGROUP_"]

# The agent writes this placeholder when an adapter reports no hardware address,
# so it is never a real MAC.
NULL_MAC = "00:00:00:00:00:00"

# hardware.IPADDR is a joined list rather than a single address. The Unix agent
# joins with "/", other agents have used commas and semicolons.
ADDRESS_SEPARATORS = ["/", ",", ";", " ", "\t"]

# Interface names that are the host's own loopback.
LOOPBACK_NAMES = ["lo", "lo0", "loopback"]

# SMBIOS strings that mean "the manufacturer left this field blank". They arrive
# from the agent as ordinary values, so a serial tag built from one would be
# shared by every whitebox machine in the estate and would read as a real
# hardware identifier.
PLACEHOLDER_VALUES = [
    "0", "n/a", "na", "none", "null", "nil", "unknown", "unspecified",
    "not specified", "not available", "not applicable", "not present",
    "not defined", "no asset tag", "asset-1234567890", "default string",
    "to be filled by o.e.m.", "to be filled by oem", "system serial number",
    "chassis serial number", "base board serial number", "system manufacturer",
    "system product name", "system version", "system name", "invalid",
    "empty", "oem", "o.e.m.", "0123456789", "1234567890", "xxxxxxx",
    "00000000", "................", "no enclosure", "not settable",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
]

# The Unix agent sets networks.VIRTUALDEV from /sys/devices/virtual/net, which
# catches lo, docker0, veth, virbr, and tun devices. The Windows agent does not
# populate that column reliably, so Windows software adapters are recognized by
# their adapter description instead. Importing these MACs is how a hypervisor
# host's virtual switch ends up attached to unrelated assets.
VIRTUAL_ADAPTER_HINTS = [
    "vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "vmnet", "docker",
    "wan miniport", "wi-fi direct virtual", "kernel debug network",
    "loopback", "tap-windows", "tap adapter",
    "teredo tunneling", "isatap", "bluetooth device (personal area network)",
    "openvpn", "wintun", "tailscale", "zerotier", "virtual ethernet",
    "virtual adapter", "pppoe", "6to4 adapter",
]

# SMBIOS chassis types, in specification order. The Unix agent resolves the
# numeric dmi chassis_type through this same table before writing bios.TYPE, but
# other agents have written the raw number, so both forms are handled.
CHASSIS_TYPES = [
    "", "other", "unknown", "desktop", "low profile desktop", "pizza box",
    "mini tower", "tower", "portable", "laptop", "notebook", "hand held",
    "docking station", "all in one", "sub notebook", "space-saving",
    "lunch box", "main server chassis", "expansion chassis", "sub chassis",
    "bus expansion chassis", "peripheral chassis", "raid chassis",
    "rack mount chassis", "sealed-case pc", "multi-system", "compactpci",
    "advancedtca", "blade", "blade enclosing", "tablet", "convertible",
    "detachable", "iot gateway", "embedded pc", "mini pc", "stick pc",
]

DEVICE_TYPES = {
    "desktop": "Desktop",
    "low profile desktop": "Desktop",
    "pizza box": "Desktop",
    "mini tower": "Desktop",
    "tower": "Desktop",
    "all in one": "Desktop",
    "space-saving": "Desktop",
    "lunch box": "Desktop",
    "sealed-case pc": "Desktop",
    "embedded pc": "Desktop",
    "mini pc": "Desktop",
    "stick pc": "Desktop",
    "portable": "Laptop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "sub notebook": "Laptop",
    "convertible": "Laptop",
    "detachable": "Laptop",
    "tablet": "Tablet",
    "hand held": "Mobile Device",
    "main server chassis": "Server",
    "rack mount chassis": "Server",
    "expansion chassis": "Server",
    "blade": "Server",
    "blade enclosing": "Server",
    "multi-system": "Server",
    "compactpci": "Server",
    "advancedtca": "Server",
    "raid chassis": "Storage",
}

# A guest reports the hypervisor's synthetic board rather than a chassis, so the
# SMBIOS system manufacturer and model are what identify it.
VIRTUAL_HINTS = [
    "vmware", "virtualbox", "innotek", "qemu", "kvm", "bochs", "xen",
    "hvm domu", "virtual machine", "virtual platform", "parallels",
    "openstack", "amazon ec2", "google compute engine", "alibaba cloud",
    "bhyve", "apple virtualization", "utm",
]

def _text(value):
    """Flatten a scalar or list into a plain string. Every OCS section is a SQL
    row rendered by DBI, which returns integer columns as JSON strings on some
    driver versions and as numbers on others, so nothing may be assumed to
    already be text."""
    if value == None:
        return ""
    if type(value) == "list":
        return ",".join([_text(item) for item in value if item != None])
    return str(value)

def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is not
    numeric."""
    if type(value) == "int":
        return value
    text = _text(value).strip()
    if not text or len(text) > 12:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)

def _truthy(value):
    """Read an OCS boolean column. The schema declares these as tinyint but the
    agents write the strings "1" and "0", and DBI may hand either back."""
    if value == None:
        return False
    if type(value) == "bool":
        return value
    if type(value) == "int":
        return value != 0
    text = _text(value).strip().lower()
    if not text:
        return False
    return text not in ["0", "false", "no"]
def _agent_registered(deviceid):
    """Recover the moment the OCS agent minted its DEVICEID. The agent builds it
    once, on its first run, as "<hostname>-YYYY-MM-DD-HH-MM-SS" and then keeps it
    in its local state file, so the trailing timestamp is the closest thing OCS
    has to a first-seen time for the record. The hostname itself may contain
    dashes, so the six fields are taken from the end and every one of them is
    validated before it is parsed."""
    parts = deviceid.split("-")
    if len(parts) < 7:
        return None
    tail = parts[-6:]
    if len(tail[0]) != 4:
        return None
    for index in range(1, 6):
        if len(tail[index]) != 2:
            return None
    return parse_ts("{}-{}-{} {}:{}:{}".format(
        tail[0], tail[1], tail[2], tail[3], tail[4], tail[5]))
def _meaningful(value):
    """Return a hardware identity string, or an empty string when the field
    holds one of the SMBIOS placeholders that mean the manufacturer never filled
    it in. Applied to every serial number, asset tag, UUID, manufacturer, and
    model, because those are the values that become tags and merge signals."""
    text = _text(value).strip()
    if text.lower() in PLACEHOLDER_VALUES:
        return ""
    return text
def _first(value):
    """Return the single row of a one-per-computer section. The API renders even
    these as a list because every section is answered with the same
    select-all-rows helper."""
    rows = dicts(value)
    if not rows:
        return {}
    return rows[0]

def _values(rows, field):
    """Collect the distinct non-empty values of one column across a section."""
    found = []
    for row in rows:
        text = _meaningful(row.get(field))
        if text and text not in found and len(found) < MAX_LIST_VALUES:
            found.append(text)
    return found

def _sum_int(rows, field):
    """Total one numeric column across a section, ignoring rows whose value is
    absent or not a number. Returns an empty string when nothing summed, so the
    attribute is dropped rather than reported as a misleading zero."""
    total = 0
    counted = 0
    for row in rows:
        number = _to_int(row.get(field))
        if number > 0:
            total += number
            counted += 1
    if not counted:
        return ""
    return total
def _split_addresses(value):
    """Split the joined hardware.IPADDR string into individual addresses. The
    Unix agent joins with a slash, other agents have used commas or spaces, and
    its IPv6 branch is known to emit mangled values, so each candidate is
    validated rather than trusted."""
    text = _text(value)
    for separator in ADDRESS_SEPARATORS:
        text = text.replace(separator, "\n")
    addresses = []
    for candidate in text.split("\n"):
        routable = routable_ip(candidate.strip())
        if routable and routable not in addresses:
            addresses.append(routable)
    return addresses

def _is_virtual_adapter(description, adapter_type):
    """Decide whether an adapter is a software device rather than real hardware.
    The Unix agent puts the interface name in DESCRIPTION and the Windows agent
    puts the adapter's product description there, so both spellings of the same
    device have to be recognized from the same field."""
    for text in [description, adapter_type]:
        lowered = text.lower()
        if not lowered:
            continue
        if lowered in LOOPBACK_NAMES:
            return True
        for hint in VIRTUAL_ADAPTER_HINTS:
            if hint in lowered:
                return True
    return False

def build_software(ctx, computer_id, entries):
    """Convert the software installations OCS records against one computer into
    Software records. The per-computer software route resolves the normalized
    name, publisher, and version tables, so the rows carry text rather than the
    bare NAME_ID and PUBLISHER_ID foreign keys the bulk listing returns. OCS
    publishes no CPE for an installation, so cpe23 is left unset rather than
    synthesized."""
    software = []
    seen = []
    for entry in dicts(entries):
        product = _text(entry.get("NAME")).strip()
        if not product:
            continue
        version = _text(entry.get("VERSION")).strip()
        key = "{}:{}".format(product, version)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:{}:software:{}".format(VENDOR, ctx["scope"], computer_id, key),
            "product": product,
            "serviceAddress": "127.0.0.1",
        }
        if version:
            params["version"] = version
        publisher = _text(entry.get("PUBLISHER")).strip()
        if publisher:
            params["vendor"] = publisher
        params["customAttributes"] = to_custom_attributes({
            "software_folder": _text(entry.get("FOLDER")).strip(),
            "software_guid": _text(entry.get("GUID")).strip(),
            "software_language": _text(entry.get("LANGUAGE")).strip(),
            "software_install_date": _text(entry.get("INSTALLDATE")).strip(),
            "software_bits": _text(entry.get("BITSWIDTH")).strip(),
            "software_architecture": _text(entry.get("ARCHITECTURE")).strip(),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software

def collect_adapters(rows):
    """Sort the networks section into the adapters worth importing and the
    software devices that are not. A virtual adapter is dropped outright: OCS
    faithfully reports every VMware, Hyper-V, docker, tunnel, and WAN miniport
    device, and those MACs belong to the hypervisor stack rather than to the
    host, so importing them invents merge signals that point at the wrong asset.
    A disabled adapter keeps its MAC, which is stable hardware, but loses its
    addresses, which are no longer bound to anything."""
    adapters = []
    skipped = []
    for row in rows:
        name = _text(row.get("DESCRIPTION")).strip()
        adapter_type = _text(row.get("TYPE")).strip()
        if _truthy(row.get("VIRTUALDEV")) or _is_virtual_adapter(name, adapter_type):
            if name and name not in skipped and len(skipped) < MAX_LIST_VALUES:
                skipped.append(name)
            continue

        mac = _text(row.get("MACADDR")).strip()
        if mac.lower() == NULL_MAC:
            mac = ""

        status = _text(row.get("STATUS")).strip()
        ips = []
        if status.lower() != "down":
            routable = routable_ip(row.get("IPADDRESS"))
            if routable:
                ips.append(routable)

        if not mac and not ips:
            continue
        adapters.append({
            "name": name,
            "type": adapter_type,
            "mac": mac,
            "ips": ips,
            "status": status,
            "speed": _text(row.get("SPEED")).strip(),
            "netmask": _text(row.get("IPMASK")).strip(),
            "gateway": _text(row.get("IPGATEWAY")).strip(),
            "dhcp": _text(row.get("IPDHCP")).strip(),
        })
    return adapters, skipped

def build_interfaces(adapters, fallback_ips):
    """Build one runZero network interface per physical OCS adapter, so a
    multi-homed host keeps its per-NIC addressing. When no adapter survived the
    filter, the joined hardware.IPADDR list becomes a single address-only
    interface rather than losing the host's addressing entirely."""
    interfaces = []
    for adapter in adapters:
        nic = network_interface(mac=adapter["mac"], ips=adapter["ips"])
        if nic:
            interfaces.append(nic)
    if interfaces or not fallback_ips:
        return interfaces
    nic = network_interface(ips=fallback_ips)
    if nic:
        interfaces.append(nic)
    return interfaces

def build_device_type(chassis, manufacturer, model):
    """Map the SMBIOS chassis type OCS records in bios.TYPE onto a runZero device
    type, falling back to the system manufacturer and model when the chassis is
    absent or reported as Other, which is what a hypervisor guest reports."""
    lowered = chassis.lower()
    numeric = _to_int(lowered)
    if numeric >= 0 and numeric < len(CHASSIS_TYPES):
        lowered = CHASSIS_TYPES[numeric]
    device_type = DEVICE_TYPES.get(lowered, "")
    if device_type:
        return device_type
    identity = "{} {}".format(manufacturer, model).lower()
    for hint in VIRTUAL_HINTS:
        if hint in identity:
            return "Virtual Machine"
    return ""

def build_asset(ctx, computer_id, record):
    """Convert one OCS computer, with every inventory section the API returned
    alongside it, into a runZero asset."""
    hardware = record["hardware"]
    bios = _first(record.get("bios"))
    account = _first(record.get("accountinfo"))
    networks = dicts(record.get("networks"))
    storages = dicts(record.get("storages"))
    drives = dicts(record.get("drives"))
    memories = dicts(record.get("memories"))
    controllers = dicts(record.get("controllers"))
    monitors = dicts(record.get("monitors"))
    printers = dicts(record.get("printers"))
    videos = dicts(record.get("videos"))
    cpus = dicts(record.get("cpus"))
    machines = dicts(record.get("virtualmachines"))

    adapters, virtual_adapters = collect_adapters(networks)
    host_ips = _split_addresses(hardware.get("IPADDR"))
    netifs = build_interfaces(adapters, host_ips)

    name = _text(hardware.get("NAME")).strip()
    deviceid = _text(hardware.get("DEVICEID")).strip()
    serial = _meaningful(bios.get("SSN"))
    manufacturer = _meaningful(bios.get("SMANUFACTURER"))
    model = _meaningful(bios.get("SMODEL"))
    chassis = _text(bios.get("TYPE")).strip()
    # OCS writes the literal "NA" into accountinfo.TAG for every computer that
    # has never been given one, which is the default state, so this goes through
    # _meaningful() rather than _text(). Taking it verbatim puts an identical
    # tag:NA on 100% of the estate and buries any real tag among them.
    tag = _meaningful(account.get("TAG"))
    workgroup = _text(hardware.get("WORKGROUP")).strip()

    tags = [VENDOR]
    if serial:
        tags.append("serial:" + serial)
    if tag:
        tags.append("tag:" + tag)

    software = ctx["software"]
    attrs = {
        "computer_id": computer_id,
        "deviceid": deviceid,
        "server": ctx["scope"],
        "name": name,
        "description": _text(hardware.get("DESCRIPTION")).strip(),
        "uuid": _meaningful(hardware.get("UUID")),
        "serial": serial,
        "asset_tag": _meaningful(bios.get("ASSETTAG")),
        "motherboard_manufacturer": _meaningful(bios.get("MMANUFACTURER")),
        "motherboard_model": _meaningful(bios.get("MMODEL")),
        "motherboard_serial": _meaningful(bios.get("MSN")),
        "system_manufacturer": manufacturer,
        "system_model": model,
        "chassis_type": chassis,
        "bios_manufacturer": _text(bios.get("BMANUFACTURER")).strip(),
        "bios_version": _text(bios.get("BVERSION")).strip(),
        "bios_date": _text(bios.get("BDATE")).strip(),
        "workgroup": workgroup,
        "user_domain": _text(hardware.get("USERDOMAIN")).strip(),
        "user": _text(hardware.get("USERID")).strip(),
        "tag": tag,
        "os_name": _text(hardware.get("OSNAME")).strip(),
        "os_version": _text(hardware.get("OSVERSION")).strip(),
        "os_comments": _text(hardware.get("OSCOMMENTS")).strip(),
        "architecture": _text(hardware.get("ARCH")).strip(),
        "memory_mb": _text(hardware.get("MEMORY")).strip(),
        "swap_mb": _text(hardware.get("SWAP")).strip(),
        "processor_type": _text(hardware.get("PROCESSORT")).strip(),
        "processor_speed_mhz": _text(hardware.get("PROCESSORS")).strip(),
        "processor_count": _text(hardware.get("PROCESSORN")).strip(),
        # IPADDR is what the agent saw locally; IPSRC is the address the server
        # saw the agent connect from, so the pair exposes NAT and VPN paths.
        "ip_addresses": host_ips,
        "reported_ip_addresses": _text(hardware.get("IPADDR")).strip(),
        "source_ip": _text(hardware.get("IPSRC")).strip(),
        "default_gateway": _text(hardware.get("DEFAULTGATEWAY")).strip(),
        "dns": _text(hardware.get("DNS")).strip(),
        "agent_version": _text(hardware.get("USERAGENT")).strip(),
        "last_inventory": _text(hardware.get("LASTDATE")).strip(),
        "last_contact": _text(hardware.get("LASTCOME")).strip(),
        "archived": _text(hardware.get("ARCHIVE")).strip(),
        # The Windows product key also lives on this row and is deliberately
        # never copied out of it.
        "windows_company": _text(hardware.get("WINCOMPANY")).strip(),
        "windows_owner": _text(hardware.get("WINOWNER")).strip(),
        "windows_product_id": _text(hardware.get("WINPRODID")).strip(),
        "adapter_count": len(adapters),
        "adapter_names": [adapter["name"] for adapter in adapters if adapter["name"]],
        "adapter_types": _values(adapters, "type"),
        "adapter_speeds": _values(adapters, "speed"),
        "virtual_adapters": virtual_adapters,
        "cpu_model": ",".join(_values(cpus, "TYPE")),
        "cpu_manufacturer": ",".join(_values(cpus, "MANUFACTURER")),
        "cpu_architecture": ",".join(_values(cpus, "CPUARCH")),
        "cpu_speed_mhz": ",".join(_values(cpus, "SPEED")),
        "cpu_count": len(cpus),
        "cpu_cores": _sum_int(cpus, "CORES"),
        "memory_modules": len(memories),
        "memory_installed_mb": _sum_int(memories, "CAPACITY"),
        "memory_types": _values(memories, "TYPE"),
        "disk_count": len(storages),
        "disk_total_mb": _sum_int(storages, "DISKSIZE"),
        "disk_models": _values(storages, "MODEL"),
        "disk_serials": _values(storages, "SERIALNUMBER"),
        "volume_count": len(drives),
        "volume_total_mb": _sum_int(drives, "TOTAL"),
        "volume_free_mb": _sum_int(drives, "FREE"),
        "volume_filesystems": _values(drives, "FILESYSTEM"),
        "controller_count": len(controllers),
        "controller_names": _values(controllers, "NAME"),
        "monitor_count": len(monitors),
        "monitor_models": _values(monitors, "CAPTION"),
        "monitor_serials": _values(monitors, "SERIAL"),
        "printer_count": len(printers),
        "printer_names": _values(printers, "NAME"),
        "video_names": _values(videos, "NAME"),
        "video_resolutions": _values(videos, "RESOLUTION"),
        # A populated virtualmachines section means this host is running guests,
        # which is worth knowing about an asset discovered on the network.
        "hosted_vm_count": len(machines),
        "hosted_vm_names": _values(machines, "NAME"),
        "software_count": len(software),
        "software_enriched": "true" if ctx["enriched"] else "false",
    }

    params = {
        # The OCS computer id is authoritative for the server, but an OCS record
        # is renamed by hand, keeps stale addressing once an agent stops
        # reporting, and is routinely duplicated when an agent re-registers, so
        # network churn must not disqualify a merge.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], computer_id),
        "hostnames": [name],
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model

    device_type = build_device_type(chassis, manufacturer, model)
    if device_type:
        params["deviceType"] = device_type

    os_name = _text(hardware.get("OSNAME")).strip()
    if os_name:
        params["os"] = os_name
    os_version = _text(hardware.get("OSVERSION")).strip()
    if os_version:
        params["osVersion"] = os_version

    # A Windows host that joined no domain reports the literal string WORKGROUP,
    # which would otherwise become a domain shared by every standalone machine.
    if workgroup and workgroup.lower() != "workgroup":
        params["domain"] = workgroup

    first_ts = _agent_registered(deviceid)
    if first_ts:
        params["firstSeenTS"] = first_ts
    # LASTCOME is written every time the agent contacts the server, LASTDATE only
    # when it delivers a full inventory, so LASTCOME is the better last-seen.
    last_ts = parse_ts(hardware.get("LASTCOME")) or parse_ts(hardware.get("LASTDATE"))
    last_ts = last_ts

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset

def fetch_software(ctx, computer_id):
    """Fetch the software installed on one computer. The bulk listing carries the
    software rows with their name, publisher, and version left as foreign keys
    into the normalized software_name, software_publisher, and software_version
    tables, and only this route resolves them, so software costs one request per
    computer. A failure is reported and treated as an empty inventory so one
    unreadable computer cannot end the run."""
    url = "{}/computer/{}/software".format(ctx["api_url"], computer_id)
    data, err = get_json(url, **ctx["http_options"])
    if err:
        print("ocs-inventory: failed to fetch software for computer {}: {}".format(computer_id, err))
        return []
    data = data or {}
    if type(data) != "dict":
        return []
    record = data.get(_text(computer_id))
    if type(record) != "dict":
        return []
    rows = record.get("software")
    if type(rows) != "list":
        # The single-computer route renders the same resolved rows under an empty
        # key when no section was named in the path.
        rows = record.get("", [])
    return rows

def build_assets(ctx, page):
    """Convert one page of OCS computers into runZero assets, enriching them with
    their software inventory until the enrichment limit is reached."""
    assets = []
    for key in page:
        record = page[key]
        if type(record) != "dict":
            continue
        # The route renders the hardware row as an object and everything else as
        # an array. A record without one describes no computer at all.
        hardware = record.get("hardware")
        if type(hardware) != "dict":
            print("ocs-inventory: skipping computer {} with no hardware section".format(_text(key)))
            continue
        # The response is keyed by the same id the hardware row carries, so the
        # key is a faithful fallback rather than an invented identity.
        computer_id = _text(hardware.get("ID")).strip() or _text(key).strip()
        if not computer_id:
            print("ocs-inventory: skipping computer with no id: name=" + _text(hardware.get("NAME")))
            continue

        # Computer groups live in the same table as computers and are returned by
        # the same route.
        if _text(hardware.get("DEVICEID")).strip() in GROUP_DEVICEIDS:
            continue

        if ctx["stale_cutoff"]:
            last_ts = parse_ts(hardware.get("LASTCOME")) or parse_ts(hardware.get("LASTDATE"))
            if last_ts == None or last_ts.unix < ctx["stale_cutoff"]:
                ctx["stale_skipped"] += 1
                continue

        ctx["software"] = []
        ctx["enriched"] = False
        if ctx["include_software"]:
            if ctx["software_limit"] and ctx["software_used"] >= ctx["software_limit"]:
                ctx["software_skipped"] += 1
            else:
                ctx["software_used"] += 1
                ctx["enriched"] = True
                ctx["software"] = build_software(ctx, computer_id, fetch_software(ctx, computer_id))

        assets.append(build_asset(ctx, computer_id, record))
    return assets

def fetch_and_report_computers(ctx):
    """Fetch and stream OCS computers one page at a time so the full inventory is
    never held in memory at once. Every inventory section for a page arrives with
    the page, so only software costs an extra request."""
    reported = 0
    start = 0
    prev_signature = None
    _pager = pager("ocs-inventory")
    while _pager.next():
        # limit is mandatory: the route answers a missing or zero limit with a
        # server error rather than a default page size.
        data, err = get_json(ctx["api_url"] + "/computers",
                             params={"start": start, "limit": PAGE_SIZE},
                             **ctx["http_options"])
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("ocs-inventory: the REST API rejected the credential; check the Require directive on the /ocsapi location:", err)
            else:
                print("ocs-inventory: failed to fetch computers:", err)
            return reported
        # An offset past the end of the table renders as a bare JSON null.
        data = data or {}
        if type(data) != "dict":
            print("ocs-inventory: unexpected response type {} from the computers route".format(type(data)))
            return reported
        if not data:
            break
        # A server whose route ignores `start` replays page one forever, and a
        # full replayed page never trips the short-page exit. Stop on the first
        # repeat, BEFORE reporting, so the page is not imported twice.
        signature = (len(data), str(sorted(data.keys())))
        if signature == prev_signature:
            print("ocs-inventory: the computers route repeated a page at start={}; stopping to avoid re-importing".format(start))
            break
        prev_signature = signature
        reported += report_assets(build_assets(ctx, data))
        if len(data) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    print("ocs-inventory: reported {} computers".format(reported))
    return reported

def main(**kwargs):
    # get_url_base would drop the path, and OCS is very often installed behind a
    # reverse proxy on a subdirectory, so the configured URL is used as written.
    url = get_string(kwargs, "url", default="").strip().rstrip("/")
    if not url:
        print("ocs-inventory: no OCS Inventory URL was configured")
        return None
    api_url = url if url.endswith(API_SUFFIX) else url + API_SUFFIX

    parsed = url_parse(url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        fail("ocs-inventory: could not determine the OCS host from the configured URL")

    headers = {"Accept": "application/json"}
    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")
    # The shipped Apache configuration guards /ocsapi with an IP allow list and
    # defines no user database, so a credential is genuinely optional here.
    if username and password:
        headers["Authorization"] = basic(username, password)
    elif username or password:
        print("ocs-inventory: configure both a username and a password, or neither")
        return None

    software_limit = get_int(kwargs, "software_limit", default=1000)
    if software_limit < 0:
        software_limit = 0
    stale_days = get_int(kwargs, "stale_days", default=0)
    current = now()
    stale_cutoff = 0
    if stale_days > 0:
        stale_cutoff = current.unix - stale_days * DAY_SECONDS

    ctx = {
        "api_url": api_url,
        "now": current,
        "http_options": get_http_options(kwargs, headers=headers),
        "scope": scope,
        "include_software": get_bool(kwargs, "include_software", default=False),
        "software_limit": software_limit,
        "software_used": 0,
        "software_skipped": 0,
        "software": [],
        "enriched": False,
        "stale_cutoff": stale_cutoff,
        "stale_skipped": 0,
    }

    reported = fetch_and_report_computers(ctx)

    if ctx["stale_skipped"]:
        print("ocs-inventory: skipped {} computers not seen in {} days".format(
            ctx["stale_skipped"], stale_days))
    if ctx["software_skipped"]:
        print("ocs-inventory: software enrichment limit of {} reached; software was not imported for {} computers".format(
            ctx["software_limit"], ctx["software_skipped"]))
    if not reported:
        print("ocs-inventory: no assets retrieved")
    return None

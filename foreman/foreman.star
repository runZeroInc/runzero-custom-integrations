# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-foreman",
    "name": "Foreman",
    "type": "inbound",
    "description": "Imports hosts, their network interfaces, Facter hardware facts, and Katello package inventory from Foreman.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Foreman URL",
            "type": "url",
            "required": True,
            "placeholder": "https://foreman.example.com",
            "description": "Base URL of the Foreman server. The /api/v2 path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Foreman user with view_hosts and view_facts permissions.",
        },
        {
            "key": "password",
            "label": "Password or Personal Access Token",
            "type": "secret",
            "required": True,
            "description": "Password of the Foreman user, or a Personal Access Token for that user. Foreman accepts a token anywhere a password is accepted, and a token is preferred.",
        },
        {
            "key": "search",
            "label": "Host search filter",
            "type": "string",
            "required": False,
            "description": "Optional Foreman search query applied to the host list, for example 'organization = Acme' or 'managed = true'. Leave blank to import every host the user can see.",
        },
        {
            "key": "include_facts",
            "label": "Import Facter facts",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch hardware, OS, and per-interface facts in bulk from the fact_values endpoint. This is what supplies serial numbers, manufacturer, CPU, memory, and multi-NIC addressing.",
        },
        {
            "key": "include_interfaces",
            "label": "Fetch the interface list per host",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Issue one extra request per host to read Foreman's own interface records, which add bonds, VLANs, and subnet names. Off by default because it is one request per host; the facts already carry per-interface addressing.",
        },
        {
            "key": "include_packages",
            "label": "Import Katello package inventory",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch installed RPM packages from Katello, Red Hat Satellite, or orcharhino. Costs one extra request per host and is silently skipped on a plain Foreman install, which has no package inventory.",
        },
        {
            "key": "detail_limit",
            "label": "Per-host request limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of hosts to enrich with the per-host interface and package requests. Hosts past the limit are still imported without them. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Hosts per page",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
            "description": "Hosts requested per page of the host list.",
        },
        {
            "key": "fact_page_size",
            "label": "Fact values per page",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "max": 10000,
            "description": "Fact values requested per page. Foreman pages this endpoint by individual fact value, not by host, so a larger page covers more hosts per request.",
        },
        {
            "key": "extra_facts",
            "label": "Additional fact names",
            "type": "string",
            "required": False,
            "description": "Comma-separated Foreman fact names to import in addition to the built-in set, for example 'ansible_processor_count,rhsm::role'. Nested facts use :: as the separator.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_http_options', 'get_string', 'get_int', 'get_bool', 'get_list')
load('time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "foreman"
ATTR_PREFIX = "foreman"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

HOSTS_PATH = "/api/v2/hosts"
FACT_VALUES_PATH = "/api/v2/fact_values"

MAX_CHILDREN = 99

# Foreman flattens a structured Facter fact tree into single keys joined with
# this separator (FactName::SEPARATOR in app/models/fact_name.rb), so
# {"dmi": {"product": {"serial_number": "X"}}} is stored as
# dmi::product::serial_number.
FACT_SEPARATOR = "::"
IFACE_FACT_PREFIX = "networking::interfaces::"
IFACE_FACT_LEAVES = ["mac", "ip", "ip6"]

# A dotted numeric token, used to find where an OS name stops and its version
# starts in Foreman's combined operatingsystem_name string.
VERSION_RE = r"^[0-9]+(\.[0-9]+)*$"

# The facts worth importing. Foreman pages the fact_values endpoint by
# individual fact value rather than by host, so an unfiltered walk would read
# every one of the several hundred facts each host reports. Naming the facts
# that are actually mapped keeps the walk proportional to the estate instead.
# Both the Facter 4 structured names and the legacy flat names are requested,
# because which set a host reports depends on the agent that uploaded it.
FACT_NAMES = [
    "dmi::manufacturer",
    "dmi::product::name",
    "dmi::product::serial_number",
    "dmi::product::uuid",
    "dmi::bios::vendor",
    "dmi::bios::version",
    "dmi::bios::release_date",
    "dmi::chassis::type",
    "processors::count",
    "processors::physicalcount",
    "processors::isa",
    "processors::models",
    "memory::system::total_bytes",
    "memory::system::total",
    "os::name",
    "os::family",
    "os::architecture",
    "os::hardware",
    "os::release::full",
    "os::distro::description",
    "os::selinux::enabled",
    "networking::fqdn",
    "networking::hostname",
    "networking::domain",
    "networking::primary",
    "networking::ip",
    "networking::ip6",
    "networking::mac",
    "system_uptime::seconds",
    "cloud::provider",
    "virtual",
    "is_virtual",
    "kernel",
    "kernelrelease",
    "kernelversion",
    "manufacturer",
    "productname",
    "serialnumber",
    "uuid",
    "architecture",
    "operatingsystem",
    "operatingsystemrelease",
    "osfamily",
    "lsbdistdescription",
    "processorcount",
    "physicalprocessorcount",
    "memorysize_mb",
    "memorytotal",
    "fqdn",
    "hostname",
    "domain",
    "ipaddress",
    "ipaddress6",
    "macaddress",
    "bios_version",
    "bios_vendor",
    "timezone",
    "uptime_seconds",
]

# Interface names are part of the fact name, so the per-interface facts cannot
# be named individually and are matched by prefix instead. Foreman's ~ operator
# compiles to a SQL LIKE.
FACT_PREFIXES = [IFACE_FACT_PREFIX]

# Loopback device names, dropped before interfaces are built.
LOOPBACK_IDENTIFIERS = ["lo", "lo0", "loopback"]

# An all-zero MAC means the source could not read one. Every host in that state
# would share a MAC, so it is dropped like loopback is.
EMPTY_MAC = "00:00:00:00:00:00"

# A BMC interface describes the service processor, which is a separate network
# endpoint with its own address and MAC. Folding it into the host would make
# runZero merge the BMC's own asset into the server it manages.
SKIP_INTERFACE_TYPES = ["bmc"]

# dmi::chassis::type as Facter reports it, lower-cased. Anything else is left
# unmapped so runZero's own fingerprinting decides.
CHASSIS_TYPES = {
    "desktop": "Desktop",
    "low profile desktop": "Desktop",
    "mini tower": "Desktop",
    "tower": "Desktop",
    "space-saving": "Desktop",
    "all in one": "Desktop",
    "notebook": "Laptop",
    "laptop": "Laptop",
    "portable": "Laptop",
    "sub notebook": "Laptop",
    "convertible": "Laptop",
    "detachable": "Laptop",
    "tablet": "Tablet",
    "hand held": "Mobile Device",
    "rack mount chassis": "Server",
    "main server chassis": "Server",
    "blade": "Server",
    "blade enclosure": "Server",
    "multi-system chassis": "Server",
    "expansion chassis": "Server",
}

# Values of the Facter virtual fact that mean the host is running on bare metal.
PHYSICAL_VIRTUAL = ["physical", "", "none"]
def _base_url(kwargs):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used: it keeps only the scheme and host and
    discards the path -- verified against the scanner, https://proxy/foreman
    comes back as https://proxy. Foreman is commonly published through a reverse
    proxy under a path prefix, and Katello's own documentation covers serving it
    that way, so dropping the path would send every /api/v2 and
    /katello/api/v2 request to the wrong place on those installs. librenms,
    netdisco and slurpit avoid it for the same reason.
    """
    return as_text(get_string(kwargs, "url", default=""), join=",").strip().rstrip("/")
def _fact(facts, names):
    """Return the first non-empty value among the named facts. Foreman stores
    every fact value as a string and writes a null for the composite parent of a
    nested fact, so both have to be screened out."""
    for name in names:
        value = facts.get(name)
        if value == None:
            continue
        text = as_text(value, join=",").strip()
        if text:
            return text
    return ""

def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable. The
    all-zero MAC is treated as absent because every host that fails to read one
    reports it."""
    mac = normalize_mac(as_text(value, join=",").strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac

def split_os_version(combined):
    """Split Foreman's combined operatingsystem_name into a name and a version.

    Foreman builds this field from the operating system's own to_label, which is
    "<name> <major>.<minor>" - "RedHat 9.4", "CentOS Stream 9", "Debian 12" - so
    the first dotted numeric token starts the version."""
    parts = [part for part in as_text(combined, join=",").strip().split(" ") if part]
    if len(parts) < 2:
        return " ".join(parts), ""
    for index in range(1, len(parts)):
        if re_match(VERSION_RE, parts[index]):
            return " ".join(parts[:index]), " ".join(parts[index:])
    return " ".join(parts), ""

def split_nvra(name, nvra):
    """Split a Katello package NVRA into version, release, and architecture.

    Katello publishes the package name and the assembled "name-version-release.arch"
    string but never the components on their own, so bash-5.1.8-9.el9.x86_64 has
    to be taken apart here."""
    rest = as_text(nvra, join=",").strip()
    if not rest:
        return "", "", ""
    if name and rest.startswith(name + "-"):
        rest = rest[len(name) + 1:]
    arch = ""
    dot = rest.rfind(".")
    if dot > 0:
        arch = rest[dot + 1:]
        rest = rest[:dot]
    release = ""
    dash = rest.rfind("-")
    if dash > 0:
        release = rest[dash + 1:]
        rest = rest[:dash]
    return rest, release, arch

def build_software(ctx, host_id, address, packages):
    """Convert the installed packages Katello records against one host into
    Software records. Katello publishes no CPE for an installed package, so
    cpe23 is left unset rather than synthesized."""
    software = []
    seen = []
    for entry in packages:
        product = as_text(entry.get("name"), join=",").strip()
        if not product:
            continue
        nvra = as_text(entry.get("nvra"), join=",").strip()
        key = as_text(entry.get("nvrea"), join=",").strip() or nvra or product
        if key in seen:
            continue
        seen.append(key)

        version, release, arch = split_nvra(product, nvra)
        params = {
            "id": "{}:{}:{}:package:{}".format(VENDOR, ctx["scope"], host_id, key)[:255],
            "product": product[:255],
            "serviceAddress": address or "127.0.0.1",
        }
        if version:
            params["version"] = version[:255]
        if release:
            params["update"] = release[:255]
        if arch:
            params["targetHardware"] = arch[:255]

        params["customAttributes"] = to_custom_attributes({
            "package_id": entry.get("id"),
            "package_nvra": nvra,
            "package_nvrea": entry.get("nvrea"),
            "package_rpm_id": entry.get("rpm_id"),
            "package_upgradable_versions": entry.get("upgradable_versions"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software

def collect_interfaces(facts, entries):
    """Group everything known about each of a host's interfaces into one entry
    per device name.

    Facter reports a host's addressing per interface and Foreman flattens that
    into networking::interfaces::<device>::<mac|ip|ip6>, which is the only bulk
    source of multi-NIC data the API has. Foreman's own interface records carry
    the same devices plus bonds, VLANs, and subnet names, but only on the
    per-host response, so they are merged in when that was fetched."""
    ifaces = {}
    for key in facts:
        if not key.startswith(IFACE_FACT_PREFIX):
            continue
        parts = key[len(IFACE_FACT_PREFIX):].split(FACT_SEPARATOR)
        if len(parts) != 2 or parts[1] not in IFACE_FACT_LEAVES:
            continue
        text = as_text(facts[key], join=",").strip()
        if not text:
            continue
        item = ifaces.setdefault(parts[0], {"identifier": parts[0], "mac": "", "ips": []})
        if parts[1] == "mac":
            item["mac"] = text
        else:
            routable = routable_ip(text)
            if routable and routable not in item["ips"]:
                item["ips"].append(routable)

    for entry in dicts(entries):
        if as_text(entry.get("type"), join=",").strip().lower() in SKIP_INTERFACE_TYPES:
            continue
        name = as_text(entry.get("identifier"), join=",").strip() or as_text(entry.get("name"), join=",").strip()
        if not name:
            continue
        item = ifaces.setdefault(name, {"identifier": name, "mac": "", "ips": []})
        mac = as_text(entry.get("mac"), join=",").strip()
        if mac:
            item["mac"] = mac
        for value in [entry.get("ip"), entry.get("ip6")]:
            routable = routable_ip(value)
            if routable and routable not in item["ips"]:
                item["ips"].append(routable)
    return ifaces

def merge_interfaces(ifaces, host_mac, host_ips):
    """Reduce the per-device entries to the set that becomes network interfaces.

    Loopback devices are dropped outright, devices that report the same MAC are
    folded together, and the address and MAC held on the host record itself are
    added last so a host with no facts at all still gets an interface."""
    merged = []
    seen_macs = {}
    for name in ifaces:
        if name.lower() in LOOPBACK_IDENTIFIERS:
            continue
        entry = ifaces[name]
        mac = _clean_mac(entry["mac"])
        if mac and mac in seen_macs:
            # A bond and its slaves, and a VLAN device and its parent, all report
            # the same MAC. They are one interface as far as runZero is
            # concerned, so their addresses are pooled under one record.
            target = merged[seen_macs[mac]]
            target["identifiers"].append(name)
            for ip in entry["ips"]:
                if ip not in target["ips"]:
                    target["ips"].append(ip)
            continue
        if not mac and not entry["ips"]:
            continue
        if mac:
            seen_macs[mac] = len(merged)
        merged.append({"identifiers": [name], "mac": mac, "ips": list(entry["ips"])})

    mac = _clean_mac(host_mac)
    if mac and mac in seen_macs:
        target = merged[seen_macs[mac]]
        for ip in host_ips:
            if ip not in target["ips"]:
                target["ips"].append(ip)
        return merged

    remaining = []
    for ip in host_ips:
        placed = False
        for entry in merged:
            if ip in entry["ips"]:
                placed = True
        if not placed and ip not in remaining:
            remaining.append(ip)
    if mac or remaining:
        merged.append({"identifiers": ["primary"], "mac": mac, "ips": remaining})
    return merged

def build_interfaces(merged):
    """Build one runZero network interface per Foreman interface, so a
    multi-homed host keeps its per-NIC addressing instead of being collapsed
    onto a single address."""
    netifs = []
    for entry in merged:
        nic = network_interface(mac=entry["mac"], ips=entry["ips"])
        if nic:
            netifs.append(nic)
    return netifs

def build_asset(ctx, record, facts, detail, packages):
    """Convert one Foreman host record into a runZero asset."""
    host_id = record.get("id")
    name = as_text(record.get("name"), join=",").strip()
    certname = as_text(record.get("certname"), join=",").strip()

    host_ips = []
    for value in [record.get("ip"), record.get("ip6")]:
        routable = routable_ip(value)
        if routable and routable not in host_ips:
            host_ips.append(routable)
    merged = merge_interfaces(
        collect_interfaces(facts, as_dict(detail).get("interfaces")),
        record.get("mac"),
        host_ips,
    )
    netifs = build_interfaces(merged)

    # Software records need a service address; the host record's own address is
    # the one Foreman treats as primary, so it wins over whatever interface the
    # facts happened to list first.
    primary_ip = host_ips[0] if host_ips else ""
    for entry in merged:
        for ip in entry["ips"]:
            if not primary_ip:
                primary_ip = ip

    serial = _fact(facts, ["dmi::product::serial_number", "serialnumber"])
    manufacturer = _fact(facts, ["dmi::manufacturer", "manufacturer"])
    model = as_text(record.get("model_name"), join=",").strip() or _fact(facts, ["dmi::product::name", "productname"])
    chassis = _fact(facts, ["dmi::chassis::type"])
    virtual = _fact(facts, ["virtual"])
    hostgroup = as_text(record.get("hostgroup_title"), join=",").strip() or as_text(record.get("hostgroup_name"), join=",").strip()
    location = as_text(record.get("location_name"), join=",").strip()
    organization = as_text(record.get("organization_name"), join=",").strip()
    domain = as_text(record.get("domain_name"), join=",").strip()
    status = as_text(record.get("global_status_label"), join=",").strip()

    # Katello adds these two facets to the host list response itself, so they
    # cost nothing extra and are absent on plain Foreman. The content view and
    # lifecycle environment are nested objects rather than flat name fields.
    content_facet = as_dict(record.get("content_facet_attributes"))
    subscription_facet = as_dict(record.get("subscription_facet_attributes"))
    errata_counts = as_dict(content_facet.get("errata_counts"))

    software = build_software(ctx, host_id, primary_ip, packages)

    tags = [VENDOR]
    if hostgroup:
        tags.append("hostgroup:" + hostgroup)
    if location:
        tags.append("location:" + location)
    if organization:
        tags.append("organization:" + organization)
    if serial:
        tags.append("serial:" + serial)
    if status:
        tags.append("status:" + status)
    if record.get("build") == True:
        tags.append("build:pending")
    if record.get("managed") == False:
        tags.append("unmanaged")
    if record.get("enabled") == False:
        tags.append("disabled")

    attrs = {
        "host_id": host_id,
        "server": ctx["scope"],
        "name": name,
        "certname": certname,
        "domain": domain,
        "hostgroup": hostgroup,
        "location": location,
        "organization": organization,
        "owner_name": record.get("owner_name"),
        "owner_type": record.get("owner_type"),
        "comment": record.get("comment"),
        "ip": record.get("ip"),
        "ip6": record.get("ip6"),
        "mac": record.get("mac"),
        "subnet": record.get("subnet_name"),
        "subnet6": record.get("subnet6_name"),
        "architecture": record.get("architecture_name"),
        "operatingsystem": record.get("operatingsystem_name"),
        "medium": record.get("medium_name"),
        "ptable": record.get("ptable_name"),
        "pxe_loader": record.get("pxe_loader"),
        "provision_method": record.get("provision_method"),
        "compute_resource": record.get("compute_resource_name"),
        "compute_profile": record.get("compute_profile_name"),
        "realm": record.get("realm_name"),
        "image": record.get("image_name"),
        "model": model,
        "uuid": record.get("uuid"),
        "build": record.get("build"),
        "managed": record.get("managed"),
        "enabled": record.get("enabled"),
        "global_status": record.get("global_status"),
        "global_status_label": status,
        "global_status_fulltext": record.get("global_status_fulltext"),
        "configuration_status_label": record.get("configuration_status_label"),
        "build_status_label": record.get("build_status_label"),
        "last_report": record.get("last_report"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        # The service processor is deliberately not an interface on this asset:
        # it is a separate network endpoint that runZero discovers on its own.
        "sp_name": record.get("sp_name"),
        "sp_ip": record.get("sp_ip"),
        "sp_mac": record.get("sp_mac"),
        "bmc_available": record.get("bmc_available"),
        "interface_count": len(merged),
        # Devices folded onto one MAC are joined with +, so a bond reads
        # "bond0+eno1" rather than losing the slave device names.
        "interface_identifiers": [
            "+".join(dedupe(entry["identifiers"])) for entry in merged
        ],
        "interface_macs": [entry["mac"] for entry in merged if entry["mac"]],
        "fact_count": len(facts),
        "software_count": len(software),
        "interfaces_enriched": "true" if detail else "false",
        # Facter facts. Every one of these is absent on a host that has never
        # uploaded facts, and to_custom_attributes drops the empty values.
        "fact_serial_number": serial,
        "fact_manufacturer": manufacturer,
        "fact_product_name": _fact(facts, ["dmi::product::name", "productname"]),
        "fact_product_uuid": _fact(facts, ["dmi::product::uuid", "uuid"]),
        "fact_chassis_type": chassis,
        "fact_bios_vendor": _fact(facts, ["dmi::bios::vendor", "bios_vendor"]),
        "fact_bios_version": _fact(facts, ["dmi::bios::version", "bios_version"]),
        "fact_bios_release_date": _fact(facts, ["dmi::bios::release_date"]),
        "fact_processor_count": _fact(facts, ["processors::count", "processorcount"]),
        "fact_physical_processor_count": _fact(facts, ["processors::physicalcount", "physicalprocessorcount"]),
        "fact_processor_models": _fact(facts, ["processors::models"]),
        "fact_processor_isa": _fact(facts, ["processors::isa", "architecture"]),
        "fact_memory_total_bytes": _fact(facts, ["memory::system::total_bytes"]),
        "fact_memory_total": _fact(facts, ["memory::system::total", "memorytotal", "memorysize_mb"]),
        "fact_os_name": _fact(facts, ["os::name", "operatingsystem"]),
        "fact_os_release": _fact(facts, ["os::release::full", "operatingsystemrelease"]),
        "fact_os_family": _fact(facts, ["os::family", "osfamily"]),
        "fact_os_description": _fact(facts, ["os::distro::description", "lsbdistdescription"]),
        "fact_os_architecture": _fact(facts, ["os::architecture"]),
        "fact_selinux_enabled": _fact(facts, ["os::selinux::enabled"]),
        "fact_kernel": _fact(facts, ["kernel"]),
        "fact_kernel_release": _fact(facts, ["kernelrelease"]),
        "fact_virtual": virtual,
        "fact_is_virtual": _fact(facts, ["is_virtual"]),
        "fact_cloud_provider": _fact(facts, ["cloud::provider"]),
        "fact_timezone": _fact(facts, ["timezone"]),
        "fact_uptime_seconds": _fact(facts, ["system_uptime::seconds", "uptime_seconds"]),
        "fact_primary_interface": _fact(facts, ["networking::primary"]),
        # Katello facets ride along on the host list when Katello is installed
        # and are absent on plain Foreman.
        "content_view": as_dict(content_facet.get("content_view")).get("name"),
        "lifecycle_environment": as_dict(content_facet.get("lifecycle_environment")).get("name"),
        "content_source": content_facet.get("content_source_name"),
        "applicable_package_count": content_facet.get("applicable_package_count"),
        "upgradable_package_count": content_facet.get("upgradable_package_count"),
        "errata_security": errata_counts.get("security"),
        "errata_bugfix": errata_counts.get("bugfix"),
        "errata_enhancement": errata_counts.get("enhancement"),
        "errata_total": errata_counts.get("total"),
        "registered_at": subscription_facet.get("registered_at"),
        "last_checkin": subscription_facet.get("last_checkin"),
        "service_level": subscription_facet.get("service_level"),
        "release_version": subscription_facet.get("release_version"),
    }
    for key in ctx["extra_facts"]:
        attrs["fact_" + key.replace(FACT_SEPARATOR, "_")] = _fact(facts, [key])

    params = {
        # The Foreman host id is authoritative for the server, but Foreman holds
        # exactly one address and one MAC on the host record, both of which are
        # rewritten by DHCP and by every fact upload, and hosts are renamed in
        # place. Network churn must not disqualify a merge.
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], host_id),
        "hostnames": dedupe([name, certname, _fact(facts, ["networking::fqdn", "fqdn"])]),
        "networkInterfaces": netifs,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
    }
    if domain:
        params["domain"] = domain
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model

    # The facts describe what the host actually runs; operatingsystem_name is
    # the provisioning record, which can still name the OS the host was built
    # with after an in-place upgrade.
    os_name = _fact(facts, ["os::name", "operatingsystem"])
    os_version = _fact(facts, ["os::release::full", "operatingsystemrelease"])
    if not os_name:
        os_name, os_version = split_os_version(record.get("operatingsystem_name"))
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version

    device_type = CHASSIS_TYPES.get(chassis.lower(), "")
    if virtual and virtual.lower() not in PHYSICAL_VIRTUAL:
        device_type = "Virtual Machine"
    elif not device_type and as_text(record.get("compute_resource_name"), join=",").strip():
        device_type = "Virtual Machine"
    if device_type:
        params["deviceType"] = device_type

    first_seen = parse_ts(record.get("created_at"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    last_seen = parse_ts(record.get("last_report"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def fetch_collection(ctx, path, params, page_size, label):
    """Fetch one page of a Foreman collection, returning (results, err).

    Every v2 index action answers with the same envelope - total, subtotal,
    page, per_page, search, sort, results - so only the results node differs
    between endpoints."""
    query = dict(params)
    query["page"] = str(ctx["page"])
    query["per_page"] = str(page_size)
    data, err = get_json(ctx["base_url"] + path, params=query, **ctx["http_options"])
    if err:
        return None, err
    data = as_dict(data)
    if "results" not in data:
        return None, "{} response carried no results node".format(label)
    return data["results"], None

def fetch_host_detail(ctx, host_id):
    """Fetch one host's own record for its interface list. Foreman returns the
    interfaces array only on the single-host response, never on the host list.
    A failure is reported and treated as no detail so one unreadable host cannot
    end the run."""
    data, err = get_json("{}{}/{}".format(ctx["base_url"], HOSTS_PATH, host_id), **ctx["http_options"])
    if err:
        print("foreman: failed to fetch detail for host {}: {}".format(host_id, err))
        return {}
    return as_dict(data)

def fetch_packages(ctx, host_id):
    """Fetch the packages Katello has recorded for one host.

    The endpoint is added by Katello, so Red Hat Satellite and orcharhino serve
    it and a plain Foreman install answers 404. That answer is not an error: it
    is how the absence of a package inventory is detected, and the whole feature
    switches itself off for the rest of the run."""
    packages = []
    _pager1 = pager("foreman-1")
    while _pager1.next():
        page = _pager1.page
        url = "{}{}/{}/packages".format(ctx["base_url"], HOSTS_PATH, host_id)
        data, err = get_json(url, params={"page": str(page), "per_page": str(MAX_CHILDREN + 1)},
                             **ctx["http_options"])
        if err:
            if err.startswith("status 404"):
                ctx["katello"] = False
                print("foreman: this server has no Katello package inventory, skipping packages:", err)
            elif err.startswith("status 403"):
                ctx["katello"] = False
                print("foreman: not permitted to read package inventory, skipping packages:", err)
            else:
                print("foreman: failed to fetch packages for host {}: {}".format(host_id, err))
            return packages
        results = dicts(as_dict(data).get("results"))
        packages.extend(results)
        if len(results) < MAX_CHILDREN + 1 or len(packages) > MAX_CHILDREN:
            break
    return packages

def _clean_fact_names(names):
    """Drop user-supplied fact names that cannot be interpolated into the
    scoped-search string. A double quote would end the quoted term early,
    Foreman would answer 400 for the whole search, and every host would then
    import without facts, so the one bad name is skipped instead."""
    cleaned = []
    for name in names:
        if '"' in name:
            print("foreman: ignoring extra fact name containing a double quote: {}".format(name))
            continue
        cleaned.append(name)
    return cleaned

def fact_search(ctx):
    """Build the Foreman search that limits the fact walk to the facts that are
    actually mapped. Exact names cover the flat facts; the per-interface facts
    carry the device name inside the fact name, so they are matched by prefix
    with the ~ operator, which Foreman compiles to a SQL LIKE."""
    terms = []
    for name in FACT_NAMES + ctx["extra_facts"]:
        terms.append('fact = "{}"'.format(name))
    for prefix in FACT_PREFIXES:
        terms.append('fact ~ "{}"'.format(prefix))
    return " or ".join(terms)

def fetch_facts(ctx):
    """Index every host's facts in one paged walk over the fact_values endpoint.

    This is the whole reason the integration does not issue a request per host:
    GET /api/v2/fact_values answers for every host at once, keyed by host name.
    The catch is that Foreman paginates it by individual fact value rather than
    by host, so one host's facts can straddle a page boundary. Pages are merged
    into a single map for exactly that reason, which also makes the endpoint's
    ordering irrelevant."""
    facts = {}
    hosts = 0
    values = 0
    params = {"search": fact_search(ctx)}
    _pager2 = pager("foreman-2")
    while _pager2.next():
        page = _pager2.page
        ctx["page"] = page
        results, err = fetch_collection(ctx, FACT_VALUES_PATH, params, ctx["fact_page_size"], "fact_values")
        if err:
            print("foreman: failed to fetch facts, importing hosts without them:", err)
            return facts
        if type(results) != "dict":
            print("foreman: unexpected fact_values response, importing hosts without facts")
            return facts
        if not results:
            break

        page_values = 0
        for hostname in results:
            entry = as_dict(results[hostname])
            page_values += len(entry)
            target = facts.get(hostname)
            if target == None:
                hosts += 1
                facts[hostname] = dict(entry)
            else:
                target.update(entry)
        values += page_values
        if page_values < ctx["fact_page_size"]:
            break

    print("foreman: indexed {} fact values for {} hosts".format(values, hosts))
    return facts

def build_assets(ctx, records, facts):
    """Convert a page of Foreman host records into runZero assets, enriching
    each with its facts and, when enabled, its interface list and packages."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        host_id = record.get("id")
        if host_id == None or as_text(host_id, join=",").strip() == "":
            print("foreman: skipping host with no id: name=" + as_text(record.get("name"), join=","))
            continue

        detail = {}
        packages = []
        wants_detail = ctx["interfaces"] or (ctx["packages"] and ctx["katello"])
        if wants_detail and ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        elif wants_detail:
            ctx["detail_used"] += 1
            if ctx["interfaces"]:
                detail = fetch_host_detail(ctx, host_id)
            if ctx["packages"] and ctx["katello"]:
                packages = fetch_packages(ctx, host_id)

        host_facts = facts.get(as_text(record.get("name"), join=",").strip(), {})
        assets.append(build_asset(ctx, record, host_facts, detail, packages))
    return assets

def fetch_and_report_hosts(ctx, facts):
    """Fetch and stream hosts one page at a time so the full inventory is never
    held in memory at once."""
    params = {}
    if ctx["search"]:
        params["search"] = ctx["search"]

    reported = 0
    _pager3 = pager("foreman-3")
    while _pager3.next():
        page = _pager3.page
        ctx["page"] = page
        results, err = fetch_collection(ctx, HOSTS_PATH, params, ctx["page_size"], "hosts")
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("foreman: authentication to the Foreman server failed:", err)
            else:
                print("foreman: failed to fetch hosts:", err)
            return reported
        records = dicts(results)
        if not records:
            break

        reported += report_assets(build_assets(ctx, records, facts))
        print("foreman: reported {} assets so far".format(reported))
        if len(records) < ctx["page_size"]:
            break

    if ctx["detail_skipped"]:
        print("foreman: per-host request limit of {} reached; interfaces and packages were not fetched for {} hosts".format(
            ctx["detail_limit"], ctx["detail_skipped"]))
    return reported

def main(**kwargs):
    base_url = _base_url(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("foreman: could not determine the Foreman server host from the configured URL")
        return None

    username = get_string(kwargs, "username", default="").strip()
    password = get_string(kwargs, "password", default="")
    if not username or not password:
        print("foreman: a Foreman username and a password or Personal Access Token are required")
        return None

    detail_limit = get_int(kwargs, "detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "base_url": base_url,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
            "Authorization": basic(username, password),
        }),
        "scope": scope,
        "search": get_string(kwargs, "search", default="").strip(),
        "page_size": get_int(kwargs, "page_size", default=100),
        "fact_page_size": get_int(kwargs, "fact_page_size", default=1000),
        "facts": get_bool(kwargs, "include_facts", default=True),
        "interfaces": get_bool(kwargs, "include_interfaces", default=False),
        "packages": get_bool(kwargs, "include_packages", default=False),
        "extra_facts": _clean_fact_names(dedupe(get_list(kwargs, "extra_facts", default=[]))),
        "katello": True,
        "detail_limit": detail_limit,
        "detail_used": 0,
        "detail_skipped": 0,
        "page": 1,
    }

    facts = fetch_facts(ctx) if ctx["facts"] else {}
    reported = fetch_and_report_hosts(ctx, facts)
    if not reported:
        print("foreman: no assets retrieved")
    return None

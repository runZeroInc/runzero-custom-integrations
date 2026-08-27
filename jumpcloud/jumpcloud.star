# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-jumpcloud",
    "name": "JumpCloud",
    "type": "inbound",
    "description": "Imports systems, the directory users bound to them, and optionally System Insights software and MAC addresses from JumpCloud.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "JumpCloud console URL",
            "type": "url",
            "required": False,
            "default": "https://console.jumpcloud.com",
            "description": "Regional JumpCloud console URL. Use https://console.eu.jumpcloud.com or https://console.in.jumpcloud.com for the EU and India regions. The API is served from /api on this host.",
        },
        {
            "key": "org_id",
            "label": "Organization ID",
            "type": "string",
            "required": False,
            "description": "JumpCloud organization ObjectID, sent as the x-org-id header. Required for multi-tenant admins whose API key can reach more than one organization; leave blank for a single-tenant admin.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "JumpCloud API key from the admin profile menu, sent as the x-api-key header.",
        },
        {
            "key": "include_bound_users",
            "label": "Import bound users",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Resolve the directory users bound to each system, directly or through a group. Costs one extra request per system plus one pass over the user directory.",
        },
        {
            "key": "include_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch installed applications from System Insights. Requires a plan that includes System Insights and costs one extra request per system that has it enabled.",
        },
        {
            "key": "include_mac_addresses",
            "label": "Import MAC addresses",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch adapter MAC addresses from System Insights. The system inventory itself publishes no MAC. Requires System Insights and costs one extra request per system that has it enabled.",
        },
        {
            "key": "detail_system_limit",
            "label": "Per-system detail limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 1,
            "description": "Maximum number of systems to query for bound users, software, and MAC addresses. Systems past this limit are imported without that detail and the skipped count is logged.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 100,
            "description": "Records requested per page. JumpCloud caps the system and user list endpoints at 100.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'normalize_mac')
load('http', 'get_json')
load('time', 'parse_ts')
load('re', re_match='match')
load('kwargs', 'require', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')

load('coerce', 'as_dict', 'as_list')
# JumpCloud runs two API generations side by side on the same host and the split
# is not cosmetic. The system inventory only exists on v1 (/api/systems), while
# every relationship in the directory graph -- including the user-to-system
# binding this integration exists to capture -- only exists on v2 (/api/v2/...).
# Both are reached with the same x-api-key header.
SYSTEMS_PATH = "/api/systems"
SYSTEM_USERS_PATH = "/api/systemusers"
SYSTEM_BOUND_USERS_PATH = "/api/v2/systems/{}/users"
INSIGHTS_APPS_PATH = "/api/v2/systeminsights/apps"
INSIGHTS_PROGRAMS_PATH = "/api/v2/systeminsights/programs"
INSIGHTS_INTERFACES_PATH = "/api/v2/systeminsights/interface_details"

# Every v1 list endpoint documents the same offset pagination and the same hard
# ceiling: "The number of records to return at once. Limited to 100."
MAX_PAGE_SIZE = 100
# Paging on skip alone walks an unstable default ordering, and JumpCloud's own
# API guidance is to pin the sort explicitly or risk seeing a record twice and
# missing another. For an inventory import a silently dropped system is the
# worst possible failure, so the sort is always sent.
SORT_FIELD = "_id"

# The two API generations disagree on filter syntax: v1 operators are dollar
# prefixed ($eq) while the v2 System Insights collections take bare operators.
# Only the v2 form is used here.
INSIGHTS_FILTER = "system_id:eq:{}"

# System Insights reports whether it is collecting for a given host. Any other
# state means the per-system tables hold nothing, so the request is not made.
INSIGHTS_ENABLED = "enabled"

CHILD_LIMIT = 99
MAX_USERS_CACHED = 50000
MAX_BOUND_USERS_LISTED = 50
MAX_USER_TAGS = 10

# A MAC of all zeros is what loopback and unbound virtual adapters report.
EMPTY_MAC = "00:00:00:00:00:00"

# Addresses that must never reach a NetworkInterface. The JumpCloud agent
# reports every adapter the host has, loopback included, and a host whose only
# usable address was 127.0.0.1 would merge with every other such host in runZero.
UNUSABLE_IP_PREFIXES = ["127.", "169.254.", "fe8", "fe9", "fea", "feb"]
UNUSABLE_IPS = ["::1", "::", "0.0.0.0", "0:0:0:0:0:0:0:1"]

# displayName defaults to the hostname but administrators routinely rewrite it
# into a human label ("<owner>'s MacBook Pro"), which is not a name anything can
# resolve. It is only promoted to a hostname when it is still hostname shaped;
# the raw value is kept as a custom attribute either way.
HOSTNAME_RE = r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,252}[A-Za-z0-9])?$"

TIMESTAMP_HAS_ZONE_RE = r"(Z|[+-]\d{2}:?\d{2})$"
NEVER_TIMESTAMP_PREFIX = "0001-01-01"

# System Insights collects a different table per platform: apps is the macOS
# bundle inventory and programs is the Windows installed-programs inventory.
# Linux agents populate neither, so no software request is made for them.
OS_MACOS_TOKENS = ["mac os", "macos", "os x", "darwin"]
OS_WINDOWS_TOKENS = ["windows"]

# Distributions that ship only as a server platform, matched against the
# reported OS name and osVersionDetail.distributionName. Ubuntu, Debian,
# Fedora, openSUSE and macOS are deliberately absent: each is as often a
# workstation as a server. So is SUSE Linux Enterprise *Desktop*, which is why
# the list carries sles and not a bare "suse" substring.
SERVER_OS_NAMES = [
    "red hat enterprise", "rhel", "centos", "rocky linux", "almalinux",
    "amazon linux", "oracle linux", "suse linux enterprise server", "sles",
]


def _clean(value):
    """Return a value as a trimmed string, mapping None and containers to empty."""
    if value == None:
        return ""
    if type(value) == "dict" or type(value) == "list":
        return ""
    if type(value) == "bool":
        if value:
            return "true"
        return "false"
    return str(value).strip()
def _usable_ip(value):
    """Return an address string only when it is routable enough to merge on."""
    text = _clean(value).lower()
    if not text or text in UNUSABLE_IPS:
        return ""
    for prefix in UNUSABLE_IP_PREFIXES:
        if text.startswith(prefix):
            return ""
    return text


def _tag_value(prefix, value):
    """Build a key:value tag, collapsing whitespace so the tag stays one token."""
    text = _clean(value)
    if not text:
        return ""
    return prefix + ":" + text.replace(" ", "-")


def _os_family(os_name):
    """Classify the reported OS into the System Insights table that covers it."""
    text = _clean(os_name).lower()
    for token in OS_MACOS_TOKENS:
        if token in text:
            return "macos"
    for token in OS_WINDOWS_TOKENS:
        if token in text:
            return "windows"
    return ""


def _device_type(system):
    """Return a runZero device type for one JumpCloud system, or "".

    The system inventory names no chassis -- there is hwVendor but no hwModel,
    and nothing that separates a laptop from a desktop -- so the only genuine
    statement of role is an OS that says what it is. The reported os,
    osVersionDetail.osName and osVersionDetail.distributionName are all
    considered, because a tenant that reports a bare "Windows" in os carries
    "Microsoft Windows Server 2022 Datacenter" in osName and the type would
    otherwise be missed.

    A bare "Windows", "Ubuntu" or "Mac OS X" stays unset: it is a desktop or a
    laptop and the record cannot say which, and a wrong hint is worse than
    none. This only ever fills a gap -- runZero prefers what it derives from
    the hardware or from a scan -- but on these hosts the gap is real, since
    hwVendor "VMware, Inc." with no model fingerprints nothing.
    """
    text = " ".join([
        _clean(system.get("os")),
        _clean(as_dict(system.get("osVersionDetail")).get("osName")),
        _clean(as_dict(system.get("osVersionDetail")).get("distributionName")),
    ]).lower()
    if not text.strip():
        return ""
    if "server" in text:
        return "Server"
    for name in SERVER_OS_NAMES:
        if name in text:
            return "Server"
    return ""


def _hostnames(system):
    """Return the names that are safe to merge on."""
    names = []
    for key in ["hostname", "displayName"]:
        candidate = _clean(system.get(key))
        if not candidate or candidate in names:
            continue
        if not re_match(HOSTNAME_RE, candidate):
            continue
        names.append(candidate)
    return names


def build_network_interfaces(system, macs):
    """Group networkInterfaces entries by adapter and build one interface each.

    JumpCloud emits one entry per adapter *per address family*, so en0 appears
    twice when it holds both an IPv4 and an IPv6 address. Entries are regrouped
    on the adapter name so a dual-stack adapter becomes one interface rather than
    two. Entries flagged internal are loopback by definition and are dropped, as
    are addresses that are unusable for merging. `macs` maps an adapter name to
    the MAC that System Insights reported for it, and is empty when that lookup
    was not enabled or not licensed.
    """
    order = []
    by_name = {}
    raw_addresses = []

    for entry in as_list(system.get("networkInterfaces")):
        if type(entry) != "dict":
            continue
        address = _clean(entry.get("address"))
        if address:
            raw_addresses.append(address)
        if entry.get("internal") == True:
            continue
        usable = _usable_ip(address)
        if not usable:
            continue
        name = _clean(entry.get("name")) or "iface{}".format(len(order))
        if name not in by_name:
            order.append(name)
            by_name[name] = []
        if usable not in by_name[name]:
            by_name[name].append(usable)

    netifs = []
    for name in order:
        # Only adapters that already carry a usable address are given a MAC.
        # System Insights also enumerates loopback, tunnel, and hypervisor
        # adapters, and turning those into MAC-only interfaces would hand
        # runZero a pile of identical virtual MACs to merge on.
        nic = network_interface(mac=macs.get(name, ""), ips=by_name[name])
        if nic:
            netifs.append(nic)

    return netifs[:CHILD_LIMIT], raw_addresses


def build_software(rows, os_family):
    """Convert one system's System Insights rows into Software objects.

    The macOS apps table and the Windows programs table describe the same idea
    with different field names, so each is mapped onto the shared Software shape.
    """
    software = []
    for row in rows:
        if type(row) != "dict":
            continue
        if os_family == "macos":
            # `name` carries the ".app" suffix, so the bundle name is preferred.
            product = _clean(row.get("bundle_name")) or _clean(row.get("name"))
            version = _clean(row.get("bundle_short_version")) or _clean(row.get("bundle_version"))
            vendor = ""
            installed_from = _clean(row.get("path"))
            identifier = _clean(row.get("bundle_identifier"))
            attrs = {
                "bundle_identifier": identifier,
                "bundle_version": _clean(row.get("bundle_version")),
                "path": installed_from,
                "category": _clean(row.get("category")),
                "collection_time": _clean(row.get("collection_time")),
            }
        else:
            product = _clean(row.get("name"))
            version = _clean(row.get("version"))
            vendor = _clean(row.get("publisher"))
            installed_from = _clean(row.get("install_location"))
            identifier = _clean(row.get("identifying_number"))
            attrs = {
                "identifying_number": identifier,
                "install_location": installed_from,
                # Windows reports this as a bare YYYYMMDD string rather than a
                # timestamp, so it is kept verbatim instead of being parsed.
                "install_date": _clean(row.get("install_date")),
                "install_source": _clean(row.get("install_source")),
                "language": _clean(row.get("language")),
                "collection_time": _clean(row.get("collection_time")),
            }
        if not product:
            continue
        # System Insights publishes no CPE for either table, so cpe23 is left
        # unset rather than synthesized.
        software.append(Software(
            id=(identifier or product)[:255],
            vendor=vendor[:255],
            product=product[:255],
            version=version[:255],
            installedFrom=installed_from[:255],
            serviceAddress="127.0.0.1",
            customAttributes=to_custom_attributes(attrs, prefix="jumpcloud", separator="_"),
        ))
        if len(software) >= CHILD_LIMIT:
            break
    return software


def build_bound_user_attributes(bound, user_index, truncated=False):
    """Summarize the users bound to one system into flat attributes and tags.

    Each element of the graph response carries the bound user's ObjectID and the
    paths that reach it. A path of a single connection is a direct system-to-user
    binding; a longer path arrives through a group. That distinction is what an
    operator needs when asking not just who can log in to a host but why, and
    which grouping would have to change to revoke it.

    When the graph walk stopped at the listing cap, the count is a floor rather
    than a total, and the attributes say so.
    """
    usernames = []
    emails = []
    user_ids = []
    direct = []
    via_group = []
    admins = []

    for item in bound:
        if type(item) != "dict":
            continue
        user_id = _clean(item.get("id"))
        if not user_id:
            continue
        user = as_dict(user_index.get(user_id))
        username = _clean(user.get("username")) or _clean(user.get("email")) or user_id
        if user_id not in user_ids:
            user_ids.append(user_id)
        if username not in usernames:
            usernames.append(username)
        email = _clean(user.get("email"))
        if email and email not in emails:
            emails.append(email)

        is_direct = False
        for path in as_list(item.get("paths")):
            if type(path) == "list" and len(path) == 1:
                is_direct = True
        if is_direct:
            if username not in direct:
                direct.append(username)
        elif username not in via_group:
            via_group.append(username)

        # The compiled graph attributes are where sudo rights end up once every
        # path has been followed. Older payloads spell the key `attributes`, so
        # both are read and neither is required.
        compiled = as_dict(item.get("compiledAttributes")) or as_dict(item.get("attributes"))
        if as_dict(compiled.get("sudo")).get("enabled") == True and username not in admins:
            admins.append(username)

    attrs = {
        "bound_user_count": "{}+".format(len(user_ids)) if truncated else len(user_ids),
        "bound_users": usernames[:MAX_BOUND_USERS_LISTED],
        "bound_user_emails": emails[:MAX_BOUND_USERS_LISTED],
        "bound_user_ids": user_ids[:MAX_BOUND_USERS_LISTED],
        "bound_users_direct": direct[:MAX_BOUND_USERS_LISTED],
        "bound_users_via_group": via_group[:MAX_BOUND_USERS_LISTED],
        "bound_users_with_sudo": admins[:MAX_BOUND_USERS_LISTED],
    }
    if truncated:
        attrs["bound_users_truncated"] = True
    tags = []
    for username in usernames[:MAX_USER_TAGS]:
        tag = _tag_value("user", username)
        if tag:
            tags.append(tag)
    return attrs, tags


def build_local_user_attributes(system, user_index):
    """Summarize the local accounts and primary user the agent reports.

    `userMetrics` is returned inline with every system and needs no extra
    request. It describes accounts as the device sees them rather than as the
    directory binds them, so it is kept in its own set of attributes and never
    merged with the graph bindings.
    """
    names = []
    admins = []
    unmanaged = []
    for entry in as_list(system.get("userMetrics")):
        if type(entry) != "dict":
            continue
        name = _clean(entry.get("userName"))
        if not name or name in names:
            continue
        names.append(name)
        if entry.get("admin") == True:
            admins.append(name)
        if entry.get("managed") == False:
            unmanaged.append(name)

    primary_id = _clean(as_dict(system.get("primarySystemUser")).get("id"))
    primary_name = ""
    if primary_id:
        primary_name = _clean(as_dict(user_index.get(primary_id)).get("username"))

    return {
        "local_user_count": len(names),
        "local_users": names[:MAX_BOUND_USERS_LISTED],
        "local_admin_users": admins[:MAX_BOUND_USERS_LISTED],
        "local_unmanaged_users": unmanaged[:MAX_BOUND_USERS_LISTED],
        "primary_user_id": primary_id,
        "primary_user": primary_name,
    }


def build_asset(system, scope, detail, user_index):
    """Build a single ImportAsset from one JumpCloud system record."""
    system_id = _clean(system.get("_id")) or _clean(system.get("id"))
    serial_number = _clean(system.get("serialNumber"))
    os_name = _clean(system.get("os"))
    os_version = _clean(system.get("version"))
    version_detail = as_dict(system.get("osVersionDetail"))
    if not os_name:
        os_name = _clean(version_detail.get("osName"))
    if not os_version:
        os_version = _clean(version_detail.get("version")) or _clean(version_detail.get("releaseName"))
    netifs, raw_addresses = build_network_interfaces(system, detail["macs"])
    fde = as_dict(system.get("fde"))
    domain_info = as_dict(system.get("domainInfo"))
    domain = ""
    if domain_info.get("partOfDomain") == True:
        domain = _clean(domain_info.get("domainName"))

    tags = ["jumpcloud"]
    serial_tag = _tag_value("serial", serial_number)
    if serial_tag:
        tags.append(serial_tag)
    if system.get("active") == True:
        tags.append("agent:active")
    else:
        tags.append("agent:inactive")
    if fde:
        if fde.get("active") == True:
            tags.append("fde:active")
        else:
            tags.append("fde:inactive")
    for tag in detail["bound_tags"]:
        tags.append(tag)

    attrs = {
        "system_id": system_id,
        "display_name": _clean(system.get("displayName")),
        "hostname": _clean(system.get("hostname")),
        "description": _clean(system.get("description")),
        "serial_number": serial_number,
        "organization": _clean(system.get("organization")),
        "hw_vendor": _clean(system.get("hwVendor")),
        "os": os_name,
        "os_family": _clean(system.get("osFamily")),
        "os_version": os_version,
        "os_version_detail": version_detail,
        "arch": _clean(system.get("arch")),
        "arch_family": _clean(system.get("archFamily")),
        "agent_version": _clean(system.get("agentVersion")),
        "agent_has_full_disk_access": _clean(system.get("agentHasFullDiskAccess")),
        "remote_assist_agent_version": _clean(system.get("remoteAssistAgentVersion")),
        "active": _clean(system.get("active")),
        # An integer UTC offset, not an IANA zone name.
        "system_timezone": _clean(system.get("systemTimezone")),
        # The NAT egress address the agent was last seen from. It is shared by
        # every host behind one gateway, so it is recorded here and deliberately
        # kept off the network interfaces.
        "remote_ip": _clean(system.get("remoteIP")),
        # The unfiltered adapter list is preserved even when every entry was
        # dropped as loopback or link-local.
        "network_addresses": ",".join(raw_addresses),
        "domain_info": domain_info,
        "azure_ad_joined": _clean(system.get("azureAdJoined")),
        "mdm": as_dict(system.get("mdm")),
        "fde_active": _clean(fde.get("active")),
        "fde_key_present": _clean(fde.get("keyPresent")),
        "system_insights_state": _clean(as_dict(system.get("systemInsights")).get("state")),
        "policy_stats": as_dict(system.get("policyStats")),
        "is_policy_bound": _clean(system.get("isPolicyBound")),
        "provision_metadata": as_dict(system.get("provisionMetadata")),
        "secure_login": as_dict(system.get("secureLogin")),
        "has_service_account": _clean(system.get("hasServiceAccount")),
        "template_name": _clean(system.get("templateName")),
        "amazon_instance_id": _clean(system.get("amazonInstanceID")),
        "desktop_capable": _clean(system.get("desktopCapable")),
        "file_system": _clean(system.get("fileSystem")),
        "allow_ssh_root_login": _clean(system.get("allowSshRootLogin")),
        "allow_ssh_password_authentication": _clean(system.get("allowSshPasswordAuthentication")),
        "allow_public_key_authentication": _clean(system.get("allowPublicKeyAuthentication")),
        "allow_multi_factor_authentication": _clean(system.get("allowMultiFactorAuthentication")),
        "ssh_root_enabled": _clean(system.get("sshRootEnabled")),
        "system_tags": as_list(system.get("tags")),
        "created": _clean(system.get("created")),
        "last_contact": _clean(system.get("lastContact")),
        "scope": scope,
    }
    for source in [build_local_user_attributes(system, user_index), detail["bound_attrs"]]:
        for key in source:
            attrs[key] = source[key]

    params = {
        # The system ObjectID is authoritative inside an organization, but
        # reinstalling the agent mints a new one, so MAC, IP, and hostname churn
        # must not disqualify a merge back onto the hardware runZero already has.
        "id": "jumpcloud:{}:{}".format(scope, system_id),
        "hostnames": _hostnames(system),
        "domain": domain,
        "networkInterfaces": netifs,
        "os": os_name,
        "osVersion": os_version,
        "manufacturer": _clean(system.get("hwVendor")),
        "tags": tags,
        "software": detail["software"][:CHILD_LIMIT],
        "customAttributes": to_custom_attributes(attrs, prefix="jumpcloud", separator="_"),
    }

    # Omitted rather than set to "" when the OS names no role: an empty
    # deviceType is still a value and displaces the type runZero would
    # otherwise derive for itself.
    device_type = _device_type(system)
    if device_type:
        params["deviceType"] = device_type

    asset = ImportAsset(**params)

    created = parse_ts(system.get("created"))
    if created:
        asset.firstSeenTS = created
    # construction.
    last_contact = parse_ts(system.get("lastContact"))

    if last_contact != None:
        asset.lastSeenTS = last_contact
    return asset


def fetch_user_index(base_url, http_options, page_size):
    """Walk the directory once and index every user by ObjectID.

    The graph endpoint that answers "who is bound to this system" returns user
    ObjectIDs and nothing else, so the directory is read once up front rather
    than resolving each id with a request of its own.
    """
    index = {}
    url = base_url + SYSTEM_USERS_PATH
    skip = 0
    _pager1 = pager("jumpcloud-1")
    while _pager1.next():
        data, err = get_json(url, params={"limit": page_size, "skip": skip, "sort": SORT_FIELD},
                             **http_options)
        if err:
            print("jumpcloud: failed to fetch the user directory:", err)
            return index
        data = data or {}
        results = as_list(data.get("results"))
        if not results:
            break
        for user in results:
            if type(user) != "dict":
                continue
            user_id = _clean(user.get("_id")) or _clean(user.get("id"))
            if not user_id:
                continue
            index[user_id] = {
                "username": _clean(user.get("username")),
                "email": _clean(user.get("email")),
            }
        if len(index) >= MAX_USERS_CACHED:
            print("jumpcloud: stopped indexing the user directory at {} users".format(len(index)))
            break
        if len(results) < page_size:
            break
        skip += page_size
    print("jumpcloud: indexed {} directory users".format(len(index)))
    return index


def fetch_bound_users(base_url, http_options, system_id, page_size):
    """Fetch the users bound to one system, directly or through a group.

    Returns (bound, truncated). truncated is True when the walk stopped at the
    MAX_BOUND_USERS_LISTED cap with rows still unread, so the caller can mark
    the count as a floor instead of reporting exactly the cap."""
    bound = []
    url = base_url + SYSTEM_BOUND_USERS_PATH.format(system_id)
    skip = 0
    _pager2 = pager("jumpcloud-2")
    while _pager2.next():
        data, err = get_json(url, params={"limit": page_size, "skip": skip},
                             **http_options)
        if err:
            print("jumpcloud: failed to fetch bound users for one system:", err)
            return bound, False
        # This endpoint answers with a bare JSON array, and a system with no
        # bound users can answer with an empty body that decodes to None.
        items = as_list(data)
        if not items:
            break
        for item in items:
            if len(bound) >= MAX_BOUND_USERS_LISTED:
                return bound, True
            bound.append(item)
        if len(items) < page_size:
            break
        skip += page_size
    return bound, False


def fetch_insights(base_url, http_options, path, system_id, page_size, insights_state):
    """Fetch one System Insights table for a single system.

    Both collections are filtered server side on system_id, which every row
    carries as a required field, so no client-side grouping over an
    account-wide dump is needed.
    """
    rows = []
    url = base_url + path
    skip = 0
    _pager3 = pager("jumpcloud-3")
    while _pager3.next():
        data, err = get_json(url, params={
            "filter": INSIGHTS_FILTER.format(system_id),
            "limit": page_size,
            "skip": skip,
        }, **http_options)
        if err:
            # System Insights is a separately licensed feature and its failure
            # mode when unlicensed is not documented, so any error is treated as
            # "no data" and reported once rather than once per system.
            insights_state["failures"] += 1
            if insights_state["failures"] == 1:
                print("jumpcloud: failed to fetch System Insights data:", err)
                print("jumpcloud: System Insights may not be available on this plan; the software and MAC address options can be turned off")
            return rows
        items = as_list(data)
        if not items:
            break
        for item in items:
            rows.append(item)
            if len(rows) >= CHILD_LIMIT:
                return rows
        if len(items) < page_size:
            break
        skip += page_size
    return rows


def build_interface_macs(rows):
    """Index the MAC System Insights reported for each adapter, by adapter name."""
    macs = {}
    for row in rows:
        if type(row) != "dict":
            continue
        name = _clean(row.get("interface"))
        mac = _clean(row.get("mac"))
        if not name or not mac or mac == EMPTY_MAC:
            continue
        if not normalize_mac(mac):
            continue
        if name not in macs:
            macs[name] = mac
    return macs


def fetch_system_detail(base_url, http_options, system, system_id, page_size,
                        user_index, include_bound_users, include_software,
                        include_mac_addresses, insights_state):
    """Fetch the optional per-system detail that needs its own requests."""
    detail = {"bound_attrs": {}, "bound_tags": [], "software": [], "macs": {}}

    if include_bound_users:
        bound, truncated = fetch_bound_users(base_url, http_options, system_id, page_size)
        detail["bound_attrs"], detail["bound_tags"] = build_bound_user_attributes(
            bound, user_index, truncated)

    if not include_software and not include_mac_addresses:
        return detail
    # The system record says whether System Insights is collecting for this host,
    # so a disabled or deferred host costs no request at all.
    if _clean(as_dict(system.get("systemInsights")).get("state")) != INSIGHTS_ENABLED:
        insights_state["not_enabled"] += 1
        return detail

    if include_software:
        os_family = _os_family(system.get("os"))
        if os_family == "macos":
            path = INSIGHTS_APPS_PATH
        elif os_family == "windows":
            path = INSIGHTS_PROGRAMS_PATH
        else:
            path = ""
        if path:
            detail["software"] = build_software(
                fetch_insights(base_url, http_options, path, system_id, page_size,
                               insights_state),
                os_family)

    if include_mac_addresses:
        detail["macs"] = build_interface_macs(
            fetch_insights(base_url, http_options, INSIGHTS_INTERFACES_PATH,
                           system_id, page_size, insights_state))

    return detail


def build_assets(systems, scope, base_url, http_options, page_size, user_index,
                 include_bound_users, include_software, include_mac_addresses,
                 detail_state, insights_state):
    """Build one page of ImportAssets, attaching optional per-system detail."""
    assets = []
    wants_detail = include_bound_users or include_software or include_mac_addresses
    for system in systems:
        if type(system) != "dict":
            print("jumpcloud: skipping malformed system record")
            continue
        system_id = _clean(system.get("_id")) or _clean(system.get("id"))
        if not system_id:
            print("jumpcloud: skipping system with no _id: hostname=" + _clean(system.get("hostname")))
            continue

        detail = {"bound_attrs": {}, "bound_tags": [], "software": [], "macs": {}}
        if wants_detail:
            if detail_state["fetched"] < detail_state["limit"]:
                detail_state["fetched"] += 1
                detail = fetch_system_detail(base_url, http_options, system, system_id,
                                             page_size, user_index, include_bound_users,
                                             include_software, include_mac_addresses,
                                             insights_state)
            else:
                detail_state["skipped"] += 1

        assets.append(build_asset(system, scope, detail, user_index))
    return assets


def fetch_and_report_systems(base_url, scope, http_options, page_size, user_index,
                             include_bound_users, include_software,
                             include_mac_addresses, detail_state, insights_state):
    """Fetch and stream systems one page at a time so the full inventory is never
    held in memory at once."""
    reported = 0
    url = base_url + SYSTEMS_PATH
    skip = 0

    _pager4 = pager("jumpcloud-4")

    while _pager4.next():
        data, err = get_json(url, params={"limit": page_size, "skip": skip, "sort": SORT_FIELD},
                             **http_options)
        if err:
            print("jumpcloud: failed to fetch systems at offset {}: {}".format(skip, err))
            if err.startswith("status 401"):
                print("jumpcloud: check the API key, and set the organization ID if this administrator manages more than one organization")
            if err.startswith("status 403") or err.startswith("status 404"):
                print("jumpcloud: check that the organization ID is correct for this API key")
            return reported
        data = data or {}
        systems = as_list(data.get("results"))
        if not systems:
            break

        assets = build_assets(systems, scope, base_url, http_options, page_size,
                              user_index, include_bound_users, include_software,
                              include_mac_addresses, detail_state, insights_state)
        if assets:
            reported += report_assets(assets)

        total = data.get("totalCount", 0) or 0
        print("jumpcloud: reported {} of {} systems".format(reported, total))
        if len(systems) < page_size:
            break
        skip += page_size

    return reported


def main(**kwargs):
    require(kwargs, "api_key")
    base_url = get_url_base(kwargs)
    api_key = get_string(kwargs, "api_key")
    org_id = get_string(kwargs, "org_id", default="")
    include_bound_users = get_bool(kwargs, "include_bound_users", default=True)
    include_software = get_bool(kwargs, "include_software", default=False)
    include_mac_addresses = get_bool(kwargs, "include_mac_addresses", default=False)
    detail_system_limit = get_int(kwargs, "detail_system_limit", default=1000)
    page_size = get_int(kwargs, "page_size", default=MAX_PAGE_SIZE)
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    headers = {
        "x-api-key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # A single-tenant administrator resolves their own organization, and sending
    # the header on a route that does not support it is itself an error, so it is
    # only sent when an administrator supplied one.
    if org_id:
        headers["x-org-id"] = org_id
    http_options = get_http_options(kwargs, headers=headers)

    # System ObjectIDs are unique inside an organization, not across the several
    # an MSP administrator can reach. The organization ID is the real boundary
    # when it is configured; otherwise the regional console host is used, because
    # it is known from configuration before any record is parsed and so can never
    # go missing mid-import.
    scope = org_id or base_url.split("://")[-1]

    user_index = {}
    if include_bound_users:
        user_index = fetch_user_index(base_url, http_options, page_size)

    detail_state = {"fetched": 0, "skipped": 0, "limit": detail_system_limit}
    insights_state = {"failures": 0, "not_enabled": 0}
    reported = fetch_and_report_systems(base_url, scope, http_options, page_size,
                                        user_index, include_bound_users,
                                        include_software, include_mac_addresses,
                                        detail_state, insights_state)

    if include_bound_users or include_software or include_mac_addresses:
        print("jumpcloud: fetched per-system detail for {} systems".format(detail_state["fetched"]))
        if detail_state["skipped"]:
            print("jumpcloud: skipped per-system detail for {} systems; raise the per-system detail limit ({}) to cover more".format(
                detail_state["skipped"], detail_system_limit))
    if insights_state["not_enabled"]:
        print("jumpcloud: System Insights is not enabled on {} systems".format(insights_state["not_enabled"]))
    if not reported:
        print("jumpcloud: no assets retrieved")
    return None

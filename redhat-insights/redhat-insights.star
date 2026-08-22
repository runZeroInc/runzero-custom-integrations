# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-redhat-insights",
    "name": "Red Hat Insights",
    "type": "inbound",
    "description": "Imports registered systems, their hardware and network inventory, installed packages, and CVE findings from Red Hat Insights.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The inventory id is authoritative, but a registered system reports
    # whatever addresses it happens to hold at check-in and a laptop or a
    # cloud instance changes them between polls, so network churn must not
    # disqualify a merge against an existing runZero asset.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Console URL",
            "type": "url",
            "required": False,
            "default": "https://console.redhat.com",
            "placeholder": "https://console.redhat.com",
            "description": "Base URL of the Red Hat Hybrid Cloud Console. The /api/inventory/v1 and /api/vulnerability/v1 paths are appended automatically.",
        },
        {
            "key": "sso_url",
            "label": "Red Hat SSO URL",
            "type": "url",
            "required": False,
            "default": "https://sso.redhat.com",
            "placeholder": "https://sso.redhat.com",
            "description": "Base URL of Red Hat single sign-on. The /auth/realms/redhat-external/protocol/openid-connect/token path is appended automatically.",
        },
        {
            "key": "client_id",
            "label": "Service account client ID",
            "type": "string",
            "required": False,
            "requiredIf": "client_secret",
            "description": "Client ID of a Red Hat Hybrid Cloud Console service account. Supply this and the client secret together, unless an identity header is used instead.",
        },
        {
            "key": "client_secret",
            "label": "Service account client secret",
            "type": "secret",
            "required": False,
            "requiredIf": "client_id",
            "description": "Client secret issued with the service account. Shown only once when the service account is created.",
        },
        {
            "key": "identity_header",
            "label": "x-rh-identity header",
            "type": "secret",
            "required": False,
            "description": "Base64-encoded x-rh-identity JSON, for internal or proxied deployments that terminate authentication ahead of the API. Leave blank when using a service account.",
        },
        {
            "key": "scope",
            "label": "Token scope",
            "type": "string",
            "required": False,
            "default": "api.console",
            "description": "OAuth2 scope requested for the service account token. Leave blank to send no scope and take the account defaults.",
        },
        {
            "key": "include_software",
            "label": "Import installed packages",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Request installed_packages and kernel_modules on the system profile. A RHEL host reports hundreds of packages, so this multiplies the response size. Off by default.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import CVE findings",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Fetch CVE findings from the Insights Vulnerability service. This is one extra request per system and requires the vulnerability:vulnerability_results:read permission.",
        },
        {
            "key": "vulnerability_limit",
            "label": "CVE enrichment limit",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "description": "Maximum number of systems to enrich with CVE findings. Systems past the limit are still imported, without findings. 0 removes the cap.",
        },
        {
            "key": "page_size",
            "label": "Systems per page",
            "type": "int",
            "required": False,
            "default": 50,
            "min": 1,
            "max": 100,
            "description": "Systems requested per page. The inventory API caps this at 100. Lower it when package import makes the responses large.",
        },
    ],
    "atLeastOneOf": [["client_secret", "identity_header"]],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', 'get_json', 'post_json', 'bearer', 'url_encode', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'parse_time', 'parse_ts')
load('re', re_match='match')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "redhat-insights"
ATTR_PREFIX = "redhat_insights"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

INVENTORY_PATH = "/api/inventory/v1"
VULNERABILITY_PATH = "/api/vulnerability/v1"
HOSTS_PATH = "/hosts"
TOKEN_PATH = "/auth/realms/redhat-external/protocol/openid-connect/token"

MAX_CHILDREN = 99
MAX_INTERFACES = 99
# The vulnerability service pages with limit/offset. Only the first page is
# fetched because the per-asset child cap is 99 findings anyway.
VULN_PAGE_SIZE = 100

# Only tokens matching runZero's own validation are trusted. Vulnerability.cve
# is checked against this exact pattern and the whole finding is rejected when
# it does not match, so anything else is dropped rather than guessed at.
CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# A CVSS score arrives as a string ('4.400'), so its shape is checked before
# float() is called; float() on a non-numeric string aborts the run.
SCORE_RE = r"^[0-9]{1,2}(\.[0-9]+)?$"

# The system profile sparse fieldset requested alongside the host list. The
# inventory API embeds these on GET /hosts, so the whole import stays at one
# request per page instead of one request per host. Field names are validated
# against the published system profile schema and an unknown name is a 400,
# which is why there is a reduced set to fall back to.
PROFILE_FIELDS = [
    "ansible", "arch", "basearch", "bios_release_date", "bios_vendor",
    "bios_version", "captured_date", "cloud_provider", "cores_per_socket",
    "cpu_model", "enabled_services", "greenboot_status", "host_type",
    "infrastructure_type", "infrastructure_vendor", "insights_client_version",
    "insights_egg_version", "installed_products", "is_marketplace",
    "last_boot_time", "network_interfaces", "number_of_cpus",
    "number_of_sockets", "operating_system", "os_kernel_version", "os_release",
    "owner_id", "public_dns", "public_ipv4_addresses", "releasever",
    "rhc_client_id", "rhsm", "sap", "satellite_managed",
    "selinux_current_mode", "subscription_status", "system_memory_bytes",
    "system_purpose", "system_update_method", "systemd", "threads_per_core",
    "tuned_profile", "virtual_host_uuid",
]

# The oldest and most certain subset, requested after the full set is rejected.
REDUCED_PROFILE_FIELDS = [
    "arch", "bios_vendor", "bios_version", "infrastructure_type",
    "infrastructure_vendor", "network_interfaces", "number_of_cpus",
    "operating_system", "os_kernel_version", "os_release",
    "system_memory_bytes",
]

# Requested only when package import is enabled. installed_packages is by far
# the largest field in the profile.
SOFTWARE_PROFILE_FIELDS = ["installed_packages", "kernel_modules"]

# The all-zero MAC is what "ip addr" reports for an interface with no hardware
# address, and every host in that state would otherwise share one MAC.
EMPTY_MAC = "00:00:00:00:00:00"

# Interface types and names that describe the loopback device rather than a
# real NIC.
LOOPBACK_TYPES = ["loopback"]
LOOPBACK_NAMES = ["lo"]

# operating_system.name is a short enum. Everything else is passed through.
OS_NAMES = {
    "RHEL": "Red Hat Enterprise Linux",
    "CentOS": "CentOS Linux",
    "CentOS Linux": "CentOS Linux",
}

# Red Hat security impact, which is the severity the Vulnerability service
# publishes for a CVE. It is not the CVSS band.
IMPACT_RANK = {"CRITICAL": 4, "IMPORTANT": 3, "MODERATE": 2, "LOW": 1}

# RPM architectures, taken from the same list insights-core uses to decide
# where a NEVRA string stops being a name-version-release. A trailing token
# that is not one of these is part of the release, not an architecture.
KNOWN_ARCHITECTURES = [
    "x86_64", "i386", "i486", "i586", "i686", "src", "ia64", "ppc", "ppc64",
    "s390", "s390x", "amd64", "(none)", "noarch", "alpha", "alphaev4",
    "alphaev45", "alphaev5", "alphaev56", "alphaev6", "alphaev67", "alphaev68",
    "alphaev7", "alphapca56", "arm64", "armv5tejl", "armv5tel", "armv6l",
    "armv7hl", "armv7hnl", "armv7l", "athlon", "armhfp", "geode", "ia32e",
    "nosrc", "ppc64iseries", "ppc64le", "ppc64p7", "ppc64pseries", "sh3",
    "sh4", "sh4a", "sparc", "sparc64", "sparc64v", "sparcv8", "sparcv9",
    "sparcv9v", "aarch64",
]
def _strings(value):
    """Coerce a field documented as a list of strings into one, dropping blanks
    and repeats."""
    out = []
    if type(value) != "list":
        return out
    for item in value:
        text = as_text(item, join=",").strip()
        if text and text not in out:
            out.append(text)
    return out
def _to_float(value):
    """Return a numeric value as a float, or -1.0 when it is absent or not a
    number. The vulnerability service serializes a CVSS score as a string."""
    if type(value) in ("int", "float"):
        return float(value)
    matched = re_match(SCORE_RE, as_text(value, join=",").strip())
    if not matched:
        return -1.0
    return float(as_text(value, join=",").strip())
def _usable_mac(value):
    """Return a MAC that is safe to merge on, or an empty string. The all-zero
    address is reported for interfaces with no hardware address and would be
    shared by every host that has one."""
    text = as_text(value, join=",").strip()
    if not text:
        return ""
    if normalize_mac(text) == EMPTY_MAC:
        return ""
    return text


def _score_rank(score):
    """Convert a CVSS score to a runZero 0-4 rank using the standard bands."""
    if score < 0.1:
        return 0
    if score < 4.0:
        return 1
    if score < 7.0:
        return 2
    if score < 9.0:
        return 3
    return 4


def parse_nevra(nevra):
    """Split an RPM NEVRA string into (name, epoch, version, release, arch).

    installed_packages holds strings, not objects. Each one is built by
    insights-core as "name-epoch:version-release.arch", for example
    "krb5-libs-0:1.16.1-23.fc29.i686". The architecture is separated by "."
    only when the last dot falls after the last dash, and the trailing token is
    an architecture only if it is a recognized one - "3.10.0-1160.el7" ends in
    a dot but "el7" is a release, not an arch. Returns None when the string
    does not have the documented shape."""
    text = as_text(nevra, join=",").strip()
    if not text:
        return None

    arch = ""
    separator = "." if text.rfind(".") > text.rfind("-") else "-"
    index = text.rfind(separator)
    if index > 0 and text[index + 1:] in KNOWN_ARCHITECTURES:
        arch = text[index + 1:]
        text = text[:index]

    index = text.rfind("-")
    if index <= 0:
        return None
    release = text[index + 1:]
    text = text[:index]

    index = text.rfind("-")
    if index <= 0:
        return None
    version = text[index + 1:]
    name = text[:index]

    # The collector always writes the epoch, even when it is zero. A string with
    # neither an epoch nor a recognized architecture gives no evidence that the
    # split above found real boundaries, so it is rejected rather than turned
    # into a plausible-looking but wrong product and version.
    epoch = ""
    if ":" in version:
        parts = version.split(":", 1)
        epoch = parts[0]
        version = parts[1]
    elif not arch:
        return None

    if not name or not version or not release:
        return None
    return (name, epoch, version, release, arch)


def build_vulnerabilities(ctx, scope, host_id, records):
    """Convert the CVE report the Vulnerability service publishes for one system
    into runZero findings. A CVE is matched against installed content, never
    against a listening port, so no service fields are set. Returns a list of
    (rank, Vulnerability) pairs so the caller can keep the most severe."""
    findings = []
    seen = []
    for record in records:
        cve = as_text(record.get("id"), join=",").strip().upper()
        if not re_match(CVE_RE, cve):
            continue
        if cve in seen:
            continue
        seen.append(cve)

        attributes = as_dict(record.get("attributes"))
        params = {
            "id": "{}:{}:{}:{}".format(VENDOR, scope, host_id, cve),
            "name": cve,
            "cve": cve,
            "category": "CVE",
        }

        description = as_text(attributes.get("description"), join=",").strip()
        if description:
            params["description"] = description[:1024]

        cvss3 = _to_float(attributes.get("cvss3_score"))
        if cvss3 >= 0:
            params["cvss3BaseScore"] = cvss3
        cvss2 = _to_float(attributes.get("cvss2_score"))
        if cvss2 >= 0:
            params["cvss2BaseScore"] = cvss2

        # Red Hat's own security impact is the severity the console shows, so it
        # drives the rank; the CVSS band only stands in when impact is absent.
        impact = as_text(attributes.get("impact"), join=",").strip()
        rank = IMPACT_RANK.get(impact.upper(), -1)
        if rank < 0:
            rank = _score_rank(cvss3) if cvss3 >= 0 else 0
        params["severityRank"] = rank
        params["riskRank"] = rank
        if cvss3 >= 0:
            params["severityScore"] = cvss3
            params["riskScore"] = cvss3

        if attributes.get("known_exploit") == True:
            params["exploitable"] = True

        published = parse_ts(attributes.get("public_date"))
        if published:
            params["publishedTS"] = published
        first_reported = parse_ts(attributes.get("first_reported"))
        if first_reported:
            params["firstDetectedTS"] = first_reported

        advisories = _strings(attributes.get("advisories_list"))
        if advisories:
            params["solution"] = "Apply {}".format(", ".join(advisories))[:1024]

        rule = as_dict(attributes.get("rule"))
        params["customAttributes"] = to_custom_attributes({
            "impact": impact,
            "status": attributes.get("status"),
            "status_text": attributes.get("status_text"),
            "business_risk": attributes.get("business_risk"),
            "synopsis": attributes.get("synopsis"),
            "advisories": advisories,
            "advisory_available": attributes.get("advisory_available"),
            "known_exploit": attributes.get("known_exploit"),
            "remediation": attributes.get("remediation"),
            "rule_id": rule.get("rule_id"),
            "rule_reboot_required": rule.get("reboot_required"),
            "rule_playbook_count": rule.get("playbook_count"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)

        findings.append((rank, Vulnerability(**params)))
    return findings


def fetch_vulnerabilities(ctx, host_id):
    """Fetch the CVE report for one system. The Vulnerability service has no
    endpoint that returns findings for several systems at once, so this is one
    request per system and the caller caps how many are made. A 404 means the
    system is not in the vulnerability database, which is normal for a host that
    has never uploaded an archive, so it is counted rather than reported."""
    url = "{}{}/systems/{}/cves".format(ctx["console_url"], VULNERABILITY_PATH, host_id)
    params = {"limit": str(VULN_PAGE_SIZE), "offset": "0", "sort": "-cvss3_score"}
    data, err = get_json(url, params=params, **ctx["http_options"])
    if err:
        if err.startswith("status 404"):
            ctx["vuln_missing"] += 1
            return []
        print("redhat-insights: failed to fetch CVEs for system {}: {}".format(host_id, err))
        return []
    data = data or {}
    return dicts(as_dict(data).get("data"))


def build_software(ctx, scope, host_id, profile):
    """Convert the NEVRA strings in installed_packages into Software records.

    Insights publishes no CPE for an installed package, so cpe23 is left unset
    rather than synthesized. The raw NEVRA is kept as a custom attribute because
    it is the exact string an operator would feed back to rpm or dnf."""
    software = []
    seen = []
    for entry in _strings(profile.get("installed_packages")):
        parsed = parse_nevra(entry)
        if not parsed:
            # Counted rather than printed per package: a host reports hundreds.
            ctx["package_skipped"] += 1
            continue
        name, epoch, version, release, arch = parsed
        key = "{}-{}-{}.{}".format(name, version, release, arch)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "id": "{}:{}:{}:package:{}".format(VENDOR, scope, host_id, key)[:255],
            "product": name[:255],
            # The package is installed on the host rather than bound to a
            # socket, so there is no real service address.
            "serviceAddress": "127.0.0.1",
            "version": "{}-{}".format(version, release)[:255],
        }
        if arch:
            params["targetHardware"] = arch[:255]
        params["customAttributes"] = to_custom_attributes({
            "package_nevra": entry,
            "package_epoch": epoch,
            "package_release": release,
            "package_arch": arch,
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software


def build_interfaces(record, profile):
    """Build runZero network interfaces for one system, and return them with the
    interface names and MACs that were used.

    system_profile.network_interfaces is preferred: it is collected from
    "ip addr" and keeps each NIC's own MAC and addresses together. The top-level
    ip_addresses and mac_addresses canonical facts are two unrelated lists that
    cannot be correlated, so they are only used when the profile is absent, and
    then the addresses become one interface and each MAC becomes another."""
    interfaces = []
    names = []
    macs = []

    for entry in dicts(profile.get("network_interfaces")):
        name = as_text(entry.get("name"), join=",").strip()
        kind = as_text(entry.get("type"), join=",").strip().lower()
        if kind in LOOPBACK_TYPES or name in LOOPBACK_NAMES:
            continue
        mac = _usable_mac(entry.get("mac_address"))
        ips = []
        for value in _strings(entry.get("ipv4_addresses")) + _strings(entry.get("ipv6_addresses")):
            routable = routable_ip(value)
            if routable and routable not in ips:
                ips.append(routable)
        if not mac and not ips:
            continue
        nic = network_interface(mac=mac, ips=ips)
        if not nic:
            continue
        interfaces.append(nic)
        if name:
            names.append(name)
        if mac:
            macs.append(mac)

    if interfaces:
        return interfaces[:MAX_INTERFACES], names, macs

    ips = []
    for value in _strings(record.get("ip_addresses")):
        routable = routable_ip(value)
        if routable and routable not in ips:
            ips.append(routable)
    if ips:
        nic = network_interface(ips=ips)
        if nic:
            interfaces.append(nic)
    for value in _strings(record.get("mac_addresses")):
        mac = _usable_mac(value)
        if not mac or mac in macs:
            continue
        nic = network_interface(mac=mac)
        if not nic:
            continue
        macs.append(mac)
        interfaces.append(nic)
    return interfaces[:MAX_INTERFACES], names, macs


def build_asset(ctx, record):
    """Convert one Insights inventory record into a runZero asset."""
    host_id = as_text(record.get("id"), join=",").strip()
    org_id = as_text(record.get("org_id"), join=",").strip()
    scope = org_id or ctx["fallback_scope"]
    profile = as_dict(record.get("system_profile"))

    interfaces, interface_names, interface_macs = build_interfaces(record, profile)

    fqdn = as_text(record.get("fqdn"), join=",").strip()
    display_name = as_text(record.get("display_name"), join=",").strip()
    # Inventory falls back to the host id when a system reports no fqdn, so a
    # name equal to the id is bookkeeping rather than a hostname and must not
    # become a searchable hostname on the asset.
    hostnames = [name for name in dedupe([fqdn, display_name]) if name != host_id]

    operating_system = as_dict(profile.get("operating_system"))
    os_name = OS_NAMES.get(as_text(operating_system.get("name"), join=",").strip(),
                           as_text(operating_system.get("name"), join=",").strip())
    os_version = ""
    major = operating_system.get("major")
    if type(major) == "int":
        minor = operating_system.get("minor")
        os_version = "{}.{}".format(major, minor if type(minor) == "int" else 0)
    if not os_version:
        os_version = as_text(profile.get("os_release"), join=",").strip()

    infrastructure = as_text(profile.get("infrastructure_type"), join=",").strip().lower()
    cloud_provider = as_text(profile.get("cloud_provider"), join=",").strip()
    reporter = as_text(record.get("reporter"), join=",").strip()
    host_type = as_text(profile.get("host_type"), join=",").strip()
    sap = as_dict(profile.get("sap"))

    groups = []
    for group in dicts(record.get("groups")):
        name = as_text(group.get("name"), join=",").strip()
        if name and name not in groups:
            groups.append(name)

    software = []
    if ctx["software"]:
        software = build_software(ctx, scope, host_id, profile)

    vulns = []
    if ctx["vulnerabilities"]:
        if ctx["vuln_limit"] and ctx["vuln_used"] >= ctx["vuln_limit"]:
            ctx["vuln_skipped"] += 1
        else:
            ctx["vuln_used"] += 1
            buckets = [[], [], [], [], []]
            for rank, finding in build_vulnerabilities(ctx, scope, host_id, fetch_vulnerabilities(ctx, host_id)):
                buckets[rank].append(finding)
            for rank in [4, 3, 2, 1, 0]:
                vulns.extend(buckets[rank])

    tags = [VENDOR]
    if org_id:
        tags.append("org:" + org_id)
    if infrastructure:
        tags.append("infrastructure:" + infrastructure)
    if cloud_provider:
        tags.append("cloud:" + cloud_provider)
    if reporter:
        tags.append("reporter:" + reporter)
    if host_type:
        tags.append("host-type:" + host_type)
    if profile.get("satellite_managed") == True:
        tags.append("satellite-managed")
    if sap.get("sap_system") == True:
        tags.append("sap")
    for name in groups:
        tags.append("workspace:" + name)

    attrs = {
        "host_id": host_id,
        "org_id": org_id,
        "display_name": as_text(record.get("display_name"), join=",").strip(),
        "fqdn": fqdn,
        "ansible_host": record.get("ansible_host"),
        # The other canonical facts. None of them is used as the runZero id -
        # see the README - but each is the join key for a different Red Hat
        # product, so all of them are searchable here.
        "insights_id": record.get("insights_id"),
        "subscription_manager_id": record.get("subscription_manager_id"),
        "satellite_id": record.get("satellite_id"),
        "bios_uuid": record.get("bios_uuid"),
        "provider_id": record.get("provider_id"),
        "provider_type": record.get("provider_type"),
        # The raw canonical address lists, kept verbatim because the interfaces
        # above have loopback and all-zero values filtered out of them.
        "ip_addresses": _strings(record.get("ip_addresses")),
        "mac_addresses": _strings(record.get("mac_addresses")),
        "interface_names": interface_names,
        "interface_macs": interface_macs,
        "reporter": reporter,
        "workspaces": groups,
        "created": record.get("created"),
        "updated": record.get("updated"),
        "last_check_in": record.get("last_check_in"),
        "stale_timestamp": record.get("stale_timestamp"),
        "stale_warning_timestamp": record.get("stale_warning_timestamp"),
        "culled_timestamp": record.get("culled_timestamp"),
        "openshift_cluster_id": record.get("openshift_cluster_id"),
        "arch": profile.get("arch"),
        "basearch": profile.get("basearch"),
        "operating_system": operating_system,
        "os_release": profile.get("os_release"),
        "os_kernel_version": profile.get("os_kernel_version"),
        "releasever": profile.get("releasever"),
        "system_update_method": profile.get("system_update_method"),
        "infrastructure_type": profile.get("infrastructure_type"),
        "infrastructure_vendor": profile.get("infrastructure_vendor"),
        "virtual_host_uuid": profile.get("virtual_host_uuid"),
        "cloud_provider": cloud_provider,
        "is_marketplace": profile.get("is_marketplace"),
        "host_type": host_type,
        "greenboot_status": profile.get("greenboot_status"),
        "cpu_model": profile.get("cpu_model"),
        "number_of_cpus": profile.get("number_of_cpus"),
        "number_of_sockets": profile.get("number_of_sockets"),
        "cores_per_socket": profile.get("cores_per_socket"),
        "threads_per_core": profile.get("threads_per_core"),
        "system_memory_bytes": profile.get("system_memory_bytes"),
        "bios_vendor": profile.get("bios_vendor"),
        "bios_version": profile.get("bios_version"),
        "bios_release_date": profile.get("bios_release_date"),
        "last_boot_time": profile.get("last_boot_time"),
        "captured_date": profile.get("captured_date"),
        "insights_client_version": profile.get("insights_client_version"),
        "insights_egg_version": profile.get("insights_egg_version"),
        "rhc_client_id": profile.get("rhc_client_id"),
        "owner_id": profile.get("owner_id"),
        "satellite_managed": profile.get("satellite_managed"),
        "subscription_status": profile.get("subscription_status"),
        "selinux_current_mode": profile.get("selinux_current_mode"),
        "tuned_profile": profile.get("tuned_profile"),
        "rhsm": profile.get("rhsm"),
        "system_purpose": profile.get("system_purpose"),
        "ansible": profile.get("ansible"),
        "systemd": profile.get("systemd"),
        "sap_system": sap.get("sap_system"),
        "sap_sids": _strings(sap.get("sids")),
        "sap_instance_number": sap.get("instance_number"),
        "sap_version": sap.get("version"),
        # Public addresses are the NAT egress or cloud front-end addresses. They
        # are recorded but never become an interface: a whole VPC shares them.
        "public_ipv4_addresses": _strings(profile.get("public_ipv4_addresses")),
        "public_dns": _strings(profile.get("public_dns")),
        "installed_products": [as_text(item.get("name"), join=",").strip() for item in dicts(profile.get("installed_products"))],
        # enabled_services holds systemd unit names with the .service suffix
        # already stripped by the collector. They are not listening ports and
        # cannot be turned into runZero services - see the README.
        "enabled_services": _strings(profile.get("enabled_services")),
        "enabled_service_count": len(_strings(profile.get("enabled_services"))),
        "kernel_modules": _strings(profile.get("kernel_modules")),
        "kernel_module_count": len(_strings(profile.get("kernel_modules"))),
        "package_count": len(_strings(profile.get("installed_packages"))),
        "software_count": len(software),
        "vulnerability_count": len(vulns),
        "profile_fields": ctx["profile_label"],
    }

    params = {
        "id": "{}:{}:{}".format(VENDOR, scope, host_id),
        "hostnames": hostnames,
        "networkInterfaces": interfaces,
        "tags": tags,
        "software": software[:MAX_CHILDREN],
        "vulnerabilities": vulns[:MAX_CHILDREN],
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),    }
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    # Only the virtual case is asserted. "physical" covers RHEL servers and
    # workstations alike, so runZero's own fingerprinting decides those.
    if infrastructure == "virtual":
        params["deviceType"] = "Virtual Machine"

    first_seen = parse_ts(record.get("created"))
    if first_seen:
        params["firstSeenTS"] = first_seen

    asset = ImportAsset(**params)
    last_seen = parse_ts(record.get("last_check_in")) or parse_ts(record.get("updated"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(ctx, records):
    """Convert a page of inventory records into runZero assets."""
    assets = []
    for record in records:
        if type(record) != "dict":
            continue
        host_id = as_text(record.get("id"), join=",").strip()
        if not host_id:
            print("redhat-insights: skipping system with no inventory id: display_name=" +
                  as_text(record.get("display_name"), join=","))
            continue
        assets.append(build_asset(ctx, record))
    return assets


def list_params(ctx, page):
    """Build the query parameters for one page of the host list.

    The sparse fieldset is a deepObject query parameter, so the requested system
    profile fields travel as one comma-joined value under fields[system_profile].
    Omitting it entirely returns no system profile data at all, which is the
    last resort when the server rejects the field names."""
    params = {
        "page": str(page),
        "per_page": str(ctx["page_size"]),
        "order_by": "updated",
        "order_how": "ASC",
    }
    fields = ctx["profile_fields"]
    if fields:
        params["fields[system_profile]"] = ",".join(fields)
    return params


def refresh_token(ctx):
    """Mint a new service account token and rebuild the request options.

    Red Hat single sign-on issues a token that expires after 15 minutes, which a
    large import can outlive, so an expired token is replaced in place rather
    than ending the run."""
    if not ctx["client_id"]:
        return False
    token = fetch_access_token(ctx["token_url"], ctx["client_id"], ctx["client_secret"],
                               ctx["token_scope"], ctx["config"])
    if not token:
        return False
    ctx["http_options"] = get_http_options(ctx["config"], headers={
        "Accept": "application/json",
        "Authorization": bearer(token),
    })
    return True


def fetch_hosts_page(ctx, page):
    """Fetch one page of the host list, returning (records, total, err).

    Two failures are recovered from rather than reported. An expired token comes
    back as a 401 and is replaced once. A rejected sparse fieldset comes back as
    a 400 naming the offending field; the request then drops to the reduced
    field set and, if that is rejected too, to no system profile at all."""
    url = ctx["inventory_url"] + HOSTS_PATH

    data, err = get_json(url, params=list_params(ctx, page), **ctx["http_options"])
    if err and err.startswith("status 401") and not ctx["reauthed"]:
        ctx["reauthed"] = True
        if refresh_token(ctx):
            data, err = get_json(url, params=list_params(ctx, page), **ctx["http_options"])

    for _attempt in range(1, 3):
        if not err or not err.startswith("status 400") or not ctx["profile_fields"]:
            break
        if ctx["profile_label"] == "full":
            ctx["profile_fields"] = REDUCED_PROFILE_FIELDS
            ctx["profile_label"] = "reduced"
        else:
            ctx["profile_fields"] = []
            ctx["profile_label"] = "none"
        print("redhat-insights: the server rejected the requested system profile fields, retrying with the {} set: {}".format(
            ctx["profile_label"], err))
        data, err = get_json(url, params=list_params(ctx, page), **ctx["http_options"])

    if err:
        return [], 0, err
    data = as_dict(data or {})
    total = data.get("total")
    return dicts(data.get("results")), total if type(total) == "int" else 0, None


def fetch_and_report_hosts(ctx):
    """Fetch and stream systems one page at a time so the full inventory is
    never held in memory at once. The system profile travels with the host list
    as a sparse fieldset, so ordinary inventory costs exactly one request per
    page rather than one per system."""
    reported = 0
    _pager = pager("redhat-insights")
    while _pager.next():
        page = _pager.page
        records, total, err = fetch_hosts_page(ctx, page)
        if err:
            if err.startswith("status 401") or err.startswith("status 403"):
                print("redhat-insights: authentication to the console API failed:", err)
            else:
                print("redhat-insights: failed to fetch systems:", err)
            return reported
        if not records:
            break

        reported += report_assets(build_assets(ctx, records))
        print("redhat-insights: reported {} of {} systems".format(reported, total or reported))
        if len(records) < ctx["page_size"]:
            break
        if total and reported >= total:
            break

    if ctx["vuln_skipped"]:
        print("redhat-insights: CVE enrichment limit of {} reached; findings were not imported for {} of {} systems".format(
            ctx["vuln_limit"], ctx["vuln_skipped"], reported))
    if ctx["vuln_missing"]:
        print("redhat-insights: {} systems are not present in the vulnerability database".format(ctx["vuln_missing"]))
    if ctx["package_skipped"]:
        print("redhat-insights: {} package strings did not have the documented NEVRA shape and were skipped".format(
            ctx["package_skipped"]))
    return reported


def fetch_access_token(token_url, client_id, client_secret, scope, config_kwargs):
    """Exchange service account credentials for a bearer token."""
    options = get_http_options(config_kwargs, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    })
    form = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        form["scope"] = scope
    data, err = post_json(token_url, body=bytes(url_encode(form)), **options)
    if err:
        print("redhat-insights: failed to obtain a service account token:", err)
        return ""
    data = as_dict(data or {})
    token = as_text(data.get("access_token"), join=",").strip()
    if not token:
        print("redhat-insights: the token response contained no access_token")
    return token


def main(**kwargs):
    console_url = get_url_base(kwargs).rstrip("/")
    if not console_url:
        print("redhat-insights: no console URL was configured")
        return None
    parsed = url_parse(console_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("redhat-insights: could not determine the console host from the configured URL")
        return None

    headers = {"Accept": "application/json"}
    client_id = get_string(kwargs, "client_id", default="").strip()
    client_secret = get_string(kwargs, "client_secret", default="")
    identity_header = get_string(kwargs, "identity_header", default="").strip()
    sso_url = get_string(kwargs, "sso_url", default="https://sso.redhat.com").strip().rstrip("/")
    token_url = sso_url + TOKEN_PATH

    if client_id and client_secret:
        token = fetch_access_token(token_url, client_id, client_secret,
                                   get_string(kwargs, "scope", default="").strip(), kwargs)
        if not token:
            return None
        headers["Authorization"] = bearer(token)
    elif identity_header:
        # Only internal and proxied deployments accept this. On console.redhat.com
        # the gateway sets the header itself from the bearer token.
        headers["x-rh-identity"] = identity_header
    else:
        print("redhat-insights: configure a service account client ID and secret, or an x-rh-identity header")
        return None

    vuln_limit = get_int(kwargs, "vulnerability_limit", default=500)
    if vuln_limit < 0:
        vuln_limit = 0

    software = get_bool(kwargs, "include_software", default=False)
    profile_fields = PROFILE_FIELDS + SOFTWARE_PROFILE_FIELDS if software else PROFILE_FIELDS

    ctx = {
        "config": kwargs,
        "console_url": console_url,
        "inventory_url": console_url + INVENTORY_PATH,
        "http_options": get_http_options(kwargs, headers=headers),
        "fallback_scope": scope,
        "token_url": token_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "token_scope": get_string(kwargs, "scope", default="").strip(),
        "page_size": get_int(kwargs, "page_size", default=50),
        "software": software,
        "profile_fields": profile_fields,
        "profile_label": "full",
        "vulnerabilities": get_bool(kwargs, "include_vulnerabilities", default=False),
        "vuln_limit": vuln_limit,
        "vuln_used": 0,
        "vuln_skipped": 0,
        "vuln_missing": 0,
        "package_skipped": 0,
        "reauthed": False,
    }

    reported = fetch_and_report_hosts(ctx)
    if not reported:
        print("redhat-insights: no assets retrieved")
    return None

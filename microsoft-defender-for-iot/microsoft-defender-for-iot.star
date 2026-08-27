# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-microsoft-defender-for-iot",
    "name": "Microsoft Defender for IoT",
    "type": "inbound",
    "description": "Imports OT devices, open ports, and vulnerabilities from one Microsoft Defender for IoT OT network sensor.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The sensor device id is a small per-sensor sequential integer, the
    # identifier shape that gets reused after a database reset or a re-image. A
    # foreign-id match cannot be vetoed by a conflicting MAC, IP, or name, so a
    # recycled id would merge unrelated devices with nothing able to stop it.
    # Correlate on the addresses instead. The id is still emitted, namespaced
    # with the sensor host. See README "Asset identity".
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "OT sensor URL",
            "type": "url",
            "required": True,
            "placeholder": "https://sensor.example.com",
            "description": "Base URL of one Defender for IoT OT network sensor. The API is per-sensor, so an estate with several sensors needs one credential and one task per sensor.",
        },
        {
            "key": "access_token",
            "label": "Sensor access token",
            "type": "secret",
            "required": True,
            "description": "Token generated on the sensor under System Settings > Integrations > Access Tokens. It is sent verbatim in the Authorization header, with no Bearer prefix.",
        },
        {
            "key": "authorized_filter",
            "label": "Device authorization filter",
            "type": "enum",
            "required": False,
            "default": "all",
            "options": ["all", "authorized", "unauthorized"],
            "description": "all omits the documented authorized query parameter and imports every device. authorized and unauthorized send authorized=true and authorized=false respectively.",
        },
        {
            "key": "include_vulnerabilities",
            "label": "Import the vulnerability report",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch /api/v1/reports/vulnerabilities/devices and attach its CVEs, open ports, and security findings. The report publishes no device id, so it is joined to the inventory by IP address or device name, which is best-effort.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'clean_hostname')
load('http', 'get_json', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_bool')
load('re', re_match='match')
load('coerce', 'as_text', 'as_dict', 'as_list', 'as_int', 'as_float', 'dedupe')

VENDOR = "microsoft-defender-for-iot"
ATTR_PREFIX = "microsoft_defender_for_iot"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# Both routes are single unpaginated calls: neither documents a limit, offset,
# page, or cursor parameter, so there is no pagination loop and no maxPages
# ceiling, because there is nothing for pager() to bound.
DEVICES_PATH = "/api/v1/devices/"
VULNERABILITY_REPORT_PATH = "/api/v1/reports/vulnerabilities/devices"

# get_json retries the transient statuses (408/425/429/5xx) with backoff and
# honors Retry-After. Three is the built-in default, named here so it sits
# beside the other tuning. Defender for IoT publishes no rate limit for the
# sensor API, so the retry budget is the only throttle handling there is.
HTTP_RETRIES = 3

MAX_INTERFACES = 32
MAX_CHILDREN = 99

# Documented `type` values that describe a map construct rather than a host.
# Compared case-folded, because the vocabulary is display text.
PSEUDO_DEVICE_TYPES = [
    "internet",
    "multicast/broadcast",
    "multicast",
    "broadcast",
    "group",
    "physical location",
]

# A MAC whose first octet has the low bit set is a group (multicast) address,
# and ff:ff:ff:ff:ff:ff is broadcast. Both parse cleanly and would otherwise be
# imported as an interface, which is a shared merge signal rather than an
# identifier, the same hazard the pseudo-device filter above exists for.
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
HEX_DIGITS = "0123456789abcdef"
DEFAULT_TRANSPORT = "tcp"
TRANSPORTS = ["tcp", "udp", "sctp"]

# Vulnerability.cve is validated against this shape and is NOT upper-cased for
# the script; a malformed value fails the whole record, so every candidate is
# upper-cased and checked before it is set.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# Characters kept when a report entry with no device id is keyed on its name.
SLUG_KEEP = "abcdefghijklmnopqrstuvwxyz0123456789.-"

# Per-record skip logging is capped and then tallied: an estate where hundreds
# of passively observed devices never yielded an address would otherwise emit
# one line each.
SKIP_LOG_LIMIT = 10

AUTHORIZED_FILTER = {"authorized": "true", "unauthorized": "false"}

# Microsoft's device `type` is display text drawn from a sensor vocabulary that
# mixes runZero's own spellings with sensor-specific ones ("Wifi Pineapple",
# "Slot"). Only spellings whose runZero equivalent is unambiguous are folded;
# everything else passes through verbatim, because a sensor's own
# classification of an OT device carries more information than a guessed one.
# The raw value survives as an attribute and the type: tag either way.
DEVICE_TYPES = {
    "workstation": "Desktop",
    "domain controller": "Server",
    "historian": "Server",
    "storage": "NAS",
    "wireless access point": "WAP",
    "access point": "WAP",
    "wifi pineapple": "WAP",
    "mobile phone": "Mobile",
    "voip": "IP Phone",
    "voip phone": "IP Phone",
    "camera": "IP Camera",
    "ip camera": "IP Camera",
    "rtu": "Industrial Control",
    "ied": "Industrial Control",
    "dcs controller": "Industrial Control",
    "industrial packaging system": "Industrial Control",
    "slot": "Industrial Control",
    "ot device": "Industrial Control",
    "iot device": "IoT",
    "unknown": "",
}


def _real_macs(macs):
    """Drop multicast and broadcast MACs, keeping only unicast hardware addresses."""
    kept = []
    for mac in macs:
        text = str(mac).strip().lower()
        if not text or text == BROADCAST_MAC:
            continue
        # First octet, however the vendor punctuated the address. Starlark
        # strings are not iterable, so this indexes rather than iterating.
        digits = ""
        for index in range(len(text)):
            ch = text[index]
            if ch in HEX_DIGITS:
                digits += ch
            if len(digits) == 2:
                break
        if len(digits) == 2 and (int(digits, 16) % 2) == 1:
            continue
        kept.append(mac)
    return kept

def _texts(value):
    """Coerce a documented JSON array of strings into a clean list of strings.

    ipAddresses, macAddresses, and antiViruses are all documented as nullable
    arrays, so a null, a bare string, or an array holding an object all have to
    survive. as_text returns "" for a dict or list rather than dumping Go
    syntax, and dedupe drops the blanks it leaves behind.
    """
    return dedupe([as_text(entry) for entry in as_list(value)])


def _hostname(value):
    """Return a value fit to import as a hostname, or "".

    Sensor-assigned device names are deliberately rejected. Defender for IoT
    labels a passively discovered device "PLC #14" or "OT Device #966", a
    display label built from a per-sensor type counter that restarts on each
    sensor, so "PLC #14" on two sensors names two unrelated devices.
    clean_hostname already refuses them; names the sensor genuinely learned
    from traffic still pass.
    """
    return clean_hostname(as_text(value)) or ""


def _slug(value):
    """Reduce a device name to an id-safe token."""
    text = as_text(value).lower()
    out = ""
    for index in range(len(text)):
        char = text[index]
        if char in SLUG_KEEP:
            out += char
        elif not out.endswith("-"):
            out += "-"
    return out.strip("-")


def _interfaces(macs, ips):
    """Build the network interfaces for one device.

    macAddresses and ipAddresses are separate arrays with no documented
    pairing, so the addresses ride on the first interface that survives
    validation and the remaining MACs become address-less interfaces. Carrying
    the pending list keeps the addresses on a device whose MACs are all
    unusable.
    """
    netifs = []
    pending = ips
    for mac in macs[:MAX_INTERFACES]:
        # network_interface returns None when nothing usable survives, and a
        # None element in networkInterfaces aborts the entire run.
        nic = network_interface(mac=mac, ips=pending)
        if nic:
            netifs.append(nic)
            pending = []
    if pending:
        nic = network_interface(ips=pending)
        if nic:
            netifs.append(nic)
    return netifs


def _protocol_names(value):
    """Collect the protocol names off a device record.

    The field table types protocols as an Object of {id, name, ipAddresses}
    while a sensor that observed several protocols can only report an array of
    them, so both shapes are accepted; as_list wraps a lone object.
    """
    names = []
    for entry in as_list(value):
        if type(entry) == "dict":
            names.append(as_text(entry.get("name")))
        else:
            names.append(as_text(entry))
    return dedupe(names)


def _device_type(raw):
    """Fold the sensor's device vocabulary onto a runZero device type.

    An unmapped value passes through unchanged rather than being dropped or
    guessed: "Wind Turbine" is a better answer than nothing, and the raw
    spelling is kept as an attribute regardless.
    """
    text = as_text(raw).strip()
    if not text:
        return ""
    mapped = DEVICE_TYPES.get(text.lower())
    if mapped == None:
        return text
    return mapped


def _rank_from_score(score):
    """Map a 0-10 CVE score onto the 0-4 runZero severity rank."""
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return 0


def _note_skip(ctx, message):
    """Log the first few skipped records and tally the rest."""
    ctx["skipped"] = ctx["skipped"] + 1
    if ctx["skipped"] <= SKIP_LOG_LIMIT:
        print("{}: {}".format(VENDOR, message))


def fetch_vulnerability_report(ctx):
    """Fetch the per-device vulnerability report and index it for the join.

    THE JOIN IS ON IP OR NAME, NOT ON THE DEVICE ID, because the report returns
    name and ipAddresses and no id at all, and the sibling CVE route takes an
    address as its path parameter for the same reason. Both keys are mutable, so
    the correlation is best-effort by construction. Each entry is indexed under
    every routable address it carries and under its lower-cased name, and is
    claimed at most once so two devices sharing an address cannot both absorb
    the same findings.
    """
    index = {"records": [], "by_ip": {}, "by_name": {}, "claimed": {}}
    if not ctx["include_vulnerabilities"]:
        return index

    data, err = get_json(ctx["base_url"] + VULNERABILITY_REPORT_PATH, **ctx["http_options"])
    if err:
        print("{}: failed to fetch the vulnerability report, importing devices without findings: {}".format(VENDOR, err))
        return index

    # The endpoint is documented as returning a JSON array. wrap=False means an
    # object arriving instead yields nothing rather than one bogus entry.
    entries = as_list(data, wrap=False)
    for entry in entries:
        if type(entry) != "dict":
            continue
        position = len(index["records"])
        index["records"].append(entry)
        for ip in routable_ips(_texts(entry.get("ipAddresses"))):
            if ip not in index["by_ip"]:
                index["by_ip"][ip] = position
        name = as_text(entry.get("name")).lower()
        if name and name not in index["by_name"]:
            index["by_name"][name] = position

    print("{}: indexed vulnerability findings for {} devices".format(VENDOR, len(index["records"])))
    return index


def claim_report(index, ips, name):
    """Claim the report entry for one device, by address first and name second.

    Returns (entry, join_key) so the asset can record which of the two mutable
    keys matched, or (None, "") when nothing did. The name compared is the raw
    sensor name, not the cleaned hostname: the report repeats the same sensor
    label ("IED #10"), a usable join key even though it is not a usable
    hostname.
    """
    for ip in ips:
        position = index["by_ip"].get(ip)
        if position != None and not index["claimed"].get(position):
            index["claimed"][position] = True
            return index["records"][position], "ip"

    key = as_text(name).lower()
    if key:
        position = index["by_name"].get(key)
        if position != None and not index["claimed"].get(position):
            index["claimed"][position] = True
            return index["records"][position], "name"
    return None, ""


def build_vulnerabilities(ctx, key, findings):
    """Build the CVE findings the vulnerability report carries for one device.

    The report's cves entries are {id, score, description}. No CVSS version is
    published alongside the score, so it drives the severity and risk ranks
    rather than being asserted as a CVSS v2 or v3 base score.
    """
    vulns = []
    for entry in as_list(findings.get("cves")):
        entry = as_dict(entry)
        raw = as_text(entry.get("id"))
        if not raw:
            continue

        cve = raw.upper()
        score = as_float(entry.get("score"), default=0.0)
        rank = _rank_from_score(score)
        params = {
            "id": "{}:{}:{}:cve:{}".format(VENDOR, ctx["scope"], key, cve),
            "name": raw[:255],
            "category": "CVE",
            "description": as_text(entry.get("description"))[:1024],
            "severityRank": rank,
            "severityScore": score,
            "riskRank": rank,
            "riskScore": score,
        }
        # A value that is not shaped like a CVE fails the whole Vulnerability
        # record rather than the field, so it is kept as the finding name only.
        if re_match(CVE_PATTERN, cve):
            params["cve"] = cve
        params["customAttributes"] = to_custom_attributes({
            "cve_score": entry.get("score"),
            "finding_source": "vulnerability_report",
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        vulns.append(Vulnerability(**params))
    return vulns


def build_services(findings, primary_ip):
    """Build Service records from the report's openedPorts list.

    Nothing is emitted without a routable address to bind the service to; a
    placeholder address is identical on every host and correlates nothing.
    """
    if not primary_ip:
        return []

    services = []
    seen = {}
    for entry in as_list(findings.get("openedPorts")):
        entry = as_dict(entry)
        port = as_int(entry.get("port"), default=0)
        if port < 1 or port > 65535:
            continue

        transport = as_text(entry.get("transport")).lower()
        assumed = transport not in TRANSPORTS
        if assumed:
            transport = DEFAULT_TRANSPORT
        key = "{}/{}".format(port, transport)
        if key in seen:
            continue
        seen[key] = True

        services.append(Service(
            address=primary_ip,
            port=port,
            transport=transport,
            customAttributes=to_custom_attributes({
                "service_source": "opened_ports",
                # protocol is the sensor's application-layer label ("SMP Over
                # IP", "HTTP"). It is kept as an attribute rather than a
                # ServiceProtocolData name, which expects a lower-case
                # protocol token.
                "protocol": entry.get("protocol"),
                "conflicting_with_firewall": entry.get("isConflictingWithFirewall"),
                "transport_source": "assumed" if assumed else "reported",
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        ))
    return services


def build_software(ctx, device_id, firmware, primary_ip):
    """Build one Software record per firmware module on the device.

    firmware is documented as an array of {address, moduleAddress, serial,
    model, firmwareVersion, additionalData, rack, slot}, naming the model and
    serial of each module in a chassis along with its rack and slot.
    """
    software = []
    modules = as_list(firmware)
    for position in range(len(modules[:MAX_CHILDREN])):
        module = as_dict(modules[position])
        model = as_text(module.get("model"))
        version = as_text(module.get("firmwareVersion"))
        serial = as_text(module.get("serial"))
        if not model and not version and not serial:
            continue

        # Software REQUIRES an id, and the name field is product, not name.
        identifier = as_text(module.get("moduleAddress")) or as_text(module.get("address")) or str(position)
        params = {
            "id": "{}:{}:device:{}:firmware:{}".format(VENDOR, ctx["scope"], device_id, identifier)[:255],
            "product": (model or "Firmware")[:255],
        }
        if version:
            params["version"] = version
        # An address-less device gets a firmware record with no serviceAddress
        # rather than a loopback placeholder, which is identical on every host.
        if primary_ip:
            params["serviceAddress"] = primary_ip
        # cpe23 is deliberately unset: the sensor publishes no CPE, and
        # Software.cpe23 accepts only the CPE 2.2 "cpe:/a:" binding.
        params["customAttributes"] = to_custom_attributes({
            "firmware_serial": serial,
            "firmware_model": model,
            "firmware_address": module.get("address"),
            "firmware_module_address": module.get("moduleAddress"),
            "firmware_rack": module.get("rack"),
            "firmware_slot": module.get("slot"),
            "firmware_additional_data": module.get("additionalData"),
        }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
        software.append(Software(**params))
    return software


def apply_report(params, attrs, tags, report, findings):
    """Fold the joined vulnerability report onto an asset under construction.

    Only fields the inventory does not already carry are filled in. The report's
    operatingSystem object is not trusted for the OS name: Microsoft's own
    sample puts a vendor string in it ("ABB Switzerland Ltd, Power Systems"), so
    only its version fields are used and the rest becomes attributes.
    """
    os_block = as_dict(report.get("operatingSystem"))
    if not params.get("manufacturer"):
        params["manufacturer"] = as_text(report.get("vendor"))
    if not params.get("model"):
        params["model"] = as_text(report.get("model"))
    if not params.get("osVersion"):
        params["osVersion"] = as_text(os_block.get("version"))

    plaintext = as_list(findings.get("plainTextPasswords"))
    weak_auth = as_list(findings.get("weakAuthentication"))
    remote_access = as_list(findings.get("remoteAccess"))

    if findings.get("malwareIndicationsDetected") == True:
        tags.append("malware-indications")
    if plaintext:
        tags.append("plaintext-passwords")
    if weak_auth:
        tags.append("weak-authentication")

    attrs["security_score"] = report.get("securityScore")
    attrs["report_firmware_version"] = report.get("firmwareVersion")
    attrs["report_os_name"] = os_block.get("name")
    attrs["report_os_type"] = os_block.get("type")
    attrs["report_os_latest_version"] = os_block.get("latestVersion")
    attrs["is_wireless_access_point"] = report.get("isWirelessAccessPoint")
    attrs["is_backup_server"] = findings.get("isBackupServer")
    attrs["report_is_engineering_station"] = findings.get("isEngineeringStation")
    attrs["report_is_known_scanner"] = findings.get("isKnownScanner")
    attrs["report_is_unauthorized"] = findings.get("isUnauthorized")
    attrs["malware_indications_detected"] = findings.get("malwareIndicationsDetected")
    attrs["anti_viruses"] = _texts(findings.get("antiViruses"))
    # Everything about each plain-text credential finding EXCEPT the credential.
    # The password is live and never leaves the sensor; strength is Microsoft's
    # own rating, which says how bad the finding is while disclosing nothing.
    attrs["plaintext_password_count"] = len(plaintext)
    attrs["plaintext_password_protocols"] = dedupe([as_text(as_dict(item).get("protocol")) for item in plaintext])
    attrs["plaintext_password_strengths"] = dedupe([as_text(as_dict(item).get("strength")) for item in plaintext])
    attrs["weak_authentication_count"] = len(weak_auth)
    # weakAuthentication is an array of strings naming the applications found
    # using weak authentication, so the names are kept beside the count: a bare
    # count names the risk without naming what to go and fix.
    attrs["weak_authentication_applications"] = _texts(weak_auth)
    # remoteAccess names a port on the device, the transport, the client that
    # reached it and the software it used. It is recorded rather than turned
    # into a Service because the report does not say the port is still open.
    attrs["remote_access_ports"] = dedupe([as_text(as_dict(item).get("port")) for item in remote_access])
    attrs["remote_access_transports"] = dedupe([as_text(as_dict(item).get("transport")) for item in remote_access])
    attrs["remote_access_clients"] = dedupe([as_text(as_dict(item).get("client")) for item in remote_access])
    attrs["remote_access_software"] = dedupe([as_text(as_dict(item).get("clientSoftware")) for item in remote_access])


def build_asset(ctx, device, index):
    """Convert one sensor inventory record into a runZero asset."""
    device_id = as_text(device.get("id"))
    if not device_id:
        _note_skip(ctx, "skipping a device record with no documented id")
        return None

    # The documented type vocabulary includes Internet, Multicast/Broadcast,
    # Group and Physical Location, which are map constructs rather than hosts.
    # With id matching off, MAC and IP do all the correlating, and a broadcast
    # or multicast MAC parses perfectly well, so importing these would give
    # every such row the same address and merge them onto one asset, and onto
    # any real asset that ever reported it.
    if as_text(device.get("type")).strip().lower() in PSEUDO_DEVICE_TYPES:
        ctx["pseudo_skipped"] = ctx.get("pseudo_skipped", 0) + 1
        return None

    ips = routable_ips(_texts(device.get("ipAddresses")))
    macs = _real_macs(dedupe(_texts(device.get("macAddresses"))))
    netifs = _interfaces(macs, ips)
    name = as_text(device.get("name"))
    hostname = _hostname(name)

    # The sensor id does not drive matching, so a record with no MAC, IP, or
    # hostname carries no correlation signal at all and would land as an
    # orphan asset that can never merge with anything. Skip it instead.
    if not netifs and not hostname:
        _note_skip(ctx, "skipping device {} with no MAC, IP, or usable hostname to correlate on".format(device_id))
        return None

    primary_ip = ips[0] if ips else ""
    protocols = _protocol_names(device.get("protocols"))

    tags = [VENDOR, "ot"]
    device_type = as_text(device.get("type"))
    if device_type:
        tags.append("type:" + device_type)
    if device.get("authorized") == False:
        tags.append("unauthorized")
    if device.get("engineeringStation") == True:
        tags.append("engineering-station")
    if device.get("scanner") == True:
        tags.append("scanner")

    attrs = {
        "device_id": device_id,
        "sensor": ctx["scope"],
        "device_name": name,
        "device_type": device_type,
        "authorized": device.get("authorized"),
        "engineering_station": device.get("engineeringStation"),
        "scanner": device.get("scanner"),
        "has_dynamic_address": device.get("hasDynamicAddress"),
        "operating_system": device.get("operatingSystem"),
        "protocols": protocols,
        "ip_addresses": ips,
        "mac_addresses": macs,
    }

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": netifs,
        "tags": tags,
        "os": as_text(device.get("operatingSystem")),
        "manufacturer": as_text(device.get("vendor")),
        "deviceType": _device_type(device_type),
    }

    firmware = as_list(device.get("firmware"))
    for module in firmware:
        module = as_dict(module)
        if not params.get("model"):
            params["model"] = as_text(module.get("model"))
        if not attrs.get("serial_number"):
            attrs["serial_number"] = as_text(module.get("serial"))
    software = build_software(ctx, device_id, firmware, primary_ip)

    services = []
    vulns = []
    report, join_key = claim_report(index, ips, name)
    if report:
        findings = as_dict(report.get("vulnerabilities"))
        apply_report(params, attrs, tags, report, findings)
        services = build_services(findings, primary_ip)
        vulns = build_vulnerabilities(ctx, "device:" + device_id, findings)
        attrs["vulnerability_join"] = join_key

    params["services"] = services[:MAX_CHILDREN]
    params["software"] = software[:MAX_CHILDREN]
    params["vulnerabilities"] = vulns[:MAX_CHILDREN]
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    # The sensor inventory publishes no first-seen or last-seen timestamp, so
    # neither is set and runZero stamps the import itself.
    return ImportAsset(**params)


def build_report_only_asset(ctx, report):
    """Build an asset for a report entry that never joined an inventory record.

    The report is documented as a strict subset of the inventory, so an
    unclaimed entry is a failed join rather than a device the inventory does not
    know. It is still reported, keyed on its own address and name, because
    dropping it would silently lose the findings; with id matching off, runZero
    correlates it back onto the inventory asset by IP or hostname.
    """
    ips = routable_ips(_texts(report.get("ipAddresses")))
    name = as_text(report.get("name"))
    hostname = _hostname(name)
    netifs = _interfaces([], ips)
    if not netifs and not hostname:
        _note_skip(ctx, "skipping a vulnerability report entry with no address or usable hostname")
        return None

    primary_ip = ips[0] if ips else ""
    key = "report:{}:{}".format(primary_ip or "noaddress", _slug(name) or "noname")
    findings = as_dict(report.get("vulnerabilities"))

    tags = [VENDOR, "ot", "vulnerability-report-only"]
    attrs = {
        "sensor": ctx["scope"],
        "device_name": name,
        "record_source": "vulnerability_report",
        "ip_addresses": ips,
    }
    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], key),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": netifs,
        "tags": tags,
    }
    apply_report(params, attrs, tags, report, findings)
    params["services"] = build_services(findings, primary_ip)[:MAX_CHILDREN]
    params["vulnerabilities"] = build_vulnerabilities(ctx, key, findings)[:MAX_CHILDREN]
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)


def fetch_and_report_devices(ctx, index):
    """Fetch the sensor inventory and stream each device as it is converted.

    The endpoint takes no paging parameters, so this is a single request whose
    body is the sensor's entire inventory. Each record is reported as it is
    built rather than accumulated, keeping one asset in flight at a time.
    """
    params = {}
    if ctx["authorized_filter"]:
        params["authorized"] = ctx["authorized_filter"]

    data, err = get_json(ctx["base_url"] + DEVICES_PATH, params=params, **ctx["http_options"])
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            print("{}: the sensor rejected the access token: {}".format(VENDOR, err))
        else:
            print("{}: failed to fetch the device inventory: {}".format(VENDOR, err))
        return 0

    devices = as_list(data, wrap=False)
    reported = 0
    for device in devices:
        if type(device) != "dict":
            _note_skip(ctx, "skipping an inventory entry that is not a device object")
            continue
        reported += report_asset(build_asset(ctx, device, index))
    return reported


def report_unjoined(ctx, index):
    """Report the vulnerability report entries no inventory record claimed."""
    reported = 0
    for position in range(len(index["records"])):
        if index["claimed"].get(position):
            continue
        reported += report_asset(build_report_only_asset(ctx, index["records"][position]))
    if reported:
        print("{}: reported {} devices seen only in the vulnerability report".format(VENDOR, reported))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    # The id namespace is the sensor HOSTNAME with the port stripped. Device
    # ids are only unique within one sensor, so the scope is mandatory, and a
    # sensor reached on a different port is still the same sensor.
    scope = parsed.hostname if parsed else ""
    if not scope:
        fail(VENDOR + ": could not determine the sensor host from the configured URL")

    # Defender for IoT takes the raw token in an Authorization header with no
    # Bearer prefix: curl -k -H "Authorization: <token>" https://<sensor>/api/v1/devices/
    http_options = get_http_options(kwargs, headers={
        "Authorization": get_string(kwargs, "access_token"),
        "Accept": "application/json",
    })
    http_options["retries"] = HTTP_RETRIES

    ctx = {
        "base_url": base_url,
        "http_options": http_options,
        "scope": scope,
        "authorized_filter": AUTHORIZED_FILTER.get(get_string(kwargs, "authorized_filter", default="all"), ""),
        "include_vulnerabilities": get_bool(kwargs, "include_vulnerabilities", default=True),
        "skipped": 0,
    }

    index = fetch_vulnerability_report(ctx)
    reported = fetch_and_report_devices(ctx, index)
    reported += report_unjoined(ctx, index)

    if ctx["skipped"] > SKIP_LOG_LIMIT:
        print("{}: skipped {} records with no id or nothing to correlate on".format(VENDOR, ctx["skipped"]))
    if ctx.get("pseudo_skipped"):
        print("{}: skipped {} Internet, multicast/broadcast, group, and physical-location records that are map constructs rather than hosts".format(VENDOR, ctx["pseudo_skipped"]))
    print("{}: reported {} assets from sensor {}".format(VENDOR, reported, scope))
    if not reported:
        print(VENDOR + ": no assets retrieved")
    return None

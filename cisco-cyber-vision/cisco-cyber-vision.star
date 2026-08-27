# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cisco-cyber-vision",
    "name": "Cisco Cyber Vision",
    "type": "inbound",
    "description": "Imports industrial devices, their hardware and firmware properties, and their vulnerabilities from a Cisco Cyber Vision Center.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # matchBehavior is deliberately absent, selecting the platform default of
    # match and break on id, MAC, IP, and name. The id is a Center-allocated
    # UUID, so it is not recycled the way a MAC- or IP-derived key is and it
    # survives a rename. See README "Asset identity".
    "maxPages": 10000,
    "params": [
        {
            "key": "url",
            "label": "Cyber Vision Center URL",
            "type": "url",
            "required": True,
            "placeholder": "https://cybervision.example.com",
            "description": "Base URL of the Cyber Vision Center. The /api/3.0 path is appended automatically.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Token created in the Center under Admin > API > Token. Sent in the x-token-id header.",
        },
        {
            "key": "inventory_source",
            "label": "Inventory source",
            "type": "enum",
            "required": False,
            "default": "auto",
            "options": ["auto", "devices", "preset"],
            "description": "auto reads /api/3.0/devices and falls back to the preset network node list if the Center refuses it. devices and preset pin one route.",
        },
        {
            "key": "preset_label",
            "label": "Preset label",
            "type": "string",
            "required": False,
            "default": "All data",
            "description": "Label of the preset whose network node list is read on the preset route. Cisco's own export script looks for 'All data'.",
        },
        {
            "key": "collect_vulnerabilities",
            "label": "Collect vulnerabilities",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read /api/3.0/devices/{id}/vulnerabilities for each device reporting a non-zero vulnerabilitiesCount. Costs one extra request per affected device.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 2000,
            "description": "Rows requested per page. Cisco's own export script reads 2000 at a time.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "Software", "Vulnerability", "to_custom_attributes")
load("net", "network_interface", "routable_ips", "clean_hostnames")
load("http", "get_json", "url_parse")
load("kwargs", "get_url_base", "get_http_options", "get_string", "get_int", "get_bool")
load("coerce", "as_text", "as_dict", "as_list", "as_int", "as_float", "as_bool", "dicts", "dedupe")
load("time", "parse_ts")
load("re", re_match="match")

VENDOR = "cisco-cyber-vision"
ATTR_PREFIX = "cisco_cyber_vision"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

DEVICES_PATH = "/api/3.0/devices"
PRESETS_PATH = "/api/3.0/presets"
NETWORKNODE_PATH = "/api/3.0/presets/{}/visualisations/networknode-list"

# The platform caps each child collection at 99 per asset and rejects the record
# above it.
CHILD_CAP = 99

# mac is documented as the device's single primary address. A list is accepted
# defensively, and this bounds what a surprising one can turn into.
MAX_INTERFACES = 8

# Vulnerability.cve is validated against this exact shape and is NOT upper-cased
# for the script, so a lower-case or malformed value fails the whole record.
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# A finding's fullDescription runs long; its attributes are truncated well
# inside the platform's 1024-character value limit.
VULN_ATTR_VALUE = 512

# otherProperties is the Center's unnormalized property bag and has no published
# key list, so it is bounded rather than copied wholesale onto the asset.
MAX_OTHER_PROPERTIES = 32

# firstActivity and lastActivity are epoch milliseconds. A Center reporting
# seconds instead would land its whole estate in January 1970, and a zero or
# year-1 value survives a != None check, so anything before 2000-01-01Z is
# treated as unusable rather than imported as an ancient date.
SEEN_FLOOR_UNIX = 946684800

# normalizedProperties keys confirmed in Cisco's own export script.
PROP_VENDOR = "vendor-name"
PROP_MODEL = "model-name"
PROP_MODEL_REF = "model-ref"
PROP_FIRMWARE = "fw-version"
PROP_HARDWARE = "hw-version"


def _center_host(base_url):
    """Return the Center hostname from the configured URL, which scopes every
    imported id.

    Device ids are allocated by one Center, so two Centers imported into one
    account would collide. The scheme and port are dropped: reaching the same
    Center on a different port must not re-key its entire estate.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def _row_id(row):
    """The row's id, used only to tell one page from a repeat of the last one."""
    return as_text(as_dict(row).get("id")).strip()

def _rows(data):
    """Return the record list in an API response.

    No response envelope is published, and Cisco's own client treats every
    /api/3.0 collection as a bare JSON array. A dict is still accepted, using
    the first non-empty list of objects inside it, so a Center that wraps its
    collections imports assets rather than silently reporting none.
    """
    if type(data) == "list":
        return dicts(data)
    for _key, value in as_dict(data).items():
        if type(value) == "list":
            found = dicts(value)
            if found:
                return found
    return []


def _is_device(row):
    """False only when the row is explicitly a component.

    The preset network node list returns a device and each of its components as
    sibling rows told apart only by isDevice, so one PLC with three interfaces
    would be imported four times. /api/3.0/devices is not documented to filter
    components out either, so the flag is honored on both routes. An absent flag
    is read as a device, so a Center that omits isDevice still imports.
    """
    if "isDevice" not in row:
        return True
    return as_bool(row.get("isDevice"), default=True)


def _values(row, key):
    """Read a field documented as a single value that may arrive as a list."""
    return dedupe([as_text(value) for value in as_list(row.get(key))])


def _properties(row, key_name):
    """Flatten a documented [{key, value}] property list into a map.

    normalizedProperties carries the hardware detail: vendor-name, model-name,
    model-ref, fw-version, and hw-version. otherProperties sits beside it in the
    same schema with whatever the Center learned but did not normalize.
    """
    out = {}
    for prop in dicts(row.get(key_name)):
        key = as_text(prop.get("key")).strip()
        value = as_text(prop.get("value")).strip()
        if key and value:
            out[key] = value
    return out


def _tags(row):
    """Tag labels, plus the device group as a group: tag.

    tags is documented as a list of objects carrying a label; bare strings are
    accepted too, so a shape change does not silently drop every tag.
    """
    out = []
    for tag in as_list(row.get("tags")):
        if type(tag) == "dict":
            out.append(as_text(tag.get("label")))
        else:
            out.append(as_text(tag))
    group_label = as_text(as_dict(row.get("group")).get("label")).strip()
    if group_label:
        out.append("group:" + group_label)
    return dedupe(out)


def _first(row, keys):
    """First non-empty value among several spellings of one documented field.

    DevNet publishes the vulnerability object in camel case (CVSSVectorString)
    while Cisco's own export script reads the same route snake-cased
    (CVSS_vector_string). Both are seen live, so both are accepted.
    """
    for key in keys:
        text = as_text(row.get(key)).strip()
        if text:
            return text
    return ""


def _rank_from_score(score):
    """Map a documented 0-10 CVSS score onto the 0-4 runZero severity rank."""
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return 0


def _seen_ts(value):
    """Parse an activity timestamp, rejecting the "never" and mis-scaled values.

    parse_ts does not return None for every empty-ish value: an ISO year-1
    stamp parses to a large negative epoch and a 1970 value to zero. unit="ms"
    is explicit because the field is documented in milliseconds and parse_ts
    deliberately does not guess the scale.
    """
    number = as_int(value, default=0)
    if number > 0:
        ts = parse_ts(number, unit="ms")
    else:
        text = as_text(value)
        if not text:
            return None
        ts = parse_ts(text)
    if ts == None or ts.unix < SEEN_FLOOR_UNIX:
        return None
    return ts


def _detected_ts(value):
    """Parse a vulnerability timestamp, rejecting only the "never" sentinels.

    These are ISO date-times rather than epochs, and the 2000 floor _seen_ts
    applies would discard a genuine 1999 CVE publication date.
    """
    text = as_text(value)
    if not text:
        return None
    ts = parse_ts(text)
    if ts == None or ts.unix <= 0:
        return None
    return ts


def _cve(row):
    """Return the CVE a finding names, upper-cased, or "".

    cve is the documented identifier field; the scan over the rest of the row is
    a fallback for a Center that leaves it empty. Neither path asserts a value
    the platform would reject, since both go through CVE_PATTERN.
    """
    text = as_text(row.get("cve")).strip().upper()
    if text and re_match(CVE_PATTERN, text):
        return text
    for _key, value in row.items():
        candidate = as_text(value).strip().upper()
        if candidate and re_match(CVE_PATTERN, candidate):
            return candidate
    return ""


def _vulnerability_key(row, cve):
    """The stable per-device key a finding is identified by.

    A CVE-less advisory still has to reconcile against itself on the next poll,
    so the documented id is used, then vendorId, then the title. Nothing
    generated is used: a random key would re-import the advisory every run.
    """
    if cve:
        return "cve:" + cve
    row_id = as_text(row.get("id")).strip()
    if row_id:
        return "finding:" + row_id
    vendor_id = _first(row, ["vendorId", "vendor_id"])
    if vendor_id:
        return "vendor:" + vendor_id
    title = _first(row, ["title", "summary"])
    if title:
        return "title:" + title
    return ""


def build_vulnerability(ctx, device_id, row, cve, key):
    """Convert one finding into a runZero Vulnerability.

    A finding with no CVE is imported under its title rather than dropped: a
    vendor advisory carrying cve null still has a title, a CVSS score, a
    summary, a solution and a vendorId, and it is a real finding.
    """
    title = _first(row, ["title", "summary"])
    params = {
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], device_id, key)[:255],
        "name": (title or cve)[:255],
        "category": "CVE" if cve else "Advisory",
    }
    if cve:
        params["cve"] = cve
    description = _first(row, ["summary", "fullDescription", "full_description"])
    if description:
        params["description"] = description[:1024]
    solution = as_text(row.get("solution")).strip()
    if solution:
        params["solution"] = solution[:1024]

    # CVSS is a documented 0-10 double, so the rank is a mapping rather than a
    # guess at an unpublished severity vocabulary. The platform accepts a score
    # above 10 without complaint, so out-of-range values are capped here.
    score = as_float(_first(row, ["CVSS", "cvss"]))
    if score > 10.0:
        score = 10.0
    if score > 0.0:
        rank = _rank_from_score(score)
        params["severityScore"] = score
        params["severityRank"] = rank
        params["riskScore"] = score
        params["riskRank"] = rank

    published = _detected_ts(row.get("publishTime"))
    if published:
        params["publishedTS"] = published
    # matchingTime is documented as "at which time the component has been found
    # vulnerable", which is a detection time rather than a publication one.
    detected = _detected_ts(row.get("matchingTime"))
    if detected:
        params["firstDetectedTS"] = detected
    updated = _detected_ts(row.get("lastUpdate"))
    if updated:
        params["lastDetectedTS"] = updated

    params["customAttributes"] = to_custom_attributes({
        "finding_id": row.get("id"),
        "cvss_version": _first(row, ["CVSSVersion", "CVSS_version"]),
        "cvss_vector_string": _first(row, ["CVSSVectorString", "CVSS_vector_string"]),
        "cvss_temporal": _first(row, ["CVSSTemporal", "CVSS_temporal"]),
        "vendor_id": _first(row, ["vendorId", "vendor_id"]),
        # The raw identifier is kept even when it was too malformed to assert as
        # the cve field, which is the only place that value survives.
        "cve_raw": row.get("cve"),
        "ack_author": row.get("ackAuthor"),
        "ack_comment": row.get("ackComment"),
    }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR, max_value=VULN_ATTR_VALUE)
    return Vulnerability(**params)


def build_software(scope, device_id, props, primary_ip):
    """Build a firmware Software record from the normalized hardware properties.

    Cyber Vision reports no installed-software inventory; the make, model, and
    firmware of the device itself is the OT equivalent.
    """
    vendor = props.get(PROP_VENDOR, "")
    model = props.get(PROP_MODEL, "")
    firmware = props.get(PROP_FIRMWARE, "")
    if not vendor and not model and not firmware:
        return []

    params = {
        # Software requires an id, and the name field is product, not name.
        "id": "{}:{}:{}:firmware".format(VENDOR, scope, device_id)[:255],
        "product": model or "Firmware",
    }
    if vendor:
        params["vendor"] = vendor
    if firmware:
        params["version"] = firmware
    # A device with no address gets a record with no serviceAddress rather than
    # a placeholder, which would be identical on every device.
    if primary_ip:
        params["serviceAddress"] = primary_ip
    # cpe23 is deliberately unset: the Center publishes no CPE, and
    # Software.cpe23 accepts only the CPE 2.2 "cpe:/a:" binding.
    params["customAttributes"] = to_custom_attributes({
        "hw_version": props.get(PROP_HARDWARE, ""),
        "model_ref": props.get(PROP_MODEL_REF, ""),
    }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return [Software(**params)]


def build_asset(ctx, row, device_id, vulns):
    """Convert one Cyber Vision device row into a runZero asset."""
    props = _properties(row, "normalizedProperties")
    other_props = _properties(row, "otherProperties")

    # routable_ips drops loopback, unspecified, and link-local values: an APIPA
    # address a device invents when DHCP fails identifies nothing and would
    # correlate unrelated hosts to each other.
    ips = routable_ips(_values(row, "ip"))
    macs = _values(row, "mac")
    # network_interface accepts only mac= and ips=, and returns None when
    # nothing usable survives; passing [None] to ImportAsset aborts the run.
    netifs = []
    if macs:
        # The two fields are not positionally paired, so the addresses ride on
        # the first interface and any further MAC becomes an interface of its own
        # rather than being dropped.
        for index in range(len(macs[:MAX_INTERFACES])):
            nic = network_interface(mac=macs[index], ips=ips if index == 0 else [])
            if nic:
                netifs.append(nic)
    else:
        nic = network_interface(mac="", ips=ips)
        if nic:
            netifs.append(nic)

    # label is the display name, customLabel what an operator set, originalLabel
    # what the Center discovered. clean_hostnames drops placeholders and values
    # that are really addresses, which is what an unidentified node is named
    # after and would follow the address to the next node holding it.
    names = clean_hostnames([
        as_text(row.get("label")),
        as_text(row.get("customLabel")),
        as_text(row.get("originalLabel")),
    ])

    # An asset with no MAC, IP, or hostname can never merge with anything and
    # would only ever accumulate as a stub.
    if not netifs and not names:
        ctx["no_correlator_skipped"] = ctx["no_correlator_skipped"] + 1
        return None

    group = as_dict(row.get("group"))
    attrs = {
        "id": device_id,
        "label": row.get("label"),
        "original_label": row.get("originalLabel"),
        "custom_label": row.get("customLabel"),
        "device_type": row.get("deviceType"),
        "device_type_description": row.get("deviceTypeDescription"),
        "risk_score": row.get("riskScore"),
        "best_achievable_score": row.get("bestAchievableScore"),
        "vulnerabilities_count": row.get("vulnerabilitiesCount"),
        "icon": row.get("icon"),
        "group_label": group.get("label"),
        "group_color": group.get("color"),
        "group_criticalness": group.get("criticalness"),
        # The raw values are recorded whether or not they parsed: parse_ts caps
        # a future stamp at now, so the attribute is the only place what the
        # Center actually reported survives.
        "first_activity": row.get("firstActivity"),
        "last_activity": row.get("lastActivity"),
    }
    for key, value in props.items():
        attrs["property_" + key.replace("-", "_")] = value
    # Bounded: otherProperties has no published key list, and a chatty Center
    # must not spend one asset's whole attribute budget on it.
    for key in sorted(other_props)[:MAX_OTHER_PROPERTIES]:
        attrs["other_property_" + key.replace("-", "_")] = other_props[key]

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": names,
        "networkInterfaces": netifs,
        "tags": _tags(row),
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                 separator=ATTR_SEPARATOR),
    }
    first_ts = _seen_ts(row.get("firstActivity"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    last_ts = _seen_ts(row.get("lastActivity"))
    if last_ts:
        params["lastSeenTS"] = last_ts
    vendor = props.get(PROP_VENDOR, "")
    if vendor:
        params["manufacturer"] = vendor
    model = props.get(PROP_MODEL, "")
    if model:
        params["model"] = model
    # deviceType is the Center's own device class. The longer
    # deviceTypeDescription stays an attribute, since runZero matches on the
    # short type. The icon path is never used: a class derived from an icon
    # filename would label most of an estate "default".
    device_type = as_text(row.get("deviceType")).strip()
    if device_type:
        params["deviceType"] = device_type
    if vulns:
        params["vulnerabilities"] = vulns
    software = build_software(ctx["scope"], device_id, props, ips[0] if ips else "")
    if software:
        params["software"] = software
    return ImportAsset(**params)


def fetch_vulnerabilities(ctx, row, device_id):
    """Read the findings for one device.

    Gated on vulnerabilitiesCount so a Center full of clean devices is not
    walked once per row for nothing, and behind an operator toggle because it
    costs one request per affected device.
    """
    if not ctx["collect_vulnerabilities"]:
        return []
    if as_int(row.get("vulnerabilitiesCount")) <= 0:
        return []

    url = "{}{}/{}/vulnerabilities".format(ctx["base_url"], DEVICES_PATH, device_id)
    data, err = get_json(url, **ctx["options"])
    if err:
        ctx["vuln_failed"] = ctx["vuln_failed"] + 1
        return []

    vulns = []
    seen = {}
    for item in _rows(data):
        cve = _cve(item)
        key = _vulnerability_key(item, cve)
        # Only a finding with nothing to key on is dropped. A row carrying no
        # CVE is still a finding, and is imported under its title.
        if not key:
            ctx["vuln_unidentified_skipped"] = ctx["vuln_unidentified_skipped"] + 1
            continue
        if key in seen:
            continue
        if len(vulns) >= CHILD_CAP:
            ctx["vuln_capped"] = ctx["vuln_capped"] + 1
            break
        seen[key] = True
        if not cve:
            ctx["vuln_advisory"] = ctx["vuln_advisory"] + 1
        vulns.append(build_vulnerability(ctx, device_id, item, cve, key))
    return vulns


def process_rows(ctx, rows):
    """Report one page of rows, dropping components and unusable records."""
    reported = 0
    for row in rows:
        if not _is_device(row):
            ctx["component_skipped"] = ctx["component_skipped"] + 1
            continue
        device_id = as_text(row.get("id")).strip()
        if not device_id:
            ctx["no_id_skipped"] = ctx["no_id_skipped"] + 1
            continue
        vulns = fetch_vulnerabilities(ctx, row, device_id)
        reported += report_asset(build_asset(ctx, row, device_id, vulns))
    return reported


def fetch_devices_route(ctx):
    """Walk /api/3.0/devices, streaming each page as it arrives.

    page and size are the documented pagination parameters for this API.
    Termination is the documented one: stop on an empty page, or on a page
    shorter than the one that was asked for.
    """
    reported = 0
    p = pager("devices")
    while p.next():
        data, err = get_json(ctx["base_url"] + DEVICES_PATH,
                             params={"page": p.page, "size": ctx["page_size"]},
                             **ctx["options"])
        if err:
            return reported, err
        rows = _rows(data)
        if not rows:
            break
        reported += process_rows(ctx, rows)
        if len(rows) < ctx["page_size"]:
            break
    return reported, None


def fetch_preset_route(ctx):
    """Walk the network node list of the configured preset.

    It pages with page and size, the parameters DevNet documents for this URI;
    limit and offset are not query parameters of this route at all, and a Center
    ignores them, returning either the whole inventory on every call or a
    silently truncated default page. The route returns devices and components
    together, which is why every row is checked with _is_device.
    """
    data, err = get_json(ctx["base_url"] + PRESETS_PATH, **ctx["options"])
    if err:
        print("cisco-cyber-vision: failed to list presets:", err)
        return 0

    preset_id = ""
    wanted = ctx["preset_label"].lower()
    for preset in _rows(data):
        if as_text(preset.get("label")).strip().lower() == wanted:
            preset_id = as_text(preset.get("id")).strip()
            break
    if not preset_id:
        print("cisco-cyber-vision: no preset labeled '{}' on this Center".format(ctx["preset_label"]))
        return 0

    reported = 0
    seen_signature = ""
    p = pager("networknode-list")
    while p.next():
        data, err = get_json(ctx["base_url"] + NETWORKNODE_PATH.format(preset_id),
                             params={"page": p.page, "size": ctx["page_size"]},
                             **ctx["options"])
        if err:
            print("cisco-cyber-vision: failed to read the preset network node list:", err)
            break
        rows = _rows(data)
        if not rows:
            break
        # A Center that ignores the paging parameters answers every request with
        # the same rows. Without this the walk re-reports one inventory until
        # maxPages raises, costing thousands of full-inventory requests and
        # failing the task. The page's length and end ids are enough to notice.
        signature = "{}|{}|{}".format(len(rows), _row_id(rows[0]), _row_id(rows[-1]))
        if signature == seen_signature:
            print("cisco-cyber-vision: the Center returned an identical page for page {}, so it is not honouring page and size; stopping the walk".format(p.page))
            break
        seen_signature = signature
        reported += process_rows(ctx, rows)
        if len(rows) < ctx["page_size"]:
            break
    return reported


def report_tallies(ctx):
    """One summary line per class of dropped record, and none when there are
    none. A per-record line here would be thousands of lines on a real Center."""
    if ctx["component_skipped"]:
        print("cisco-cyber-vision: skipped {} component rows that belong to an imported device".format(ctx["component_skipped"]))
    if ctx["no_id_skipped"]:
        print("cisco-cyber-vision: skipped {} rows with no device id".format(ctx["no_id_skipped"]))
    if ctx["no_correlator_skipped"]:
        print("cisco-cyber-vision: skipped {} devices with no MAC, IP, or hostname".format(ctx["no_correlator_skipped"]))
    if ctx["vuln_failed"]:
        print("cisco-cyber-vision: {} device vulnerability lookups failed".format(ctx["vuln_failed"]))
    if ctx["vuln_advisory"]:
        print("cisco-cyber-vision: imported {} findings that name no CVE, under their titles".format(ctx["vuln_advisory"]))
    if ctx["vuln_unidentified_skipped"]:
        print("cisco-cyber-vision: skipped {} findings with no CVE, id, or title".format(ctx["vuln_unidentified_skipped"]))
    if ctx["vuln_capped"]:
        print("cisco-cyber-vision: capped findings at {} on {} devices".format(CHILD_CAP, ctx["vuln_capped"]))


def main(**kwargs):
    base_url = get_url_base(kwargs)
    # CONFIG defaults are not applied on the script --kwargs path, so every
    # default is repeated here.
    source = get_string(kwargs, "inventory_source", default="auto")
    preset_label = get_string(kwargs, "preset_label", default="All data")
    page_size = get_int(kwargs, "page_size", default=500)
    if page_size < 1:
        page_size = 500

    scope = _center_host(base_url)
    if not scope:
        print("cisco-cyber-vision: could not derive a Center hostname from the configured URL")
        return None
    if not get_string(kwargs, "api_token"):
        print("cisco-cyber-vision: no API token configured; create one under Admin > API > Token")
        return None

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "page_size": page_size,
        "preset_label": preset_label or "All data",
        "collect_vulnerabilities": get_bool(kwargs, "collect_vulnerabilities", default=True),
        # The credential is a static header token issued under Admin > API >
        # Token. Cisco documents no lifetime for it, so there is no refresh
        # flow and the options are built once.
        "options": get_http_options(kwargs, headers={
            "x-token-id": get_string(kwargs, "api_token"),
            "Accept": "application/json",
        }),
        "component_skipped": 0,
        "no_id_skipped": 0,
        "no_correlator_skipped": 0,
        "vuln_failed": 0,
        "vuln_advisory": 0,
        "vuln_unidentified_skipped": 0,
        "vuln_capped": 0,
    }

    reported = 0
    if source == "preset":
        reported = fetch_preset_route(ctx)
    else:
        reported, err = fetch_devices_route(ctx)
        if err and reported == 0 and source == "auto":
            # The bare device list is corroborated by a third-party client
            # rather than by a DevNet reference page, so a Center that does not
            # serve it falls back to the route Cisco's own script uses.
            print("cisco-cyber-vision: {} was refused ({}), falling back to the preset network node list".format(DEVICES_PATH, err))
            reported = fetch_preset_route(ctx)
        elif err:
            print("cisco-cyber-vision: failed to read the device list:", err)

    report_tallies(ctx)
    print("cisco-cyber-vision: reported {} devices".format(reported))
    return None

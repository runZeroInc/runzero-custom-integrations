# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-phpipam",
    "name": "phpIPAM",
    "type": "inbound",
    "description": "Imports IPAM address records and the registered device inventory from a self-hosted phpIPAM instance.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # An 'address' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'address': "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "phpIPAM URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ipam.example.com",
            "description": "Base URL of the phpIPAM web application, including any path prefix it is mounted under. Must be HTTPS: phpIPAM refuses every API request that does not arrive over TLS.",
        },
        {
            "key": "app_id",
            "label": "API app ID",
            "type": "string",
            "required": True,
            "placeholder": "runzero",
            "description": "The App ID of the API client created under Administration -> API. It is a path segment on every request.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "phpIPAM user that authenticates against the API app. Sent as the HTTP Basic username to POST /api/<app_id>/user/.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Password for that phpIPAM user.",
        },
        {
            "key": "import_addresses",
            "label": "Import IPAM addresses",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import one asset per managed IP address. Addresses are walked subnet by subnet so memory stays bounded by a single subnet.",
        },
        {
            "key": "import_devices",
            "label": "Import registered devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the operator-maintained device inventory (switches, routers, firewalls) from /devices/.",
        },
        {
            "key": "sections",
            "label": "Sections",
            "type": "string",
            "required": False,
            "description": "Comma-separated section names or numeric IDs to import. Leave blank to import every section the API user can read.",
        },
        {
            "key": "address_tags",
            "label": "Address tags",
            "type": "string",
            "required": False,
            "description": "Comma-separated phpIPAM address tag names or IDs to import, for example 'Used,Reserved'. Leave blank to import every tag. Default phpIPAM tags are Offline, Used, Reserved, and DHCP.",
        },
        {
            "key": "require_identity",
            "label": "Skip addresses with no hostname or MAC",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Skip address rows that carry only an IP. An IPAM is mostly empty reservations, and a bare address merges onto whatever else holds that IP today.",
        },
        {
            "key": "max_subnets",
            "label": "Maximum subnets",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on subnets walked in one run. 0 removes the cap.",
        },
        {
            "key": "max_addresses",
            "label": "Maximum addresses",
            "type": "int",
            "required": False,
            "default": 100000,
            "min": 0,
            "description": "Cap on address assets imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", "get_json", "post_json", "basic", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", 'parse_ts')

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "phpipam"
ATTR_PREFIX = "phpipam"
ATTR_SEPARATOR = "_"

HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null", "-", "0.0.0.0", "n/a"]

# phpIPAM writes '1970-01-01 00:00:01' into ipaddresses.lastSeen as the "never
# seen" sentinel (it is the column default in the shipped schema). Treating it
# as a real sighting would backdate every unscanned reservation to the epoch.
NEVER_SEEN = "1970-01-01 00:00:01"

# devices.snmp_community and the snmp_v3_* pair are stored in CLEARTEXT and are
# returned verbatim by GET /devices/ - phpIPAM runs SELECT * over the table and
# does not redact them. Copying them into runZero would spread the credential to
# a second system, so they are dropped before any attribute mapping. Verified
# against phpIPAM 1.8.1.
SNMP_SECRET_FIELDS = [
    "snmp_community",
    "snmp_v3_auth_pass",
    "snmp_v3_priv_pass",
    "snmp_v3_ctx_engine_id",
]

# phpIPAM's device type table is user-editable; these are the nine types the
# shipped schema creates. The names are resolved from /tools/device_types/ at
# runtime, and this table only maps a resolved NAME onto a runZero device type.
DEVICE_TYPE_MAP = {
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "wireless": "Wireless Access Point",
    "database": "Server",
    "workstation": "Desktop",
    "laptop": "Laptop",
    "server": "Server",
    "printer": "Printer",
    "storage": "Storage",
}
def _to_int(value):
    if type(value) == "int":
        return value
    text = as_text(value, join=",").strip()
    if not text or len(text) > 12:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)

def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    normalize_mac is deliberately avoided. It clears the locally administered
    bit, and an IPAM records whatever MAC an operator or a discovery scan
    observed - including randomized client MACs, every one of which sets that
    bit. Two such addresses differing only in the LAA bit would collapse onto
    one value.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    if text == "000000000000" or text == "ffffffffffff":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text
def _scope(base_url):
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]

def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used. It keeps only scheme and host, and
    phpIPAM is very commonly reverse-proxied under a path prefix such as
    /phpipam/ - the shipped config.php has a BASE setting for exactly that - so
    dropping the path would send every request to the wrong place.
    """
    return as_text(url, join=",").strip().rstrip("/")

def login(ctx, username, password):
    """Exchange Basic credentials for a phpIPAM API token.

    POST /api/<app_id>/user/ answers
    {"code":200,"success":true,"data":{"token":"...","expires":"..."}}.
    The token goes back in a bare `token` header - not Authorization, and not
    a Bearer credential. It is valid for 6 hours by default, far longer than a
    collection run, so no refresh path is implemented.
    """
    url = "{}/api/{}/user/".format(ctx["base_url"], ctx["app_id"])
    options = get_http_options(ctx["kwargs"], headers={
        "Authorization": basic(username, password),
        "Accept": "application/json",
    })
    data, err = post_json(url, json={}, **options)
    if err:
        # phpIPAM answers 503 "SSL connection is required for API" to every
        # request that did not arrive over TLS, whatever the app's security
        # mode. It is the single most common setup failure, so name it.
        if "503" in err:
            print("phpipam: login failed: {}. If this says 'SSL connection is required for API', ".format(err) +
                  "the phpIPAM URL must be https:// - phpIPAM refuses API requests over plain HTTP.")
        else:
            print("phpipam: login failed:", err)
        return ""
    if type(data) != "dict":
        print("phpipam: login returned an unexpected body")
        return ""
    payload = data.get("data")
    if type(payload) != "dict":
        print("phpipam: login succeeded but returned no data object")
        return ""
    token = as_text(payload.get("token"), join=",").strip()
    if not token:
        print("phpipam: login succeeded but returned no token")
        return ""
    return token

def fetch(ctx, path):
    """Call a phpIPAM API endpoint and return its `data` payload, or None.

    Every phpIPAM response is the envelope
    {"code":N,"success":bool,"data":...,"message":"..."}. An EMPTY COLLECTION IS
    A 404, not a 200 with an empty array - "No devices configured", "No
    addresses found", "No custom fields defined" all arrive that way. So a 404
    is translated into an empty list rather than treated as a failure, which is
    the single most important behaviour in this function.
    """
    url = "{}/api/{}{}".format(ctx["base_url"], ctx["app_id"], path)
    data, err = get_json(url, **ctx["http_options"])
    if err:
        # Only a real 404 status is an empty collection; matching "404"
        # anywhere in the error would also swallow a 5xx whose body happens
        # to mention 404.
        if err.startswith("status 404"):
            return []
        print("phpipam: {} failed: {}".format(path, err))
        return None
    if type(data) != "dict":
        print("phpipam: {} returned an unexpected body".format(path))
        return None
    if data.get("success") == False:
        code = _to_int(data.get("code"))
        if code == 404:
            return []
        print("phpipam: {} returned an error: {}".format(path, as_text(data.get("message"), join=",")))
        return None
    payload = data.get("data")
    if payload == None:
        return []
    return payload

def fetch_list(ctx, path):
    payload = fetch(ctx, path)
    if payload == None:
        return None
    return dicts(payload)

def _lookup(ctx, path, key_field, value_field):
    """Build an id -> name map from one of phpIPAM's small reference tables."""
    rows = fetch_list(ctx, path)
    out = {}
    if not rows:
        return out
    for row in rows:
        key = as_text(row.get(key_field), join=",").strip()
        value = as_text(row.get(value_field), join=",").strip()
        if key and value:
            out[key] = value
    return out

def _location_name(ctx, value):
    """Resolve a location, which phpIPAM returns in three different shapes.

    On an address it is an integer id. On a subnet it is a nested object when
    set and an EMPTY LIST when unset - not null, not an empty object - so the
    type has to be checked before any subscript.
    """
    if type(value) == "dict":
        return as_text(value.get("name"), join=",").strip()
    if type(value) == "list":
        return ""
    key = as_text(value, join=",").strip()
    if not key or key == "0":
        return ""
    return ctx["locations"].get(key, "")

def _wanted(selectors, ident, name):
    """True when no filter is configured, or this row matches one by id or name."""
    if not selectors:
        return True
    if as_text(ident, join=",").strip().lower() in selectors:
        return True
    if as_text(name, join=",").strip().lower() in selectors:
        return True
    return False

def build_address_asset(ctx, record, subnet):
    """Convert one phpIPAM address row into a runZero asset."""
    address_id = as_text(record.get("id"), join=",").strip()
    if not address_id:
        print("phpipam: skipping address row with no id in subnet " + as_text(subnet.get("id"), join=","))
        return None

    ip = routable_ip(record.get("ip"))
    mac = _mac_key(record.get("mac"))
    hostname = _hostname(record.get("hostname"))

    if not ip and not mac and not hostname:
        print("phpipam: skipping address {} with no usable address, MAC, or hostname".format(address_id))
        return None

    if ctx["require_identity"] and not mac and not hostname:
        # Only the id is logged, never the row: an IPAM description or owner
        # field routinely carries names and ticket references.
        print("phpipam: skipping address {} with no hostname or MAC".format(address_id))
        return None

    nic = network_interface(mac=mac, ips=[ip] if ip else [])

    tag_id = as_text(record.get("tag"), join=",").strip()
    tag_name = ctx["tags"].get(tag_id, "")

    subnet_cidr = ""
    if subnet:
        network = as_text(subnet.get("subnet"), join=",").strip()
        mask = as_text(subnet.get("mask"), join=",").strip()
        if network and mask:
            subnet_cidr = network + "/" + mask

    vlan_id = as_text(subnet.get("vlanId"), join=",").strip() if subnet else ""
    vlan = ctx["vlans"].get(vlan_id, {}) if vlan_id and vlan_id != "0" else {}

    device_id = as_text(record.get("deviceId"), join=",").strip()
    device_name = ctx["device_names"].get(device_id, "") if device_id and device_id != "0" else ""

    attrs = {
        "record_type": "address",
        "address_id": address_id,
        "ip": record.get("ip"),
        "mac": record.get("mac"),
        "hostname": record.get("hostname"),
        "description": record.get("description"),
        "owner": record.get("owner"),
        "note": record.get("note"),
        "tag_id": tag_id,
        "tag": tag_name,
        "is_gateway": record.get("is_gateway"),
        "exclude_ping": record.get("excludePing"),
        "port": record.get("port"),
        # phpIPAM renames two columns on the wire: ipaddresses.switch is
        # published as deviceId, and ipaddresses.state as tag.
        "device_id": device_id,
        "device_hostname": device_name,
        "subnet_id": record.get("subnetId"),
        "subnet": subnet_cidr,
        "subnet_description": subnet.get("description") if subnet else None,
        "section_id": subnet.get("sectionId") if subnet else None,
        "section": ctx["sections"].get(as_text(subnet.get("sectionId"), join=",").strip(), "") if subnet else "",
        "vlan_number": vlan.get("number"),
        "vlan_name": vlan.get("name"),
        "location": _location_name(ctx, record.get("location")),
        "customer_id": record.get("customer_id"),
        # Raw timestamps are kept verbatim because the parsed values are
        # clamped to now: phpIPAM writes local time with no zone.
        "last_seen_raw": record.get("lastSeen"),
        "edit_date_raw": record.get("editDate"),
        "phpipam_host": ctx["scope"],
    }
    if type(record.get("custom_fields")) == "dict":
        attrs["custom_fields"] = record.get("custom_fields")

    tags = [VENDOR, "phpipam-address"]
    if tag_name:
        tags.append("ipam-tag:" + tag_name)
    if record.get("is_gateway") == 1 or as_text(record.get("is_gateway"), join=",") == "1":
        tags.append("phpipam-gateway")
    section_name = attrs["section"]
    if section_name:
        tags.append("ipam-section:" + section_name)

    params = {
        # ipaddresses.id is a surrogate primary key, stable across edits to the
        # hostname, MAC, owner, or description. It still identifies an ADDRESS
        # RESERVATION rather than a device, which is why it is paired with
        # no-id-match - see the README's Asset identity section.
        "id": "{}:{}:address:{}".format(VENDOR, ctx["scope"], address_id),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "assetType": "address",
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    asset = ImportAsset(**params)
    # NEVER_SEEN is a datetime string, so parse_ts would read it as a real
    # epoch+1s sighting (the non-positive-epoch rule applies only to numeric
    # input). The raw value is still preserved in last_seen_raw.
    if as_text(record.get("lastSeen"), join=",").strip() != NEVER_SEEN:
        last_seen = parse_ts(record.get("lastSeen"))
        if last_seen != None:
            asset.lastSeenTS = last_seen
    return asset

def build_device_asset(ctx, record):
    """Convert one phpIPAM registered device into a runZero asset."""
    device_id = as_text(record.get("id"), join=",").strip()
    if not device_id:
        print("phpipam: skipping device row with no id")
        return None

    ip = routable_ip(record.get("ip"))
    hostname = _hostname(record.get("hostname"))
    if not ip and not hostname:
        print("phpipam: skipping device {} with no usable address or hostname".format(device_id))
        return None

    nic = network_interface(ips=[ip] if ip else [])

    type_id = as_text(record.get("type"), join=",").strip()
    type_name = ctx["device_types"].get(type_id, "")

    section_names = []
    for part in as_text(record.get("sections"), join=",").split(";"):
        for piece in part.split(","):
            name = ctx["sections"].get(piece.strip(), "")
            if name:
                section_names.append(name)

    attrs = {
        "record_type": "device",
        "device_id": device_id,
        "hostname": record.get("hostname"),
        "ip": record.get("ip"),
        "description": record.get("description"),
        "type_id": type_id,
        "type": type_name,
        "sections": dedupe(section_names),
        "section_ids": record.get("sections"),
        "location": _location_name(ctx, record.get("location")),
        "rack": record.get("rack"),
        "rack_start": record.get("rack_start"),
        "rack_size": record.get("rack_size"),
        "snmp_version": record.get("snmp_version"),
        "snmp_port": record.get("snmp_port"),
        "edit_date_raw": record.get("editDate"),
        "phpipam_host": ctx["scope"],
    }
    if type(record.get("custom_fields")) == "dict":
        attrs["custom_fields"] = record.get("custom_fields")

    tags = [VENDOR, "phpipam-device"]
    if type_name:
        tags.append("device-type:" + type_name)
    for name in dedupe(section_names):
        tags.append("ipam-section:" + name)

    params = {
        # devices.id is a surrogate primary key on an operator-maintained
        # device record - one row per physical device - so it is a stable
        # foreign id and drives merging.
        "id": "{}:{}:device:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": [hostname] if hostname else [],
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "assetType": "device",
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    device_type = DEVICE_TYPE_MAP.get(type_name.lower(), "")
    if device_type:
        params["deviceType"] = device_type

    asset = ImportAsset(**params)
    edited = parse_ts(record.get("editDate"))
    if edited:
        asset.lastSeenTS = edited
    return asset

def collect_addresses(ctx):
    """Walk subnets and stream each subnet's addresses.

    phpIPAM has NO pagination anywhere - /addresses/all/ runs a bare
    SELECT * over the whole ipaddresses table and returns every row in one
    body, which on a real IPAM is hundreds of thousands of rows. Walking
    subnet by subnet is what keeps memory bounded to one subnet at a time, and
    it also supplies the subnet, VLAN, and section context each address is
    reported with.
    """
    subnets = fetch_list(ctx, "/subnets/")
    if subnets == None:
        return 0, 0
    if not subnets:
        print("phpipam: no subnets are readable by this API app")
        return 0, 0

    reported = 0
    skipped = 0
    walked = 0
    for subnet in subnets:
        if ctx["max_subnets"] and walked >= ctx["max_subnets"]:
            break
        subnet_id = as_text(subnet.get("id"), join=",").strip()
        if not subnet_id:
            continue
        # A folder is an organisational node in the subnet tree, not a network,
        # and holds no addresses.
        if _to_int(subnet.get("isFolder")) == 1:
            continue
        section_id = as_text(subnet.get("sectionId"), join=",").strip()
        if not _wanted(ctx["section_filter"], section_id, ctx["sections"].get(section_id, "")):
            continue
        walked += 1

        rows = fetch_list(ctx, "/subnets/{}/addresses/".format(subnet_id))
        if not rows:
            continue

        for record in rows:
            if ctx["max_addresses"] and reported >= ctx["max_addresses"]:
                skipped += 1
                continue
            tag_id = as_text(record.get("tag"), join=",").strip()
            if not _wanted(ctx["tag_filter"], tag_id, ctx["tags"].get(tag_id, "")):
                continue
            asset = build_address_asset(ctx, record, subnet)
            if asset == None:
                continue
            report_asset(asset)
            reported += 1

    return reported, skipped

def collect_devices(ctx):
    """Import the registered device inventory.

    The rows were fetched once in main() and cached, because the address walk
    also needs them to resolve an address's deviceId to a switch hostname.
    Every SNMP credential column is dropped before mapping; see
    SNMP_SECRET_FIELDS.
    """
    rows = ctx["device_rows"]
    if not rows:
        return 0

    reported = 0
    for record in rows:
        for field in SNMP_SECRET_FIELDS:
            if field in record:
                record.pop(field)
        asset = build_device_asset(ctx, record)
        if asset == None:
            continue
        report_asset(asset)
        reported += 1
    return reported

def _selectors(raw):
    """Lower-cased include-filter terms. Matched against both ids and names."""
    out = []
    for entry in as_text(raw, join=",").split(","):
        value = entry.strip().lower()
        if value and value not in out:
            out.append(value)
    return out

def main(**kwargs):
    base_url = _base(get_string(kwargs, "url"))
    scope = _scope(base_url)
    if not base_url or not scope:
        fail("phpipam: could not determine the phpIPAM host from the configured URL")
    if not base_url.startswith("https://"):
        print("phpipam: warning: the configured URL is not https. phpIPAM answers 503 " +
              "'SSL connection is required for API' to every API request that does not arrive over TLS.")

    app_id = as_text(get_string(kwargs, "app_id"), join=",").strip().strip("/")
    if not app_id:
        print("phpipam: an API app ID is required; it is a path segment on every request")
        return None

    ctx = {
        "base_url": base_url,
        "app_id": app_id,
        "scope": scope,
        "kwargs": kwargs,
        "require_identity": get_bool(kwargs, "require_identity", default=True),
        "max_subnets": max(0, get_int(kwargs, "max_subnets", default=5000)),
        "max_addresses": max(0, get_int(kwargs, "max_addresses", default=100000)),
        "section_filter": _selectors(get_string(kwargs, "sections", default="")),
        "tag_filter": _selectors(get_string(kwargs, "address_tags", default="")),
        "sections": {},
        "tags": {},
        "locations": {},
        "device_types": {},
        "device_names": {},
        "device_rows": [],
        "vlans": {},
    }

    token = login(ctx, get_string(kwargs, "username"), get_string(kwargs, "password"))
    if not token:
        return None

    ctx["http_options"] = get_http_options(kwargs, headers={
        # phpIPAM wants the token in a bare `token` header.
        "token": token,
        "Accept": "application/json",
    })

    # Small reference tables, one call each. Every one of these degrades to an
    # empty map rather than failing the run: they only decorate assets.
    ctx["sections"] = _lookup(ctx, "/sections/", "id", "name")
    ctx["tags"] = _lookup(ctx, "/tools/tags/", "id", "type")
    ctx["locations"] = _lookup(ctx, "/tools/locations/", "id", "name")
    ctx["device_types"] = _lookup(ctx, "/tools/device_types/", "tid", "tname")

    vlan_rows = fetch_list(ctx, "/vlans/")
    for row in vlan_rows if vlan_rows else []:
        key = as_text(row.get("id"), join=",").strip()
        if key:
            ctx["vlans"][key] = {"number": row.get("number"), "name": row.get("name")}

    # Fetched once and cached: the address walk resolves deviceId to a switch
    # hostname from the same rows the device import consumes.
    device_rows = fetch_list(ctx, "/devices/")
    ctx["device_rows"] = device_rows if device_rows else []
    for row in ctx["device_rows"]:
        key = as_text(row.get("id"), join=",").strip()
        name = _hostname(row.get("hostname"))
        if key and name:
            ctx["device_names"][key] = name

    address_count = 0
    address_skipped = 0
    if get_bool(kwargs, "import_addresses", default=True):
        address_count, address_skipped = collect_addresses(ctx)
        print("phpipam: reported {} addresses".format(address_count))
        if address_skipped:
            print("phpipam: address limit of {} reached; {} further addresses were not imported".format(
                ctx["max_addresses"], address_skipped))

    device_count = 0
    if get_bool(kwargs, "import_devices", default=True):
        device_count = collect_devices(ctx)
        print("phpipam: reported {} registered devices".format(device_count))

    if not address_count and not device_count:
        print("phpipam: no assets retrieved")
    return None

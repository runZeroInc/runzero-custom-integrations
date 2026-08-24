# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-home-assistant",
    "name": "Home Assistant",
    "type": "inbound",
    "description": "Imports network-attached devices from Home Assistant - IoT hardware in its device registry that carries a MAC address, and network clients its device_tracker entities report. Entities that are not devices are deliberately not imported.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Home Assistant device ids are install-local and correspond to nothing
    # any other source knows, so merging is left to the MAC, IP, and
    # hostname the device actually presents on the network.
    "matchBehavior": "no-id-match no-id-break",
    "maxPages": 10000,
    "params": [
        {
            "key": "url",
            "label": "Home Assistant URL",
            "type": "url",
            "required": True,
            "placeholder": "https://homeassistant.example.com:8123",
            "description": "Base URL of the Home Assistant instance, including the port. The default port is 8123. Home Assistant is self-hosted, so there is no default host. Prefer an IP address or a real DNS name over homeassistant.local, whose mDNS resolution is frequently slow.",
        },
        {
            "key": "api_token",
            "label": "Long-lived access token",
            "type": "secret",
            "required": True,
            "description": "A long-lived access token belonging to an ADMINISTRATOR account. An admin is required twice over: the template endpoint that reads the device registry rejects non-admin tokens, and /api/states silently filters entities for non-admin users rather than reporting an error.",
        },
        {
            "key": "collect_device_registry",
            "label": "Collect the device registry",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Read the device registry by rendering a Jinja template server-side. This is where manufacturer, model, firmware version, serial number, and the MAC addresses of IoT hardware come from. Requires an admin token and Home Assistant 2023.9 or later; the run degrades to device_tracker entities alone when it is unavailable.",
        },
        {
            "key": "collect_device_trackers",
            "label": "Collect device trackers",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import device_tracker entities that report a MAC or an IP address. These are the network clients a router, UniFi controller, or nmap scan told Home Assistant about.",
        },
        {
            "key": "include_away",
            "label": "Include absent trackers",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import device_tracker entities whose state is not_home. They are still real devices with a real MAC; only their presence has changed. Turn this off to import only what is currently on the network.",
        },
        {
            "key": "mine_entity_addresses",
            "label": "Mine addresses from all entities",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Also read ip, ip_address, mac, and mac_address attributes from entities outside the device_tracker domain. Off by default because these attributes are not a convention: an integration can put a remote service's address in one, which would then be attached to the wrong asset.",
        },
        {
            "key": "device_page_size",
            "label": "Devices per template request",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 500,
            "description": "How many device registry entries to render per template request. Home Assistant caps a rendered template at 256 KiB and answers 400 when that is exceeded, which is why the registry is paged rather than fetched at once.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'normalize_mac', 'routable_ip')
load('http', http_get='get', http_post='post', 'get_json', 'bearer', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('json', json_encode='encode', json_decode='decode')
load('time', 'now', 'parse_ts')
load('re', re_match='match', re_search='search')
load('jsonstream', 'iter_array')

load('coerce', 'as_dict', 'as_list', 'as_text', 'dedupe')
VENDOR = "home-assistant"
ATTR_PREFIX = "hass"
ATTR_SEPARATOR = "_"

STATES_PATH = "/api/states"
TEMPLATE_PATH = "/api/template"
CONFIG_ENTRIES_PATH = "/api/config/config_entries/entry"

MAX_ATTR_VALUES = 32

# The guard that makes streaming safe. jsonstream.iter_array raises when the
# body is not a JSON array, and a raise aborts the whole script because Starlark
# has no exceptions. /api/states answers with a bare top-level array, so an
# error page or an HTML login redirect has to be caught before the iterator is
# built rather than by it.
ARRAY_RE = r"^\s*\["

EMPTY_MAC = "00:00:00:00:00:00"

# A DNS label sequence, used to keep a friendly name like "Kitchen Light" or a
# stringified IP out of the hostname list.
HOSTNAME_RE = r"^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$"

# Entity attribute keys that hold an address. device_tracker publishes ip, mac,
# and host_name, all three added only when non-null; a 2022-era UniFi release
# also emitted hostname alongside host_name, so both spellings are read.
MAC_KEYS = ["mac", "mac_address"]
IP_KEYS = ["ip", "ip_address"]
HOSTNAME_KEYS = ["host_name", "hostname"]

# UniFi copies the controller's own client record onto the tracker entity, which
# is the richest per-client data available anywhere over the REST API.
TRACKER_EXTRA_KEYS = [
    "source_type", "friendly_name", "scanner", "oui", "ap_mac", "essid", "ssid",
    "vlan", "radio", "radio_proto", "is_guest", "authorized", "note",
    "connected_to", "connection_type", "last_time_reachable", "gps_accuracy",
]

# A device_tracker whose state is one of these is not currently on the network.
AWAY_STATES = ["not_home", "unavailable", "unknown"]

# The connection types Home Assistant records on a device. Only the Ethernet MAC
# is usable as a network interface address: a Bluetooth address looks identical
# but is a BD_ADDR that no scanner will ever see on the wire, and a Zigbee IEEE
# address is eight bytes rather than six. Both are kept as attributes instead.
MAC_CONNECTION = "mac"

# Entity domains that identify what a device is well enough to set a device
# type. Home Assistant's device registry records no device class of its own, so
# this is deliberately short: a wrong device type is worse than none.
DOMAIN_DEVICE_TYPES = {
    "camera": "IP Camera",
}

# Integration domains whose devices are unambiguous.
INTEGRATION_DEVICE_TYPES = {
    "brother": "Printer",
    "ipp": "Printer",
    "escpos": "Printer",
    "roku": "TV",
    "apple_tv": "TV",
    "samsungtv": "TV",
    "webostv": "TV",
    "androidtv": "TV",
    "braviatv": "TV",
    "printer": "Printer",
}

# Device registry entries whose entry_type is "service" are not hardware at all -
# they are the cloud account or hub a set of entities came from.
SERVICE_ENTRY_TYPE = "service"
def _clean_mac(value):
    """Return a canonical MAC, or an empty string when it is unusable.

    Case is not consistent across Home Assistant integrations: nmap and asuswrt
    normalize to lower case, mikrotik passes RouterOS's upper case through
    untouched, and the legacy tracker path upper-cases deliberately.
    normalize_mac accepts all of them."""
    mac = normalize_mac(as_text(value, join=",").strip())
    if not mac or mac == EMPTY_MAC:
        return ""
    return mac

def _hostname_like(value):
    """Report whether a string is usable as a hostname.

    Home Assistant names are display names - "Kitchen Motion Sensor" - far more
    often than they are hostnames, and a tracker friendly_name is usually a
    person's phone as they named it. Anything with a space, and any bare IP
    address, is refused rather than imported as a placeholder hostname."""
    text = as_text(value, join=",").strip()
    if not text or len(text) > 253:
        return False
    if ip_address(text) != None:
        return False
    return re_match(HOSTNAME_RE, text) != None

def _domain_of(entity_id):
    """Return the domain half of an entity id."""
    text = as_text(entity_id, join=",")
    dot = text.find(".")
    return text[:dot] if dot > 0 else ""

def stream_states(ctx):
    """Stream /api/states, returning (iterator, err).

    This is the only unbounded response Home Assistant serves: it returns every
    entity with every attribute in one unpaginated array, and there is no
    server-side filter for it. A mature install is several megabytes, and
    decoding that into Starlark values costs several times the wire size, so the
    raw body is streamed and only one entity is live at a time.

    The raw http builtin is used because the body is needed as text; it accepts
    no retries kwarg and so gets one attempt."""
    resp = http_get(ctx["base_url"] + STATES_PATH, **ctx["http_options"])
    if resp == None:
        return None, "no response"
    if resp.status_code != 200:
        return None, "status {}: {}".format(resp.status_code, as_text(resp.body, join=",")[:200])
    if not re_search(ARRAY_RE, as_text(resp.body, join=",")[:64]):
        return None, "the states response was not a JSON array"
    return iter_array(resp.body), None

def index_entities(ctx):
    """Index the entities that carry an address, keyed by entity id.

    Home Assistant is an entity store, not an asset inventory: on a mature
    install the overwhelming majority of what comes back here is automations,
    scripts, helpers, the sun, the weather, and per-sensor readings, none of
    which is a device. Only entities carrying a MAC or a routable IP are kept,
    which is both the correct filter and what keeps this bounded - the index is
    proportional to the number of addressable devices, not to entity count."""
    index = {}
    stream, err = stream_states(ctx)
    if err:
        return None, err

    total = 0
    trackers = 0
    for entry in stream:
        record = as_dict(entry)
        entity_id = as_text(record.get("entity_id"), join=",").strip()
        if not entity_id:
            continue
        total += 1
        domain = _domain_of(entity_id)
        is_tracker = domain == "device_tracker"
        if not is_tracker and not ctx["mine_addresses"]:
            continue

        attributes = as_dict(record.get("attributes"))
        mac = ""
        for key in MAC_KEYS:
            mac = _clean_mac(attributes.get(key))
            if mac:
                break
        ips = []
        for key in IP_KEYS:
            routable = routable_ip(attributes.get(key))
            if routable and routable not in ips:
                ips.append(routable)
        if not mac and not ips:
            continue

        hostname = ""
        for key in HOSTNAME_KEYS:
            candidate = as_text(attributes.get(key), join=",").strip()
            if candidate:
                hostname = candidate
                break

        entry_data = {
            "entity_id": entity_id,
            "domain": domain,
            "tracker": is_tracker,
            "state": as_text(record.get("state"), join=",").strip(),
            "mac": mac,
            "ips": ips,
            "hostname": hostname,
            "last_changed": record.get("last_changed"),
            "last_updated": record.get("last_updated"),
            "extra": {},
        }
        for key in TRACKER_EXTRA_KEYS:
            if key in attributes:
                entry_data["extra"][key] = attributes[key]
        index[entity_id] = entry_data
        if is_tracker:
            trackers += 1

    ctx["entity_total"] = total
    print("home-assistant: read {} entities, {} of which carry an address ({} device trackers)".format(
        total, len(index), trackers))
    return index, None

def fetch_config_entries(ctx):
    """Index config entries by id, for integration provenance.

    Which integration a device came from - hue, zwave_js, esphome, unifi - is
    the single most useful piece of context Home Assistant can add to an asset,
    because it says how the device was discovered and therefore how much to
    trust the rest. This endpoint is not in the published REST documentation but
    is a real HomeAssistantView, and reading it here avoids routing the same
    question through config_entry_attr in the template, which raises on an
    unrecognized attribute and would fail the whole render."""
    index = {}
    data, err = get_json(ctx["base_url"] + CONFIG_ENTRIES_PATH, **ctx["http_options"])
    if err:
        print("home-assistant: could not read config entries, continuing without integration names:", err)
        return index
    for item in as_list(data):
        record = as_dict(item)
        entry_id = as_text(record.get("entry_id"), join=",").strip()
        if entry_id:
            index[entry_id] = record
    return index

def device_template(start, end):
    """Build the Jinja template that dumps one page of the device registry.

    The device registry is not exposed over REST in any Home Assistant release -
    config/device_registry/list is a WebSocket command, and there is no
    WebSocket transport available here - so it is read by asking Home Assistant
    to render a template that walks it and emits JSON.

    Three things about this template are load-bearing. There is no function that
    lists every device, so the set is derived by mapping every entity through
    device_id and de-duplicating. The rendered output is capped at 256 KiB and a
    larger render is answered 400, which is why a slice is taken rather than the
    whole registry. And the row list is built with concatenation rather than
    list.append, which the sandboxed Jinja environment refuses as unsafe.

    The template is assembled by concatenation rather than by str.format,
    because Jinja's own braces would be read as format placeholders."""
    # Starlark has no implicit adjacent string concatenation, so the fragments
    # are joined explicitly.
    return "".join([
        "{% set dids = states | map(attribute='entity_id') | map('device_id')",
        " | reject('none') | unique | list %}\n",
        "{% set ns = namespace(rows=[]) %}\n",
        "{% for did in dids[", str(start), ":", str(end), "] %}\n",
        "{% set ns.rows = ns.rows + [{",
        "'id': did,",
        "'name': device_attr(did, 'name'),",
        "'name_by_user': device_attr(did, 'name_by_user'),",
        "'manufacturer': device_attr(did, 'manufacturer'),",
        "'model': device_attr(did, 'model'),",
        "'model_id': device_attr(did, 'model_id'),",
        "'sw_version': device_attr(did, 'sw_version'),",
        "'hw_version': device_attr(did, 'hw_version'),",
        "'serial_number': device_attr(did, 'serial_number'),",
        "'area_id': device_attr(did, 'area_id'),",
        # entry_type and disabled_by are enums, and orjson refuses an enum, so
        # they are stringified in the template rather than failing the render.
        "'entry_type': device_attr(did, 'entry_type') | string,",
        "'disabled_by': device_attr(did, 'disabled_by') | string,",
        "'via_device_id': device_attr(did, 'via_device_id'),",
        "'configuration_url': device_attr(did, 'configuration_url') | string,",
        "'config_entry_id': device_attr(did, 'config_entry_id'),",
        # connections and identifiers are Python sets of tuples. to_json cannot
        # serialize a set, so both are converted to lists first; the tuples
        # inside then serialize as two-element arrays.
        "'connections': device_attr(did, 'connections') | list,",
        "'identifiers': device_attr(did, 'identifiers') | list,",
        "'entities': device_entities(did) | list",
        "}] %}\n",
        "{% endfor %}\n",
        "{{ ns.rows | to_json }}",
    ])

def fetch_device_page(ctx, start, end):
    """Render one page of the device registry, returning (rows, err).

    The endpoint answers asymmetrically and that asymmetry has to be handled
    rather than papered over: a successful render is raw text with a text/plain
    content type, while a failure is a JSON object carrying a message. So the
    status decides how the body is read, and the text is checked for an opening
    bracket before json_decode sees it, because json_decode aborts the entire
    script on input it cannot parse."""
    body = json_encode({"template": device_template(start, end)})
    resp = http_post(ctx["base_url"] + TEMPLATE_PATH, body=bytes(body), **ctx["template_options"])
    if resp == None:
        return None, "no response"
    text = as_text(resp.body, join=",")
    if resp.status_code == 401 or resp.status_code == 403:
        return None, "status {}: the template endpoint requires an administrator token, and the device registry cannot be read with this credential".format(resp.status_code)
    if resp.status_code != 200:
        message = text[:300]
        detail = as_dict(json_decode(text)).get("message") if re_search(r"^\s*\{", text[:16]) else None
        if detail:
            message = as_text(detail, join=",")
        return None, "status {}: {}".format(resp.status_code, message)
    if not re_search(ARRAY_RE, text[:64]):
        return None, "the rendered template was not a JSON array: " + text[:200]
    return as_list(json_decode(text)), None

def device_addresses(ctx, record, entity_index):
    """Collect every MAC and IP that belongs to one device registry entry.

    Three sources, in decreasing order of confidence. The registry's own
    connections list is authoritative for the MAC. configuration_url is the
    device's own web interface, so when it names an IP literal that is the
    device's address by construction. Finally the device's entities can carry an
    address, which is where a device_tracker's view of the same device joins
    up."""
    macs = []
    ips = []
    other_connections = []
    for item in as_list(record.get("connections")):
        pair = as_list(item)
        if len(pair) != 2:
            continue
        kind = as_text(pair[0], join=",").strip().lower()
        value = as_text(pair[1], join=",").strip()
        if kind == MAC_CONNECTION:
            mac = _clean_mac(value)
            if mac and mac not in macs:
                macs.append(mac)
        elif value:
            # A Bluetooth BD_ADDR is six bytes and normalizes exactly like an
            # Ethernet MAC, but it is a different address space that no network
            # scan observes, so treating it as a MAC would invent a correlation.
            other_connections.append("{}={}".format(kind, value))

    url = as_text(record.get("configuration_url"), join=",").strip()
    if url:
        parsed = url_parse(url)
        if parsed:
            routable = routable_ip(parsed.hostname)
            if routable and routable not in ips:
                ips.append(routable)

    hostnames = []
    entities = []
    for entity_id in as_list(record.get("entities")):
        key = as_text(entity_id, join=",").strip()
        if not key:
            continue
        entities.append(key)
        found = as_dict(entity_index.get(key))
        if not found:
            continue
        if found.get("mac") and found["mac"] not in macs:
            macs.append(found["mac"])
        for ip in as_list(found.get("ips")):
            if ip not in ips:
                ips.append(ip)
        if found.get("hostname"):
            hostnames.append(found["hostname"])
    return macs, ips, hostnames, entities, other_connections

def build_device_asset(ctx, record, entity_index, config_entries):
    """Convert one device registry entry into a runZero asset."""
    device_id = as_text(record.get("id"), join=",").strip()
    macs, ips, hostnames, entities, other_connections = device_addresses(ctx, record, entity_index)

    nic = network_interface(mac=macs[0] if macs else "", ips=ips)
    netifs = [nic] if nic else []
    # A device with several MACs - a wireless access point with a wired and a
    # radio address - gets one interface per MAC so both correlate.
    for mac in macs[1:]:
        extra = network_interface(mac=mac)
        if extra:
            netifs.append(extra)

    entry = as_dict(config_entries.get(as_text(record.get("config_entry_id"), join=",").strip()))
    integration = as_text(entry.get("domain"), join=",").strip()

    name = as_text(record.get("name_by_user"), join=",").strip() or as_text(record.get("name"), join=",").strip()
    manufacturer = as_text(record.get("manufacturer"), join=",").strip()
    model = as_text(record.get("model"), join=",").strip()

    entity_domains = dedupe([_domain_of(item) for item in entities])
    device_type = INTEGRATION_DEVICE_TYPES.get(integration, "")
    if not device_type:
        for domain in entity_domains:
            mapped = DOMAIN_DEVICE_TYPES.get(domain, "")
            if mapped:
                device_type = mapped
                break

    tags = [VENDOR, "device-registry"]
    if integration:
        tags.append("integration:" + integration)
    area = as_text(record.get("area_id"), join=",").strip()
    if area:
        tags.append("area:" + area)
    if manufacturer:
        tags.append("vendor:" + manufacturer)

    attrs = {
        "source": "device_registry",
        "server": ctx["scope"],
        "device_id": device_id,
        "name": record.get("name"),
        "name_by_user": record.get("name_by_user"),
        "manufacturer": manufacturer,
        "model": model,
        "model_id": record.get("model_id"),
        "sw_version": record.get("sw_version"),
        "hw_version": record.get("hw_version"),
        "serial_number": record.get("serial_number"),
        "area_id": area,
        "entry_type": record.get("entry_type"),
        "via_device_id": record.get("via_device_id"),
        "configuration_url": record.get("configuration_url"),
        "config_entry_id": record.get("config_entry_id"),
        "integration": integration,
        "integration_title": entry.get("title"),
        "integration_state": entry.get("state"),
        # Bluetooth, Zigbee, UPnP, and Z-Wave identifiers are recorded but are
        # deliberately not imported as MAC addresses.
        "other_connections": other_connections[:MAX_ATTR_VALUES],
        "identifier_count": len(as_list(record.get("identifiers"))),
        "entity_count": len(entities),
        "entity_domains": entity_domains[:MAX_ATTR_VALUES],
        "entities": entities[:MAX_ATTR_VALUES],
        "mac_count": len(macs),
        "ip_count": len(ips),
    }
    params = {
        # A Home Assistant device id is a random 32-character hex string minted
        # when the device is first seen and stored in the local registry. It is
        # stable across restarts, which is why it is emitted, but it is
        # meaningless outside this one install - no other system has ever heard
        # of it - so it is not used to find merge candidates.
        "id": "{}:{}:device:{}".format(VENDOR, ctx["scope"], device_id),
        "hostnames": dedupe([h for h in hostnames + [name] if _hostname_like(h)]),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    if device_type:
        params["deviceType"] = device_type
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    return ImportAsset(**params)

def build_tracker_asset(ctx, found):
    """Convert one device_tracker entity into a runZero asset.

    This covers the devices Home Assistant knows about only as network
    presence - a phone seen by the router, a client on a UniFi controller -
    which have no device registry entry of their own."""
    entity_id = found["entity_id"]
    extra = as_dict(found.get("extra"))

    nic = network_interface(mac=found.get("mac", ""), ips=as_list(found.get("ips")))
    netifs = [nic] if nic else []

    hostnames = []
    if _hostname_like(found.get("hostname")):
        hostnames.append(found["hostname"])
    friendly = as_text(extra.get("friendly_name"), join=",").strip()
    if _hostname_like(friendly):
        hostnames.append(friendly)

    state = found.get("state", "")
    tags = [VENDOR, "device-tracker"]
    source_type = as_text(extra.get("source_type"), join=",").strip()
    if source_type:
        tags.append("source:" + source_type)
    if state:
        tags.append("presence:" + state)
    essid = as_text(extra.get("essid") or extra.get("ssid"), join=",").strip()
    if essid:
        tags.append("ssid:" + essid)

    attrs = {
        "source": "device_tracker",
        "server": ctx["scope"],
        "entity_id": entity_id,
        "state": state,
        "mac": found.get("mac"),
        "ip": ",".join(as_list(found.get("ips"))),
        "host_name": found.get("hostname"),
        "last_changed": found.get("last_changed"),
        "last_updated": found.get("last_updated"),
    }
    for key in extra:
        attrs["attr_" + as_text(key, join=",")] = extra[key]

    # UniFi publishes the OUI lookup its controller already did, which is the
    # only vendor name available on a tracker entity. runZero performs its own
    # OUI resolution on the MAC, so nothing is looked up here.
    manufacturer = as_text(extra.get("oui"), join=",").strip()

    params = {
        # An entity id is stable in the entity registry across restarts and
        # renames of the friendly name, which makes it a usable key, but like a
        # device id it means nothing outside this install.
        "id": "{}:{}:entity:{}".format(VENDOR, ctx["scope"], entity_id),
        "hostnames": dedupe(hostnames),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),
    }
    if manufacturer:
        params["manufacturer"] = manufacturer
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    # it has to be assigned after construction.
    last_seen = parse_ts(found.get("last_updated")) or parse_ts(found.get("last_changed"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def collect_devices(ctx, entity_index, config_entries):
    """Page through the device registry, streaming each page as it is built.

    Returns (reported, claimed_entities, ok). claimed_entities is the set of
    entity ids already accounted for by a device, so the tracker pass does not
    emit a second asset for the same physical device: two assets carrying
    different foreign ids from one integration can never merge onto each other,
    so a duplicate here would be permanent."""
    reported = 0
    claimed = {}
    seen_devices = {}
    skipped_service = 0
    skipped_unaddressed = 0
    skipped_repeated = 0

    _pager = pager("home-assistant")

    while _pager.next():

        page = _pager.page - 1
        start = page * ctx["device_page_size"]
        rows, err = fetch_device_page(ctx, start, start + ctx["device_page_size"])
        if err:
            print("home-assistant: could not read the device registry:", err)
            return reported, claimed, False
        if not rows:
            break

        for item in rows:
            record = as_dict(item)
            device_id = as_text(record.get("id"), join=",").strip()
            if not device_id:
                continue
            # The device-id list is re-derived from states and sliced on every
            # render, so a device registered mid-run shifts the later slices and
            # one row can appear in two pages. The first copy wins; a second
            # would emit a duplicate foreign id in one run.
            if device_id in seen_devices:
                skipped_repeated += 1
                continue
            seen_devices[device_id] = True
            # A "service" entry is the cloud account or hub an integration
            # created, not a physical device on any network.
            if as_text(record.get("entry_type"), join=",").strip().lower() == SERVICE_ENTRY_TYPE:
                skipped_service += 1
                continue
            macs, ips, _hostnames, _entities, _other = device_addresses(ctx, record, entity_index)
            if not macs and not ips:
                # A device with neither a MAC nor an IP is a Zigbee bulb, a
                # Bluetooth sensor, or a cloud-backed integration. It is a real
                # thing in the home, but runZero could never see it or merge it
                # with anything, so importing it would add a row that can only
                # ever sit alone.
                skipped_unaddressed += 1
                continue
            # Claim this row's entities only now that the row is certain to
            # become an asset. Claiming before the skip decisions above threw
            # away every entity of a row that was then skipped: a router-style
            # integration registers its hub as a `service` entry that OWNS the
            # device_tracker entity of every client on the network, so those
            # clients were claimed by an asset that was never emitted and then
            # dropped by the tracker pass as "already covered". An install whose
            # only network visibility is a router integration imported nothing.
            for entity_id in as_list(record.get("entities")):
                key = as_text(entity_id, join=",").strip()
                if key:
                    claimed[key] = True
            reported += report_asset(build_device_asset(ctx, record, entity_index, config_entries))

        if len(rows) < ctx["device_page_size"]:
            break

    print("home-assistant: imported {} devices from the registry; skipped {} with no MAC or IP and {} service entries".format(
        reported, skipped_unaddressed, skipped_service))
    if skipped_repeated:
        print("home-assistant: skipped {} device rows repeated across registry pages (registry changed mid-run)".format(skipped_repeated))
    return reported, claimed, True

def collect_trackers(ctx, entity_index, claimed):
    """Emit an asset for each addressed device_tracker not already claimed."""
    reported = 0
    skipped_claimed = 0
    skipped_away = 0
    seen_macs = {}
    for entity_id in sorted(entity_index):
        found = entity_index[entity_id]
        if not found.get("tracker"):
            continue
        if entity_id in claimed:
            skipped_claimed += 1
            continue
        if not ctx["include_away"] and found.get("state") in AWAY_STATES:
            skipped_away += 1
            continue
        mac = found.get("mac", "")
        if mac and mac in seen_macs:
            # Two trackers for one MAC happens when a router integration and a
            # UniFi controller both report the same client. They are one device.
            skipped_claimed += 1
            continue
        if mac:
            seen_macs[mac] = True
        reported += report_asset(build_tracker_asset(ctx, found))

    print("home-assistant: imported {} device trackers; {} already covered by a registry device, {} not on the network".format(
        reported, skipped_claimed, skipped_away))
    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        print("home-assistant: could not determine the Home Assistant host from the configured URL")
        return None

    api_token = get_string(kwargs, "api_token", default="").strip()
    if not api_token:
        print("home-assistant: a Home Assistant long-lived access token is required")
        return None

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Authorization": bearer(api_token),
            "Content-Type": "application/json",
        }),
        "template_options": get_http_options(kwargs, headers={
            "Authorization": bearer(api_token),
            "Content-Type": "application/json",
        }),
        "mine_addresses": get_bool(kwargs, "mine_entity_addresses", default=False),
        "include_away": get_bool(kwargs, "include_away", default=True),
        "device_page_size": get_int(kwargs, "device_page_size", default=100),
        "entity_total": 0,
    }

    entity_index, err = index_entities(ctx)
    if err:
        if err.startswith("status 401"):
            print("home-assistant: the access token was rejected:", err)
        else:
            print("home-assistant: failed to read entity states:", err)
        return None

    total = 0
    claimed = {}
    if get_bool(kwargs, "collect_device_registry", default=True):
        config_entries = fetch_config_entries(ctx)
        reported, claimed, ok = collect_devices(ctx, entity_index, config_entries)
        total += reported
        if not ok:
            print("home-assistant: continuing with device_tracker entities only")

    if get_bool(kwargs, "collect_device_trackers", default=True):
        total += collect_trackers(ctx, entity_index, claimed)

    if not total:
        print("home-assistant: no assets retrieved. Home Assistant is an entity store rather than an" +
              " asset inventory, so an install with no networked IoT hardware and no device_tracker" +
              " integration legitimately produces nothing")
    return None

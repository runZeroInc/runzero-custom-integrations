# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ubiquiti-unifi-protect",
    "name": "Ubiquiti UniFi Protect",
    "type": "inbound",
    "description": "Imports cameras, sensors, lights, chimes, viewers, and the NVR itself from the official UniFi Protect Integration API.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "UniFi console URL",
            "type": "url",
            "required": True,
            "placeholder": "https://192.0.2.1",
            "description": "Base URL of the UniFi OS console running Protect. The /proxy/protect/integration/v1 path is appended automatically. Include a path prefix only if the console is reverse-proxied under one.",
        },
        {
            "key": "api_key",
            "label": "UniFi API key",
            "type": "secret",
            "required": True,
            "description": "UniFi OS API key, created under Settings -> Control Plane -> Integrations. The same key works for the UniFi Network integration.",
        },
        {
            "key": "collect_cameras",
            "label": "Collect cameras",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import cameras and doorbells.",
        },
        {
            "key": "collect_nvr",
            "label": "Collect the NVR",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the console running Protect as an asset. The NVR record carries no MAC on Protect older than 7.1 and is skipped there.",
        },
        {
            "key": "collect_sensors",
            "label": "Collect sensors",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import UP-Sense door, window, leak, and environmental sensors.",
        },
        {
            "key": "collect_accessories",
            "label": "Collect lights, chimes, and viewers",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import floodlights, chimes, and viewport devices.",
        },
        {
            "key": "collect_extended",
            "label": "Collect speakers, sirens, relays, fobs, bridges, link stations, and alarm hubs",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import the device classes added by the Protect 7.x API. Off by default: these paths return 404 on Protect 6.x, and most sites own none of them.",
        },
        {
            "key": "include_disconnected",
            "label": "Include disconnected devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import devices whose state is DISCONNECTED. They are still adopted hardware, so this defaults on.",
        },
        {
            "key": "max_devices",
            "label": "Maximum devices",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on devices imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", "from_timestamp")

load('coerce', 'as_text', 'dedupe', 'dicts')
VENDOR = "ubiquiti-unifi-protect"
ATTR_PREFIX = "unifi_protect"
ATTR_SEPARATOR = "_"
MANUFACTURER = "Ubiquiti"

API_PATH = "/proxy/protect/integration/v1"
HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "unknown", "none", "null", "-", "n/a", "unnamed"]

# Every collection endpoint returns a BARE JSON ARRAY with no pagination and no
# envelope - the Protect Integration API has no limit/offset/page parameter
# anywhere. /nvrs is the exception: despite the plural path it returns a SINGLE
# OBJECT.
COLLECTIONS = [
    # (path, modelKey, runZero deviceType, config toggle)
    ("/cameras", "camera", "IP Camera", "collect_cameras"),
    ("/sensors", "sensor", "IoT Sensor", "collect_sensors"),
    ("/lights", "light", "IoT Light", "collect_accessories"),
    ("/chimes", "chime", "IoT Chime", "collect_accessories"),
    ("/viewers", "viewer", "Media Player", "collect_accessories"),
    ("/speakers", "speaker", "IoT Speaker", "collect_extended"),
    ("/sirens", "siren", "IoT Siren", "collect_extended"),
    ("/relays", "relay", "IoT Relay", "collect_extended"),
    ("/fobs", "fob", "IoT Remote", "collect_extended"),
    ("/bridges", "bridge", "IoT Bridge", "collect_extended"),
    ("/link-stations", "linkStation", "IoT Gateway", "collect_extended"),
    ("/alarm-hubs", "alarmHub", "IoT Gateway", "collect_extended"),
]
def _to_int(value):
    if type(value) == "int":
        return value
    if type(value) == "float":
        return int(value)
    text = as_text(value, join=",").strip()
    if not text or len(text) > 18:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    Protect publishes MACs UPPERCASE WITH NO SEPARATORS ("24A43C3DFEB9"),
    unlike the Network API's colon-delimited form. normalize_mac is avoided
    here for the same reason as everywhere else in this repo - it clears the
    locally administered bit - even though Protect hardware always carries a
    burned-in Ubiquiti address.
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
    """A Protect device name, or "" when it cannot serve as a hostname.

    `name` is declared required AND nullable on every device type, so an
    unnamed camera really does arrive as {"name": null}. Passing that straight
    into hostnames would put None in the list.
    """
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    return text
def _parse_ms(value, current):
    """Convert a Protect epoch-MILLISECOND timestamp to a time, or None.

    Protect emits timestamps as bare JSON numbers in milliseconds
    (1445408038748), not as the RFC 3339 strings the Network API uses. Three
    guards matter here. from_timestamp requires an INT and rejects a float, so
    the value is floored to seconds with integer division. A future timestamp
    makes the platform reject the ENTIRE asset record rather than the field,
    and several Protect fields are legitimately in the future - armMode
    .willBeArmedAt is a scheduled time, and lcdMessage.resetAt is when a
    doorbell message will be removed - so the result is clamped to now. And a
    zero or negative value is Protect's "never", not 1970.
    """
    millis = _to_int(value)
    if millis <= 0:
        return None
    seconds = millis // 1000
    if seconds <= 0 or seconds > 4102444800:
        return None
    parsed = from_timestamp(seconds)
    if parsed.unix > current.unix:
        return current
    return parsed


def _scope(base_url):
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def _base(url):
    """Return the configured URL with any trailing slash removed.

    get_url_base is deliberately NOT used: it discards the path, which breaks a
    console reached through a reverse proxy mounted under a prefix. The Protect
    proxy path is appended to whatever is configured.
    """
    return as_text(url, join=",").strip().rstrip("/")


def fetch(ctx, path):
    """GET one Protect collection.

    Returns a list of records, or None when the call failed. A 404 is
    ambiguous by design and is reported as such: the path does not exist on
    Protect older than 5.3, and it also does not exist when Protect is not
    installed or has crashed. The two cannot be told apart from the response.
    """
    url = ctx["base_url"] + API_PATH + path
    data, err = get_json(url, **ctx["http_options"])
    if err:
        if "404" in err:
            print(("unifi-protect: {} returned 404. Either this Protect release predates the " +
                   "Integration API (added in Protect 5.3), or the Protect application is not " +
                   "installed or not running on this console.").format(path))
            return None
        if "401" in err or "403" in err:
            print("unifi-protect: {} was rejected: {}. Check the API key and that it was created on this console.".format(path, err))
            return None
        print("unifi-protect: {} failed: {}".format(path, err))
        return None
    # /nvrs answers with a single object despite the plural path.
    if type(data) == "dict":
        return [data]
    if type(data) == "list":
        return dicts(data)
    print("unifi-protect: {} returned an unexpected shape".format(path))
    return None


def preflight(ctx):
    """Read /meta/info, which validates the key and reports the version.

    One request gives reachability, credential validation, and the version
    gate. It is the same call Home Assistant uses to validate a Protect key.
    """
    url = ctx["base_url"] + API_PATH + "/meta/info"
    data, err = get_json(url, **ctx["http_options"])
    if err:
        if "404" in err:
            print("unifi-protect: /meta/info returned 404. The official Protect Integration API " +
                  "was added in Protect 5.3; older consoles have no such path. It also 404s when " +
                  "Protect is not installed on this console.")
        elif "401" in err or "403" in err:
            print("unifi-protect: /meta/info was rejected: {}. The API key is wrong, revoked, or ".format(err) +
                  "was created on a different console.")
        else:
            print("unifi-protect: /meta/info failed:", err)
        return ""
    if type(data) != "dict":
        print("unifi-protect: /meta/info returned an unexpected body")
        return ""
    version = as_text(data.get("applicationVersion"), join=",").strip()
    if not version:
        print("unifi-protect: /meta/info returned no applicationVersion")
        return ""
    major = _to_int(version.split(".")[0])
    if major > 0 and major < 7:
        print(("unifi-protect: Protect {} predates 7.0. The Integration API is present but thinner " +
               "there: devices carry no `type` (model name) and no `guid`, and the NVR record has " +
               "no MAC before 7.1, so the NVR cannot be imported.").format(version))
    return version


def build_asset(ctx, record, model_key, device_type):
    """Convert one Protect device into a runZero asset."""
    device_id = as_text(record.get("id"), join=",").strip()
    if not device_id:
        print("unifi-protect: skipping {} record with no id".format(model_key))
        return None

    mac = _mac_key(record.get("mac"))
    name = _hostname(record.get("name"))

    if not mac and not name:
        # The Integration API publishes no address of any kind, so a device
        # with neither MAC nor name has nothing to correlate on and would be an
        # orphan forever.
        print("unifi-protect: skipping {} {} with no MAC and no name".format(model_key, device_id))
        return None

    nic = network_interface(mac=mac) if mac else None

    state = as_text(record.get("state"), join=",").strip()
    # `type` is the model name ("UVC G4 Doorbell"); `modelKey` is the class.
    model = as_text(record.get("type"), join=",").strip()

    attrs = {
        "protect_id": device_id,
        # guid is Protect's own "stable identifier" for the device model. It
        # exists only on Protect 7.x and is nullable, so it cannot be the
        # foreign id, but it is worth carrying.
        "guid": record.get("guid"),
        "model_key": model_key,
        "model": model,
        "name": record.get("name"),
        "state": state,
        "mac_raw": record.get("mac"),
        "console": ctx["scope"],
        "protect_version": ctx["version"],
    }

    # Per-class detail worth keeping. Every read is a plain .get so a field the
    # running Protect release does not publish is simply absent.
    if model_key == "camera":
        flags = record.get("featureFlags")
        if type(flags) == "dict":
            attrs["has_mic"] = flags.get("hasMic")
            attrs["has_speaker"] = flags.get("hasSpeaker")
            attrs["has_hdr"] = flags.get("hasHdr")
            attrs["video_modes"] = flags.get("videoModes")
            attrs["smart_detect_types"] = flags.get("smartDetectTypes")
        attrs["video_mode"] = record.get("videoMode")
        attrs["hdr_type"] = record.get("hdrType")
        attrs["has_package_camera"] = record.get("hasPackageCamera")
        attrs["is_mic_enabled"] = record.get("isMicEnabled")
    elif model_key == "sensor":
        attrs["mount_type"] = record.get("mountType")
        wireless = record.get("wirelessConnectionState")
        if type(wireless) == "dict":
            battery = wireless.get("batteryStatus")
            if type(battery) == "dict":
                attrs["battery_percentage"] = battery.get("percentage")
                attrs["battery_is_low"] = battery.get("isLow")
            signal = wireless.get("signalState")
            if type(signal) == "dict":
                attrs["signal_quality"] = signal.get("signalQuality")
                attrs["signal_strength"] = signal.get("signalStrength")
        flags = record.get("featureFlags")
        if type(flags) == "dict":
            attrs["sensor_capabilities"] = dedupe(
                [key for key in flags if flags.get(key) == True])
    elif model_key == "light":
        attrs["is_light_on"] = record.get("isLightOn")
        attrs["is_dark"] = record.get("isDark")
        attrs["paired_camera_id"] = record.get("camera")
    elif model_key == "viewer":
        attrs["liveview_id"] = record.get("liveview")
        attrs["stream_limit"] = record.get("streamLimit")
    elif model_key == "chime":
        attrs["paired_camera_ids"] = record.get("cameraIds")
    elif model_key == "bridge":
        attrs["platform"] = record.get("platform")
        attrs["client_count"] = record.get("clients")
        attrs["max_clients"] = record.get("maxClients")
    elif model_key == "nvr":
        arm = record.get("armMode")
        if type(arm) == "dict":
            attrs["arm_status"] = arm.get("status")

    tags = [VENDOR, "unifi-protect-" + model_key]
    if state:
        tags.append("protect-state:" + state.lower())

    params = {
        # The Protect `id` is a MongoDB ObjectId minted when Protect first
        # creates the device document. It is stable for the life of an
        # adoption, one per physical device, and namespaced here on the console
        # host so two consoles cannot collide. The MAC is deliberately NOT the
        # id - see the README's Asset identity section - but it still drives
        # correlation, because it is on the interface.
        "id": "{}:{}:{}:{}".format(VENDOR, ctx["scope"], model_key, device_id),
        "hostnames": [name] if name else [],
        "networkInterfaces": [nic] if nic else [],
        "tags": tags,
        "manufacturer": MANUFACTURER,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if model:
        params["model"] = model
    if device_type:
        params["deviceType"] = device_type

    asset = ImportAsset(**params)

    # Protect exposes no adoption or last-seen timestamp on the Integration
    # API. The only per-device times are event times, and only some classes
    # have one; they are used as a last-seen hint rather than invented.
    last_seen = None
    for field in ["lastMotion", "openStatusChangedAt", "motionDetectedAt", "alarmTriggeredAt"]:
        candidate = _parse_ms(record.get(field), ctx["current"])
        if candidate and (last_seen == None or candidate.unix > last_seen.unix):
            last_seen = candidate
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def collect(ctx, path, model_key, device_type):
    """Fetch and stream one Protect device collection."""
    rows = fetch(ctx, path)
    if rows == None:
        return 0, False
    if not rows:
        return 0, True

    reported = 0
    for record in rows:
        if ctx["max_devices"] and ctx["total"] + reported >= ctx["max_devices"]:
            break
        state = as_text(record.get("state"), join=",").strip().upper()
        if state == "DISCONNECTED" and not ctx["include_disconnected"]:
            continue
        asset = build_asset(ctx, record, model_key, device_type)
        if asset == None:
            continue
        report_asset(asset)
        reported += 1
    return reported, True


def main(**kwargs):
    base_url = _base(get_string(kwargs, "url"))
    scope = _scope(base_url)
    if not base_url or not scope:
        print("unifi-protect: could not determine the console host from the configured URL")
        return None

    ctx = {
        "base_url": base_url,
        "scope": scope,
        "current": now(),
        "version": "",
        "total": 0,
        "include_disconnected": get_bool(kwargs, "include_disconnected", default=True),
        "max_devices": max(0, get_int(kwargs, "max_devices", default=5000)),
        "http_options": get_http_options(kwargs, headers={
            "X-API-KEY": get_string(kwargs, "api_key"),
            "Accept": "application/json",
        }),
    }

    version = preflight(ctx)
    if not version:
        return None
    ctx["version"] = version
    print("unifi-protect: Protect {} on {}".format(version, scope))

    total = 0

    if get_bool(kwargs, "collect_nvr", default=True):
        rows = fetch(ctx, "/nvrs")
        if rows:
            for record in rows:
                # The NVR carries no MAC before Protect 7.1, which leaves it
                # with no hardware identity at all on those releases.
                if not _mac_key(record.get("mac")):
                    print("unifi-protect: skipping the NVR record, which carries no MAC. " +
                          "Protect only publishes the NVR MAC on 7.1 and later.")
                    continue
                asset = build_asset(ctx, record, "nvr", "NVR")
                if asset:
                    total += report_asset(asset)

    for path, model_key, device_type, toggle in COLLECTIONS:
        if not get_bool(kwargs, toggle, default=(toggle != "collect_extended")):
            continue
        ctx["total"] = total
        reported, ok = collect(ctx, path, model_key, device_type)
        total += reported
        if reported:
            print("unifi-protect: reported {} {}".format(reported, model_key))

    print("unifi-protect: reported {} devices in total".format(total))
    if ctx["max_devices"] and total >= ctx["max_devices"]:
        print("unifi-protect: device limit of {} reached; further devices were not imported".format(
            ctx["max_devices"]))
    if not total:
        print("unifi-protect: no assets retrieved")
    return None

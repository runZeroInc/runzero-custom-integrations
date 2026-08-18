# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-synology-dsm",
    "name": "Synology DSM",
    "type": "inbound",
    "description": "Imports a Synology NAS and the devices it knows about - Virtual Machine Manager guests, Surveillance Station cameras, Active Backup for Business agents, and DHCP leases - over the DSM webapi.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge - the NAS
    # identified by its chassis serial, and a VM by its guest id - where what
    # must not veto a merge is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # These kinds are identified by an address- or scope-derived id, which is
    # reassigned, so it must neither drive nor block a merge; correlation falls
    # back to the MAC, address, and hostname on the record.
    "assetTypeBehavior": {
        "nas-unidentified": "no-id-match no-id-break",
        "camera": "no-id-match no-id-break",
        "backup-device": "no-id-match no-id-break",
        "lease": "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "url",
            "label": "DSM URL",
            "type": "url",
            "required": True,
            "placeholder": "https://nas.example.com:5001",
            "description": "Base URL of DSM, including the port. The webapi is resolved as <url>/webapi/, so include any path prefix if DSM is behind a reverse proxy.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "secret",
            "required": True,
            "description": "DSM account. An administrator is required for the network interface, system, and DHCP APIs - see the README.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "otp_code",
            "label": "One-time password",
            "type": "secret",
            "required": False,
            "description": "Only for an account with 2FA enabled, and only useful for a one-off manual run - a code expires in seconds. Use a dedicated service account without 2FA for scheduled collection.",
        },
        {
            "key": "collect_vms",
            "label": "Collect Virtual Machine Manager guests",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import VMM guests. Each guest reports its virtual NIC MACs, which is what lets it merge with the machine runZero scans.",
        },
        {
            "key": "collect_cameras",
            "label": "Collect Surveillance Station cameras",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import cameras as assets. Requires the Surveillance Station package; the number visible is bounded by the device licenses installed.",
        },
        {
            "key": "collect_backup_devices",
            "label": "Collect Active Backup for Business devices",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import the machines Active Backup for Business protects. These records carry an address, a hostname, and an OS name.",
        },
        {
            "key": "collect_dhcp_leases",
            "label": "Collect DHCP leases",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import leases when the NAS is running the DHCP Server package. Most Synology units are DHCP clients rather than servers, so this commonly finds nothing.",
        },
        {
            "key": "dhcp_interfaces",
            "label": "DHCP interfaces",
            "type": "string",
            "required": False,
            "default": "bond0,eth0,ovs_eth0,eth1",
            "description": "Comma-separated interface names to ask the DHCP server about. The lease API takes one interface at a time and DSM names them differently depending on bonding and Open vSwitch.",
        },
        {
            "key": "max_assets",
            "label": "Maximum assets",
            "type": "int",
            "required": False,
            "default": 5000,
            "min": 0,
            "description": "Cap on the number of assets imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "ip_address", "ip_in_network", "network_interface", 'routable_ip')
load("http", "get_json", "post_json", "url_parse", "url_encode")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")

load('coerce', 'as_dict', 'as_text', 'dicts')
VENDOR = "synology"
ATTR_PREFIX = "synology"
ATTR_SEPARATOR = "_"

REPORT_BATCH = 200

HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null",
                     "-", "*", "0.0.0.0", "diskstation", "synology", "nas", "rackstation"]

# The webapi answers every request with HTTP 200 and puts the outcome in the
# body. These are the documented codes worth naming.
COMMON_ERRORS = {
    100: "unknown error",
    101: "no parameter of API, method or version",
    102: "the requested API does not exist",
    103: "the requested method does not exist",
    104: "the requested version does not support the functionality",
    105: "the logged in session does not have permission",
    106: "session timeout",
    107: "session interrupted by duplicated login",
    114: "lost parameters for this API",
    119: "invalid session",
    150: "request source IP does not match the login IP",
}

AUTH_ERRORS = {
    400: "no such account or incorrect password",
    401: "disabled account",
    402: "denied permission",
    403: "2-factor authentication code required",
    404: "failed to authenticate the 2-factor authentication code",
    406: "the account is enforced to use 2-factor authentication",
    407: "the request source IP is blocked by DSM auto-block",
    408: "the password has expired and cannot be changed",
    409: "the password has expired",
    410: "the password must be changed",
}

# A session that has gone stale answers with one of these rather than failing
# the transport.
SESSION_ERRORS = [106, 107, 119]

# Candidate key spellings for a DHCP lease record. Synology publishes no
# documentation for this API and no capture of it exists, so every field is
# read through a candidate list rather than a single guess.
LEASE_MAC_KEYS = ["mac", "mac_address", "macaddress", "hwaddr", "hw_addr", "client_mac"]
LEASE_IP_KEYS = ["ip", "ip_address", "ipaddr", "ipaddress", "address", "client_ip"]
LEASE_NAME_KEYS = ["hostname", "host_name", "name", "client_name", "device_name"]
LEASE_EXPIRY_KEYS = ["expired_time", "expire_time", "expires", "lease_time", "valid_until"]
def _pick(record, keys):
    for key in keys:
        value = as_text(record.get(key), join=",").strip()
        if value:
            return value
    return ""


def _mac_key(value):
    """Return a MAC as lowercase colon-separated hex, or "" when it is not one.

    DSM returns MACs DASH-separated and upper-cased ("00-11-32-AA-BB-CC"), and
    VMM returns them colon-separated, so both need canonicalising before
    anything can be compared or keyed.

    net.normalize_mac is deliberately not used: it clears the locally
    administered bit, and every VMM virtual NIC is assigned one from the
    locally administered 02:11:32 space, so normalizing would fold distinct
    guests together. Correct for an interface, wrong for an identity.
    """
    text = as_text(value, join=",").strip().lower()
    for separator in [":", "-", ".", " "]:
        text = text.replace(separator, "")
    if len(text) != 12:
        return ""
    for index in range(12):
        if text[index] not in HEXDIGITS:
            return ""
    if int(text[0:2], 16) % 2 == 1:
        return ""
    if text == "000000000000":
        return ""
    return ":".join([text[index * 2:index * 2 + 2] for index in range(6)])
def _hostname(value):
    text = as_text(value, join=",").strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDER_NAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text


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


def options(ctx, extra_headers):
    """Build HTTP options carrying the current session's headers.

    Rebuilt per request rather than cached once. get_http_options snapshots the
    header map it is handed into the Go layer, so mutating the Starlark dict
    afterwards does NOT reach later requests - and the SynoToken only exists
    after the login has already happened. Caching the options up front would
    therefore silently drop the CSRF header on every call that needs it, which
    fails only on DSMs that have cross-site request forgery protection turned
    on: exactly the ones hardest to get access to for debugging.
    """
    headers = {"Accept": "application/json"}
    if ctx["synotoken"]:
        headers["X-SYNO-TOKEN"] = ctx["synotoken"]
    for key in extra_headers:
        headers[key] = extra_headers[key]
    return get_http_options(ctx["kwargs"], headers=headers)


def _base(url):
    """Return <configured url>/webapi.

    get_url_base is deliberately not used: it keeps only the scheme and host,
    and a NAS published through a reverse proxy is commonly mounted under a
    path prefix, so dropping the path would send every request to the wrong
    place. The port matters here too - DSM's webapi is on 5000/5001 by default,
    not 80/443.
    """
    return as_text(url, join=",").strip().rstrip("/") + "/webapi"


def _scope(url):
    parsed = url_parse(url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return as_text(url, join=",").split("://")[-1].split("/")[0].split(":")[0]


def _describe_error(payload, authenticating):
    """Turn a webapi failure body into a sentence, or return "" on success."""
    if type(payload) != "dict":
        return "unexpected response body"
    if payload.get("success") == True:
        return ""
    error = as_dict(payload.get("error"))
    code = _to_int(error.get("code"))
    if code < 0:
        return "the request failed with no error code"
    known = AUTH_ERRORS.get(code) if authenticating else None
    if known == None:
        known = COMMON_ERRORS.get(code)
    detail = ""
    errors = error.get("errors")
    if type(errors) == "list" and errors:
        parts = []
        for entry in dicts(errors):
            text = _pick(entry, ["msg", "message", "path"])
            if text:
                parts.append(text)
        if parts:
            detail = " (" + "; ".join(parts) + ")"
    if known:
        return "error {}: {}{}".format(code, known, detail)
    return "error {}{}".format(code, detail)


def discover(ctx):
    """Query SYNO.API.Info for every API this DSM publishes.

    This is not optional politeness. The CGI that serves an API differs between
    DSM versions - SYNO.API.Auth lives at auth.cgi on DSM 6 and entry.cgi on
    DSM 7 - and so does its version range. Hardcoding either produces a 102 or
    a 104 on exactly the installs that are hardest to debug remotely. It also
    tells us which optional packages exist, so a NAS without Surveillance
    Station is never asked about cameras.
    """
    url = ctx["base"] + "/query.cgi"
    data, err = get_json(url, params={
        "api": "SYNO.API.Info",
        "version": "1",
        "method": "query",
        "query": "all",
    }, **options(ctx, {}))
    if err:
        print("synology: API discovery failed: " + as_text(err, join=","))
        return {}
    problem = _describe_error(data, False)
    if problem:
        print("synology: API discovery refused: " + problem)
        return {}
    catalog = as_dict(as_dict(data).get("data"))
    apis = {}
    for name in catalog:
        entry = as_dict(catalog.get(name))
        path = as_text(entry.get("path"), join=",").strip()
        if not path:
            continue
        apis[name] = {
            "path": path,
            "min": _to_int(entry.get("minVersion")),
            "max": _to_int(entry.get("maxVersion")),
        }
    return apis


def api_version(ctx, name, preferred):
    """Clamp a preferred version into the range this DSM advertises."""
    entry = as_dict(ctx["apis"].get(name))
    if not entry:
        return -1
    low = entry.get("min")
    high = entry.get("max")
    if low == None or high == None or low < 1 or high < 1:
        return preferred
    if preferred > high:
        return high
    if preferred < low:
        return low
    return preferred


def has_api(ctx, name):
    return name in ctx["apis"]


def first_api(ctx, names):
    """Return the first API name this DSM actually publishes."""
    for name in names:
        if name in ctx["apis"]:
            return name
    return ""


def login(ctx, username, password, otp):
    """Exchange credentials for a session id.

    Sent as a POST with a form-encoded body rather than as a query string, so
    the password does not end up in a URL that DSM or a proxy might log.
    format=sid asks for the session id in the JSON body instead of a cookie,
    which keeps the whole flow explicit.

    enable_syno_token is always requested. A DSM with "Improve protection
    against cross-site request forgery attacks" turned on refuses subsequent
    calls without the returned SynoToken, and asking for it costs nothing on a
    DSM that does not need it.
    """
    name = "SYNO.API.Auth"
    entry = as_dict(ctx["apis"].get(name))
    path = as_text(entry.get("path"), join=",").strip() or "entry.cgi"
    # Version 6 is what Synology's own guide recommends. Versions above it add
    # an encrypted handshake this integration does not implement.
    version = api_version(ctx, name, 6)
    if version < 1:
        version = 6

    form = {
        "api": name,
        "version": str(version),
        "method": "login",
        "account": username,
        "passwd": password,
        # session is hardcoded to a value DSM accepts for non-administrator
        # accounts as well as administrators.
        "session": "runzero",
        "format": "sid",
        "enable_syno_token": "yes",
    }
    if otp:
        form["otp_code"] = otp

    payload, err = post_json(
        ctx["base"] + "/" + path,
        # url_encode is a query-string builder over a MAP, which is exactly the
        # form encoding DSM wants. It returns a string, and post_json's body
        # parameter requires bytes - passing the string raises a type error
        # that aborts the whole script, so the conversion is explicit.
        body=bytes(url_encode(form)),
        **options(ctx, {"Content-Type": "application/x-www-form-urlencoded"})
    )
    if err:
        print("synology: login failed: " + as_text(err, join=","))
        return False
    problem = _describe_error(payload, True)
    if problem:
        print("synology: login refused: " + problem)
        return False

    data = as_dict(as_dict(payload).get("data"))
    sid = as_text(data.get("sid"), join=",").strip()
    if not sid:
        print("synology: login succeeded but returned no sid")
        return False
    ctx["sid"] = sid
    ctx["auth_path"] = path
    ctx["auth_version"] = version
    ctx["synotoken"] = as_text(data.get("synotoken"), join=",").strip()
    return True


def logout(ctx):
    """End the session.

    DSM's concurrent-session allowance is small and a session lingers well past
    a collection run, so a scheduled task that never logs out eventually locks
    itself out of its own account.
    """
    if not ctx["sid"]:
        return
    get_json(ctx["base"] + "/" + ctx["auth_path"], params={
        "api": "SYNO.API.Auth",
        "version": str(ctx["auth_version"]),
        "method": "logout",
        "session": "runzero",
        "_sid": ctx["sid"],
    }, **options(ctx, {}))


def call(ctx, name, method, preferred_version, extra, label):
    """Call one webapi method and return its data object, or None."""
    entry = as_dict(ctx["apis"].get(name))
    if not entry:
        print("synology: skipping {}: this DSM does not publish {}".format(label, name))
        return None
    version = api_version(ctx, name, preferred_version)
    params = {
        "api": name,
        "version": str(version),
        "method": method,
        "_sid": ctx["sid"],
    }
    for key in extra:
        params[key] = extra[key]

    payload, err = get_json(ctx["base"] + "/" + as_text(entry.get("path"), join=",").strip(),
                            params=params, **options(ctx, {}))
    if err:
        print("synology: {} failed: {}".format(label, as_text(err, join=",")))
        return None
    problem = _describe_error(payload, False)
    if problem:
        code = _to_int(as_dict(as_dict(payload).get("error")).get("code"))
        if code in SESSION_ERRORS:
            print("synology: {} lost the session ({}). ".format(label, problem) +
                  "DSM allows few concurrent sessions; check that no other tool is signing in as this account.")
        elif code == 105:
            print("synology: {} refused ({}). ".format(label, problem) +
                  "This API requires an administrator account on DSM.")
        else:
            print("synology: {} refused: {}".format(label, problem))
        return None
    return as_dict(as_dict(payload).get("data"))


def room(ctx):
    """Report whether another asset may be emitted under the cap."""
    if not ctx["max_assets"]:
        return True
    return ctx["emitted"] < ctx["max_assets"]


def emit(ctx, assets):
    if not assets:
        return 0
    report_assets(assets)
    ctx["emitted"] += len(assets)
    return len(assets)


def nas_interfaces(ctx):
    """Return (network_interfaces, hostname, attributes) for the NAS.

    SYNO.DSM.Network is version 2 only and is administrator-gated, and it is
    the only API that returns the NAS's own MACs. Interface records are
    {id, mac, type, ip: [{address, netmask}], ipv6: [{address, prefix_length,
    scope}]}. A PPPoE interface carries no mac key at all, and ipv6 is absent
    rather than empty when unused.
    """
    data = call(ctx, "SYNO.DSM.Network", "list", 2, {}, "network interfaces")
    if data == None:
        return [], [], "", {}
    netifs = []
    own = []
    summary = []
    for entry in dicts(data.get("interfaces")):
        name = as_text(entry.get("id"), join=",").strip()
        mac = _mac_key(entry.get("mac"))
        addresses = []
        for record in dicts(entry.get("ip")) + dicts(entry.get("ipv6")):
            address = routable_ip(record.get("address"))
            if address and address not in addresses:
                addresses.append(address)
        if not mac and not addresses:
            continue
        if mac and mac not in own:
            own.append(mac)
        nic = network_interface(mac=mac, ips=addresses)
        # network_interface returns None when nothing usable survives, and a
        # networkInterfaces list containing None aborts the run.
        if nic:
            netifs.append(nic)
        summary.append("{}[{}]={}".format(name, as_text(entry.get("type"), join=","), mac or ",".join(addresses)))
    attrs = {
        "dns": data.get("dns"),
        "gateway": data.get("gateway"),
        "workgroup": data.get("workgroup"),
        "interfaces": summary,
    }
    return netifs, own, as_text(data.get("hostname"), join=",").strip(), attrs


def build_nas_asset(ctx, info, system, netifs, network_attrs, network_hostname):
    serial = as_text(info.get("serial"), join=",").strip() or as_text(system.get("serial"), join=",").strip()
    model = as_text(info.get("model"), join=",").strip() or as_text(system.get("model"), join=",").strip()
    version_string = as_text(info.get("version_string"), join=",").strip() or as_text(system.get("firmware_ver"), join=",").strip()

    hostnames = []
    for name in [_hostname(network_hostname), _hostname(ctx["scope"])]:
        if name and name not in hostnames:
            hostnames.append(name)

    if not hostnames and not netifs:
        print("synology: the NAS has no usable hostname, address, or MAC; not importing it")
        return None

    attrs = {
        "host": ctx["scope"],
        "model": model,
        "serial": serial,
        "version": info.get("version"),
        "version_string": version_string,
        "ram_mb": info.get("ram") or system.get("ram_size"),
        "temperature_c": info.get("temperature") or system.get("sys_temp"),
        "uptime_seconds": info.get("uptime"),
        "up_time_raw": system.get("up_time"),
        "cpu_vendor": system.get("cpu_vendor"),
        "cpu_family": system.get("cpu_family"),
        "cpu_series": system.get("cpu_series"),
        "cpu_cores": system.get("cpu_cores"),
        "cpu_clock_speed": system.get("cpu_clock_speed"),
        "firmware_date": system.get("firmware_date"),
        "ntp_server": system.get("ntp_server"),
        "time_zone": system.get("time_zone"),
    }
    for key in network_attrs:
        attrs["network_" + key] = network_attrs[key]
    usb = system.get("usb_dev")
    if type(usb) == "list":
        devices = []
        for entry in dicts(usb):
            label = _pick(entry, ["product", "producer", "cls"])
            if label:
                devices.append(label)
        if devices:
            attrs["usb_devices"] = devices

    tags = [VENDOR, "synology-nas"]
    if serial:
        tags.append("serial:" + serial)

    if serial:
        # The DSM serial is the serial on the chassis. It is unique to the
        # hardware and survives a DSM reinstall, a re-address, and a rename.
        asset_id = "{}:serial:{}".format(VENDOR, serial)
        asset_type = ""
    else:
        asset_id = "{}:{}:nas".format(VENDOR, ctx["scope"])
        asset_type = "nas-unidentified"

    params = {
        "id": asset_id,
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "deviceType": "Storage",
        "manufacturer": "Synology",
        "os": "DSM",
        "tags": tags,
        "assetType": asset_type,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    if version_string:
        params["osVersion"] = version_string
    if model:
        params["model"] = model
    return ImportAsset(**params)


def collect_vms(ctx):
    """Import Virtual Machine Manager guests.

    SYNO.Virtualization.API.Guest is the OFFICIAL, documented API and the only
    one that returns vnics. The similarly named SYNO.Virtualization.Guest is
    the internal UI API: it has no vnics at all and its ip field is an empty
    string in practice, which is why clients built on it never surface guest
    MACs. Getting this wrong yields guests with no correlator whatsoever.
    """
    data = call(ctx, "SYNO.Virtualization.API.Guest", "list", 1,
                {"additional": '["vnics"]'}, "virtual machines")
    if data == None:
        return 0
    batch = []
    skipped = 0
    for guest in dicts(data.get("guests")):
        guest_id = as_text(guest.get("guest_id"), join=",").strip()
        name = as_text(guest.get("guest_name"), join=",").strip()
        macs = []
        networks = []
        for vnic in dicts(guest.get("vnics")):
            mac = _mac_key(vnic.get("mac"))
            if mac and mac not in macs:
                macs.append(mac)
            network = as_text(vnic.get("network_name"), join=",").strip()
            if network and network not in networks:
                networks.append(network)
        if not guest_id or not macs:
            # A guest with no virtual NIC has no MAC, no address, and no
            # usable hostname, so an asset for it could never merge with the
            # machine runZero scans and would be a permanent duplicate.
            skipped += 1
            continue
        if not room(ctx):
            skipped += 1
            continue

        netifs = []
        for mac in macs:
            nic = network_interface(mac=mac)
            if nic:
                netifs.append(nic)
        if not netifs:
            skipped += 1
            continue

        attrs = {
            "host": ctx["scope"],
            "nas": ctx["nas_name"],
            "guest_id": guest_id,
            "guest_name": name,
            "status": guest.get("status"),
            "vcpu_num": guest.get("vcpu_num"),
            "vram_size_mb": guest.get("vram_size"),
            "networks": networks,
            "macs": macs,
            "storage_name": guest.get("storage_name"),
            "autorun": guest.get("autorun"),
            "description": guest.get("description"),
        }
        batch.append(ImportAsset(
            # guest_id is a VMM-assigned UUID: stable across a rename, a
            # migration between hosts, and a DSM upgrade.
            id="{}:vm:{}".format(VENDOR, guest_id),
            hostnames=[_hostname(name)] if _hostname(name) else [],
            networkInterfaces=netifs,
            deviceType="Virtual Machine",
            tags=[VENDOR, "synology-vm"],
            customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        ))
    count = emit(ctx, batch)
    if skipped:
        print("synology: {} virtual machines had no virtual NIC and were skipped".format(skipped))
    return count


def collect_cameras(ctx):
    """Import Surveillance Station cameras.

    The method name is List with a capital L. Camera records carry an address
    in `host` - which may be an IP or a hostname or a DDNS name - plus vendor,
    model, and firmware, but NO MAC anywhere in the response.
    """
    # v8 and v9 restructure the response, so the version is held at 7.
    data = call(ctx, "SYNO.SurveillanceStation.Camera", "List", 7,
                {"blFromCamList": "true", "basic": "true", "streamInfo": "true", "privCamType": "3"},
                "cameras")
    if data == None:
        return 0
    batch = []
    skipped = 0
    for camera in dicts(data.get("cameras")):
        camera_id = as_text(camera.get("id"), join=",").strip()
        host = as_text(camera.get("host"), join=",").strip()
        address = routable_ip(host)
        hostname = "" if address else _hostname(host)
        name = _hostname(camera.get("name"))
        if not camera_id or (not address and not hostname):
            skipped += 1
            continue
        if not room(ctx):
            skipped += 1
            continue

        nic = network_interface(ips=[address]) if address else None
        hostnames = []
        for candidate in [hostname, name]:
            if candidate and candidate not in hostnames:
                hostnames.append(candidate)

        attrs = {
            "host": ctx["scope"],
            "nas": ctx["nas_name"],
            "camera_id": camera_id,
            "camera_name": camera.get("name"),
            "camera_host": host,
            "port": camera.get("port"),
            "vendor": camera.get("vendor"),
            "model": camera.get("model"),
            "firmware": camera.get("firmware"),
            "enabled": camera.get("enabled"),
            "status": camera.get("status"),
            "resolution": camera.get("resolution"),
            "fps": camera.get("fps"),
            "channel_id": camera.get("channel_id"),
        }
        params = {
            # The Surveillance Station camera id is a small per-install index
            # that is reused when a camera is deleted, so it is scoped and
            # deliberately inert; see the README.
            "id": "{}:{}:camera:{}".format(VENDOR, ctx["scope"], camera_id),
            "hostnames": hostnames,
            "networkInterfaces": [nic] if nic else [],
            "deviceType": "IP Camera",
            "tags": [VENDOR, "synology-camera"],
            "assetType": "camera",
            "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        vendor = as_text(camera.get("vendor"), join=",").strip()
        if vendor and vendor.lower() not in ["user", "user-defined"]:
            params["manufacturer"] = vendor
        model = as_text(camera.get("model"), join=",").strip()
        if model and model.lower() not in ["define", "user-defined"]:
            params["model"] = model
        firmware = as_text(camera.get("firmware"), join=",").strip()
        if firmware:
            params["osVersion"] = firmware
        batch.append(ImportAsset(**params))
    count = emit(ctx, batch)
    if skipped:
        print("synology: {} cameras had no usable address and were skipped".format(skipped))
    return count


def collect_backup_devices(ctx):
    """Import the machines Active Backup for Business protects.

    Devices are nested inside tasks: data.tasks[].devices[]. These are the best
    described records on a DSM - a real address, a hostname, and an OS name for
    a machine that is not the NAS.
    """
    data = call(ctx, "SYNO.ActiveBackup.Task", "list", 1, {}, "backup devices")
    if data == None:
        return 0
    batch = []
    seen = []
    skipped = 0
    for task in dicts(data.get("tasks")):
        for device in dicts(task.get("devices")):
            address = routable_ip(device.get("host_ip"))
            hostname = _hostname(device.get("host_name"))
            # device_uuid is preferred. device_id is a positive integer, so a
            # zero is Active Backup's "unset" sentinel rather than a real id -
            # taking it literally would key every unregistered row on "0" and
            # collapse them into one asset. The two forms are kept in separate
            # id namespaces so a uuid can never collide with a numeric id.
            device_uuid = as_text(device.get("device_uuid"), join=",").strip()
            numeric_id = _to_int(device.get("device_id"))
            device_id = device_uuid if device_uuid else ("id-{}".format(numeric_id) if numeric_id > 0 else "")
            if not device_id or (not address and not hostname):
                skipped += 1
                continue
            if device_id in seen:
                continue
            if not room(ctx):
                skipped += 1
                continue
            seen.append(device_id)

            nic = network_interface(ips=[address]) if address else None
            attrs = {
                "host": ctx["scope"],
                "nas": ctx["nas_name"],
                "device_uuid": device.get("device_uuid"),
                "device_id": device.get("device_id"),
                "host_ip": device.get("host_ip"),
                "host_name": device.get("host_name"),
                "os_name": device.get("os_name"),
                "agent_status": device.get("agent_status"),
                "backup_type": device.get("backup_type"),
                "login_user": device.get("login_user"),
                "task_name": task.get("task_name"),
            }
            params = {
                # An Active Backup device_uuid identifies an AGENT
                # REGISTRATION, not the machine: reinstalling the agent mints a
                # new one. So the id is scoped and deliberately inert, and
                # correlation runs on the address and hostname; see the README.
                "id": "{}:{}:backup-device:{}".format(VENDOR, ctx["scope"], device_id),
                "hostnames": [hostname] if hostname else [],
                "networkInterfaces": [nic] if nic else [],
                "tags": [VENDOR, "synology-backup-device"],
                "assetType": "backup-device",
                "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
            }
            os_name = as_text(device.get("os_name"), join=",").strip()
            if os_name:
                params["os"] = os_name
            batch.append(ImportAsset(**params))
    count = emit(ctx, batch)
    if skipped:
        print("synology: {} backup devices had no usable identifier, address, or hostname and were skipped".format(skipped))
    return count


def collect_dhcp_leases(ctx, interfaces):
    """Import DHCP leases when the NAS is running the DHCP server.

    Two things make this the least dependable collection here, and both are
    handled rather than assumed. The API was renamed between DSM 6, where the
    DHCP server is built in, and DSM 7, where it is a separate package - so
    both spellings are probed. And Synology documents no response schema for
    it and no public capture exists, so every field is read through a list of
    candidate spellings.
    """
    name = first_api(ctx, ["SYNO.Core.Network.DHCPServer.ClientList",
                           "SYNO.Network.DHCPServer.ClientList"])
    if not name:
        print("synology: skipping DHCP leases: this DSM publishes no DHCP server API, " +
              "which is normal unless the DHCP Server package is installed")
        return 0
    index = {}
    order = []
    for ifname in interfaces:
        data = call(ctx, name, "list", 1, {"ifname": ifname},
                    "DHCP leases on " + ifname)
        if data == None:
            continue
        rows = data.get("clients")
        if type(rows) != "list":
            for key in ["leases", "items", "data", "list"]:
                if type(data.get(key)) == "list":
                    rows = data.get(key)
                    break
        for lease in dicts(rows):
            mac = _mac_key(_pick(lease, LEASE_MAC_KEYS))
            if not mac or mac in ctx["nas_macs"]:
                continue
            if mac not in index:
                if not room(ctx) or (ctx["max_assets"] and len(order) + ctx["emitted"] >= ctx["max_assets"]):
                    continue
                index[mac] = {"mac": mac, "ips": [], "hostnames": [], "interfaces": [], "expiry": ""}
                order.append(mac)
            record = index[mac]
            address = routable_ip(_pick(lease, LEASE_IP_KEYS))
            if address and address not in record["ips"]:
                record["ips"].append(address)
            hostname = _hostname(_pick(lease, LEASE_NAME_KEYS))
            if hostname and hostname not in record["hostnames"]:
                record["hostnames"].append(hostname)
            if ifname not in record["interfaces"]:
                record["interfaces"].append(ifname)
            expiry = _pick(lease, LEASE_EXPIRY_KEYS)
            if expiry and not record["expiry"]:
                record["expiry"] = expiry

    batch = []
    for mac in order:
        record = index[mac]
        nic = network_interface(mac=mac, ips=record["ips"])
        if not nic:
            continue
        attrs = {
            "host": ctx["scope"],
            "nas": ctx["nas_name"],
            "mac": mac,
            "addresses": record["ips"],
            "dhcp_interfaces": record["interfaces"],
            # Preserved verbatim and never converted into a timestamp: the
            # field is undocumented, so whether it is an epoch, a duration, or
            # a formatted string is not established, and a value misread into
            # the future would make the platform reject the whole record.
            "lease_expiry_raw": record["expiry"],
        }
        batch.append(ImportAsset(
            # A lease has no identifier but its MAC, canonicalised losslessly
            # and paired with no-id-match; see the README.
            id="{}:{}:lease:{}".format(VENDOR, ctx["scope"], mac),
            hostnames=record["hostnames"],
            networkInterfaces=[nic],
            tags=[VENDOR, "synology-dhcp-lease"],
            assetType="lease",
            customAttributes=to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        ))
    return emit(ctx, batch)


def main(**kwargs):
    url = get_string(kwargs, "url", default="")
    base = _base(url)
    scope = _scope(url)
    if not scope or base == "/webapi":
        print("synology: could not determine the NAS host from the configured URL")
        return None

    max_assets = get_int(kwargs, "max_assets", default=5000)
    ctx = {
        "base": base,
        "scope": scope,
        "kwargs": kwargs,
        "synotoken": "",
        "apis": {},
        "sid": "",
        "auth_path": "entry.cgi",
        "auth_version": 6,
        "max_assets": max_assets if max_assets > 0 else 0,
        "emitted": 0,
        "nas_name": "",
        "nas_macs": [],
    }

    ctx["apis"] = discover(ctx)
    if not ctx["apis"]:
        print("synology: could not read the API catalog. Check the URL and port " +
              "(DSM serves the webapi on 5000 for HTTP and 5001 for HTTPS by default) " +
              "and that the Explorer can reach DSM.")
        return None

    if not login(ctx, get_string(kwargs, "username"), get_string(kwargs, "password"),
                 get_string(kwargs, "otp_code", default="")):
        return None

    # SYNO.DSM.Info is version 2 only and works for a non-administrator, so it
    # is the reliable source of model, serial, and DSM version.
    info = call(ctx, "SYNO.DSM.Info", "getinfo", 2, {}, "system info") or {}
    # SYNO.Core.System adds CPU and firmware detail but is administrator-gated;
    # its absence is not an error.
    system = call(ctx, "SYNO.Core.System", "info", 3, {}, "system detail") or {}

    netifs, own_macs, network_hostname, network_attrs = nas_interfaces(ctx)
    ctx["nas_name"] = network_hostname or as_text(info.get("model"), join=",").strip()
    ctx["nas_macs"] = own_macs

    nas_count = 0
    asset = build_nas_asset(ctx, info, system, netifs, network_attrs, network_hostname)
    if asset:
        emit(ctx, [asset])
        nas_count = 1
        if not (as_text(info.get("serial"), join=",").strip() or as_text(system.get("serial"), join=",").strip()):
            print("synology: no serial number was returned, so the NAS asset is keyed on the " +
                  "configured host and its id will not drive merges")
    if not netifs:
        print("synology: no network interfaces were returned. SYNO.DSM.Network requires an " +
              "administrator account, and it is the only API that exposes the NAS's own MAC addresses.")

    vm_count = 0
    if get_bool(kwargs, "collect_vms", default=True):
        vm_count = collect_vms(ctx)
        print("synology: reported {} virtual machines".format(vm_count))

    camera_count = 0
    if get_bool(kwargs, "collect_cameras", default=True):
        camera_count = collect_cameras(ctx)
        print("synology: reported {} cameras".format(camera_count))

    backup_count = 0
    if get_bool(kwargs, "collect_backup_devices", default=True):
        backup_count = collect_backup_devices(ctx)
        print("synology: reported {} backup devices".format(backup_count))

    lease_count = 0
    if get_bool(kwargs, "collect_dhcp_leases", default=True):
        interfaces = []
        for entry in get_string(kwargs, "dhcp_interfaces", default="bond0,eth0,ovs_eth0,eth1").split(","):
            value = entry.strip()
            if value and value not in interfaces:
                interfaces.append(value)
        lease_count = collect_dhcp_leases(ctx, interfaces)
        print("synology: reported {} DHCP leases".format(lease_count))

    logout(ctx)

    if ctx["max_assets"] and ctx["emitted"] >= ctx["max_assets"]:
        print("synology: asset limit of {} reached; further records were not imported".format(
            ctx["max_assets"]))
    print("synology: reported {} NAS, {} virtual machines, {} cameras, {} backup devices, {} leases".format(
        nas_count, vm_count, camera_count, backup_count, lease_count))
    if not ctx["emitted"]:
        print("synology: no assets retrieved")
    return None

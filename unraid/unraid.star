# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-unraid",
    "name": "Unraid",
    "type": "inbound",
    "description": "Imports an Unraid server and the Docker containers that hold their own address on the network, over the official GraphQL API.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    # The 'machine' records are the exception: their id is issued by the vendor
    # rather than derived from an address, so it may drive a merge, and only
    # a changed MAC, address, or name must not veto one.
    "assetTypeBehavior": {
        'machine': "no-mac-break no-ip-break no-name-break",
    },
    "params": [
        {
            "key": "url",
            "label": "Unraid URL",
            "type": "url",
            "required": True,
            "placeholder": "http://tower.local",
            "description": "Base URL of the Unraid web interface. The API is resolved as <url>/graphql, which is served by the same nginx as the WebGUI.",
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
            "description": "Key created with 'unraid-api apikey --create --name runzero -r VIEWER'. Sent in the x-api-key header; bearer tokens are not accepted.",
        },
        {
            "key": "collect_containers",
            "label": "Collect Docker containers",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Import containers that have their own IP or MAC, which means macvlan or a custom bridge. Containers on host networking share the server's stack and are recorded on the server asset instead.",
        },
        {
            "key": "container_services",
            "label": "Import container published ports as services",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Attach each container's published ports to its asset as services.",
        },
        {
            "key": "include_stopped_containers",
            "label": "Include stopped containers",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "A stopped container has no live address. Enabling this imports it anyway when Docker still reports one.",
        },
        {
            "key": "include_nat_containers",
            "label": "Include containers on the default Docker bridge",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Off by default. Containers on Docker's default bridge are NAT'd behind the server and are addressed from 172.17.0.0/16, which is the same range on every Docker host, so importing them can merge unrelated containers running on different servers.",
        },
        {
            "key": "collect_vms",
            "label": "Collect virtual machines",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Record the VM inventory on the server asset. Unraid's API exposes no MAC or IP for a guest, so VMs are not emitted as assets of their own - see the README.",
        },
        {
            "key": "collect_storage",
            "label": "Collect array and disk detail",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Record array state, capacity, and per-disk model and serial on the server asset.",
        },
        {
            "key": "max_containers",
            "label": "Maximum containers",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 0,
            "description": "Cap on the number of container assets imported in one run. 0 removes the cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "Service", "to_custom_attributes")
load("net", "ip_address", "network_interface", 'routable_ip')
load("http", "post_json", "url_parse")
load("kwargs", "get_http_options", "get_bool", "get_int", "get_string")
load("time", "now", "parse_time")

load('coerce', 'as_dict', 'as_text', 'dicts')
VENDOR = "unraid"
ATTR_PREFIX = "unraid"
ATTR_SEPARATOR = "_"

# The platform caps child collections at 99 per asset.
MAX_SERVICES = 99

HEXDIGITS = "0123456789abcdef"
DIGITS = "0123456789"

PLACEHOLDER_NAMES = ["localhost", "localhost.localdomain", "unknown", "none", "null",
                     "-", "*", "0.0.0.0", "tower", "unraid"]

# Interfaces that are not the server's attachment to the network. br0 and bond0
# are deliberately absent: on Unraid the bridge is normally the primary
# interface, and the API's own primaryNetwork resolver prefers br0 over eth0.
VIRTUAL_INTERFACE_PREFIXES = [
    "lo", "docker", "veth", "virbr", "vhost", "shim", "wg", "tun", "tap",
    "vnet", "dummy", "zt", "tailscale", "nordlynx",
]

# Container network modes that give the container no identity of its own: it
# shares the server's stack, or another container's.
HOST_NETWORK_MODES = ["host", "none", "container"]

# Container network modes that are NAT behind the server. Docker's default
# bridge hands out 172.17.0.0/16 on EVERY Docker host, so those addresses are
# not unique to this server and are not reachable from the network. Importing
# them would correlate unrelated containers on different servers to each other.
NAT_NETWORK_MODES = ["bridge", "default", "nat"]
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

    net.normalize_mac is deliberately not used: it clears the locally
    administered bit, and Docker assigns every bridged container a locally
    administered MAC (02:42:...), so normalizing would fold containers together
    and onto anything else in that space. Correct for an interface, wrong for
    an identity. This canonicalisation is lossless.
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

def _strip_prefixed_id(value):
    """Drop the server prefix from a PrefixedID.

    Every id in this schema is returned as "<serverIdentifier>:<id>", for
    example "1:3f9a2b7c1d4e". The prefix is not part of the underlying Docker
    or libvirt identifier.
    """
    text = as_text(value, join=",").strip()
    if ":" in text:
        return text.split(":", 1)[1]
    return text

def _is_virtual_interface(name):
    lowered = as_text(name, join=",").strip().lower()
    if not lowered:
        return True
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if lowered == prefix:
            return True
        if lowered.startswith(prefix) and len(lowered) > len(prefix):
            tail = lowered[len(prefix)]
            if tail in "0123456789-_.":
                return True
    return False

def _parse_iso(value, current):
    """Parse an RFC3339 timestamp, or return None.

    time.parse_time ABORTS the whole script on unparseable input and Starlark
    has no exception handling, so the shape is validated first. The result is
    clamped to now because the platform rejects the ENTIRE asset record - not
    the field - on a future timestamp.
    """
    text = as_text(value, join=",").strip()
    if len(text) < 20 or text[4] != "-" or text[7] != "-" or text[10] != "T":
        return None
    if text[13] != ":" or text[16] != ":":
        return None
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]:
        if text[index] not in DIGITS:
            return None
    if not (text.endswith("Z") or text.endswith("z") or "+" in text[19:] or "-" in text[19:]):
        return None
    month = _to_int(text[5:7])
    day = _to_int(text[8:10])
    if month < 1 or month > 12 or day < 1 or day > 31:
        return None
    parsed = parse_time(text)
    if parsed.unix > current.unix:
        return current
    return parsed

def _base(url):
    """Return <configured url>/graphql.

    get_url_base is deliberately not used: it keeps only the scheme and host,
    and an Unraid server published through a reverse proxy is commonly mounted
    under a path prefix, so dropping the path would post to the wrong place.
    """
    return as_text(url, join=",").strip().rstrip("/") + "/graphql"

def _scope(url):
    parsed = url_parse(url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return as_text(url, join=",").split("://")[-1].split("/")[0].split(":")[0]

def _error_messages(payload):
    """Collect error text from BOTH envelopes this endpoint produces.

    A normal GraphQL error is {"errors": [{"message": "..."}]}. But when the
    unraid-api service is stopped, stock nginx intercepts the upstream 502 and
    returns HTTP 200 with a hand-written body whose shape is NOT standard
    GraphQL: {"errors":[{"error":{"name":"InternalError","message":"Graphql is
    offline."}}]}. Reading only .message would find nothing there and report a
    successful, empty collection.
    """
    messages = []
    for entry in dicts(payload.get("errors")):
        text = as_text(entry.get("message"), join=",").strip()
        if not text:
            text = as_text(as_dict(entry.get("error")).get("message"), join=",").strip()
        if text and text not in messages:
            messages.append(text)
    return messages

def _is_unknown_field(messages):
    """True when a GraphQL error list is a schema-validation refusal.

    graphql-js (which unraid-api's Apollo server is built on) phrases it
    'Cannot query field "x" on type "Y"'; other engines say 'Unknown field' or
    "doesn't exist on type". Any of them means the document named a field this
    server's schema does not have, which is retryable with a smaller query --
    unlike an auth refusal or the api-offline masquerade.
    """
    for message in messages:
        lowered = as_text(message, join=",").lower()
        if "cannot query field" in lowered:
            return True
        if "unknown field" in lowered:
            return True
        if "doesn't exist on type" in lowered:
            return True
    return False

def graphql(ctx, query, label, required, errors_out=None):
    """Run one GraphQL query and return its data object, or None.

    The endpoint answers HTTP 200 for everything, including errors, so the body
    is the only signal. Queries are deliberately kept small and separate rather
    than combined into one document: a field this server's schema does not have
    fails the whole document at validation time, and one unknown field should
    not cost every other collection.

    errors_out, when given, is a list the GraphQL error messages are appended
    to, so a caller can tell a schema-validation failure apart from the rest
    and retry with a smaller query.
    """
    payload, err = post_json(ctx["endpoint"], json={"query": query}, **ctx["http_options"])
    if err:
        lowered = as_text(err, join=",").lower()
        if "status 401" in lowered or "status 403" in lowered or "unauthorized" in lowered:
            print("unraid: {} refused: the API key was rejected. Create one with ".format(label) +
                  "'unraid-api apikey --create --name runzero -r VIEWER' and check it is sent as x-api-key.")
            return None
        print("unraid: {} failed: {}".format(label, err))
        return None
    if type(payload) != "dict":
        print("unraid: {} returned an unexpected body".format(label))
        return None

    messages = _error_messages(payload)
    if errors_out != None:
        for message in messages:
            errors_out.append(message)
    for message in messages:
        if "graphql is offline" in message.lower():
            print("unraid: the Unraid API service is not running. nginx answers /graphql with " +
                  "HTTP 200 and 'Graphql is offline.' when the backend socket is down. " +
                  "Start it on the server with 'unraid-api start' and check 'unraid-api status'.")
            return None

    data = payload.get("data")
    if type(data) != "dict":
        if messages:
            print("unraid: {} returned no data: {}".format(label, "; ".join(messages)))
        elif required:
            print("unraid: {} returned no data".format(label))
        return None
    # Partial success is normal here: a key without one resource permission
    # returns the resources it can read alongside an error for the rest.
    if messages:
        print("unraid: {} returned partial data: {}".format(label, "; ".join(messages)))
    return data

QUERY_INFO = """query RunZeroUnraidInfo {
  info {
    machineId
    os { platform distro release kernel arch hostname fqdn uptime uefi }
    system { manufacturer model version serial uuid sku virtual }
    baseboard { manufacturer model version serial assetTag }
    cpu { manufacturer brand vendor family model cores threads processors socket speed speedmax }
    versions { core { unraid api kernel } packages { docker php nginx openssl node } }
    networkInterfaces {
      name description macAddress mtu speed duplex internal virtual operstate type vlanId
      ipv4Addresses { address netmask }
      ipv6Addresses { address prefixLength }
      ipAddress netmask useDhcp ipv6Address status
    }
  }
}"""

QUERY_VARS = """query RunZeroUnraidVars {
  vars { version name comment timeZone domain localTld sysModel flashGuid flashProduct flashVendor regTy regState deviceCount }
  metrics { memory { total used free available percentTotal } }
}"""

# The container query, in two tiers. The full tier names every field this
# integration can use, but GraphQL fails the whole document at validation time
# on ONE unknown field, and unraid-api releases add and remove container fields
# quickly. When the full tier is rejected by the schema, the walk drops to the
# core tier -- the fields the asset is actually built from -- rather than
# importing zero containers. Every read downstream is a .get, so a container
# from the core tier simply lacks the enrichment attributes.
QUERY_DOCKER = """query RunZeroUnraidDocker {
  docker {
    containers {
      id names image imageId state status created
      autoStart isOrphaned isUpdateAvailable
      ports { ip privatePort publicPort type }
      labels
      hostConfig { networkMode }
      networkSettings
      templatePath projectUrl webUiUrl
    }
  }
}"""

QUERY_DOCKER_CORE = """query RunZeroUnraidDocker {
  docker {
    containers {
      id names image state status
      ports { ip privatePort publicPort type }
      hostConfig { networkMode }
      networkSettings
    }
  }
}"""

QUERY_VMS = """query RunZeroUnraidVms { vms { domains { id name state } } }"""

QUERY_STORAGE = """query RunZeroUnraidStorage {
  array {
    state
    capacity { kilobytes { free used total } disks { free used total } }
    disks { id idx name device size status type fsType temp rotational transport }
    parities { id idx name device size status type }
    caches { id idx name device size status type fsType }
  }
  disks { id device type name vendor size serialNum firmwareRevision interfaceType smartStatus temperature }
}"""

def server_interfaces(info):
    """Return (network_interfaces, summary) for the Unraid server.

    The gateway field is deliberately ignored: the resolver hardcodes it to the
    literal string "unknown". ipv4Addresses/ipv6Addresses are built from a
    single ip4/ip6 value upstream, so they hold at most one entry each even on
    a multi-addressed interface, and ipAddress carries the same value - both
    are read so neither shape is missed.
    """
    netifs = []
    summary = []
    for entry in dicts(info.get("networkInterfaces")):
        name = as_text(entry.get("name"), join=",").strip()
        # internal is the API's own loopback flag. virtual is NOT used as a
        # filter: Unraid's primary interface br0 is a bridge and reports
        # virtual=true, and dropping it would discard the server's real address.
        if entry.get("internal") == True or _is_virtual_interface(name):
            continue
        mac = _mac_key(entry.get("macAddress"))
        addresses = []
        for record in dicts(entry.get("ipv4Addresses")) + dicts(entry.get("ipv6Addresses")):
            address = routable_ip(record.get("address"))
            if address and address not in addresses:
                addresses.append(address)
        for key in ["ipAddress", "ipv6Address"]:
            address = routable_ip(entry.get(key))
            if address and address not in addresses:
                addresses.append(address)
        if not mac and not addresses:
            continue
        nic = network_interface(mac=mac, ips=addresses)
        # network_interface returns None when nothing usable survives, and a
        # networkInterfaces list containing None aborts the run.
        if nic:
            netifs.append(nic)
        summary.append("{}[{}]={}".format(name, as_text(entry.get("operstate"), join=","), mac or ",".join(addresses)))
    return netifs, summary

def build_server_asset(ctx, info, extras, netifs, summary):
    os_info = as_dict(info.get("os"))
    system = as_dict(info.get("system"))
    baseboard = as_dict(info.get("baseboard"))
    cpu = as_dict(info.get("cpu"))
    versions = as_dict(info.get("versions"))
    core = as_dict(versions.get("core"))

    machine_id = as_text(info.get("machineId"), join=",").strip()
    hostname = _hostname(os_info.get("hostname"))
    fqdn = _hostname(os_info.get("fqdn"))
    hostnames = []
    for name in [hostname, fqdn, _hostname(as_dict(extras.get("vars")).get("name"))]:
        if name and name not in hostnames:
            hostnames.append(name)

    if not hostnames and not netifs:
        print("unraid: the server has no usable hostname, address, or MAC; not importing it")
        return None

    attrs = {
        "host": ctx["scope"],
        "machine_id": machine_id,
        "platform": os_info.get("platform"),
        "distro": os_info.get("distro"),
        "release": os_info.get("release"),
        "kernel": os_info.get("kernel"),
        "arch": os_info.get("arch"),
        "uefi": os_info.get("uefi"),
        "boot_time_raw": os_info.get("uptime"),
        "system_manufacturer": system.get("manufacturer"),
        "system_model": system.get("model"),
        "system_serial": system.get("serial"),
        "system_uuid": system.get("uuid"),
        "baseboard_manufacturer": baseboard.get("manufacturer"),
        "baseboard_model": baseboard.get("model"),
        "baseboard_serial": baseboard.get("serial"),
        "cpu_manufacturer": cpu.get("manufacturer"),
        "cpu_brand": cpu.get("brand"),
        "cpu_cores": cpu.get("cores"),
        "cpu_threads": cpu.get("threads"),
        "cpu_speed_ghz": cpu.get("speed"),
        "version_unraid": core.get("unraid"),
        "version_api": core.get("api"),
        "docker_version": as_dict(versions.get("packages")).get("docker"),
        "interfaces": summary,
    }
    for key in extras:
        block = as_dict(extras.get(key))
        for field in block:
            attrs[key + "_" + field] = block[field]

    tags = [VENDOR, "unraid-server"]
    for serial in [as_text(system.get("serial"), join=",").strip(), as_text(baseboard.get("serial"), join=",").strip()]:
        if serial and serial.lower() not in ["", "default string", "to be filled by o.e.m.", "none"]:
            tag = "serial:" + serial
            if tag not in tags:
                tags.append(tag)

    if machine_id:
        # machineId is the machine identifier this API exposes, and it comes
        # from the same info resolver everything else here needs, so it cannot
        # disappear independently of the rest of the collection.
        asset_id = "{}:machine:{}".format(VENDOR, machine_id)
        asset_type = "machine"
    else:
        asset_id = "{}:{}:server".format(VENDOR, ctx["scope"])
        asset_type = "server"

    params = {
        "id": asset_id,
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "deviceType": "Server",
        "tags": tags,
        "assetType": asset_type,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        "os": "Unraid",
    }
    version = as_text(core.get("unraid"), join=",").strip() or as_text(os_info.get("release"), join=",").strip()
    if version:
        params["osVersion"] = version
    model = as_text(system.get("model"), join=",").strip() or as_text(baseboard.get("model"), join=",").strip()
    if model:
        params["model"] = model
    manufacturer = as_text(system.get("manufacturer"), join=",").strip() or as_text(baseboard.get("manufacturer"), join=",").strip()
    if manufacturer:
        params["manufacturer"] = manufacturer

    asset = ImportAsset(**params)
    # os.uptime is documented in the schema as a "Boot time ISO string" - it is
    # a timestamp, not a duration, and misreading it as seconds would produce a
    # nonsense date.
    boot = _parse_iso(os_info.get("uptime"), ctx["current"])
    if boot:
        asset.firstSeenTS = boot
    return asset

def container_endpoints(container):
    """Return (mac, ips, networks) from a container's networkSettings.

    networkSettings is the JSON scalar - a raw passthrough of the Docker Engine
    ContainerInfo.NetworkSettings, so the shape is Docker's:
    {"Networks": {"<name>": {"IPAddress": ..., "MacAddress": ...,
    "GlobalIPv6Address": ...}}}. A container on host networking has empty
    strings for all of them, because it shares the host's stack.
    """
    settings = as_dict(container.get("networkSettings"))
    networks = as_dict(settings.get("Networks"))
    mac = ""
    ips = []
    names = []
    for name in networks:
        entry = as_dict(networks.get(name))
        names.append(name)
        if not mac:
            mac = _mac_key(entry.get("MacAddress"))
        for key in ["IPAddress", "GlobalIPv6Address"]:
            address = routable_ip(entry.get(key))
            if address and address not in ips:
                ips.append(address)
    return mac, ips, names

def container_services(container, ips):
    """Turn published ports into Service objects bound to the container."""
    services = []
    if not ips:
        return services
    address = ips[0]
    seen = []
    for entry in dicts(container.get("ports")):
        port = _to_int(entry.get("privatePort"))
        if port < 1 or port > 65535:
            continue
        transport = as_text(entry.get("type"), join=",").strip().lower() or "tcp"
        key = "{}/{}".format(port, transport)
        if key in seen:
            continue
        seen.append(key)
        if len(services) >= MAX_SERVICES:
            break
        attributes = {"container_port": str(port)}
        public = _to_int(entry.get("publicPort"))
        if public > 0 and public < 65536:
            attributes["published_port"] = str(public)
        bind = as_text(entry.get("ip"), join=",").strip()
        if bind:
            attributes["published_on"] = bind
        services.append(Service(
            address=address,
            port=port,
            transport=transport,
            customAttributes=attributes,
        ))
    return services

def build_container_asset(ctx, container, mac, ips, networks):
    names = container.get("names")
    name = ""
    if type(names) == "list" and names:
        name = as_text(names[0], join=",").strip().lstrip("/")
    if not name:
        name = _strip_prefixed_id(container.get("id"))

    labels = as_dict(container.get("labels"))
    attrs = {
        "host": ctx["scope"],
        "server": ctx["server_name"],
        "container_name": name,
        "container_id": _strip_prefixed_id(container.get("id")),
        "image": container.get("image"),
        "image_id": container.get("imageId"),
        "state": container.get("state"),
        "status": container.get("status"),
        "network_mode": as_dict(container.get("hostConfig")).get("networkMode"),
        "networks": networks,
        "auto_start": container.get("autoStart"),
        "is_orphaned": container.get("isOrphaned"),
        "update_available": container.get("isUpdateAvailable"),
        "template_path": container.get("templatePath"),
        "project_url": container.get("projectUrl"),
        "web_ui": container.get("webUiUrl"),
        "addresses": ips,
        "mac": mac,
    }
    for key in labels:
        value = as_text(labels.get(key), join=",").strip()
        if value:
            attrs["label_" + key] = value

    tags = [VENDOR, "unraid-container"]
    compose_project = as_text(labels.get("com.docker.compose.project"), join=",").strip()
    if compose_project:
        tags.append("compose-project:" + compose_project)

    nic = network_interface(mac=mac, ips=ips)
    params = {
        # A container id changes on every recreate, and Unraid recreates a
        # container on every image update, so the id is built from the
        # container NAME - which Unraid's Docker manager keeps stable because
        # it comes from the template. Paired with no-id-match; see the README.
        "id": "{}:{}:container:{}".format(VENDOR, ctx["scope"], name),
        "hostnames": [],
        "networkInterfaces": [nic] if nic else [],
        "deviceType": "Container",
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }
    image = as_text(container.get("image"), join=",").strip()
    if image:
        params["os"] = image
    if ctx["container_services"]:
        services = container_services(container, ips)
        if services:
            params["services"] = services
    return ImportAsset(**params)

def collect_containers(ctx):
    """Emit assets for containers that hold an address of their own.

    A container on host networking shares the server's network stack: it has no
    MAC, no address, and no hostname, so an asset for it could never merge with
    anything and would be a permanent orphan. Those are recorded on the server
    asset instead of being invented as devices.
    """
    errors = []
    data = graphql(ctx, QUERY_DOCKER, "docker containers", False, errors)
    if data == None and _is_unknown_field(errors):
        # This server's schema lacks one of the optional fields. Retry with the
        # core field set instead of version-gating the whole container import.
        print("unraid: this API release does not carry every optional container field; " +
              "retrying with the core field set")
        data = graphql(ctx, QUERY_DOCKER_CORE, "docker containers (core fields)", False)
    if data == None:
        return 0, [], []
    containers = dicts(as_dict(data.get("docker")).get("containers"))
    emitted = 0
    shared_stack = []
    for container in containers:
        names = container.get("names")
        name = ""
        if type(names) == "list" and names:
            name = as_text(names[0], join=",").strip().lstrip("/")
        if not name:
            name = _strip_prefixed_id(container.get("id"))
        state = as_text(container.get("state"), join=",").strip().upper()
        summary = "{}={}".format(name, state or "UNKNOWN")

        if state != "RUNNING" and not ctx["include_stopped_containers"]:
            shared_stack.append(summary + " (not running)")
            continue

        mac, ips, networks = container_endpoints(container)
        mode = as_text(as_dict(container.get("hostConfig")).get("networkMode"), join=",").strip().lower()
        if mode.split(":")[0] in HOST_NETWORK_MODES:
            shared_stack.append(summary + " (shares the host network stack)")
            continue
        if mode in NAT_NETWORK_MODES and not ctx["include_nat_containers"]:
            shared_stack.append(summary + " (NAT behind the server on the default bridge)")
            continue
        if not mac and not ips:
            shared_stack.append(summary + " (no address of its own)")
            continue
        if ctx["max_containers"] and emitted >= ctx["max_containers"]:
            shared_stack.append(summary + " (over the container limit)")
            continue

        report_asset(build_container_asset(ctx, container, mac, ips, networks))
        emitted += 1
    return emitted, shared_stack, [as_text(c.get("image"), join=",").strip() for c in containers]

def collect_vms(ctx):
    """Summarize the VM inventory.

    No asset is emitted. Unraid's schema exposes exactly four fields for a
    guest - id, name, state, and a deprecated uuid - with no NIC list, no MAC,
    no address, and no libvirt XML. An asset built from a UUID and a display
    name such as "Windows 11" carries no MAC, IP, or hostname, so it could
    never merge with the real machine runZero scans and would be a permanent
    duplicate. The inventory is recorded on the server instead.
    """
    data = graphql(ctx, QUERY_VMS, "virtual machines", False)
    if data == None:
        return []
    domains = dicts(as_dict(data.get("vms")).get("domains"))
    summary = []
    for domain in domains:
        name = as_text(domain.get("name"), join=",").strip()
        if not name:
            continue
        summary.append("{}={}".format(name, as_text(domain.get("state"), join=",").strip() or "UNKNOWN"))
    return summary

def collect_storage(ctx):
    """Return array and disk detail for the server asset."""
    data = graphql(ctx, QUERY_STORAGE, "array and disks", False)
    if data == None:
        return {}
    array = as_dict(data.get("array"))
    capacity = as_dict(as_dict(array.get("capacity")).get("kilobytes"))
    disk_summary = []
    serials = []
    for disk in dicts(data.get("disks")):
        name = as_text(disk.get("name"), join=",").strip() or as_text(disk.get("device"), join=",").strip()
        serial = as_text(disk.get("serialNum"), join=",").strip()
        if name:
            disk_summary.append("{}[{}]".format(name, serial or "no-serial"))
        if serial and serial not in serials:
            serials.append(serial)
    slots = []
    for key in ["disks", "parities", "caches"]:
        for entry in dicts(array.get(key)):
            label = as_text(entry.get("name"), join=",").strip()
            if label:
                slots.append("{}:{}".format(label, as_text(entry.get("status"), join=",").strip()))
    return {
        "array_state": array.get("state"),
        "array_total_kb": capacity.get("total"),
        "array_used_kb": capacity.get("used"),
        "array_free_kb": capacity.get("free"),
        "array_slots": slots,
        "disks": disk_summary,
        "disk_serials": serials,
    }

def main(**kwargs):
    url = get_string(kwargs, "url", default="")
    endpoint = _base(url)
    scope = _scope(url)
    if not scope or endpoint == "/graphql":
        print("unraid: could not determine the server host from the configured URL")
        return None

    max_containers = get_int(kwargs, "max_containers", default=500)
    ctx = {
        "endpoint": endpoint,
        "scope": scope,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/json",
            # The API accepts an API key in x-api-key only. Bearer tokens are
            # not a registered strategy and are rejected before validation.
            "x-api-key": get_string(kwargs, "api_key"),
        }),
        "current": now(),
        "max_containers": max_containers if max_containers > 0 else 0,
        "container_services": get_bool(kwargs, "container_services", default=True),
        "include_stopped_containers": get_bool(kwargs, "include_stopped_containers", default=False),
        "include_nat_containers": get_bool(kwargs, "include_nat_containers", default=False),
        "server_name": "",
    }

    data = graphql(ctx, QUERY_INFO, "system info", True)
    if data == None:
        print("unraid: no system info, nothing collected. The API needs Unraid 7.2 or newer " +
              "(or the Unraid Connect plugin on 7.0-7.1), and the key needs at least INFO:READ_ANY, " +
              "which the VIEWER role grants.")
        return None
    info = as_dict(data.get("info"))
    if not info:
        print("unraid: the info query returned no server. Check the key's permissions.")
        return None
    ctx["server_name"] = as_text(as_dict(info.get("os")).get("hostname"), join=",").strip()

    extras = {}
    vars_data = graphql(ctx, QUERY_VARS, "vars and metrics", False)
    if vars_data != None:
        block = as_dict(vars_data.get("vars"))
        if block:
            extras["vars"] = block
        memory = as_dict(as_dict(vars_data.get("metrics")).get("memory"))
        if memory:
            extras["memory"] = memory

    if get_bool(kwargs, "collect_storage", default=True):
        storage = collect_storage(ctx)
        if storage:
            extras["storage"] = storage

    container_count = 0
    shared_stack = []
    images = []
    if get_bool(kwargs, "collect_containers", default=True):
        container_count, shared_stack, images = collect_containers(ctx)
        print("unraid: reported {} containers with an address of their own".format(container_count))
        if shared_stack:
            print("unraid: {} containers were not imported as assets ".format(len(shared_stack)) +
                  "(host networking, stopped, or over the limit); they are recorded on the server")

    vms = []
    if get_bool(kwargs, "collect_vms", default=True):
        vms = collect_vms(ctx)
        if vms:
            print("unraid: recorded {} virtual machines on the server asset ".format(len(vms)) +
                  "(the API exposes no MAC or address for a guest, so they are not separate assets)")

    docker_block = {}
    if images:
        docker_block["container_images"] = images
    if shared_stack:
        docker_block["containers_without_own_address"] = shared_stack
    if container_count:
        docker_block["containers_imported"] = container_count
    if docker_block:
        extras["docker"] = docker_block
    if vms:
        extras["vm"] = {"guests": vms, "guest_count": len(vms)}

    netifs, summary = server_interfaces(info)
    asset = build_server_asset(ctx, info, extras, netifs, summary)
    server_count = 0
    if asset:
        report_assets(asset)
        server_count = 1
        if not as_text(info.get("machineId"), join=",").strip():
            print("unraid: the API returned no machineId, so the server asset is keyed on the " +
                  "configured host and its id will not drive merges")

    print("unraid: reported {} server and {} containers".format(server_count, container_count))
    if not server_count and not container_count:
        print("unraid: no assets retrieved")
    return None

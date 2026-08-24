# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-portainer",
    "name": "Portainer / Docker Engine",
    "type": "inbound",
    "description": "Imports Docker hosts, Swarm nodes, and routable containers from Portainer or a Docker Engine API.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Merge policy is declared per integration, not per asset. The default
    # covers the records whose id is stable and may drive a merge; what must
    # not veto one is a changed MAC, address, or name.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # A 'container' record is identified by an address-derived id, which is
    # reassigned and so must neither drive nor block a merge; correlation
    # falls back to its MAC, address, and hostname.
    "assetTypeBehavior": {
        'container': "no-id-match no-id-break",
    },
    "params": [
        {
            "key": "mode",
            "label": "Connection mode",
            "type": "enum",
            "required": False,
            "default": "portainer",
            "options": ["portainer", "docker"],
            "description": "portainer talks to a Portainer server and covers every environment it manages. docker talks straight to one Docker Engine API socket.",
        },
        {
            "key": "url",
            "label": "Base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://portainer.example.com:9443",
            "description": "Portainer server URL in portainer mode, or the Docker Engine API URL (normally https://dockerhost.example.com:2376) in docker mode.",
        },
        {
            "key": "api_key",
            "label": "Portainer API key",
            "type": "secret",
            "required": False,
            "requiredIf": "mode",
            "requiredIfValue": "portainer",
            "description": "Access token from the Portainer UI, sent as X-API-Key. Use an administrator's token: a restricted token silently filters the container list.",
        },
        {
            "key": "environment_ids",
            "label": "Limit to environment IDs",
            "type": "string",
            "required": False,
            "description": "Optional comma-separated Portainer environment IDs. Leave blank to collect every Docker environment.",
        },
        {
            "key": "import_containers",
            "label": "Import containers as assets",
            "type": "enum",
            "required": False,
            "default": "routable-only",
            "options": ["routable-only", "all", "none"],
            "description": "routable-only emits a container asset only when the container holds an address on the physical network (macvlan/ipvlan). all emits every container, most of which have no routable identity. none imports hosts only.",
        },
        {
            "key": "routable_networks",
            "label": "Additional routable network names",
            "type": "string",
            "required": False,
            "description": "Optional comma-separated Docker network names whose addresses should be treated as routable, for drivers other than macvlan and ipvlan.",
        },
        {
            "key": "import_published_ports",
            "label": "Import published ports as services",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Attach each container's published host port to the Docker host asset as a service, naming the container and image that owns it.",
        },
        {
            "key": "include_stopped_containers",
            "label": "Include stopped containers",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Send all=1 on the container listing. Disable to see only running containers.",
        },
        {
            "key": "max_environments",
            "label": "Maximum environments to collect",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 5000,
        },
        {
            "key": "page_size",
            "label": "Portainer page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# Portainer / Docker Engine -> runZero ImportAsset integration
#
# What this integration decided a container is
# --------------------------------------------
# A container is a process group with a filesystem, not a machine. Its identity,
# its lifetime, and above all its addressing differ from a host's in ways that
# matter to an asset inventory:
#
#   * Its id changes on every recreate. `docker compose up` after an image bump
#     produces a new 64-hex id for the same service.
#   * Its default address is 172.17.0.2 on the default bridge, which is the
#     same address on every Docker host on earth. Importing it would correlate
#     one site's Redis onto another site's Postgres.
#   * Its default MAC is *derived from* that address -- 172.17.0.2 becomes
#     02:42:ac:11:00:02 -- so the MAC is exactly as duplicated as the IP and is
#     no safer to import.
#   * Its published ports listen on the HOST, not on the container. `-p 8080:80`
#     means the host answers on 8080.
#
# So: the Docker host is an asset, always. Swarm nodes are assets, because a
# swarm node is a machine and the API reports its real address. A container
# becomes an asset only when it holds an address on the physical network --
# macvlan and ipvlan attachments, which really are separate devices on the LAN
# and which runZero would otherwise see as unattributed IPs. Everything else a
# container knows is attached to the host that runs it: published ports become
# services on the host, and the image, compose project, and state become
# attributes. `import_containers=all` overrides this for operators who want the
# full container inventory and accept that most of it correlates on name alone.
#
# This mirrors the shipped kubernetes/ integration, which emits Nodes and
# routable LoadBalancer/NodePort Services and deliberately keeps cluster-CIDR
# ClusterIPs off every interface for the same reason.

load("runzero.types", "ImportAsset", "Service", "ServiceProtocolData", "to_custom_attributes")
load("net", "network_interface", "ip_address", "normalize_mac")
load("http", "get_json", "url_parse")
load("kwargs", "get_bool", "get_int", "get_string", "get_list", "get_http_options")
load("runzero.progress", progress_info="info")

load('coerce', 'as_dict', 'as_list')
DEFAULT_MODE = "portainer"
DEFAULT_IMPORT_CONTAINERS = "routable-only"
DEFAULT_IMPORT_PUBLISHED_PORTS = True
DEFAULT_INCLUDE_STOPPED = True
DEFAULT_MAX_ENVIRONMENTS = 200
DEFAULT_PAGE_SIZE = 100

# Portainer EndpointType, 1-based, from api/portainer.go. Only the Docker-family
# values are collected; Azure and the Kubernetes variants describe a different
# object model that the shipped kubernetes/ integration already covers.
DOCKER_ENDPOINT_TYPES = [1, 2, 4]
ENDPOINT_TYPE_NAMES = {
    1: "docker-local",
    2: "docker-agent",
    3: "azure",
    4: "docker-edge-agent",
    5: "kubernetes-local",
    6: "kubernetes-agent",
    7: "kubernetes-edge-agent",
}
ENDPOINT_STATUS_NAMES = {1: "up", 2: "down"}

# Network drivers whose addresses sit on the physical network. A macvlan or
# ipvlan endpoint gets a real address and, for macvlan, a real MAC on the LAN
# segment -- it is a device runZero can scan. Every other driver allocates from
# a per-host or per-cluster private pool that repeats across installations.
ROUTABLE_DRIVERS = ["macvlan", "ipvlan"]

# Compose writes these on every container it creates.
LABEL_COMPOSE_PROJECT = "com.docker.compose.project"
LABEL_COMPOSE_SERVICE = "com.docker.compose.service"
LABEL_COMPOSE_NUMBER = "com.docker.compose.container-number"
LABEL_COMPOSE_ONEOFF = "com.docker.compose.oneoff"
LABEL_COMPOSE_WORKDIR = "com.docker.compose.project.working_dir"

# The platform caps child collections at 99 per asset and rejects the record
# outright past that, so services are bounded before they are attached.
MAX_SERVICES_PER_ASSET = 99

# An address a published port binds to that names no particular interface.
WILDCARD_BIND_ADDRESSES = ["0.0.0.0", "::", "[::]", ""]

# A container name that is not worth importing as a hostname.
PLACEHOLDER_HOSTNAMES = ["localhost", "unknown", "none", "null", "-"]


def _log(msg):
    print("portainer: " + msg)


def _clean(value):
    """Return a value as a trimmed string, or "" for anything unusable."""
    if value == None:
        return ""
    if type(value) == "string":
        return value.strip()
    if type(value) in ("int", "float", "bool"):
        return str(value)
    return ""
def _int(value, fallback):
    """Return value as an int, or fallback. Docker mixes ints and strings."""
    if type(value) == "int":
        return value
    if type(value) == "float":
        return int(value)
    text = _clean(value)
    if not text:
        return fallback
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if not digits:
        return fallback
    for ch in digits.elems():
        if ch not in "0123456789":
            return fallback
    return int(text)


def _routable_ip(value):
    """Return the canonical form of an address worth importing, or "".

    The platform drops loopback, multicast, and unspecified addresses itself but
    deliberately keeps link-local, so APIPA and fe80:: are filtered here. A
    link-local address is invented by a host that could not configure itself and
    correlates every such host to every other one.
    """
    text = _clean(value)
    if not text:
        return ""
    addr = ip_address(text)
    if addr == None:
        return ""
    canonical = str(addr)
    if canonical.startswith("169.254.") or canonical.startswith("127."):
        return ""
    lowered = canonical.lower()
    if lowered.startswith("fe8") or lowered.startswith("fe9") or lowered.startswith("fea") or lowered.startswith("feb"):
        return ""
    if lowered in ("::", "::1", "0.0.0.0"):
        return ""
    return canonical


def _usable_hostname(value):
    text = _clean(value)
    if not text:
        return ""
    if text.lower() in PLACEHOLDER_HOSTNAMES:
        return ""
    if ip_address(text) != None:
        return ""
    return text


def _namespace(base_url):
    """Return the hostname every emitted id is scoped under, plus the parsed URL."""
    parsed = url_parse(base_url)
    if parsed == None:
        return "", None
    if not parsed.scheme or not parsed.hostname:
        return "", None
    return parsed.hostname, parsed


def _host_from_url_string(value):
    """Return a literal IP written into a URL-ish string, or "".

    Portainer records an environment's address as `docker.example.com:2375` or
    `tcp://10.0.0.5:2376`. Only a literal address is used: a name may resolve to
    a proxy, and attaching a proxy's address to a Docker host is worse than
    attaching none.
    """
    text = _clean(value)
    if not text:
        return ""
    for prefix in ["tcp://", "https://", "http://", "unix://", "npipe://"]:
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.split("/")[0]
    # Bracketed IPv6, with or without a port.
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            return _routable_ip(text[1:end])
        return ""
    # A bare IPv6 literal has several colons; a host:port has exactly one.
    if text.count(":") == 1:
        text = text.split(":")[0]
    return _routable_ip(text)


def _api_get(ctx, endpoint_id, path):
    """GET a Docker Engine path, through Portainer's proxy when in portainer mode.

    Portainer routes on the literal `/docker/` segment and strips any
    `/vX.Y` prefix before applying RBAC, so unversioned paths are sent. Docker
    itself negotiates the version when none is given; pinning one either 400s on
    a newer daemon that dropped it or is rejected outright as too new.
    """
    if ctx["mode"] == "portainer":
        url = "{}/api/endpoints/{}/docker{}".format(ctx["base_url"], endpoint_id, path)
    else:
        url = ctx["base_url"] + path
    return get_json(url, **ctx["options"])


def _portainer_endpoints(ctx, max_environments, page_size, wanted_ids):
    """Return the Docker environments Portainer manages.

    /api/endpoints answers with a bare array and reports the filtered total in
    the X-Total-Count header, which get_json does not surface, so the loop
    terminates on a short page instead. `start` is 1-based: the handler
    decrements it, so start=1 and start=0 both mean the first record.
    """
    endpoints = []
    start = 1
    while len(endpoints) < max_environments:
        url = "{}/api/endpoints?start={}&limit={}&excludeSnapshots=true".format(
            ctx["base_url"], start, page_size)
        data, err = get_json(url, **ctx["options"])
        if err:
            if not endpoints:
                return [], err
            _log("stopping environment enumeration at {} ({})".format(len(endpoints), err))
            return endpoints, None
        page = as_list(data)
        if not page:
            break
        for item in page:
            record = as_dict(item)
            endpoint_id = _int(record.get("Id"), -1)
            if endpoint_id < 0:
                _log("skipping environment with no numeric Id")
                continue
            if wanted_ids and str(endpoint_id) not in wanted_ids:
                continue
            kind = _int(record.get("Type"), 0)
            if kind not in DOCKER_ENDPOINT_TYPES:
                _log("skipping environment {} of type {} ({}), which is not a Docker environment".format(
                    endpoint_id, kind, ENDPOINT_TYPE_NAMES.get(kind, "unknown")))
                continue
            endpoints.append(record)
            if len(endpoints) >= max_environments:
                break
        if len(page) < page_size:
            break
        start += page_size
    return endpoints, None


def _network_drivers(ctx, endpoint_id):
    """Return {network name: driver} for one Docker environment."""
    drivers = {}
    data, err = _api_get(ctx, endpoint_id, "/networks")
    if err:
        _log("could not list networks for environment {} ({}); treating every container address as non-routable".format(endpoint_id, err))
        return drivers
    for item in as_list(data):
        record = as_dict(item)
        name = _clean(record.get("Name"))
        if name:
            drivers[name] = _clean(record.get("Driver")).lower()
    return drivers


def _host_addresses(info, endpoint):
    """Return the Docker host's own addresses.

    /info carries no address for a non-swarm daemon, so three sources are tried
    in order of trustworthiness: the swarm advertise address the node published
    about itself, then a literal address Portainer recorded for the environment.
    A hostname is never resolved -- see _host_from_url_string.
    """
    ips = []
    swarm = as_dict(info.get("Swarm"))
    node_addr = _routable_ip(swarm.get("NodeAddr"))
    if node_addr:
        ips.append(node_addr)
    for key in ("URL", "PublicURL"):
        candidate = _host_from_url_string(as_dict(endpoint).get(key))
        if candidate and candidate not in ips:
            ips.append(candidate)
    return ips


def _compose_key(labels):
    """Return a stable per-container key from compose labels, or ""."""
    project = _clean(labels.get(LABEL_COMPOSE_PROJECT))
    service = _clean(labels.get(LABEL_COMPOSE_SERVICE))
    if not project or not service:
        return ""
    number = _clean(labels.get(LABEL_COMPOSE_NUMBER)) or "1"
    return "{}/{}/{}".format(project, service, number)


def _container_health(container):
    """Return the container's health check state, or None when it has none.

    The Docker list API carries no Health field: health is embedded in the
    Status string ("Up 3 weeks (healthy)", "Up 10 seconds (health: starting)").
    An inspect-shaped Health object is still read as a fallback for proxies
    that inline it.
    """
    status = _clean(container.get("Status"))
    if "(healthy)" in status:
        return "healthy"
    if "(unhealthy)" in status:
        return "unhealthy"
    if "(health: starting)" in status:
        return "starting"
    return as_dict(container.get("Health")).get("Status")


def _container_name(container):
    """Return the container's primary name without Docker's leading slash."""
    for raw in as_list(container.get("Names")):
        name = _clean(raw)
        if name.startswith("/"):
            name = name[1:]
        if name:
            return name
    return ""


def _container_services(container, host_ips, name, image):
    """Return Service objects for the container's published host ports.

    A published port listens on the HOST, not inside the container, so these are
    attached to the host asset. A port with no PublicPort is not published at
    all and is invisible from outside the daemon.
    """
    services = []
    ports = as_list(container.get("Ports"))
    for entry in ports:
        record = as_dict(entry)
        public = _int(record.get("PublicPort"), 0)
        if public <= 0 or public > 65535:
            continue
        private = _int(record.get("PrivatePort"), 0)
        transport = _clean(record.get("Type")).lower() or "tcp"

        # A bind address of 0.0.0.0 or :: names no interface. Fall back to the
        # host's own addresses; with neither, the service has no address the
        # platform will accept and is dropped rather than bound to a wildcard.
        bind = _clean(record.get("IP"))
        addresses = []
        if bind and bind not in WILDCARD_BIND_ADDRESSES:
            resolved = _routable_ip(bind)
            if resolved:
                addresses = [resolved]
        if not addresses:
            addresses = host_ips
        if not addresses:
            continue

        attrs = {
            "docker.container": name,
            "docker.image": image,
            "docker.container_port": private,
            "docker.transport": transport,
        }
        for address in addresses:
            services.append(Service(
                address=address,
                port=public,
                transport=transport,
                product=image,
                protocolData=[ServiceProtocolData(name="docker", attributes=to_custom_attributes({
                    "container": name,
                    "image": image,
                    "container_port": private,
                }))],
                customAttributes=to_custom_attributes(attrs),
            ))
    return services


def _container_routable_endpoints(container, drivers, extra_routable):
    """Return (ips, macs, networks) restricted to genuinely routable attachments.

    Bridge and overlay addresses are refused unconditionally. A default bridge
    address is 172.17.0.x on every Docker host in existence, a user-defined
    bridge allocates from the same per-host pool, and an overlay address is
    allocated per swarm cluster from a default pool every cluster shares. The
    MAC is no better: on a bridge Docker derives it from the address, so
    172.17.0.2 is always 02:42:ac:11:00:02.
    """
    ips = []
    macs = []
    networks = []
    settings = as_dict(container.get("NetworkSettings"))
    for net_name, raw in as_dict(settings.get("Networks")).items():
        endpoint = as_dict(raw)
        name = _clean(net_name)
        driver = drivers.get(name, "")
        routable = driver in ROUTABLE_DRIVERS or name in extra_routable
        networks.append("{}={}".format(name, driver or "unknown"))
        if not routable:
            continue
        for key in ("IPAddress", "GlobalIPv6Address"):
            address = _routable_ip(endpoint.get(key))
            if address and address not in ips:
                ips.append(address)
        mac = normalize_mac(_clean(endpoint.get("MacAddress")))
        if mac and mac not in macs:
            macs.append(mac)
    return ips, macs, networks


def _container_asset(ctx, container, drivers, extra_routable, namespace, endpoint_id, daemon_id):
    """Build an ImportAsset for one container, or None when it should not be one."""
    name = _container_name(container)
    labels = as_dict(container.get("Labels"))
    compose_key = _compose_key(labels)
    image = _clean(container.get("Image"))

    key = compose_key or name
    if not key:
        _log("skipping container with no name and no compose labels")
        return None

    ips, macs, networks = _container_routable_endpoints(container, drivers, extra_routable)
    if ctx["import_containers"] == "routable-only" and not ips and not macs:
        return None

    # A compose container's name is project-service-N, which is specific enough
    # to be worth correlating on. A bare `docker run` name may be a generic word
    # or a Docker-invented pair, so it is used only when nothing better exists.
    hostname = _usable_hostname(compose_key and name or name)

    nic = network_interface(mac=macs[0] if macs else None, ips=ips)
    nics = [nic] if nic else []
    if not nics and not hostname:
        _log("skipping container {} with no routable address and no usable name".format(key))
        return None

    state = _clean(container.get("State")).lower()
    health = _container_health(container)
    attrs = {
        "docker.container_id": _clean(container.get("Id")),
        "docker.container_name": name,
        "docker.image": image,
        "docker.image_id": container.get("ImageID"),
        "docker.command": container.get("Command"),
        "docker.created_epoch": container.get("Created"),
        "docker.state": state,
        "docker.status": container.get("Status"),
        "docker.network_mode": as_dict(container.get("HostConfig")).get("NetworkMode"),
        "docker.networks": ", ".join(networks),
        "docker.health": health,
        "docker.compose_project": labels.get(LABEL_COMPOSE_PROJECT),
        "docker.compose_service": labels.get(LABEL_COMPOSE_SERVICE),
        "docker.compose_container_number": labels.get(LABEL_COMPOSE_NUMBER),
        "docker.compose_oneoff": labels.get(LABEL_COMPOSE_ONEOFF),
        "docker.compose_working_dir": labels.get(LABEL_COMPOSE_WORKDIR),
        "docker.host_daemon_id": daemon_id,
        "docker.portainer_endpoint_id": endpoint_id,
        "docker.labels": labels,
    }

    tags = ["docker", "docker-container"]
    if state:
        tags.append("docker-" + state)
    if ips or macs:
        tags.append("docker-routable")

    return ImportAsset(
        id="docker:{}:{}:container:{}".format(namespace, daemon_id, key),
        hostnames=[hostname],
        networkInterfaces=nics,
        deviceType="Container",
        tags=tags,
        # Docker issues no durable container identity: the 64-hex Id is minted
        # fresh on every recreate. The id above is this script's own composite of
        # the compose project, service, and replica number (or the container
        # name), which is deterministic across recreates but is not a vendor id,
        # so it must not drive or block a merge.
        assetType="container",
        customAttributes=to_custom_attributes(attrs, list_join="json"),
    )


def _collect_environment(ctx, endpoint, namespace, extra_routable):
    """Collect one Docker environment and return the assets it produced."""
    endpoint_id = _int(as_dict(endpoint).get("Id"), 0)
    endpoint_name = _clean(as_dict(endpoint).get("Name"))

    info, err = _api_get(ctx, endpoint_id, "/info")
    if err:
        _log("skipping environment {} ({}): {}".format(endpoint_id, endpoint_name or "unnamed", err))
        return []
    info = as_dict(info)

    daemon_id = _clean(info.get("ID"))
    if not daemon_id:
        _log("skipping environment {}: /info returned no daemon ID".format(endpoint_id))
        return []

    # One asset per DAEMON, not per environment. A host registered twice --
    # once as a local socket entry and again through the Portainer agent, or
    # simply adopted twice -- appears as two environments whose /info returns
    # the same daemon ID. Every id minted below is scoped on that daemon ID, so
    # collecting both produced two assets carrying identical foreign ids for
    # the host and for every container on it.
    #
    # Folding the environment id into the identity would fix the collision and
    # replace it with something worse: two permanent assets for one machine,
    # which can never merge, because two foreign ids from one integration never
    # match each other. Two environments reading one Docker socket are two
    # paths to one machine, so the second is skipped whole and said out loud.
    first_endpoint = ctx["seen_daemons"].get(daemon_id)
    if first_endpoint != None:
        _log("environment {} ({}) reports daemon {}, already collected from environment {}; two environments fronting one Docker daemon describe one machine".format(
            endpoint_id, endpoint_name or "unnamed", daemon_id, first_endpoint))
        return []
    ctx["seen_daemons"][daemon_id] = endpoint_id

    host_ips = _host_addresses(info, endpoint)
    host_name = _usable_hostname(info.get("Name"))
    if not host_ips and not host_name:
        _log("skipping environment {}: daemon {} has no address and no usable hostname".format(endpoint_id, daemon_id))
        return []

    drivers = {}
    containers = []
    if ctx["import_containers"] != "none" or ctx["import_published_ports"]:
        path = "/containers/json?all=1" if ctx["include_stopped"] else "/containers/json"
        raw, err = _api_get(ctx, endpoint_id, path)
        if err:
            _log("no container list for environment {}: {}".format(endpoint_id, err))
        else:
            containers = as_list(raw)
        if ctx["import_containers"] != "none" and containers:
            drivers = _network_drivers(ctx, endpoint_id)

    assets = []
    services = []
    images = []
    compose_projects = []
    running = 0

    for raw in containers:
        container = as_dict(raw)
        if not container:
            continue
        name = _container_name(container)
        image = _clean(container.get("Image"))
        if _clean(container.get("State")).lower() == "running":
            running += 1
        if image and image not in images:
            images.append(image)
        project = _clean(as_dict(container.get("Labels")).get(LABEL_COMPOSE_PROJECT))
        if project and project not in compose_projects:
            compose_projects.append(project)

        if ctx["import_published_ports"] and len(services) < MAX_SERVICES_PER_ASSET:
            for service in _container_services(container, host_ips, name, image):
                if len(services) >= MAX_SERVICES_PER_ASSET:
                    break
                services.append(service)

        if ctx["import_containers"] != "none":
            asset = _container_asset(ctx, container, drivers, extra_routable, namespace, endpoint_id, daemon_id)
            if asset != None:
                assets.append(asset)

    swarm = as_dict(info.get("Swarm"))
    swarm_state = _clean(swarm.get("LocalNodeState")).lower()

    host_attrs = {
        "docker.daemon_id": daemon_id,
        "docker.daemon_name": _clean(info.get("Name")),
        "docker.server_version": info.get("ServerVersion"),
        "docker.api_kernel_version": info.get("KernelVersion"),
        "docker.os_type": info.get("OSType"),
        "docker.os_version": info.get("OSVersion"),
        "docker.architecture": info.get("Architecture"),
        "docker.ncpu": info.get("NCPU"),
        "docker.mem_total": info.get("MemTotal"),
        "docker.storage_driver": info.get("Driver"),
        "docker.docker_root_dir": info.get("DockerRootDir"),
        "docker.cgroup_version": info.get("CgroupVersion"),
        "docker.default_runtime": info.get("DefaultRuntime"),
        "docker.live_restore": info.get("LiveRestoreEnabled"),
        "docker.security_options": info.get("SecurityOptions"),
        "docker.containers_total": info.get("Containers"),
        "docker.containers_running": info.get("ContainersRunning"),
        "docker.containers_paused": info.get("ContainersPaused"),
        "docker.containers_stopped": info.get("ContainersStopped"),
        "docker.images": info.get("Images"),
        "docker.swarm_state": swarm_state,
        "docker.swarm_node_id": swarm.get("NodeID"),
        "docker.swarm_managers": swarm.get("Managers"),
        "docker.swarm_nodes": swarm.get("Nodes"),
        "docker.container_images": images,
        "docker.compose_projects": compose_projects,
        "docker.containers_seen": len(containers),
        "docker.containers_running_seen": running,
        # /info reports Labels as an array of "k=v" strings, unlike a container's
        # Labels which is a map. Kept as written rather than split, so an
        # unusual value is never silently mangled.
        "docker.host_labels": info.get("Labels"),
    }
    if ctx["mode"] == "portainer":
        endpoint_record = as_dict(endpoint)
        host_attrs["portainer.endpoint_id"] = endpoint_id
        host_attrs["portainer.endpoint_name"] = endpoint_name
        host_attrs["portainer.endpoint_type"] = ENDPOINT_TYPE_NAMES.get(
            _int(endpoint_record.get("Type"), 0), "unknown")
        host_attrs["portainer.endpoint_status"] = ENDPOINT_STATUS_NAMES.get(
            _int(endpoint_record.get("Status"), 0), "unknown")
        host_attrs["portainer.endpoint_url"] = endpoint_record.get("URL")
        host_attrs["portainer.endpoint_public_url"] = endpoint_record.get("PublicURL")
        host_attrs["portainer.container_engine"] = endpoint_record.get("ContainerEngine")
        host_attrs["portainer.group_id"] = endpoint_record.get("GroupId")
        host_attrs["portainer.tag_ids"] = endpoint_record.get("TagIds")

    nic = network_interface(ips=host_ips)
    host_tags = ["docker", "docker-host"]
    if swarm_state == "active":
        host_tags.append("docker-swarm")

    assets.append(ImportAsset(
        id="docker:{}:host:{}".format(namespace, daemon_id),
        hostnames=[host_name],
        networkInterfaces=[nic] if nic else [],
        os=_clean(info.get("OperatingSystem")),
        osVersion=_clean(info.get("OSVersion")),
        deviceType="Server",
        tags=host_tags,
        services=services,
        # The daemon ID is minted once and persisted by the engine, so it is a
        # stable vendor id and drives merges. Docker supplies at most one
        # address for the host, so a differing MAC, IP, or name must not
        # disqualify a merge with the machine runZero already scans. That is the
        # integration-wide policy in CONFIG, which this type inherits.
        assetType="host",
        customAttributes=to_custom_attributes(host_attrs, list_join="json"),
    ))
    if len(services) >= MAX_SERVICES_PER_ASSET:
        _log("environment {} published more than {} ports; the list was truncated".format(
            endpoint_id, MAX_SERVICES_PER_ASSET))

    if swarm_state == "active":
        assets.extend(_swarm_nodes(ctx, endpoint_id, namespace, daemon_id))

    return assets


def _swarm_nodes(ctx, endpoint_id, namespace, daemon_id):
    """Return one asset per Swarm node.

    A swarm node is a machine, and unlike a plain daemon the API reports its
    real address in Status.Addr. This is the one place Docker hands out routable
    addresses for hosts other than the one being queried.
    """
    assets = []
    data, err = _api_get(ctx, endpoint_id, "/nodes")
    if err:
        _log("no swarm node list for environment {} ({})".format(endpoint_id, err))
        return assets
    for raw in as_list(data):
        node = as_dict(raw)
        node_id = _clean(node.get("ID"))
        if not node_id:
            _log("skipping swarm node with no ID")
            continue
        description = as_dict(node.get("Description"))
        status = as_dict(node.get("Status"))
        spec = as_dict(node.get("Spec"))
        platform = as_dict(description.get("Platform"))
        engine = as_dict(description.get("Engine"))

        hostname = _usable_hostname(description.get("Hostname"))
        address = _routable_ip(status.get("Addr"))
        if not hostname and not address:
            _log("skipping swarm node {} with no hostname and no address".format(node_id))
            continue

        nic = network_interface(ips=[address] if address else [])
        manager = as_dict(node.get("ManagerStatus"))
        attrs = {
            "docker.swarm_node_id": node_id,
            "docker.swarm_role": spec.get("Role"),
            "docker.swarm_availability": spec.get("Availability"),
            "docker.swarm_state": status.get("State"),
            "docker.swarm_message": status.get("Message"),
            "docker.swarm_leader": manager.get("Leader"),
            "docker.swarm_reachability": manager.get("Reachability"),
            "docker.swarm_manager_addr": manager.get("Addr"),
            "docker.architecture": platform.get("Architecture"),
            "docker.os_type": platform.get("OS"),
            "docker.server_version": engine.get("EngineVersion"),
            "docker.engine_labels": engine.get("Labels"),
            "docker.node_labels": spec.get("Labels"),
            "docker.reported_by_daemon": daemon_id,
            "docker.portainer_endpoint_id": endpoint_id,
        }
        assets.append(ImportAsset(
            id="docker:{}:swarm-node:{}".format(namespace, node_id),
            hostnames=[hostname],
            networkInterfaces=[nic] if nic else [],
            os=_clean(platform.get("OS")),
            deviceType="Server",
            tags=["docker", "docker-swarm-node"],
            assetType="swarm-node",
            customAttributes=to_custom_attributes(attrs, list_join="json"),
        ))
    return assets


def main(*args, **kwargs):
    base_url = _clean(kwargs.get("url"))
    if not base_url:
        _log("url is required")
        return None
    base_url = base_url.rstrip("/")

    # url_parse before any fetch: the raw http verbs raise on a transport error
    # rather than returning nil, so a URL with no scheme aborts the run.
    namespace, parsed = _namespace(base_url)
    if not namespace:
        _log("url must be an absolute URL with a scheme and a host, for example https://portainer.example.com:9443")
        return None

    mode = get_string(kwargs, "mode", DEFAULT_MODE)
    api_key = _clean(kwargs.get("api_key"))
    if mode == "portainer" and not api_key:
        _log("api_key is required in portainer mode; create an access token under My account -> Access tokens")
        return None

    ctx = {
        "mode": mode,
        "base_url": base_url,
        "import_containers": get_string(kwargs, "import_containers", DEFAULT_IMPORT_CONTAINERS),
        "import_published_ports": get_bool(kwargs, "import_published_ports", DEFAULT_IMPORT_PUBLISHED_PORTS),
        "include_stopped": get_bool(kwargs, "include_stopped_containers", DEFAULT_INCLUDE_STOPPED),
        # daemon ID -> the environment id that first reported it. Two Portainer
        # environments can front one Docker socket; see _collect_environment.
        "seen_daemons": {},
        "options": {},
    }

    headers = {"Accept": "application/json"}
    if mode == "portainer":
        # Portainer rejects a request carrying both an API key and an
        # Authorization header, so only the key is ever sent.
        headers["X-API-Key"] = api_key
    ctx["options"] = get_http_options(kwargs, "http_", "tls_", headers)

    max_environments = get_int(kwargs, "max_environments", DEFAULT_MAX_ENVIRONMENTS)
    page_size = get_int(kwargs, "page_size", DEFAULT_PAGE_SIZE)
    wanted_ids = []
    for value in get_list(kwargs, "environment_ids", []):
        text = _clean(value)
        if text:
            wanted_ids.append(text)
    extra_routable = []
    for value in get_list(kwargs, "routable_networks", []):
        text = _clean(value)
        if text:
            extra_routable.append(text)

    if mode == "portainer":
        endpoints, err = _portainer_endpoints(ctx, max_environments, page_size, wanted_ids)
        if err:
            _log("could not list Portainer environments: " + err)
            return None
        if not endpoints:
            _log("no Docker environments matched; nothing to import")
            return None
        _log("collecting {} Docker environment(s)".format(len(endpoints)))
    else:
        # Direct mode has exactly one environment: the daemon at `url`. Its
        # address is the one the task was pointed at, and only when written as a
        # literal IP.
        endpoints = [{"Id": 0, "Name": "docker-engine", "URL": base_url}]
        _log("collecting a single Docker Engine at {}".format(namespace))

    total = 0
    for index in range(len(endpoints)):
        endpoint = endpoints[index]
        assets = _collect_environment(ctx, endpoint, namespace, extra_routable)
        if assets:
            # Reported per environment so memory stays bounded by one host's
            # container list rather than by the whole Portainer estate.
            total += report_assets(assets)
        progress_info("portainer: {}/{} environment(s), {} asset(s)".format(
            index + 1, len(endpoints), total))

    _log("reported {} assets from {} environment(s)".format(total, len(endpoints)))
    return None

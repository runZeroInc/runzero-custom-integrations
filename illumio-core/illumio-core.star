# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-illumio-core",
    "name": "Illumio Core",
    "type": "inbound",
    "description": "Imports workloads, their listening services, and segmentation labels from an Illumio Core PCE.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The workload href is authoritative and strictly one row per workload,
    # so it alone should drive merges. Illumio publishes no MAC at all, and
    # its addresses and hostnames are the workload's own view of itself:
    # a cloud workload reports its private interface address while runZero
    # may only ever have scanned it at a load balancer or elastic address,
    # and an autoscaled host's name churns on every replacement. Leaving the
    # breaks on would disqualify exactly those legitimate first-contact
    # merges and fragment the estate. mac-break is included for symmetry
    # with the rest of the library; with no MACs in the source it can never
    # fire either way.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "PCE URL",
            "type": "url",
            "required": True,
            "placeholder": "https://pce.example.com:8443",
            "description": "Base URL of the Policy Compute Engine, including the API port. The /api/v2/ path is appended automatically.",
        },
        {
            "key": "org_id",
            "label": "Organization ID",
            "type": "string",
            "required": True,
            "default": "1",
            "pattern": "[0-9]+",
            "description": "Numeric PCE organization ID. Single-tenant on-premises PCEs are almost always 1; the value is shown in the console URL after /orgs/.",
        },
        {
            "key": "api_key_id",
            "label": "API key username",
            "type": "string",
            "required": True,
            "placeholder": "api_1a2b3c4d5e6f7890",
            "description": "The Authentication Username issued with the API key, used as the HTTP Basic username.",
        },
        {
            "key": "api_secret",
            "label": "API key secret",
            "type": "secret",
            "required": True,
            "description": "The API key secret issued alongside the username, used as the HTTP Basic password.",
        },
        {
            "key": "import_services",
            "label": "Import listening services",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Fetch each workload individually to collect its open service ports. The PCE omits services from collection responses, so this costs one extra request per workload.",
        },
        {
            "key": "service_detail_limit",
            "label": "Service enrichment limit",
            "type": "int",
            "required": False,
            "default": 1000,
            "min": 0,
            "description": "Maximum number of workloads to fetch individually for services. Workloads past the limit are still imported, without services. 0 removes the cap.",
        },
        {
            "key": "managed_only",
            "label": "Only import managed workloads",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Restrict the import to workloads that report through a VEN. Unmanaged workloads are records an administrator created by hand.",
        },
        {
            "key": "async_timeout_seconds",
            "label": "Asynchronous collection timeout (seconds)",
            "type": "int",
            "required": False,
            "default": 600,
            "min": 30,
            "max": 3600,
            "description": "How long to wait for the PCE to finish an asynchronous GET collection job when the estate exceeds the synchronous 500-workload cap.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Service', 'to_custom_attributes')
load('net', 'ip_address', 'network_interface', 'routable_ip')
load('http', http_get='get', 'get_json', 'basic', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int', 'get_bool')
load('time', 'sleep', 'parse_ts')
load('re', re_search='search')
load('jsonstream', 'iter_array')

load('coerce', 'as_dict', 'as_text', 'dedupe', 'dicts')
VENDOR = "illumio-core"
ATTR_PREFIX = "illumio_core"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator
API_BASE = "/api/v2"

# The PCE caps a synchronous GET collection at 500 objects and documents the
# asynchronous GET collection as the only supported way past it.
SYNC_LIMIT = 500
LABEL_LIMIT = 500
MAX_CHILDREN = 99
MAX_POLLS = 600
DEFAULT_RETRY_AFTER = 5
MAX_RETRY_AFTER = 30
DIGITS = "0123456789"
# jsonstream.iter_array raises on a body that is not a JSON array, and a raise
# aborts the whole script, so every streamed body is sniffed for an opening
# bracket first.
ARRAY_RE = r"^\s*\["
# open_service_ports[].protocol is an IANA protocol number, not a name. Only the
# port-bearing transports runZero models are mapped; ICMP (1) and IPv6-ICMP (58)
# carry no port and are counted rather than invented into a Service.
PROTOCOL_NAMES = {6: "tcp", 17: "udp", 132: "sctp"}

# Illumio os_id looks like "ubuntu-x86_64-xenial" or "windows-x86_64-server2016".
# The leading token is the platform; anything not listed here is left unmapped
# and survives verbatim in the illumio_core_os_id attribute.
OS_PLATFORMS = {
    "windows": "Windows",
    "ubuntu": "Ubuntu Linux",
    "debian": "Debian Linux",
    "centos": "CentOS Linux",
    "rhel": "Red Hat Enterprise Linux",
    "redhat": "Red Hat Enterprise Linux",
    "oracle": "Oracle Linux",
    "amazon": "Amazon Linux",
    "amzn": "Amazon Linux",
    "suse": "SUSE Linux",
    "sles": "SUSE Linux Enterprise Server",
    "fedora": "Fedora Linux",
    "alpine": "Alpine Linux",
    "aix": "AIX",
    "solaris": "Solaris",
}

# Interface names whose addresses are container, hypervisor, or overlay bridge
# endpoints rather than the workload's own network identity. The default Docker
# bridge hands 172.17.0.1 to every Docker host on earth, so importing these
# would give thousands of unrelated workloads a shared address to merge on.
# Illumio's own guidance is to add exactly these names to a workload's
# ignored_interface_names, which is honored separately below.
VIRTUAL_INTERFACE_PREFIXES = [
    "docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "tunl",
    "vxlan", "weave", "antrea-", "kube-ipvs", "cbr", "nodelocaldns", "utun",
    "lo",
]

def _log(msg):
    """Emit one prefixed log line."""
    print("{}: {}".format(VENDOR, msg))


def _fail(msg):
    """End the task in error, prefixed the same way as _log.

    Used where the run cannot do its job at all -- a credential the PCE
    rejected, or an inventory that could not be read. Returning no assets
    there is indistinguishable from an empty PCE.
    """
    fail("{}: {}".format(VENDOR, msg))
def _to_int(value):
    """Convert an int or an all-digit string to an int, or -1 when it is not numeric."""
    if type(value) == "int":
        return value
    text = as_text(value, join=",").strip()
    if not text or len(text) > 10:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)
def _is_virtual_interface(name):
    """Report whether an interface name belongs to a container, hypervisor, or
    overlay bridge whose address is shared across unrelated hosts."""
    text = as_text(name, join=",").strip().lower()
    if not text:
        return False
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if text.startswith(prefix):
            return True
    return False

def _header(response, name):
    """Read one response header value. The header map is keyed by the Go
    canonical name and every value is a list, so the lookup is done on both
    casings and the first element is returned."""
    headers = response.headers
    if type(headers) != "dict":
        return ""
    for key in (name, name.lower(), name.upper()):
        value = headers.get(key)
        if value == None:
            continue
        if type(value) == "list":
            return as_text(value[0], join=",").strip() if value else ""
        return as_text(value, join=",").strip()
    return ""

def _api_url(ctx, href):
    """Resolve an href returned by the PCE into an absolute API URL. The PCE
    returns org-scoped hrefs such as /orgs/1/jobs/<uuid> which are relative to
    the /api/v2 root, but a proxy may rewrite Location into an absolute URL."""
    text = as_text(href, join=",").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if not text.startswith("/"):
        text = "/" + text
    if text.startswith(API_BASE + "/"):
        return ctx["base_url"] + text
    return ctx["base_url"] + API_BASE + text

def _index_label(index, label):
    """Add one label record to the href index."""
    record = as_dict(label)
    href = as_text(record.get("href"), join=",").strip()
    key = as_text(record.get("key"), join=",").strip()
    value = as_text(record.get("value"), join=",").strip()
    if href and key:
        index[href] = "{}:{}".format(key, value) if value else key

def build_label_index(ctx):
    """Index the organization's labels by href so a workload that only carries
    label references can still be tagged. A collection GET may return labels
    either expanded (href, key, value) or as bare references depending on the
    PCE release, and requesting an expanded representation is not portable
    across releases, so the catalog is fetched once instead. A catalog that
    hits the synchronous 500-object cap is re-fetched as an asynchronous GET
    collection, the same escape hatch the workload collection uses."""
    index = {}
    url = ctx["org_url"] + "/labels"
    data, err = get_json(url, params={"max_results": str(LABEL_LIMIT)}, **ctx["http_options"])
    if err:
        _log("failed to fetch the label catalog, workloads will carry label references only: " + err)
        return index
    labels = data if type(data) == "list" else []
    for label in dicts(labels):
        _index_label(index, label)
    if len(labels) < LABEL_LIMIT:
        return index

    _log("the label catalog returned the {} object collection cap; re-running it as an asynchronous GET collection".format(LABEL_LIMIT))
    location, retry_after, err = start_async_job(ctx, "/labels", {})
    href = ""
    if not err:
        href, err = poll_async_job(ctx, location, retry_after)
    if err:
        _log("the asynchronous label collection failed ({}); some workload labels may import as references".format(err))
        return index
    response = http_get(_api_url(ctx, href), **ctx["http_options"])
    if response == None or response.status_code != 200:
        _log("failed to download the label collection result; some workload labels may import as references")
        return index
    if not re_search(ARRAY_RE, as_text(response.body, join=",")[:64]):
        _log("the label collection result was not a JSON array; some workload labels may import as references")
        return index
    total = 0
    for label in iter_array(response.body):
        _index_label(index, label)
        total += 1
    _log("asynchronous label collection returned {} labels".format(total))
    return index

def build_label_tags(ctx, labels):
    """Convert a workload's labels into runZero key:value tags, resolving bare
    href references through the label catalog."""
    tags = []
    for label in dicts(labels):
        key = as_text(label.get("key"), join=",").strip()
        value = as_text(label.get("value"), join=",").strip()
        if key:
            tags.append("{}:{}".format(key, value) if value else key)
            continue
        resolved = ctx["labels"].get(as_text(label.get("href"), join=",").strip())
        if resolved:
            tags.append(resolved)
    return dedupe(tags)

def build_interfaces(record):
    """Split the workload interfaces into (ips, raw, skipped). The PCE reports
    the addresses the VEN read from the host's own interface table, so unlike a
    NAT egress address they genuinely belong to this machine and are safe to
    import. Loopback, link-local, and container or overlay bridge addresses are
    dropped: those are shared across unrelated hosts and would invite merges.
    The unfiltered list is preserved as a custom attribute either way."""
    ips = []
    raw = []
    skipped = []
    ignored = [as_text(name, join=",").strip().lower() for name in (record.get("ignored_interface_names") or []) if as_text(name, join=",").strip()]
    for entry in dicts(record.get("interfaces")):
        address = as_text(entry.get("address"), join=",").strip()
        name = as_text(entry.get("name"), join=",").strip()
        if address:
            raw.append("{}={}".format(name, address) if name else address)
        routable = routable_ip(address)
        if not routable:
            continue
        # Illumio marks a loopback interface explicitly; honor it before any
        # name heuristic, and honor the workload's own ignore list next.
        if entry.get("loopback") == True:
            skipped.append(routable)
            continue
        if name and name.lower() in ignored:
            skipped.append(routable)
            continue
        if _is_virtual_interface(name):
            skipped.append(routable)
            continue
        ips.append(routable)
    return dedupe(ips), dedupe(raw), dedupe(skipped)

def build_services(record, address):
    """Build Service objects from services.open_service_ports. These are the
    workload's own listening sockets as observed by the VEN, not remote peers,
    so they map onto runZero services directly. protocol is an IANA protocol
    number rather than a name and is converted; entries on a protocol with no
    port concept are counted instead of guessed at. A wildcard bind address is
    replaced with the workload's primary address, because a Service pinned to
    0.0.0.0 would be meaningless and 0.0.0.0 is never imported as an IP."""
    ports = dicts(as_dict(record.get("services")).get("open_service_ports"))
    if not ports:
        return [], 0

    services = []
    seen = []
    unmapped = 0
    for entry in ports:
        port = _to_int(entry.get("port"))
        if port < 1 or port > 65535:
            unmapped += 1
            continue
        transport = PROTOCOL_NAMES.get(_to_int(entry.get("protocol")), "")
        if not transport:
            unmapped += 1
            continue

        bind = routable_ip(entry.get("address")) or address
        if not bind:
            unmapped += 1
            continue

        key = "{}/{}/{}".format(bind, port, transport)
        if key in seen:
            continue
        seen.append(key)

        params = {
            "address": bind,
            "port": int(port),
            "transport": transport,
            "customAttributes": to_custom_attributes({
                "bind_address": entry.get("address"),
                "process_name": entry.get("process_name"),
                "package": entry.get("package"),
                "user": entry.get("user"),
                "win_service_name": entry.get("win_service_name"),
            }, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
        }
        # process_name is the listening binary on Linux; Windows reports the
        # service unit instead. Neither carries a version, so version is left
        # unset rather than parsed out of the package string.
        product = as_text(entry.get("process_name"), join=",").strip() or as_text(entry.get("win_service_name"), join=",").strip()
        if product:
            params["product"] = product
        services.append(Service(**params))

    return services, unmapped

def fetch_workload_detail(ctx, href):
    """Fetch one workload individually. A collection response never carries
    services, because a PCE with thousands of workloads each running dozens of
    services would not survive expanding them, so the per-workload GET is the
    only place open_service_ports exists. A failure is logged and treated as an
    empty document so one unreadable workload cannot end the run."""
    data, err = get_json(_api_url(ctx, href), **ctx["http_options"])
    if err:
        _log("failed to fetch workload {}: {}".format(href, err))
        ctx["detail_failed"] += 1
        return {}
    return as_dict(data)

def build_asset(ctx, record):
    """Convert one Illumio workload into a runZero asset, optionally enriched
    with the listening services from a per-workload GET."""
    href = as_text(record.get("href"), join=",").strip()

    detail = record
    enriched = False
    if ctx["import_services"]:
        if ctx["detail_limit"] and ctx["detail_used"] >= ctx["detail_limit"]:
            ctx["detail_skipped"] += 1
        else:
            ctx["detail_used"] += 1
            fetched = fetch_workload_detail(ctx, href)
            if fetched:
                enriched = True
                detail = dict(record)
                detail.update(fetched)

    ips, raw_interfaces, skipped_ips = build_interfaces(detail)
    nic = network_interface(ips=ips)
    netifs = [nic] if nic else []
    address = ips[0] if ips else ""

    hostname = as_text(detail.get("hostname"), join=",").strip()
    hostnames = [hostname]
    name = as_text(detail.get("name"), join=",").strip()
    # An unmanaged workload's name is whatever an operator typed, so it is only
    # treated as a hostname when it actually looks like one.
    if name and name != hostname and " " not in name and ip_address(name) == None:
        hostnames.append(name)

    labels = build_label_tags(ctx, detail.get("labels"))
    services, unmapped_ports = build_services(detail, address)

    agent = as_dict(detail.get("agent"))
    agent_status = as_dict(agent.get("status"))
    vuln_summary = as_dict(detail.get("vulnerabilities_summary"))
    online = detail.get("online")
    managed = detail.get("managed")
    if managed == None:
        # The PCE omits managed on some releases; a VEN or agent reference is
        # the same statement by other means.
        managed = True if (as_dict(detail.get("ven")) or agent) else False
    enforcement = as_text(detail.get("enforcement_mode"), join=",").strip()

    tags = [VENDOR]
    tags.append("managed" if managed else "unmanaged")
    if online == True:
        tags.append("online")
    elif online == False:
        tags.append("offline")
    if enforcement:
        tags.append("enforcement:" + enforcement)
    visibility = as_text(detail.get("visibility_level"), join=",").strip()
    if visibility:
        tags.append("visibility:" + visibility)
    for label in labels:
        tags.append(label)

    attrs = {
        "href": href,
        "pce": ctx["scope"],
        "org_id": ctx["org_id"],
        "name": detail.get("name"),
        "description": detail.get("description"),
        "online": online,
        "managed": managed,
        "enforcement_mode": enforcement,
        "visibility_level": visibility,
        "data_center": detail.get("data_center"),
        "data_center_zone": detail.get("data_center_zone"),
        "service_provider": detail.get("service_provider"),
        "distinguished_name": detail.get("distinguished_name"),
        "labels": labels,
        "os_id": detail.get("os_id"),
        "os_detail": detail.get("os_detail"),
        # public_ip is the NAT egress address the PCE observed, shared by every
        # workload behind one gateway, so it is recorded but never imported as
        # an interface address.
        "public_ip": detail.get("public_ip"),
        "interfaces": raw_interfaces,
        "interfaces_excluded": skipped_ips,
        "ignored_interface_names": detail.get("ignored_interface_names"),
        "created_at": detail.get("created_at"),
        "updated_at": detail.get("updated_at"),
        "deleted": detail.get("deleted"),
        "ven_href": as_dict(detail.get("ven")).get("href"),
        "agent_href": agent.get("href"),
        "agent_type": agent.get("type"),
        "agent_status": agent_status.get("status"),
        "agent_version": agent_status.get("agent_version"),
        "agent_last_heartbeat_on": agent_status.get("last_heartbeat_on"),
        "agent_managed_since": agent_status.get("managed_since"),
        "security_policy_sync_state": agent_status.get("security_policy_sync_state"),
        "uptime_seconds": as_dict(detail.get("services")).get("uptime_seconds"),
        "services_enriched": "true" if enriched else "false",
        "service_count": len(services),
        # The PCE publishes only a vulnerability count and exposure scores for a
        # workload, never the individual findings, so no Vulnerability object is
        # synthesized from them. The scores are carried verbatim instead.
        "num_vulnerabilities": vuln_summary.get("num_vulnerabilities"),
        "vulnerability_score": vuln_summary.get("vulnerability_score"),
        "vulnerability_exposure_score": vuln_summary.get("vulnerability_exposure_score"),
        "vulnerable_port_exposure": vuln_summary.get("vulnerable_port_exposure"),
    }
    if unmapped_ports:
        attrs["service_ports_unmapped"] = unmapped_ports

    container_cluster = as_dict(detail.get("container_cluster"))
    if container_cluster:
        attrs["container_cluster_href"] = container_cluster.get("href")
        attrs["container_cluster_name"] = container_cluster.get("name")

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], href),
        "hostnames": dedupe(hostnames),
        "networkInterfaces": netifs,
        "tags": dedupe(tags),
        "services": services[:MAX_CHILDREN],    }

    os_id = as_text(detail.get("os_id"), join=",").strip()
    if os_id:
        tokens = os_id.split("-")
        platform = OS_PLATFORMS.get(tokens[0].lower(), "")
        if platform:
            params["os"] = platform
        if len(tokens) > 2:
            # The third token is the release for RPM-family platforms ("7.9")
            # and a codename for others ("xenial"), so only a numeric value is
            # promoted to osVersion. The full os_id survives as an attribute.
            release = tokens[2]
            if release and release[0] in DIGITS:
                params["osVersion"] = release
        attrs["os_arch"] = tokens[1] if len(tokens) > 1 else ""

    first_ts = parse_ts(detail.get("created_at"))
    if first_ts:
        params["firstSeenTS"] = first_ts
    last_ts = parse_ts(agent_status.get("last_heartbeat_on")) or parse_ts(detail.get("updated_at"))

    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)
    if last_ts != None:
        asset.lastSeenTS = last_ts
    return asset

def report_one(ctx, record):
    """Validate and report one workload record, returning the count reported.
    A malformed, href-less, or deleted record is counted and skipped so one bad
    row cannot end the run."""
    if type(record) != "dict":
        ctx["malformed"] += 1
        return 0
    href = as_text(record.get("href"), join=",").strip()
    if not href:
        _log("skipping workload with no href: hostname=" + as_text(record.get("hostname"), join=","))
        ctx["skipped"] += 1
        return 0
    if record.get("deleted") == True:
        ctx["deleted"] += 1
        return 0
    return report_asset(build_asset(ctx, record))

def report_workloads(ctx, records):
    """Report a workload collection to runZero one record at a time, so only
    one ImportAsset object exists at a time."""
    reported = 0
    for record in records:
        reported += report_one(ctx, record)
    return reported

def fetch_sync(ctx):
    """Fetch a workload collection with an ordinary synchronous GET."""
    params = {"max_results": str(SYNC_LIMIT)}
    if ctx["managed_only"]:
        params["managed"] = "true"
    data, err = get_json(ctx["org_url"] + "/workloads", params=params, **ctx["http_options"])
    if err:
        return [], err
    return (data if type(data) == "list" else []), None

def start_async_job(ctx, path, params):
    """Ask the PCE to run one collection as an offline job and return the job
    href it publishes in the Location response header. This request has to use
    the raw HTTP builtin, because get_json does not expose response headers and
    Location is the only handle on the job. Raw requests take no retry budget,
    so this single call gets one attempt; it is issued only after a synchronous
    collection has already succeeded, so the PCE is known to be reachable at
    that point.

    max_results is deliberately omitted from params: it is what caps a
    collection, and the whole point of the offline job is to return the set
    uncapped."""
    response = http_get(ctx["org_url"] + path, params=params, **ctx["async_options"])
    if response == None:
        return "", 0, "no response to the asynchronous collection request"
    if response.status_code >= 400:
        return "", 0, "status {}".format(response.status_code)

    location = _header(response, "Location")
    if not location:
        return "", 0, "the PCE returned no Location header, so the job cannot be polled"
    retry_after = _to_int(_header(response, "Retry-After"))
    if retry_after < 1 or retry_after > MAX_RETRY_AFTER:
        retry_after = DEFAULT_RETRY_AFTER
    return location, retry_after, None

def poll_async_job(ctx, location, retry_after):
    """Poll an asynchronous collection job until it reports done or failed, and
    return the href of the result data file. The PCE spells success as done for
    policy objects and completed for traffic queries, and publishes the result
    either as an object carrying an href or as a bare href string."""
    waited = 0
    delay = retry_after
    for _poll in range(MAX_POLLS):
        sleep("{}s".format(delay))
        waited += delay
        data, err = get_json(_api_url(ctx, location), **ctx["http_options"])
        if err:
            return "", "failed to poll the collection job: " + err
        job = as_dict(data)
        status = as_text(job.get("status"), join=",").strip().lower()
        if status == "failed":
            return "", "the PCE reported the collection job as failed"
        if status in ("done", "completed"):
            result = job.get("result")
            href = as_text(result.get("href"), join=",").strip() if type(result) == "dict" else as_text(result, join=",").strip()
            if not href:
                return "", "the collection job finished without publishing a result href"
            return href, None
        if waited >= ctx["async_timeout"]:
            return "", "the collection job did not finish within {} seconds (last status {})".format(ctx["async_timeout"], status or "unknown")
        # Back off gently, the way Illumio's own client does, but never past the
        # documented maximum polling interval.
        delay = delay + 1 if delay < MAX_RETRY_AFTER else MAX_RETRY_AFTER
    return "", "the collection job did not finish within {} polls".format(MAX_POLLS)

def stream_async_result(ctx, href, sync_hrefs):
    """Download the asynchronous collection datafile and stream it record by
    record via jsonstream, so the estate is never decoded into memory whole --
    the datafile is precisely the response taken when the estate exceeds 500
    workloads, and a large PCE can hold tens of thousands. The raw HTTP builtin
    is used because jsonstream needs the body; it takes no retry budget, so
    this single request gets one attempt. Each record's href is marked in
    sync_hrefs as it streams, so the caller can tell which synchronous rows the
    datafile did not carry.

    Returns (reported, streamed, err). Every failure is detected before the
    first record is reported, so on err the caller can still fall back to the
    synchronous result without duplicating assets."""
    response = http_get(_api_url(ctx, href), **ctx["http_options"])
    if response == None:
        return 0, 0, "no response downloading the collection result"
    if response.status_code != 200:
        return 0, 0, "status {} downloading the collection result".format(response.status_code)
    if not re_search(ARRAY_RE, as_text(response.body, join=",")[:64]):
        return 0, 0, "the collection result was not a JSON array"

    reported = 0
    streamed = 0
    for record in iter_array(response.body):
        streamed += 1
        if type(record) == "dict":
            record_href = as_text(record.get("href"), join=",").strip()
            if record_href and record_href in sync_hrefs:
                sync_hrefs[record_href] = True
        reported += report_one(ctx, record)
    return reported, streamed, None

def fetch_and_report_workloads(ctx):
    """Fetch every workload and stream it to runZero. A synchronous collection
    is tried first because it is one request and covers most estates; when it
    comes back at the documented 500 object cap the result may be truncated, so
    the same collection is re-run as an asynchronous offline job and its
    datafile is streamed."""
    records, err = fetch_sync(ctx)
    if err:
        if err.startswith("status 401") or err.startswith("status 403"):
            _log("authentication to the PCE failed: " + err)
        else:
            _log("failed to fetch workloads: " + err)
        return 0

    if len(records) < SYNC_LIMIT:
        return report_workloads(ctx, records)

    _log("the synchronous collection returned the {} object cap, so the estate may be larger; re-running it as an asynchronous GET collection".format(SYNC_LIMIT))
    params = {}
    if ctx["managed_only"]:
        params["managed"] = "true"
    location, retry_after, err = start_async_job(ctx, "/workloads", params)
    href = ""
    if not err:
        _log("asynchronous collection job accepted, polling {} every {}s".format(location, retry_after))
        href, err = poll_async_job(ctx, location, retry_after)
    if not err:
        sync_hrefs = {}
        for record in records:
            if type(record) == "dict":
                record_href = as_text(record.get("href"), join=",").strip()
                if record_href:
                    sync_hrefs[record_href] = False
        reported, streamed, err = stream_async_result(ctx, href, sync_hrefs)
        if not err:
            _log("asynchronous collection returned {} workloads".format(streamed))
            missing = [r for r in records if type(r) == "dict" and sync_hrefs.get(as_text(r.get("href"), join=",").strip()) == False]
            if missing:
                _log("WARNING: the asynchronous result was missing {} workloads the synchronous call returned; importing those rows from the synchronous snapshot".format(len(missing)))
                reported += report_workloads(ctx, missing)
            return reported

    _log("WARNING: the asynchronous GET collection failed ({}), so only the first {} workloads were imported and an unknown number were skipped. Every workload past the cap is missing from runZero until this is resolved.".format(err, len(records)))
    return report_workloads(ctx, records)

def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ""
    if not scope:
        _fail("could not determine the PCE host from the configured URL")

    org_id = get_string(kwargs, "org_id", default="1").strip()
    headers = {
        "Authorization": basic(get_string(kwargs, "api_key_id"), get_string(kwargs, "api_secret")),
        "Accept": "application/json",
    }
    # get_json retries the transient statuses (408/425/429/5xx) three times with
    # exponential backoff and honors Retry-After, which is the built-in default.
    http_options = get_http_options(kwargs, headers=headers)
    async_headers = dict(headers)
    async_headers["Prefer"] = "respond-async"
    async_options = get_http_options(kwargs, headers=async_headers)

    detail_limit = get_int(kwargs, "service_detail_limit", default=1000)
    if detail_limit < 0:
        detail_limit = 0

    ctx = {
        "base_url": base_url,
        "org_url": base_url + API_BASE + "/orgs/" + org_id,
        "org_id": org_id,
        "scope": scope,
        "http_options": http_options,
        "async_options": async_options,
        "import_services": get_bool(kwargs, "import_services", default=True),
        "managed_only": get_bool(kwargs, "managed_only", default=False),
        "detail_limit": detail_limit,
        "async_timeout": get_int(kwargs, "async_timeout_seconds", default=600),
        "labels": {},
        "detail_used": 0,
        "detail_skipped": 0,
        "detail_failed": 0,
        "malformed": 0,
        "skipped": 0,
        "deleted": 0,
    }
    ctx["labels"] = build_label_index(ctx)

    reported = fetch_and_report_workloads(ctx)
    _log("reported {} assets".format(reported))
    if ctx["skipped"]:
        _log("skipped {} workloads with no href".format(ctx["skipped"]))
    if ctx["malformed"]:
        _log("skipped {} malformed workload records".format(ctx["malformed"]))
    if ctx["deleted"]:
        _log("skipped {} workloads marked deleted".format(ctx["deleted"]))
    if ctx["detail_failed"]:
        _log("could not read services for {} workloads".format(ctx["detail_failed"]))
    if ctx["detail_skipped"]:
        _log("service enrichment limit of {} reached; services were not imported for {} workloads".format(
            ctx["detail_limit"], ctx["detail_skipped"]))
    if not reported:
        _log("no assets retrieved")
    return None

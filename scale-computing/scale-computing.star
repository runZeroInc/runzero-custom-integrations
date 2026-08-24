# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-scale-computing",
    "name": "Scale Computing",
    "type": "inbound",
    "description": "Imports virtual machines from a Scale Computing HC3 cluster.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "base_url",
            "label": "Cluster base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://hc3.example.com",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset')
load('base64', base64_encode='encode')
load('coerce', 'dicts')
load('kwargs', 'get_bool')
load('net', 'network_interface', 'routable_ips')

INSECURE_ALLOWED = False
# See the comment at the ImportAsset call below for why this is knowable here.
VM_DEVICE_TYPE = "Virtual Machine"

def try_login(ctx):
    """Authenticate via POST /rest/v1/login and rely on the session cookie.

    Whether HyperCore's v1 API accepts per-request Basic auth on every route is
    unverified against a real cluster; Scale's own client tooling logs in and
    carries a session. Basic stays the first attempt, and this fallback fires
    once when Basic is answered with a 401 so either behavior works.
    """
    resp = ctx["session"].post(
        ctx["base_url"] + "/rest/v1/login",
        json={"username": ctx["username"], "password": ctx["password"], "useOIDC": False},
    )
    if resp and resp.status_code >= 200 and resp.status_code < 300:
        print("scale-computing: Basic auth was rejected; continuing with a /rest/v1/login session")
        return True
    print("scale-computing: the /rest/v1/login fallback also failed (status {})".format(
        resp.status_code if resp else "no response"))
    return False

def get_rows(ctx, path, label):
    """GET one HC3 collection and return (rows, ok).

    A 401 on the first Basic-authenticated request triggers one login-session
    fallback and a retry. The body is sniffed before decoding: these endpoints
    answer bare JSON arrays, and json_decode on an HTML proxy error page would
    abort the whole run.
    """
    url = ctx["base_url"] + path
    resp = ctx["session"].get(url)
    if resp and resp.status_code == 401 and not ctx["login_attempted"]:
        ctx["login_attempted"] = True
        if try_login(ctx):
            resp = ctx["session"].get(url)
    if not (resp and resp.status_code == 200):
        print("scale-computing: could not {} (status {})".format(
            label, resp.status_code if resp else "no response"))
        return [], False
    if not resp.body or resp.body[0:1] != "[":
        print("scale-computing: could not {}: the response body was not a JSON list".format(label))
        return [], False
    return dicts(json_decode(resp.body)), True

def main(*args, **kwargs):
    # Prefer structured top-level kwargs (params[] schema). Fall back
    # to the legacy JSON-stuffed password for back-compat.
    base_url = kwargs.get('base_url', '').rstrip('/')
    username = kwargs.get('username', '')
    password = kwargs.get('password', '')
    if password.startswith('{'):
        secret = json_decode(password)
        if type(secret) == 'dict' and len(secret) > 0:
            base_url = base_url or secret.get('base_url', '').rstrip('/')
            username = username or secret.get('username', '')
            password = secret.get('password', password)
    if not base_url or not username or not password:
        print("scale-computing: base_url, username, and password are all required")
        return []

    # Session & Auth header
    auth_str = "{}:{}".format(username, password)
    auth_hdr = "Basic {}".format(base64_encode(auth_str))
    insecure_allowed = get_bool(kwargs, 'tls_disable_validation', INSECURE_ALLOWED)
    session = Session(insecure_skip_verify=insecure_allowed)
    session.headers.set("Accept", "application/json")
    session.headers.set("Authorization", auth_hdr)
    if kwargs.get('http_user_agent'):
        session.headers.set('User-Agent', kwargs.get('http_user_agent'))

    ctx = {
        "session": session,
        "base_url": base_url,
        "username": username,
        "password": password,
        "login_attempted": False,
    }

    # 1) Fetch the cluster this endpoint belongs to.
    #
    # The previous code built a map keyed by the CLUSTER uuid and then looked it
    # up with the VM's nodeUUID, which is a NODE uuid, so the lookup never
    # matched: clusterName was never set and this whole call was wasted. The
    # /rest/v1/Cluster endpoint is scoped to the appliance being queried and
    # describes that cluster, so its uuid and name apply to every VM the same
    # endpoint returns and the first record is the one to use.
    cluster_uuid = ""
    cluster_name = ""
    cl_data, ok = get_rows(ctx, "/rest/v1/Cluster", "read the cluster record")
    if ok:
        print("scale-computing: read {} clusters".format(len(cl_data)))
        for c in cl_data:
            cluster_uuid = str(c.get("uuid", "") or "")
            cluster_name = str(c.get("clusterName", "") or "")
            break
    else:
        print("scale-computing: VMs will carry no cluster name")

    # 2) Fetch VMs
    vm_list, ok = get_rows(ctx, "/rest/v1/VirDomain", "list VMs")
    if not ok:
        return []
    print("scale-computing: read {} VMs".format(len(vm_list)))

    # 3) Fetch VM network-devices (for MACs & IPs)
    netdevs, ok = get_rows(ctx, "/rest/v1/VirDomainNetDevice", "list network devices")
    if ok:
        print("scale-computing: read {} network devices".format(len(netdevs)))
    else:
        print("scale-computing: VMs will carry no addresses")
    # Group by VM UUID
    netdevs_by_vm = {}
    for d in netdevs:
        vm_uuid = d.get("virDomainUUID")
        netdevs_by_vm.setdefault(vm_uuid, []).append(d)

    # 4) Build and stream one ImportAsset per VM
    reported = 0
    skipped = 0
    skipped_name = ""
    for vm in vm_list:
        vid = vm.get("uuid")
        # HC3 assigns the uuid, so a VirDomain row without one is a record the
        # cluster is still writing or has partly deleted. There was no guard
        # here: vid went straight to ImportAsset(id=None), which the runtime
        # rejects with "id must be a string", and with no exceptions in Starlark
        # that killed the whole run -- every VM already built was lost and none
        # were reported.
        if not vid:
            # Tallied rather than logged per record: a cluster mid-rebuild can
            # return many of these at once, and a count plus one example says
            # everything a line per VM would.
            skipped += 1
            if skipped == 1:
                skipped_name = str(vm.get("name", ""))
            continue

        # VM properties
        hostname    = vm.get("name")
        os_name     = vm.get("operatingSystem")
        # description is a free-text note an operator types about the VM ("IIS
        # front end"), not a version of anything. HC3 publishes no OS version
        # field, so osVersion is left unset and the note becomes an attribute.
        description = vm.get("description", "")
        state       = vm.get("state")
        disposition = vm.get("desiredDisposition")
        console     = vm.get("console")
        boot_devs   = vm.get("bootDevices", [])
        ui_state    = vm.get("uiState")
        snaps       = vm.get("snapUUIDs", [])
        snap_serial = vm.get("snapshotSerialNumber")
        repl_uuids  = vm.get("replicationUUIDs", [])
        src_uuid    = vm.get("sourceVirDomainUUID")
        mem_bytes   = vm.get("mem")
        cpus        = vm.get("numVCPU")
        tags        = vm.get("tags", "")

        # Network interfaces with MACs & IPs. The address lists are what the
        # GUEST TOOLS report, so they routinely include link-local noise;
        # routable_ips drops the values that would cross-correlate unrelated
        # VMs while keeping RFC1918 and public addresses.
        interfaces = []
        for nd in netdevs_by_vm.get(vid, []):
            mac = nd.get("macAddress")
            ips = routable_ips(nd.get("ipv4Addresses") or [])
            iface = network_interface(mac=mac, ips=ips)
            # network_interface returns None when neither a MAC nor a usable
            # address survives; appending it aborts the run at ImportAsset.
            if iface:
                interfaces.append(iface)

        asset = ImportAsset(
            id                = vid,
            hostnames         = [hostname],
            os                = os_name,
            # Every record this integration imports comes from /rest/v1/VirDomain,
            # and an HC3 VirDomain is a guest virtual machine -- the collection
            # holds nothing else, so the type is carried by the resource itself
            # rather than guessed from a name or an OS. This is the same value
            # the other hypervisor sources in this repository emit for a guest
            # (nutanix-prism, truenas, synology-dsm), so a search for VMs across
            # them returns one consistent type.
            deviceType        = VM_DEVICE_TYPE,
            networkInterfaces = interfaces,
            customAttributes  = {
                "clusterId":         cluster_uuid,
                "clusterName":       cluster_name,
                "nodeUUID":          vm.get("nodeUUID"),
                "description":       description,
                "state":             state,
                "desiredDisposition": disposition,
                "console":           console,
                "bootDevices":       boot_devs,
                "uiState":           ui_state,
                "snapUUIDs":         snaps,
                "snapshotSerial":    snap_serial,
                "replicationUUIDs":  repl_uuids,
                "sourceReplicaOf":   src_uuid,
                "memoryBytes":       mem_bytes,
                "cpuCount":          cpus,
                "tags":              tags,
                "createdAt":         vm.get("created"),
                "modifiedAt":        vm.get("modified"),
            },
        )
        # Streamed per VM rather than accumulated: a late abort can then only
        # lose the record that caused it, not everything already built.
        reported += report_asset(asset)

    if skipped > 0:
        print("scale-computing: skipped {} VMs with no uuid (first name: {})".format(
            skipped, skipped_name))

    print("scale-computing: reported {} assets".format(reported))
    return None

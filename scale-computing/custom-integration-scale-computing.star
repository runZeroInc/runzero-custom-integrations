load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('base64', base64_encode='encode')

INSECURE_ALLOWED = True
DEBUG = True  # set to False to disable debug prints

def debug_print(msg):
    if DEBUG:
        print(msg)

def main(*args, **kwargs):
    debug_print(">>> main() start")

    # Decode the secret
    secret = json_decode(kwargs.get('access_secret', '{}'))
    username = secret.get('access_key')
    password = secret.get('access_secret')
    base_url = secret.get('base_url', '').rstrip('/')
    debug_print("Base URL: {}".format(base_url))
    if not base_url or not username or not password:
        debug_print("Failed to parse configuration")
        return []

    # Session & Auth header
    auth_str = "{}:{}".format(username, password)
    auth_hdr = "Basic {}".format(base64_encode(auth_str))
    session = Session(insecure_skip_verify=INSECURE_ALLOWED)
    session.headers.set("Accept", "application/json")
    session.headers.set("Authorization", auth_hdr)
    debug_print("Session headers: {}".format(session.headers))

    # 1) Fetch clusters
    clusters = {}
    clu_url = "{}{}/rest/v1/Cluster".format("", base_url)  # avoid f-strings
    debug_print("GET Clusters => {}".format(clu_url))
    resp = session.get(clu_url)
    debug_print("Clusters status: {}".format(getattr(resp, 'status_code', None)))
    if resp and resp.status_code == 200:
        cl_data = json_decode(resp.body)
        debug_print("Got {} clusters".format(len(cl_data)))
        for c in cl_data:
            clusters[c["uuid"]] = c["clusterName"]
    else:
        debug_print("Skipping cluster mapping")

    # 2) Fetch VMs
    vm_url = "{}{}/rest/v1/VirDomain".format("", base_url)
    debug_print("GET VMs => {}".format(vm_url))
    resp = session.get(vm_url)
    debug_print("VMs status: {}".format(getattr(resp, 'status_code', None)))
    if not (resp and resp.status_code == 200):
        debug_print("No VMs fetched; exiting")
        return []
    vm_list = json_decode(resp.body)
    debug_print("Got {} VMs".format(len(vm_list)))

    # 3) Fetch VM network-devices (for MACs & IPs)
    netdev_url = "{}{}/rest/v1/VirDomainNetDevice".format("", base_url)
    debug_print("GET NetDevices => {}".format(netdev_url))
    resp = session.get(netdev_url)
    debug_print("NetDevices status: {}".format(getattr(resp, 'status_code', None)))
    netdevs = []
    if resp and resp.status_code == 200:
        netdevs = json_decode(resp.body)
        debug_print("Got {} network-devices".format(len(netdevs)))
    else:
        debug_print("No network-devices fetched")
    # Group by VM UUID
    netdevs_by_vm = {}
    for d in netdevs:
        vm_uuid = d.get("virDomainUUID")
        netdevs_by_vm.setdefault(vm_uuid, []).append(d)

    # 4) Build ImportAsset objects
    assets = []
    for vm in vm_list:
        vid = vm.get("uuid")
        debug_print("Processing VM: {}".format(vid))

        # VM properties
        hostname    = vm.get("name")
        os_name     = vm.get("operatingSystem")
        os_version  = vm.get("description", "")
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

        # Network interfaces with MACs & IPs
        interfaces = []
        for nd in netdevs_by_vm.get(vid, []):
            mac = nd.get("macAddress")
            ips = nd.get("ipv4Addresses", [])
            debug_print("  NetDev: MAC={}, IPs={}, VLAN={}, connected={}".format(
                mac, ips, nd.get("vlan"), nd.get("connected")))
            iface = NetworkInterface(
                macAddress=mac,
                ipv4Addresses=ips
            )
            interfaces.append(iface)

        asset = ImportAsset(
            id                = vid,
            hostnames         = [hostname],
            os                = os_name,
            osVersion         = os_version,
            networkInterfaces = interfaces,
            customAttributes  = {
                "clusterId":         vm.get("nodeUUID"),
                "clusterName":       clusters.get(vm.get("nodeUUID"), ""),
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
            }
        )
        debug_print("Built asset: {}".format(asset))
        assets.append(asset)

    debug_print(">>> main() complete: returning {} assets".format(len(assets)))
    return assets

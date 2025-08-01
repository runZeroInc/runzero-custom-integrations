load('requests', 'Session')

load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')

# Toggle debug prints on or off
DEBUG = False
INSECURE_ALLOWED = True

def main(*args, **kwargs):
    """
    Entrypoint for Proxmox VE integration, with debug prints
    controlled by the DEBUG global, robust GA-interface handling,
    and optional guest‐agent OS detection.
    """
    # --- 1) Parse config & auth ---
    secret       = json_decode(kwargs.get('access_secret', '{}'))
    if DEBUG:
        print("DEBUG: Parsed secret: {}".format(secret))
    base_url     = secret.get('base_url', '').rstrip('/')
    token_id     = secret.get('access_key')
    token_secret = secret.get('access_secret')
    if DEBUG:
        print("DEBUG: base_url='{}', token_id='{}'".format(base_url, token_id))
    if not (base_url and token_id and token_secret):
        print("ERROR: Missing base_url or credentials")
        return []

    # --- 2) Setup session & fetch Proxmox version ---
    token_header = "PVEAPIToken={}={}".format(token_id, token_secret)
    session      = Session(insecure_skip_verify=INSECURE_ALLOWED)
    session.headers.set('Accept', 'application/json')
    session.headers.set('Authorization', token_header)
    api_url      = base_url + "/api2/json"
    if DEBUG:
        print("DEBUG: API URL: {}".format(api_url))

    ver_resp = session.get(api_url + "/version")
    if DEBUG:
        print("DEBUG: /version status code: {}".format(ver_resp.status_code))
    version = json_decode(ver_resp.body).get('data', {}).get('release', '')
    if DEBUG:
        print("DEBUG: Proxmox version: {}".format(version))

    assets = []

    # --- 3) Discover cluster nodes ---
    nodes = json_decode(session.get(api_url + "/nodes").body).get('data', [])
    if DEBUG:
        print("DEBUG: Found {} nodes".format(len(nodes)))
    for node in nodes:
        node_name = node.get('node')
        asset_id  = node_name
        mgmt_ip   = node.get('ip')
        if DEBUG:
            print("DEBUG: Node {} entry: {}".format(node_name, node))

        # Management IP interface
        network_ifaces = []
        if mgmt_ip:
            ip_clean = mgmt_ip.split('/', 1)[0]
            ip_obj   = ip_address(ip_clean)
            if ip_obj:
                network_ifaces.append(NetworkInterface(
                    macAddress    = None,
                    ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                    ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                ))

        node_attrs = {
            'status':       node.get('status'),
            'cpu_usage':    node.get('cpu'),
            'max_cpu':      node.get('maxcpu'),
            'memory_used':  node.get('mem'),
            'memory_total': node.get('maxmem'),
            'disk_used':    node.get('disk'),
            'disk_total':   node.get('maxdisk'),
            'uptime':       node.get('uptime'),
        }
        assets.append(ImportAsset(
            id                = asset_id,
            hostnames         = [node_name],
            networkInterfaces = network_ifaces,
            os                = "Proxmox VE",
            osVersion         = version,
            manufacturer      = "Proxmox",
            model             = node_name,
            deviceType        = "Proxmox Cluster Node",
            tags              = ["proxmox","cluster","node"],
            customAttributes  = node_attrs,
        ))

        # --- 4) QEMU VMs on this node ---
        vms = json_decode(session.get(api_url + "/nodes/{}/qemu".format(node_name)).body).get('data', [])
        if DEBUG:
            print("DEBUG: Node {} has {} VMs".format(node_name, len(vms)))
        for vm in vms:
            vmid     = vm.get('vmid')
            asset_id = str(vmid)
            if DEBUG:
                print("DEBUG: Processing VMID: {}".format(vmid))

            # 4.1) Fetch VM status/current
            detail = json_decode(session.get(
                api_url + "/nodes/{}/qemu/{}/status/current".format(node_name, vmid)
            ).body).get('data', {})

            # 4.2) Build network interfaces via guest agent
            ga_json    = json_decode(session.get(
                api_url + "/nodes/{}/qemu/{}/agent/network-get-interfaces".format(node_name, vmid)
            ).body) or {}
            if DEBUG:
                print("DEBUG: GA JSON for VM {}: {}".format(vmid, ga_json))

            data_val   = ga_json.get('data') or {}
            iface_res  = data_val.get('result') or []
            # If Proxmox returned an error object (dict with "error"), skip GA interfaces
            if iface_res and ("error" in iface_res):
                if DEBUG:
                    print("DEBUG: GA error for VM {}, skipping GA interfaces".format(vmid))
                raw_ifaces = []
            else:
                raw_ifaces = iface_res

            vm_ifaces = []
            for nic in raw_ifaces:
                # only process if this nic dict has a hardware-address field
                if "hardware-address" in nic:
                    mac = nic.get("hardware-address")
                    for ipinfo in nic.get("ip-addresses", []):
                        ip_str = ipinfo.get("ip-address")
                        if ip_str:
                            ip_clean = ip_str.split('/', 1)[0]
                            ip_obj   = ip_address(ip_clean)
                            if ip_obj:
                                vm_ifaces.append(NetworkInterface(
                                    macAddress    = mac,
                                    ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                                    ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                                ))

            # 4.3) Fallback: parse VM config for MACs and status/current for IPs
            if not vm_ifaces:
                cfg_data = (json_decode(session.get(
                    api_url + "/nodes/{}/qemu/{}/config".format(node_name, vmid)
                ).body) or {}).get('data', {}) or {}
                for key, val in cfg_data.items():
                    if key.startswith("net"):
                        parts = val.split(',')
                        mac = None
                        for p in parts:
                            if p.startswith("mac="):
                                mac = p.split("=",1)[1]
                                break
                        vm_ifaces.append(NetworkInterface(
                            macAddress    = mac,
                            ipv4Addresses = [],
                            ipv6Addresses = []
                        ))
                for ip in detail.get("ip", []):
                    if ip:
                        ip_clean = ip.split("/",1)[0]
                        ip_obj   = ip_address(ip_clean)
                        if ip_obj:
                            vm_ifaces.append(NetworkInterface(
                                macAddress    = None,
                                ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                                ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                            ))

            if DEBUG:
                print("DEBUG: Total interfaces for VM {}: {}".format(vmid, len(vm_ifaces)))

            # --- 4.4) Attempt guest-agent OS info ---
            os_field         = detail.get("template", "QEMU VM")
            os_version_field = version

            os_json = json_decode(session.get(
                api_url + "/nodes/{}/qemu/{}/agent/get-osinfo".format(node_name, vmid)
            ).body) or {}
            if DEBUG:
                print("DEBUG: OS-Info JSON for VM {}: {}".format(vmid, os_json))

            os_data = os_json.get("data") or {}
            os_info = os_data.get("result") or os_data

            # only if no error key present and pretty-name is provided
            if os_info and ("error" not in os_info) and ("pretty-name" in os_info):
                pretty = os_info.get("pretty-name") or os_info.get("name")
                major  = os_info.get("major")
                minor  = os_info.get("minor")
                if pretty:
                    os_field = pretty
                if major != None and minor != None:
                    os_version_field = "{}.{}".format(major, minor)
                if DEBUG:
                    print("DEBUG: Resolved OS for VM {}: {} {}".format(
                        vmid, os_field, os_version_field
                    ))

            vm_attrs = {
                'vmid':   vmid,
                'node':   node_name,
                'status': detail.get('status'),
                'memory': detail.get('maxmem'),
                'cpu':    detail.get('maxcpu'),
                'uptime': detail.get('uptime'),
            }
            assets.append(ImportAsset(
                id                = asset_id,
                hostnames         = [detail.get("name")] if detail.get("name") else [],
                networkInterfaces = vm_ifaces,
                os                = os_field,
                osVersion         = os_version_field,
                manufacturer      = "Proxmox",
                model             = "VM",
                deviceType        = "Proxmox VM",
                tags              = ["proxmox","qemu","vm"],
                customAttributes  = vm_attrs,
            ))

        # --- 5) LXC containers on this node ---
        cts = json_decode(session.get(api_url + "/nodes/{}/lxc".format(node_name)).body).get('data', [])
        for ct in cts:
            ct_id    = ct.get("vmid")
            asset_id = str(ct_id)
            detail   = json_decode(session.get(
                api_url + "/nodes/{}/lxc/{}/status/current".format(node_name, ct_id)
            ).body).get("data", {}) or {}

            ct_ifaces = []
            lxc_cfg   = (json_decode(session.get(
                api_url + "/nodes/{}/lxc/{}/config".format(node_name, ct_id)
            ).body) or {}).get("data", {}) or {}
            for key, val in lxc_cfg.items():
                if key.startswith("net"):
                    parts = val.split(",")
                    mac = None
                    for p in parts:
                        if p.startswith("hwaddr=") or p.startswith("mac="):
                            mac = p.split("=",1)[1]
                            break
                    ct_ifaces.append(NetworkInterface(
                        macAddress    = mac,
                        ipv4Addresses = [],
                        ipv6Addresses = []
                    ))
            for ip in detail.get("ip", []):
                if ip:
                    ip_obj = ip_address(ip)
                    if ip_obj:
                        ct_ifaces.append(NetworkInterface(
                            macAddress    = None,
                            ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                            ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                        ))

            ct_attrs = {
                'vmid':   ct_id,
                'node':   node_name,
                'status': detail.get('status'),
                'memory': detail.get('maxmem'),
                'cpu':    detail.get('maxcpu'),
                'uptime': detail.get('uptime'),
            }
            assets.append(ImportAsset(
                id                = asset_id,
                hostnames         = [detail.get("name")] if detail.get("name") else [],
                networkInterfaces = ct_ifaces,
                os                = detail.get("template","LXC Container"),
                osVersion         = version,
                manufacturer      = "Proxmox",
                model             = "CT",
                deviceType        = "Proxmox LXC Container",
                tags              = ["proxmox","lxc","container"],
                customAttributes  = ct_attrs,
            ))

    if DEBUG:
        print("DEBUG: Total assets collected: {}".format(len(assets)))
    return assets

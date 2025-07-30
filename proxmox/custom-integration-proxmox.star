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
    controlled by the DEBUG global, and robust handling when
    the Guest Agent returns an error object instead of a list.
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

    # --- 2) Setup session & fetch version ---
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
        if DEBUG:
            print("DEBUG: Node entry: {}".format(node))
        node_name = node.get('node')
        asset_id  = node_name
        mgmt_ip   = node.get('ip')
        if DEBUG:
            print("DEBUG: Node {} mgmt_ip: {}".format(node_name, mgmt_ip))

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
            tags              = ["proxmox", "cluster", "node"],
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

            # 4.1) status/current
            detail = json_decode(session.get(
                api_url + "/nodes/{}/qemu/{}/status/current".format(node_name, vmid)
            ).body).get('data', {})

            # 4.2) Guest Agent
            ga_json = json_decode(session.get(
                api_url + "/nodes/{}/qemu/{}/agent/network-get-interfaces".format(node_name, vmid)
            ).body) or {}
            if DEBUG:
                print("DEBUG: GA JSON for VM {}: {}".format(vmid, ga_json))

            data_val = ga_json.get('data') or {}
            raw_ifaces = data_val.get('result') or []
            # Guard: ensure raw_ifaces is actually a list
            if type(raw_ifaces) != type([]):
                if DEBUG:
                    print("DEBUG: GA result not a list for VM {}, clearing".format(vmid))
                raw_ifaces = []
            if DEBUG:
                print("DEBUG: GA ifaces list for VM {}: {}".format(vmid, raw_ifaces))

            vm_ifaces = []
            if raw_ifaces:
                for nic in raw_ifaces:
                    if DEBUG:
                        print("DEBUG: GA NIC entry for VM {}: {}".format(vmid, nic))
                    mac = nic.get('hardware-address')
                    for ipinfo in nic.get('ip-addresses', []):
                        ip_str = ipinfo.get('ip-address')
                        if ip_str:
                            ip_clean = ip_str.split('/', 1)[0]
                            ip_obj   = ip_address(ip_clean)
                            if ip_obj:
                                vm_ifaces.append(NetworkInterface(
                                    macAddress    = mac,
                                    ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                                    ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                                ))

            # 4.3) Fallback to config & status/current IPs
            if not vm_ifaces:
                cfg_data = (json_decode(session.get(
                    api_url + "/nodes/{}/qemu/{}/config".format(node_name, vmid)
                ).body) or {}).get('data', {}) or {}
                for key, val in cfg_data.items():
                    if key.startswith('net'):
                        parts = val.split(',')
                        mac = None
                        for p in parts:
                            if p.startswith('mac='):
                                mac = p.split('=',1)[1]
                                break
                        if DEBUG:
                            print("DEBUG: Fallback MAC from {} for VM {}: {}".format(key, vmid, mac))
                        vm_ifaces.append(NetworkInterface(
                            macAddress    = mac,
                            ipv4Addresses = [],
                            ipv6Addresses = []
                        ))
                for ip in detail.get('ip', []):
                    if ip:
                        ip_clean = ip.split('/',1)[0]
                        ip_obj   = ip_address(ip_clean)
                        if ip_obj:
                            vm_ifaces.append(NetworkInterface(
                                macAddress    = None,
                                ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                                ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                            ))

            if DEBUG:
                print("DEBUG: Total interfaces for VM {}: {}".format(vmid, len(vm_ifaces)))

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
                hostnames         = [detail.get('name')] if detail.get('name') else [],
                networkInterfaces = vm_ifaces,
                os                = detail.get('template', 'QEMU VM'),
                osVersion         = version,
                manufacturer      = "Proxmox",
                model             = "VM",
                deviceType        = "Proxmox VM",
                tags              = ["proxmox", "qemu", "vm"],
                customAttributes  = vm_attrs,
            ))

        # --- 5) LXC containers on this node ---
        cts = json_decode(session.get(api_url + "/nodes/{}/lxc".format(node_name)).body).get('data', [])
        for ct in cts:
            ct_id   = ct.get('vmid')
            asset_id= str(ct_id)
            detail  = json_decode(session.get(
                api_url + "/nodes/{}/lxc/{}/status/current".format(node_name, ct_id)
            ).body).get('data', {}) or {}

            ct_ifaces = []
            lxc_cfg_data = (json_decode(session.get(
                api_url + "/nodes/{}/lxc/{}/config".format(node_name, ct_id)
            ).body) or {}).get('data', {}) or {}
            for key, val in lxc_cfg_data.items():
                if key.startswith('net'):
                    parts = val.split(',')
                    mac = None
                    for p in parts:
                        if p.startswith('hwaddr=') or p.startswith('mac='):
                            mac = p.split('=',1)[1]
                            break
                    ct_ifaces.append(NetworkInterface(
                        macAddress    = mac,
                        ipv4Addresses = [],
                        ipv6Addresses = []
                    ))
            for ip in detail.get('ip', []):
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
                hostnames         = [detail.get('name')] if detail.get('name') else [],
                networkInterfaces = ct_ifaces,
                os                = detail.get('template', 'LXC Container'),
                osVersion         = version,
                manufacturer      = "Proxmox",
                model             = "CT",
                deviceType        = "Proxmox LXC Container",
                tags              = ["proxmox", "lxc", "container"],
                customAttributes  = ct_attrs,
            ))

    if DEBUG:
        print("DEBUG: Total assets collected: {}".format(len(assets)))
    return assets

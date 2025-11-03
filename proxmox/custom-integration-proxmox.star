load('requests', 'Session')
load('json', json_decode='decode', json_encode='encode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')

# Toggle debug prints on or off
DEBUG = False
INSECURE_ALLOWED = True

def is_external_ip(ip_str):
    """Check if IP is external (not loopback, link-local, or internal k8s)"""
    if not ip_str:
        return False
    # Skip loopback
    if ip_str.startswith('127.') or ip_str == '::1':
        return False
    # Skip link-local
    if ip_str.startswith('169.254.') or ip_str.startswith('fe80:'):
        return False
    # Skip k8s internal ranges
    if ip_str.startswith('10.255.') or ip_str.startswith('10.244.'):
        return False
    return True

def is_external_interface(iface_name):
    """Check if interface name suggests it's external (not k8s/docker/calico)"""
    if not iface_name:
        return False
    # Skip k8s/calico/docker interfaces
    skip_prefixes = ['cali', 'vxlan', 'docker', 'nodelocaldns', 'flannel', 'cni', 'veth']
    for prefix in skip_prefixes:
        if iface_name.startswith(prefix):
            return False
    # Skip loopback
    if iface_name == 'lo':
        return False
    return True

def extract_mac_from_config(config_val):
    """Extract MAC address from Proxmox net config string"""
    if not config_val or type(config_val) != 'string':
        return None
    parts = config_val.split(',')
    for part in parts:
        part = part.strip()
        # virtio=MAC or e1000=MAC format
        if '=' in part:
            key, val = part.split('=', 1)
            if key in ['virtio', 'e1000', 'rtl8139', 'vmxnet3', 'hwaddr', 'mac']:
                # MAC address format check
                if ':' in val and len(val) == 17:
                    return val.upper()
    return None

def main(*args, **kwargs):
    """
    Comprehensive Proxmox integration: nodes, VMs, and LXC containers.
    Focuses on external IPs, MACs, hostnames, and running status.
    """
    # --- 1) Parse config & auth ---
    secret       = json_decode(kwargs.get('access_secret', '{}'))
    base_url     = secret.get('base_url', '').rstrip('/')
    token_id     = secret.get('access_key')
    token_secret = secret.get('access_secret')
    if not (base_url and token_id and token_secret):
        print("ERROR: Missing base_url or credentials")
        return []

    # --- 2) Setup session & fetch Proxmox version ---
    token_header = "PVEAPIToken={}={}".format(token_id, token_secret)
    session      = Session(insecure_skip_verify=INSECURE_ALLOWED)
    session.headers.set('Accept', 'application/json')
    session.headers.set('Authorization', token_header)
    api_url      = base_url + "/api2/json"

    ver_resp = session.get(api_url + "/version")
    version = json_decode(ver_resp.body).get('data', {}).get('release', '')

    # Get cluster name from cluster status
    cluster_name = 'proxmox'  # default fallback
    cluster_status_resp = session.get(api_url + "/cluster/status")
    cluster_status_body = json_decode(cluster_status_resp.body) if cluster_status_resp and cluster_status_resp.body else {}
    cluster_status = cluster_status_body.get('data', []) if cluster_status_body else []
    if type(cluster_status) == 'list':
        for item in cluster_status:
            if type(item) == 'dict' and item.get('type') == 'cluster':
                cluster_name = item.get('name', 'proxmox')
                break

    # Get cluster config for management IPs
    cluster_config_resp = session.get(api_url + "/cluster/config/nodes")
    cluster_config_body = json_decode(cluster_config_resp.body) if cluster_config_resp and cluster_config_resp.body else {}
    cluster_config = cluster_config_body.get('data', []) if cluster_config_body else []
    mgmt_ip_by_node = {}
    if type(cluster_config) == 'list':
        for node_cfg in cluster_config:
            if type(node_cfg) == 'dict':
                name = node_cfg.get('node')
                ring0 = node_cfg.get('ring0_addr')
                if name and ring0:
                    mgmt_ip_by_node[name] = ring0

    assets = []

    # --- 3) Discover cluster nodes ---
    cluster_nodes_resp = session.get(api_url + "/cluster/resources?type=node")
    cluster_nodes_body = json_decode(cluster_nodes_resp.body) if cluster_nodes_resp and cluster_nodes_resp.body else {}
    cluster_nodes = cluster_nodes_body.get('data', []) if cluster_nodes_body else []

    for cn in cluster_nodes:
        node_name = cn.get('node')
        if not node_name:
            continue

        # Get management IP from cluster config (Corosync ring0)
        mgmt_ip = mgmt_ip_by_node.get(node_name)
        
        # Get node status
        status_val = cn.get('status', 'unknown')
        online_bool = (status_val == 'online')

        # Build network interface for management IP (no MAC available from API)
        network_ifaces = []
        if mgmt_ip:
            ip_obj = ip_address(mgmt_ip)
            if ip_obj:
                network_ifaces.append(NetworkInterface(
                    macAddress    = None,
                    ipv4Addresses = [ip_obj] if ip_obj.version == 4 else [],
                    ipv6Addresses = [ip_obj] if ip_obj.version == 6 else []
                ))

        node_attrs = {
            'cluster':        cluster_name,
            'node_type':      'hypervisor',
            'status':         status_val,
            'online':         online_bool,
            'uptime':         cn.get('uptime'),
            'mem_total':      cn.get('maxmem'),
            'cpu_total':      cn.get('maxcpu'),
        }

        if DEBUG:
            print("Node: {} | IP: {} | Status: {}".format(node_name, mgmt_ip, status_val))

        assets.append(ImportAsset(
            id                = "{}-node-{}".format(cluster_name, node_name),
            hostnames         = [node_name],
            networkInterfaces = network_ifaces,
            os                = "Proxmox VE",
            osVersion         = version,
            manufacturer      = "Proxmox",
            model             = "Hypervisor",
            deviceType        = "Hypervisor",
            tags              = ["proxmox", "hypervisor", "node"],
            customAttributes  = node_attrs,
        ))

        # --- 4) QEMU VMs on this node ---
        vms_resp = session.get(api_url + "/nodes/{}/qemu".format(node_name))
        vms_body = json_decode(vms_resp.body) if vms_resp and vms_resp.body else {}
        vms = vms_body.get('data', []) if vms_body else []
        
        for vm in vms:
            vmid      = vm.get('vmid')
            vm_name   = vm.get('name', '')
            vm_status = vm.get('status', 'unknown')
            is_running = (vm_status == 'running')
            
            # Get VM config for MAC address
            config_resp = session.get(api_url + "/nodes/{}/qemu/{}/config".format(node_name, vmid))
            config_body = json_decode(config_resp.body) if config_resp and config_resp.body else {}
            config = config_body.get('data', {}) if config_body else {}
            
            # Extract MAC from first network interface (net0)
            mac_addr = None
            net0 = config.get('net0')
            if net0:
                mac_addr = extract_mac_from_config(net0)

            # Get external IPs from guest agent (only if running)
            # Match IPs to the MAC from config to avoid k8s internal interfaces
            vm_ifaces = []
            
            if is_running and mac_addr:
                ga_resp = session.get(api_url + "/nodes/{}/qemu/{}/agent/network-get-interfaces".format(node_name, vmid))
                ga_json = json_decode(ga_resp.body) if ga_resp and ga_resp.body else {}
                ga_data = ga_json.get('data', {}) if ga_json else {}
                ga_result = ga_data.get('result', []) if ga_data else []
                
                # Find the interface that matches our MAC address
                matched_ips = []
                if type(ga_result) == 'list':
                    for iface in ga_result:
                        if type(iface) != 'dict':
                            continue
                        
                        # Check if this interface's MAC matches our config MAC
                        iface_mac = iface.get('hardware-address', '')
                        if iface_mac.upper() == mac_addr.upper():
                            # Get IPs from this specific interface
                            ip_addrs = iface.get('ip-addresses', [])
                            if type(ip_addrs) == 'list':
                                for ip_info in ip_addrs:
                                    if type(ip_info) != 'dict':
                                        continue
                                    ip_str = ip_info.get('ip-address', '')
                                    if is_external_ip(ip_str):
                                        matched_ips.append(ip_str)
                            break  # Found the matching interface

                # Build network interface with MAC and matched IPs
                if matched_ips:
                    ipv4_addrs = []
                    ipv6_addrs = []
                    for ip_str in matched_ips:
                        ip_obj = ip_address(ip_str)
                        if ip_obj:
                            if ip_obj.version == 4:
                                ipv4_addrs.append(ip_obj)
                            else:
                                ipv6_addrs.append(ip_obj)
                    
                    vm_ifaces.append(NetworkInterface(
                        macAddress    = mac_addr,
                        ipv4Addresses = ipv4_addrs,
                        ipv6Addresses = ipv6_addrs
                    ))
            elif mac_addr:
                # VM not running or no guest agent - just add MAC
                vm_ifaces.append(NetworkInterface(
                    macAddress    = mac_addr,
                    ipv4Addresses = [],
                    ipv6Addresses = []
                ))

            # Get OS info from guest agent
            os_name = "QEMU VM"
            os_version = ""
            if is_running:
                os_resp = session.get(api_url + "/nodes/{}/qemu/{}/agent/get-osinfo".format(node_name, vmid))
                os_json = json_decode(os_resp.body) if os_resp and os_resp.body else {}
                os_data = os_json.get('data', {}) if os_json else {}
                os_info = os_data.get('result', {}) if os_data else {}
                if type(os_info) == 'dict' and 'error' not in os_info:
                    os_name = os_info.get('pretty-name') or os_info.get('name') or os_name
                    major = os_info.get('version-id') or os_info.get('major')
                    if major:
                        os_version = str(major)

            vm_attrs = {
                'cluster':    cluster_name,
                'node':       node_name,
                'vm_type':    'qemu',
                'status':     vm_status,
                'running':    is_running,
            }

            if DEBUG:
                all_ips = []
                for iface in vm_ifaces:
                    for ip in iface.ipv4Addresses:
                        all_ips.append(str(ip))
                    for ip in iface.ipv6Addresses:
                        all_ips.append(str(ip))
                ip_summary = ', '.join(all_ips[:3]) if all_ips else 'none'
                print("VM {}: {} | MAC: {} | IPs: {} | Status: {}".format(
                    vmid, vm_name, mac_addr or 'none', ip_summary, vm_status
                ))

            assets.append(ImportAsset(
                id                = "{}-{}-vm-{}".format(cluster_name, node_name, vmid),
                hostnames         = [vm_name] if vm_name else [],
                networkInterfaces = vm_ifaces,
                os                = os_name,
                osVersion         = os_version,
                manufacturer      = "Proxmox",
                model             = "Virtual Machine",
                deviceType        = "Virtual Machine",
                tags              = ["proxmox", "vm", "qemu"],
                customAttributes  = vm_attrs,
            ))

        # --- 5) LXC containers on this node ---
        cts_resp = session.get(api_url + "/nodes/{}/lxc".format(node_name))
        cts_body = json_decode(cts_resp.body) if cts_resp and cts_resp.body else {}
        cts = cts_body.get('data', []) if cts_body else []
        
        for ct in cts:
            ct_id     = ct.get('vmid')
            ct_name   = ct.get('name', '')
            ct_status = ct.get('status', 'unknown')
            is_running = (ct_status == 'running')
            
            # Get LXC config for hostname
            config_resp = session.get(api_url + "/nodes/{}/lxc/{}/config".format(node_name, ct_id))
            config_body = json_decode(config_resp.body) if config_resp and config_resp.body else {}
            config = config_body.get('data', {}) if config_body else {}
            hostname = config.get('hostname', ct_name) if config else ct_name

            # Get IPs and MACs from interfaces endpoint (only if running)
            # Only add IPs that match the first external interface's MAC
            ct_ifaces = []
            
            if is_running:
                ifaces_resp = session.get(api_url + "/nodes/{}/lxc/{}/interfaces".format(node_name, ct_id))
                ifaces_body = json_decode(ifaces_resp.body) if ifaces_resp and ifaces_resp.body else {}
                ifaces_data = ifaces_body.get('data', []) if ifaces_body else []
                
                # Find first external interface and use its MAC + IPs together
                if type(ifaces_data) == 'list':
                    for iface in ifaces_data:
                        if type(iface) != 'dict':
                            continue
                        iface_name = iface.get('name', '')
                        
                        # Skip internal interfaces
                        if not is_external_interface(iface_name):
                            continue
                        
                        # Get MAC from this interface
                        hw = iface.get('hwaddr') or iface.get('hardware-address')
                        if not hw or hw == '00:00:00:00:00:00':
                            continue
                        mac_addr = hw.upper()
                        
                        # Get IPs from this specific interface
                        external_ips = []
                        ip_addrs = iface.get('ip-addresses', [])
                        if type(ip_addrs) == 'list':
                            for ip_info in ip_addrs:
                                if type(ip_info) != 'dict':
                                    continue
                                ip_str = ip_info.get('ip-address', '')
                                if is_external_ip(ip_str):
                                    external_ips.append(ip_str)
                        
                        # Build network interface for this external interface
                        if mac_addr and external_ips:
                            ipv4_addrs = []
                            ipv6_addrs = []
                            for ip_str in external_ips:
                                ip_obj = ip_address(ip_str)
                                if ip_obj:
                                    if ip_obj.version == 4:
                                        ipv4_addrs.append(ip_obj)
                                    else:
                                        ipv6_addrs.append(ip_obj)
                            
                            ct_ifaces.append(NetworkInterface(
                                macAddress    = mac_addr,
                                ipv4Addresses = ipv4_addrs,
                                ipv6Addresses = ipv6_addrs
                            ))
                        
                        # Only use first external interface
                        break

            ct_attrs = {
                'cluster':    cluster_name,
                'node':       node_name,
                'vm_type':    'lxc',
                'status':     ct_status,
                'running':    is_running,
            }

            if DEBUG:
                ip_summary = ', '.join(external_ips[:3]) if external_ips else 'none'
                print("LXC {}: {} | MAC: {} | IPs: {} | Status: {}".format(
                    ct_id, hostname, mac_addr or 'none', ip_summary, ct_status
                ))

            assets.append(ImportAsset(
                id                = "{}-{}-ct-{}".format(cluster_name, node_name, ct_id),
                hostnames         = [hostname] if hostname else [],
                networkInterfaces = ct_ifaces,
                os                = config.get('ostype', 'LXC Container'),
                osVersion         = "",
                manufacturer      = "Proxmox",
                model             = "Container",
                deviceType        = "Container",
                tags              = ["proxmox", "container", "lxc"],
                customAttributes  = ct_attrs,
            ))

    if DEBUG:
        print("=" * 60)
        print("Total assets discovered: {}".format(len(assets)))
    
    return assets

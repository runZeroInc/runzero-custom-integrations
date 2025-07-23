# Proxmox VE Custom Integration for runZero (with VM & Container discovery)

load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')

def main(*args, **kwargs):
    """
    Entrypoint for Proxmox VE integration.
    Expects kwargs['access_secret'] to be a JSON string containing:
      - base_url:      Proxmox URL, e.g. "https://lab-vm.runzero.com:8006"
      - access_key:    API token ID,   e.g. "root@pam!monitoring"
      - access_secret: API token secret (UUID)
    Returns a list of ImportAsset objects for each cluster node, VM, and LXC container.
    """
    # --- 1) Parse JSON config & auth setup ---
    secret       = json_decode(kwargs.get('access_secret', '{}'))
    base_url     = secret.get('base_url', '').rstrip('/')
    token_id     = secret.get('access_key')
    token_secret = secret.get('access_secret')
    if not (base_url and token_id and token_secret):
        return []

    # Build the PVEAPIToken header
    token_header = "PVEAPIToken={}={}".format(token_id, token_secret)
    session      = Session()
    session.headers.set('Accept', 'application/json')
    session.headers.set('Authorization', token_header)

    api_url = "{}{}".format(base_url, "/api2/json")  # Base API URL :contentReference[oaicite:0]{index=0}

    # --- 2) Fetch Proxmox VE version ---
    ver_resp = session.get(api_url + "/version")
    version  = json_decode(ver_resp.body).get('data', {}).get('release', '')

    assets = []
    idx    = 1

    # --- 3) Discover cluster nodes ---
    nodes_resp = session.get(api_url + "/nodes")
    nodes      = json_decode(nodes_resp.body).get('data', [])  # GET /nodes :contentReference[oaicite:1]{index=1}
    for node in nodes:
        node_name = node.get('node')

        # Build NetworkInterface list from management IP
        network_ifaces = []
        mgmt_ip = node.get('ip')
        if mgmt_ip:
            ip_addr = ip_address(mgmt_ip)
            network_ifaces.append(
                NetworkInterface(
                    macAddress=None,
                    ipv4Addresses=[ip_addr] if ip_addr.version == 4 else [],
                    ipv6Addresses=[ip_addr] if ip_addr.version == 6 else []
                )
            )

        # Flatten key stats into customAttributes
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

        assets.append(
            ImportAsset(
                id                = idx,
                hostnames         = [node_name],
                networkInterfaces = network_ifaces,
                os                = "Proxmox VE",
                osVersion         = version,
                manufacturer      = "Proxmox",
                model             = node_name,
                deviceType        = "Proxmox Cluster Node",
                tags              = ["proxmox", "cluster", node.get('type', 'node')],
                customAttributes  = node_attrs,
            )
        )
        idx += 1

        # --- 4) Discover QEMU VMs on this node ---
        vms_resp = session.get(api_url + "/nodes/{}/qemu".format(node_name))
        vms      = json_decode(vms_resp.body).get('data', [])
        for vm in vms:
            vmid = vm.get('vmid')
            # Fetch current VM status/details
            detail = json_decode(
                session.get(api_url + "/nodes/{}/qemu/{}/status/current".format(node_name, vmid)).body
            ).get('data', {})

            # Build VM network interfaces (if any IPs reported)
            vm_ifaces = []
            for ip in detail.get('ip', []):
                ip_addr = ip_address(ip)
                vm_ifaces.append(
                    NetworkInterface(
                        macAddress=None,
                        ipv4Addresses=[ip_addr] if ip_addr.version == 4 else [],
                        ipv6Addresses=[ip_addr] if ip_addr.version == 6 else []
                    )
                )

            vm_attrs = {
                'vmid':  vmid,
                'node':  node_name,
                'status':detail.get('status'),
                'memory': detail.get('maxmem'),
                'cpu':    detail.get('maxcpu'),
                'uptime': detail.get('uptime'),
            }

            assets.append(
                ImportAsset(
                    id                = idx,
                    hostnames         = [ detail.get('name') ] if detail.get('name') else [],
                    networkInterfaces = vm_ifaces,
                    os                = detail.get('template', 'QEMU VM'),
                    osVersion         = version,
                    manufacturer      = "Proxmox",
                    model             = "VM {}".format(vmid),
                    deviceType        = "Proxmox VM",
                    tags              = ["proxmox", "qemu", "vm"],
                    customAttributes  = vm_attrs,
                )
            )
            idx += 1

        # --- 5) Discover LXC containers on this node ---
        ct_resp = session.get(api_url + "/nodes/{}/lxc".format(node_name))
        cts     = json_decode(ct_resp.body).get('data', [])
        for ct in cts:
            ct_id = ct.get('vmid')
            detail = json_decode(
                session.get(api_url + "/nodes/{}/lxc/{}/status/current".format(node_name, ct_id)).body
            ).get('data', {})

            # Build container interfaces
            ct_ifaces = []
            for ip in detail.get('ip', []):
                ip_addr = ip_address(ip)
                ct_ifaces.append(
                    NetworkInterface(
                        macAddress=None,
                        ipv4Addresses=[ip_addr] if ip_addr.version == 4 else [],
                        ipv6Addresses=[ip_addr] if ip_addr.version == 6 else []
                    )
                )

            ct_attrs = {
                'vmid':   ct_id,
                'node':   node_name,
                'status': detail.get('status'),
                'memory': detail.get('maxmem'),
                'cpu':    detail.get('maxcpu'),
                'uptime': detail.get('uptime'),
            }

            assets.append(
                ImportAsset(
                    id                = idx,
                    hostnames         = [ detail.get('name') ] if detail.get('name') else [],
                    networkInterfaces = ct_ifaces,
                    os                = detail.get('template', 'LXC Container'),
                    osVersion         = version,
                    manufacturer      = "Proxmox",
                    model             = "CT {}".format(ct_id),
                    deviceType        = "Proxmox LXC Container",
                    tags              = ["proxmox", "lxc", "container"],
                    customAttributes  = ct_attrs,
                )
            )
            idx += 1

    return assets

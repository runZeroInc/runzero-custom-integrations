# Proxmox VE Custom Integration for runZero (JSON-configurable)

load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')

def main(*args, **kwargs):
    """
    Entrypoint for Proxmox VE integration.
    Expects kwargs['access_secret'] to be a JSON string containing:
      - base_url:    Proxmox URL, e.g. "https://lab-vm.runzero.com:8006"
      - access_key:  API token ID,   e.g. "root@pam!monitoring"
      - access_secret: API token secret (UUID)
    Returns a list of ImportAsset objects for each cluster node.
    """
    # --- 1) Parse JSON config ---
    secret = json_decode(kwargs.get('access_secret', '{}'))
    base_url     = secret.get('base_url', '').rstrip('/')
    token_id     = secret.get('access_key')
    token_secret = secret.get('access_secret')
    if not (base_url and token_id and token_secret):
        return []

    # Build the PVEAPIToken header
    token_header = "PVEAPIToken={}={}".format(token_id, token_secret)

    # --- 2) HTTP session setup ---
    session = Session()
    session.headers.set('Accept', 'application/json')
    session.headers.set('Authorization', token_header)

    api_url = "{}{}".format(base_url, "/api2/json")

    # --- 3) Fetch Proxmox VE version ---
    ver_resp = session.get(api_url + "/version")
    ver_data = json_decode(ver_resp.body).get('data', {}) if ver_resp else {}
    version  = ver_data.get('release', '')

    # --- 4) List all cluster nodes ---
    nodes_resp = session.get(api_url + "/nodes")
    nodes      = json_decode(nodes_resp.body).get('data', []) if nodes_resp else []

    # --- 5) Build and return assets ---
    assets = []
    idx    = 1
    for node in nodes:
        # Hostnames
        hostnames = [node.get('node')]

        # Management IP → NetworkInterface
        mgmt_ip = node.get('ip')
        network_ifaces = []
        if mgmt_ip:
            ip_addr = ip_address(mgmt_ip)
            network_ifaces.append(
                NetworkInterface(
                    macAddress=None,
                    ipv4Addresses=[ip_addr] if ip_addr.version == 4 else [],
                    ipv6Addresses=[ip_addr] if ip_addr.version == 6 else []
                )
            )

        # Device type & tags
        device_type = "Proxmox Cluster Node"
        tags        = ["proxmox", "cluster", node.get('type', 'node')]

        # Custom attributes
        custom_attrs = {
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
                hostnames         = hostnames,
                networkInterfaces = network_ifaces,
                os                = "Proxmox VE",
                osVersion         = version,
                manufacturer      = "Proxmox",
                model             = node.get('node'),
                deviceType        = device_type,
                tags              = tags,
                customAttributes  = custom_attrs,
            )
        )
        idx += 1

    return assets

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-proxmox",
    "name": "Proxmox",
    "type": "inbound",
    "description": "Imports VMs, containers, and nodes from Proxmox VE.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "base_url",
            "label": "Proxmox base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://pve.example.com:8006",
        },
        {
            "key": "api_token_id",
            "label": "API token ID",
            "type": "string",
            "required": True,
            "description": "user@realm!tokenid",
        },
        {
            "key": "api_token_secret",
            "label": "API token secret",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('http', 'get_json')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'to_custom_attributes')
load('net', 'ip_address')
load('kwargs', 'get_http_options')

# to_custom_attributes joins the prefix to each key with the separator, so the
# separator has to be passed too or every attribute is named proxmox.<key>.
ATTR_PREFIX = "proxmox"
ATTR_SEPARATOR = "_"

# Extra attempts for transient failures (5xx from a busy node, resets).
# Guest-agent calls opt out: a guest without the agent answers 500 every
# time, and retrying that on every VM would stall the whole walk.
RETRIES = 2

# Toggle debug prints on or off
DEBUG = False

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

def _host_scope(base_url):
    """Derive a per-deployment scope from the base URL, for standalone hosts
    that belong to no cluster. Strips the scheme, any credentials, the port and
    any path, leaving the bare host so the value is stable across runs even if
    the operator later adds a port or a trailing path to the configured URL."""
    text = base_url
    for scheme in ["https://", "http://"]:
        if text.startswith(scheme):
            text = text[len(scheme):]
            break
    text = text.split("/")[0]
    if "@" in text:
        text = text.split("@")[-1]
    # An IPv6 literal is bracketed and its colons are part of the address, so
    # only strip a port when the colon is not inside brackets.
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            text = text[:end + 1]
    elif ":" in text:
        text = text.split(":")[0]
    return text or "proxmox"


def _describe(err):
    """Attach a credential hint to auth-shaped errors, so a refused token reads
    as a refused token instead of as an empty cluster."""
    text = str(err)
    if text.startswith("status 401"):
        return text + " (the API token was refused; check the token id user@realm!tokenid and its secret)"
    if text.startswith("status 403"):
        return text + " (the token authenticated but lacks privileges; it needs PVEAuditor on /)"
    return text


def fetch(ctx, path, what, quick=False):
    """GET one API path and return the envelope's 'data' member, or None.

    Every Proxmox endpoint wraps its payload as {"data": ...}, and an error
    body is {"data": null} -- present-but-null must come back as None here
    rather than reach a .get() or an iteration in a caller. get_json supplies
    the status check, transient-failure retries, and err-tuple transport
    handling, so a reset or timeout mid-walk is a printed skip instead of an
    abort. quick=True disables retries for calls whose failure is an expected
    answer (a guest without the QEMU guest agent answers 500 every time).
    """
    options = ctx["http_options"]
    if quick:
        options = dict(options)
        options["retries"] = 0
    data, err = get_json(ctx["api_url"] + path, **options)
    if err:
        text = str(err)
        if text.startswith("status 401") or text.startswith("status 403"):
            ctx["auth_refused"] = True
        print("proxmox: could not read {}: {}".format(what, _describe(err)))
        return None
    if type(data) != 'dict':
        if data != None:
            print("proxmox: unexpected response body from {}".format(path))
        return None
    return data.get('data')


def fetch_list(ctx, path, what, quick=False):
    """fetch(), coerced to a list; {"data": null} and non-lists become []."""
    payload = fetch(ctx, path, what, quick=quick)
    return payload if type(payload) == 'list' else []


def fetch_dict(ctx, path, what, quick=False):
    """fetch(), coerced to a dict; {"data": null} and non-dicts become {}."""
    payload = fetch(ctx, path, what, quick=quick)
    return payload if type(payload) == 'dict' else {}


def _attrs(values):
    """Namespace a flat attribute dict and drop the keys Proxmox left unset.

    Two problems this fixes. A None value is rendered by the platform as the
    literal string "None", so an absent uptime or memory total read back as a
    real value. And an unprefixed key like 'cluster' or 'status' collides with
    the same key from any other integration once the asset merges, so each one
    is namespaced.
    """
    kept = {}
    for key, value in values.items():
        if value == None or value == "":
            continue
        kept[key] = value
    return to_custom_attributes(kept, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR)


def main(*args, **kwargs):
    """
    Comprehensive Proxmox integration: nodes, VMs, and LXC containers.
    Focuses on external IPs, MACs, hostnames, and running status.
    """
    # --- 1) Parse config & auth ---
    # Prefer structured top-level kwargs (params[] schema). Fall back to
    # the legacy JSON-stuffed API token secret for back-compat.
    base_url     = kwargs.get('base_url', '').rstrip('/')
    token_id     = kwargs.get('api_token_id', '')
    token_secret = kwargs.get('api_token_secret', '')
    if not base_url or token_secret.startswith('{'):
        legacy = json_decode(token_secret) if token_secret.startswith('{') else {}
        if type(legacy) == 'dict' and len(legacy) > 0:
            base_url     = base_url     or legacy.get('base_url', '').rstrip('/')
            token_id     = token_id     or legacy.get('api_token_id', '')
            token_secret = legacy.get('api_token_secret', token_secret)
    if not (base_url and token_id and token_secret):
        print("proxmox: base_url, api_token_id, and api_token_secret are all required")
        return []

    # --- 2) Setup HTTP options & fetch Proxmox version ---
    token_header = "PVEAPIToken={}={}".format(token_id, token_secret)
    http_options = get_http_options(kwargs, headers={
        'Accept': 'application/json',
        'Authorization': token_header,
    })
    http_options["retries"] = RETRIES
    ctx = {
        "api_url": base_url + "/api2/json",
        "http_options": http_options,
        "auth_refused": False,
    }

    ver_data = fetch_dict(ctx, "/version", "the PVE version")
    # A refused token fails every later call the same way, so the run stops
    # here with a credential diagnostic instead of walking the whole cluster
    # printing the same error and ending as a plausible-looking empty import.
    if ctx["auth_refused"]:
        fail("proxmox: authentication failed; nothing collected")
    version = ver_data.get('release', '')

    # Get cluster name from cluster status. This value scopes every asset id, so
    # the fallback matters: a STANDALONE host is not in a cluster and reports no
    # cluster entry at all, which is the common single-server deployment. A
    # literal constant here gave every standalone host the same scope, so two of
    # them systematically collided -- VMID 100 exists on both, and both minted
    # "proxmox-vm-100" for different machines, merging unrelated guests onto one
    # asset. The base URL host is unique per deployment and is used instead, the
    # same way the other single-appliance integrations in this repo scope theirs.
    # Clustered deployments are unaffected: they report a real cluster name and
    # keep the ids they already have.
    cluster_name = _host_scope(base_url)
    for item in fetch_list(ctx, "/cluster/status", "the cluster status"):
        if type(item) == 'dict' and item.get('type') == 'cluster':
            name = item.get('name', '')
            if name:
                cluster_name = name
            break

    # Get cluster config for management IPs
    mgmt_ip_by_node = {}
    for node_cfg in fetch_list(ctx, "/cluster/config/nodes", "the cluster node config"):
        if type(node_cfg) == 'dict':
            name = node_cfg.get('node')
            ring0 = node_cfg.get('ring0_addr')
            if name and ring0:
                mgmt_ip_by_node[name] = ring0

    reported = 0

    # --- 3) Discover cluster nodes ---
    cluster_nodes = fetch_list(ctx, "/cluster/resources?type=node", "the node list")
    if not cluster_nodes:
        print("proxmox: the API answered but no nodes are visible to this token")

    for cn in cluster_nodes:
        if type(cn) != 'dict':
            continue
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
            print("proxmox: node {} at {} is {}".format(node_name, mgmt_ip, status_val))

        # Each asset is streamed as it is built, so one failure later in the
        # walk cannot lose everything already collected.
        reported += report_asset(ImportAsset(
            id                = "{}-node-{}".format(cluster_name, node_name),
            hostnames         = [node_name],
            networkInterfaces = network_ifaces,
            os                = "Proxmox VE",
            osVersion         = version,
            manufacturer      = "Proxmox",
            model             = "Hypervisor",
            deviceType        = "Hypervisor",
            tags              = ["proxmox", "hypervisor", "node"],
            customAttributes  = _attrs(node_attrs),
        ))

        # --- 4) QEMU VMs on this node ---
        vms = fetch_list(ctx, "/nodes/{}/qemu".format(node_name),
                         "the QEMU guest list on " + node_name)

        for vm in vms:
            if type(vm) != 'dict':
                continue
            vmid      = vm.get('vmid')
            if vmid == None:
                print("proxmox: skipping a QEMU record with no vmid on " + node_name)
                continue
            vm_name   = vm.get('name', '')
            vm_status = vm.get('status', 'unknown')
            is_running = (vm_status == 'running')

            # Get VM config for MAC address
            config = fetch_dict(ctx, "/nodes/{}/qemu/{}/config".format(node_name, vmid),
                                "the config of VM {}".format(vmid))

            # Extract MAC from first network interface (net0)
            mac_addr = None
            net0 = config.get('net0')
            if net0:
                mac_addr = extract_mac_from_config(net0)

            # Get external IPs from guest agent (only if running)
            # Match IPs to the MAC from config to avoid k8s internal interfaces
            vm_ifaces = []

            if is_running and mac_addr:
                ga_data = fetch_dict(ctx, "/nodes/{}/qemu/{}/agent/network-get-interfaces".format(node_name, vmid),
                                     "the guest agent interfaces of VM {}".format(vmid), quick=True)
                ga_result = ga_data.get('result', [])

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
                os_data = fetch_dict(ctx, "/nodes/{}/qemu/{}/agent/get-osinfo".format(node_name, vmid),
                                     "the guest agent OS info of VM {}".format(vmid), quick=True)
                os_info = os_data.get('result', {})
                if type(os_info) == 'dict' and 'error' not in os_info:
                    os_name = os_info.get('pretty-name') or os_info.get('name') or os_name
                    major = os_info.get('version-id') or os_info.get('major')
                    if major:
                        os_version = str(major)

            vm_attrs = {
                'cluster':    cluster_name,
                'node':       node_name,
                'vm_type':    'qemu',
                'vm_name':    vm_name,
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
                print("proxmox: VM {} ({}) mac={} ips={} status={}".format(
                    vmid, vm_name, mac_addr or 'none', ip_summary, vm_status
                ))

            reported += report_asset(ImportAsset(
                # VMIDs are unique across the whole cluster, not per node, so
                # the node name adds nothing to uniqueness — and including it
                # would change the id whenever a guest moves between nodes,
                # which live migration and HA failover do routinely, minting a
                # duplicate asset on every such event. The node is kept as a
                # custom attribute instead.
                id                = "{}-vm-{}".format(cluster_name, vmid),
                # The VM name is the only correlator a stopped VM with no
                # net0 MAC has; Proxmox constrains it to a DNS-name shape.
                hostnames         = [vm_name] if vm_name else [],
                networkInterfaces = vm_ifaces,
                os                = os_name,
                osVersion         = os_version,
                manufacturer      = "Proxmox",
                model             = "Virtual Machine",
                deviceType        = "Virtual Machine",
                tags              = ["proxmox", "vm", "qemu"],
                customAttributes  = _attrs(vm_attrs),
            ))

        # --- 5) LXC containers on this node ---
        cts = fetch_list(ctx, "/nodes/{}/lxc".format(node_name),
                         "the LXC guest list on " + node_name)

        for ct in cts:
            if type(ct) != 'dict':
                continue
            ct_id     = ct.get('vmid')
            if ct_id == None:
                print("proxmox: skipping an LXC record with no vmid on " + node_name)
                continue
            ct_name   = ct.get('name', '')
            ct_status = ct.get('status', 'unknown')
            is_running = (ct_status == 'running')

            # Get LXC config for hostname
            config = fetch_dict(ctx, "/nodes/{}/lxc/{}/config".format(node_name, ct_id),
                                "the config of container {}".format(ct_id))
            hostname = config.get('hostname', ct_name) or ct_name

            # Get IPs and MACs from interfaces endpoint (only if running)
            # Only add IPs that match the first external interface's MAC
            ct_ifaces = []

            if is_running:
                ifaces_data = fetch_list(ctx, "/nodes/{}/lxc/{}/interfaces".format(node_name, ct_id),
                                         "the interfaces of container {}".format(ct_id))

                # Find first external interface and use its MAC + IPs together
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
                    # Older PVE (7.x through 8.1) has no ip-addresses array on
                    # this endpoint; it reports inet/inet6 CIDR strings instead.
                    if not external_ips:
                        for key in ['inet', 'inet6']:
                            value = iface.get(key)
                            if value and type(value) == 'string':
                                addr = value.split('/')[0]
                                if is_external_ip(addr):
                                    external_ips.append(addr)

                    ipv4_addrs = []
                    ipv6_addrs = []
                    for ip_str in external_ips:
                        ip_obj = ip_address(ip_str)
                        if ip_obj:
                            if ip_obj.version == 4:
                                ipv4_addrs.append(ip_obj)
                            else:
                                ipv6_addrs.append(ip_obj)

                    # A known MAC is a correlator on its own, so the interface
                    # is emitted even when no external address was parsed.
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
                print("proxmox: container {} ({}) interfaces={} status={}".format(
                    ct_id, hostname, len(ct_ifaces), ct_status
                ))

            reported += report_asset(ImportAsset(
                # Cluster-unique, and deliberately free of the node name — see
                # the VM id above; containers migrate for the same reasons.
                id                = "{}-ct-{}".format(cluster_name, ct_id),
                hostnames=[hostname],
                networkInterfaces = ct_ifaces,
                os                = config.get('ostype', 'LXC Container'),
                osVersion         = "",
                manufacturer      = "Proxmox",
                model             = "Container",
                deviceType        = "Container",
                tags              = ["proxmox", "container", "lxc"],
                customAttributes  = _attrs(ct_attrs),
            ))

    print("proxmox: reported {} assets".format(reported))
    return None

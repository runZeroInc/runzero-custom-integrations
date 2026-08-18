# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-wazuh",
    "name": "Wazuh",
    "type": "inbound",
    "description": "Imports agents from a Wazuh manager.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # This integration reports ONE population - Wazuh agents - but two grades of
    # identifier, so the policy is declared per asset type here and the script
    # picks a type per agent from whether the record carries a registration
    # timestamp. See build_asset_id and registration_key for the id halves.
    #
    # no-type-break, because the split is about identifier quality inside one
    # population and not about two different kinds of thing. An agent that
    # reports no dateAdd today can report one tomorrow - a Wazuh upgrade, a
    # re-enrollment, an API that starts populating the field - and it is the same
    # agent on the same host throughout, so nothing about a type change should be
    # allowed to veto a merge on its own.
    #
    # Be aware of what that does NOT buy, because it is easy to over-read:
    # gaining dateAdd also changes the foreign id, from wazuh:<ns>:agent:<n> to
    # wazuh:<ns>:agent:<n>:<reg>. Two foreign ids from one custom integration
    # cannot sit on one asset whatever the break flags say, so that particular
    # transition still forks and is reconciled in runZero. no-type-break is
    # necessary but not sufficient here; it is declared so the type boundary is
    # not a SECOND, independent reason for the same fork.
    "matchBehavior": "no-type-break",
    "assetTypeBehavior": {
        # Registration time pins the ordinal, so the id can no longer be
        # inherited by a later agent and is safe to merge on. An agent's own
        # addressing must not then veto that merge: a laptop that moves
        # between networks, a VM that is renamed, or a host that gains an
        # interface is the same agent under the same id.
        "agent": "no-mac-break no-ip-break no-name-break",
        # Deliberately absent: "agent-unpinned", the type used when the record
        # carries no dateAdd. Its id CAN be inherited by a later agent reusing
        # the ordinal -- Wazuh allocates ids from a counter seeded off the
        # highest id in client.keys, and <auth><purge> defaults to yes -- and a
        # disagreeing MAC is then the only thing that can stop an unrelated new
        # host being merged onto the old agent's asset. Wazuh's syscollector
        # data is read off the host itself, so it is good enough evidence to
        # break on. With no entry here that type keeps the platform default,
        # every flag on, which is exactly what it needs.
    },
    "params": [
        {
            "key": "url",
            "label": "Wazuh API URL",
            "type": "url",
            "required": False,
            "placeholder": "https://wazuh-manager:55000",
            "description": "Full base URL of the Wazuh manager API. Set this for a deployment that is not plain https on the API port -- behind a reverse proxy, on a path prefix, or on http. When empty, the URL is composed from the hostname and port below.",
        },
        {
            "key": "hostname",
            "label": "Wazuh manager hostname or IP",
            "type": "string",
            "required": False,
            "placeholder": "wazuh-manager or 10.1.2.3",
            "description": "Used to compose https://<hostname>:<port> when the URL above is empty.",
        },
        {
            "key": "port",
            "label": "Wazuh API port",
            "type": "int",
            "required": False,
            "default": 55000,
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
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 20000,
            "min": 1,
            "description": "Safety ceiling on the paging walk. Raise it if a run reports hitting the limit.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_parse')
load('base64', base64_encode='encode')
load('time', 'parse_time')
load('re', re_sub='sub')
load('kwargs', 'require', 'get_string', 'get_int', 'get_http_options')

# Wazuh caps `limit` at 500 on the /agents endpoint and answers a larger value
# with error 1405, so this is the vendor's maximum page, not a choice.
PAGE_SIZE = 500

# The repo-wide record target for a bounded walk: no integration should import
# more than ten million records in one run, so the page ceiling is that target
# divided by the page size. At 500 agents a page that is 20,000 pages. The page
# size is fixed by the vendor; the page COUNT is not, which is why the ceiling
# is exposed as max_pages and the message that reports hitting it says so.
#
# The ceiling is a backstop, not the working guard. The walk's only exit is a
# page with no affected_items, so a manager that ignores `offset` -- or a proxy
# replaying a cached response -- never reaches it and re-reads the same 500
# agents forever. The no-progress check catches that on the first repeat. Either
# stop is logged, because a truncated import that says nothing looks exactly
# like a complete one.
MAX_RECORDS = 10000000
MAX_PAGES = (MAX_RECORDS + PAGE_SIZE - 1) // PAGE_SIZE

# os.platform values that name a distribution shipping only as a server
# platform. Wazuh sets platform from the agent's own os-release ID, so these are
# the ID values, not display names. Deliberately absent are ubuntu, debian,
# fedora, arch, opensuse, alpine and darwin, each of which is as often a
# workstation as a server, and sled (SUSE Linux Enterprise *Desktop*), the
# desktop half of sles.
SERVER_OS_PLATFORMS = [
    'rhel', 'redhat', 'centos', 'rocky', 'almalinux', 'alma',
    'amzn', 'ol', 'oracle', 'sles',
]

def device_type_for_os(os_data):
    """Return a runZero device type for one agent's os block, or "".

    The agent record is id, name, ip, status, version, node_name, group and the
    os block -- there is no chassis, model or asset class anywhere in it, and
    syscollector's netiface data adds only addressing -- so the os block is the
    only genuine statement of role. An os.name carrying "server" ("Windows
    Server 2019") and the server-only platforms above are unambiguous.

    A bare "Ubuntu", "Debian", "Alpine Linux" or a macOS agent stays unset: it
    is a desktop or a laptop and the record cannot say which, and a wrong hint
    is worse than none.

    This is only a hint. runZero prefers what it derives from the hardware or
    from its own scan, and falls back to this exactly where an agent-only host
    has never been reached by one.
    """
    if type(os_data) != 'dict':
        return ""
    name = str(os_data.get('name', '') or '').lower()
    platform = str(os_data.get('platform', '') or '').strip().lower()
    if 'server' in name:
        return "Server"
    for candidate in SERVER_OS_PLATFORMS:
        if platform == candidate:
            return "Server"
    return ""

def page_signature(agents):
    """A fingerprint of one page's rows, used to notice a manager that answers
    every offset with the same page."""
    ids = []
    for a in agents:
        if type(a) == 'dict':
            ids.append(str(a.get('id', '')))
        else:
            ids.append('')
    return ','.join(ids)

def reported_total(data):
    """Wazuh returns total_affected_items alongside affected_items. Read it when
    it is there and answer None when it is not -- a total this script invented
    would be worse than saying the API did not report one."""
    if type(data) != 'dict':
        return None
    total = data.get('total_affected_items')
    if type(total) == 'int' and total >= 0:
        return total
    return None

def retrieved_of(reported, total):
    """The 'retrieved x' clause of a truncation message, in the with-total form
    when the API reported one and the no-total form when it did not."""
    if total == None:
        return 'retrieved {} assets, total not reported'.format(reported)
    return 'retrieved {}/{} available assets'.format(reported, total)

# --- Wazuh API helpers ---
def authenticate_wazuh(host, username, password, config):
    """
    Authenticate with Wazuh API and retrieve JWT token.

    Args:
        host: Wazuh host URL (e.g., https://wazuh-manager:55000)
        username: Wazuh username
        password: Wazuh password

    Returns:
        JWT token string or None if authentication fails
    """
    auth_url = "{}/security/user/authenticate".format(host)

    # Create basic auth header
    credentials = "{}:{}".format(username, password)
    auth_header = "Basic {}".format(base64_encode(credentials))

    headers = {
        'Authorization': auth_header,
        'Content-Type': 'application/json'
    }

    response = http_post(auth_url, timeout=600, **get_http_options(config, headers=headers))

    if response.status_code != 200:
        print("Wazuh authentication failed. Status:", response.status_code)
        return None

    auth_data = json_decode(response.body)

    if auth_data.get('error', 1) != 0:
        print("Wazuh API error:", auth_data.get('message', 'Unknown error'))
        return None

    token = auth_data.get('data', {}).get('token', "")
    if not token:
        print("No token received from Wazuh API")
        return None

    print("Successfully authenticated with Wazuh API")
    return token

def get_wazuh_agents(host, token, config, max_pages):
    """
    Retrieve agents from Wazuh using pagination.

    Args:
        host: Wazuh host URL
        token: JWT authentication token

    Returns:
        List of agent dictionaries
    """
    agents_url = "{}/agents".format(host)
    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'application/json'
    }

    all_agents = []
    offset = 0
    pages = 0
    total = None
    capped = True
    last_signature = None

    for _page in range(0, max_pages):

        params = {
            'offset': offset,
            'limit': PAGE_SIZE
        }

        response = http_get(agents_url, params=params, timeout=600, **get_http_options(config, headers=headers))

        if response.status_code != 200:
            print("Failed to fetch agents from Wazuh. Status:", response.status_code)
            capped = False
            break

        response_data = json_decode(response.body)

        if response_data.get('error', 1) != 0:
            print("Wazuh API error:", response_data.get('message', 'Unknown error'))
            capped = False
            break
        data = response_data.get('data', {})
        if total == None:
            total = reported_total(data)
        agents_batch = data.get('affected_items', [])

        if not agents_batch:
            capped = False  # No more agents to fetch
            break

        pages += 1

        # A page whose agent ids are identical to the previous page's means the
        # manager ignored `offset` or replayed a cached response. The walk's
        # only exit is an empty page, so a repeat produces no exit at all and
        # the same 500 agents would be re-read to the ceiling. Stop on the
        # first repeat, and stop BEFORE extending, so the replayed page is not
        # collected twice.
        signature = page_signature(agents_batch)
        if signature == last_signature:
            print('wazuh: paging stopped after {} pages (API returned the same page twice, {})'.format(
                pages, retrieved_of(len(all_agents), total)))
            capped = False
            break
        last_signature = signature

        all_agents.extend(agents_batch)

        offset += PAGE_SIZE

    if capped:
        print('wazuh: page limit of {} hit (integration safety limit, {}) - raise the max_pages parameter to import the rest'.format(
            max_pages, retrieved_of(len(all_agents), total)))

    print("Retrieved {} agents from Wazuh".format(len(all_agents)))
    return all_agents

# NEW FUNCTION: get network interfaces with MAC addresses
def get_agent_network_interfaces(host, token, agent_id, config):
    """
    Retrieve network interfaces for a specific agent.

    Args:
        host: Wazuh host URL
        token: JWT authentication token
        agent_id: The ID of the agent

    Returns:
        Tuple of (list of network interface dictionaries, status_code)
        Returns ([], status_code) if fails
    """
    netiface_url = "{}/syscollector/{}/netiface".format(host, agent_id)
    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'application/json'
    }

    response = http_get(netiface_url, timeout=600, **get_http_options(config, headers=headers))

    if response.status_code != 200:
        if response.status_code != 401:  # Don't print for 401, we'll handle that
            print("Failed to fetch network interfaces for agent {}. Status: {}".format(agent_id, response.status_code))
        return [], response.status_code

    response_data = json_decode(response.body)

    if response_data.get('error', 1) != 0:
        print("Wazuh API error for agent {}: {}".format(agent_id, response_data.get('message', 'Unknown error')))
        return [], response.status_code

    return response_data.get('data', {}).get('affected_items', []), response.status_code


# NEW FUNCTION: get network addresses (IPs) for interfaces
def get_agent_network_addresses(host, token, agent_id, config):
    """
    Retrieve network addresses (IP addresses) for a specific agent.

    Args:
        host: Wazuh host URL
        token: JWT authentication token
        agent_id: The ID of the agent

    Returns:
        Tuple of (list of network address dictionaries, status_code)
        Returns ([], status_code) if fails
    """
    netaddr_url = "{}/syscollector/{}/netaddr".format(host, agent_id)
    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'application/json'
    }

    response = http_get(netaddr_url, timeout=600, **get_http_options(config, headers=headers))

    if response.status_code != 200:
        if response.status_code != 401:  # Don't print for 401, we'll handle that
            print("Failed to fetch network addresses for agent {}. Status: {}".format(agent_id, response.status_code))
        return [], response.status_code

    response_data = json_decode(response.body)

    if response_data.get('error', 1) != 0:
        print("Wazuh API error for agent {}: {}".format(agent_id, response_data.get('message', 'Unknown error')))
        return [], response.status_code

    return response_data.get('data', {}).get('affected_items', []), response.status_code


# --- NEW: Helper function to validate MAC addresses ---
def is_valid_mac(mac_address):
    """
    Checks if a MAC address is not a known invalid value.
    """
    if not mac_address:
        return False
    # List of known invalid MAC addresses
    invalid_macs = ["00:00:00:00:00:00", "ee:ee:ee:ee:ee:ee"]
    return mac_address.lower() not in invalid_macs


def is_kubernetes_interface(iface_name):
    """
    Checks if an interface name belongs to Kubernetes networking.
    These interfaces should be excluded as they contain virtual IPs
    for pods/services, not the actual host addresses.
   
    Args:
        iface_name: The name of the network interface
       
    Returns:
        True if the interface is a Kubernetes-related interface, False otherwise
    """
    if not iface_name:
        return False
   
    iface_lower = iface_name.lower()
   
    # Kubernetes IPVS interface - contains all service virtual IPs
    if iface_lower == "kube-ipvs0":
        return True
   
    # Kubernetes local DNS interface
    if iface_lower == "nodelocaldns":
        return True
   
    # Calico CNI interfaces (container networking)
    # These start with "cali" followed by a hash
    if iface_lower.startswith("cali"):
        return True
   
    # Calico VXLAN overlay interface
    if iface_lower.startswith("vxlan.calico"):
        return True
   
    # Flannel CNI interfaces
    if iface_lower.startswith("flannel"):
        return True
    if iface_lower == "cni0":
        return True
   
    # Docker bridge interface
    if iface_lower == "docker0":
        return True
   
    # Kubernetes bridge interfaces
    if iface_lower.startswith("cbr"):
        return True
   
    # Cilium CNI interfaces
    if iface_lower.startswith("cilium"):
        return True
    if iface_lower.startswith("lxc"):
        return True
   
    # Weave CNI interfaces
    if iface_lower.startswith("weave"):
        return True
    if iface_lower.startswith("vethwe"):
        return True
   
    # Generic veth interfaces (container virtual ethernet)
    if iface_lower.startswith("veth"):
        return True
   
    # Kubernetes dummy interfaces
    if iface_lower.startswith("kube-"):
        return True
   
    # IPVS-related interfaces
    if iface_lower.startswith("ipvs"):
        return True
   
    return False


def build_network_interface(network_interfaces_data, network_addresses_data, primary_ip_str):
    """
    Create a list of NetworkInterface objects from Wazuh network interface data.

    Args:
        network_interfaces_data: List of network interface dictionaries from Wazuh API (netiface endpoint).
        network_addresses_data: List of network address dictionaries from Wazuh API (netaddr endpoint).
        primary_ip_str: The primary IP address from the main agent data, as fallback.

    Returns:
        List of NetworkInterface objects
    """
    interfaces = []

    # Build a mapping of interface name to IP addresses
    # Skip Kubernetes-related interfaces to avoid adding virtual IPs
    iface_to_ips = {}
    for addr_data in network_addresses_data:
        iface_name = addr_data.get('iface', '')
        ip_addr_str = addr_data.get('address', '')
       
        # Skip Kubernetes interfaces (kube-ipvs0, cali*, nodelocaldns, etc.)
        if is_kubernetes_interface(iface_name):
            continue
       
        if iface_name and ip_addr_str:
            if iface_name not in iface_to_ips:
                iface_to_ips[iface_name] = []
            iface_to_ips[iface_name].append(ip_addr_str)

    # Process interfaces from syscollector data
    for interface_data in network_interfaces_data:
        iface_name = interface_data.get('name', '')
       
        # Skip Kubernetes interfaces (kube-ipvs0, cali*, nodelocaldns, etc.)
        if is_kubernetes_interface(iface_name):
            continue
       
        mac_address_string = interface_data.get('mac', "")
       
        # Split by space to handle multiple MACs
        macs = mac_address_string.split()

        for mac_address in macs:
            # Filter out invalid MAC addresses
            if is_valid_mac(mac_address):
                ip4s = []
                ip6s = []
               
                # Get IPs for this interface from netaddr data
                ip_addresses = iface_to_ips.get(iface_name, [])
               
                # If no IPs found for this interface, use primary IP as fallback
                if not ip_addresses and primary_ip_str:
                    ip_addresses = [primary_ip_str]
               
                # Parse and categorize IPs
                for ip_addr_str in ip_addresses:
                    if ip_addr_str:
                        ip_addr = ip_address(ip_addr_str)
                        if ip_addr.version == 4:
                            ip4s.append(ip_addr)
                        elif ip_addr.version == 6:
                            ip6s.append(ip_addr)
               
                interfaces.append(NetworkInterface(
                    macAddress=mac_address,
                    ipv4Addresses=ip4s,
                    ipv6Addresses=ip6s
                ))

    return interfaces

def manager_namespace(host):
    """Scope asset ids on the manager the agents are enrolled with.

    Wazuh agent ids are small per-manager ordinals, so nothing about `001` is
    unique outside one manager. Two Wazuh deployments imported into one runZero
    account would otherwise collide on every agent.
    """
    parsed = url_parse(host)
    if parsed and parsed.hostname:
        return parsed.hostname
    # url_parse returns None on a value it cannot parse; fall back to stripping
    # the scheme, any path, and the port by hand.
    bare = host.replace("https://", "").replace("http://", "")
    return bare.split("/")[0].split(":")[0]


def registration_key(date_add):
    """Reduce a registration timestamp to its digits, or "" when there is none.

    `dateAdd` is the agent's registration time and is what separates a recycled
    agent id from the agent that previously held it. Only the digits are kept so
    the id does not move if the API's rendering does -- Wazuh has shipped both
    `2026-01-15T09:00:00Z` and `2026-01-15 09:00:00` for this field, and both
    reduce to the same key here.
    """
    return re_sub(r"[^0-9]", "", str(date_add or ""))


def build_asset_id(namespace, agent_id, date_add):
    """Compose the foreign id for one agent.

    `agent.id` is the stable half: it is assigned once at registration, lives in
    the manager's `client.keys`, and is what every agent-scoped route is
    addressed by -- `/syscollector/{agent_id}/netiface` in this very script. It
    does NOT change when an agent rebalances onto a different cluster worker.
    `node_name` and `manager`, which the previous id was derived from, are the
    fields that DO change on a rebalance: Wazuh documents both as the node the
    agent is currently reporting to.

    `dateAdd` is the disambiguating half. Wazuh allocates agent ids from a
    counter seeded off the highest id in `client.keys`, so once the top-numbered
    agent is purged -- and `<auth><purge>` defaults to `yes` -- the next
    enrollment receives that same id. Registration time separates the new agent
    from the old one.
    """
    reg = registration_key(date_add)
    if reg:
        return "wazuh:{}:agent:{}:{}".format(namespace, agent_id, reg)
    # No registration data to pin the ordinal with. Still namespaced and still
    # deterministic, but this agent's id can be inherited by a later one.
    return "wazuh:{}:agent:{}".format(namespace, agent_id)

def parse_os_info(os_data):
    """
    Parse Wazuh OS information into standardized format.
    """
    if not os_data:
        return "Unknown", "Unknown"
   
    os_name = os_data.get('name', "")
    os_platform = os_data.get('platform', "")
    os_version = os_data.get('version', "")
   
    # Combine name and platform for better identification
    if os_platform and os_platform.lower() != os_name.lower():
        full_os_name = "{} ({})".format(os_name, os_platform)
    else:
        full_os_name = os_name
   
    return full_os_name, os_version

# REVISED FUNCTION: build_assets to use the new network interface data
def build_assets(agents, agent_net_interfaces, agent_net_addresses, namespace):
    """
    Convert Wazuh agent data into RunZero ImportAsset objects.

    Args:
        agents: List of agent dictionaries from Wazuh API
        agent_net_interfaces: A dictionary mapping agent ID to a list of its network interfaces.
        agent_net_addresses: A dictionary mapping agent ID to a list of its network addresses.
        namespace: The manager hostname, used to scope every foreign id.

    Returns:
        List of ImportAsset objects
    """
    assets = []
   
    for agent in agents:
        # print(agent)  # Uncomment for debugging
        agent_id = agent.get('id', "")
        if not agent_id:
            print("wazuh: skipping agent with no id: name=" + str(agent.get('name', '')))
            continue
        agent_name = agent.get('name', "")
        node_name = agent.get('node_name', '')
       
        # Get the primary IP from the main agent data
        agent_ip = agent.get('ip', "")
        agent_status = agent.get('status', "")
       
        # Parse OS information
        os_data = agent.get('os', {})
        os_name, os_version = parse_os_info(os_data)
       
        # Build network interface from the detailed network data
        net_interfaces_data = agent_net_interfaces.get(agent_id, [])
        net_addresses_data = agent_net_addresses.get(agent_id, [])
        network_interfaces = build_network_interface(net_interfaces_data, net_addresses_data, agent_ip)
       
        # Parse timestamps
        first_seen_ts = agent.get('dateAdd', '')
        last_seen_ts = agent.get('lastKeepAlive', '')
       
        # Build hostnames list with length validation
        hostnames = []
        if agent_name and agent_name != 'unknown-agent':
            hostname = agent_name
            if hostname:
                hostnames.append(hostname)
       
        # Prepare custom attributes with all available Wazuh data
        custom_attrs = {
            'wazuh_agent_id': str(agent_id),
            'wazuh_agent_status': agent_status,
            'wazuh_agent_version': agent.get('version', ''),
            'wazuh_agent_manager': agent.get('manager', ''),
            'wazuh_node_name': node_name,
            'wazuh_date_add': agent.get('dateAdd', ''),
            'wazuh_last_keep_alive': agent.get('lastKeepAlive', ''),
            'wazuh_group_config_status': agent.get('group_config_status', ''),
            'wazuh_groups': str(agent.get('group', [])),
            'wazuh_merged_sum': agent.get('mergedSum', ''),
            'wazuh_config_sum': agent.get('configSum', ''),
        }
       
        if first_seen_ts:
            custom_attrs['first_seen_timestamp'] = first_seen_ts
        if last_seen_ts:
            custom_attrs['last_seen_timestamp'] = last_seen_ts
       
        if os_data:
            custom_attrs.update({
                'os_arch': os_data.get('arch', ''),
                'os_codename': os_data.get('codename', ''),
                'os_major': os_data.get('major', ''),
                'os_minor': os_data.get('minor', ''),
                'os_platform': os_data.get('platform', ''),
                'os_uname': os_data.get('uname', ''),
            })
       
        date_add = agent.get('dateAdd', '')

        asset_params = {
            'id': build_asset_id(namespace, agent_id, date_add),
            'networkInterfaces': network_interfaces,
            'hostnames': hostnames,
            'os': os_name,
            'osVersion': os_version,
            'customAttributes': custom_attrs,
        }

        # Omitted rather than set to '' when the os block names no role: an
        # empty deviceType is still a value and displaces the type runZero would
        # otherwise derive for itself.
        device_type = device_type_for_os(os_data)
        if device_type:
            asset_params['deviceType'] = device_type

        # The runtime condition selects the asset type, which is what selects
        # the merge policy; CONFIG["assetTypeBehavior"] holds the reasoning for
        # both grades.
        if registration_key(date_add):
            asset_params['assetType'] = 'agent'
        else:
            asset_params['assetType'] = 'agent-unpinned'
            print("wazuh: agent {} reports no dateAdd; keeping default match behavior, since its ordinal could be reused".format(agent_id))
       
        asset = ImportAsset(**asset_params)
        if agent_status == "active":
            assets.append(asset)
   
    return assets

def main(**kwargs):
    """
    Main function to retrieve and return Wazuh asset data.

    Expected kwargs:
        hostname: Wazuh manager hostname or IP address (e.g., wazuh-manager or 10.1.2.3)
        port: Wazuh API port (defaults to 55000)
        username: Wazuh username
        password: Wazuh password

    Returns:
        List of ImportAsset objects
    """
    require(kwargs, "username", "password")
    wazuh_hostname = get_string(kwargs, "hostname", default="")
    port = get_int(kwargs, "port", default=55000)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    # CONFIG defaults are applied by the Console, not by the plain script
    # --kwargs path, so the default is repeated here.
    max_pages = get_int(kwargs, "max_pages", default=MAX_PAGES)
    if max_pages < 1:
        max_pages = MAX_PAGES

    # The API base was compiled in as https://<hostname>:<port>, which cannot
    # reach a manager behind a reverse proxy, on a path prefix, or on plain
    # http. An explicit url replaces the composed base entirely; hostname/port
    # stay as the fallback so existing configurations keep working unchanged.
    wazuh_url = (kwargs.get("url") or "").rstrip("/")
    if wazuh_url:
        wazuh_host = wazuh_url
    elif wazuh_hostname:
        wazuh_host = "https://{}:{}".format(wazuh_hostname, port)
    else:
        print("set either the Wazuh API URL or the manager hostname")
        return None

    namespace = manager_namespace(wazuh_host)
    print("Connecting to Wazuh at:", wazuh_host)
   
    # Authenticate with Wazuh
    token = authenticate_wazuh(wazuh_host, username, password, kwargs)
    if not token:
        print("Authentication to Wazuh failed; no token returned")
        return []

    # Retrieve agents
    agents = get_wazuh_agents(wazuh_host, token, kwargs, max_pages)
    if not agents:
        print("No agents retrieved from Wazuh")
        return []
   
    agent_net_interfaces = {}
    agent_net_addresses = {}
    print("Retrieving detailed network information for each agent...")

    # Enrich active agents with per-agent network data and stream them to
    # runZero in batches via report_assets so the full asset set is never held
    # in memory.
    reported = 0
    batch_size = 200
    batch = []

    for agent in agents:
        if agent.get('status') != "active":
            continue
        agent_id = agent.get('id')
        if agent_id:
            # Get network interfaces
            interfaces, status_code = get_agent_network_interfaces(wazuh_host, token, agent_id, kwargs)
           
            # Check if token expired (401), re-authenticate and retry
            if status_code == 401:
                print("Token expired, re-authenticating...")
                token = authenticate_wazuh(wazuh_host, username, password, kwargs)
                if not token:
                    print("Re-authentication failed, stopping network data collection")
                    break
                # Retry with new token
                interfaces, status_code = get_agent_network_interfaces(wazuh_host, token, agent_id, kwargs)
           
            if interfaces:
                agent_net_interfaces[agent_id] = interfaces
           
            # Get network addresses
            addresses, status_code = get_agent_network_addresses(wazuh_host, token, agent_id, kwargs)
           
            # Check if token expired (401), re-authenticate and retry
            if status_code == 401:
                print("Token expired, re-authenticating...")
                token = authenticate_wazuh(wazuh_host, username, password, kwargs)
                if not token:
                    print("Re-authentication failed, stopping network data collection")
                    break
                # Retry with new token
                addresses, status_code = get_agent_network_addresses(wazuh_host, token, agent_id, kwargs)
           
            if addresses:
                agent_net_addresses[agent_id] = addresses

        batch.append(agent)
        if len(batch) >= batch_size:
            reported += report_assets(build_assets(batch, agent_net_interfaces, agent_net_addresses, namespace))
            batch = []
            agent_net_interfaces = {}
            agent_net_addresses = {}

    if batch:
        reported += report_assets(build_assets(batch, agent_net_interfaces, agent_net_addresses, namespace))

    print("Successfully processed {} Wazuh agents into RunZero assets".format(reported))
    return None
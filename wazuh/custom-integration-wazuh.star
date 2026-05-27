load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get')
load('uuid', 'new_uuid')
load('base64', base64_encode='encode')
load('time', 'parse_time')

# --- Existing functions (no changes) ---

def authenticate_wazuh(host, username, password):
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

    response = http_post(auth_url, headers=headers, timeout=600)

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

def get_wazuh_agents(host, token):
    """
    Retrieve up to 10000 agents from Wazuh using pagination.

    Args:
        host: Wazuh host URL
        token: JWT authentication token

    Returns:
        List of agent dictionaries (limited to 10000)
    """
    agents_url = "{}/agents".format(host)
    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'application/json'
    }

    all_agents = []
    offset = 0
    hasNextPage = True
    limit = 500  # Maximum items per request

    while hasNextPage:

        params = {
            'offset': offset,
            'limit': limit
        }

        response = http_get(agents_url, headers=headers, params=params, timeout=600)

        if response.status_code != 200:
            print("Failed to fetch agents from Wazuh. Status:", response.status_code)
            break

        response_data = json_decode(response.body)

        if response_data.get('error', 1) != 0:
            print("Wazuh API error:", response_data.get('message', 'Unknown error'))
            break
        agents_batch = response_data.get('data', {}).get('affected_items', [])

        if not agents_batch:
            hasNextPage = False  # No more agents to fetch

        all_agents.extend(agents_batch)

        offset += limit

    print("Retrieved {} agents from Wazuh".format(len(all_agents)))
    return all_agents

# NEW FUNCTION: get network interfaces with MAC addresses
def get_agent_network_interfaces(host, token, agent_id):
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

    response = http_get(netiface_url, headers=headers, timeout=600)

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
def get_agent_network_addresses(host, token, agent_id):
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

    response = http_get(netaddr_url, headers=headers, insecure_skip_verify=True, timeout=600)

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

def extract_environment_from_node_name(node_name):
    """
    Extract environment from node name.
    Takes the 3rd element from the end when split by '-'.
   
    Examples:
        'wazuh3-worker-prod-sc2-03' -> 'prod'
        'wazuh3-worker-pp-rs-01' -> 'pp'
        'wazuh3-manager-pp-rs-01' -> 'pp'
   
    Args:
        node_name: The Wazuh node name string
       
    Returns:
        Environment string or empty string if not found
    """
    if not node_name:
        return ""
   
    parts = node_name.split('-')
   
    # Environment is the 3rd element from the end
    if len(parts) >= 3:
        return parts[-3]
   
    return ""

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
def build_assets(agents, agent_net_interfaces, agent_net_addresses):
    """
    Convert Wazuh agent data into RunZero ImportAsset objects.

    Args:
        agents: List of agent dictionaries from Wazuh API
        agent_net_interfaces: A dictionary mapping agent ID to a list of its network interfaces.
        agent_net_addresses: A dictionary mapping agent ID to a list of its network addresses.

    Returns:
        List of ImportAsset objects
    """
    assets = []
   
    for agent in agents:
        # print(agent)  # Uncomment for debugging
        agent_id = agent.get('id', "")
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
       
        # Create composite ID from environment and agent ID
        environment = extract_environment_from_node_name(node_name)
        if environment:
            composite_id = "{}-{}".format(environment, agent_id)
        else:
            composite_id = str(agent_id)
       
        asset_params = {
            'id': composite_id,
            'networkInterfaces': network_interfaces,
            'hostnames': hostnames,
            'os': os_name,
            'osVersion': os_version,
            'customAttributes': custom_attrs
        }
       
        asset = ImportAsset(**asset_params)
        if agent_status == "active":
            assets.append(asset)
   
    return assets

def main(**kwargs):
    """
    Main function to retrieve and return Wazuh asset data.

    Expected kwargs:
        access_key: Wazuh hostname or IP address (e.g., wazuh-manager or 10.1.2.3)
        access_secret: Wazuh credentials in format "username::password"

    Returns:
        List of ImportAsset objects
    """
    wazuh_hostname = kwargs.get('access_key')
    credentials = kwargs.get('access_secret')
   
    if not wazuh_hostname:
        print("Error: Wazuh hostname/IP not provided in access_key")
        return []
   
    if not credentials:
        print("Error: Wazuh credentials not provided in access_secret")
        return []
   
    if '::' not in credentials:
        print("Error: Credentials should be in format 'username::password'")
        return []
   
    username, password = credentials.split('::', 1)
   
    if not username or not password:
        print("Error: Invalid credentials format")
        return []
   
    wazuh_host = "https://{}:55000".format(wazuh_hostname)
   
    print("Connecting to Wazuh at:", wazuh_host)
   
    # Authenticate with Wazuh
    token = authenticate_wazuh(wazuh_host, username, password)
    if not token:
        print("Authentication to Wazuh failed; no token returned")
        return []

    # Retrieve agents
    agents = get_wazuh_agents(wazuh_host, token)
    if not agents:
        print("No agents retrieved from Wazuh")
        return []
   
    agent_net_interfaces = {}
    agent_net_addresses = {}
    print("Retrieving detailed network information for each agent...")
   
    for agent in agents:
        agent_id = agent.get('id')
        if agent_id:
            # Get network interfaces
            interfaces, status_code = get_agent_network_interfaces(wazuh_host, token, agent_id)
           
            # Check if token expired (401), re-authenticate and retry
            if status_code == 401:
                print("Token expired, re-authenticating...")
                token = authenticate_wazuh(wazuh_host, username, password)
                if not token:
                    print("Re-authentication failed, stopping network data collection")
                    break
                # Retry with new token
                interfaces, status_code = get_agent_network_interfaces(wazuh_host, token, agent_id)
           
            if interfaces:
                agent_net_interfaces[agent_id] = interfaces
           
            # Get network addresses
            addresses, status_code = get_agent_network_addresses(wazuh_host, token, agent_id)
           
            # Check if token expired (401), re-authenticate and retry
            if status_code == 401:
                print("Token expired, re-authenticating...")
                token = authenticate_wazuh(wazuh_host, username, password)
                if not token:
                    print("Re-authentication failed, stopping network data collection")
                    break
                # Retry with new token
                addresses, status_code = get_agent_network_addresses(wazuh_host, token, agent_id)
           
            if addresses:
                agent_net_addresses[agent_id] = addresses
   
    print("Retrieved network interfaces for {} agents".format(len(agent_net_interfaces)))
    print("Retrieved network addresses for {} agents".format(len(agent_net_addresses)))
   
    # Convert to RunZero assets
    assets = build_assets(agents, agent_net_interfaces, agent_net_addresses)
   
    print("Successfully processed {} Wazuh agents into RunZero assets".format(len(assets)))
    return assets
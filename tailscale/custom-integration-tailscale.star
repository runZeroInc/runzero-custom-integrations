# Tailscale API + OAuth2 Client -> runZero ImportAsset Integration
#
# Supports both:
#   - Direct API key (tskey-api-xxxxx)
#   - OAuth client credentials (access_key = client_id, access_secret = client_secret)
#
# Only two credential inputs are required:
#   access_key    : client_id (if OAuth) or unused for API key mode
#   access_secret : client_secret (if OAuth) or API key (tskey-api-xxxxx)
#
# Tailnet ID is defined below as a global variable.

load("runzero.types", "ImportAsset", "NetworkInterface")
load("json", json_decode="decode")
load("net", "ip_address")
load("http", http_get="get", http_post="post", "url_encode")
load("time", "parse_time")

# --- Configuration ---
TAILSCALE_API_BASE = "https://api.tailscale.com/api/v2"
TAILSCALE_TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
TAILNET_DEFAULT = "YOUR_TAILNET_ID"  # change to your tailnet ID, e.g. "T1234CNTRL"
DEFAULT_SCOPE = "devices:core:read"
INSECURE_SKIP_VERIFY_DEFAULT = False


def _log(msg):
    print("[TAILSCALE] " + msg)


def obtain_oauth_token(client_id, client_secret, scope, insecure_skip_verify):
    """
    Request an OAuth2 access token from Tailscale.
    """
    _log("Requesting OAuth2 token from Tailscale...")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    form = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }

    resp = http_post(
        url=TAILSCALE_TOKEN_URL,
        headers=headers,
        body=bytes(url_encode(form)),
        insecure_skip_verify=insecure_skip_verify,
    )

    if resp == None:
        _log("ERROR: No response from OAuth token endpoint.")
        return None

    _log("DEBUG: OAuth token response status: " + str(resp.status_code))
    if resp.status_code != 200:
        _log("ERROR: OAuth token request failed: " + str(resp.status_code))
        if resp.body != None:
            _log("ERROR: Response: " + str(resp.body))
        return None

    body = json_decode(resp.body)
    token = body.get("access_token")
    expires = body.get("expires_in")
    if token == None:
        _log("ERROR: Missing access_token in OAuth response.")
        return None

    _log("SUCCESS: Obtained access token (expires_in=" + str(expires) + "s)")
    return token


def tailscale_get_devices(access_token, tailnet, insecure_skip_verify):
    """
    Fetch device inventory for a tailnet using an access token or API key.
    Uses fields=all to get complete device information including clientConnectivity.
    """
    url = TAILSCALE_API_BASE + "/tailnet/" + tailnet + "/devices?fields=all"
    headers = {"Authorization": "Bearer " + access_token, "Accept": "application/json"}
    _log("DEBUG: Fetching devices from " + url)

    resp = http_get(url=url, headers=headers, insecure_skip_verify=insecure_skip_verify)
    if resp == None:
        _log("ERROR: No response from Tailscale devices endpoint.")
        return None

    _log("DEBUG: Devices response status: " + str(resp.status_code))

    if resp.status_code == 401:
        _log("ERROR: Unauthorized (401) - invalid or expired token.")
        return None
    if resp.status_code == 403:
        _log("ERROR: Forbidden (403) - insufficient permissions or missing scope.")
        if resp.body != None:
            _log("ERROR: Body: " + str(resp.body))
        return None
    if resp.status_code == 404:
        _log("ERROR: Not Found (404) - invalid tailnet ID.")
        return None
    if resp.status_code != 200:
        _log("ERROR: Unexpected status: " + str(resp.status_code))
        if resp.body != None:
            _log("ERROR: Body: " + str(resp.body))
        return None

    body = json_decode(resp.body)
    devices = body.get("devices", [])
    _log("SUCCESS: Retrieved " + str(len(devices)) + " devices.")
    return devices


def _clean_address(addr):
    """
    Remove CIDR notation from addresses (e.g., 10.0.0.1/32 -> 10.0.0.1)
    """
    if addr == None:
        return None
    parts = addr.split("/")
    return parts[0]


def _extract_ip_from_endpoint(endpoint):
    """
    Extract IP address from endpoint string (e.g., "129.222.196.154:63425" -> "129.222.196.154")
    Handles both IPv4 and IPv6 formats:
    - IPv4: 129.222.196.154:63425
    - IPv6: [2605:59c0:2959:8910:d1aa:3b0:5142:f680]:41641
    """
    if endpoint == None or endpoint == "":
        return None
    
    # IPv6 format: [address]:port
    if endpoint.startswith("["):
        end_bracket = endpoint.find("]")
        if end_bracket > 0:
            return endpoint[1:end_bracket]
    
    # IPv4 format: address:port
    colon_pos = endpoint.rfind(":")
    if colon_pos > 0:
        return endpoint[:colon_pos]
    
    return endpoint


def build_network_interface_from_addresses(addresses, mac):
    """
    Build NetworkInterface from Tailscale addresses (Tailscale IPs)
    """
    if addresses == None:
        return None
    ipv4s = []
    ipv6s = []
    for a in addresses:
        ipstr = _clean_address(a)
        if ipstr == None:
            continue
        ipobj = ip_address(ipstr)
        if ipobj == None:
            continue
        if ipobj.version == 4:
            ipv4s.append(ipobj)
        else:
            ipv6s.append(ipobj)
        if len(ipv4s) + len(ipv6s) >= 99:
            break
    if len(ipv4s) == 0 and len(ipv6s) == 0 and mac == None:
        return None
    return NetworkInterface(macAddress=mac, ipv4Addresses=ipv4s, ipv6Addresses=ipv6s)


def build_network_interfaces_from_endpoints(endpoints):
    """
    Build additional NetworkInterfaces from clientConnectivity endpoints.
    These are the actual physical IPs (public and private) that runZero can correlate with.
    """
    if endpoints == None or len(endpoints) == 0:
        return []
    
    ipv4s = []
    ipv6s = []
    
    for endpoint in endpoints:
        ipstr = _extract_ip_from_endpoint(endpoint)
        if ipstr == None:
            continue
        ipobj = ip_address(ipstr)
        if ipobj == None:
            continue
        if ipobj.version == 4:
            ipv4s.append(ipobj)
        else:
            ipv6s.append(ipobj)
        if len(ipv4s) + len(ipv6s) >= 99:
            break
    
    if len(ipv4s) == 0 and len(ipv6s) == 0:
        return []
    
    return [NetworkInterface(ipv4Addresses=ipv4s, ipv6Addresses=ipv6s)]


def transform_device_to_importasset(device, tailnet):
    device_id = device.get("id", "")
    hostname = device.get("hostname", device.get("name", ""))
    addresses = device.get("addresses", [])
    os_name = device.get("os", "Unknown")

    if device_id == "":
        return None

    # Build primary interface from Tailscale VPN addresses
    network_interfaces = []
    tailscale_netif = build_network_interface_from_addresses(addresses, None)
    if tailscale_netif != None:
        network_interfaces.append(tailscale_netif)

    attrs = {
        "source": "Tailscale Integration",
        "tailscale_device_id": device_id,
        "tailscale_tailnet": tailnet,
        "tailscale_user": device.get("user", ""),
        "tailscale_os": os_name,
        "tailscale_client_version": device.get("clientVersion", ""),
        "tailscale_authorized": str(device.get("authorized", False)),
        "tailscale_update_available": str(device.get("updateAvailable", False)),
        "tailscale_key_expiry_disabled": str(device.get("keyExpiryDisabled", False)),
        "tailscale_is_external": str(device.get("isExternal", False)),
        "tailscale_blocks_incoming_connections": str(device.get("blocksIncomingConnections", False)),
        "tailscale_created": device.get("created", ""),
    }

    # Extract clientConnectivity information (available with fields=all)
    client_conn = device.get("clientConnectivity")
    if client_conn != None:
        endpoints = client_conn.get("endpoints", [])
        if endpoints != None and len(endpoints) > 0:
            # Store raw endpoints for reference
            attrs["tailscale_client_endpoints"] = ", ".join(endpoints)
            
            # Build additional network interfaces from physical IPs for runZero correlation
            endpoint_interfaces = build_network_interfaces_from_endpoints(endpoints)
            network_interfaces.extend(endpoint_interfaces)
            _log("DEBUG: Added " + str(len(endpoint_interfaces)) + " endpoint interfaces for device " + device_id)
        
        derp = client_conn.get("derp", "")
        if derp != None and derp != "":
            attrs["tailscale_client_derp"] = derp
        
        mapping_varies = client_conn.get("mappingVariesByDestIP")
        if mapping_varies != None:
            attrs["tailscale_mapping_varies_by_dest_ip"] = str(mapping_varies)
        
        latency = client_conn.get("latency")
        if latency != None:
            for region, ms in latency.items():
                attrs["tailscale_latency_" + region] = str(ms)

    # Require at least one network interface for correlation
    if len(network_interfaces) == 0:
        _log("WARN: Skipping device " + device_id + " - no network interfaces available")
        return None

    parsed_time = device.get("created")
    if parsed_time != None and parsed_time != "":
        parsed = parse_time(parsed_time)
        if parsed != None:
            attrs["tailscale_created_ts"] = parsed.unix

    tags = device.get("tags", [])
    if tags != None and len(tags) > 0:
        attrs["tailscale_tags"] = ", ".join(tags)

    adv_routes = device.get("advertisedRoutes", [])
    if adv_routes != None and len(adv_routes) > 0:
        attrs["tailscale_advertised_routes"] = ", ".join(adv_routes)

    en_routes = device.get("enabledRoutes", [])
    if en_routes != None and len(en_routes) > 0:
        attrs["tailscale_enabled_routes"] = ", ".join(en_routes)

    asset_id = "tailscale-" + device_id
    hostnames = [hostname] if hostname != "" else []
    asset_tags = ["tailscale", "api"] + tags

    return ImportAsset(
        id=asset_id,
        hostnames=hostnames,
        networkInterfaces=network_interfaces,
        os=os_name,
        tags=asset_tags,
        customAttributes=attrs,
    )


def main(*args, **kwargs):
    _log("=== TAILSCALE API / OAUTH INTEGRATION ===")

    client_id = kwargs.get("access_key")  # used only for OAuth
    secret = kwargs.get("access_secret")  # API key or OAuth client_secret
    insecure_skip_verify = INSECURE_SKIP_VERIFY_DEFAULT

    if secret == None or secret == "":
        _log("ERROR: Missing required access_secret (API key or client secret).")
        return []

    # Detect auth type
    if client_id != None and client_id != "":
        _log("Detected OAuth client credentials mode.")
        token = obtain_oauth_token(client_id, secret, DEFAULT_SCOPE, insecure_skip_verify)
        if token == None:
            _log("ERROR: Failed to obtain OAuth access token.")
            return []
    else:
        _log("Detected API key mode.")
        token = secret

    tailnet = TAILNET_DEFAULT
    _log("Fetching devices for tailnet: " + tailnet)

    devices = tailscale_get_devices(token, tailnet, insecure_skip_verify)
    if devices == None or len(devices) == 0:
        _log("WARN: No devices found or API call failed.")
        return []

    assets = []
    for d in devices:
        ia = transform_device_to_importasset(d, tailnet)
        if ia != None:
            assets.append(ia)

    _log("SUCCESS: Prepared " + str(len(assets)) + " ImportAsset objects.")
    _log("=== INTEGRATION COMPLETE ===")
    return assets

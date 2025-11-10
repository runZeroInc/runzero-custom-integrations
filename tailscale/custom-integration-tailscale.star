# Tailscale API -> runZero ImportAsset Starlark integration (DEBUG VERSION)
# Uses a single API token or client secret (tskey-client-xxxxx / tskey-api-xxxxx)
#
# Required kwargs:
#   access_secret  : Tailscale API key or OAuth client secret
#   tailnet        : tailnet ID (e.g., T1234CNTRL or "-" for default)
# Optional:
#   insecure_skip_verify : bool (default False)

load("runzero.types", "ImportAsset", "NetworkInterface")
load("json", json_decode="decode")
load("net", "ip_address")
load("http", http_get="get")
load("time", "parse_time")

TAILSCALE_API_BASE = "https://api.tailscale.com/api/v2"
INSECURE_SKIP_VERIFY_DEFAULT = False


def _log(msg):
    print("[TAILSCALE] " + msg)


def tailscale_get_devices(api_token, tailnet, insecure_skip_verify):
    url = TAILSCALE_API_BASE + "/tailnet/" + tailnet + "/devices"
    headers = {
        "Authorization": "Bearer " + api_token,
        "Accept": "application/json"
    }
    _log("DEBUG: Fetching devices from " + url)

    resp = http_get(url=url, headers=headers, insecure_skip_verify=insecure_skip_verify)
    if resp == None:
        _log("ERROR: No response from Tailscale API.")
        return None

    _log("DEBUG: Devices response status: " + str(resp.status_code))

    if resp.status_code == 401:
        _log("ERROR: Unauthorized (401) - invalid or expired API token")
        return None
    if resp.status_code == 404:
        _log("ERROR: Tailnet '" + tailnet + "' not found")
        return None
    if resp.status_code != 200:
        _log("ERROR: Unexpected response " + str(resp.status_code))
        if resp.body != None:
            _log("ERROR: Body: " + str(resp.body))
        return None

    body = json_decode(resp.body)
    devices = body.get("devices", [])
    _log("SUCCESS: Retrieved " + str(len(devices)) + " devices.")
    if len(devices) > 0:
        _log("DEBUG: First device hostname: " + str(devices[0].get("hostname", "N/A")))
    return devices


def _clean_address(addr):
    if addr == None:
        return None
    parts = addr.split("/")
    return parts[0]


def build_network_interface_from_addresses(addresses, mac):
    ipv4s = []
    ipv6s = []

    if addresses == None:
        return None

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

    if len(ipv4s) == 0 and len(ipv6s) == 0:
        return None

    return NetworkInterface(macAddress=mac, ipv4Addresses=ipv4s, ipv6Addresses=ipv6s)


def transform_device_to_importasset(device, tailnet):
    device_id = device.get("id", "")
    hostname = device.get("hostname", device.get("name", ""))
    addresses = device.get("addresses", [])
    os_name = device.get("os", "Unknown")

    _log("DEBUG: Transforming device " + hostname + " (" + device_id + ")")

    if device_id == "" or len(addresses) == 0:
        _log("WARN: Skipping device missing id or addresses")
        return None

    network = build_network_interface_from_addresses(addresses, None)
    if network == None:
        return None

    attrs = {
        "source": "Tailscale API Integration",
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
        "tailscale_oauth_authentication": "false",
    }

    created_raw = device.get("created")
    if created_raw != None and created_raw != "":
        parsed = parse_time(created_raw)
        if parsed != None:
            attrs["tailscale_created_ts"] = parsed.unix

    tags = device.get("tags", [])
    if tags == None:
        tags = []
    if len(tags) > 0:
        attrs["tailscale_tags"] = ", ".join(tags)

    adv_routes = device.get("advertisedRoutes", [])
    if adv_routes != None and len(adv_routes) > 0:
        attrs["tailscale_advertised_routes"] = ", ".join(adv_routes)

    en_routes = device.get("enabledRoutes", [])
    if en_routes != None and len(en_routes) > 0:
        attrs["tailscale_enabled_routes"] = ", ".join(en_routes)

    asset_id = "tailscale-" + device_id
    hostnames = [hostname] if hostname != "" else []
    asset_tags = ["tailscale", "api-token"] + tags

    return ImportAsset(
        id=asset_id,
        hostnames=hostnames,
        networkInterfaces=[network],
        os=os_name,
        tags=asset_tags,
        customAttributes=attrs,
    )


def main(*args, **kwargs):
    _log("=== TAILSCALE API TOKEN INTEGRATION ===")
    _log("DEBUG: kwargs: " + str(kwargs.keys()))

    api_token = kwargs.get("access_secret")
    tailnet = kwargs.get("tailnet")
    if tailnet == None or tailnet == "":
        tailnet = "-"  # default tailnet
    insecure_skip_verify = kwargs.get("insecure_skip_verify")
    if insecure_skip_verify == None:
        insecure_skip_verify = INSECURE_SKIP_VERIFY_DEFAULT

    if api_token == None or api_token == "":
        _log("ERROR: Missing required 'access_secret' (API key)")
        return []

    _log("Starting Tailscale API sync for tailnet: " + tailnet)

    devices = tailscale_get_devices(api_token, tailnet, insecure_skip_verify)
    if devices == None:
        _log("ERROR: Failed to retrieve devices.")
        return []

    if len(devices) == 0:
        _log("WARN: No devices found.")
        return []

    assets = []
    for d in devices:
        ia = transform_device_to_importasset(d, tailnet)
        if ia != None:
            assets.append(ia)

    _log("SUCCESS: Prepared " + str(len(assets)) + " ImportAsset objects.")
    _log("=== INTEGRATION COMPLETE ===")
    return assets

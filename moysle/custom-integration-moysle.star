load('requests', 'Session')
load('json', json_encode='encode', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')

BASE_URL = "https://managerapi.mosyle.com/v2"


def parse_credentials(secret):
    """
    Parse access_secret provided as a dict or JSON string containing email/username and password.
    """
    if not secret:
        return None, None

    creds = secret
    if type(secret) == "string":
        print(creds)
        if secret.find("{") != -1:
            creds = json_decode(secret)
        elif secret.find(":") != -1:
            # Backward-compat for email:password format.
            email, password = secret.split(":", 1)
            if email and password:
                return email, password
            return None, None

    if type(creds) == "dict":
        email = creds.get("email") or creds.get("username")
        password = creds.get("password")
        if email and password:
            return email, password

    return None, None


def get_bearer_token(session, access_token, email, password):
    """
    Perform JWT login and return the bearer token from the Authorization header.
    """
    login_url = "{}/login".format(BASE_URL)
    payload = {
        "accessToken": access_token,
        "email": email,
        "password": password,
    }
    resp = session.post(login_url, body=bytes(json_encode(payload)))
    if not resp or resp.status_code != 200:
        print("Login failed: {}".format(resp.status_code if resp else "no response"))
        return None
    print("response: ", resp)
    auth_header = None
    if resp.headers:
        if "Authorization" in resp.headers:
            auth_header = resp.headers["Authorization"]
        elif "authorization" in resp.headers:
            auth_header = resp.headers["authorization"]

    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1]

    print("Login succeeded but bearer token missing from headers")
    return None


def build_network_interface(mac, ips):
    """
    Build a NetworkInterface from a MAC and list of IP strings.
    """
    ip4s = []
    ip6s = []
    for ip in ips:
        if not ip:
            continue
        addr = ip_address(ip)
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)

    if not mac and not ip4s and not ip6s:
        return None

    return NetworkInterface(macAddress=mac or None, ipv4Addresses=ip4s, ipv6Addresses=ip6s)


def collect_hostnames(device):
    names = []
    for key in ["device_name", "devicename", "HostName", "LocalHostName", "hostname"]:
        name = device.get(key, "")
        if name and name not in names:
            names.append(name)
    return names


def build_custom_attributes(device, used_keys):
    attrs = {}
    for key in device:
        if key in used_keys:
            continue
        value = device.get(key)
        if value == None:
            continue
        # Normalize lists and dicts to JSON strings; primitives to strings.
        if type(value) == "dict" or type(value) == "list":
            attrs[key] = json_encode(value)
        else:
            attrs[key] = "{}".format(value)
    return attrs


def main(*args, **kwargs):
    """
    Custom integration for importing Mosyle device inventory into runZero.
    Requires access_key (API token) and access_secret (JSON or dict with email/username and password).
    """
    api_token = kwargs.get("access_key")
    email, password = parse_credentials(kwargs.get("access_secret"))
    if not api_token or not email or not password:
        print("Missing required credentials")
        return []

    session = Session()
    session.headers.set("Content-Type", "application/json")
    session.headers.set("Accept", "application/json")
    session.headers.set("User-Agent", "runZeroCustomScript/1.0")

    bearer = get_bearer_token(session, api_token, email, password)
    if not bearer:
        return []

    session.headers.set("Authorization", "Bearer {}".format(bearer))

    assets = []
    page = 0

    while True:
        list_url = "{}/listdevices".format(BASE_URL)
        list_payload = {
            "accessToken": api_token,
            "options": {
                "os": "all",
                "page": page,
            },
        }

        device_resp = session.post(list_url, body=bytes(json_encode(list_payload)))
        if not device_resp or device_resp.status_code != 200:
            print("Device list request failed on page {}: {}".format(page, device_resp.status_code if device_resp else "no response"))
            break

        data = json_decode(device_resp.body)
        response = data.get("response", {})
        devices = response.get("devices", [])
        if not devices:
            break

        for d in devices:
            device_id = d.get("deviceudid") or d.get("serial_number") or ""
            if not device_id:
                continue

            hostnames = collect_hostnames(d)

            wifi_mac = d.get("wifi_mac_address")
            eth_mac = d.get("ethernet_mac_address")
            wifi_ips = []
            if d.get("last_ip_beat"):
                wifi_ips.append(d.get("last_ip_beat"))
            eth_ips = []
            if d.get("last_lan_ip"):
                eth_ips.append(d.get("last_lan_ip"))

            network_interfaces = []
            wifi_iface = build_network_interface(wifi_mac, wifi_ips)
            if wifi_iface:
                network_interfaces.append(wifi_iface)
            eth_iface = build_network_interface(eth_mac, eth_ips)
            if eth_iface:
                network_interfaces.append(eth_iface)

            model = d.get("device_model_name") or d.get("model_name") or d.get("device_model") or d.get("model") or ""
            os_name = d.get("os", "")
            os_version = d.get("osversion", "")

            used_keys = set([
                "deviceudid",
                "serial_number",
                "device_name",
                "devicename",
                "HostName",
                "LocalHostName",
                "hostname",
                "os",
                "osversion",
                "wifi_mac_address",
                "ethernet_mac_address",
                "last_ip_beat",
                "last_lan_ip",
                "device_model_name",
                "model_name",
                "device_model",
                "model",
            ])
            custom_attrs = build_custom_attributes(d, used_keys)

            asset = ImportAsset(
                id=device_id,
                hostnames=hostnames,
                os=os_name,
                osVersion=os_version,
                model=model,
                networkInterfaces=network_interfaces if network_interfaces else None,
                customAttributes=custom_attrs if custom_attrs else None,
            )
            assets.append(asset)

        page += 1

    return assets

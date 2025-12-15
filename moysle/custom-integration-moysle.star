load('requests', 'Session')
load('json', json_encode='encode', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('net', 'ip_address')
load('flatten_json', 'flatten')

BASE_URL = "https://managerapi.mosyle.com/v2"


def parse_credentials(secret):
    """
    Parse access_secret provided as a dict or JSON string containing email/username and password.
    """
    if not secret:
        return None, None

    creds = secret
    if type(secret) == "string":
        if secret.find("{") != -1:
            creds = json_decode(secret)
        else:
            print("access_secret must be a JSON string with email/password")
            return None, None

    if type(creds) == "dict":
        email = creds.get("email") or creds.get("username")
        password = creds.get("password")
        if email and password:
            return email, password
        else:
            print("Missing email or password in access_secret")
            return None, None

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
    auth_header = None
    if resp.headers:
        if "Authorization" in resp.headers:
            auth_header = resp.headers.get("Authorization", None)
        elif "authorization" in resp.headers:
            auth_header = resp.headers.get("authorization", None)

    if auth_header:
        print("Login succeeded with bearer token")
        return auth_header[0].split(" ")[1]
    else:
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
        # IPv6 has a %interface appended
        ip = ip.split("%")[0]
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
            safe_name = name.replace(" ", "-")
            names.append(safe_name)
    return names


def parse_tags(raw_tags, asset_tag):
    tags = []
    if raw_tags and type(raw_tags) == "string":
        for chunk in raw_tags.split(","):
            for part in chunk.split():
                part = part.strip()
                if part and part not in tags:
                    tags.append(part)
    if asset_tag and asset_tag not in tags:
        tags.append(asset_tag)
    return tags if tags else None


def build_custom_attributes(device, used_keys):
    flat = flatten(device)
    attrs = {}
    for key in flat:
        if key in used_keys:
            continue
        value = flat.get(key)
        if value == None:
            continue
        attrs[key] = "{}".format(value)
    return attrs if attrs else None


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

    for os_type in ["ios", "mac", "tvos", "visionos"]:
        print("Fetching {} devices".format(os_type))
        page = 0

        while True:
            list_url = "{}/listdevices".format(BASE_URL)
            list_payload = {
                "accessToken": api_token,
                "options": {
                    "os": os_type,
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
                
                if len(wifi_ips) > 0 and wifi_mac:
                    wifi_iface = build_network_interface(wifi_mac, wifi_ips)
                    network_interfaces.append(wifi_iface)
                
                if len(eth_ips) > 0 and eth_mac:
                    eth_iface = build_network_interface(eth_mac, eth_ips)
                    network_interfaces.append(eth_iface)

                model = d.get("device_model_name") or d.get("model_name") or d.get("device_model") or d.get("model") or ""
                os_name = d.get("os", "")
                os_version = d.get("osversion", "")
                tags = parse_tags(d.get("tags"), d.get("asset_tag"))

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
                    "tags",
                    "asset_tag",
                ])
                custom_attrs = build_custom_attributes(d, used_keys)

                asset = ImportAsset(
                    id=device_id,
                    hostnames=hostnames,
                    os=os_name,
                    osVersion=os_version,
                    model=model,
                    networkInterfaces=network_interfaces if network_interfaces else None,
                    tags=tags,
                    customAttributes=custom_attrs,
                )
                assets.append(asset)

            page += 1

    return assets

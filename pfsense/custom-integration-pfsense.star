load("runzero.types", "ImportAsset", "NetworkInterface")
load("json", json_decode="decode")
load("http", http_get="get")
load("net", "ip_address")

def _parse_bool(value, default_value):
    if value == None:
        return default_value
    if type(value) == "bool":
        return value
    if type(value) == "string":
        lower = value.lower()
        if lower in ["1", "true", "yes", "on"]:
            return True
        if lower in ["0", "false", "no", "off"]:
            return False
    return default_value

def _normalize_base_url(base_url):
    if not base_url:
        return ""
    return base_url.rstrip("/")

def _safe_decode_config(secret_value):
    if type(secret_value) != "string":
        return {}
    value = secret_value.strip()
    if not value or not value.startswith("{"):
        return {}
    decoded = json_decode(value)
    if type(decoded) != "dict":
        return {}
    return decoded

def build_network_interface(ips, mac):
    ip4s = []
    ip6s = []
    # Limit to 99 IPs to prevent excessive payload sizes
    for ip in ips[:99]:
        ip_addr = ip_address(ip)
        if ip_addr.version == 4:
            ip4s.append(ip_addr)
        elif ip_addr.version == 6:
            ip6s.append(ip_addr)
        else:
            continue

    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def _build_settings(kwargs):
    raw_access_key = kwargs.get("access_key", "")
    raw_access_secret = kwargs.get("access_secret", "")

    parsed_secret = _safe_decode_config(raw_access_secret)

    base_url = _normalize_base_url(parsed_secret.get("base_url", raw_access_key))

    api_token = raw_access_secret
    if len(parsed_secret) > 0:
        api_token = parsed_secret.get("access_secret", parsed_secret.get("api_token", ""))

    auth_header = parsed_secret.get("auth_header", "x-api-key")
    if type(auth_header) != "string":
        auth_header = "authorization"
    insecure_skip_verify = _parse_bool(parsed_secret.get("insecure_skip_verify", False), False)

    return {
        "base_url": base_url,
        "api_token": api_token,
        "auth_header": auth_header.lower(),
        "insecure_skip_verify": insecure_skip_verify,
    }

def _build_headers(api_token, auth_header):
    headers = {
        "Accept": "application/json",
    }

    if auth_header == "x-api-key":
        headers["X-API-Key"] = api_token
    elif auth_header == "api-key":
        headers["api_key"] = api_token
    else:
        headers["Authorization"] = "Bearer {}".format(api_token)

    return headers

def _request_json(url, headers, insecure_skip_verify):
    response = http_get(url=url, headers=headers, insecure_skip_verify=insecure_skip_verify)
    if response == None:
        return None, "no response", 0
    if response.status_code != 200:
        return None, "HTTP {}".format(response.status_code), response.status_code
    if not response.body:
        return None, "empty body", response.status_code

    decoded = json_decode(response.body)
    if type(decoded) != "dict":
        return None, "unexpected JSON shape", response.status_code

    # Some pfSense APIs wrap payloads under a top-level data object.
    if type(decoded.get("data")) == "dict":
        decoded = decoded.get("data")

    return decoded, "ok", response.status_code

def _pick(payload, keys, default_value):
    if payload == None:
        return default_value
    for key in keys:
        value = payload.get(key)
        if value != None and value != "":
            return value
    return default_value

def _extract_interfaces(payload):
    data = payload.get("data")
    if data == None:
        return []

    interfaces = []
    for item in data:
        interface = NetworkInterface()
        mac = item.get("macaddr")
        if mac != None and mac != "":
            interface.macAddress=mac

        ipv4 = item.get("ipaddr")
        if ipv4 != None and ipv4 != "":
            interface.ipv4Addresses=[ipv4]

        ipv6 = item.get("ipaddrv6")
        if ipv6 != None and ipv6 != "":
            interface.ipv6Addresses=[ipv6]

        interfaces.append(interface)

    return interfaces

def _sanitize_identifier(value):
    result = value
    replacements = ["https://", "http://", "/", ":", " "]
    for token in replacements:
        result = result.replace(token, "-")
    while "--" in result:
        result = result.replace("--", "-")
    return result.strip("-")

def get(settings, headers, path):
    url = settings.get("base_url") + path
    print("INFO: ", url)
    decoded, status_text, _ = _request_json(url, headers, settings.get("insecure_skip_verify"))
    if decoded != None:
        system_data = decoded
        endpoint_used = path

        return system_data, endpoint_used

def getVersion(settings, headers):
    system_data, _ = get(settings, headers, "/api/v2/system/version")
    platform = _pick(system_data, ["product_name", "name", "platform"], "pfSense")
    return platform, _pick(system_data, ["version", "product_version", "pf_version", "release"], "unknown")

def getHostInfo(settings, headers):
    system_data, _ = get(settings, headers, "/api/v2/system/hostname")
    return _pick(system_data, ["hostname", "host", "system_hostname"], ""), _pick(system_data, ["domain"], "")

def getInterfaces(settings, headers):
    system_data, _ = get(settings, headers, "/api/v2/status/interfaces")
    return _extract_interfaces(system_data)

def getSystemInfo(settings, headers):
    system_data, _ = get(settings, headers, "/api/v2/status/system")
    base_id = _pick(system_data, ["netgate_id"], settings.get("base_url"))
    model = _pick(system_data, ["product_name", "name", "platform"], "pfSense")
    serial = _pick(system_data, ["serial", "serial_number"], "")
    build = _pick(system_data, ["build_time", "builddate", "build"], "")
    return "pfsense-{}".format(_sanitize_identifier(base_id)), model, serial, build

def main(*args, **kwargs):
    settings = _build_settings(kwargs)
    if not settings.get("base_url"):
        print("ERROR: access_key must be the pfSense base URL, or include base_url in access_secret JSON.")
        return []
    if not settings.get("api_token"):
        print("ERROR: access_secret must be the API token, or include access_secret/api_token in access_secret JSON.")
        return []

    headers = _build_headers(settings.get("api_token"), settings.get("auth_header"))

    hostname, domain = getHostInfo(settings, headers)
    platform, version = getVersion(settings, headers)
    network_interfaces = getInterfaces(settings, headers)
    last_error = "unknown error"

    asset_id, model, serial, build_id = getSystemInfo(settings, headers)
    attrs = {
        "source": "pfSense REST API",
    }

    if serial:
        attrs["serial"] = serial

    if build_id:
        attrs["build"] = build_id


    return [ImportAsset(
        id=asset_id,
        domain=str(domain) if domain else "",
        hostnames=[hostname] if hostname else [],
        os=platform,
	trust_os=True,
        osVersion=str(version),
	trust_os_version=True,
        device_type="Firewall",
	trust_device_type=True,
        networkInterfaces=network_interfaces,
        customAttributes=attrs,
    )]


# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-pfsense",
    "name": "pfSense",
    "type": "inbound",
    "description": "Imports firewall objects and DHCP leases from pfSense.",
    "version": "26052700",
    "params": [
        {
            "key": "base_url",
            "label": "pfSense base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://pfsense.example.com",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
        },
        {
            "key": "auth_header",
            "label": "Auth header name",
            "type": "string",
            "required": False,
            "default": "X-API-Key",
            "description": "Header used to send the API token",
        },
        {
            "key": "legacy_credentials",
            "label": "Legacy JSON credential",
            "type": "secret",
            "required": False,
            "group": "Legacy",
            "description": "Back-compat: JSON object containing base_url, api_token, auth_header, insecure_skip_verify",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load("runzero.types", "ImportAsset", "NetworkInterface", "to_custom_attributes")
load("json", json_decode="decode")
load("http", "get_json", "bearer")
load("kwargs", "get_http_options", "get_http_tls")
load("net", "network_interface")
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

def _build_settings(kwargs):
    legacy_credentials = kwargs.get("legacy_credentials", "")

    parsed_secret = _safe_decode_config(legacy_credentials)

    # Prefer structured top-level kwargs and fall back to legacy JSON credentials.
    base_url = _normalize_base_url(
        kwargs.get("base_url", "")
        or parsed_secret.get("base_url", ""),
    )

    api_token = kwargs.get("api_token", "")
    if not api_token:
        if len(parsed_secret) > 0:
            api_token = parsed_secret.get("api_token", "")
        else:
            api_token = legacy_credentials

    auth_header = kwargs.get("auth_header", "") or parsed_secret.get("auth_header", "x-api-key")
    if type(auth_header) != "string":
        auth_header = "authorization"

    insecure_skip_verify = _parse_bool(
        kwargs.get("insecure_skip_verify", parsed_secret.get("insecure_skip_verify", False)),
        False,
    )

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
        headers["Authorization"] = bearer(api_token)

    return headers

def _request_json(url, http_options):
    decoded, err = get_json(url=url, **http_options)
    if err:
        return None, err, 0
    if decoded == None:
        return None, "empty body", 0
    if type(decoded) != "dict":
        return None, "unexpected JSON shape", 0

    # Some pfSense APIs wrap payloads under a top-level data object.
    if type(decoded.get("data")) == "dict":
        decoded = decoded.get("data")

    return decoded, "ok", 200

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

def get(settings, http_options, path):
    url = settings.get("base_url") + path
    print("INFO: ", url)
    decoded, status_text, _ = _request_json(url, http_options)
    if decoded != None:
        system_data = decoded
        endpoint_used = path

        return system_data, endpoint_used

def getVersion(settings, http_options):
    system_data, _ = get(settings, http_options, "/api/v2/system/version")
    platform = _pick(system_data, ["product_name", "name", "platform"], "pfSense")
    return platform, _pick(system_data, ["version", "product_version", "pf_version", "release"], "unknown")

def getHostInfo(settings, http_options):
    system_data, _ = get(settings, http_options, "/api/v2/system/hostname")
    return _pick(system_data, ["hostname", "host", "system_hostname"], ""), _pick(system_data, ["domain"], "")

def getInterfaces(settings, http_options):
    system_data, _ = get(settings, http_options, "/api/v2/status/interfaces")
    return _extract_interfaces(system_data)

def getSystemInfo(settings, http_options):
    system_data, _ = get(settings, http_options, "/api/v2/status/system")
    base_id = _pick(system_data, ["netgate_id"], settings.get("base_url"))
    model = _pick(system_data, ["product_name", "name", "platform"], "pfSense")
    serial = _pick(system_data, ["serial", "serial_number"], "")
    build = _pick(system_data, ["build_time", "builddate", "build"], "")
    return "pfsense-{}".format(_sanitize_identifier(base_id)), model, serial, build

def main(*args, **kwargs):
    settings = _build_settings(kwargs)
    if not settings.get("base_url"):
        print("ERROR: base_url is required, or include base_url in legacy_credentials JSON.")
        return []
    if not settings.get("api_token"):
        print("ERROR: api_token is required, or include api_token in legacy_credentials JSON.")
        return []

    headers = _build_headers(settings.get("api_token"), settings.get("auth_header"))
    tls = get_http_tls(kwargs)
    if settings.get("insecure_skip_verify"):
        tls["insecure"] = True
    http_options = get_http_options(kwargs, headers=headers)
    http_options["tls"] = tls

    hostname, domain = getHostInfo(settings, http_options)
    platform, version = getVersion(settings, http_options)
    network_interfaces = getInterfaces(settings, http_options)
    last_error = "unknown error"

    asset_id, model, serial, build_id = getSystemInfo(settings, http_options)
    attrs = {
        "source": "pfSense REST API",
    }

    if serial:
        attrs["serial"] = serial

    if build_id:
        attrs["build"] = build_id


    # Stream the asset to runZero via report_assets instead of returning a list.
    report_assets(ImportAsset(
        id=asset_id,
        domain=str(domain) if domain else "",
        hostnames=[hostname],
        os=platform,
	trust_os=True,
        osVersion=str(version),
	trust_os_version=True,
        device_type="Firewall",
	trust_device_type=True,
        networkInterfaces=network_interfaces,
        customAttributes=to_custom_attributes(attrs),
    ))
    return None


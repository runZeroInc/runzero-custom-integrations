# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-tailscale",
    "name": "Tailscale",
    "type": "inbound",
    "description": "Imports devices from a Tailscale tailnet.",
    "version": "26052700",
    "params": [
        {
            "key": "url",
            "label": "Tailscale API URL",
            "type": "url",
            "required": False,
            "default": "https://api.tailscale.com",
        },
        {
            "key": "tailnet",
            "label": "Tailnet",
            "type": "string",
            "required": True,
            "pattern": "[a-zA-Z0-9][a-zA-Z0-9_.@-]*",
            "description": "Tailnet ID or name, for example T1234CNTRL or example.com",
        },
        {
            "key": "client_id",
            "label": "OAuth client ID",
            "type": "string",
            "required": False,
            "description": "Leave blank to use a plain API key",
        },
        {
            "key": "api_key_or_client_secret",
            "label": "API key / OAuth client secret",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# Tailscale API + OAuth2 Client -> runZero ImportAsset Integration
#
# Supports both:
#   - Direct API key (tskey-api-xxxxx)
#   - OAuth client credentials (client_id + api_key_or_client_secret)
#
# Credential inputs:
#   url           : API host, defaulting to https://api.tailscale.com
#   tailnet       : tailnet ID or name
#   client_id                 : OAuth client ID, or blank for API key mode
#   api_key_or_client_secret  : OAuth client secret, or API key (tskey-api-xxxxx)

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "bearer", "oauth2_token")
load("kwargs", "get_url_base", "get_http_options")
load("time", "parse_time")

# --- Configuration ---
TAILSCALE_API_PATH = "/api/v2"
TAILSCALE_TOKEN_PATH = "/api/v2/oauth/token"
DEFAULT_SCOPE = "devices:core:read"


def _log(msg):
    print("[TAILSCALE] " + msg)


def tailscale_get_devices(api_base_url, access_token, tailnet, config_kwargs):
    """Fetch device inventory for a tailnet using an access token or API key."""
    url = api_base_url + "/tailnet/" + tailnet + "/devices?fields=all"
    data, err = get_json(url, **get_http_options(config_kwargs, headers={"Authorization": bearer(access_token), "Accept": "application/json"}))
    if err:
        _log("ERROR: " + err)
        return None
    return data.get("devices", [])


def transform_device_to_importasset(device, tailnet):
    device_id = device.get("id", "")
    if device_id == "":
        return None

    hostname = device.get("hostname", device.get("name", ""))
    os_name = device.get("os", "Unknown")

    # Build primary interface from the device's Tailscale (VPN) addresses.
    # network_interface() handles v4/v6 classification, port/CIDR stripping,
    # dedupe, and capping at 99 addresses per family.
    nics = []
    tailscale_nic = network_interface(ips=device.get("addresses", []))
    if tailscale_nic:
        nics.append(tailscale_nic)

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

    client_conn = device.get("clientConnectivity")
    if client_conn:
        endpoints = client_conn.get("endpoints") or []
        if endpoints:
            attrs["tailscale_client_endpoints"] = ", ".join(endpoints)
            # Physical IPs (public + private). network_interface() also
            # strips "addr:port" and "[ipv6]:port" forms automatically.
            phys_nic = network_interface(ips=endpoints)
            if phys_nic:
                nics.append(phys_nic)

        derp = client_conn.get("derp", "")
        if derp:
            attrs["tailscale_client_derp"] = derp

        mapping_varies = client_conn.get("mappingVariesByDestIP")
        if mapping_varies != None:
            attrs["tailscale_mapping_varies_by_dest_ip"] = str(mapping_varies)

        latency = client_conn.get("latency")
        if latency:
            for region, ms in latency.items():
                attrs["tailscale_latency_" + region] = str(ms)

    if len(nics) == 0:
        _log("WARN: Skipping device " + device_id + " - no network interfaces available")
        return None

    created = device.get("created")
    if created:
        parsed = parse_time(created)
        if parsed != None:
            attrs["tailscale_created_ts"] = parsed.unix

    tags = device.get("tags") or []
    if tags:
        attrs["tailscale_tags"] = ", ".join(tags)

    for field in ("advertisedRoutes", "enabledRoutes"):
        vals = device.get(field) or []
        if vals:
            attrs["tailscale_" + field] = ", ".join(vals)

    return ImportAsset(
        id="tailscale-" + device_id,
        hostnames=[hostname],
        networkInterfaces=nics,
        os=os_name,
        tags=["tailscale", "api"] + tags,
        customAttributes=to_custom_attributes(attrs),
    )


def main(*args, **kwargs):
    _log("=== TAILSCALE API / OAUTH INTEGRATION ===")

    client_id = kwargs.get("client_id")
    secret = kwargs.get("api_key_or_client_secret")
    base_url = get_url_base(kwargs, default="https://api.tailscale.com")
    api_url = base_url + TAILSCALE_API_PATH
    token_url = base_url + TAILSCALE_TOKEN_PATH
    tailnet = (kwargs.get("tailnet") or "").strip()

    if not secret:
        _log("ERROR: Missing required api_key_or_client_secret (API key or client secret).")
        return []
    if not tailnet:
        _log("ERROR: Missing required tailnet ID or name.")
        return []

    # If a client_id was supplied, exchange it for an OAuth access token;
    # otherwise treat `secret` as a long-lived API key.
    if client_id:
        _log("Detected OAuth client credentials mode.")
        token = oauth2_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=secret,
            scope=DEFAULT_SCOPE,
            **get_http_options(kwargs)
        )
    else:
        _log("Detected API key mode.")
        token = secret

    devices = tailscale_get_devices(api_url, token, tailnet, kwargs) or []
    if not devices:
        _log("WARN: No devices found or API call failed.")
        return []

    assets = []
    for d in devices:
        ia = transform_device_to_importasset(d, tailnet)
        if ia != None:
            assets.append(ia)

    _log("SUCCESS: Prepared " + str(len(assets)) + " ImportAsset objects.")
    return assets

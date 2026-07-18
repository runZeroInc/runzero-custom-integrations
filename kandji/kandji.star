# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-kandji",
    "name": "Kandji",
    "type": "inbound",
    "description": "Imports devices from Kandji.",
    "version": "26061000",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "url",
            "label": "Kandji API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<subdomain>.api.kandji.io/api/v1",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
## Kandji

load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('net', 'network_interface')

PAGE_LIMIT = 300  # Number of devices to fetch per request

def _auth_headers(api_token):
    return {
        "Authorization": bearer(api_token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def stream_devices(api_url, api_token, config_kwargs):
    """Fetch devices from Kandji with pagination, building and streaming each
    page of assets (including per-device details) via report_assets so the full
    device set is never held in memory. Returns the number of assets reported."""
    headers = _auth_headers(api_token)
    http_options = get_http_options(config_kwargs, headers=headers)
    reported = 0
    offset = 0
    while True:
        params = {"limit": str(PAGE_LIMIT), "offset": str(offset)}
        data, err = get_json(api_url + "/devices", params=params, **http_options)
        if err:
            print("Error fetching device list from Kandji:", err)
            break
        if not data:
            break
        reported += report_assets(build_assets(api_url, api_token, data, config_kwargs))
        offset += PAGE_LIMIT
    return reported

def get_device_details(api_url, api_token, device_id, config_kwargs):
    """Fetch detailed information for a single device."""
    url = "{}/devices/{}/details".format(api_url, device_id)
    data, err = get_json(url, **get_http_options(config_kwargs, headers=_auth_headers(api_token)))
    if err:
        print("Error fetching details for device:", device_id, err)
        return None
    return data

def build_assets(api_url, api_token, devices, config_kwargs):
    """Transform a page of Kandji devices into runZero assets."""
    assets = []

    for device in devices:
        device_id = device.get("device_id", "")
        details = get_device_details(api_url, api_token, device_id, config_kwargs)
        if not details:
            continue

        general = details.get("general", {}) or {}
        network = details.get("network", {}) or {}
        hardware = details.get("hardware_overview", {}) or {}

        # network_interface() classifies v4/v6 automatically, strips
        # ports/zones, dedupes, and returns None when nothing usable
        # is present.
        ips = []
        for key in ("ip_address", "public_ip"):
            v = network.get(key)
            if v:
                if type(v) == "list":
                    ips.extend(v)
                else:
                    ips.append(v)
        nic = network_interface(mac=network.get("mac_address"), ips=ips)
        nics = [nic] if nic else []

        assets.append(ImportAsset(
            id=device_id,
            hostnames=[network.get("local_hostname", "")],
            networkInterfaces=nics,
            os=general.get("model", ""),
            os_version=general.get("os_version", ""),
            customAttributes=to_custom_attributes({
                "model": general.get("model"),
                "serial_number": hardware.get("serial_number"),
            }),
        ))

    return assets

def main(**kwargs):
    api_url = kwargs['url'].rstrip('/')
    api_token = kwargs['api_token']
    # Devices (and their details) are streamed page-by-page via report_assets.
    reported = stream_devices(api_url, api_token, kwargs)
    if not reported:
        print("No assets found in Kandji")
    return None

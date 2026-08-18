# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-ubiquiti-unifi-network",
    "name": "Ubiquiti UniFi Network",
    "type": "inbound",
    "description": "Imports devices from a UniFi Network controller.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # The controller's id is authoritative, so it drives the merge --
    # and the network identifiers must not veto one. A Wi-Fi client
    # that re-randomizes its per-SSID MAC, or picks up a new lease,
    # is the same client under the same id and has to land on the
    # same asset.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "UniFi controller URL",
            "type": "url",
            "required": True,
            "placeholder": "https://controller.example.com",
        },
        {
            "key": "site_name",
            "label": "Site name",
            "type": "string",
            "required": False,
            "default": "Default",
        },
        {
            "key": "extract_clients",
            "label": "Extract clients",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "extract_devices",
            "label": "Extract devices",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "client_api_filter",
            "label": "Client API filter",
            "type": "string",
            "required": False,
        },
        {
            "key": "page_limit",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 1000,
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
#
# runZero Starlark script for Ubiquiti UniFi Network Integration API
#
# This version adds the ability to extract UniFi network devices (switches, APs)
# and provides toggles to enable/disable client and device extraction.
#

# Load necessary runZero and Starlark libraries
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', url_encode='url_encode')
load('kwargs', 'get_url_base', 'get_http_options', 'get_bool', 'get_string', 'get_int')
load('time', 'parse_time')
load('re', re_match='match')

# parse_time aborts the script on anything it cannot parse, and Starlark has no
# exception handling, so a timestamp is screened against this before the call.
TIMESTAMP_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"

DEFAULT_SITE_NAME = "Default"
DEFAULT_EXTRACT_CLIENTS = True
DEFAULT_EXTRACT_DEVICES = True
DEFAULT_CLIENT_API_FILTER = ""
DEFAULT_PAGE_LIMIT = 100

VENDOR = "unifi"

# The UniFi id is issued by the controller and survives the churn that MAC-based
# identity cannot: a Wi-Fi client re-randomizing its per-SSID MAC keeps its `id`.
# The id is scoped to the site it was issued under, so the site id is part of the
# key -- both endpoints are addressed as /sites/{siteId}/{clients,devices}. That
# also namespaces the value, so two controllers imported into one runZero account
# cannot collide.
def asset_id(site_id, kind, record_id):
    return "{}:{}:{}:{}".format(VENDOR, site_id, kind, record_id)

# A record with no id, or no MAC, cannot be imported: the id is the asset
# identity and the MAC is the only thing left to correlate on. Both are counted
# by cause -- with one example kept for diagnosis -- rather than logged per
# record, so a controller full of unusable records costs two lines, not
# thousands. Skips accumulate across pages and are reported once at the end.
def _new_skips():
    return {"no_id": 0, "no_mac": 0, "first_no_id": "", "first_no_mac": ""}

def _tally_skip(skips, cause, example):
    skips[cause] += 1
    if skips[cause] == 1:
        skips["first_" + cause] = example

def _report_skips(skips, kind):
    if skips["no_id"] > 0:
        print("unifi: skipped {} {} with no id (first mac: {})".format(
            skips["no_id"], kind, skips["first_no_id"]))
    if skips["no_mac"] > 0:
        print("unifi: skipped {} {} with no MAC (first name: {})".format(
            skips["no_mac"], kind, skips["first_no_mac"]))

def get_site_id(base_url, api_key, site_name, config_kwargs):
    """
    Finds the UUID for a given site name.
    """
    sites_url = base_url + "/proxy/network/integration/v1/sites"
    headers = { "X-API-KEY": api_key, "Accept": "application/json" }
    
    print("unifi: looking up the ID for site '{}'".format(site_name))
    response_json, err = get_json(url=sites_url, **get_http_options(config_kwargs, headers=headers))

    if err:
        print("unifi: failed to get the sites list: {}".format(err))
        return None

    if type(response_json) != "dict" or "data" not in response_json:
        print("unifi: the API did not return a valid sites object")
        return None
    
    for site in response_json.get("data", []):
        if site.get("name") == site_name:
            site_id = site.get("id")
            print("unifi: found site ID {}".format(site_id))
            return site_id
            
    print("unifi: no site is named '{}'".format(site_name))
    return None

def get_all_clients(base_url, api_key, site_id, page_limit, client_filter, config_kwargs):
    """
    Fetches all client devices from the UniFi API, building and streaming each
    page of assets via report_assets so the full client set is never buffered.
    Returns the number of client assets reported.
    """
    reported = 0
    offset = 0
    # Drops are tallied across every page and reported once at the end, so a
    # controller full of unusable records cannot turn into a line per record.
    skips = _new_skips()

    while True:
        params = {"offset": str(offset), "limit": str(page_limit)}

        if client_filter:
            params["filter"] = client_filter
            
        clients_url = base_url + "/proxy/network/integration/v1/sites/{}/clients?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=clients_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            print("unifi: failed to retrieve clients: {}".format(err))
            break
        if type(response_json) != "dict":
            print("unifi: the API did not return a valid JSON object while fetching clients")
            break
        
        clients_batch = response_json.get("data", [])
        if not clients_batch:
            break
        
        reported += report_assets(build_client_assets(clients_batch, site_id, skips))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(clients_batch)
        print("unifi: fetched {}/{} clients".format(current_count, total_count))

        if current_count >= total_count:
            break

        offset += page_limit

    _report_skips(skips, "clients")
    return reported

def get_all_devices(base_url, api_key, site_id, page_limit, config_kwargs):
    """
    Fetches all network devices (switches, APs, etc.) from the UniFi API,
    building and streaming each page of assets via report_assets. Returns the
    number of device assets reported.
    """
    reported = 0
    offset = 0
    skips = _new_skips()

    while True:
        params = {"offset": str(offset), "limit": str(page_limit)}
        devices_url = base_url + "/proxy/network/integration/v1/sites/{}/devices?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=devices_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            print("unifi: failed to retrieve devices: {}".format(err))
            break
        if type(response_json) != "dict":
            print("unifi: the API did not return a valid JSON object while fetching devices")
            break
        
        devices_batch = response_json.get("data", [])
        if not devices_batch:
            break
        
        reported += report_assets(build_device_assets(devices_batch, site_id, skips))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(devices_batch)
        print("unifi: fetched {}/{} devices".format(current_count, total_count))

        if current_count >= total_count:
            break

        offset += page_limit

    _report_skips(skips, "devices")
    return reported

def build_client_assets(clients_json, site_id, skips):
    """
    Converts client data from UniFi into a list of runZero ImportAsset objects.
    """
    assets = []
    for client in clients_json:
        client_id = client.get("id")
        if not client_id:
            _tally_skip(skips, "no_id", str(client.get("macAddress", "")))
            continue

        mac = client.get("macAddress")
        hostname = client.get("name")

        if mac and hostname:
            mac_parts = mac.split(":")
            if len(mac_parts) == 6:
                mac_suffix = " " + ":".join(mac_parts[4:])
                if hostname.endswith(mac_suffix):
                    hostname = hostname.removesuffix(mac_suffix)

        # A client the controller cannot name a MAC for has nothing this
        # integration can correlate on beyond a lease address it may already have
        # handed to something else, so it is dropped rather than imported.
        if not mac:
            _tally_skip(skips, "no_mac", str(hostname or ""))
            continue

        ip = client.get("ipAddress")
        ips = [ip] if ip else []
        # network_interface returns None when neither the MAC nor any address
        # parses, and passing [None] to ImportAsset aborts the entire run.
        network = network_interface(ips=ips, mac=mac)
        interfaces = [network] if network else []
        hostnames=[hostname]

        # The controller omits connectedAt for a client it has a record of but
        # no active session -- a wired client seen only in the ARP table, or one
        # whose session predates a controller restart. parse_time(None) aborted
        # the script with "parse_time: got NoneType, want string" and took the
        # whole import down with it, so the value is screened before the call
        # and connectedAt.unix is only dereferenced when it parsed.
        connected_at_raw = client.get("connectedAt")
        connectedAt = None
        if type(connected_at_raw) == "string" and re_match(TIMESTAMP_RE, connected_at_raw):
            connectedAt = parse_time(connected_at_raw)

        custom_attrs = {
            "unifi_id": client_id,
            "unifi_site_id": site_id,
            "connectionType": client.get("type", ""),
            "uplinkDeviceId": client.get("uplinkDeviceId", "")
        }
        if connectedAt != None:
            custom_attrs["connectedAt"] = connectedAt
            custom_attrs["connectedAtTS"] = connectedAt.unix

        assets.append(
            ImportAsset(
                id=asset_id(site_id, "client", client_id),
                hostnames=hostnames,
                networkInterfaces=interfaces,
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )
    return assets

def build_device_assets(devices_json, site_id, skips):
    """
    Converts UniFi device data into a list of runZero ImportAsset objects.
    """
    assets = []
    for device in devices_json:
        device_id = device.get("id")
        if not device_id:
            _tally_skip(skips, "no_id", str(device.get("macAddress", "")))
            continue

        mac = device.get("macAddress")
        if not mac:
            _tally_skip(skips, "no_mac", str(device.get("name", "") or ""))
            continue

        ip = device.get("ipAddress")
        ips = [ip] if ip else []
        # network_interface returns None when neither the MAC nor any address
        # parses, and passing [None] to ImportAsset aborts the entire run.
        network = network_interface(ips=ips, mac=mac)
        interfaces = [network] if network else []

        hostname = device.get("name")
        hostnames=[hostname]

        model = device.get("model", "UniFi Device")
        # "Unknown" is not one of runZero's device types, so asserting it
        # overwrites whatever the platform's own fingerprinting worked out with a
        # value that means nothing. An unrecognised model leaves the field unset
        # instead, which lets runZero keep its own answer.
        device_type = None
        # Attempt to determine a more specific device type from the model name
        if "USW" in model:
            device_type = "Switch"
        elif "UAP" in model or "U6" in model:
            device_type = "WAP"
        elif "UDM" in model or "USG" in model:
            device_type = "Gateway"

        custom_attrs = {
            "unifi_id": device_id,
            "unifi_site_id": site_id,
            "unifi_state": device.get("state", ""),
            "unifi_features": ", ".join(device.get("features", [])),
            "unifi_interfaces": ", ".join(device.get("interfaces", []))
        }

        assets.append(
            ImportAsset(
                id=asset_id(site_id, "device", device_id),
                hostnames=hostnames,
                networkInterfaces=interfaces,
                manufacturer="Ubiquiti",
                model=model,
                deviceType=device_type,
                # Same reasoning as clients: the controller's id is the
                # authoritative key, and a management-VLAN address change or a
                # rename must not disqualify the merge onto the existing asset.
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )
    return assets


def main(**kwargs):
    """
    The main entrypoint for the runZero custom integration script.
    """
    base_url = get_url_base(kwargs)
    site_name = get_string(kwargs, "site_name", DEFAULT_SITE_NAME)
    extract_clients = get_bool(kwargs, "extract_clients", DEFAULT_EXTRACT_CLIENTS)
    extract_devices = get_bool(kwargs, "extract_devices", DEFAULT_EXTRACT_DEVICES)
    client_filter = get_string(kwargs, "client_api_filter", DEFAULT_CLIENT_API_FILTER)
    page_limit = get_int(kwargs, "page_limit", DEFAULT_PAGE_LIMIT)

    api_key = kwargs.get('api_key')

    if not api_key:
        print("unifi: api_key is required")
        return None

    # 1. Find the Site ID from the Site Name
    site_id = get_site_id(base_url, api_key, site_name, kwargs)
    if not site_id:
        return None

    total = 0

    # 2. Get and process clients if enabled
    if extract_clients:
        client_count = get_all_clients(base_url, api_key, site_id, page_limit, client_filter, kwargs)
        print("unifi: reported {} client assets".format(client_count))
        total += client_count
    else:
        print("unifi: client import is disabled (extract_clients is False)")

    # 3. Get and process devices if enabled
    if extract_devices:
        device_count = get_all_devices(base_url, api_key, site_id, page_limit, kwargs)
        print("unifi: reported {} device assets".format(device_count))
        total += device_count
    else:
        print("unifi: device import is disabled (extract_devices is False)")

    print("unifi: reported {} assets".format(total))
    # Assets are streamed via report_assets above; nothing to return here.
    return None

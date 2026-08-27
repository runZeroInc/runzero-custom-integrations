# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

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
            # The Integration API documents a maximum page size of 200; a
            # larger value is rejected by the controller.
            "max": 200,
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
        },
    ],
    # Backstop for the pager() loop guards on the sites, clients, and devices
    # walks; the totalCount stop is the working bound.
    "maxPages": 100000,
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
# The Integration API documents a 200-row maximum page size.
MAX_PAGE_LIMIT = 200

VENDOR = "unifi"

# Characters that can appear in a hostname. Underscore is tolerated because
# real client names carry it, even though strict DNS does not.
HOSTNAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._"


def _dns_name(value):
    """Return a value fit to import as a hostname, or "".

    UniFi's client and device names are free-text display labels - "Kitchen TV"
    is a real one - and a label with a space or any other character that cannot
    appear in a DNS name is an operator annotation, not a machine name. Those
    stay in the unifi_name attribute rather than becoming a weak merge key.
    """
    if type(value) != "string":
        return ""
    text = value.strip().rstrip(".")
    if not text or len(text) > 253:
        return ""
    for ch in text.lower().elems():
        if ch not in HOSTNAME_CHARS:
            return ""
    return text


def _strings(value):
    """Return only the string members of a list, or [] for anything else.

    A present-but-null list field, or a junk element inside one, would
    otherwise abort the run at a join().
    """
    if type(value) != "list":
        return []
    return [v for v in value if type(v) == "string"]

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

def get_site_id(base_url, api_key, site_name, page_limit, config_kwargs):
    """
    Finds the UUID for a given site name, paging through the sites collection.

    The lookup used to send a single unpaginated request, so an MSP console
    with more sites than the default page could never surface a site beyond
    page one and the run ended with "no site is named".
    """
    headers = { "X-API-KEY": api_key, "Accept": "application/json" }

    print("unifi: looking up the ID for site '{}'".format(site_name))
    offset = 0
    p = pager("sites")
    while p.next():
        params = {"offset": str(offset), "limit": str(page_limit)}
        sites_url = base_url + "/proxy/network/integration/v1/sites?" + url_encode(params)
        response_json, err = get_json(url=sites_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            # Every later read is scoped by the site id, so a failed site list
            # is the run rather than a console with no sites.
            fail("unifi: failed to get the sites list: {}".format(err))

        if type(response_json) != "dict" or "data" not in response_json:
            fail("unifi: the API did not return a valid sites object")

        batch = response_json.get("data")
        if type(batch) != "list" or not batch:
            break

        for site in batch:
            if type(site) != "dict":
                continue
            if site.get("name") == site_name:
                site_id = site.get("id")
                print("unifi: found site ID {}".format(site_id))
                return site_id

        total_count = response_json.get("totalCount")
        current_count = offset + len(batch)
        if type(total_count) != "int" or total_count <= 0:
            print("unifi: the sites response carried no usable totalCount; " +
                  "stopping the lookup after {} sites".format(current_count))
            break
        if current_count >= total_count:
            break
        offset += page_limit

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

    p = pager("clients")
    while p.next():
        params = {"offset": str(offset), "limit": str(page_limit)}

        if client_filter:
            params["filter"] = client_filter

        clients_url = base_url + "/proxy/network/integration/v1/sites/{}/clients?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=clients_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            fail("unifi: failed to retrieve clients: {}".format(err))
        if type(response_json) != "dict":
            fail("unifi: the API did not return a valid JSON object while fetching clients")

        clients_batch = response_json.get("data")
        if type(clients_batch) != "list":
            if clients_batch != None:
                print("unifi: the clients response carried a non-list data field; stopping")
            break
        if not clients_batch:
            break

        reported += report_assets(build_client_assets(clients_batch, site_id, skips))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(clients_batch)
        print("unifi: fetched {}/{} clients".format(current_count, total_count))

        # totalCount is the only forward signal this walk has. A response
        # missing it, or reporting zero alongside a non-empty page, would end
        # the walk after one page and look complete - so the early stop is
        # named rather than silent.
        if type(total_count) != "int" or total_count <= 0:
            print("unifi: the clients response carried no usable totalCount; " +
                  "stopping after this page - the import may be incomplete")
            break
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

    p = pager("devices")
    while p.next():
        params = {"offset": str(offset), "limit": str(page_limit)}
        devices_url = base_url + "/proxy/network/integration/v1/sites/{}/devices?".format(site_id) + url_encode(params)
        headers = { "X-API-KEY": api_key, "Accept": "application/json" }
        response_json, err = get_json(url=devices_url, **get_http_options(config_kwargs, headers=headers))

        if err:
            fail("unifi: failed to retrieve devices: {}".format(err))
        if type(response_json) != "dict":
            fail("unifi: the API did not return a valid JSON object while fetching devices")

        devices_batch = response_json.get("data")
        if type(devices_batch) != "list":
            if devices_batch != None:
                print("unifi: the devices response carried a non-list data field; stopping")
            break
        if not devices_batch:
            break

        reported += report_assets(build_device_assets(devices_batch, site_id, skips))
        total_count = response_json.get("totalCount", 0)
        current_count = offset + len(devices_batch)
        print("unifi: fetched {}/{} devices".format(current_count, total_count))

        # Same reasoning as the clients walk: a missing or zero totalCount
        # stops the walk after one page, and that stop must be visible.
        if type(total_count) != "int" or total_count <= 0:
            print("unifi: the devices response carried no usable totalCount; " +
                  "stopping after this page - the import may be incomplete")
            break
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
        if type(client) != "dict":
            print("unifi: skipping non-object client row")
            continue
        client_id = client.get("id")
        if not client_id:
            _tally_skip(skips, "no_id", str(client.get("macAddress", "")))
            continue

        mac = client.get("macAddress")
        display_name = client.get("name")
        if type(display_name) != "string":
            display_name = ""

        if mac and type(mac) == "string" and display_name:
            mac_parts = mac.split(":")
            if len(mac_parts) == 6:
                mac_suffix = " " + ":".join(mac_parts[4:])
                if display_name.endswith(mac_suffix):
                    display_name = display_name.removesuffix(mac_suffix)

        # A client the controller cannot name a MAC for has nothing this
        # integration can correlate on beyond a lease address it may already have
        # handed to something else, so it is dropped rather than imported.
        if not mac:
            _tally_skip(skips, "no_mac", str(display_name or ""))
            continue

        ip = client.get("ipAddress")
        ips = [ip] if ip else []
        # network_interface returns None when neither the MAC nor any address
        # parses, and passing [None] to ImportAsset aborts the entire run.
        network = network_interface(ips=ips, mac=mac)
        interfaces = [network] if network else []
        # A free-text display label ("Kitchen TV") stays in unifi_name; only a
        # DNS-shaped value is imported as a hostname. See _dns_name.
        hostname = _dns_name(display_name)
        hostnames = [hostname] if hostname else []

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
            "unifi_name": display_name,
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
        if type(device) != "dict":
            print("unifi: skipping non-object device row")
            continue
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

        display_name = device.get("name")
        if type(display_name) != "string":
            display_name = ""
        # A free-text display label ("Office Switch") stays in unifi_name; only
        # a DNS-shaped value is imported as a hostname. See _dns_name.
        hostname = _dns_name(display_name)
        hostnames = [hostname] if hostname else []

        # A present-but-null model used to abort the run at the `in` checks
        # below; anything that is not a non-empty string falls back.
        model = device.get("model")
        if type(model) != "string" or not model:
            model = "UniFi Device"
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
            "unifi_name": display_name,
            "unifi_state": device.get("state", ""),
            # features and interfaces can be present-but-null, and a junk
            # element inside either would abort the join; only strings survive.
            "unifi_features": ", ".join(_strings(device.get("features"))),
            "unifi_interfaces": ", ".join(_strings(device.get("interfaces")))
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
    # CONFIG bounds only apply on the Console path, so the CLI path clamps too:
    # the Integration API rejects a limit above 200.
    if page_limit < 1:
        page_limit = DEFAULT_PAGE_LIMIT
    if page_limit > MAX_PAGE_LIMIT:
        print("unifi: page_limit {} exceeds the API maximum; using {}".format(
            page_limit, MAX_PAGE_LIMIT))
        page_limit = MAX_PAGE_LIMIT

    api_key = kwargs.get('api_key')

    if not api_key:
        print("unifi: api_key is required")
        return None

    # 1. Find the Site ID from the Site Name
    site_id = get_site_id(base_url, api_key, site_name, page_limit, kwargs)
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

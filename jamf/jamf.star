# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-jamf",
    "name": "JAMF",
    "type": "inbound",
    "description": "Imports computers and mobile devices from Jamf Pro.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Jamf base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<tenant>.jamfcloud.com",
        },
        {
            "key": "client_id",
            "label": "API client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "API client secret",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'ip_in_network', 'network_interface')
load('http', 'get_json', 'post_json', 'bearer', 'oauth2_token')
load('kwargs', 'get_url_base', 'get_http_options')
load('time', 'now', 'parse_duration')
load('flatten_json', 'flatten')
DAYS_AGO = 60  # Adjust as needed
duration_str = "-{}h".format(DAYS_AGO * 24)  # Go duration format, e.g. "-720h" for 30 days
ago_duration = parse_duration(duration_str)
start_time = now() + ago_duration  # Subtracting the duration
START_DATE = str(start_time)[:10]  # "YYYY-MM-DD"
MAX_REQUESTS = 100
COMPUTER_ASSETS = True
MOBILE_ASSETS = True
DEV_MODE = False

# A hard bound on both inventory walks below. Each pages 100 records at a time
# and the only exit is a page that comes back empty, so a Jamf Pro that ignores
# `page` -- or a proxy in front of it that replays one response -- never ends
# either walk. 2000 pages x 100 records = 200,000 devices per walk, past the
# device count of the largest Jamf Pro tenant. Reaching the ceiling is logged,
# because a silently truncated import looks exactly like a complete one.
MAX_PAGES = 2000

# Both walks fetch one detail record per device, so a run is one request per
# page plus one per device and spends most of its time in that second loop. A
# 10,000-device tenant is 10,000 detail calls, which is minutes with nothing on
# the console to distinguish a slow run from a hung one. A line every this many
# devices is enough to tell them apart without a line per device.
PROGRESS_EVERY = 500

# Jamf manages Apple hardware and nothing else, and Apple names the chassis in
# the hardware model itself -- both in the marketing name ("MacBook Pro
# (16-inch, 2019)", "Mac mini") and in the model identifier ("MacBookPro18,3",
# "iPad13,1"). Which of the two lands in the model field varies by endpoint and
# by enrollment, so both are folded onto the same key before matching.
#
# Two classes of hardware are deliberately absent. Apple's post-2022 Macs report
# an unqualified identifier such as "Mac15,3" that names no chassis at all, and
# Apple Watch and Vision Pro have no counterpart in runZero's device-type
# vocabulary. Both fall through with no deviceType, leaving runZero to
# fingerprint the hardware, which is the better answer than a guess.
MODEL_DEVICE_TYPES = [
    ("ipad", "Tablet"),
    ("iphone", "Mobile"),
    ("ipod", "Mobile"),
    ("appletv", "Smart TV"),
    ("macbook", "Laptop"),
    ("imac", "Desktop"),
    ("macmini", "Desktop"),
    ("macstudio", "Desktop"),
    ("macpro", "Desktop"),
]

# A mobile-device record also carries an explicit family in `type`, documented
# as ios, tvos, watchos, visionos, or unknown. Only tvos names a form factor on
# its own: ios covers both iPhone and iPad, so it is left to the model, and
# runZero has no type for a watch or a headset.
MOBILE_TYPE_DEVICE_TYPES = {"tvos": "Smart TV"}

def device_type_from_model(model):
    """Return the runZero device type for a Jamf model string, or None."""
    if type(model) != "string" or not model:
        return None
    key = model.lower().replace(" ", "").replace("-", "")
    for entry in MODEL_DEVICE_TYPES:
        if entry[0] in key:
            return entry[1]
    return None

def mobile_device_type(item, model):
    """Return the runZero device type for a Jamf mobile device, or None.

    `type` is consulted first because it is the field Jamf documents, then the
    hardware model, which is what separates an iPhone from an iPad inside the
    single `ios` family.
    """
    family = str(item.get("type", "") or "").strip().lower()
    mapped = MOBILE_TYPE_DEVICE_TYPES.get(family, None)
    if mapped:
        return mapped
    return device_type_from_model(model) or device_type_from_model(item.get("modelIdentifier", ""))

def sanitize_string(s):
    if s:
        return s.replace(" ", "_").replace(".", "").replace("+", "").replace("(", "").replace(")", "").lower()
    else:
        return None

def item_label(item):
    """A short display name for a record, for skip logs.

    The record itself is never logged: a Jamf inventory entry carries the
    assigned user's name, email address, building and room. Log the field that
    identifies which record was skipped, and nothing else.
    """
    if type(item) != "dict":
        return ""
    general = item.get("general") or {}
    return str(general.get("displayName") or general.get("name") or item.get("name") or "")

def new_stats():
    """Counters for records skipped during a run, reported once at the end."""
    return {
        "computers_read": 0,
        "mobile_read": 0,
        "inventory_no_id": 0,
        "mobile_inventory_no_id": 0,
        "detail_no_udid": 0,
        "mobile_detail_no_udid": 0,
        # Details actually requested, which is what the run spends its time on
        # and so what the progress lines count. Distinct from *_read, which
        # counts inventory rows including the ones skipped without a request.
        "computer_details": 0,
        "mobile_details": 0,
    }

def get_bearer_token(base_url, client_id, client_secret, config_kwargs):
    token = oauth2_token(
        "{}/api/oauth/token".format(base_url),
        client_id=client_id,
        client_secret=client_secret,
        **get_http_options(config_kwargs)
    )
    return token, 0

def get_valid_token(token, request_count, base_url, client_id, client_secret, config_kwargs):
    if token and request_count < MAX_REQUESTS:
        return token, request_count + 1
    else:
        print("Fetching new token after", request_count, "requests")
        return get_bearer_token(base_url, client_id, client_secret, config_kwargs)

def http_request(method, url, config_kwargs=None, headers=None, params=None, body=None, token=None, request_count=None, base_url=None, client_id=None, client_secret=None):
    token, request_count = get_valid_token(token, request_count, base_url, client_id, client_secret, config_kwargs)
    if not token:
        return None, "no token", token, request_count

    headers = dict(headers or {})
    headers["Authorization"] = bearer(token)
    http_options = get_http_options(config_kwargs, headers=headers)

    if method == "GET":
        data, err = get_json(url=url, params=params or {}, **http_options)
    elif method == "POST":
        data, err = post_json(url=url, body=body, **http_options)
    else:
        return None, "unsupported method: " + method, token, request_count

    if err and err.startswith("status 403"):
        print("403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(base_url, client_id, client_secret, config_kwargs)
        if not token:
            return None, "refresh failed", token, request_count
        headers["Authorization"] = bearer(token)
        http_options = get_http_options(config_kwargs, headers=headers)
        if method == "GET":
            data, err = get_json(url=url, params=params or {}, timeout=300, **http_options)
        elif method == "POST":
            data, err = post_json(url=url, body=body, **http_options)

    return data, err, token, request_count

def stream_computer_assets(base_url, config_kwargs, token, request_count, client_id, client_secret, stats):
    """Paginate computer inventory, fetch per-device details, then build and
    stream each page of assets via report_assets so the full inventory is never
    held in memory. Returns (reported_count, token, request_count)."""
    page = 0
    page_size = 100
    reported = 0
    # hardcoded filter for the time being until we support datetime
    url = base_url + '/api/v1/computers-inventory'

    # MAX_PAGES + 1 iterations, with the last reserved for the ceiling message.
    # The loop has four ways out and none of them is the ceiling, so this is the
    # one place the exhausted case can be reported without a flag that has to be
    # kept in step with every one of those exits. The extra iteration issues no
    # request: the ceiling is still exactly MAX_PAGES pages.
    for _page in range(0, MAX_PAGES + 1):
        if _page == MAX_PAGES:
            print("jamf: stopped reading computer inventory at the {} page ceiling with {} computers read; the listing never returned an empty page, so this run is truncated".format(
                MAX_PAGES, stats["computers_read"]))
            break

        params = {"page": page, "page-size": page_size, "filter": 'general.lastContactTime=ge="{}T00:00:00Z"'.format(START_DATE)}
        inventory, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, params=params, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve inventory:", err)
            return reported, token, request_count

        if not inventory:
            print("Empty inventory response")
            return reported, token, request_count

        results = inventory.get('results', [])

        if not results:
            break

        details, token, request_count = get_jamf_details(base_url, config_kwargs, token, request_count, client_id, client_secret, results, stats)
        reported += report_assets(build_assets(details, stats))
        page += 1

    return reported, token, request_count

def get_jamf_details(base_url, config_kwargs, token, request_count, client_id, client_secret, inventory, stats):
    endpoints_final = []
    stats["computers_read"] += len(inventory)
    for item in inventory:
        uid = item.get('id')
        if not uid:
            # One example names the record; the rest are counted, so an estate
            # with thousands of id-less entries costs one line, not thousands.
            if stats["inventory_no_id"] == 0:
                print("jamf: skipping inventory item with no id: name=" + item_label(item))
            stats["inventory_no_id"] += 1
            continue

        url = "{}/api/v1/computers-inventory-detail/{}".format(base_url, uid)
        # One line every PROGRESS_EVERY detail calls, not one per device: this
        # loop is where a large tenant spends minutes, and without it a slow run
        # and a hung one look identical from the console.
        stats["computer_details"] += 1
        if stats["computer_details"] % PROGRESS_EVERY == 0:
            print("jamf: fetched details for {} computers so far".format(stats["computer_details"]))
        extra, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve details for ID:", uid, err)
            continue

        if DEV_MODE:
            build_asset(extra, stats)
        if not extra:
            print("Empty detail for ID:", uid)
            continue

        item.update(extra)
        endpoints_final.append(item)

    return endpoints_final, token, request_count

def stream_mobile_assets(base_url, config_kwargs, token, request_count, client_id, client_secret, stats):
    """Paginate mobile device inventory, fetch per-device details, then build and
    stream each page of assets via report_assets so the full inventory is never
    held in memory. Returns (reported_count, token, request_count)."""
    page = 0
    page_size = 100
    reported = 0
    # hardcoded filter for the time being until we support datetime
    url = base_url + "/api/v2/mobile-devices/detail"

    # See stream_computer_assets for why the last iteration is reserved rather
    # than a flag being threaded through every exit.
    for _page in range(0, MAX_PAGES + 1):
        if _page == MAX_PAGES:
            print("jamf: stopped reading mobile inventory at the {} page ceiling with {} mobile devices read; the listing never returned an empty page, so this run is truncated".format(
                MAX_PAGES, stats["mobile_read"]))
            break

        params = {"page": page, "page-size": page_size, "section": "GENERAL", "filter": 'lastInventoryUpdateDate=ge="{}T00:00:00Z"'.format(START_DATE)}
        inventory, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, params=params, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve mobile device inventory:", err)
            return reported, token, request_count

        if not inventory:
            print("Empty mobile inventory response")
            return reported, token, request_count

        results = inventory.get('results', [])

        if not results:
            break

        details, token, request_count = get_mobile_device_details(base_url, config_kwargs, token, request_count, client_id, client_secret, results, stats)
        reported += report_assets(build_mobile_assets(details, stats))
        page += 1

    return reported, token, request_count

def get_mobile_device_details(base_url, config_kwargs, token, request_count, client_id, client_secret, inventory, stats):
    mobile_devices_final = []
    stats["mobile_read"] += len(inventory)
    for item in inventory:
        uid = item.get('mobileDeviceId')
        if not uid:
            if stats["mobile_inventory_no_id"] == 0:
                print("jamf: skipping mobile device item with no mobileDeviceId: name=" + item_label(item))
            stats["mobile_inventory_no_id"] += 1
            continue

        url = "{}/api/v2/mobile-devices/{}/detail".format(base_url, uid)
        # See get_jamf_details: one line every PROGRESS_EVERY detail calls.
        stats["mobile_details"] += 1
        if stats["mobile_details"] % PROGRESS_EVERY == 0:
            print("jamf: fetched details for {} mobile devices so far".format(stats["mobile_details"]))
        extra, err, token, request_count = http_request("GET", url, config_kwargs=config_kwargs, token=token, request_count=request_count, base_url=base_url, client_id=client_id, client_secret=client_secret)
        if err:
            print("Failed to retrieve details for mobile device ID:", uid, err)
            continue

        if DEV_MODE:
            build_mobile_asset(extra, stats)
        if not extra:
            print("Empty detail for mobile device ID:", uid)
            continue

        item.update(extra)
        mobile_devices_final.append(item)

    return mobile_devices_final, token, request_count

# Only addresses from these ranges are imported. A Jamf-managed laptop spends
# most of its life off the corporate network, and the address Jamf records is
# then the ISP's NAT egress -- which is shared by every subscriber behind it, so
# importing it would IP-match unrelated devices onto each other.
#
# Written as CIDRs and evaluated with net.ip_in_network rather than as string
# prefixes. The prefix form got 172.16/12 right only by enumerating sixteen
# separate startswith() tests, and it had no way to express the two ranges it
# was missing entirely:
#
#   100.64.0.0/10  RFC 6598 carrier-grade NAT. Every Apple device on a modern
#                  mobile carrier, and every client behind an ISP running CGNAT,
#                  reports an address from here. It is private by definition and
#                  was being discarded.
#   fc00::/7       RFC 4193 IPv6 unique local addresses, the v6 counterpart of
#                  10/8. No IPv6 address of any kind survived the old filter,
#                  because every one of them failed all eighteen prefix tests.
PRIVATE_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
]

def is_private_ip(ip):
    """True when the address is in a private/CGNAT/ULA range worth importing."""
    if type(ip) != "string" or not ip:
        return False
    for cidr in PRIVATE_NETWORKS:
        # ip_in_network returns False for malformed or mixed-family input rather
        # than aborting, so an unparseable value simply fails every test.
        if ip_in_network(ip, cidr):
            return True
    return False

def asset_ips(item):
    general = item.get("general") or {}
    ips = []
    for key in ["lastIpAddress", "ipAddress", "lastReportedIp"]:
        ip = general.get(key)
        # only add Private IPs to the inventory 
        # remote assets put a lot of junk in the inventory with ISP public IP addresses
        if ip and is_private_ip(ip):
            ips.append(ip)
    return ips

def asset_networks(ips, macs):
    """Build one NetworkInterface per MAC, with the addresses on the FIRST only.

    Jamf reports a device's addresses at the DEVICE level -- general.lastIpAddress,
    ipAddress, lastReportedIp -- and its MACs at the HARDWARE level, with nothing
    tying any address to any particular NIC. The previous shape emitted one
    interface per MAC and repeated the FULL address list on every one of them,
    which asserts something Jamf never said: that the built-in Ethernet, the
    alternate NIC and the Wi-Fi radio all hold the same address at the same time.
    A Mac with a Thunderbolt dock reports two MACs and one address, and that made
    the address look like it lived on both.

    The addresses go on the first MAC, which is Jamf's own ordering:
    hardware.macAddress is the primary interface, altMacAddress the secondary,
    wifiMacAddress the mobile radio. The rest become address-less interfaces, so
    every MAC still reaches runZero for correlation without any of them claiming
    an address it was never reported with.

    network_interface() also replaces the hand-rolled v4/v6 split this used to
    do: ip_address() returns None for an unparseable value and reading .version
    off that aborted the whole script.
    """
    interfaces = []
    seen = {}
    pending = ips
    for mac in macs:
        key = str(mac).lower()
        if key in seen:
            continue
        seen[key] = True
        nic = network_interface(ips=pending, mac=mac)
        # Whether or not this MAC parsed, the addresses have been offered to it
        # and must not be offered again -- an unparseable MAC still yields an
        # interface carrying them.
        pending = []
        if nic:
            interfaces.append(nic)

    if not interfaces:
        # No usable MAC anywhere, so the addresses need an interface of their
        # own. network_interface answers None when neither survives.
        nic = network_interface(ips=pending, mac=None)
        if nic:
            interfaces.append(nic)

    return interfaces

def asset_os_hardware(item):
    operating_system = item.get("operatingSystem") or {}
    hardware = item.get("hardware") or {}
    general = item.get("general") or {}

    os_name = operating_system.get("name", "") if operating_system else "iOS"
    os_version = operating_system.get("version", "") or general.get("osVersion", "")
    model = hardware.get("model", "") or item.get("model", "")
    manufacturer = hardware.get("make", "") or "Apple"
    macs = [mac for mac in [hardware.get("macAddress", ""), hardware.get("altMacAddress", ""), item.get("wifiMacAddress", "")] if mac]
    serial_number = hardware.get("serialNumber", "")

    return {
        'os_name': os_name,
        'os_version': os_version,
        'model': model,
        'manufacturer': manufacturer,
        'macs': macs,
        'serial_number': serial_number
    }

def build_asset(item, stats):
    if not item:
        return

    asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not asset_id:
        if stats["detail_no_udid"] == 0:
            print("jamf: skipping detail record with no udid/mobileDeviceId: name=" + item_label(item))
        stats["detail_no_udid"] += 1
        return

    general = item.get("general") or {}
    name = general.get("displayName", "")

    os_hardware = asset_os_hardware(item) or {}
    ips = asset_ips(item)
    networks = asset_networks(ips, [mac for mac in os_hardware.get("macs", []) if mac])

    security = item.get("security") or {}
    disk = item.get("diskEncryption") or {}
    boot = disk.get("bootPartitionEncryptionDetails") or {}
    user = item.get("userAndLocation") or {}
    

    # add flattened version of certain attributes
    custom_attributes = {}
    # add extension attributes
    main_ext_attrs = item.get("extensionAttributes", [])
    if len(main_ext_attrs) > 0:
        for ext in main_ext_attrs:
            ext_name = sanitize_string(ext.get("name", None))
            ext_values = ext.get("values", None) or ext.get("value", None)
            if ext_name and ext_values:
                key_name = "ext_attr_" + ext_name
                custom_attributes[key_name] = ",".join(ext_values)
    # add user extension attributes
    user_ext_attrs = item.get("userAndLocation", {}).get("extensionAttributes", [])
    if len(user_ext_attrs) > 0:
        for ext in user_ext_attrs:
            user_ext_name = sanitize_string(ext.get("name", None))
            user_ext_values = ext.get("values", None) or ext.get("value", None)
            if user_ext_name and user_ext_values:
                key_name = "ext_attr_" + user_ext_name
                custom_attributes[key_name] = ",".join(user_ext_values)

    for key in item.keys():
        if key not in ["purchasing", "storage", "packageReceipts", "contentCaching", "extensionAttributes", "userAndLocation"]:
            if type(item[key]) == "dict":
                custom_attributes.update(flatten(item[key]))
            elif type(item[key]) == "string":
                custom_attributes[key] = item[key]
            elif type(item[key]) == "list":
                # skip lists unless we have more context on them like extensionAttributes
                continue

    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        # None rather than "" when the model names no chassis: an empty string
        # is still a value, and it would displace the type runZero fingerprints
        # from the hardware for itself.
        deviceType=device_type_from_model(os_hardware.get('model', '')),
        hostnames=[name],
        customAttributes=to_custom_attributes(custom_attributes),
    )

def build_assets(inventory, stats):
    assets = []
    for item in inventory:
        asset = build_asset(item, stats)
        if asset:
            assets.append(asset)
    return assets

def build_mobile_asset(item, stats):
    if not item:
        return None
    mobile_asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not mobile_asset_id:
        if stats["mobile_detail_no_udid"] == 0:
            print("jamf: skipping mobile detail record with no udid/mobileDeviceId: name=" + item_label(item))
        stats["mobile_detail_no_udid"] += 1
        return None

    general = item.get("general") or {}
    name = item.get("name", "")
    os_hardware = asset_os_hardware(item)
    ips = asset_ips(item)
    networks = asset_networks(ips, [mac for mac in os_hardware.get("macs", []) if mac])

    # add flattened version of certain attributes
    custom_attributes = {}
    for key in item.keys():
        if key == "extensionAttributes":
            for ext in item["extensionAttributes"]:
                ext_name = ext.get("name", None).replace(" ", "_").lower()
                ext_values = ext.get("values", None) or ext.get("value", None)
                if ext_name and ext_values:
                    key_name = "ext_attr_" + ext_name
                    custom_attributes[key_name] = ",".join(ext_values)
        elif key not in ["applications", "certificates", "purchasing", "serviceSubscription", "ebooks", "fonts", ]:
            if type(item[key]) == "dict":
                custom_attributes.update(flatten(item[key]))
            elif type(item[key]) == "string" or type(item[key]) == "bool":
                custom_attributes[key] = str(item[key])
            elif type(item[key]) == "list":
                # skip lists unless we have more context on them like extensionAttributes
                continue
        else:
            continue

    return ImportAsset(
        id=mobile_asset_id,
        networkInterfaces=networks,
        hostnames=[name.replace(" ", "-")],
        os=os_hardware.get('os_name', ''),
        osVersion=os_hardware.get('os_version', ''),
        manufacturer=os_hardware.get('manufacturer', ''),
        model=os_hardware.get('model', ''),
        # None rather than "" for a family and model that name no chassis, for
        # the same reason as the computer path above.
        deviceType=mobile_device_type(item, os_hardware.get('model', '')),
        customAttributes=to_custom_attributes(custom_attributes),
    )

def build_mobile_assets(inventory, stats):
    assets = []
    for item in inventory:
        asset = build_mobile_asset(item, stats)
        if asset:
            assets.append(asset)
    return assets

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    client_id = kwargs['client_id']
    client_secret = kwargs['client_secret']

    token, request_count = get_bearer_token(base_url, client_id, client_secret, kwargs)
    if not token:
        print("Failed to get bearer token")
        return None

    # Assets are streamed page-by-page via report_assets.
    stats = new_stats()
    reported = 0
    if COMPUTER_ASSETS:
        # Fetch and process computer inventory
        computers, token, request_count = stream_computer_assets(base_url, kwargs, token, request_count, client_id, client_secret, stats)
        reported += computers
    if MOBILE_ASSETS:
        # Fetch and process mobile device inventory
        mobile, token, request_count = stream_mobile_assets(base_url, kwargs, token, request_count, client_id, client_secret, stats)
        reported += mobile

    if stats["inventory_no_id"]:
        print("jamf: skipped {} inventory item(s) with no id".format(stats["inventory_no_id"]))
    if stats["mobile_inventory_no_id"]:
        print("jamf: skipped {} mobile device item(s) with no mobileDeviceId".format(stats["mobile_inventory_no_id"]))
    if stats["detail_no_udid"]:
        print("jamf: skipped {} detail record(s) with no udid/mobileDeviceId".format(stats["detail_no_udid"]))
    if stats["mobile_detail_no_udid"]:
        print("jamf: skipped {} mobile detail record(s) with no udid/mobileDeviceId".format(stats["mobile_detail_no_udid"]))
    print("jamf: read {} computer and {} mobile inventory item(s), reported {} assets".format(
        stats["computers_read"], stats["mobile_read"], reported))
    return None

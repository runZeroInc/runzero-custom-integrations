# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-device42",
    "name": "Device42",
    "type": "inbound",
    "description": "Imports configuration items from Device42.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Device42 API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://device42.example.com",
            "description": "Your Device42 appliance, with no path suffix. Device42 is customer-hosted, so there is no vendor endpoint to fall back to.",
        },
        {
            "key": "auth_scheme",
            "label": "Auth scheme",
            "type": "enum",
            "required": True,
            "options": ["basic", "bearer"],
            "default": "basic",
        },
        {
            "key": "credential",
            "label": "Credential",
            "type": "secret",
            "required": True,
            "description": "Base64 user:pass for basic, or bearer token",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json')
load('kwargs', 'get_url_base', 'get_http_options')

# Device42 is customer-hosted, so every deployment has its own appliance and
# there is no vendor endpoint that could serve as a default. The url parameter
# is required for that reason: the obvious candidate, the vendor's public
# swaggerdemo sandbox, holds Device42's own demo records, so a deployment that
# silently fell back to it would import someone else's fictional inventory as
# real assets.
DEVICE42_ENDPOINT = '/api/1.0/devices/all/'
PAGE_SIZE         = 1000

# A hard bound on the offset walk below. Its exits are an empty page and a short
# page, and an appliance that ignores `offset` produces neither -- it just keeps
# answering with the same full page. 200 pages x 1000 rows = 200,000 devices,
# past the CMDB size of the largest Device42 appliance. Reaching the ceiling is
# logged: a truncated import that says nothing looks exactly like a complete one.
MAX_PAGES = 200

# runZero's exact-match device-type vocabulary, from
# IdentifyTypeFromCustomIntegration in the platform. A value outside this list is
# NOT rejected: it falls through to normalize.DeviceType(), which title-cases
# anything it does not recognise and sets that on the asset verbatim.
RUNZERO_DEVICE_TYPES = [
    "BMC", "Database", "Desktop", "Firewall", "Game Console", "Hypervisor",
    "IP Camera", "IP Phone", "Laptop", "Load Balancer", "Mobile",
    "Network Management Server", "Printer", "Router", "Server", "Serverless",
    "Smart TV", "Switch", "Tablet", "Video Conferencing", "WAP",
]

# Device42's `type` says how a device is REALIZED -- physical, virtual, blade,
# cluster, other, unknown -- not what kind of device it is, and the two fields
# beside it are the customer's own taxonomy. None of that is a runZero device
# type, and passing the raw value through was actively harmful. The platform
# does not discard a value it does not know: it misses the exact-match list,
# then normalize.DeviceType() title-cases anything unrecognised and returns it,
# so "physical" and "virtual" became device types in their own right. That
# displaces the type runZero would otherwise fingerprint from hw_model and
# manufacturer, and it makes a type search over these assets useless.
#
# Only values naming a real form factor are mapped, and only onto members of the
# exact-match list above. "blade" is a blade SERVER in Device42's vocabulary.
# "virtual" and "cluster" are deliberately absent: runZero's vocabulary has no
# member for either, and there is no honest approximation -- a Device42 cluster
# is a logical grouping, not a device at all.
D42_TYPE_DEVICE_TYPES = {
    "blade": "Server",
    "physical server": "Server",
    "virtual server": "Server",
}

def device_type(d):
    """Return the runZero device type for a Device42 device, or None.

    device_sub_type is consulted first because it is the more specific field --
    a customer who has named a sub-type "Switch" or "Firewall" has said exactly
    what runZero wants to know -- but it is honoured ONLY when it already spells
    a runZero type. Everything unrecognised leaves deviceType unset, which is
    the better answer than a guess: runZero then fingerprints from hw_model and
    manufacturer, which this integration also imports.
    """
    for key in ('device_sub_type', 'type'):
        raw = d.get(key)
        if type(raw) != "string":
            continue
        value = raw.strip().lower()
        if not value:
            continue
        for known in RUNZERO_DEVICE_TYPES:
            if value == known.lower():
                return known
        mapped = D42_TYPE_DEVICE_TYPES.get(value)
        if mapped:
            return mapped
    return None

def build_network_interfaces(mac_entries, ip_entries):
    interfaces = []
    seen_macs = {}
    for ip_obj in ip_entries:
        ip_str = ip_obj.get('ip')
        if not ip_str:
            continue
        macaddr = ip_obj.get('macaddress') or ip_obj.get('mac_address')
        seen_macs[macaddr] = seen_macs.get(macaddr, [])
        seen_macs[macaddr].append(ip_str)
        # network_interface answers None when nothing usable survives -- here an
        # address that is not parseable as one, with no MAC alongside it to
        # carry the interface. Passing that None on to ImportAsset aborts the
        # whole run, losing every asset already parsed and every later page, so
        # drop the interface instead.
        nic = network_interface(ips=[ip_str], mac=macaddr)
        if nic:
            interfaces.append(nic)

    for m in mac_entries:
        mac_addr = m.get('mac') or m.get('mac_address')
        if mac_addr not in seen_macs:
            # Likewise None when the record carried neither key, leaving an
            # interface with no address and no MAC.
            nic = network_interface(ips=[], mac=mac_addr)
            if nic:
                interfaces.append(nic)

    return interfaces

def build_assets(devices, skipped):
    assets = []
    for d in devices:
        raw_id = d.get('id') or d.get('uuid') or d.get('device_id') or d.get('serial_no')
        if not raw_id:
            # Tallied across every page and reported once by main; logging each
            # one costs a line per device on a large estate.
            skipped[0] += 1
            if skipped[0] == 1:
                skipped[1] = str(d.get('name', ''))
            continue
        asset_id = str(raw_id)

        hostnames = []
        for key in ('name', 'preferred_alias', 'virtual_host_name'):
            val = d.get(key)
            if val and val not in hostnames:
                hostnames.append(val)

        mac_entries = d.get('macAddresses', []) + d.get('mac_addresses', [])
        ip_entries  = d.get('ipAddresses', [])  + d.get('ip_addresses', [])
        network_ifaces = build_network_interfaces(mac_entries, ip_entries)

        asset_os = d.get('os')
        asset_os_version = d.get('osver') or d.get('osverno')
        asset_model = d.get('hw_model')
        asset_manufacturer = d.get('manufacturer')
        asset_device_type = device_type(d)

        asset_tags = []
        raw_tags = d.get('tags') or []
        # type() returns a STRING in Starlark, so comparing it to the `list`
        # builtin was always false and no tag was ever imported. Device42's tags
        # are one of the more useful things it carries, so this silently dropped
        # the field for every asset since the integration shipped.
        if type(raw_tags) == "list":
            for t in raw_tags:
                asset_tags.append(str(t))

        # type, device_sub_type and virtual_subtype are NOT excluded. They used
        # to be, because they were consumed to build deviceType; now that most
        # of their values map to no runZero type, dropping them as well would
        # lose the information entirely. They are Device42's own record of how a
        # device is realized and what the customer calls it, so they are kept as
        # custom attributes where they are searchable without being asserted as
        # a device type.
        exclude_keys = [
            'id', 'uuid', 'device_id', 'macAddresses', 'mac_addresses',
            'ipAddresses', 'ip_addresses', 'name', 'preferred_alias',
            'virtual_host_name', 'os', 'osver', 'osverno', 'hw_model',
            'manufacturer', 'tags',
        ]

        custom = {}
        for k, v in d.items():
            if k in exclude_keys:
                continue
            custom[k] = str(v)[:1023]

        assets.append(
            ImportAsset(
                id=asset_id,
                hostnames=hostnames,
                os=asset_os,
                osVersion=asset_os_version,
                model=asset_model,
                manufacturer=asset_manufacturer,
                deviceType=asset_device_type,
                tags=asset_tags,
                networkInterfaces=network_ifaces,
                customAttributes=to_custom_attributes(custom),
            )
        )
    return assets

def main(**kwargs):
    auth_type = kwargs['auth_scheme'].lower()
    secret = kwargs['credential']
    # The appliance root only: get_url_base drops any path an operator pasted
    # from the browser, and DEVICE42_ENDPOINT is appended below.
    base_url = get_url_base(kwargs)

    if auth_type == 'basic':
        headers = {
            'Authorization': 'Basic ' + secret,
            'Accept': 'application/json',
        }
    elif auth_type == 'bearer':
        headers = {
            'Authorization': 'Bearer ' + secret,
            'Accept': 'application/json',
        }
    else:
        print('device42: unsupported auth_scheme (must be "basic" or "bearer")')
        return None
    http_options = get_http_options(kwargs, headers=headers)

    offset = 0
    total = 0
    capped = True
    reported = 0
    # [count, first name] -- a list so build_assets can accumulate across pages.
    skipped = [0, ""]
    for _page in range(0, MAX_PAGES):
        url = '{}{}?format=json&limit={}&offset={}'.format(
            base_url, DEVICE42_ENDPOINT, PAGE_SIZE, offset
        )
        body, err = get_json(url, **http_options)

        if err:
            print('device42: API error: {}'.format(err))
            return None
        # Device42 answers with an object carrying code/msg/Devices. Check that
        # before reading it: .get on a list aborts the script, so an error
        # document returned as a bare array would end the run silently instead
        # of reporting the problem here.
        if type(body) != "dict":
            print('device42: API error: unexpected response shape, wanted an object')
            return None
        if body.get('code', 0) != 0:
            print('device42: API logical error: {}'.format(body.get('msg')))
            return None

        page = body.get('Devices', [])
        if not page:
            capped = False
            break

        # Build and stream this page's assets, then let it be reclaimed before
        # fetching the next page so memory stays bounded by a single page.
        reported += report_assets(build_assets(page, skipped))
        total += len(page)

        if len(page) < PAGE_SIZE:
            capped = False
            break
        offset += PAGE_SIZE

    if capped:
        print('device42: stopped at the {} page ceiling after {} devices; every page came back full, so this run is truncated'.format(
            MAX_PAGES, total))

    if skipped[0] > 0:
        print('device42: skipped {} devices with no stable id (first name: {})'.format(
            skipped[0], skipped[1]))

    print('device42: reported {} assets'.format(reported))

    return None


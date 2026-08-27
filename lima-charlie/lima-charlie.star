# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-limacharlie",
    "name": "LimaCharlie",
    "type": "inbound",
    "description": "Imports endpoints from LimaCharlie.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Backstop for the continuation-token walk, enforced by pager(). The
    # repeated-token guard below is the working stop for a server that stops
    # advancing; this ceiling only ends an adversarially rotating one.
    "maxPages": 100000,
    "params": [
        {
            "key": "url",
            "label": "LimaCharlie API URL",
            "type": "url",
            "required": False,
            "default": "https://api.limacharlie.io/v1",
            "placeholder": "https://api.limacharlie.io/v1",
            "description": "LimaCharlie's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "jwt_url",
            "label": "LimaCharlie JWT URL",
            "type": "url",
            "required": False,
            "default": "https://jwt.limacharlie.io",
            "placeholder": "https://jwt.limacharlie.io",
            "description": "LimaCharlie's token-exchange endpoint, which lives on a different host to the API. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "organization_id",
            "label": "Organization ID (OID)",
            "type": "string",
            "required": True,
        },
        {
            "key": "api_token",
            "label": "API access token",
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
load('net', 'network_interface')
load('http', 'get_json', 'post_json', 'bearer', 'url_encode')
load('kwargs', 'get_http_options')

# Used when the jwt_url and url parameters are unset. LimaCharlie serves the
# token exchange and the API from different hosts, so each stays separately
# configurable rather than compiled in, letting a regional or self-hosted
# deployment be reached without editing the script.
DEFAULT_LIMACHARLIE_JWT_URL = 'https://jwt.limacharlie.io'
DEFAULT_LIMACHARLIE_BASE_URL = 'https://api.limacharlie.io/v1'

# Exclusion list for sensors that you want to ignore by hostname.
SENSORS_TO_IGNORE = [
    # sensor_hostname_01,
    # sensor_hostname_02,
    # sensor_hostname_03
]

# List of attributes that are not pulled into runZero.
# Note: sid, hostname, mac_addr and int_ip are imported as core asset attributes so
# they are ignored for the purpose of custom LimaCharlie attributes. ext_ip is
# deliberately NOT in this list -- it is kept as a custom attribute rather than
# put on an interface; see build_assets.
CUSTOM_ATTRIBS_TO_IGNORE = [
    'sid',
    'hostname',
    'mac_addr',
    'int_ip'
]

# LimaCharlie pages the sensor list with an opaque continuation token, returned
# as `continuation_token` on the response and sent back under the same name as a
# query parameter. The walk ends when the token comes back absent, null, or
# empty -- all three are falsy and all three mean the same thing.
# Source: refractionPOINT/python-limacharlie, Organization.list_sensors(), which
# loops on `qp["continuation_token"] = continuation_token` until `not
# continuation_token`; and refractionPOINT/go-limacharlie sensor.go, whose page
# struct is `{"continuation_token": string, "sensors": ...}`. The walk is
# bounded by CONFIG["maxPages"] through pager().

# Filter based on what architectures you want to import into runZero
# By default, Chromium browsed based extensions are excluded from import
ARCHITECTURE = {
    1: True,   # x86
    2: True,   # x64
    3: True,   # arm
    4: True,   # arm64
    5: True,   # alpine64
    6: False,  # chromium
    7: True,   # wireguard
    8: True,   # arml
    9: False,  # usp_adapter
}

# LimaCharlie reports the sensor's platform as a numeric constant in `plat`.
# Only the two mobile platforms imply a form factor, so only they are mapped:
# windows (0x10000000), linux (0x20000000) and macos (0x30000000) are desktop
# and server operating systems alike, ChromeOS (0x60000000) runs on laptops and
# desktops both, and vpn (0x70000000) is a network sensor rather than an
# endpoint. The same field also carries the ~50 telemetry-source platforms
# (crowdstrike, okta, office365 and the rest), which are log connectors and not
# devices at all; those are unmapped for the same reason.
PLATFORM_DEVICE_TYPES = {
    "1073741824": "Mobile",  # 0x40000000 ios
    "1342177280": "Mobile",  # 0x50000000 android
}

def platform_device_type(plat):
    """Return the runZero device type for a LimaCharlie platform, or None.

    `plat` is a uint32 on the wire, but it reaches Starlark through a JSON
    decode, so it can arrive as an int or a float depending on the payload.
    Both are normalised to the same integer spelling before the lookup.
    """
    key = str(plat).strip()
    if key.endswith(".0"):
        key = key[:-len(".0")]
    return PLATFORM_DEVICE_TYPES.get(key, None)

def get_token(jwt_url, oid, token, config_kwargs):
    url = '{}/?oid={}'.format(jwt_url, oid)
    # The secret is sent BOTH ways: as the X-LC-Secret header (undocumented,
    # but confirmed accepted by a live probe of jwt.limacharlie.io and by this
    # integration's history) and as the form body the vendor docs and both
    # official SDKs use. Whichever contract the endpoint honors, the exchange
    # works -- and a vendor-side tightening to the documented form no longer
    # breaks every deployment at the first request.
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-LC-Secret': token
    }
    body = bytes(url_encode({'oid': oid, 'secret': token}))

    response_json, err = post_json(url, body=body,
                                   **get_http_options(config_kwargs, headers=headers))
    if err:
        fail('lima-charlie: could not exchange the API key for a JWT: {}'.format(err))
    # The documented response is an object carrying "jwt". Reading .get off a
    # list would abort the script, so the shape is checked rather than assumed.
    if type(response_json) != 'dict':
        fail('lima-charlie: the token endpoint returned an unexpected response shape, wanted an object')
    jwt = response_json.get('jwt')
    if not jwt:
        fail('lima-charlie: the token endpoint returned no jwt; check the OID and the API key')
    return jwt

def build_assets(oid, sensors):
    assets = []
    for item in sensors:
        # A non-dict entry -- null, or a bare string -- would abort the script
        # at the first .get, losing the rest of the page. Skip it and say so.
        if type(item) != 'dict':
            print('lima-charlie: skipping non-object sensor record: ' + str(item))
            continue
        sid = item.get('sid')
        hostname = item.get('hostname', '')
        arch_id = item.get('arch', '')

        if not sid:
            # A partially provisioned or deleted sensor comes back with a null
            # sid. ImportAsset(id=None) is rejected by the runtime with "id must
            # be a string", and Starlark has no exceptions, so that aborted the
            # whole run and lost every sensor already parsed.
            print('lima-charlie: skipping sensor with no sid: hostname=' + str(hostname))
        elif hostname in SENSORS_TO_IGNORE:
            print('Skipping sensor because it has been explicitly ignored in custom integration script:', sid, hostname)
        # Only an architecture explicitly mapped to False is filtered. A sensor
        # with no arch field, or one carrying a value the map has never heard
        # of, is imported rather than silently dropped behind a message
        # implying the operator configured the exclusion.
        elif ARCHITECTURE.get(arch_id, True) == False:
            print('Skipping sensor because sensor architecture', arch_id, 'has been set to False in custom integration script:', sid, hostname)
        else:
            # Parse IPs and mac addresses and build network interfaces.
            #
            # int_ip only. `ext_ip` is documented as the "External (public-facing)
            # IP address of the endpoint" -- the NAT egress address of whatever
            # gateway the sensor sits behind -- so every endpoint in one office
            # reports the same value. Putting it on an interface beside the
            # endpoint's own MAC invites unrelated machines to correlate onto one
            # shared address, and leaves a sensor with no MAC and no internal
            # address asserting nothing but that shared value. It is carried as a
            # custom attribute instead, which is what cybereason and kandji do
            # with the equivalent field.
            ips = []
            int_ip = item.get('int_ip', '')
            if int_ip:
                ips.append(int_ip)

            mac = item.get('mac_addr', '')
            if mac:
                mac = mac.replace("-", ":")
                network = network_interface(ips=ips, mac=mac)
            else:
                network = network_interface(ips=ips, mac=None)

            # network_interface returns None when nothing usable survives -- a
            # sensor that has enrolled but not yet checked in reports no int_ip,
            # no ext_ip and no mac_addr. Passing [None] to ImportAsset aborts the
            # entire run, losing every sensor already parsed, so such a sensor
            # gets no interface and correlates on its hostname instead.
            interfaces = [network] if network else []

            # Parse additional attributes collected from sensors, ignore attributes defined in ATTRIBS_TO_IGNORE
            custom_attrs = {}
            for key, value in item.items():
                if type(value) != 'dict':
                    if key not in CUSTOM_ATTRIBS_TO_IGNORE:
                        custom_attrs[key] = str(value)[:1023]

            assets.append(
                ImportAsset(
                    # The foreign id is scoped by the organization id so two
                    # LimaCharlie organizations imported into one runZero org
                    # cannot collide. The oid arrives through CONFIG, but it is
                    # the tenant identity the API itself keys on -- it sits in
                    # every request path and the JWT is minted for exactly that
                    # oid -- so it is immutable per tenant: changing it points
                    # the credential at a different organization outright, which
                    # SHOULD re-identify. The sid leaf is unchanged.
                    id='lima-charlie:{}:{}'.format(oid, sid),
                    hostnames=[hostname],
                    networkInterfaces=interfaces,
                    deviceType=platform_device_type(item.get('plat')),
                    customAttributes=to_custom_attributes(custom_attrs),
                )
            )

    return assets

def main(**kwargs):
    oid = kwargs['organization_id']
    access_token = kwargs['api_token']
    # The platform applies the CONFIG defaults, but fall back explicitly so the
    # script still works if it is invoked without them.
    base_url = (kwargs.get('url') or DEFAULT_LIMACHARLIE_BASE_URL).rstrip('/')
    jwt_url = (kwargs.get('jwt_url') or DEFAULT_LIMACHARLIE_JWT_URL).rstrip('/')

    # get_token ends the task in error itself when the exchange fails or
    # returns no jwt, so the token here is always usable.
    token = get_token(jwt_url, oid, access_token, kwargs)

    # Get sensors. The list is paged with a continuation token: a large
    # organization used to import only whatever the first response happened to
    # carry, silently, because the response was read once and never followed.
    url = '{}/{}/{}'.format(base_url, 'sensors', oid)
    http_options = get_http_options(kwargs, headers={"Authorization": bearer(token)})

    reported = 0
    total_sensors = 0
    continuation_token = None
    seen_tokens = {}

    p = pager('limacharlie-sensors')
    while p.next():
        page = p.page
        params = {}
        if continuation_token:
            params['continuation_token'] = continuation_token
        # `is_compressed` is deliberately not sent. With it, LimaCharlie replaces
        # the `sensors` array with a base64-encoded gzip blob, which this script
        # would then have to decode; without it the array arrives as plain JSON.
        data, err = get_json(url, params=params, **http_options)
        if err:
            fail('lima-charlie: failed to fetch sensors on page {} after reporting {}: {}'.format(
                page, reported, err))

        if type(data) != 'dict':
            fail('lima-charlie: the sensors endpoint returned an unexpected response shape, wanted an object')

        sensors_json = data.get('sensors', []) or []
        total_sensors += len(sensors_json)
        if sensors_json:
            reported += report_assets(build_assets(oid, sensors_json))

        continuation_token = data.get('continuation_token')
        if not continuation_token:
            break
        # A server that echoes the same token forever would spin here. Ending the
        # walk is the safe failure: a truncated import is recoverable, a task that
        # never finishes is not.
        if continuation_token in seen_tokens:
            print('Stopping: LimaCharlie repeated continuation token on page {}'.format(page))
            break
        seen_tokens[continuation_token] = True

    print('Reported {} assets from {} sensors'.format(reported, total_sensors))
    if not reported:
        print('No sensors were retrieved.')

    return None
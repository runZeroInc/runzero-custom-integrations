# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-tailscale",
    "name": "Tailscale",
    "type": "inbound",
    "description": "Imports devices from a Tailscale tailnet.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # sourceId/sourceName are deliberately NOT set. They bind a script to a
    # fixed native source identity and are reserved for platform-embedded
    # integrations under content/integrations/; a user-uploaded custom
    # integration may not claim one, and the platform validates the pair.
    #
    # The three keys below are forward-looking: a runZero build that predates
    # them ignores them and the integration behaves exactly as before, so they
    # are safe to ship now and start working when support lands.
    #
    # Store attributes under "tailscale.device.*" instead of the generic
    # "tailscale.custom.*" category. Individual assets may override via the
    # assetType field on ImportAsset.
    "assetType": "device",
    # Resolve the Tailscale account that owns each node into asset ownership,
    # the same way native integrations surface a logged-in user.
    "ownershipAttributes": ["tailscale_user"],
    # Tailscale reports the operating system authoritatively, so keep the
    # script-provided OS even when the fingerprint engine cannot normalize it.
    "trustOS": True,
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

load("runzero.types", "ImportAsset", "Software", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "post_json", "bearer", "url_encode")
load("kwargs", "get_url_base", "get_http_options")
load("time", "parse_time")
load("re", re_match="match")

# --- Configuration ---
# parse_time aborts the script on anything it cannot parse, and Starlark has no
# exception handling, so `created` is screened against this before the call. A
# space-separated or zone-less value -- what a proxy or an older node reports --
# used to take the whole import down. Checking the return value instead does not
# work: parse_time never returns, so a `!= None` guard after the call is dead
# code.
TIMESTAMP_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"

TAILSCALE_API_PATH = "/api/v2"
TAILSCALE_TOKEN_PATH = "/api/v2/oauth/token"
DEFAULT_SCOPE = "devices:core:read"

# Why a device was dropped. Each cause is tallied separately so one summary
# line per cause replaces one log line per device.
SKIP_NO_ID = "no_id"
SKIP_NO_INTERFACE = "no_interface"
SKIP_NOT_OBJECT = "not_object"


def _log(msg):
    print("tailscale: " + msg)


def _fail(msg):
    """End the task in error, prefixed the same way as _log."""
    fail("tailscale: " + msg)


def _strings(value):
    """Return only the string members of a list, or [] for anything else.

    A present-but-null field, a bare string where an array is documented, or a
    junk element inside one would otherwise abort the run at a join() or an
    iteration.
    """
    if type(value) != "list":
        return []
    return [v for v in value if type(v) == "string"]


def oauth_access_token(token_url, client_id, secret, config_kwargs):
    """Exchange OAuth client credentials for an access token.

    A refused exchange ends the task in error, as it must: no later request
    works without a token. The exchange goes through post_json rather than
    oauth2_token() because that builtin raises with a raw error of its own,
    where post_json hands the failure back as a string this can name.
    """
    form = url_encode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": DEFAULT_SCOPE,
    })
    data, err = post_json(
        token_url,
        body=bytes(form),
        **get_http_options(config_kwargs, headers={"Content-Type": "application/x-www-form-urlencoded"})
    )
    if err:
        _fail("OAuth token exchange failed: " + err)
    if type(data) != "dict":
        _fail("OAuth token exchange returned an unexpected response shape")
    token = data.get("access_token")
    if type(token) != "string" or not token:
        _fail("OAuth token exchange returned no access_token")
    return token


# Map Tailscale-reported operating systems to runZero device types where the
# form factor is unambiguous. General-purpose desktop/server OSes are left
# unset so fingerprinting and other data sources can classify them.
_OS_DEVICE_TYPES = {
    "ios": "Mobile",
    "ipados": "Tablet",
    "android": "Mobile",
    "tvos": "Smart TV",
}


def _device_type_for_os(os_name):
    return _OS_DEVICE_TYPES.get(os_name.lower(), "")


def tailscale_get_devices(api_base_url, access_token, tailnet, config_kwargs):
    """Fetch device inventory for a tailnet using an access token or API key."""
    url = api_base_url + "/tailnet/" + tailnet + "/devices?fields=all"
    data, err = get_json(url, **get_http_options(config_kwargs, headers={"Authorization": bearer(access_token), "Accept": "application/json"}))
    if err:
        _log(err)
        return None
    # The documented response is an object with a "devices" array. Anything else
    # is checked rather than assumed: reading .get off a list aborts the script
    # outright, so an API that answers with a bare array or an error document
    # would take down the whole import with no diagnostic.
    if type(data) != "dict":
        _log("unexpected response shape from " + url + ", wanted an object")
        return None
    return data.get("devices", [])


def transform_device_to_importasset(device, tailnet):
    # Returns (asset, skip_reason). A skip_reason is one of the SKIP_* keys
    # below, so main can tally each cause separately instead of logging one
    # line per device.
    device_id = device.get("id", "")
    if device_id == "":
        return None, SKIP_NO_ID

    # Tailscale exposes two names: `name` is the MagicDNS FQDN (a valid DNS
    # hostname, e.g. "my-laptop.tailnet.ts.net"), while `hostname` is the raw
    # machine name which can contain spaces/apostrophes (e.g. "<owner>'s Work
    # Laptop (2)") and would be rejected as a bogus hostname. Use the MagicDNS
    # name for hostnames and keep the display name as an attribute.
    magic_dns_name = device.get("name", "")
    machine_name = device.get("hostname", "")
    hostnames = []
    if magic_dns_name:
        hostnames.append(magic_dns_name)

    os_name = device.get("os", "Unknown")

    # Build primary interface from the device's Tailscale (VPN) addresses.
    # network_interface() handles v4/v6 classification, port/CIDR stripping,
    # dedupe, and capping at 99 addresses per family.
    nics = []
    tailscale_nic = network_interface(ips=_strings(device.get("addresses")))
    if tailscale_nic:
        nics.append(tailscale_nic)

    attrs = {
        "source": "Tailscale Integration",
        "tailscale_device_id": device_id,
        "tailscale_tailnet": tailnet,
        "tailscale_user": device.get("user", ""),
        "tailscale_machine_name": machine_name,
        "tailscale_magic_dns_name": magic_dns_name,
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
    if type(client_conn) == "dict":
        endpoints = _strings(client_conn.get("endpoints"))
        if endpoints:
            # Endpoints are the addresses the client is reachable at from the
            # OUTSIDE, and they include the public NAT egress address - which
            # every device in the same office shares. Placing that on a network
            # interface would invite cross-device IP correlation under the
            # default matchBehavior, so the endpoints are kept as a custom
            # attribute only and never become interface data.
            attrs["tailscale_client_endpoints"] = ", ".join(endpoints)

        derp = client_conn.get("derp", "")
        if derp:
            attrs["tailscale_client_derp"] = derp

        mapping_varies = client_conn.get("mappingVariesByDestIP")
        if mapping_varies != None:
            attrs["tailscale_mapping_varies_by_dest_ip"] = str(mapping_varies)

        latency = client_conn.get("latency")
        # A present-but-null or non-object latency map used to abort the run at
        # .items(); anything but an object is ignored.
        if type(latency) == "dict":
            for region, info in latency.items():
                # Each region maps to an object like
                # {"latencyMs": 182.89, "preferred": true}. Flatten the numeric
                # latency into its own attribute (searchable) instead of
                # stringifying the whole object.
                if type(info) == "dict":
                    ms = info.get("latencyMs")
                    if ms != None:
                        attrs["tailscale_latency_ms_" + region] = str(ms)
                    if info.get("preferred"):
                        attrs["tailscale_derp_preferred_region"] = region
                else:
                    attrs["tailscale_latency_ms_" + region] = str(info)

    if len(nics) == 0:
        # No address at all, so nothing to correlate on.
        return None, SKIP_NO_INTERFACE

    created = device.get("created")
    if type(created) == "string" and re_match(TIMESTAMP_RE, created):
        parsed = parse_time(created)
        if parsed != None:
            attrs["tailscale_created_ts"] = parsed.unix

    tags = _strings(device.get("tags"))
    if tags:
        attrs["tailscale_tags"] = ", ".join(tags)

    for field in ("advertisedRoutes", "enabledRoutes"):
        vals = _strings(device.get(field))
        if vals:
            attrs["tailscale_" + field] = ", ".join(vals)

    # Report the Tailscale client as installed software so it is tracked in the
    # software inventory (searchable, versioned).
    software = []
    client_version = device.get("clientVersion", "")
    if client_version:
        software.append(Software(
            id="tailscale-client-" + device_id,
            vendor="Tailscale",
            product="Tailscale",
            version=client_version,
        ))

    device_type = _device_type_for_os(os_name)

    return ImportAsset(
        id="tailscale-" + device_id,
        hostnames=hostnames,
        networkInterfaces=nics,
        os=os_name,
        deviceType=device_type or None,
        software=software,
        tags=["tailscale", "api"] + tags,
        customAttributes=to_custom_attributes(attrs),
    ), ""


def main(*args, **kwargs):
    client_id = kwargs.get("client_id")
    secret = kwargs.get("api_key_or_client_secret")
    base_url = get_url_base(kwargs, default="https://api.tailscale.com")
    api_url = base_url + TAILSCALE_API_PATH
    token_url = base_url + TAILSCALE_TOKEN_PATH
    tailnet = (kwargs.get("tailnet") or "").strip()

    if not secret:
        _log("api_key_or_client_secret (API key or client secret) is required")
        return []
    if not tailnet:
        _log("tailnet ID or name is required")
        return []

    # If a client_id was supplied, exchange it for an OAuth access token;
    # otherwise treat `secret` as a long-lived API key. The exchange reports
    # failures as a printed diagnostic and a clean return rather than a raw
    # abort - see oauth_access_token.
    if client_id:
        _log("using OAuth client credentials")
        # oauth_access_token ends the task in error itself when the exchange
        # fails, so the token here is always usable.
        token = oauth_access_token(token_url, client_id, secret, kwargs)
    else:
        _log("using an API key")
        token = secret

    devices = tailscale_get_devices(api_url, token, tailnet, kwargs) or []
    if not devices:
        _log("no devices found, or the API call failed")
        return []

    # Each asset is streamed as it is built, so a malformed record late in the
    # walk costs only itself rather than the whole buffered tailnet.
    reported = 0
    skipped = {SKIP_NO_ID: 0, SKIP_NO_INTERFACE: 0, SKIP_NOT_OBJECT: 0}
    first_skipped = {SKIP_NO_ID: "", SKIP_NO_INTERFACE: "", SKIP_NOT_OBJECT: ""}
    for d in devices:
        if type(d) != "dict":
            skipped[SKIP_NOT_OBJECT] += 1
            if skipped[SKIP_NOT_OBJECT] == 1:
                first_skipped[SKIP_NOT_OBJECT] = str(d)[:40]
            continue
        ia, reason = transform_device_to_importasset(d, tailnet)
        if ia == None:
            # Tally by cause and keep one example of each for diagnosis; a
            # tailnet-wide problem would otherwise print a line per device.
            skipped[reason] += 1
            if skipped[reason] == 1:
                first_skipped[reason] = str(d.get("name", ""))
            continue
        reported += report_asset(ia)

    if skipped[SKIP_NOT_OBJECT] > 0:
        _log("skipped {} device rows that were not objects (first: {})".format(
            skipped[SKIP_NOT_OBJECT], first_skipped[SKIP_NOT_OBJECT]))
    if skipped[SKIP_NO_ID] > 0:
        _log("skipped {} devices with no id (first: {})".format(
            skipped[SKIP_NO_ID], first_skipped[SKIP_NO_ID]))
    if skipped[SKIP_NO_INTERFACE] > 0:
        _log("skipped {} devices with no network interfaces (first: {})".format(
            skipped[SKIP_NO_INTERFACE], first_skipped[SKIP_NO_INTERFACE]))

    _log("reported " + str(reported) + " assets")
    return None

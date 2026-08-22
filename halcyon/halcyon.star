# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-halcyon",
    "name": "Halcyon",
    "type": "inbound",
    "description": "Imports endpoints from Halcyon.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Halcyon API URL",
            "type": "url",
            "required": False,
            "default": "https://api.halcyon.ai",
            "placeholder": "https://api.halcyon.ai",
            "description": "Halcyon's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
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
load('http', 'get_json', 'post_json', 'bearer')
load('kwargs', 'get_http_options')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_HALCYON_URL = "https://api.halcyon.ai"

# Distributions that ship only as a server platform, matched against the
# reported operatingSystem. Ubuntu, Debian, Fedora, openSUSE and macOS are
# deliberately absent: each is as often a workstation as a server. So is SUSE
# Linux Enterprise *Desktop*, which is why the list carries sles and not a bare
# "suse" substring.
SERVER_OS_NAMES = [
    "red hat enterprise", "rhel", "centos", "rocky linux", "almalinux",
    "amazon linux", "oracle linux", "suse linux enterprise server", "sles",
]


def _device_type(os_name):
    """Return a runZero device type for one Halcyon asset, or "".

    The search row is id, name, operatingSystem, agentVersion, heartbeat,
    policyGroup and registeredDate, and the detail record adds only addresses
    and dates -- no chassis, no model, no asset class anywhere -- so
    operatingSystem is the only genuine statement of role. "Windows Server
    2022" and the server-only distributions above are unambiguous.

    A bare "Windows 11", "Ubuntu 22.04" or "macOS 14" stays unset: it is a
    desktop or a laptop and the record cannot say which, and a wrong hint is
    worse than none.

    This is only a hint, and runZero prefers what it derives from the hardware
    or from its own scan. Nothing here feeds the hardware fingerprinter, so for
    a Halcyon-only endpoint this is the only type it will have.
    """
    text = str(os_name or "").lower()
    if "server" in text:
        return "Server"
    for name in SERVER_OS_NAMES:
        if name in text:
            return "Server"
    return ""


def _get_access_token(base_url, username, password, config_kwargs):
    data, err = post_json(
        "{}/identity/auth/login".format(base_url),
        json={"username": username, "password": password},
        **get_http_options(config_kwargs, headers={"Accept": "application/json"})
    )
    if err:
        print("Halcyon login failed:", err)
        return None
    return data.get("accessToken") if data else None

def _build_headers(api_token):
    return {
        "Authorization": bearer(api_token),
        "Accept": "application/json",
    }

def _refresh_access_token(auth_state):
    username = auth_state.get("username")
    password = auth_state.get("password")
    if not username or not password:
        return False
    api_token = _get_access_token(
        auth_state.get("base_url"), username, password, auth_state.get("config_kwargs"))
    if not api_token:
        return False
    auth_state["api_token"] = api_token
    return True

def _authorized_post_json(url, auth_state, payload):
    data, err = post_json(
        url,
        json=payload,
        **get_http_options(auth_state.get("config_kwargs"), headers=_build_headers(auth_state.get("api_token")))
    )
    if err and err.startswith("status 401") and _refresh_access_token(auth_state):
        data, err = post_json(
            url,
            json=payload,
            **get_http_options(auth_state.get("config_kwargs"), headers=_build_headers(auth_state.get("api_token")))
        )
    return data, err

def _authorized_get_json(url, auth_state):
    data, err = get_json(
        url,
        **get_http_options(auth_state.get("config_kwargs"), headers=_build_headers(auth_state.get("api_token")))
    )
    if err and err.startswith("status 401") and _refresh_access_token(auth_state):
        data, err = get_json(
            url,
            **get_http_options(auth_state.get("config_kwargs"), headers=_build_headers(auth_state.get("api_token")))
        )
    return data, err

def _build_network_interfaces(ip_objects, mac_list):
    # Halcyon IP entries are objects like {"ipAddressType": "IPv4", "value": "1.2.3.4"}.
    ips = [obj.get("value") for obj in ip_objects if type(obj) == "dict"]
    mac = ""
    if type(mac_list) == "list" and len(mac_list) > 0 and mac_list[0]:
        mac = str(mac_list[0])
    nic = network_interface(mac=mac, ips=ips)
    return [nic] if nic else []

def main(*args, **kwargs):
    username = kwargs.get('username')
    password_or_token = kwargs.get('password')
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_HALCYON_URL).rstrip('/')

    if not password_or_token:
        print("Error: Missing password.")
        return []

    api_token = None
    if username:
        api_token = _get_access_token(base_url, username, password_or_token, kwargs)
        if not api_token:
            return []
    else:
        # Backward compatible mode: password is already a bearer token.
        api_token = password_or_token

    auth_state = {
        "base_url": base_url,
        "username": username,
        "password": password_or_token if username else "",
        "api_token": api_token,
        "config_kwargs": kwargs,
    }

    reported = 0
    page = 1
    page_size = 10

    for _ in range(1000000000000):
        search_url = "{}/v2/assets/search".format(base_url)
        payload = {
            "filters": [],
            "pagination": {
                "page": page,
                "pageSize": page_size
            },
            "sorting": {
                "sortBy": "RegisteredDate",
                "sortOrder": "Desc"
            }
        }

        data, err = _authorized_post_json(search_url, auth_state, payload)
        if err:
            print("API Error during asset search:", err)
            break
        items = data.get("items", []) if data else []

        if not items:
            break

        page_assets = []
        for item in items:
            asset_id = item.get("id")
            if not asset_id:
                print("halcyon: skipping asset with no id: name=" + str(item.get("name", "")))
                continue

            detail_url = "{}/v2/assets/{}".format(base_url, asset_id)
            detail_data, detail_err = _authorized_get_json(detail_url, auth_state)

            ips = []
            macs = []
            if detail_err:
                print("Failed to fetch detailed info for asset {}: {}".format(asset_id, detail_err))
                detail_data = {}
            elif detail_data:
                ips = detail_data.get("ipAddresses", [])
                macs = detail_data.get("macAddresses", [])
            else:
                detail_data = {}

            net_interfaces = _build_network_interfaces(ips, macs)

            # Explicit allowlist mapping for the only custom fields we want.
            item_policy_group = item.get("policyGroup") if type(item.get("policyGroup")) == "dict" else {}
            detail_policy_group = detail_data.get("policyGroup") if type(detail_data.get("policyGroup")) == "dict" else {}

            mapping = {
                "agentVersion": item.get("agentVersion") or detail_data.get("agentVersion"),
                "heartbeat": item.get("heartbeat") or detail_data.get("heartbeat"),
                "policyGroupOwner": item_policy_group.get("owner") or detail_policy_group.get("owner"),
                "registeredDate": item.get("registeredDate") or detail_data.get("registeredDate"),
                "createdDate": detail_data.get("createdDate"),
                "lastHeartbeatDate": detail_data.get("lastHeartbeatDate"),
                "lastUpdatedDate": detail_data.get("lastUpdatedDate"),
            }

            custom_attrs = {}
            for key, value in mapping.items():
                if value != None and value != "":
                    custom_attrs[key] = str(value)

            hostname = item.get("name")
            if not hostname and type(detail_data) == "dict":
                hostname = detail_data.get("name")

            os_name = item.get("operatingSystem")
            asset_params = {
                "id": str(asset_id),
                "hostnames": [str(hostname)] if hostname else [],
                "os": str(os_name) if os_name else "",
                "networkInterfaces": net_interfaces,
                "customAttributes": to_custom_attributes(custom_attrs),
            }

            # Omitted rather than set to "" when the OS names no role: an empty
            # deviceType is still a value and displaces the type runZero would
            # otherwise derive for itself.
            device_type = _device_type(os_name)
            if device_type:
                asset_params["deviceType"] = device_type

            page_assets.append(ImportAsset(**asset_params))

        # Build and stream each page via report_assets so the full asset set is
        # never held in memory.
        reported += report_assets(page_assets)

        # Handle pagination using the API's pagination block
        pagination = data.get("pagination", {})
        current_page = pagination.get("currentPage", page)
        total_pages = pagination.get("totalPages", 1)

        if current_page >= total_pages:
            break

        page += 1

    if not reported:
        print("no assets")

    return None
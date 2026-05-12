load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_decode='decode', json_encode='encode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get')

BASE_URL = "https://api.halcyon.ai"


def _get_access_token(username, password):
    login_url = "{}/identity/auth/login".format(BASE_URL)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "username": username,
        "password": password,
    }

    response = http_post(login_url, headers=headers, body=bytes(json_encode(payload)))

    if response.status_code != 200:
        print("Halcyon login failed: {} {}".format(response.status_code, response.body))
        return None

    token = json_decode(response.body).get("accessToken")

    return token

def _build_headers(api_token):
    return {
        "Authorization": "Bearer {}".format(api_token),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def _refresh_access_token(auth_state):
    username = auth_state.get("username")
    password = auth_state.get("password")

    if not username or not password:
        return False

    api_token = _get_access_token(username, password)
    if not api_token:
        return False

    auth_state["api_token"] = api_token
    return True

def _authorized_post(url, auth_state, payload):
    response = http_post(url, headers=_build_headers(auth_state.get("api_token")), body=bytes(json_encode(payload)))

    if response.status_code == 401 and _refresh_access_token(auth_state):
        response = http_post(url, headers=_build_headers(auth_state.get("api_token")), body=bytes(json_encode(payload)))

    return response

def _authorized_get(url, auth_state):
    response = http_get(url, headers=_build_headers(auth_state.get("api_token")))

    if response.status_code == 401 and _refresh_access_token(auth_state):
        response = http_get(url, headers=_build_headers(auth_state.get("api_token")))

    return response

def _build_network_interfaces(ip_objects, mac_list):
    ip4s = []
    ip6s = []

    # Halcyon IP entries are objects like: {"ipAddressType": "IPv4", "value": "1.2.3.4"}
    for ip_obj in ip_objects:
        if type(ip_obj) != "dict":
            continue
        ip_text = ip_obj.get("value")
        if not ip_text:
            continue

        addr = ip_address(ip_text)
        if not addr:
            continue
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)

    mac_address = ""
    if type(mac_list) == "list" and len(mac_list) > 0 and mac_list[0]:
        mac_address = str(mac_list[0])

    if not mac_address and not ip4s and not ip6s:
        return []

    return [NetworkInterface(macAddress=mac_address, ipv4Addresses=ip4s, ipv6Addresses=ip6s)]

def main(*args, **kwargs):
    # Preferred credential mode: access_key=username, access_secret=password.
    username = kwargs.get('access_key')
    password_or_token = kwargs.get('access_secret')

    if not password_or_token:
        print("Error: Missing access_secret.")
        return []

    api_token = None
    if username:
        api_token = _get_access_token(username, password_or_token)
        if not api_token:
            return []
    else:
        # Backward compatible mode: access_secret is already a bearer token.
        api_token = password_or_token

    auth_state = {
        "username": username,
        "password": password_or_token if username else "",
        "api_token": api_token,
    }

    assets = []
    page = 1
    page_size = 10

    for _ in range(1000000000000):
        search_url = "{}/v2/assets/search".format(BASE_URL)
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

        response = _authorized_post(search_url, auth_state, payload)

        if response.status_code != 200:
            print("API Error during asset search: {} {}".format(response.status_code, response.body))
            break

        data = json_decode(response.body)
        items = data.get("items", [])

        if not items:
            break

        for item in items:
            asset_id = item.get("id")
            if not asset_id:
                continue

            detail_url = "{}/v2/assets/{}".format(BASE_URL, asset_id)
            detail_res = _authorized_get(detail_url, auth_state)

            ips = []
            macs = []
            detail_data = {}

            if detail_res.status_code == 200:
                detail_data = json_decode(detail_res.body)
                ips = detail_data.get("ipAddresses", [])
                macs = detail_data.get("macAddresses", [])
            else:
                print("Failed to fetch detailed info for asset {}: {}".format(asset_id, detail_res.status_code))

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
            assets.append(ImportAsset(
                id=str(asset_id),
                hostnames=[str(hostname)] if hostname else [],
                os=str(os_name) if os_name else "",
                networkInterfaces=net_interfaces,
                customAttributes=custom_attrs
            ))

        # Handle pagination using the API's pagination block
        pagination = data.get("pagination", {})
        current_page = pagination.get("currentPage", page)
        total_pages = pagination.get("totalPages", 1)

        if current_page >= total_pages:
            break

        page += 1

    return assets
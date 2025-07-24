load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('requests', 'Session')
load('json', json_encode='encode', json_decode='decode')
load('uuid', 'new_uuid')
load('flatten_json', 'flatten')
load('net', 'ip_address')

SKIP_UNMANAGED = False

def asset_networks(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        ip_obj = ip_address(ip)
        if ip_obj.version == 4:
            ip4s.append(ip_obj)
        elif ip_obj.version == 6:
            ip6s.append(ip_obj)
    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(*args, **kwargs):
    username = kwargs.get('access_key')
    password = kwargs.get('access_secret')

    session = Session()
    session.headers.set('Content-Type', 'application/json')
    session.headers.set('Accept', 'application/json')

    login_payload = {
        "username": username,
        "password": password
    }
    login_resp = session.post("https://api.extremecloudiq.com/login", body=bytes(json_encode(login_payload)))
    print("Login response code:", login_resp.status_code)
    login_body = json_decode(login_resp.body)
    print("Login response body:", login_body.keys())

    if not login_resp or login_resp.status_code != 200:
        return []

    token = login_body.get("access_token")
    if not token:
        print("Access token not found in response.")
        return []

    session.headers.set("Authorization", "Bearer {}".format(token))

    assets = []
    page = 1
    limit = 100

    while True:
        url = "https://api.extremecloudiq.com/devices?page={}&limit={}&view=full".format(page, limit)
        print("Fetching page:", page)
        resp = session.get(url)
        print("Page response code:", resp.status_code)
        devices_body = json_decode(resp.body)

        if not resp or resp.status_code != 200:
            break

        devices = devices_body.get("data", [])
        if not devices:
            print("No devices on page", page)
            break

        for device in devices:

            if device.get("device_admin_state", "") != "MANAGED" and SKIP_UNMANAGED:
                print("Skipping unmanaged device.")
                continue

            ips = []
            if "ip_address" in device and device["ip_address"]:
                ips.append(device["ip_address"])
            if "ipv6_address" in device and device["ipv6_address"]:
                ips.append(device["ipv6_address"])

            mac = device.get("mac_address", "")

            asset = ImportAsset(
                id=device.get("id") or new_uuid(),
                hostnames=[device.get("hostname", "")],
                networkInterfaces=[asset_networks(ips, mac)],
                device_type=device.get("device_function", ""),
                customAttributes={}
            )

            for key in device.keys():
                if key not in ["id", "hostname", "mac_address", "ip_address", "ipv6_address"]:
                    val = device[key]
                    if type(val) == "dict":
                        asset.customAttributes.update(flatten(val))
                    elif type(val) in ["string", "int", "bool"]:
                        asset.customAttributes[key] = str(val)

            assets.append(asset)

        if len(devices) < limit:
            break
        page += 1

    print("Total assets imported:", len(assets))
    return assets

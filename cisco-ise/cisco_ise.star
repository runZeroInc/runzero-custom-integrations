load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')

# Constants
CISCO_ISE_HOST = "<UPDATE_ME>"
ENDPOINTS_API_URL = "{}/admin/API/mnt/Session/ActiveList".format(CISCO_ISE_HOST)

def extract_sessions(xml):
    sessions = []
    chunks = xml.split("<activeSession>")
    for chunk in chunks[1:]:
        session = {}
        for tag in ["user_name", "calling_station_id", "nas_ip_address", "acct_session_id", "audit_session_id", "server", "framed_ip_address", "device_ip_address"]:
            open_tag = "<{}>".format(tag)
            close_tag = "</{}>".format(tag)
            if open_tag in chunk and close_tag in chunk:
                value = chunk.split(open_tag)[1].split(close_tag)[0]
                session[tag] = value
            else:
                session[tag] = None
        sessions.append(session)
    return sessions

def get_endpoints(auth_b64):
    """Retrieve all endpoints from Cisco ISE."""
    headers = {
        "Accept": "application/xml",
        "Authorization": "Basic {}".format(auth_b64)
    }

    response = http_get(ENDPOINTS_API_URL, headers=headers)

    if response.status_code != 200:
        print("Failed to retrieve endpoints. Status: {}".format(response.status_code))
        print(response.body)
        return []

    xml = response.body
    sessions = extract_sessions(xml)

    print("Total number of sessions: {}".format(len(sessions)))

    return sessions

def build_network_interface(ip, mac=None):
    """Build a runZero NetworkInterface object."""
    ip4s, ip6s = [], []

    if ip:
        ip_addr = ip_address(ip)
        if ip_addr.version == 4:
            ip4s.append(ip_addr)
        elif ip_addr.version == 6:
            ip6s.append(ip_addr)

    if not ip4s and not ip6s and not mac:
        return None

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def build_assets(sessions):
    """Convert Cisco ISE session data into runZero assets."""
    assets = []

    for session in sessions:
        mac = session.get("calling_station_id")
        ip = session.get("device_ip_address") or session.get("framed_ip_address")
        hostname = session.get("user_name")

        if not mac and not ip:
            continue

        network = build_network_interface(ip=ip, mac=mac)

        custom_attrs = {
            "acct_session_id": session.get("acct_session_id"),
            "audit_session_id": session.get("audit_session_id"),
            "nas_ip_address": session.get("nas_ip_address"),
            "server": session.get("server")
        }

        assets.append(
            ImportAsset(
                id=session.get("audit_session_id"),
                hostnames=[hostname] if hostname else [],
                networkInterfaces=[network] if network else [],
                customAttributes=custom_attrs
            )
        )

    return assets

def main(*args, **kwargs):
    """Main function for Cisco ISE integration."""
    auth_b64 = kwargs.get('access_secret')

    if not auth_b64:
        print("Missing authentication credentials.")
        return []

    sessions = get_endpoints(auth_b64)

    if not sessions:
        print("No sessions found.")
        return []

    assets = build_assets(sessions)

    if not assets:
        print("No assets created.")

    return assets

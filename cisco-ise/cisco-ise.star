# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-cisco-ise",
    "name": "Cisco ISE",
    "type": "inbound",
    "description": "Imports endpoints from Cisco Identity Services Engine.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Cisco ISE URL",
            "type": "url",
            "required": True,
            "placeholder": "https://ise.example.com",
        },
        {
            "key": "basic_auth_credential",
            "label": "Base64 basic-auth credential",
            "type": "secret",
            "required": True,
            "description": "Base64-encoded user:password for the Cisco ISE API",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', http_get='get')
load('kwargs', 'get_url_base', 'get_http_options')

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

def get_endpoints(endpoints_api_url, auth_b64, config_kwargs):
    """Retrieve all endpoints from Cisco ISE."""
    headers = {
        "Accept": "application/xml",
        "Authorization": "Basic {}".format(auth_b64)
    }

    response = http_get(endpoints_api_url, **get_http_options(config_kwargs, headers=headers))

    if response.status_code != 200:
        print("Failed to retrieve endpoints. Status: {}".format(response.status_code))
        print(response.body)
        return []

    xml = response.body
    sessions = extract_sessions(xml)

    print("Total number of sessions: {}".format(len(sessions)))

    return sessions

def build_assets(sessions):
    """Convert Cisco ISE session data into runZero assets."""
    assets = []

    for session in sessions:
        mac = session.get("calling_station_id")
        ip = session.get("device_ip_address") or session.get("framed_ip_address")
        hostname = session.get("user_name")

        if not mac and not ip:
            continue

        network = network_interface(ip=ip, mac=mac)

        custom_attrs = {
            "acct_session_id": session.get("acct_session_id"),
            "audit_session_id": session.get("audit_session_id"),
            "nas_ip_address": session.get("nas_ip_address"),
            "server": session.get("server")
        }

        assets.append(
            ImportAsset(
                id=session.get("audit_session_id"),
                hostnames=[hostname],
                networkInterfaces=[network],
                customAttributes=to_custom_attributes(custom_attrs),
                matchBehavior="no-id-match no-id-break",
            )
        )

    return assets

def main(*args, **kwargs):
    """Main function for Cisco ISE integration."""
    base_url = get_url_base(kwargs)
    endpoints_api_url = base_url + "/admin/API/mnt/Session/ActiveList"
    auth_b64 = kwargs.get('basic_auth_credential')

    if not auth_b64:
        print("Missing authentication credentials.")
        return []

    sessions = get_endpoints(endpoints_api_url, auth_b64, kwargs)

    if not sessions:
        print("No sessions found.")
        return None

    # Stream assets to runZero via report_assets instead of returning a list.
    if not report_assets(build_assets(sessions)):
        print("No assets created.")

    return None

# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-cisco-ise",
    "name": "Cisco ISE",
    "type": "inbound",
    "description": "Imports endpoints from Cisco Identity Services Engine.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
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

SESSION_PATH = "/admin/API/mnt/Session/ActiveList"

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
        # The body is the full ActiveList session XML: usernames, MAC addresses
        # and endpoint IPs. The status and the path say what failed and why
        # without reproducing any of it.
        print("cisco-ise: failed to retrieve endpoints from {}: status {}".format(
            SESSION_PATH, response.status_code))
        return []

    xml = response.body
    sessions = extract_sessions(xml)

    print("Total number of sessions: {}".format(len(sessions)))

    return sessions

def build_assets(sessions):
    """Convert Cisco ISE session data into runZero assets."""
    assets = []
    # A one-element list so the loop below can increment it; Starlark has no
    # nonlocal, and a bare int rebinding inside the loop is fine but this keeps
    # the count next to its report at the end.
    skipped_no_interface = [0]
    skipped_no_addressing = [0]

    for session in sessions:
        mac = session.get("calling_station_id")
        ip = session.get("device_ip_address") or session.get("framed_ip_address")
        user_name = session.get("user_name")

        if not mac and not ip:
            # An ISE session carries no device identifier beyond its addressing:
            # audit_session_id names the SESSION, not the endpoint, and is
            # already excluded from matching by matchBehavior below. With
            # neither a MAC nor an address there is nothing to correlate on at
            # all, so the record cannot become an asset. The session id is
            # logged rather than user_name, which is a person's login. Only the
            # first one is named; the rest are counted, so a broken export does
            # not emit a line per session.
            if skipped_no_addressing[0] == 0:
                print("cisco-ise: skipping session with no calling_station_id/ip: session=" + str(session.get("audit_session_id", "")))
            skipped_no_addressing[0] += 1
            continue

        # network_interface takes a list of addresses as `ips`; there is no
        # singular `ip` keyword, and passing one aborts the script.
        ips = [ip] if ip else []
        network = network_interface(ips=ips, mac=mac)

        # It returns None when nothing usable survives -- an RA-VPN session
        # reports the client's public address in calling_station_id rather than
        # a MAC and carries no framed address, so neither field parses. Passing
        # [None] to ImportAsset aborts the whole run, losing every session
        # already parsed, so such a record is skipped instead.
        if not network:
            skipped_no_interface[0] += 1
            continue

        # user_name is the RADIUS User-Name, not a hostname: for 802.1X user
        # authentication it is the person who logged in, and for MAB it is the
        # endpoint's MAC address as a string. Importing it as a hostname made
        # every endpoint a user touched merge into one asset, because custom
        # integration hostnames are trusted for both matching and breaking.
        # Machine authentication is the one case that does name a host, and it
        # is identifiable by the host/ prefix.
        hostnames = []
        if user_name and user_name.startswith("host/"):
            machine_name = user_name[len("host/"):].strip()
            if machine_name:
                hostnames.append(machine_name)

        custom_attrs = {
            "acct_session_id": session.get("acct_session_id"),
            "audit_session_id": session.get("audit_session_id"),
            "nas_ip_address": session.get("nas_ip_address"),
            "server": session.get("server"),
            "user_name": user_name,
        }

        assets.append(
            ImportAsset(
                id=session.get("audit_session_id"),
                hostnames=hostnames,
                networkInterfaces=[network],
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )

    if skipped_no_addressing[0]:
        print("cisco-ise: skipped {} session(s) with no calling_station_id/ip".format(
            skipped_no_addressing[0]))

    if skipped_no_interface[0]:
        print("cisco-ise: skipped {} session(s) with no usable MAC or IP address".format(
            skipped_no_interface[0]))

    return assets

def main(*args, **kwargs):
    """Main function for Cisco ISE integration."""
    base_url = get_url_base(kwargs)
    endpoints_api_url = base_url + SESSION_PATH
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

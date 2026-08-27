# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-nexthink",
    "name": "Nexthink",
    "type": "inbound",
    "description": "Imports devices from Nexthink using the NQL export workflow.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "auth_url",
            "label": "Nexthink authentication URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<instance>-login.<region>.nexthink.cloud",
        },
        {
            "key": "api_url",
            "label": "Nexthink API URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<instance>.api.<region>.nexthink.cloud",
        },
        {
            "key": "client_id",
            "label": "Client ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "client_secret",
            "label": "Client secret",
            "type": "secret",
            "required": True,
        },
        {
            "key": "query_id",
            "label": "NQL query ID",
            "type": "string",
            "required": False,
            "default": "#runzero_integration",
        },
        {
            "key": "scope",
            "label": "OAuth scope",
            "type": "string",
            "required": False,
            "default": "service:integration",
        },
        {
            "key": "poll_timeout",
            "label": "Export poll timeout (seconds)",
            "description": "How long to wait for the asynchronous NQL export to complete. Large estates can take several minutes.",
            "type": "int",
            "required": False,
            "default": 300,
            "min": 10,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('http', http_post='post', http_get='get', url_parse='url_parse', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('base64', base64_encode='encode')
load('net', 'ip_address')
load('csv', csv_read='read_all')
load('kwargs', 'require', 'get_string', 'get_int', 'get_http_options')
load('time', 'sleep')

# Nexthink runs the export asynchronously, so the status endpoint is polled
# until it reports COMPLETED, with a sleep between attempts so the budget is
# real wall-clock time. The budget itself is the poll_timeout CONFIG
# parameter (default 300 seconds), because a large estate's export routinely
# needs minutes and a too-small fixed budget imports nothing on every run.
STATUS_POLL_INTERVAL = "2s"
STATUS_POLL_INTERVAL_SECONDS = 2

# Nexthink's NQL device table carries an explicit form factor at
# `device.hardware.type`, documented as "the device form factor" and taking
# exactly three values: desktop, laptop, virtual. Only the first two name a
# chassis. "virtual" says the device is a hypervisor guest, which is not a form
# factor and has no counterpart in runZero's device-type vocabulary, so it is
# deliberately unmapped -- the value still travels as a custom attribute, and
# runZero's own fingerprinting keeps deciding what the guest actually is.
#
# The column is only present when the saved NQL query selects it, so a query
# written before this mapping existed simply produces no device type rather
# than failing. See the README's field list.
HARDWARE_DEVICE_TYPES = {
    "desktop": "Desktop",
    "laptop": "Laptop",
}

def _safe_str(value):
    if value == None:
        return ""
    return str(value)

def _device_type(hardware_type):
    """Map device.hardware.type onto a runZero device type, or None."""
    return HARDWARE_DEVICE_TYPES.get(hardware_type.strip().lower(), None)

def _normalize_ipv4_mapped_ip(ip_raw):
    if not ip_raw:
        return ""
    ip_text = str(ip_raw)
    if ip_text.startswith("::ffff:"):
        return ip_text[7:]
    return ip_text

def _build_os_version(build_value):
    if not build_value:
        return ""
    text = str(build_value).strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1]
        parts = [p.strip() for p in inner.split(",")]
        if len(parts) >= 2 and parts[0] and parts[1]:
            return "{}.{}".format(parts[0], parts[1])
    return text

def _body_to_text(body):
    if type(body) == "string":
        return body
    return str(body)

def _log_path(url):
    """The path portion of a URL, for error logs.

    Never log a whole response body from this API: the token endpoint answers
    with the access token itself, and the export endpoints answer with device
    inventory. The path plus the status says what failed and why. The query
    string is dropped too, because resultsFileUrl is pre-signed and carries its
    signature there.
    """
    parsed = url_parse(url)
    if parsed and parsed.path:
        return parsed.path
    return _safe_str(url).split("?")[0]

def _parse_ip_addrs(ip_raw):
    ip4s = []
    ip6s = []
    parsed = None
    if ip_raw:
        parsed = ip_address(_normalize_ipv4_mapped_ip(ip_raw))
    if parsed and parsed.version == 4:
        ip4s.append(parsed)
    elif parsed and parsed.version == 6:
        ip6s.append(parsed)
    return ip4s, ip6s

def parse_csv_rows(csv_text):
    # csv.read_all handles quoting properly, including a quoted field that
    # contains a newline -- the case a hand-rolled split-on-newlines parser
    # corrupts. Rows shorter than the header are padded with "".
    if not csv_text:
        return []
    return csv_read(csv_text)

def get_token(client_id, client_secret, base_url, scope, config):
    token_url = "{}/oauth2/default/v1/token".format(base_url)
    auth_str = "{}:{}".format(client_id, client_secret)
    encoded_auth = base64_encode(auth_str)

    headers = {
        "Authorization": "Basic {}".format(encoded_auth),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    # Okta-hosted token endpoints require grant_type (and scope) in the
    # x-www-form-urlencoded BODY; parameters riding the query string are
    # rejected with invalid_grant/unsupported_grant_type.
    form = {"grant_type": "client_credentials"}
    if scope:
        form["scope"] = scope

    response = http_post(token_url, body=bytes(url_encode(form)), **get_http_options(config, headers=headers))
    if response.status_code != 200:
        fail("nexthink: the token endpoint {} answered status {}; check the client id and secret".format(
            _log_path(token_url), response.status_code))

    data = json_decode(response.body)
    token = data.get("access_token")
    if not token:
        fail("nexthink: the token endpoint {} returned no access_token".format(_log_path(token_url)))
    return token

def start_nql_export(token, api_url, query_id, config):
    # Nexthink documents the export start as POST /api/v1/nql/export with a
    # JSON body carrying queryId. A GET with a query parameter is rejected by
    # the real API. The raw http_post never retries, so a slow export is not
    # started twice.
    url = "{}/api/v1/nql/export".format(api_url)
    headers = {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {"queryId": _safe_str(query_id)}

    response = http_post(url, body=bytes(json_encode(payload)), **get_http_options(config, headers=headers))
    if response.status_code == 200:
        # json_decode aborts the script on malformed input, and reading .get off
        # a list aborts it too, so the body is screened before either happens.
        body = response.body.strip() if response.body else ""
        if not body.startswith("{"):
            print("Unexpected NQL export response body; wanted a JSON object.")
            return None
        data = json_decode(body)
        if type(data) != "dict":
            print("Unexpected NQL export response shape; wanted an object.")
            return None
        return data.get("exportId")
    if response.status_code == 401:
        return "__UNAUTHORIZED__"

    print("nexthink: failed to start NQL export at {}: status {}".format(
        _log_path(url), response.status_code))
    return None

def get_export_status(token, api_url, export_id, config):
    url = "{}/api/v1/nql/status/{}".format(api_url, export_id)
    headers = {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/json",
    }

    response = http_get(url, **get_http_options(config, headers=headers))
    if response.status_code == 200:
        # Screened for the same reason as the export call above: a malformed
        # body aborts json_decode, and callers read this result with .get.
        body = response.body.strip() if response.body else ""
        if not body.startswith("{"):
            print("Unexpected export status body; wanted a JSON object.")
            return None
        status = json_decode(body)
        if type(status) != "dict":
            print("Unexpected export status shape; wanted an object.")
            return None
        return status
    if response.status_code == 401:
        return {"__unauthorized__": True}

    print("nexthink: failed to get export status from {}: status {}".format(
        _log_path(url), response.status_code))
    return None

def fetch_all_export_rows(token, api_url, query_id, client_id, client_secret, auth_url, scope, max_polls, config):
    export_id = start_nql_export(token, api_url, query_id, config)
    if export_id == "__UNAUTHORIZED__":
        token = get_token(client_id, client_secret, auth_url, scope, config)
        if not token:
            return []
        export_id = start_nql_export(token, api_url, query_id, config)
    if not export_id:
        return []

    status_data = None
    for attempt in range(0, max_polls):
        # The gap goes between attempts, not before the first one, so an export
        # that is already finished still costs a single request and no wait.
        if attempt > 0:
            sleep(STATUS_POLL_INTERVAL)
        status_data = get_export_status(token, api_url, export_id, config)
        if not status_data:
            return []

        if status_data.get("__unauthorized__"):
            token = get_token(client_id, client_secret, auth_url, scope, config)
            if not token:
                return []
            status_data = get_export_status(token, api_url, export_id, config)
            if not status_data or status_data.get("__unauthorized__"):
                return []

        status = _safe_str(status_data.get("status")).upper()
        if status == "COMPLETED" or status == "COMPLETE":
            break
        if status == "FAILED" or status == "CANCELED" or status == "ERROR":
            print("NQL export failed with status: {}".format(status))
            return []

    if not status_data:
        print("NQL export status was not available")
        return []

    final_status = _safe_str(status_data.get("status")).upper()
    if final_status != "COMPLETED" and final_status != "COMPLETE":
        print("NQL export did not complete in time. Last status: {}".format(final_status))
        return []

    results_file_url = _safe_str(status_data.get("resultsFileUrl"))
    if not results_file_url:
        print("NQL export completed but no resultsFileUrl was returned")
        return []

    # The raw http_get ends the whole script on a transport-level failure rather
    # than returning a response, and Starlark has no exception handling, so a URL
    # it could never fetch is refused before the call is made. A scheme-less or
    # host-less resultsFileUrl -- what a misconfigured object store front end or
    # an egress proxy rewrite produces -- used to abort the run with
    # 'unsupported protocol scheme ""' instead of reporting a failed download.
    parsed_url = url_parse(results_file_url)
    if not parsed_url or not parsed_url.hostname or parsed_url.scheme not in ("http", "https"):
        print("Failed to download export results from {}: not an absolute http(s) URL".format(results_file_url))
        return []

    # resultsFileUrl is pre-signed. Do not send Authorization headers.
    download_response = http_get(results_file_url, **get_http_options(config))
    if not download_response:
        print("Failed to download export results from {}: no response".format(results_file_url))
        return []

    if download_response.status_code == 406:
        download_response = http_get(results_file_url, **get_http_options(config, headers={"Accept": "text/csv"}))
        if not download_response:
            print("Failed to download export results from {}: no response".format(results_file_url))
            return []

    if download_response.status_code != 200:
        print("nexthink: failed to download export results from {}: status {}".format(
            _log_path(results_file_url), download_response.status_code))
        return []

    csv_text = _body_to_text(download_response.body)
    return parse_csv_rows(csv_text)

def main(**kwargs):
    require(kwargs, "client_id", "client_secret", "auth_url", "api_url")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    auth_url = get_string(kwargs, "auth_url")
    api_url = get_string(kwargs, "api_url")
    query_id = get_string(kwargs, "query_id", default="#runzero_integration")
    scope = get_string(kwargs, "scope", default="service:integration")

    # The wall-clock budget for the asynchronous export, spent in
    # 2-second poll intervals.
    poll_timeout = get_int(kwargs, "poll_timeout", default=300)
    max_polls = poll_timeout // STATUS_POLL_INTERVAL_SECONDS
    if max_polls < 1:
        max_polls = 1

    token = get_token(client_id, client_secret, auth_url, scope, kwargs)
    if not token:
        return []

    rows = fetch_all_export_rows(token, api_url, query_id, client_id, client_secret, auth_url, scope, max_polls, kwargs)
    if type(rows) != "list" or len(rows) == 0:
        print("No rows returned from Nexthink export workflow")
        return []

    reported = 0

    for row in rows:
        asset_id = row.get("device.uid")
        if not asset_id:
            continue

        hostname = _safe_str(row.get("device.name"))
        os_name = _safe_str(row.get("device.operating_system.name"))
        os_build_raw = row.get("device.operating_system.build")
        os_version = _build_os_version(os_build_raw)

        manufacturer = _safe_str(row.get("device.hardware.manufacturer"))
        model = _safe_str(row.get("device.hardware.model"))
        hardware_type = _safe_str(row.get("device.hardware.type"))
        serial = _safe_str(row.get("device.hardware.chassis_serial_number"))
        first_seen = _safe_str(row.get("device.first_seen"))
        last_seen = _safe_str(row.get("device.last_seen"))

        ip4s, ip6s = _parse_ip_addrs(row.get("device.collector.local_ip"))

        net_ifaces = []
        if ip4s or ip6s:
            net_ifaces.append(NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s))

        custom_attrs = {
            "nexthink.first_seen": first_seen,
            "nexthink.last_seen": last_seen,
            "nexthink.hardware.manufacturer": manufacturer,
            "nexthink.hardware.model": model,
            "nexthink.hardware.type": hardware_type,
            "nexthink.hardware.chassis_serial_number": serial,
            "nexthink.operating_system.build": _safe_str(os_build_raw),
            "nexthink.collector.local_ip": _safe_str(row.get("device.collector.local_ip")),
        }

        # Report each asset as it is built so a failure partway through the
        # walk keeps everything already reported, instead of buffering the
        # whole estate for one flush at the end.
        reported += report_asset(ImportAsset(
            id=str(asset_id),
            hostnames=[hostname] if hostname else [],
            os=os_name,
            osVersion=os_version,
            deviceType=_device_type(hardware_type),
            networkInterfaces=net_ifaces,
            customAttributes=custom_attrs,
        ))

    print("nexthink: reported {} assets".format(reported))
    return None

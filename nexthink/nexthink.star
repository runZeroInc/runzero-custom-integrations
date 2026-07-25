# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-nexthink",
    "name": "Nexthink",
    "type": "inbound",
    "description": "Imports devices from Nexthink using the NQL export workflow.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
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
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('http', http_post='post', http_get='get')
load('json', json_encode='encode', json_decode='decode')
load('base64', base64_encode='encode')
load('net', 'ip_address')
load('kwargs', 'require', 'get_string', 'get_http_options')

def _safe_str(value):
    if value == None:
        return ""
    return str(value)

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

def _encode_query_id(query_id):
    qid = _safe_str(query_id)
    if qid.startswith("#"):
        return "%23{}".format(qid[1:])
    return qid

def _body_to_text(body):
    if type(body) == "string":
        return body
    return str(body)

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

def _parse_csv_line(line):
    fields = []
    current = ""
    in_quotes = False
    quote_escaped = False

    for i in range(len(line)):
        ch = line[i]

        if quote_escaped:
            quote_escaped = False
            continue

        if in_quotes:
            if ch == '"':
                if i + 1 < len(line) and line[i + 1] == '"':
                    current += '"'
                    quote_escaped = True
                else:
                    in_quotes = False
            else:
                current += ch
        else:
            if ch == '"':
                in_quotes = True
            elif ch == ',':
                fields.append(current)
                current = ""
            else:
                current += ch

    fields.append(current)
    return fields

def parse_csv_rows(csv_text):
    lines = csv_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) == 0 or lines[0] == "":
        return []

    headers = _parse_csv_line(lines[0])
    rows = []

    for line in lines[1:]:
        if not line:
            continue
        values = _parse_csv_line(line)
        row = {}
        for idx in range(len(headers)):
            key = headers[idx]
            if idx < len(values):
                row[key] = values[idx]
            else:
                row[key] = ""
        rows.append(row)

    return rows

def get_token(client_id, client_secret, base_url, scope, config):
    token_url = "{}/oauth2/default/v1/token".format(base_url)
    auth_str = "{}:{}".format(client_id, client_secret)
    encoded_auth = base64_encode(auth_str)

    headers = {
        "Authorization": "Basic {}".format(encoded_auth),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    params = {"grant_type": "client_credentials"}
    if scope:
        params["scope"] = scope

    response = http_post(token_url, params=params, **get_http_options(config, headers=headers))
    if response.status_code != 200:
        print("Failed to get Nexthink token. Status Code: {}".format(response.status_code))
        print("Failed to get Nexthink token. Response Body: {}".format(response.body))
        return None

    data = json_decode(response.body)
    return data.get("access_token")

def start_nql_export(token, api_url, query_id, config):
    url = "{}/api/v1/nql/export?queryId={}".format(api_url, _encode_query_id(query_id))
    headers = {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/json",
    }

    response = http_get(url, **get_http_options(config, headers=headers))
    if response.status_code == 200:
        data = json_decode(response.body)
        return data.get("exportId")
    if response.status_code == 401:
        return "__UNAUTHORIZED__"

    print("Failed to start NQL export. Status Code: {}".format(response.status_code))
    print("Failed to start NQL export. Response Body: {}".format(response.body))
    return None

def get_export_status(token, api_url, export_id, config):
    url = "{}/api/v1/nql/status/{}".format(api_url, export_id)
    headers = {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/json",
    }

    response = http_get(url, **get_http_options(config, headers=headers))
    if response.status_code == 200:
        return json_decode(response.body)
    if response.status_code == 401:
        return {"__unauthorized__": True}

    print("Failed to get export status. Status Code: {}".format(response.status_code))
    print("Failed to get export status. Response Body: {}".format(response.body))
    return None

def fetch_all_export_rows(token, api_url, query_id, client_id, client_secret, auth_url, scope, config):
    export_id = start_nql_export(token, api_url, query_id, config)
    if export_id == "__UNAUTHORIZED__":
        token = get_token(client_id, client_secret, auth_url, scope, config)
        if not token:
            return []
        export_id = start_nql_export(token, api_url, query_id, config)
    if not export_id:
        return []

    status_data = None
    for _ in range(0, 120):
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

    results_file_url = status_data.get("resultsFileUrl")
    if not results_file_url:
        print("NQL export completed but no resultsFileUrl was returned")
        return []

    # resultsFileUrl is pre-signed. Do not send Authorization headers.
    download_response = http_get(results_file_url, **get_http_options(config))

    if download_response.status_code == 406:
        download_response = http_get(results_file_url, **get_http_options(config, headers={"Accept": "text/csv"}))

    if download_response.status_code != 200:
        print("Failed to download export results. Status Code: {}".format(download_response.status_code))
        print("Failed to download export results. Response Body: {}".format(download_response.body))
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

    token = get_token(client_id, client_secret, auth_url, scope, kwargs)
    if not token:
        return []

    rows = fetch_all_export_rows(token, api_url, query_id, client_id, client_secret, auth_url, scope, kwargs)
    if type(rows) != "list" or len(rows) == 0:
        print("No rows returned from Nexthink export workflow")
        return []

    assets = []

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
            "nexthink.hardware.chassis_serial_number": serial,
            "nexthink.operating_system.build": _safe_str(os_build_raw),
            "nexthink.collector.local_ip": _safe_str(row.get("device.collector.local_ip")),
        }

        assets.append(ImportAsset(
            id=str(asset_id),
            hostnames=[hostname] if hostname else [],
            os=os_name,
            osVersion=os_version,
            networkInterfaces=net_ifaces,
            customAttributes=custom_attrs,
        ))

    # Stream assets to runZero via report_assets instead of returning a list.
    report_assets(assets)
    return None

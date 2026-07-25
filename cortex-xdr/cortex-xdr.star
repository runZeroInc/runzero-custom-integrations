# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-cortex-xdr",
    "name": "Cortex XDR",
    "type": "inbound",
    "description": "Imports endpoints from Palo Alto Cortex XDR.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Cortex XDR base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://api-<tenant>.xdr.us.paloaltonetworks.com",
        },
        {
            "key": "api_key_id",
            "label": "API key ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
## Cortex XDR integration

load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'post_json')
load('kwargs', 'get_url_base', 'get_http_options')

def do_cortex_api_call(base_url, api_key, api_key_id, api_call, post_data={}, config_kwargs={}):
    """Perform API request to Cortex XDR, handling authentication"""

    headers = {
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key,
        "Content-Type": "application/json"
    }

    data, err = post_json(base_url + "/public_api/v1/" + api_call, json=post_data, **get_http_options(config_kwargs, headers=headers))

    if err:
        print("API call failed:", err)
        return None

    return data

def stream_endpoints(base_url, api_key, api_key_id, config_kwargs):
    """Retrieve Cortex XDR endpoints using pagination, building and streaming
    each page of assets via report_assets so the full endpoint set is never held
    in memory. Returns the number of assets reported."""
    cortex_filter = {"request_data": {"search_from": 0, "search_to": 100}}
    reported = 0
    page_size = 100

    while True:
        result = do_cortex_api_call(base_url, api_key, api_key_id, "endpoints/get_endpoint", cortex_filter, config_kwargs)

        if not result or "reply" not in result:
            print("Error retrieving endpoints")
            break

        reply = result["reply"]
        if type(reply) == "list":
            fetched_endpoints = reply
        else:
            fetched_endpoints = reply.get("endpoints", [])
        reported += report_assets(build_assets(fetched_endpoints))

        if len(fetched_endpoints) < page_size:
            break  # Stop when fewer than page_size results are returned

        cortex_filter["request_data"]["search_from"] += page_size
        cortex_filter["request_data"]["search_to"] += page_size

    print("Loaded", reported, "endpoints")
    return reported

def build_assets(all_endpoints):
    """Convert a page of Cortex XDR endpoint data into runZero asset format"""
    assets = []

    for endpoint in all_endpoints:
        endpoint_id = endpoint.get("agent_id") or endpoint.get("endpoint_id")
        if not endpoint_id:
            print("cortex-xdr: skipping endpoint with no agent_id/endpoint_id: name=" + str(endpoint.get("endpoint_name", "")))
            continue
        endpoint_tags = endpoint.get("tags", {}).get("endpoint_tags", [])
        server_tags = endpoint.get("tags", {}).get("server_tags", [])
        group_names = endpoint.get("group_name", endpoint_tags + server_tags)

        last_seen_raw = endpoint.get("last_seen")
        first_seen_raw = endpoint.get("first_seen")

        last_seen = ""
        if last_seen_raw != None and str(last_seen_raw) != "":
            last_seen_int = int(last_seen_raw)
            if last_seen_int > 9999999999:
                last_seen = str(int(last_seen_int / 1000))
            else:
                last_seen = str(last_seen_int)

        first_seen = ""
        if first_seen_raw != None and str(first_seen_raw) != "":
            first_seen_int = int(first_seen_raw)
            if first_seen_int > 9999999999:
                first_seen = str(int(first_seen_int / 1000))
            else:
                first_seen = str(first_seen_int)

        custom_attrs = {
            "operational_status": endpoint.get("operational_status", ""),
            "agent_status": endpoint.get("agent_status", endpoint.get("endpoint_status", "")),
            "agent_type": endpoint.get("agent_type", endpoint.get("endpoint_type", "")),
            "last_seen": last_seen,
            "first_seen": first_seen,
            "groups": ";".join(group_names),
            "users": ";".join(endpoint.get("users", [])),
            "assigned_prevention_policy": endpoint.get("assigned_prevention_policy", ""),
            "assigned_extensions_policy": endpoint.get("assigned_extensions_policy", ""),
            "endpoint_version": endpoint.get("endpoint_version", "")
        }

        mac_address = endpoint.get("mac_address", [""])[0] if endpoint.get("mac_address") else ""

        assets.append(
            ImportAsset(
                id=str(endpoint_id),
                networkInterfaces=[network_interface(ips=endpoint.get("ip", []) + endpoint.get("ipv6", []), mac=mac_address)],
                hostnames=[endpoint.get("host_name", endpoint.get("endpoint_name", ""))],
                os_version=endpoint.get("os_version", ""),
                os=endpoint.get("operating_system", ""),
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )
    return assets

def main(**kwargs):
    """Main function to retrieve and stream Cortex XDR asset data"""
    base_url = get_url_base(kwargs)
    api_key = kwargs['api_key']
    api_key_id = kwargs['api_key_id']

    # Endpoints are streamed page-by-page via report_assets in stream_endpoints.
    reported = stream_endpoints(base_url, api_key, api_key_id, kwargs)

    if not reported:
        print("No assets retrieved from Cortex XDR")

    return None

# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cortex-xdr",
    "name": "Cortex XDR",
    "type": "inbound",
    "description": "Imports endpoints from Palo Alto Cortex XDR.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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

# Cortex XDR classes every agent it manages, and reports that class as
# endpoint_type on the endpoint record. The documented values carry an
# AGENT_TYPE_ prefix ("AGENT_TYPE_SERVER"); the prefix is stripped before the
# lookup so a tenant that returns the bare token maps the same way.
#
# WORKSTATION is the one coarse value: Cortex does not separate a desktop from
# a laptop, so it is mapped to the runZero type that means "user endpoint" and
# nothing finer is claimed. runZero's own hardware fingerprinting runs ahead of
# a custom integration's type whenever it has a model, so this only fills the
# gap where nothing else knows. AGENT_TYPE_UNKNOWN and anything unrecognised
# leave the type unset rather than guessing.
DEVICE_TYPES = {
    "server": "Server",
    "workstation": "Desktop",
    "mobile": "Mobile",
}

AGENT_TYPE_PREFIX = "AGENT_TYPE_"

PAGE_SIZE = 100

# A BACKSTOP, not the primary guard. get_endpoint answers at most 100 records
# per call and the walk's only exit is a page shorter than that, so a Cortex
# that ignores the search_from/search_to window and keeps answering with a full
# page never ends it. That case is caught by the repeated-page check in the walk
# below, after two requests. A page ceiling is a poor first line of defence: it
# lets a stuck tenant be hammered for the whole ceiling before anything stops
# it.
#
# The number is derived from a record target rather than hand-picked, so it
# scales with the page size instead of encoding a guess about tenant size:
# 100,000 pages x 100 records = 10,000,000 endpoints, past any real Cortex XDR
# deployment. With the repeated-page check in front of it this should never be
# reached; reaching it anyway is logged, because a silently truncated import
# looks exactly like a complete one.
MAX_PAGES = 100000


def retrieved_of(retrieved, total):
    """The "Retrieved X/Y available assets" half of a truncation message.

    A truncated run has to say how much of the estate it actually got: a bare
    count tells the reader nothing about whether the import is nearly complete
    or stopped at the first percent. Where the API reports no total, say so
    plainly rather than printing a bare slash or inventing a denominator.
    """
    if type(total) == "int" and total > 0:
        return "Retrieved {}/{} available assets".format(retrieved, total)
    return "Retrieved {} assets; the API does not report a total".format(retrieved)


def page_signature(rows):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the server re-served one
    page rather than advancing through the inventory. Comparing ends rather than
    every row keeps this O(1) per page, and it is enough for the failure it
    guards against -- a Cortex that ignores the search window returns
    byte-identical responses, not a rearrangement of one.
    """
    if not rows:
        return "empty"
    first = rows[0]
    last = rows[-1]
    first_id = ""
    last_id = ""
    if type(first) == "dict":
        first_id = first.get("agent_id") or first.get("endpoint_id") or ""
    if type(last) == "dict":
        last_id = last.get("agent_id") or last.get("endpoint_id") or ""
    return "{}|{}|{}".format(len(rows), first_id, last_id)

def endpoint_device_type(endpoint):
    """Map a Cortex endpoint class onto a runZero device type, or '' when the
    record carries no class this integration is willing to translate."""
    raw = str(endpoint.get("endpoint_type") or endpoint.get("agent_type") or "").strip()
    if raw.upper().startswith(AGENT_TYPE_PREFIX):
        raw = raw[len(AGENT_TYPE_PREFIX):]
    return DEVICE_TYPES.get(raw.lower(), "")

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
    cortex_filter = {"request_data": {"search_from": 0, "search_to": PAGE_SIZE}}
    reported = 0
    page_size = PAGE_SIZE
    capped = True
    last_signature = ""
    # Cortex reports the size of the whole result set alongside every page. It
    # is captured so a truncated run can say what fraction of the estate it got,
    # rather than a bare count the reader cannot judge.
    total_count = None

    for _page in range(0, MAX_PAGES):
        result = do_cortex_api_call(base_url, api_key, api_key_id, "endpoints/get_endpoint", cortex_filter, config_kwargs)

        if not result or "reply" not in result:
            print("Error retrieving endpoints")
            capped = False
            break

        reply = result["reply"]
        if type(reply) == "list":
            fetched_endpoints = reply
        else:
            fetched_endpoints = reply.get("endpoints", [])
            reported_total = reply.get("total_count")
            if type(reported_total) == "int" and reported_total >= 0:
                total_count = reported_total

        # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it means
        # Cortex is ignoring the search_from/search_to window and re-serving the
        # same records, so the walk is not advancing and continuing can only
        # re-report endpoints already reported. Checked BEFORE the page is
        # reported, so the repeated records never reach runZero, and it can
        # never truncate genuine data: it only fires on a page that adds
        # nothing. It catches the stuck tenant in two requests where the page
        # ceiling would take 100,000.
        signature = page_signature(fetched_endpoints)
        if fetched_endpoints and signature == last_signature:
            capped = False
            print("cortex-xdr: paging stopped after {} pages: the API returned the same page twice. {}".format(
                _page + 1, retrieved_of(reported, total_count)))
            break
        last_signature = signature

        reported += report_assets(build_assets(fetched_endpoints))

        if len(fetched_endpoints) < page_size:
            capped = False
            break  # Stop when fewer than page_size results are returned

        cortex_filter["request_data"]["search_from"] += page_size
        cortex_filter["request_data"]["search_to"] += page_size

    if capped:
        print("cortex-xdr: page limit of {} hit (integration safety limit). {}".format(
            MAX_PAGES, retrieved_of(reported, total_count)))

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

        # network_interface returns None when nothing usable survives -- an
        # agent that has registered but not yet reported its adapters has no ip,
        # no ipv6 and no mac_address. Passing [None] to ImportAsset aborts the
        # entire run, losing every endpoint already parsed, so such an endpoint
        # gets no interface and correlates on its hostname instead.
        network = network_interface(ips=endpoint.get("ip", []) + endpoint.get("ipv6", []), mac=mac_address)
        interfaces = [network] if network else []

        params = {
            "id": str(endpoint_id),
            "networkInterfaces": interfaces,
            "hostnames": [endpoint.get("host_name", endpoint.get("endpoint_name", ""))],
            "os_version": endpoint.get("os_version", ""),
            "os": endpoint.get("operating_system", ""),
            "customAttributes": to_custom_attributes(custom_attrs),
        }

        # Omitted rather than set to "" when Cortex reports no class it names:
        # an empty deviceType is still a value, and it displaces the type
        # runZero would otherwise derive for itself.
        device_type = endpoint_device_type(endpoint)
        if device_type:
            params["deviceType"] = device_type

        assets.append(ImportAsset(**params))
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

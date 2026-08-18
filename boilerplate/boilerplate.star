# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-boilerplate",
    "name": "Product Name",
    "type": "inbound",
    "description": "Replace with your integration description.",
    "version": "1",
    # Bump by one whenever this script changes. This is the SCRIPT's revision
    # and is informational only; minVersion below is a different thing --
    # the minimum runZero platform version required to run it.
    "maturity": "alpha",
    # alpha: new or unproven. beta: in use and broadly working.
    # stable: promoted deliberately after real-world validation.
    "minVersion": "5.1.260818.0",
    # How runZero reconciles these records with the assets it already knows,
    # declared once for the whole integration. Omit it for the default, which
    # matches and breaks on all four dimensions. The preset below suits a source
    # with a stable vendor id whose addresses and names drift; a source that only
    # emits per-run ids wants "no-id-match no-id-break" instead. Say WHY in a
    # comment here -- the reasoning is what a future reader needs.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "validationMode": "compile",
    "params": [
        {
            "key": "client_id",
            "label": "Client ID",
            "type": "string",
            "required": True,
            "description": "Client ID, username, or organization ID",
        },
        {
            "key": "client_secret",
            "label": "Client secret",
            "type": "secret",
            "required": True,
            "description": "Client secret, password, or API token",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# This script demonstrates how to import and use the runZero custom Starlark
# libraries. The most commonly used libraries are:
#
#   1. runzero.types (ImportAsset, NetworkInterface, Service,
#                     ServiceProtocolData, Software, Vulnerability,
#                     to_custom_attributes)
#   2. kwargs        (require, has, get_string, get_bool, get_int, get_list,
#                     get_http_options)
#   3. json          (json_encode="encode", json_decode="decode")
#   4. net           (ip_address, network_interface, normalize_mac, resolve)
#   5. http          (http_post="post", http_get="get", get_json, post_json,
#                     url_encode, bearer, basic, oauth2_token)
#   6. uuid          (new_uuid)
#   7. time          (now, parse_time, parse_duration)
#   8. re            (find_all, sub)
#   9. csv           (read_all)
#  10. runzero.progress (report, info)
#
# Additional modules not shown here — requests, xml, jsonstream, jwt,
# crypto, base64/hex/base32, gzip, and the low-level socket / runzero.ssh /
# runzero.smb / runzero.winrm / runzero.wmi / runzero.sql modules — are
# documented in docs/starlark-helpers.md.
#
# The kwargs passed to main() are declared in the CONFIG block at the top of
# this file. The runZero UI builds its credential form from those param
# definitions, and the platform routes any param marked "type":"secret"
# through encrypted storage.

load("runzero.types", "ImportAsset", "NetworkInterface", "Service", "ServiceProtocolData", "Software", "Vulnerability", "to_custom_attributes")
load("json", json_encode="encode", json_decode="decode")
load("net", "ip_address", "network_interface", "normalize_mac", "resolve")
load("http", http_post="post", http_get="get", "get_json", "post_json", "url_encode", "bearer", "basic", "oauth2_token")
load("uuid", "new_uuid")
load("time", "now", "parse_time", "parse_duration")
load("re", re_find_all="find_all", re_sub="sub")
load("csv", csv_read="read_all")
load("runzero.progress", progress_report="report", progress_info="info")
load("kwargs", "require", "get_string", "get_bool", "get_int", "get_list", "has", "get_http_options")


# -------------------------
# runzero.types (3 examples)
# -------------------------

def create_asset_example():
    """
    Demonstrates how to create an ImportAsset object, which is used
    to represent a device or endpoint for ingestion into runZero.

    The `network_interface()` helper accepts a MAC in any common form
    (colon, dash, Cisco-dotted, bare-hex) and a mixed list of IPv4
    and IPv6 strings. It classifies them automatically, strips
    "addr:port" and "%zone" suffixes, dedupes, and caps at 99 per
    family. It returns None when nothing usable is present.

    Returns:
        ImportAsset: a populated ImportAsset object
    """
    netif = network_interface(
        mac="AA:BB:CC:DD:EE:FF",
        ips=["192.168.1.10", "fe80::1%eth0", "[2001:db8::1]:443"],
    )
    # Always guard the result like this. network_interface returns None when
    # nothing usable survives -- a record with no parseable MAC and no routable
    # address -- and passing [None] to ImportAsset does not skip that one record,
    # it aborts the ENTIRE run with "network_interfaces must be an iterable of
    # NetworkInterface objects", losing everything already parsed.
    interfaces = [netif] if netif else []
    return ImportAsset(
        id="asset-12345",
        networkInterfaces=interfaces,
        hostnames=["sample-device"],
        os="ExampleOS",
        osVersion="1.0",
        # match_behavior tells the runZero cruncher how aggressively
        # to merge this asset with existing records. The default is
        # full matching on id+mac+ip+name. When your source provides
        # a stable foreign id (vendor-assigned permanent device id,
        # serial number, etc.) the recommended setting is:
        #   "no-mac-break no-ip-break no-name-break"
        # which keeps id-based merging but stops other dimensions
        # from disqualifying a merge. When your source only emits
        # per-run / ephemeral ids, prefer:
        #   "no-id-match no-id-break"
        # so the platform falls back to MAC/IP/name matching.
    )

def create_software_example():
    """
    Demonstrates how to create a Software object, which can be attached
    to an ImportAsset for software inventory tracking.

    Returns:
        Software: a populated Software object
    """
    return Software(
        id="software-456",
        vendor="ExampleVendor",
        product="ExampleProduct",
        version="v2.1.3",
        serviceAddress="127.0.0.1"
    )

def create_vulnerability_example():
    """
    Demonstrates how to create a Vulnerability object, which can be attached
    to an ImportAsset for vulnerability information tracking.

    Returns:
        Vulnerability: a populated Vulnerability object
    """
    return Vulnerability(
        id="vuln-789",
        name="CVE-1234-5678",
        description="Example vulnerability",
        cve="CVE-1234-5678",
        solution="Update to the latest patch",
        severityRank=4,          # 0=Info, 1=Low, 2=Med, 3=High, 4=Critical
        severityScore=10.0,
        riskRank=4,
        riskScore=10.0
    )

def create_custom_attrs_example():
    """
    Demonstrates `to_custom_attributes(...)`, which flattens an
    arbitrary value into the string->string shape required by
    `ImportAsset.customAttributes`. The helper:

      - Flattens nested dicts using a configurable separator (default ".")
      - Joins lists with a configurable separator (default ",")
      - Stringifies bool/int/float values
      - Drops empty strings / None by default
      - Truncates keys/values and caps the total entry count
    """
    raw = {
        "name": "host1",
        "active": True,
        "sys": {"os": "linux", "ver": {"major": 5, "minor": 15}},
        "tags": ["a", "b", "c"],
        "empty": "",   # dropped by default
    }
    return to_custom_attributes(raw, exclude=["empty"])


# ---------------
# json library
# ---------------
def example_json_usage():
    """
    Demonstrates how to use the json library for encoding and decoding.
    """
    sample_data = {"key": "value", "numbers": [1, 2, 3]}
    encoded = json_encode(sample_data)
    print("JSON-encoded data:", encoded)
    decoded = json_decode(encoded)
    print("JSON-decoded data:", decoded)
    return decoded


# --------------
# net library
# --------------
def example_ip_usage():
    """
    Parse and classify IP addresses.
    """
    print("IPv4 version:", ip_address("192.168.10.55").version)
    # normalize_mac accepts any common form; returns lowercase
    # colon-separated form, or None for unparseable input.
    print("MAC:", normalize_mac("AABB.CCDD.EEFF"))
    # resolve returns a list of IPAddress values (empty list, never an
    # error, on failure) so it is safe to iterate directly.
    for addr in resolve("localhost"):
        print("resolved:", addr, "v", addr.version)


# --------------
# time library
# --------------
def example_time_usage():
    """
    Parse timestamps and durations; do arithmetic with them.
    """
    t = parse_time("2023-10-27T10:00:00Z")
    print("unix:", t.unix, "year:", t.year)
    window = parse_duration("24h")
    print("cutoff:", (now() - window).unix)


# --------------
# re library
# --------------
def example_re_usage(text):
    """
    Extract and rewrite text with Go RE2 regular expressions.
    """
    ids = re_find_all(r"id=(\d+)", text)
    collapsed = re_sub(r"\s+", " ", text)
    return ids, collapsed


# --------------
# csv library
# --------------
def example_csv_usage(csv_text):
    """
    Parse a CSV payload into a list of dicts keyed by the header row.
    """
    return csv_read(csv_text)


# ---------------
# http library
# ---------------
def example_http_usage(config_kwargs):
    """
    Build common request shapes:
      - GET / POST with auto-decoded JSON (recommended for typical APIs)
      - GET with params (raw response when you need headers/cookies)
      - POST with `json=<dict>` (auto-encodes + sets Content-Type)
      - OAuth2 client_credentials token exchange in one call
      - Bearer / Basic auth header builders
    """
    headers = {"Authorization": bearer("my-token")}
    http_options = get_http_options(config_kwargs, headers=headers)

    # get_json / post_json: decode the JSON body for you, retry on
    # transient failures (408, 425, 429, 5xx) with exponential backoff
    # + Retry-After honoring, and return (data, err) instead of an
    # http response. `err` is None on success or a short string on
    # failure ("status 401: <snippet>", "transport: ...").
    #
    # data, err = get_json("https://example.com/api/devices",
    #                      params={"limit": 100},
    #                      **http_options)
    # if err:
    #     print("device fetch failed:", err)
    #     return []
    #
    # data, err = post_json("https://example.com/api/search",
    #                       json={"q": "alive:t"},
    #                       **http_options)

    # GET with query params (raw response when you need headers/cookies)
    # response = http_get("https://example.com/api",
    #                     params={"search": "alive:t", "limit": 10},
    #                     **http_options)

    # POST with auto-JSON body
    # response = http_post("https://example.com/api",
    #                      json={"name": "runZero"},
    #                      **http_options)

    # OAuth2 client_credentials (returns access_token string; raises
    # on non-2xx or missing access_token).
    # token = oauth2_token(
    #     token_url="https://idp.example.com/oauth/token",
    #     client_id="cid",
    #     client_secret="csec",
    #     scope="read",
    #     **get_http_options(config_kwargs),
    # )

    # Basic auth (handles base64 encoding internally)
    # headers = {"Authorization": basic("user", "pass")}
    return http_options


# ---------------
# uuid library
# ---------------
def example_uuid_usage():
    """Generate a unique ID."""
    unique_id = new_uuid()
    print("Generated UUID:", unique_id)
    return unique_id


# -------------
# main function
# -------------
def main(*args, **kwargs):
    """
    User-configured fields declared in the embedded ``CONFIG['params']``
    block are delivered through ``**kwargs``. Use the ``kwargs`` helper
    module to validate and coerce them safely:

        require(kwargs, "client_id", "client_secret")
        client_id = get_string(kwargs, "client_id")
        client_secret = get_string(kwargs, "client_secret")

    Optional fields use the typed accessors with defaults:

        page_size = get_int(kwargs, "page_size", default=100)
        include_offline = get_bool(kwargs, "include_offline", default=False)
        regions = get_list(kwargs, "regions", default=[])

    Credential fields declared in CONFIG are available in ``kwargs``.
    set on the credential continue to work without any CONFIG block.
    """
    require(kwargs, "client_id", "client_secret")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")

    if has(kwargs, "region"):
        print("region override:", get_string(kwargs, "region"))

    progress_report(0, "starting custom integration")
    print("welcome to runZero custom integrations:", client_id)
    progress_info("custom integration setup complete")

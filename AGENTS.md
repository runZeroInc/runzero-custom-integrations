# Custom Integration Agents

This document provides guidance for creating custom integration scripts for runZero.

## Goal
Create a custom integration script to import assets into runZero from a third-party service (Inbound) or export runZero assets to a third-party service (Outbound).

## Directory Structure
Each integration must be placed in its own directory at the root of the repository.

```
repo-root/
├── <integration-name>/
│   ├── <integration-name>.star  # The main script (also carries the integration metadata)
│   └── README.md                # Documentation
```

### 1. Integration metadata (embedded `CONFIG` block)

Every new script must declare `CONFIG = {...}` as its first top-level statement
of the file. The platform extracts this block (via a strict literal-only
Starlark walk) to render the credential form, validate user input, apply
defaults, and route secret fields through encrypted storage. Only literal
expressions are permitted on the right-hand side — no function calls, no
variable references, no arithmetic. The only exception is
`CONFIG["includes"]`, which may reference allowlisted shared option-set
identifiers such as `OPTIONS_TLS` and `OPTIONS_HTTP`.

**Format:**
```python
CONFIG = {
    "id": "runzero-example",
    "name": "Integration Name",
    "type": "inbound",
    "description": "Short summary shown in the catalog.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
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
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset")
# ...rest of script
```

**Required rules:**
- `CONFIG` must be the first top-level statement. Comments and blank lines may precede it; `load(...)`, constants, and other statements may not.
- All values must be literals (`True`/`False`/`None`, strings, ints, floats, lists, tuples, dicts with string keys, negated numbers via unary `-`).
- `id` must be a stable lower-case integration identifier, e.g. `runzero-tailscale`.
- `version` must use the integration version string for the target release, e.g. `26052700`.
- Scripts in this v2 library must set `minVersion` to `5.1.0` or later. Before the script runs, the Explorer version is compared against it and older releases fail with a clear upgrade message. Development builds using the `0.0.0` sentinel skip the check.
- `type` must be `inbound`, `outbound`, or `internal`.
- Each `params[].key` must match `^[a-zA-Z_][a-zA-Z0-9_]*$` and must match the kwarg name the script reads.
- `type: "secret"` (or `secret: True`) marks the field for masked input and log redaction; never log or print these values, and never set a `default` on them. All dynamic credential fields are encrypted at rest.
- `includes` expands shared option sets with the dict key as a prefix, for example `{"src_tls_": OPTIONS_TLS, "dst_http_": OPTIONS_HTTP}`.
- Baseline URL parameters for API endpoints must be set in the `CONFIG`.
- IP addresses for direct protocol connections must be set in the `CONFIG`. 

**Supported top-level CONFIG fields:** `id`, `name`, `type`, `description`, `version`, `minVersion`, `params`, `includes`, `rejectUnknown`, `atLeastOneOf`, `exactlyOneOf`, `validationMode`.

**Supported param types:** `string`, `secret`, `int`, `float`, `bool`, `enum` (requires `options`), `url`, `textarea`, `json`.

**Supported param fields:** `key`, `label`, `description`, `type`, `required`, `secret`, `default`, `placeholder`, `options`, `multi`, `min`, `max`, `pattern`, `caseInsensitive`, `aliases`, `dependsOn`, `visibleIf`, `visibleIfValue`, `requiredIf`, `requiredIfValue`, `group`.

Enum aliases are normalized to their canonical `options` value before `main`
runs. CONFIG-based integrations reject unknown kwargs. Use
`"validationMode": "compile"` only for templates and integrations that use
direct protocols such as SSH, SMB, WMI, WinRM, or SQL; HTTP integrations should
omit it and use the default HTTP wiring validation.

Direct-protocol modules execute on the selected Explorer and intentionally can
connect to internal addresses available from that Explorer. Treat the script
and its credentials as privileged discovery configuration, and scope the
Explorer and credential to the intended source system.

### 2. `<integration-name>.star`
This is the main script written in Starlark. Name it after the
integration directory (e.g. `tailscale/tailscale.star`).

## Script Development

The CONFIG model and standard helper modules are designed to be easy to use
with external authoring tools, including LLM-based editors. runZero does not run
an LLM in the Console, Explorer, or Starlark sandbox; generated scripts are
reviewed and executed like any other source file.

### Language
The script is written in **Starlark**, a Python-like language with some key differences:
*   **No Exceptions**: Use return values and status codes for error handling.
*   **No f-strings**: Use `"{}".format(var)` for string interpolation.
*   **Limited Standard Library**: Only specific built-ins and loaded libraries are available.

### Entrypoint
The script must define a `main` function.

```python
def main(*args, **kwargs):
    # Your logic here
    return assets # List of ImportAsset objects (for inbound) or None
```

*   **Arguments** — keys delivered through `**kwargs` are those declared in `CONFIG["params"]`. Reserved keys (those starting with `_`, e.g. `_integration_id`) are stored on the credential but **not** forwarded to the script. The platform applies declared `default` values, coerces `int`/`float`/`bool`/`enum` types, and rejects requests that fail validation (`required`, `min`, `max`, `pattern`, `options`) before `main` runs.

#### Reading kwargs safely

A helper module exposes typed accessors and validators:

```python
load("kwargs", "require", "has", "get_string", "get_bool", "get_int", "get_float", "get_list")

def main(*args, **kwargs):
    require(kwargs, "client_id", "client_secret")
    client_id = get_string(kwargs, "client_id")
    client_secret = get_string(kwargs, "client_secret")
    page_size = get_int(kwargs, "page_size", default=100)
    include_offline = get_bool(kwargs, "include_offline", default=False)
    regions = get_list(kwargs, "regions", default=[])
    if has(kwargs, "region"):
        ...
```

Use descriptive parameter keys such as `username`, `password`, `api_token`, `client_id`, or `client_secret`; each `params[].key` must match the kwarg name the script reads.

### Return Type
*   **Inbound**: Either return a `list` of `ImportAsset` objects from `main`,
    **or** stream assets incrementally with `report_assets(...)` and return
    `None`. The two approaches can be combined (anything returned from `main`
    is imported in addition to whatever was already reported).
*   **Outbound**: Typically returns `None` after performing the export operation.

### Streaming assets with `report_assets` (large datasets)

Returning one giant `list` from `main` forces the whole result set — every
`ImportAsset`, plus the raw API responses used to build them — to live in
memory at once. For integrations that page through large inventories this can
exhaust the Explorer's memory. Instead, report assets to runZero as you build
them and let each page be garbage-collected before the next is fetched:

```python
def main(**kwargs):
    total = 0
    cursor = None
    while True:
        page, cursor = fetch_page(kwargs, cursor)  # one page of raw records
        if not page:
            break
        assets = build_assets(page)                # build just this page
        report_assets(assets)                      # stream it to runZero
        total += len(assets)
        if not cursor:
            break
    print("reported {} assets".format(total))
    return None                                    # nothing buffered in main
```

`report_assets` is a predeclared builtin (no `load` required) and accepts any
combination of:

```python
report_assets(asset)            # a single ImportAsset
report_assets(asset1, asset2)   # several as positional args
report_assets(page_assets)      # a list/tuple of ImportAsset
report_assets(*page_assets)     # the same, spread
n = report_assets(batch)        # returns the count reported, for logging
```

Notes:
*   Reported assets are merged with any `list` returned from `main`, so a
    partial migration (report some pages, return the rest) is safe.


### Available Libraries
Load libraries at the top of your script. The list below covers the most
common modules; see [docs/starlark-helpers.md](docs/starlark-helpers.md)
for the complete reference (including `kwargs`, `requests`, `re`, `csv`,
`xml`, `jsonstream`, `jwt`, and the low-level `socket`/`runzero.ssh`/
`runzero.smb`/`runzero.winrm`/`runzero.wmi`/`runzero.sql` modules).

```python
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Service',
                      'ServiceProtocolData', 'Software', 'Vulnerability',
                      'to_custom_attributes')
load('kwargs', 'require', 'has', 'get_string', 'get_bool', 'get_int',
               'get_list', 'get_http_options')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address', 'network_interface', 'normalize_mac', 'resolve')
load('http', http_post='post', http_get='get', 'get_json', 'post_json',
             'url_encode', 'bearer', 'basic', 'oauth2_token')
load('uuid', 'new_uuid')
load('time', 'parse_time', 'parse_duration', 'now')
load('gzip', gzip_decompress='decompress', gzip_compress='compress')
load('base64', base64_encode='encode', base64_decode='decode')
load('crypto', 'sha256', 'sha512', 'sha1', 'md5', 'hmac_sha256')
load('flatten_json', 'flatten')
```

## runZero SDK Types
The Starlark `runzero.types` library exposes `ImportAsset`, `NetworkInterface`, `Service`, `ServiceProtocolData`, `Software`, `Vulnerability`, and the `to_custom_attributes` helper. The Python SDK wraps the same REST models and also provides `Hostname`, `Tag`, `ScanOptions`, `ScanTemplate`, and `ScanTemplateOptions`. These wrappers enforce validation and normalization, so build your payloads to fit the expected shape:

- `ImportAsset`: unique `id`; `hostnames`/`tags` accept plain strings or wrapped types; optional `os`, `osVersion`, `services`, `software`, `vulnerabilities`; `customAttributes` should stay under 1024 entries with keys <=256 chars and values <=1024 chars.
- `NetworkInterface`: `macAddress`, `ipv4Addresses`, `ipv6Addresses`; IP strings are parsed/validated.
- `Software`, `Service`, `ServiceProtocolData`: lower-case transports/protocol names, parse addresses from strings, and share the same custom attribute limits as `ImportAsset`.
- `Vulnerability`: lower-cases transport/CPE, upper-cases CVE, and parses addresses from strings; custom attribute limits apply.
- `CustomAttribute` in the SDK is deprecated—use plain strings for `customAttributes`.

### Inbound asset example with SDK types
```python
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software', 'Vulnerability')
load('net', 'ip_address')

assets.append(ImportAsset(
    id="device-123",
    hostnames=["web1.acme.local"],
    os="Linux",
    osVersion="5.15",
    tags=["prod", "web"],
    networkInterfaces=[
        NetworkInterface(macAddress="aa:bb:cc:dd:ee:ff", ipv4Addresses=[ip_address("10.0.0.5")])
    ],
    software=[Software(name="nginx", version="1.25.3", serviceTransport="tcp")],
    vulnerabilities=[Vulnerability(cve="CVE-2023-0001", serviceTransport="tcp", serviceAddress="10.0.0.5")],
    customAttributes={"location": "SFO-1", "serial": "ABC123"}
))
```

### Best Practices

1.  **Pagination**: APIs often return paginated results. Use `while` loops to fetch all data.
    ```python
    while url:
        response = http_get(url, headers=headers)
        if response.status_code != 200:
            break
        data = json_decode(response.body)
        # Process data...
        # Update url for next page or break
    ```

2.  **Error Handling**: Check `response.status_code` after every HTTP request.
    ```python
    if response.status_code != 200:
        print("Error: {}".format(response.status_code))
        return []
    ```

3.  **Data Mapping**: Map third-party fields to `ImportAsset` fields carefully.
    *   `id`: unique identifier (string).
    *   `hostnames`: list of strings.
    *   `os`, `osVersion`: strings.
    *   `networkInterfaces`: list of `NetworkInterface` objects.
    *   `customAttributes`: dict for any extra data.

4.  **Network Interfaces**: Use `ip_address` to validate and categorize IPs (IPv4 vs IPv6).
    ```python
    def build_network_interface(ips, mac):
        ip4s = []
        ip6s = []
        for ip in ips:
            addr = ip_address(ip)
            if addr.version == 4:
                ip4s.append(addr)
            elif addr.version == 6:
                ip6s.append(addr)
        return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)
    ```

## Library Reference & Examples

This section provides usage examples for the available Starlark libraries.

### requests
Used for handling HTTP sessions and cookies.

```python
load('requests', 'Session', 'Cookie')
load('json', json_decode='decode')

def requests_example():
    session = Session()
    session.headers.set('Accept', 'application/json')
    session.headers.set('User-Agent', 'Mozilla/5.0')

    url = 'https://api.example.com/data'
    session.cookies.set(url, {"session_id": "12345"})

    response = session.get(url)
    if response and response.status_code == 200:
        data = json_decode(response.body)
        print("Data:", data)
```

### http
Used for stateless HTTP requests (`get`, `post`, `patch`, `delete`) and URL encoding.

```python
load('http', http_post='post', http_get='get', 'url_encode')

def http_example():
    url = "https://api.example.com/resource"
    headers = {"Accept": "application/json"}

    # GET request
    response = http_get(url, headers=headers)

    # POST request with JSON body
    payload = {"name": "runZero"}
    response_post = http_post(
        url,
        headers=headers,
        body=bytes(json_encode(payload))
    )
```

### net
Used for IP address parsing and validation.

```python
load('net', 'ip_address')

def net_example(ip_str):
    # ip_str can be IPv4 or IPv6
    addr = ip_address(ip_str)
    print("IP:", addr)
    print("Version:", addr.version) # 4 or 6
```

### json
Used for JSON encoding and decoding.

```python
load('json', json_encode='encode', json_decode='decode')

def json_example():
    data = {"name": "runZero", "active": True}

    # Encode to string
    encoded = json_encode(data)

    # Decode to dict
    decoded = json_decode(encoded)
```

### time
Used for parsing time strings.

```python
load('time', 'parse_time')

def time_example():
    time_str = "2023-10-27T10:00:00Z"
    parsed = parse_time(time_str)
    print("Unix Timestamp:", parsed.unix)
```

### uuid
Used for generating UUIDs.

```python
load('uuid', 'new_uuid')

def uuid_example():
    uid = new_uuid()
    print("New UUID:", uid)
```

### gzip
Used for compression and decompression.

```python
load('gzip', gzip_decompress='decompress', gzip_compress='compress')

def gzip_example(data_bytes):
    compressed = gzip_compress(data_bytes)
    decompressed = gzip_decompress(compressed)
```

### base64
Used for Base64 encoding and decoding.

```python
load('base64', base64_encode='encode', base64_decode='decode')

def base64_example():
    creds = "user:pass"
    encoded = base64_encode(creds)
    decoded = base64_decode(encoded)
```

### crypto
Used for hashing (SHA256, SHA512, SHA1, MD5).

```python
load('crypto', 'sha256', 'sha512', 'sha1', 'md5')

def crypto_example():
    data = "secret_data"
    hash_256 = sha256(data)
    hash_512 = sha512(data)
    print("SHA256:", hash_256)
```

### flatten (json)
Used to flatten nested JSON structures.

```python
load('flatten_json', 'flatten')

def flatten_example():
    nested = {"a": {"b": 1, "c": 2}, "d": 3}
    flat = flatten(nested)
    # Result: {"a.b": 1, "a.c": 2, "d": 3}
```

### kwargs
Typed, validating accessors over the `**kwargs` passed to `main()`.

```python
load('kwargs', 'require', 'has', 'get_string', 'get_int', 'get_bool', 'get_list')

def kwargs_example(**kwargs):
    require(kwargs, 'client_id', 'client_secret')   # error if missing/blank
    page = get_int(kwargs, 'page_size', default=100)
    regions = get_list(kwargs, 'regions', default=[])  # CSV or list -> list
```

### get_json / post_json
Drop-in replacements for `GET` + status-check + `json_decode`, with retry
and backoff. Return `(data, err)`.

```python
load('http', 'get_json', 'post_json', 'bearer')

def get_json_example(token):
    data, err = get_json("https://api.example.com/devices",
                         headers={"Authorization": bearer(token)},
                         params={"limit": 100})
    if err:
        print("fetch failed:", err)
        return []
    return data
```

### re
Regular expressions (Go RE2 syntax).

```python
load('re', re_find_all='find_all', re_sub='sub')

def re_example(s):
    ids = re_find_all(r"id=(\d+)", s)
    clean = re_sub(r"\s+", " ", s)
    return ids, clean
```

### csv / xml / jsonstream
Parse non-JSON payloads and stream large responses.

```python
load('csv', csv_read='read_all')
load('xml', xml_parse='parse')
load('jsonstream', 'iter_array')

def parse_examples(csv_text, xml_text, big_json):
    rows = csv_read(csv_text)                 # list[dict] keyed by header
    doc = xml_parse(xml_text)                 # element tree
    name = doc.find("device/name").text if doc else None
    for item in iter_array(big_json, path="data.items"):  # streamed
        print(item.get("id"))
    return rows, name
```

### runzero.progress
Report progress and log lines into the runZero UI.

```python
load('runzero.progress', progress_report='report', progress_info='info')

def progress_example():
    progress_report(50, "halfway done")   # pct clamped to [0, 100]
    progress_info("processing next page")
```

### Low-level protocols (socket / ssh / smb / winrm / wmi / sql)
For sources without a REST API, open a raw connection and **always
`close()`** it. See [docs/starlark-helpers.md](docs/starlark-helpers.md)
for full signatures.

```python
load('runzero.ssh', ssh_dial='dial')

def ssh_example(host, user, password):
    sess = ssh_dial(host, username=user, password=password)
    stdout, stderr, code = sess.run("uname -a")
    sess.close()
    return stdout
```

## Testing

Use the `runzero` CLI to test your script locally.

1.  **Run with arguments**:
    ```bash
    runzero script --filename <path/to/script.star> --kwargs client_id=MY_ID --kwargs client_secret=MY_SECRET
    ```

2.  **REPL**:
    ```bash
    runzero script repl --filename <path/to/script.star>
    ```

## Example Template (Inbound)

```python
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get')

API_URL = "https://api.example.com/devices"

def build_network_interface(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips:
        if not ip: continue
        addr = ip_address(ip)
        if addr.version == 4:
            ip4s.append(addr)
        elif addr.version == 6:
            ip6s.append(addr)
    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    api_key = kwargs.get('api_token')
    headers = {"Authorization": "Bearer {}".format(api_key)}

    assets = []
    response = http_get(API_URL, headers=headers)

    if response.status_code != 200:
        print("API Error: {}".format(response.status_code))
        return []

    devices = json_decode(response.body)

    for device in devices:
        assets.append(ImportAsset(
            id=device.get("id"),
            hostnames=[device.get("hostname")],
            os=device.get("os"),
            networkInterfaces=[build_network_interface(device.get("ips", []), device.get("mac"))],
            customAttributes={"serial": device.get("serial")}
        ))

    return assets
```

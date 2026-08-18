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
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
- `version` is the script's own revision, not a date stamp. Every integration in this library ships `"1"`; bump it only if a script needs to be versioned independently.
- Scripts in this v2 library set `minVersion` to `5.1.260818.0`. Before the script runs, the Explorer version is compared against it and older releases fail with a clear upgrade message rather than aborting somewhere inside the script. Development builds using the `0.0.0` sentinel skip the check. Raise it above the library value only when a script needs a capability that shipped later, and say which one in a comment beside it.
- `type` must be `inbound`, `outbound`, or `internal`.
- Each `params[].key` must match `^[a-zA-Z_][a-zA-Z0-9_]*$` and must match the kwarg name the script reads.
- `type: "secret"` (or `secret: True`) marks the field for masked input and log redaction; never log or print these values, and never set a `default` on them. All dynamic credential fields are encrypted at rest.
- `includes` expands shared option sets with the dict key as a prefix, for example `{"src_tls_": OPTIONS_TLS, "dst_http_": OPTIONS_HTTP}`.
- Baseline URL parameters for API endpoints must be set in the `CONFIG`.
- IP addresses for direct protocol connections must be set in the `CONFIG`. 

- `maturity` is `alpha`, `beta`, or `stable` and drives how the integration is presented in the catalog. An absent value is read as `alpha`.
- `sourceId` and `sourceName` are reserved for runZero-shipped integrations. A script that declares either is rejected on save.

**Supported top-level CONFIG fields:** `id`, `name`, `type`, `description`, `version`, `maturity`, `minVersion`, `matchBehavior`, `assetTypeBehavior` (alias `sourceTypeBehavior`), `assetType`, `ownershipAttributes`, `trustOS`, `trustOSVersion`, `trustType`, `maxPages`, `params`, `includes`, `rejectUnknown`, `atLeastOneOf`, `exactlyOneOf`, `validationMode`.

- `assetType` sets the default attribute category for every asset the script reports, matching `^[a-z0-9][a-z0-9_-]{0,63}$`. Individual assets override it with `ImportAsset(assetType=...)`.
- `ownershipAttributes` lists `customAttributes` keys whose values name the asset's owner, so device ownership is populated automatically.
- `trustOS`, `trustOSVersion`, `trustType` are booleans. When true, the script-supplied OS, OS version, or device type is authoritative and is not replaced by runZero fingerprinting. Leave them out unless the source is genuinely more reliable than fingerprinting.

`matchBehavior` declares the asset-reconciliation policy once for the whole
integration, as a space-separated flag string placed after `minVersion` and
before `params`. It is not a field on `ImportAsset`; the merge path needs the
behavior before it has an asset, so a script that passes `matchBehavior=` to
`ImportAsset` fails validation. Omit the key for the default, which matches and
breaks on all four dimensions. Keep a comment beside the value explaining why
the default is wrong for this source — see the root README for the flag table
and presets.

### Asset types and per-type merge policy

Some integrations report genuinely different kinds of thing from one source: a
NAS and the VMs on it, a router and the hosts it observed, an agent record and
a DHCP lease. `assetType` labels each population, and `assetTypeBehavior` gives
a population its own merge policy on top of the integration-wide one.

```python
CONFIG = {
    ...
    # The policy that fits MOST records goes here.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    # Only the populations that need something different are named here.
    "assetTypeBehavior": {
        "lease": "no-id-match no-id-break",
    },
}

# ...and the script labels that population as it builds it:
ImportAsset(id=..., assetType="lease", ...)
```

Rules worth knowing before you use it:

- A key in `assetTypeBehavior` only takes effect on assets the script actually
  labels with that `assetType`. A declared key nothing emits is dead
  configuration, and the mistake is invisible at runtime — the records quietly
  inherit the integration-wide policy instead, which is usually the opposite of
  what was intended.
- Type keys match `^[a-z0-9][a-z0-9_-]{0,63}$`, the same constraint as
  `assetType`.
- Levels layer rather than replace: the integration-wide value survives
  wherever the type-specific string is silent. Splitting one population's flags
  across the two levels leaks them onto every other population, so give each
  type its complete policy.
- Emitting an `assetType` with no matching `assetTypeBehavior` entry is normal
  and often the point — it labels the population for the operator while leaving
  the integration-wide policy in force.
- An integration that splits one population across asset types usually also
  wants `no-type-break`, so a record moving between types is not refused a
  merge for that reason alone.
- `sourceTypeBehavior` is an accepted alias. Declaring a key under both
  spellings with different values is an error.

Choose the type name for the operator, not for the code: it becomes a visible
attribute category, so `lease`, `container`, `camera`, and `swarm-node` are
good names and `type2` is not.

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

### Streaming assets with `report_asset` (large datasets)

Returning one giant `list` from `main` forces the whole result set — every
`ImportAsset`, plus the raw API responses used to build them — to live in
memory at once. For integrations that page through large inventories this can
exhaust the Explorer's memory. Instead, report each asset as you build it:

```python
def main(**kwargs):
    total = 0
    cursor = None
    p = pager("devices")                           # CONFIG-bounded loop guard
    while p.next():
        page, cursor = fetch_page(kwargs, cursor)  # one page of raw records
        if not page:
            break
        for record in page:
            total += report_asset(build_asset(record))
        if not cursor:
            break
    print("reported {} assets".format(total))
    return None                                    # nothing buffered in main
```

`report_asset` and `report_assets` are predeclared builtins (no `load`
required).

**Do not batch.** The accumulate-then-flush pattern —
`batch.append(asset)`, flush at `BATCH_SIZE`, plus a trailing `if batch:` —
buys nothing: the host already writes incrementally, so the batch is just a
second buffer in front of it. Reporting per asset bounds memory regardless of
estate size and cannot lose a partial final batch when a script returns early.

*   `report_asset(asset)` takes exactly one `ImportAsset` and returns `1`, so
    `total += report_asset(asset)` accumulates a count. `report_asset(None)` is
    a no-op returning `0`, so it is safe to wrap a builder that may decline a
    record.
*   `report_assets(...)` remains available for the cases where you genuinely
    have a list, and accepts a single asset, several positional assets, a
    list/tuple, or a spread. It returns the count reported.
*   Reported assets are merged with any `list` returned from `main`, so a
    partial migration (report some pages, return the rest) is safe.

### Bounding pagination loops

Every pagination loop needs a backstop, or a source whose cursor never
terminates spins until the task's wall-clock deadline with no indication of
why. Do **not** declare your own `MAX_PAGES` constant. Set the limit in
`CONFIG` where an operator can see it, and guard the loop with `pager()`:

```python
CONFIG = {
    ...
    "maxPages": 5000,      # optional; defaults to 1,000,000
}
```

`p.next()` returns `True` while the loop may continue and **raises** when the
limit is reached, naming the label and the `maxPages` key — an incomplete
import is reported as an error rather than silently truncated. Give each loop
its own label; a script that pages parents and then each parent's children has
two different bounds. See `docs/starlark-helpers.md` for the full API.


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
load('net', 'ip_address', 'network_interface', 'normalize_mac', 'mac_key',
            'routable_ip', 'routable_ips', 'hostname', 'hostnames', 'resolve')
load('coerce', 'text', 'as_dict', 'as_list', 'dicts', 'as_int', 'as_float',
               'as_bool', 'dedupe')
load('http', http_post='post', http_get='get', 'get_json', 'post_json',
             'url_encode', 'bearer', 'basic', 'oauth2_token')
load('uuid', 'new_uuid')
load('time', 'parse_ts', 'parse_time', 'parse_duration', 'now')
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
- `Vulnerability`: `cve` is accepted in any case and canonicalized to upper case, so a source that reports `cve-2024-0001` imports cleanly; it must still match `CVE-YYYY-NNNN` in shape, and a malformed id fails the whole record rather than the field. `cpe23` needs only the `cpe:` prefix (`Software.cpe23` is stricter — it requires the CPE 2.2 URI binding `cpe:/a:`). Addresses are parsed from strings; custom attribute limits apply.
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

**Use `parse_ts` for anything that came from an API.** `parse_time` raises on
input it does not recognize, and a raise from a builtin aborts the whole
script — so one malformed or zero timestamp on one record loses the entire
import. `parse_ts` returns its `default` (`None`) instead, accepts epoch
numbers and the offset-less shapes on-premise sources emit
(`2026-08-15 08:44:01`), and clamps future values to now so a fast appliance
clock does not cause the platform to drop every record.

```python
load('time', 'parse_ts')

def time_example(record):
    first_seen = parse_ts(record.get("created"))          # None if unparseable
    last_seen = parse_ts(record.get("last_seen_ms"), unit="ms")
    print("Unix Timestamp:", first_seen.unix if first_seen else "unknown")
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
Drop-in replacements for `GET` + status-check + `json_decode`. Return
`(data, err)`.

Retry and backoff are on by default: `retries` defaults to `3` (up to four
attempts), covering `408, 425, 429, 500, 502, 503, 504` and transport
errors with exponential backoff, honoring `Retry-After`. Rate-limited and
paged APIs need no extra configuration.

A target the scanner refuses to dial -- on a hosted scan, a URL that
resolves to an internal address -- aborts the script rather than
returning an `err` string, so a tolerant fetch helper cannot walk its
whole endpoint list logging one dial failure per endpoint. Other
transport failures (DNS, refused, TLS, timeout) still arrive as `err`.

Pass `retries=0` when a request is not safe to repeat, or narrow
`retry_on` to statuses that mean the request was rejected unprocessed
(e.g. `retry_on=[429, 503]`) — a retried `post_json` that creates
something can otherwise apply twice. Note the raw `http.get`/`post`/
`put`/`patch` builtins take no `retries` kwarg at all; passing one is an
error.

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

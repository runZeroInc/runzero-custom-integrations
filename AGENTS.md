# Custom Integration Agents

This document provides guidance for creating custom integration scripts for runZero.

## Goal
Create a custom integration script to import assets into runZero from a third-party service (Inbound) or export runZero assets to a third-party service (Outbound).

## Directory Structure
Each integration must be placed in its own directory at the root of the repository.

```
repo-root/
├── <integration-name>/
│   ├── custom-integration-<integration-name>.star  # The main script
│   ├── config.json                                 # Metadata
│   └── README.md                                   # Documentation
```

### 1. `config.json`
This file contains metadata about the integration.

**Format:**
```json
{
  "name": "Integration Name",
  "type": "inbound"
}
```
*   `type`: Use `"inbound"` for importing assets into runZero, `"outbound"` for exporting assets from runZero.

### 2. `custom-integration-<name>.star`
This is the main script written in Starlark.

## Script Development

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

*   **Arguments**:
    *   `kwargs['access_key']`: Typically the username, client ID, or organization ID.
    *   `kwargs['access_secret']`: Typically the password, API token, or secret key.

### Return Type
*   **Inbound**: Must return a `list` of `ImportAsset` objects.
*   **Outbound**: Typically returns `None` after performing the export operation.

### Available Libraries
Load libraries at the top of your script.

```python
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')
load('time', 'parse_time')
load('gzip', gzip_decompress='decompress', gzip_compress='compress')
load('base64', base64_encode='encode', base64_decode='decode')
load('crypto', 'sha256', 'sha512', 'sha1', 'md5')
load('flatten_json', 'flatten')
```

## runZero SDK Types
The Starlark `runzero.types` library exposes `ImportAsset`, `NetworkInterface`, `Software`, and `Vulnerability`. The Python SDK wraps the same REST models and also provides `Hostname`, `Tag`, `Service`, `ServiceProtocolData`, `ScanOptions`, `ScanTemplate`, and `ScanTemplateOptions`. These wrappers enforce validation and normalization, so build your payloads to fit the expected shape:

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

## Testing

Use the `runzero` CLI to test your script locally.

1.  **Run with arguments**:
    ```bash
    runzero script --filename <path/to/script.star> --kwargs access_key=MY_KEY --kwargs access_secret=MY_SECRET
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
    api_key = kwargs.get('access_secret')
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

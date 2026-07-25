# Starlark helpers for runZero custom integrations

This page is a quick reference for the runZero-provided Starlark
builtins available to integration scripts. Use them in place of
hand-rolled helpers whenever possible — they handle the awkward
edge cases (mixed v4/v6 IPs, zone IDs, port suffixes, base64
encoding, retries, JSON decoding, length limits, ...) so your
scripts stay short and consistent.

## Local validation boundaries

Run `runzero script --filename <file-or-directory> --validate` before submitting
an integration. For HTTP integrations, validation parses CONFIG, generates
type-appropriate placeholder values, initializes the script, calls `main`, and
routes requests to a local TLS server. It verifies that at least one request was
made and that declared User-Agent and TLS options reached the HTTP client.

The generated values are not vendor credentials, and the synthetic responses
do not model vendor authentication, pagination, response schemas, or asset
mapping. A successful validation is a CONFIG and wiring check, not proof that a
vendor API accepts the credentials or returns the expected payload. Use
fixture-driven tests for response parsing and asset construction.

Templates and direct-protocol integrations may declare
`"validationMode": "compile"`. Compile validation parses CONFIG, initializes
the script, and verifies that `main` exists without dialing a target. Live SSH,
SMB, WMI, WinRM, and SQL behavior still requires a controlled test endpoint.

The full list of registered modules is loaded automatically when
your script runs; you only need a `load(...)` line for the names
you actually use.

## Loading

The full list of registered modules is loaded automatically; you only need a
`load(...)` line for the names you actually use.

```python
load("runzero.types", "ImportAsset", "NetworkInterface", "Service",
                       "ServiceProtocolData", "Software", "Vulnerability",
                       "to_custom_attributes")
load("net",  "ip_address", "network_interface", "normalize_mac",
             "ip_network", "ip_in_network", "resolve")
load("http", http_get="get", http_post="post",
              "head", "put", "patch", "delete",
              "get_json", "post_json",
              "url_encode", "url_parse", "url_join", "multipart",
              "bearer", "basic", "oauth2_token")
load("kwargs", "require", "has", "get", "get_string", "get_bool", "get_int",
               "get_float", "get_list", "get_url_base", "get_http_tls",
               "get_http_options")
load("json", json_encode="encode", json_decode="decode")
load("jsonstream", "iter_array", "iter_lines")
load("csv", csv_read="read_all", csv_write="write_dicts")
load("xml", xml_parse="parse")
load("re", re_match="match", re_find_all="find_all", re_sub="sub")
load("uuid", "new_uuid")
load("time", "now", "parse_time", "parse_duration", "sleep")
load("requests", "Session", "Cookie")
load("base64", base64_encode="encode", base64_decode="decode")
load("hex", hex_encode="encode", hex_decode="decode")
load("crypto", "sha256", "hmac_sha256", "sign_v4", "random_hex")
load("jwt", jwt_encode="encode", jwt_decode="decode")
load("gzip", gzip_decompress="decompress", gzip_compress="compress")
load("flatten_json", "flatten")
load("runzero.progress", progress_report="report", progress_info="info")
```

Lower-level network modules — `socket`, `runzero.ssh`, `runzero.smb`,
`runzero.winrm`, `runzero.wmi`, and `runzero.sql` — are documented under
[Low-level network & database](#low-level-network--database) below.

These modules run on the selected Explorer and intentionally can connect to
internal addresses available from that Explorer. This is the accepted product
model for collecting from internal management systems; use an appropriately
scoped Explorer and credential.

## Shared HTTP/TLS Options

Use `CONFIG["includes"]` for common connection controls instead of copying
the same parameter blocks into every script. The include prefix becomes part
of each generated kwarg name.

```python
CONFIG = {
  "id": "runzero-example",
  "name": "Example",
  "type": "inbound",
  "version": "26052700",
  "minVersion": "5.0.260723.0",
  "params": [
    {"key": "url", "type": "url", "required": True},
    {"key": "api_token", "type": "secret", "required": True},
  ],
  "includes": {
    "tls_": OPTIONS_TLS,
    "http_": OPTIONS_HTTP,
  },
}
```

For one endpoint, pass the collected dict directly to the HTTP helper:

```python
options = get_http_options(kwargs, "http_", "tls_", {
  "Authorization": bearer(kwargs["api_token"]),
})
data, err = get_json(url, **options)
```

For multiple endpoints, give each include a prefix and collect by that prefix:

```python
src_options = get_http_options(kwargs, "src_http_", "src_tls_", src_headers)
dst_options = get_http_options(kwargs, "dst_http_", "dst_tls_", dst_headers)
```

Use `get_http_tls(kwargs, "src_tls_")` when a script only needs the `tls=`
dict and manages headers separately.

## `http.get_json` / `http.post_json`

Drop-in replacements for the common `GET then status-check then
json_decode` pattern.

```python
data, err = get_json(url, headers=headers, params={"limit": 100})
if err:
    print("fetch failed:", err)
    return []
```

Behaviour:

- Returns a `(data, err)` tuple. `err` is `None` on success or a
  short string on failure (`"status 401: <body snippet>"`,
  `"transport: ..."`).
- 2xx responses with empty bodies decode to `None`.
- Retries transient failures with exponential backoff (default
  statuses: `408, 425, 429, 500, 502, 503, 504`). Pass
  `retry_on=[418]` (or `None` to disable) to override.
- Honors `Retry-After` headers in seconds or HTTP-date form.
- All `http.get`/`http.post` kwargs are accepted
  (`headers`, `params`, `timeout`, `insecure_skip_verify`, ...).
- `post_json` accepts either `json=<dict>` (auto-encodes and sets
  `Content-Type: application/json`) or `body=<bytes>`.

Use the raw `http.get`/`http.post` builtins when you need the
response headers, cookies, or status code directly.

## `http.bearer(token)` / `http.basic(user, pass)`

Format auth headers without manual base64:

```python
headers = {
    "Authorization": bearer(api_key),
    # or
    "Authorization": basic(username, password),
}
```

## `http.oauth2_token(...)`

Run a `client_credentials` token exchange and return the
`access_token` string. Raises on non-2xx or a missing
`access_token`.

```python
token = oauth2_token(
    token_url="https://idp.example.com/oauth/token",
    client_id=client_id,
    client_secret=client_secret,
    scope="read",         # optional
    audience="my-api",    # optional
    extra={"resource": "..."},  # optional extra form fields
)
```

Authentication flows that aren't `client_credentials`
(username/password login endpoints, refresh tokens, custom flows)
should keep using `http.post` directly.

## Other `http` helpers

- `http.head(url, headers=None, params=None, timeout=30, tls=None)` and
  `http.put(url, ..., body=b"", json=None)` round out the verb set
  alongside `get`/`post`/`patch`/`delete`. Every verb returns the same
  response struct (`.status_code`, `.status`, `.headers`, `.body`).
- `http.url_parse(url)` returns a struct with `scheme`, `host`,
  `hostname`, `port`, `path`, `query` (dict of `str -> list[str]`),
  `raw_query`, `fragment`, `username`, `password`, `raw`; returns
  `None` on parse failure.
- `http.url_join(base, ref)` resolves a relative reference against a base
  URL (handy for pagination `next` links).
- `http.multipart(fields)` builds a `multipart/form-data` body and
  returns `(body_bytes, content_type)`. Each field value is a `str`/
  `bytes` (plain field) or a dict `{"filename":..., "content_type":...,
  "content":...}` (file part). Pass the returned content type as the
  request `Content-Type` header.

```python
body, content_type = multipart({
    "name": "report",
    "file": {"filename": "a.csv", "content_type": "text/csv", "content": data},
})
http_post(url, headers={"Content-Type": content_type}, body=body)
```

## `net.network_interface(...)`

Build a `NetworkInterface` from a MAC and a mixed list of IP
strings.

```python
nic = network_interface(
    mac="AA:BB:CC:DD:EE:FF",          # any common form
    ips=["192.0.2.5", "fe80::1%eth0", "[2001:db8::1]:443"],
)
```

- MAC is normalized (colon/dash/Cisco-dotted/bare-hex all accepted).
  Invalid MACs are silently dropped.
- `ips` is auto-classified into v4 / v6; `ipv4=` and `ipv6=` may
  also be passed explicitly.
- Strips `[bracket]:port`, `addr:port`, `%zone` suffixes.
- Dedupes; caps at 99 addresses per family.
- Returns `None` when no usable address is present AND no MAC was
  supplied, so callers can do `if nic: nics.append(nic)`.

## `net.normalize_mac(s)`

Returns the canonical lowercase colon form, or `None` for
unparseable input.

## `net.ip_address(s)`

Validates and classifies a single address. The result exposes
`.version` (4 or 6) and stringifies to the canonical form.

## `net.ip_network(cidr)` / `net.ip_in_network(ip, cidr)`

`ip_network(cidr)` parses a CIDR and returns a struct with `cidr`,
`version` (4/6), `prefix`, `network`, `broadcast`, `netmask`, and a
`contains(ip) -> bool` method (returns `None` on parse failure).
`ip_in_network(ip, cidr)` is the one-shot form and returns `False` for
malformed or mixed-family input.

```python
net10 = ip_network("10.0.0.0/8")
if net10 and net10.contains(addr):
    ...
if ip_in_network("10.1.2.3", "10.0.0.0/8"):
    ...
```

## `net.resolve(host, timeout=10)`

Looks up A/AAAA records and returns a list of `IPAddress` values (mixed
v4/v6, de-duplicated). Returns an empty list (never an error) for empty,
unresolvable, or timed-out lookups, so you can iterate directly. A bare
IP literal resolves to itself; trailing `:port`, brackets, and `%zone`
suffixes are tolerated.

```python
for ip in resolve("api.example.com"):
    print(ip, ip.version)
```

## `runzero.types.to_custom_attributes(value, ...)`

Coerces an arbitrary value into the `string -> string` shape
required by `ImportAsset.customAttributes`. Replaces hand-rolled
`force_string`/flatten helpers.

```python
attrs = to_custom_attributes({
    "name": host.get("name"),
    "tags": host.get("tags", []),     # joined with ","
    "sys": {"os": "linux", "ver": 5}, # flattened with "."
    "active": True,                   # stringified
    "blank": "",                      # dropped
})
```

Supported kwargs:

- `separator` — key separator for nested dicts (default `"."`)
- `list_join` — `","` (default), `"json"`, or `""` to recurse
- `prefix` — prepended to every key
- `exclude` — list of dotted keys to skip
- `drop_empty` — drop empty strings / None / empty lists (default
  `True`)
- `max_key` / `max_value` / `max_entries` — limits applied to keep
  the platform happy (the platform itself caps keys at 256 and
  values at 1024 chars, and supports up to 1024 entries).

## ImportAsset notes

- `hostnames`, `tags` and `networkInterfaces` automatically drop
  empty / `None` entries, so you can write
  `hostnames=[device.get("hostname")]` without the
  `[x] if x else []` wrapper. Pass `[]` to keep them empty.
- `matchBehavior` accepts a space-separated flag string. The two
  presets to remember:
  - `"no-mac-break no-ip-break no-name-break"` — recommended when
    your source supplies a **stable foreign id** (vendor-assigned
    UUID, serial number). The id still drives merges, but
    differing MACs/IPs/names won't disqualify a merge against an
    existing asset.
  - `"no-id-match no-id-break"` — recommended when your source
    only emits **ephemeral / per-run ids**. The id is ignored,
    and merging falls back to MAC/IP/hostname.

## `runzero.types.Service` / `ServiceProtocolData`

Attach richer service detail to an `ImportAsset` via `services=[...]`.

```python
load("runzero.types", "Service", "ServiceProtocolData")

svc = Service(
    address="10.0.0.5",
    port=443,
    transport="tcp",                 # lower-cased
    vendor="nginx",
    product="nginx",
    version="1.25.3",
    protocolData=[
        ServiceProtocolData(name="http", attributes={"server": "nginx"}),
        ServiceProtocolData(name="tls", attributes={"subject": "CN=acme"}),
    ],
    customAttributes={"tier": "edge"},
)
```

- `Service` requires `address`, `port`, `transport`; `vendor`, `product`,
  `version`, `protocolData`/`protocol_data`, and `customAttributes`/
  `custom_attributes` are optional.
- `ServiceProtocolData` requires `name`; `attributes` is an optional
  mapping of protocol-specific fields. Both camelCase and snake_case
  keyword spellings are accepted everywhere in `runzero.types`.

## `kwargs` accessors

Typed, validating accessors over the `**kwargs` dict passed to `main()`.
Each `params[].key` in `CONFIG` arrives as a kwarg of the same name.

```python
load("kwargs", "require", "has", "get_string", "get_bool", "get_int",
               "get_float", "get_list")

def main(*args, **kwargs):
    require(kwargs, "client_id", "client_secret")  # error if missing/blank
    client_id     = get_string(kwargs, "client_id")
    page_size     = get_int(kwargs, "page_size", default=100)
    ratio         = get_float(kwargs, "ratio", default=1.0)
    include_down  = get_bool(kwargs, "include_offline", default=False)
    regions       = get_list(kwargs, "regions", default=[])   # CSV or list -> list[str]
    if has(kwargs, "region"):
        ...
```

- `get`/`get_string` are aliases. `get_bool` accepts `true/false/1/0/
  yes/no/on/off`. `get_list` splits a comma-separated string or passes a
  list through. Missing optional values fall back to `default`.
- `get_url_base(kwargs, key)` extracts the scheme+host (drops path/query)
  from a URL kwarg.
- `get_http_tls(kwargs, "tls_")` collects the `OPTIONS_TLS` include into a
  `tls=` dict.
- `get_http_options(kwargs, "http_", "tls_", headers)` collects the
  `OPTIONS_HTTP` + `OPTIONS_TLS` includes (timeout, proxy, TLS, etc.) into
  a kwargs dict you can splat into any `http` helper (see
  [Shared HTTP/TLS Options](#shared-httptls-options)).

## `time`

Re-exports the standard Starlark `time` module plus `time.sleep`.

```python
load("time", "now", "parse_time", "parse_duration", "from_timestamp", "sleep")

t = parse_time("2023-10-27T10:00:00Z")   # time.time
print(t.unix, t.year, t.hour)
print(t.format("2006-01-02"))
d = parse_duration("90m")                 # time.duration
print(d.minutes)                          # 90.0
later = now() + d                          # time + duration -> time
sleep("250ms")                            # honors the sandbox deadline
```

- `time.time` fields: `year`, `month`, `day`, `hour`, `minute`, `second`,
  `nanosecond`, `unix`, `unix_nano`; methods `format(layout)`,
  `in_location(name)`.
- `time.duration` fields: `hours`, `minutes`, `seconds`, `milliseconds`,
  `microseconds`, `nanoseconds`. Arithmetic with `time`/`duration` is
  supported (`time - time -> duration`, `duration / duration -> float`).
- Constants: `time.second`, `time.minute`, `time.hour`, ...

## `requests` (stateful HTTP sessions)

Use a `Session` when you need cookie persistence or sticky headers across
requests. Method names are case-insensitive (`session.get` ==
`session.GET`).

```python
load("requests", "Session", "Cookie")
load("json", json_decode="decode")

session = Session()                       # Session(insecure_skip_verify=False)
session.headers.set("Accept", "application/json")
session.cookies.set("https://api.example.com", {"sid": "abc"})

resp = session.get("https://api.example.com/data", params={"limit": 100})
if resp.status_code == 200:
    data = json_decode(resp.body)
```

- Verbs: `get`, `post`, `put`, `patch`, `delete`, `head`. Each accepts
  `headers`, `cookies`, `params`, `body`, `json`, `timeout` and returns
  the same response struct as the `http` module.
- `session.headers` exposes `get(key)` / `set(key, value)` (`value=None`
  deletes). `session.cookies` exposes `get(url)` / `set(url, cookies)` /
  `clear()`.
- `Cookie(name, value, path="", domain="", secure=False, http_only=False,
  max_age=0, ...)` constructs a cookie for `cookies.set`.

## Encoding & hashing

```python
load("base64", b64_encode="encode", b64_decode="decode")
load("hex", hex_encode="encode", hex_decode="decode")
load("base32", b32_encode="encode", b32_decode="decode")
load("crypto", "sha256", "sha512", "md5",
               "hmac_sha256", "hmac", "sign_v4", "random_hex", "random_bytes")
load("jwt", jwt_encode="encode", jwt_decode="decode")
```

- `base64` also provides `raw_encode`/`raw_decode` (unpadded) and
  `url_encode`/`url_decode` (URL-safe alphabet). `hex` and `base32`
  (`raw_*` for unpadded) cover the other common encodings.
- `crypto` hashes (`sha1`, `sha256`, `sha512`, `md5`) take a `str`/`bytes`
  and return hex. HMAC: `hmac_sha1/256/512(key, data, output="hex")` and
  the generic `hmac(algorithm, key, data, output="hex")`; `output` may be
  `"hex"`, `"base64"`, `"base64_raw"`, or `"bytes"`.
- `crypto.sign_v4(method, url, headers, body, access_key, secret_key,
  region, service, session_token=None, timestamp=None)` returns the AWS
  SigV4 headers dict (`Authorization`, `X-Amz-Date`,
  `X-Amz-Content-Sha256`, optional `X-Amz-Security-Token`).
- `crypto.random_bytes(n)` / `crypto.random_hex(n)` produce CSPRNG output.
- `jwt.encode(claims, key, algorithm="HS256", headers=None)`,
  `jwt.decode(token, key, algorithms=None)` (verifies), and
  `jwt.decode_unverified(token)` (returns `{"header", "claims"}`). The
  `none` algorithm is rejected.

## Data parsing: `json` / `jsonstream` / `csv` / `xml` / `re`

```python
load("jsonstream", "iter_array", "iter_lines")
load("csv", csv_read="read_all", csv_write="write_dicts")
load("xml", xml_parse="parse")
load("re", re_match="match", re_find_all="find_all", re_sub="sub")
```

- `jsonstream.iter_array(body, path=None)` streams elements of a (possibly
  nested, dot-pathed) JSON array without materializing the whole document;
  `jsonstream.iter_lines(body)` streams NDJSON / JSON-lines. Prefer these
  for large responses.
- `csv.read_all(text, delimiter=",", comment="", header=True)` returns a
  list of dicts (or list-of-lists with `header=False`);
  `csv.read_rows(...)` is the header-less form; `csv.write_all(rows)` and
  `csv.write_dicts(rows, fields=None)` serialize back to a CSV string.
- `xml.parse(text)` returns an element tree (XXE-safe). Elements expose
  `tag`, `text`, `tail`, `attrib`, `children`, and methods `find(path)`,
  `find_all(path)`, `get(name, default="")`, `text_all()`.
- `re` uses Go RE2 syntax. `match`/`search` return a struct
  (`.match`, `.start`, `.end`, `.groups`, `.named`) or `None`; `find_all`,
  `find_all_groups`, `sub(pattern, repl, string, count=-1)`, `split`,
  `escape`, and `compile(pattern)` (reusable object with
  `.match`/`.find_all`/`.sub`) are also available.

## Low-level network & database

These modules open raw connections for protocols that don't have a REST
API. They return connection/session objects with a `close()` method —
always close them when done.

```python
load("socket", "tcp", "udp", "tls")
load("runzero.ssh", ssh_dial="dial")
load("runzero.smb", smb_dial="dial")
load("runzero.winrm", winrm_dial="dial")
load("runzero.wmi", wmi_dial="dial")
load("runzero.sql", sql_connect="connect")
```

- `socket.tcp(host, port, timeout=30, tls=False, ...)` / `socket.udp(...)`
  / `socket.tls(...)` return a socket with `send`, `recv`, `recv_exact`,
  `recv_line`, `recv_until`, `starttls`, `set_timeout`, `close` and
  attributes `local_addr`, `remote_addr`, `is_tls`, `closed`.
- `runzero.ssh.dial(host, username, password=None, private_key=None,
  port=22, timeout=30)` → session with `run(command) -> (stdout, stderr,
  exit_code)`.
- `runzero.smb.dial(host, username, password="", nt_hash=None, port=445)`
  → session with `mount(share)`, `list_shares()`; a mounted share offers
  `read`, `list`, `stat`, `exists`.
- `runzero.winrm.dial(host, username, password, https=False, auth="ntlm")`
  → session with `run(command)`, `run_powershell(script)`,
  `wql(query, namespace="root/cimv2")`.
- `runzero.wmi.dial(host, username, password, transport="tcp",
  namespace="//./root/cimv2")` → session with `query(wql, limit=0,
  page=100) -> list[dict]`.
- `runzero.sql.connect(driver, dsn, ...)` (`driver` ∈ `postgres`,
  `mysql`, `mssql`) → session with `query(sql, params=None) -> list[dict]`
  and `exec(sql, params=None) -> {rows_affected, last_insert_id}`. DSNs are
  restricted to network-only access.

## `runzero.progress`

Surface task progress and log lines in the runZero UI.

```python
load("runzero.progress", progress_report="report", progress_info="info")

progress_report(40, "fetched 4/10 pages")   # pct clamped to [0, 100]
progress_info("retrying after 429")
```

- `report(pct, msg="")` — calls within 250ms are coalesced; messages are
  truncated to 256 bytes.
- `info(msg)` / `warn(msg)` — emit log lines through the per-task logger.

## `report_assets` (streaming inbound assets)

`report_assets` is a predeclared builtin (no `load` required) that streams
`ImportAsset` values to runZero as your script runs, instead of accumulating
them all and returning a single `list` from `main`. Use it for inbound
integrations that page through large inventories so memory stays bounded by a
single page rather than the entire dataset.

```python
def main(**kwargs):
    cursor = None
    while True:
        page, cursor = fetch_page(kwargs, cursor)
        if not page:
            break
        report_assets(build_assets(page))   # stream this page
        if not cursor:
            break
    return None                             # nothing buffered in main
```

Accepted argument shapes:

```python
report_assets(asset)            # a single ImportAsset
report_assets(a, b)             # several positional ImportAssets
report_assets(page_assets)      # a list/tuple of ImportAsset
report_assets(*page_assets)     # the same, spread
n = report_assets(batch)        # returns the int count reported
```

- Reported assets are merged with any `list` returned from `main`, so partial
  adoption is safe.

## See also

- `boilerplate/boilerplate.star` — a runnable
  example that exercises the common helpers above.
- `AGENTS.md` — guidance for authoring new integrations.

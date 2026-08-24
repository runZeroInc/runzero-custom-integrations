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
load("net",  "ip_address", "network_interface", "normalize_mac", "mac_key",
             "ip_network", "ip_in_network", "resolve",
             "routable_ip", "routable_ips", "clean_hostname", "clean_hostnames")
load("coerce", "as_text", "as_dict", "as_list", "dicts",
               "as_int", "as_float", "as_bool", "dedupe")
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
load("time", "now", "parse_ts", "parse_time", "parse_duration", "sleep")
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
  "version": "1",
  "maturity": "alpha",
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
- **Retries transient failures by default.** `retries` defaults to `3`,
  so a call makes up to four attempts. Transient statuses (default
  `408, 425, 429, 500, 502, 503, 504`) and transport errors are retried
  with exponential backoff, and `Retry-After` response headers (seconds
  or HTTP-date form) are honored. You do not need to opt in.
- Tuning knobs, all optional: `retry_on=[418]` (or `None`) overrides the
  status list, and `retry_backoff` / `retry_max_backoff` (defaults `1.0`
  / `30.0` seconds) control the sleep, which doubles each attempt up to
  the maximum.
- **Pass `retries=0` for a request that is not safe to repeat.** A
  retried `post_json` that creates or mutates something can apply twice:
  a 5xx may mean the server processed the request and only the response
  was lost. For non-idempotent writes either disable retries or narrow
  the list to statuses that mean the request was rejected unprocessed:

  ```python
  post_json(url, json=payload, retry_on=[429, 503], **http_options)
  ```
- **A target the scanner refuses to dial ends the run.** On hosted
  scans, a URL that resolves to an internal address is refused by the
  scanner itself, and that failure aborts the script instead of coming
  back as an `err` string -- no retries, one log line. A script does not
  need to guard for it: without the abort, a tolerant fetch helper walks
  the whole endpoint list and reports one dial failure per endpoint plus
  a run's worth of misleading "0 records read" lines. Every other
  transport failure (DNS, refused, TLS, timeout) still arrives as `err`,
  because those can be endpoint-specific.
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

## `net.normalize_mac(mac, preserve_bits=True)`

Returns the canonical lowercase colon form, or `None` for
unparseable input. Accepts colon, dash, dotted-quad Cisco
(`AABB.CCDD.EEFF`), and bare 12-hex forms.

`preserve_bits=True` (the default) keeps the first octet exactly as the
source reported it. Pass `preserve_bits=False` for the platform's
cross-source matching form, which clears the locally administered bit —
that maps `aa:bb:cc:dd:ee:ff` and `a8:bb:cc:dd:ee:ff` onto the same
value.

> **These helpers are for keys your script builds for itself** — joining
> a DHCP lease table to a device table, de-duplicating records, indexing
> by MAC — where the source's own value is what should match, and where
> collapsing two locally administered addresses would join the wrong
> records. Locally administered addresses are the norm on virtual and
> containerized NICs, so that collapse is not rare.
>
> They are **not** a way to change the MAC that lands on an asset.
> `network_interface(mac=...)` stores the platform's LAA-cleared
> canonical form regardless of what you pass, because that is what
> `Asset.addMAC` stores and what the platform's bogus/common/virtual MAC
> tables are keyed on. A custom integration must not introduce a second
> spelling into that matching path.

## `net.mac_key(value)`

`normalize_mac` plus the rejections a usable key needs. Returns `None`
for the all-zero and broadcast placeholders, and for the synthetic
`ip-<address>` hardware address that dnsmasq-derived sources (Pi-hole /
FTL among them) invent for a client they never saw at layer 2. Use it as
the "is this a real MAC" gate; use `normalize_mac` when you only need
canonical formatting.

```python
# Index the lease table, then join devices onto it.
leases_by_mac = {}
for lease in dicts(data.get("leases")):
    key = mac_key(lease.get("hwaddr"))   # None for 00:00:00:00:00:00, ip-10.0.0.1
    if key:
        leases_by_mac[key] = lease

lease = leases_by_mac.get(mac_key(device.get("hwaddr")), {})
```

## `net.routable_ip(value, exclude=None)` / `net.routable_ips(values, exclude=None)`

Returns the canonical form of an address usable as an asset identity, or
`None`. Input is normalized first, so a bracketed address, a
`host:port`, an IPv6 zone id (`fe80::1%igb0`), and a CIDR-suffixed
address (`10.0.0.1/24`) are all accepted — real inventory APIs emit all
four, and hand-rolled filters routinely miss one and silently drop those
addresses.

Rejected by default: loopback, unspecified/`0.0.0.0`, link-local,
multicast, and broadcast. These are not "bogons" — they are the values
that are actively harmful as an identity, because many devices carry
them at once and importing them merges every such device onto a single
asset. RFC1918, CGNAT, and ULA addresses are deliberately **kept**.

`routable_ips` maps over an iterable, dropping rejects and
de-duplicating while preserving order:

```python
addresses = routable_ips([e.get("ip") for e in device.get("ips", [])])
```

Pass `exclude=[...]` to replace the default CIDR set, or `exclude=[]` to
disable exclusion entirely. A malformed CIDR raises, rather than
silently excluding nothing.

## `net.clean_hostname(value, extra=None)` / `net.clean_hostnames(values, extra=None)`

Returns a value fit to import as a hostname, or `None`. Rejects
placeholder names (`localhost`, `unknown`, `none`, `-`, `n/a`, ...),
values that are really IP addresses, all-numeric names, empty or
over-long labels, names past the 253-character DNS limit, and anything
containing a character that cannot appear in a DNS name.

Each of those is a merge hazard rather than merely useless: every device
whose reverse lookup failed carries the same one.

`extra=[...]` adds source-specific placeholders — the appliance's own
alias for itself, a vendor's "New Device" default — matched
case-insensitively. `clean_hostnames` maps over an iterable and de-duplicates
case-insensitively, keeping the first spelling seen.

```python
names = clean_hostnames(raw_names, extra=["pi.hole"])
```

## `net.ip_address(s)`

Validates and classifies a single address. The result exposes
`.version` (4 or 6) and stringifies to the canonical form.

## `net.mac_vendor(mac)`

> **Not yet available.** This function exists in the platform source but is not
> in any released Explorer build. `load("net", "mac_vendor")` currently fails
> with `name mac_vendor not found in module net`, and a failed load aborts the
> whole script before `main` runs — so do not reference it yet. The description
> below is here so the capability is documented when it ships.

Looks the MAC up in the OUI registry and returns the registered vendor
name, or `None` when the address is unparseable or its prefix is not
assigned. Accepts the same forms as `normalize_mac`.

Locally administered addresses — randomized client MACs, and the space
AWS assigns to EC2 interfaces — have no registered vendor by
construction, so `None` means "no assigned prefix", not "bad input".
Treat a `None` as unknown rather than as a reason to discard the
address.

```python
vendor = mac_vendor(mac)          # "VMware, Inc." / None
if vendor:
    attrs["mac_vendor"] = vendor
```

The most useful application is validating a MAC recovered from an
opaque or undocumented field: a registered prefix is strong evidence
that the value really is a MAC rather than a coincidentally
hex-shaped identifier.

## `net.enterprise_vendor(id)`

> **Not yet available** — same caveat as `net.mac_vendor` above.

Resolves an IANA enterprise (SNMP private enterprise) number to its
registered organization name, or `None` when the id is negative or
absent from the table. Takes an integer, not a string.

```python
name = enterprise_vendor(9)       # "ciscoSystems"
```

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

- `hostnames` and `tags` drop empty-string entries, and
  `networkInterfaces` drops `None` entries — but a `None` element in
  `hostnames` is an error ("hostnames must be an iterable of strings"),
  so `hostnames=[device.get("hostname")]` aborts when the field is
  absent. Route names through `clean_hostnames([...])`, which also
  screens placeholders. Pass `[]` to keep the list empty.
- **The constructor ignores empty arguments** — `None`, a blank or
  whitespace-only string, an empty list or dict. Pass every optional
  field unconditionally instead of building the arguments up through an
  `if x: params["x"] = x` ladder:

  ```python
  asset = ImportAsset(
      id=asset_id,
      os=as_text(record.get("os")),               # skipped when ""
      osVersion=as_text(record.get("os_version")),
      manufacturer=as_text(record.get("vendor")),
      hostnames=names,                          # skipped when []
      firstSeenTS=parse_ts(record.get("created")),   # skipped when None
      lastSeenTS=parse_ts(record.get("last_seen")),
  )
  ```

  A `False` boolean is a real value and is **not** skipped, so
  `trustOS=False` still sets the flag. `id` is always forwarded.
- `lastSeenTS` (and `last_seen_ts`) are accepted by the constructor,
  alongside `firstSeenTS`. Older scripts assign `asset.lastSeenTS` after
  construction because the constructor used to reject it; that still
  works, but is no longer necessary.
- `matchBehavior` is **not** an `ImportAsset` field. It is declared once
  per integration as a top-level `CONFIG` key, placed after `minVersion`,
  and applies to every record the script emits; passing it to
  `ImportAsset` fails validation. It accepts a space-separated flag
  string, and the two presets to remember are:
  - `"no-mac-break no-ip-break no-name-break"` — recommended when
    your source supplies a **stable foreign id** (vendor-assigned
    UUID, serial number). The id still drives merges, but
    differing MACs/IPs/names won't disqualify a merge against an
    existing asset.
  - `"no-id-match no-id-break"` — recommended when your source
    only emits **ephemeral / per-run ids**. The id is ignored,
    and merging falls back to MAC/IP/hostname.

  Carry a comment alongside the value saying why the default is wrong
  for this source. See the root README for the full flag table.

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

## `coerce` (defensive type conversion)

A JSON API's schema is a suggestion. A field documented as a string
arrives as a number, an object arrives as `null`, an array arrives as a
bare object when it holds one element. Indexing into those directly
raises, and a raise aborts the import — which is why nearly every script
grew its own `_text` / `_dict` / `_list` / `_to_int` guards.

Nothing in `coerce` raises. Each function returns the requested type or
the supplied default, so calls chain without guarding.

```python
load("coerce", "as_text", "as_dict", "as_list", "dicts", "as_int", "as_float",
     "as_bool", "dedupe")

result = as_dict(data.get("result"))          # {} when the API sent null
for record in dicts(result.get("devices")):   # skips nulls and stray strings
    name  = as_text(record.get("hostname"))      # "" when absent
    count = as_int(record.get("num_queries")) # 0 when absent or unparseable
```

| Function | Returns |
| --- | --- |
| `as_text(value, default="")` | Trimmed string. `None` → default; `True` → `"true"` (not Starlark's `"True"`); a whole float `42.0` → `"42"`; a dict or list → default, rather than a Go-syntax dump. |
| `as_dict(value)` | The dict, or `{}`. |
| `as_list(value, wrap=True)` | The list. `None` → `[]`; a tuple converts; any other value is wrapped in a one-element list (a string is never split into characters). `wrap=False` yields `[]` instead. |
| `dicts(value)` | Only the dict members of an iterable. A bare dict yields a one-element list. |
| `as_int(value, default=0)` | Int. Parses numeric strings; truncates floats toward zero. |
| `as_float(value, default=0.0)` | Float. |
| `as_bool(value, default=False)` | Bool. Matches `true/t/yes/y/on/1/enabled/active` and their negatives, case-insensitively. **An unrecognized string yields `default`, not Starlark truthiness** — under which the string `"false"` is `True`. |
| `dedupe(values, fold_case=False)` | Trimmed strings, in order, blanks and repeats removed. |

## `time`

Re-exports the standard Starlark `time` module plus `time.sleep` and
`time.parse_ts`.

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

### `time.parse_ts(value, default=None, assume_utc=True, clamp_to_now=True, unit="s")`

**Use this instead of `parse_time` for anything that came from an API.**
`parse_time` raises on input it does not recognize, and a raise from a
builtin aborts the entire script — so one malformed or zero timestamp on
one record loses the whole import. `parse_ts` returns `default` instead.

```python
load("time", "parse_ts")

first_seen = parse_ts(record.get("created"))     # None if absent or malformed
last_seen  = parse_ts(record.get("last_seen_ms"), unit="ms")
```

Accepts a `time` (returned as-is, still clamped), an int/float epoch, a
numeric string, and datetime strings in the usual layouts — including
the offset-less shapes that on-premise sources actually emit
(`2026-08-15 08:44:01` from SQL `DATETIME`, `2026-08-15T08:44:01`
without the trailing `Z`). Those are read as UTC unless
`assume_utc=False`.

A non-positive epoch yields `default`: sources write `0` for "never" far
more often than they mean 1970.

`clamp_to_now=True` (the default) caps a future value at the current
time. This is not cosmetic — the platform rejects an `ImportAsset` whose
first- or last-seen time is ahead of now and drops **the entire record**,
so an appliance whose clock runs fast would otherwise import nothing at
all. Pass `clamp_to_now=False` if you want to detect skew yourself.

`unit` selects the scale of a numeric value (`"s"`, `"ms"`, `"us"`,
`"ns"`). It is explicit rather than magnitude-guessed, because guessing
silently reinterprets dates far from the present. An unrecognized `unit`
raises — that is a bug in the script, not bad data.

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
  attributes `local_addr`, `remote_addr`, `is_tls`, `closed`. The `tls`
  argument on `socket.tcp` (and the `tls=` kwarg on `socket.tls` /
  `.starttls`) accepts either a bool or a dict of TLS overrides in the same
  shape as the `http` module (`insecure`, `server_name`, `ca_pem`,
  `client_cert_pem`, `client_key_pem`, `thumbprints`), so you can splat
  `get_http_tls(kwargs, "tls_")` straight into a raw TLS socket:
  ```python
  conn = tls(host, 9390, timeout=60, tls=get_http_tls(kwargs, "tls_"))
  ```
- `runzero.ssh.dial(host, username, password=None, private_key=None,
  port=22, timeout=30)` → session with `run(command) -> (stdout, stderr,
  exit_code)`. The session also offers:
  - `open_unix(path)` — forward to a UNIX-domain socket on the remote host
    (the SSH `direct-streamlocal` extension, i.e. `ssh -L
    localport:/remote.sock`) and return a `socket` value. Speak a raw
    protocol (e.g. GMP to `/run/gvmd/gvmd.sock`) with no remote helper such
    as `socat`/`netcat`.
  - `open_tcp(host, port)` — forward to a TCP address reachable from the
    remote host (`direct-tcpip`, i.e. `ssh -L localport:host:port`) and
    return a `socket` value; call `.starttls(...)` to speak TLS over it.
  - `stream(command, stdin=None, timeout=0)` — start a long-lived remote
    command and return a stream object with `send`, `recv(max, timeout)`
    (`b""` at EOF), `close_stdin`, `close`, and `exit_code` / `stderr`
    attributes, for incrementally consuming large command output.
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

## `report_asset` / `report_assets` (streaming inbound assets)

Both are predeclared builtins (no `load` required) that stream
`ImportAsset` values to runZero as your script runs, instead of
accumulating them and returning a single `list` from `main`.

**Prefer `report_asset`, and do not batch.** Report each asset as it is
built:

```python
def main(**kwargs):
    p = pager("devices")
    cursor = None
    reported = 0
    while p.next():
        page, cursor = fetch_page(kwargs, cursor)
        for record in page:
            reported += report_asset(build_asset(record))
        if not cursor:
            break
    print("reported {} assets".format(reported))
    return None                             # nothing buffered in main
```

The accumulate-and-flush pattern some older scripts use —

```python
batch.append(asset)
if len(batch) >= BATCH_SIZE:
    reported += report_assets(batch)
    batch = []
...
if batch:                       # the trailing flush that is easy to forget
    reported += report_assets(batch)
```

— buys nothing. The host already writes incrementally, so the batch is
just a second buffer in front of it. Reporting per asset bounds memory
regardless of estate size and cannot lose a partial final batch when a
script returns early.

`report_asset(asset)` takes exactly one `ImportAsset` and returns `1`, so
`reported += report_asset(asset)` accumulates a count directly. Passing
`None` is a no-op returning `0`, so
`report_asset(build_asset(record))` stays safe when your builder declines
a record.

`report_assets` remains available for the cases where you genuinely have
a list in hand:

```python
report_assets(asset)            # a single ImportAsset
report_assets(a, b)             # several positional ImportAssets
report_assets(page_assets)      # a list/tuple of ImportAsset
report_assets(*page_assets)     # the same, spread
n = report_assets(batch)        # returns the int count reported
```

- Reported assets are merged with any `list` returned from `main`, so partial
  adoption is safe.

## Pagination: `CONFIG["maxPages"]` and `pager()`

Every pagination loop needs a backstop, because a source whose cursor
never terminates otherwise spins until the task's wall-clock deadline
kills it with no indication of why. Do **not** declare your own
`MAX_PAGES` constant for this; the limit belongs in `CONFIG`, where an
operator can see and change it.

```python
CONFIG = {
    "id": "runzero-example",
    "name": "Example",
    "type": "inbound",
    "version": "1",
    "minVersion": "5.0.260723.0",
    "maxPages": 5000,          # optional; defaults to 1,000,000
    "params": [...],
}
```

`pager(label="pages", limit=0)` returns a loop guard enforcing that
value:

```python
p = pager("devices")
while p.next():
    data, err = get_json(url, params={"cursor": cursor})
    if err:
        break
    for record in dicts(data.get("results")):
        report_asset(build_asset(record))
    cursor = data.get("next")
    if not cursor:
        break
```

- `p.next()` returns `True` while the loop may continue. **It never
  returns `False`** — reaching the limit raises, naming the label, the
  limit, and the `maxPages` key. A pagination loop is supposed to end
  because the source said there is no next page; running out of allowed
  pages instead means the import is incomplete, and silently returning
  `False` would hand back a truncated asset set that looks complete.
- `p.page` is `0` before the first `next()`, then the 1-based number of
  the page the body is handling — use it directly in a `page=` query
  parameter or a log line.
- `p.limit` and `p.label` expose what the guard was built with.
- Give each loop its own label. A script that pages through parents and
  then through each parent's children has two very different bounds, and
  the label is what tells you which one failed to terminate.
- `limit=` lets an inner loop tighten its own bound. It cannot raise the
  bound past `CONFIG["maxPages"]`.
- `max_pages()` returns the effective limit if you need the number
  itself.

`maxPages` must be positive when set; omit it to take the default of
1,000,000.

## See also

- `boilerplate/boilerplate.star` — a runnable
  example that exercises the common helpers above.
- `AGENTS.md` — guidance for authoring new integrations.

## Asset types and merge policy

Neither `matchBehavior` nor `assetTypeBehavior` is a helper you `load` — both
are CONFIG keys, because the merge path needs the policy before it has an
asset. Passing `matchBehavior=` to `ImportAsset` fails validation.

`ImportAsset(assetType="lease")` labels one asset's population, and
`CONFIG["assetTypeBehavior"]` gives that population its own merge policy on top
of the integration-wide `CONFIG["matchBehavior"]`. A type named in
`assetTypeBehavior` that no asset actually carries is dead configuration: those
records silently inherit the integration-wide policy instead.

See the "Asset types and per-type merge policy" section of `AGENTS.md` for the
full rules and the flag table.

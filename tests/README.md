# Integration fixture tests

`rumble-scanner script --validate` proves an integration wires up: its CONFIG
parses, its parameters resolve, it makes at least one HTTP request, and it does
not abort. It cannot prove the integration is *correct*, because its dummy
server answers from three built-in heuristics and every collection it returns is
empty — no row is ever parsed, no second page is ever fetched, no token ever
expires.

These tests close that gap. Each scenario stands up a fixture server with
scripted responses, runs the **real scanner** against it, and checks the assets
that come out. Because the scanner is real, anything the runtime rejects — a
future timestamp, a malformed CVE, an unexpected keyword argument — fails here
exactly as it would in production.

## Running

```bash
python3 tests/run.py                     # every scenario
python3 tests/run.py bmc-discovery       # one integration
python3 tests/run.py bmc-discovery/paged # one scenario
```

Point `RUNZERO_SCANNER` at a scanner binary. `/usr/local/bin/runzero` is a
zero-byte stub and does not work; build the dev scanner instead:

```bash
cd /Users/dev/go/platform/product/rumble-scanner && go build -tags recogNocloud,development -o /tmp/rumble-scanner .
```

## Tuning the fixture servers

Both mock servers (`harness/server.py` for HTTP, `harness/gmp_server.py` for
GMP) serve from a bounded worker pool rather than a thread per connection,
which is what an earlier `ThreadingHTTPServer` did — under a parallel run that
was enough live threads to take the machine down.

| variable | default | what it does |
| --- | --- | --- |
| `MAX_WORKERS` | 1000 | ceiling on concurrent HTTP handlers |
| `LISTEN_BACKLOG` | 1000 | accept queue depth for the HTTP server |
| `CONN_TIMEOUT` | 10 | seconds before an idle connection is dropped |
| `GMP_MAX_WORKERS` | 1000 | ceiling on concurrent GMP handlers |
| `GMP_LISTEN_BACKLOG` | 1000 | accept queue depth for the GMP server |

These are ceilings, not allocations: the pool grows lazily to whatever is
genuinely concurrent, which for these scenarios is a handful.

Every HTTP response closes its connection, and that is load-bearing. With
keep-alive a worker stays checked out for the life of the connection rather
than the life of the request, so a bounded pool fills with idle connections,
later connections are accepted but never serviced, and the scanner waits on a
reply that cannot come — the run deadlocks instead of failing. **If a scenario
hangs, suspect that before raising `MAX_WORKERS`.**

## Layout

```
tests/
  run.py                        shared entry point
  harness/server.py             declarative fixture server
  harness/runner.py             drives the scanner, checks expectations
  harness/invariants.py         checks that apply to every integration

<slug>/tests/fixtures/<name>.json   one scenario
```

Scenarios live beside the integration they cover, so everything an integration
owns — its script, its README, and its tests — sits in one directory. Only the
shared harness is top-level.

## Scenario schema

```jsonc
{
  "name": "paged",
  "integration": "bmc-discovery",          // defaults to the directory name
  "script": "akamai-guardicore-centra/centra-v4-api.star", // when the script is
                                           // not <slug>/<slug>.star, or a
                                           // directory ships more than one
  "description": "What this scenario proves.",

  "kwargs": {                              // $BASE becomes the fixture server URL
    "url": "$BASE",
    "api_token": "fixture-token"
  },

  "routes": [
    {
      "match": {                           // first matching route wins
        "method": "POST",                  // optional
        "path": "/api/v1/devices",         // exact
        "path_prefix": "/api/",            // or prefix
        "path_regex": "/hosts/[0-9]+$",    // or regex
        "query_contains": "page=2",        // optional
        "body_contains": "SEARCH Host",    // optional; needed for RPC-style APIs
        "header": {"aw-tenant-code": ""}   // optional; "" matches on presence
      },
      "responses": [                       // consumed IN ORDER, one per call
        {"status": 200, "json": {"items": []}},
        {"status": 401, "json": {"error": "expired"}},
        {"status": 200, "json": {"items": []}},
        {"status": 303, "headers": {"Location": "$BASE/blob"}, "text": ""},
        {"status": 200, "body_base64": "H4sIAA..."}  // a binary body
      ],
      "when_exhausted": "repeat_last"      // or "empty" or "error"
    }
  ],

  "default_response": {"status": 404, "text": "no fixture route"},

  "expect": {
    "assets": [                            // assert individual field values
      {
        "id": "vendor:$BASE_HOST:abc",
        "fields": {
          "_match.behavior": "no-id-match no-id-break mac-match ...",
          "deviceType": "Server",
          "vendor_serial": "SVC12345"
        },
        "fields_absent": ["macAddresses"]  // must be empty or missing
      }
    ],
    "asset_count": 4,
    "min_assets": 1,
    "ids": ["vendor:tenant:abc"],          // must be present
    "ids_absent": ["vendor:tenant:skipme"],// must have been skipped
    "request_count": 3,
    "min_requests": 2,
    "requests_include": [                  // assert the CALL SEQUENCE
      {"method": "POST", "path_contains": "/search"},
      {"query_contains": "offset=2"},
      {"header_contains": "fixture-token"},
      {"header": {"aw-tenant-code": "fixture-tenant"}}
    ],
    "requests_absent": [{"path_contains": "/admin"}],
    "log_contains": ["skipping device with no id"],
    "min_services_total": 1,
    "min_software_total": 2,
    "min_vulnerabilities_total": 3
  },

  "invariants": {"skip": ["namespaced_ids"]},
  "check_determinism": true,               // run twice, ids must match
  "timeout": 180
}
```

### Substitution tokens

`$BASE` becomes the fixture server's URL. It is expanded in `kwargs` **and
throughout `expect`**, so an integration that scopes its ids on the base URL can
still have those ids asserted exactly despite the server binding an ephemeral
port. `$BASE_HOST` expands to `host:port` and `$HOST` to the host alone — use
whichever matches how the integration builds its namespace:

```jsonc
"ids": ["vendor:$BASE_HOST:device-1"]   // scoped on host:port
"ids": ["vendor:$HOST:device-1"]        // scoped on hostname only
```

Reach for these rather than disabling `check_determinism`; an id you cannot
assert is the assertion most worth having.

The ordered `responses` list is the point of the whole design. It is what makes
the *sequence* testable rather than just the wiring: page 2 can differ from page
1, a session can expire on the third call, an async job can report `running`
before `done`, and a rate limit can be served once and then relent.

A response body comes from exactly one of three keys. `json` serializes a
literal, `text` sends a UTF-8 string, and `body_base64` sends **raw bytes**
decoded from base64. The last exists because `text` is UTF-8 encoded on the way
out, which mangles every byte above `0x7f` — a gzip member begins `1f 8b` and
cannot survive it. `runzero-task-sync` downloads gzipped scan data and
decompresses it, so without `body_base64` its only real code path is untestable.
Generate one with `base64.b64encode(gzip.compress(payload))`.

### GMP scenarios (raw socket, not HTTP)

`FixtureServer` only ever hands a script an HTTP base URL, so it cannot drive an
integration that speaks a socket protocol. `greenbone/greenbone.star`
makes zero HTTP requests — it goes `runzero.ssh.dial` → `open_unix()`, or
`socket.tls()`, and then exchanges XML. A scenario that declares a top-level
`gmp` block additionally starts a TLS listener speaking the Greenbone Management
Protocol, and `$GMP_HOST` / `$GMP_PORT` expand to it:

```jsonc
"kwargs": {
  "transport": "tls",
  "gmp_host": "$GMP_HOST", "gmp_port": "$GMP_PORT",
  "tls_disable_validation": "true"        // NOT tls_insecure_skip_verify
},
"gmp": {
  "routes": [
    {"match": {"command": "get_reports"},
     "responses": [{"xml_file": "report-page1.xml"},
                   {"xml_file": "report-page2.xml"}]}
  ]
}
```

Routes match on `command` (the request's first tag), `body_contains`, or
`body_regex`. A response is inline `xml` or an `xml_file` beside the scenario —
prefer the file, because a recorded transcript is the point of the test and is
worth reading as XML rather than as one long JSON string. `"close": true` closes
the connection instead of answering, which is how gvmd really behaves when it
rejects a command.

Requests are recorded with method `GMP` and `path` set to the command name, so
the usual `requests_include` / `requests_absent` matchers work unchanged. An
`<authenticate>` body is logged redacted, so a scenario can assert that
authentication happened without a password reaching the request log.

The listener is started only when a scenario declares `gmp`, so HTTP scenarios
are unaffected. It needs `openssl` on PATH to mint a throwaway certificate.

## Invariants

Every scenario runs these against the emitted assets. They encode defects found
by review that a wiring check cannot see. Skip one only with a reason recorded
in the scenario's `description`.

| Invariant | What it catches |
| --- | --- |
| `unique_ids` | The same foreign id emitted twice in one run. |
| `namespaced_ids` | An id with no tenant/appliance scope, so two deployments collide. |
| `no_loopback_interfaces` | **Link-local** (`169.254/16`, `fe80::/10`) on an interface — an address a host invents when DHCP fails, which identifies nothing and can correlate two such hosts to each other. See the caveat below: loopback itself never reaches an asset. |
| `no_mac_in_id` | A MAC used as the foreign id. `normalize_mac` clears the locally administered bit, so two distinct endpoints can normalize to one value — correct for an interface, wrong for identity. |
| `child_caps` | More than 99 software, services, or vulnerabilities on one asset. |
| `has_correlator` | An asset with no MAC, IP, or hostname, which can never merge with anything. |
| `no_placeholder_hostnames` | `localhost`, `unknown`, or a bare IP imported as a hostname. |
| `service_addresses_sane` | A service on port 0/65536+ or bound to a placeholder address. |

### What the runtime filters before you see it

The platform's `NormalizeAddress` (`runzero/net/ip.go`) rejects **loopback,
multicast, and unspecified** addresses as a "filtered range" before they reach
an asset, while `IsUnicast` deliberately **keeps link-local** APIPA `169.254/16`
and `fe80::/10`.

Two consequences for scenario authors:

- A script that puts `127.0.0.1` on an interface produces an asset with **no
  address**, not one carrying loopback. So `no_loopback_interfaces` passing does
  **not** prove the integration filters loopback — you would be testing the
  runtime. To prove a script's own loopback handling, assert at the record
  level: that the loopback-only host is skipped entirely, or that a real address
  survived alone alongside it.
- Link-local *does* survive, so an integration that fails to filter APIPA will
  be caught, and that is what this invariant is really for.

`check_determinism` runs the scenario a second time and requires identical ids.
That is what catches an id built from `new_uuid()`, a timestamp, or anything
else that changes between polls — such a script reconciles against nothing and
duplicates its estate every time it runs.

## Scenarios worth writing

Start with `happy`, then add whichever of these the integration can actually
exercise. Each one corresponds to a class of bug found in this repo:

- **paged** — at least two pages, asserting the second request carries the
  cursor, offset, or page number the first response returned.
- **auth-refresh** — a 401 mid-run, then success, proving re-authentication
  happens and the run continues.
- **rate-limit** — a 429 followed by success. `get_json`/`post_json` retry three
  times by default; no integration should hand-roll this.
- **empty** — a tenant with no records. Must report zero assets, not fail.
- **malformed** — a string where an object is documented, a number where a
  string is, a null id. Must skip the record and keep going.
- **detail-cap** — for N+1 enrichment, prove the cap is honoured and the skip
  count logged.
- **identity-stability** — the same device with a changed IP, hostname, or host
  node must keep its id. This is the regression test for an id that embedded
  something mutable.

# Live endpoint tests

A fixture scenario proves a script parses what the scenario feeds it. It cannot
prove the scenario resembles the vendor — a response shape invented from
documentation is a hypothesis, and only a real controller settles it. These runs
are the other half: same scanner, same invariants, real endpoint.

```bash
python3 tests/run_live.py                          # every configured integration
python3 tests/run_live.py ubiquiti-unifi-network   # one, by slug or env prefix
python3 tests/run_live.py --list                   # what is configured, and what is not
python3 tests/run_live.py --log                    # print the full run log on failure
python3 tests/run_live.py --env ~/creds.env        # a credential file somewhere else
```

`tests/run.py` never runs these and never will. A live test calls someone's
production controller; it must not happen because a developer typed the wrong
command.

## Credentials

Everything comes from a **git-ignored `.env`** at the repo root, or from the
real environment, which wins — so CI can inject secrets from its own vault
without writing them to disk:

```bash
UNIFI_API_KEY=$(vault read -field=key unifi) python3 tests/run_live.py unifi
```

`cp .env.example .env` and uncomment what you can reach. `.env.example` is
committed and lists every variable of every integration with fake values; it is
generated, so regenerate it after a CONFIG change:

```bash
python3 tests/run_live.py --env-template > .env.example
```

Two globals:

| Variable | Meaning |
| --- | --- |
| `RUNZERO_CLI` | The scanner that runs each script. Defaults to `runzero` on PATH. |
| `<PREFIX>_*` | One integration's parameters. Everything else. |

## Naming

Every variable is `<PREFIX>_<PARAMETER>`, where `PARAMETER` is the **CONFIG
parameter key upper-cased**. `api_key` is `<PREFIX>_API_KEY`; nothing declares
that mapping because CONFIG already did, and a second list would only drift from
the first. Parameters that arrive through `includes` follow their prefix, so
`OPTIONS_TLS` under `"tls_"` gives `<PREFIX>_TLS_DISABLE_VALIDATION`.

`PREFIX` defaults to the directory name upper-cased —
`ubiquiti-unifi-network` → `UBIQUITI_UNIFI_NETWORK`. An integration that wants
a shorter one, or an alias for an awkward parameter, declares it in
**`<slug>/tests/live.json`**, beside the script and its fixtures:

```jsonc
{
  "env_prefix": "UNIFI",              // UNIFI_URL instead of UBIQUITI_UNIFI_NETWORK_URL
  "aliases": {                        // a friendlier name for one parameter
    "TLS_INSECURE": "tls_disable_validation"
  },
  "script": "akamai-guardicore-centra/centra-v4-api.star",  // only when a
                                      // directory ships more than one script
  "invariants": {"skip": ["no_mac_in_id"]},   // with a reason, as for fixtures
  "timeout": 900                      // seconds; default 600
}
```

The file is optional. An integration with no `live.json` is still live-testable
under its derived prefix.

Three suffixes belong to the harness rather than to an integration:

| Variable | Meaning |
| --- | --- |
| `<PREFIX>_EXPECT` | What a valid result looks like. Required. |
| `<PREFIX>_EXPECT_FILE` | The same terms, one per line, `#` comments allowed, from a file outside git. Combined with `_EXPECT` when both are set. |
| `<PREFIX>_LIVE_TIMEOUT` | Seconds before the run is failed. |

It is `LIVE_TIMEOUT` rather than `TIMEOUT` because four integrations declare a
`timeout` parameter of their own meaning something else entirely — how long to
wait on the vendor. The parameter that reaches the endpoint keeps the plain name.

## What runs, and what is merely skipped

- **No `<PREFIX>_` variable set** → skipped silently and counted. Two configured
  credentials produce two runs and one skip count, not 77 failures.
- **Some set** → the integration is claimed, and is then held to the whole
  contract: every CONFIG-required parameter present, an expectation present and
  parseable, and no `<PREFIX>_` variable that matches no parameter.

That last rule is the point. `UNIFI_API_KY=...` silently ignored is a run that
reports green while testing nothing, so an unrecognised variable fails loudly
and names the closest one that exists.

## Expectations

`EXPECT` is a space-separated list of terms, shell-quoted. **Every term must
parse**; an unrecognised one fails the run before any request is made. An
expectation with a typo that silently passes is worse than no expectation at
all, because it reports success for an assertion nobody is making.

| Term | Asserts |
| --- | --- |
| `asset_count>=5` | How many assets came back. Also `>` `=` `<` `<=` `==`. |
| `services>=1` | Services across every asset. Also `software`, `vulnerabilities`. |
| `any:hostnames=JOHNS-IPHONE` | Some asset carries this value in this field. |
| `any:os~Windows` | Some asset's field contains this substring. |
| `asset[unifi:abc]` | This exact foreign id was emitted. |
| `asset[unifi:abc]:deviceType=Switch` | …and that asset's field has this value. |

Field names are the ones on the **emitted asset**, not the vendor's: `id`,
`hostnames`, `ipAddresses`, `macAddresses`, `deviceType`, `os`, and whatever
custom attributes the script produced. `=` matches one whole value
case-insensitively — the platform joins multi-value fields with a tab, and each
tab-separated part is one value. `~` is a case-insensitive substring over the
raw field, which is how to match inside a value the script comma-joined itself.
Quote values containing spaces: `any:os="Windows Server 2019"`.

A failure says what it saw, so a wrong guess is one edit rather than one
investigation:

```
FAIL  ubiquiti-unifi-network
        asset_count>=99: got 4
        any:hostnames=NOSUCHHOST: matched none of 4 assets (hostnames seen: JOHNS-IPHONE, LAPTOP-01, BEDROOM03)
        any:hostnamez=x: no asset carries a field named 'hostnamez'. Closest fields present: hostnames
```

Expectations appear in failure output, so put no secrets in them.

## Invariants

Every live run is checked by the same invariants as a fixture scenario, skips
declared in `live.json` rather than per-scenario. This is deliberate: a real
endpoint is exactly where an unnamespaced id, a randomized MAC, or an APIPA
address first shows up, because no fixture author thinks to invent one. A run
whose expectations all pass still fails on the invariant:

```
FAIL  ubiquiti-unifi-network
        invariant no_loopback_interfaces: non-identifying addresses on interfaces: ['aa:bb:cc:00:00:09 -> 169.254.11.22']
```

## Secrets

A parameter is treated as secret when CONFIG marks it `type: "secret"` or
`secret: True`, or when its name looks like a credential — the name test is what
covers option-set parameters such as `tls_client_key`, which CONFIG does not
list. Secret values are replaced with `***` in the echoed command and in the run
log; short secrets are replaced only on token boundaries so a two-character
password cannot turn the log into confetti.

The run log is printed only on failure, and only its last 20 lines, because a
live log carries real hostnames and addresses. `--log` prints all of it.

## Credentials the CLI cannot carry

`runzero script --kwargs key=value` corrupts two shapes of value in silence, so
the harness refuses them up front rather than letting you debug a 401 that is
really a parsing bug. Both are verified against the scanner:

| Value | What arrives |
| --- | --- |
| `a=b,c=d` | `a=b`, **plus an invented parameter** `c=d`. A value holding `=` makes the flag parser treat the pair as CSV, so it splits on the comma and the remainder becomes a parameter the integration never declared — which it then rejects by a name nobody set. |
| `p@ssw0rd"` | `p@ssw0rd`. With a single `=` the parser trims quotes from the whole pair, eating the value's trailing quote. |

A comma alone is safe (`a,b` survives); it is the combination with `=` that
triggers it. A credential of either shape cannot be live-tested until the CLI
takes kwargs some other way — through a file or stdin rather than a flag.

## What this deliberately does not do

- **No determinism check.** The fixture harness runs each scenario twice and
  requires identical ids; a live estate legitimately changes between two polls —
  a client roams off, a VM is deleted — so the same check here would fail for
  reasons that are not defects. Prove identity stability with a fixture.
- **No writes.** Only `inbound` collection is exercised. An outbound integration
  with credentials set will run and push to the real destination, so point it at
  a test tenant or leave it unconfigured.
- **No fixture-style request assertions.** The harness never sees the vendor's
  traffic, so `requests_include`, `log_contains`, and response-sequence
  assertions belong to fixture scenarios and have no live equivalent.
- **One credential per integration.** Two tenants of the same vendor need two
  runs with different environments.

## Adding an integration

Usually nothing: set `<DERIVED_PREFIX>_*` and an `EXPECT`, and it runs. Add
`<slug>/tests/live.json` only for a shorter prefix, an alias, an invariant skip,
a longer timeout, or to name which script a multi-script directory means.
`python3 tests/run_live.py --list` shows every prefix.

# Containerized integration tests

`python3 tests/run_containers.py` starts the vendor's real software in a
container, seeds it, points the integration at it, and asserts on the assets
that come out.

This is the sibling of the live-endpoint suite above. Same idea — run against
something real rather than a fixture — but the endpoint is a container the
harness starts itself, so it needs no credentials, no tenant, and no network
beyond a registry pull. A fixture proves the script parses what its author
*believed* the API returns; this proves it parses what the software *actually*
returns.

Everything downstream of "the scanner ran" is shared with the fixture harness.
The export parser, the whole `expect` vocabulary, and the invariants come from
`harness/runner.py` and `harness/invariants.py` rather than being reimplemented,
so an integration behaves here exactly as it does under `tests/run.py`.

## Running

```
python3 tests/run_containers.py                # every light integration
python3 tests/run_containers.py pihole         # one integration
python3 tests/run_containers.py --heavy        # include the heavy stacks
python3 tests/run_containers.py --list         # what is available
python3 tests/run_containers.py --sweep-all    # also clear other runs' strays
```

Needs Docker with the `compose` plugin, and a scanner binary in
`RUNZERO_SCANNER` (same as the fixture suite). **This is a separate entry point
and never runs as part of `python3 tests/run.py`** — it needs Docker, pulls
images, and a single case can take minutes.

When Docker is unavailable the run prints a `SKIP` notice and exits 0. A missing
Docker is a missing tool, not a broken integration. Any actual failure exits
non-zero, so the suite can gate CI.

## Host hygiene

These tests start real databases and real application servers. Run carelessly
they will saturate the machine they are meant to be protecting, so the harness
is deliberate about it:

- **One integration's stack at a time.** The runner is strictly sequential and
  never skips teardown. Nothing runs in parallel, on purpose. Two instances of
  the suite on one host break that rule; each warns when it sees the other's
  stack, and neither removes it.
- **Teardown is verified, not assumed.** Every case tears down in a `finally`,
  then `docker ps` is checked for survivors. Anything left is force-removed and
  reported as a failure of that case — a stack that needs `docker rm -f` to die
  has a bug in its compose file, and hiding it moves the failure onto whoever
  runs the suite next.
- **A leaked container fails the run.** It holds its published port and its
  share of the host, so the next case fails with a collision that looks like its
  own bug. The end of every run prints the actual `docker ps` it finished with.
- **Only harness containers are ever touched.** The sweep matches the `rzci-`
  compose-project prefix. Your own containers survive a run untouched.
- **And only *this* run's containers are removed.** That prefix is shared by
  every instance of the suite, so the end-of-run sweep force-removes only the
  projects it started itself — its own `rzci-<pid>-…`. Anything else carrying
  the prefix is reported and left running: nothing about a stray says whether it
  is an earlier run's litter or a second run's live stack, and killing a run in
  flight is the worse mistake. Once you know no other run is active,
  `--sweep-all` clears them.
- **Every image tag is pinned, with exactly one waived exception.** A `:latest`
  that moves upstream turns a vendor release into a flaky test instead of the
  deliberate upgrade it should be. The exception is **`ntopng`**, and it is the
  only unpinned stack in this suite: `ntop/ntopng` publishes exactly one tag on
  Docker Hub — `latest` — so there is no version to pin to, and ntop ships no
  alternative repository for the stable channel. Rather than leave the
  integration untested, the rule was waived for it deliberately. In exchange,
  `ntopng/tests/docker/manifest.json` records `_image_digest`: the digest the
  case was actually written and verified against, so a failure can be attributed
  to an upstream rebuild rather than to the integration. Re-record it after a
  deliberate upgrade:

  ```bash
  docker inspect --format '{{index .RepoDigests 0}}' ntop/ntopng:latest
  ```

  Do not treat this as a precedent. Anything that publishes a version tag pins
  it; `icinga2`, added alongside it, pins `icinga/icinga2:2.16.4` for exactly
  that reason.
- **Every wait is bounded and polls for real readiness.** There are no blind
  sleeps: a `sleep 30` either wastes 25 seconds or fails intermittently on a
  slow machine. Gates poll the API and give up cleanly.
- **Heavy stacks opt out of the default run.** A manifest with `"heavy": true`
  is skipped unless named explicitly or run under `--heavy`.

## Layout

Container assets live beside the integration, next to its fixtures:

```
<slug>/tests/docker/compose.yml     the stack, with pinned image tags
<slug>/tests/docker/manifest.json   readiness, seeding, kwargs, expectations
<slug>/tests/docker/seed.py         creates the admin user, credential, and data
```

`compose.yml` receives the harness-allocated host port as `${RZ_HOST_PORT}`.
Ports are never hard-coded: two runs, or two integrations, would collide, and a
collision looks exactly like a broken integration.

## Manifest schema

On top of the fixture scenario's `expect`, `invariants`, and
`check_determinism`, a manifest declares the container lifecycle:

| key | meaning |
| --- | --- |
| `compose` | compose file name, default `compose.yml` |
| `service` | service name used by `exec` readiness gates and seeding |
| `scheme` | `http` or `https`; builds `$BASE` with the allocated port |
| `ready` | ordered readiness gates, polled before seeding |
| `seed` | script run once the gates pass; prints a JSON object |
| `ready_after_seed` | gates polled again after seeding, for async workers |
| `kwargs` | parameters passed to the integration |
| `heavy` / `heavy_reason` | opt out of the default run, and say why |
| `startup_timeout`, `seed_timeout`, `timeout` | bounds, in seconds |

A readiness gate is either an HTTP probe or a command in the container:

```json
{"name": "api answering", "http": {"path": "/api/status", "status": [200, 401]},
 "timeout": 180, "interval": 2}
{"name": "node is Ready", "exec": ["kubectl", "get", "nodes"], "contains": "True"}
```

Readiness is layered, which is why gates are ordered: the HTTP port opens well
before the database migration finishes, and an API answers `/status` long before
it will answer `/nodes`. A `401` from an API that is up but wants credentials is
a perfectly good readiness signal, so the gate names which statuses count.

### Seeding

A test that needs a human to click through a setup wizard is not a test, so
every integration owns a seed script that creates its admin user, its API
credential, and at least one device record. The script prints a JSON object as
its last line, and the manifest references those values as `${seed.<key>}`:

```json
"kwargs": {"url": "$BASE", "api_key": "${seed.api_key}"},
"expect": {"assets": [{"id": "docker:$HOST:host:${seed.daemon_id}"}]}
```

Discover rather than hard-code anything the software mints itself — row ids,
UUIDs, daemon ids, generated tokens. A Pi-hole device id depends on the order
FTL happened to see the interfaces in; a hard-coded `1` passes on a fast machine
and fails on a slow one.

`$BASE` and `$HOST` work exactly as they do in fixture scenarios.

### What a manifest cannot assert

Request-level assertions — `request_count`, `min_requests`, `requests_include`,
`requests_absent` — are rejected at load time. There is no recording proxy in
front of the container, so they would silently pass. Assert those in a fixture
scenario, where the harness sees every request.

## Adding an integration

1. Confirm the vendor publishes a self-hostable image, and pin a tag.
2. Write `compose.yml`, publishing the API port as `${RZ_HOST_PORT}`.
3. Bring it up by hand and probe the API. Find out what the software actually
   returns before writing a single expectation.
4. Write `seed.py`, ending with a JSON object of everything the manifest needs.
5. Write `manifest.json` with bounded readiness gates and real assertions.
6. Run it, confirm teardown is clean, and check the fixture suite still passes.

Prefer light stacks: a single static binary that boots in seconds is worth more
than a three-container stack nobody will wait for. Mark anything that needs
emulation or gigabytes of RAM `"heavy": true`.

**Assert what the software returns, not what you expected.** Real software
returns real data — link-local addresses, docker-bridge MACs, `localhost`
hostnames, its own loopback interface as a device. That is the entire value of
this suite. Two examples currently asserted:

- Pi-hole reports its own `lo` as a device, hwaddr `00:00:00:00:00:00` on
  `127.0.0.1`, named `localhost`. No hand-written fixture would think to include
  it. The manifest asserts by id that it is *dropped*.
- The platform's `network_interface()` helper clears the locally-administered
  bit, so a container MAC configured as `02:42:0a:de:07:02` is emitted as
  `00:42:0a:de:07:02`. The manifests assert the normalized value and say why, so
  the transformation is visible rather than surprising.

## Integrations that cannot be containerized

Not everything can be, and faking it would defeat the point — a stub that
returns what the script expects is a fixture with extra steps, and a worse one
than the fixtures already in `<slug>/tests/fixtures/`. These have no
self-hostable image and are covered by fixtures plus the live-endpoint suite:

| integration | why not |
| --- | --- |
| `infoblox` | NIOS ships as a licensed hardware or VM appliance; no public image. |
| `quest-kace` | SMA is a licensed virtual appliance distributed to customers only. |
| `nozomi-networks` | Guardian is a licensed sensor appliance, hardware or VM. |
| `truenas` | An OS image, not an application container; needs its own storage stack. |
| `unraid` | A licensed OS that boots from its own media; there is no image to run. |
| `ubiquiti-unifi-protect` | Firmware for UniFi NVR hardware; not distributed as an image. |

Anything reached only as a vendor-hosted SaaS — no on-premise build exists to
run — belongs in the same category. Use `tests/run_live.py` for those.

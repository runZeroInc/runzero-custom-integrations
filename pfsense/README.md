# Custom Integration: pfSense

This integration imports a pfSense firewall as a single runZero `ImportAsset`, carrying its
hostname and domain, platform and version, serial and build, and every interface the firewall
reports with a MAC or an address.

> **It imports one asset: the firewall itself.** No DHCP lease, alias, rule, or ARP entry is
> read, and nothing but the appliance becomes an asset. The `CONFIG` description used to
> claim "Imports firewall objects and DHCP leases from pfSense", which was wrong on both
> counts; it now describes what the script does. See [Future](#future) for what adding
> leases would involve.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the pfSense management interface. This is normally an
  internal or DMZ address, so the Explorer has to sit somewhere that can reach it.

## pfSense requirements

- **pfSense with the REST API package installed.** The API is not part of a stock pfSense
  install — it is the third-party pfSense REST API package. This integration speaks its **v2**
  routes; a v1-only installation will not answer them.
- An API key with read access to system status. The integration only reads: it issues four
  `GET` requests and never writes.
- The pfSense web GUI normally presents a self-signed certificate, so plan on either
  installing a trusted certificate or setting the credential's `tls_` options.

### Which endpoints are called

All four are called on every run, unconditionally. There is no fallback chain — an endpoint
that fails degrades that part of the asset rather than being retried against a different path:

| Endpoint | What it supplies | If it fails |
|---|---|---|
| `GET /api/v2/system/hostname` | `hostname`, `domain` | asset gets an empty hostname |
| `GET /api/v2/system/version` | `os` (platform), `osVersion` | falls back to `pfSense` / `unknown` |
| `GET /api/v2/status/interfaces` | network interfaces | asset gets no interfaces |
| `GET /api/v2/status/system` | **the asset id** (`netgate_id`), model, serial, build | the id falls back to the base URL — see [Asset identity](#asset-identity) |

Each response is unwrapped one level when it carries a top-level `data` object, and each field
is read from a list of candidate spellings rather than a fixed key, so a package version that
renames a field degrades to the default instead of failing.

## Steps

### pfSense configuration

1. Install and enable the pfSense REST API package, and confirm it serves the **v2** routes.
2. Create an API key with read access to system and status data.
3. Decide how the key is sent. The package supports more than one scheme and this is the most
   common reason a valid key is rejected — see `auth_header` below.
4. Confirm the endpoint answers from the Explorer host before configuring anything in runZero:

   ```bash
   curl -sk -H 'X-API-Key: <token>' \
     'https://pfsense.example.com/api/v2/status/system'
   ```

   `-k` is used here because of the self-signed certificate; decide deliberately whether to
   keep skipping validation on the runZero credential.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "pfSense").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **pfSense base URL** (`base_url`): required; scheme and host of the management interface, for example `https://pfsense.example.com`. The `/api/v2/...` paths are appended by the script, so give a base only.
   - **API token** (`api_token`): required; secret. The API key created above.
   - **Auth header name** (`auth_header`): optional; **defaults to `X-API-Key`**. Three values are recognized, matched case-insensitively:

     | Value | Header actually sent |
     |---|---|
     | `X-API-Key` (default) | `X-API-Key: <token>` |
     | `api-key` | `api_key: <token>` |
     | anything else, including `authorization` | `Authorization: Bearer <token>` |

   - **Legacy JSON credential** (`legacy_credentials`): optional; secret. Back-compat only — see below.
   - **TLS options** (`tls_*`): set `tls_disable_validation` or `tls_ca_cert` for the self-signed certificate case.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### The legacy JSON credential

`legacy_credentials` exists so credentials created before this integration had a `CONFIG`
block keep working. It is a JSON object and the named parameters take precedence over every
key in it:

```json
{
  "base_url": "https://pfsense.example.com",
  "api_token": "YOUR_API_TOKEN",
  "auth_header": "x-api-key",
  "insecure_skip_verify": false
}
```

Two things about it are worth knowing:

- **A `legacy_credentials` value that is not JSON is treated as the bare API token.** If
  `api_token` is empty and the legacy field does not begin with `{`, its whole value becomes
  the token. That is deliberate — the oldest credentials stored just the key — but it means a
  malformed JSON blob is silently sent as a password rather than reported as a parse error.
- **`insecure_skip_verify` is reachable only through this JSON**, and only for back-compat.
  It is **not declared in `CONFIG`**, and a `CONFIG`-based integration rejects undeclared
  kwargs, so it can never arrive as a named parameter or via `--kwargs`. The script used to
  read it from kwargs as well, which was unreachable code that read like a supported option;
  that read has been removed and only the legacy JSON key remains. Use
  `tls_disable_validation` instead, which is the supported route and does the same thing.

Prefer the named parameters for anything new. The JSON form cannot be passed on the command
line at all — see below.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to find out
whether the API package is answering and whether the key is being sent in the form it expects.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename pfsense/pfsense.star \
  --kwargs base_url=https://pfsense.example.com \
  --kwargs api_token=8f3c1a20b7de49560c1f2e3d4a5b6c78 \
  --kwargs auth_header=X-API-Key \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./pfsense-run
```

`--output` writes the serialized asset so you can inspect exactly what would be imported. It
requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a local
run. Add `--overwrite` to re-run into a directory that already exists. Omit `--output` to see
only the log lines, and add `--verbose` for the request-by-request log.

The script prints `INFO: <url>` before every request and
`INFO: no usable response from <path>: <status>` for each one that fails, so a run tells you
exactly which of the four endpoints answered without needing `--verbose`. **A run that
"succeeds" with an unreachable API still imports an asset** — every field degrades to a
default and the id falls back to the base URL — so read those lines rather than trusting the
asset count.

There is no page size, cap, or filter parameter. One appliance produces one asset and four
requests, so there is nothing to bound.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact — `--kwargs 'x=a,b'` arrives as `a,b`. Only a
value that *also* contains a second `=` flips the flag into comma-separated parsing, and then
the value is cut at the first comma and the remainder becomes a fabricated parameter. **This
is why `legacy_credentials` cannot be passed on the command line**: JSON carries both
characters several times over. Use the named parameters for command-line runs and keep the
JSON form for existing console credentials.

To check the `CONFIG` block and the HTTP and TLS wiring without a live firewall:

```bash
runzero script --filename pfsense/pfsense.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server, so it
proves the script initializes, declares its parameters correctly, and issues a request. It
does not prove the REST API package is installed, that the key is accepted, or that the
`auth_header` choice is the right one.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py pfsense
```

The same script also runs under the `scan` command, which is what the platform itself invokes
for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat pfsense/pfsense.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'base_url=https://pfsense.example.com,api_token=<token>,auth_header=X-API-Key' \
  --output ./pfsense-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is a different flag with a stricter rule: it takes **one**
comma-separated `key=value` string, so no value passed through it may contain a comma at all.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing asset with the data pulled from pfSense, or create one if no existing asset meets merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:pfsense`.

## Asset identity

- Target entity: the pfSense appliance itself — one asset per configured credential, not one per object the firewall knows about.
- Source ID field: `netgate_id` from `GET /api/v2/status/system`, **falling back to the configured `base_url`** when that field is absent or empty.
- Documentation evidence: the Netgate ID is the per-appliance identifier Netgate issues and pfSense displays on its dashboard; it is what the appliance is registered and licensed under. It is a property of the hardware rather than of the configuration, which is exactly what a foreign id wants. The fallback is not — see below.
- Uniqueness scope: global when `netgate_id` is present, because Netgate assigns it. Tied to the configured URL string when the fallback fires.
- Cardinality: exactly one asset per run.
- Stability: **conditional, and this is the property to understand before scheduling this integration.**
  - With `netgate_id`: stable across reboots, address changes, hostname changes, and pfSense upgrades. This is the good case.
  - With the fallback: the id is the base URL, sanitized by replacing `https://`, `http://`, `/`, `:`, and spaces with `-`, collapsing runs of `-`, and trimming the ends. So `https://pfsense.example.com` becomes `pfsense-pfsense.example.com`. It is stable only while nobody edits the credential. Re-pointing the same firewall from an IP to a DNS name, or adding a port, mints a **new** asset and strands the old one.
  - Worse, the two are not independent. A run in which `GET /api/v2/status/system` fails — a permissions problem, an API-package upgrade, a timeout — silently switches an appliance from its Netgate ID to the URL-derived id and creates a duplicate asset. Nothing in the task log flags this beyond the `INFO: no usable response from /api/v2/status/system` line, which is why that line is worth watching.
- Reuse behavior: Netgate IDs are not recycled. The URL fallback is trivially reusable — point the credential at a different firewall on the same address and it inherits the previous one's identity.
- Presence: `netgate_id` is present on Netgate hardware. A community pfSense install on generic hardware or in a VM may not carry one, in which case the fallback is not an edge case but the normal path.
- Final runZero ID: `pfsense-<sanitized netgate_id or base_url>`.
- Missing-ID behavior: not reachable. `_pick()` always returns something, so no record is ever skipped.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative on Netgate hardware; **configuration-derived, not authoritative**, on anything else.

### Why the default `matchBehavior` is right, and why it matters more here

The default is correct for this source, and for once the argument does not rest on the foreign id at all.

A firewall is the asset runZero is most likely to have already discovered by scanning, and it is the asset where a mis-merge is most damaging — it sits on every segment and shares subnets with everything. `GET /api/v2/status/interfaces` returns every interface with its MAC, IPv4, and IPv6 address, which is strong, contemporaneous, first-party evidence, and it is exactly what should be allowed to find the existing asset. Keeping `mac-break`, `ip-break`, and `name-break` on preserves their protection on precisely the path where this record is most likely to be about to merge onto the wrong thing.

The `no-mac-break no-ip-break no-name-break` preset would be actively wrong here, because the identity above is only conditionally stable. That preset is safe when the foreign id is dependable enough that nothing else needs to guard a merge. When the id can silently fall back to a string derived from the credential, the break flags are the remaining safety net, and removing them would let a fallback-id record merge onto whatever asset happens to share an address.

### Notes

- **`trust_os`, `trust_os_version`, and `trust_device_type` are all set.** The appliance reports its own platform, version, and role authoritatively, so the script overrides runZero's fingerprinting rather than deferring to it. `deviceType` is hardcoded to `Firewall`.
- **The interface list is not filtered.** Every entry `GET /api/v2/status/interfaces` returns with a `macaddr`, `ipaddr`, or `ipaddrv6` becomes a `NetworkInterface`, including bridges, VLAN children, and tunnel interfaces. On a firewall that is usually what you want — those really are its addresses — but it does mean an OpenVPN or WireGuard interface address is imported as an address of the appliance.
- **Fields are read from candidate lists, not fixed keys.** `model` comes from the first of `product_name`, `name`, `platform` that is set; `serial` from `serial` or `serial_number`; `build` from `build_time`, `builddate`, or `build`. This is deliberate: the REST API package renames fields between versions, and degrading to a default is better than aborting.
- **Every request failure is non-fatal by design.** `get()` returns a `(None, path)` pair rather than falling off the end, because a bare `None` return aborted the script on the tuple unpack. The consequence is the one recorded under **Asset identity**: a completely unreachable API still produces an asset.
- Rate limiting is not documented for the pfSense REST API. The shared HTTP helper retries 408/425/429 and 5xx with exponential backoff and honors `Retry-After`, three additional attempts by default.
- This integration was validated against local fixtures, not a live pfSense appliance.

## Future

- **DHCP leases as assets.** This is the largest gap and the most useful addition, and it is what the `CONFIG` description used to claim before it was corrected to match the behaviour. The REST API package exposes the DHCP server's leases (`GET /api/v2/status/dhcp_server/leases`, with the v2 package also serving Kea and static-mapping views), and each lease carries a MAC, an address, and usually a client hostname. Those are real devices on segments the firewall serves and often on segments no Explorer sits in, which makes them coverage a scan cannot reach. The identity design is the interesting part and it is already settled by precedent in this library: a lease is ephemeral scan-derived data with no stable vendor id, so lease-derived assets want `matchBehavior="no-id-match no-id-break"` and correlation on MAC and IP, exactly as `opnsense`, `openwrt`, `adguard-home`, and `pihole` do for the same data. Emitting them under the appliance's own identity scheme would be a mistake.
- **ARP and NDP tables as a second discovery source.** `GET /api/v2/diagnostics/arp_table` and the NDP equivalent list every neighbour the firewall has resolved, including statically addressed devices that never take a lease. Same identity treatment as leases, and the two together are close to a full picture of each attached segment.
- **Firewall rules, aliases, and NAT as exposure context.** The v2 API serves the full configuration (`/api/v2/firewall/rules`, `/api/v2/firewall/aliases`, `/api/v2/firewall/nat/port_forwards`). Port forwards are the interesting one for runZero: each is a documented statement that an internal service is deliberately published to the outside, which is precisely the kind of exposure an external scan tries to infer. Importing them as services or attributes on the internal target would turn an inference into a fact.
- **Outbound: runZero queries as pfSense aliases.** This is the direction with real leverage. pfSense aliases are named address lists that rules reference, and the v2 API can create and update them (`POST`/`PATCH /api/v2/firewall/alias`, followed by `POST /api/v2/firewall/apply`). A runZero query — unmanaged devices, assets missing an EDR agent, anything on a quarantine list — could maintain an alias that an existing block or restrict rule already points at, so discovery drives enforcement without an operator editing a list by hand. Two warnings: this writes live firewall configuration and needs a far tighter confirmation model than any scheduled read, and the apply step is what makes changes take effect, so a half-finished run leaves staged changes behind.
- **Interface, gateway, and service status as availability data.** `GET /api/v2/status/gateways` and the service-status routes report WAN health, gateway latency and loss, and which services are running. Useful as attributes on the appliance asset, and cheap — one request each.
- **Certificate inventory.** `GET /api/v2/system/certificate` lists the certificates and CAs the firewall holds, including the ones terminating VPN tunnels and the web GUI. Expiry dates on infrastructure certificates are a classic blind spot and nothing else in a runZero estate reports them.
- **There is no event or alert feed.** The REST API package is a configuration and status interface with no webhook, no event stream, and no change cursor. pfSense's own notification path is syslog, which is a different integration shape entirely — anything near-real-time would be a log pipeline, not a poll of this API.
- **Log ingestion is possible but probably not worthwhile here.** The v2 package can return firewall log entries, but a firewall log is a high-volume event stream and runZero is an asset inventory. The addresses in it are better obtained from the ARP and DHCP tables above, at a tiny fraction of the request cost.

## API documentation

- The pfSense REST API is a third-party package for pfSense rather than a Netgate product, and its reference is published by the package author: <https://pfrest.org/>
- pfSense product documentation, for the appliance itself and the Netgate ID: <https://docs.netgate.com/pfsense/en/latest/>

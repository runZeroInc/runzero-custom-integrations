# Custom Integration: Mosyle

Imports iOS, macOS, tvOS, and visionOS devices from Mosyle Manager.

> **Note on naming.** This directory is spelled `mosyle`, which transposes two
> letters of the vendor's name. The product is **Mosyle**, and the integration's
> `CONFIG` declares `"id": "runzero-mosyle"` and `"name": "Mosyle"`. The
> directory name is left alone here to avoid breaking existing references; be
> aware of the discrepancy when searching.

## runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with outbound HTTPS access to `https://managerapi.mosyle.com`.

## Mosyle Requirements

- Mosyle API token (`api_token`).
- Mosyle admin account email and password, provided in `email` and `password` fields. The `legacy_credentials` JSON/dict field remains supported for existing credentials.
- Account must have permission to access device inventory.

**All three credentials are genuinely required together.** The `email` and
`password` parameters are marked optional in `CONFIG` only because
`legacy_credentials` can supply them instead — they are not optional to the
authentication flow. Mosyle uses a two-step login: the API token identifies the
tenant, and the admin account authenticates. A token on its own will not work.

### This integration targets Mosyle Manager, not Mosyle Business

Mosyle runs two separate APIs and they are not interchangeable:

| Product | Base URL | Where the token goes |
| --- | --- | --- |
| Mosyle **Manager** (education) | `https://managerapi.mosyle.com/v2` | `accessToken` in the **JSON body** |
| Mosyle **Business** | `https://businessapi.mosyle.com/v1` | `accesstoken` **HTTP header** |

This integration's default `url` is the Manager v2 endpoint and it sends the
token in the request body, so it works against Manager. Pointing it at the
Business endpoint will fail with `accessToken Required`, because Business reads
the token from a header this script does not set. Whether Mosyle Fuse exposes
the Business API, the Manager API, or something else is **not something we could
establish** — Mosyle publishes no public API documentation at all.

Both endpoints are POST-only; a `GET` returns HTTP 405.

### A caveat about these instructions

**Mosyle publishes no public API documentation.** There is no `docs.mosyle.com`,
no developer portal, and no vendor-hosted API reference — the documentation is
distributed inside the product console and through Mosyle support. The console
navigation described below is drawn from third-party integrator guides and is
**not verified against vendor documentation**. Treat the menu names as a strong
hint rather than a specification, and if your console differs, ask Mosyle
support rather than assuming these steps are wrong in substance.

What *is* verified, because it was confirmed against the live API and matches
this integration's implementation, is the authentication flow and the endpoint
shapes described in the next section.

## Steps

### Mosyle Configuration

1. Gather your Mosyle API credentials:
   - Obtain your **API token** from the Mosyle admin portal. Third-party guides
     place this under a **Mosyle API Integration** area, with an
     **Add new token** action and an optional "Restricted by Server IP"
     setting. If you use the IP restriction, it must allow the Explorer's egress
     address.
   - Use a valid Mosyle admin email and password. The script performs the login
     and bearer retrieval for you. Administrators are managed under
     **My School > Administrators** according to third-party guides.
   - The admin account needs read access to device inventory. Third-party
     integrator documentation names view-level permissions covering end users,
     administrators, user groups, and device settings. We could not confirm a
     specific Mosyle permission string from vendor documentation, so grant the
     narrowest set your console offers that still returns devices, and verify
     with the calls below rather than assuming.

2. Test your credentials (optional but recommended):
   - Use a tool like Postman or curl to confirm login is working.
   - Example request (bearer is returned in the `Authorization` response header, **not** in the body; the script handles this automatically):
     ```bash
     curl -i -X POST "https://managerapi.mosyle.com/v2/login" \
     -H "Content-Type: application/json" \
     -d '{
       "accessToken": "<API_TOKEN>",
       "email": "<EMAIL>",
       "password": "<PASSWORD>"
     }'
     ```

     Use `curl -i` so you can see the response headers — that is where the token
     is. Mosyle moved from basic authentication to this JWT flow in early 2024,
     so older integration guides describing a single-step call are out of date.

3. Verify device access:
   - Use the bearer token returned above and include the access token in the request body (the script loops per-OS over `ios`, `mac`, `tvos`, `visionos`):
     ```bash
     curl -X POST "https://managerapi.mosyle.com/v2/listdevices" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "accessToken": "<API_TOKEN>",
       "options": {
         "os": "all",
         "page": 0
       }
     }'
     ```

### runZero Configuration

1. (OPTIONAL) - Modify the Starlark script to match your desired filtering, pagination, or attribute mapping.

2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - Use the `url` field only to override the default `https://managerapi.mosyle.com/v2`.
   - Use the `api_token` field for your API token.
   - Use the `email` and `password` fields for the admin login. Existing credentials can continue to use `legacy_credentials` as JSON/dict with keys `{"email": "<EMAIL>", "password": "<PASSWORD>"}` (or `username`). Pre-issued bearer tokens are not used by the script.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., `mosyle`).
   - Toggle `Enable custom integration script` to paste in the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.

4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 2 and 3.
   - Set the task schedule to run as needed.
   - Select the hosted Explorer to run the integration from.
   - Click `Save` to activate the task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm the three-part credential and see what Mosyle returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename mosyle/mosyle.star \
  --kwargs url=https://managerapi.mosyle.com/v2 \
  --kwargs api_token=7f3a91c4e0b84d26a5c8f1e7d09b3a42 \
  --kwargs email=mdm-admin@example.com \
  --kwargs password='Ch4nge-Me!2026' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./mosyle-run
```

`url` defaults to `https://managerapi.mosyle.com/v2`, so in practice only the
three credential values are needed.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

There are no page-size or cap parameters. The script walks four OS families —
`ios`, `mac`, `tvos`, `visionos` — paging through each in turn, so a run costs
one login plus at least four listing calls and more on a large fleet.

Two failure modes are worth telling apart, and `--verbose` is how you do it:

- **`accessToken Required` on the login call** means the token is not reaching
  the API in the form it expects — most often because `url` was pointed at the
  Business endpoint, which wants a header instead of a body field.
- **`Invalid accessToken`** means the request shape is right and the token value
  is wrong.

**`legacy_credentials` cannot be passed from the command line.** `--kwargs` takes
its value verbatim as long as the whole argument holds a single `=`, so a comma
on its own is harmless — `--kwargs 'password=a,b'` arrives as `a,b`. What breaks
is a value carrying **both** a second `=` and a comma: the flag then parses the
argument as a CSV record, so `--kwargs 'x=a=b,c=d'` yields `x=a=b` plus a
fabricated parameter `c="d"`. A JSON object is exactly that shape — it is full of
both — so `legacy_credentials` cannot survive the flag. Use the named `email` and
`password` parameters on the command line and keep the JSON form for existing
console credentials. A password carrying both characters can be passed by
wrapping the whole argument in a second pair of quotes:

```bash
  --kwargs '"password=Ch4nge=Me,2026"'
```

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename mosyle/mosyle.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Mosyle accepts the token or
the admin login, and it does not exercise the `Authorization` response-header
handshake — which, being unusual, is the part most worth testing for real.

The fixtures under `mosyle/tests/fixtures/` exercise the parsing offline,
including the paged case:

```bash
python3 tests/run.py mosyle
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat mosyle/mosyle.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'api_token=7f3a91c4e0b84d26a5c8f1e7d09b3a42,email=mdm-admin@example.com,password=<password>' \
  --output ./mosyle-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` is a different flag with a stricter rule: it
takes **one** comma-separated `key=value` string, so no value passed through it
may contain a comma at all. Neither `legacy_credentials` nor a comma-bearing
password can be expressed through it.

### What's Next?

- The task will appear on the [Tasks](https://console.runzero.com/tasks) page and run like any other integration.
- It will update existing assets or create new ones based on device merge criteria (hostname, MAC, etc.).
- You can filter assets imported via this integration using `custom_integration:mosyle`. The search term comes from the `CONFIG` id (`runzero-mosyle`) with the `runzero-` prefix removed, which is how every integration in this repository derives it. If that returns nothing, check the name you gave the integration in the console.
## Asset identity

- Target entity: an Apple device enrolled in Mosyle Manager MDM — iPhone, iPad, iPod, Mac, Apple TV, or Vision Pro. The script asks for each family separately (`ios`, `mac`, `tvos`, `visionos`), so the entity is always a physical Apple device rather than a user or a configuration record.
- Source ID field: `deviceudid`, falling back to `serial_number`. A record carrying neither is skipped with `continue`.
- Documentation evidence: **none from the vendor.** Mosyle publishes no public API reference at all, as recorded at the top of this document, so the field names come from the live API and the fixtures rather than from a contract. What *can* be leaned on is what the values are: `deviceudid` is Apple's device UDID, minted by Apple per device, and `serial_number` is the hardware serial engraved by Apple. Both are properties of Apple hardware that Mosyle reports rather than identifiers Mosyle invents, which is why they are strong despite the missing documentation.
- Uniqueness scope: globally unique in principle, because both candidate values are Apple-assigned hardware identifiers rather than tenant-local rows. The id is used verbatim with no vendor prefix and no tenant scope. That is unusually defensible here — a UDID means the same device whichever Mosyle tenant reports it — but it is worth knowing that the safety comes from the *value*, not from anything the script does.
- Cardinality: one record per enrolled device per OS family query. A device cannot appear in two families, so the four-pass loop cannot double-report one device.
- Stability: the UDID survives rename, OS upgrade, address change, wipe, and re-enrollment. It does not survive a logic-board replacement, which mints new Apple identifiers — the correct outcome, since that is new hardware.
- Reuse behavior: not applicable in practice. Apple does not recycle UDIDs or serials.
- Presence: not guaranteed. The fallback to `serial_number` exists because it is not, and the `continue` after it exists because sometimes neither arrives. **Note the consequence of the fallback order:** a device that reports a UDID on one run and only a serial on the next changes foreign id and mints a second asset. That has not been observed, but nothing in the code prevents it.
- Final runZero ID: the raw `deviceudid` (or `serial_number`), unprefixed.
- Missing-ID behavior: skip the record silently. There is no log line naming the skipped device, which makes a partial import hard to notice — every other integration in this library prints one.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative, on the strength of the identifier rather than of the vendor's documentation.

### Why the default `matchBehavior` is right here, and where it is worth watching

The governing rule points at the foreign id, and the code follows it: a UDID is exactly the persistent remote identifier the rule is written for, so `id-match` stays on and the id drives merges. The usual companion preset for a source like this is `no-mac-break no-ip-break no-name-break`, and it is deliberately not needed — once a UDID has matched, no MAC, address, or hostname disagreement can fragment the asset, because those checks exist only on the MAC, IP, and hostname match paths. The break flags govern **first contact** only, before any UDID has ever matched, which is precisely where this source's network data should be allowed to find the asset runZero already scanned.

One field deserves scrutiny before anyone relaxes those flags, and it is **`last_ip_beat`**. The script pairs it with the Wi-Fi MAC and `last_lan_ip` with the Ethernet MAC. `last_lan_ip` is named unambiguously; `last_ip_beat` is not, and Mosyle documents neither. If it turns out to be the address Mosyle *saw the check-in arrive from* rather than an address on the device, it is the tenant's egress NAT address — identical for every device in an office — and importing it would attach the whole fleet to whatever asset holds that address. The fixtures in this repository use RFC 1918 values, but those fixtures were written here and are not evidence about the vendor. **This is the one unverified assumption in this integration's identity story**; confirm it against a live tenant before treating the Wi-Fi interface as trustworthy, and note that `ip-break` being on is currently the thing that limits the blast radius if the assumption is wrong.

## Future

Mosyle publishes no API reference, so this section is bounded by what the two endpoints this integration uses reveal and by what the product is documented to do. Where an endpoint would be needed and cannot be confirmed to exist, that is stated rather than guessed.

- **Application inventory as runZero software records.** This is the largest gap and the most likely to exist. Mosyle Manager tracks installed and managed applications per device — it is an MDM, and app management is its core function — but this integration reads only `POST /v2/listdevices` and emits no `Software` at all. Whether the app list arrives as a field on the device record under a different `options` selector, or from a separate endpoint, could not be established without a live tenant. That is the first thing to check: re-run `listdevices` and diff the returned keys against the `used_keys` set in the script, which currently routes everything unrecognized into custom attributes.
- **Device compliance and posture as findings.** Mosyle evaluates encryption (FileVault), passcode policy, OS patch level, and supervision state, and an MDM's compliance verdict is the natural source of a runZero `Vulnerability`-style finding for a managed fleet. The device record already surfaces some of this into custom attributes today by virtue of the catch-all attribute mapping; promoting the relevant keys to findings is a mapping change rather than a new API call, once the key names are confirmed against a real tenant.
- **Outbound: runZero data as Mosyle device tags or groups.** Mosyle supports device tags — the integration reads `tags` and `asset_tag` off every device today — and a write path would let runZero push its own classification (unmanaged neighbours, site, criticality, exposure) onto the MDM record so Mosyle profiles could be scoped by it. **No write endpoint is confirmed.** The two calls this integration makes are `POST /v2/login` and `POST /v2/listdevices`, both reads, and nothing observed suggests the shape of a mutation. Treat this as a question for Mosyle support rather than as a design.
- **MDM coverage-gap reporting, in both directions.** This needs no new endpoint and is the highest-value item that can be built today. runZero fingerprints Apple hardware it discovers on the network whether or not it is enrolled, and Mosyle knows only what enrolled. Assets that runZero classifies as Apple hardware and that carry no `custom_integration:mosyle` source are unenrolled devices on the network — the report an Apple fleet owner actually wants. The reverse direction is also useful: enrolled devices whose `last_ip_beat`/`last_lan_ip` never appear in a runZero scan are either off-network or in a segment with no Explorer coverage.
- **Alert and event ingestion has no path.** Nothing observed exposes a webhook, an event stream, or a change feed, and the device listing carries no per-device change timestamp that could drive an incremental poll. Any near-real-time behavior would be re-listing all four OS families on a short schedule, which is what the task already does — and at four-plus requests per run plus a login, that is the cost to weigh.
- **Mosyle Business would be a second integration, not a parameter.** As recorded above, Business uses a different base URL, a different token placement (header rather than body), and a different API version. Supporting it is not a matter of widening the `url` default; it is a second script, and whether Mosyle Fuse exposes one API, the other, or something else again could not be established.

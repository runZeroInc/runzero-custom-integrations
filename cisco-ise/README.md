# Custom Integration: Cisco ISE

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cisco ISE requirements

- An ISE deployment with a **Monitoring (MnT) persona** node the Explorer can reach. In a small deployment this is usually the Primary Administration Node; in a distributed deployment it is a specific node, and calls to a Policy Service node will not work.
- An ISE **internal** admin account in one of three admin groups (see below).
- The account's `username:password` **Base64-encoded**, which is what the credential field takes.

### Which admin group

Cisco is explicit about this: "to perform operations using the Monitoring REST
APIs, the users must be assigned to one of the following Admin Groups: **Super
Admin, System Admin, MnT Admin**." Of those, **MnT Admin** is the least-privilege
choice and the one to use.

Two consequences worth knowing before you start:

- **The ERS roles are the wrong ones.** "External RESTful Services Admin" and "External RESTful Services Operator" govern the ERS API family, which is a different API on a different port. Granting ERS Operator does not grant access to the MnT session data this integration reads.
- **You do not need to enable ERS.** ISE's API families — ERS (ports 443/9060), Open API (9070), and Monitoring/MnT (9443) — are separate, with separate enablement and separate roles. The documented prerequisites for the Monitoring REST API are only a valid Monitoring node and one of the three admin groups above. The **Administration > System > Settings > API Settings** toggles apply to ERS and Open API, not to this.

**The account must be an ISE internal user.** Cisco states that "Monitoring REST
APIs are only supported for internal users. Communication with the external ID
stores is not supported", so an Active Directory or LDAP-backed admin will not
authenticate against this API.

## Steps

### Cisco ISE configuration

1. **Create the admin account**:
   - In the ISE administration console, create an internal admin user and assign it to the **MnT Admin** admin group.
2. **Verify API access**:
   - Test against the Monitoring node. Paths on this API are **case-sensitive**:
     ```bash
     curl -sk -u 'runzero-mnt:<password>' \
       -H 'Accept: application/xml' \
       'https://ise.example.com/admin/API/mnt/Session/ActiveList'
     ```
   - A successful response is XML containing `<activeSession>` elements. An empty session list is a valid response and means nobody is currently authenticated — not that the credential is wrong.
3. **Base64 encode credentials**:
   - Encode `username:password` using Base64. Use `printf`, not `echo` — `echo` appends a newline that becomes part of the encoded credential and produces a value ISE rejects:
     ```bash
     printf 'username:password' | base64
     ```

### runZero configuration

1. (OPTIONAL) Modify the script if needed:
   - You may adjust parsing logic to capture additional session fields from the XML.
   - There is nothing to edit to set the host. The ISE URL is the `url` credential parameter, not a constant in the script.

2. **Create a Credential for the Custom Integration**:
   - Go to [runZero Credentials](https://console.runzero.com/credentials).
   - Select `Custom Integration Script Secrets`.
   - **Cisco ISE URL** (`url`): the base URL of the Monitoring node, e.g. `https://ise.example.com`. Give a scheme and host only; the script appends `/admin/API/mnt/Session/ActiveList` itself.
   - **Base64 basic-auth credential** (`basic_auth_credential`): the Base64 string produced above.
   - **TLS options** (`tls_*`): set these if the node presents a certificate the Explorer does not trust.

3. **Create the Custom Integration**:
   - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
   - Add a name (e.g., `cisco-ise`) and icon for the integration.
   - Toggle **Enable custom integration script** and paste in the script.
   - Click `Validate`, then `Save`.

4. **Schedule the Integration Task**:
   - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
   - Select the credential and custom integration you created.
   - Set a schedule for recurring updates.
   - Choose the Explorer instance to run the integration.
   - Click `Save`.

### What's next?

- The integration will retrieve active sessions from Cisco ISE.
- Device IP and MAC addresses will be mapped to runZero assets.
- You can find enriched assets using the runZero search query `custom_integration:cisco-ise`.

### Running it from the command line

The runZero CLI runs a script directly, which is the fastest way to confirm a
credential and see what a real deployment returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename cisco-ise/cisco-ise.star \
  --kwargs url=https://ise.example.com \
  --kwargs basic_auth_credential=cnVuemVyby1tbnQ6aHVudGVyMi1ub3QtYS1yZWFsLXBhc3N3b3Jk \
  --kwargs tls_disable_validation=true \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/cisco-ise-run --overwrite
```

`--output` writes the serialized assets to a directory (as `scan.runzero.gz`) so
you can inspect exactly what would be imported; without it the assets are parsed
and discarded. It requires `--custom-integration-id`, and for a local run any
well-formed UUID is accepted — the value is only stamped into the export. The
scanner refuses an existing output directory unless `--overwrite` is passed.

Notes specific to this integration:

- **`url` is a base URL only.** It is read with `get_url_base()`, so any path you
  put on it is discarded and the script appends
  `/admin/API/mnt/Session/ActiveList` itself. Pass `https://ise.example.com`, not
  the full API path.
- **`basic_auth_credential` is already-encoded Base64**, not a username and
  password. Generate it with `printf 'user:pass' | base64` — using `echo` without
  `-n` appends a newline and produces a credential the node rejects. The script
  places the value straight into `Authorization: Basic <value>`.
- **Base64 padding and `--kwargs` interact.** The `--kwargs` flag parses an
  argument containing a **second** `=` as a CSV record, and a padded Base64 value
  (one ending in `=` or `==`) is exactly that shape. It still comes through
  intact here, because the Base64 alphabet contains no commas and it is the
  comma that does the damage — a value carrying **both** an `=` and a comma is
  split into a fabricated extra parameter. A comma on its own is harmless:
  `--kwargs 'basic_auth_credential=a,b'` arrives as `a,b`. If you ever need to pass a value with
  both, wrap the whole argument in double quotes so it is one CSV field —
  `--kwargs '"basic_auth_credential=a=b,c=d"'` — and double any quote inside it.
- **`tls_disable_validation` appears above because ISE deployments commonly
  present an internally-issued or self-signed certificate.** That this is ISE's
  default could not be confirmed from Cisco documentation, so treat it as a
  practical starting point rather than an assumption: drop the flag if your node
  presents a certificate the Explorer already trusts.
- **Point it at a Monitoring node.** A run against a Policy Service node fails
  even with a correct credential, and paths on this API are case-sensitive.

There are no paging or limit parameters to cap a first run: the script issues one
request for the active session list and parses whatever comes back. On a busy
deployment that is every current session, so expect the first local run to be
large.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real node:

```bash
runzero script --filename cisco-ise/cisco-ise.star --validate
```

`--validate` points the script at a local dummy server. It proves the parameter
block and the HTTP and TLS plumbing are wired up; it never parses a real
`<activeSession>` element, so it confirms nothing about the credential or the
session XML.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://ise.example.com,basic_auth_credential=...'
```

That flag takes one comma-separated `key=value` string, so no value passed
through it may contain a comma.

The recorded fixtures run without an ISE deployment:

```bash
python3 tests/run.py cisco-ise
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

- Target entity: an **active RADIUS session**, not an endpoint. `GET /admin/API/mnt/Session/ActiveList` returns the sessions authenticated on the deployment at the moment of the call, so what this integration imports is "who is on the network right now", and an endpoint that is powered off or unplugged is simply absent.
- Source ID field: `audit_session_id`, parsed out of the `<activeSession>` XML.
- Documentation evidence: `audit_session_id` is the value ISE itself uses to name a session across its own interfaces — it is the key a Change of Authorization is addressed by and the field session-correlation consumers join on. It identifies a *session*, and Cisco does not describe it as identifying an endpoint.
- Uniqueness scope: the ISE deployment. The value is an opaque string minted by the Policy Service node that authenticated the session; its internal structure is not documented in a form that can be cited here, so nothing beyond deployment-scoped uniqueness is claimed.
- Cardinality: **many sessions per endpoint, and this is the normal case rather than an edge case.** One laptop connected over both wired and wireless holds two concurrent sessions with two different `audit_session_id` values; the same laptop reconnecting tomorrow holds a third. All of them carry the same `calling_station_id`, which is the MAC, and that is what collapses them onto one runZero asset.
- Stability: **none, by design.** A new `audit_session_id` is issued at every authentication — on reconnect, on reauthentication, on session timeout, and on a roam between switch ports or access points. It is ephemeral scan-derived data in the precise sense the governing rule describes.
- Reuse behavior: not documented, and largely irrelevant given the value never persists long enough to be re-observed.
- Presence: expected on every session element. **The script does not check** — unlike the other integrations in this repository it has no missing-id skip path, so a session element that carried no `audit_session_id` would reach `ImportAsset` with `id=None` rather than being skipped and logged. That is a robustness gap rather than an identity decision, and it is recorded here rather than changed.
- Final runZero ID: the raw `audit_session_id`.
- Missing-ID behavior: none. Sessions *are* skipped for a different reason — when neither `calling_station_id` nor an IP address parses into a usable network interface, which is what an RA-VPN session looks like from here. The count is logged as `cisco-ise: skipped N session(s) with no usable MAC or IP address`.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`** — declared once at the top level of `CONFIG`, not per record.
- Verdict: **not authoritative, and correctly declared as such.** This is the clearest example in this repository of the governing rule applied properly: the source has no stable per-device identifier, so the foreign id is excluded from matching entirely and correlation is left to the MAC and IP address that the session record does carry reliably.

Why the relaxed setting is not merely conservative but necessary: had the default been left in place, every reauthentication would present a *new* foreign id for a device runZero already knows. That never merges onto the existing asset — runZero refuses any merge placing two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior` — so a busy deployment would fork a new asset per session and accumulate them indefinitely. `no-id-match` is what prevents that.

The one thing correlation here depends on is the MAC being real. `calling_station_id` is the endpoint MAC for 802.1X and MAB, but for remote-access VPN it is the client's public IP address rendered as a string; those records fail to produce a usable interface and are skipped rather than imported with a fabricated identity. Note also that MAC randomization on modern client operating systems means one physical laptop can present several MACs over time — ISE cannot see through that either, and the result is separate runZero assets, which is the honest outcome rather than a merge based on a guess.

### Notes

- The integration extracts fields like `device_ip_address`, `calling_station_id` (MAC), and `user_name` (the RADIUS identity).
- `user_name` is **not** a hostname. For 802.1X user authentication it is the person who signed in, and for MAB it is the endpoint's MAC rendered as a string. It is imported as a custom attribute, and contributes a hostname only in the machine-authentication case, where it takes the form `host/<machine name>`. Importing it as a hostname outright would merge every endpoint a given user authenticated on into a single asset.
- Assets are ISE **sessions**, which are inherently temporary, so `matchBehavior` is `no-id-match no-id-break`: the `audit_session_id` changes with every new session and must not drive correlation. Merging happens on MAC and IP instead.
- If `device_ip_address` is missing, it falls back to `framed_ip_address`.
- All ISE session IDs and NAS information are stored as `customAttributes`.
- You can customize the `build_assets()` function to include more session fields if needed.
- The XML is parsed by splitting on `<activeSession>` and then on the individual tags rather than with an XML parser. That is tolerant of the fields it does not know about, but it is also why only the eight tags listed in `extract_sessions` are available — adding a field means adding it to that list.

## Future

- **Import the endpoint database instead of, or alongside, the session list — this is the big one.** The ERS API's `GET /ers/config/endpoint` returns ISE's persistent endpoint records: a stable UUID `id` per endpoint, the MAC, the profiler's assigned `profileId`, `groupId`, and static-assignment flags. That is a genuine inventory with a genuine identity, and it would let this integration match on the foreign id instead of relying entirely on MAC correlation. It answers a different question from the session list — "every endpoint ISE has ever profiled" rather than "who is connected right now" — and the two together are strictly better than either alone. ISE 3.x additionally exposes `GET /api/v1/endpoint` through the Open API family on port 9070. Note that both are separate APIs with separate enablement and separate roles from the MnT API this integration uses today, so this is a credential change as well as a code change: the ERS roles this README currently tells you *not* to grant are exactly the ones such an addition would require.
- **Network access devices are assets too.** `GET /ers/config/networkdevice` returns the switches, wireless LAN controllers, and firewalls configured as RADIUS clients, with their IP addresses and model information. Those are infrastructure assets runZero cares about, and today the integration only sees them indirectly as the `nas_ip_address` custom attribute on a session.
- **Authentication history rather than a live snapshot.** The MnT family also publishes session history and failure detail (`/admin/API/mnt/Session/AuthList/...`, `/admin/API/mnt/FailureReasons`), and per-endpoint lookups by MAC and by IP address. A history-based import would find endpoints that authenticate intermittently — exactly the ones a single `ActiveList` snapshot misses — and failure data would surface devices repeatedly rejected by policy, which is often how an unmanaged device announces itself.
- **Outbound: push runZero's classification into ISE so authorization policy can use it.** ISE supports custom endpoint attributes on endpoint records, settable through `PUT /ers/config/endpoint/{id}`. runZero routinely fingerprints IoT, OT, and medical devices more precisely than the ISE profiler does, and pushing that classification back would let an ISE authorization rule act on it directly — "if runZero says this is a building-management controller, put it in the BMS VLAN". This is the single most valuable outbound direction available for this integration, because it turns runZero's fingerprinting into enforcement rather than into a report.
- **Outbound: quarantine through ANC.** `POST /ers/config/ancendpoint/apply` applies an Adaptive Network Control policy (defined at `/ers/config/ancpolicy`) to a MAC address, and the MnT family exposes Change of Authorization directly — a reauthentication or a session disconnect addressed by the `audit_session_id` this integration already imports. A runZero finding could therefore bounce or quarantine a device on the spot. It is also a way to disconnect a fleet by accident, so it needs explicit per-device confirmation, a dry-run mode, and an audit trail before it goes anywhere near a scheduled task.
- **NAC coverage-gap reporting, in both directions.** Devices ISE has authenticated that runZero has never scanned are scan-coverage gaps — often on segments no Explorer is positioned to reach. Devices runZero discovers that ISE has no session or endpoint record for are the more interesting half: they are on the network without going through network access control, which usually means an unmanaged switch, a MAB exception, or a port that was never configured for 802.1X. The session data already imported here supplies one side of that diff.
- **What the session API cannot give you.** There is no software inventory, no CVE data, no open-port information, and no hardware detail on a session record — ISE reports who authenticated, from where, and under which policy. `Software`, `Service`, and `Vulnerability` records are therefore out of reach from this endpoint regardless of how much more of the API is consumed; the endpoint database above adds profiling and posture, not a package list.

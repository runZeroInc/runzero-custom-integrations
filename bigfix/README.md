# Custom Integration: HCL BigFix

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the BES root server on its REST API port (52311 by default).

## HCL BigFix requirements

- A BigFix console operator account. A Master Operator sees the whole deployment; a Non-Master Operator only sees the computers assigned to it, and the import is scoped accordingly.
- The REST API enabled on the BES root server. It listens on the same port as the console gather service, 52311 by default.
- BES root servers ship with a self-signed certificate. Enable `disable_validation` in the integration's TLS options if the certificate is not trusted by the Explorer, or install a trusted certificate on the root server.

## Steps

### HCL BigFix configuration

1. Confirm the REST API answers by opening `https://<bes-root-server>:52311/api/help` in a browser and signing in with the console account.
2. Note which retrieved properties the deployment publishes. The default list this integration requests covers the stock BigFix properties plus the hardware properties most deployments add through an analysis (`MAC Addresses`, `Serial Number`, `Computer Manufacturer`, `Computer Model`). A property that does not exist is simply skipped, so an inaccurate list costs nothing but the data it would have carried.
3. Optionally activate an analysis that reports installed applications as a multi-value property, and note its exact name for the **Installed software property** field.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "HCL BigFix").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **BigFix root server URL** (`url`): base URL of the BES root server REST API, including the port, for example `https://bes.example.com:52311`.
   - **Console username** (`username`): BigFix console operator with read access to the computers to import.
   - **Console password** (`password`): password for that operator.
   - **Retrieved properties** (`properties`): optional; comma-separated BigFix property names to read for every computer.
   - **Installed software property** (`software_property`): optional; name of a multi-value property that reports installed applications. Blank disables software import.
   - **Computers per query** (`page_size`): optional; how many computers each session relevance query covers (default: 500).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename bigfix/bigfix.star \
  --kwargs url=https://bes.example.com:52311 \
  --kwargs username=runzero \
  --kwargs password=Passw0rd-not-real \
  --kwargs 'properties=MAC Addresses,Serial Number,Computer Model' \
  --kwargs page_size=50 \
  --kwargs tls_disable_validation=true \
  --output ./bigfix-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.
`tls_disable_validation=true` is usually needed against a stock root server, which ships a
self-signed certificate.

**A note on commas in `properties`.** `--kwargs` is a `stringToString` flag whose parsing
changes depending on how many `=` signs the whole argument contains. With exactly one — the
normal case — the value is taken verbatim, so a comma-separated property list is passed
through intact and `properties=MAC Addresses,Serial Number` works as written. If the
argument contains a *second* `=` (a password with an equals sign, for instance) the value
is CSV-parsed instead, and then commas do split it into extra parameters and a bare double
quote is a hard parse error. Quote the whole argument in the shell, and avoid `=` in
values you pass alongside commas.

To check the `CONFIG` block and the HTTP and TLS wiring without a live root server:

```bash
runzero script --filename bigfix/bigfix.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove BigFix accepts the operator credentials or that any computer is
parsed — against the dummy server the script correctly reports `the response was not a
BESAPI document` and stops.

The recorded BESAPI shapes, including the relevance fallback, are exercised by the fixture
suite:

```bash
python3 tests/run.py bigfix
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat bigfix/bigfix.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://bes.example.com:52311,username=runzero,password=<password>' \
  --output ./bigfix-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so the
comma-separated `properties` list genuinely cannot be passed through it — configure that
field on the console credential, or use `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with endpoint inventory pulled from HCL BigFix.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:bigfix`.

## Asset identity

- Target entity: a physical or virtual computer running the BigFix agent (BESClient), as the root server records it.
- Source ID field: `id of <bes computer>`, returned as the first member of every tuple this integration queries. The same value is the `ID` property on `/api/computer/{id}`.
- Documentation evidence: the `<bes computer>` relevance reference defines `id` as "Returns the numeric ID unique to the specified BES computer" (<https://developer.bigfix.com/relevance/reference/bes-computer.html>). The agent stores its assigned id locally — `HKLM\SOFTWARE\Wow6432Node\BigFix\EnterpriseClient\GlobalOptions` on Windows, `/var/opt/BESClient/besclient.config` on Linux, `/Library/Preferences/com.bigfix.BESAgent.plist` on macOS — and replays it on every registration, which is what makes it survive reboots, renames, and address changes.
- Uniqueness scope: one BigFix deployment (one BES root server and its database). Two separate deployments hand out ids from the same small integer space and will collide, so the id is not globally unique.
- Cardinality: one computer per id. The queries this integration runs return exactly one row per computer; multi-value property results are folded into a single answer inside the relevance rather than being allowed to multiply rows.
- Stability: preserved across rename, IP and MAC change, reboot, relay change, and agent upgrade, because the agent replays the id it has stored. **Replaced** when the agent is reinstalled, when the machine is reimaged, or when a VM is reverted to a snapshot taken before registration: HCL documents that the client "receives a new Data Source Computer ID" in those cases and the console then shows a duplicate entry. Preserving the identity across a reimage requires restoring the stored ComputerID and KeyStorage, or setting the server's `ClientIdentityMatch` parameter (default `0`). This behavior was confirmed from HCL's own documentation, not from a live deployment.
- Reuse behavior: not documented publicly, and **not verified**. Treat a deleted computer's id as potentially reusable and rely on the merge behavior below rather than on non-reuse.
- Presence: always present. It is a native inspector on `<bes computer>` rather than a retrieved property, so it does not depend on the agent having reported an analysis.
- Final runZero ID: `bigfix:<root-server-hostname>:<computer-id>` — the hostname is taken from the configured URL and lower-cased, which supplies the deployment scope the raw id lacks.
- Missing-ID behavior: skip. A row whose id answer is empty, or whose tuple width does not match the query, is logged and dropped; no identifier is invented.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The computer id is authoritative inside a deployment, while the console name, the reported address, and the MAC list all change independently of it — a laptop that changes docks reports a different MAC on the next check-in.
- Verdict: scoped authoritative. Authoritative within one BES deployment; namespaced by the root server host to make it safe across deployments.

### Notes

- Assets come from `GET /api/query`, the session relevance endpoint, and nothing else. No other REST resource is read.
- The alternative shape, `GET /api/computers` followed by `GET /api/computer/{id}` for each result, is a request per computer. This integration uses session relevance instead so that one request covers up to `page_size` computers with all of their properties.
- Two relevance expressions are used. The first is a census, `(id of it as string) of bes computers`, which is the cheapest query the root server can answer. The ids it returns are sorted and cut into ranges of `page_size` computers, and each range is then fetched with a tuple query constrained by `whose (id of it >= <low> and id of it <= <high>)`. Session relevance has no offset or cursor, so an id range is the pagination mechanism; cutting the ranges from the census rather than from a fixed stride keeps every range full regardless of how sparse the id space is. Each range is streamed with `report_asset` before the next is fetched, so the whole deployment is never held in memory.
- Core fields come from native `<bes computer>` inspectors (`id`, `name`, `hostname`, `operating system`, `ip address`, `last report time`), each wrapped in `if (exists ...) then ... else ""`. This guard is not cosmetic: a tuple member that evaluates to nothing removes that computer's entire row from the result, so an unguarded member would silently drop every computer that has not reported that one property.
- Retrieved properties are read with `concatenation "~|~" of (values of results (it, bes property "<name>") ; "")`. The trailing empty string keeps the member singular even when the property does not exist in the deployment, for the same reason. The joined values are split back apart in the script.
- **These queries get one attempt each.** The endpoint answers XML, so the script uses the raw `http.get` builtin, and `retries` is a parameter of `get_json`/`post_json` only — a raw request has no retry budget and cannot opt in. Nothing here hand-rolls a retry loop. Instead the failure is contained: a range that fails is logged and the remaining ranges are still fetched, and if a range fails while properties are configured the same range is retried once with the core-only relevance. If that succeeds, the property list is dropped for the rest of the run and every computer is still imported with its core fields. Only a failure of the initial census ends the run, because there is nothing to page over without it.
- `/api/query` also accepts `output=json` on newer BES releases, which would restore the retry budget by making `get_json` usable. XML is used instead because it is the response format every BigFix release supports; `output=xml` is requested explicitly.
- The relevance is encoded once with `url_encode` and appended to the URL, with `+` rewritten to `%20`. Relevance expressions are full of spaces, parentheses, quotes and comparison operators, and this was verified on the wire against a local fixture: the request reaches the server as `relevance=%28id%20of%20it%20as%20string%2C%20...%20%3E%3D%20101%20...%29` with no raw `+` anywhere.
- **Network interfaces**: BigFix reports MAC addresses as a flat list with no adapter pairing, and the native `ip address` inspector reports a single address. The addresses are therefore attached to the first interface and each remaining MAC becomes an interface of its own rather than being dropped. This is a faithful record of what BigFix knows, not a real adapter map. Loopback, unspecified, and link-local addresses are filtered before any interface is built — an agent that cannot see a usable adapter reports `127.0.0.1`, and importing that would merge every such host onto one asset — while the raw reported values are kept as `bigfix_ip_address` and `bigfix_mac_addresses`.
- **OS mapping**: BigFix reports the OS as a platform code and a build, for example `Win2016 10.0.14393.6796`. A trailing dotted build number becomes `osVersion` and the remainder becomes `os`, with the `WinNNNN` codes expanded to their product names. Strings that end in something else, such as `Linux Red Hat Enterprise Linux Server release 7.9 (Maipo)`, are imported whole with no version, because pulling `7.9` out of the middle would leave a nonsense OS name behind. The untouched string is always kept as `bigfix_os`.
- **Property mapping**: a retrieved property is matched to a runZero field by what its lower-cased name contains — `mac address`, `ip address`, `serial number`, `manufacturer`, `model`, `device type`/`computer type` — because deployments name these analysis properties themselves. Every requested property is also kept verbatim as a `bigfix_`-prefixed custom attribute, and the serial number additionally becomes a `serial:` tag.
- **Software** is off by default and opt-in through **Installed software property**, because the core BES database only holds installed applications if an analysis retrieves them and the property name varies per deployment. When enabled, the property is added to the same per-range query rather than costing a second round trip, but it makes each query substantially more expensive for the root server to evaluate. Each value becomes one `Software` record; a trailing dotted version, in parentheses or not, is split into `version`. `cpe23` is left unset because BigFix publishes no CPE and `Software.cpe23` only accepts the CPE 2.2 application URI binding. Software is capped at 99 records per asset.
- **No vulnerabilities are imported.** BigFix patch and compliance state is *patch* state — a fixlet is relevant on a computer or it is not — and a relevant fixlet is not a CVE. Fixlets carry no reliable CVE field, so nothing here is presented as a `Vulnerability`. See Future for what a defensible patch import would need.
- No ports or services are imported. BigFix is an agent-based management source and observes no listening sockets.
- Rate limiting: the BigFix REST API publishes no rate limit and returns no `Retry-After`. The cost control that matters is the root server's relevance evaluation time, which is what `page_size` bounds; lower it if the root server times out on large deployments.
- Unverified assumptions, stated plainly: the relevance constructs used here were assembled from HCL's inspector reference and from published session relevance examples, and were exercised end to end against a local fixture that mimics the documented BESAPI response, **not against a live BES root server**. In particular, the exact behavior of `concatenation` over a `bes property` that does not exist in the deployment was not observed live; if it turns out to yield nothing rather than an empty string, the effect is that the property query for a range errors and the script falls back to the core-only relevance, which is a tested path. Computer id reuse after deletion was not verified either way.
- This integration was validated against local fixtures, not a live HCL BigFix deployment.

## Future

- **Fixlet and action deployment as an outbound integration.** `POST /api/actions` takes a `SourcedFixletAction` document naming a site, a fixlet id, an action id, and a target computer list, and `/api/action/{id}/status` and `/api/action/{id}/stop` manage it afterwards. This would let a runZero query drive remediation directly. **It should be flagged as highly disruptive and must not be built as a scheduled sync**: a BigFix action runs an action script on the endpoints it targets, which installs software, edits the registry, and reboots machines. Any such integration belongs behind an explicit, per-action human approval, never behind a recurring task.
- **Relevance as a general on-demand enrichment API.** `/api/query` will evaluate any session relevance expression, which means anything the BigFix agent can compute about an endpoint — a registry value, a file version, a service state, a certificate, a specific package — is reachable with a single request and no new agent-side content. That is a much better fit for answering a targeted question about a small set of assets than for a scheduled full-inventory sync, and it is the natural shape for a runZero enrichment or lookup action.
- **Patch compliance as a runZero signal.** `/api/fixlets/{site}` and `/api/fixlet/{site}/{id}` expose fixlet metadata including `SourceSeverity`, `SourceReleaseDate`, and `SourceID`, and session relevance can report which fixlets are relevant on which computers. Imported as an attribute or tag — "N critical patches outstanding", "oldest outstanding patch released on D" — this is genuinely useful. Imported as `Vulnerability` objects it would be wrong unless the fixlet's own text yields a real CVE id; where a CVE can be extracted and upper-cased to match `^CVE-[0-9]{4}-[0-9]{4,19}$`, those findings could be mapped with `category="patch"` and a description that says exactly what they are, and everything else left as patch state.
- **Endpoint-management coverage gaps.** This is the highest-value pairing. runZero discovers what is on the network; BigFix knows what has an agent. Assets that runZero sees but BigFix has never reported are unmanaged endpoints, and assets BigFix last heard from months ago are stale agents. Both fall out of the imported `bigfix_last_report_time` and the presence or absence of the `bigfix` tag, and neither needs any additional API surface.
- **Site and operator scoping.** `/api/sites` and `/api/site/{type}/{name}` enumerate the master, external, operator, and custom sites, and `bes computers` can be filtered by site subscription in relevance. A future revision could import a per-site subset, or tag assets with their subscribed sites, for deployments where one root server serves several business units.

## API documentation

- BigFix REST API tutorial, base URL and port 52311, HTTP Basic authentication, and a worked `/api/query` request with its tuple XML response: <https://developer.bigfix.com/rest-api/gettingstarted.html>
- `/api/query` request parameters (`relevance`, `output`), the BESAPI response schema, and the `Error` and `Evaluation` elements: <https://developer.bigfix.com/rest-api/api/query.html>
- `<bes computer>` inspector reference — `id`, `name`, `hostname`, `operating system`, `ip address`, `last report time`, `property result`: <https://developer.bigfix.com/relevance/reference/bes-computer.html>
- `<bes property>` inspector reference — `bes property "<name>"`, `name`, `results`: <https://developer.bigfix.com/relevance/reference/bes-property.html>
- `<bes property result>` inspector reference — `computer`, `property`, `value`, `plural flag`, `error flag`: <https://developer.bigfix.com/relevance/reference/bes-property-result.html>
- Session relevance guide: <https://developer.bigfix.com/relevance/guide/session/>
- Efficient session relevance for computer properties, the source of the `values of results (it, bes property "...")` and `concatenation ";" of ...` forms used here: <https://forum.bigfix.com/t/efficient-session-relevance-query-for-computer-properties/32820>
- Avoiding duplicate computers when a client is reinstalled or restored, and the `ClientIdentityMatch` parameter — the evidence for computer id stability across a reimage: <https://help.hcl-software.com/bigfix/11.0/platform/Platform/Installation/t_preserving_bundling_when_clientreinstalled.html>
- `besapi`, the community Python client, for the `/api/query` request shape and the `Query/Result/Answer` parsing pattern: <https://github.com/jgstew/besapi>

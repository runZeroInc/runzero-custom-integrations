# Custom Integration: Stairwell

Imports assets from a Stairwell environment. Stairwell is a file-analysis and
threat-detection platform; the assets it knows about are the hosts its forwarders
report from, so what this contributes to runZero is coverage — which machines are
running a Stairwell forwarder, and which are not.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to `https://app.stairwell.com` (or your own
  Stairwell API host) over HTTPS.

## Stairwell requirements

- An **API token**, sent as `Authorization: Bearer <token>`.
- An **Environment ID** — the environment whose assets you want imported.
- The Stairwell API URL, which defaults to `https://app.stairwell.com`. The
  script appends `/v1/environments/<environment_id>/assets` itself, so supply the
  base URL only.

Note that this integration authenticates with a **single bearer token**, not a
client ID and secret. Earlier revisions of this README described an "API client
ID and secret"; there is no OAuth exchange here and no `client_id` parameter.
The two values you need are `environment_id` and `api_token`.

### Creating the credential in Stairwell

**Least privilege here depends entirely on *who* generates the token.** Stairwell
documents that API/CLI tokens *"inherit the permissions of the user who
generated them"*, and separately that tokens are managed by Admin users. Follow
both statements literally and an Admin ends up minting an Admin-privileged
token for a read-only integration. The correct sequence is two people, or one
person wearing two hats:

1. **An Admin creates a read-only user.** Click the **Settings** icon in the left
   menu, open the **Users** tab, and use the pencil icon to set the role. The
   four roles are **Admin**, **User**, **Read Only**, and **Disabled**; Stairwell
   describes Read Only as *"View-only access. All permissions are downgraded to
   read only."* Only Org Admins can change user roles.
2. **That read-only user signs in and generates their own token.** Go to
   <https://app.stairwell.com>, click the **Settings** icon, select the **Auth
   tokens** tab under the **Organization** section, and click **Generate Token**.
   Choose **API/CLI token** from the type dropdown — *not* File Forwarder token,
   which authenticates forwarder deployments rather than API calls. Give it a
   descriptive name and click **Generate**. Copy the value immediately; it is not
   displayed again.

Stairwell states that **tokens do not expire automatically**, so there is no
rotation deadline to plan around — but equally nothing retires a forgotten
token. Revoking one is permanent and cannot be undone.

If you run Stairwell as an MSSP, note that a token created at the parent level
reaches all child environments and shared environments; scope the token at the
level you actually want imported.

### Finding the Environment ID

Click the **Settings** icon, select the **Managed environments** tab under the
**Organization** section, and read the value in the **Identifier** column.
Stairwell's own quickstart describes a slightly different path (an
**Environments** tab, with the ID on the environment detail page); the Managed
environments wording is the more specific of the two and matches the older
documented path.

The identifier is four hyphen-separated uppercase alphanumeric groups of 6, 6, 6
and 8 characters — Stairwell's API reference uses `VXKCDN-GSPRN8-M4QW7Z-2TPLJHK9`
as its example. It is a path segment, not a query parameter or a header, so a
token that is valid but scoped to a different environment produces an
authorization error on that path rather than an empty list, which is the useful
way round.

### Confirming both values

```bash
curl -s -H 'Authorization: Bearer ExampleFakeStairwellToken0123456789abcdef' \
  'https://app.stairwell.com/v1/environments/VXKCDN-GSPRN8-M4QW7Z-2TPLJHK9/assets?limit=1'
```

A success returns a JSON object with an `assets` array and, when there is more
to fetch, a `nextPageToken`. If you get back a JSON *array* rather than an
object, or an error document, the script stops cleanly and logs
`stairwell: unexpected response shape, wanted an object` rather than aborting.

**One inconsistency to be aware of if that call fails on authentication.**
Stairwell's sources disagree about the header format. The API quickstart shows
`Authorization: Bearer <token>`, which is what `stairwell.star` sends. Stairwell's
own OpenAPI `securitySchemes` block declares the token as a plain `apiKey` in the
`Authorization` header — that is, the raw token with **no** `Bearer` prefix — and
Stairwell's official Python client leaves the prefix commented out by default.
The server most likely accepts both. If a token you are confident in is rejected,
retry the curl above with `-H 'Authorization: ExampleFakeStairwellToken...'` to
find out which form your tenant wants; the script's format is not configurable.
Whatever the answer, put the bare token in `api_token` — the script adds its own
prefix.

## Steps

### Stairwell configuration

1. Have an Admin create a **Read Only** user for this integration, then sign in
   as that user and generate an **API/CLI token** from **Settings > Auth tokens**.
2. Read the Environment ID from **Settings > Managed environments**, in the
   **Identifier** column.
3. Note the API URL. `https://app.stairwell.com` is the default and is correct
   for the standard tenant. It is not `api.stairwell.com`.
4. Confirm both with the curl above.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - The script pages the asset list 5 records at a time following `nextPageToken`. Raise `PAGE_SIZE` in the script if you have a large environment and want fewer round trips; the `max_pages` default is derived from it, so a larger page lowers the page count needed to reach the same record ceiling.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **Stairwell API URL** (`url`): optional; defaults to `https://app.stairwell.com`.
    - **Environment ID** (`environment_id`): the environment whose assets to import.
    - **API token** (`api_token`): the Stairwell API token.
    - **Maximum pages to retrieve** (`max_pages`, optional, default `2000000`): safety ceiling on the paging walk. The default is the repo-wide ten-million-record target divided by the 5-asset page this script requests, so it does not truncate any real environment. Raise it only if a run logs `page limit of 2000000 hit (integration safety limit, ...)`; that line is the only signal that an import was cut short. A run that instead logs `paging stopped after N pages (API returned the same cursor twice, ...)` is a server that stopped advancing its `nextPageToken`, which no ceiling change will fix.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "Stairwell").
    - Upload an image file for the Stairwell icon.
        - Download [Stairwell logos and icons](https://www.Stairwell.com/wp-content/uploads/2024/10/Stairwell-Logos-and-Favicons.zip)
        - Resize selected icon to be 256px by 256px
        - Upload resized icon file
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename stairwell/stairwell.star \
  --kwargs url=https://app.stairwell.com \
  --kwargs environment_id=VXKCDN-GSPRN8-M4QW7Z-2TPLJHK9 \
  --kwargs api_token=ExampleFakeStairwellToken0123456789abcdef \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./stairwell-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. There is no cap parameter, and the script pages 5 assets at a time, so a first
run against a large environment is both a full collection and a lot of round trips —
worth watching with `--verbose` before you schedule it.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma
— the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. A Stairwell API token is opaque; if one arrives with an
`=` and a comma in it, wrap the whole argument in a second pair of quotes:
`--kwargs '"api_token=ab=cd,ef"'`.

To check the `CONFIG` block and the HTTP and TLS wiring without a live tenant:

```bash
runzero script --filename stairwell/stairwell.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Stairwell accepts the token, that the environment ID exists,
or that any asset is parsed. The fixture scenario is what exercises the parsing:

```bash
python3 tests/run.py stairwell
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat stairwell/stairwell.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://app.stairwell.com,environment_id=VXKCDN-GSPRN8-M4QW7Z-2TPLJHK9,api_token=ExampleFakeStairwellToken0123456789abcdef' \
  --output ./stairwell-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so a token containing a comma cannot be passed this
way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:stairwell`. The slug is the script's `CONFIG` id with the `runzero-` prefix removed, and it is lower-case; if it returns nothing, check the name you gave the integration in the console.
- The asset ID is the **last** component of Stairwell's `environments/<env>/assets/<asset>` resource name. Taking the wrong component here would give every asset in an environment the same foreign ID and collapse them into one; the script comments record that trap.

## Asset identity

- Target entity: an asset in a Stairwell managed environment — a host running the Stairwell forwarder, which collects and uploads files for analysis. The population is therefore the forwarder deployment, not everything Stairwell has ever seen a file from.
- Source ID field: the **last** path component of the asset's `name`, which Stairwell returns as the resource name `environments/<environment_id>/assets/<asset_id>`. The script splits on `/`, drops empty segments, and takes `parts[-1]`.
- Documentation evidence: this is Google-style API resource naming, which Stairwell's API follows throughout — the collection is addressed as `GET /v1/environments/{environment}/assets` and an individual asset as the full resource name. In that convention the trailing segment is the resource's own id and the preceding segments are its parents, so the last component is the asset identifier by construction rather than by inference.
- Uniqueness scope: **the environment, and the id does not encode it.** This is the notable weakness. The resource name carries the environment explicitly and the script discards it, keeping only the leaf. `environment_id` is a required parameter and is also captured on each asset as the `environment` custom attribute, so the material to scope the id is in hand twice over and is used neither time. Two Stairwell environments imported into one runZero organization share a namespace; whether their asset ids can collide depends on whether Stairwell allocates them globally or per environment, which is not documented.

  There is a second, sharper reason the environment belongs in the id: **the previous version of this script took `parts[1]` instead of `parts[-1]`**, which is the environment segment. Every asset in an environment therefore received the same foreign id and the whole environment collapsed onto one runZero asset. That is fixed and the script comments record it, but it is a reminder that the two segments are adjacent in the same string and that the id is parsed rather than read from a field.
- Cardinality: one asset per row.
- Stability: stable for the life of the asset record in Stairwell. A forwarder reinstall is the case with no published guarantee; assume it can mint a new asset and produce a second runZero record rather than a collision.
- Reuse behavior: not documented.
- Presence: derived from `name`, which is present on every asset in the documented response. A record whose `name` yields no path segments is skipped with `stairwell: skipping asset with no resource name`, and one with no address, MAC, or label is skipped with `stairwell: skipping asset <id> with no address, MAC, or label` — it would have nothing to correlate on.
- Final runZero ID: the bare trailing segment of the resource name, unprefixed and unscoped.
- Missing-ID behavior: skip the record and log. No fallback id is synthesized.
- Match behavior: **left at the platform default** — all eight flags on.
- Verdict: authoritative within one environment; the environment boundary is enforced by the credential rather than by the id.

### Address and MAC are both optional (two fixed defects)

Both were in `build_assets()` and both decided which assets existed at all, so they
belong here rather than in a notes list. Both are fixed; `tests/fixtures/interface-optional.json`
covers every combination.

**A record with no MAC address is now an asset with no MAC, not a dropped host.** The
MAC block used to read `if not mac or mac == '-': continue`, and that `continue` sat in
the per-**asset** loop rather than an interface loop, so a record with no `macAddress` — or
one carrying Stairwell's `-` placeholder — never became an asset at all. Not a lost
interface: a lost host, with no log line and no count. A Stairwell environment of hosts
that report an address and no MAC imported as nothing. The interface is now built from
whatever survives, and `network_interface()` returns `None` when neither an address nor a
MAC is left, so an asset with no interface is simply one with an empty list.

**No synthetic loopback address.** `if not ip: ip = '127.0.0.1'` used to substitute
loopback whenever `ipAddress` was empty. It was inert only because the platform's address
normalization rejects loopback before it reaches an asset — the same literal was removed
from the `netskope` integration for the same reason, on the principle that correctness
which depends on a filter somewhere else is not correctness. `127.0.0.1` is identical on
every host, so every address-less asset was an IP-match candidate for every other one.
An address-less record now reports no address, and a loopback address Stairwell itself
returns is dropped rather than forwarded.

**One record is still skipped, and now says so.** A record with no address, no MAC and no
`label` carries nothing runZero can correlate on, so it can never merge with anything and
would only accumulate as an orphan on every run. It is skipped with
`stairwell: skipping asset <id> with no address, MAC, or label`.

### Why the default `matchBehavior` is right

The trailing resource-name segment is a persistent, vendor-assigned identifier, so the governing rule points at foreign-ID matching and the code follows it.

The usual companion preset `no-mac-break no-ip-break no-name-break` would relax the very
checks that carry the weight here. Now that a record with no MAC is imported rather than
dropped, the correlation signal is not guaranteed to be a MAC: an asset may arrive with a
MAC, an address, a hostname, or any combination of the three. Relaxing `mac-break`,
`ip-break` and `name-break` would remove the guard on all of them, in exchange for
protecting against churn that cannot occur — a foreign-ID match is never disqualified by a
conflicting MAC, address, or name.

`label` is asserted as the hostname. Stairwell's asset label is the name the forwarder reported for the host, so it is a real machine name rather than an operator's annotation, which is why `name-break` staying on is safe.

## Future

- **Widen the collection.** The MAC-less drop that used to narrow every import to the subset of hosts reporting a MAC is fixed, so everything below now applies to the whole environment rather than to that subset.
- **The file and object corpus — Stairwell's actual product.** This integration imports the asset list, which is the smallest and least interesting part of what Stairwell holds. Stairwell's value is its file analysis: `GET /v1/objects/{hash}` and the object metadata endpoints return verdicts, YARA matches, variant relationships, and the environments an object has been seen in. An integration that pulled malicious and suspicious objects and attached them to the assets they were seen on would produce runZero findings from a source no scanner can replicate — a scanner sees what is listening, and Stairwell sees what is on disk.
- **Asset-to-object association as the join.** The interesting query is "which objects has this asset uploaded", and the asset id this integration already imports is the key it would be asked with. That association is the bridge between the two halves of the product, and it is what would turn this from an inventory import into a detection feed.
- **Forwarder health as coverage data.** The asset record already carries `forwarderVersion`, `lastCheckinTime`, `backscanState`, and `state`, all of which this integration imports as custom attributes and none of which it acts on. Together they answer "which forwarders are stale, out of date, or never completed their initial backscan" — a deployment-quality report that needs no new endpoint at all, only a runZero-side query over attributes already present.
- **Multiple environments in one task.** `environment_id` is a single required value, so a tenant with several managed environments needs one credential and one task per environment. `GET /v1/environments` would let one task enumerate and sweep them all — and it is also the natural moment to fix the scoping weakness above, since an id that spans environments has to encode which one it came from.
- **Page size as a parameter.** `page_size` is hardcoded to **5**. That is an unusually small page, and on any real environment it means a great many round trips following `nextPageToken`. Raising it currently means editing the script. Promoting it to a `CONFIG` parameter with a sensible default would be a one-line change with a large effect on run time.
- **Outbound: runZero context into Stairwell.** Stairwell's API is primarily a read and upload surface — the write path that exists is for submitting files and creating rules, not for annotating assets. There is no documented endpoint for writing a tag, a note, or a custom field onto an asset, so runZero could not currently push its own verdict back. The one genuine outbound possibility is **rule creation**: Stairwell supports YARA and IOC rules, so a runZero-derived indicator list could in principle seed detection content. That is a very different integration from an asset sync and it writes live detection logic, so it would need a much tighter confirmation model.
- **Coverage-gap reporting needs no new endpoint.** Stairwell knows only hosts with a forwarder. runZero discovers hosts regardless. In-scope runZero assets carrying no `custom_integration:stairwell` source are forwarder deployment gaps — and because the forwarder is what feeds the file corpus, a gap there is a blind spot in the detection product, not just in an inventory.
- **There is no event or alert feed on this endpoint.** The assets collection is a paged list with a page token and no change cursor, so anything near-real-time would be re-listing. If a live feed is wanted, the object and detection side of the API is where to look for it, not here.

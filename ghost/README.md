# Custom Integration: Ghost Security

## Overview

This custom integration automatically imports **Ghost Security findings** into **runZero**, creating assets for each repository and attaching vulnerability data derived from Ghost scans.

The integration now dynamically:

* Retrieves all repositories (and their deployments) from the Ghost API.
* Extracts hostnames from each project’s deployment environments.
* Fetches all findings and associates them with the appropriate repository using the `repo_id` field.
* Creates `ImportAsset` objects in runZero, complete with hostnames, network interfaces, and vulnerabilities.

No manual mapping of repositories to IPs or hostnames is required.

---

## runZero Requirements

* **Superuser access** to [Custom Integrations](https://console.runzero.com/custom-integrations).
* A configured **Custom Integration Credential** for the Ghost API.

---

## Ghost Requirements

* A **Ghost API key** with read access to:

  * `/v1/repos`
  * `/v1/findings`
* API base URL:
  `https://api.ghostsecurity.ai/v1/`

---

## Configuration Steps

### 1. Generate Your Ghost API Key

1. Log in to your **Ghost Security console**.
2. Navigate to your account or organization **API Keys** section.
3. Generate a new key with **read permissions** for repositories and findings.
4. Copy the key — you’ll use it as your `api_token` in runZero.

---

### 2. Add the Credential in runZero

1. Go to [runZero Credentials](https://console.runzero.com/credentials).
2. Choose **Custom Integration Script Secrets**.
3. Enter:

  * **API token** (`api_token`): **required**, stored as a secret — your Ghost API key.
  * **Ghost Security API URL** (`url`): optional, defaults to `https://api.ghostsecurity.ai`. The `/v1/...` path is appended by the script, so configure a scheme and host only. Override for a regional or self-hosted deployment.
4. Save the credential.

---

### 3. Create the Custom Integration

1. Go to [Custom Integrations](https://console.runzero.com/custom-integrations/new).
2. Add a **name** (e.g., `ghost-security`) and optional icon.
3. Enable **Custom integration script**.
4. Paste in the `ghost.star` script (latest version).
5. Click **Validate** to confirm syntax.
6. Save the integration.

---

### 4. Schedule the Integration Task

1. Go to [Ingest → Custom](https://console.runzero.com/ingest/custom/).
2. Choose your **Ghost credential** and **Ghost custom integration**.
3. Assign an **Explorer** to run the task.
4. Set a **schedule** (e.g., daily or weekly sync).
5. Save to start ingesting Ghost data.

---

## How It Works

1. The integration calls `GET /v1/repos` to fetch all repositories.

   * Each repo’s project `deployments` are parsed to extract hostnames (production, staging, etc.).
2. It then calls `GET /v1/findings` to collect findings.

   * Each finding includes a `repo_id` and optional `project.deployments`.
   * The script maps findings back to repositories using `repo_id`.
3. Assets are created for each repo in runZero with:

   * Hostnames from Ghost deployments.
   * Associated vulnerabilities for each finding.

---

## Data Mapped to runZero

| Ghost Field                                                          | runZero Field                |
| -------------------------------------------------------------------- | ---------------------------- |
| repository `name` (**not** `repo_id`)                                | Asset ID — see Asset identity below |
| `repo_id` / `repo_url`                                               | Vulnerability custom attributes |
| `deployments` (from projects)                                        | Asset Hostnames              |
| `findings.*`                                                         | Vulnerabilities              |
| `severity`, `confidence`, `attack_feasibility`, `remediation_effort` | Vulnerability Attributes     |
| `attack_walkthrough`, `remediation`, `description`                   | Vulnerability Details        |

---

## Notes & Tips

* ✅ **No manual repo mapping needed** — the script auto-discovers deployments from Ghost.
* ⚙️ Supports pagination for large repo lists.
* 🧩 Each Ghost finding becomes a `Vulnerability` in runZero.
* 🕒 You can schedule periodic syncs to keep findings up to date.
* 🧾 All Ghost metadata (e.g. `repo_url`, `repo_id`, `project_id`) is stored under `custom_attributes` in each vulnerability.

---

## Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what an
integration would import before scheduling it. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename ghost/ghost.star \
  --kwargs url=https://api.ghostsecurity.ai \
  --kwargs api_token=exampleFakeGhostApiKey0123456789 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./ghost-run
```

`url` is optional and defaults to `https://api.ghostsecurity.ai`, so `api_token` is the only
parameter a real run needs.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

This script logs heavily by design: every repository, its extracted hostnames, and every
finding with its `repo_id` and `repo_url` are printed as they are processed. Read that log
rather than only the asset count — it is where a repository that failed to match a finding
becomes visible.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so a
comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma —
the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`.

To check the `CONFIG` block and the HTTP and TLS wiring without touching the real API:

```bash
runzero script --filename ghost/ghost.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server, so
it proves the script initializes, declares its parameters correctly, and issues a request.
It does not prove Ghost accepts the key or that any finding is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat ghost/ghost.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.ghostsecurity.ai,api_token=<token>' \
  --output ./ghost-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value containing
a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### Troubleshooting

* If no assets appear:
  * Ensure your Ghost account has repositories **with findings**. Repositories with no
    findings never become assets — see Asset identity below.
  * Confirm the API key has access to `/v1/repos` and `/v1/findings`.

---

## Example Output

Example asset in runZero created by this integration:

| Field               | Example                                               |
| ------------------- | ----------------------------------------------------- |
| **Asset Name**      | `juice-shop`                                          |
| **Hostnames**       | `juice.shop`, `staging.juice.shop`, `test.juice.shop` |
| **Vulnerabilities** | 35                                                    |
| **Severity**        | High / Medium / Low                                   |
| **Source**          | Custom Integration: Ghost                             |

---

## Asset identity

- Target entity: a **source-code repository tracked by Ghost Security**, represented in runZero by the hostnames its projects are deployed to. It is not a host: one asset stands for a codebase, and the deployment hostnames are what tie it to anything else in the inventory.
- Source ID field: **the repository `name`** — specifically `mapping["name"]`, which is the `name` field from `GET /v1/repos`, or `repo_url` when a finding references a repository that was not in the repo list.
- **The repository's own `id` is fetched, used as the lookup key for the repo map, and then not used as the identity.** `repo_map` is keyed by `repo.id` and the finding is matched against it by `repo_id`, so the stable identifier is in hand at exactly the moment the asset is built — and the name is used instead. This is a mismatch between the code and the governing rule, and it is recorded here rather than corrected because this pass does not modify scripts.
- Consequences, all three of which follow directly from using the name:
  - **A repository rename mints a new foreign id**, forking a second runZero asset. No `matchBehavior` flag recovers that merge — runZero refuses any merge placing two different foreign ids from the same custom integration on one asset, and that check does not consult `matchBehavior`.
  - **Two repositories with the same name collide into one asset.** Repository names are unique within an organization, not across organizations, so a tenant tracking `api` under two GitHub organizations gets one runZero asset carrying both codebases' findings. Because `matchBehavior` is left at the default the foreign id *is* used to find merge candidates, and once matched it cannot be vetoed by a conflicting hostname.
  - **The fallback path can collapse many repositories onto one asset.** When a finding's `repo_id` is not in the repo map, the mapping is built as `{"name": repo_url or "unknown", ...}`. Every such finding with no `repo_url` therefore lands on a single shared asset whose foreign id is the literal string `unknown`.
- Uniqueness scope: the Ghost tenant, with the same-name caveat above.
- Cardinality: one asset per distinct repository name; every finding referencing it becomes a `Vulnerability` on that asset. **Every repository is an asset, whether or not it has findings** — see below.
- Stability: stable for as long as the repository keeps its name.
- Presence: `name` is defaulted to `"unknown"` when absent, so there is no missing-id skip path; a record with no name silently joins the shared `unknown` asset.
- Final runZero ID: the repository name, e.g. `juice-shop`.
- Missing-ID behavior: none — the value is defaulted rather than skipped.
- Match behavior: **not set** — the platform default, all match and break dimensions on.
- Verdict: **derived, and weaker than it needs to be.** The correct identity is available in the same data structure: keying on `repo_id` (optionally namespaced, e.g. `ghost:<repo_id>`) would eliminate the rename fork, the cross-organization collision, and the `unknown` bucket in one change. Nothing about the source forces the current choice.

Two further things worth knowing before reading the results:

- **Every repository becomes an asset, including clean ones.** Assets used to be created exclusively inside the findings loop: `get_all_repositories` walked and logged every repository, but `asset_map` was only ever written when a finding referenced one. A repository Ghost had scanned and found nothing wrong with was fetched, logged, and then discarded, which made this an import of *findings* grouped by repository rather than an inventory of repositories. Pinned by the `clean-repo` scenario.
- **Ghost publishes no addresses**, and both places that build a mapping hard-code `"ips": []`. These assets therefore carry no network interface and correlate on their deployment hostnames alone.
- **A repository with no deployment hostname is skipped**, logged as `ghost: skipping repository with no deployment hostname: name=…`, and counted in the run summary. It follows from the point above: with no addresses published, the deployment hostnames are the only thing tying a repository asset to anything else in the inventory, so a repository deployed nowhere would arrive as an orphan that can never merge with a scanned host. This is the one case where a repository is fetched and not imported.

## Pagination

Both collections page the same way, and it is a **cursor**, not a page number. The request carries `cursor` and `size`; the response carries `items`, `has_more`, `next_cursor`, and `total`. **There is no `page`, `offset`, or `limit` parameter anywhere in the Ghost API.**

The source is Ghost's own OpenAPI document, which is served **without authentication** at `https://api.ghostsecurity.ai/openapi.json` even though the human-readable docs at `docs.ghostsecurity.ai` are behind an access gate. Every collection in it declares `cursor` ("Pagination cursor") and `size` (default 100, minimum 1, maximum 1000), and the paginated envelope declares `has_more`, `items`, `next_cursor` and `total`. Ghost's own MCP client, `github.com/ghostsecurity/ghost-mcp-server`, used the same `cursor`+`size` contract while it still defaulted to the `/v1` base, before it was ported to v2 — which is the best available evidence that `/v1` shares the contract, since the `/v1` routes are undocumented (they answer `401`, not `404`, so they still exist).

Two defects were fixed here:

- **`/v1/findings` was fetched once, with no paging at all.** On any tenant with more findings than one page holds, the remainder were silently missing.
- **`/v1/repos` sent `?page=N` and incremented it.** No such parameter exists, so the value was ignored. The walk then either truncated at the first page or, if the server kept answering `has_more`, refetched that same page forever.

Both walks now stop on `has_more: false`, and both bail out if the server ever echoes a cursor it has already returned — a task that never finishes is worse than one that truncates. The `paged` scenario is the regression test for both, asserting the records that exist only on pages 2 and 3 and that neither trailing cursor is followed.

## Future

Ghost Security's human-readable API reference is behind an access gate, but its OpenAPI document is served unauthenticated at `https://api.ghostsecurity.ai/openapi.json`; that document covers the `/v2` surface, while the `/v1` routes this integration calls are undocumented. The endpoints named below are limited to the two this integration already calls. Everything else is described by what it would need rather than by a guessed path — confirm the routes against your own tenant before building on them.

- **Resolve deployment hostnames to addresses so these assets merge with scanned ones.** With no IP data from Ghost, a repository asset and the host actually serving `staging.juice.shop` will not correlate unless the hostnames match exactly. Deployment URLs are publicly resolvable names and the Starlark runtime exposes a resolver, so the addresses could be looked up at import time. This is the same limitation `exe-dev` has, with the same fix, and it is what would turn this from a standalone list into something that enriches assets runZero already holds.
- **Keep the deployment environment.** Each project's `deployments` object is keyed by environment — production, staging, and so on — and the script flattens every environment's URLs into one hostname list, discarding the label. Carrying it through as a tag would make "which staging deployments are reachable from the internet" a runZero query, which is a materially more interesting question than "which hostnames does this repo deploy to".
- **Ghost's API and endpoint discovery is the product's distinctive capability and none of it is imported.** Ghost exists to find the APIs and routes an application actually exposes, which is exactly the kind of thing that maps onto runZero `Service` records attached to the hosts serving them — a far better fit for runZero's model than a repository standing in for a host. If the tenant's API surface is reachable through this credential, it is the most valuable addition available here.
- **These findings carry no CVE identifiers, and that will not change.** They are application-security findings against source code — attack feasibility, remediation effort, an attack walkthrough — not CVEs against installed packages. They import as `Vulnerability` records with severity and rank, but runZero's CVE-based vulnerability reporting will not recognise them, and no amount of additional endpoint work turns them into CVEs. If Ghost also reports dependency or SBOM findings, those *would* carry CVEs and would be worth importing separately so the two are not conflated.
- **Outbound is not obviously useful here, which is worth saying rather than inventing a use for.** Pushing runZero data into a code-scanning platform has no clear consumer: Ghost's inputs are repositories and traffic, neither of which runZero produces. The valuable direction for this pair is inbound and lateral — connecting findings to the hosts that serve the code — not a write back.

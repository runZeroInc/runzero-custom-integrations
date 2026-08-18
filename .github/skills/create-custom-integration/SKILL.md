---
name: create-custom-integration
description: 'Create a new runZero custom integration from vendor API documentation and a brief description of the data to import. Use when asked to build, scaffold, generate, or add an inbound Starlark integration. Requires an explicit foreign-ID uniqueness, stability, scope, and cardinality decision before writing code so repeated ingest does not create duplicate assets.'
argument-hint: '<vendor documentation URL> -- import <assets and fields>'
user-invocable: true
disable-model-invocation: false
---

# Create a Custom Integration

Build a production-ready inbound runZero Starlark integration from vendor
documentation and a short import brief. The output is a new repository folder
containing `<integration-name>.star` and `README.md`, plus regenerated catalog
metadata when available.

## Required Inputs

Collect these before implementation:

1. A public or accessible link to the vendor API documentation.
2. A brief statement of which vendor objects and fields should become runZero
   assets, software, services, vulnerabilities, tags, or custom attributes.
3. Authentication and deployment constraints if they are not documented.

If the documentation link or import brief is missing, ask for it. If the docs
need authentication and cannot be read, ask for exported docs, an OpenAPI file,
or representative redacted request/response samples.

## Source of Truth

Read these repository files before coding:

- [Authoring rules](../../../AGENTS.md)
- [Starlark helper reference](../../../docs/starlark-helpers.md)
- [Boilerplate script](../../../boilerplate/boilerplate.star)
- [v1 to v2 migration guide](../../../docs/migration-v1-to-v2.md)
- [Identity decision reference](./references/identity-decision.md)

Inspect one or two existing integrations with similar authentication,
pagination, and data shape. Reuse repository patterns and helper modules rather
than copying generic Python or inventing APIs.

## Workflow

### 1. Research the Vendor API

Read the supplied documentation and identify:

- Base URL and required API version.
- Authentication flow, token lifetime, and required scopes.
- Inventory endpoints and object relationships.
- Pagination mechanism, maximum page size, and termination condition.
- Rate limits, retry guidance, and relevant response headers.
- Fields for identity, hostname, IP, MAC, OS, hardware, timestamps, tags,
  software, services, vulnerabilities, and custom attributes.
- Whether one response row represents an asset, an event, an interface, an
  agent installation, a user/device association, or another child record.

Prefer the documented API contract over examples or field names that merely
look plausible. Record the documentation URLs used for authentication,
pagination, object schema, and identity in the integration README.

### 2. Complete the Asset Identity Gate

Do not write the integration until the foreign-ID decision is explicit.
Complete the decision record from
[identity-decision.md](./references/identity-decision.md) and include it in the
new integration README under `## Asset identity`.

The key question is not only "is this field unique?" The field must be:

- Stable across repeated polls and normal asset lifecycle changes.
- Unique within a known scope.
- One-to-one with the asset type described in the import brief.
- Present on every record that will be imported.
- Not an event, session, interface, finding, temporary, or installation ID when
  multiple such records can describe one asset.

Choose exactly one verdict:

1. **Authoritative foreign ID.** Use a namespaced ID such as
   `vendor:<account-or-tenant>:<source-id>`. Keep default ID matching. If MAC,
   IP, or hostname are expected to churn while the vendor ID remains
   authoritative, use `no-mac-break no-ip-break no-name-break`.
2. **Scoped foreign ID.** The source ID is unique only inside an account,
   organization, site, or region. Include that stable scope in the namespaced
   ID. Never use the raw local ID by itself.
3. **No authoritative foreign ID.** Build a deterministic, documented composite
   only from stable source fields. If that composite is not guaranteed unique,
   declare `"matchBehavior": "no-id-match no-id-break"` in `CONFIG` and require at
   least one usable MAC, IP, or hostname for correlation.
4. **Identity unresolved.** Stop and ask for documentation or representative
   samples. Do not generate an integration that guesses.

Never use `new_uuid()` or another random value as an imported asset ID or as a
fallback. A random fallback creates a new asset on every poll. If a record lacks
the required identity and no safe deterministic fallback exists, skip it with a
concise message that does not contain credentials or the full vendor object.

### 3. Design the Mapping

Write a short mapping plan before implementation:

| Vendor object/field | runZero field | Conversion | Required |
| --- | --- | --- | --- |
| documented identity | `ImportAsset.id` | scoped/namespaced | yes |
| documented names | `hostnames` | trim and deduplicate | no |
| IP and MAC fields | `networkInterfaces` | `network_interface(...)` | no |
| remaining useful fields | `customAttributes` | `to_custom_attributes(...)` | no |

Decide whether child records should be attached as software, services, or
vulnerabilities rather than emitted as separate assets. This cardinality check
is part of duplicate prevention.

### 4. Implement the Integration

Create `<slug>/<slug>.star` and `<slug>/README.md`.

The script must:

- Put a literal `CONFIG = {...}` first, with `minVersion: "5.1.0"` or later.
- Declare every kwarg and mark credential fields as `secret` without defaults.
- Use `OPTIONS_HTTP` and `OPTIONS_TLS` plus `get_http_options` for HTTP APIs.
- Use the runZero `http`, `kwargs`, `net`, parsing, and type helpers.
- Use `validationMode: "compile"` only for direct-protocol integrations.
- Handle all pages and stop on the documented pagination condition. Guard each
  loop with `pager("<label>")` and set `maxPages` in CONFIG rather than
  declaring a local `MAX_PAGES` constant.
- Stream each asset with `report_asset(asset)` and return `None`. Do not
  accumulate batches; the host already writes incrementally.
- Use `parse_ts` rather than `parse_time`, and the `coerce` helpers rather than
  hand-rolled `_text`/`_dict`/`_to_int` guards, so one malformed record cannot
  abort the whole import.
- Skip malformed records that lack the approved identity instead of inventing
  IDs.
- Keep credentials out of logs, errors, tags, and custom attributes.
- Respect documented rate limits and use bounded retry behavior.

The README must document setup, required permissions/scopes, parameters,
imported data, pagination, known limits, validation steps, documentation links,
and the completed asset identity decision.

### 5. Validate with Representative Data

Validation must exercise more than compilation.

1. Run `runzero script --filename <script> --validate` when the generic local
   HTTP fixture matches the script response shape.
2. If generic validation cannot model the vendor response, start a small local
   HTTP fixture with representative redacted responses and run the real
   `runzero script` command against it.
3. Confirm at least one asset serializes successfully when the integration is
   inbound.
4. Run the same fixture twice and verify the emitted `ImportAsset.id` is
   identical across runs.
5. Include two source rows that represent the same asset when the vendor API can
   return duplicates or child records; verify the mapping emits one intended
   asset identity or documented enrichment records.
6. Include two distinct assets with similar names or addresses; verify their IDs
   remain distinct.
7. Test missing identity, empty optional values, pagination, authentication
   failure, rate limiting, malformed records, and duplicate source records.

If a sibling platform checkout exists, run its compatibility test with this
repository as `RZ_CUSTOM_INTEGRATION_SCRIPTS_DIR`. Do not modify the platform
repository unless the user asked for platform changes.

### 6. Regenerate and Review

Run the repository catalog generator. Run it twice and confirm the second run
does not change generated files. Review the complete diff for:

- Random, temporary, event, session, or child-record IDs.
- Missing account/tenant namespace on locally scoped IDs.
- Secrets in logs or examples.
- Incomplete pagination, or a locally declared `MAX_PAGES` instead of CONFIG
  `maxPages` plus `pager()`.
- Unbounded response accumulation, or manual batching, instead of
  `report_asset`.
- Hand-written helpers that duplicate the provided Starlark modules —
  especially `_text`/`_dict`/`_list`/`_to_int` (use `coerce`), `_routable_ip`
  and `_hostname` (use `net`), and validate-then-`parse_time` wrappers (use
  `time.parse_ts`).
- Undocumented assumptions from unavailable vendor docs.

Do not commit or push unless explicitly requested.

## Completion Report

Report:

1. Documentation sources used.
2. Objects and fields imported.
3. The foreign-ID verdict, evidence, namespace, fallback behavior, and the
   `matchBehavior` declared in `CONFIG`.
4. Files created or updated.
5. Validation commands and results.
6. Any assumptions or vendor behavior that still requires confirmation.

An integration is not complete if the asset identity verdict is absent or
uncertain.
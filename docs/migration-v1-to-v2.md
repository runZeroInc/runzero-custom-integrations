# Migrating custom integrations from v1 to v2

Existing scripts without CONFIG continue to run with the legacy `access_key` and
`access_secret` credential fields. Migration is opt-in and can be completed one
integration at a time.

## Migration checklist

1. Move integration metadata from `config.json` into a literal `CONFIG = {...}`
   block as the first top-level statement in the script. Only comments and blank
   lines may appear before it.
2. Declare every value read from `kwargs` in `CONFIG["params"]`. Use `secret`
   for credentials and the typed `url`, `int`, `float`, `bool`, `enum`,
   `textarea`, or `json` forms where appropriate. Secret params cannot declare
   defaults.
3. Set `minVersion` to `5.1.0` or later for scripts that use the v2 CONFIG,
   helper, protocol, matching, or streaming APIs.
4. Add `OPTIONS_HTTP` and `OPTIONS_TLS` includes for HTTP integrations, then use
   `kwargs.get_http_options` so User-Agent, CA, pinning, mTLS, and validation
   settings reach the HTTP client.
5. Replace hand-written authentication, retry, URL, parsing, network-interface,
   and custom-attribute helpers with the standard Starlark modules.
6. For paginated imports, call `report_assets(page)` after each page and return
   `None` so the Explorer does not retain the full vendor dataset in memory.
7. Review the stability and uniqueness of each `ImportAsset.id`. Declare a
   top-level `CONFIG["matchBehavior"]` only when the default id, MAC, IP, and
   name rules do not match the source's identity model. It is no longer a field
   on `ImportAsset`.
8. Run `runzero script --filename <script> --validate`. Direct-protocol scripts
   can declare `"validationMode": "compile"`, but still require a controlled
   endpoint test for their protocol behavior.
9. Test with representative vendor fixtures, including empty optional values,
   pagination, authentication failures, malformed records, and duplicate asset
   identifiers.

## Compatibility notes

- Legacy scripts can keep returning a list of `ImportAsset` values from `main`.
- Legacy key/value kwargs remain readable; new task writes use JSON.
- Existing credentials continue to work. A CONFIG-backed credential uses the
  generated typed form and validates against the script schema when saved.
- CONFIG-based scripts reject unknown kwargs and receive canonical enum option
  values after alias and case-insensitive normalization.
- Leaving `matchBehavior` out of `CONFIG` preserves the existing matcher behavior.
- Migration does not add an in-product LLM. External authoring tools only draft
  source that must pass normal review and validation.
- Direct-protocol modules intentionally can reach internal addresses available
   to the selected Explorer. This is accepted behavior; scope the Explorer and
   credential to the intended source system.

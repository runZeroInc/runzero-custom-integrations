# Asset Identity Decision

Complete this decision before writing `ImportAsset` construction code. Add the
final decision to the integration README.

## Decision Record

```markdown
## Asset identity

- Target entity: <physical device, VM, cloud resource, application, etc.>
- Source ID field: `<documented.field.path>`
- Documentation evidence: <URL and quoted/paraphrased contract>
- Uniqueness scope: <global, tenant, account, organization, site, region>
- Cardinality: <one source row per target asset, or explain many-to-one>
- Stability: <what lifecycle events preserve or replace the ID>
- Reuse behavior: <whether deleted IDs can be assigned to another asset>
- Presence: <required, nullable, or missing for specific object types>
- Final runZero ID: `<vendor>:<stable-scope>:<source-id>`
- Missing-ID behavior: <skip, or documented deterministic composite>
- Match behavior: <default or exact matchBehavior tokens>
- Verdict: <authoritative, scoped authoritative, derived/non-authoritative,
  unresolved>
```

## Required Evidence

Use vendor documentation, an OpenAPI schema, or representative response samples
to answer all of the following:

1. Does the field identify the desired asset, or a child such as an event,
   interface, agent installation, session, user association, or finding?
2. Can one desired asset appear in multiple rows with different values?
3. Can two desired assets share the value in different accounts, sites, or
   regions?
4. Does the value survive rename, reboot, IP/MAC change, agent upgrade, and
   ordinary inventory refresh?
5. Does reinstall, reprovision, clone, or restore generate a new value?
6. Can the vendor recycle a deleted object's value?
7. Is the field always present in list and detail responses?

An API field named `id`, `uuid`, `device_id`, or `temporary_id` is not evidence
by itself.

## Decision Rules

### Authoritative ID

Use default ID matching when the source documents a stable, one-to-one ID. Add a
vendor namespace and every scope required for uniqueness:

```python
asset_id = "vendor:{}:{}".format(account_id, source_id)
```

If network identifiers are expected to change independently of that ID:

```python
matchBehavior = "no-mac-break no-ip-break no-name-break"
```

This keeps the authoritative ID as the matching signal while preventing normal
network churn from fragmenting one asset.

### Derived, Non-Authoritative ID

Use a deterministic composite only when its inputs are stable and documented.
Namespace and delimit each component. Do not hash ambiguous concatenated values.

If uniqueness is not guaranteed, the ID must not drive or block matching:

```python
matchBehavior = "no-id-match no-id-break"
```

In that case each record must still contain a usable MAC, IP, or hostname. If it
does not, skip the record because runZero has no reliable correlation signal.

### Missing Identity

Never write:

```python
asset_id = item.get("id") or new_uuid()
```

Use the approved deterministic fallback or skip the malformed record:

```python
source_id = item.get("id")
if not source_id:
    print("vendor: skipping record with no documented asset id")
    continue
```

Do not log the full source object because it may contain credentials, personal
data, or large nested content.

## Duplicate-Oriented Tests

At minimum, test these cases with a local fixture:

| Case | Expected result |
| --- | --- |
| Same source object in two polls | Same `ImportAsset.id` |
| Same local ID in two tenants | Different namespaced IDs |
| Two child rows for one asset | One asset identity or explicit enrichment |
| Missing authoritative ID | Record skipped or approved deterministic fallback |
| Same hostname, distinct source IDs | Distinct assets unless policy says otherwise |
| Stable ID with changed IP/MAC/name | Same ID; match behavior permits intended merge |

If any expected result cannot be justified, the verdict is unresolved and the
integration should not be generated yet.
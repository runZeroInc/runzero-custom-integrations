# Custom Integration: Red Hat Insights

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- Network access from the selected Explorer to `console.redhat.com` and `sso.redhat.com` over HTTPS.

## Red Hat Insights requirements

- A Red Hat account with systems registered to Red Hat Insights (Red Hat Lightspeed).
- A Hybrid Cloud Console **service account**, and an organization administrator to grant it permissions.
- The service account needs the **Inventory Hosts viewer** role (`inventory:hosts:read`). Importing CVE findings additionally needs the **Vulnerability viewer** role (`vulnerability:vulnerability_results:read`, `vulnerability:report_and_export:read`).
- **Inventory Hosts viewer is not a platform-default role.** Red Hat's published RBAC configuration marks it `platform_default: false`, which means it is *not* included in the Default access group. Assuming a new service account inherits it is the single most common way to end up with a credential that authenticates perfectly and reads nothing.
- Package data (`include_software`) is read from the inventory system profile, so Inventory Hosts viewer covers it. Note that Red Hat's own tooling requires a separate **Patch viewer** role for the Patch service's package and advisory endpoints — if you extend this integration toward those, budget for that role too.
- Basic authentication with a Red Hat account username and password is **not** an option. Red Hat ended support for it on the console APIs and disabled it entirely on 30 April 2026; token-based service account authentication is the only supported path.

## Steps

### Red Hat Insights configuration

1. Create the service account. In [console.redhat.com](https://console.redhat.com), open the settings gear, then **Service Accounts**, then **Create service account**. Record the **Client ID** and **Client secret** — the secret is shown once and cannot be retrieved later.
2. Grant it permissions. Service accounts start with no access, and **Inventory Hosts viewer is not part of the Default access group**, so this step is mandatory rather than a tightening. In **Settings > Identity & Access Management > User Access > Groups**, either add the service account to an existing group or create a new group, add the service account on the **Service accounts** tab, and assign the **Inventory Hosts viewer** role. Add **Vulnerability viewer** as well if you want CVE findings. Note that any user can create a service account, but only an Organization Administrator or a User Access administrator can add it to a group — so this step may need someone else.
3. Confirm the credential works:
   ```
   TOKEN=$(curl -s https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token \
     -d grant_type=client_credentials \
     -d client_id="$CLIENT_ID" \
     -d client_secret="$CLIENT_SECRET" \
     --data-urlencode scope=api.console | jq -r .access_token)

   curl -s -H "Authorization: Bearer $TOKEN" \
     'https://console.redhat.com/api/inventory/v1/hosts?per_page=1'
   ```
   The response is `{"total": ..., "count": 1, "page": 1, "per_page": 1, "results": [...]}`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Red Hat Insights").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Console URL** (`url`): optional; base URL of the Hybrid Cloud Console (default: `https://console.redhat.com`). The `/api/inventory/v1` and `/api/vulnerability/v1` paths are appended automatically.
   - **Red Hat SSO URL** (`sso_url`): optional; base URL of Red Hat single sign-on (default: `https://sso.redhat.com`).
   - **Service account client ID** (`client_id`): the service account's client ID. Supply this together with the client secret.
   - **Service account client secret** (`client_secret`): the secret issued when the service account was created.
   - **x-rh-identity header** (`identity_header`): optional; base64-encoded identity JSON, for internal or proxied deployments only. Leave blank on `console.redhat.com`.
   - **Token scope** (`scope`): optional; OAuth2 scope requested for the token (default: `api.console`). Leave blank to send no scope.
   - **Import installed packages** (`include_software`): optional; import the RPM inventory (default: false).
   - **Import CVE findings** (`include_vulnerabilities`): optional; import findings from the Vulnerability service (default: false).
   - **CVE enrichment limit** (`vulnerability_limit`): optional; cap on how many systems get CVE findings (default: 500, 0 removes the cap).
   - **Systems per page** (`page_size`): optional; systems requested per page (default: 50, maximum 100).

   Supply **either** the client ID and secret pair **or** the identity header. Configuring neither is an error and the run stops with a message naming both options.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a service account and see what the inventory returns before scheduling
anything. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename redhat-insights/redhat-insights.star \
  --kwargs client_id=service-account-runzero-a1b2c3d4 \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Ng \
  --kwargs page_size=20 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./redhat-insights-run
```

`url`, `sso_url`, and `scope` all have working defaults
(`https://console.redhat.com`, `https://sso.redhat.com`, and `api.console`), so
a normal hosted account needs only the client ID and secret. Set them
explicitly only for a proxied or internal deployment.

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

The two enrichment switches are both expensive and both off by default. Turn
them on one at a time, capped:

```bash
runzero script --filename redhat-insights/redhat-insights.star \
  --kwargs client_id=service-account-runzero-a1b2c3d4 \
  --kwargs client_secret=Zm9vYmFyc2VjcmV0ZXhhbXBsZTEyMzQ1Ng \
  --kwargs include_vulnerabilities=true \
  --kwargs vulnerability_limit=5 \
  --kwargs page_size=20 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./redhat-insights-cves --overwrite
```

`include_software` needs no limit parameter because it rides along on the
system profile rather than costing a request per host, but a RHEL system
reports hundreds of packages — lower `page_size` when you enable it, or the
responses get very large.

The failure worth recognizing is a **service account with no group
membership**. It authenticates against `sso.redhat.com` perfectly, receives a
valid token, and is then refused by the inventory API — or returns an empty
list. If the token call succeeds and the host count is zero, check User Access
before checking the credential.

For the proxied case, pass `identity_header` instead of the client pair. It is
base64-encoded JSON, and base64 has no commas, so it survives `--kwargs`
intact — but it does contain `=` padding, and only the **first** `=` separates
the key from the value, so the padding is preserved correctly.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename redhat-insights/redhat-insights.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove Red Hat SSO issues a token,
that User Access grants anything, or that any system is parsed. In particular
it does not exercise the `atLeastOneOf` pairing between `client_secret` and
`identity_header` against real credentials.

The fixtures under `redhat-insights/tests/fixtures/` exercise the parsing
offline, including the token-refresh, profile-fallback, and CVE-cap cases:

```bash
python3 tests/run.py redhat-insights
```

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat redhat-insights/redhat-insights.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'client_id=service-account-runzero-a1b2c3d4,client_secret=<secret>' \
  --output ./redhat-insights-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way; prefer `script --kwargs`
for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Red Hat Insights.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:redhat-insights`.

## Asset identity

- Target entity: one registered system — a physical machine, a VM, a cloud instance, or a RHEL for Edge device — as tracked by one deduplicated row in the Insights Host Based Inventory.
- Source ID field: `results[].id`
- Documentation evidence: the inventory OpenAPI specification describes `HostOut.id` as "A durable and reliable platform-wide host identifier. **Applications should use this identifier to reference hosts.**" ([`swagger/api.spec.yaml`](https://github.com/RedHatInsights/insights-host-inventory/blob/master/swagger/api.spec.yaml), `HostId` / `HostOut.id`). It is a UUID (`NonStrictUUID`), and it is the only value accepted by every `/hosts/{host_id_list}...` path.
- Uniqueness scope: global within the inventory service, and further scoped to the tenant by `org_id`, which the API marks `required` on every `HostOut`. The id is namespaced by `org_id` anyway so that two Red Hat organizations polled by one runZero instance can never collide.
- Cardinality: one row per **deduplicated** system. Inventory performs its own deduplication before a row exists, using the ID facts `provider_id` (immutable, highest priority), then `subscription_manager_id`, then `insights_id` ([Host Deduplication](https://github.com/RedHatInsights/insights-host-inventory/blob/master/docs/index.md#host-deduplication)). Several reporters — `puptoo`, `rhsm-conduit`, `satellite`, `cloud-connector` — collapse onto one row and one `id`.
- Stability: survives rename, reboot, IP/MAC change, OS upgrade, `insights-client` upgrade, workspace reassignment, and being reported by a different reporter. It is replaced only when the row itself is deleted — manually, or by culling after `conventional_time_to_delete` (30 days of inactivity by default) — and the system later re-registers.
- Reuse behavior: no. It is a UUID minted per inventory row, never handed to a different system.
- Presence: always present on the host list and on every detail response. A record without it is not expected and is skipped rather than invented.
- Final runZero ID: `redhat-insights:<org_id>:<results[].id>`
- Missing-ID behavior: skip the record and print only the display name.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. A registered system reports whatever addresses it holds at check-in; a laptop, a VPN client, or an autoscaled cloud instance changes them between polls. The inventory id stays the authoritative merge signal while that churn is prevented from disqualifying a merge against an existing runZero asset.
- Verdict: scoped authoritative.

### Why `id` and not `insights_id`, `subscription_manager_id`, or `bios_uuid`

All four are present on a host record, and the other three are imported as custom attributes so they stay searchable, but none of them is safe as the foreign id:

- **`bios_uuid` is the trap.** It is the SMBIOS system UUID, and the API declares it `nullable`. Critically, inventory does **not** use it for deduplication — it is a canonical fact, not an ID fact — so two distinct inventory rows are permitted to carry the same `bios_uuid`. VMs cloned from a template and golden-image VDI pools routinely report an identical SMBIOS UUID, so keying on it would silently collapse many real machines onto one runZero asset. That failure is neither visible nor recoverable.
- **`insights_id` is nullable and is not machine-derived.** The API documents it as "An ID defined in `/etc/insights-client/machine-id`" and marks it `nullable`. A system registered only through subscription-manager or a cloud provider integration has no `insights-client` installed and therefore no `insights_id` at all. It is also a file: `insights-client --unregister` followed by `--register` writes a new one, and cloning a VM without resetting the file duplicates it.
- **`subscription_manager_id` is nullable and re-minted on re-registration.** It is the RHSM consumer UUID. Unregistered, unsubscribed, and edge systems do not have one, and `subscription-manager unregister && register` issues a new consumer.
- **`id` is the one field Red Hat tells applications to use**, is always present, and is the output of inventory's own deduplication rather than an input to it. Every one of the failure modes above has already been resolved by the time a row has an `id`.

The trade is deliberate and matches the Fleet integration's reasoning. Keying on `id` means a system that is culled from inventory and re-registers arrives as a new foreign id; runZero then merges it back onto the existing asset on hostname, MAC, or IP, which is the ordinary recoverable case. Keying on any of the others would mean two real machines silently becoming one asset.

### Notes

- **Assets come from `GET /api/inventory/v1/hosts`**, paged with `page` (numbered from **one**) and `per_page` (maximum 100, default 50), ordered by `updated` ascending. The response envelope is `{"total", "count", "page", "per_page", "results"}`; paging stops on the first short page or once `total` has been reached. Each asset is streamed with `report_asset` as it is built, so the full inventory is never held in memory.
- **There is no N+1 for inventory.** The system profile — where all of the real hardware, OS, and network detail lives — is requested *on the host list itself* as a sparse fieldset: `?fields[system_profile]=arch,network_interfaces,...`. Red Hat documents this explicitly: "In addition to the `/hosts/{host_id_list}/system_profile` endpoint, this query can also be used on the upper-level `/hosts` endpoint to fetch partial system profile data for hosts. On the `/hosts` endpoint, if this query is not included, no system profile data will be returned." ([HBI docs](https://github.com/RedHatInsights/insights-host-inventory/blob/master/docs/index.md#fetching-sparse-system-profile-fieldsets)). Ordinary inventory therefore costs **exactly one request per page**, not one per system.
- **The batched `system_profile` endpoint works too, and is deliberately not used.** `GET /hosts/{host_id_list}/system_profile` takes `host_id_list` as "A comma-separated list of host IDs" (`type: array` of `NonStrictUUID`, `components/parameters/hostIdList`), so it genuinely would batch and would avoid the classic N+1. It is unnecessary here because the sparse fieldset on `/hosts` already returns the same data in the same request as the canonical facts, and using it would double the request count for no gain.
- **Sparse fieldsets degrade rather than fail.** Field names are validated server-side against the published system profile schema, and an unknown name returns `400 Requested field '<x>' is not present in the system_profile schema`. The integration requests a full set of 43 fields; if the server rejects it, it retries with a reduced set of 11 long-established fields, and if that is rejected too it drops the parameter entirely and imports canonical facts only. Which tier was used is recorded in `redhat_insights_profile_fields` (`full`, `reduced`, or `none`) so a degraded run is visible on the asset rather than silent. Sparse fieldsets support top-level fields only.
- **Authentication is an OAuth2 client-credentials exchange** against `https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token` with `grant_type=client_credentials` and `scope=api.console`, producing a bearer token. Red Hat's tokens expire after **15 minutes**, which a large import outlives repeatedly, so every `401` — on a host page or on a per-system CVE call — causes the token to be re-minted and that request retried once with the new token. The `x-rh-identity` header path exists for internal and proxied deployments; on `console.redhat.com` the gateway sets that header itself from the bearer token, so it must be left blank there.
- **Network interfaces prefer `system_profile.network_interfaces[]`** over the top-level canonical facts. That array is collected from `ip addr` and keeps each NIC's own name, MAC, IPv4, IPv6, state, and type together, so a multi-homed host keeps its per-NIC addressing instead of being collapsed. The top-level `ip_addresses[]` and `mac_addresses[]` are two *unrelated* lists that cannot be correlated with each other; they are only used when the profile is unavailable, and then the addresses become one interface and each MAC becomes another.
- **Loopback filtering is not cosmetic here.** `insights-client` reports the `lo` interface, `127.0.0.1`, and `::1` on essentially every host, and reports `00:00:00:00:00:00` for any interface with no hardware address. If either reached a NetworkInterface, every such host would share an address and runZero could merge an entire estate onto one asset. Interfaces typed `loopback` or named `lo` are dropped, `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0`, `::1`, `::`, and `fe80::/10` are filtered out of every address list, and the all-zero MAC is dropped. The unfiltered lists are kept verbatim as `redhat_insights_ip_addresses` and `redhat_insights_mac_addresses`. A system whose only address is loopback imports with **no** network interfaces at all — its identity rests on the inventory id.
- **`public_ipv4_addresses` and `public_dns` never become interfaces.** They are the NAT egress or cloud front-end addresses that an entire VPC or office shares. They are kept as custom attributes.
- **`enabled_services` are systemd unit names, not listening ports, and are deliberately not imported as runZero Services.** The collector builds this list from `systemctl list-unit-files`, keeps only enabled units, and strips the `.service` suffix, so it contains values like `sshd`, `chronyd`, and `rhsmcertd` ([`profile.py`](https://github.com/RedHatInsights/insights-puptoo/blob/master/src/puptoo/process/profile.py), `_enabled_services`). There is no port, no transport, and no bind address anywhere in the system profile, and a runZero `Service` requires all three. Inventing a port for `sshd` would be a fabrication, and the unit list is not evidence that anything is listening. They are recorded as `redhat_insights_enabled_services` and `redhat_insights_enabled_service_count` instead. This is the same trap the Cyberwatch integration documents for that vendor's `services[]` array.
- **Software comes from `system_profile.installed_packages[]` and is opt-in.** These are **NEVRA strings, not objects** — `name-epoch:version-release.arch`, for example `krb5-libs-0:1.16.1-23.fc29.i686`. They are parsed with the same algorithm `insights-core` uses to produce them: the architecture is separated by `.` only when the last dot falls after the last dash, and the trailing token counts as an architecture only if it is a recognized one, so `kernel-0:5.14.0-427.13.1.el9_4.x86_64` splits correctly and `3.10.0-1160.el7` does not lose `el7`. The result maps to `Software(product=name, version="<version>-<release>", targetHardware=arch)` with the raw string kept as `redhat_insights_package_nevra`. A string with neither an epoch nor a recognized architecture gives no evidence the split found real boundaries, so it is skipped and counted rather than turned into a plausible-looking but wrong product; the count is printed once at the end of the run.
- **No CPE is set on Software.** Insights publishes no CPE for an installed package, so `cpe23` is left unset rather than synthesized. (`installed_products[]` carries Red Hat product *subscription* names and IDs, which are not CPEs either; they are recorded as an attribute.)
- **Packages are capped at 99 per asset**, the platform limit. A RHEL host reports several hundred. The API returns them in RPM name order, so the retained set is the first 99 by name — this is a deterministic but arbitrary slice, and it is the reason package import is off by default. `redhat_insights_package_count` records how many the system actually reported.
- **Vulnerabilities come from `GET /api/vulnerability/v1/systems/{inventory_id}/cves` and are opt-in.** The linkage is clean: the path parameter is the inventory `id` this integration already uses as its foreign id, so no correlation guesswork is involved. This is the one genuine N+1 in the integration — the Vulnerability service has no endpoint that returns findings for several systems at once — so it is capped by `vulnerability_limit` (default 500) and the number of systems skipped past the cap is printed at the end of the run.
- Findings map `id` to `cve` (upper-cased, then checked against `^CVE-[0-9]{4}-[0-9]{4,19}$`; anything that still does not match is dropped rather than failing the record), `cvss3_score` and `cvss2_score` to `cvss3BaseScore` / `cvss2BaseScore` (both arrive as **strings** like `"4.400"` and are shape-checked before conversion), `known_exploit` to `exploitable`, `public_date` to `publishedTS`, `first_reported` to `firstDetectedTS`, and `advisories_list` to the solution text. Severity rank comes from Red Hat's own **security impact** (`Critical`/`Important`/`Moderate`/`Low`), which is what the console displays, falling back to the CVSS band when impact is absent. Findings are bucketed by rank before the 99-per-asset cap so the most severe survive.
- **No service fields are set on a Vulnerability.** Insights matches a CVE against installed content, never against a listening port, so `serviceAddress`, `servicePort`, and `serviceTransport` are deliberately left unset.
- A system absent from the vulnerability database returns `404`. That is normal for a host that has never uploaded an archive, so it is counted and reported once at the end rather than logged per host.
- **`manufacturer` and `model` are not set.** The system profile carries `bios_vendor` and `bios_version`, which describe the firmware, not the chassis — a Dell server and a KVM guest report `Dell Inc.` and `SeaBIOS` respectively, and neither is the system manufacturer or model. Both are kept as custom attributes and runZero's own fingerprinting decides.
- **`deviceType` is only asserted for virtual systems.** `infrastructure_type == "virtual"` (derived by the collector from `virt-what`) maps to `Virtual Machine`. `physical` covers RHEL servers and workstations alike and is left unmapped.
- `os` comes from `operating_system.name` (`RHEL` is expanded to `Red Hat Enterprise Linux`; `CentOS Linux` passes through) and `osVersion` from `operating_system.major.minor`, falling back to `os_release`. Note that `os_release` in this schema is a **version** string such as `9.4`, not a distribution name — the collector sets it from `redhat_release.rhel`.
- A `display_name` or `fqdn` equal to the host id is dropped rather than imported as a hostname: inventory falls back to the id when a system reports no FQDN, and importing a UUID as a hostname would be noise.
- `firstSeenTS` comes from `created` and `lastSeenTS` from `last_check_in`, falling back to `updated`. All inventory timestamps carry an explicit offset, but each one is shape-checked before it reaches `parse_time`, which aborts the whole script on a value with no timezone.
- **Staleness is left at the API default.** `GET /hosts` returns `fresh`, `stale`, and `stale_warning` systems and excludes culled ones unless the `staleness` parameter says otherwise. That parameter is an OpenAPI array, which requires repeated query keys that the shared HTTP helper's `params=` dict cannot express, so it is not sent. `stale_timestamp`, `stale_warning_timestamp`, and `culled_timestamp` are imported as attributes so staleness remains queryable in runZero.
- Transient failures (408/425/429/500/502/503/504) are retried with exponential backoff by the shared HTTP helper, which honors the `Retry-After` header. No retry loop is hand-rolled.
- Host **tags** (`GET /hosts/{id}/tags`) are not imported. They are a separate paged endpoint and would reintroduce an N+1 for data that is largely operational bookkeeping. Workspace/group membership, which is on the host record already, is imported as `workspace:<name>` tags.
- Unverified assumptions, stated plainly:
  - **This integration was validated against local fixtures, not a live Red Hat Insights tenant.** No Red Hat account was available. Every field name, response envelope, pagination contract, and identity claim above is taken from Red Hat's own published OpenAPI specifications and collector source (linked below), not from an observed live response.
  - The three-tier sparse-fieldset degradation was exercised against fixtures that return `400` for a named field. A live `console.redhat.com` should accept the full set, since every requested name is in the current published schema; the fallback exists for schema drift and for non-production deployments.
  - CVE mapping was exercised against fixtures built from the Vulnerability Engine's own OpenAPI response schema. The `impact` string values (`Critical`/`Important`/`Moderate`/`Low`) are Red Hat's documented security-impact ratings but were not observed live.
  - The `x-rh-identity` header path is wired and tested against fixtures, but it is only meaningful for internal or proxied deployments and could not be exercised against a real gateway.

## Future

- **Insights Advisor recommendations as a distinct data class.** `GET /api/insights/v1/system/{inventory_id}/reports/` and `GET /api/insights/v1/rule/` return the rules a system is failing, each with a category (Availability, Stability, Performance, Security), a total risk rating, a human-readable description, and resolution steps. This is the product's actual reason for existing and it is genuinely different from CVE data — an Advisor hit is a misconfiguration or a known-bad state, not a vulnerable package version. It does not map onto `Vulnerability` cleanly because most hits have no CVE, so it deserves either its own integration or an opt-in that imports hits as findings with `category` set to the Advisor category and no `cve`.
- **Compliance (OpenSCAP) as a policy-state import.** `GET /api/compliance/v2/systems` and `GET /api/compliance/v2/policies` return each system's SCAP policy assignments, its compliance score, and pass/fail counts against benchmarks such as CIS and DISA STIG. Modelled the way the Fleet integration models policy results — a `compliance:failing` tag plus per-policy attributes — this would let runZero answer "which discovered RHEL hosts are out of compliance" alongside "which exist at all".
- **Patch and errata state.** `GET /api/patch/v3/systems` and `GET /api/patch/v3/systems/{inventory_id}/advisories` return applicable RHSA/RHBA/RHEA advisories per system, split by type and severity, plus the count of installable versus applicable updates. This is closer to what an operator acts on than a raw CVE list, because an advisory is the unit Red Hat actually ships, and `advisories_list` on a CVE finding already points at it. Importing advisories as findings with the RHSA id as the name would pair naturally with the CVE import this integration already offers.
- **The Vulnerability service beyond per-system CVEs.** `GET /api/vulnerability/v1/vulnerabilities/cves` lists CVEs across the whole org with affected-system counts, and `GET /api/vulnerability/v1/cves/{cve_id}/affected_systems` inverts the join. Neither replaces the per-system call for import — they are org-wide and CVE-first — but a CVE-first lookup integration ("which of my runZero assets are affected by this CVE") is exactly the shape those endpoints serve, and it would avoid the N+1 entirely because one request answers the whole question.
- **Remediation playbook generation as an outbound surface — flag as disruptive.** `POST /api/remediations/v1/remediations` creates a remediation plan from a list of `(system, issue)` pairs, and `GET /api/remediations/v1/remediations/{id}/playbook` renders it as an Ansible playbook. A runZero workflow could turn discovery findings into a plan. **Anything that executes must stay out of scope or behind an explicit confirmation parameter:** `POST /api/remediations/v1/remediations/{id}/playbook_run` actually runs the playbook against production systems through the RHC/Satellite executor, which reconfigures, restarts services, and reboots hosts. Generating a playbook for a human to review is safe; running one from an automated runZero task is not, and should never be reachable without deliberate opt-in.
- **RHEL fleet coverage-gap reporting.** This is the strongest outbound case and it runs opposite to this integration. runZero discovers assets by scanning the network, including RHEL hosts that never registered with Insights; Insights only knows about systems that did. Comparing the two sets — runZero assets fingerprinted as RHEL with no matching `redhat-insights` foreign id — produces the list of unmanaged, unpatched, unmonitored RHEL machines, which is precisely the blind spot an Insights operator cannot see from inside Insights. `GET /api/inventory/v1/host_exists?insights_id=` and the `hostname_or_id`, `fqdn`, and `subscription_manager_id` filters on `/hosts` are enough to confirm a candidate is genuinely absent before reporting it as a gap. Subscription compliance makes this commercially interesting as well as operationally useful.
- **Newer system profile fields worth revisiting.** `workloads`, `bootc_status`, `conversions` (systems converted from CentOS/Oracle Linux), `image_builder`, `rhel_ai`, and `third_party_services` are in the current published schema but are recent additions. They are deliberately not requested today so that a deployment lagging the schema cannot force the whole sparse fieldset onto its fallback tier. Once they are safely ubiquitous they would add real signal, particularly `conversions` and `bootc_status` for image-mode RHEL.
- **What the API does not support.** There is no webhook or push subscription an Explorer could subscribe to for inventory changes; the console's notification service delivers to email, Slack, ServiceNow, Splunk, and generic webhooks, which would require an inbound listener rather than a polled integration. There is also no endpoint that returns listening ports, open sockets, or any network-service inventory — the system profile simply does not collect it — so runZero's own scanning remains the only source for that, which is precisely the complementary value of pairing the two.

## API documentation

- Inventory REST API specification, used for endpoints, pagination, `HostOut`, `HostId`, and the canonical facts: https://github.com/RedHatInsights/insights-host-inventory/blob/master/swagger/api.spec.yaml
- Inventory pagination contract (`page`, `per_page` maximum 100, `total`/`count`/`page`/`per_page` envelope): https://github.com/RedHatInsights/insights-host-inventory/blob/master/swagger/pagination.yaml
- Host deduplication, ID facts, staleness and culling, and the sparse-fieldset contract on `/hosts`: https://github.com/RedHatInsights/insights-host-inventory/blob/master/docs/index.md
- Sparse-fieldset server-side validation, and the exact 400 message on an unknown field: https://github.com/RedHatInsights/insights-host-inventory/blob/master/app/custom_validator.py
- System profile JSON schema — the authoritative field list, types, and enums: https://github.com/RedHatInsights/inventory-schemas/blob/master/schemas/system_profile/v1.yaml
- System profile collector, the source of truth for how `os_release`, `operating_system`, `infrastructure_type`, `network_interfaces`, `installed_packages`, and `enabled_services` are actually populated: https://github.com/RedHatInsights/insights-puptoo/blob/master/src/puptoo/process/profile.py
- NEVRA construction and the recognized-architecture list used to parse it back apart: https://github.com/RedHatInsights/insights-core/blob/master/insights/parsers/installed_rpms.py
- Vulnerability service API specification, used for `/systems/{inventory_id}/cves`, its `data`/`links`/`meta` envelope, and the CVE attribute set: https://github.com/RedHatInsights/vulnerability-engine/blob/master/manager.spec.yaml
- Service accounts, permissions, and the client-credentials token exchange: https://docs.redhat.com/en/documentation/red_hat_hybrid_cloud_console/1-latest/html/creating_and_managing_service_accounts/index
- Authenticating to the console APIs with a service account token: https://docs.redhat.com/en/documentation/red_hat_lightspeed/1-latest/html/using_apis_to_configure_red_hat_lightspeed_services/apis-authentication
- Transition from basic authentication to token-based service account authentication: https://access.redhat.com/articles/7036194
- Console API catalog: https://console.redhat.com/docs/api

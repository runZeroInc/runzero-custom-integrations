# Custom Integration: Digital Ocean

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Digital Ocean requirements

- A **Personal Access Token** for the team whose Droplets you want to import. Tokens belong to a user within a team, so a token only ever sees one team's resources.
- The token needs **read** scope on Droplets. This integration calls `GET /v2/droplets` only; it never creates, resizes, or deletes anything, so `droplet:create` and the other write scopes should not be granted.
- The API base URL is `https://api.digitalocean.com`. The `/v2/droplets` path is appended by the integration, so configure the host only.

## Steps

### Digital Ocean configuration

1. Sign in to the DigitalOcean Control Panel and switch to the team you want to import.
2. Go to **API** in the left-hand navigation (or open the [Applications & API page](https://cloud.digitalocean.com/account/api/tokens) directly), and on the **Tokens** tab click **Generate New Token**.
3. Give the token a name, for example `runzero`, and set an expiry. DigitalOcean offers 30, 60, or 90 days, a custom date, or no expiry; a token with an expiry has to be rotated on that cadence or the task starts failing with `401`.
4. Choose **Custom Scopes** and grant **Read** on `droplet`. Full Access works but grants far more than this integration uses. Read scope lets a token list Droplets and view what those resources return; it cannot create or modify them.
5. Click **Generate Token**. The value is displayed once, immediately after creation, and cannot be retrieved afterwards.
6. Confirm the token from the Explorer host:

   ```bash
   curl -s -H "Authorization: Bearer <token>" \
     'https://api.digitalocean.com/v2/droplets?per_page=1'
   ```

   A `401` means the token is wrong or expired; a `403` means it is valid but lacks the `droplet:read` scope.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter assets.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - **API token** (`api_token`): **required**, stored as a secret. The Personal Access Token created above.
    - **DigitalOcean API URL** (`url`): optional, defaults to `https://api.digitalocean.com`. Override only for a proxy or a non-production endpoint; the `/v2` path is appended by the script.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "digital-ocean").
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
runzero script --filename digital-ocean/digital-ocean.star \
  --kwargs url=https://api.digitalocean.com \
  --kwargs api_token=dop_v1_............. \
  --output ./digital-ocean-run \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b
```

`url` is optional and defaults to `https://api.digitalocean.com`, so `api_token` is the only
parameter a real run needs.

`--output` writes the serialized assets so you can inspect exactly what would be imported.
It requires `--custom-integration-id` to be a well-formed UUID — any UUID will do for a
local run, and without one the command fails with `custom integration ID required for
output`. Add `--overwrite` to re-run into a directory that already exists. Omit `--output`
to see only the log lines, and add `--verbose` for the request-by-request log.

To check the `CONFIG` block and the HTTP and TLS wiring without touching the real API:

```bash
runzero script --filename digital-ocean/digital-ocean.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove DigitalOcean accepts the token or that any Droplet is parsed.

The recorded API shapes are exercised by the fixture suite:

```bash
python3 tests/run.py digital-ocean
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat digital-ocean/digital-ocean.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://api.digitalocean.com,api_token=<token>' \
  --output ./digital-ocean-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a value
containing a comma cannot be passed this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:digital-ocean`.

## Asset identity

- Target entity: a **Droplet** — DigitalOcean's cloud compute instance. `GET /v2/droplets` returns nothing else, which is why the device type is set to `Server` from the resource itself rather than guessed from an image name or a size slug.
- Source ID field: `id`, from `GET /v2/droplets`.
- Documentation evidence: DigitalOcean addresses a Droplet by this value throughout its own API — `/v2/droplets/{droplet_id}`, its actions, its snapshots, and its neighbors are all keyed on it. It is the resource identifier, not an incidental field.
- Uniqueness scope: at minimum the team the Personal Access Token belongs to, since a token only ever sees one team. DigitalOcean assigns Droplet ids from a platform-wide integer sequence, so a collision between two teams is implausible, but **no vendor guarantee of global uniqueness is cited here** — treat team scope as what is established.
- Cardinality: one source row per Droplet.
- Stability: **immutable for the life of the Droplet.** Rename, resize, reboot, reassignment of the public address, and even a rebuild from a different image all preserve it — the id names the instance, not its configuration.
- **The cloud caveat that matters more than any of the above: destroying and recreating is not the same as rebuilding.** A Droplet destroyed and re-created — which is what Terraform's replace, an autoscaling event, or any immutable-infrastructure pipeline does routinely — is a *new* Droplet with a *new* id, even if it comes back with the same name, the same image, and the same address. Each generation therefore becomes a separate runZero asset. That is the correct answer semantically (it genuinely is a different machine) but it means a fleet managed this way accumulates assets over time, and the old ones have to be aged out in runZero rather than merged.
- Reuse behavior: not documented. The value is a monotonic integer, so recycling after destruction cannot be excluded on shape alone; nothing observed suggests it happens.
- Presence: expected on every Droplet. A record without one is skipped with `digital-ocean: skipping droplet with no id: name=<name>`.
- Final runZero ID: the raw Droplet id as a string, e.g. `3164494`. It is also preserved as the `id` custom attribute.
- Missing-ID behavior: skip and log. No identifier is synthesized from the name or the address.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule, and in a cloud environment the foreign id is doing more work than usual: DigitalOcean addresses are pooled and reserved IPs are explicitly designed to be moved between Droplets, so an address is a *worse* correlation signal here than on a physical network. The stable id is what keeps the asset coherent when the address is reassigned.
- Verdict: **authoritative for a Droplet instance.** Not authoritative for "the workload that used to run here", which is a question this API cannot answer.

Note also what is deliberately not imported: the Droplet's `networks` block yields both the public and private addresses, both of which belong to that Droplet, so both are attached — but no MAC address is available anywhere in this API, so correlation with an agent-based source rests on the address and the name alone.

## Future

- **Everything else in the account that has an address.** `/v2/droplets` is one resource among many that occupy IP space: `/v2/load_balancers` have public addresses and forwarding rules, `/v2/databases` publish connection hosts for managed database clusters, `/v2/kubernetes/clusters` describe DOKS control planes and node pools, and App Platform apps under `/v2/apps` have ingress hostnames. All of them are things runZero would otherwise discover from the outside without knowing what they are. Each has its own stable resource id, so each could carry a proper identity rather than being inferred from an address.
- **`/v2/reserved_ips` is the missing half of this integration's address story.** Reserved (floating) IPs are addresses that deliberately move between Droplets, which is precisely the case where address-based correlation misleads. Importing the reservation records would let runZero see that an address it observed yesterday on one asset legitimately belongs to a different one today, instead of inferring a machine change.
- **`/v2/firewalls` as exposure data.** DigitalOcean's cloud firewalls define which inbound ports are permitted to which Droplets, by tag or by id. That is a statement about reachability that no scan from outside the VPC can fully establish, and it would either seed `Service` records or — more honestly — land as exposure attributes describing what the platform permits, distinct from what runZero actually observed.
- **`/v2/domains` and its records, to recover real hostnames.** A Droplet's `name` is an operator-assigned label, not a DNS name. Importing the account's DNS zones and resolving the A and AAAA records back to Droplet addresses would give these assets their actual hostnames, which is what makes them correlate with data from a source that knows names rather than cloud ids.
- **`/v2/vpcs` as scan scope.** VPC definitions give the private ranges in use, which is a ready-made target list for runZero's own scanning — and one that includes segments an operator may never have thought to point an Explorer at.
- **Outbound: push runZero classification back as Droplet tags.** DigitalOcean tags are first-class and are already imported here (converted from `key:value` to `key=value`). The write direction would let a runZero query — Droplets running an unsupported OS, Droplets exposed to the internet, Droplets missing an expected agent — become a DigitalOcean tag, which firewalls and load balancers can then select on. That makes runZero's findings actionable inside the platform rather than only visible in runZero.
- **Droplet power and lifecycle actions are reachable and deliberately out of scope.** The actions endpoints can power off, rebuild, or destroy a Droplet. The credential guidance above exists precisely to make that impossible: grant read scope on `droplet` only, and no future misconfiguration of an outbound integration can reach them.
- **Rate limiting shapes what is affordable.** DigitalOcean applies a per-token hourly request budget with a much tighter per-minute burst limit, and the shared HTTP helper already retries `429` with backoff and honors `Retry-After`. The current integration pages 200 Droplets at a time and caps the walk at 1,000 pages, so it is nowhere near the limit — but any addition that issues a request per Droplet rather than per page would be, which argues for the list endpoints above over per-resource enrichment calls.

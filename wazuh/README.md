# Custom Integration: Wazuh

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Wazuh manager's API port (55000 by default). This is an on-premises service, so the Explorer must sit inside the network that serves it.

## Wazuh requirements

- Wazuh API endpoint reachable on port 55000 (for example: https://wazuh-manager.example.com:55000).
- Wazuh API user credentials with permission to authenticate and read agent/syscollector data.

Three things about the Wazuh API are worth knowing before you start, because each
of them causes a failure that looks like something else:

- **This is the Wazuh server API, not the dashboard.** The credential you want is
  not your Wazuh dashboard login and not an indexer account. The server API is a
  distinct service listening on 55000, with its own users and its own RBAC. It is
  managed as part of the `wazuh-manager` package — `systemctl restart wazuh-manager`
  restarts it — and its configuration lives in
  `/var/ossec/api/configuration/api.yaml`, where the defaults are
  `host: ['0.0.0.0','::']` and `port: 55000`.
- **The API presents a self-signed certificate by default.** If no certificate
  exists in `/var/ossec/api/configuration/ssl/` when the API first starts, it
  generates one. Wazuh recommends replacing it, which is why every example in
  their documentation passes `curl -k`. Either install a trusted certificate or
  set the integration's `tls_` options.
- **Tokens are short-lived.** A successful login returns a JWT valid for **900
  seconds** (15 minutes). The API is also rate limited to 300 requests per minute,
  with a separate limit of 50 login attempts per 300 seconds.

### Which RBAC role — the one that catches people out

Wazuh ships these default roles: `administrator`, `agents_admin`,
`agents_readonly`, `cluster_admin`, `cluster_readonly`, `readonly`, and
`users_admin`.

The obvious pick is `agents_readonly`, and **it is the wrong one.** Wazuh defines
it as read-only access to agent-related functionality, and it carries the
`agents_read_*` policies and nothing else — `agents_read_agents` (action
`agent:read` on `agent:id:*` and `agent:group:*`) plus `agents_read_groups`
(`group:read`).

This integration reads agents *and* their hardware inventory: after `GET /agents`
it calls `GET /syscollector/{agent_id}/netiface` and
`GET /syscollector/{agent_id}/netaddr` for network interfaces and addresses.
Every `/syscollector/` route requires the action **`syscollector:read`**, which
lives in a separate policy — `syscollector_read_syscollector`, granting
`syscollector:read` on `agent:id:*`, exposed as the `syscollector_read_*` policy
group. `agents_readonly` does not carry it. Wazuh's default RBAC mode is
`white`, i.e. deny-by-default, so the result is an import that lists agents
correctly and then has no MAC addresses or IPs on any of them, with 403s buried
in the log.

Use one of:

- **`readonly`** — the only default role that carries both `agents_read_*` and
  `syscollector_read_*`. Simplest, and correct. Note that it also grants rules,
  decoders, CDB lists, SCA, FIM, rootcheck, MITRE, cluster, and vulnerability
  reads that this integration never uses.
- **A custom role combining `agents_read_*` and `syscollector_read_*`** — the true
  least-privilege option, and worth the effort on a shared manager. The whole
  grant is one policy:

  ```json
  {"actions": ["agent:read", "syscollector:read"],
   "resources": ["agent:id:*", "agent:group:*"],
   "effect": "allow"}
  ```

Do not use `administrator` for this. Both action names and every default role
name above are unchanged from Wazuh 4.9 through the current release, so this
does not depend on which 4.x you run.

## Steps

### Wazuh configuration

1. **Find out what credentials you already have.** Which ones exist depends on how
   Wazuh was installed:
   - **OVA / virtual appliance:** the API users `wazuh` (password `wazuh`) and
     `wazuh-wui` (password `wazuh-wui`) are created for you. Change them.
   - **Assistant script install:** the `wazuh` user is created with a *generated*
     password. Retrieve it from the install bundle:

     ```bash
     tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O
     ```

   Passwords must be 8 to 64 characters and contain upper case, lower case, a
   number, and a symbol. Note that changing the `wazuh-wui` password also requires
   editing `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`, so prefer
   creating a dedicated user over repurposing that one.

2. **Create a dedicated API user.** The server API has no user-management UI of its
   own; users are created through the API itself. Authenticate as an existing
   administrator, then:

   ```bash
   TOKEN=$(curl -s -k -u <admin_user>:<admin_password> -X POST \
     'https://wazuh-manager.example.com:55000/security/user/authenticate?raw=true')

   curl -s -k -X POST 'https://wazuh-manager.example.com:55000/security/users' \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"username":"runzero","password":"Ch4nge-Me!2026"}'
   ```

   The response includes the new user's `id`. A newly created user comes back with
   an **empty roles array** — it can authenticate and read nothing, which is the
   single most common cause of "the credential works but the import is empty".

3. **Assign the role.** Attach `readonly` (or your custom agents+syscollector role)
   to the user you just created. The **Security** section of the Wazuh dashboard
   does this in a few clicks and is the easier route. Through the API it is
   `POST /security/users/{user_id}/roles`, taking the role ids as a query
   parameter; building a custom role instead is `POST /security/policies` (body
   `{name, policy: {actions, resources, effect}}` — all three policy fields are
   required), then `POST /security/roles`, then
   `POST /security/roles/{role_id}/policies` to bind them.

   Your own manager is authoritative for the version you are running, and serves
   both its route list and its own API reference:

   ```bash
   curl -s -k 'https://wazuh-manager.example.com:55000/' -H "Authorization: Bearer $TOKEN"
   ```

   The Wazuh documentation's RBAC reference lists the default roles and the
   policies each one carries.

4. **Confirm the credential end to end**, including the syscollector call that
   `agents_readonly` would fail:

   ```bash
   TOKEN=$(curl -s -k -u runzero:'Ch4nge-Me!2026' -X POST \
     'https://wazuh-manager.example.com:55000/security/user/authenticate?raw=true')

   curl -s -k -H "Authorization: Bearer $TOKEN" \
     'https://wazuh-manager.example.com:55000/agents?limit=1'

   curl -s -k -H "Authorization: Bearer $TOKEN" \
     'https://wazuh-manager.example.com:55000/syscollector/000/netiface'
   ```

   If the first succeeds and the second returns 403, the role is the problem, not
   the password. `GET /security/users/me/policies` answers the same question
   directly, listing the policies the token actually holds — check for
   `syscollector:read` in it.

5. **Decide how to address the manager.** The integration accepts either form:
   - Leave `url` blank and set `hostname` and `port`; the URL is composed as
     `https://<hostname>:<port>`.
   - Set `url` to the full base URL. Use this whenever the deployment is not plain
     HTTPS on the API port — behind a reverse proxy, on a path prefix, or on HTTP.
     `url` replaces the composed base entirely.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
   - Modify API calls as needed to filter inventory data.
   - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with every field below.
   - **Wazuh API URL** (`url`): optional; the full base URL of the manager API. Set this for a reverse-proxied, path-prefixed, or plain-HTTP deployment — it replaces the composed base entirely. Leave blank to compose the URL from the two fields below.
   - **Wazuh manager hostname or IP** (`hostname`): optional; used to compose `https://<hostname>:<port>` when `url` is empty. Do not include a protocol or a port.
   - **Wazuh API port** (`port`): optional; defaults to `55000`.
   - **Username** (`username`): required; your Wazuh API username.
   - **Password** (`password`): required; secret. That user's password.
   - **Maximum pages to retrieve** (`max_pages`): optional; defaults to `20000`. Safety ceiling on the `/agents` paging walk. The default is the repo-wide ten-million-record target divided by the 500-agent page Wazuh caps `limit` at, so it does not truncate any real deployment. Raise it only if a run logs `page limit of 20000 hit (integration safety limit, ...)`; that line is the only signal an import was cut short. Note that the 500-agent page size is the vendor's — a larger `limit` is refused with error 1405 — so only the page count is adjustable.
   - **Syscollector requests per minute** (`requests_per_minute`): optional; defaults to `240`. Paces the two per-agent enrichment requests under Wazuh's `max_request_per_minute` budget (default 300), which otherwise answers 429 and silently costs those agents their interface data. Raise it only if the manager's budget was raised; `0` disables the pacing entirely.
   - **TLS options** (`tls_*`): set `tls_ca_cert` or `tls_disable_validation` for the self-signed certificate case.

   Note that `url` and `hostname` are both declared optional, so a credential that sets
   **neither** passes validation and then fails at runtime with an unusable base URL. Set one.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (for example: wazuh).
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 2 and 3.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm an API user — and its role — before scheduling anything. `--kwargs` is
repeated once per parameter:

```bash
runzero script --filename wazuh/wazuh.star \
  --kwargs hostname=wazuh-manager.example.com \
  --kwargs port=55000 \
  --kwargs username=runzero \
  --kwargs password='Ch4nge-Me!2026' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./wazuh-run
```

Or, for a manager that is not plain HTTPS on the API port, use `url` instead of
`hostname` and `port`:

```bash
runzero script --filename wazuh/wazuh.star \
  --kwargs url=https://wazuh.example.com/wazuh-api \
  --kwargs username=runzero \
  --kwargs password='Ch4nge-Me!2026' \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./wazuh-proxied --overwrite
```

Because the API's certificate is self-signed unless you replaced it, a first run
frequently fails on TLS rather than on the credential. Point at the manager's CA
rather than reaching for the URL:

```bash
  --kwargs tls_ca_cert=/var/ossec/api/configuration/ssl/server.crt
```

`--output` writes the assets the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the request-by-request log. Omit
`--output` to see only the log lines.

**Run this one verbose, and look at the syscollector calls specifically.** The
role trap described above is invisible in the asset count — agents import fine
and simply arrive with no network interfaces. The 403s on
`/syscollector/{id}/netiface` in the verbose log are the only direct evidence.

The integration makes **two extra requests per agent** for interfaces and
addresses. Against a manager with several thousand agents that is several
thousand requests into a 300-per-minute rate limit, which is why they are paced
by the `requests_per_minute` parameter (default 240) — expect a command-line
run against a large estate to take a while, and do not run several at once.

`--kwargs` takes its value verbatim as long as the whole argument holds a single
`=`, so a comma on its own is harmless — `--kwargs 'password=a,b'` arrives as
`a,b`. What breaks is a value carrying **both** a second `=` and a comma: the
flag then parses the argument as a CSV record, so `--kwargs 'x=a=b,c=d'` yields
`x=a=b` plus a fabricated parameter `c="d"`. Wazuh passwords are required to
contain a symbol, and both `=` and `,` are symbols, so a password holding both is
a live risk here. Wrap the whole argument in a second pair of quotes when one
does:

```bash
  --kwargs '"password=Ch4nge=Me,2026"'
```

Or configure the password through the console credential form, which has no such
limitation.

To check the `CONFIG` block and the HTTP and TLS wiring without a live manager:

```bash
runzero script --filename wazuh/wazuh.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy
server, so it proves the script initializes, declares its parameters correctly,
and issues a request. It does not prove the manager issues a JWT, that the user
holds a role covering syscollector, or that any agent is parsed.

There are no fixtures in `wazuh/tests/fixtures/`, so there is no offline parsing
test to run for this integration — the command-line run against a real manager is
the test.

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat wazuh/wazuh.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'hostname=wazuh-manager.example.com,port=55000,username=runzero,password=<password>' \
  --output ./wazuh-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
password containing a comma cannot be passed this way either; prefer
`script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with the data pulled from the custom integration source.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:wazuh`.

## Asset identity

This integration reports **one population** — Wazuh agents — but two grades of identifier, so it declares two asset types and picks one per agent at runtime with `ImportAsset(assetType=...)`:

- **`agent`** — the record carries a `dateAdd`, so the ordinal is pinned. `CONFIG["assetTypeBehavior"]["agent"]` is `no-mac-break no-ip-break no-name-break`.
- **`agent-unpinned`** — no `dateAdd`. It has *no* `assetTypeBehavior` entry, so it keeps the platform default with every flag on, which is what it needs.

`CONFIG["matchBehavior"]` carries `no-type-break`, because the split is about identifier quality inside one population rather than two different kinds of thing. An agent reporting no `dateAdd` today can report one tomorrow — a Wazuh upgrade, a re-enrollment, an API that starts populating the field — and it is the same agent on the same host throughout, so a type change must not be a reason to veto a merge.

Be careful not to over-read that. Gaining `dateAdd` also changes the foreign id, from `wazuh:<manager>:agent:<id>` to `wazuh:<manager>:agent:<id>:<dateAdd digits>`, and two foreign ids from one custom integration cannot sit on one asset whatever the break flags say — so that transition still forks and is reconciled in runZero. `no-type-break` is necessary but not sufficient here; it is declared so the type boundary is not a *second*, independent reason for the same fork.

- Target entity: a Wazuh agent — a host running the Wazuh agent daemon and enrolled with the manager, from `GET /agents`. Only agents whose `status` is `active` become assets; disconnected, pending, and never-connected agents are filtered out.
- Source ID field: a **composite of `agent.id` and `agent.dateAdd`**, scoped by the manager hostname.
  - `agent.id` is Wazuh's zero-padded per-manager ordinal (`000`, `001`, `002`, …). It is the stable half: assigned once at registration, stored in the manager's `client.keys`, and the value every agent-scoped route is addressed by — `/syscollector/{agent_id}/netiface` and `/syscollector/{agent_id}/netaddr` are exactly how this integration fetches interfaces and addresses.
  - `agent.dateAdd` is the registration timestamp, and it is the disambiguating half. Only its digits are kept, so `2026-01-15T09:00:00Z` and `2026-01-15 09:00:00` — Wazuh has shipped both renderings — reduce to the same key and an API upgrade cannot re-key the estate.
- Documentation evidence: the `Agent` schema in `api/api/spec/spec.yaml` in `wazuh/wazuh` declares `id`, `dateAdd`, `registerIP`, `node_name`, and `manager` among others. `node_name` is documented as the node the agent is *reporting to* and `manager` as the hostname of that manager, which is why neither may appear in an identity. There is **no UUID and no key in the agent object** in Wazuh 4.x; the agent key is a separate `GET /agents/{agent_id}/key` and is an authentication credential rather than an identifier, so it is not used here.
- Uniqueness scope: **one Wazuh manager.** An agent id is a small per-manager ordinal, so `001` means nothing outside one manager. The id is namespaced on the manager hostname taken from the configured URL, so two Wazuh deployments imported into one runZero account cannot collide.
- Cardinality: one asset per active agent.
- Stability: **survives a cluster rebalance.** The master node is authoritative for registration and pushes the agent keys file to the workers, so `id` does not change when an agent reconnects to a different worker. `node_name` and `manager` do change, and neither is in the id.
- Reuse behavior: **the ordinal is recyclable, and the id is not.** See below.
- Presence: `agent.id` is on every agent record. An agent record without one is skipped and logged.
- Final runZero ID: `wazuh:<manager-hostname>:agent:<id>:<dateAdd digits>`, for example `wazuh:wazuh-manager.example.com:agent:005:20260301100000`.
- Missing-ID behavior: skip and log — `wazuh: skipping agent with no id: name=…`. No identity is synthesized and `new_uuid()` is never used.
- Asset type: **`agent`**, or **`agent-unpinned`** when the record carries no `dateAdd`.
- Match behavior: **`no-mac-break no-ip-break no-name-break`**, with one deliberate exception — see below.
- Verdict: **authoritative within one manager**, namespaced by the manager hostname.

### The two defects this replaced

**1. The ordinal is recycled, and nothing disambiguated it.** `agent.id` is allocated from a counter seeded off the highest id in `client.keys` (`OS_AddNewAgent` in `src/addagent/validate.c`, and the counter is bumped *before* the removed-entry check, so gaps are never backfilled). Once the top-numbered agent is purged the next enrollment receives that same id — and `ossec.conf`'s `<auth><purge>` defaults to **`yes`**, so purging is the normal path. The corroborating detail is that `schema_global.sql` declares `id INTEGER PRIMARY KEY` with no `AUTOINCREMENT`, so SQLite itself will reuse the top rowid. A brand-new, unrelated host therefore inherited the previous agent's runZero asset: its history, its hostname, and its interfaces. `dateAdd` is now part of the id, so the new agent gets a different one.

**2. The `environment` prefix was a site-specific naming convention, and it moved.** The id used to be `"{environment}-{agent_id}"`, where `environment` was `node_name.split('-')[-3]`. That yields `prod` from `wazuh3-worker-prod-sc2-03`, which is presumably what it was written for. It also yields:

| `node_name` | `environment` | comment |
|---|---|---|
| `wazuh3-worker-prod-sc2-03` | `prod` | the intended case |
| `wazuh3-worker-prod-01` | `worker` | one fewer segment, completely different prefix |
| `node01` | *(empty)* | single-node install — the common default |
| `wazuh-manager` | *(empty)* | two segments |

So the prefix was meaningful only on an estate using the naming scheme the function assumed, and arbitrary everywhere else. Worse, **it was not stable**: `node_name` is the cluster node an agent is *currently* connected to, and agents rebalance across workers on reconnection, worker restart, and failover. An agent moving from `wazuh3-worker-prod-sc2-03` to `wazuh3-worker-prod-01` changed its `environment` from `prod` to `worker`, and therefore its foreign id, minting a duplicate asset with no log line and no error. The function is gone; `node_name` survives only as the `wazuh_node_name` attribute, which is where a mutable field belongs.

The two defects pushed in opposite directions, which is the only reason the old scheme worked as well as it did in practice: the prefix accidentally reduced collisions from recycled ids across environments, while creating instability of its own.

### This is a breaking change for existing deployments

**Every asset this integration has imported changes its foreign id in one run.** `prod-005` becomes `wazuh:wazuh-manager.example.com:agent:005:20260301100000`. There is no in-script migration, and there could not be a reliable one: the old id depended on which cluster worker the agent happened to be talking to at the time.

On the first run after upgrading, every agent is imported under a new id and merges onto its existing runZero asset by hostname, MAC, and address — which is exactly the evidence Wazuh is strongest on, since `netiface` and `netaddr` are read off the host by syscollector rather than inferred. The old ids remain attached until they age out. Plan the first run as a re-import rather than an incremental poll.

### Why the break flags are relaxed now, and where they are not

The earlier revision of this document argued for keeping `mac-break` and `ip-break` on, on the grounds that when a recycled agent id was about to pull an unrelated host onto an old asset, a disagreeing MAC was the only thing that could stop it. That argument was right, and its premise is now gone: with `dateAdd` in the id, the ordinal cannot be inherited, so there is no collision left for the break flags to guard against. What remains is the ordinary case for a stable vendor id — an agent whose laptop moves between networks, whose VM is renamed, or which gains an interface is the same agent, and its own addressing must not disqualify the merge onto its own asset. Hence `no-mac-break no-ip-break no-name-break`.

**The exception is an agent that reports no `dateAdd`.** Its id falls back to `wazuh:<manager>:agent:<id>`, which *can* be inherited by a later agent reusing the ordinal — so that agent is reported under the `agent-unpinned` asset type, which has no `assetTypeBehavior` entry and therefore keeps the platform default, where a disagreeing MAC still vetoes the merge. A line is logged saying so. Both asset types are asserted side by side in the `identity-stability` scenario.

`registerIP` was considered as a disambiguator and rejected: it is frequently the literal `"Any"`, because `use_source_ip` defaults to `no`.

### Notes

- **Only active agents are imported.** An agent that is disconnected at poll time vanishes from the import rather than being refreshed. On an estate with laptops that is most of the fleet at any given moment.
- **Agents stream page by page.** Each 500-agent page is enriched and reported before the next page is fetched, so the full agent list is never buffered and a failure partway through a large estate keeps everything already reported.
- **Two extra requests per agent, paced.** `GET /syscollector/{id}/netiface` and `GET /syscollector/{id}/netaddr` are issued for every active agent. Against a manager with several thousand agents that is several thousand requests into a documented 300-per-minute rate limit, so they are paced by `requests_per_minute` (default 240); above the manager's budget the API answers 429 and those agents silently import with no interface data.
- **Token expiry is handled mid-run.** The JWT is valid for 900 seconds and a long run outlives it, so a `401` on a syscollector call triggers re-authentication and a retry rather than losing the rest of the agents. The `auth-refresh` scenario locks this path.
- **Addresses are screened before they reach an interface.** syscollector reports link-local `fe80::/10` and Windows APIPA `169.254/16` per interface, and `agent.ip` can hold the registration literal `any` — none of which identifies a host. Only routable addresses survive, junk values cost the field rather than the run, and a `mac: null` interface contributes no NIC. The `malformed` scenario locks all of it.
- **`agent.name` becomes the hostname**, except for the literal `unknown-agent`, which is filtered. The Wazuh agent name is set at enrollment and is usually the host's real name, so this is sound.
- Fixture scenarios cover the happy path, paging truncation and stuck cursors, malformed records, an empty manager, identity stability, device typing, and mid-run re-authentication (`tests/fixtures/`); a command-line run against a real manager remains the only live test.

## Future

- **Vulnerability detection as findings — the largest gap by far.** Wazuh's vulnerability detector correlates each agent's installed-package inventory against CVE feeds, and it is arguably the most valuable thing the product produces. It is reachable per agent, and the agent id this integration already uses is the join key. Importing it would turn this from an inventory sync into a findings source covering every host with an agent, from a scanner that sees installed packages rather than network banners. Note that the endpoint moved between major Wazuh versions — older releases served `GET /vulnerability/{agent_id}` from the manager API, and newer ones expose the results through the Wazuh indexer instead — so this needs a version check before it needs code.
- **The rest of syscollector.** This integration calls two of its endpoints and there are several more, all keyed on the same agent id: `/syscollector/{id}/packages` (installed software, straight into runZero `Software`), `/syscollector/{id}/os` and `/hardware` (richer OS and hardware detail than the agent record carries), `/syscollector/{id}/ports` (listening services, straight into runZero `Service`), and `/syscollector/{id}/processes`. Packages and ports are the two that would most change what runZero knows. The cost model is the constraint — each is another request per agent — so they belong behind parameters the way `include_alerts` does in comparable integrations here.
- **SCA results as compliance findings.** `GET /sca/{agent_id}` returns Security Configuration Assessment policy results per agent — CIS benchmark checks and their pass/fail state. That is posture data with a remediation path attached, and it is expressible as findings on assets this integration already creates.
- **Agent groups as runZero tags.** The agent record already carries `group`, and this integration stringifies the whole list into one `wazuh_groups` attribute. Wazuh groups are how an estate expresses role and environment — which is what the removed `node_name` parsing was trying and failing to derive. Mapping them to runZero tags would recover that intent from a field that actually carries it.
- **Import inactive agents behind a parameter.** Filtering to `active` loses every host that is off, asleep, or on a disconnected network at poll time. An `include_inactive` parameter with `status` and `lastKeepAlive` as attributes would let an operator decide, and would make "which agents have stopped reporting" answerable from runZero — which is a question a security team asks constantly and cannot currently answer here.
- **Server-side filtering.** `GET /agents` accepts `status`, `group`, and a `q` query, none of which this integration uses (`limit` and `offset` it does use, at the vendor-maximum 500 a page). Pushing the `active` filter to the server would cut the response size, and a `group` filter would let one task import a subset of a shared manager.

### When a run stops early

The `/agents` walk ends on a page with no `affected_items`. Two other things can
end it, and both say so in the log:

- `wazuh: paging stopped after N pages (API returned the same page twice, ...)` — the manager answered two consecutive offsets with the same agent ids, meaning it ignored `offset` or a proxy replayed a cached response. Raising `max_pages` will not help; the walk was not making progress. Check for a caching reverse proxy in front of the API.
- `wazuh: page limit of N hit (integration safety limit, ...) - raise the max_pages parameter to import the rest` — a genuinely larger estate than the ceiling allows. Raise `max_pages`.
- **Outbound: runZero discovery as Wazuh agent groups.** `PUT /agents/{agent_id}/group/{group_id}` assigns an agent to a group, and Wazuh scopes its detection rules and SCA policies by group. A runZero verdict — an asset on a sensitive segment, an asset exposing an unexpected service — could move an agent into a group with tighter rules, so discovery drives detection policy. Two constraints: this needs a write role rather than the `readonly` role this document argues for, and it changes live detection behavior on production hosts, so it needs a much tighter confirmation model than a scheduled read.
- **Agent coverage-gap reporting needs no new endpoint.** Wazuh knows only hosts with an agent enrolled; runZero discovers hosts regardless. In-scope runZero assets carrying no `custom_integration:wazuh` source are agent deployment gaps, and on a security estate that gap is a monitoring blind spot rather than just a missing inventory row.
- **Alerts are not on this API.** Wazuh's alert stream lives in the Wazuh indexer (OpenSearch), not in the manager API this integration speaks. An alert-ingestion integration is therefore a different credential, a different endpoint, and a different script — worth building, but not an extension of this one. The same is true of the vulnerability data on current Wazuh versions, which is one more reason an indexer-side integration would be the higher-value next piece of work.

# Custom Integration: Tactical RMM

Imports every endpoint a [Tactical RMM](https://docs.tacticalrmm.com/) server has an agent on, with the hardware, OS, address, and serial detail the agent reports, and optionally the installed-software inventory.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Tactical RMM backend host over HTTPS.

## Tactical RMM requirements

- A Tactical RMM server, self-hosted. A standard install publishes three subdomains — `rmm.` (the dashboard), `api.` (the REST backend), and `mesh.` (the bundled MeshCentral). **This integration talks to the `api.` host**, and the REST resources are mounted at the root of it: `https://api.example.com/agents/`, not `https://api.example.com/api/agents/`.
- An API key, created in the dashboard. The key is issued to a user and inherits that user's role, so the user must be a superuser or hold a role with `can_list_agents` — and `can_list_software` as well if software import is enabled. A non-superuser with **no** role assigned is denied everything, which surfaces as an empty import rather than an error.
- Standard installs terminate TLS with a Let's Encrypt certificate, so no TLS option is normally needed. If the deployment uses a private CA or a self-signed certificate, use the integration's TLS options rather than disabling validation blindly.

## Steps

### Tactical RMM configuration

1. Sign in to the dashboard as a superuser.
2. Go to **Settings → Global Settings → API Keys** and add a key.
3. Choose the user the key acts as. Its role decides what the import can see: a key issued to a technician scoped to one client imports only that client's agents, which is a supported way to scope the integration.
4. Optionally set an expiration. Leaving it blank means the key never expires.
5. Copy the key. Confirm it works before leaving the dashboard:

   ```bash
   curl https://api.example.com/clients/ -H "X-API-KEY: YOUR_API_KEY"
   ```

   Note the trailing slash — Tactical RMM's URL routing requires it on every path.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Tactical RMM").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Tactical RMM API URL** (`url`): base URL of the backend, for example `https://api.example.com`.
   - **API key** (`api_key`): the key created above.
   - **Agent type** (`monitoring_type`): optional; `all` (default), `server`, or `workstation`.
   - **Import installed software** (`extract_software`): optional; off by default. See the note on cost below.
   - **Maximum agents to query for software** (`software_agent_limit`): optional; default 250.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with endpoint inventory pulled from Tactical RMM.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:tactical-rmm`.

## Running from the command line

The runZero CLI runs the same script the console does, which makes it the fastest way to iterate on a change or to prove a credential works before wiring up a task.

Check the CONFIG block and the HTTP/TLS wiring without touching the server:

```bash
runzero script --filename tactical-rmm/tactical-rmm.star --validate
```

Run it for real against a server. `--kwargs` is repeatable, one parameter per flag:

```bash
runzero script --filename tactical-rmm/tactical-rmm.star \
  --kwargs url=https://api.example.com \
  --kwargs api_key=YOUR_API_KEY \
  --kwargs monitoring_type=server \
  --kwargs extract_software=true \
  --kwargs software_agent_limit=25 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./tacticalrmm-out --overwrite
```

`--output` writes the emitted assets to a directory; `--overwrite` replaces it on a re-run. Without `--output` the assets are summarized to the log and discarded, which is usually what you want while iterating.

**One caveat on `--kwargs`, and it is silent when it bites.** The flag parses `key=value` pairs as CSV, so a value that contains **both** an `=` and a comma is split at the comma and the remainder becomes a parameter the integration never declared — which it then rejects by a name nobody set. A value with a `=` alone, or a comma alone, is fine. Tactical RMM API keys are alphanumeric, so this does not affect `api_key`; it is worth knowing before you paste an awkward value into any integration.

The same script also runs under the `scan` command, as the `custom-integration` probe. That is the shape the platform itself uses, and it is the way to exercise the script exactly as a scheduled task will:

```bash
runzero scan --probes custom-integration \
  --custom-integration-id 11111111-2222-3333-4444-555555555555 \
  --custom-integration-script-source "$(cat tactical-rmm/tactical-rmm.star)" \
  --custom-integration-script-kwargs '{"url":"https://api.example.com","api_key":"YOUR_API_KEY"}'
```

Three things about that form, all verified against the scanner rather than assumed:

- **`--custom-integration-id` is required.** Without it the probe disables itself at startup with `disabling probe due to missing custom integration ID` and the scan completes having run nothing. Any UUID works for a local run; use the console's real integration UUID when the result is meant to reach a task.
- **`--custom-integration-script-kwargs` takes a JSON object** and that is the form to use. It is parsed as JSON first and only falls back to space-delimited `key=value` pairs if the JSON parse fails, so the JSON form is immune to the `=`-in-value problem described above.
- `scan` drives a terminal UI and needs a TTY; redirect through `script -q /dev/null` if you are running it from somewhere that has none.

## Asset identity

- Target entity: one endpoint running the Tactical RMM agent — a physical or virtual machine, on Windows, Linux, or macOS.
- Source ID field: `agent_id`, present on every row of `GET /agents/` and the key `GET /agents/{agent_id}/` is addressed by.
- Documentation evidence: `agent_id` is generated server-side at registration by `GenerateAgentID` as 40 random letters (`[a-zA-Z]{40}`, no digits) and stored on the agent, which replays it on every check-in. The URL routing reinforces that it is the natural key: the detail route's path converter uses the regex `[^/]{20}[^/]+`, so an identifier shorter than 21 characters does not route at all.
- Uniqueness scope: one Tactical RMM server and its database. The value is 40 random letters from a 52-character alphabet, so a collision across two servers is not a practical concern, but the id means nothing outside the server that issued it and carries no tenant information of its own.
- Cardinality: one agent per id, and one machine per agent. `GET /agents/` returns one row per agent with no duplication.
- Stability: preserved across rename, IP change, reboot, OS upgrade, and agent auto-update, because the value lives in the agent's configuration and is replayed rather than recomputed. **Replaced** when the agent is uninstalled and reinstalled, when the machine is reimaged, or when a VM is cloned and the clone re-registers.
- Reuse behavior: not reused. Ids are randomly generated per registration and are never recycled to a different machine, so a stale id goes dead rather than pointing somewhere new.
- Presence: always present on the list view.
- Final runZero ID: `tacticalrmm:<api-hostname>:<agent_id>` — the hostname comes from the configured URL, lower-cased, and supplies the per-server scope the raw id lacks.
- Missing-ID behavior: skip. A row with no `agent_id`, and a row that is not an object at all, is logged and dropped. No identifier is invented; `new_uuid()` is not used anywhere in the script.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The agent id is authoritative within a server, while a laptop's address changes with every network it joins and a machine can be renamed without the agent noticing.
- **Reinstalling an agent forks the asset, and no flag prevents that.** A reinstall mints a new `agent_id`, which is a second foreign id from the same custom integration. runZero refuses, unconditionally and without consulting `matchBehavior`, to place two different foreign ids from one custom integration on a single asset — so the new registration becomes a new asset and the old one goes stale. This must be reconciled in runZero, by deleting the stale asset, rather than by changing integration settings.
- Verdict: **scoped authoritative.** Authoritative for the lifetime of an agent installation within one server, namespaced by the API hostname to stay safe across servers, and explicitly not durable across a reinstall.

### Notes

- **The agent list is one request and it is not paginated.** Tactical RMM configures Django REST Framework with no default pagination class, and the list view returns a plain array of every agent the key can see. On an MSP install that is a single response of tens of megabytes. The script therefore streams the response body with `jsonstream.iter_array` rather than decoding it whole, and reports each asset as it is built, so peak memory is one record rather than one estate.
- **That one request carries its own bounded retry.** Streaming needs the raw body, so the request uses the `http.get` builtin, and `retries` is a parameter of `get_json`/`post_json` only — so the script retries by hand: up to three attempts with a short backoff, repeated only on a missing response or a transient status (408/425/429/5xx). A GET is safe to repeat, and without the retry one transient 502 from a reverse proxy turned the whole run into a green zero-asset import. A persistent failure still ends the run with a logged error rather than importing a partial estate. The per-agent software requests use `get_json` and get its default three retries, including `Retry-After` handling on a 429.
- **`local_ips` is a string, not a list**, despite the plural name: the serializer joins the addresses with `", "`. The two platforms format it differently, and both shapes are handled. Windows filters through an IPv4 validator, so the addresses arrive bare and IPv6 is already gone. Posix joins the agent's own list straight through, so the addresses carry CIDR suffixes and include IPv6 — `203.0.113.54/24, fd70::253:70dc:fe65:143/64` is a real value. Prefix lengths and `%zone` suffixes are stripped before parsing.
- **`public_ip` is deliberately never placed on an interface.** It is the address the NAT gateway presents, so every agent behind one shares it; importing it as an address would correlate an entire office onto a single asset. It is kept as `tacticalrmm_public_ip`.
- **Loopback and APIPA are filtered before any interface is built.** An agent that cannot read its adapters reports `127.0.0.1`, and one that failed DHCP reports a `169.254/16` address; either would merge every affected host together. The platform drops loopback on its own but deliberately keeps link-local, so APIPA has to be filtered here. An agent left with no address and no usable hostname is skipped rather than imported as an asset nothing can ever merge with.
- **The agent's sentinel strings are treated as absent, not as data.** `error getting local ips`, `unknown make/model`, `error getting make/model`, `unknown cpu model`, `unknown disk`, `No graphics cards`, `error`, and `n/a` are all values the agent sends in place of a reading it could not take. Importing any of them would put the same false model on every affected asset, so each is mapped to empty. The raw `operating_system` string is always kept as an attribute regardless of how it parsed.
- **OS parsing.** The agent builds `operating_system` itself, differently per platform. Windows produces `Windows 10 Pro, 64 bit v22H2 (build 19045.3324)`, which is split at the comma into `os` with the release and build recombined into `osVersion`. Posix produces `<platform> <platformVersion> <kernelArch> <kernelVersion>`, and the split is made at the first token that looks like a version rather than at the first space — the platform name is not always one word, and `Rocky Linux 9.3 x86_64 5.14.0-362.el9.x86_64` must yield `Rocky Linux` and `9.3`, not `Rocky`.
- **No MAC addresses are imported, because the API does not carry any.** `AgentTableSerializer` has no MAC field, and neither does the detail serializer; the closest thing is the raw WMI dump, which is Windows-only. Assets therefore correlate on hostname and address alone.
- **Software is off by default** and costs one request per agent. `software_agent_limit` bounds the fan-out; agents past the limit are imported without software and the number skipped is logged. The endpoint is `GET /software/{agent_id}/` — note that `/agents/{agent_id}/software/` does **not** exist; only `checks/`, `tasks/`, and `pendingactions/` are aliased under the agent path. The response is genuinely polymorphic: an agent with a record answers `{"id", "agent", "software": [...]}`, and an agent without one answers `200` with a bare `[]`, which Tactical RMM's own test suite asserts. Both shapes are handled. Software is capped at 99 records per asset.
- **`cpe23` is left unset on every Software record.** `Software.cpe23` accepts only the CPE 2.2 application URI binding (`^cpe:/a:`), and Tactical RMM publishes no CPE of any kind, so there is nothing to put there that would not be invented.
- **Software is Windows-only.** Posix agents never populate the list, so enabling software import on a Linux-heavy estate costs a request per agent and returns nothing.
- **No vulnerabilities are imported.** Tactical RMM tracks Windows Update patch state, and a pending patch is not a CVE. Nothing here is presented as a `Vulnerability`; `tacticalrmm_patches_pending` carries the signal instead.
- No ports or services are imported. Tactical RMM is an agent-based management source and observes no listening sockets.
- **`total_ram` and the disk list are not imported**, though they look like they should be. Neither is on the list serializer — `total_ram`'s absence was reported upstream as issue #1978 — and the only way to get them is the detail endpoint, one request per agent, whose response also embeds the full WMI dump and the entire `zoneinfo` timezone list. That is a poor trade for two fields. See Future.
- **`checks` on the list view is read from a Redis cache** populated by a periodic task, so on a cold cache it reports zeros rather than real counts. The values are imported as attributes and should be read as indicative.
- Rate limiting: the stable API publishes no documented rate limit and returns no `Retry-After`. The cost that matters is the size of the single agent-list response.
- **Deliberately not built against the beta API.** `/beta/v1/agent/` does offer pagination and filtering, but it is gated off behind `BETA_API_ENABLED` (a separate setting from `SWAGGER_ENABLED`, which is what gates the OpenAPI schema), its detail route keys on the integer primary key rather than `agent_id`, and its queryset skips the role scoping the stable API applies. Building on it would make the integration depend on a setting most deployments never turn on.
- This integration was validated against local fixtures and the vendor's own serializers and test data, **not against a live Tactical RMM server**. The response shapes in `tests/fixtures/` follow `AgentTableSerializer`'s field list, a user-captured `GET /agents/` response from upstream issue #1978, and the project's own `test_data/software1.json`.

## Future

- **Per-agent detail as an opt-in enrichment.** `GET /agents/{agent_id}/` adds `total_ram`, the mounted-disk list, the service list, `mesh_node_id`, and the full `wmi_detail` blob. A future revision could offer it behind the same style of cap that bounds software today. The reason to be careful is the response size: no `.defer()` is applied, so every response ships the whole WMI dump plus roughly 600 timezone strings, which makes a per-agent fan-out expensive on a large estate.
- **MAC addresses from `wmi_detail`.** The Windows WMI dump contains the adapter list, which would give Windows agents a MAC and therefore a much stronger correlator than hostname and address alone. It is only reachable through the detail endpoint, and only on Windows, so it belongs with the item above.
- **Services as runZero services.** The detail endpoint's `services` array lists Windows services with their state and start mode. These are not listening sockets, so they should not become `Service` records with ports; the honest mapping is a software-style inventory or a set of attributes, and it is worth doing only alongside the detail-endpoint work.
- **Client and site as runZero sites.** `GET /clients/` returns each client with its sites nested, and every agent row already carries `client_name` and `site_name`. Mapping a Tactical RMM client onto a runZero site or organization would let an MSP keep one credential and still land assets in the right place, rather than running one task per client.
- **Agent health as a coverage signal.** The pairing worth having is not more fields but the gap: assets runZero discovers that Tactical RMM has no agent on are unmanaged endpoints, and agents whose `status` is `overdue` are stale. Both fall out of the imported `tacticalrmm_status` and `tacticalrmm_last_seen` and the presence or absence of the `tacticalrmm` custom-integration tag, with no additional API surface.
- **The bundled MeshCentral server.** A standard Tactical RMM install ships MeshCentral on the `mesh.` subdomain and every agent row carries a `mesh_node_id` on the detail view. MeshCentral holds deeper hardware inventory — BIOS, motherboard, memory, disks, NICs — but exposes it only over a WebSocket control channel, which this runtime has no transport for. See the MeshCentral notes in `OPEN-NEXT.md`.

## API documentation

- API access, the `X-API-KEY` header, key creation under Settings → Global Settings → API Keys, and the warning that trailing slashes matter: <https://docs.tacticalrmm.com/functions/api/>
- Install topology and the `rmm.` / `api.` / `mesh.` subdomain split: <https://docs.tacticalrmm.com/install_server/>
- `AgentTableSerializer` and `AgentSerializer` — the authoritative field lists for the list and detail views: <https://github.com/amidaware/tacticalrmm/blob/master/api/tacticalrmm/agents/serializers.py>
- `GetAgents` and the `detail`, `monitoring_type`, `site`, and `client` query parameters: <https://github.com/amidaware/tacticalrmm/blob/master/api/tacticalrmm/agents/views.py>
- The `Agent` model, including the `local_ips`, `cpu_model`, `physical_disks`, and `make_model` properties and their sentinel values: <https://github.com/amidaware/tacticalrmm/blob/master/api/tacticalrmm/agents/models.py>
- `APIAuthentication`, the class that reads `HTTP_X_API_KEY` and binds the request to the key's user: <https://github.com/amidaware/tacticalrmm/blob/master/api/tacticalrmm/tacticalrmm/auth.py>
- `GetSoftware` and `InstalledSoftwareSerializer`, and the test that asserts a bare `[]` for an agent with no software record: <https://github.com/amidaware/tacticalrmm/tree/master/api/tacticalrmm/software>
- `osString()` in the agent, the source of both `operating_system` formats: <https://github.com/amidaware/rmmagent>
- A user-captured `GET /agents/` response, and the report that `total_ram` is absent from the list view: <https://github.com/amidaware/tacticalrmm/issues/1978>

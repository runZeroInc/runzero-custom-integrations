# Custom Integration: Home Assistant

Imports the network-attached hardware a Home Assistant install knows about: IoT
devices in its **device registry** that carry a MAC address, and the network
clients its **`device_tracker`** entities report. Access points, cameras, smart
plugs, printers, TVs, thermostats, phones — much of which answers an active scan
with nothing at all, and is therefore invisible to runZero any other way.

The awkward part is worth stating up front, because it shapes everything else.
Home Assistant's REST API exposes **entities, not devices**. `GET /api/states`
returns every entity with every attribute — automations, scripts, helpers, the
sun, the weather forecast, one row per sensor reading — and on a mature install
the overwhelming majority of that is not a device and never will be. The device
registry, which is the part holding a manufacturer, a model, a firmware version
and a MAC, has **no REST endpoint in any release**:
`config/device_registry/list` is a WebSocket command, and there is no WebSocket
transport available to a custom integration.

So this integration reads the registry the only way REST allows — by asking Home
Assistant to render a **Jinja template** server-side that walks the registry and
emits JSON. That is not a trick; `POST /api/template` is a documented endpoint
and `device_attr` a documented template function. But it does mean the registry
read requires an administrator token, and it is why the script degrades to
`device_tracker` entities alone when the render is refused.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer with network access to the Home Assistant HTTP front end, by default **TCP 8123**, over `http` or `https` depending on what the site put in front of it. Prefer an IP address or a real DNS name over `homeassistant.local`: that name resolves over mDNS, which is frequently slow and sometimes does not resolve at all from a different subnet.

## Home Assistant requirements

- The **`api` integration** must be loaded. It is not listed among the integrations `default_config` enables, but it is a hard dependency of `frontend`, so every install running the web UI already has it. Home Assistant's own REST documentation puts it plainly: "If you are not using the frontend in your setup then you need to add the api integration to your `configuration.yaml` file." For a headless install, add:

  ```yaml
  api:
  ```

- A long-lived access token belonging to an **administrator** account. This is not a recommendation, it is a requirement, and it bites twice — both confirmed from Home Assistant's own source rather than from documentation, because the documentation does not say either:
  - `APITemplateView.post` in `homeassistant/components/api/__init__.py` carries a `@require_admin` decorator. A non-admin token cannot render a template at all, so the device registry is simply unavailable to it.
  - `APIStatesView.get` branches on `user.is_admin`. An admin gets every state; anyone else gets only the entities that pass `user.permissions.check_entity(entity_id, POLICY_READ)`. A non-admin token therefore returns a **filtered entity list with no error at all** — the run succeeds and quietly imports a subset, which is far worse than a refusal.
- **Home Assistant 2021.11 or newer** for `device_attr`, which is the function the registry template is built on. Later releases added fields the template asks for — `serial_number` and `model_id` in particular — but that costs nothing on an older install: `device_attr` "returns `None`" when "the device or attribute doesn't exist" rather than raising, so an older Home Assistant renders the same JSON with nulls in those slots. **The `CONFIG` parameter description claims a floor of 2023.9; that specific version was not confirmed**, and the evidence found points at 2023.11 for `serial_number` and later still for `model_id`. Treat 2021.11 as the real floor and expect thinner data below roughly 2024.
- No add-on, no plugin, and no configuration change beyond the above. This integration only reads.

### Creating the credential in Home Assistant

1. Sign in to Home Assistant **as an administrator**. Check the account first:
   **Settings → People**, open the user, and confirm it is marked as an
   administrator. A token cannot be more privileged than the account that
   minted it.
2. Click your user name or avatar at the **bottom of the left sidebar** to open
   your profile, then choose the **Security** tab. Home Assistant's own
   authentication documentation refers to this as **User profile → Security**
   and notes that "These settings only affect your own account."
3. Scroll to the bottom, to **Long-Lived Access Tokens**, and choose
   **Create Token**.
4. Give it a name — `runZero` — and confirm.
5. **Copy the token now.** It is displayed exactly once: "The access token
   string is not retained within Home Assistant itself, so users must securely
   store it when created." If you lose it, delete it from this same screen and
   mint another.
6. The token is valid for **10 years** and carries the permissions of the account
   that created it. Revoke it from the same Security tab if it is ever exposed.
7. Confirm the token from the Explorer host. The first call proves
   authentication; the second is the one that actually proves the token is an
   administrator's, because it exercises the `@require_admin` path:

   ```bash
   curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.FAKE-TOKEN-VALUE.FAKE' \
     'https://homeassistant.example.com:8123/api/states' | head -c 300

   curl -s -X POST \
     -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.FAKE-TOKEN-VALUE.FAKE' \
     -H 'Content-Type: application/json' \
     -d '{"template":"{{ states | map(attribute=\"entity_id\") | map(\"device_id\") | reject(\"none\") | unique | list | count }}"}' \
     'https://homeassistant.example.com:8123/api/template'
   ```

   The second call returns a bare number — how many devices the registry holds —
   on an admin token. A non-admin token is refused, and Home Assistant also logs
   `Login attempt or request with invalid authentication from <ip>. Requested
   URL: '/api/template'` on the server side, which is the fastest way to confirm
   the diagnosis from the Home Assistant end.

**Home Assistant has no service accounts and no scoped tokens.** There is no
read-only role, no per-integration credential, and no way to narrow a token to
the registry. An administrator token can do everything an administrator can do,
including calling services that turn things on and off. This integration only
issues `GET /api/states`, `GET /api/config/config_entries/entry`, and
`POST /api/template`, but the credential itself is unavoidably broad — treat it
accordingly, and prefer a dedicated administrator account created for runZero so
the token can be revoked without disturbing a person's login.

## Steps

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Home Assistant").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Home Assistant URL** (`url`): base URL including the port, for example `https://homeassistant.example.com:8123`. The default port is 8123. Home Assistant is self-hosted, so there is no default host.
   - **Long-lived access token** (`api_token`): the token from step 4 above, from an administrator account.
   - **Collect the device registry** (`collect_device_registry`): optional, default enabled. This is where manufacturer, model, firmware version, serial number, and IoT MAC addresses come from.
   - **Collect device trackers** (`collect_device_trackers`): optional, default enabled. These are the network clients a router, UniFi controller, or nmap scan told Home Assistant about.
   - **Include absent trackers** (`include_away`): optional, default enabled. Turn it off to import only what is currently on the network.
   - **Mine addresses from all entities** (`mine_entity_addresses`): optional, default **disabled**. See the note below before turning it on.
   - **Devices per template request** (`device_page_size`): optional, default 100, minimum 1, maximum 500.
   - **TLS options** (`tls_*`) and **HTTP options** (`http_*`): set these if Home Assistant is behind a self-signed certificate, which is the common case for a self-hosted instance.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Presence state changes constantly, but the registry does not, so hourly is generous and daily is usually enough.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from Home Assistant.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- Search for everything this integration touched with `custom_integration:home-assistant`.
- Split the two asset kinds with `tag:device-registry` and `tag:device-tracker`.
- Provenance is the most useful tag here: `tag:integration:unifi`, `tag:integration:esphome`, `tag:integration:zwave_js`, `tag:integration:reolink` tell you *how* Home Assistant learned about the device, and therefore how much to trust the rest of the record. Areas become `tag:area:living_room` and the registry manufacturer becomes `tag:vendor:Ubiquiti Inc.`.
- Trackers add `tag:source:router`, `tag:presence:home` or `tag:presence:not_home`, and `tag:ssid:HomeNet` where the reporting integration supplies an SSID.
- Everything imported is searchable under the `hass_` prefix — `hass_integration:brother`, `hass_sw_version`, `hass_serial_number`, `hass_area_id`, `hass_entity_count`, `hass_other_connections`. Raw tracker attributes land under `hass_attr_`, so UniFi's per-client fields are `hass_attr_essid`, `hass_attr_ap_mac`, `hass_attr_vlan`, and `hass_attr_oui`.

## Running it from the command line

The runZero CLI runs a script directly, which is the quickest way to confirm a
token and see what a real install returns. Each `CONFIG` parameter is a
`--kwargs key=value` pair:

```bash
runzero script --filename home-assistant/home-assistant.star \
  --kwargs url=https://homeassistant.example.com:8123 \
  --kwargs api_token=eyJhbGciOiJIUzI1NiJ9.FAKE-TOKEN-VALUE.FAKE \
  --kwargs device_page_size=25 \
  --kwargs include_away=false \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output /tmp/home-assistant-run --overwrite
```

`--output` writes the serialized assets so you can inspect exactly what would be
imported; `--overwrite` lets you re-run into the same directory. The log line
this integration prints first is the one to read — `home-assistant: read 1843
entities, 6 of which carry an address (4 device trackers)` tells you
immediately whether this install has anything worth importing.

No parameter of this integration takes a value that can contain a comma, so the
usual `--kwargs` splitting caveat does not apply here.

To check only that the `CONFIG` block and the HTTP/TLS wiring are sound, without
touching a real install:

```bash
runzero script --filename home-assistant/home-assistant.star --validate
```

`python3 tests/run.py home-assistant` exercises the fixture scenarios in
`home-assistant/tests/fixtures/` against the real scanner — a full install with
entities that must be skipped and devices that must not be, and a paged registry
read.

To run it the way the platform does — as an integration task that uploads its
results — use the `scan` command with the custom integration flags.
`--custom-integration-id` is the UUID shown on the integration's page in the
console:

```bash
runzero scan --api-key "$RUNZERO_API_KEY" \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --custom-integration-script-kwargs 'url=https://homeassistant.example.com:8123,api_token=eyJhbGciOiJIUzI1NiJ9.FAKE-TOKEN-VALUE.FAKE'
```

Confirm the flag set with `runzero script --help` and `runzero scan --help` on
your own scanner build; it does change between releases.

## Asset identity

Two asset kinds, and **both are deliberately inert**: the id is emitted so runs
reconcile and `custom_integration:home-assistant` works, but it is never allowed
to find a merge candidate. This is the honest position for this source, and the
reasoning is the same for both kinds — a Home Assistant identifier means nothing
outside the one install that minted it.

### Device registry entries

- Target entity: one row of Home Assistant's device registry that is real, addressable network hardware. Rows whose `entry_type` is `service` are skipped, because those are the cloud account or hub an integration created rather than a thing on a network. Rows with neither a MAC nor a routable IP are skipped too.
- Source ID field: the registry entry's **`id`**, a 32-character hex string Home Assistant mints locally when the device is first seen.
- Documentation evidence: the device registry documentation describes `id` as the "Unique ID of device (generated by Home Assistant)". "Generated by Home Assistant" is the whole problem — it is not a serial number, not a vendor id, and not anything the device itself knows.
- Uniqueness scope: one Home Assistant install, and the id is namespaced on the host taken from the configured URL to say so.
- Cardinality: one asset per registry row. A physical device produces many *entities* and exactly one registry row, which is precisely why the registry is worth the template gymnastics.
- Stability: stable across restarts, across renaming the device, and across renaming its entities. It changes if the integration is removed and re-added, which re-discovers the device under a fresh id.
- Reuse behavior: not recycled in practice — it is random — but the question barely matters given the id is not used for matching.
- Presence: required; a row without one is skipped silently.
- Final runZero ID: `home-assistant:<hass-host>:device:<device-id>`, for example `home-assistant:homeassistant.example.com:device:b1f2c3d4e5f60718293a4b5c6d7e8f90`.
- Missing-ID behavior: skipped. Nothing is invented and `new_uuid()` is never used.
- Match behavior (set once in `CONFIG`): **`no-id-match no-id-break`** — the literal string `CONFIG` declares. The platform records it expanded, as `no-id-match no-id-break mac-match mac-break ip-match ip-break name-match name-break`. Read that carefully: the id neither matches nor breaks, and the three real correlators are all left at their defaults, so a **conflicting** MAC, address, or hostname will disqualify a merge.
- Verdict: **install-local, deliberately inert.** In practice this integration contributes *enrichment keyed on a MAC address* — manufacturer, model, firmware, serial, area, and provenance attached to something runZero already found — rather than a standalone inventory.

### `device_tracker` entities

- Target entity: one `device_tracker` entity that reports a MAC or a routable IP. These are the clients a router, UniFi controller, or nmap integration told Home Assistant about, and they usually have no registry entry of their own.
- Source ID field: the **`entity_id`**, for example `device_tracker.johns_iphone`.
- Documentation evidence: the entity id is the key every REST and WebSocket call addresses an entity by, and it is present on every state object.
- Uniqueness scope: one Home Assistant install; namespaced on the host as above.
- Cardinality: one asset per unaddressed-by-a-device tracker. Two integrations reporting the same client — a router integration and a UniFi controller both seeing one phone — are collapsed on the MAC before anything is emitted.
- Stability: stable in the entity registry across restarts and across friendly-name changes. It is not stable against an operator editing the entity id itself, which the UI permits. Because the id never drives a merge, that costs a re-key rather than a duplicate.
- Reuse behavior: an entity id can be freed and reassigned by hand. Again, inert.
- Presence: always.
- Final runZero ID: `home-assistant:<hass-host>:entity:<entity-id>`, for example `home-assistant:homeassistant.example.com:entity:device_tracker.johns_iphone`.
- Missing-ID behavior: an entity with no `entity_id` is never indexed; one with no MAC and no routable IP is never indexed either, so it cannot reach this point.
- Match behavior: **`no-id-match no-id-break`**, identical to the above and for the same reason — one CONFIG-level declaration covers both asset kinds.
- Verdict: **install-local, deliberately inert.**

**Two honest caveats about this identity story.** First, a tracker's only
correlator is frequently a MAC, and modern phones present a **randomized,
per-network MAC** that rotates, so such an asset will fork over time. That is a
property of the data, not of the script, and no id scheme fixes it. Second,
because Home Assistant ids mean nothing elsewhere, an imported device runZero has
never seen on the network sits as a lone asset until something scans it — which
is why the script skips devices with no MAC and no IP outright, rather than
importing rows that could only ever sit alone.

## Notes

### What is imported

| Endpoint | Gated by | What it gives |
|---|---|---|
| `GET /api/states` | always | Every entity; the source of tracker MACs, IPs, and hostnames |
| `GET /api/config/config_entries/entry` | `collect_device_registry` | Integration provenance: domain, title, and state per config entry |
| `POST /api/template` | `collect_device_registry` | One page of the device registry, rendered as JSON |

| runZero | Home Assistant |
|---|---|
| `id` | registry `id`, or the `entity_id`, namespaced by host |
| `hostnames` | tracker `host_name`/`hostname`, `friendly_name`, and the device name — each only if it looks like a hostname |
| `networkInterfaces` | registry `connections` `("mac", …)` tuples, the IP inside `configuration_url`, and tracker `ip`/`mac` attributes |
| `manufacturer` | registry `manufacturer`, or a tracker's `oui` when UniFi supplies one |
| `model` | registry `model` |
| `deviceType` | derived from the integration domain, or from a `camera` entity |
| `lastSeenTS` | tracker `last_updated`, falling back to `last_changed` |
| `tags` | kind, integration domain, area, vendor, source type, presence, SSID |
| `customAttributes` | everything else, under `hass_` |

No `Service`, `Software`, or `Vulnerability` records are emitted. Home Assistant
inventories none of those. `sw_version` is kept as `hass_sw_version` rather than
mapped to `osVersion`, because a thermostat's firmware version is not an
operating system release and pairing it with an absent `os` would produce a
misleading field.

### Reading the device registry through a template

Three things about the template are load-bearing, and all three come from real
constraints rather than preference.

**There is no function that lists every device.** Home Assistant exposes
`device_id(entity_id)`, `device_attr(id, attr)`, and `device_entities(id)`, but
nothing that enumerates the registry. So the device set is derived by mapping
every entity through `device_id` and de-duplicating:

```jinja
{% set dids = states | map(attribute='entity_id') | map('device_id')
   | reject('none') | unique | list %}
```

A consequence worth knowing: a registry device with **no entities at all** is
invisible to this integration, because there is no entity to map through.

**The render is capped and a larger render is a 400.** `MAX_TEMPLATE_OUTPUT` is
262,144 characters — 256 KiB — and exceeding it raises `Template output exceeded
maximum size of 262144 characters`, which the REST view catches and returns as
`400` with a JSON body carrying a `message`. So the registry is **paged** by
slicing `dids[start:end]`, `device_page_size` rows at a time, and the walk stops
on the first page shorter than requested. The `paged` fixture asserts the slices
themselves — `dids[0:2]`, then `dids[2:4]`, then `dids[4:6]`, and no `dids[6:8]`
after a short page.

**Rows are built by concatenation, not `append`.** Home Assistant renders
templates in Jinja's immutable sandbox, where `list.append` raises `SecurityError:
access to attribute 'append' of 'list' object is unsafe`. The documented
workaround, and what the template does, is a `namespace` reassigned with
`ns.rows = ns.rows + [ … ]`.

Two smaller details: `entry_type`, `disabled_by`, and `configuration_url` are
piped through `| string` because they are enums and the JSON serializer refuses
an enum; and `connections` and `identifiers` are Python **sets of tuples**, which
`to_json` cannot serialize, so both are `| list`-ed first and the tuples arrive as
two-element arrays.

The endpoint answers asymmetrically — a successful render is raw text with a
`text/plain` content type, a failure is a JSON object — so the status decides how
the body is read, and the text is checked for an opening bracket before
`json_decode` sees it, because `json_decode` aborts the script on input it cannot
parse.

### Integration provenance comes from a separate, undocumented endpoint

Which integration a device came from is the single most useful piece of context
Home Assistant can add, and it is read from
`GET /api/config/config_entries/entry`, which returns every config entry with its
`domain`, `title`, and `state`. **This endpoint is not in the published REST
documentation.** It is a real `HomeAssistantView` registered by the `config`
integration, which `frontend` depends on, so it is present wherever the UI is —
but it is undocumented and a future release could change it without a deprecation
note. The run continues without integration names if it fails, and says so.

Reading it here rather than through `config_entry_attr` in the template means one
request instead of three template lookups per device, and it yields `title` and
`state`, which `config_entry_attr` does not. (The script's own comment justifies
the choice by saying `config_entry_attr` raises on an unrecognized attribute; the
current vendor documentation says it returns `None` instead. The choice is still
the better one, for the reasons just given.)

**Whether this endpoint requires an administrator was not established.** Its
`get` handler carries no `@require_admin` decorator in current core, unlike the
template view, but the point is moot in practice — the template endpoint already
forces an admin token.

### Only some entities are read, and only some connections become MACs

`/api/states` is the one unbounded response Home Assistant serves: every entity,
every attribute, one array, no pagination and no server-side filter. A mature
install is several megabytes and decoding it into Starlark values costs several
times the wire size, so the raw body is **streamed** with `jsonstream.iter_array`
and only one entity is live at a time. The index that survives holds only
entities carrying a MAC or a routable IP, so it is proportional to the number of
addressable devices rather than to entity count. Because `iter_array` raises —
and a raise aborts the whole script, since Starlark has no exceptions — the body
is checked for a leading `[` first, or an HTML login redirect from a reverse
proxy would end the run outright. Streaming also means the raw `http.get` verb,
which takes no retry budget, so this call gets a single attempt.

**Mine addresses from all entities** is off by default and should usually stay
off. Reading `ip`, `ip_address`, `mac`, and `mac_address` from entities outside
the `device_tracker` domain sounds harmless, but those attribute names are not a
convention — an integration is free to put a *remote service's* address in one,
and that address would then be attached to the wrong asset.

On the registry side, only the `mac` connection type becomes a network interface.
A Bluetooth `BD_ADDR` is six bytes and normalizes exactly like an Ethernet MAC,
and a Zigbee IEEE address is eight; neither is an address any network scan will
ever observe, so importing them as MACs would invent correlations. They are kept
as `hass_other_connections` instead. Loopback, unspecified, and link-local
addresses never reach an interface either, and both matter here specifically:
integrations report `127.0.0.1` for anything running on the Home Assistant host
itself, and a tracker whose DHCP lease has lapsed reports an APIPA address.

### Names are filtered hard

Home Assistant names are display names — "Kitchen Motion Sensor", "John's iPhone"
— far more often than hostnames. Anything containing a space, anything longer
than 253 characters, and any bare IP address is refused rather than imported as a
placeholder. A device whose name does not survive carries no hostname, which is
correct; a fabricated one would be a false merge signal.

### Entity claiming, and why a duplicate here would be permanent

The registry pass records every entity id belonging to every registry row it saw,
and the tracker pass skips those. Without it, a printer with both a registry
entry and a `device_tracker` entity would produce **two** assets — and because two
foreign ids from one integration can never merge onto each other, that duplicate
would be permanent rather than self-healing. Claiming happens for every row the
registry returned, including rows the script then skipped as `service` entries or
as unaddressed, on the reasoning that a device the registry already accounts for
should not reappear through a side door. Trackers are also collapsed on MAC,
because a router integration and a UniFi controller reporting the same client are
reporting one device.

### Timestamps

Home Assistant renders timestamps with `datetime.isoformat()` on a UTC-aware
value, which produces a `+00:00` offset and **never** a `Z`, and which drops the
fractional part entirely when the microsecond happens to be zero. All three
forms have to match the guard or `parse_time` aborts the run. Parsed values are
clamped to now, because the platform rejects the entire `ImportAsset` — not just
the field — when a timestamp is in the future. Only trackers get a `lastSeenTS`;
a registry entry records no observation time, so inventing one would be a lie.

### Verification status

Verified against the fixture scenarios in `home-assistant/tests/fixtures/` and
against Home Assistant's documentation and core source. It has **not** been run
against a live Home Assistant install.

Established from core source rather than documentation, because the docs are
silent on all three: the `@require_admin` decorator on `APITemplateView.post`;
the `user.is_admin` branch in `APIStatesView.get` that filters states for
non-admin users; and the absence of an admin decorator on
`ConfigManagerEntryIndexView.get`. Established from vendor documentation: the
long-lived token flow and its ten-year lifetime; `device_attr` returning `None`
for an unknown attribute; `config_entry_attr`'s supported attribute list; the
device registry field list and the `(connection_type, identifier)` tuple shape;
and the immutable-sandbox restriction on `list.append`. The 262,144-character cap
and its error text come from a core issue report plus the view's own exception
handling.

Not verified: the 2023.9 version floor asserted in `CONFIG`; whether
`/api/config/config_entries/entry` is reachable with a non-admin token in
practice; and the behaviour of `/api/states` on a genuinely large install, which
the fixtures approximate with eleven entities. There is no `empty` and no
`malformed` fixture here — only `happy` and `paged` — so the degraded paths, in
particular a 401 on `/api/states` and a 400 from an oversized render, are
covered by code reading rather than by test.

## Future

- **A WebSocket transport.** Everything awkward here dissolves if the runtime ever grows one: `config/device_registry/list`, `config/entity_registry/list`, and `config/area_registry/list` return the registries directly, typed, paginated by nothing because they are small, and without needing an admin-only template render. This is the single largest improvement available and it is a platform change, not a script change.
- **Area names instead of area ids.** Today an area arrives as `living_room`, its slug, because the device registry stores an `area_id`. The area registry holds the human name and the floor it belongs to. Over REST this needs a second template render; over WebSocket it is one more list call.
- **The `via_device` hub chain.** `via_device_id` says which hub routes a device's messages — which Zigbee coordinator, which Z-Wave stick, which bridge. It is imported as an attribute today but not resolved to the hub's own asset. Resolving it would give a genuine parent-child topology for the part of an estate that has no IP addresses at all.
- **Entity-derived device facts.** A device's entities frequently carry exactly the fields an inventory wants — an `update` entity holds installed and latest firmware versions, a `sensor` may hold uptime or signal strength. The entities are already indexed by device; reading a short allowlist of entity suffixes would add firmware currency without another request.
- **`GET /api/config` for install context.** Version, location name, unit system, and the loaded component list would let an operator see which Home Assistant an asset came from, and would make the version-floor warnings above concrete rather than advisory. It is one cheap request that is currently not made.
- **Presence history.** `GET /api/history/period/<timestamp>` returns state changes over a window, which would turn `presence:home` from an instantaneous reading into "seen on this network 4 times in the last week" — much more useful for deciding whether a tracker asset is a real resident device or a visitor's phone.
- **Skipping randomized MACs.** A tracker whose MAC has the locally administered bit set is very likely a per-network randomized address that will rotate. Tagging those, or optionally skipping them, would stop a phone from forking into a new asset every few weeks. This needs a deliberate decision, because some legitimate hardware sets that bit too.

## API documentation

- REST API reference — https://developers.home-assistant.io/docs/api/rest/. Source for `GET /api/states`, `GET /api/config`, `POST /api/template`, the `Authorization: Bearer` scheme, and the statement that a setup not using the frontend must add the `api` integration to `configuration.yaml`.
- Long-lived access tokens — https://developers.home-assistant.io/docs/auth_api/#long-lived-access-token. Source for the ten-year lifetime, the profile-page creation flow, and the fact that the token string is not retained by Home Assistant.
- Authentication — https://www.home-assistant.io/docs/authentication/. Source for the **User profile → Security** tab path.
- Permissions — https://developers.home-assistant.io/docs/auth_permissions/. Source for owner, administrator, and regular-user roles, and for the statement that certain APIs "will always be accessible to all users, but might offer a limited scope based on the permissions, like rendering a template".
- Device registry — https://developers.home-assistant.io/docs/device_registry_index/. Source for the registry field list, the `(connection_type, identifier)` tuple shape of `connections`, `CONNECTION_NETWORK_MAC`, and the `service` entry type.
- `device_attr` — https://www.home-assistant.io/template-functions/device_attr/. Source for the "available since 2021.11" floor and for the guarantee that an unknown attribute returns `None` rather than raising.
- `config_entry_attr` — https://www.home-assistant.io/template-functions/config_entry_attr/. Source for its six supported attributes and its `None`-on-unsupported behaviour.
- The `api` integration — https://www.home-assistant.io/integrations/api/. Confirms the `api:` configuration key.
- **Behaviour taken from source**, because it is documented nowhere: [`homeassistant/components/api/__init__.py`](https://github.com/home-assistant/core/blob/dev/homeassistant/components/api/__init__.py) for the `@require_admin` decorator on `APITemplateView.post`, the `user.is_admin` filtering in `APIStatesView.get`, and the 400-with-`message` error path; [`homeassistant/components/config/config_entries.py`](https://github.com/home-assistant/core/blob/dev/homeassistant/components/config/config_entries.py) for `ConfigManagerEntryIndexView` and its URL; and [`homeassistant/components/frontend/manifest.json`](https://github.com/home-assistant/core/blob/dev/homeassistant/components/frontend/manifest.json), which lists `api` and `config` among the frontend's dependencies.
- Template output limit — https://github.com/home-assistant/core/issues/137017, which reports the exact text `Template output exceeded maximum size of 262144 characters`.

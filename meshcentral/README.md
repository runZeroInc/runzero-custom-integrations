# MeshCentral — investigated, not viable as an integration today

**There is no integration script in this directory, deliberately.** This file records why, and what would have to change for one to be worth building.

MeshCentral was picked up from [`OPEN-NEXT.md`](../OPEN-NEXT.md) entry 15, which describes it as having "a limited REST surface (`/api/v1/login`, `/api/v1/devices`)" and advises prototyping REST before considering an SSH fallback. That prototype was attempted. **The REST surface described does not exist**, and neither does any other one.

## Verdict

| Question | Answer |
| --- | --- |
| Is there an HTTP API that lists devices? | **No.** Not at any version. |
| Do `/api/v1/login` and `/api/v1/devices` exist? | **No.** The claim in `OPEN-NEXT.md` is not correct. |
| Can the WebSocket control channel be used? | **No.** This platform has no WebSocket module. |
| Is the `runzero.ssh` + `meshctrl` fallback viable? | **Possible, but not yet worth building.** See below. |
| Recommendation | **Defer.** Revisit when the conditions below are met. |

## Evidence

### 1. MeshCentral has no REST API at all

- `grep -cE "'/api|\"/api|api/v1"` over `meshctrl.js` at upstream `master` returns **0**. The same search over the complete route table in `webserver.js` returns **0**. There is no `/api/` prefix of any kind anywhere in the server.
- The only device-related plain-HTTP GET is `devicepowerevents.ashx`, which takes a single node id and returns a four-column power-state timeline (`UTC Time, Local Time, State, Previous State`). No hostname, no MAC, no OS, no hardware. It cannot enumerate devices and carries nothing an inventory needs.
- `webrelay.ashx` is not an API. Its plain-HTTP handler is a one-line stub that answers `Websocket connection expected`; the real handler is the WebSocket upgrade, and what it proxies is a TCP tunnel to a port on the *managed endpoint*, not server data.
- The entire `webserver.js` contains **three** `res.json()` calls: the web app manifest, custom icon upload, and custom icon delete.
- MeshCentral's own [Design and Architecture](https://docs.meshcentral.com/design/) documentation states that it makes almost no use of RESTful APIs and does almost everything over WebSocket.
- The maintainer, answering this exact question in [issue #1466](https://github.com/Ylianst/MeshCentral/issues/1466), says there is no way to add REST calls, and directs users to reimplement the WebSocket protocol or use `meshctrl.js`.

### 2. The control channel is WebSocket-only, and we have no WebSocket transport

Every authenticated operation goes through `wss://<server>/control.ashx`. `meshctrl.js` has no non-WebSocket code path: all three of its authentication modes (`--loginpass`, `--loginkey`, `--loginkeyfile`) terminate in `new WebSocket(...)`. The `x-meshauth` header and the login tokens minted by the `loginTokens` action are consumed only on the WebSocket upgrade — `PerformWSSessionAuth` takes a `ws` argument and is unreachable from a plain GET.

Per [`OPEN-NEXT.md` § Platform constraints](../OPEN-NEXT.md), the available transports are `http`/`requests`, `socket.tcp`/`udp`/`tls`, `runzero.ssh`, `runzero.smb`, `runzero.winrm`, `runzero.wmi`, and `runzero.sql`. There is no WebSocket module. Hand-rolling RFC 6455 framing over `socket.tls` is theoretically possible and is explicitly a last resort; it is not justified for one source.

One thing that *does* work: `POST /login` accepts urlencoded credentials and sets a `cookie-session` that genuinely authorizes later HTTP GETs. So the authentication half of a plain-HTTP integration is achievable. There is simply nothing to point it at.

### 3. The SSH fallback is real, but the data it depends on is not in the shipping release

`OPEN-NEXT.md` names `runzero.ssh` running `node meshctrl.js ListDevices --json` as the alternative. Two things were checked against the **official container image** `ghcr.io/ylianst/meshcentral:1.1.46`:

- **`meshctrl.js` does ship with the server**, at `/opt/meshcentral/meshcentral/meshctrl.js`. So the approach is mechanically possible on any host an operator can reach over SSH.
- **`ListDevices --details` is not available in that release.** Its `ListDevices` help lists only `--id`, `--group`, `--count`, `--json`, `--csv`, `--filter`, and `--filterid`. The `--details` flag is present at upstream `master` (`meshctrl.js:468`, dispatched at `:1406`) but not in 1.1.46.

That distinction is the whole argument. Plain `ListDevices --json` returns only the node documents — `_id`, `name`, `rname`, `host`, `ip`, `osdesc`, `meshid`, `groupname`, `conn` — with **no MAC addresses, no serials, and no hardware inventory**. It is thin enough that the resulting assets would correlate on hostname and a single address, which is roughly what a ping sweep already produces.

`--details` is what makes MeshCentral interesting. It issues one `getDeviceDetails` call for the whole estate — not N+1 — and joins each node document with its `sysinfo` and `netinfo` records, yielding a 49-column table including `macs`, `addresses`, `biosSerial`, `chassisSerial`, `productUuid`, `boardSerial`, `arch`, `osbuild`, and `totalMemory`. Those are exactly the correlation keys runZero wants. They are also not in the release most people are running.

### 4. Why this was not built anyway

Three reasons, in order of weight:

1. **The valuable output depends on an unreleased flag.** Building a parser against `--details` today means building against `master`. Building against plain `ListDevices --json` instead means shipping an integration whose assets carry no MAC and no serial.
2. **The output shape could not be verified end to end.** In the probe container, account creation failed and `meshctrl` could not authenticate, so no real device payload was ever observed. Every field name available is read from server source rather than from a response. `OPEN-NEXT.md` itself says: *"Prototype REST first; do not build the SSH path speculatively."* Writing a parser against a payload nobody has seen is that speculation.
3. **It is a different and much heavier credential.** Every other integration in this repository authenticates with an API token scoped to one product. This one would need **interactive shell access to the management server**, plus a MeshCentral administrator login passed on the command line, plus `node` on the path. That is a large privilege escalation to ask of an operator, and it deserves a clearly better payoff than "hostname and one IP".

A fresh MeshCentral also has no enrolled devices, so obtaining a realistic payload requires installing agent software on real hosts. That was out of scope for this investigation.

## What would make this worth revisiting

Any one of these changes the calculation:

- **`--details` reaches a stable MeshCentral release** and the 49-column output can be captured from a real server with enrolled agents. This is the most likely trigger and the one to watch — the flag is already on `master`.
- **A WebSocket module is added to the Starlark runtime.** MeshCentral becomes straightforward immediately, and so do TrueNAS 25.04+ and Uptime Kuma, which have the same problem. Three sources unblocked by one platform capability is a much better argument than one integration.
- **MeshCentral adds a documented REST surface.** The maintainer has declined this, so it is unlikely without a change of position.

If the first of these happens, the integration should look like this: `runzero.ssh` to the MeshCentral host, `"validationMode": "compile"` in `CONFIG` (as [`linux-ssh/`](../linux-ssh/) does, since there is no HTTP wiring to smoke-test), one `node meshctrl.js ListDevices --details --csv` invocation, and `csv.read_all` over the result. `--csv` is preferable to `--json` because the column set is flat and fixed, so a schema change is visible immediately rather than silently dropping nested fields. Identity should key on `productUuid` where present and fall back to `id` (the MeshCentral node id, `node/<domain>/<hash>`), never on a MAC. Note that MeshCentral scrubs credentials server-side before export — `CloneSafeNode` strips them and BitLocker recovery keys are dropped — so the output is safe to ingest.

## Suggested corrections to `OPEN-NEXT.md`

Entry 15 should be amended; it is currently misleading in a way that would cost the next person the same investigation:

1. Delete the `/api/v1/login`, `/api/v1/devices` claim. Those routes do not exist at any version.
2. Delete "Prototype REST first" — there is no REST to prototype.
3. Change "primary control channel is WebSocket" to "**only** control channel is WebSocket".
4. If the SSH path is retained, specify `ListDevices --details --csv` rather than bare `ListDevices --json`, and note that `--details` requires a build newer than 1.1.46.
5. Reclassify the effort. This is not "REST is thin", it is "no REST at all", which changes the integration's shape — an SSH credential and a server-side CLI dependency — and probably its priority.

These edits were **not** made here, because `OPEN-NEXT.md` is outside this change's scope.

## References

- MeshCentral source: https://github.com/Ylianst/MeshCentral
- `meshctrl.js` at `master` (where `--details` lives): https://github.com/Ylianst/MeshCentral/blob/master/meshctrl.js
- Design and architecture — "almost everything is done using WebSocket": https://docs.meshcentral.com/design/
- Maintainer on the absence of REST: https://github.com/Ylianst/MeshCentral/issues/1466
- MeshCtrl documentation: https://docs.meshcentral.com/meshctrl/
- Official container image used for the probe: `ghcr.io/ylianst/meshcentral:1.1.46`
- Python client, for the WebSocket protocol shape: https://pylibmeshctrl.readthedocs.io/

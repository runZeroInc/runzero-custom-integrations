# Custom Integration: Miradore

Imports managed devices from a Miradore site: hardware, operating system,
installed applications, the assigned user, and the addresses Miradore holds for
each device.

## Which Miradore API this uses, and why

**This integration reads Miradore API v1, not v2.** That is not a preference —
v2 cannot list devices.

Miradore ships two APIs, and they do different jobs:

| | API v1 | API v2 |
|---|---|---|
| Purpose | Reporting / export | Device management |
| Can list devices | **Yes** | **No** |
| Payload | XML | JSON |
| Auth | `auth=<key>` in the query string | `X-API-Key` header |

The v2 [OpenAPI document](https://online.miradore.com/swagger/v2/swagger.json)
declares no collection `GET` for devices at all. Its only device reads are
`/api/v2/Device/{id}/Location`, `/api/v2/Device/{id}/CustomAttribute`, and
`/api/v2/Device/SuspendedDevices`, and its `Device` schema appears **only** as
the request body of `POST /api/v2/Device` and `PATCH /api/v2/Device/{id}` — never
as a response. That schema also carries no OS, serial number, MAC, IP, or
software field, and nothing anywhere in the v2 document accepts a paging
parameter.

Miradore's own v2 documentation says so directly:

> The device ID can be retrieved using Miradore API v1, as an attribute of the
> Device item.

So an integration written against v2 has no endpoint to enumerate from and would
import zero assets. Everything below is v1, whose contract comes from the
**Miradore API Specification** PDF linked from
[Programmer's guide to API v1](https://www.miradore.com/knowledge/integrations/programmers-guide-to-api-v1/)
(version 1.14 was used here). Every attribute the script requests is from that
document's Appendix 2.

v2 remains the right API for *acting* on a device — lock, wipe, reboot, lost
mode. This integration never writes, so it does not use it.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Miradore requirements

- A Miradore site with the **API feature activated**.
- An **authentication key** with read access.
- The **site name**, as shown in the Miradore console.

### Creating the authentication key

1. In the Miradore console, go to **System > Infrastructure diagram**.
2. Activate the API feature if it is not already on.
3. Generate an authentication key.

The key is shown once. Miradore recommends generating a separate key per
integration, so that revoking this one does not disturb anything else.

The key looks like `1_AaDf234sdf8!4`: a numeric site id, an underscore, then a
random secret. **The key identifies the site on its own**, which is why the
request URL carries no site name — `https://online.miradore.com/API/Device` with
a valid key reaches that key's site directly.

> **The key travels in the query string.** That is how v1 authenticates; there is
> no header form. The script therefore never logs a request URL — log lines name
> the path and page number only. Treat the key as you would any credential, and
> prefer a key scoped to this integration.

The same key works for both API versions.

## Configuration

| Parameter | Required | Default | Notes |
|---|---|---|---|
| **Miradore base URL** | yes | `https://online.miradore.com` | Host only — do **not** append the site name, the script adds it. For an on-premises Miradore server, use its base URL. |
| **API v1 authentication key** | yes | — | From System > Infrastructure diagram. |
| **Miradore site name** | yes | — | The segment in your console URL — for `online.miradore.com/acme/` it is `acme`. Used in the request path *and* to scope imported asset IDs. **Case matters to the API**, though the script retries in lower case automatically. |
| **Devices per page** | no | 100 | Maps to the API's `rows` option. **Automatically capped at 25 while application inventory is on** — see below. |
| **Import installed applications** | no | on | The application inventory is ~97% of the response. Turning it off makes a run dramatically faster and lets you page in much larger chunks. |
| **Include deleted and auto-generated devices** | no | off | Miradore keeps `Deleted` records in the database and returns them to the API. By default only `Active` and `New` are imported. |

### The site name does two jobs

**It selects the endpoint.** Miradore Online serves each site under its own path
segment, so the request goes to `/<site>/API/Device`. This is not optional: with a
valid key, `online.miradore.com/API/Device` — the site-less form — answers **HTTP
500**, and so does a wrong site name.

**The segment is case-sensitive.** A live site answers 200 to `/acme/` and 500 to
`/Acme/`, `/ACME/` and every other casing — the same answer it gives for a site
that does not exist, so the error never tells you which problem you have. Because
a console site name is not always written the way the URL wants it, the script
tries your spelling, then the lower-case form, then the site-less path, and logs
which one worked:

```
miradore: using /acme/API/Device
```

If your spelling was not the one that worked, you will see it say so first:

```
miradore: /Acme/API/Device did not answer (status 500)
miradore: using /acme/API/Device
```

(The v1 specification documents a third form, `https://<site>.online.miradore.com/API/`.
That one is dead — no such DNS record resolves — so it is not tried.)

Asset IDs use the **case-folded** site name, so the same site typed two ways cannot
produce two sets of assets.

**It scopes asset IDs.** Miradore numbers devices **per site**, starting at 1. Two
Miradore sites both have a device with ID 1, so importing the bare number would
merge unrelated devices onto one runZero asset. Asset IDs are therefore
`miradore:<site name>:<device id>` — for example `miradore:acme:412`.

Because the site name is part of every asset ID, **changing it re-identifies
every asset**. Pick the console's site name and leave it alone; if it must
change, expect a one-time fork of the imported assets.

## What gets imported

| runZero field | Miradore source |
|---|---|
| `id` | `miradore:<site>:<Device.ID>` |
| `hostnames` | `InvDevice.DeviceName` |
| `os` / `osVersion` | `InvOS.Platform` + `InvOS.Version`, falling back to `Device.Platform` / `Device.OSVersionName` |
| `manufacturer` | `InvDevice.Manufacturer`, falling back to `BIOS.Manufacturer` |
| `model` | `InvDevice.MarketingName`, then `Model`, then `ProductName` |
| `deviceType` | Derived from the model, then the platform |
| `networkInterfaces` | `Device.IPAddress`, `Device.LocalIpAddress`, `Device.MACAddress`, `InvDevice.WiFiMAC`, `InvDevice.BluetoothMAC` |
| `software` | `InvApplication` (name, version, identifier), capped at 999 per device |
| `firstSeenTS` / `lastSeenTS` | `Device.Created` / `Device.LastReported` |
| ownership | `miradore_user_email` |

Everything else — status, online status, IMEI, UDID, serial numbers, Android ID,
location, organization, category, tags, client version, management type, BIOS
version, storage volumes, and the raw addresses and timestamps — is imported as a
`miradore_*` custom attribute.

Some deliberate choices worth knowing:

- **Device names are not always hostnames.** MDM display names like
  `Ana's Galaxy Tab` are not valid DNS names, and importing them as hostnames
  would correlate unrelated devices. Only DNS-valid names become `hostnames`; the
  display name is always kept as `miradore_device_name`.
- **Loopback addresses are filtered off interfaces.** An agent that reports
  `127.0.0.1` as a device's only address would otherwise give every such device
  the same address and merge them onto one asset. The raw values stay in
  `miradore_ip_address` and `miradore_local_ip_address`.
- **Windows chassis is left to runZero.** Model names settle Apple hardware and
  Android tablets; naming every Windows OEM laptop line would be a guess, and
  runZero fingerprints it better.
- **Timestamps are clamped to now.** v1 stamps carry no timezone, and are read
  in the documented default `dd.MM.yyyy` ordering. runZero rejects
  an asset carrying a future timestamp — the whole record, not just the field —
  so a site whose clock runs ahead of the Explorer's would otherwise import
  nothing. The unmodified strings are kept as `miradore_last_reported`,
  `miradore_created`, and `miradore_modified`.

## Asset identity

`matchBehavior` is `no-mac-break no-ip-break no-name-break`.

`Device.ID` is the site's own database key for the enrollment, so it is stable
across runs and one-per-device — a strong foreign id that should stay
authoritative. What churns on an MDM fleet is everything else: phones roam
between networks, take new DHCP leases, and get renamed by their owners. Those
three flags stop that drift from blocking a legitimate merge, while id matching
continues to drive reconciliation.

## Behavior worth knowing

**The query is deliberately plain.** It sends only `auth`, `select`, and
`options=rows=N,page=N` — the exact shape of the specification's own paging
example. Two things an earlier version of this script added were removed after a
live Miradore Online site answered **HTTP 500** to any query carrying them:

- `options=...,dateformat=...` — the format string's spaces and colons sit inside
  an options value that is itself comma- and equals-delimited. Timestamps are now
  parsed in Miradore's default `dd.MM.yyyy HH:mm:ss` rendering instead.
- `orderby=ID` — ordering would make the paged walk stricter, but a walk that
  500s is not stricter than one that works. The no-progress guard below covers
  the case it was protecting against.

**A rejected query degrades rather than failing the import.** v1 fails an entire
query if it dislikes any part of it, and it reports that as a 500 rather than a
400. So the script walks an attribute ladder on the first page and uses the first
rung the site accepts:

1. the full attribute set;
2. the core set — identity, addressing, and OS only;
3. **no `select` at all**, which makes the API return its own default attribute
   set. A site cannot reject this rung on its attribute list.

If it ends below the first rung it says so:

```
miradore: ran with core attribute set; some inventory detail was not imported
```

That line means a field in the wider set is not supported by your site's Miradore
version. The import still succeeds, with less detail.

**A credential failure is not retried.** A 401 ends the run in one request rather
than walking the ladder — no attribute list fixes a rejected key, and retrying
would blame the wrong thing.

**Only transient failures are retried.** v1 answers in XML, so the script uses the
raw HTTP client and carries its own small retry loop: a 408/425/429/502/503/504 or
a dropped connection is retried up to three times with backoff before the page is
declared failed, so a one-off proxy blip mid-walk no longer truncates the import.
A 500 is deliberately not retried here -- a live site answers 500 to a query whose
syntax it dislikes, and that failure belongs to the select ladder above. Any other
page failure ends the walk, and the log names the page.

**Page size is capped when application inventory is on.** Measured against a live
site, a device costs about **1.3 KB** of XML without its applications and **45 KB**
with them — applications are roughly 97% of the response. What has to fit in the
Explorer's memory budget is not the raw response but the *parsed* XML document,
which expands roughly 70x over it. A single page holding a 186-device estate with
applications is 8.4 MB of XML, and that exceeded the Explorer's 512 MB limit
outright:

```
memory limit exceeded: 578457152 bytes live after collection, limit 536870912
```

— which reports **zero assets**, because the script is killed mid-walk. So while
applications are enabled the page size is capped at 25 and the script says so:

```
miradore: lowering the page size from 100 to 25 because application inventory is enabled
```

The important property is that this bound is **per page, not per estate**: a fleet
ten times larger takes ten times the requests at the same peak memory. If you want
larger pages, turn off **Import installed applications** — without them the cap
does not apply and a page of 500 devices is still under 700 KB.

**Paging stops if it stops progressing.** If the server ever returns the same
page twice — because it ignored the `page` option, or a proxy replayed a response
— the script stops and logs it rather than paging forever.

### If a run reports 0 assets

First check it is not simply working as configured: **Miradore keeps deleted
devices in the database and returns them to the API**, and on a real site they can
be a large share of the total. A run that says

```
miradore: skipped 84 devices (deleted, auto-generated, or missing an ID)
miradore: reported 102 of 186 devices matched by the query
```

is correct — 186 is everything Miradore holds, not everything it manages. If your
site is mostly deleted records, turn on **Include deleted and auto-generated
devices** to see them.

If the log shows `could not read the device list`, reproduce it outside runZero:

```bash
curl -sS "https://online.miradore.com/YOUR_SITE/API/Device?auth=YOUR_KEY&options=rows=1,page=1"
```

`<Content><Items count="…">` means the endpoint and key are good.
`<Error><Description>Authentication failed</Description>` means the key. A **500**
almost always means the site name is wrong — that is the same answer the API
gives for a site that does not exist and for the site-less URL form.

## Testing

```bash
python3 tests/run.py miradore
```

Six scenarios run the real scanner against a fixture server: `happy` (XML
parsing, the wrapped list containers, the record-level guards, and the
`dd.MM.yyyy` parse), `paged` (five devices at `rows=2`), `select-fallback` (a site
that 500s every attribute list must still import via the default-attribute rung),
`path-fallback` (a deployment serving the API at the root must still be found),
and `auth-failure` (a 401 must end the run in one request rather than walking
either ladder).

The script has also been run end to end against a live Miradore Online site: 102
assets from 186 records, with software, tags, storage, ownership, and timestamps
populated — 102 assets and 35,754 software rows from 186 records.

## Future

- **No custom attributes.** Miradore's per-device custom attributes are readable
  only through v2's `GET /api/v2/Device/{id}/CustomAttribute`, which is one
  request per device. That is not worth an N+1 walk for most fleets, so it is not
  implemented.
- **No device location history.** Also v2-only and per-device.
- **Certificates, profiles, and security posture are not imported.** v1 exposes
  `InvCertificate`, `InvIosProfile`, `MobileSecurity`, and the per-platform
  security items as child items of `Device`. They are omitted to keep the
  response size manageable; add them to `SELECT_EXTRA` if you want them.
- **Most MDM device names are not hostnames.** On a real site, 97 of 102 device
  names were of the form `Someone's MacBook Pro`, which is not a valid DNS name.
  Those are kept as `miradore_device_name` and do not become `hostnames`; every
  asset still correlates on MAC and IP.
- **Apple model identifiers do not always give a device type.** Macs from 2021
  onward report models like `Mac14,10`, which unlike `MacBookPro18,1` does not
  name the chassis. Those assets are left without a `deviceType` for runZero to
  fingerprint rather than guessed at from a hardcoded Apple model table.

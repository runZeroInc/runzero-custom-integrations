# Custom Integration: Miradore

Imports managed devices from a Miradore site: hardware, operating system,
installed applications, the assigned user, and the addresses Miradore holds for
each device.

## Which Miradore APIs this uses, and why

**Devices are enumerated from API v1. API v2 adds per-device detail on top.**
That split is forced: v2 cannot list devices, and v1 does not carry what v2
knows.

| | API v1 | API v2 |
|---|---|---|
| Purpose | Reporting / export | Device management |
| Can list devices | **Yes** | **No** |
| Payload | XML | JSON |
| Auth | `auth=<key>` in the query string | `X-API-Key` header |
| Names the site | in the URL path | in the `X-Instance-Name` header |

### v2 cannot enumerate devices

Not inferred from the documentation. Verified against `online.miradore.com` on
**2026-08-26** with a working key and the site named in `X-Instance-Name`:

| Request | Answer | Meaning |
|---|---|---|
| `GET /api/v2/CustomAttribute` | **200** `[]` | works |
| `GET /api/v2/Device/{id}/CustomAttribute` | **200** `[]` | works |
| `GET /api/v2/Device/{id}/Location` | **200** `[]` | works |
| `GET /api/v2/Device/{id}/...` | 404 | that device id is deleted or unknown |
| `GET /api/v2/Device` | 404 | the route is `POST`-only |
| `GET /api/v2/Device/SuspendedDevices` | **401** | refuses every credential |
| `GET /api/v2/Devices` | **401** | refuses every credential |

The key is not the problem: the *same* key returns 200 on the first three rows.
There is no device collection to read and no device *record* to read either,
since `/api/v2/Device` carries only `POST` and `/api/v2/Device/{id}` only
`DELETE` and `PATCH`. The two 401s are settled rather than open:
`/api/v2/Devices` returns a **byte-identical 401 body** for a valid key, a
deliberately invalid key, and no `X-API-Key` header at all, so nothing about the
credential changes the answer. It is genuinely routed rather than a stray pattern
match (`/api/v2/ZZZDevices` and `/api/v2/Devices123` both 404), but a route no
caller can pass is not an enumeration endpoint. `SuspendedDevices` behaves
identically.

The published
[OpenAPI document](https://online.miradore.com/swagger/v2/swagger.json) agrees:
its `Device` schema appears solely as a request body, never as a response, and
carries no OS, serial number, MAC, IP, or software field. None of its 29 paths
accepts a paging parameter. Miradore's own v2 documentation says it outright:

> The device ID can be retrieved using Miradore API v1, as an attribute of the
> Device item.

### What v2 is used for

Three reads, none with any equivalent in v1:

| v2 endpoint | Cost | What it adds | Live status |
|---|---|---|---|
| `GET /api/v2/Device/SuspendedDevices` | one request per run | which devices Miradore has suspended | **401 to any key**, never available on Miradore Online |
| `GET /api/v2/Device/{id}/CustomAttribute` | one request per device | the site's own custom attribute values | works; returns a JSON array |
| `GET /api/v2/Device/{id}/Location` | one request per device | the last reported coordinates | works; returns a JSON array |

All three declare `200 Success` with *no schema at all* in the OpenAPI document,
so observation is the only evidence there is. The live site confirms the top
level of both per-device routes is a **bare JSON array**, which is what the
script parses, but it could not confirm the shape of an *element*: the test site
defines no custom attributes and records no locations, so every array came back
empty. The element field names (`identifier` / `name` / `value`, and `timestamp`
/ `latitude` / `longitude`) still come from the runZero platform connector rather
than from observation, and the parsing stays deliberately defensive about them.

The v1 contract comes from the **Miradore API Specification** PDF linked below
(version 1.14 was used here). Every attribute the script requests by name is from
that document's Appendix 2.

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

The key is shown once, and the same key works for both API versions. Miradore
recommends generating a separate key per integration, so that revoking this one
does not disturb anything else.

The key looks like `1_AaDf234sdf8!4`: a numeric instance id, an underscore, then
a random secret. **The leading number does not select the site for you.** Both
APIs need the site named separately, v1 in the URL path and v2 in the
`X-Instance-Name` header, which is why **Miradore site name** is a required
parameter and not a convenience. The secret half routinely contains characters
needing percent-encoding in a URL; the key used for live testing held `{`, `}`
and a comma. If you reproduce a request with `curl`, quote the URL and pass
`--globoff`, or curl will brace-expand the key and refuse the request.

> **The v1 key travels in the query string.** That is how v1 authenticates;
> there is no header form, so the whole request URL is a secret. The script
> therefore never logs a v1 URL, and those log lines name the path and page
> number only. v2 takes the same key in an `X-API-Key` header, so its URLs are
> safe to log and are logged. Treat the key as you would any credential, and
> prefer a key scoped to this integration.

## Configuration

| Parameter | Required | Default | Notes |
|---|---|---|---|
| **Miradore base URL** | yes | `https://online.miradore.com` | Host only. Do **not** append the site name, the script adds it. For an on-premises Miradore server, use its base URL. |
| **API authentication key** | yes | none | From System > Infrastructure diagram. The same key authenticates v1 and v2. |
| **Miradore site name** | yes | none | The segment in your console URL: for `online.miradore.com/acme/` it is `acme`. Used in the request path *and* to scope imported asset IDs. **Case matters to the API**, though the script retries in lower case automatically. |
| **Devices per page** | no | 100 | Maps to the API's `rows` option. **Automatically capped at 25 while application inventory is on**, see below. |
| **Import installed applications** | no | on | The application inventory is ~97% of the response. Turning it off makes a run dramatically faster and lets you page in much larger chunks. |
| **Include deleted and auto-generated devices** | no | off | Miradore keeps `Deleted` records in the database and returns them to the API. By default only `Active` and `New` are imported. |
| **Add API v2 detail** | no | on | The suspended-device list and each device's custom attribute values, neither of which API v1 exposes. Costs one extra request per device. |
| **Add the last reported location** | no | on | Each device's most recent reported coordinates, also v2-only. Split out from the switch above because it is employee-device geolocation, and it costs a second request per device. |
| **Maximum devices to detail** | no | 5000 | Upper bound on the per-device v2 requests. The v1 walk still imports the whole estate; devices past the bound arrive without their v2 detail. |

### The site name does two jobs

**It selects the endpoint.** Miradore Online serves each site under its own path
segment, so the request goes to `/<site>/API/Device`. This is not optional: with
a valid key, the site-less `online.miradore.com/API/Device` answers **HTTP 500**,
and so does a wrong or wrongly-cased site name.

**The segment is case-sensitive, and so is the v2 header.** Confirmed on a live
site, 2026-08-26. v1 answers 200 to `/acme/` and 500 to every other casing, the
same answer it gives for a site that does not exist, so the error never tells you
which problem you have. `X-Instance-Name` is case-sensitive too and fails
*differently*:

| `X-Instance-Name` | v2 answer |
|---|---|
| `acme`, the casing v1 accepted | the endpoint's real answer |
| `Acme`, `ACME`: right site, wrong case | **403**, empty body |
| a site that does not exist | **500**, empty body |
| header omitted entirely | 401, and a *v1-style* XML `Authentication failed` envelope |

So one mistake produces 500 from v1 and 403 from v2. That is why the script
settles the spelling once against v1 and hands the winner to v2 rather than
asking for the site name twice. Because a console site name is not always written
the way the URL wants it, it tries your spelling, then the lower-case form, then
the site-less path, and logs which one worked:

```
miradore: /Acme/API/Device did not answer (status 500)
miradore: using /acme/API/Device
```

(The v1 specification documents a third form,
`https://<site>.online.miradore.com/API/`. No such DNS record resolves, so it is
not tried.)

**It scopes asset IDs.** Miradore numbers devices **per site**, starting at 1.
Two Miradore sites both have a device with ID 1, so importing the bare number
would merge unrelated devices onto one runZero asset. Asset IDs are therefore
`miradore:<site name>:<device id>`, for example `miradore:acme:412`. The
case-folded site name is used, so the same site typed two ways cannot produce two
sets of assets.

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
| `networkInterfaces` | `Device.LocalIPAddress`, `Device.MACAddress`, `InvDevice.WiFiMAC`, `InvDevice.BluetoothMAC` |
| `software` | `InvApplication` (name, version, identifier, size), capped at 999 per device |
| `firstSeenTS` / `lastSeenTS` | `Device.Created` / `Device.LastReported` |
| ownership | `miradore_user_email` |

Everything else is imported as a `miradore_*` custom attribute: status, online
status, IMEI, UDID, serial numbers, Android ID, location, organization, category,
tags, client version, management type, BIOS version, firmware version, storage
volumes, and the raw addresses and timestamps.

The v2 half adds three more groups of custom attribute, alongside the device
security and enrollment posture that v1 returns:

| Attribute | Source |
|---|---|
| `miradore_attr_<name>` | v2 `GET /Device/{id}/CustomAttribute`, keyed on the field's **Identifier** so a renamed label does not rename the attribute |
| `miradore_geo_<field>` | v2 `GET /Device/{id}/Location`, the newest entry in the window |
| `miradore_suspended` | v2 `GET /Device/SuspendedDevices` |
| `miradore_security_*`, `miradore_enrollment_*` | v1 `Security` and `Enrollment`, requested as wildcards and flattened under whatever names the site returns |

**The `Security.*` and `Enrollment.*` wildcards are accepted**, confirmed on a
live site, 2026-08-26, which returned `Security/PasscodeSet`,
`Security/EncryptionStatus`, and `Enrollment/ID`, `Created`, `Completed`, `Type`.
The field names are not hardcoded: the wildcard is requested and whatever comes
back is flattened, so a site with a different schema keeps its own names.

**`InvApplication` has no vendor property.** The entity has exactly six, each
confirmed by probing it: `Name`, `Version`, `Identifier`, `Size`, `OSCategory`,
`InventoryTime`. Asking for `InvApplication.Vendor` fails the whole query with
the 400 shown below, so the vendor is derived from a reverse-DNS bundle
identifier (`com.apple.Safari` gives `apple`) instead. Anything that is not
reverse DNS is left for runZero's own software normalization.

Some deliberate choices worth knowing:

- **Device names are not always hostnames.** MDM display names like
  `Loaner's Galaxy Tab` are not valid DNS names, and importing them as hostnames
  would correlate unrelated devices. Only DNS-valid names become `hostnames`; the
  display name is always kept as `miradore_device_name`.
- **The public address is not an asset address.** Miradore reports two:
  `LocalIPAddress`, the device's own LAN address, and `IPAddress`, the egress
  address the Miradore *service* saw the device arrive from. The second is
  identical for every device behind one NAT, so importing it would hand a whole
  office one address to correlate on. Only `LocalIPAddress` becomes an asset
  address; the egress address is kept as `miradore_public_ip`, which is what the
  built-in runZero Miradore connector does with it too. On the live estate this
  mattered more than expected: **all 102 devices reported a MAC and none reported
  a `LocalIPAddress` at all**, so every asset correlated on its MAC. Had the
  egress address been imported instead, the whole fleet would have merged onto
  one address.
- **Loopback addresses are filtered off interfaces**, for the same reason: an
  agent reporting `127.0.0.1` as a device's only address would merge every such
  device onto one asset. The raw values stay in `miradore_local_ip_address`.
- **v2 detail never blocks the import.** Every v2 read is enrichment: if the site
  is not entitled to v2, or the endpoint fails, the device is still imported from
  v1 and the failure is logged **once for the run** rather than once per device.
- **Windows chassis is left to runZero.** Model names settle Apple hardware and
  Android tablets; naming every Windows OEM laptop line would be a guess, and
  runZero fingerprints it better.
- **Timestamps are clamped to now.** v1 stamps carry no timezone. runZero rejects
  an asset carrying a future timestamp, discarding the whole record rather than
  the field, so a site whose clock runs ahead of the Explorer's would otherwise
  import nothing. The unmodified strings are kept as `miradore_last_reported`,
  `miradore_created`, and `miradore_modified`.

## Asset identity

`matchBehavior` is `no-mac-break no-ip-break no-name-break`.

`Device.ID` is the site's own database key for the enrollment, so it is stable
across runs and one per device: a strong foreign id that should stay
authoritative. What churns on an MDM fleet is everything else. Phones roam
between networks, take new DHCP leases, and get renamed by their owners. Those
three flags stop that drift from blocking a legitimate merge, while id matching
continues to drive reconciliation.

## Behavior worth knowing

**The query is deliberately plain.** It sends only `auth`, `select`, and
`options=rows=N,page=N`, the exact shape of the specification's own paging
example. `dateformat` and `orderby` are both accepted by a live site when each
query key is percent-encoded separately (checked 2026-08-26), but neither is
sent. `dateformat` is unnecessary, since the script recognises both the default
`dd.MM.yyyy HH:mm:ss` rendering and the `yyyy-MM-dd HH:mm:ss` one a `dateformat`
produces. `orderby=ID` would make the walk stricter, but the no-progress guard
below already covers the case it protects against, and every option left out is
one less thing a deployment can reject.

**The key must be percent-encoded, and this is not theoretical.** A real
Miradore key contains characters that are significant in a query string; the one
used for testing held braces and a comma. Passed through raw it is rejected
before it reaches the API. The script encodes each query key separately.

**A rejected query degrades rather than failing the import.** v1 fails an entire
query if it dislikes any part of it, and reports an unknown attribute as a
**400** carrying an `<Error>` envelope that names the offending entity and
property:

```xml
<Content><Error><Description>Entity 'InvApplication' does not have property 'Vendor'.</Description><Code>400</Code></Error></Content>
```

(A **500** is a different failure: a site name it cannot resolve.) So the script
walks an attribute ladder on the first page and uses the first rung the site
accepts:

1. the full attribute set;
2. the inventory and application attributes, dropping the `Security.*` and
   `Enrollment.*` wildcards, which are the likeliest thing for a site to refuse;
3. the inventory attributes alone, dropping installed applications;
4. the core set: identity, addressing, and OS only;
5. **no `select` at all**, which makes the API return its own default attribute
   set. A site cannot reject this rung on its attribute list.

It steps down one group at a time rather than jumping to the core set, because
the API never says *which* attribute it objected to, so giving up one group per
attempt is the only way to keep what a site does support. If it ends below the
first rung it says so, which means a field in the wider set is not supported by
your site's Miradore version. The import still succeeds, with less detail.

```
miradore: ran with the core attribute set; some inventory detail was not imported
```

**A credential failure is not retried.** A 401 ends the run in one request rather
than walking the ladder: no attribute list fixes a rejected key, and retrying
would blame the wrong thing.

**Only transient failures are retried.** v1 answers in XML, so the script uses
the raw HTTP client and carries its own small retry loop: a 408/425/429/502/503/504
or a dropped connection is retried up to three times with backoff, so a one-off
proxy blip mid-walk does not truncate the import. A 500 is deliberately not
retried, since a live site answers 500 for a site name it cannot resolve and no
number of retries repairs that. Any other page failure ends the walk, and the log
names the page.

**Page size is capped when application inventory is on.** Measured against a live
site on 2026-08-26, sweeping `rows` and weighing the response:

| `rows` | applications | XML per page | per device |
|---|---|---|---|
| 25 | on | 1002 KB | 40.1 KB |
| 50 | on | 2224 KB | 44.5 KB |
| 25 | off | 39 KB | 1.6 KB |
| 100 | off | 151 KB | 1.5 KB |

So applications are roughly **97%** of the response, and the 25-row cap lands a
page just under 1 MB. What has to fit in the Explorer's memory budget is not the
raw response but the *parsed* XML document, which expands roughly 70x over it. A
single page holding a 186-device estate with applications is 8.4 MB of XML, and
that exceeded the Explorer's 512 MB limit outright, reporting **zero assets**
because the script is killed mid-walk:

```
memory limit exceeded: 578457152 bytes live after collection, limit 536870912
```

The important property is that this bound is **per page, not per estate**: a
fleet ten times larger takes ten times the requests at the same peak memory. If
you want larger pages, turn off **Import installed applications**; without them
the cap does not apply and a page of 500 devices is around 750 KB.

**Paging stops if it stops progressing.** If the server ever returns the same
page twice, because it ignored the `page` option or a proxy replayed a response,
the script stops and logs it rather than paging forever.

### If a run reports 0 assets

First check it is not simply working as configured. **Miradore keeps deleted
devices in the database and returns them to the API**, and on a real site they
can be a large share of the total, so a run like this is correct: 186 is
everything Miradore holds, not everything it manages. If your site is mostly
deleted records, turn on **Include deleted and auto-generated devices**.

```
miradore: skipped 84 devices (deleted, auto-generated, or missing an ID)
miradore: reported 102 of 186 devices matched by the query
```

If the log shows `could not read the device list`, reproduce it outside runZero:

```bash
curl -sS --globoff "https://online.miradore.com/YOUR_SITE/API/Device?auth=YOUR_KEY&options=rows=1,page=1"
```

`--globoff` matters: a key containing `{` or `[` makes curl try to brace-expand
the URL and fail before sending anything. Note this URL contains your key, so
keep it out of shell history and terminal logs.

`<Content><Items count="...">` means the endpoint and key are good.
`<Error><Description>Authentication failed</Description>` means the key. A **400**
naming an entity and property means one attribute in the `select` is not in your
site's schema. A **500** almost always means the site name is wrong, since that
is the same answer the API gives for a site that does not exist, for the
site-less URL form, and for a site name in the wrong case.

## Testing

```bash
python3 tests/run.py miradore        # fixtures
python3 tests/run_live.py miradore   # a real Miradore site, credentials from .env
```

Thirteen scenarios run the real scanner against a fixture server.

The v1 walk: `happy` (XML parsing, the wrapped list containers, the `dd.MM.yyyy`
parse, and the public/local address split), `paged` (five devices at `rows=2`),
`empty` (a site matching nothing must end cleanly), `select-fallback` (every
attribute list refused with the real recorded 400 `<Error>` envelope, which
carries no `<?xml?>` prolog and escapes its quotes as the live service sends it,
must still import via the default-attribute rung, degrading one group at a time),
`path-fallback` (the API served at the root), `case-fallback` (the site segment
is case-sensitive), `transient-retry` (a 502 mid-walk), and `auth-failure` (a 401
must end the run in one request rather than walking either ladder).

The v2 half: `v2-online-shapes` (the responses Miradore Online really returns,
recorded 2026-08-26: `SuspendedDevices` 401, both per-device routes `200 []`, and
a real device record with its `Security`/`Enrollment` children), `v2-detail` (a
site that *does* populate them, including custom attributes keyed on Identifier,
the newest location entry winning, and v2 addressed at the server root with the
site in a header), `v2-unavailable` (every v2 route 401s, so the v1 import is
unaffected and each endpoint announces itself once, not once per device),
`detail-cap` (the per-device bound), and `malformed` (every v2 response the wrong
shape, none of which may abort the script or lose the v1 device).

### Live run, 2026-08-26

Run end to end against a real Miradore Online site with `include_software`,
`include_v2_details` and `include_v2_location` all on:

```
102 assets, 35,767 software rows, from 186 records
(102 New, 79 Deleted, 5 AutoGenerated: the latter two are skipped by default)
```

That run is what found the `InvApplication.Vendor` defect. Because v1 fails a
query whole, one attribute name that the schema does not have was costing the
**entire application inventory** of the estate, silently, by pushing the select
ladder down past both software rungs. The live expectation asserts
`software>=30000` precisely so that a reintroduced bad attribute fails the run
instead of quietly importing nothing.

The live scenario carries one invariant skip, recorded in
`miradore/tests/live.json`: `child_caps`, which flags more than 99 software rows
on one asset. Real Macs on this estate reported an average of ~350 applications
and a peak of 557, so a 99-row cap would discard two thirds of what the API
returned.

**Still not confirmed against a live site:** the *element* shape of the two
per-device v2 responses, for the reason given above. `v2-detail` and `malformed`
exist precisely because a response shape that has not been seen is a response
shape that might be wrong.

## Future

- **Certificates, profiles, and SIM details are not imported.** v1 exposes
  `InvCertificate`, `InvIosProfile`, `InvSIM`, `InvOperatorNetwork` and the
  per-platform battery, camera, CPU, display and sensor items as child items of
  `Device`. They are omitted to keep page memory manageable. Add them to
  `SELECT_EXTRA` or `SELECT_POSTURE` if you want them.
- **Application OS categories and inventory times are not imported.** They are
  the only two `InvApplication` properties left on the table, and a device
  reports hundreds of applications, so both would cost more page memory than
  they return.
- **Most MDM device names are not hostnames.** On a real site, 97 of 102 device
  names were of the form `Someone's MacBook Pro`, which is not a valid DNS name.
  Those stay as `miradore_device_name`; every asset still correlates on MAC.
- **Apple model identifiers do not always give a device type.** Macs from 2021
  onward report models like `Mac14,10`, which unlike `MacBookPro18,1` does not
  name the chassis. Those are left without a `deviceType` for runZero to
  fingerprint rather than guessed at from a hardcoded Apple model table.

## API documentation

- [Programmer's guide to API v1](https://www.miradore.com/knowledge/integrations/programmers-guide-to-api-v1/),
  which links the **Miradore API Specification** PDF, whose Appendix 2 is the
  attribute list this script selects from.
- [Miradore API v2](https://www.miradore.com/knowledge/integrations/miradore-api-v2/)
- [v2 OpenAPI document](https://online.miradore.com/swagger/v2/swagger.json)

# Custom Integration: Icinga 2

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the Icinga 2 API listener, by default TCP 5665.

## Icinga 2 requirements

- The `api` feature enabled on the Icinga 2 master.
- An `ApiUser` object with the `objects/query/Host` permission, plus
  `objects/query/Service` if service checks are summarized and `status/query` for the
  version banner. The integration only reads; it never needs `objects/create`,
  `objects/modify`, `objects/delete`, `actions/*`, or `console`.
- Network reachability to port 5665. Icinga's API is TLS-only and there is no plaintext
  listener.

## Steps

### Icinga 2 configuration

1. Enable the API feature and generate the certificate the listener needs. On the master:

   ```bash
   icinga2 api setup
   systemctl restart icinga2
   ```

   `icinga2 api setup` enables the `api` feature, creates the CA and the node
   certificate, and writes `/etc/icinga2/conf.d/api-users.conf` with a `root` ApiUser
   holding a generated password.

2. Add a dedicated read-only ApiUser rather than reusing `root`. Edit
   `/etc/icinga2/conf.d/api-users.conf`:

   ```
   object ApiUser "runzero" {
     password = "<a long random password>"
     permissions = [ "objects/query/Host", "objects/query/Service", "status/query" ]
   }
   ```

   Drop `objects/query/Service` if you leave **Summarize service checks** off, and
   `status/query` if you would rather the run not log the Icinga version. Narrowing
   further than this is not possible: `objects/query` is the only permission that reads
   host objects.

3. Reload Icinga so the new user exists:

   ```bash
   systemctl reload icinga2
   ```

4. Confirm the credential and the permission from the Explorer host:

   ```bash
   curl -k -u 'runzero:<password>' \
     -H 'Accept: application/json' \
     'https://icinga.example.com:5665/v1/objects/hosts?attrs=name&attrs=address'
   ```

   A `401` means the password is wrong; a `404` with
   `{"error":404,"status":"No objects found."}` most often means the ApiUser lacks
   `objects/query/Host` rather than that the estate is empty.

5. Note the certificate situation. `icinga2 api setup` issues a certificate from
   Icinga's own CA, which no operating system trusts. Either add
   `/var/lib/icinga2/ca/ca.crt` as the **CA certificate** in the runZero credential, or
   replace the listener certificate with one from a CA the Explorer already trusts.
   Turning validation off is a last resort, not the intended configuration.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Icinga 2").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Icinga 2 API URL** (`url`): base URL of the API listener, for example `https://icinga.example.com:5665`.
   - **API user** (`username`): the name of the `ApiUser` object.
   - **API password** (`password`): that object's `password` attribute.
   - **Host group** (`host_group`): optional; import only hosts in this host group.
   - **Host filter expression** (`host_filter`): optional; raw Icinga DSL filter, combined with the host group filter when both are set.
   - **Import last check output** (`include_check_output`): optional; request `last_check_result` and keep its plugin output (default: false).
   - **Summarize service checks** (`include_checks`): optional; record per-host check counts and names (default: false).
   - **Check names per host** (`max_check_names`): optional; cap on the recorded check-name list (default: 40).
   - TLS options arrive through the shared include: set **CA certificate** to Icinga's own CA certificate for a stock `icinga2 api setup` install.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it. `--kwargs` is repeated once per
parameter:

```bash
runzero script --filename icinga2/icinga2.star \
  --kwargs url=https://icinga.example.com:5665 \
  --kwargs username=runzero \
  --kwargs password='<password>' \
  --kwargs include_checks=true \
  --kwargs tls_ca_cert=/var/lib/icinga2/ca/ca.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./icinga-run
```

`--output` writes the assets the run produced, and `--overwrite` replaces a directory
from a previous run. Add `--verbose` for the request-by-request log. Omit `--output` to
see only the log lines.

To check the `CONFIG` block and the HTTP and TLS wiring without a live server:

```bash
runzero script --filename icinga2/icinga2.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove Icinga accepts the credential or that any host is parsed.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat icinga2/icinga2.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://icinga.example.com:5665,username=runzero,password=<password>' \
  --output ./icinga-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a parameter
value containing a comma cannot be passed this way; prefer `script --kwargs` for
ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with monitoring data pulled from Icinga 2.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:icinga2`.

## Asset identity

- Target entity: an Icinga 2 `Host` object — one configured, actively monitored machine.
  Not a check, not a service, not a host group.
- Source ID field: the object `name`, read from the top level of each `results[]` entry
  (`results[].name`), which the API returns on every query regardless of the requested
  attribute set.
- Documentation evidence: the API reference addresses a single object as
  `/v1/objects/hosts/<name>` and every filter example matches on `host.name`, so the name
  is the API's own primary key. Icinga's configuration compiler refuses two objects of
  the same type with the same name, which makes it unique by construction rather than by
  convention. The response's `attrs.__name` carries the same value.
- Uniqueness scope: one Icinga 2 installation. A distributed setup with satellites and
  agents is still one configuration namespace — zones partition where a check *runs*, not
  which names exist — so the master's hostname alone is enough to scope the id.
- Cardinality: one `Host` object per asset. Service objects are children of a host and
  are folded into that host's attributes; they never become assets or services of their
  own.
- Stability: survives address changes, template changes, group membership changes,
  reboots, `icinga2 reload`, certificate renewal, and moving the host to a different
  zone or satellite. The name is a configuration identifier, not an observation.
- Reuse behavior: yes, and this is the one real weakness. Icinga host objects are
  conventionally named for the machine's FQDN, and an organization that decommissions
  `web01.example.com` and later gives the name to a new machine produces the same id for
  a different device. That is also, defensibly, what a monitoring system means: the
  object named `web01.example.com` is whatever currently answers to it. Sites that rename
  hosts frequently should expect the merged asset to follow the name.
- Presence: always. The name is how the object is addressed and it cannot be empty.
- Final runZero ID: `icinga2:<icinga-host>:<object-name>`, for example
  `icinga2:icinga.example.com:web01.example.com`. The host comes from the configured URL
  without the port, so moving the listener off 5665 does not re-key an existing estate.
- Missing-ID behavior: the record is skipped and one line is logged carrying the check
  command only, never the record body. No identity is synthesized and `new_uuid()` is
  never used.
- Match behavior (set once in `CONFIG`): `no-mac-break no-ip-break no-name-break`. The object name is
  authoritative, but `address` is a free-text attribute that operators edit by hand and
  frequently leave stale, and Icinga models no MAC at all, so address churn must not
  disqualify a merge.
- Verdict: **scoped authoritative** — authoritative within one Icinga installation,
  namespaced by the master's hostname, with the documented caveat that a reused host name
  is a reused identity.

### Notes

- **What is imported.** One asset per `Host` object from `POST /v1/objects/hosts`. Each
  carries its addresses, hostnames, host groups, templates, check command, state,
  acknowledgement and downtime status, zone, notes, and every custom variable under
  `vars`. With **Summarize service checks** enabled, `POST /v1/objects/services`
  contributes a per-host check count, a problem count, and a capped list of check names.
- **Monitoring checks are not services, and are not imported as services.** This is the
  most important design decision here and it is deliberate. An Icinga `Service` object is
  a *check* — "disk usage on web01", "certificate expiry on api02" — and the object type
  reference gives it no port, no transport, and no listening address, because it does not
  describe one. Many checks describe nothing on the host at all: `check_ping` runs from
  the master, and an `http` check against a load balancer VIP says nothing about what
  `web01` is listening on. Importing those as runZero `Service` objects would invent open
  ports that no scan would ever confirm and would corrupt exactly the data runZero is
  authoritative for. This repository already rejected Centreon for the same reason. The
  checks are still worth knowing about, so they are recorded as
  `icinga_check_count`, `icinga_check_problem_count`, and `icinga_check_names` on the host
  itself.
- **Reads are sent as POST.** Every object query goes out as `POST` carrying
  `X-HTTP-Method-Override: GET`, which the API reference documents as the way to give a
  read a request body. That is a requirement rather than a preference: `attrs` is a
  *repeated* query parameter in URL form (`?attrs=name&attrs=address`), and the runtime's
  `params=` dict cannot hold a duplicate key, so the JSON body is the only way to request
  a trimmed attribute set. It also keeps the filter expression out of the URL and out of
  any proxy log. Without the override header Icinga would treat the POST as an object
  creation and reject it for lacking `objects/create`.
- **The attribute set is explicit for a reason.** Omitting `attrs` returns every
  attribute of every object, and a `Host` has well over a hundred — including
  `last_check_result`, which nests the full command line, the parsed performance data,
  and the custom variables before and after execution. On an install with tens of
  thousands of hosts that is the difference between a response measured in megabytes and
  one measured in tens of megabytes. `last_check_result` is requested only when
  **Import last check output** is enabled.
- **The response is streamed, not decoded.** `/v1/objects/hosts` does not paginate: there
  is no `limit`, no offset, and no cursor anywhere in the API reference. It answers with
  every matching object in one `results` array. The body is therefore handed to
  `jsonstream.iter_array`, which walks the array element by element without ever
  materializing the decoded document, and each asset is reported as it is built. The
  trade-off is that this needs the raw `http.post` verb, which accepts no retry budget,
  so the two large reads get one attempt each while the small status call retries as
  normal. A transient failure fails that run and the next scheduled run recovers.
- **`iter_array` aborts the script, so the shape is checked first.** A missing path, a
  path holding something other than an array, an empty body, and a body that is not JSON
  all end the run outright — there is no recoverable error. Icinga answers a permission
  failure with `{"error":404,"status":"..."}` and a reverse proxy in front of the API
  answers with HTML, and both would otherwise abort. Each response is therefore checked
  for a genuine `"results": [` before the parser sees it, and a body that fails the check
  is reported and skipped.
- **`address` is not necessarily an address.** The object type reference calls `address`
  "The host's IPv4 address", but it is an unvalidated string attribute, and filling it
  with a DNS name is normal on installs that let the resolver do the work. Each of
  `address` and `address6` is therefore classified by what it actually holds: a routable
  IP becomes an interface address, a name becomes a hostname, and loopback or link-local
  is dropped.
- **Names are filtered.** A host object named for a bare IP, named `localhost` (which
  ships in the default configuration of every install), or whose `display_name` is a
  human caption with spaces in it — "Core switch 01" — contributes no hostname. A value
  made only of digits and dots is rejected too, because that is what a typo in the
  address field looks like rather than a name.
- **A host with nothing to correlate on is skipped.** The default `localhost` object has
  only `127.0.0.1`, `::1`, and the name `localhost`; after filtering it has no MAC, no
  routable address, and no usable hostname. Importing it would give every runZero account
  that adds a second Icinga server an asset that can never merge with anything, so it is
  dropped with a log line instead.
- **Numbers arrive as floats.** Every numeric attribute Icinga emits is a JSON float,
  including the ones the reference documents as enumerations: a host that is UP
  serializes as `"state": 0.0`, and `"max_check_attempts": 3.0`. Reading those with an
  integer type test silently discards every state and every interval, so floats are
  accepted and truncated.
- **Timestamps are epochs with fractional seconds, and are clamped.** `last_check` and
  `last_state_change` arrive as values such as `1443019345.093372`. The runtime's
  `from_timestamp` takes an integer and rejects a float with an error that would abort
  the whole script, so each is truncated to a whole second first. It is then clamped to
  the current time, because runZero rejects an asset whose last-seen time is in the
  future and drops the **entire record** rather than the field — so an Icinga server
  whose clock runs ahead of the Explorer's would otherwise import nothing at all, with no
  error. `last_check` becomes `lastSeenTS`; the raw epoch is kept as
  `icinga_last_check_epoch`. There is no `firstSeenTS`: an Icinga object exists from the
  moment it is configured, and `last_state_change` is not when the host was first seen.
- **MACs come only from custom variables, and only when they parse.** Icinga models no
  hardware, so a MAC exists only where an operator put one. A short list of conventional
  variable names (`mac`, `mac_address`, `macaddress`, `mac_addr`, `hwaddr`, `hw_address`)
  is checked and the value is used only if it parses as a MAC, which keeps a variable
  holding a serial number or an asset tag from being read as hardware addressing.
- **`vars` is where the real inventory data lives.** Icinga has no field for owner,
  location, serial, environment, or application, so every site puts them in custom
  variables. The whole `vars` dictionary is flattened under the `icinga_var_` prefix, so
  `vars.notification.mail.groups` becomes `icinga_var_notification_mail_groups`.
- **`vars.os` sets the asset's operating system.** That variable is set by the host
  template in Icinga's own shipped example configuration, which makes it the closest
  thing to a standard. `operating_system` and `osfamily` are accepted as fallbacks. This
  is a naming convention, not a guarantee; an install that uses a different variable name
  will produce assets with no OS and the value still present as a custom attribute.
- **Filters are parameterized where they can be.** A configured host group is sent as
  `{"filter": "group in host.groups", "filter_vars": {"group": "<name>"}}`, which is what
  the API reference recommends and what keeps a group name containing a quote from
  changing the meaning of the expression. A raw **Host filter expression** is passed
  through verbatim — it is Icinga DSL evaluated server-side, so it is as powerful and as
  dangerous as the ApiUser's permissions allow. When both are set they are combined with
  `&&`.
- **Rate limiting.** Icinga publishes no rate limit and returns no rate-limit headers. The
  small status call retries transient failures with exponential backoff through the shared
  HTTP helper; the two streamed reads do not, as described above.
- **Client certificate authentication is not implemented.** The API also accepts an
  X.509 client certificate matched against an ApiUser's `client_cn`. Basic authentication
  was chosen because it is what `icinga2 api setup` configures out of the box and because
  the shared TLS options already carry a client certificate for transport, not for
  identity. See Future.
- This integration was validated against local fixtures built from the response shapes in
  the Icinga 2 API reference and object type documentation. It has **not** been run
  against a live Icinga 2 master, and in particular the exact body of the 401 and 404
  error envelopes, and the behaviour of a very large `/v1/objects/hosts` response, are
  taken from documentation rather than observed.

## Future

- **Client certificate authentication.** `ApiUser` supports a `client_cn` attribute that
  matches the common name of a client certificate, which is how Icinga's own satellites
  authenticate and is meaningfully better than a shared password. This needs the client
  certificate and key to reach the HTTP client as an *identity* rather than as transport
  configuration, which the shared TLS include does not currently distinguish.
- **`joins` for host group and endpoint detail.** The API supports `joins` on a query, so
  a single host request could return each host's `check_command` object and its
  `command_endpoint` in the same response instead of leaving them as bare names. The
  strongest use is joining the `Endpoint` and `Zone` objects, which would tell runZero
  which satellite observed a host — useful for mapping monitored hosts onto runZero sites.
- **Downtime and acknowledgement as suppression signals.** `Downtime` and `Comment` are
  first-class objects with their own endpoints. A host in a scheduled downtime window is
  expected to be unreachable, and feeding that into runZero would stop a maintenance
  window from reading as an estate change.
- **The event stream.** `/v1/events` is a long-lived HTTP response that pushes
  `StateChange`, `ObjectCreated`, and `ObjectDeleted` events as newline-delimited JSON.
  It is a far better fit for incremental sync than re-reading every host on a schedule,
  and `jsonstream.iter_lines` is exactly the right tool for the body. What blocks it is
  that a custom integration task is a bounded run rather than a daemon, so consuming an
  unbounded stream needs a resume position and a run deadline. Worth revisiting.
- **Icinga Director and the IcingaDB REST API.** Most large installs configure Icinga
  through Director, whose own API exposes the imported source rows — often the CMDB or
  DHCP export the hosts were generated from, which carries serial numbers and MACs that
  never reach the Host object. IcingaDB's API likewise exposes the monitoring state from
  a relational store and would page properly, which would remove the single-array
  constraint this integration works around.
- **Outbound: push runZero assets into Icinga.** `PUT /v1/objects/hosts/<name>` creates a
  host object, which would let runZero-discovered assets be enrolled for monitoring
  automatically. This should be built carefully and default to off: creating objects in a
  monitoring master generates checks, notifications, and pages, so it needs a dedicated
  zone, a template chosen by the operator, and a dry-run mode.

## API documentation

- Icinga 2 API reference (authentication, permissions table, parameters,
  `X-HTTP-Method-Override`, filters and `filter_vars`, object queries, status codes):
  https://icinga.com/docs/icinga-2/latest/doc/12-icinga2-api/
- Object types reference (`Host` and `Service` configuration and runtime attributes,
  state encodings, `CheckResult` value type):
  https://icinga.com/docs/icinga-2/latest/doc/09-object-types/
- `ApiUser` object and `icinga2 api setup`:
  https://icinga.com/docs/icinga-2/latest/doc/12-icinga2-api/#setting-up-the-api
- Distributed monitoring, zones, and endpoints:
  https://icinga.com/docs/icinga-2/latest/doc/06-distributed-monitoring/
- Source: https://github.com/Icinga/icinga2
- API examples: https://github.com/Icinga/icinga2-api-examples

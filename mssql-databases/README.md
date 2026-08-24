# Microsoft SQL Server databases

Inbound integration that connects to a SQL Server instance using the
`runzero.sql` module and emits one runZero asset per database, with
recovery model, state, collation, creation date, and size metadata.

This is not an HTTP API integration. There is no token, no base URL and no
tenant: the Explorer opens a TDS connection to the instance with the
`github.com/microsoft/go-mssqldb` driver and runs two `SELECT` statements. The
credential is a SQL Server login.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the instance on its TDS port — 1433 by default. A
  named instance listening on a dynamic port needs that port opened and set
  explicitly; this integration does not speak the SQL Browser protocol on UDP
  1434, so it cannot resolve `HOST\INSTANCE` to a port for you.

## Required permissions

The account needs to read `sys.databases` and `sys.master_files`. Those two
views have **different** permission requirements, and the difference is the
single most common way this integration is misconfigured.

| View | Microsoft's documented requirement | Held by `public` by default? |
|---|---|---|
| `sys.databases` | `ALTER ANY DATABASE`, `VIEW ANY DATABASE`, or `CREATE DATABASE` in `master` | **Yes** — `public` holds `VIEW ANY DATABASE` |
| `sys.master_files` | `CREATE DATABASE`, `ALTER ANY DATABASE`, or `VIEW ANY DEFINITION` | **No** |

So `public` alone is *not* sufficient, despite appearing to work. The query
joins the two views with a `LEFT JOIN`, so a login holding only `public` still
gets one row per database — it just gets no matching file rows, and every asset
is imported with `database.size_kb` of `0`. Nothing errors and nothing in the
task log says the size is missing. If every database in runZero reports zero
size, this is why.

`VIEW ANY DEFINITION` is the least-privilege grant that fixes it. It is
server-wide metadata visibility; it does not grant read access to any data in
any table.

### Creating the login

```sql
CREATE LOGIN [runzero] WITH PASSWORD = 'ExampleFakePassw0rd!';

-- Required for sys.master_files. Without this every database reports 0 KB.
GRANT VIEW ANY DEFINITION TO [runzero];

-- Held by public by default; grant it explicitly only if your instance
-- revoked VIEW ANY DATABASE from public as a hardening measure.
GRANT VIEW ANY DATABASE TO [runzero];
```

`CREATE LOGIN` grants `CONNECT SQL` on its own, so no separate connect grant is
needed. The login needs no database user, no role membership in any user
database, and no `db_datareader` anywhere — it never reads application data.
Leave the **Initial catalog** as `master`, which `public` can always connect to.

Verify the grant took before configuring anything in runZero. Run this as the
new login; if `size_kb` comes back `NULL`, `VIEW ANY DEFINITION` did not apply:

```sql
SELECT d.name, SUM(CAST(mf.size AS BIGINT)) * 8 AS size_kb
FROM sys.databases d
LEFT JOIN sys.master_files mf ON mf.database_id = d.database_id
GROUP BY d.name;
```

Windows authentication is not available here — the driver is given a username
and password, so this must be a **SQL Server authentication** login, and the
instance must be in Mixed Mode. An instance set to Windows Authentication only
rejects the login regardless of the grants above.

## DSN format

Internally the script builds a `sqlserver://` URL DSN consumed by the
`github.com/microsoft/go-mssqldb` driver:

```
sqlserver://<username>:<password>@<host>:<port>?database=<database>&encrypt=<true|disable>[&trustservercertificate=true]
```

The username, password, and database components are **percent-encoded** before they are
interpolated, so a password containing `@ : / ? # % &` or a space cannot corrupt the URL
parse into a wrong host or a failed login. (The runZero CLI's `--kwargs` flag has its own
quoting rules for `=` and `,` — see **Running it from the command line** below — but the
DSN itself is safe for any password.)

The `encrypt` credential parameter is a boolean and maps to exactly two of the
driver's values: `true` when set, `disable` when clear. TLS encryption is on by
default; disable only on isolated test instances.

**Read this before turning encryption on against a stock SQL Server.**

In `go-mssqldb`, the DSN option `trustservercertificate` defaults to `false` whenever
`encrypt` is specified explicitly — which this script always does. With `encrypt` on,
the driver therefore **validates the server's certificate**: chain and hostname both.

A stock SQL Server install presents a **self-signed certificate** that nothing trusts. The
connection fails with a certificate error and does not fall back to an unencrypted session, so
the symptom is a task that cannot connect at all rather than one that connects insecurely.
The script prints a hint naming this exact failure mode before it connects.

That leaves three options, in order of preference:

1. **Install a certificate on the instance that the Explorer host trusts**, issued for the name
   you put in `host`. This is the correct answer and it is what SQL Server's own documentation
   recommends. Note the hostname has to match: connecting by IP to a certificate issued for an
   FQDN fails validation just as surely as an untrusted chain.
2. **Set `trust_server_certificate`** to keep the session encrypted while skipping certificate
   validation. This is the TDS equivalent of `tls_disable_validation` on the HTTP integrations:
   the wire is still encrypted, but the server is no longer authenticated, so an on-path
   attacker could impersonate it. It is opt-in and defaults to off so that a properly issued
   certificate is still verified.
3. **Clear `encrypt`** and accept an unencrypted TDS connection on a trusted network. The
   credential travels in that connection, so this is a real trade rather than a formality —
   prefer option 2 over this one.

## Steps

### SQL Server configuration

1. Confirm the instance accepts SQL Server authentication (Mixed Mode).
2. Create the login and grant `VIEW ANY DEFINITION` as above.
3. Note the host and port. For a named instance, look the port up in SQL Server
   Configuration Manager under **SQL Server Network Configuration > Protocols
   for `<instance>` > TCP/IP > IP Addresses**, and pin it to a static port if it
   is dynamic — a dynamic port changes on restart and silently breaks the task.
4. Decide the TLS posture described under **DSN format**.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "SQL Server databases").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **SQL Server host** (`host`): hostname or address of the instance.
   - **Port** (`port`): optional; default `1433`.
   - **Username** (`username`): the SQL login created above.
   - **Password** (`password`): that login's password.
   - **Initial catalog** (`database`): optional; default `master`. Leave it alone unless the login cannot connect to `master`.
   - **Require TLS encryption** (`encrypt`): optional; default **enabled**. Read the certificate note above before leaving it on — a stock self-signed instance needs either a trusted certificate installed or `trust_server_certificate` set.
   - **Trust the server certificate** (`trust_server_certificate`): optional; default **disabled**. Keeps the session encrypted while skipping certificate validation, for instances presenting a self-signed certificate.
   - **Query timeout (seconds)** (`timeout`): optional; default `30`, range 1–600.

   There are no `tls_*` or `http_*` options on this credential. The script declares no
   `includes` block because those configure the shared HTTP client, and this integration speaks
   TDS. `encrypt` and `trust_server_certificate` are its TLS controls.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes. Database inventory changes slowly, so daily is usually plenty.
   - Select the Explorer that can reach the instance.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it — and the fastest way to see whether
the login's grants are right. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename mssql-databases/mssql-databases.star \
  --kwargs host=sql01.example.com \
  --kwargs port=1433 \
  --kwargs username=runzero \
  --kwargs password='ExampleFakePassw0rd!' \
  --kwargs database=master \
  --kwargs encrypt=true \
  --kwargs timeout=30 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./mssql-databases-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for a fuller log, or omit `--output` to see only the log lines. Read
`database.size_kb` in the output: if every asset reports `0`, the login is missing
`VIEW ANY DEFINITION`, not failing to connect.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a password containing a comma is passed through intact. Only a password that *also*
contains an `=` flips the flag into comma-separated parsing, and then the value is cut at
the first comma — the remainder either becomes a fabricated second parameter or aborts
the run with `must be formatted as key=value`. Both characters are legal in a SQL Server
password, so wrap the whole argument in a second pair of quotes when one needs them:

```bash
  --kwargs '"password=Example=Fake,Passw0rd"'
```

To check the script compiles and its `CONFIG` block is well-formed:

```bash
runzero script --filename mssql-databases/mssql-databases.star --validate
```

This integration declares `"validationMode": "compile"`, so validation stops at
compilation and the CONFIG block. There is no HTTP wiring for the validator's dummy
server to exercise — the driver speaks TDS — so `--validate` proves nothing at all
about whether SQL Server is reachable, whether the login authenticates, whether TLS
negotiates, or whether any row is parsed. Only a real run against a real instance
tells you that. There are no fixture scenarios for this integration.

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat mssql-databases/mssql-databases.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'host=sql01.example.com,port=1433,username=runzero,password=ExampleFakePassw0rd!' \
  --output ./mssql-databases-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string, so a password containing a comma cannot be passed
this way; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- One asset is created per database, identified as `mssql://<host>:<port>/<database>`.
- Each asset carries the instance's `@@SERVERNAME` as its hostname and `@@VERSION` as its OS version.
- The integration declares `"matchBehavior": "no-name-match no-name-break"` once in `CONFIG`. Every database on one instance reports the same server hostname and none carries a MAC or IP, so allowing hostname matching would collapse the whole instance into a single asset and lose the per-database granularity this integration exists to provide.
- Search for everything this integration touched with `custom_integration:mssql-databases`, and inspect a specific field with `database.recovery_model:SIMPLE` or `database.state:ONLINE`.

## Asset identity

This integration models **a database as an asset**, which is unusual and is the decision every
other property here follows from. One SQL Server instance holding forty databases produces
forty runZero assets, all reporting the same server hostname and none carrying a MAC or an IP.

- Target entity: a database on one SQL Server instance, one row of `sys.databases`. System databases (`master`, `model`, `msdb`, `tempdb`) are included — the query does not filter them.
- Source ID field: **none from the server.** The id is `mssql://<host>:<port>/<name>`, built from the configured `host` and `port` plus the database `name` from `sys.databases`.
- Documentation evidence: `sys.databases.name` is the database's identifier within an instance and SQL Server enforces its uniqueness there. The instance side of the URI is configuration, not something read from the server — note in particular that it is **not** `@@SERVERNAME`, which the script does query and does use as the asset's hostname.
- Uniqueness scope: the `host:port` string as configured, plus the database name. That combination is genuinely unique in practice, and the URI form makes the namespace explicit — which is better than most of the ad-hoc ids in this library.
- Cardinality: one asset per database. The `LEFT JOIN` to `sys.master_files` is aggregated with `GROUP BY`, so a database spread across a dozen files is still one row and one asset.
- Stability: stable while both halves are stable, and each has a way of not being.
  - **Renaming a database changes its id.** `ALTER DATABASE ... MODIFY NAME` mints a new asset and strands the old one. `database_id` — a genuinely instance-stable integer — is collected and stored as the `database.id` attribute but is deliberately not used in the id, and that is the right call: SQL Server **reuses** `database_id` after a drop, so keying on it would merge a newly created database onto a dropped one's asset. Name churn producing a duplicate is the safer failure of the two.
  - **The instance half is configuration.** Re-pointing the credential from an IP to an FQDN, or changing the port, re-identifies every database on the instance in one run. This is the same property `windows-smb-shares` has, and the same convention fixes it: pick one addressing form and use it for every credential naming that instance.
- Reuse behavior: reusable in the ordinary way — a dropped and re-created database of the same name on the same instance inherits the previous asset. For a database that is usually the correct outcome.
- Presence: always produced. `name` defaults to an empty string if absent, which would yield a trailing-slash id rather than a skip; `sys.databases` does not return nameless rows, so this is not reachable in practice.
- Final runZero ID: `mssql://<host>:<port>/<database name>`, e.g. `mssql://sql01.example.com:1433/AdventureWorks`.
- Missing-ID behavior: no skip path. Every row becomes an asset.
- Match behavior (set once in `CONFIG`): **`no-name-match no-name-break`** — the only integration among this group that declares `matchBehavior` at all.
- Device type: **`Database`**, set unconditionally. It is a property of the query rather than of any column — every row of `sys.databases` is a database — and `Database` is one of runZero's own asset types, so it resolves without `trustDeviceType`. Nothing here reports a manufacturer or model, and hardware fingerprinting outranks a custom integration's `deviceType`, so this is the value the asset keeps.
- Verdict: configuration-scoped and deterministic. Authoritative for what it models, which is a database rather than a machine.

### Why `no-name-match no-name-break`, and why it is the right call

This is the one place in this group where the flags were chosen deliberately rather than left
at the default, and the reasoning is in the script's own comment. It is worth restating because
it is the crux of the whole design.

Every database on one instance reports **the same server hostname** — `@@SERVERNAME`, assigned
identically to all of them — and none of these assets carries a MAC or an IP. If hostname
matching were on, every database asset on an instance would be a merge candidate for every
other one, and runZero would collapse the whole instance into a single asset. That would
destroy exactly the per-database granularity this integration exists to provide.

So `no-name-match` switches off the hostname **match path** — which is what prevents the
collapse — and `no-name-break` switches off the corresponding veto, which is consistent rather
than load-bearing: with matching off there is no name-based merge left for a break to
disqualify.

Three consequences follow, and they are worth being explicit about:

- **`mac-break` and `ip-break` are still on and are entirely inert.** These assets have no network interfaces at all, so neither flag has anything to act on. They are on because they were not turned off, not because they are doing anything.
- **These assets merge with nothing.** With hostname matching off and no MAC or IP, the `mssql://` URI is the only identity, and the only thing it can match is a previous run of this same integration. A database asset will never merge onto the SQL Server host runZero discovered by scanning — which is correct, because it is not that host. Expect the instance to appear in runZero twice: once as the scanned server, and once per database as these records.
- **The hostname is still asserted, and still useful.** `@@SERVERNAME` is set on every asset even though it plays no part in matching, so it remains searchable and it is how an operator groups the forty databases belonging to one instance back together.

If you want one asset per **server** instead of one per database, the script's comment gives the
right answer: emit a single record per instance with the databases as attributes, rather than
changing this flag. Turning `no-name-match` off would not produce that — it would produce one
arbitrarily-merged asset with one database's attributes on it.

## Future

- **Listening endpoint data, so these assets can merge with the real server.** The largest structural gap. `sys.dm_exec_connections` exposes `local_net_address` and `local_tcp_port` for the current connection, which is the instance's own view of the address the Explorer reached it on. Emitting that as a `Service` on a per-instance asset — see the next item — would let the SQL Server show up as a service on the host runZero already scanned, rather than as a set of assets that merge with nothing.
- **An instance-level asset alongside the database assets.** `@@SERVERNAME`, `@@VERSION`, and `SERVERPROPERTY('Edition')`, `('ProductLevel')`, `('IsClustered')`, `('IsHadrEnabled')` describe the instance itself. A single asset per instance, keyed `mssql://<host>:<port>`, carrying those properties and the address above, would be the record that actually correlates with the scanned host — and it would give the database assets something to hang off. This is probably the single most valuable addition here.
- **Configuration and posture as findings.** SQL Server's security posture is entirely queryable and none of it is collected today: `sys.configurations` (xp_cmdshell enabled, CLR enabled, remote admin connections), `sys.server_principals` (the `sa` account's state, orphaned logins, logins with no password policy), `sys.database_permissions` and `sys.database_principals` (guest access, over-broad grants), and `sys.dm_database_encryption_keys` (whether TDE is on). Each is a documented misconfiguration a scanner cannot see from outside, and each is expressible as a runZero finding.
- **Backup state.** `msdb.dbo.backupset` records the last backup per database, joined on database name. "Which databases have never been backed up, or were last backed up months ago" is exactly the sort of question an inventory should answer, and this integration already produces the per-database assets to hang the answer on. Note it requires read access to `msdb`, which the current least-privilege grant does not include.
- **Availability groups and replicas.** `sys.availability_groups` and `sys.dm_hadr_availability_replica_states` describe which instances participate in an AG and which is primary. On a clustered estate, a database exists on several instances at once, and this integration's per-instance id means it currently appears as several unrelated assets with no indication they are replicas of one database.
- **Named-instance resolution.** As the requirements note, this integration does not speak the SQL Browser protocol on UDP 1434, so `HOST\INSTANCE` cannot be resolved to a port and a dynamic port has to be pinned by hand. Adding Browser support would remove the most fiddly part of the setup, and would also let one credential discover every instance on a host rather than one.
- **Filtering system databases.** `master`, `model`, `msdb`, and `tempdb` are imported alongside real databases and are identical on every instance in an estate. An `include_system_databases` parameter defaulting to off would cut the asset count meaningfully on a large SQL estate without losing anything anyone wants.
- **Outbound push-back is technically trivial and should not be built.** A SQL connection can write, so runZero data could in principle be inserted into a table. Nothing about that is a good idea: it would need a credential with write access to a production database, and there is no natural destination for the data. If SQL Server inventory needs to reach another system, it should go through runZero's own export API rather than back down this connection.
- **There is no event feed, and the alternatives are not integration-shaped.** SQL Server can push through Service Broker, Query Notifications, or Extended Events, but all of them require a long-lived subscriber and a session that outlives a task. A runZero custom integration is a scheduled run with a bounded lifetime, so this is a poll by necessity. Database inventory changes slowly, which is why the setup notes suggest a daily schedule.

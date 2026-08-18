#!/usr/bin/env python3
"""Create two user databases on the live server and read their catalog rows back.

A stock SQL Server has only its four system databases, and an integration that
emits one asset per database would then be asserted entirely against rows the
image happens to ship with. So this seed creates two user databases with
deliberately *different* catalog properties -- one FULL recovery, one SIMPLE --
and puts a real table with real rows in each, so the size the catalog reports is
a size something actually occupies rather than an empty file's floor.

Everything the manifest asserts is read back from sys.databases afterwards
rather than assumed. database_id in particular is assigned by the server in
creation order and is not something to hard-code: it is 5 and 6 on a fresh
container, but a re-run against a surviving container would produce different
values, and the manifest should keep asserting the right rows either way.

There is no SQL client on the host and none in the Edge image, so every
statement is run through `docker compose exec` into the sqlclient sidecar. See
compose.yml for why that sidecar exists.
"""

import json
import os
import subprocess
import sys
import time

COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
PROJECT = os.environ["RZ_PROJECT"]
HOST_PORT = os.environ["RZ_HOST_PORT"]

# Must match compose.yml. Written here rather than generated: the container is
# destroyed at the end of the test and is never reachable off loopback, and a
# fixed value keeps a failed run reproducible by hand.
SA_PASSWORD = "runZero-Test-Pw-2026!"

# The service the engine runs in, as compose DNS resolves it from the sidecar.
SERVER = "sqledge"
CLIENT_SERVICE = "sqlclient"
SQLCMD = "/opt/mssql-tools18/bin/sqlcmd"

# Bounds. The engine is already past its readiness gate by the time this runs,
# so a statement that does not return in a minute means something is wedged.
STATEMENT_TIMEOUT = 120
SETTLE_DEADLINE = 120

INVENTORY_DB = "rz_inventory"
METRICS_DB = "rz_metrics"

# Deliberately not the server default (SQL_Latin1_General_CP1_CI_AS). The
# integration copies `collation_name` per row, and if every database shared one
# collation a bug that reported the server's collation for all of them would
# pass unnoticed.
INVENTORY_COLLATION = "Latin1_General_100_CS_AS"


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def sqlcmd(query, database="master"):
    """Run one T-SQL batch in the sidecar. Returns stdout; dies on failure."""
    argv = [
        "docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
        "exec", "-T", CLIENT_SERVICE,
        SQLCMD,
        "-S", SERVER,
        "-U", "sa",
        "-P", SA_PASSWORD,
        # -C trusts the server's self-signed certificate. sqlcmd 18 encrypts by
        # default and would otherwise refuse the connection. Worth noticing:
        # this is the very knob mssql-databases.star does not expose, which is
        # why the manifest has to run the integration with encrypt=false. See
        # the note in manifest.json.
        "-C",
        "-d", database,
        "-b",            # non-zero exit on a SQL error, so a failure is not silent
        "-h", "-1",      # no column headers
        "-W",            # trim padding
        "-s", "|",       # field separator
        "-Q", "SET NOCOUNT ON; " + query,
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=STATEMENT_TIMEOUT)
    except subprocess.SubprocessError as exc:
        die("sqlcmd could not be run: %s" % exc)
    if proc.returncode != 0:
        die("sqlcmd failed (exit %d) for %r:\n%s\n%s"
            % (proc.returncode, query[:120], proc.stdout, proc.stderr))
    return proc.stdout


def rows(query, database="master"):
    """Run a query and return its rows as lists of trimmed strings."""
    out = []
    for line in sqlcmd(query, database=database).splitlines():
        line = line.strip()
        # sqlcmd prints trailing blank lines and, on some batches, a row-count
        # line even under SET NOCOUNT ON.
        if not line or line.startswith("(") and line.endswith("rows affected)"):
            continue
        out.append([field.strip() for field in line.split("|")])
    return out


def scalar(query, database="master"):
    result = rows(query, database=database)
    if not result or not result[0]:
        die("query returned no rows: %s" % query[:120])
    return result[0][0]


def create_databases():
    """Create both user databases, with content, idempotently."""
    # CREATE DATABASE cannot run inside a multi-statement batch that also uses
    # the database, so each step is its own batch.
    sqlcmd(
        "IF DB_ID('%s') IS NULL CREATE DATABASE [%s] COLLATE %s;"
        % (INVENTORY_DB, INVENTORY_DB, INVENTORY_COLLATION))
    sqlcmd("IF DB_ID('%s') IS NULL CREATE DATABASE [%s];" % (METRICS_DB, METRICS_DB))

    # FULL recovery on one and SIMPLE on the other, so recovery_model_desc is
    # actually discriminating rather than the same word on every asset.
    sqlcmd("ALTER DATABASE [%s] SET RECOVERY FULL;" % INVENTORY_DB)
    sqlcmd("ALTER DATABASE [%s] SET RECOVERY SIMPLE;" % METRICS_DB)

    # Real rows, so sys.master_files reports the size of something that exists.
    sqlcmd(
        "IF OBJECT_ID('dbo.hosts') IS NULL "
        "CREATE TABLE dbo.hosts (id INT PRIMARY KEY, name NVARCHAR(64), mac CHAR(17));",
        database=INVENTORY_DB)
    sqlcmd(
        "IF NOT EXISTS (SELECT 1 FROM dbo.hosts) INSERT INTO dbo.hosts (id, name, mac) "
        "VALUES (1, N'web01', '00:11:22:33:44:55'), (2, N'db01', '00:11:22:33:44:66');",
        database=INVENTORY_DB)
    sqlcmd(
        "IF OBJECT_ID('dbo.samples') IS NULL "
        "CREATE TABLE dbo.samples (id INT IDENTITY PRIMARY KEY, taken DATETIME2, value FLOAT);",
        database=METRICS_DB)
    sqlcmd(
        "IF NOT EXISTS (SELECT 1 FROM dbo.samples) INSERT INTO dbo.samples (taken, value) "
        "VALUES (SYSUTCDATETIME(), 1.5), (SYSUTCDATETIME(), 2.5);",
        database=METRICS_DB)

    # CHECKPOINT forces the pages out so the file size the catalog reports is
    # settled before the integration reads it.
    sqlcmd("CHECKPOINT;", database=INVENTORY_DB)
    sqlcmd("CHECKPOINT;", database=METRICS_DB)


def wait_until_online(names):
    """Both databases must report ONLINE before the integration looks at them."""
    deadline = time.time() + SETTLE_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        states = dict(
            (r[0], r[1]) for r in rows(
                "SELECT name, state_desc FROM sys.databases WHERE name IN (%s)"
                % ", ".join("'%s'" % n for n in names))
            if len(r) >= 2)
        if all(states.get(n) == "ONLINE" for n in names):
            return
        last = str(states)
        time.sleep(2)
    die("databases did not all come ONLINE within %ds (last: %s)"
        % (SETTLE_DEADLINE, last))


def catalog_row(name):
    """The sys.databases row the integration will see, for one database."""
    result = rows(
        "SELECT d.database_id, d.recovery_model_desc, d.state_desc, d.collation_name "
        "FROM sys.databases d WHERE d.name = '%s'" % name)
    if not result or len(result[0]) < 4:
        die("no sys.databases row for %s (got %r)" % (name, result))
    row = result[0]
    return {
        "id": row[0],
        "recovery_model": row[1],
        "state": row[2],
        "collation": row[3],
    }


def main():
    create_databases()
    wait_until_online([INVENTORY_DB, METRICS_DB])

    server_name = scalar("SELECT @@SERVERNAME")
    if not server_name or server_name.lower() in ("localhost", "unknown"):
        die("@@SERVERNAME is %r; the integration puts it in `hostnames`, where a "
            "placeholder would correlate this asset with every other placeholder "
            "in the estate. Check `hostname:` in compose.yml." % server_name)

    database_count = scalar("SELECT COUNT(*) FROM sys.databases")

    inventory = catalog_row(INVENTORY_DB)
    metrics = catalog_row(METRICS_DB)

    # msdb's create_date is baked into the image at build time -- every
    # container from this tag reports the same instant -- so the manifest can
    # assert the emitted value as a literal. It is echoed here as the server
    # renders it so that a failure shows both halves of the conversion side by
    # side: the catalog says "2023-01-25 11:15:47.897", the asset says
    # "2023-01-25T11:15:47.897Z". `database.created` is the one place in this
    # integration where a SQL DATETIME crosses out of the driver into a Starlark
    # string, and nothing else in the suite pins how that renders.
    msdb_created_raw = scalar(
        "SELECT CONVERT(VARCHAR(33), create_date, 126) FROM sys.databases WHERE name = 'msdb'")

    print(json.dumps({
        "port": HOST_PORT,
        "server_name": server_name,
        "database_count": database_count,
        "msdb_created_raw": msdb_created_raw,
        "inventory_db": INVENTORY_DB,
        "inventory_id": inventory["id"],
        "inventory_recovery": inventory["recovery_model"],
        "inventory_state": inventory["state"],
        "inventory_collation": inventory["collation"],
        "metrics_db": METRICS_DB,
        "metrics_id": metrics["id"],
        "metrics_recovery": metrics["recovery_model"],
        "metrics_collation": metrics["collation"],
    }))


if __name__ == "__main__":
    main()

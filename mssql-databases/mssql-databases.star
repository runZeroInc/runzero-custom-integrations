CONFIG = {
    "id": "runzero-mssql-databases",
    "name": "Microsoft SQL Server databases",
    "type": "inbound",
    "description": "Connects to a SQL Server instance and emits one asset per database with size and recovery model metadata.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Every database on one instance necessarily reports the same
    # server hostname, and these assets carry no MAC or IP, so hostname
    # matching would find all of them as candidates for each other and
    # collapse the whole instance into a single asset — losing exactly
    # the per-database granularity this integration exists to provide.
    # The mssql:// URI is the authoritative identity. To model one asset
    # per server instead, emit a single record per instance with the
    # databases as attributes rather than changing this flag.
    "matchBehavior": "no-name-match no-name-break",
    "validationMode": "compile",
    "params": [
        {"key": "host", "label": "SQL Server host", "type": "string", "required": True},
        {"key": "port", "label": "Port", "type": "int", "required": False, "default": 1433, "min": 1, "max": 65535},
        {"key": "username", "label": "Username", "type": "string", "required": True},
        {"key": "password", "label": "Password", "type": "secret", "required": True, "description": "SQL Server authentication password. Any characters are safe: the value is percent-encoded into the connection string."},
        {"key": "database", "label": "Initial catalog", "type": "string", "required": False, "default": "master"},
        {"key": "encrypt", "label": "Require TLS encryption", "type": "bool", "required": False, "default": True},
        {"key": "trust_server_certificate", "label": "Trust the server certificate", "type": "bool", "required": False, "default": False},
        {"key": "timeout", "label": "Query timeout (seconds)", "type": "int", "required": False, "default": 30, "min": 1, "max": 600},
    ],
}

load("runzero.types", "ImportAsset")
load("runzero.sql", sql_connect="connect")
load("kwargs", "require", "get_string", "get_int", "get_bool")


_QUERY = """
SELECT
    d.database_id,
    d.name,
    d.recovery_model_desc,
    d.state_desc,
    d.collation_name,
    d.create_date,
    SUM(CAST(mf.size AS BIGINT)) * 8 AS size_kb
FROM sys.databases d
LEFT JOIN sys.master_files mf ON mf.database_id = d.database_id
GROUP BY d.database_id, d.name, d.recovery_model_desc, d.state_desc, d.collation_name, d.create_date
ORDER BY d.name
"""


# RFC 3986 unreserved characters: the only bytes that pass through _dsn_escape
# unencoded. Everything else is percent-encoded.
_DSN_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
_HEX_DIGITS = "0123456789ABCDEF"


def _dsn_escape(value):
    """Percent-encode one component of the sqlserver:// DSN.

    The DSN is parsed as a URL, so a password holding @ : / ? # % or & would
    otherwise corrupt the parse -- the wrong host, or a failed login with a
    misleading error. Encoding walks UTF-8 bytes, so multi-byte characters
    are encoded correctly too.
    """
    out = []
    for b in bytes(value).elems():
        ch = chr(b)
        if ch in _DSN_UNRESERVED:
            out.append(ch)
        else:
            out.append("%" + _HEX_DIGITS[b // 16] + _HEX_DIGITS[b % 16])
    return "".join(out)


def _dsn(host, port, username, password, database, encrypt, trust_cert):
    enc = "true" if encrypt else "disable"
    dsn = "sqlserver://{}:{}@{}:{}?database={}&encrypt={}".format(
        _dsn_escape(username), _dsn_escape(password), host, port,
        _dsn_escape(database), enc,
    )
    # A stock SQL Server presents a self-signed certificate generated at install
    # time, which no trust store contains. With encrypt=true and nothing else,
    # the TLS handshake fails and the integration cannot connect to a default
    # installation at all -- so this is the difference between working and not
    # working on most deployments, not a hardening nicety. It is opt-in and
    # defaults to False so that a properly issued certificate is still verified.
    if trust_cert:
        dsn += "&trustservercertificate=true"
    return dsn


def main(*args, **kwargs):
    require(kwargs, "host", "username", "password")
    host = get_string(kwargs, "host")
    port = get_int(kwargs, "port", default=1433)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    database = get_string(kwargs, "database", default="master")
    encrypt = get_bool(kwargs, "encrypt", default=True)
    trust_cert = get_bool(kwargs, "trust_server_certificate", default=False)
    timeout = get_int(kwargs, "timeout", default=30)

    dsn = _dsn(host, port, username, password, database, encrypt, trust_cert)

    # Starlark cannot intercept a raise from a builtin, so a failed connect or
    # query still errors the task. These context lines make the driver's raw
    # error attributable -- go-mssqldb's message names neither the target nor
    # the TLS knobs. The password never appears in the log.
    print("mssql: connecting to {}:{} as {} (database={}, encrypt={}, trust_server_certificate={})".format(
        host, port, username, database, encrypt, trust_cert))
    if encrypt and not trust_cert:
        print("mssql: certificate validation is on; if the connect fails with a TLS handshake error, " +
              "the instance is presenting an untrusted (usually self-signed) certificate -- install a " +
              "trusted one or enable trust_server_certificate")

    # connect() pings eagerly, so an unreachable host, a rejected login, and a
    # failed TLS handshake all surface here, before any handle exists. The
    # runtime registers the session with a closer at connect(), so even a
    # raise inside query() cannot leak the connection past the script's end;
    # the explicit close below runs as soon as both reads finish.
    db = sql_connect(driver="mssql", dsn=dsn, timeout=timeout)
    server_info = db.query("SELECT @@SERVERNAME AS server, @@VERSION AS version")
    rows = db.query(_QUERY)
    db.close()

    server_name = host
    server_version = ""
    if len(server_info) > 0:
        row = server_info[0]
        if row.get("server"):
            server_name = row["server"]
        if row.get("version"):
            server_version = row["version"]

    total = 0
    for row in rows:
        db_id = row.get("database_id")
        name = row.get("name") or ""
        asset = ImportAsset(
            id="mssql://{}:{}/{}".format(host, port, name),
            hostnames=[server_name],
            os="Microsoft SQL Server",
            osVersion=server_version,
            # Every asset this integration emits is one row of sys.databases, so
            # the type is a property of the query, not of any per-row field.
            # "Database" is one of runZero's own asset types, so it resolves on
            # the exact-match list and needs no trustDeviceType. Nothing here
            # sets manufacturer or model, so hardware fingerprinting -- which
            # outranks a custom integration's deviceType -- has nothing to say
            # and this value is what the asset ends up with.
            deviceType="Database",
            customAttributes={
                "database.id": "{}".format(db_id) if db_id != None else "",
                "database.name": name,
                "database.recovery_model": row.get("recovery_model_desc") or "",
                "database.state": row.get("state_desc") or "",
                "database.collation": row.get("collation_name") or "",
                "database.created": row.get("create_date") or "",
                "database.size_kb": "{}".format(row.get("size_kb") or 0),
                "server.host": host,
                "server.port": "{}".format(port),
            },
        )
        # Stream each asset as it is built rather than accumulating a list.
        total += report_asset(asset)

    print("mssql: reported {} database assets from {}:{}".format(total, host, port))
    if not total:
        print("no assets")
    return None

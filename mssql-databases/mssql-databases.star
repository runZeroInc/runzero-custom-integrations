CONFIG = {
    "id": "runzero-mssql-databases",
    "name": "Microsoft SQL Server databases",
    "type": "inbound",
    "description": "Connects to a SQL Server instance and emits one asset per database with size and recovery model metadata.",
    "version": "26052700",
    "minVersion": "5.1.0",
    "validationMode": "compile",
    "params": [
        {"key": "host", "label": "SQL Server host", "type": "string", "required": True},
        {"key": "port", "label": "Port", "type": "int", "required": False, "default": 1433, "min": 1, "max": 65535},
        {"key": "username", "label": "Username", "type": "string", "required": True},
        {"key": "password", "label": "Password", "type": "secret", "required": True},
        {"key": "database", "label": "Initial catalog", "type": "string", "required": False, "default": "master"},
        {"key": "encrypt", "label": "Require TLS encryption", "type": "bool", "required": False, "default": True},
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


def _dsn(host, port, username, password, database, encrypt):
    enc = "true" if encrypt else "disable"
    return "sqlserver://{}:{}@{}:{}?database={}&encrypt={}".format(
        username, password, host, port, database, enc,
    )


def main(*args, **kwargs):
    require(kwargs, "host", "username", "password")
    host = get_string(kwargs, "host")
    port = get_int(kwargs, "port", default=1433)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    database = get_string(kwargs, "database", default="master")
    encrypt = get_bool(kwargs, "encrypt", default=True)
    timeout = get_int(kwargs, "timeout", default=30)

    dsn = _dsn(host, port, username, password, database, encrypt)
    db = sql_connect(driver="mssql", dsn=dsn, timeout=timeout)

    server_info = db.query("SELECT @@SERVERNAME AS server, @@VERSION AS version")
    server_name = host
    server_version = ""
    if len(server_info) > 0:
        row = server_info[0]
        if row.get("server"):
            server_name = row["server"]
        if row.get("version"):
            server_version = row["version"]

    rows = db.query(_QUERY)
    db.close()

    assets = []
    for row in rows:
        db_id = row.get("database_id")
        name = row.get("name") or ""
        asset = ImportAsset(
            id="mssql://{}:{}/{}".format(host, port, name),
            hostnames=[server_name],
            os="Microsoft SQL Server",
            osVersion=server_version,
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
        assets.append(asset)

    # Stream assets to runZero via report_assets instead of returning a list.
    if not report_assets(assets):
        print("no assets")
    return None

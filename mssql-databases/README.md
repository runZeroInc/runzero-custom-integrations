# Microsoft SQL Server databases

Inbound integration that connects to a SQL Server instance using the
`runzero.sql` module and emits one runZero asset per database, with
recovery model, state, collation, creation date, and size metadata.

## Required permissions

The account used must be able to read `sys.databases` and
`sys.master_files`. The built-in `public` role is sufficient on most
deployments.

## DSN format

Internally the script builds a `sqlserver://` URL DSN consumed by the
`github.com/microsoft/go-mssqldb` driver. TLS encryption is on by
default; disable only on isolated test instances.

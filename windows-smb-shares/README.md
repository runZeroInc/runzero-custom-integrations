# Windows SMB shares

Inbound integration that authenticates to a Windows host over SMB2/3
using NTLMv2, lists all advertised shares, and counts the entries in
each share that the supplied account can access.

## Authentication

Provide **either** a password **or** an NTLM hash (hex-encoded). NTLM
hashes let operators run the integration without exposing the
plaintext password.

If the username includes a backslash (e.g. `ACME\svc-runzero`) the
domain is parsed automatically; otherwise pass `domain` explicitly.

## Output

A single asset is reported per target host with custom attributes:

- `smb.target` — `host:port`
- `smb.share_count` — total advertised share count
- `smb.accessible_share_count` — shares whose root we listed
  successfully
- `share.<name>` — `listed` flag per advertised share
- `share.<name>.entries` — first 20 top-level entries (when readable)

Admin shares ending in `$` (other than `ADMIN$`) are not enumerated by
default to avoid scanning user home directories.

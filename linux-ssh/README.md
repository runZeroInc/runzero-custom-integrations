# Linux via SSH

Inbound integration that authenticates to a Linux/Unix host over SSH,
collects basic identification facts, and reports the system as a single
runZero asset.

## What it collects

- Fully qualified hostname (`hostname -f`)
- OS distribution and version (`/etc/os-release`)
- Kernel release (`uname -r`)
- `/etc/machine-id` for stable asset identity
- IPv4 / IPv6 addresses and MAC addresses for every interface
  reported by `ip link` / `ip addr`

## Authentication

Provide **either** a password **or** an OpenSSH private key (PEM format).
You may also supply a passphrase for an encrypted key.

The `host_key` field accepts the server's public key in
`authorized_keys` format (e.g. `ssh-ed25519 AAAA…`). When supplied, the
script pins the host key and refuses to connect to any other key. If
left blank, the host key is not verified — only use that mode in
trusted networks where the SSH endpoint identity is otherwise enforced.

## Required tools on the target

- `bash`, `cat`, `hostname`, `uname`
- `ip` (from `iproute2`) for interface enumeration

If the target image does not provide `iproute2`, the network interfaces
list will be empty but the asset will still be reported.

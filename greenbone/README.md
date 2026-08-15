# Greenbone (GMP) Import

Inbound integration that connects to a Greenbone / OpenVAS scanner over the
**Greenbone Management Protocol (GMP)** and imports the latest scan results as
runZero assets, complete with services, software, and vulnerabilities.

It pairs with **[Greenbone (GMP) Scan Launch](../greenbone-scan/README.md)**:
assets discovered by runZero can be scanned in Greenbone, and the results
scanned in Greenbone can be imported back into runZero.

## What it imports

For each task's most recent report (within the configured age window):

- **Assets** — one per scanned host, keyed by the Greenbone host asset ID
  (falling back to `greenbone:<ip>`), with OS name/CPE, hostnames, and MAC/IP
  network interfaces.
- **Services** — open ports (TCP/UDP) with detected service name, banner, and
  per-port severity.
- **Software** — application CPEs detected on the host (`cpe:/a:…`), parsed into
  vendor / product / version.
- **Vulnerabilities** — one per CVE (or per NVT when no CVE), with name,
  description, solution, CVSS base score, severity rank, QoD, and the NVT OID.

Reports are streamed page-by-page and assets are emitted with `report_assets`
as each host completes, so memory stays bounded regardless of report size.

## Transports

Choose one with the **Transport** setting:

- **`ssh`** (default) — SSH into the appliance and forward to the local gvmd
  UNIX socket (`/run/gvmd/gvmd.sock` by default). No `socat`/`netcat` helper is
  required on the appliance; the forward uses the SSH `direct-streamlocal`
  channel (equivalent to `ssh -L localport:/run/gvmd/gvmd.sock`). Authenticate
  with an SSH password or private key, and pin the appliance host key with
  `ssh_host_key` (authorized_keys format from `ssh-keyscan`).
- **`tls`** — connect directly to the GMP TLS listener (port `9390` by default).
  Uses the standard runZero TLS options (`tls_disable_validation`, `tls_ca_cert`,
  `tls_peer_hash` thumbprint pinning, and client certificates).

Both transports authenticate to GMP with **`gmp_username`** / **`gmp_password`**.

## Selecting what to import

- **Maximum report age (days)** — only import a task's latest report if it
  finished within this window (default `30`; `0` disables the limit).
- **Task filter (GMP)** — optional GMP filter selecting which tasks to import,
  e.g. `name~Production`.
- **Report result filter (GMP)** — optional extra GMP filter terms applied to
  report results, e.g. `os~Windows`.
- **Severity levels** — `h`igh, `m`edium, `l`ow, lo`g`. Include `g` (the
  default) so hosts with no vulnerabilities are still imported as assets.
- **Minimum QoD** — minimum Quality of Detection (default `70`).
- **Results per page** — GMP page size (default `100`); larger values reduce
  round-trips at the cost of more memory per page.

## Notes

- The integration runs on the selected Explorer and connects to the Greenbone
  appliance, which is typically on an internal network. Scope the Explorer and
  credentials accordingly.
- Tested against Greenbone Community Edition (gvmd 22.6 / GVM 25.2.1).

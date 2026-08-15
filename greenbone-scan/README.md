# Greenbone (GMP) Scan Launch

Internal integration that reads matching assets from runZero, exports their
**primary addresses**, and launches a Greenbone / OpenVAS scan against them over
the **Greenbone Management Protocol (GMP)**.

It pairs with **[Greenbone (GMP) Import](../greenbone/README.md)**: addresses
scanned by runZero can be scanned in Greenbone, and the Greenbone results can be
imported back into runZero — a closed loop between the two systems.

## What it does

1. Calls the runZero **export CSV** endpoint
   (`/api/v1.0/export/org/assets.csv`) with your search filter and collects the
   primary `address` of each matching asset (de-duplicated, validated, capped at
   **Maximum hosts**).
2. Connects to Greenbone over GMP and authenticates.
3. Creates a **target** containing those addresses (using the configured port
   list), creates a **task** (using the configured scan config and scanner), and
   — unless disabled — **starts** the scan. The new report ID is logged.

If task creation fails, the just-created target is rolled back so a failed run
does not leave orphaned objects on the appliance.

## runZero export

- **runZero console URL** — e.g. `https://console.runzero.com`.
- **runZero Export API key** — an organization Export API key.
- **Export search filter** — runZero asset search selecting the scan targets.
  Empty means all assets. Examples: `os:Windows`, `last_seen:<30d`,
  `first_seen:<3d`.
- **Maximum hosts** — cap on the number of addresses sent to Greenbone.

The export request uses the standard runZero HTTP/TLS options (prefixed
`rz_http_` / `rz_tls_`).

## Transports

Same as the import integration — choose **`ssh`** (forward to the gvmd UNIX
socket over SSH; no remote helper needed) or **`tls`** (connect to the GMP TLS
port directly with the standard runZero TLS trust/thumbprint/client-cert
options). Authenticate to GMP with **`gmp_username`** / **`gmp_password`**.

## Scan definition

- **Target/task name prefix** — a timestamp is appended to keep each run unique.
- **Scan config ID** — default `daba56c8-73ec-11df-a475-002264764cea`
  (*Full and fast*).
- **Scanner ID** — default `08b69003-5fc2-4037-a479-93b440211c73`
  (*OpenVAS Default*).
- **Port list ID** — default `33d0cd82-57c6-11e1-8ed1-406186ea4fc5`
  (*All IANA assigned TCP*).
- **Start scan immediately** — create-only when disabled.

## Notes

- The integration runs on the selected Explorer and connects to the Greenbone
  appliance, which is typically on an internal network. Scope the Explorer and
  credentials accordingly.
- Tested against Greenbone Community Edition (gvmd 22.6 / GVM 25.2.1).

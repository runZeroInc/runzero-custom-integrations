# Windows WMI integration

Imports basic Windows asset information into runZero by querying
`Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_NetworkAdapterConfiguration`,
`Win32_Service`, and `Win32_Product` from a single Windows host.

The script supports two transports:

- **WinRM** (default): SOAP-over-HTTP/S using the Windows Remote Management
  service. Default ports 5985/HTTP and 5986/HTTPS. NTLM auth is preferred;
  Basic auth is only safe over HTTPS with a trusted CA.
- **DCE/RPC WMI**: Direct DCOM/MS-WMI. Uses TCP/135 (`ncacn_ip_tcp`) by
  default or named pipes over TCP/445 (`ncacn_np`) when
  `transport=wmi-smb`.

The integration is "one host per run". To scan many hosts, schedule one
job per credential/target pair, or extend the script to loop.

## Parameters

| key                    | type   | required | description                                              |
| ---------------------- | ------ | -------- | -------------------------------------------------------- |
| `host`                 | string | yes      | Hostname or IP of the Windows target                     |
| `username`             | string | yes      | `DOMAIN\user`, `user@domain`, or local account name      |
| `password`             | secret | yes      | Account password                                         |
| `transport`            | enum   | no       | `winrm-https`, `winrm-http`, `wmi-tcp`, `wmi-smb`        |
| `winrm_port`           | int    | no       | Override default 5985/5986                               |
| `winrm_insecure`       | bool   | no       | Skip TLS verification (NOT for production)               |
| `winrm_ca_cert`        | string | no       | PEM-encoded CA chain for the target                      |
| `winrm_auth`           | enum   | no       | `ntlm` (default) or `basic`                              |
| `wmi_namespace`        | string | no       | Defaults to `//./root/cimv2`                             |
| `timeout`              | int    | no       | Per-operation timeout in seconds (default 60, max 600)   |

## Example

```sh
runzero script --filename windows-wmi/windows-wmi.star \
  --kwargs host=10.0.0.5 \
  --kwargs username='ACME\svc-runzero' \
  --kwargs password='…' \
  --kwargs transport=winrm-https
```

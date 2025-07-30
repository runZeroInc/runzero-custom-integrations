## Proxmox VE Custom Integration for runZero

This custom integration discovers Proxmox VE cluster nodes, QEMU VMs and LXC containers, and imports them into runZero as assets—complete with hostnames, management IPs, in-guest IPs, MAC addresses, device metadata, and custom attributes. A global `DEBUG` flag controls verbose logging.

---

## Features

* **Cluster Nodes**

  * Discovers all nodes via `/nodes`
  * Captures management IP, CPU/memory/disk stats, uptime, status

* **QEMU VM Discovery**

  * Enumerates VMs via `/nodes/{node}/qemu`
  * Fetches live in-guest interfaces (MAC + IP) via the QEMU Guest Agent
  * Falls back to parsing VM config for MACs and to `/status/current` for IPs

* **LXC Container Discovery**

  * Enumerates containers via `/nodes/{node}/lxc`
  * Parses container config for MACs and `/status/current` for IPs

* **Insecure TLS**

  * Global `INSECURE_ALLOWED = True|False` allows connections to endpoints without valid TLS certificates

* **Debug Logging**

  * Global `DEBUG = True|False` toggles all `print("DEBUG: …")` statements

---

## Prerequisites

### 1. Proxmox VE API Token

Create a token in **Datacenter → Permissions → API Tokens** (e.g. `root@pam!monitoring`) and note its UUID secret.

#### Required Privileges

To ensure the script can read node, VM, container, storage, and other resource details, grant **Audit/Monitor** privileges at the root (`/`) path (with “Propagate” checked) or individually:

| Resource                                   | ACL Path    | Minimum Privilege |
| ------------------------------------------ | ----------- | ----------------- |
| Cluster nodes                              | `/nodes`    | `Sys.Audit`       |
| QEMU VMs                                   | `/vms`      | `VM.Audit`        |
| Guest-Agent commands                       | `/vms/VMID` | `VM.Monitor`      |
| LXC containers                             | `/lxc`      | `PVEVM.Audit`     |
| Storage                                    | `/storage`  | `Datastore.Audit` |
| Pools                                      | `/pool`     | `Pool.Audit`      |
| SDN                                        | `/sdn`      | `SDN.Audit`       |
| (Or use built-in “PVEAuditor” role at `/`) |             |                   |

### 2. runZero Console

1. **Credentials** → **Add Credential** → **Custom Script Secret**

   * **Access Key**: any placeholder (e.g. `foo`)
   * **Access Secret**: your JSON config (see below)

2. **Integrations** → **Custom Integrations** → **Add Script**

   * Paste the Starlark code (with the `DEBUG` global at top)
   * Save and attach to a discovery job

---

## Configuration

**Access Secret** (paste as a single-line JSON string):

```json
{"base_url":"https://your.proxmox.server:8006","access_key":"root@pam!monitoring","access_secret":"123e4567-e89b-12d3-a456-426614174000"}
```

| Field           | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `base_url`      | Proxmox API URL (including port), e.g. `https://pve.local:8006` |
| `access_key`    | Your API token ID, e.g. `root@pam!monitoring`                   |
| `access_secret` | UUID secret of your API token                                   |

---

## Script Entry Point

```python
# Toggle debug prints on or off
DEBUG = True

def main(*args, **kwargs):
    """
    Entrypoint for Proxmox VE integration.
    Expects kwargs['access_secret'] to be a JSON string containing:
      - base_url:      Proxmox URL
      - access_key:    API token ID
      - access_secret: API token secret (UUID)
    Returns: list of ImportAsset objects for nodes, VMs, containers.
    """
    # (…script code with DEBUG guards…)
```

---

## Running the Integration

1. **Associate** the custom script with a discovery job.
2. **Select** the credential (Access Key=`foo`, your JSON `access_secret`).
3. **Run** the scan.
4. **Review** discovered assets—nodes, VMs, and containers with IPs and MACs—in runZero.

---

## Extending the Integration

* **Additional Resources**: Call `/cluster/resources` to pull storage, pools, SDN, OpenVZ, etc., as generic assets.
* **Network Topology**: Query `/nodes/{node}/status/network` for full NIC details on cluster nodes.
* **Custom Tags**: Map Proxmox tags or pool names into runZero asset tags.

---

## Support

For help, contact your runZero administrator or see the [runZero docs](https://docs.runzero.com).

## Proxmox VE Custom Integration for runZero

This custom integration discovers Proxmox VE cluster nodes and imports them into runZero as assets, complete with hostnames, management IPs, device metadata, and custom attributes.

---

## Features

* **Automatic Discovery**: Enumerates all Proxmox VE cluster nodes via the REST API.
* **Rich Metadata**: Captures OS version, hostnames, management IPs, CPU/memory/disk stats, uptime, and more.
* **Flexible Configuration**: Pass a single JSON blob containing your Proxmox URL and API token parameters.

---

## Prerequisites

1. **Proxmox VE API Token**

   * Create an API token in the Proxmox UI (e.g. `root@pam!monitoring`).
   * Copy the token’s UUID secret.

2. **runZero Console**

   * Go to **Credentials** → **Add Credential** → **Custom Script Secret**.
   * **Access Key**: can be any placeholder (e.g. `foo`).
   * **Access Secret**: paste your JSON configuration (see below).

3. **Script Upload**

   * In **Integrations** → **Custom Integrations**, create a new script.
   * Copy the provided Starlark script into the editor.
   * Save and assign to your discovery task.

---

## Configuration

When you create or edit your credential in runZero:

* **Access Key**:

  ```text
  foo
  ```
* **Access Secret**: a single-line JSON string (no spaces), for example:

  ```json
  {"base_url":"https://your.proxmox0-console.com","access_key":"root@pam!monitoring","access_secret":"123e4567-e89b-12d3-a456-426614174000"}
  ```

| JSON Field      | Description                                                             |
| --------------- | ----------------------------------------------------------------------- |
| `base_url`      | Proxmox UI URL (including port), e.g. `https://lab-vm.runzero.com:8006` |
| `access_key`    | Your Proxmox API token ID, e.g. `root@pam!monitoring`                   |
| `access_secret` | The UUID secret of your API token                                       |

---

## Script Entry Point

```python
def main(*args, **kwargs):
    """
    Entrypoint for Proxmox VE integration.
    Expects kwargs['access_secret'] to be a JSON string containing:
      - base_url:       Proxmox URL
      - access_key:     API token ID
      - access_secret:  API token secret (UUID)
    Returns: list of ImportAsset objects for each cluster node.
    """
    # (Script code as provided...)
```

---

## Running the Integration

1. **Associate** the custom integration with a discovery job in runZero.
2. **Select** the credential you created (with Access Key=`foo` and your JSON `access_secret`).
3. **Launch** the scan.
4. **Review** discovered Proxmox nodes in the Assets view.

---

## Extending the Integration

* **Network Details**: Query `/nodes/{node}/status/network` for full NIC enumeration.
* **Guest Workloads**: Import VMs via `/nodes/{node}/qemu` and containers via `/nodes/{node}/lxc`.
* **Additional Metadata**: Add fields such as storage usage, firewall settings, or custom tags.

---

## Support

For questions or assistance, please reach out to your runZero administrator or consult the [runZero documentation](https://docs.runzero.com).

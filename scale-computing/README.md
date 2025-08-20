## Scale API v1 Custom Integration for runZero

This custom integration discovers Scale clusters and virtual machines (VirDomain), enriches them with network‐device details (MACs, IPs, VLANs), and imports everything into runZero as assets—complete with hostnames, OS info, memory/CPU, state, console settings, boot order, snapshots, replication metadata, and custom attributes. A global `DEBUG` flag controls verbose logging, and `INSECURE_ALLOWED` lets you opt into insecure TLS.

---

## Features

* **Scale Clusters**

  * Discovers all clusters via `GET /rest/v1/Cluster`
  * Captures each cluster’s UUID and name

* **Virtual Machine Discovery**

  * Enumerates VMs via `GET /rest/v1/VirDomain`
  * Pulls VM properties:

    * **ID/UUID**, **hostname**, **operatingSystem**, **description**
    * **State**, **desiredDisposition**, **console** (type, IP, port, keymap)
    * **Boot devices**, **UI state**, **snapshot UUIDs**, **snapshot serial**, **replication UUIDs**, **source VM UUID**
    * **Memory** (bytes), **CPU count**, **tags**, **created/modified timestamps**

* **Network Interface Details**

  * Fetches `/rest/v1/VirDomainNetDevice` to get per‐interface:

    * **MAC address**, **IPv4 addresses**, **VLAN tag**, **connected flag**

* **Insecure TLS**

  * Set `INSECURE_ALLOWED = True|False` to allow/deny endpoints without valid certificates

* **Debug Logging**

  * Set `DEBUG = True|False` at the top of the script to toggle all `debug_print()` output

---

## Prerequisites

### 1. Scale API v1 Credentials

You need a Scale user (or API token) with read access to:

* **Cluster** (`/rest/v1/Cluster`)
* **VirDomain** (`/rest/v1/VirDomain`)
* **VirDomainNetDevice** (`/rest/v1/VirDomainNetDevice`)

Make note of:

| Field           | Description                                    |
| --------------- | ---------------------------------------------- |
| `base_url`      | Scale API endpoint, e.g. `https://scale.local` |
| `access_key`    | Your Scale username or token ID                |
| `access_secret` | Your Scale password or token secret            |

### 2. runZero Console

1. **Credentials** → **Add Credential** → **Custom Script Secret**

   * **Access Key**: any placeholder (e.g. `foo`)
   * **Access Secret**: your JSON config (see below)

2. **Integrations** → **Custom Integrations** → **Add Script**

   * Paste the Starlark code (with `INSECURE_ALLOWED` and `DEBUG` at top)
   * Save and tie it to a discovery job

---

## Configuration

**Access Secret** (paste as a single-line JSON string):

```json
{"base_url":"https://scale.api.server","access_key":"scale_user","access_secret":"s3cr3tP@ssw0rd"}
```

| Field           | Description                                                   |
| --------------- | ------------------------------------------------------------- |
| `base_url`      | Scale API URL (no trailing slash), e.g. `https://scale.local` |
| `access_key`    | Scale username or token ID                                    |
| `access_secret` | Scale password or token secret                                |

---

## Script Entry Point

```python
# Toggle TLS verification
INSECURE_ALLOWED = True

# Toggle verbose debug logs
DEBUG = True

def main(*args, **kwargs):
    """
    Entrypoint for Scale API v1 integration.
    Expects kwargs['access_secret'] to be a JSON string containing:
      - base_url       : Scale API URL
      - access_key     : Username or token ID
      - access_secret  : Password or token secret
    Returns: list of ImportAsset objects for clusters and VMs.
    """
    # …script code with debug_print(), json_decode(), base64_encode(), Session, etc.…
```

---

## Running the Integration

1. **Associate** this custom script with a discovery job in runZero.
2. **Select** the credential you created (Access Key=`foo`, Access Secret=`{...JSON...}`).
3. **Run** the scan.
4. **Review** discovered assets—clusters and VMs with full network, OS, and metadata—in your runZero inventory.

---

## Extending the Integration

* **Block Devices**: Call `GET /rest/v1/VirDomainBlockDevice` to capture VM disks and storage info.
* **Snapshots & Replication**: Pull full snapshot details or replication schedules via `/rest/v1/Snapshot` and `/rest/v1/Replication`.
* **Metrics & Performance**: Integrate host-level metrics (CPU, memory, disk I/O) via Scale’s monitoring endpoints.
* **Custom Tags & Attributes**: Map additional Scale properties into `customAttributes` for richer asset context.

---

## Support

For assistance, reach out to your runZero administrator or consult the [runZero documentation](https://docs.runzero.com).

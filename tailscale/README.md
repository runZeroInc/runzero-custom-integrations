# 🧩 Tailscale API → runZero Integration

A custom [runZero](https://www.runzero.com/) Starlark integration that imports assets directly from the [Tailscale API](https://tailscale.com/api).  
This version uses a single API token or client secret — **no OAuth2 handshake required**.

---

## 🚀 Overview

This integration connects to the Tailscale REST API using your **API token** (or **client secret**) and retrieves all devices in a tailnet.  
Each Tailscale device is converted into a `runZero ImportAsset` with metadata, IP addresses, and custom attributes.

---

## 🔑 Requirements

You’ll need:

| Requirement | Description |
|--------------|-------------|
| **Tailscale API Key or Client Secret** | A `tskey-api-xxxxx` or `tskey-client-xxxxx` token from the [Tailscale admin console → Keys page](https://login.tailscale.com/admin/settings/keys). |
| **Tailnet ID** | Usually found on the General Settings page of your Tailscale admin console (e.g., `T1234CNTRL`). You may also use `-` to reference the default tailnet. |
| **runZero Organization Role** | You must have permission to upload or manage integrations. |

---


## 🔒 API Key Permissions

Tailscale has **two different API credential types**, and they have different permission behaviors.

### 🔹 **User API Keys** (`tskey-api-...`)
- Created under **Settings → Keys → Create API key**
- Have the **same permissions as the user who created them**
- Work automatically with this integration if:
  - The user has **admin or owner** access to the tailnet
  - The user can view devices in the Tailscale admin console

✅ **Recommended for most users** — easiest to use and requires no special scopes.


### 🔹 **OAuth Client Secrets** (`tskey-client-...`)
- Created under **Settings → OAuth Clients**
- Require explicit permission scopes to be set
- To fetch devices successfully, your OAuth client must include:

```text
devices:core:read
devices:routes:read
devices:posture_attributes:read
```

## ⚙️ Configuration

When adding this integration in **runZero → Integrations → Custom Integration**, configure the following fields:

| Parameter | Key | Required | Example | Description |
|------------|-----|-----------|----------|--------------|
| **Access Secret** | `access_secret` | ✅ | `tskey-api-abc123def456` | The API key or client secret used for authentication. |
| **Tailnet** | `tailnet` | ✅ | `T1234CNTRL` or `-` | The Tailnet ID or `-` for the default tailnet. |
| **Insecure Skip Verify** | `insecure_skip_verify` | ❌ | `false` | Set to `true` to disable SSL verification (not recommended). |

---

## 🔍 Data Collected

Each Tailscale device is imported as a `runZero ImportAsset` with these details:

| Field | Source | Example |
|--------|---------|---------|
| `hostnames` | `device.hostname` | `laptop01` |
| `networkInterfaces` | `device.addresses` | IPv4 and IPv6 addresses |
| `os` | `device.os` | `linux` |
| `customAttributes.tailscale_user` | `device.user` | `amelie@example.com` |
| `customAttributes.tailscale_client_version` | `device.clientVersion` | `v1.36.0` |
| `customAttributes.tailscale_authorized` | `device.authorized` | `true` |
| `customAttributes.tailscale_advertised_routes` | `device.advertisedRoutes` | `10.0.0.0/16` |
| `customAttributes.tailscale_enabled_routes` | `device.enabledRoutes` | `192.168.1.0/24` |
| `customAttributes.tailscale_tags` | `device.tags` | `tag:prod, tag:subnetrouter` |

---

## 🧠 How It Works

1. **Authenticate** – The integration reads your `access_secret` and sets it as a `Bearer` token:
```

Authorization: Bearer tskey-api-xxxxx

```
2. **Fetch Devices** – Calls:
```

GET [https://api.tailscale.com/api/v2/tailnet/{tailnet}/devices](https://api.tailscale.com/api/v2/tailnet/{tailnet}/devices)

````
3. **Transform** – Each device is normalized into a `runZero ImportAsset`.
4. **Import** – Assets are returned to runZero for inventory enrichment.

---

## 🧪 Testing

You can test the script using the **Custom Integrations** feature in the runZero console or by using the local `runzero script` tool.

Example test run:

```bash
runzero script run tailscale_integration.star \
--access_secret tskey-api-abc123def456 \
--tailnet T1234CNTRL
````

---

## ⚠️ Troubleshooting

| Symptom              | Cause                                        | Fix                                                                |
| -------------------- | -------------------------------------------- | ------------------------------------------------------------------ |
| `401 Unauthorized`   | Invalid or expired API token                 | Regenerate token in the Tailscale admin console.                   |
| `404 Not Found`      | Tailnet name is incorrect                    | Use the Tailnet ID (e.g., `T1234CNTRL`) or `-` for default.        |
| `0 devices returned` | Tailnet has no active devices or wrong scope | Ensure devices exist and token has `devices:core:read` permission. |
| `SSL Error`          | Certificate issue                            | Use `insecure_skip_verify=true` (only for diagnostics).            |

---

## 🧰 Example Output

```
[TAILSCALE] SUCCESS: Retrieved 6 devices.
[TAILSCALE] SUCCESS: Prepared 6 ImportAsset objects.
[TAILSCALE] === INTEGRATION COMPLETE ===
```

---

## 🪪 Licensing

This integration is provided under the BSD 3-Clause license terms of the Tailscale API and runZero’s integration platform.

---

## 📚 References

* [Tailscale API Documentation](https://tailscale.com/api)
* [runZero Custom Integrations Guide](https://www.runzero.com/docs/integrations/custom/)
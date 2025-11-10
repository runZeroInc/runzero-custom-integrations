# Custom Integration: Tailscale API

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- A [Custom Integration Script Secret](https://console.runzero.com/credentials) credential configured with:
  - `access_key`: your **Tailscale OAuth Client ID** (leave blank if using a standard API key)
  - `access_secret`: your **Tailscale API key** or **OAuth Client Secret**

## Tailscale requirements

- Either:
  - A **User API Key** (`tskey-api-xxxxx`) created under **Settings → Keys** in the [Tailscale Admin Console](https://login.tailscale.com/admin/settings),  
    **or**
  - An **OAuth Client ID / Secret** pair created under **Settings → OAuth Clients** with the following scopes:
    ```
    devices:core:read
    devices:routes:read
    devices:posture_attributes:read
    ```

- The integration script defines your tailnet globally:
  ```python
  TAILNET_DEFAULT = "-"
````

Update this value inside the script if your environment uses a specific tailnet ID (e.g., `"T1234CNTRL"`).

## Steps

### Tailscale configuration

1. Log into the [Tailscale Admin Console](https://login.tailscale.com/admin/settings).
2. Choose one of the following:

   * **Option 1 – API Key:**
     Create a new API key under **Settings → Keys → Create API key**.
     Ensure the user has admin access to the tailnet.
   * **Option 2 – OAuth Client:**
     Create a new OAuth client under **Settings → OAuth Clients**.
     Add the required scopes listed above and record the client ID and secret.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).

   * Select **Custom Integration Script Secrets**.
   * For `access_secret`, enter your **API key** or **OAuth client secret**.
   * For `access_key`, enter your **OAuth client ID**, or a placeholder value (e.g., `foo`) if using an API key.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).

   * Add a descriptive name (e.g., `tailscale-sync`).
   * Toggle **Enable custom integration script** and paste the finalized script.
   * Click **Validate** to confirm syntax, then **Save**.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).

   * Select the Credential and Custom Integration created above.
   * Adjust the task schedule to your preferred frequency.
   * Select an Explorer to execute the task.
   * Click **Save** to start the integration.

### What's next?

* The task will execute and retrieve device data from the Tailscale API.
* Each Tailscale device will be imported as a `runZero ImportAsset`.
* You can view the integration run under [Tasks](https://console.runzero.com/tasks) in the runZero console.

### Notes

* The integration automatically detects whether you’re using an **API key** or **OAuth client credentials**.
* If you encounter a `403` error, verify your API key or OAuth client has the `devices:core:read` permission.
* The `TAILNET_DEFAULT` variable can be modified in the script if your organization uses multiple tailnets.
* Device metadata, tags, and IP addresses from Tailscale are mapped to `runZero` custom attributes and interfaces.
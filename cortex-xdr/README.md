# Custom Integration: Cortex XDR

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cortex XDR requirements

- **API Key ID** and **API Key** required for authentication.
- **Cortex XDR API Base URL** (depends on your region).

## Steps

### Cortex XDR configuration

1. **Obtain your Cortex XDR API credentials**:
   - Log in to **Cortex XDR**.
   - Navigate to **Settings** > **Configurations** > **Integrations** > **API Keys**.
   - Select **+ New Key**.
   - Choose **Standard** as the type of API Key.
   - Note the **API Key** and **API Key ID**.
2. **Find your Cortex XDR API Base URL**:
   - Example: `https://api-{fqdn}.xdr.us.paloaltonetworks.com/public_api/v1/`.

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter endpoint data.
    - Customize attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - Enter your **Cortex XDR API Key** as `api_key`.
    - Enter your **Cortex XDR API Key ID** as `api_key_id`.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "cortex-xdr").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

### What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated with **endpoint data from Cortex XDR**.
- The script captures details like **agent status, policies, OS version, compliance, and IPs**.
- Search for these assets in runZero using `custom_integration:cortex-xdr`.

### Notes

- The script **retrieves all endpoints** using pagination.
- All attributes from Cortex XDR are stored in `customAttributes`.
- The task **can be scheduled** to sync endpoint data regularly.

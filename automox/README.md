# Custom Integration: Automox

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Automox requirements

- **API Key** with permissions to retrieve device inventory.
- **Automox API URL**: `https://console.automox.com/api/servers`.

## Steps

### Automox configuration

1. **Obtain your Automox API Key**:
   - Log in to your Automox console.
   - Navigate to the kebab menu (3 vertical dots in the upper right) and then click on **Keys**
   - Generate a **new API Key** with read permissions.
2. **Note your API Key** for use in the integration.

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter device data.
    - Customize data attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - Enter your **Automox API Key** as `api_token`.
    - Optionally set `organization_hint` to an Automox organization ID or name.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "automox").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

### What's next?

- The task will kick off on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated based on **Automox device inventory**.
- The script captures details like **OS version, agent status, compliance, and IPs**.
- Search for these assets in runZero using `custom_integration:automox`.

### Notes

- The script **automatically retrieves all devices**, including paginated results.
- All attributes from Automox are stored in `customAttributes`.
- The task **can be scheduled** to sync device inventory at regular intervals.

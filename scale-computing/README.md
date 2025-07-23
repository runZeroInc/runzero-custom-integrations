# Custom Integration: Scale Computing

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Scale Computing requirements

- API Key with access to the SC//Fleet Manager API.
- Base URL: `https://api.scalecomputing.com`

## Steps

### Scale Computing configuration

1. Generate an API Key via SC//Fleet Manager:
   - Navigate to the [API Keys](https://fleet.scalecomputing.com/organization/settings) section.
   - Choose a role with `vmView` or `clusterView` permissions.
   - Note down the API Key.

2. Confirm API access:
   - Test access to the endpoint `https://api.scalecomputing.com/api/v2/clusters` using the API Key.

### runZero configuration

1. (OPTIONAL) - Modify the script if needed:
   - Filter for specific clusters or tags.
   - Customize attributes captured in runZero.

2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials):
   - Select **Custom Integration Script Secrets**.
   - Input your Scale API Key into `access_secret`.
   - Use a placeholder like `foo` for `access_key`.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new):
   - Name your integration (e.g., `scale-computing`).
   - Paste the finalized script.
   - Click **Validate**, then **Save**.

4. [Create the Integration Task](https://console.runzero.com/ingest/custom/):
   - Choose the Credential and Integration.
   - Select an Explorer to run the script.
   - Set your schedule and **Save**.

### What's next?

- Task execution will appear on the [Tasks page](https://console.runzero.com/tasks).
- New and updated assets will be visible in the Inventory.
- Use the search query:  

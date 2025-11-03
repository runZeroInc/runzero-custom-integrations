# Custom Integration: Ubiquiti Unifi Network
Custom Integration for retrieving clients and Unifi devices from the Unifi Network API
## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Ubiquiti Unifi Network requirements

- Network API Key
- Unifi Site Name (default: `Default`)
- Unifi Gateway URL

## Steps

### Ubiquiti Unifi Network configuration

1. Generate a API Token in Unifi at `Network -> Settings -> Control Plane -> Integrations`
3. Test your API token by making a sample request using a tool like `curl` or Postman to verify access.

### runZero configuration

1. Make any necessary changes to the script to align with your environment.
    - Set `UNIFI_CONTROLLER_URL`
    - Set `UNIFI_SITE_NAME`
    - (OPTIONAL) Disable client extract with `EXTRACT_CLIENTS = False`
    - (OPTIONAL) Disable device extract with `EXTRACT_DEVICES = False`
    - (OPTIONAL) Modify `UNIFI_CLIENT_API_FILTER`
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_secret` field for your Unifi API token.
    - For `access_key`, input a placeholder value like `foo` (unused in this integration).
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "unifi").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:unifi`.

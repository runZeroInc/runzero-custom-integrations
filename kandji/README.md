# Custom Integration: Kandji

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Kandji requirements

- Kandji API Bearer Token.
- Kandji subdomain.

## Steps

### Kandji configuration

1. Obtain your **API Key** from Kandji:
   - Navigate to **Settings** > **Access** > **Add API Token** to create a new API key in the Kandji console.
   - Note down the **API Token** and tenant-specific **API URL**.
2. Find your Kandji API URL:
   - This depends on your region (e.g., `https://SubDomain.api.eu.kandji.io`).
   - Refer to the [Kandji API Documentation](https://support.kandji.io/kb/kandji-api) for the steps to get your tenet-specific **API URL** when creating an API token.

### runZero configuration

1. Make any necessary changes to the script to align with your environment.
    - Update the **Kandji_API_URL** variable in the script and set to your tenant-specific **API URL** from Kandji
    - (OPTIONAL) Modify API queries as needed to filter asset data.
    - (OPTIONAL) Adjust which attributes are included in runZero.
3. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_secret` field for your **Kandji API Key**.
    - Use a placeholder value like `foo` for `access_key` (unused in this integration).
4. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "kandji").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
5. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from Kandji.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:kandji`.

### Notes

- The integration automatically retrieves **all devices** available in Kandji.
- Data such as **serial number and OS model** are included in `customAttributes`.
- Use the **runZero search queries** to filter assets by key attributes.

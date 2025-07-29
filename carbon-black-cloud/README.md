# Custom Integration: Carbon Black

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Carbon Black requirements

- API Key with permissions to access the **Devices API**.
- Organization Key (`org_key`), required for API requests.
- Carbon Black API URL (e.g., `https://defense.conferdeploy.net`).

## Steps

### Carbon Black configuration

1. Obtain your **API Key** from Carbon Black Cloud:
   - Navigate to **Settings** > **API Access** > **API Keys** tab in the Carbon Black Cloud console.
   - Generate an API Key with access to the **Devices API** and **Vulnerability API**.
   - Note down the **API Key** and **Org Key** (`org_key`).
2. Find your Carbon Black API URL:
   - This depends on your region (e.g., `https://defense.conferdeploy.net`).
   - Refer to the [Carbon Black API Documentation](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication/#hostname) for a list of hostnames it could be.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API queries as needed to filter asset data.
    - Adjust which attributes are included in runZero.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_key` field for your **Carbon Black Org Key**.
    - Use the `access_secret` field for your **Carbon Black API Key**.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "carbonblack").
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
- The task will update the existing assets with the data pulled from Carbon Black.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:carbonblack`.

### Notes

- The integration automatically retrieves **all device attributes** available in Carbon Black Cloud.
- Data such as **sensor version, status, policy, network details, and security attributes** are included in `customAttributes`.
- Use the **runZero search queries** to filter assets by key attributes.

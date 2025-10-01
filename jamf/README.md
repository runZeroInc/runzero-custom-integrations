# Custom Integration: JAMF

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## JAMF requirements

- API Client ID and API Client Secret with appropriate permissions.
- JAMF API URL: `https://<your-jamf-instance>.jamfcloud.com`.

## Steps

### JAMF configuration

1. Generate an API Client ID and API Client Secret in your JAMF instance.
   - Refer to the [JAMF API Documentation](https://developer.jamf.com/) for guidance.
   - Ensure the credentials have permissions to access the `computers-inventory` and `computers-inventory-detail` endpoints.
   - Read Computer Inventory Collection, Read Computer Security, Read Computers, Read Computer Extension Attributes
2. Note down your JAMF API URL (e.g., `https://<your-jamf-instance>.jamfcloud.com`).
3. Test your API credentials by retrieving a bearer token using the `oauth/token` endpoint.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter inventory data.
      - NOTE: `START_DATE` will limit the data fetch to assets seen since the date you input.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_key` field for your JAMF API Client ID.
    - Use the `access_secret` field for your JAMF API Client Secret.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "JAMF").
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:JAMF`.

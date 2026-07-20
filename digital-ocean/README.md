# Custom Integration: Digital Ocean

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Digital Ocean requirements

- API Client Token (Personal Access Token) with appropriate permissions.
- API URL: `https://api.digitalocean.com/v2/`.

## Steps

### Digital Ocean configuration

1. Generate a Personal Access Token from the [API Tokens page](https://cloud.digitalocean.com/account/api/tokens) in your Digital Ocean account.
   - Ensure the token has the required permissions to access droplets and associated metadata.
2. Note down the API URL: `https://api.digitalocean.com/v2/`.
3. Test your API token by making a sample request using a tool like `curl` or Postman to verify access.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter assets.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `api_token` field for your Digital Ocean API token.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "digital-ocean").
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:digital-ocean`.

# Custom Integration: Endpoint Central

## runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Endpoint Central Requirements

- Valid Endpoint Central URL (`EC_HOST`) for your account.
- API Version (e.g., `1.4`, default is 1.4).
- Endpoint Central API token (`access_secret`) with permissions to access inventory data.

## Steps

### Endpoint Central Configuration

1. Set up your Endpoint Central API:
   - Obtain your API token from the Endpoint Central admin console.
   - Confirm your Endpoint Central URL (e.g., `https://your-endpoint-central.com`).
   - Ensure the API version is set correctly (default is `1.4`).

2. Test your credentials:
   - Use a tool like Postman or curl to confirm you can reach the Endpoint Central API.
   - Example request:
     ```bash
     curl -X GET "https://your-endpoint-central.com/api/1.4/inventory/scancomputers?format=json&pagelimit=1&page=1" \
     -H "Authorization: Bearer <your_auth_token>" \
     -H "Accept: application/json"
     ```
   - You should receive a 200 response with a list of devices if your credentials are correct.

### runZero Configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter device data.
    - Adjust the custom attributes as needed for your specific use case.

2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_key` field for your Endpoint Central URL.
    - Use the `access_secret` field for your API token.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "endpoint-central").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.

4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's Next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with data pulled from the custom integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:endpoint-central`.

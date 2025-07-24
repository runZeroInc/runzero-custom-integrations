# Custom Integration: ExtremeCloud IQ

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## ExtremeCloud IQ requirements

- An account with username and password that has API access enabled.
- The base API URL for ExtremeCloud IQ is: `https://api.extremecloudiq.com`.

## Steps

### ExtremeCloud IQ configuration

1. Ensure your account has permissions to access the `devices` endpoint via the ExtremeCloud IQ API.
   - The account must be able to retrieve devices via `GET /devices`.
2. Verify access by using your credentials in a POST request to `https://api.extremecloudiq.com/login` and receive a bearer token in return.
   - Refer to the [ExtremeCloud IQ API Documentation](https://extremecloudiq.com/api-docs/) if needed.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - You may modify the script to filter inventory by site, device type, or other parameters.
    - All discovered assets will be enriched with additional metadata using `customAttributes`.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_key` field for your ExtremeCloud IQ username.
    - Use the `access_secret` field for your ExtremeCloud IQ password.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "ExtremeCloudIQ").
    - Toggle `Enable custom integration script` and paste in the finalized script.
    - Click `Validate` to ensure the script syntax is correct.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to run on your desired frequency.
    - Select a hosted Explorer that can execute the integration.
    - Click `Save` to schedule and start the task.

### What's next?

- The integration task will appear on the [Tasks page](https://console.runzero.com/tasks) and begin execution.
- The task will update existing assets in your runZero inventory or create new assets based on the data retrieved from ExtremeCloud IQ.
- You can search for enriched assets using the query: `custom_integration:ExtremeCloudIQ`.

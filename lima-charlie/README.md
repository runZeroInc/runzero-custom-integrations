# Custom Integration: Lima Charlie

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Lima Charlie requirements

- Organization ID (`oid`) for your Lima Charlie account.
- API Access Token with permissions to access sensor data.
- JWT Endpoint URL: `https://jwt.limacharlie.io`.
- API Base URL: `https://api.limacharlie.io/v1`.

## Steps

### Lima Charlie configuration

1. Obtain your Organization ID (`oid`) and API Access Token from your Lima Charlie account.
   - Refer to the [Lima Charlie Documentation](https://www.limacharlie.io/docs) for instructions.
2. Test your credentials:
   - Use the JWT endpoint (`https://jwt.limacharlie.io`) to generate a bearer token with your `oid` and API Access Token.
   - Use the generated token to query the `/sensors` endpoint (`https://api.limacharlie.io/v1/sensors/{oid}`) and verify access to your sensor data.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API calls as needed to filter sensor data.
    - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `access_key` field for your Lima Charlie Organization ID (`oid`).
    - Use the `access_secret` field for your API Access Token.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "lima-charlie").
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:lima-charlie`.

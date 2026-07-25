# Custom Integration: Tanium

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Tanium requirements

- Tanium API URL (e.g., `https://<your-tanium-instance>/plugin/products/gateway/graphql`).
- API Token with permissions to access endpoint and compliance data via the Tanium GraphQL API.

## Steps

### Tanium configuration

1. Obtain the API Token from your Tanium instance:
   - Follow the [Tanium API Documentation](https://docs.tanium.com/) for guidance on generating an API token.
   - Ensure the token has permissions to query endpoint data and compliance findings.
2. Note down your Tanium API URL.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify API queries as needed to filter endpoint data or compliance findings.
    - Adjust data parsing or mappings to suit your organizational needs.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `api_token` field for your Tanium API Token.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "tanium").
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
- The task will retrieve endpoint, software, and vulnerability data from your Tanium instance and upload it to runZero.
- Assets in runZero will be updated or created based on the data retrieved from Tanium.

### Notes

- Ensure that your Tanium GraphQL API endpoint is accessible from the system running the runZero Explorer.
- You can monitor task execution and check for any errors or issues in the [tasks](https://console.runzero.com/tasks) page.
- Customize the `build_assets` function to include additional fields or mappings as needed for your organization.
- Search for assets enriched by this integration using the runZero search query `custom_integration:tanium`.

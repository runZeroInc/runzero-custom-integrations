# Custom Integration: Netskope

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Netskope requirements

- REST API token with appropriate permissions. This script calls the `/v2/events/datasearch/clientstatus` API endpoint.
- Netskope API URL: `https://<your-netskope-account>.goskope.com/`.

## Steps

### Netskope configuration

1. Generate an API token in your Netskope account.
   - Refer to the [Netskope API Documentation](https://docs.netskope.com/en/api-tokens/) for guidance.
2. Document your Netskope API URL (e.g., `https://<your-netskope-account>.goskope.com`).

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify the NETSKOPE_API variable to reflect your environment.
    - Modify the NETSKOPE_API_GROUPBYS attribute, if appropriate. By default this script groups by nsdeviceuid to avoid duplicate records. Modifying this variable could alter what attributes are available.
    - Modify the NETSKOPE_API_ATTRIBUTES array. These are the attributes that runZero will ingest. It is passed to Netskope as part of the API call.
    - Modify datapoints uploaded to runZero as needed. If you modify the NETSKOPE_API_ATTRIBUTES, you will also need to update `ImportAssets` so that the asset is included in the import. 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Leave the `access_client` blank.
    - Use the `access_secret` field for your Netskope API token.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "netskope").
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:netskope`.

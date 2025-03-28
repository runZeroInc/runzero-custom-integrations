# Custom Integration: NinjaOne

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## NinjaOne requirements

- TBD

## Steps

### NinjaOne configuration

1. Generate an API Client Token from your NinjaOne account.
   - Refer to the [NinejaOne API Documentation](https://app.ninjarmm.com/apidocs/) for instructions.
2. Note down the API URL: `https://app.ninjarmm.com/v2/`.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - TBD
    - TBD
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - For the `access_secret`, input your NinjaOne client ID.
    - For the `access_key`, input your NinjaOne client secret.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "drata").
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:drata`.

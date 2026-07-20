# Custom Integration: Wazuh

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Wazuh requirements

- Wazuh API endpoint reachable on port 55000 (for example: https://wazuh-manager.example.com:55000).
- Wazuh API user credentials with permission to authenticate and read agent/syscollector data.

## Steps

### Wazuh configuration

1. Confirm API access to your Wazuh manager endpoint over HTTPS on port 55000.
2. Create or identify an API user with access to authentication, agents, and syscollector endpoints.
3. Validate the credentials by testing an API login to /security/user/authenticate.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
   - Modify API calls as needed to filter inventory data.
   - Modify datapoints uploaded to runZero as needed.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - Set `password` to your Wazuh API user password.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (for example: wazuh).
   - Toggle `Enable custom integration script` to input the finalized script.
   - Configure the integration parameters:
     - `hostname`: your Wazuh manager hostname or IP (do not include protocol or port).
     - `port`: the Wazuh API port (defaults to `55000`).
     - `username`: your Wazuh API username.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 2 and 3.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with the data pulled from the custom integration source.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:wazuh`.

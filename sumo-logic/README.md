# Custom Integration: Sumo Logic

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- API Export Token with permissions to access the `export/org/assets.json` endpoint.

## Sumo Logic requirements

- HTTP Source URL configured in Sumo Logic.
  - This should be the endpoint URL where runZero will send asset data.
  - Example format: `https://<your-instance>.sumologic.com/receiver/v1/http/<unique-token>`.

## Steps

### Sumo Logic configuration

1. Create an HTTP Source in your Sumo Logic account:
   - Navigate to **Manage Data** > **Collection** > **HTTP Sources** in Sumo Logic.
   - Follow the instructions to create an HTTP Source and note down the generated endpoint URL.
2. Replace `<UPDATE_ME>` in the script with your Sumo Logic HTTP Source URL.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Modify the `SEARCH` variable to adjust the query used to filter assets in runZero.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - Use the `runzero_export_token` field for your runZero API Export Token.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "sumo-logic-export").
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
- The task will retrieve asset data from runZero and upload it to your configured Sumo Logic HTTP Source.
- Asset data in Sumo Logic will be updated with each successful task execution.

### Notes

- Ensure the `SEARCH` variable in the script is customized to meet your asset filtering needs (e.g., `alive:t` to include only live assets).
- You can monitor the ingestion of data in Sumo Logic through the configured HTTP Source logs.
- Use Sumo Logic’s query tools to analyze and visualize the runZero asset data.

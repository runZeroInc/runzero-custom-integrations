# Custom Integration: Cyberint

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cyberint requirements

- **API Key** required for authentication.
- Access to the Cyberint Argos Threat Intelligence platform.

## Steps

### Cyberint configuration

1. **Obtain your Cyberint API credentials**:
   - Log in to your **Cyberint Argos platform**.
   - Navigate to the API settings or developer section to generate a new API key.
   - Note the **API Key**.

### runZero configuration

1. **(OPTIONAL)** - Modify the script if needed:
    - Adjust API queries to filter data.
    - Customize attributes stored in runZero.
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - Enter your **Access Secret** as `cyberint_api_key`.
    - Enter your **Access Key** with any placeholder value.
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "Cyberint").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

## What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be updated with data from Cyberint.
- The script captures details about leaked credentials, domains, and other threat intelligence data.
- Search for these assets in runZero using `source:cyberint`.

## Notes

- The script retrieves data from the Cyberint Argos API.
- The task can be scheduled to sync data regularly.

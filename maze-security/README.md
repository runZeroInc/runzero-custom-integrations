# Custom Integration: Maze

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Maze requirements

- Maze API key with access to the Investigations API.

## Steps

### Maze configuration

1. Obtain your **API Key** from the Maze platform.
2. Confirm API access to `https://api.mazehq.com/v1/investigations/search`.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Maze").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
   - The script embeds its `CONFIG` block, so the credential form is generated automatically with the fields below.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Maze API key** (`api_key`): your Maze API key with access to the Investigations API.
   - **Lookback window (days)** (`days_back`): optional; how far back to fetch updated investigations (default: 30).
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update existing assets with vulnerability investigation data pulled from Maze.
- The task will create new assets when there are no existing assets that meet merge criteria (hostname, MAC, etc).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:maze`.

### Notes

- The integration fetches investigations updated within the last 30 days by default. Change the **Lookback window (days)** credential field (`days_back`) to adjust this.
- Each investigation is mapped to a **Vulnerability** on the corresponding asset, including CVE, CVSS scores, exploitability verdict, and root cause analysis.
- When `related_scanner_findings` data is available, additional metadata (cloud platform, region, scanner type, account ID) is included as custom attributes.
- Assets are grouped from paginated investigations and streamed to runZero in batches via `report_assets`.
- Transient API errors (429/5xx) are retried automatically with backoff by the shared HTTP helper.

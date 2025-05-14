# Custom Integration: Task Sync

## Overview

This integration script is designed to sync tasks between a runZero SaaS instance and a self-hosted runZero console. It retrieves tasks from a SaaS instance, downloads their data, and uploads them to a self-hosted site. Optionally, it can hide the tasks in the SaaS instance after a successful sync.

## Requirements

### runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

### API Requirements

- SaaS Organization ID
- SaaS Site ID
- Self-hosted Organization ID
- Self-hosted Site ID
- API Tokens for both the SaaS and self-hosted instances

## Configuration Steps

1. **Obtain Required IDs and Tokens**
   - SaaS Organization ID (`ORG-UUID-REPLACE`)
   - SaaS Site ID (`SITE-UUID-REPLACE`)
   - Self-hosted Organization ID (`ORG-UUID-REPLACE`)
   - Self-hosted Site ID (`SITE-UUID-REPLACE`)
   - API Tokens for both SaaS and self-hosted instances

2. **Create the Credential for the Custom Integration**
   - Go to [runZero Credentials](https://console.runzero.com/credentials).
   - Select `Custom Integration Script Secrets`.
   - Use the `access_key` field for the SaaS token.
   - Use the `access_secret` field for the self-hosted token.

3. **Create the Custom Integration**
   - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Task Sync").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.

4. **Create the Custom Integration Task**
   - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in the previous steps.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you'd like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

## Optional Settings

- To automatically hide tasks in the SaaS instance after sync, set the `HIDE_TASKS_ON_SYNC` flag to `True` in the script.

## Troubleshooting

- **Task Sync Failures**: Ensure that both the SaaS and self-hosted tokens are valid and have the necessary permissions.
- **Data Transfer Issues**: Confirm that the self-hosted console is reachable from the machine running this script.
- **Network Timeouts**: Increase the timeout in the `sync_task()` function if syncing large tasks.

---

## License

This integration is provided under the MIT License. See the LICENSE file for more details.

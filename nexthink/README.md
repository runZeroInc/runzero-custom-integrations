# Custom Integration: Nexthink

## runZero requirements

- Superuser access to the runZero Custom Integrations configuration
- Access to create credentials and ingest tasks in runZero

## Nexthink requirements

- Nexthink API credentials (Client ID and Client Secret)
- Permissions to run NQL API queries and exports
- A saved NQL API query ID (default in script: `#runzero_integration`)

## What this integration imports

The script imports assets from Nexthink using NQL export workflow and maps:

- `id` from `device.uid`
- `hostnames` from `device.name`
- `os` from `device.operating_system.name`
- `osVersion` derived from `device.operating_system.build`
- `networkInterfaces` from `device.collector.local_ip`
- `customAttributes`:
  - `nexthink.first_seen`
  - `nexthink.last_seen`
  - `nexthink.hardware.manufacturer`
  - `nexthink.hardware.model`
  - `nexthink.hardware.chassis_serial_number`
  - `nexthink.operating_system.build`
  - `nexthink.collector.local_ip`

## Steps

### 1. Configure Nexthink

1. Create API credentials in Nexthink for a service account.
2. Ensure the account has permissions to manage/execute NQL API queries.
3. Create a saved NQL API query in Nexthink Content Management.
4. Ensure your NQL query returns these fields:
   - `device.uid`
   - `device.name`
   - `device.operating_system.name`
   - `device.operating_system.build`
   - `device.collector.local_ip`
   - `device.hardware.manufacturer`
   - `device.hardware.model`
   - `device.hardware.chassis_serial_number`
   - `device.first_seen`
   - `device.last_seen`

### 2. Configure the script

Edit [nexthink/custom-integration-nexthink.star](nexthink/custom-integration-nexthink.star) constants:

- `AUTH_URL` format: `https://<instance>-login.<region>.nexthink.cloud`
- `API_URL` format: `https://<instance>.api.<region>.nexthink.cloud`
- `QUERY_ID` format: `#<your_query_id>`
- `SCOPE` usually: `service:integration`

### 3. Configure runZero credential

1. In runZero, create a credential of type Custom Integration Script Secrets.
2. Set:
   - `access_key` = Nexthink Client ID
   - `access_secret` = Nexthink Client Secret

### 4. Configure runZero custom integration

1. Create a new custom integration in runZero.
2. Paste the script from [nexthink/custom-integration-nexthink.star](nexthink/custom-integration-nexthink.star).
3. Validate and save.

### 5. Create an ingest task

1. Create a custom ingest task.
2. Select the credential and custom integration.
3. Select an explorer.
4. Save and run.

## Validation checklist

- Task succeeds without authentication errors.
- Export starts and reaches `COMPLETED`.
- Assets in runZero show `custom_integration:nexthink`.
- Imported assets include expected hostnames, OS, and custom attributes.

## Troubleshooting

- `No rows returned from Nexthink export workflow`:
  - Verify query fields and data availability in Nexthink.
  - Verify `QUERY_ID` matches a saved Nexthink query.
- `Failed to download export results ... Only one auth mechanism allowed`:
  - Ensure no `Authorization` header is sent to `resultsFileUrl`.
- Exactly 1,000 rows imported:
  - This script already uses export workflow to avoid execute endpoint limits.

## Preparing a pull request

1. Ensure these files exist:
   - [nexthink/custom-integration-nexthink.star](nexthink/custom-integration-nexthink.star)
   - [nexthink/config.json](nexthink/config.json)
   - [nexthink/README.md](nexthink/README.md)
2. Verify your branch is `nexthink` and only intended files changed.
3. Run a quick manual validation in runZero with test credentials.
4. Commit with a clear message, for example:
   - `Add Nexthink inbound custom integration with export workflow`
5. Open a PR including:
   - Summary of mapping
   - Validation notes/screenshots
   - Any known limitations

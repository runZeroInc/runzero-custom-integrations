# Custom Integration: Scan Passive Assets

This custom integration finds assets discovered only by passive sources, creates targeted scans from the last-seen agent, and can optionally delete the original passive assets after the scans are scheduled.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- A runZero Organization API token.

## Scan Passive Assets requirements

- A runZero **Site ID** to target for scans (set in `SITE_ID`).
- A CIDR allow list to scope targets (set in `ALLOW_LIST`).
- A decision on whether to delete passive assets after scan creation (set in `DELETE_ASSETS`).

## Steps

### Script configuration

1. Open `scan-passive-assets/custom-integrastion-scan-passive-assets.star`.
2. Update the global configuration values:
   - `SITE_ID`: runZero site ID where scans should run.
   - `ALLOW_LIST`: list of allowed IPv4 CIDR ranges.
   - `DELETE_ASSETS`: set to `False` to keep passive assets after scans are created.
3. (Optional) Adjust the search filter in the export request if you want to include more than `source:sample source_count:1`.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - Set `access_secret` to your runZero API token.
   - Set `access_key` to a placeholder value like `foo` (unused).
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon (e.g., `scan-passive-assets`).
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created above.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you'd like the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- The task exports passive assets matching the search filter and groups allowed IPv4 addresses by `last_agent_id`.
- The script creates one scan per agent with the matching targets.
- If `DELETE_ASSETS` is enabled, the matching passive assets are removed after scan creation.
- You can review task activity on the [tasks](https://console.runzero.com/tasks) page.

### Notes

- Only IPv4 addresses are considered; IPv6 addresses are skipped.
- The allow list applies before scans are created, so verify `ALLOW_LIST` matches your internal ranges.
- Disabling `DELETE_ASSETS` is recommended for initial testing.

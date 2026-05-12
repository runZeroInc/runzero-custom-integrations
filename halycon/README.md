# Custom Integration: Halycon

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Halcyon requirements

- Access to the Halcyon API at `https://api.halcyon.ai` from the runZero Explorer.
- One of the following authentication methods:
  - Recommended: Halcyon username in `access_key` and password in `access_secret`.
  - Supported: pre-issued bearer token in `access_secret` with `access_key` set to a placeholder value.
- Permissions to query the Halcyon asset search and asset detail endpoints.

## Authentication behavior

- When `access_key` is set, the script authenticates to Halcyon, retrieves a JWT access token, and automatically refreshes that token if the API returns `401 Unauthorized` during asset collection.
- When `access_key` is omitted, the script treats `access_secret` as an already-issued bearer token.
- Bearer token mode does not support automatic token refresh because the script does not have credentials to request a new token.

## Data imported into runZero

- Asset ID
- Hostname
- Operating system
- IPv4 and IPv6 addresses
- MAC address
- Custom attributes:
  - `agentVersion`
  - `heartbeat`
  - `policyGroupOwner`
  - `registeredDate`
  - `createdDate`
  - `lastHeartbeatDate`
  - `lastUpdatedDate`

## Steps

### Halcyon configuration

1. Confirm that the runZero Explorer can reach `https://api.halcyon.ai` over HTTPS.
2. Choose your authentication method:
   - Preferred: use a Halcyon username and password so the script can automatically refresh expired JWTs.
   - Alternative: use a pre-issued bearer token if your environment requires token-based authentication.
3. Verify that the credentials can access the Halcyon asset APIs.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - If using username/password authentication:
     - Set `access_key` to your Halcyon username.
     - Set `access_secret` to your Halcyon password.
   - If using bearer token authentication:
     - Leave `access_key` blank if allowed, or use a placeholder value like `foo`.
     - Set `access_secret` to the Halcyon bearer token.
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration, such as `halycon`.
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in the earlier steps.
   - Update the task schedule to recur at the desired interval.
   - Select the Explorer you want the Custom Integration to run from.
   - Click `Save` to kick off the first task.

### What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will create new assets or update existing assets in runZero based on merge criteria such as hostname, MAC address, and IP address.
- Asset search pagination and per-asset detail lookups are handled automatically by the script.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:halycon`.

## Notes

- Username/password mode is recommended for long-running imports because the script can re-authenticate if the Halcyon JWT expires mid-run.
- Bearer token mode is best suited to tokens that remain valid for the full duration of the task.
- The script uses Halcyon asset detail responses to enrich each asset with IP, MAC, and selected custom attribute data.
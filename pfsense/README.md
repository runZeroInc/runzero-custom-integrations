# Custom Integration: pfSense

This integration imports your pfSense firewall as a runZero `ImportAsset` and captures version information from the pfSense REST API.

## runZero requirements

- Superuser access to [Custom Integrations](https://console.runzero.com/custom-integrations).
- A **Custom Integration Script Secret** credential:
  - `access_key`: your pfSense base URL (example: `https://pfsense.example.local`)
  - `access_secret`: your pfSense REST API token

## Optional JSON credential mode

If you prefer to keep all settings in `access_secret`, you can store JSON instead:

```json
{
  "base_url": "https://pfsense.example.local",
  "access_secret": "YOUR_API_TOKEN",
  "auth_header": "authorization",
  "insecure_skip_verify": false
}
```

- `auth_header`: `authorization` (default, uses `Bearer`) or `x-api-key`.
- `insecure_skip_verify`: set to `true` only if your pfSense API certificate is self-signed.

## API endpoints used

The script tries these endpoints in order and uses the first successful response:

1. `/api/v1/status/system`
2. `/api/v1/system/version`

## Setup steps

1. In pfSense, generate an API token with read access to status/system data.
2. In runZero, create the credential values above.
3. Create a new Custom Integration and paste `custom-integration-pfsense.star`.
4. Validate, save, and attach it to a task.

## Local test with runZero CLI

```bash
runzero script --filename pfsense/custom-integration-pfsense.star --kwargs access_key=https://pfsense.example.local --kwargs access_secret=YOUR_API_TOKEN
```

If your API token/header model is different, use the JSON `access_secret` mode so you can switch header behavior.


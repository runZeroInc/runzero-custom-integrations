# Custom Integration: Device42

## runZero requirements

- A runZero **superuser** account to access [Custom Integrations](https://console.runzero.com/custom-integrations).

## Device42 requirements

- Access to the Device42 REST API at the `/api/1.0/devices/all/` endpoint.
- Either:
  - A valid Device42 **username and password**, or
  - A valid **Bearer token**.

## Preparing the API credentials

Device42 supports **Basic** or **Bearer** authentication.

You must configure both fields in your runZero credential:

- `access_key`: must be either `basic` or `bearer`.
- `access_secret`:  
  - For `basic`: a base64-encoded string of `username:password`.
  - For `bearer`: your raw API token.

### Example for Basic Authentication

```bash
echo -n 'myuser:mypassword' | base64
```

Use the output as your `access_secret`. Set `access_key` to `basic`.

### Example for Bearer Authentication

Set `access_key` to `bearer`, and `access_secret` to your API token string.

## Steps

### 1. Create a Credential in runZero

- Go to [runZero Credentials](https://console.runzero.com/credentials).
- Select the type: **Custom Integration Script Secrets**.
- Set:
  - `access_key`: `basic` or `bearer`
  - `access_secret`: base64-encoded `username:password` or API token

### 2. Create the Custom Integration

- Navigate to [Custom Integrations](https://console.runzero.com/custom-integrations/new).
- Name your integration (e.g. `device42`).
- Paste the finalized script into the code editor.
- Click **Validate**, then **Save**.

### 3. Create and Run the Integration Task

- Go to [Ingest Task](https://console.runzero.com/ingest/custom/).
- Select the Credential and Custom Integration you created.
- Choose the runZero Explorer where it will run.
- Set your schedule and click **Save**.

### Notes

- Your Device42 instance must be reachable from the runZero Explorer.
- API pagination is handled automatically using `limit` and `offset`.
- Assets will be enriched with all available fields (except IP/MAC/name) in `customAttributes`.

## Search Syntax in runZero

To find assets imported by this integration:

```
custom_integration:device42
```

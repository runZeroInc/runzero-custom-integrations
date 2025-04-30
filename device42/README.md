# Custom Integration: Device42

## runZero requirements

- A runZero **superuser** account to access [Custom Integrations](https://console.runzero.com/custom-integrations).

## Device42 requirements

- Access to the Device42 REST API at the `/api/1.0/devices/all/` endpoint.
- A valid Device42 **username and password**.

## Preparing the API credentials

Device42 uses **Basic Authentication**. For this integration, you must base64-encode your Device42 username and password in the format:

```
username:password
```

Example using `base64` on the command line:

```bash
echo -n 'myuser:mypassword' | base64
```

This will output a string like:

```
bXl1c2VyOm15cGFzc3dvcmQ=
```

Use this encoded string as your `access_secret` in runZero.

## Steps

### 1. Create a Credential in runZero

- Go to [runZero Credentials](https://console.runzero.com/credentials).
- Select the type: **Custom Integration Script Secrets**.
- Leave `access_key` empty or set to any placeholder value (not used).
- Set `access_secret` to your base64-encoded `username:password` string.

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

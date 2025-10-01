# Custom Integration: Ghost

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Ghost requirements

- **API Key** with permissions to retrieve findings.
- **Ghost API URL**: `https://api.ghostsecurity.ai/v1/findings`.

## Steps

### Ghost configuration

1. **Obtain your Ghost API Key**:
   - Log in to your Ghost Security console.
   - Generate a **new API Key** with read permissions for findings.
2. **Note your API Key** for use in the integration.

### runZero configuration

1. **(REQUIRED)** - Modify the script to map your repositories to IP addresses or hostnames.
    - Open the `custom-integration-ghost.star` script.
    - Locate the `repo_map` dictionary.
    - Update the dictionary to reflect your environment. For example:
      ```python
      repo_map = {
          "my-repo": {
              "ips": ["10.0.0.5", "10.0.0.6"],
              "hostnames": ["db01.local", "db02.local"]
          },
          "api-repo": {
              "ips": ["192.168.1.20"],
              "hostnames": ["api.example.com", "api.internal"]
          }
      }
      ```
2. **Create a Credential for the Custom Integration**:
    - Go to [runZero Credentials](https://console.runzero.com/credentials).
    - Select `Custom Integration Script Secrets`.
    - Enter your **Ghost API Key** as `access_secret`.
    - Use a placeholder value like `foo` for `access_key` (unused in this integration).
3. **Create the Custom Integration**:
    - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
    - Add a **Name and Icon** for the integration (e.g., "ghost").
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` and then `Save`.
4. **Schedule the Integration Task**:
    - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
    - Select the **Credential and Custom Integration** created earlier.
    - Set a schedule for recurring updates.
    - Select the **Explorer** where the script will run.
    - Click **Save** to start the task.

### What's next?

- The task will kick off on the [tasks](https://console.runzero.com/tasks) page.
- Assets in runZero will be created or updated based on **Ghost security findings**.
- The script captures details like **vulnerability name, description, severity, and remediation advice**.
- Search for these assets in runZero using `custom_integration:ghost`.

### Notes

- The script **automatically retrieves all findings**.
- It is **critical** to map your repository names to the correct IP addresses or hostnames in the `repo_map` dictionary for the integration to work correctly.
- All attributes from Ghost are stored in `customAttributes` on the vulnerability.
- The task **can be scheduled** to sync findings at regular intervals.

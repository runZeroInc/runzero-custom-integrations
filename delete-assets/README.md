# Custom Script: Delete Assets Matching Search in runZero

This runZero custom integration script identifies and deletes all assets that match a given asset search (default: `alive:f`). This script runs entirely within runZero — it does **not integrate with an external system**.

## 🔧 Use Case

This script is useful for:
- Cleaning up stale or decommissioned assets (`alive:f`)
- Automating asset cleanup via scheduled tasks
- Performing scoped deletions via search filters

## 📋 Requirements

### runZero

- A runZero user account with **Superuser** permissions.
- A valid **runZero Org API token** (see below).
- A configured [Custom Integration](https://console.runzero.com/custom-integrations).
- A [Credential](https://console.runzero.com/credentials) containing your Org token.

## 🔑 Credentials Setup

1. Go to [runZero Credentials](https://console.runzero.com/credentials).
2. Choose **Custom Integration Script Secrets**.
3. For `access_secret`, enter your **Org API token** (from Org Settings → API keys).
4. Use a placeholder for `access_key` (e.g., `foo` – it's not used).

## ⚙️ Configuration

### Custom Integration Setup

1. Navigate to [Custom Integrations](https://console.runzero.com/custom-integrations/new).
2. Name your integration (e.g., `Delete Stale Assets`).
3. Paste the script into the custom integration editor.
4. Click **Validate**, then **Save**.

### Schedule a Task

1. Go to [Custom Ingest](https://console.runzero.com/ingest/custom/).
2. Select your integration and credential.
3. Choose an Explorer to run the script.
4. Set a schedule (e.g., daily, weekly).
5. Save the task.

## 🔍 Default Search

The script uses the runZero search query:
```
alive:f
```
This matches all assets that are currently not alive (offline). You can modify this by editing the `SEARCH` variable at the top of the script.

## 📝 Notes

- The script **prints out the asset IDs** it will delete.
- Successful deletions will return `204 No Content`.
- Modify the `SEARCH` variable to target different sets of assets.
- API usage is governed by your organization's permissions and rate limits.

# Custom Integration: Ghost Security

## Overview

This custom integration automatically imports **Ghost Security findings** into **runZero**, creating assets for each repository and attaching vulnerability data derived from Ghost scans.

The integration now dynamically:

* Retrieves all repositories (and their deployments) from the Ghost API.
* Extracts hostnames from each project’s deployment environments.
* Fetches all findings and associates them with the appropriate repository using the `repo_id` field.
* Creates `ImportAsset` objects in runZero, complete with hostnames, network interfaces, and vulnerabilities.

No manual mapping of repositories to IPs or hostnames is required.

---

## runZero Requirements

* **Superuser access** to [Custom Integrations](https://console.runzero.com/custom-integrations).
* A configured **Custom Integration Credential** for the Ghost API.

---

## Ghost Requirements

* A **Ghost API key** with read access to:

  * `/v1/repos`
  * `/v1/findings`
* API base URL:
  `https://api.ghostsecurity.ai/v1/`

---

## Configuration Steps

### 1. Generate Your Ghost API Key

1. Log in to your **Ghost Security console**.
2. Navigate to your account or organization **API Keys** section.
3. Generate a new key with **read permissions** for repositories and findings.
4. Copy the key — you’ll use it as your `access_secret` in runZero.

---

### 2. Add the Credential in runZero

1. Go to [runZero Credentials](https://console.runzero.com/credentials).
2. Choose **Custom Integration Script Secrets**.
3. Enter:

   * `access_secret`: your Ghost API key
   * `access_key`: any placeholder value (unused)
4. Save the credential.

---

### 3. Create the Custom Integration

1. Go to [Custom Integrations](https://console.runzero.com/custom-integrations/new).
2. Add a **name** (e.g., `ghost-security`) and optional icon.
3. Enable **Custom integration script**.
4. Paste in the `custom-integration-ghost.star` script (latest version).
5. Click **Validate** to confirm syntax.
6. Save the integration.

---

### 4. Schedule the Integration Task

1. Go to [Ingest → Custom](https://console.runzero.com/ingest/custom/).
2. Choose your **Ghost credential** and **Ghost custom integration**.
3. Assign an **Explorer** to run the task.
4. Set a **schedule** (e.g., daily or weekly sync).
5. Save to start ingesting Ghost data.

---

## How It Works

1. The integration calls `GET /v1/repos` to fetch all repositories.

   * Each repo’s project `deployments` are parsed to extract hostnames (production, staging, etc.).
2. It then calls `GET /v1/findings` to collect findings.

   * Each finding includes a `repo_id` and optional `project.deployments`.
   * The script maps findings back to repositories using `repo_id`.
3. Assets are created for each repo in runZero with:

   * Hostnames from Ghost deployments.
   * Associated vulnerabilities for each finding.

---

## Data Mapped to runZero

| Ghost Field                                                          | runZero Field                |
| -------------------------------------------------------------------- | ---------------------------- |
| `repo_id` / `repo_url`                                               | Asset ID / Custom Attributes |
| `deployments` (from projects)                                        | Asset Hostnames              |
| `findings.*`                                                         | Vulnerabilities              |
| `severity`, `confidence`, `attack_feasibility`, `remediation_effort` | Vulnerability Attributes     |
| `attack_walkthrough`, `remediation`, `description`                   | Vulnerability Details        |

---

## Notes & Tips

* ✅ **No manual repo mapping needed** — the script auto-discovers deployments from Ghost.
* ⚙️ Supports pagination for large repo lists.
* 🧩 Each Ghost finding becomes a `Vulnerability` in runZero.
* 🕒 You can schedule periodic syncs to keep findings up to date.
* 🧾 All Ghost metadata (e.g. `repo_url`, `repo_id`, `project_id`) is stored under `custom_attributes` in each vulnerability.

---

## Validation & Troubleshooting

* Run locally for testing:

  ```bash
  runzero script -f custom-integration-ghost.star --kwargs access_secret=<YOUR_GHOST_API_KEY>
  ```
* Logs will show:

  * Repositories discovered
  * Findings processed
  * Assets and vulnerabilities created
* If no assets appear:

  * Ensure your Ghost account has repositories with findings.
  * Confirm the API key has access to `/v1/repos` and `/v1/findings`.

---

## Example Output

Example asset in runZero created by this integration:

| Field               | Example                                               |
| ------------------- | ----------------------------------------------------- |
| **Asset Name**      | `juice-shop`                                          |
| **Hostnames**       | `juice.shop`, `staging.juice.shop`, `test.juice.shop` |
| **Vulnerabilities** | 35                                                    |
| **Severity**        | High / Medium / Low                                   |
| **Source**          | Custom Integration: Ghost                             |

---

Would you like me to add a **“Changelog”** section at the bottom (summarizing this update vs. the old repo_map-based approach)?
That can help future maintainers quickly see why the new version doesn’t use manual mappings anymore.

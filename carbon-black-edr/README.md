# runZero Custom Integration: Carbon Black EDR On-Prem

This integration discovers all managed Carbon Black EDR sensors (endpoints) on your on-premises Carbon Black server, and imports them into runZero as assets—complete with hostnames, OS information, network interfaces, sensor health, and (where available) vulnerability data.

---

## Table of Contents

* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Configuration](#configuration)
* [Script Structure](#script-structure)
* [Usage](#usage)
* [Scheduling in runZero](#scheduling-in-runzero)
* [Troubleshooting](#troubleshooting)
* [License](#license)

---

## Prerequisites

1. **runZero 1.20+** (self-hosted or cloud)
2. **Carbon Black EDR On-Prem** (7.8+ recommended) with API access
3. A **Carbon Black API Token** with at least *read* privileges on the Sensor and Vulnerability APIs.
4. Network connectivity from your runZero Scanner to the Carbon Black server’s API port (typically 443).

---

## Installation

1. **Create a new Custom Integration** in the runZero web console.
2. Name it e.g. `Carbon Black EDR On-Prem`.
3. Choose **“Script”** as the integration type, and paste in the contents of `runzero-carbonblack-onprem.star`.
4. Save the integration but do **not** enable scheduling yet.

---

## Configuration

1. **Custom Integration Script Secrets**

   * **access\_key** → (OPTIONAL) Your Org ID placeholder (unused on-prem, can be any value).
   * **access\_secret** → Your Carbon Black API Token.

2. **Edit the script constant**
   In `runzero-carbonblack-onprem.star`, update:

   ```python
   CARBON_BLACK_HOST = "<UPDATE_ME>"   # e.g. "https://cb-server.mycompany.local"
   ```

   to match your on-prem Carbon Black console base URL.

3. **Validate**
   In the runZero console, click **Validate** on the integration page to ensure HTTP connectivity and correct authentication.

---

## Script Structure

* **Entry point**: `main(*args, **kwargs)`

  * Reads `access_key` / `access_secret` from `kwargs`.
  * Calls `get_sensors()` → list of sensor dicts.
  * Calls `build_assets()` to convert to `ImportAsset` objects.

* **Core functions**:

  * `get_sensors()` & `get_sensor_details()` — List and fetch sensor metadata.
  * `get_device_vulnerabilities()` — Optional vuln lookup if on-prem vulnerability module present.
  * `build_vulnerabilities()` — Maps Carbon Black fields to `Vulnerability` objects.
  * `build_network_interface()` — Parses “IP,MAC|…” strings into `NetworkInterface`.
  * `build_assets()` — Assembles all data into `ImportAsset` objects.

* **Libraries loaded**:

  ```python
  load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')
  load('json', json_encode='encode', json_decode='decode')
  load('net', 'ip_address')
  load('http', http_get='get', http_post='post')
  ```

---

## Usage

1. **Run an inventory scan** (one-off):

   * From **Integrations → Your Carbon Black On-Prem** page, click **Run Now**.
   * Inspect the **Logs** panel for any errors.
   * Assets will appear under **Assets → Sources** with the “Carbon Black On-Prem” tag.

2. **Review imported assets**:

   * Hostnames, OS, IPs and MACs populate in the asset details.
   * Vulnerabilities (if any) appear under the **Vulnerabilities** tab for each asset.

---

## Scheduling in runZero

To keep your inventory up to date, schedule periodic pulls:

1. In the integration’s page, click **Schedule** → **Add Schedule**.
2. Choose frequency (e.g. hourly or daily).
3. Confirm and enable.

---

## Troubleshooting

* **No sensors found**

  * Verify `CARBON_BLACK_HOST` URL and API Token validity.
  * Check network/firewall between runZero Scanner and EDR server.

* **HTTP errors (4xx/5xx)**

  * 401/403 → API Token lacks permissions or expired.
  * 404 → Wrong endpoint path or version mismatch. Confirm your Carbon Black API version.

* **Partial data**

  * On-prem vulnerability module may be unavailable; script safely skips vuln lookup if API returns non-200.

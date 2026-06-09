# Maze Security Custom Integration

## Overview
This integration imports vulnerability investigation data from the Maze Security API into runZero. Each Maze investigation is mapped to a runZero Vulnerability and grouped by affected asset.

## Configuration

| Parameter | Value |
|-----------|-------|
| **Access Key** | *(not used)* |
| **Access Secret** | Maze Security API key |

## How It Works

1. Fetches all investigations from `POST /v1/investigations/search` with cursor-based pagination
2. Groups investigations by asset (extracted from `scanner_finding_hash` or `related_scanner_findings`)
3. Each investigation becomes a `Vulnerability` on the corresponding `ImportAsset`
4. Maze-specific data (exploitability verdict, root cause analysis, severity reasoning) is stored in custom attributes

## Asset Mapping

| Maze Field | runZero Field |
|------------|---------------|
| Asset ID (from scanner_finding_hash) | `ImportAsset.id` |
| Asset name | `ImportAsset.hostnames` |
| CVE ID | `Vulnerability.cve` |
| CVSS base score | `Vulnerability.cvss3BaseScore` |
| Maze severity | `Vulnerability.severityRank` / `severityScore` |
| Exploitability | `Vulnerability.exploitable` |
| Remediation | `Vulnerability.solution` |
| Investigation details | `Vulnerability.customAttributes` |

## Testing

```bash
runzero script --filename maze-security/custom-integration-maze-security.star \
  --kwargs access_secret=YOUR_MAZE_API_KEY
```

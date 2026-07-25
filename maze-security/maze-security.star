# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-maze",
    "name": "Maze",
    "type": "inbound",
    "description": "Imports vulnerability investigations from Maze.",
    "version": "26072400",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "api_key",
            "label": "Maze API key",
            "type": "secret",
            "required": True,
            "description": "Maze API key with access to the Investigations API.",
        },
        {
            "key": "days_back",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 30,
            "min": 1,
            "description": "How many days of updated investigations to fetch.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('json', json_encode='encode')
load('http', 'post_json')
load('kwargs', 'get_string', 'get_int', 'get_http_options')
load('time', 'now', 'parse_duration')

MAZE_API_URL = "https://api.mazehq.com"
PAGE_LIMIT = 1000
REPORT_BATCH = 500

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NOT_EXPLOITABLE": 0,
}

SEVERITY_SCORE = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "NOT_EXPLOITABLE": 0.0,
}


def compute_updated_from(days_back):
    """Compute ISO 8601 timestamp for N days ago."""
    duration_str = "-{}h".format(days_back * 24)
    cutoff = now() + parse_duration(duration_str)
    raw = str(cutoff).split(".")[0]
    return raw.replace(" ", "T") + "Z"


def parse_asset_id(scanner_finding_hash):
    """Extract asset identifier from scanner_finding_hash (format: scanner::CVE::asset_id)."""
    if not scanner_finding_hash:
        return ""
    parts = scanner_finding_hash.split("::")
    if len(parts) >= 3:
        return parts[2]
    return scanner_finding_hash


def force_string(value):
    """Coerce value to string, truncated to 1023 chars for customAttributes."""
    if value == None:
        return ""
    if type(value) == "list":
        return ",".join([str(v) for v in value])[:1023]
    if type(value) == "dict":
        return json_encode(value)[:1023]
    return str(value)[:1023]


def build_root_cause_summary(rca_list):
    """Summarize vulnerability_root_cause_analysis into a compact string."""
    if not rca_list:
        return ""
    parts = []
    for rca in rca_list:
        title = rca.get("title", "")
        status = rca.get("status", "")
        reasoning = rca.get("reasoning", "")
        parts.append("{}: {} - {}".format(title, status, reasoning))
    return " | ".join(parts)[:1023]


def build_vulnerability(investigation):
    """Convert a Maze investigation into a runZero Vulnerability object."""
    inv_id = investigation.get("id", "")
    cve_id = investigation.get("cve_id", "")
    maze_severity = investigation.get("maze_severity", "")
    exploitability = investigation.get("exploitability", "")
    exploitability_reason = investigation.get("exploitability_reason", "")

    snapshot = investigation.get("snapshot", {}) or {}
    cve_info = snapshot.get("cve", {}) or {}
    cvss_info = snapshot.get("cvss", {}) or {}

    description = cve_info.get("description", "")
    cvss_base = cvss_info.get("base_score", 0.0)
    if cvss_base == None:
        cvss_base = 0.0
    cvss_version = cvss_info.get("version", "")

    rank = SEVERITY_RANK.get(maze_severity, 0)
    score = SEVERITY_SCORE.get(maze_severity, 0.0)

    is_exploitable = exploitability == "exploitable"

    severity_details = investigation.get("severity_details", {}) or {}
    severity_reasoning = severity_details.get("reasoning", "")

    rca_list = investigation.get("vulnerability_root_cause_analysis", []) or []
    rca_summary = build_root_cause_summary(rca_list)

    remediation = investigation.get("remediation", "") or ""

    custom_attrs = to_custom_attributes({
        "maze_investigation_id": force_string(inv_id),
        "maze_exploitability": force_string(exploitability),
        "maze_exploitability_reason": force_string(exploitability_reason),
        "maze_severity": force_string(maze_severity),
        "maze_severity_reasoning": force_string(severity_reasoning),
        "maze_root_cause_analysis": rca_summary,
        "maze_snapshot_status": force_string(snapshot.get("status", "")),
        "maze_cvss_vector": force_string(cvss_info.get("vector_string", "")),
        "maze_cvss_source": force_string(cvss_info.get("source", "")),
        "maze_cve_potential_impact": force_string(cve_info.get("potential_impact", "")),
        "maze_updated_at": force_string(investigation.get("updated_at", "")),
        "maze_likelihood": force_string(investigation.get("likelihood", "")),
        "maze_impact": force_string(investigation.get("impact", "")),
    })

    vuln_params = {
        "id": inv_id,
        "name": cve_id,
        "description": str(description)[:1024],
        "cve": cve_id,
        "solution": str(remediation)[:1024],
        "severityRank": rank,
        "severityScore": float(score),
        "riskRank": rank,
        "riskScore": float(score),
        "exploitable": is_exploitable,
        "customAttributes": custom_attrs,
    }

    if cvss_version.startswith("2"):
        vuln_params["cvss2BaseScore"] = float(cvss_base)
    else:
        vuln_params["cvss3BaseScore"] = float(cvss_base)

    return Vulnerability(**vuln_params)


def extract_os_from_rca(rca_list):
    """Extract OS name and version from vulnerability_root_cause_analysis."""
    os_name = ""
    os_version = ""
    if not rca_list:
        return os_name, os_version
    for rca in rca_list:
        title = rca.get("title", "").lower()
        actual = rca.get("actual_value", "")
        if not actual:
            continue
        if "operating system" in title:
            os_name = actual
        elif "kernel version" in title or "os version" in title:
            os_version = actual
    return os_name, os_version


def add_to_asset_map(asset_map, asset_id, hostname, finding, inv):
    """Add an investigation to the asset map, accumulating metadata and vulns."""
    if asset_id not in asset_map:
        asset_map[asset_id] = {
            "id": asset_id,
            "hostname": hostname,
            "asset_type": "",
            "cloud_platform": "",
            "region": "",
            "account_id": "",
            "scanner": "",
            "asset_full_id": "",
            "os": "",
            "os_version": "",
            "vulnerabilities": [],
        }

    entry = asset_map[asset_id]

    if finding:
        if not entry["asset_type"]:
            entry["asset_type"] = finding.get("asset_type", "")
        if not entry["cloud_platform"]:
            entry["cloud_platform"] = finding.get("cloud_platform", "")
        if not entry["region"]:
            entry["region"] = finding.get("region", "")
        if not entry["account_id"]:
            entry["account_id"] = finding.get("account_id", "")
        if not entry["scanner"]:
            entry["scanner"] = finding.get("scanner", "")
        if not entry["asset_full_id"]:
            entry["asset_full_id"] = finding.get("asset_id", "")

    rca_list = inv.get("vulnerability_root_cause_analysis", []) or []
    os_name, os_version = extract_os_from_rca(rca_list)
    if os_name and not entry["os"]:
        entry["os"] = os_name
    if os_version and not entry["os_version"]:
        entry["os_version"] = os_version

    vuln = build_vulnerability(inv)
    entry["vulnerabilities"].append(vuln)


def group_investigations(asset_map, investigations):
    """Group a page of investigations by asset into asset_map."""
    for inv in investigations:
        scanner_hash = inv.get("scanner_finding_hash", "")
        asset_id = parse_asset_id(scanner_hash)
        if not asset_id:
            asset_id = inv.get("id", "")

        related = inv.get("related_scanner_findings", []) or []
        if related:
            for finding in related:
                finding_asset = finding.get("asset_name", "") or asset_id
                add_to_asset_map(asset_map, finding_asset, finding_asset, finding, inv)
        else:
            add_to_asset_map(asset_map, asset_id, asset_id, None, inv)


def build_asset(asset_id, asset_data):
    """Build a single ImportAsset from a grouped asset_map entry."""
    hostname = asset_data["hostname"]
    vulns = asset_data["vulnerabilities"]
    os_name = asset_data["os"]
    os_version = asset_data["os_version"]

    custom_attrs = {
        "maze_finding_count": str(len(vulns)),
        "source": "maze",
    }
    if asset_data["asset_type"]:
        custom_attrs["maze_asset_type"] = force_string(asset_data["asset_type"])
    if asset_data["cloud_platform"]:
        custom_attrs["maze_cloud_platform"] = force_string(asset_data["cloud_platform"])
    if asset_data["region"]:
        custom_attrs["maze_region"] = force_string(asset_data["region"])
    if asset_data["account_id"]:
        custom_attrs["maze_account_id"] = force_string(asset_data["account_id"])
    if asset_data["scanner"]:
        custom_attrs["maze_scanner"] = force_string(asset_data["scanner"])
    if asset_data["asset_full_id"]:
        custom_attrs["maze_asset_full_id"] = force_string(asset_data["asset_full_id"])

    asset_params = {
        "id": str(asset_id),
        "hostnames": [hostname] if hostname else [],
        "vulnerabilities": vulns[:999],
        "customAttributes": to_custom_attributes(custom_attrs),
    }
    if os_name:
        asset_params["os"] = os_name
    if os_version:
        asset_params["osVersion"] = os_version
    if asset_data["asset_type"]:
        asset_params["deviceType"] = asset_data["asset_type"]

    return ImportAsset(**asset_params)


def main(**kwargs):
    api_key = get_string(kwargs, "api_key")
    days_back = get_int(kwargs, "days_back", default=30)
    updated_from = compute_updated_from(days_back)

    http_options = get_http_options(kwargs, headers={
        "X-API-Key": api_key,
        "Accept": "application/json",
    })
    url = "{}/v1/investigations/search".format(MAZE_API_URL)

    # Investigations are grouped into assets across pages, so accumulate the
    # grouped map while paging (dropping each raw page as we go) and stream the
    # finished assets to runZero in batches at the end.
    asset_map = {}
    cursor = None
    total_inv = 0
    page = 0

    for page in range(1, 100001):
        body = {"limit": PAGE_LIMIT, "updated_from": updated_from}
        if cursor:
            body["cursor"] = cursor

        data, err = post_json(url, json=body, **http_options)
        if err:
            print("Maze API error on page {}: {}".format(page, err))
            break

        data = data or {}
        investigations = data.get("data", []) or []
        total_inv += len(investigations)
        group_investigations(asset_map, investigations)

        cursor = data.get("next_cursor")
        if not data.get("has_more", False) or not cursor:
            break

    total_assets = 0
    batch = []
    for asset_id, asset_data in asset_map.items():
        batch.append(build_asset(asset_id, asset_data))
        if len(batch) >= REPORT_BATCH:
            report_assets(batch)
            total_assets += len(batch)
            batch = []
    if batch:
        report_assets(batch)
        total_assets += len(batch)

    print("Reported {} assets from {} investigations".format(total_assets, total_inv))
    return None

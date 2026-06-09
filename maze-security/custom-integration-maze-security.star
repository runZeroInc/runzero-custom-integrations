load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('http', http_post='post')
load('time', 'now', 'parse_duration')

MAZE_API_URL = "https://api.mazehq.com"
PAGE_LIMIT = 1000
DEFAULT_DAYS_BACK = 30
MAX_RETRIES = 3

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


def search_investigations(api_key):
    """Fetch investigations from Maze API updated within DEFAULT_DAYS_BACK."""
    updated_from = compute_updated_from(DEFAULT_DAYS_BACK)
    print("Starting Maze API fetch (updated_from: {})...".format(updated_from))
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    url = "{}/v1/investigations/search".format(MAZE_API_URL)
    print("URL: {}".format(url))

    all_investigations = []
    cursor = None
    has_more = True
    page = 0

    while has_more:
        page += 1
        body = {"limit": PAGE_LIMIT, "updated_from": updated_from}
        if cursor:
            body["cursor"] = cursor

        print("Fetching page {}...".format(page))
        response = None
        for attempt in range(MAX_RETRIES):
            response = http_post(url, headers=headers, body=bytes(json_encode(body)), timeout=600)
            print("Response status: {}".format(response.status_code))
            if response.status_code == 200:
                break
            if response.status_code >= 500 and attempt < MAX_RETRIES - 1:
                print("Server error {}, retry {}/{}...".format(response.status_code, attempt + 1, MAX_RETRIES))
                continue
            break

        if response.status_code != 200:
            print("Maze API error: status {}".format(response.status_code))
            print("Response body: {}".format(response.body[:500]))
            break

        data = json_decode(response.body)
        investigations = data.get("data", [])
        all_investigations.extend(investigations)
        print("Page {}: got {} investigations (total: {})".format(page, len(investigations), len(all_investigations)))

        has_more = data.get("has_more", False)
        cursor = data.get("next_cursor")

        if not cursor:
            has_more = False

    print("Fetched {} total investigations from Maze API".format(len(all_investigations)))
    return all_investigations


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

    snapshot = investigation.get("snapshot", {})
    if not snapshot:
        snapshot = {}
    cve_info = snapshot.get("cve", {})
    if not cve_info:
        cve_info = {}
    cvss_info = snapshot.get("cvss", {})
    if not cvss_info:
        cvss_info = {}

    description = cve_info.get("description", "")
    cvss_base = cvss_info.get("base_score", 0.0)
    if cvss_base == None:
        cvss_base = 0.0
    cvss_version = cvss_info.get("version", "")

    rank = SEVERITY_RANK.get(maze_severity, 0)
    score = SEVERITY_SCORE.get(maze_severity, 0.0)

    is_exploitable = exploitability == "exploitable"

    severity_details = investigation.get("severity_details", {})
    if not severity_details:
        severity_details = {}
    severity_reasoning = severity_details.get("reasoning", "")

    rca_list = investigation.get("vulnerability_root_cause_analysis", [])
    if not rca_list:
        rca_list = []
    rca_summary = build_root_cause_summary(rca_list)

    remediation = investigation.get("remediation", "")
    if not remediation:
        remediation = ""

    custom_attrs = {
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
    }

    likelihood = investigation.get("likelihood", "")
    if likelihood:
        custom_attrs["maze_likelihood"] = force_string(likelihood)
    impact = investigation.get("impact", "")
    if impact:
        custom_attrs["maze_impact"] = force_string(impact)

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

    if cvss_version.startswith("3"):
        vuln_params["cvss3BaseScore"] = float(cvss_base)
    elif cvss_version.startswith("2"):
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

    rca_list = inv.get("vulnerability_root_cause_analysis", [])
    if not rca_list:
        rca_list = []
    os_name, os_version = extract_os_from_rca(rca_list)
    if os_name and not entry["os"]:
        entry["os"] = os_name
    if os_version and not entry["os_version"]:
        entry["os_version"] = os_version

    vuln = build_vulnerability(inv)
    entry["vulnerabilities"].append(vuln)


def build_assets(investigations):
    """Group investigations by asset and build ImportAsset objects with Vulnerability lists."""
    asset_map = {}

    for inv in investigations:
        scanner_hash = inv.get("scanner_finding_hash", "")
        asset_id = parse_asset_id(scanner_hash)

        if not asset_id:
            asset_id = inv.get("id", "")

        related = inv.get("related_scanner_findings", [])
        if not related:
            related = []

        if related:
            for finding in related:
                finding_asset = finding.get("asset_name", "")
                if not finding_asset:
                    finding_asset = asset_id
                add_to_asset_map(asset_map, finding_asset, finding_asset, finding, inv)
        else:
            add_to_asset_map(asset_map, asset_id, asset_id, None, inv)

    assets = []
    for asset_id, asset_data in asset_map.items():
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
            "customAttributes": custom_attrs,
        }
        if os_name:
            asset_params["os"] = os_name
        if os_version:
            asset_params["osVersion"] = os_version
        if asset_data["asset_type"]:
            asset_params["deviceType"] = asset_data["asset_type"]

        assets.append(ImportAsset(**asset_params))

    return assets


def main(*args, **kwargs):
    print("=== Maze Integration Starting ===")
    print("kwargs keys: {}".format(list(kwargs.keys())))

    api_key = kwargs.get("access_secret")

    if not api_key:
        print("Error: Maze API key not provided in access_secret")
        return []

    print("API key length: {}".format(len(api_key)))

    investigations = search_investigations(api_key)

    if not investigations:
        print("No investigations returned from Maze API")
        return []

    assets = build_assets(investigations)
    print("Built {} assets from {} investigations".format(len(assets), len(investigations)))
    print("=== Maze Integration Complete ===")

    return assets

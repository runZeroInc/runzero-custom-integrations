# runzero-carbonblack-onprem.star

load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_get='get', http_post='post')

# ==== CONFIGURATION ====

# Point this at your Carbon Black EDR server
CARBON_BLACK_HOST = "<UPDATE_ME>"   # e.g. "https://cb-server.mycompany.local"

# Endpoints
SENSOR_LIST_URL    = CARBON_BLACK_HOST + "/api/v1/sensor"
SENSOR_DETAIL_URL  = CARBON_BLACK_HOST + "/api/v1/sensor/{}"
VULNERABILITY_URL  = CARBON_BLACK_HOST + "/api/v1/sensor/{}/vulnerabilities"

# ==== API CLIENTS ====

def get_sensors(org_id, api_token):
    """
    Fetch all sensors (endpoints) from Carbon Black.
    Returns a list of sensor dicts, or [] on error.
    """
    headers = {
        "X-Auth-Token": api_token,
        "Content-Type": "application/json",
    }
    resp = get(SENSOR_LIST_URL, headers=headers)
    if resp.status_code != 200:
        print("Failed to list sensors. Status:", resp.status_code)
        return []
    return json_decode(resp.body)

def get_sensor_details(org_id, api_token, sensor_id):
    """
    Fetch full details for a single sensor.
    Returns a dict, or {} on error.
    """
    headers = {
        "X-Auth-Token": api_token,
        "Content-Type": "application/json",
    }
    url = SENSOR_DETAIL_URL.format(sensor_id)
    resp = get(url, headers=headers)
    if resp.status_code != 200:
        print("Failed to get details for sensor", sensor_id, "Status:", resp.status_code)
        return {}
    return json_decode(resp.body)

def get_device_vulnerabilities(org_id, api_token, sensor_id, limit=None):
    """
    Fetch vulnerability data for a sensor (if available).
    Returns a list of vuln dicts, or [].
    """
    headers = {
        "X-Auth-Token": api_token,
        "Content-Type": "application/json",
    }
    url = VULNERABILITY_URL.format(sensor_id)
    resp = get(url, headers=headers)
    if resp.status_code != 200:
        # Vulnerability module may not be installed on-prem
        return []
    body = json_decode(resp.body)
    vulns = body.get("results", [])
    if limit != None and len(vulns) > limit:
        return vulns[:limit]
    return vulns

# ==== BUILDERS ====

def build_vulnerabilities(vuln_list):
    """
    Map raw vuln dicts to runZero Vulnerability objects.
    """
    severity_map = {
        "CRITICAL": 4,
        "HIGH":     3,
        "MODERATE": 2,
        "LOW":      1,
    }
    out = []
    for v in vuln_list:
        info = v.get("vuln_info", {})
        cve = info.get("cve_id", v.get("vuln_id", ""))
        score = float(v.get("risk_meter_score", 0))
        rank  = severity_map.get(v.get("severity", "").upper(), 0)
        out.append(
            Vulnerability(
                id            = cve,
                name          = cve,
                description   = info.get("cve_description", ""),
                cve           = cve,
                riskScore     = score,
                riskRank      = rank,
                severityScore = score,
                severityRank  = rank,
                solution      = info.get("fixed_by", ""),
                customAttributes = {
                    "nvd_link":       info.get("nvd_link", ""),
                    "cvss_score":     info.get("cvss_score", ""),
                    "cvss_v3_score":  info.get("cvss_v3_score", ""),
                }
            )
        )
    return out

def build_network_interface(network_adapters):
    """
    Parse pipe-delimited "IP,MAC|IP,MAC|…" string.
    Returns a single NetworkInterface.
    """
    ipv4s = []
    ipv6s = []
    mac_addr = None

    for entry in network_adapters.split("|"):
        if not entry:
            continue
        parts = entry.split(",")
        if len(parts) != 2:
            continue
        ip_str = parts[0].strip()
        mac     = parts[1].strip()
        mac_addr = mac or mac_addr
        try:
            addr = ip_address(ip_str)
            if addr.version == 4:
                ipv4s.append(addr)
            else:
                ipv6s.append(addr)
        except:
            # skip invalid IPs
            pass

    return NetworkInterface(
        macAddress   = mac_addr,
        ipv4Addresses = ipv4s,
        ipv6Addresses = ipv6s,
    )

def build_assets(org_id, api_token, sensors, vuln_limit=None):
    """
    Convert sensors → ImportAsset list, including vulnerabilities.
    """
    assets = []
    for s in sensors:
        sid       = str(s.get("id", ""))
        hostname  = s.get("computer_name", "")
        # Prefer human-readable OS if available
        os_name   = s.get("os_environment_display_string") or s.get("os_type","")
        os_version= s.get("os_version") or ""

        # Fetch vuln data (if any)
        vulns_raw = get_device_vulnerabilities(org_id, api_token, sid, vuln_limit)
        vulns     = build_vulnerabilities(vulns_raw)

        # Parse network adapters
        net_iface = build_network_interface(s.get("network_adapters",""))

        # Custom attributes: everything else
        custom = {}
        for k, v in s.items():
            if k in ("id", "computer_name", "os_environment_display_string",
                     "os_type","os_version","network_adapters"):
                continue
            custom[k] = str(v)

        assets.append(
            ImportAsset(
                id               = sid,
                hostnames        = [hostname] if hostname else [],
                os               = os_name,
                osVersion        = os_version,
                networkInterfaces= [net_iface],
                vulnerabilities  = vulns,
                customAttributes = custom,
            )
        )
    return assets

# ==== ENTRYPOINT ====

def main(*args, **kwargs):
    """
    runZero entrypoint.
    Expects:
      access_key    → Org ID (unused on-prem, but passed in)
      access_secret → API token
    """
    org_id    = kwargs.get("access_key")
    api_token = kwargs.get("access_secret")

    sensors = get_sensors(org_id, api_token)
    if not sensors:
        print("No sensors found.")
        return None

    assets = build_assets(org_id, api_token, sensors)
    return assets

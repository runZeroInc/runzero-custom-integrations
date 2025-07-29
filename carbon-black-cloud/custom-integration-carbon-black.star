load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')

CARBON_BLACK_HOST = "<UPDATE_ME>"  # Example: https://defense.conferdeploy.net
SCROLL_API_URL = "{}/appservices/v6/orgs/{}/devices/_scroll"
VULNERABILITY_API_URL = "{}/vulnerability/assessment/api/v1/orgs/{}/devices/{}/vulnerabilities/_search?dataForExport=true"
PAGE_SIZE = 1000  # Max devices per request
VULN_PAGE_SIZE = 100  # Max vulnerabilities per API call
MAX_VULNS = None  # Set to None for all, or an integer for a limit (e.g., 50)

def get_devices(org_key, api_key):
    """Retrieve all devices from Carbon Black Cloud API using _scroll for large datasets"""
    headers = {
        "X-Auth-Token": "{}/{}".format(api_key, org_key),
        "Content-Type": "application/json",
    }

    devices = []
    
    # Step 1: Start the scroll session
    payload = {
        "criteria": {},
        "rows": PAGE_SIZE
    }
    url = SCROLL_API_URL.format(CARBON_BLACK_HOST, org_key)
    response = http_post(url, headers=headers, body=bytes(json_encode(payload)))

    if response.status_code != 200:
        print("Failed to start scroll session. Status: {}".format(response.status_code))
        return devices

    response_json = json_decode(response.body)
    batch = response_json.get("results", [])
    scroll_id = response_json.get("scroll_id", None)

    if not batch:
        print("No devices returned or missing scroll_id.")
        return devices

    devices.extend(batch)

    if not scroll_id:
        return devices

    # Step 2: Continue fetching batches using scroll_id
    while scroll_id:
        payload = {"scroll_id": scroll_id}
        response = http_post(url, headers=headers, body=bytes(json_encode(payload)))

        if response.status_code != 200:
            print("Failed to retrieve next batch. Status: {}".format(response.status_code))
            break

        response_json = json_decode(response.body)
        batch = response_json.get("results", [])
        scroll_id = response_json.get("scroll_id", None)

        if not batch:
            break  # No more data to retrieve

        devices.extend(batch)

    return devices

def get_device_vulnerabilities(org_key, api_key, device_id, MAX_VULNS):
    """Retrieve vulnerabilities for a specific device, with optional max limit"""
    headers = {
        "X-Auth-Token": "{}/{}".format(api_key, org_key),
        "Content-Type": "application/json",
    }
    
    vulnerabilities = []
    start = 0

    while MAX_VULNS == None or len(vulnerabilities) < MAX_VULNS:
        remaining = VULN_PAGE_SIZE
        if MAX_VULNS != None:
            remaining = min(MAX_VULNS - len(vulnerabilities), VULN_PAGE_SIZE)

        payload = {
            "query": "",
            "rows": remaining,
            "start": start,
            "criteria": {},
            "sort": [{"field": "risk_meter_score", "order": "DESC"}]
        }
        
        url = VULNERABILITY_API_URL.format(CARBON_BLACK_HOST, org_key, device_id)
        response = http_post(url, headers=headers, body=bytes(json_encode(payload)))

        if response.status_code != 200:
            print("Failed to retrieve vulnerabilities for device:", device_id)
            return vulnerabilities

        response_json = json_decode(response.body)
        batch = response_json.get("results", [])
        
        if not batch:
            break  # No more vulnerabilities left

        vulnerabilities.extend(batch)
        start += VULN_PAGE_SIZE

    if MAX_VULNS != None:
        return vulnerabilities[:MAX_VULNS]
    return vulnerabilities

def build_vulnerabilities(vuln_data):
    """Convert Carbon Black vulnerabilities into runZero vulnerability format"""
    vulnerabilities = []

    for vuln in vuln_data:
        vuln_info = vuln.get("vuln_info", {})
        cve_id = vuln_info.get("cve_id", "")
        description = vuln_info.get("cve_description", "")
        severity = vuln_info.get("severity", "LOW").upper()
        risk_meter_score = vuln_info.get("risk_meter_score", 0)

        # Map severity to numeric risk rank
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1}
        risk_rank = severity_map.get(severity, 0)

        vulnerabilities.append(
            Vulnerability(
                id=cve_id,
                name=cve_id,
                description=description,
                cve=cve_id,
                riskScore=float(risk_meter_score),
                riskRank=risk_rank,
                severityScore=float(risk_meter_score),
                severityRank=risk_rank,
                solution=vuln_info.get("solution", ""),
                customAttributes={
                    "fixed_by": vuln_info.get("fixed_by", ""),
                    "created_at": vuln_info.get("created_at", ""),
                    "nvd_link": vuln_info.get("nvd_link", ""),
                    "cvss_score": vuln_info.get("cvss_score", ""),
                    "cvss_v3_score": vuln_info.get("cvss_v3_score", ""),
                }
            )
        )

    return vulnerabilities

def build_assets(org_key, api_key, devices):
    """Convert Carbon Black devices into runZero assets with vulnerability data"""
    assets = []
    
    for device in devices:
        device_id = str(device.get("id", ""))
        hostname = device.get("name", "")
        os = device.get("os", "")
        os_version = device.get("os_version", "")
        ip = device.get("last_internal_ip_address", "")
        mac = device.get("mac_address", "")

        # Fetch vulnerabilities for the device
        vuln_data = get_device_vulnerabilities(org_key, api_key, device_id, MAX_VULNS)
        vulnerabilities = build_vulnerabilities(vuln_data)

        # Build network interfaces
        network = build_network_interface(ips=[ip], mac=mac if mac else None)

        # Manually build customAttributes for compatibility
        custom_attrs = {
            "activation_code": device.get("activation_code", ""),
            "ad_domain": device.get("ad_domain", ""),
            "av_engine": device.get("av_engine", ""),
            "compliance_status": device.get("compliance_status", ""),
            "deployment_type": device.get("deployment_type", ""),
            "device_owner_id": str(device.get("device_owner_id", "")),
            "organization_name": device.get("organization_name", ""),
            "os_version": device.get("os_version", ""),
            "sensor_version": device.get("sensor_version", ""),
            "status": device.get("status", ""),
            "target_priority": device.get("target_priority", ""),
            "virtual_machine": str(device.get("virtual_machine", "")),
            "vulnerability_score": str(device.get("vulnerability_score", "")),
            "vulnerability_severity": device.get("vulnerability_severity", ""),
        }

        assets.append(
            ImportAsset(
                id=device_id,
                hostnames=[hostname],
                os=os,
                osVersion=os_version,
                networkInterfaces=[network],
                vulnerabilities=vulnerabilities,
                customAttributes=custom_attrs
            )
        )

    return assets

def build_network_interface(ips, mac):
    """Build runZero network interfaces"""
    ip4s = []
    ip6s = []

    for ip in ips[:99]:
        if ip:
            ip_addr = ip_address(ip)
            if ip_addr.version == 4:
                ip4s.append(ip_addr)
            elif ip_addr.version == 6:
                ip6s.append(ip_addr)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)

def main(**kwargs):
    """Main function for Carbon Black integration"""
    org_key = kwargs['access_key']
    api_key = kwargs['access_secret']

    devices = get_devices(org_key, api_key)
    
    if not devices:
        print("No devices found.")
        return None

    assets = build_assets(org_key, api_key, devices)
    
    if not assets:
        print("No assets created.")
    
    return assets

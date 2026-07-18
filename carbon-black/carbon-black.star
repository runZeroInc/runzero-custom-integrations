# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-carbon-black",
    "name": "Carbon Black",
    "type": "inbound",
    "description": "Imports endpoints from VMware Carbon Black Cloud.",
    "version": "26061000",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "url",
            "label": "Carbon Black base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://defense.conferdeploy.net",
        },
        {
            "key": "organization_key",
            "label": "Organization key",
            "type": "string",
            "required": True,
        },
        {
            "key": "api_key",
            "label": "API key",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'post_json')
load('kwargs', 'get_url_base', 'get_http_options')

SCROLL_API_URL = "{}/appservices/v6/orgs/{}/devices/_scroll"
VULNERABILITY_API_URL = "{}/vulnerability/assessment/api/v1/orgs/{}/devices/{}/vulnerabilities/_search?dataForExport=true"
PAGE_SIZE = 1000  # Max devices per request
VULN_PAGE_SIZE = 100  # Max vulnerabilities per API call
MAX_VULNS = None  # Set to None for all, or an integer for a limit (e.g., 50)

def fetch_and_report_devices(base_url, org_key, api_key, config_kwargs):
    """Scroll through all devices, building and reporting assets one page at a
    time so the full device + vulnerability dataset is never held in memory."""
    headers = {
        "X-Auth-Token": "{}/{}".format(api_key, org_key),
        "Content-Type": "application/json",
    }
    http_options = get_http_options(config_kwargs, headers=headers)

    url = SCROLL_API_URL.format(base_url, org_key)
    total = 0

    # Step 1: Start the scroll session
    payload = {
        "criteria": {},
        "rows": PAGE_SIZE
    }

    while True:
        response_json, err = post_json(url, json=payload, **http_options)
        if err:
            print("Failed to retrieve devices:", err)
            break

        response_json = response_json or {}
        batch = response_json.get("results", [])
        scroll_id = response_json.get("scroll_id", None)

        if not batch:
            break  # No more data to retrieve

        # Build and report this page's assets immediately, then drop the
        # references so memory usage stays bounded by a single page.
        assets = build_assets(base_url, org_key, api_key, batch, config_kwargs)
        if assets:
            report_assets(assets)
            total += len(assets)

        if not scroll_id:
            break

        # Step 2: Continue fetching batches using scroll_id
        payload = {"scroll_id": scroll_id}

    return total

def get_device_vulnerabilities(base_url, org_key, api_key, device_id, MAX_VULNS, config_kwargs):
    """Retrieve vulnerabilities for a specific device, with optional max limit"""
    headers = {
        "X-Auth-Token": "{}/{}".format(api_key, org_key),
        "Content-Type": "application/json",
    }
    http_options = get_http_options(config_kwargs, headers=headers)
    
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
        
        url = VULNERABILITY_API_URL.format(base_url, org_key, device_id)
        response_json, err = post_json(url, json=payload, **http_options)

        if err:
            print("Failed to retrieve vulnerabilities for device:", device_id, err)
            return vulnerabilities

        response_json = response_json or {}
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
                customAttributes=to_custom_attributes({
                    "fixed_by": vuln_info.get("fixed_by"),
                    "created_at": vuln_info.get("created_at"),
                    "nvd_link": vuln_info.get("nvd_link"),
                    "cvss_score": vuln_info.get("cvss_score"),
                    "cvss_v3_score": vuln_info.get("cvss_v3_score"),
                })
            )
        )

    return vulnerabilities

def build_assets(base_url, org_key, api_key, devices, config_kwargs):
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
        vuln_data = get_device_vulnerabilities(base_url, org_key, api_key, device_id, MAX_VULNS, config_kwargs)
        vulnerabilities = build_vulnerabilities(vuln_data)

        # Build network interfaces
        network = network_interface(ips=[ip], mac=mac if mac else None)

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
                customAttributes=to_custom_attributes(custom_attrs),
            )
        )

    return assets

def main(**kwargs):
    """Main function for Carbon Black integration"""
    base_url = get_url_base(kwargs)
    org_key = kwargs['organization_key']
    api_key = kwargs['api_key']

    # Devices are streamed to runZero page-by-page via report_assets() inside
    # fetch_and_report_devices, so nothing is returned from main().
    total = fetch_and_report_devices(base_url, org_key, api_key, kwargs)

    if total == 0:
        print("No assets created.")

    return None

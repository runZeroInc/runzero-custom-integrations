# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-carbon-black",
    "name": "Carbon Black",
    "type": "inbound",
    "description": "Imports endpoints from VMware Carbon Black Cloud.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
            "description": "The Org Key from Settings > General. It scopes the request path and is never sent as a header.",
        },
        {
            "key": "api_id",
            "label": "API ID",
            "type": "string",
            "required": True,
            "description": "The API ID issued alongside the secret when the API key was created, shown on Settings > API Access under the key's Actions menu.",
        },
        {
            "key": "api_key",
            "label": "API secret key",
            "type": "secret",
            "required": True,
            "description": "The API Secret Key, displayed once when the API key is created.",
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

# deployment_type is Carbon Black's own device class, documented on the Devices
# API with the values ENDPOINT, WORKLOAD, VDI, AWS, AZURE, and GCP. WORKLOAD is
# a server under Workload Protection and the three cloud values are compute
# instances, so all four name a server; VDI is a virtual desktop.
#
# ENDPOINT is deliberately absent. It covers desktops and laptops without
# separating them, so translating it would assert a chassis Carbon Black never
# reported and displace the one runZero derives from the hardware itself.
DEVICE_TYPES = {
    "WORKLOAD": "Server",
    "AWS": "Server",
    "AZURE": "Server",
    "GCP": "Server",
    "VDI": "Desktop",
}

def auth_headers(api_key, api_id):
    """Carbon Black documents X-Auth-Token as <API Secret Key>/<API ID>, secret
    first. The second component is the API ID minted with the key -- NOT the Org
    Key, which is a separate value that only ever appears in the request path.
    Building the header from the Org Key sent a token Carbon Black cannot match
    to any key, so every request was refused. Both callers share this so the two
    header sites cannot drift apart again."""
    return {
        "X-Auth-Token": "{}/{}".format(api_key, api_id),
        "Content-Type": "application/json",
    }

def fetch_and_report_devices(base_url, org_key, api_key, api_id, config_kwargs):
    """Scroll through all devices, building and reporting assets one page at a
    time so the full device + vulnerability dataset is never held in memory."""
    http_options = get_http_options(config_kwargs, headers=auth_headers(api_key, api_id))

    url = SCROLL_API_URL.format(base_url, org_key)
    total = 0
    # Drops accumulate across every scroll page and are reported once at the
    # end, so a degraded export costs two lines rather than one per row.
    skipped = {"non_dict": 0, "no_id": 0}

    # Step 1: Start the scroll session
    payload = {
        "criteria": {},
        "rows": PAGE_SIZE
    }

    while True:
        response_json, err = post_json(url, json=payload, **http_options)
        if err:
            print("carbon-black: failed to retrieve devices: {}".format(err))
            break

        response_json = response_json or {}
        batch = response_json.get("results", [])
        scroll_id = response_json.get("scroll_id", None)

        if not batch:
            break  # No more data to retrieve

        # Build and report this page's assets immediately, then drop the
        # references so memory usage stays bounded by a single page.
        assets = build_assets(base_url, org_key, api_key, api_id, batch, config_kwargs, skipped)
        if assets:
            report_assets(assets)
            total += len(assets)

        if not scroll_id:
            break

        # Step 2: Continue fetching batches using scroll_id
        payload = {"scroll_id": scroll_id}

    if skipped["non_dict"] > 0:
        print("carbon-black: skipped {} non-object device rows".format(skipped["non_dict"]))
    if skipped["no_id"] > 0:
        print("carbon-black: skipped {} devices with no id".format(skipped["no_id"]))
    return total

def get_device_vulnerabilities(base_url, org_key, api_key, api_id, device_id, MAX_VULNS, config_kwargs):
    """Retrieve vulnerabilities for a specific device, with optional max limit"""
    http_options = get_http_options(config_kwargs, headers=auth_headers(api_key, api_id))

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
            print("carbon-black: failed to retrieve vulnerabilities for device {}: {}".format(device_id, err))
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
        # .get's default only applies when the key is ABSENT, not when it is
        # present with a null value. Carbon Black leaves risk_meter_score null
        # for a vulnerability it has not scored yet, and float(None) aborts the
        # script -- one unscored CVE on one endpoint used to take down the whole
        # import. severity and vuln_info reach the same abort the same way, via
        # .upper() and .get() on None.
        vuln_info = vuln.get("vuln_info") or {}
        cve_id = vuln_info.get("cve_id", "")
        description = vuln_info.get("cve_description", "")
        severity = (vuln_info.get("severity") or "LOW").upper()
        risk_meter_score = vuln_info.get("risk_meter_score") or 0

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

def build_assets(base_url, org_key, api_key, api_id, devices, config_kwargs, skipped):
    """Convert Carbon Black devices into runZero assets with vulnerability data"""
    assets = []
    
    for device in devices:
        # A scroll page can carry something that is not an object -- an error
        # document, or a row the API degraded into a bare string. Calling .get
        # on it aborts the script and every device already parsed is lost, so
        # the shape is checked rather than assumed.
        if type(device) != "dict":
            skipped["non_dict"] += 1
            continue

        # An explicit null id is not caught by .get's default, which only
        # applies when the key is ABSENT. str(None) turned every id-less device
        # into the single foreign id "None", collapsing them all onto one asset,
        # and interpolated that same "None" into the vulnerability URL so the
        # run issued POST .../devices/None/vulnerabilities/_search.
        raw_id = device.get("id")
        if raw_id == None or str(raw_id) == "":
            skipped["no_id"] += 1
            continue
        device_id = str(raw_id)
        hostname = device.get("name", "")
        os = device.get("os", "")
        os_version = device.get("os_version", "")
        ip = device.get("last_internal_ip_address", "")
        mac = device.get("mac_address", "")

        # Fetch vulnerabilities for the device
        vuln_data = get_device_vulnerabilities(base_url, org_key, api_key, api_id, device_id, MAX_VULNS, config_kwargs)
        vulnerabilities = build_vulnerabilities(vuln_data)

        # Build network interfaces. network_interface returns None when nothing
        # usable survives -- a sensor that has registered but not yet reported
        # an adapter has neither address nor MAC -- and passing [None] to
        # ImportAsset aborts the entire run, so the interface is only added when
        # one was actually built.
        network = network_interface(ips=[ip] if ip else [], mac=mac if mac else None)
        interfaces = [network] if network else []

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

        params = {
            "id": device_id,
            "hostnames": [hostname],
            "os": os,
            "osVersion": os_version,
            "networkInterfaces": interfaces,
            "vulnerabilities": vulnerabilities,
            "customAttributes": to_custom_attributes(custom_attrs),
        }

        # Omitted rather than set to "" for an unmapped class: an empty
        # deviceType is still a value and displaces the type runZero would
        # otherwise fingerprint for itself.
        device_type = DEVICE_TYPES.get(str(device.get("deployment_type") or "").strip().upper(), "")
        if device_type:
            params["deviceType"] = device_type

        assets.append(ImportAsset(**params))

    return assets

def main(**kwargs):
    """Main function for Carbon Black integration"""
    base_url = get_url_base(kwargs)
    org_key = kwargs['organization_key']
    api_id = kwargs['api_id']
    api_key = kwargs['api_key']

    # Devices are streamed to runZero page-by-page via report_assets() inside
    # fetch_and_report_devices, so nothing is returned from main().
    total = fetch_and_report_devices(base_url, org_key, api_key, api_id, kwargs)

    print("carbon-black: reported {} assets".format(total))

    return None

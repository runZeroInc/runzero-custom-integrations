# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-tanium",
    "name": "Tanium",
    "type": "inbound",
    "description": "Imports endpoints from Tanium.",
    "version": "26061000",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "url",
            "label": "Tanium URL",
            "type": "url",
            "required": True,
            "placeholder": "https://tenant.titankube.com",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software', 'Vulnerability', 'to_custom_attributes')
load('net', 'ip_address')
load('http', 'post_json')
load('kwargs', 'get_url_base', 'get_http_options')



def build_vulnerabilities(vulnerabilities):
    output_vulnerabilities = []
    uuid = 0
    for vuln in vulnerabilities:
        uuid += 1
        absoluteFirstFoundDate = vuln.get("absoluteFirstFoundDate", "")
        affectedProducts = vuln.get("affectedProducts", "")
        cisaDateAdded = vuln.get("cisaDateAdded", "")
        cisaDueDate = vuln.get("cisaDueDate", "")
        cisaNotes = vuln.get("cisaNotes", "")
        cisaProduct = vuln.get("cisaProduct", "")
        cisaRequiredAction = vuln.get("cisaRequiredAction", "")
        cisaShortDescription = vuln.get("cisaShortDescription", "")
        cisaVendor = vuln.get("cisaVendor", "")
        cisaVulnerabilityName = vuln.get("cisaVulnerabilityName", "")
        cpes = vuln.get("cpes", [])
        cveId = vuln.get("cveId", "")
        cveYear = vuln.get("cveYear", "")
        cvssScore = vuln.get("cvssScore", 0)
        if cvssScore == None:
            cvssScore = 0
        excepted = vuln.get("excepted", "")
        firstFound = vuln.get("firstFound", "")
        isCisaKev = vuln.get("isCisaKev", "")
        lastFound = vuln.get("lastFound", "")
        lastScanDate = vuln.get("lastScanDate", "")
        scanType = vuln.get("scanType", "")

        # take plain text severity and map to rz integer
        severity = vuln.get("severity", 0)

        rank_map = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
        }

        score_map = {
            "Critical": 10,
            "High": 7,
            "Medium": 5,
            "Low": 2,
        }

        if severity in rank_map:
            risk_rank = rank_map[severity]
            score = score_map[severity]
        else:
            risk_rank = 0
            score = 0
        summary = vuln.get("summary", "")
        output_vulnerabilities.append(
                Vulnerability(
                    id=str(uuid),
                    name=str(summary)[:255],
                    description=str(summary)[:255],
                    cve=str(cveId)[:13],
                    solution=str(cisaRequiredAction),
                    cvss2BaseScore=float(cvssScore),
                    cvss2TemporalScore=float(cvssScore),
                    cvss3BaseScore=float(cvssScore),
                    cvss3TemporalScore=float(cvssScore),
                    riskScore=float(score),
                    riskRank=risk_rank,
                    severityScore=float(score),
                    severityRank=risk_rank,
                    serviceAddress="127.0.0.1",
                    customAttributes=to_custom_attributes({
                        "affectedProducts": affectedProducts,
                        "cisaDueDate": cisaDueDate,
                        "cisaNotes": cisaNotes,
                        "cisaProduct": cisaProduct,
                        "cisaRequiredAction": cisaRequiredAction,
                        "cisaVulnerabilityName": cisaVulnerabilityName,
                        "cisaVendor": cisaVendor,
                        "cveYear": cveYear,
                        "excepted": excepted,
                        "firstFound": firstFound,
                        "lastScanDate": lastScanDate,
                        "scanType": scanType,
                        "summary": summary,
                        "cpes": cpes,
                        "absoluteFirstFoundDate": absoluteFirstFoundDate,
                        "cisaDateAdded": cisaDateAdded,
                        "isCisaKev": isCisaKev,
                        "lastFound": lastFound,
                        "cisaShortDescription": cisaShortDescription,
                    }),
                )
            )

    return output_vulnerabilities
def build_software(applications, installed_software):
    software = []
    unique_applications = {}
    for a in applications + installed_software:
        key_list = a.get("name", "").split(" ")
        key_unique = (
            "_".join(key_list[0:2]) if len(key_list) > 1 else "_".join(key_list)
        )
        if key_unique not in unique_applications:
            unique_applications[key_unique] = {
                "name": a.get("name", ""),
                "version": a.get("version", ""),
                "vendor": a.get("vendor", ""),
            }
    final_applications = []
    for index, value in unique_applications.items():
        final_applications.append(value)

    for index in range(len(final_applications)):
        name = final_applications[index].get("name", "")
        vendor = final_applications[index].get("vendor", "")
        version = final_applications[index].get("version", "")
        software.append(
            Software(
                id=str(index),
                vendor=vendor,
                    product=name,
                    version=version,
                    serviceAddress="127.0.0.1",
                )
            )

    return software
def asset_networks(ips, mac):
    ip4s = []
    ip6s = []
    for ip in ips[:99]:
        ip_addr = ip_address(ip)
        if ip_addr.version == 4:
            ip4s.append(ip_addr)
        elif ip_addr.version == 6:
            ip6s.append(ip_addr)
        else:
            continue

    if not mac:
        return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)

    return NetworkInterface(macAddress=mac, ipv4Addresses=ip4s, ipv6Addresses=ip6s)


def build_asset(item):
    asset_id = item.get('id', None)
    if not asset_id:
        return None
    
    eid_first_seen = item.get("eidFirstSeen", None)
    computer_id = item.get("computerID", None)
    eid_last_seen = item.get("eidLastSeen", None)
    namespace = item.get("namespace", None)
    system_uuid = item.get("systemUUID", None)
    name = item.get("name", None)
    domain_name = item.get("domainName", None)
    serial_number = item.get("serialNumber", None)
    manufacturer = item.get("manufacturer", None)
    model = item.get("model", None)
    ip_address = item.get("ipAddress", None)
    mac_addresses = item.get("macAddresses", None)
    primary_user = item.get("primaryUser", None)
    last_logged_in_user = item.get("lastLoggedInUser", None)
    is_virtual = item.get("isVirtual", None)
    is_encrypted = item.get("isEncrypted", None)
    chassis_type = item.get("chassisType", None)
    os = item.get("os", None)
    services = item.get("services", None)
    installed_applications = item.get("installedApplications", None)
    deployed_software_packages = item.get("deployedSoftwarePackages", None)
    risk = item.get("risk", None)
    compliance = item.get("compliance", None)

    # create network interfaces
    ips = [ip_address]
    networks = []
    for m in mac_addresses:
        network = asset_networks(ips=ips, mac=m)
        networks.append(network)

    software = build_software(applications=installed_applications, installed_software=deployed_software_packages)
    vulnerabilities = build_vulnerabilities(vulnerabilities=compliance.get("cveFindings", []))
    return ImportAsset(
        id=asset_id,
        networkInterfaces=networks,
        os=os.get("name", None),
        osVersion=os.get('generation', ''),
        manufacturer=manufacturer,
        model=model,
        hostnames=[name],
        customAttributes=to_custom_attributes({
            "eid_first_seen": eid_first_seen,
            "eid_last_seen": eid_last_seen,
            "namespace": namespace,
            "system_uuid": system_uuid,
            "serial_number": serial_number,
            "mac_addresses": mac_addresses,
            "primary_user": primary_user,
            "last_logged_in_user": last_logged_in_user,
            "is_virtual": is_virtual,
            "is_encrypted": is_encrypted,
            "risk": risk,
            "computer_id": computer_id,
        }),
        domain=domain_name,
        # firstSeenTS=eid_first_seen, # TODO: add parsing
        deviceType=chassis_type,
        software=software[:99],
        vulnerabilities=vulnerabilities[:99],
    )


def build_assets(inventory):
    assets = []
    for item in inventory:
        asset_info = item.get("node", {})
        asset = build_asset(asset_info)
        if asset:
            assets.append(asset)

    return assets

def get_endpoints(tanium_url, tanium_token, config_kwargs):
    query = """query getEndpoints($first: Int, $after: Cursor) {
    endpoints(first: $first, after: $after) {
        edges {
        node {
            id
            eidFirstSeen
            eidLastSeen
            namespace
            computerID
            systemUUID
            name
            domainName
            serialNumber
            manufacturer
            model
            ipAddress
            macAddresses
            primaryUser {
                name
                email
            }
            lastLoggedInUser
            isVirtual
            isEncrypted
            chassisType
            os {
                name 
                platform
                generation
                language
            }
            services {
                name
                status
            }
            installedApplications {
                name
                version
            }
            deployedSoftwarePackages {
                name
                vendor
                version
            }
            risk {
                totalScore
                riskLevel
                assetCriticality
                criticalityScore
            }
            compliance {
                cveFindings {
                    absoluteFirstFoundDate
                    affectedProducts
                    cisaDateAdded
                    cisaDueDate
                    cisaNotes
                    cisaProduct
                    cisaRequiredAction
                    cisaShortDescription
                    cisaVendor
                    cisaVulnerabilityName
                    cpes
                    cveId
                    cveYear
                    cvssScore
                    excepted
                    firstFound
                    isCisaKev
                    lastFound
                    lastScanDate
                    scanType
                    severity
                    summary
                }
            }
        }
        }
        pageInfo {
        hasNextPage
        endCursor
        startCursor
        }
        totalRecords
    }
    }"""
    cursor = None
    hasNextPage = True
    reported = 0
    while hasNextPage:
        # set cursor if it exists (all but the first query)
        if cursor:
            variables = {"first": 100, "after": cursor}
        else:
            variables = {"first": 100}

        body = {"query": query, "variables": variables}

        # get endpoints
        data, err = post_json(
            tanium_url + "/plugin/products/gateway/graphql",
            json=body,
            **get_http_options(config_kwargs, headers={"session": tanium_token})
        )
        if err:
            print("Failed to fetch endpoints:", err)
            return reported

        # unpack results and add to the endpoints
        json_data = data or {}
        new_endpoints = json_data.get("data", {}).get("endpoints", {}).get("edges", [])

        # Build and stream this page before fetching the next so the full
        # endpoint set is never held in memory at once.
        reported += report_assets(build_assets(new_endpoints))

        # check if there is a next page
        hasNextPage = json_data.get("data", {}).get("endpoints", {}).get("pageInfo", {}).get("hasNextPage", False)
        cursor = json_data.get("data", {}).get("endpoints", {}).get("pageInfo", {}).get("endCursor", None)
    
    return reported

def main(*args, **kwargs):
    tanium_url = get_url_base(kwargs)
    tanium_token = kwargs['api_token']

    # Endpoints are streamed page-by-page via report_assets in get_endpoints.
    reported = get_endpoints(tanium_url, tanium_token, kwargs)

    if not reported:
        print("got nothing from Tanium")

    return None

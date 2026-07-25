# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-bitsight",
    "name": "Bitsight",
    "type": "inbound",
    "description": "Imports company assets from Bitsight.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "company_id",
            "label": "Company ID",
            "type": "string",
            "required": True,
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
load('base64', base64_encode='encode', base64_decode='decode')
load('http', 'get_json', 'basic')
load('kwargs', 'get_http_options')
load('net', 'network_interface')
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('time', 'parse_time')

#Change the URL to match your Guardicore BITSIGHT server
BITSIGHT_BASE_URL = 'https://api.bitsighttech.com'
RUNZERO_REDIRECT = 'https://console.runzero.com/'

def build_assets(assets, company_id, http_options):
    assets_import = []
    for asset in assets:
        ip_addresses = asset.get('ip_addresses', [])
        bitsight_tags = asset.get('tags') or []
        tags = [tag.strip().replace(' ', '_') for tag in bitsight_tags]
        asset_name = asset.get('asset', '')
        asset_type = asset.get('asset_type', '')
        if not asset_name:
            print("bitsight: skipping record with no asset field")
            continue
        asset_id = "bitsight:{}:{}".format(asset_type or "unknown", asset_name)
        app_grade = str(asset.get('app_grade', ''))
        country_code = str(asset.get('country_code', ''))
        country = str(asset.get('coutry', ''))
        hosted_by = asset.get('hosted_by') or {}
        hosted_by_guid = hosted_by.get('guid', '')
        hosted_by_name = hosted_by.get('name', '')
        importance = str(asset.get('importance', ''))
        importance_category = asset.get('importance_category', '')
        long = str(asset.get('longitude', ''))
        lat = str(asset.get('latitude', ''))
        origin_sub = asset.get('origin_subsidiary') or {}
        origin_sub_guid = origin_sub.get('guid', '')
        origin_sub_name = origin_sub.get('name', '')
        is_monitored = str(asset.get('is_monitored', ''))
        grace_period_end_date = str(asset.get('grace_period_end_date', ''))
        is_in_grace_period = str(asset.get('is_in_grace_period', ''))
        guest_network_end_date = str(asset.get('guest_network_end_date', ''))
        is_in_guest_network = str(asset.get('is_in_guest_network', ''))
        cloud_context = asset.get('cloud_context') or {}
        provider = cloud_context.get('provider') or {}
        slug = provider.get('slug', '')
        cloud_name = provider.get('name', '')
        region = provider.get('region', '')
        service = provider.get('service', '')
        findings = asset.get('findings') or {}
        findings_count_total = str(findings.get('total_count', 0))
        findings_count_severe = str(findings.get('counts_by_severity', {}).get('severe', 0))
        findings_count_material = str(findings.get('counts_by_severity', {}).get('material', 0))
        findings_count_moderate = str(findings.get('counts_by_severity', {}).get('moderate', 0))
        findings_count_minor = str(findings.get('counts_by_severity', {}).get('minor', 0))
        threats = asset.get('threats') or {}
        threat_ids = threats.get('rolledup_observation_ids', [])
        evidence_keys = threats.get('evidence_keys', [])

        custom_attributes = {
                             'asset': asset_name,
                             'assetType': asset_type,
                             'appGrade': app_grade,
                             'countryCode': country_code,
                             'country': country,
                             'hostedBy.guid': hosted_by_guid,
                             'hostedBy.name': hosted_by_name,
                             'importance': importance,
                             'importanceCategory': importance_category,
                             'longitude': long,
                             'latitude': lat,
                             'originSubsidiary.guid': origin_sub_guid,
                             'originSubsidiary.name': origin_sub_name,
                             'isMonitored': is_monitored,
                             'gracePeriodEndDate': grace_period_end_date,
                             'isInGracePeriod': is_in_grace_period,
                             'guestNetworkEndDate': guest_network_end_date,
                             'isInGuestNetwork': is_in_guest_network,
                             'cloudContext.slug': slug,
                             'cloudContext.name': cloud_name,
                             'cloudContext.region': region,
                             'cloudContext.service': service,
                             'findingsCount.total': findings_count_total,
                             'findingsCount.severe': findings_count_severe,
                             'findingsCount.material': findings_count_material,
                             'findingsCount.moderate': findings_count_moderate,
                             'findingsCount.minor': findings_count_minor,
                             'threats.rolledUpObservationIds': threat_ids[:1023],
                             'threats.evidenceKeys': evidence_keys[:1023]
                             }
        
        products = asset.get('products', [])
        for product in products:
            for k, v in product.items():
                custom_attributes['product' + str(products.index(product)) + k] = v

        vulns = []
        if ip_addresses:
            for address in ip_addresses:
                findings = get_findings(address, company_id, http_options)
                for finding in findings:
                    vuln = build_vuln(finding)
                    vulns.append(vuln)
        elif not ip_addresses and asset_name:
            findings = get_findings(asset_name, company_id, http_options)
            for finding in findings:
                vuln = build_vuln(finding)
                vulns.append(vuln)
        
        # create the network interfaces
        interface = network_interface(ips=ip_addresses, mac=None)

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[asset_name],
                tags=tags,
                networkInterfaces=[interface],
                customAttributes=to_custom_attributes(custom_attributes),
                vulnerabilities=vulns,
                matchBehavior="no-id-match no-id-break",
            )
        )
    return assets_import

def build_vuln(vuln):
    details = vuln.get('details') or {}
    observed_ips = details.get('observed_ips') or []
    diligence_annotations = details.get('diligence_annotations') or {}
    identifier = diligence_annotations.get('message', '')
    name = identifier
    description = diligence_annotations.get('Title', '')
    description = description[:1023] if description else ''
    service_address = observed_ips[0] if len(observed_ips) > 0 else ''
    if '[' in service_address:
        resolved_ip = service_address.split('[')[1]
        service_address = resolved_ip.split(']')[0]
    else:
        service_address = service_address.split(':')[0]
    service_port = int(details.get('dest_port', 0))
    service_transport = diligence_annotations.get('transport', '')
    first_seen = vuln.get('first_seen')
    # reformat timestamp if it is not in proper format
    if first_seen and 'T' not in first_seen: first_seen = first_seen + 'T00:00:00Z'
    first_detected_ts = parse_time(first_seen)
    cvss2_base_score = details.get('cvss', {}).get('base', [])
    cvss2_base_score = float(cvss2_base_score[0]) if cvss2_base_score else 0
    severity_score = float(vuln.get('severity') or 0)
    if severity_score >= 0.1 and severity_score <=3.9:
        risk_rank = 1
    elif severity_score >= 4.0 and severity_score <=6.9:
        risk_rank = 2
    elif severity_score >= 7.0 and severity_score <= 8.9:
        risk_rank = 3
    elif severity_score >= 9.0 and severity_score <= 10.0:
        risk_rank = 4
    else:
        risk_rank = 0
    remediation = details.get('remediation', [])
    solutions = [r.get('message', '') + ': ' + r.get('help_text', '') for r in remediation]
    solution = '\n'.join(solutions)[:1023]

    # Map custom attributes
    affects_rating = str(vuln.get('affects_rating', ''))
    evidence_key = vuln.get('evidence_key', '')
    pcap_id = vuln.get('pcap_id', '')
    remaining_decay = vuln.get('remaining_decay', '')
    remediated = vuln.get('remediated', '')
    risk_category = vuln.get('risk_category', '')
    risk_vector = vuln.get('risk_vector', '')
    risk_vector_label = vuln.get('risk_vector_label', '')
    severity_category = vuln.get('severity_category', '')
    threat_groups_list = vuln.get('threat_groups', [])
    threat_groups = '\n'.join(threat_groups_list) if threat_groups_list else ''
    threat_activity_score_label = vuln.get('threat_activity_score_label', '')

    custom_attributes = {
                    'affectsRating': affects_rating,
                    'evidenceKey': evidence_key,
                    'pcapId': pcap_id,
                    'remainingDecay': remaining_decay,
                    'remediated': remediated,
                    'riskCategory': risk_category,
                    'riskVector': risk_vector,
                    'rickVectorLabel': risk_vector_label,
                    'severityCategory': severity_category,
                    'threatGroups': threat_groups,
                    'threatActivityScoreLabel': threat_activity_score_label
                    }
    
    return Vulnerability(id=identifier,
                        name=name,
                        description=description,
                        firstDetectedTS=first_detected_ts,
                        serviceAddress=service_address,
                        servicePort=service_port,
                        serviceTransport=service_transport,
                        cvss2BaseScore=cvss2_base_score,
                        riskRank=risk_rank,
                        severityScore=severity_score,
                        solution=solution,
                        customAttributes=to_custom_attributes(custom_attributes)
                        )

def get_assets(company_id, http_options):
    assets_all = []
    total_count = 10000
    url = BITSIGHT_BASE_URL + '/ratings/v1/companies/' + company_id + '/assets?'
    params = {'is_ip': 'true'}
    # The default operation is to return only IP-based assets (i.e. filter out domains and CIDRs) comment the above params variable and uncomment the following params variable if you wish to import all asset types.
    # params = {}

    while len(assets_all) < total_count - 1:
        data, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve assets:', err)
            break
        if not data:
            break
        url = data.get('links', {}).get('next', '')
        total_count = data.get('count', 1)
        assets_all.extend(data.get('results', []))

    return assets_all

def get_findings(asset, company_id, http_options):
    vulns_all = []
    vulns_count = 10000
    url = BITSIGHT_BASE_URL + '/ratings/v1/companies/' + company_id + '/findings?'
    params = {'assets.asset': asset}

    while len(vulns_all) < vulns_count - 1:
        data, err = get_json(url, params=params, **http_options)
        if err:
            print('failed to retrieve findings:', err)
            break
        if not data:
            break
        url = data.get('links', {}).get('next', '')
        vulns_count = data.get('count', 1)
        vulns_all.extend(data.get('results', []))

    return vulns_all


def main(*args, **kwargs):
    company_id = kwargs['company_id']
    token = kwargs['api_token']
    b64_creds = base64_encode(token + ':')
    http_options = get_http_options(kwargs, headers={'Accept': 'application/json', 'Authorization': 'Basic ' + b64_creds})
    assets = get_assets(company_id, http_options)

    # Build and stream asset import via report_assets instead of returning a list
    if not report_assets(build_assets(assets, company_id, http_options)):
        print('no assets')

    return None
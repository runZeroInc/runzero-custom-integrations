# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-bitsight",
    "name": "Bitsight",
    "type": "inbound",
    "description": "Imports company assets from Bitsight.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    "params": [
        {
            "key": "url",
            "label": "Bitsight API URL",
            "type": "url",
            "required": False,
            "default": "https://api.bitsighttech.com",
            "placeholder": "https://api.bitsighttech.com",
            "description": "Bitsight's API endpoint. Override only for a regional or self-hosted deployment.",
        },
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
load('re', re_match='match')
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('time', 'parse_time')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script.
DEFAULT_BITSIGHT_URL = 'https://api.bitsighttech.com'

# parse_time ABORTS the script on a value it cannot parse rather than returning
# an error, and Starlark has no exception handling -- so a timestamp is screened
# against this before the call. Testing the result instead does not work:
# parse_time never returns, so a `!= None` check after it is dead code.
RFC3339_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"

# A hard bound on either cursor walk. Bitsight pages 100 rows at a time, so this
# is well past any real company's asset or finding count, and it means a cursor
# that never resolves cannot spin forever.
MAX_PAGES = 1001

def build_assets(assets, base_url, company_id, http_options):
    assets_import = []
    # `asset` is the record's whole identity here, so a row without one cannot
    # be imported. Counted rather than logged per record: a bad export would
    # otherwise be one line per row across the whole company.
    skipped = 0
    for asset in assets:
        ip_addresses = asset.get('ip_addresses', [])
        bitsight_tags = asset.get('tags') or []
        tags = [tag.strip().replace(' ', '_') for tag in bitsight_tags]
        asset_name = asset.get('asset', '')
        asset_type = asset.get('asset_type', '')
        if not asset_name:
            skipped += 1
            continue
        asset_id = "bitsight:{}:{}".format(asset_type or "unknown", asset_name)
        app_grade = str(asset.get('app_grade', ''))
        country_code = str(asset.get('country_code', ''))
        country = str(asset.get('country') or '')
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
                findings = get_findings(address, base_url, company_id, http_options)
                for finding in findings:
                    vuln = build_vuln(finding)
                    vulns.append(vuln)
        elif not ip_addresses and asset_name:
            findings = get_findings(asset_name, base_url, company_id, http_options)
            for finding in findings:
                vuln = build_vuln(finding)
                vulns.append(vuln)
        
        # create the network interfaces
        # network_interface returns None when no address survives -- a domain or
        # CIDR asset has none, and Bitsight returns those whenever the is_ip
        # filter is relaxed. Passing [None] to ImportAsset aborts the entire
        # run, so such an asset gets no interface and correlates on its name.
        interface = network_interface(ips=ip_addresses, mac=None)
        interfaces = [interface] if interface else []

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[asset_name],
                tags=tags,
                networkInterfaces=interfaces,
                customAttributes=to_custom_attributes(custom_attributes),
                vulnerabilities=vulns,
            )
        )
    if skipped > 0:
        print("bitsight: skipped {} records with no asset field".format(skipped))
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
    # Bitsight reports first_seen as a bare date, so it is padded out to RFC 3339
    # before parsing. The value is then screened rather than parsed on trust:
    # parse_time aborts the script on anything it cannot handle, so a finding
    # with no first_seen -- or one carrying a shape Bitsight has never
    # documented -- used to take the whole import down along with every finding
    # and asset already built.
    first_seen = vuln.get('first_seen')
    if type(first_seen) == "string" and 'T' not in first_seen:
        first_seen = first_seen + 'T00:00:00Z'
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
    
    vuln_args = {
                'id': identifier,
                'name': name,
                'description': description,
                'serviceAddress': service_address,
                'servicePort': service_port,
                'serviceTransport': service_transport,
                'cvss2BaseScore': cvss2_base_score,
                'riskRank': risk_rank,
                'severityScore': severity_score,
                'solution': solution,
                'customAttributes': to_custom_attributes(custom_attributes)
                }

    # Omitted rather than set from an unscreened value, so a finding with an
    # unusable first_seen still becomes a vulnerability instead of ending the run.
    if type(first_seen) == "string" and re_match(RFC3339_RE, first_seen):
        vuln_args['firstDetectedTS'] = parse_time(first_seen)

    return Vulnerability(**vuln_args)

def get_page(url, http_options, params):
    """Fetch one page, omitting `params` entirely when there is nothing to send.

    Bitsight's links.next is an absolute URL that already carries its own limit
    and offset. The HTTP helper REPLACES a URL's query string with `params`
    rather than merging into it, so re-sending the filter on the cursor discarded
    the offset and re-fetched page one on every iteration -- every asset and
    every finding arriving as many times as there were pages. The cursor is
    followed verbatim instead; the filter it already encodes is preserved.
    """
    options = dict(http_options)
    if params:
        options['params'] = params
    return get_json(url, **options)

def get_assets(base_url, company_id, http_options):
    assets_all = []
    total_count = None
    url = base_url + '/ratings/v1/companies/' + company_id + '/assets'
    params = {'is_ip': 'true'}
    # The default operation is to return only IP-based assets (i.e. filter out domains and CIDRs) comment the above params variable and uncomment the following params variable if you wish to import all asset types.
    # params = {}

    for _page in range(1, MAX_PAGES):
        data, err = get_page(url, http_options, params)
        if err:
            print('bitsight: failed to retrieve assets: {}'.format(err))
            break
        if not data:
            break
        assets_all.extend(data.get('results', []))

        # `count` is a backstop rather than the loop driver. The walk used to be
        # bounded by len(assets_all) < count - 1, which stops one row short of
        # the reported total and so drops the last page; an absent count made it
        # one instead, ending the walk after a single page.
        count = data.get('count')
        if type(count) == "int":
            total_count = count

        url = str((data.get('links') or {}).get('next', '') or '')
        if not url:
            break
        params = {}
        if total_count != None and len(assets_all) >= total_count:
            break

    return assets_all

def get_findings(asset, base_url, company_id, http_options):
    vulns_all = []
    total_count = None
    url = base_url + '/ratings/v1/companies/' + company_id + '/findings'
    params = {'assets.asset': asset}

    for _page in range(1, MAX_PAGES):
        data, err = get_page(url, http_options, params)
        if err:
            print('bitsight: failed to retrieve findings: {}'.format(err))
            break
        if not data:
            break
        vulns_all.extend(data.get('results', []))

        count = data.get('count')
        if type(count) == "int":
            total_count = count

        url = str((data.get('links') or {}).get('next', '') or '')
        if not url:
            break
        params = {}
        if total_count != None and len(vulns_all) >= total_count:
            break

    return vulns_all


def main(*args, **kwargs):
    company_id = kwargs['company_id']
    token = kwargs['api_token']
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_BITSIGHT_URL).rstrip('/')
    b64_creds = base64_encode(token + ':')
    http_options = get_http_options(kwargs, headers={'Accept': 'application/json', 'Authorization': 'Basic ' + b64_creds})
    assets = get_assets(base_url, company_id, http_options)

    # Build and stream asset import via report_assets instead of returning a list
    reported = report_assets(build_assets(assets, base_url, company_id, http_options))
    print('bitsight: reported {} assets'.format(reported))

    return None
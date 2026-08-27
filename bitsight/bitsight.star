# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-bitsight",
    "name": "Bitsight",
    "type": "inbound",
    "description": "Imports company assets from Bitsight.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "matchBehavior": "no-id-match no-id-break",
    # A hard bound on either cursor walk. Bitsight pages 100 rows at a time, so
    # this is well past any real company's asset or finding count, and it means
    # a cursor that never resolves raises a clear error instead of spinning
    # until the task deadline.
    "maxPages": 1000,
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
        {
            "key": "findings_limit",
            "label": "Findings enrichment limit",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Maximum number of assets to enrich with findings. Each asset costs one paginated findings walk per IP address, so a large portfolio can spend the whole API rate budget here. Assets past the limit are imported without vulnerabilities and the skip is logged. 0 enriches every asset.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('base64', base64_encode='encode')
load('coerce', 'as_dict', 'as_float', 'as_int', 'as_list', 'dicts', text='as_text')
load('http', 'get_json')
load('kwargs', 'get_http_options', 'get_int')
load('net', 'network_interface')
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')
load('time', 'parse_ts')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script.
DEFAULT_BITSIGHT_URL = 'https://api.bitsighttech.com'

def build_asset(asset, base_url, company_id, http_options, ctx):
    """Convert one Bitsight asset row into an ImportAsset, enriched with the
    findings behind each of its addresses. Returns None when the row carries no
    asset name, which is the record's whole identity here."""
    ip_addresses = [text(ip) for ip in as_list(asset.get('ip_addresses')) if text(ip)]
    tags = [text(tag).strip().replace(' ', '_') for tag in as_list(asset.get('tags')) if text(tag).strip()]
    asset_name = text(asset.get('asset'))
    asset_type = text(asset.get('asset_type'))
    if not asset_name:
        return None
    # Scoped by the company GUID so two portfolio companies imported into one
    # runZero organization cannot collide on a shared address. asset_type is
    # deliberately NOT part of the id: Bitsight reclassifying a record would
    # re-identify the asset. It stays available as the assetType attribute.
    asset_id = "bitsight:{}:{}".format(company_id, asset_name)
    app_grade = str(asset.get('app_grade', ''))
    country_code = str(asset.get('country_code', ''))
    country = str(asset.get('country') or '')
    hosted_by = as_dict(asset.get('hosted_by'))
    hosted_by_guid = hosted_by.get('guid', '')
    hosted_by_name = hosted_by.get('name', '')
    importance = str(asset.get('importance', ''))
    importance_category = asset.get('importance_category', '')
    long = str(asset.get('longitude', ''))
    lat = str(asset.get('latitude', ''))
    origin_sub = as_dict(asset.get('origin_subsidiary'))
    origin_sub_guid = origin_sub.get('guid', '')
    origin_sub_name = origin_sub.get('name', '')
    is_monitored = str(asset.get('is_monitored', ''))
    grace_period_end_date = str(asset.get('grace_period_end_date', ''))
    is_in_grace_period = str(asset.get('is_in_grace_period', ''))
    guest_network_end_date = str(asset.get('guest_network_end_date', ''))
    is_in_guest_network = str(asset.get('is_in_guest_network', ''))
    cloud_context = as_dict(asset.get('cloud_context'))
    provider = as_dict(cloud_context.get('provider'))
    slug = provider.get('slug', '')
    cloud_name = provider.get('name', '')
    region = provider.get('region', '')
    service = provider.get('service', '')
    findings = as_dict(asset.get('findings'))
    findings_counts = as_dict(findings.get('counts_by_severity'))
    findings_count_total = str(findings.get('total_count', 0))
    findings_count_severe = str(findings_counts.get('severe', 0))
    findings_count_material = str(findings_counts.get('material', 0))
    findings_count_moderate = str(findings_counts.get('moderate', 0))
    findings_count_minor = str(findings_counts.get('minor', 0))
    threats = as_dict(asset.get('threats'))
    threat_ids = as_list(threats.get('rolledup_observation_ids'))
    evidence_keys = as_list(threats.get('evidence_keys'))

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

    for index, product in enumerate(dicts(asset.get('products'))):
        for k, v in product.items():
            custom_attributes['product' + str(index) + k] = v

    # One paginated findings walk per address is the expensive half of this
    # integration, so it is bounded by the findings_limit parameter: an asset
    # past the cap still imports, without vulnerabilities.
    vulns = []
    if ctx["findings_limit"] and ctx["findings_used"] >= ctx["findings_limit"]:
        ctx["findings_capped"] += 1
    else:
        ctx["findings_used"] += 1
        lookups = ip_addresses if ip_addresses else [asset_name]
        for address in lookups:
            for finding in dicts(get_findings(address, base_url, company_id, http_options)):
                vulns.append(build_vuln(finding))

    # create the network interfaces
    # network_interface returns None when no address survives -- a domain or
    # CIDR asset has none, and Bitsight returns those whenever the is_ip
    # filter is relaxed. Passing [None] to ImportAsset aborts the entire
    # run, so such an asset gets no interface and correlates on its name.
    interface = network_interface(ips=ip_addresses, mac=None)
    interfaces = [interface] if interface else []

    return ImportAsset(
        id=asset_id,
        hostnames=[asset_name],
        tags=tags,
        networkInterfaces=interfaces,
        customAttributes=to_custom_attributes(custom_attributes),
        vulnerabilities=vulns,
    )

def build_vuln(vuln):
    details = as_dict(vuln.get('details'))
    observed_ips = [text(ip) for ip in as_list(details.get('observed_ips')) if text(ip)]
    diligence_annotations = as_dict(details.get('diligence_annotations'))
    identifier = text(diligence_annotations.get('message'))
    name = identifier
    description = text(diligence_annotations.get('Title'))[:1023]
    service_address = observed_ips[0] if len(observed_ips) > 0 else ''
    if '[' in service_address:
        resolved_ip = service_address.split('[')[1]
        service_address = resolved_ip.split(']')[0]
    else:
        service_address = service_address.split(':')[0]
    # dest_port arrives null on findings without a socket -- a diligence
    # finding on a domain, for example -- and int(None) aborts the script, so
    # the value is coerced instead.
    service_port = as_int(details.get('dest_port'), default=0)
    service_transport = text(diligence_annotations.get('transport'))
    # Bitsight reports first_seen as a bare date, so a date-only value is
    # padded to RFC 3339 when the direct parse declines it. parse_ts returns
    # None on anything it cannot handle instead of aborting the script, and
    # clamps future values so a fast clock cannot drop the record.
    first_seen = vuln.get('first_seen')
    first_detected = parse_ts(first_seen)
    if first_detected == None and type(first_seen) == "string" and 'T' not in first_seen:
        first_detected = parse_ts(first_seen + 'T00:00:00Z')
    # cvss arrives as an object holding a list, but a finding without a score
    # carries an explicit null, and the base value has been observed as a bare
    # number too, so every layer is coerced.
    cvss_values = as_list(as_dict(details.get('cvss')).get('base'))
    cvss2_base_score = as_float(cvss_values[0]) if cvss_values else 0
    severity_score = as_float(vuln.get('severity'))
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
    # remediation rows and their message fields arrive null often enough that
    # each layer is coerced; a null message used to abort the run in the string
    # concatenation here.
    solutions = [text(r.get('message')) + ': ' + text(r.get('help_text')) for r in dicts(details.get('remediation'))]
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
    # A threat group has been observed as a bare string and as an object; text()
    # keeps the strings and drops the rest rather than aborting the join.
    threat_groups_list = [text(t) for t in as_list(vuln.get('threat_groups')) if text(t)]
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

    # Omitted rather than set from an unusable value, so a finding with no
    # parseable first_seen still becomes a vulnerability.
    if first_detected != None:
        vuln_args['firstDetectedTS'] = first_detected

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

def import_assets(base_url, company_id, http_options, ctx):
    """Walk the company's assets, building and reporting each one as it is
    parsed so nothing is buffered for the length of the run -- an abort or an
    error partway keeps everything already reported. Returns the count."""
    reported = 0
    skipped = 0
    rows_seen = 0
    total_count = None
    url = base_url + '/ratings/v1/companies/' + company_id + '/assets'
    params = {'is_ip': 'true'}
    # The default operation is to return only IP-based assets (i.e. filter out domains and CIDRs) comment the above params variable and uncomment the following params variable if you wish to import all asset types.
    # params = {}

    p = pager("assets")
    while p.next():
        data, err = get_page(url, http_options, params)
        if err:
            fail('bitsight: failed to retrieve assets after reporting {}: {}'.format(reported, err))
        if not data:
            break
        rows = as_list(data.get('results'), wrap=False)
        rows_seen += len(rows)
        for row in dicts(rows):
            # `asset` is the record's whole identity here, so a row without one
            # cannot be imported. Counted rather than logged per record: a bad
            # export would otherwise be one line per row across the company.
            asset = build_asset(row, base_url, company_id, http_options, ctx)
            if asset == None:
                skipped += 1
                continue
            reported += report_asset(asset)

        # `count` is a backstop rather than the loop driver. The walk used to be
        # bounded by len(assets) < count - 1, which stops one row short of the
        # reported total and so drops the last page; an absent count made it
        # one instead, ending the walk after a single page.
        count = data.get('count')
        if type(count) == "int":
            total_count = count

        url = str((data.get('links') or {}).get('next', '') or '')
        if not url:
            break
        params = {}
        if total_count != None and rows_seen >= total_count:
            break

    if skipped > 0:
        print("bitsight: skipped {} records with no asset field".format(skipped))
    if ctx["findings_capped"] > 0:
        print("bitsight: findings limit of {} reached; {} assets were imported without findings".format(
            ctx["findings_limit"], ctx["findings_capped"]))
    return reported

def get_findings(asset, base_url, company_id, http_options):
    vulns_all = []
    total_count = None
    url = base_url + '/ratings/v1/companies/' + company_id + '/findings'
    params = {'assets.asset': asset}

    p = pager("findings")
    while p.next():
        data, err = get_page(url, http_options, params)
        if err:
            print('bitsight: failed to retrieve findings: {}'.format(err))
            break
        if not data:
            break
        vulns_all.extend(as_list(data.get('results'), wrap=False))

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

    ctx = {
        "findings_limit": get_int(kwargs, "findings_limit", default=0),
        "findings_used": 0,
        "findings_capped": 0,
    }

    # Assets are streamed one at a time via report_asset inside import_assets.
    reported = import_assets(base_url, company_id, http_options, ctx)
    print('bitsight: reported {} assets'.format(reported))

    return None

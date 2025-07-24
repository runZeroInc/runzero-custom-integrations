load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Software', 'Vulnerability')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', 'url_encode')
load('uuid', 'new_uuid')

# Sets the Burp Suite GraphQL API endpoint
BURP_API_URL = 'https://<your-burp-console>:8443/graphql/v1'

# Sets the number of scans to check for issues. Using '1' will only pull the most recent scan.
SCAN_LIMIT = 1

# Sets the timeout for HTTP requests
HTTP_TIMEOUT = 300

# Sets the page size when pulling issue serial numbers
ISSUE_PAGE_SIZE = 1000

# GraphQL query to pull the site tree from Burp
QUERY_SITE_TREE = """
query GetSiteTree {
  site_tree {
    sites {
      id
      name
      parent_id
      ephemeral
      scope_v2 {
        start_urls
        out_of_scope_url_prefixes
      }
    }
  }
}
"""
# GraphQL query to pull scan IDs for for a given site
QUERY_SCANS = """
query GetScans($siteId: ID!, $limit: Int!) {
  scans(site_id: $siteId, limit: $limit) {
    id
  }
}
"""

# GraphQL query to pull issue serial numbers for given scan ID
QUERY_SCAN_ISSUES = """
query GetScan($scanId: ID!, $start: Int!, $count: Int!) {
  scan(id: $scanId) {
    issues(start:$start, count:$count) {
      serial_number
      severity
    }
  }
}
"""

# GraphQL query to pull issue details for a given scan ID and issue serial number
QUERY_ISSUE = """
query getIssue($scanId: ID!, $serialNumber: ID!) {
  issue(scan_id: $scanId, serial_number: $serialNumber) {
    issue_type {
      type_index
      name
      description_html
      remediation_html
      vulnerability_classifications_html
      references_html
    }
    display_confidence
    serial_number
    remediation_html
    description_html
    confidence
    severity
    path
    origin
    evidence {
      ... on Request {
        request_index
        request_count
        request_segments {
          ... on DataSegment {
            data_html
          }
          ... on HighlightSegment {
            highlight_html
          }
          ... on SnipSegment {
            snip_length
          }
        }
      }
      ... on Response {
        response_index
        response_count
        response_segments {
          ... on DataSegment {
            data_html
          }
          ... on HighlightSegment {
            highlight_html
          }
        }
      }
    }
  }
}
"""

# Sets Burp risk ratings to numeric values that runZero can interpret
RISK_RANK_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}
RISK_SCORE_MAP = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
}

# Fetches the site tree from Burp
def get_sites(token):
    print('fetching site tree from ' + BURP_API_URL)
    headers = {'Content-Type':'application/json','Authorization': token}
    body = {'query': QUERY_SITE_TREE}
    resp = http_post(BURP_API_URL, headers=headers, body=bytes(json_encode(body)), timeout=300)
    
    if resp.status_code != 200:
        print('failed to fetch site tree ' + '(' + resp.status_code + ')')

    resp_json = json_decode(resp.body)
    
    resp_err = resp_json.get('errors', [])
    if resp_err:
        for m in resp_err:
            print('error: ', m.get('message', ''))
        return None
    
    return resp_json.get('data').get('site_tree', {}).get('sites', [])
        
# Fetches scan IDs for a given site
def get_scans(token, site_id, site_name):
    print('fetching scan data for ' + site_name + ' (' + 'site_id: ' + site_id + ')')
    headers = {'Content-Type':'application/json','Authorization': token}
    body = {'query': QUERY_SCANS, 'variables':{'siteId': site_id, 'limit': SCAN_LIMIT}}
    
    resp = http_post(BURP_API_URL, headers=headers, body=bytes(json_encode(body)), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        print('failed to fetch scan data for ' + site_name + ' (' + resp.status_code + ')')

    resp_json = json_decode(resp.body)    

    resp_err = resp_json.get('errors', [])
    if resp_err:
        for m in resp_err:
            print('error fetching scan data for ' + site_name + ' (' + m.get('message', '') + ')')
        return None
    
    return resp_json.get('data').get('scans', [])

# Fetches the serial numbers of each issue from a given scan ID
def get_issue_serial_numbers(token, scan_id, start=0, count=1000):
    headers = {'Content-Type':'application/json','Authorization': token}
    body = {'query': QUERY_SCAN_ISSUES, 'variables':{'scanId': scan_id, 'start': start, 'count': count}}
    resp = http_post(BURP_API_URL, headers=headers, body=bytes(json_encode(body)), timeout=HTTP_TIMEOUT)

    if resp.status_code != 200:
        print('failed to fetch serial numbers for scan ID ' + scan_id + ' (' + resp.status_code + ')')
        
    resp_json = json_decode(resp.body)

    resp_err = resp_json.get('errors', [])
    if resp_err:
        for m in resp_err:
            print('error fetching serial numbers for scan ID ' + scan_id + ' (' + m.get('message', '') + ')')
        return None

    return resp_json.get('data', {}).get('scan', {}).get('issues', [])

def get_issue(token, scan_id, serial_number):
    headers = {'Content-Type':'application/json','Authorization': token}
    body = {'query': QUERY_ISSUE, 'variables':{'scanId': scan_id, 'serialNumber': serial_number}}
    resp = http_post(BURP_API_URL, headers=headers, body=bytes(json_encode(body)), timeout=HTTP_TIMEOUT)
    
    if resp.status_code != 200:
        print('failed to fetch issue details for serial number ' + serial_number + ' (' + resp.status_code + ')')

    resp_json = json_decode(resp.body)  

    resp_err = resp_json.get('errors', [])
    if resp_err:
        for m in resp_err:
            print('error fetching issue details for serial number ' + serial_number + ' (' + m.get('message', '') + ')')
        return None
    
    return resp_json.get('data', {}).get('issue', {})

# Builds asset records for importing into runZero
def build_assets(sites, token):
    assets = []
    network = build_network_interface()
    for s in sites:
        scans = []
        scan_ids = []
        issue_serial_numbers = []
        issues = []
        
        site_id = s.get('id', '')
        site_name = s.get('name', '')
        parent_id = s.get('parent_id', '')
        ephemeral = s.get('ephemeral', '')
        
        scans = get_scans(token, site_id, site_name)
        if scans:
            for sid in scans:
                scan_id = sid.get('id', '')
                scan_ids.append(sid.get('id'))
                issue_serial_numbers = get_issue_serial_numbers(token, scan_id)
                if issue_serial_numbers:
                    for i in issue_serial_numbers:
                        serial_number = i.get('serial_number', '')
                        issue_details = get_issue(token, scan_id, serial_number)
                        if issue_details:
                            issues.append(issue_details)

        if issues:
            vulnerabilities = build_vulnerabilities(site_id, site_name, issues)
        else:
            vulnerabilities = None

        # Create string of scan IDs
        scan_ids_string = ', '.join(scan_ids)

        # Create string of serial numbers
        serial_numbers = [item['serial_number'] for item in issue_serial_numbers]
        serial_numbers_string = ", ".join(serial_numbers)     

        assets.append(
            ImportAsset(
                id=site_id,
                hostnames=[site_name],
                networkInterfaces=[network],
                vulnerabilities=vulnerabilities,
                customAttributes={
                    'ephemeral': ephemeral,
                    'lastSeenScanIds': scan_ids_string,
                    'lastSeenIssueSerialNumbers': serial_numbers_string,
                    'siteId': site_id,
                    'siteName': site_name,
                    'parentId': parent_id

                }
            )
    )
    return assets

# Build runZero network interface placeholder. Burp does not collect IP address or mac address.
def build_network_interface():
    return NetworkInterface(ipv4Addresses=[ip_address('127.0.0.1')])

# Build vulnerability records to include in asset import
def build_vulnerabilities(site_id, site_name, issues):
    print('fetching vulnerability details for ' + site_name + ' (' + 'site_id: ' + site_id + ')')
    vulns = []
    vulnerability_count = 0
    for i in issues:
        confidence = i.get('confidence', '')
        description = clean_html_tags(i.get('issue_type', {}).get('description_html', ''))
        name = i.get('issue_type', {}).get('name', '')
        origin = i.get('origin', '')
        remediation = clean_html_tags(i.get('issue_type', {}).get('remediation_html', ''))
        serial_number = i.get('serial_number', '')
        type_index = i.get('issue_type', {}).get('type_index', '')
                
        severity = i.get('severity', '').lower()
        if severity in RISK_RANK_MAP:
            risk_rank = RISK_RANK_MAP[severity]
            score = RISK_SCORE_MAP[severity]
        else:
            risk_rank = 0
            score = 0                

        evidence = i.get('evidence', [])
        if evidence:
            for item in evidence:
                if 'request_segments' in item:
                    request_count = item['request_count']
                    request_segments = []
                    for segment in item['request_segments']:
                        if 'data_html' in segment:
                            request_segments.append(segment['data_html'])
                        elif 'highlight_html' in segment:
                            request_segments.append(segment['highlight_html'])
                        else:
                            continue
                elif 'response_segments' in item:
                    response_count = item['response_count']
                    response_segments = ''
                    for segment in item['response_segments']:
                        if 'data_html' in segment:
                            response_segments += segment['data_html']
                            response_segments += '\n\n'
                        elif 'highlight_html' in segment:
                            response_segments += segment['highlight_html']
                            response_segments += '\n\n'
                        else:
                            continue
        else:
            print('no evidence available for issue serial number ' + serial_number)
            evidence_request_count = ''
            evidence_request_segments = ''
            evidence_request_is_trunc = ''
            evidence_response_count = ''
            evidence_response_segments = ''
            evidence_response_is_trunc = ''

        vulns.append(
            Vulnerability(
                id=str(new_uuid()),
                name=name,
                description=str(description),
                solution=str(remediation),
                riskScore=float(score),
                riskRank=risk_rank,
                severityScore=float(score),
                severityRank=risk_rank,  
                serviceAddress="127.0.0.1",
                customAttributes={
                    'confidence': confidence,
                    'evidenceRequestCount': request_count,
                    'evidenceRequestSegments': request_segments,
                    'evidenceResponseCount': response_count,
                    'evidenceResponseSegments': response_segments,
                    'origin': origin,   
                    'serial_number': serial_number,
                    'type_index': type_index
                }                  
            )
        )
        vulnerability_count += 1
    
    print('fetched ' + str(vulnerability_count) + ' vulnerabilities for site ' + site_name)
    return vulns

# Replace HTML tags added by Burp
# Note: runZero uses markdown to format vulnerability description and solution attributes.
def clean_html_tags(content):

    if not content:
        return content

    # Replace paragraph tags
    content = content.replace('<p>', '')
    content = content.replace('</p>', '\n\n')

    # Replace list tags
    content = content.replace('<ul>',  '')
    content = content.replace('</ul>', '')
    content = content.replace('<li>', '\n- ')

    # Replace bold tags with a backtick. Text between backticks will appear in a code block.
    content = content.replace('<b>', '`')
    content = content.replace('</b>', '`')
    
    return content

def main(**kwargs):
    # kwargs!!
    token = kwargs['access_secret']

    # get site tree
    sites = get_sites(token)
    if not sites:
        print('no sites were retrieved')
        return None
    
    # build asset import
    imported_assets = build_assets(sites, token)

    return imported_assets
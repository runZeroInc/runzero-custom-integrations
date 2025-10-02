load('requests', 'Session', 'Cookie')
load('json', json_encode='encode', json_decode='decode')
load('runzero.types', 'ImportAsset', 'Vulnerability')
load('uuid', 'new_uuid')

DOMAIN = "UPDATE_ME"
INSECURE_ALLOWED = True

def main(*args, **kwargs):
    """
    Cyberint integration script for runZero.
    Fetches assets from Cyberint API and imports them as runZero assets.
    """

    # Cyberint credentials
    access_token = kwargs.get('access_secret')  # used as cookie auth

    # Cyberint API endpoint (tenant-specific, includes asset-configuration)
    url = "https://{}.cyberint.io/alert/api/v1/alerts".format(DOMAIN)

    # Setup session with cookie authentication
    session = Session(insecure_skip_verify=INSECURE_ALLOWED)
    session.headers.set('Accept', 'application/json')
    session.cookies.set(url, {"access_token": access_token})
    
    related_assets = {}
    assets = []

    response = session.post(url, body=bytes(json_encode({})), timeout=300)

    if response and response.status_code == 200:
        data = json_decode(response.body)
        total_assets = data.get("total_assets", 0)
        for item in data.get("alerts", []):
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            risk_rank = severity_map.get(item.get("severity", "low").lower(), 0)
            vuln = Vulnerability(
                    id=new_uuid(),
                    name=item.get("title", "No title available"),
                    description=item.get("description", "No description available"),
                    solution=item.get("recommendation", "No recommendation available"),
                    severityRank=risk_rank, 
                    riskRank=risk_rank,
                )

            related_assets_alert = item.get("related_assets")
            for a in related_assets_alert:
                asset_type = a.get("type")
                if asset_type == "domain":
                    domain = a.get("name")
                    
                    if domain not in related_assets:
                        related_assets[domain] = [vuln]
                    related_assets[domain].append(vuln)

    for domain, vulns in related_assets.items():
        assets.append(ImportAsset(
            id=domain.replace(".", "-"),
            hostnames=[domain],
            vulnerabilities=vulns
    ))

    return assets

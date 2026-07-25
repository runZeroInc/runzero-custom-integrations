# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-cyberint",
    "name": "Cyberint",
    "type": "inbound",
    "description": "Imports assets from Cyberint.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "Cyberint base URL",
            "type": "url",
            "required": True,
            "placeholder": "https://<tenant>.cyberint.io",
        },
        {
            "key": "access_token",
            "label": "Access token (cookie)",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('requests', 'Session', 'Cookie')
load('json', json_encode='encode', json_decode='decode')
load('runzero.types', 'ImportAsset', 'Vulnerability')
load('kwargs', 'get_url_base', 'get_bool')

INSECURE_ALLOWED = False

def main(*args, **kwargs):
    """
    Cyberint integration script for runZero.
    Fetches assets from Cyberint API and imports them as runZero assets.
    """

    # Cyberint credentials
    access_token = kwargs.get('access_token')  # used as cookie auth

    base_url = get_url_base(kwargs)
    # Cyberint API endpoint (tenant-specific, includes asset-configuration)
    url = base_url + "/alert/api/v1/alerts"

    # Setup session with cookie authentication
    insecure_allowed = get_bool(kwargs, 'tls_disable_validation', INSECURE_ALLOWED)
    session = Session(insecure_skip_verify=insecure_allowed)
    session.headers.set('Accept', 'application/json')
    if kwargs.get('http_user_agent'):
        session.headers.set('User-Agent', kwargs.get('http_user_agent'))
    session.cookies.set(url, {"access_token": access_token})
    
    related_assets = {}
    assets = []

    response = session.post(url, json={}, timeout=300)

    if response and response.status_code == 200:
        data = json_decode(response.body)
        total_assets = data.get("total_assets", 0)
        for item in data.get("alerts", []):
            alert_id = item.get("id")
            if not alert_id:
                print("cyberint: skipping alert with no id")
                continue
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            risk_rank = severity_map.get(item.get("severity", "low").lower(), 0)
            vuln = Vulnerability(
                    id=str(alert_id),
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
            vulnerabilities=vulns,
    ))

    # Stream assets to runZero via report_assets instead of returning a list.
    reported = report_assets(assets)
    if not reported:
        print("no assets")

    return None

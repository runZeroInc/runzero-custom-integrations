# Ghost Findings → runZero Integration
#
# - Fetches findings from Ghost Security API
# - Maps "repository" → list of IPs/hostnames using a hard-coded dictionary
# - Builds proper NetworkInterface objects (IPv4/IPv6 separation)
# - Creates runZero ImportAsset objects with richly detailed vulnerabilities attached

load('http', http_get='get')
load('json', json_decode='decode')
load('net', 'ip_address')
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')

def get_repo_name_from_url(repo_url):
    """Extracts the repository name from a URL using Starlark's string manipulation."""
    if not repo_url:
        return None

    # Remove query strings or fragments
    clean_url = repo_url
    query_index = clean_url.find('?')
    if query_index != -1:
        clean_url = clean_url[:query_index]

    # Remove trailing slashes to ensure the split works correctly
    if clean_url.endswith('/'):
        clean_url = clean_url[:-1]

    # Split the URL by '/' and return the last part
    parts = clean_url.split('/')
    if parts:
        return parts[-1]
    
    return None

def build_network_interface(ips, mac=None):
    """Convert IPs and MAC addresses into a NetworkInterface object"""
    ip4s = []
    ip6s = []

    for ip in ips[:99]:  # enforce 99-address cap
        if ip:
            ip_addr = ip_address(ip)
            if ip_addr:
                if ip_addr.version == 4:
                    ip4s.append(ip_addr)
                elif ip_addr.version == 6:
                    ip6s.append(ip_addr)
            else:
                 print("Skipping invalid IP address '{}'".format(ip))
        else:
            continue

    return NetworkInterface(
        macAddress=mac,
        ipv4Addresses=ip4s,
        ipv6Addresses=ip6s
    )

def main(*args, **kwargs):
    """
    Entrypoint for the Ghost → runZero integration.
    Requires:
      - access_key = Ghost API token
    """

    api_token = kwargs.get('access_secret')
    if not api_token:
        print("Ghost API access_secret is required.")
        return []

    # 🔒 Hard-coded repository → host mapping
    repo_map = {
        "my-repo": {
            "ips": ["10.0.0.5", "10.0.0.6"],
            "hostnames": ["db01.local", "db02.local"]
        },
        "api-repo": {
            "ips": ["192.168.1.20"],
            "hostnames": ["api.example.com", "api.internal"]
        },
        "frontend-repo": {
            "ips": ["192.168.1.25"],
            "hostnames": ["frontend.local"]
        },
        "juice-shop": {
            "ips": ["10.10.10.50"],
            "hostnames": ["juice-shop.corp.local", "juice-shop"]
        }
    }

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    base_url = "https://api.ghostsecurity.ai/v1/findings"
    headers = {
        "Authorization": "Bearer {}".format(api_token),
        "Accept": "application/json"
    }

    response = http_get(base_url, headers=headers)
    if not response or response.status_code != 200:
        print("Failed to fetch Ghost findings, status={}. Body: {}".format(
            response.status_code if response else 'N/A', 
            response.body if response else 'N/A'
        ))
        return []

    data = json_decode(response.body)
    findings = data.get("items", [])
    if not findings:
        print("No findings returned from the Ghost API.")
        return []

    asset_map = {}

    for f in findings:
        print(f.get("severity"))
        repo_name = get_repo_name_from_url(f.get("repo_url")) or "unknown"
        
        mapping = repo_map.get(repo_name)
        if not mapping:
            continue

        ips = mapping.get("ips", [])
        hostnames = mapping.get("hostnames", [])

        asset_key = repo_name

        if asset_key not in asset_map:
            asset = ImportAsset(
                id=asset_key,
                hostnames=hostnames,
                networkInterfaces=[
                    build_network_interface(ips)
                ]
            )
            asset.vulnerabilities = []
            asset_map[asset_key] = asset
        
        vuln = Vulnerability(
            id=f.get("id"),
            name=f.get("name", "Ghost Finding"),
            description=f.get("description", "No description available"),
            solution=f.get("remediation"),
            severityRank=severity_map.get(f.get("severity", "medium"), 2),
            riskRank=severity_map.get(f.get("severity", "medium"), 2),
            custom_attributes={
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", "medium"),
                "created_at": f.get("created_at"),
                "remediation_effort": f.get("remediation_effort", "medium"),
                "attack_feasibility": f.get("attack_feasibility", "medium"),
                "attack_walkthrough": f.get("attack_walkthrough", "No walkthrough available")
            }
        )
        asset_map[asset_key].vulnerabilities.append(vuln)

    return list(asset_map.values())
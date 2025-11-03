# Ghost Findings → runZero Integration
#
# Fetches repositories and findings from Ghost Security API.
# Each repository's project deployments (URLs) are mapped to runZero assets.
# Finds matching vulnerabilities based on repo_id from findings.
#
# Updated: 2025-10-24

load('http', http_get='get')
load('json', json_decode='decode')
load('net', 'ip_address')
load('runzero.types', 'ImportAsset', 'NetworkInterface', 'Vulnerability')

def get_all_repositories(api_token):
    """
    Fetch all repositories from Ghost API with pagination.
    Extracts deployment hostnames from each repo's projects.deployments field.
    """
    headers = {"Authorization": "Bearer {}".format(api_token), "Accept": "application/json"}
    base_url = "https://api.ghostsecurity.ai/v1/repos"
    repos = []
    page = 1
    has_more = True

    print("Starting get_all_repositories()")

    while has_more:
        url = "{}?page={}".format(base_url, page)
        print("Requesting repos page {}".format(page))
        response = http_get(url, headers=headers)
        if not response or response.status_code != 200:
            print("Failed to get repo list at page {}: {}".format(page, response.status_code))
            return repos

        data = json_decode(response.body)
        items = data.get("items", [])
        has_more = data.get("has_more", False)
        print("Page {} contains {} repos (has_more={})".format(page, len(items), has_more))

        for repo in items:
            repo_id = repo.get("id")
            repo_name = repo.get("name", "unknown")
            projects = repo.get("projects", [])
            hostnames = []

            for proj in projects:
                deployments = proj.get("deployments", {})
                for env in deployments:
                    env_urls = deployments.get(env, [])
                    for url in env_urls:
                        if "://" in url:
                            host = url.split("://")[1].split("/")[0]
                        else:
                            host = url
                        if host and host not in hostnames:
                            hostnames.append(host)

            repos.append({
                "id": repo_id,
                "name": repo_name,
                "hostnames": hostnames
            })
            print("Repo '{}' [{}] hostnames: {}".format(repo_name, repo_id, hostnames))

        page = page + 1

    print("Completed fetching repos. Total: {}".format(len(repos)))
    return repos


def build_network_interface(ips):
    """Convert IPs into a NetworkInterface object."""
    ip4s = []
    ip6s = []
    for ip in ips:
        addr = ip_address(ip)
        if addr:
            if addr.version == 4:
                ip4s.append(addr)
            else:
                ip6s.append(addr)
    return NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)


def main(*args, **kwargs):
    print("Starting main()")
    api_token = kwargs.get("access_secret")
    if not api_token:
        print("Ghost API token missing.")
        return []

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # 1️⃣ Fetch repositories and build lookup by repo_id
    repos = get_all_repositories(api_token)
    print("Fetched {} repos".format(len(repos)))

    repo_map = {}
    for r in repos:
        repo_map[r["id"]] = {"name": r["name"], "hostnames": r["hostnames"], "ips": []}

    print("Built repo_map with repo_ids: {}".format(list(repo_map.keys())))

    # 2️⃣ Fetch findings
    headers = {"Authorization": "Bearer {}".format(api_token), "Accept": "application/json"}
    findings_url = "https://api.ghostsecurity.ai/v1/findings"
    print("Fetching findings from {}".format(findings_url))
    resp = http_get(findings_url, headers=headers)
    if not resp or resp.status_code != 200:
        print("Failed to fetch findings, status={}".format(resp.status_code if resp else 'N/A'))
        return []

    data = json_decode(resp.body)
    findings = data.get("items", [])
    print("Total findings returned: {}".format(len(findings)))

    asset_map = {}

    # 3️⃣ Process findings
    for f in findings:
        fid = f.get("id")
        fname = f.get("name")
        repo_id = f.get("repo_id")
        repo_url = f.get("repo_url")
        project = f.get("project", {})

        print("Finding id={} name='{}' repo_id={} repo_url={}".format(fid, fname, repo_id, repo_url))

        mapping = repo_map.get(repo_id)
        hostnames = []

        # Fallback: use project.deployments if repo not found
        if not mapping:
            deployments = project.get("deployments", {})
            for env in deployments:
                env_urls = deployments.get(env, [])
                for url in env_urls:
                    if "://" in url:
                        host = url.split("://")[1].split("/")[0]
                    else:
                        host = url
                    if host and host not in hostnames:
                        hostnames.append(host)
            mapping = {"name": repo_url or "unknown", "hostnames": hostnames, "ips": []}
            print("No repo match; built mapping from project.deployments: {}".format(hostnames))

        asset_key = mapping["name"]
        if asset_key not in asset_map:
            print("Creating ImportAsset for '{}'".format(asset_key))
            asset = ImportAsset(
                id=asset_key,
                hostnames=mapping["hostnames"],
                networkInterfaces=[build_network_interface(mapping["ips"])]
            )
            asset.vulnerabilities = []
            asset_map[asset_key] = asset

        vuln = Vulnerability(
            id=fid,
            name=fname or "Ghost Finding",
            description=f.get("description", ""),
            solution=f.get("remediation"),
            severityRank=severity_map.get(f.get("severity", "medium"), 2),
            riskRank=severity_map.get(f.get("severity", "medium"), 2),
            custom_attributes={
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "attack_feasibility": f.get("attack_feasibility"),
                "remediation_effort": f.get("remediation_effort"),
                "attack_walkthrough": f.get("attack_walkthrough"),
                "repo_url": repo_url,
                "repo_id": repo_id,
                "project_id": f.get("project_id"),
                "created_at": f.get("created_at"),
                "updated_at": f.get("updated_at"),
            }
        )
        asset_map[asset_key].vulnerabilities.append(vuln)

    print("Completed. Assets created: {}".format(len(asset_map)))
    return list(asset_map.values())

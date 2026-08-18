# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-ghost-security",
    "name": "Ghost Security",
    "type": "inbound",
    "description": "Imports assets from Ghost Security.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Ghost Security API URL",
            "type": "url",
            "required": False,
            "default": "https://api.ghostsecurity.ai",
            "placeholder": "https://api.ghostsecurity.ai",
            "description": "Ghost Security's API endpoint. Override only for a regional or self-hosted deployment.",
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
# Ghost Findings → runZero Integration
#
# Fetches repositories and findings from Ghost Security API.
# Each repository's project deployments (URLs) are mapped to runZero assets.
# Finds matching vulnerabilities based on repo_id from findings.
#
# Updated: 2025-10-24

load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('net', 'network_interface')
load('runzero.types', 'ImportAsset', 'Vulnerability')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_GHOST_API_URL = 'https://api.ghostsecurity.ai'

# Ghost pages every collection the same way, and it is a CURSOR, not a page
# number. The request carries `cursor` and `size`; the response carries `items`,
# `has_more` and `next_cursor`. There is no `page`, `offset`, or `limit`
# parameter anywhere in the API.
#
# Source: Ghost's own OpenAPI document, served without authentication at
# https://api.ghostsecurity.ai/openapi.json (title "Ghost API"). Every
# collection declares `cursor` ("Pagination cursor") and `size` (default 100,
# min 1, max 1000), and the paginated envelope declares `has_more`, `items`,
# `next_cursor`, and `total`. Ghost's own MCP client
# (github.com/ghostsecurity/ghost-mcp-server) used the same `cursor`+`size`
# contract while it still defaulted to the /v1 base, before it was ported to v2.
#
# The repository walk previously sent `?page=N` and incremented it. No such
# parameter exists, so the value was ignored: a tenant with more repositories
# than one page either truncated at the first page or, if the server kept
# answering `has_more`, refetched that same first page forever.
PAGE_SIZE = 100
MAX_PAGES = 100000


def fetch_page(url, http_options, cursor, label, page):
    """Fetch one page of a Ghost collection. Returns (items, next_cursor, err).

    next_cursor is None when the walk is finished, so a caller stops on a falsy
    cursor rather than having to consult has_more separately.
    """
    params = {"size": str(PAGE_SIZE)}
    if cursor:
        params["cursor"] = cursor
    data, err = get_json(url, params=params, **http_options)
    if err:
        print("ghost: failed to fetch {} page {}: {}".format(label, page, err))
        return [], None, err
    if type(data) != "dict":
        print("ghost: unexpected {} response shape, wanted an object".format(label))
        return [], None, "unexpected response shape"

    items = data.get("items", []) or []
    next_cursor = data.get("next_cursor")
    if not data.get("has_more", False):
        next_cursor = None
    print("ghost: {} page {} returned {} rows (has_more={})".format(
        label, page, len(items), data.get("has_more", False)))
    return items, next_cursor, None


def deployment_hostnames(projects, hostnames):
    """Collect the deployment hostnames out of a projects list, in place."""
    for proj in projects or []:
        deployments = proj.get("deployments", {}) or {}
        for env in deployments:
            for url in deployments.get(env, []) or []:
                if "://" in url:
                    host = url.split("://")[1].split("/")[0]
                else:
                    host = url
                if host and host not in hostnames:
                    hostnames.append(host)
    return hostnames


def get_all_repositories(base_url, api_token, config_kwargs):
    """
    Fetch all repositories from Ghost API with pagination.
    Extracts deployment hostnames from each repo's projects.deployments field.
    """
    headers = {"Authorization": bearer(api_token), "Accept": "application/json"}
    http_options = get_http_options(config_kwargs, headers=headers)
    repos_url = base_url + "/v1/repos"
    repos = []
    cursor = None
    seen_cursors = {}

    print("Starting get_all_repositories()")

    for page in range(1, MAX_PAGES + 1):
        items, cursor, err = fetch_page(repos_url, http_options, cursor, "repos", page)
        if err:
            return repos

        for repo in items:
            repo_id = repo.get("id")
            repo_name = repo.get("name", "unknown")
            hostnames = deployment_hostnames(repo.get("projects", []), [])
            repos.append({
                "id": repo_id,
                "name": repo_name,
                "hostnames": hostnames
            })
            print("Repo '{}' [{}] hostnames: {}".format(repo_name, repo_id, hostnames))

        if not cursor:
            break
        # A server that echoes the same cursor forever would spin here.
        if cursor in seen_cursors:
            print("ghost: repos repeated cursor on page {}; stopping".format(page))
            break
        seen_cursors[cursor] = True

    print("Completed fetching repos. Total: {}".format(len(repos)))
    return repos



def ensure_asset(asset_map, skipped, mapping):
    """Create the ImportAsset for a repository mapping if it does not exist yet.

    Returns False when the repository has no deployment hostname. Ghost publishes
    no addresses -- both places that build a mapping hard-code "ips": [] -- so the
    deployment hostnames are the only thing that ties a repository asset to
    anything else in the inventory. A repository deployed nowhere has nothing to
    correlate on and would be imported as an orphan, so it is skipped instead.

    `skipped` records which keys were dropped so the log line and the run count
    are one per repository, not one per finding that referenced it.
    """
    asset_key = mapping["name"]
    if asset_key in asset_map:
        return True
    if not mapping["hostnames"]:
        if asset_key not in skipped:
            skipped[asset_key] = True
            print("ghost: skipping repository with no deployment hostname: name={}".format(asset_key))
        return False

    print("Creating ImportAsset for '{}'".format(asset_key))
    # network_interface returns None when nothing usable is passed, and handing
    # ImportAsset networkInterfaces=[None] aborts the whole run. An asset with no
    # interface, correlating on its deployment hostnames, is the right result.
    nic = network_interface(ips=mapping["ips"])
    interfaces = [nic] if nic else []
    asset = ImportAsset(
        id=asset_key,
        hostnames=mapping["hostnames"],
        networkInterfaces=interfaces,
    )
    asset.vulnerabilities = []
    asset_map[asset_key] = asset
    return True


def main(*args, **kwargs):
    print("Starting main()")
    api_token = kwargs.get("api_token")
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get("url") or DEFAULT_GHOST_API_URL).rstrip("/")
    if not api_token:
        print("Ghost API token missing.")
        return []

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # 1️⃣ Fetch repositories and build lookup by repo_id
    repos = get_all_repositories(base_url, api_token, kwargs)
    print("Fetched {} repos".format(len(repos)))

    repo_map = {}
    for r in repos:
        repo_map[r["id"]] = {"name": r["name"], "hostnames": r["hostnames"], "ips": []}

    print("Built repo_map with repo_ids: {}".format(list(repo_map.keys())))

    asset_map = {}
    skipped = {}

    # 2️⃣ Every repository is an asset, whether or not Ghost has a finding
    # against it. Assets used to be created only inside the findings loop, so a
    # repository that Ghost had scanned and found clean was fetched, logged, and
    # then discarded -- which made this an import of findings grouped by
    # repository rather than an inventory of repositories. A clean codebase is
    # still an asset, and it is the one whose deployment hostnames most want
    # correlating against what runZero already knows.
    for repo_id in repo_map:
        ensure_asset(asset_map, skipped, repo_map[repo_id])

    # 3️⃣ Fetch findings, paged the same way as repos. This walk was previously a
    # single unpaged GET, so on any tenant with more findings than one page holds
    # the remainder were silently missing.
    headers = {"Authorization": bearer(api_token), "Accept": "application/json"}
    http_options = get_http_options(kwargs, headers=headers)
    findings_url = base_url + "/v1/findings"
    print("Fetching findings from {}".format(findings_url))

    findings = []
    cursor = None
    seen_cursors = {}
    for page in range(1, MAX_PAGES + 1):
        items, cursor, err = fetch_page(findings_url, http_options, cursor, "findings", page)
        if err:
            break
        findings.extend(items)
        if not cursor:
            break
        if cursor in seen_cursors:
            print("ghost: findings repeated cursor on page {}; stopping".format(page))
            break
        seen_cursors[cursor] = True

    print("Total findings returned: {}".format(len(findings)))

    # 4️⃣ Process findings
    for f in findings:
        fid = f.get("id")
        fname = f.get("name")
        repo_id = f.get("repo_id")
        repo_url = f.get("repo_url")
        project = f.get("project", {})

        print("Finding id={} name='{}' repo_id={} repo_url={}".format(fid, fname, repo_id, repo_url))

        mapping = repo_map.get(repo_id)

        # Fallback: use project.deployments if repo not found
        if not mapping:
            hostnames = deployment_hostnames([project], [])
            mapping = {"name": repo_url or "unknown", "hostnames": hostnames, "ips": []}
            print("No repo match; built mapping from project.deployments: {}".format(hostnames))

        asset_key = mapping["name"]
        if not ensure_asset(asset_map, skipped, mapping):
            continue

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
    if skipped:
        print("ghost: skipped {} repositories with no deployment hostname".format(len(skipped)))
    # Stream assets to runZero via report_assets instead of returning a list.
    report_assets(list(asset_map.values()))
    return None

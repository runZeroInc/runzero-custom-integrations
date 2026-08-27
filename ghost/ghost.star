# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-ghost-security",
    "name": "Ghost Security",
    "type": "inbound",
    "description": "Imports assets from Ghost Security.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "maxPages": 100000,
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
# Findings join to their repository by repo_id and attach as vulnerabilities.
#
# Only the finding buckets (capped per asset) and the repository name/hostname
# mappings are held in memory; each ImportAsset is reported as it is built, so
# a failure late in the run cannot lose the assets already streamed.

load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('runzero.types', 'ImportAsset', 'Vulnerability', 'to_custom_attributes')

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

# runZero caps the children attached to one asset at 99; anything past the cap
# is counted and logged rather than silently dropped or fatally over-cap.
MAX_VULNS = 99

# The script's contract was built against /v1, but Ghost's current OpenAPI
# documents /v2 with the same cursor envelope. When /v1 answers 404 the run
# switches to /v2 rather than failing outright.
V1_PREFIX = "/v1"
V2_PREFIX = "/v2"


def _text(value):
    """Return value when it is a string, else an empty string. Ghost fields
    documented as strings can arrive null, and handing None to a field that
    validates would abort the whole import."""
    return value if type(value) == "string" else ""


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
    if type(items) != "list":
        print("ghost: unexpected {} items shape, wanted a list".format(label))
        items = []
    next_cursor = data.get("next_cursor")
    if not data.get("has_more", False):
        next_cursor = None
    print("ghost: {} page {} returned {} rows (has_more={})".format(
        label, page, len(items), data.get("has_more", False)))
    return items, next_cursor, None


def deployment_hostnames(projects, hostnames):
    """Collect the deployment hostnames out of a projects list, in place.
    Every level is shape-checked: a null project, a string where the
    deployments object should be, or a scalar where the URL list should be
    must skip rather than abort the record."""
    if type(projects) != "list":
        return hostnames
    for proj in projects:
        if type(proj) != "dict":
            continue
        deployments = proj.get("deployments", {}) or {}
        if type(deployments) != "dict":
            continue
        for env in deployments:
            urls = deployments.get(env, []) or []
            if type(urls) != "list":
                continue
            for url in urls:
                if type(url) != "string" or not url:
                    continue
                if "://" in url:
                    host = url.split("://")[1].split("/")[0]
                else:
                    host = url
                if host and host not in hostnames:
                    hostnames.append(host)
    return hostnames


def get_all_repositories(base_url, api_token, config_kwargs, api_prefix):
    """
    Fetch all repositories from Ghost API with pagination, returning
    (repos, api_prefix). Extracts deployment hostnames from each repo's
    projects.deployments field. A 404 for /v1/repos on the first page switches
    the rest of the run to the documented /v2 API.
    """
    headers = {"Authorization": bearer(api_token), "Accept": "application/json"}
    http_options = get_http_options(config_kwargs, headers=headers)
    repos_url = base_url + api_prefix + "/repos"
    repos = []
    cursor = None
    seen_cursors = {}

    print("Starting get_all_repositories()")

    p = pager("repos")
    while p.next():
        items, cursor, err = fetch_page(repos_url, http_options, cursor, "repos", p.page)
        if err and p.page == 1 and api_prefix == V1_PREFIX and err.startswith("status 404"):
            api_prefix = V2_PREFIX
            repos_url = base_url + api_prefix + "/repos"
            print("ghost: {} is gone (404); retrying against the documented {} API".format(
                V1_PREFIX + "/repos", V2_PREFIX))
            items, cursor, err = fetch_page(repos_url, http_options, cursor, "repos", p.page)
        if err:
            return repos, api_prefix

        for repo in items:
            if type(repo) != "dict":
                print("ghost: skipping malformed repository record (not an object)")
                continue
            repo_id = repo.get("id")
            repo_name = _text(repo.get("name", "unknown"))
            if not repo_name:
                print("ghost: skipping repository with no name: id={}".format(repo_id))
                continue
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
            print("ghost: repos repeated cursor on page {}; stopping".format(p.page))
            break
        seen_cursors[cursor] = True

    print("Completed fetching repos. Total: {}".format(len(repos)))
    return repos, api_prefix


def build_finding(f, repo_url, repo_id, severity_map):
    """Convert one Ghost finding into a Vulnerability. Every free-form field is
    shape-checked or routed through to_custom_attributes, so a null or an
    object where a string is documented degrades instead of aborting."""
    severity = f.get("severity", "medium")
    if type(severity) != "string":
        severity = "medium"
    rank = severity_map.get(severity, 2)
    return Vulnerability(
        id=f.get("id"),
        name=_text(f.get("name")) or "Ghost Finding",
        description=_text(f.get("description")),
        solution=_text(f.get("remediation")),
        severityRank=rank,
        riskRank=rank,
        custom_attributes=to_custom_attributes({
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
        })
    )


def main(*args, **kwargs):
    print("Starting main()")
    api_token = kwargs.get("api_token")
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get("url") or DEFAULT_GHOST_API_URL).rstrip("/")
    if not api_token:
        fail("Ghost API token missing.")

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # 1️⃣ Fetch repositories and build the asset mappings by repo_id. The
    # mapping (name plus deployment hostnames) is the only thing buffered per
    # repository; the ImportAssets themselves are streamed at the end of the
    # join, one at a time.
    repos, api_prefix = get_all_repositories(base_url, api_token, kwargs, api_prefix=V1_PREFIX)
    print("Fetched {} repos".format(len(repos)))

    repo_map = {}
    mappings = {}       # asset key -> {"name", "hostnames"}
    for r in repos:
        repo_map[r["id"]] = {"name": r["name"], "hostnames": r["hostnames"]}
        # 2️⃣ Every repository is an asset, whether or not Ghost has a finding
        # against it. A clean codebase is still an asset, and it is the one
        # whose deployment hostnames most want correlating against what
        # runZero already knows.
        if r["name"] not in mappings:
            mappings[r["name"]] = repo_map[r["id"]]

    print("Built repo_map with repo_ids: {}".format(list(repo_map.keys())))

    # 3️⃣ Fetch findings, paged the same way as repos, and bucket each one
    # under the asset it joins to. Buckets are capped at 99 per asset with the
    # overflow counted, so one noisy repository cannot produce an over-cap
    # asset or unbounded memory.
    headers = {"Authorization": bearer(api_token), "Accept": "application/json"}
    http_options = get_http_options(kwargs, headers=headers)
    findings_url = base_url + api_prefix + "/findings"
    print("Fetching findings from {}".format(findings_url))

    vuln_map = {}       # asset key -> [Vulnerability], capped at MAX_VULNS
    truncated = {}      # asset key -> findings dropped past the cap
    total_findings = 0
    cursor = None
    seen_cursors = {}
    p = pager("findings")
    while p.next():
        items, cursor, err = fetch_page(findings_url, http_options, cursor, "findings", p.page)
        if err:
            break

        for f in items:
            if type(f) != "dict":
                print("ghost: skipping malformed finding record (not an object)")
                continue
            fid = f.get("id")
            if fid == None or str(fid).strip() == "":
                print("ghost: skipping finding with no id")
                continue
            total_findings += 1

            fname = f.get("name")
            repo_id = f.get("repo_id")
            repo_url = f.get("repo_url")
            project = f.get("project", {})
            if type(project) != "dict":
                project = {}

            print("Finding id={} name='{}' repo_id={} repo_url={}".format(fid, fname, repo_id, repo_url))

            mapping = repo_map.get(repo_id)

            # Fallback: use project.deployments if repo not found
            if not mapping:
                hostnames = deployment_hostnames([project], [])
                mapping = {"name": _text(repo_url) or "unknown", "hostnames": hostnames}
                print("No repo match; built mapping from project.deployments: {}".format(hostnames))

            asset_key = mapping["name"]
            if asset_key not in mappings:
                mappings[asset_key] = mapping

            bucket = vuln_map.get(asset_key)
            if bucket == None:
                bucket = []
                vuln_map[asset_key] = bucket
            if len(bucket) >= MAX_VULNS:
                truncated[asset_key] = truncated.get(asset_key, 0) + 1
                continue
            bucket.append(build_finding(f, repo_url, repo_id, severity_map))

        if not cursor:
            break
        if cursor in seen_cursors:
            print("ghost: findings repeated cursor on page {}; stopping".format(p.page))
            break
        seen_cursors[cursor] = True

    print("Total findings returned: {}".format(total_findings))
    for asset_key in truncated:
        print("ghost: capped vulnerabilities for '{}' at {}; {} more findings were truncated".format(
            asset_key, MAX_VULNS, truncated[asset_key]))

    # 4️⃣ Stream one asset per repository mapping. Ghost publishes no
    # addresses, so the deployment hostnames are the only thing tying a
    # repository asset to anything else in the inventory; a repository
    # deployed nowhere has nothing to correlate on and would be imported as an
    # orphan, so it is skipped and counted instead.
    reported = 0
    skipped = 0
    for asset_key in mappings:
        mapping = mappings[asset_key]
        if not mapping["hostnames"]:
            skipped += 1
            print("ghost: skipping repository with no deployment hostname: name={}".format(asset_key))
            continue
        print("Creating ImportAsset for '{}'".format(asset_key))
        # A repository asset carries no network interface at all: Ghost
        # publishes no addresses, and the asset correlates on its deployment
        # hostnames (handing ImportAsset networkInterfaces=[None] aborts the
        # whole run, which is why nothing synthesizes an interface here).
        reported += report_asset(ImportAsset(
            id=asset_key,
            hostnames=mapping["hostnames"],
            vulnerabilities=vuln_map.get(asset_key, []),
        ))

    print("Completed. Assets created: {}".format(reported))
    if skipped:
        print("ghost: skipped {} repositories with no deployment hostname".format(skipped))
    return None

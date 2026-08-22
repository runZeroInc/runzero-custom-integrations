# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cyberint",
    "name": "Cyberint",
    "type": "inbound",
    "description": "Imports assets from Cyberint.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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

# Cyberint pages POST /alert/api/v1/alerts with a 1-based `page` and a `size`,
# both top-level fields of the request body, and answers with `total` (the
# number of matching alerts across ALL pages) alongside `alerts`. There is no
# cursor and no `pagination` wrapper object.
#
# Cyberint publishes no public API reference -- cyberint.com's API documentation
# page is a gated resource and the live Swagger sits behind tenant auth -- so the
# contract is taken from four independent implementations that agree exactly, two
# of them authored by Cyberint itself:
#   - github.com/CyberInt/servicenow-integration, whose fetchAlerts(page) posts
#     {page, size, filters} with size = 100 and loops on the returned `total`.
#   - github.com/CyberInt/qradar-universal-cloud-rest-api, cyberint-workflow.xml,
#     which posts {"page": 1, "size": ..., "filters": {...}} literally.
#   - Check Point's Splunk SOAR app (splunk-soar-connectors/cyberintalerts) and
#     the Cortex XSOAR pack (demisto/content Packs/Cyberint), both of which read
#     the count as `total` and cap `size` at 100.
#
# Note what is NOT there: this script previously decoded a `total_assets` field
# and never used it. No such field exists in this response -- the only count is
# `total` -- so it would have been 0 on every run even if something had read it.
PAGE_SIZE = 100
MAX_PAGES = 100000

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

    # The request used to be a single POST with an empty {} body, so whatever
    # one unpaged response happened to carry was the entire import and every
    # alert past it was invisible. Walk the pages instead, stopping when a page
    # comes back empty or the running count reaches the reported total.
    seen = 0
    total = 0
    # An alert with no id cannot be keyed on. Counted across every page and
    # reported once, so a bad export costs a line rather than one per alert.
    skipped = 0
    for page in range(1, MAX_PAGES + 1):
        response = session.post(url, json={"page": page, "size": PAGE_SIZE}, timeout=300)
        if not response or response.status_code != 200:
            status = response.status_code if response else "no response"
            print("cyberint: failed to fetch alerts page {}: {}".format(page, status))
            break
        # json_decode aborts the whole script on malformed input and Starlark has
        # no exceptions, so an empty body is screened rather than decoded.
        if not response.body:
            print("cyberint: empty body on alerts page {}".format(page))
            break
        data = json_decode(response.body)
        if type(data) != "dict":
            print("cyberint: unexpected response shape on page {}, wanted an object".format(page))
            break

        alerts = data.get("alerts", []) or []
        total = data.get("total", 0) or 0
        # An empty page ends the walk whatever the count says, and it is also
        # what stops a server that ignores `page` from spinning here.
        if not alerts:
            break
        seen += len(alerts)

        for item in alerts:
            alert_id = item.get("id")
            if not alert_id:
                skipped += 1
                continue
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            # .get's default only applies when the key is ABSENT. An alert whose
            # severity is present but null reaches .lower() as None and aborts
            # the script, losing every alert in the response.
            risk_rank = severity_map.get((item.get("severity") or "low").lower(), 0)
            vuln = Vulnerability(
                    id=str(alert_id),
                    name=item.get("title", "No title available"),
                    description=item.get("description", "No description available"),
                    solution=item.get("recommendation", "No recommendation available"),
                    severityRank=risk_rank,
                    riskRank=risk_rank,
                )

            # An alert that names nothing carries "related_assets": null, and
            # iterating None aborts the script -- one such alert used to lose
            # every alert in the response.
            related_assets_alert = item.get("related_assets") or []
            for a in related_assets_alert:
                asset_type = a.get("type")
                if asset_type == "domain":
                    domain = a.get("name")
                    if not domain:
                        continue

                    # The seeding branch used to be `related_assets[domain] =
                    # [vuln]` followed by this same unconditional append, so
                    # every domain's FIRST alert was imported twice.
                    if domain not in related_assets:
                        related_assets[domain] = []
                    related_assets[domain].append(vuln)

        # `total` is the number of matching alerts across every page, not the
        # length of this one, so the walk ends when the running count reaches it.
        # This is the terminator Cyberint's own ServiceNow client uses.
        if seen >= total:
            break

    print("cyberint: read {} alerts of {} reported".format(seen, total))
    if skipped > 0:
        print("cyberint: skipped {} alerts with no id".format(skipped))

    for domain, vulns in related_assets.items():
        assets.append(ImportAsset(
            id=domain.replace(".", "-"),
            hostnames=[domain],
            vulnerabilities=vulns,
    ))

    # Stream assets to runZero via report_assets instead of returning a list.
    reported = report_assets(assets)
    print("cyberint: reported {} assets".format(reported))

    return None

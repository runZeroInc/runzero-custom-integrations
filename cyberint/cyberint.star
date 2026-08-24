# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-cyberint",
    "name": "Cyberint",
    "type": "inbound",
    "description": "Imports assets from Cyberint.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Backstop for the alert page walk; the normal exits are an empty page and
    # the running count reaching the reported total.
    "maxPages": 100000,
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
load('runzero.types', 'ImportAsset', 'Vulnerability')
load('http', 'post_json')
load('kwargs', 'get_url_base', 'get_http_options')

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

    # The token travels as a cookie rather than an Authorization header, which
    # is the vendor's documented approach. get_http_options wires the shared
    # TLS and HTTP options a raw Session ignored, and post_json retries the
    # transient statuses (429/5xx) with backoff -- the alert search is a
    # read-only POST, so a retried request cannot double-apply anything.
    http_options = get_http_options(kwargs, headers={
        "Accept": "application/json",
        "Cookie": "access_token=" + str(access_token or ""),
    })
    if "timeout" not in http_options:
        http_options["timeout"] = 300

    related_assets = {}

    # The request used to be a single POST with an empty {} body, so whatever
    # one unpaged response happened to carry was the entire import and every
    # alert past it was invisible. Walk the pages instead, stopping when a page
    # comes back empty or the running count reaches the reported total.
    seen = 0
    total = 0
    # An alert with no id cannot be keyed on. Counted across every page and
    # reported once, so a bad export costs a line rather than one per alert.
    skipped = 0
    p = pager("alerts")
    while p.next():
        page = p.page
        data, err = post_json(url, json={"page": page, "size": PAGE_SIZE}, **http_options)
        if err:
            # The documented failure mode of an expired or invalid cookie is a
            # 200 login page rather than a 401. The HTML body fails JSON
            # decoding inside post_json and arrives here as an error string, so
            # it is named for what it is instead of aborting the task with a
            # decode error. Domains already collected still get reported below.
            if err.startswith("status 200") and "invalid JSON" in err:
                print("cyberint: page {} returned a non-JSON body; the access token cookie is likely expired or invalid (the portal answers a bad cookie with its login page)".format(page))
            else:
                print("cyberint: failed to fetch alerts page {}: {}".format(page, err))
            break
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
            # A non-object element in the alerts array cannot be keyed on and
            # would abort the run at .get; count it with the id-less alerts.
            if type(item) != "dict":
                skipped += 1
                continue
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
                # A bare string in related_assets would abort the run at .get.
                if type(a) != "dict":
                    continue
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

    # The import pivots alerts onto the domains they name, and a later page can
    # add findings to a domain seen earlier, so the domain index has to survive
    # the whole walk. Each asset is still streamed as it is built rather than
    # buffered into a second list, and a walk that ended early reports every
    # domain collected so far instead of losing them.
    reported = 0
    for domain, vulns in related_assets.items():
        reported += report_asset(ImportAsset(
            id=domain.replace(".", "-"),
            hostnames=[domain],
            vulnerabilities=vulns,
        ))
    print("cyberint: reported {} assets".format(reported))

    return None

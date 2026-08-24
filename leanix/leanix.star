# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-leanix",
    "name": "SAP LeanIX",
    "type": "inbound",
    "description": "Imports fact sheets (IT components, applications, and other configured types) from a SAP LeanIX workspace as inventory assets.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # A fact sheet's id is a UUID that survives renames and every attribute
    # edit, so the id drives merging. LeanIX is a logical inventory: most
    # records carry no addressing at all, and the few hostname-shaped names
    # that are imported must not veto an id merge when they change.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Workspace URL",
            "type": "url",
            "required": True,
            "placeholder": "https://acme.leanix.net",
            "description": "Base URL of the LeanIX workspace instance, copied from the workspace address. There is no global API host; token exchange and GraphQL both live on this instance.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Technical user API token created under Administration > Technical Users. Exchanged for a bearer token on every run.",
        },
        {
            "key": "fact_sheet_types",
            "label": "Fact sheet types",
            "type": "string",
            "required": False,
            "default": "ITComponent",
            "description": "Comma-separated fact sheet types to import, e.g. ITComponent,Application,TechnicalStack,System. Type names are workspace-specific; unknown types simply match nothing.",
        },
        {
            "key": "page_size",
            "label": "Page size",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 1000,
            "description": "Fact sheets per GraphQL page. LeanIX recommends at most 1000.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("http", "post_json", "bearer", "basic", "url_encode")
load("kwargs", "require", "get_string", "get_int", "get_url_base", "get_http_options")
load("net", "clean_hostname")
load("runzero.progress", progress_report="report")

TOKEN_PATH = "/services/mtm/v1/oauth2/token"
GRAPHQL_PATH = "/services/pathfinder/v1/graphql"

# The paged inventory query, in two tiers. The full tier asks for the standard
# meta-model fields; a workspace whose meta model was customized away from one
# of them fails the whole query with a GraphQL error, so the walk drops to the
# minimal tier -- fields every meta model carries -- rather than importing
# nothing.
QUERY_FULL = ("query inv($filter: FilterInput!, $first: Int!, $after: String) { " +
              "allFactSheets(filter: $filter, first: $first, after: $after) { " +
              "totalCount pageInfo { hasNextPage endCursor } " +
              "edges { node { id name displayName type description status updatedAt " +
              "tags { name } lifecycle { asString } } } } }")
QUERY_MINIMAL = ("query inv($filter: FilterInput!, $first: Int!, $after: String) { " +
                 "allFactSheets(filter: $filter, first: $first, after: $after) { " +
                 "totalCount pageInfo { hasNextPage endCursor } " +
                 "edges { node { id name displayName type description tags { name } } } } }")

MAX_TAGS = 25


def fetch_token(base_url, api_token, config):
    """Exchange the long-lived API token for a bearer token.

    LeanIX documents this as HTTP Basic with the literal username "apitoken"
    and the API token as the password, so the exchange is built by hand rather
    than with oauth2_token, which would put the credentials in the form body.

    post_json carries the exchange so it gets the default transient-failure
    retries: this is the very first request of every run, the grant is
    idempotent, and a single 502/503 blip here used to end the entire scheduled
    import before it started.
    """
    options = get_http_options(config, headers={
        "Authorization": basic("apitoken", api_token),
        "Content-Type": "application/x-www-form-urlencoded",
    })
    data, err = post_json(base_url + TOKEN_PATH,
                          body=bytes(url_encode({"grant_type": "client_credentials"})),
                          **options)
    if err:
        print("leanix: token exchange failed: {}".format(err))
        if err.startswith("status 401") or err.startswith("status 403"):
            print("leanix: check the API token; it is exchanged as Basic apitoken:<token>")
        return ""
    if type(data) != "dict":
        print("leanix: token endpoint returned an unexpected body")
        return ""
    token = str(data.get("access_token", "") or "")
    if not token:
        print("leanix: token endpoint returned no access_token")
    return token


def graphql(base_url, token, config, query, variables):
    """Run one GraphQL request and return (data, errors, err)."""
    options = get_http_options(config, headers={
        "Authorization": bearer(token),
        "Content-Type": "application/json",
    })
    payload, err = post_json(base_url + GRAPHQL_PATH,
                             json={"query": query, "variables": variables},
                             **options)
    if err:
        return None, [], err
    if type(payload) != "dict":
        return None, [], "unexpected response of type " + type(payload)
    errors = payload.get("errors", []) or []
    return payload.get("data"), errors, None


def error_summary(errors):
    """Reduce a GraphQL error list to one printable line."""
    parts = []
    for e in errors[:3]:
        if type(e) == "dict":
            parts.append(str(e.get("message", "") or ""))
        else:
            parts.append(str(e))
    return "; ".join([p for p in parts if p])


def type_filter(types):
    """Build the facet filter that scopes the walk to the requested types."""
    return {"facetFilters": [{
        "facetKey": "FactSheetTypes",
        "operator": "OR",
        "keys": types,
    }]}


def hostname_for(node):
    """Return the node's name as a hostname only when it is FQDN-shaped.

    Fact sheet names are mostly product names ("PostgreSQL 14"), which must
    never be imported as hostnames. A name that survives clean_hostname AND
    contains a dot is overwhelmingly a real machine or service FQDN, which is
    exactly the record worth correlating.
    """
    for candidate in [node.get("name"), node.get("displayName")]:
        cleaned = clean_hostname(candidate)
        if cleaned and "." in cleaned:
            return cleaned
    return ""


def sanitize_tag(value):
    """Keep a LeanIX tag usable as a runZero tag."""
    return str(value or "").strip().replace(" ", "-")[:64]


def asset_type_key(fs_type):
    """Reduce a fact sheet type to a legal assetType key, or ""."""
    key = ""
    for ch in str(fs_type or "").lower().elems():
        if ("a" <= ch and ch <= "z") or ("0" <= ch and ch <= "9") or ch in "-_":
            key += ch
    return key[:64]


def build_asset(node, namespace):
    """Build one ImportAsset from a fact sheet node."""
    fs_id = str(node.get("id", "") or "")
    if not fs_id:
        print("leanix: skipping fact sheet with no id: name=" + str(node.get("name", "")))
        return None
    fs_type = str(node.get("type", "") or "")

    tags = ["leanix"]
    if fs_type:
        tags.append("leanix-type:" + sanitize_tag(fs_type))
    for tag in node.get("tags", []) or []:
        if type(tag) != "dict":
            continue
        name = sanitize_tag(tag.get("name"))
        if name and len(tags) < MAX_TAGS:
            tags.append(name)

    lifecycle = ""
    lc = node.get("lifecycle")
    if type(lc) == "dict":
        lifecycle = str(lc.get("asString", "") or "")

    attrs = to_custom_attributes({
        "factSheetId": fs_id,
        "type": fs_type,
        "name": node.get("name", ""),
        "displayName": node.get("displayName", ""),
        "description": node.get("description", ""),
        "status": node.get("status", ""),
        "updatedAt": node.get("updatedAt", ""),
        "lifecycle": lifecycle,
    }, prefix="leanix", separator="_")

    asset_args = {
        "id": "leanix:{}:{}".format(namespace, fs_id),
        "tags": tags,
        "customAttributes": attrs,
    }
    hostname = hostname_for(node)
    if hostname:
        asset_args["hostnames"] = [hostname]
    type_key = asset_type_key(fs_type)
    if type_key:
        asset_args["assetType"] = type_key
    return ImportAsset(**asset_args)


def main(**kwargs):
    require(kwargs, "url", "api_token")
    base_url = get_url_base(kwargs)
    api_token = get_string(kwargs, "api_token")
    types_raw = get_string(kwargs, "fact_sheet_types", default="ITComponent")
    page_size = get_int(kwargs, "page_size", default=500)
    if page_size < 1 or page_size > 1000:
        page_size = 500

    types = [t.strip() for t in types_raw.split(",") if t.strip()]
    if not types:
        types = ["ITComponent"]

    # Hostname only, no port: the id namespace must not change if the
    # workspace is later reached through a proxy port.
    namespace = base_url.split("://")[-1].split("/")[0].split(":")[0]

    token = fetch_token(base_url, api_token, kwargs)
    if not token:
        return None

    query = QUERY_FULL
    cursor = None
    reported = 0
    skipped = 0
    total = None
    p = pager("leanix-factsheets")
    while p.next():
        variables = {
            "filter": type_filter(types),
            "first": page_size,
            "after": cursor,
        }
        data, errors, err = graphql(base_url, token, kwargs, query, variables)

        # The bearer token lives 3600 seconds; a workspace big enough to
        # outlast it gets one fresh token and the same page retried.
        if err and (err.startswith("status 401") or err.startswith("status 403")):
            print("leanix: bearer token rejected; re-authenticating")
            token = fetch_token(base_url, api_token, kwargs)
            if not token:
                break
            data, errors, err = graphql(base_url, token, kwargs, query, variables)

        if err:
            print("leanix: fact sheet query failed:", err)
            break
        if errors and query == QUERY_FULL:
            # A customized meta model can reject a standard field; retry the
            # same cursor with the minimal field set instead of importing
            # nothing.
            print("leanix: full query rejected ({}); retrying with minimal fields".format(
                error_summary(errors)))
            query = QUERY_MINIMAL
            continue
        if errors:
            print("leanix: query failed:", error_summary(errors))
            break

        sheets = {}
        if type(data) == "dict":
            sheets = data.get("allFactSheets") or {}
        if type(sheets) != "dict":
            print("leanix: unexpected allFactSheets payload")
            break

        if total == None:
            total = sheets.get("totalCount")
            if type(total) == "int":
                print("leanix: workspace reports {} fact sheets of types {}".format(
                    total, ",".join(types)))

        edges = sheets.get("edges", []) or []
        for edge in edges:
            if type(edge) != "dict":
                skipped += 1
                continue
            node = edge.get("node")
            if type(node) != "dict":
                skipped += 1
                continue
            asset = build_asset(node, namespace)
            if asset == None:
                skipped += 1
                continue
            reported += report_asset(asset)

        if type(total) == "int" and total > 0:
            progress_report(min(reported * 100 // total, 100),
                            "imported {}/{} fact sheets".format(reported, total))

        page_info = sheets.get("pageInfo", {}) or {}
        if type(page_info) != "dict" or not page_info.get("hasNextPage", False):
            break
        cursor = str(page_info.get("endCursor", "") or "")
        if not cursor:
            print("leanix: hasNextPage was true but endCursor was empty; stopping")
            break
        if not edges:
            print("leanix: empty page with hasNextPage true; stopping to avoid a loop")
            break

    if skipped:
        print("leanix: skipped {} records without a usable id".format(skipped))
    print("leanix: reported {} assets".format(reported))
    return None

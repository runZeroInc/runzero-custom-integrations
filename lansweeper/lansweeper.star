# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-lansweeper",
    "name": "Lansweeper",
    "type": "inbound",
    "description": "Imports assets and installed software from Lansweeper.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Backstop for the per-site cursor walk, enforced by pager(). At the
    # 200-asset default page size this is well past the repo-wide
    # ten-million-record target.
    "maxPages": 100000,
    # Lansweeper is a discovery source: the site-scoped key is authoritative
    # while the single primary MAC/IP it reports churn with DHCP and NIC
    # changes, so network churn must not disqualify a merge.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "Lansweeper API URL",
            "type": "url",
            "required": False,
            "default": "https://api.lansweeper.com",
            "description": "Lansweeper Data API endpoint. Leave the default unless Lansweeper directs you elsewhere.",
        },
        {
            "key": "site_ids",
            "label": "Site IDs",
            "type": "string",
            "required": False,
            "description": "Comma-separated Lansweeper site IDs. Leave blank to import every authorized site.",
        },
        {
            "key": "application_identity_code",
            "label": "Application identity code",
            "type": "secret",
            "required": True,
            "description": "Identity code of a personal application authorized in Lansweeper Developer Tools.",
        },
        {
            "key": "import_software",
            "label": "Import installed software",
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Request the softwares fields alongside each asset.",
        },
        {
            "key": "page_size",
            "label": "Assets per page",
            "type": "int",
            "required": False,
            "default": 200,
            "min": 1,
            "max": 500,
            "description": "Lansweeper caps a response page at 4 MB; lower this if pages are rejected.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'post_json')
load('kwargs', 'get_url_base', 'get_string', 'get_int', 'get_bool', 'get_list', 'get_http_options')
load('time', 'now', 'parse_time')
load('re', re_match='match')

LANSWEEPER_API_URL = "https://api.lansweeper.com"
GRAPHQL_PATH = "/api/v2/graphql"

# Lansweeper caps a response page at 4 MB and a request at 30 element paths.
# 500 is the largest limit its own tooling uses; the lower default keeps pages
# well under the size cap once the softwares list is attached to each asset.
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 500

# http.post_json retries the retryable statuses with exponential backoff on its
# own; three is its default, restated here so the bound is visible.
HTTP_RETRIES = 3

# Site IDs are interpolated into the GraphQL document, so only accept the
# opaque identifier characters Lansweeper actually issues.
SITE_ID_RE = r"^[A-Za-z0-9._:-]+$"

# RFC 3339 with a mandatory zone, because time.parse_time aborts the script on
# anything it cannot parse and Starlark has no exception handling.
TIMESTAMP_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"

# Software.cpe23 only accepts the CPE 2.2 application URI binding and rejects
# the whole import otherwise. Lansweeper does not document which binding its
# softwares.cpe field emits, so anything else is kept as a custom attribute.
CPE22_APP_RE = r"^cpe:/a:"

SITES_QUERY = """query getAuthorizedSites {
  authorizedSites {
    sites {
      id
      name
    }
  }
}"""

ASSET_FIELDS = [
    # The site-scoped asset key is the foreign id. It is requested explicitly
    # rather than assumed present: vendor examples that consume `key` name it
    # in `fields`, and if a Lansweeper release returned only the requested
    # fields, every item would arrive keyless and the run would import nothing.
    "key",
    "assetBasicInfo.name",
    "assetBasicInfo.domain",
    "assetBasicInfo.userName",
    "assetBasicInfo.userDomain",
    "assetBasicInfo.fqdn",
    "assetBasicInfo.description",
    "assetBasicInfo.type",
    "assetBasicInfo.mac",
    "assetBasicInfo.ipAddress",
    "assetBasicInfo.firstSeen",
    "assetBasicInfo.lastSeen",
    "assetCustom.model",
    "assetCustom.serialNumber",
    "assetCustom.manufacturer",
    "assetCustom.sku",
    "assetCustom.firmwareVersion",
    "assetCustom.dnsName",
    "assetCustom.location",
    "assetCustom.department",
    "assetCustom.stateName",
    "operatingSystem.caption",
    "operatingSystem.productType",
    "url",
]

SOFTWARE_FIELDS = [
    "softwares.name",
    "softwares.version",
    "softwares.publisher",
    "softwares.cpe",
    "softwares.installDate",
]


def build_assets_query(site_id, include_software, include_total):
    """Build the per-site assetResources document with the paging variable bound.

    Lansweeper rejects `total` on any page other than FIRST, so that field is
    only selected on the opening request.
    """
    names = ASSET_FIELDS
    if include_software:
        names = ASSET_FIELDS + SOFTWARE_FIELDS
    fields = ", ".join(['"{}"'.format(name) for name in names])
    total = ""
    if include_total:
        total = "      total\n"
    return ("query getAssetResources($pagination: AssetsPaginationInputValidated) {\n" +
            '  site(id: "' + site_id + '") {\n' +
            "    assetResources(assetPagination: $pagination, fields: [" + fields + "]) {\n" +
            total +
            "      pagination { limit current next page }\n" +
            "      items\n" +
            "    }\n" +
            "  }\n" +
            "}")


def parse_timestamp(value):
    """Parse a Lansweeper ISO 8601 timestamp, returning None when unusable.

    The result is capped at the current time. runZero rejects an ImportAsset
    whose first- or last-seen time is ahead of now by failing the whole record,
    and that aborts main, so one scanned host with a wrong BIOS clock would
    otherwise take the rest of the run -- including every remaining site -- with
    it. The value as reported is kept in the lansweeper_first_seen /
    lansweeper_last_seen attributes.
    """
    text = str(value or "").strip()
    if not text:
        return None
    if not re_match(TIMESTAMP_RE, text):
        return None
    parsed = parse_time(text)
    ceiling = now()
    if parsed.unix > ceiling.unix:
        return ceiling
    return parsed


def build_hostnames(basic, custom):
    """Collect the distinct names Lansweeper reports for one asset."""
    names = []
    for value in [basic.get("name", ""), basic.get("fqdn", ""), custom.get("dnsName", "")]:
        name = str(value or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def build_software(entries):
    """Convert the softwares list on one asset into Software objects."""
    software = []
    seen = {}
    for entry in entries:
        if type(entry) != "dict":
            continue
        product = str(entry.get("name", "") or "").strip()
        if not product:
            continue
        version = str(entry.get("version", "") or "").strip()
        software_id = "{}:{}".format(product, version)[:255]
        if software_id in seen:
            continue
        seen[software_id] = True

        software_params = {
            "id": software_id,
            "product": product,
            # No socket is associated with an installed package.
            "serviceAddress": "127.0.0.1",
        }
        if version:
            software_params["version"] = version
        publisher = str(entry.get("publisher", "") or "").strip()
        if publisher:
            software_params["vendor"] = publisher
        cpe = str(entry.get("cpe", "") or "").strip()
        if cpe:
            if re_match(CPE22_APP_RE, cpe):
                software_params["cpe23"] = cpe
            else:
                software_params["customAttributes"] = to_custom_attributes(
                    {"cpe": cpe}, prefix="lansweeper", separator="_")
        installed_at = parse_timestamp(entry.get("installDate", ""))
        if installed_at:
            software_params["installedAt"] = installed_at

        software.append(Software(**software_params))
    return software


def build_tags(site_name, serial_number, state_name):
    """Build the tag list for one asset."""
    tags = ["lansweeper"]
    if site_name:
        tags.append("site:" + str(site_name))
    if serial_number:
        tags.append("serial:" + str(serial_number))
    if state_name:
        tags.append("state:" + str(state_name))
    return tags


def build_asset(site_id, site_name, item):
    """Convert one Lansweeper assetResources item into an ImportAsset."""
    if type(item) != "dict":
        print("lansweeper: skipping non-object asset record in site " + str(site_id))
        return None

    basic = item.get("assetBasicInfo", {}) or {}
    custom = item.get("assetCustom", {}) or {}
    operating_system = item.get("operatingSystem", {}) or {}

    key = str(item.get("key", "") or "").strip()
    if not key:
        print("lansweeper: skipping asset with no key: name=" + str(basic.get("name", "")))
        return None

    ips = []
    ip_address = str(basic.get("ipAddress", "") or "").strip()
    if ip_address:
        ips.append(ip_address)
    nic = network_interface(mac=str(basic.get("mac", "") or ""), ips=ips)
    netifs = [nic] if nic else []

    attrs = {
        "site_id": site_id,
        "site_name": site_name,
        "asset_key": key,
        "asset_type": basic.get("type", ""),
        "description": basic.get("description", ""),
        "user_name": basic.get("userName", ""),
        "user_domain": basic.get("userDomain", ""),
        "first_seen": basic.get("firstSeen", ""),
        "last_seen": basic.get("lastSeen", ""),
        "serial_number": custom.get("serialNumber", ""),
        "sku": custom.get("sku", ""),
        # Reported as the hardware/BIOS revision, not an OS build, so it stays
        # out of osVersion where it would contradict operatingSystem.caption.
        "firmware_version": custom.get("firmwareVersion", ""),
        "location": custom.get("location", ""),
        "department": custom.get("department", ""),
        "state_name": custom.get("stateName", ""),
        "os_product_type": operating_system.get("productType", ""),
        "url": item.get("url", ""),
    }

    software = build_software(item.get("softwares", []) or [])

    asset_params = {
        "id": "lansweeper:{}:{}".format(site_id, key),
        "hostnames": build_hostnames(basic, custom),
        "networkInterfaces": netifs,
        "software": software[:99],
        "tags": build_tags(site_name, custom.get("serialNumber", ""), custom.get("stateName", "")),        # prefix is joined to each key with separator, so this yields
        # "lansweeper_site_id" rather than "lansweeper_.site_id".
        "customAttributes": to_custom_attributes(attrs, prefix="lansweeper", separator="_"),
    }

    domain = str(basic.get("domain", "") or "").strip()
    if domain:
        asset_params["domain"] = domain
    device_type = str(basic.get("type", "") or "").strip()
    if device_type:
        asset_params["deviceType"] = device_type
    manufacturer = str(custom.get("manufacturer", "") or "").strip()
    if manufacturer:
        asset_params["manufacturer"] = manufacturer
    model = str(custom.get("model", "") or "").strip()
    if model:
        asset_params["model"] = model
    os_caption = str(operating_system.get("caption", "") or "").strip()
    if os_caption:
        asset_params["os"] = os_caption

    first_seen = parse_timestamp(basic.get("firstSeen", ""))
    if first_seen:
        asset_params["firstSeenTS"] = first_seen

    asset = ImportAsset(**asset_params)

    # lastSeenTS is settable as an attribute but is not a constructor keyword.
    last_seen = parse_timestamp(basic.get("lastSeen", ""))

    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(site_id, site_name, items):
    """Convert one page of assetResources items into ImportAsset objects."""
    assets = []
    for item in items:
        asset = build_asset(site_id, site_name, item)
        if asset:
            assets.append(asset)
    return assets


def graphql_error_message(errors):
    """Return the first GraphQL error's message as printable text.

    The spec says each entry is an object carrying `message`, but a bare
    string here would abort the script at .get, so the shape is checked.
    """
    if not errors:
        return ""
    entry = errors[0]
    if type(entry) == "dict":
        return str(entry.get("message", "") or "")[:200]
    return str(entry)[:200]


def fetch_sites(endpoint, http_options):
    """Fetch the sites the application identity code is authorized for."""
    data, err = post_json(endpoint, json={"query": SITES_QUERY}, retries=HTTP_RETRIES,
                          **http_options)
    if err:
        print("lansweeper: failed to fetch authorized sites:", err)
        return []
    data = data or {}
    errors = data.get("errors", []) or []
    if errors:
        print("lansweeper: authorized site query returned an error:",
              graphql_error_message(errors))
        return []
    authorized = (data.get("data") or {}).get("authorizedSites") or {}
    return authorized.get("sites", []) or []


def select_sites(endpoint, http_options, wanted_ids):
    """Resolve the sites to import, honoring an optional site ID allowlist."""
    sites = []
    for site in fetch_sites(endpoint, http_options):
        site_id = str(site.get("id", "") or "").strip()
        if not site_id:
            continue
        if not re_match(SITE_ID_RE, site_id):
            print("lansweeper: skipping site with unexpected id characters")
            continue
        if wanted_ids and site_id not in wanted_ids:
            continue
        sites.append({"id": site_id, "name": str(site.get("name", "") or "")})
    return sites


def fetch_and_report_site_assets(endpoint, http_options, site, page_size, include_software):
    """Fetch and stream one site's assets a page at a time so the full
    inventory is never held in memory at once."""
    site_id = site["id"]
    site_name = site["name"]
    first_query = build_assets_query(site_id, include_software, True)
    next_query = build_assets_query(site_id, include_software, False)
    reported = 0
    total = 0
    cursor = None

    p = pager("lansweeper-site-assets")
    while p.next():
        query = next_query
        pagination = {"limit": page_size, "page": "NEXT", "cursor": cursor}
        if not cursor:
            query = first_query
            pagination = {"limit": page_size, "page": "FIRST"}

        data, err = post_json(endpoint,
                              json={"query": query, "variables": {"pagination": pagination}},
                              retries=HTTP_RETRIES, **http_options)
        if err:
            print("lansweeper: failed to fetch assets for site {}: {}".format(site_id, err))
            return reported

        data = data or {}
        errors = data.get("errors", []) or []
        if errors:
            print("lansweeper: asset query returned an error for site {}: {}".format(
                site_id, graphql_error_message(errors)))
            return reported

        resources = ((data.get("data") or {}).get("site") or {}).get("assetResources") or {}
        items = resources.get("items", []) or []
        if not items:
            break
        if not total:
            total = resources.get("total", 0) or 0

        reported += report_assets(build_assets(site_id, site_name, items))

        # `next` is null once the final page has been served. A short page is
        # deliberately not treated as the end, since truncating an inventory is
        # worse than one extra request; a repeated cursor still stops the loop.
        next_cursor = (resources.get("pagination", {}) or {}).get("next", None)
        if not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor

    print("lansweeper: reported {} of {} assets from site {} ({})".format(
        reported, total, site_name, site_id))
    return reported


def main(**kwargs):
    identity_code = get_string(kwargs, "application_identity_code")
    include_software = get_bool(kwargs, "import_software", default=True)
    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    endpoint = get_url_base(kwargs, default=LANSWEEPER_API_URL) + GRAPHQL_PATH
    http_options = get_http_options(kwargs, headers={
        "Authorization": "Token " + identity_code,
        "Accept": "application/json",
    })

    wanted_ids = get_list(kwargs, "site_ids", default=[])
    sites = select_sites(endpoint, http_options, wanted_ids)
    if not sites:
        print("lansweeper: no authorized sites available to import")
        return None

    reported = 0
    for site in sites:
        reported += fetch_and_report_site_assets(endpoint, http_options, site, page_size,
                                                 include_software)

    if not reported:
        print("lansweeper: no assets retrieved")
    return None

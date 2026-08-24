# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-automox",
    "name": "Automox",
    "type": "inbound",
    "description": "Imports endpoints from the Automox platform.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Automox API URL",
            "type": "url",
            "required": False,
            "default": "https://console.automox.com",
            "placeholder": "https://console.automox.com",
            "description": "Automox's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "organization_hint",
            "label": "Organization hint",
            "type": "string",
            "required": False,
            "description": "Optional Automox organization ID or name",
        },
        {
            "key": "api_token",
            "label": "Automox API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
## Automox!

load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')
load('coerce', 'as_dict', 'as_list', 'as_text')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script. The /api prefix is applied in the code below, so
# the parameter carries only the scheme and host.
DEFAULT_AUTOMOX_URL = "https://console.automox.com"

# Every Automox listing below pages 500 rows at a time and ends when a page
# comes back empty. A console that keeps answering the same non-empty page --
# or one whose `page=` parameter is ignored -- never produces that empty page,
# so the walk needs a hard stop of its own. 2000 pages x 500 rows = 1,000,000
# records, past the device count of the largest Automox tenant and past the
# package rows those devices produce. Hitting it is logged, because a silently
# truncated import is indistinguishable from a complete one.
MAX_PAGES = 2000

# The platform rejects an asset carrying more than 99 software children, and a
# real Automox endpoint routinely reports hundreds of package rows, so the list
# is capped with a printed note rather than failing the record.
MAX_SOFTWARE_PER_ASSET = 99

def page_signature(rows):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the console re-served one
    page rather than advancing, so the walk is not making progress and every
    further request can only duplicate rows already collected."""
    if not rows:
        return "empty"
    first = rows[0]
    last = rows[-1]
    first_id = first.get("id", "") if type(first) == "dict" else ""
    last_id = last.get("id", "") if type(last) == "dict" else ""
    return "{}|{}|{}".format(len(rows), first_id, last_id)

def looks_numeric(v):
    if v == None:
        return False
    s = str(v)
    if s == "":
        return False
    return s.isdigit()

def normalize_list(decoded):
    if decoded == None:
        return []
    t = type(decoded)
    if t == "list":
        return decoded
    if t == "dict":
        if "data" in decoded and type(decoded["data"]) == "list":
            return decoded["data"]
        if "results" in decoded and type(decoded["results"]) == "list":
            return decoded["results"]
        if "items" in decoded and type(decoded["items"]) == "list":
            return decoded["items"]
        if "records" in decoded and type(decoded["records"]) == "list":
            return decoded["records"]
        # An unexpected envelope ends the walk with what was already collected
        # rather than aborting the task and losing every asset already streamed.
        print("automox: unexpected dict response (no data/results/items/records list field); treating the page as empty")
        return []
    print("automox: unexpected response type: " + t + "; treating the page as empty")
    return []

def get_orgs(base_url, http_options):
    orgs = []
    limit = 500
    capped = True
    last_signature = ""

    for page in range(0, MAX_PAGES):
        params = {"limit": str(limit), "page": str(page)}
        data, err = get_json(base_url + "/api/orgs", params=params, **http_options)

        if err:
            print("automox: failed to fetch orgs: " + err + "; continuing with the {} collected".format(len(orgs)))
            capped = False
            break

        batch = normalize_list(data)
        if not batch:
            capped = False
            break

        # A console that ignores page= re-serves the same organizations forever;
        # without this check that shape costs MAX_PAGES requests and duplicates
        # every org row MAX_PAGES times.
        signature = page_signature(batch)
        if signature == last_signature:
            print("automox: stopped reading organizations after {} pages (API returned the same page twice) with {} collected".format(
                page + 1, len(orgs)))
            capped = False
            break
        last_signature = signature

        for o in batch:
            orgs.append(o)

    if capped:
        print("automox: stopped reading organizations at the {} page ceiling with {} collected; the listing never returned an empty page, so this run is truncated".format(
            MAX_PAGES, len(orgs)))

    return orgs

def resolve_org(base_url, http_options, org_hint):
    """Resolve organization_hint to (org_id, scope_servers).

    CONFIG documents the parameter as "organization ID or name", and only the id
    form ever worked: a non-numeric value fell through to orgs[0] for the package
    read and was ignored outright by the device read, so an operator who typed
    their organization's name got a different organization's inventory with no
    indication anything had been disregarded. A name is now looked up against
    /api/orgs, and a name that matches nothing is LOGGED rather than swallowed.

    scope_servers is the id to send as `o=` on /api/servers, or None to leave the
    listing unscoped. It is None when there is no hint and when a hint could not
    be resolved, which preserves the behaviour of an unhinted run exactly: the
    device listing stays unscoped even though the package read has to name some
    organization.
    """
    if looks_numeric(org_hint):
        return str(org_hint), str(org_hint)

    orgs = get_orgs(base_url, http_options)
    if not orgs:
        print("automox: no organizations returned; software will be skipped and the device listing left unscoped")
        return None, None

    first = orgs[0] if type(orgs[0]) == "dict" else {}
    hint = str(org_hint or "").strip()
    if hint:
        wanted = hint.lower()
        for org in orgs:
            if type(org) != "dict":
                continue
            name = str(org.get("name", "") or "").strip()
            if name and name.lower() == wanted:
                oid = org.get("id", None)
                if oid != None:
                    print("automox: organization_hint '{}' resolved to org id {}".format(hint, oid))
                    return str(oid), str(oid)
        print("automox: organization_hint '{}' matched no organization by id or name; using '{}' and leaving the device listing unscoped".format(
            hint, str(first.get("name", "") or first.get("id", ""))))

    oid = first.get("id", None)
    if oid == None:
        print("automox: /orgs response missing 'id'; software will be skipped and the device listing left unscoped")
        return None, None
    return str(oid), None

def fetch_org_packages(base_url, http_options, org_id):
    url = base_url + "/api/orgs/" + str(org_id) + "/packages"
    packages = []
    limit = 500
    capped = True

    for page in range(0, MAX_PAGES):
        params = {"limit": str(limit), "page": str(page), "o": str(org_id)}
        data, err = get_json(url, params=params, **http_options)

        if err:
            print("automox: failed to fetch org packages: " + err + "; software will be incomplete for this run")
            capped = False
            break

        batch = normalize_list(data)
        if not batch:
            capped = False
            break

        for p in batch:
            packages.append(p)

    if capped:
        print("automox: stopped reading org packages at the {} page ceiling with {} collected; software will be incomplete for this run".format(
            MAX_PAGES, len(packages)))

    return packages

def index_software_by_server(packages):
    by_server = {}

    for soft in packages:
        if type(soft) != "dict":
            continue
        sid = soft.get("server_id", None)
        if sid == None:
            continue

        sw = Software(
            id=str(soft.get("id", "")),
            installedFrom=str(soft.get("repo", "")),
            product=str(soft.get("display_name", "")),
            version=str(soft.get("version", "")),
            customAttributes=to_custom_attributes({
                "server_id": soft.get("server_id"),
                "package_id": soft.get("package_id"),
                "software_id": soft.get("software_id"),
                "installed": soft.get("installed"),
                "ignored": soft.get("ignored"),
                "group_ignored": soft.get("group_ignored"),
                "deferred_until": soft.get("deferred_until"),
                "group_deferred_until": soft.get("group_deferred_until"),
                "name": soft.get("name"),
                "cves": soft.get("cves"),
                "cve_score": soft.get("cve_score"),
                "agent_severity": soft.get("agent_severity"),
                "severity": soft.get("severity"),
                "package_version_id": soft.get("package_version_id"),
                "os_name": soft.get("os_name"),
                "os_version": soft.get("os_version"),
                "os_version_id": soft.get("os_version_id"),
                "create_time": soft.get("create_time"),
                "requires_reboot": soft.get("requires_reboot"),
                "patch_classification_category_id": soft.get("patch_classification_category_id"),
                "patch_scope": soft.get("patch_scope"),
                "is_uninstallable": soft.get("is_uninstallable"),
                "secondary_id": soft.get("secondary_id"),
                "is_managed": soft.get("is_managed"),
                "impact": soft.get("impact"),
                "organization_id": soft.get("organization_id"),
            }),
        )

        key = str(sid)
        if key not in by_server:
            by_server[key] = []
        by_server[key].append(sw)

    return by_server

def build_network_interfaces_from_device(device):
    details = device.get("details", device.get("detail", {}))
    if type(details) == "dict":
        nics = details.get("NICS", None)
        if type(nics) == "list" and nics:
            out = []
            for nic in nics[:99]:
                if type(nic) != "dict":
                    continue
                mac = as_text(nic.get("MAC"))
                ips = [as_text(ip) for ip in as_list(nic.get("IPS")) if as_text(ip)]
                # network_interface returns None when neither the addresses nor
                # the MAC survive parsing -- a NICS entry with an empty IPS list
                # and a null or unparseable MAC does that. Appending None makes
                # ImportAsset abort the entire run with "network_interfaces must
                # be an iterable of NetworkInterface objects", losing every asset
                # already reported and every page still to come.
                nic_iface = network_interface(ips=ips, mac=mac)
                if nic_iface:
                    out.append(nic_iface)
            if out:
                return out

    # Reached when the device has no NICS, and also when every NIC above was
    # dropped as unusable. A device with no addresses either yields None here for
    # the same reason, so this needs the same guard; returning no interfaces
    # leaves the asset to correlate on its hostname. as_list defends the
    # present-but-null shape: `"ip_addrs": null` is not a device with no
    # addresses, it is None + None, which aborts the whole run.
    ips = []
    for ip in as_list(device.get("ip_addrs")) + as_list(device.get("ip_addrs_private")):
        candidate = as_text(ip)
        if candidate:
            ips.append(candidate)
    iface = network_interface(ips=ips, mac="")
    if iface:
        return [iface]
    return []

def build_device_asset(device, sw_by_server):
    if type(device) != "dict":
        print("automox: skipping non-dict device record: " + type(device))
        return None
    device_id = device.get("id")
    if not device_id:
        print("automox: skipping device with no id: name=" + str(device.get("name", "")))
        return None

    custom_attrs = {
        "os_version": as_text(device.get("os_version")),
        "os_name": as_text(device.get("os_name")),
        "os_family": as_text(device.get("os_family")),
        "agent_version": as_text(device.get("agent_version")),
        "compliant": str(device.get("compliant", "")),
        "last_logged_in_user": as_text(device.get("last_logged_in_user")),
        "serial_number": as_text(device.get("serial_number")),
        # as_dict defends the present-but-null shape: `"status": null` is a
        # device row the API really emits, and None.get aborts the whole run.
        "agent_status": as_text(as_dict(device.get("status")).get("agent_status")),
    }

    software = sw_by_server.get(str(device_id), [])
    if len(software) > MAX_SOFTWARE_PER_ASSET:
        print("automox: device {} reports {} software entries; importing the first {}".format(
            device_id, len(software), MAX_SOFTWARE_PER_ASSET))
        software = software[:MAX_SOFTWARE_PER_ASSET]

    return ImportAsset(
        id=str(device_id),
        networkInterfaces=build_network_interfaces_from_device(device),
        hostnames=[as_text(device.get("name"))],
        os_version=as_text(device.get("os_version")),
        os=as_text(device.get("os_family")) + " " + as_text(device.get("os_name")),
        software=software,
        customAttributes=to_custom_attributes(custom_attrs),
        # trust_os / trust_os_version are meaningful: Automox reports the OS
        # from an agent running on the host, which is better evidence than a
        # network fingerprint, and both fields are set above.
        trust_os=True,
        trust_os_version=True,
        # trust_device_type is NOT set, and no deviceType is set either.
        #
        # The flag used to be here and could never do anything.
        # IdentifyTypeFromCustomIntegration reads the trust flag only after a
        # non-empty type -- `if candidate.PlatformType == "" { continue }` comes
        # first -- so a trust flag with no type beside it is discarded before the
        # flag is ever consulted. It read as a deliberate decision to override
        # runZero's fingerprint while overriding nothing.
        #
        # There is no type to set. Automox is a patch-management agent: /api/servers
        # reports os_family, os_name, os_version, and hardware detail, and nothing
        # naming a chassis or a role. The manufacturer and model in `detail` are
        # what runZero fingerprints the type from for itself, which is the right
        # answer here rather than a guess from the OS family.
    )

def stream_device_assets(base_url, http_options, scope_org_id, sw_by_server):
    """Paginate Automox devices, building and streaming each page of assets via
    report_assets so the full device set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    page = 0
    limit = 500
    use_o = scope_org_id != None
    capped = True

    # MAX_PAGES + 1 iterations rather than MAX_PAGES: the unscoped retry below
    # restarts the walk at page 0 without consuming a page of the listing, so it
    # gets one iteration of its own. The ceiling is checked against the page
    # number rather than the iteration count so that retry cannot spend a page.
    for _attempt in range(0, MAX_PAGES + 1):
        if page >= MAX_PAGES:
            break

        params = {"limit": str(limit), "page": str(page), "include_details": "1"}
        if use_o:
            params["o"] = str(scope_org_id)

        data, err = get_json(base_url + "/api/servers", params=params, **http_options)

        if err and err.startswith("status 404") and use_o:
            print("automox: /api/servers answered 404 for org {}; retrying the listing unscoped".format(scope_org_id))
            use_o = False
            reported = 0
            page = 0
            continue

        if err:
            print("automox: failed to fetch devices: " + err + "; ending the walk with {} assets reported".format(reported))
            capped = False
            break

        batch = normalize_list(data)
        if not batch:
            capped = False
            break

        page_assets = []
        for device in batch:
            asset = build_device_asset(device, sw_by_server)
            if asset:
                page_assets.append(asset)
        reported += report_assets(page_assets)

        page = page + 1

    if capped:
        print("automox: stopped reading devices at the {} page ceiling with {} reported; the listing never returned an empty page, so this run is truncated".format(
            MAX_PAGES, reported))

    return reported

def build_assets(base_url, api_token, org_hint, config_kwargs):
    headers = {"Authorization": "Bearer " + api_token, "Content-Type": "application/json"}
    http_options = get_http_options(config_kwargs, headers=headers)

    org_id, scope_org_id = resolve_org(base_url, http_options, org_hint)

    # A run that could not resolve any organization still imports devices; it
    # just cannot read the package table, so those assets carry no software.
    sw_by_server = {}
    if org_id != None:
        packages = fetch_org_packages(base_url, http_options, org_id)
        sw_by_server = index_software_by_server(packages)

    return stream_device_assets(base_url, http_options, scope_org_id, sw_by_server)

def main(**kwargs):
    org_hint = kwargs.get("organization_hint", None)
    api_token = kwargs.get("api_token", None)
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get("url") or DEFAULT_AUTOMOX_URL).rstrip("/")

    if not api_token:
        print("automox: missing api_token (Automox API token); nothing imported")
        return None

    # Assets are streamed page-by-page via report_assets in build_assets.
    build_assets(base_url, api_token, org_hint, kwargs)
    return None

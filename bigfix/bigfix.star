# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-bigfix",
    "name": "HCL BigFix",
    "type": "inbound",
    "description": "Imports managed endpoints and their reported hardware, network, and software inventory from an HCL BigFix root server.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # The computer id is authoritative inside the deployment, while an
    # agent-reported MAC list, DHCP address, and console name all churn
    # independently of it.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "params": [
        {
            "key": "url",
            "label": "BigFix root server URL",
            "type": "url",
            "required": True,
            "placeholder": "https://bes.example.com:52311",
            "description": "Base URL of the BES root server REST API, including the port. The default port is 52311 and the /api path is appended automatically.",
        },
        {
            "key": "username",
            "label": "Console username",
            "type": "string",
            "required": True,
            "description": "BigFix console operator with read access to the computers that should be imported. A Master Operator sees the whole deployment.",
        },
        {
            "key": "password",
            "label": "Console password",
            "type": "secret",
            "required": True,
            "description": "Password for the console operator. The REST API authenticates with HTTP Basic.",
        },
        {
            "key": "properties",
            "label": "Retrieved properties",
            "type": "string",
            "required": False,
            "default": "MAC Addresses,Serial Number,Computer Manufacturer,Computer Model,CPU,RAM,BIOS,Device Type,Agent Version,User Name,Active Directory Path,Subnet Address,License Type,Relay",
            "description": "Comma-separated BigFix property names to read for every computer. Names are matched exactly as they appear in the console; a property that does not exist in the deployment simply returns nothing. Property names containing a comma or a double quote cannot be used.",
        },
        {
            "key": "software_property",
            "label": "Installed software property",
            "type": "string",
            "required": False,
            "description": "Optional name of a multi-value BigFix property that reports installed applications, one value per application, for example a custom analysis built on 'names of applications'. Leave blank to skip software entirely. Enabling this makes every query substantially more expensive on the root server.",
        },
        {
            "key": "page_size",
            "label": "Computers per query",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 5000,
            "description": "How many computers each session relevance query covers. Lower this if the root server times out on large deployments.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'ip_address', 'ip_in_network', 'network_interface', 'routable_ip')
load('http', http_get='get', 'url_encode', 'url_parse', 'basic')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int')
load('xml', xml_parse='parse')
load('time', 'now', 'parse_time', 'parse_ts')

load('coerce', 'as_text')
VENDOR = "bigfix"
ATTR_PREFIX = "bigfix"
ATTR_SEPARATOR = "_"        # to_custom_attributes joins the prefix with the separator

QUERY_PATH = "/api/query"

DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 5000
# Mirrors the CONFIG default so a credential saved before the field existed
# still reads the same inventory.
DEFAULT_PROPERTIES = ("MAC Addresses,Serial Number,Computer Manufacturer,Computer Model,CPU,RAM," +
                      "BIOS,Device Type,Agent Version,User Name,Active Directory Path," +
                      "Subnet Address,License Type,Relay")
MAX_COMPUTERS = 500000
MAX_RANGES = 100000
MAX_PROPERTIES = 25
MAX_CHILDREN = 99
MAX_VALUES = 500

# Separator folded into the relevance expression so a multi-value property
# result comes back as one <Answer>. Property values are free text, so the
# marker is deliberately something no inventory string produces.
VALUE_SEPARATOR = "~|~"

DIGITS = "0123456789"
MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
          "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
# BigFix reports the OS as a short platform code followed by a build number,
# for example "Win2016 10.0.14393.6796". The code is expanded so the imported
# os field reads the same way it does everywhere else in runZero; the untouched
# string is kept as the bigfix_os custom attribute either way.
OS_NAMES = {
    "win2000": "Windows 2000",
    "winxp": "Windows XP",
    "win2003": "Windows Server 2003",
    "winvista": "Windows Vista",
    "win2008": "Windows Server 2008",
    "win2008r2": "Windows Server 2008 R2",
    "win7": "Windows 7",
    "win8": "Windows 8",
    "win8.1": "Windows 8.1",
    "win2012": "Windows Server 2012",
    "win2012r2": "Windows Server 2012 R2",
    "win10": "Windows 10",
    "win11": "Windows 11",
    "win2016": "Windows Server 2016",
    "win2019": "Windows Server 2019",
    "win2022": "Windows Server 2022",
    "win2025": "Windows Server 2025",
}

# Only the "Device Type" and "Computer Type" values with a faithful runZero
# equivalent are mapped; everything else survives as a custom attribute.
DEVICE_TYPES = {
    "server": "Server",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "portable": "Laptop",
    "desktop": "Desktop",
    "workstation": "Desktop",
    "mobile": "Mobile Device",
}

# Substrings matched against a lower-cased property name to decide which
# retrieved property feeds which runZero field. Deployments name these
# properties themselves, so the match is on meaning rather than an exact name.
MAC_HINTS = ["mac address"]
IP_HINTS = ["ip address"]
SERIAL_HINTS = ["serial number", "serial no"]
MANUFACTURER_HINTS = ["manufacturer", "vendor"]
MODEL_HINTS = ["model"]
DEVICE_TYPE_HINTS = ["device type", "computer type"]

# The six leading tuple members of every computer query, in order. These are
# native <bes computer> inspectors rather than retrieved properties, so they
# are present on any BigFix release. Each optional one is guarded: a tuple
# member that evaluates to nothing drops the whole row for that computer.
CORE_TERMS = [
    'id of it as string',
    '(if (exists name of it) then (name of it) else "")',
    '(if (exists hostname of it) then (hostname of it) else "")',
    '(if (exists operating system of it) then (operating system of it) else "")',
    '(if (exists ip address of it) then (ip address of it as string) else "")',
    '(if (exists last report time of it) then (last report time of it as string) else "")',
]
CORE_FIELDS = ["id", "name", "dns_name", "os", "ip_address", "last_report_time"]
def _to_int(value):
    """Convert an all-digit string to an int, or -1 when it is not numeric."""
    text = as_text(value).strip()
    if not text or len(text) > 18:
        return -1
    for index in range(len(text)):
        if text[index] not in DIGITS:
            return -1
    return int(text)


def _is_version(text):
    """Report whether a token looks like a dotted release or build number."""
    if "." not in text or text.startswith(".") or text.endswith("."):
        return False
    for index in range(len(text)):
        if text[index] != "." and text[index] not in DIGITS:
            return False
    return True


def _pad2(value):
    """Render a small non-negative int as two digits."""
    return "0" + str(value) if value < 10 else str(value)


def _attr_key(name):
    """Fold a BigFix property name into a custom attribute key."""
    key = ""
    for index in range(len(name)):
        char = name[index].lower()
        if char in DIGITS or (char >= "a" and char <= "z"):
            key += char
        elif key and not key.endswith("_"):
            key += "_"
    if key.endswith("_"):
        key = key[:-1]
    return key


def _matches(name, hints):
    """Report whether a lower-cased property name contains any of the hints."""
    for hint in hints:
        if hint in name:
            return True
    return False
def _split_os(value):
    """Split a BigFix OS string into an OS name and a version.

    Only a trailing dotted build number is taken as the version. Distribution
    strings such as "Linux Red Hat Enterprise Linux Server release 7.9 (Maipo)"
    end in a codename, and pulling "7.9" out of the middle would leave a
    nonsense OS name behind, so those are imported whole.
    """
    text = value.strip()
    if not text:
        return "", ""
    parts = text.split(" ")
    version = ""
    if len(parts) > 1 and _is_version(parts[-1]):
        version = parts[-1]
        parts = parts[:-1]
    name = " ".join(parts).strip()
    return OS_NAMES.get(name.lower(), name), version


def _split_values(value):
    """Split one joined multi-value property result back into its values."""
    values = []
    for item in as_text(value).split(VALUE_SEPARATOR):
        item = item.strip()
        if item and item not in values:
            values.append(item)
        if len(values) >= MAX_VALUES:
            break
    return values


def _property_term(name):
    """Build the tuple member that reads one named property for a computer.

    The empty string is appended to the value list so the member always
    evaluates to exactly one answer. A property name that is not defined in the
    deployment otherwise yields nothing, and a tuple member that yields nothing
    silently removes that computer's entire row from the result.
    """
    return 'concatenation "{}" of (values of results (it, bes property "{}") ; "")'.format(
        VALUE_SEPARATOR, name)


def build_relevance(properties, low, high):
    """Build the session relevance for one range of computer ids."""
    terms = [] + CORE_TERMS
    for name in properties:
        terms.append(_property_term(name))
    return "({}) of bes computers whose (id of it >= {} and id of it <= {})".format(
        ", ".join(terms), low, high)


def build_software(scope, computer_id, address, entries):
    """Convert the values of the configured software property into Software.

    BigFix publishes no CPE for an inventoried application, so cpe23 is left
    unset rather than synthesized: Software.cpe23 only accepts the CPE 2.2
    application URI binding and a wrong guess fails the whole record.
    """
    software = []
    seen = {}
    for entry in entries:
        product = entry.strip()
        if not product:
            continue
        version = ""
        if product.endswith(")") and "(" in product:
            head = product[:product.rfind("(")].strip()
            tail = product[product.rfind("(") + 1:-1].strip()
            if head and _is_version(tail):
                product = head
                version = tail
        if not version:
            parts = product.split(" ")
            if len(parts) > 1 and _is_version(parts[-1]):
                version = parts[-1]
                product = " ".join(parts[:-1]).strip()
        if not product:
            continue
        key = "{}:{}".format(product.lower(), version.lower())
        if key in seen:
            continue
        seen[key] = True

        params = {
            "id": "{}:{}:{}:software:{}".format(VENDOR, scope, computer_id, key)[:255],
            "product": product,
            # An inventoried application has no socket of its own.
            "serviceAddress": address if address else "127.0.0.1",
        }
        if version:
            params["version"] = version
        software.append(Software(**params))
        if len(software) >= MAX_CHILDREN:
            break
    return software


def build_asset(ctx, record):
    """Convert one computer's query row into a runZero asset."""
    computer_id = record["id"]
    properties = record["properties"]

    macs = []
    addresses = [record.get("ip_address", "")]
    serial = ""
    manufacturer = ""
    model = ""
    device_type = ""
    attrs = {"computer_id": computer_id, "root_server": ctx["host"]}
    for field in CORE_FIELDS:
        if field != "id" and record.get(field):
            attrs[field] = record[field]

    for name in ctx["properties"]:
        values = _split_values(properties.get(name, ""))
        if not values:
            continue
        if name == ctx["software_property"]:
            continue
        attrs[_attr_key(name)] = values
        lowered = name.lower()
        if _matches(lowered, MAC_HINTS):
            # A single value can itself hold several addresses when the
            # analysis concatenates them.
            for value in values:
                for part in value.replace(",", " ").replace(";", " ").split(" "):
                    part = part.strip()
                    if part and part not in macs:
                        macs.append(part)
        elif _matches(lowered, IP_HINTS):
            for value in values:
                for part in value.replace(",", " ").replace(";", " ").split(" "):
                    addresses.append(part.strip())
        elif _matches(lowered, SERIAL_HINTS) and not serial:
            serial = values[0]
        elif _matches(lowered, MANUFACTURER_HINTS) and not manufacturer:
            manufacturer = values[0]
        elif _matches(lowered, MODEL_HINTS) and not model:
            model = values[0]
        elif _matches(lowered, DEVICE_TYPE_HINTS) and not device_type:
            device_type = DEVICE_TYPES.get(values[0].strip().lower(), "")

    # The native IP Address inspector reports one address, so any configured
    # address property is folded into the same list. An agent that cannot see a
    # usable adapter reports 127.0.0.1, which would merge every such host onto
    # one asset, so the raw list is kept as an attribute and only routable
    # addresses reach an interface.
    ips = []
    for value in addresses:
        routable = routable_ip(value)
        if routable and routable not in ips:
            ips.append(routable)

    # BigFix reports MAC addresses as a flat list with no adapter pairing, so
    # the addresses are attached to the first interface and every remaining MAC
    # becomes an interface of its own rather than being dropped.
    netifs = []
    if macs:
        for index in range(len(macs[:MAX_CHILDREN])):
            nic = network_interface(mac=macs[index], ips=ips if index == 0 else [])
            if nic:
                netifs.append(nic)
    if not netifs:
        nic = network_interface(ips=ips)
        if nic:
            netifs.append(nic)

    address = ips[0] if ips else ""
    software = []
    if ctx["software_property"]:
        software = build_software(ctx["scope"], computer_id, address,
                                  _split_values(properties.get(ctx["software_property"], "")))
        attrs["software_count"] = len(software)

    tags = [VENDOR]
    if serial:
        tags.append("serial:" + serial)

    params = {
        "id": "{}:{}:{}".format(VENDOR, ctx["scope"], computer_id),
        "hostnames": [record.get("name", ""), record.get("dns_name", "")],
        "networkInterfaces": netifs,
        "software": software[:MAX_CHILDREN],
        "tags": tags,    }
    os_name, os_version = _split_os(record.get("os", ""))
    if os_name:
        params["os"] = os_name
    if os_version:
        params["osVersion"] = os_version
    if manufacturer:
        params["manufacturer"] = manufacturer
    if model:
        params["model"] = model
    if device_type:
        params["deviceType"] = device_type
    params["customAttributes"] = to_custom_attributes(attrs, prefix=ATTR_PREFIX,
                                                      separator=ATTR_SEPARATOR)
    asset = ImportAsset(**params)

    # Last Report Time is the last agent check-in the root server recorded,
    # which is the closest thing BigFix holds to an observation of the device.
    last_seen = parse_ts(record.get("last_report_time", ""))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def build_assets(ctx, records):
    """Convert one range of computer rows into runZero assets."""
    assets = []
    for record in records:
        if not record["id"]:
            print("bigfix: skipping computer row with no id")
            continue
        assets.append(build_asset(ctx, record))
    return assets


def run_query(ctx, relevance):
    """Run one session relevance query and return (rows, err).

    Each row is the list of <Answer> strings for one <Tuple>. The relevance is
    encoded once and appended to the URL rather than passed as params, because
    params re-encodes a space as "+" while the query string built here keeps the
    %20 form the BigFix documentation uses.
    """
    query = url_encode({"output": "xml", "relevance": relevance}).replace("+", "%20")
    resp = http_get(ctx["base_url"] + QUERY_PATH + "?" + query, **ctx["http_options"])
    if resp == None:
        return [], "no response from the root server"
    if resp.status_code == 401 or resp.status_code == 403:
        return [], "status {}: check the console username and password".format(resp.status_code)
    if resp.status_code != 200:
        return [], "status {}".format(resp.status_code)

    doc = xml_parse(resp.body)
    if doc == None or doc.tag != "BESAPI":
        return [], "the response was not a BESAPI document"
    failure = doc.find("Query/Error")
    if failure != None:
        return [], "relevance error: " + as_text(failure.text).strip()

    rows = []
    for entry in doc.find_all("Query/Result/Tuple"):
        rows.append([as_text(answer.text) for answer in entry.find_all("Answer")])
    if not rows:
        # A one-member relevance is not a tuple, so its answers sit directly
        # under <Result>.
        for answer in doc.find_all("Query/Result/Answer"):
            rows.append([as_text(answer.text)])
    return rows, None


def fetch_computer_ids(ctx):
    """Read every computer id in the deployment as a sorted list of ints.

    The census is deliberately its own query. It is the cheapest relevance the
    root server can answer, and the ids it returns are what the per-range
    queries below are cut against, so a large deployment is never asked for in
    one response.
    """
    rows, err = run_query(ctx, "(id of it as string) of bes computers")
    if err:
        print("bigfix: failed to list computers:", err)
        return []
    ids = []
    skipped = 0
    for row in rows:
        value = _to_int(row[0]) if row else -1
        if value < 0:
            skipped += 1
            continue
        ids.append(value)
        if len(ids) >= MAX_COMPUTERS:
            print("bigfix: computer list capped at {} records".format(MAX_COMPUTERS))
            break
    if skipped:
        print("bigfix: skipped {} computers with an unreadable id".format(skipped))
    return sorted(ids)


def build_records(ctx, rows, properties):
    """Turn the answer rows of one range query into per-computer records."""
    width = len(CORE_FIELDS) + len(properties)
    records = []
    malformed = 0
    for row in rows:
        if len(row) != width:
            malformed += 1
            continue
        record = {"properties": {}}
        for index in range(len(CORE_FIELDS)):
            record[CORE_FIELDS[index]] = row[index].strip()
        for index in range(len(properties)):
            record["properties"][properties[index]] = row[len(CORE_FIELDS) + index]
        records.append(record)
    if malformed:
        print("bigfix: skipped {} rows that did not match the requested tuple width".format(malformed))
    return records


def fetch_range(ctx, low, high):
    """Fetch one range of computers, falling back to the core relevance once if
    the configured property list is what the root server rejected.

    Raw http.get takes no retry budget, so a query that fails is not retried.
    The fallback keeps a deployment that is missing one configured property from
    losing its whole inventory, and every other range is still attempted after a
    range that fails outright.
    """
    if ctx["properties"]:
        rows, err = run_query(ctx, build_relevance(ctx["properties"], low, high))
        if not err:
            return build_records(ctx, rows, ctx["properties"]), True
        print("bigfix: query for computers {}-{} failed: {}".format(low, high, err))

        rows, err = run_query(ctx, build_relevance([], low, high))
        if err:
            print("bigfix: core query for computers {}-{} failed: {}".format(low, high, err))
            return [], False
        print("bigfix: dropping the configured properties for the rest of the run")
        ctx["properties"] = []
        ctx["software_property"] = ""
        return build_records(ctx, rows, []), True

    rows, err = run_query(ctx, build_relevance([], low, high))
    if err:
        print("bigfix: core query for computers {}-{} failed: {}".format(low, high, err))
        return [], False
    return build_records(ctx, rows, []), True


def fetch_and_report_computers(ctx, ids):
    """Fetch and stream computers one id range at a time so the whole
    deployment is never held in memory at once."""
    reported = 0
    ranges = 0
    failed = 0
    index = 0
    for _range in range(1, MAX_RANGES + 1):
        if index >= len(ids):
            break
        end = index + ctx["page_size"] - 1
        if end >= len(ids):
            end = len(ids) - 1
        ranges += 1
        records, ok = fetch_range(ctx, ids[index], ids[end])
        if ok:
            reported += report_assets(build_assets(ctx, records))
        else:
            failed += 1
        index = end + 1

    if failed:
        print("bigfix: {} of {} id ranges could not be read".format(failed, ranges))
    print("bigfix: reported {} assets from {}".format(reported, ctx["host"]))
    return reported


def main(**kwargs):
    base_url = get_url_base(kwargs)
    parsed = url_parse(base_url)
    host = parsed.hostname.lower() if parsed and parsed.hostname else ""
    if not host:
        print("bigfix: could not determine the root server host from the configured URL")
        return None

    page_size = get_int(kwargs, "page_size", default=DEFAULT_PAGE_SIZE)
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE

    software_property = get_string(kwargs, "software_property", default="").strip()
    properties = []
    for name in get_string(kwargs, "properties", default=DEFAULT_PROPERTIES).split(","):
        name = name.strip()
        # A double quote or a newline would break out of the relevance string
        # literal the name is embedded in.
        if not name or '"' in name or "\n" in name:
            continue
        if name not in properties:
            properties.append(name)
        if len(properties) >= MAX_PROPERTIES:
            break
    if software_property and '"' not in software_property and software_property not in properties:
        properties.append(software_property)

    ctx = {
        "base_url": base_url,
        "host": host,
        "scope": host,
        "properties": properties,
        "software_property": software_property,
        "page_size": page_size,
        "http_options": get_http_options(kwargs, headers={
            "Accept": "application/xml",
            "Authorization": basic(get_string(kwargs, "username"), get_string(kwargs, "password")),
        }),
    }

    ids = fetch_computer_ids(ctx)
    if not ids:
        print("bigfix: no computers retrieved")
        return None

    reported = fetch_and_report_computers(ctx, ids)
    if not reported:
        print("bigfix: no assets retrieved")
    return None

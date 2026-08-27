# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-forescout-rem",
    "name": "Forescout Risk and Exposure Management",
    "type": "inbound",
    "description": "Imports the cross-product asset inventory and risk scores from Forescout Risk and Exposure Management (eyeFocus).",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # Nothing states whether a REM id survives re-addressing or can be
    # recycled; Forescout publishes no schema for this API. A foreign-id match
    # cannot be vetoed by a conflicting MAC, IP, or name, so a recycled id
    # would merge unrelated devices with nothing able to stop it. Correlate on
    # the addresses instead. Cost: a record with none of the three is skipped.
    # See README "Asset identity".
    "matchBehavior": "no-id-match no-id-break",
    # This endpoint has no page cursor: coverage comes from splitting the
    # search window, so maxPages bounds how many windows one task may query.
    # 5000 is roughly the most a task can walk inside the Console's one-hour
    # wall; running out is reported rather than passed off as a full import.
    "maxPages": 5000,
    "params": [
        {
            "key": "url",
            "label": "Forescout Cloud API endpoint URL",
            "type": "url",
            "required": True,
            "placeholder": "https://demo.cloud.forescout.com",
            "description": "The API endpoint URL the console prints beneath the generated Risk Sharing API key. The /api/data-exchange/v3 path is appended automatically.",
        },
        {
            "key": "api_key",
            "label": "Risk Sharing API key",
            "type": "secret",
            "required": True,
            "description": "API key generated under Administration > Integrations with the key type Risk Sharing API. The Health Alerts and Log Query key types do not return assets.",
        },
        {
            "key": "sync_strategy",
            "label": "Sync strategy",
            "type": "enum",
            "required": False,
            "default": "incremental",
            "options": ["incremental", "full"],
            "description": "incremental searches the last_seen window covered by the lookback below. full searches a fixed 10-year window, longer than Forescout Cloud has existed, and costs many more requests. It reaches every asset the tenant holds only if the search budget lasts; on a large tenant it can run out, and the shortfall is counted and reported rather than passed off as a complete import.",
        },
        {
            "key": "lookback_days",
            "label": "Lookback window (days)",
            "type": "int",
            "required": False,
            "default": 7,
            "min": 1,
            "max": 3650,
            "description": "How far back the incremental last_seen window reaches. Set it to at least the task interval, because this API has no server-side checkpoint and an asset quiet for longer than the window is not returned at all.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'Software', 'to_custom_attributes')
load('net', 'network_interface', 'routable_ips', 'clean_hostnames')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string', 'get_int')
load('coerce', 'as_text', 'as_dict', 'as_int', 'as_list', 'dicts', 'dedupe')
load('time', 'now', 'from_timestamp', 'parse_ts')

SEARCH_PATH = "/api/data-exchange/v3/rem-asset-search"

# The API renders datetimes to millisecond precision and answers HTTP 400 when
# `from` equals `to`, so every bound is built in whole milliseconds.
ISO_LAYOUT = "2006-01-02T15:04:05.000Z"
MS_PER_DAY = 86400000

SORT_ORDER = "ASCENDING"
ORDER_BY_RISK = "risk_score"
ORDER_BY_LAST_SEEN = "last_seen"

# Risk scores run 0.0 to 10.0 with one decimal place, so a band is carried as
# whole tenths and a single tenth is the finest the API can distinguish.
RISK_MAX_TENTHS = 100

# A capped window is narrowed on the risk axis first and then on the time axis,
# and one depth counter is shared by both. Seven halvings reduce the 0-100
# tenths of the risk scale to a single tenth, so that many are spent before the
# time axis is reached at all.
RISK_SPLIT_DEPTH = 7

# The time allowance is an absolute floor rather than a fixed halving count,
# because a count tuned for one window size is wrong for every other: the five
# halvings that suit the 7-day default bottom the 10-year full sweep out at a
# 114-day slice. Keep halving until a slice is no longer than this.
MIN_TIME_SLICE_MS = 21600000

# Backstop on the derived allowance, not a budget: maxPages is what bounds a
# run. The legal window range (1 to 3650 days) never reaches this.
MAX_TIME_SPLIT_DEPTH = 20

# A window narrower than this cannot be halved into two windows that each still
# satisfy from < to.
MIN_WINDOW_MS = 2

FULL_WINDOW_DAYS = 3650
DEFAULT_LOOKBACK_DAYS = 7

# mac_addresses is a list, but a REM asset aggregates sources rather than
# interfaces; this only stops a malformed array from fanning out interfaces.
MAX_INTERFACES = 8

ATTR_PREFIX = "forescout_rem"
ATTR_SEPARATOR = "_"   # to_custom_attributes joins the prefix with the separator

# Entity fields copied verbatim into custom attributes, vendor name to attribute
# name. rem_vendor, rem_os and rem_model are absent because they are mapped onto
# first-class asset fields instead.
ENTITY_ATTR_FIELDS = {
    "rem_category": "category",
    "rem_function": "function",
    "rem_firmware": "firmware",
    "risk_score": "risk_score",
    "risk_severity": "risk_severity",
    "risk_device_criticality": "device_criticality",
    "last_seen": "last_seen",
    "last_seen_online": "last_seen_online",
}

def _scope(base_url):
    """Return the instance hostname used to namespace asset ids.

    A REM asset id is meaningful only inside one Forescout Cloud tenant, and
    the tenant is the instance host, so the host is the required scope. The
    port is deliberately excluded: it is not part of the tenant's identity, and
    including it would re-key an entire estate the day the endpoint moved."""
    return base_url.split("://")[-1].split("/")[0].split(":")[0].lower()

def _iso(millis):
    """Render epoch milliseconds as the ISO 8601 UTC string the API takes."""
    stamp = from_timestamp(millis // 1000, (millis % 1000) * 1000000)
    return stamp.in_location("UTC").format(ISO_LAYOUT)

def _decimal(tenths):
    """Render a risk bound held in tenths as the decimal string the API takes.

    Starlark's str.format rejects width and precision specs, and the value is a
    single digit after the point by construction, so the two halves are
    formatted separately."""
    return "{}.{}".format(tenths // 10, tenths % 10)

def _max_split_depth(span_ms):
    """Depth allowance for a search window of this width.

    The risk axis costs a fixed seven halvings whatever the window is, so only
    the time allowance scales: enough halvings to bring the window down to
    MIN_TIME_SLICE_MS."""
    depth = 0
    span = span_ms
    for _ in range(MAX_TIME_SPLIT_DEPTH):
        if span <= MIN_TIME_SLICE_MS:
            break
        span = span // 2
        depth += 1
    return RISK_SPLIT_DEPTH + depth

def _window(from_ms, to_ms, low, high, depth, banded=True):
    """One unit of work: a last_seen range and, optionally, a risk band."""
    return {
        "from": from_ms,
        "to": to_ms,
        "low": low,
        "high": high,
        "depth": depth,
        "banded": banded,
    }

def _label(window):
    """Describe a window for a log line, without dumping the whole dict."""
    if not window["banded"]:
        return "unbanded"
    return "risk {} to {}".format(_decimal(window["low"]), _decimal(window["high"]))

def _split(window, max_depth):
    """Return the two narrower windows that replace a truncated one, or [].

    Risk banding is the primary axis because assets are stamped in last_seen
    bursts no datetime split can separate, while their risk scores still spread
    across the scale. Time is the fallback, reached once a band has narrowed to
    a single tenth. An empty result means the remainder is lost."""
    if window["depth"] >= max_depth:
        return []
    depth = window["depth"] + 1

    low = window["low"]
    high = window["high"]
    # An unbanded window cannot be narrowed on the risk axis at all: the whole
    # point of it is that it carries no risk bound, because sending either one
    # makes the API drop score-0 assets. Narrow it on time instead.
    if not window["banded"] and high > low:
        span = window["to"] - window["from"]
        if span < MIN_WINDOW_MS:
            return []
        middle = window["from"] + span // 2
        return [
            _window(window["from"], middle, low, high, depth, banded=False),
            _window(middle, window["to"], low, high, depth, banded=False),
        ]

    if high > low:
        middle = (low + high) // 2
        # Tenths are the API's own precision, so [low, middle] and
        # [middle + 1, high] are disjoint and together cover the parent.
        return [
            _window(window["from"], window["to"], low, middle, depth),
            _window(window["from"], window["to"], middle + 1, high, depth),
        ]

    span = window["to"] - window["from"]
    if span < MIN_WINDOW_MS:
        return []
    middle = window["from"] + span // 2
    # The halves share their boundary millisecond rather than skipping it,
    # because both bounds read as inclusive and a gap would drop assets. The
    # overlap costs one duplicate entity, which the id de-duplication absorbs.
    return [
        _window(window["from"], middle, low, high, depth),
        _window(middle, window["to"], low, high, depth),
    ]

def _params(window):
    """Build the query for one window.

    The unbanded sweep orders by risk_score ASCENDING so its page starts at the
    bottom of the scale, which is what captures the zero-score assets. Banded
    sweeps order along last_seen, the axis their fallback split works on, which
    keeps a truncated page contiguous in it."""
    params = {
        "from_date_time_iso_utc": _iso(window["from"]),
        "to_date_time_iso_utc": _iso(window["to"]),
        "sort_order": SORT_ORDER,
    }
    if window["banded"]:
        params["order_by"] = ORDER_BY_LAST_SEEN
        params["risk_score_min"] = _decimal(window["low"])
        params["risk_score_max"] = _decimal(window["high"])
    else:
        params["order_by"] = ORDER_BY_RISK
    return params

def _truncated(entities, total_hits):
    """Say whether the API held back part of the window.

    The endpoint caps every response at 1000 entities and honours no limit,
    offset or page parameter, so total_hits is the only completeness signal
    there is. An absent total_hits means the response was complete."""
    if total_hits == None:
        return 0
    missing = as_int(total_hits) - len(entities)
    if missing < 0:
        return 0
    return missing

def _texts(value):
    """Return a vendor list field as trimmed strings, blanks and repeats gone."""
    out = []
    for entry in as_list(value):
        out.append(as_text(entry))
    return dedupe(out)

def build_software(asset_id, entity):
    """Build the firmware Software record, when the entity carries firmware.

    rem_firmware is the only software-shaped field this endpoint is known to
    return; there is no installed-package array, so nothing else is emitted."""
    firmware = as_text(entity.get("rem_firmware"))
    if not firmware:
        return []

    params = {
        # Software requires an id, and it has to be unique per asset rather
        # than per firmware string, or two assets on the same release collide.
        "id": "{}:firmware".format(asset_id)[:255],
        "product": as_text(entity.get("rem_model")) or "Firmware",
        "version": firmware[:255],
    }
    vendor = as_text(entity.get("rem_vendor"))
    if vendor:
        params["vendor"] = vendor[:255]
    return [Software(**params)]

def _seen_ts(value):
    """Parse a vendor timestamp, rejecting the "never" sentinels.

    parse_ts does NOT return None for every empty-ish value: an ISO year-1
    value (Go's zero time) parses to unix=-62135596800 and any 1970-01-01 value
    to unix=0. Both survive a `!= None` check and epoch 0 survives a plain
    truth test, so an unguarded parse dates a never-seen asset instead of
    leaving it unknown.
    """
    ts = parse_ts(value)
    if ts == None or ts.unix <= 0:
        return None
    return ts

def build_asset(entity, scope, stats):
    """Convert one rem-asset-search entity into a runZero ImportAsset."""
    asset_id = as_text(entity.get("id"))
    if not asset_id:
        stats["no_id"] += 1
        return None

    # routable_ips drops loopback, unspecified, and link-local values: an APIPA
    # address a device invents when DHCP fails identifies nothing and would
    # correlate unrelated hosts to each other.
    addresses = routable_ips(_texts(entity.get("ip_addresses")))
    macs = _texts(entity.get("mac_addresses"))[:MAX_INTERFACES]

    netifs = []
    nic = network_interface(mac=macs[0] if macs else "", ips=addresses)
    if nic:
        netifs.append(nic)
    # A REM asset aggregates every source that saw the device, so it can carry
    # several MACs with no way to say which address belongs to which.
    for mac in macs[1:]:
        extra = network_interface(mac=mac, ips=[])
        if extra:
            netifs.append(extra)

    # clean_hostnames rejects placeholder names and values that are really IP
    # addresses, either of which would merge unrelated assets.
    hostnames = clean_hostnames([as_text(entity.get("hostname"))])

    # Because the id is barred from matching, a record with no address and no
    # name gives runZero nothing to correlate on: it would create a fresh
    # orphan asset on every poll rather than merging with anything. Skipping is
    # the only safe outcome, and the count is reported once at the end.
    if not netifs and not hostnames:
        stats["no_correlator"] += 1
        return None

    attrs = {}
    for source, target in ENTITY_ATTR_FIELDS.items():
        attrs[target] = entity.get(source)

    tags = []
    category = as_text(entity.get("rem_category"))
    if category:
        tags.append("category:" + category)
    severity = as_text(entity.get("risk_severity"))
    if severity:
        tags.append("risk:" + severity)
    criticality = as_text(entity.get("risk_device_criticality"))
    if criticality:
        tags.append("criticality:" + criticality)

    params = {
        "id": "forescout-rem:{}:{}".format(scope, asset_id),
        "hostnames": hostnames,
        "networkInterfaces": netifs,
        "tags": tags,
        "customAttributes": to_custom_attributes(attrs, prefix=ATTR_PREFIX, separator=ATTR_SEPARATOR),
    }

    software = build_software(params["id"], entity)
    if software:
        params["software"] = software

    os_name = as_text(entity.get("rem_os"))
    if os_name:
        params["os"] = os_name
    vendor = as_text(entity.get("rem_vendor"))
    if vendor:
        params["manufacturer"] = vendor
    model = as_text(entity.get("rem_model"))
    if model:
        params["model"] = model
    # rem_function is the device's role ("Infusion Pump", "PLC"), which is the
    # grain runZero's device type expects. rem_category is a six-value estate
    # class (IT, OT, IoT, Medical Device, Network Device, Unknown) and only
    # stands in when the function is missing; it is a tag either way.
    device_type = as_text(entity.get("rem_function")) or category
    if device_type:
        params["deviceType"] = device_type

    asset = ImportAsset(**params)
    # parse_ts rather than parse_time: a malformed timestamp aborts the whole
    # script, and a future one would make the platform drop the record.
    last_seen = _seen_ts(entity.get("last_seen"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset

def _api_options(config_kwargs, api_key, raw_header):
    """Collect the HTTP options used for every search under one header form.

    The two published descriptions of this API's Authorization header disagree:
    the one working public client sends `Bearer <key>`, while Forescout's prose
    for the sibling SCIM API says to paste the key bare. Bearer is tried first
    and _search falls back. get_http_options snapshots the header map, which is
    why a change of form rebuilds the options rather than mutating the dict."""
    return get_http_options(config_kwargs, headers={
        "Authorization": api_key if raw_header else bearer(api_key),
        "Accept": "application/json",
    })

def _search(ctx, window):
    """Run one window and return (entities, total_hits, error).

    A 401 on the first call is retried once with the bare key, because the two
    published descriptions of this API's Authorization header disagree and only
    a tenant settles which one it wants. Rate limiting is not handled here:
    get_json already retries 429 and 5xx with backoff and honors Retry-After."""
    for attempt in range(2):
        data, err = get_json(ctx["base_url"] + SEARCH_PATH, params=_params(window), **ctx["http_options"])
        if not err:
            # as_dict rather than a bare .get: a response that decodes to a
            # list or a bare null would otherwise abort the whole script, and
            # this API publishes no schema to promise it never does.
            envelope = as_dict(data)
            return dicts(envelope.get("entities")), envelope.get("total_hits"), None
        if err.startswith("status 401") and attempt == 0 and not ctx["raw_header"]:
            print("forescout-rem: bearer authorization rejected, retrying with the bare API key header")
            ctx["raw_header"] = True
            ctx["http_options"] = _api_options(ctx["kwargs"], ctx["api_key"], True)
            continue
        return [], None, err
    return [], None, "unreachable"

def report_window(ctx, entities, stats):
    """Report the entities of one window that no earlier window already covered.

    Adjacent risk bands and the shared boundary millisecond of a time split
    both hand the same asset back more than once, so the id is the de-duplication
    key exactly as it is in the reference client."""
    reported = 0
    for entity in entities:
        asset_id = as_text(entity.get("id"))
        if not asset_id:
            stats["no_id"] += 1
            continue
        if ctx["seen"].get(asset_id):
            stats["duplicates"] += 1
            continue
        ctx["seen"][asset_id] = True
        reported += report_asset(build_asset(entity, ctx["scope"], stats))
    return reported

def sweep_zero_score(ctx, stats, unbanded, missing):
    """Narrow the bound-free probe on time until it stops being truncated.

    Score 0 is the vendor's "risk score not available" class, not a low band:
    unbounded in size and largest on freshly onboarded or passive-only
    estates. Every banded query sends a risk bound, and the API drops score-0
    assets from any query carrying one, so this probe is the only call that can
    ever see them. Leaving it at one truncated call would lose the excess while
    still printing a clean success line. Time is the only axis available here.
    """
    if not missing:
        return 0
    parts = _split(unbanded, ctx["max_depth"])
    if not parts:
        stats["capped_windows"] += 1
        stats["capped_assets"] += missing
        print("forescout-rem: the zero-score probe was truncated and cannot be narrowed further; about {} assets with no risk score were not imported".format(missing))
        return 0

    print("forescout-rem: the zero-score probe was truncated with about {} assets unseen; narrowing it on time".format(missing))
    reported = 0
    stack = parts
    p = pager("zero-score-windows")
    while p.next():
        if not stack:
            break
        if p.page >= max_pages():
            stats["abandoned"] += len(stack)
            break
        window = stack.pop()
        entities, total_hits, err = _search(ctx, window)
        if err:
            print("forescout-rem: zero-score search failed for {}: {}".format(_label(window), err))
            stats["abandoned"] += len(stack) + 1
            break
        stats["windows"] += 1
        reported += report_window(ctx, entities, stats)
        short = _truncated(entities, total_hits)
        if not short:
            continue
        deeper = _split(window, ctx["max_depth"])
        if deeper:
            stack.extend(deeper)
            continue
        stats["capped_windows"] += 1
        stats["capped_assets"] += short
        print("forescout-rem: a zero-score window could not be narrowed further; about {} assets with no risk score were not imported".format(short))
    return reported

def sweep(ctx, stats):
    """Walk the whole search window, narrowing it whenever the API truncates.

    Starlark forbids recursion, so the splitter is an explicit stack rather
    than a recursive descent: pop a window, query it, and on truncation push
    the two narrower windows that replace it. Popping from the end makes the
    walk depth-first, which keeps the stack shallow -- a breadth-first queue
    would hold every window of a whole level at once."""
    # Sending either risk bound makes the API drop assets scored exactly 0, so
    # this bound-free call, ordered by risk_score ASCENDING, is the only one
    # that can see them. See sweep_zero_score.
    unbanded = _window(ctx["from_ms"], ctx["to_ms"], 0, RISK_MAX_TENTHS, 0, banded=False)
    entities, total_hits, err = _search(ctx, unbanded)
    if err:
        print("forescout-rem: asset search failed:", err)
        return 0

    stats["windows"] += 1
    reported = report_window(ctx, entities, stats)
    unbanded_missing = _truncated(entities, total_hits)
    if not unbanded_missing:
        print("forescout-rem: the whole window fit in one response, so no risk banding was needed")
        return reported
    print("forescout-rem: the search window is larger than one response; banding the risk scale to cover it")

    # A capped probe is split on time and re-queued rather than accepted; the
    # banded queue below cannot recover what it misses.
    reported += sweep_zero_score(ctx, stats, unbanded, unbanded_missing)

    queue = [_window(ctx["from_ms"], ctx["to_ms"], 0, RISK_MAX_TENTHS, 0)]
    budget = max_pages()

    p = pager("windows")
    while p.next():
        if not queue:
            break
        # p.next() raises at maxPages rather than ending the loop, so the last
        # permitted window is given up here instead, with a count of what was
        # never queried. A raise would lose that count along with the run.
        if p.page >= budget:
            stats["abandoned"] += len(queue)
            break

        window = queue.pop()
        entities, total_hits, err = _search(ctx, window)
        if err:
            print("forescout-rem: asset search failed for {}: {}".format(_label(window), err))
            stats["abandoned"] += len(queue) + 1
            break

        stats["windows"] += 1
        reported += report_window(ctx, entities, stats)

        missing = _truncated(entities, total_hits)
        if not missing:
            continue
        children = _split(window, ctx["max_depth"])
        if children:
            queue.extend(children)
        else:
            stats["capped_windows"] += 1
            stats["capped_assets"] += missing

    return reported

def main(**kwargs):
    base_url = get_url_base(kwargs)
    api_key = get_string(kwargs, "api_key")
    # CONFIG defaults are not applied on the script --kwargs path, so each one
    # is repeated here or the script behaves differently from the console.
    strategy = get_string(kwargs, "sync_strategy", default="incremental")
    lookback_days = get_int(kwargs, "lookback_days", default=DEFAULT_LOOKBACK_DAYS)

    days = lookback_days
    if strategy == "full":
        # The API needs a from bound, so a full sweep is a fixed wide window
        # rather than an absent one. Ten years is longer than Forescout Cloud
        # has existed. Reaching every asset still depends on the search budget
        # lasting, and the shortfall is counted either way.
        days = FULL_WINDOW_DAYS
    elif days < 1:
        days = DEFAULT_LOOKBACK_DAYS

    to_ms = now().unix_nano // 1000000
    span_ms = days * MS_PER_DAY
    ctx = {
        "base_url": base_url,
        "api_key": api_key,
        "kwargs": kwargs,
        "raw_header": False,
        "http_options": _api_options(kwargs, api_key, False),
        "scope": _scope(base_url),
        "from_ms": to_ms - span_ms,
        "to_ms": to_ms,
        "max_depth": _max_split_depth(span_ms),
        "seen": {},
    }

    stats = {"windows": 0, "duplicates": 0, "no_id": 0, "no_correlator": 0,
             "capped_windows": 0, "capped_assets": 0, "abandoned": 0}
    reported = sweep(ctx, stats)

    print("forescout-rem: reported {} assets from {} search windows".format(reported, stats["windows"]))
    if stats["duplicates"]:
        print("forescout-rem: {} entities were returned by more than one window and imported once".format(stats["duplicates"]))
    if stats["no_id"]:
        print("forescout-rem: skipped {} entities with no asset id".format(stats["no_id"]))
    if stats["no_correlator"]:
        print("forescout-rem: skipped {} assets with no MAC, IP, or hostname to correlate on".format(stats["no_correlator"]))
    # An incomplete import that reports success is worse than a failure, so the
    # shortfall is named and counted rather than left for someone to notice.
    if stats["capped_windows"]:
        print("forescout-rem: {} windows were still truncated after the maximum number of splits; about {} assets were not imported. Shorten the lookback and run the task more often.".format(
            stats["capped_windows"], stats["capped_assets"]))
    if stats["abandoned"]:
        print("forescout-rem: gave up with {} windows never searched; the assets in them were not imported".format(stats["abandoned"]))
    if not reported:
        print("forescout-rem: no assets retrieved")
    return None

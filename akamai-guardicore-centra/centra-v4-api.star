# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-akamai-guardicore-centra-v4-api",
    "name": "Akamai Guardicore Centra",
    "type": "inbound",
    "description": "Imports Centra agents and assets via the Centra v3 or v4 API.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "Centra URL",
            "type": "url",
            "required": True,
            "placeholder": "https://centra.example.com",
            "group": "Connection",
        },
        {
            "key": "username",
            "label": "Centra username",
            "type": "string",
            "required": True,
            "group": "Authentication",
        },
        {
            "key": "password",
            "label": "Centra password",
            "type": "secret",
            "required": True,
            "group": "Authentication",
        },
        {
            "key": "max_pages",
            "label": "Maximum pages to retrieve",
            "type": "int",
            "required": False,
            "default": 10000,
            "min": 1,
            "description": "Safety ceiling on the paging walk. Raise it if a run reports hitting the limit.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('http', 'get_json', 'post_json', 'bearer')
load('kwargs', 'get_int', 'get_url_base', 'get_http_options')
load('net', 'network_interface')
load('time', 'parse_time')
load('re', re_match='match')
load('coerce', 'as_dict', 'as_list', 'as_text')

# Centra documents its timestamps as 'YYYY-MM-DD HH:MM:SS', but agent and
# orchestration paths report RFC 3339 instead. Splitting on the space and taking
# [1] raised 'list index out of range' on anything else, which ended the whole
# run. parse_time also aborts the script on input it cannot read and Starlark
# has no exception handling, so the shape is checked before either is used.
SPACE_TS_RE = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$"
RFC3339_TS_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"

# asset_type is Centra's own classification of the asset, distinct from the
# operating system it also reports. Akamai does not publish the value set, so
# only the one value confirmed against a real response is translated and every
# other value -- including the orchestration asset types that describe an F5
# virtual server rather than a host -- is left for runZero to fingerprint. A
# type invented here would displace the one runZero derives for itself.
DEVICE_TYPES = {"server": "Server"}

RESULTS_PER_PAGE = 1000

# A BACKSTOP, not the primary guard. The walk's real runaway protection is the
# repeated-page check in the loop below, which notices a Centra that ignores
# start_at after two requests. A page ceiling is a poor first line of defence:
# it lets a stuck appliance be hammered for the whole ceiling before anything
# stops it.
#
# The number is derived from a record target rather than hand-picked, so it
# scales with the page size instead of encoding a guess about deployment size:
# 10,000 pages x 1,000 results per page = 10,000,000 assets per status, past any
# real Centra deployment. With the repeated-page check in front of it this
# should never be reached; reaching it anyway is logged, because a truncated
# import that says nothing looks exactly like a complete one.
MAX_PAGES = 10000


def retrieved_of(retrieved, total):
    """The retrieved/available half of a truncation message.

    A truncated run has to say how much of the estate it actually got: a bare
    count tells the reader nothing about whether the import is nearly complete
    or stopped at the first percent. Where the API reports no total, say so
    plainly rather than printing a bare slash or inventing a denominator.
    """
    if type(total) == 'int' and total > 0:
        return 'retrieved {}/{} available assets'.format(retrieved, total)
    return 'retrieved {} assets, total not reported'.format(retrieved)


def page_signature(rows):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the appliance re-served
    one page rather than advancing through the inventory. Comparing ends rather
    than every row keeps this O(1) per page, and it is enough for the failure it
    guards against -- a Centra that ignores start_at returns byte-identical
    responses, not a rearrangement of one.
    """
    if not rows:
        return 'empty'
    first = rows[0]
    last = rows[-1]
    first_id = first.get('id', '') if type(first) == 'dict' else ''
    last_id = last.get('id', '') if type(last) == 'dict' else ''
    return '{}|{}|{}'.format(len(rows), first_id, last_id)


def parse_centra_ts(value):
    """Return a time for a Centra timestamp, or None when it is absent or in a
    shape parse_time cannot read."""
    text = str(value or '').strip()
    if not text:
        return None
    if re_match(SPACE_TS_RE, text):
        return parse_time(text.replace(' ', 'T') + 'Z')
    if re_match(RFC3339_TS_RE, text):
        return parse_time(text)
    print('centra-v4: unrecognized timestamp, leaving it unset: ' + text)
    return None


def build_assets(base_url, assets, token, config_kwargs, label_mapping):
    assets_import = []
    for asset in assets:
        if type(asset) != 'dict':
            print('centra-v4: skipping non-dict asset record: ' + type(asset))
            continue
        # Agentless assets report agent/os_info/nics/scoping_details as null
        # rather than omitting them, and None.get aborts the whole run --
        # one such asset used to end the import. as_dict/as_list turn every
        # present-but-null block into an empty one.
        agent_info = as_dict(asset.get('agent'))
        os_info = as_dict(asset.get('os_info'))
        raw_id = asset.get('id') or asset.get('bios_uuid') or asset.get('instance_id')
        if not raw_id:
            print("centra-v4: skipping asset with no stable id: name=" + str(asset.get('name', '')))
            continue
        asset_id = str(raw_id)
        hostname = asset.get('name', '')
        os = os_info.get('type', '')
        #reformat first_seen timestamp for runZero parsing
        first_seen = parse_centra_ts(asset.get('first_seen', ''))

        # create the network interfaces
        interfaces = []
        nics = as_list(asset.get('nics'))
        for nic in nics:
            if type(nic) != 'dict':
                continue
            addresses = as_list(nic.get('ip_addresses'))
            interface = network_interface(ips=addresses, mac=nic.get('mac_address', None))
            # network_interface returns None when neither the addresses nor the
            # MAC survive parsing -- a NIC entry carrying only a link-local or
            # an unparseable MAC does that. Appending None makes ImportAsset
            # abort the entire run with "network_interfaces must be an iterable
            # of NetworkInterface objects", losing every asset already built.
            if interface:
                interfaces.append(interface)

        # Retrieve and map custom attributes
        
        orchestration_metadata = as_dict(asset.get('orchestration_metadata'))
        scoping_details = as_dict(as_dict(asset.get('scoping_details')).get('worksite'))
        agent_id = agent_info.get('id', '')
        #reformat agent_last_seen timestamp for runZero parsing
        agent_last_seen = parse_centra_ts(agent_info.get('agent_last_seen', ''))
        agent_last_seen = agent_last_seen.unix if agent_last_seen else ''
        agent_version = agent_info.get('agent_version', '')
        asset_type = asset.get('asset_type', '')
        bios_uuid = asset.get('bios_uuid', '')
        comments = asset.get('comments', '')
        # 'instance_is' was a typo, so the instanceId attribute was always empty.
        instance_id = asset.get('instance_id', '')
        #reformat last_seen timestamp for runZero parsing
        last_seen = parse_centra_ts(asset.get('last_seen', ''))
        last_seen = last_seen.unix if last_seen else ''
        mssp_tenant = asset.get('mssp_tenant_name', '')
        orc_asset_type = orchestration_metadata.get('asset_type', '')
        orc_dev_name = orchestration_metadata.get('f5_device_hostname', '')
        orc_partition = orchestration_metadata.get('partition', '')
        orc_vs_name = orchestration_metadata.get('vs_name', '')
        os_kernel = os_info.get('full_kernel_version', '')
        status = asset.get('status', '')
        worksite_mod = scoping_details.get('modified', '')
        worksite_name = scoping_details.get('name', '')

        labels = as_list(asset.get('labels'))
        label_guids = [v for item in labels if type(item) == 'dict' for k,v in item.items() if k == 'id']
        label_names = []
        for guid in label_guids:
            # Membership, not truthiness. A label the API user cannot read, one
            # that has been deleted, or one whose lookup 404s answers nothing
            # usable, and testing `if not name` treated that empty result as
            # "never asked" -- so the same failing GET /labels/<guid> was
            # repeated once per asset carrying the label. On an estate where a
            # policy label is on every host that is one wasted round trip per
            # asset. The miss is now cached as '' alongside the hits, so each
            # guid costs exactly one request per run whether it resolves or not.
            if guid not in label_mapping:
                new_mapping = get_labels(base_url, guid, token, config_kwargs)
                for k, v in new_mapping.items():
                    label_mapping[k] = v
                if guid not in label_mapping:
                    label_mapping[guid] = ''
            name = label_mapping[guid]
            # A label the API user cannot read leaves name empty; keeping it
            # would make the tag loop below split '' and index [1].
            if name:
                label_names.append(name)

        tags = []
        for label in label_names:
            # get_labels joins the label key and value with ': ', but a label
            # with no value has nothing after the colon. Indexing [1] blindly
            # raised 'list index out of range' and ended the whole run, so an
            # unusable label is skipped instead.
            split_label = label.split(':')
            if len(split_label) < 2:
                continue
            key = split_label[0].strip().replace(' ', '_')
            value = split_label[1].strip().replace(' ', '_')
            if not key or not value:
                continue
            tags.append(key + '=' + value)
        

        custom_attributes = {
            'agent.Id': agent_id,
            'agent.LastSeenTS': agent_last_seen,
            'agent.Version': agent_version,
            'assetType': asset_type,
            'biosUuid': bios_uuid,
            'comments': comments,
            'instanceId': instance_id,
            'labels': label_names,
            'lastSeenTS': last_seen,
            'msspTenantName': mssp_tenant,
            'osInfo.fullKernelVersion': os_kernel,
            'scopingDetails.worksite.modified': worksite_mod,
            'scopingDetails.worksite.name': worksite_name,
            'status': status,
            'orchestrationMetadata.assetType': orc_asset_type,
            'orchestrationMetadata.f5DeviceHostname': orc_dev_name,
            'orchestrationMetadata.partition': orc_partition,
            'orchestrationMetadata.vsName': orc_vs_name
        }

        label_groups = as_list(asset.get('label_groups'))
        for group in label_groups:
            # A member that is not an object has no .items() and would abort
            # the run; it is preserved whole under its index instead.
            if type(group) != 'dict':
                custom_attributes['labelGroup.' + str(label_groups.index(group))] = as_text(group)
                continue
            for k, v in group.items():
                custom_attributes['labelGroup.' + str(label_groups.index(group)) + '.' + k] = v
        orchestration_details = as_list(asset.get('orchestration_details'))
        for detail in orchestration_details:
            if type(detail) != 'dict':
                continue
            for k, v in detail.items():
                custom_attributes['orchestrationDetails.' + str(orchestration_details.index(detail)) + '.' + k] = v

        params = {
            'id': asset_id,
            'hostnames': [hostname],
            'os': os,
            'networkInterfaces': interfaces,
            'customAttributes': to_custom_attributes(custom_attributes),
            'tags': tags,
        }

        # Omitted rather than passed as '' when the asset carries no readable
        # first_seen. parse_centra_ts answers None for an absent or unparseable
        # timestamp, and first_seen_ts takes only a time object or None -- an
        # empty string there makes ImportAsset ABORT the whole run with
        # "first_seen_ts must be a time object", losing every asset already
        # built rather than just this row's timestamp.
        if first_seen:
            params['first_seen_ts'] = first_seen

        # Omitted rather than set to '' for an untranslated asset_type: an empty
        # deviceType is still a value and displaces runZero's own fingerprint.
        device_type = DEVICE_TYPES.get(str(asset_type or '').strip().lower(), '')
        if device_type:
            params['deviceType'] = device_type

        # Build assets for import
        assets_import.append(ImportAsset(**params))
    return assets_import

def get_labels(base_url, guid, token, config_kwargs):
    url = base_url + '/api/v4.0/labels/' + guid + '?'
    headers = {'Accept': 'application/json',
            'Authorization': bearer(token)}
    params = {'asset_limit': 1}
    data, err = get_json(url, params=params, **get_http_options(config_kwargs, headers=headers))
    if err:
        print('failed to retrieve label info for ' + guid + ': ' + err)
        return {}
    label_info = as_list(as_dict(data).get('objects'))
    if not label_info or type(label_info[0]) != 'dict':
        return {}
    label_key = as_text(label_info[0].get('key'))
    label_value = as_text(label_info[0].get('value'))
    return { guid: label_key + ': ' + label_value }

def stream_assets(base_url, token, config_kwargs):
    """Paginate Centra assets ('on' then 'off'), building and streaming each page
    via report_assets so the full asset set is never held in memory. The label
    cache is shared across pages to avoid redundant label lookups. Returns the
    number of assets reported."""
    label_mapping = {}
    reported = 0
    results_per_page = RESULTS_PER_PAGE
    # The ceiling is a parameter so an operator whose estate outgrows the
    # record target can move it without editing the script.
    max_pages = get_int(config_kwargs, 'max_pages', default=MAX_PAGES)

    for status in ('on', 'off'):
        # Return all assets for this status. Remove 'off' from the tuple above to
        # restrict import to only status 'on' assets.
        start = 0
        capped = True
        last_signature = ''
        # Centra reports the size of the whole result set alongside every page.
        # It is captured so a truncated run can say what fraction of the estate
        # it got, rather than a bare count the reader cannot judge.
        total_count = None
        for _page in range(0, max_pages):
            url = base_url + '/api/v4.0/assets?'
            headers = {'Accept': 'application/json',
                        'Authorization': bearer(token)}
            http_options = get_http_options(config_kwargs, headers=headers)
            params = {'max_results': results_per_page,
                      'start_at': start,
                      'status': status,
                      'expand': 'agent'}
            data, err = get_json(url, params=params, **http_options)
            if err:
                print('failed to retrieve "' + status + '" assets ' + str(start) + ' to ' + str(start + results_per_page) + ': ' + err)
                capped = False
                break
            envelope = data or {}
            reported_total = envelope.get('total_count')
            if type(reported_total) == 'int' and reported_total >= 0:
                total_count = reported_total

            assets = envelope.get('objects', [])

            # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it
            # means Centra is ignoring start_at and re-serving the same rows, so
            # the walk is not advancing and continuing can only re-report assets
            # already reported. Checked BEFORE the page is reported, so the
            # repeated rows never reach runZero -- which also spares the label
            # lookups build_assets would issue for them -- and it can never
            # truncate genuine data: it only fires on a page that adds nothing.
            # It catches the stuck appliance in two requests where the page
            # ceiling would take 10,000.
            signature = page_signature(assets)
            if assets and signature == last_signature:
                capped = False
                # No quotes around the status: the runtime escapes them in the
                # log line, which makes the message awkward to assert and grep.
                print('centra-v4: paging stopped after {} pages (API returned the same page twice walking status={}, {})'.format(
                    _page + 1, status, retrieved_of(reported, total_count)))
                break
            last_signature = signature

            reported += report_assets(build_assets(base_url, assets, token, config_kwargs, label_mapping))
            last_return = len(assets)
            start += last_return
            if last_return < results_per_page:
                capped = False
                break

        if capped:
            # No quotes around the status: the runtime escapes them in the log
            # line, which makes the message awkward to assert on and to grep.
            print('centra-v4: page limit of {} hit (integration safety limit, walking status={}, {}) - raise the max_pages parameter to import the rest'.format(
                max_pages, status, retrieved_of(reported, total_count)))

    return reported

VERSION_LABEL = 'centra-v4'


def get_token(base_url, username, password, config_kwargs):
    url = base_url + '/api/v3.0/authenticate'
    data, err = post_json(url, json={'username': username, 'password': password}, **get_http_options(config_kwargs))
    if err:
        fail('{}: authentication failed: {}'.format(VERSION_LABEL, err))
    if not data or type(data) != 'dict':
        fail('{}: the authenticate endpoint returned an unexpected response shape, wanted an object'.format(VERSION_LABEL))
    token = data.get('access_token')
    if not token:
        # A 2FA-enabled account answers 200 without an access_token.
        fail('{}: the authenticate response carried no access_token (is 2FA enabled for this account?)'.format(VERSION_LABEL))
    return token

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    username = kwargs['username']
    password = kwargs['password']
    # get_token ends the task in error itself: a rejected credential is never a
    # run that reports zero assets.
    token = get_token(base_url, username, password, kwargs)

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(base_url, token, kwargs)
    if not reported:
        print('no assets')

    return None
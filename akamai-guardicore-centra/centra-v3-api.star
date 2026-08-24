# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-akamai-guardicore-centra-v3-api",
    "name": "Akamai Guardicore Centra (v3)",
    "type": "inbound",
    "description": "Imports assets from Akamai Guardicore Centra using the v3 API.",
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
            "description": "Centra API base URL.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "Centra API username.",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
            "description": "Centra API password.",
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
load('coerce', 'as_dict', 'as_list', 'as_text')

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


def build_assets(assets):
    assets_import = []
    for asset in assets:
        if type(asset) != 'dict':
            print('centra-v3: skipping non-dict asset record: ' + type(asset))
            continue
        # Agentless assets -- common in a Centra inventory -- report
        # guest_agent_details as null rather than omitting it, and None.get
        # aborts the whole run. as_dict turns every present-but-null block
        # into an empty one.
        agent_info = as_dict(asset.get('guest_agent_details'))
        hardware = as_dict(agent_info.get('hardware'))
        raw_id = asset.get('id') or asset.get('bios_uuid') or hardware.get('hw_uuid')
        if not raw_id:
            print("centra-v3: skipping asset with no stable id: name=" + str(asset.get('name', '')))
            continue
        asset_id = str(raw_id)
        os_info = as_dict(agent_info.get('os_details'))
        hostname = agent_info.get('hostname', '')
        os = os_info.get('os_version_name', '')
        vendor = hardware.get('vendor', '')
        first_seen = asset.get('first_seen', None)

        # create the network interfaces
        interfaces = []
        networks = as_list(agent_info.get('network'))
        for network in networks:
            if type(network) != 'dict':
                continue
            ips = [address.get('address', '') for address in as_list(network.get('ip_addresses')) if type(address) == 'dict']
            interface = network_interface(ips=ips, mac=network.get('hardware_address', None))
            # See the v4 script: a None interface here aborts the whole run.
            if interface:
                interfaces.append(interface)

        # Retrieve and map custom attributes
        active = asset.get('active', '')
        agent_last_seen = asset.get('last_guest_agent_details_update', '')
        agent_type = agent_info.get('agent_type', '')
        agent_version = agent_info.get('agent_version', '')
        arch = hardware.get('architecture', '')
        bios_uuid = asset.get('bios_uuid', '')
        client_cert = agent_info.get('client_cert_ssl_cn_name', '')
        comments = asset.get('comments', '')
        doc_version = asset.get('doc_version', '')
        hw_uuid = hardware.get('hw_uuid', '')
        is_on = asset.get('is_on', '')
        labels = as_list(agent_info.get('labels'))
        last_seen = asset.get('last_seen', '')
        kernel_major = os_info.get('os_kernel_major', '')
        kernel_minor = os_info.get('os_kernel_minor', '')
        os_kernel = str(kernel_major) + '.' + str(kernel_minor)
        os_type = os_info.get('os_type', '')
        proc_count = os_info.get('num_of_processors', '')
        recent_domains = as_list(asset.get('recent_domains'))
        serial = hardware.get('serial', '')
        status = asset.get('status', '')
        vm_id = asset.get('vm_id', '')
        vm_name = asset.get('vm_name', '')

        custom_attributes = {
            'active': active,
            'agent.LastSeenTS': agent_last_seen,
            'agent.type': agent_type,
            'agent.Version': agent_version,
            'biosUuid': bios_uuid,
            'client_cert': client_cert,
            'comments': comments,
            'docVersion': doc_version,
            'hardware.Arch': arch,
            'hardware.SerialNumber': serial,
            'hardware.Uuid': hw_uuid,
            'isOn': is_on,
            'labels': labels,
            'firstSeenTS': first_seen,
            'lastSeenTS': last_seen,
            'recentDomains': recent_domains,
            'status': status,
            'osInfo.fullKernelVersion': os_kernel,
            'osInfo.osType': os_type,
            'processorCount': proc_count,
            'vmId': vm_id,
            'vmName': vm_name
        }

        agent_labels = as_list(agent_info.get('labels'))
        for label in agent_labels:
            custom_attributes['agent.labels.' + str(agent_labels.index(label))] = label
        labels = as_list(asset.get('labels'))
        for label in labels:
            # A label that is not an object has no .items() and would abort the
            # run; it is preserved whole under its index instead.
            if type(label) != 'dict':
                custom_attributes['labels.' + str(labels.index(label))] = as_text(label)
                continue
            for k, v in label.items():
                custom_attributes['labels.' + str(labels.index(label)) + '.' + k ] = v
        metadata = as_list(asset.get('metadata'))
        for data in metadata:
            # A metadata member holding anything but strings would abort
            # ':'.join; each element is coerced to text first, and a bare
            # scalar member is treated as a one-element list.
            custom_attributes['metadata.' + str(metadata.index(data))] = ':'.join([as_text(item) for item in as_list(data)])
        orc_details = as_list(asset.get('orchestration_details'))
        for detail in orc_details:
            if type(detail) != 'dict':
                continue
            for k, v in detail.items():
                custom_attributes['orchestrationDetails.' + str(orc_details.index(detail)) + '.' + k ] = v
        agent_supported_features = as_list(as_dict(agent_info.get('supported_features')).get('RevealAgent'))
        for feature in agent_supported_features:
            custom_attributes['agent.supportedFeatures.' + str(agent_supported_features.index(feature))] = feature

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                manufacturer=vendor,
                hostnames=[hostname],
                os=os,
                networkInterfaces=interfaces,
                customAttributes=to_custom_attributes(custom_attributes),
            )
        )
    return assets_import

def walk_status_assets(url, status, token, config_kwargs, max_pages, already_reported):
    """Walk one status's asset listing, streaming each page via report_assets.

    Returns (reported, first_page_404). first_page_404 is True only when the
    FIRST request answers 404 -- the signal that this endpoint does not exist
    on the deployment, and the only point at which a caller can safely retry
    another endpoint: nothing has been reported yet, so a fallback walk cannot
    re-report assets.
    """
    reported = 0
    results_per_page = RESULTS_PER_PAGE
    start = 0
    capped = True
    last_signature = ''
    # Centra reports the size of the whole result set alongside every page.
    # It is captured so a truncated run can say what fraction of the estate
    # it got, rather than a bare count the reader cannot judge.
    total_count = None
    for _page in range(0, max_pages):
        headers = {'Accept': 'application/json',
                    'Authorization': bearer(token)}
        http_options = get_http_options(config_kwargs, headers=headers)
        params = {'max_results': results_per_page,
                  'start_at': start,
                  'status': status}
        data, err = get_json(url, params=params, **http_options)
        if err:
            if start == 0 and err.startswith('status 404'):
                return reported, True
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
        # repeated rows never reach runZero, and it can never truncate
        # genuine data: it only fires on a page that adds nothing. It
        # catches the stuck appliance in two requests where the page ceiling
        # would take 10,000.
        signature = page_signature(assets)
        if assets and signature == last_signature:
            capped = False
            # No quotes around the status: the runtime escapes them in the
            # log line, which makes the message awkward to assert and grep.
            print('centra-v3: paging stopped after {} pages (API returned the same page twice walking status={}, {})'.format(
                _page + 1, status, retrieved_of(already_reported + reported, total_count)))
            break
        last_signature = signature

        reported += report_assets(build_assets(assets))
        last_return = len(assets)
        start += last_return
        if last_return < results_per_page:
            capped = False
            break

    if capped:
        # No quotes around the status: the runtime escapes them in the log
        # line, which makes the message awkward to assert on and to grep.
        print('centra-v3: page limit of {} hit (integration safety limit, walking status={}, {}) - raise the max_pages parameter to import the rest'.format(
            max_pages, status, retrieved_of(already_reported + reported, total_count)))

    return reported, False

def stream_assets(base_url, token, config_kwargs):
    """Paginate Centra assets ('on' then 'off'), building and streaming each page
    via report_assets so the full asset set is never held in memory. Returns the
    number of assets reported."""
    reported = 0
    # The ceiling is a parameter so an operator whose estate outgrows the
    # record target can move it without editing the script.
    max_pages = get_int(config_kwargs, 'max_pages', default=MAX_PAGES)

    # The 'on' and 'off' status queries historically target different API
    # versions; preserve those endpoints exactly. Deployments without the v4
    # API answer 404 to the v4 path, which used to cost the whole status=on
    # collection, so that walk falls back to the v3 endpoint when its first
    # page 404s.
    status_urls = [
        ('on', [base_url + '/api/v4.0/assets?', base_url + '/api/v3.0/assets?']),
        ('off', [base_url + '/api/v3.0/assets?']),
    ]

    for status, urls in status_urls:
        # Remove the 'off' entry above to restrict import to only status 'on'
        # assets.
        for index in range(len(urls)):
            count, first_page_404 = walk_status_assets(urls[index], status, token,
                                                       config_kwargs, max_pages, reported)
            reported += count
            if not first_page_404:
                break
            if index + 1 < len(urls):
                print('centra-v3: {} answered 404 for status={}; retrying against {}'.format(
                    urls[index], status, urls[index + 1]))
            else:
                print('failed to retrieve "' + status + '" assets: every endpoint answered 404')

    return reported

def get_token(base_url, username, password, config_kwargs):
    url = base_url + '/api/v3.0/authenticate'
    data, err = post_json(url, json={'username': username, 'password': password}, **get_http_options(config_kwargs))
    if err:
        print('authentication failed:', err)
        return None
    if not data or type(data) != 'dict':
        print('invalid authentication data')
        return None
    token = data.get('access_token')
    if not token:
        # A 2FA-enabled account answers 200 without an access_token.
        print('authentication response carried no access_token (is 2FA enabled for this account?)')
        return None
    return token

def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    username = kwargs['username']
    password = kwargs['password']
    token = get_token(base_url, username, password, kwargs)
    if not token:
        # get_token already printed why. Passing None to bearer() would abort
        # with a type error instead of this clean stop.
        print('centra-v3: authentication failed; no assets retrieved')
        return None

    # Assets are streamed page-by-page via report_assets in stream_assets.
    reported = stream_assets(base_url, token, kwargs)
    if not reported:
        print('no assets')

    return None
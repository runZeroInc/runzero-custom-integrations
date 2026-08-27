# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-snipe-it",
    "name": "Snipe-IT",
    "type": "inbound",
    "description": "Imports hardware assets from Snipe-IT.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # Bound on the paging loop. A server that keeps answering with a full page
    # -- because it ignores 'offset', or because its 'total' never settles
    # while rows are being added -- must not spin forever; hitting this raises
    # so a truncated register is an error rather than a silent partial import.
    "maxPages": 10000,
    "params": [
        {
            "key": "url",
            "label": "Snipe-IT URL",
            "type": "url",
            "required": True,
            "description": "Base URL for the Snipe-IT instance.",
            "placeholder": "https://snipeit.example.com",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "API token used to authenticate to Snipe-IT.",
        },
        {
            "key": "page_size",
            "label": "Hardware per page",
            "type": "int",
            "required": False,
            "default": 500,
            "min": 1,
            "max": 1000,
            "description": "Hardware records requested per page. Snipe-IT's own default when no limit is sent is 50, and some installs cap the limit below what is asked for; neither truncates the import, because paging continues until the reported total is reached.",
        },
        {
            "key": "max_assets",
            "label": "Maximum assets",
            "type": "int",
            "required": False,
            "default": 0,
            "min": 0,
            "description": "Cap on the number of assets imported in one run, as a safety valve on a very large register. 0, the default, imports every record; a run stopped by the cap says so in the task log.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface', 'clean_hostname')
load('http', 'get_json', 'bearer', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_int')

VENDOR = "snipe-it"

DEFAULT_PAGE_SIZE = 500

# Snipe-IT custom field formats that hold an address. The custom_fields map is
# keyed by the operator's own field NAME, so no name can be assumed; the
# field_format Snipe-IT records alongside the value identifies the content
# whatever the field was called. The names are a fallback for a field created
# with the free-form ANY format, which carries no usable field_format.
IP_FIELD_FORMATS = ['ip', 'ipv4', 'ipv6']
IP_FIELD_NAMES = ['ip', 'ip address', 'ipv4 address', 'ipv6 address']


def custom_field_ips(custom_fields):
    """Return the IP addresses recorded in an asset's custom fields.

    A v7 hardware row carries NO address data of its own -- verified against a
    real snipe/snipe-it:v7.0.13 container. This script used to read
    asset['networks'] and walk networks['v4'] and networks['v6'], a key the API
    never returns, so every address it claimed to import was dead code and the
    MAC was the only thing that ever reached an interface.

    Snipe-IT stores an address the same way it stores the MAC this script
    already reads: in a custom field on the model's fieldset.
    """
    if type(custom_fields) != 'dict':
        return []
    ips = []
    for name in custom_fields:
        entry = custom_fields[name]
        if type(entry) != 'dict':
            continue
        value = entry.get('value')
        if type(value) != 'string' or not value.strip():
            continue
        field_format = str(entry.get('field_format') or '').strip().lower()
        if field_format not in IP_FIELD_FORMATS and str(name).strip().lower() not in IP_FIELD_NAMES:
            continue
        # One field can hold several addresses on a multi-homed host.
        for part in value.split(','):
            text = part.strip()
            if text and text not in ips:
                ips.append(text)
    return ips

def build_assets(assets_json, scope):
    assets_import = []
    for asset in assets_json:
        id = asset.get('id') or asset.get('asset_tag') or asset.get('serial')
        if not id:
            print("snipe-it: skipping hardware with no id/asset_tag/serial")
            continue
        model_info = asset.get('model', {})
        if model_info:
            model = model_info.get('name', '')
        else:
            model = ''
        device_info = asset.get('category', {})
        if device_info:
            device_type = device_info.get('name', '')
        else:
            device_type = ''
        manuf_info = asset.get('manufacturer', {})
        if manuf_info:
            manufacturer = manuf_info.get('name', '')
        else:
            manufacturer = ''
        # Map custom fields from Snipe-IT
        # mac is reset on every iteration. Starlark locals are function-scoped,
        # not loop-scoped, so a row that had custom fields but no 'MAC Address'
        # among them used to keep the PREVIOUS row's value: a monitor was
        # imported carrying a laptop's MAC. MAC is a matching attribute, so that
        # merged unrelated hardware onto one asset.
        mac = None
        custom_fields = asset.get('custom_fields', {})
        if custom_fields:
            mac_info =custom_fields.get('MAC Address', {})
            if mac_info:
                mac = mac_info.get('value', None)

        # Map additional Snipe-IT fields as custom attributes
        age = asset.get('age', '')
        asset_tag = asset.get('asset_tag', '')
        book_value = asset.get(str('book_value'), '')
        byod = asset.get(str('byod'), '')
        checkin_count = asset.get(str('checkin_counter'), '')
        checkout_count = asset.get(str('checkout_counter'), '')
        company_info = asset.get('company', {})
        if company_info:
            company_name = company_info.get('name', '')
        else:
            company_name = ''
        created_info = asset.get('created_at', {})
        if created_info:
            created = created_info.get('datetime', '')
        else:
            created = ''
        eol = asset.get(str('eol'), '')
        eol_date = asset.get(str('asset_eol_date'), 'NA')
        expected_checkin = asset.get(str('expected_checkin'), '')
        last_audit = asset.get('last_audit_date', '')
        last_checkout = asset.get(str('last_checkout'), '')
        location_info = asset.get('location', {})
        if location_info:
            location = location_info.get('name', '')
        else:
            location = ''
        model_number = asset.get('model_number', '')
        name = asset.get('name', '')
        next_audit = asset.get('next_audit_date', '')
        notes = asset.get('notes', '')
        order_number = asset.get(str('order_number'), '')
        purchase_cost = asset.get('purchase_cost', '')
        purchase_date = asset.get('purchase_date', '')
        requests_count = asset.get(str('requests_counter'), '')
        serial = asset.get('serial', '')
        status_info = asset.get('status_label', {})
        if status_info:
            status_name = status_info.get('name', '')
            status_type = status_info.get('status_type', '')
        else:
            status_name = ''
            status_type = ''
        supplier_info = asset.get('supplier', {})
        if supplier_info:
            supplier = supplier_info.get('name', '')
        else:
            supplier = ''
        updated_info = asset.get('updated_at', {})
        if updated_info:
            updated = updated_info.get('datetime', '')
        else:
            updated = ''
        user_checkout = asset.get(str('user_can_checkout'), '')
        warranty_months = asset.get('warranty_months', '')
        warranty_exp = asset.get(str('warranty_expires'), '')

        # parse IP addresses
        #
        # These come from the custom fields, not from asset['networks']: that
        # key does not exist in the v7 API, verified against a real
        # snipe/snipe-it:v7.0.13 container, so the block that read it imported
        # nothing while looking like it imported addresses.
        ips = custom_field_ips(custom_fields)

        # The addresses collected above are passed through: network_interface
        # used to be called with ips=[], which discarded every IP the asset
        # reported and left the MAC as the only possible interface.
        #
        # It returns None when nothing usable survives, and a stock Snipe-IT
        # install has no 'MAC Address' custom field at all, so a row with no MAC
        # and no networks is the common case rather than the exception. Passing
        # [None] to ImportAsset aborts the whole run, losing every row already
        # parsed, so the interface is only added when one was actually built.
        network = network_interface(ips=ips, mac=mac)
        interfaces = [network] if network else []

        # The asset name is usually the device's real hostname, and without it
        # a stock install's rows carry no correlator at all and can never merge
        # with scanned assets. clean_hostname rejects free-text labels,
        # placeholders, and IP-shaped values, so only a name that can actually
        # be a hostname is imported as one; the raw name stays an attribute.
        host = clean_hostname(name)

        assets_import.append(
            ImportAsset(
                # Snipe-IT's hardware id is a per-instance auto-increment
                # primary key: every install numbers its register from 1, so a
                # bare '1' collides with the '1' of every other Snipe-IT. The
                # id is scoped on the hostname of the configured URL so two
                # instances imported into one runZero account stay apart.
                id='{}:{}:hardware:{}'.format(VENDOR, scope, id),
                model=model,
                deviceType=device_type,
                manufacturer=manufacturer,
                hostnames=[host] if host else [],
                networkInterfaces=interfaces,
                customAttributes=to_custom_attributes({
                    "age": age,
                    "asset.tag": asset_tag,
                    "book.value": book_value,
                    "byod": byod,
                    "checkin.count": checkin_count,
                    "checkout.count": checkout_count,
                    "company.name": company_name,
                    "eol": eol,
                    "eol.date": eol_date,
                    "expected.checkin": expected_checkin,
                    "first.seen": created,
                    "last.audit": last_audit,
                    "last.checkout": last_checkout,
                    "last.seen": updated,
                    "location": location,
                    "model.number": model_number,
                    "name": name,
                    "next.audit": next_audit,
                    "notes": notes,
                    "order.number": order_number,
                    "purchase.cost": purchase_cost,
                    "purchase.date": purchase_date,
                    "requests.count": requests_count,
                    "serial.number": serial,
                    "status.name": status_name,
                    "status.type": status_type,
                    "supplier.name": supplier,
                    "user.checkout": user_checkout,
                    "warranty.months": warranty_months,
                    "warranty.expiration": warranty_exp
                }),
            )
        )
    return assets_import

def to_count(value):
    """Return a non-negative int for a value that may arrive as an int, a float
    or a numeric string, and 0 for anything else.

    Comparing an int against a string aborts the script and Starlark has no way
    to catch it, so 'total' is never used in the shape it arrives in.
    """
    if type(value) == 'int':
        return value if value > 0 else 0
    if type(value) == 'float':
        return int(value) if value > 0 else 0
    if type(value) == 'string':
        text = value.strip()
        if text.isdigit():
            return int(text)
    return 0


def stream_assets(base_url, scope, http_options, page_size, max_assets):
    """Page through /api/v1/hardware with limit and offset, building and
    streaming each page via report_assets so the whole register is never held in
    memory at once. Returns the number of assets reported.

    The offset advances by the number of ROWS received rather than by the number
    of assets reported: build_assets drops rows with no id, asset_tag or serial,
    so advancing by the reported count would request those same rows again.
    """
    url = '{}/{}'.format(base_url, 'api/v1/hardware')
    fetched = 0
    reported = 0
    total = 0

    # Bounded by CONFIG["maxPages"]: running out of pages raises, naming the
    # label and the key, so a register the server keeps re-serving surfaces as
    # an error rather than a silently truncated import.
    _pager = pager("hardware")
    while _pager.next():
        params = {'limit': page_size, 'offset': fetched}
        data, err = get_json(url, params=params, **http_options)
        if err:
            print('snipe-it: failed to retrieve hardware at offset {}: {}'.format(fetched, err))
            return reported
        data = data or {}
        rows = data.get('rows', [])
        if type(rows) != 'list':
            print('snipe-it: hardware at offset {} answered with no usable rows; stopping'.format(fetched))
            return reported
        # 'total' counts every record matching the request, not the ones on this
        # page. It is re-read every time because the register can grow between
        # two requests, and kept from the previous page when a response omits it.
        total = to_count(data.get('total')) or total
        if not rows:
            break

        fetched += len(rows)
        reported += report_assets(build_assets(rows, scope))
        print('snipe-it: reported {} assets from {} of {} hardware records'.format(
            reported, fetched, total or fetched))

        if max_assets and reported >= max_assets:
            print('snipe-it: stopped at the {} asset import limit after {} hardware records; raise or clear "Maximum assets" to import the rest'.format(
                max_assets, fetched))
            return reported

        # 'total' is the reliable end signal, so it is tested first. A short page
        # only means the end of the register when there is no total to check
        # against: an install that caps 'limit' below the requested page size
        # answers every page short, and ending the run on the first one is the
        # single-page truncation this pagination replaced.
        if total:
            if fetched >= total:
                break
        elif len(rows) < page_size:
            break

    return reported


# build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    base_url = get_url_base(kwargs)
    # The instance scope for every foreign id. Snipe-IT's hardware id is a bare
    # per-instance auto-increment key, so without this two installs collide on
    # 1, 2, 3.
    parsed = url_parse(base_url)
    scope = parsed.hostname if parsed else ''
    if not scope:
        fail('snipe-it: could not determine the Snipe-IT host from the configured URL')
    token = kwargs['api_token']
    http_options = get_http_options(kwargs, headers={'Accept': 'application/json', 'Authorization': bearer(token)})

    # CONFIG's min and max are console-side hints, so a run from the command
    # line or an older credential can still arrive with anything. A page_size
    # below 1 would make every page look short and end the import after one
    # request, which is exactly the truncation this replaced.
    page_size = get_int(kwargs, 'page_size', default=DEFAULT_PAGE_SIZE)
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    max_assets = get_int(kwargs, 'max_assets', default=0)
    if max_assets < 0:
        max_assets = 0

    # Hardware is streamed page by page via report_assets in stream_assets.
    if not stream_assets(base_url, scope, http_options, page_size, max_assets):
        print('no assets')

    return None
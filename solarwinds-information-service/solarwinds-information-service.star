# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-solarwinds-information-service",
    "name": "SolarWinds Information Service",
    "type": "inbound",
    "description": "Imports devices via the SolarWinds Information Service (SWIS) API.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "SWIS URL",
            "type": "url",
            "required": False,
            "default": "https://localhost:17774",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "query",
            "label": "SWQL query",
            "type": "textarea",
            "required": False,
            "default": "SELECT N.NodeID, N.Caption, N.DNS, N.SysName, N.IPAddress, N.Vendor, N.MachineType, N.NodeDescription, N.IOSVersion, N.CPULoad, N.PercentMemoryUsed, N.MemoryUsed, N.ResponseTime, N.Status, N.StatusDescription, N.SysObjectID, N.SystemUpTime FROM Orion.Nodes N",
            "description": "SWQL executed against the Information Service. The default selects only documented Orion.Nodes properties and the script reads them by those names; alias any column you add to the name the script reads. Which columns exist depends on the Orion version and the modules installed, so narrow or extend this to match your estate.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('base64', base64_encode='encode')
load('http', http_get='get', 'url_parse')
load('jsonstream', 'iter_array')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')
load('net', 'network_interface', 'clean_hostnames')

VENDOR = "swis"

# The default SWQL. Every property named here exists on Orion.Nodes in the
# published OrionSDK schema; an earlier build selected invented names (Fqdn,
# OsVersion, Uptime, Pollers...) which SWIS rejects outright, so a stock
# install imported nothing until the operator rewrote the query.
DEFAULT_QUERY = "SELECT N.NodeID, N.Caption, N.DNS, N.SysName, N.IPAddress, N.Vendor, N.MachineType, N.NodeDescription, N.IOSVersion, N.CPULoad, N.PercentMemoryUsed, N.MemoryUsed, N.ResponseTime, N.Status, N.StatusDescription, N.SysObjectID, N.SystemUpTime FROM Orion.Nodes N"


def _scope(base_url):
    """Return the SWIS server's host, used to namespace every asset id.

    Orion's NodeID is a small per-install integer and DNS and IPAddress are
    only unique inside one installation, so an unscoped id collides the moment
    two Orion servers are imported into one runZero account -- and with
    integers counting from 1, a collision is close to certain rather than
    unlucky. The configured URL's host is the only thing distinguishing them
    that this API exposes.
    """
    parsed = url_parse(base_url)
    if parsed and parsed.hostname:
        return parsed.hostname
    return base_url.split("://")[-1].split("/")[0].split(":")[0]


def build_asset(asset, scope):
    """Convert one SWQL result row into an ImportAsset, or None to skip it."""
    if type(asset) != "dict":
        return None
    raw_id = asset.get('NodeID') or asset.get('DNS') or asset.get('IPAddress')
    if not raw_id:
        return None
    # Namespaced by the SWIS server: see _scope for why an unscoped NodeID
    # cannot be an identity.
    asset_id = "{}:{}:node:{}".format(VENDOR, scope, raw_id)

    # DNS is whatever the poller resolved, SysName is the SNMP sysName, and
    # Caption is a free-text display name. Any of them can hold a bare IP or a
    # placeholder, so all three go through the hostname scrubber rather than
    # straight onto the asset.
    names = clean_hostnames([asset.get('DNS'), asset.get('SysName'), asset.get('Caption')])

    # create the network interface
    interfaces = []
    interface = network_interface(ips=[asset.get('IPAddress')], mac=None)
    # network_interface returns None when nothing usable survives;
    # appending it aborts the whole run at ImportAsset.
    if interface:
        interfaces.append(interface)

    custom_attributes = to_custom_attributes({
        'caption':           asset.get('Caption'),
        'dns':               asset.get('DNS'),
        'sysName':           asset.get('SysName'),
        'machineType':       asset.get('MachineType'),
        'nodeDescription':   asset.get('NodeDescription'),
        'cpuLoad':           asset.get('CPULoad'),
        'percentMemoryUsed': asset.get('PercentMemoryUsed'),
        'memoryUsed':        asset.get('MemoryUsed'),
        'responseTime':      asset.get('ResponseTime'),
        'status':            asset.get('Status'),
        'statusDescription': asset.get('StatusDescription'),
        'sysObjectId':       asset.get('SysObjectID'),
        'systemUpTime':      asset.get('SystemUpTime'),
    })

    return ImportAsset(
        id=asset_id,
        hostnames=names,
        # IOSVersion is a bare software/OS version string; Orion.Nodes has no
        # OS-name property, so `os` is left to runZero fingerprinting.
        osVersion=asset.get('IOSVersion'),
        manufacturer=asset.get('Vendor'),
        networkInterfaces=interfaces,
        customAttributes=custom_attributes,
    )


def fetch_results(base_url, creds, config_kwargs, query):
    """Run the SWQL query and return the raw response body, or None on failure.

    The body is returned undecoded so the caller can stream the results array
    with iter_array: SWIS has no paging, so a large estate arrives as one
    response and this avoids materializing every parsed row at once.
    """
    url = base_url + '/SolarWinds/InformationService/v3/Json/Query'
    headers = {'Accept': 'application/json',
               'Authorization': 'Basic ' + creds}
    http_options = get_http_options(config_kwargs, headers=headers)
    response = http_get(url, params={'query': query}, **http_options)
    if not response:
        fail('swis: failed to retrieve assets: no response from the Information Service')
    if response.status_code != 200:
        fail('swis: failed to retrieve assets: status {}: {}'.format(
            response.status_code, str(response.body)[:200]))
    body = response.body
    # A 200 from a proxy can carry an HTML body, and decoding that aborts the
    # whole run; a SWIS answer is always a JSON object.
    if not body or body[0:1] != '{':
        fail('swis: failed to retrieve assets: the response body was not JSON')
    return body


def main(*args, **kwargs):
    base_url = get_url_base(kwargs, default='https://localhost:17774')
    username = kwargs['username']
    password = kwargs['password']
    b64_creds = base64_encode(username + ":" + password)
    query = get_string(kwargs, 'query', default=DEFAULT_QUERY).strip()
    if not query:
        print('swis: no SWQL query configured; nothing to ask for')
        return None

    body = fetch_results(base_url, b64_creds, kwargs, query)
    scope = _scope(base_url)
    reported = 0
    # A node with none of the three identity fields cannot be imported.
    # Counted rather than logged per record: a query that selects the wrong
    # columns would otherwise print a line for every node in the estate.
    skipped = 0
    if body:
        for row in iter_array(body, path='results'):
            asset = build_asset(row, scope)
            if asset:
                reported += report_asset(asset)
            else:
                skipped += 1
    if skipped > 0:
        print("swis: skipped {} nodes with no NodeID/DNS/IPAddress".format(skipped))
    print('swis: reported {} assets'.format(reported))

    return None

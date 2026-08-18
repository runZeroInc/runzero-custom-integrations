# Copyright 2026 runZero, Inc. Available under the MIT License

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
            "default": "SELECT N.NodeID AS NodeId, N.Fqdn, N.OsVersion, N.Vendor, N.IPAddress AS IpAddress, N.CpuPercentUtilization, N.DiscoveryProfileId, N.PercentMemoryUsed, N.MemoryUsed, N.Pollers, N.ResponseTime, N.Status, N.SysObjectId, N.Uptime FROM Orion.Nodes N",
            "description": "SWQL executed against the Information Service. The default selects the columns this integration maps; alias any column you add to the name the script reads. Which columns exist depends on the Orion version and the modules installed, so narrow or extend this to match your estate.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('base64', base64_encode='encode', base64_decode='decode')
load('http', 'get_json', 'url_encode', 'url_parse')
load('kwargs', 'get_url_base', 'get_http_options', 'get_string')

# Repeated as a constant because a CONFIG default is applied by the console but
# not on every path that can reach main(); see the note in AGENTS.md.
VENDOR = "swis"


def _scope(base_url):
    """Return the SWIS server's host, used to namespace every asset id.

    Orion's NodeId is a small per-install integer and Fqdn and IpAddress are
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


DEFAULT_QUERY = "SELECT N.NodeID AS NodeId, N.Fqdn, N.OsVersion, N.Vendor, N.IPAddress AS IpAddress, N.CpuPercentUtilization, N.DiscoveryProfileId, N.PercentMemoryUsed, N.MemoryUsed, N.Pollers, N.ResponseTime, N.Status, N.SysObjectId, N.Uptime FROM Orion.Nodes N"
load('net', 'network_interface')

def build_assets(assets, scope):
    assets_import = []
    # A node with none of the three identity fields cannot be imported.
    # Counted rather than logged per record: a query that selects the wrong
    # columns would otherwise print a line for every node in the estate.
    skipped = 0
    for asset in assets:
        raw_id = asset.get('NodeId') or asset.get('Fqdn') or asset.get('IpAddress')
        if not raw_id:
            skipped += 1
            continue
        # Namespaced by the SWIS server: see _scope for why an unscoped
        # NodeId cannot be an identity.
        asset_id = "{}:{}:node:{}".format(VENDOR, scope, raw_id)
        hostname = asset.get('Fqdn', '')
        os = asset.get('OsVersion', '')
        vendor = asset.get('Vendor', '')

        # create the network interfaces
        interfaces = []
        addresses = asset.get('IpAddress', [])
        interface = network_interface(ips=[addresses], mac=None)
        # network_interface returns None when nothing usable survives;
        # appending it aborts the whole run at ImportAsset.
        if interface:
            interfaces.append(interface)

        # Retrieve and map custom attributes
        custom_attributes = to_custom_attributes({
            'percentCpuUtilization':    asset.get('CpuPercentUtilization'),
            'discoveryProfileId':       asset.get('DiscoveryProfileId'),
            'percentMemoryUtilization': asset.get('PercentMemoryUsed'),
            'memoryUtilized':           asset.get('MemoryUsed'),
            'pollers':                  asset.get('Pollers'),
            'responseTime':             asset.get('ResponseTime'),
            'snmp.port':                asset.get('SnmpPort'),
            'snmp.version':             asset.get('SnmpVersion'),
            'status':                   asset.get('Status'),
            'sysObjectId':              asset.get('SysObjectId'),
            'uptime':                   asset.get('Uptime'),
        })

        # Build assets for import
        assets_import.append(
            ImportAsset(
                id=asset_id,
                hostnames=[hostname],
                os=os,
                manufacturer=vendor,
                networkInterfaces=interfaces,
                customAttributes=custom_attributes,
            )
        )
    if skipped > 0:
        print("swis: skipped {} nodes with no NodeId/Fqdn/IpAddress".format(skipped))
    return assets_import

def get_assets(base_url, creds, config_kwargs, query):

    url = base_url + '/SolarWinds/InformationService/v3/Json/Query?'
    headers = {'Accept': 'application/json',
                'Authorization': 'Basic ' + creds}
    http_options = get_http_options(config_kwargs, headers=headers)
    # Populate the SWQL query to return desired assets and attributes in the params query value e.g. 
    # params = {'query': 'SELECT N.NodeID, N.OsVersion, N.Fqdn, N.Vendor, N.IPAddress, N.CpuPercentUtilization, N.DiscoveryProfileId, N.PercentMemoryUsed, N.MemoryUsed, N.Pollers, N.responseTime, N.snmp.port, N.snmp.version, N.status, N.sysObjectId, N.Uptime FROM Orion.Nodes'}
    params = {'query': query}
    data, err = get_json(url, params=params, **http_options)
    if err:
        print('swis: failed to retrieve assets: {}'.format(err))
        return []
    assets = (data or {}).get('results', [])

    return assets

def main(*args, **kwargs):
    base_url = get_url_base(kwargs, default='https://localhost:17774')
    username = kwargs['username']
    password = kwargs['password']
    b64_creds = base64_encode(username + ":" + password)
    query = get_string(kwargs, 'query', default=DEFAULT_QUERY).strip()
    if not query:
        print('swis: no SWQL query configured; nothing to ask for')
        return None
    assets = get_assets(base_url, b64_creds, kwargs, query)
    
    # Build and stream asset import via report_assets instead of returning a list
    reported = report_assets(build_assets(assets, _scope(base_url)))
    print('swis: reported {} assets'.format(reported))

    return None

load('requests', 'Session')
load('json', json_decode='decode')
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('base64', base64_encode='encode')

def main(*args, **kwargs):
    """
    runZero custom integration using Scale API v1.
    Authenticates with Basic Auth using values from a JSON-formatted access_secret dict.
    """
    secret =json_decode(kwargs['access_secret'])
    username = secret['access_key']
    password = secret['access_secret']
    base_url = secret['base_url'].rstrip('/')
    if not base_url:
        return []

    # Construct Basic Auth header
    auth_string = "{}:{}".format(username, password)
    auth_header = "Basic {}".format(base64_encode(auth_string))

    session = Session()
    session.headers.set("Accept", "application/json")
    session.headers.set("Authorization", auth_header)

    # Get all clusters
    clusters = {}
    cluster_url = "{}/v1/clusters".format(base_url)
    resp = session.get(cluster_url)
    if resp and resp.status_code == 200:
        data =json_decode(resp.body)
        for cluster in data:
            clusters[cluster["id"]] = cluster["name"]

    # Get all VMs
    assets = []
    vm_url = "{}/v1/vms".format(base_url)
    resp = session.get(vm_url)
    if resp and resp.status_code == 200:
        data =json_decode(resp.body)
        for vm in data:
            ip_list = vm.get("ip_addresses", [])
            interfaces = [NetworkInterface(ip=ip) for ip in ip_list if ip]

            asset = ImportAsset(
                id=vm["id"],
                hostname=vm["name"],
                os="Scale VM",
                osVersion=vm.get("description", ""),
                customAttributes={
                    "clusterId": vm["cluster_id"],
                    "clusterName": clusters.get(vm["cluster_id"], ""),
                    "status": vm.get("status"),
                    "tags": vm.get("tags", []),
                    "memoryMB": vm.get("memory_mb"),
                    "cpuCount": vm.get("cpu_count"),
                    "createdAt": vm.get("created_at"),
                    "updatedAt": vm.get("updated_at")
                },
                networkInterfaces=interfaces
            )
            assets.append(asset)

    return assets

load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('http', http_post='post', http_get='get', 'url_encode')
load('net', 'ip_address')

def k8s_api_request(hostname, token, endpoint):
    """Generic function to interact with Kubernetes API"""
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json"
    }
    response = http_get(hostname + endpoint, headers=headers)
    if response.status_code != 200:
        print("Error fetching data:", response.status_code)
        return None
    return json_decode(response.body)

def discover_k8s_nodes(hostname, token):
    """Fetches Kubernetes nodes and converts them into runZero assets"""
    nodes = k8s_api_request(hostname, token, "/api/v1/nodes")
    if not nodes:
        return []

    assets = []
    for node in nodes.get("items", []):
        metadata = node.get("metadata", {})
        status = node.get("status", {})
        node_name = metadata.get("name", "")
        node_ips = [addr["address"] for addr in status.get("addresses", []) if addr["type"] == "InternalIP"]

        ip4s = [ip_address(ip) for ip in node_ips if "." in ip]
        ip6s = [ip_address(ip) for ip in node_ips if ":" in ip]

        assets.append(
            ImportAsset(
                id="k8s-node-" + node_name,
                hostnames=[node_name],
                networkInterfaces=[NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)],
                os="Kubernetes",
                osVersion=status.get("nodeInfo", {}).get("kubeletVersion", ""),
                customAttributes={
                    "k8s_node_uid": metadata.get("uid", ""),
                    "k8s_node_name": node_name,
                    "k8s_roles": metadata.get("labels", {}).get("kubernetes.io/role", ""),
                    "k8s_creation_timestamp": metadata.get("creationTimestamp", ""),
                    "k8s_kernel_version": status.get("nodeInfo", {}).get("kernelVersion", ""),
                    "k8s_os_image": status.get("nodeInfo", {}).get("osImage", ""),
                    "k8s_architecture": status.get("nodeInfo", {}).get("architecture", ""),
                    "k8s_container_runtime": status.get("nodeInfo", {}).get("containerRuntimeVersion", ""),
                    "k8s_capacity": status.get("capacity", {}),
                    "k8s_allocatable": status.get("allocatable", {}),
                    "k8s_conditions": status.get("conditions", []),
                    "k8s_pod_cidr": node.get("spec", {}).get("podCIDR", ""),
                    "k8s_pod_cidrs": node.get("spec", {}).get("podCIDRs", []),
                    "k8s_provider_id": node.get("spec", {}).get("providerID", ""),
                    "k8s_daemon_endpoints": status.get("daemonEndpoints", {}),
                    "k8s_images": status.get("images", [])
                }
            )
        )
    return assets

def discover_k8s_pods(hostname, token):
    """Fetches Kubernetes Pods and their metadata"""
    pods = k8s_api_request(hostname, token, "/api/v1/pods")
    if not pods:
        return []

    pod_assets = []
    for pod in pods.get("items", []):
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})
        spec = pod.get("spec", {})
        
        pod_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        node_name = spec.get("nodeName", "Unknown")

        pod_ips = [addr["ip"] for addr in status.get("podIPs", [])]
        ip4s = [ip_address(ip) for ip in pod_ips if "." in ip]
        ip6s = [ip_address(ip) for ip in pod_ips if ":" in ip]

        container_images = [c["image"] for c in spec.get("containers", [])]
        container_statuses = status.get("containerStatuses", [])

        pod_assets.append(
            ImportAsset(
                id="k8s-pod-" + pod_name,
                hostnames=[pod_name],
                networkInterfaces=[NetworkInterface(ipv4Addresses=ip4s, ipv6Addresses=ip6s)],
                os="Containerized",
                customAttributes={
                    "k8s_pod_uid": metadata.get("uid", ""),
                    "k8s_pod_name": pod_name,
                    "k8s_namespace": namespace,
                    "k8s_node": node_name,
                    "k8s_pod_status": status.get("phase", ""),
                    "k8s_pod_start_time": status.get("startTime", ""),
                    "k8s_pod_conditions": status.get("conditions", []),
                    "k8s_pod_owner": metadata.get("ownerReferences", []),
                    "k8s_pod_ip": status.get("podIP", ""),
                    "k8s_pod_host_ip": status.get("hostIP", ""),
                    "k8s_container_images": ",".join(container_images),
                    "k8s_container_statuses": container_statuses
                }
            )
        )

    return pod_assets

def main(*args, **kwargs):
    """Entry point for the integration"""
    hostname = kwargs["access_key"]
    token = kwargs["access_secret"]
    node_assets = discover_k8s_nodes(hostname, token)
    pod_assets = discover_k8s_pods(hostname, token)

    all_assets = node_assets + pod_assets
    return all_assets if all_assets else None
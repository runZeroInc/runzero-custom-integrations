# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-kubernetes",
    "name": "Kubernetes",
    "type": "inbound",
    "description": "Imports nodes, pods, and services from a Kubernetes cluster.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "API server URL",
            "type": "url",
            "required": True,
            "placeholder": "https://k8s.example.com:6443",
        },
        {
            "key": "bearer_token",
            "label": "Bearer token",
            "type": "secret",
            "required": True,
        },
        {
            "key": "include_loadbalancer_services",
            "label": "Import LoadBalancer/NodePort services",
            "type": "bool",
            "required": False,
            "default": True,
        },
        {
            "key": "request_timeout",
            "label": "Request timeout (seconds)",
            "type": "int",
            "required": False,
            "default": 300,
            "min": 10,
            "max": 3600,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
# Kubernetes -> runZero ImportAsset Integration
#
# Pulls cluster Nodes from the Kubernetes API server and converts each
# Node into a runZero ImportAsset. Optionally also pulls Services of
# type LoadBalancer / NodePort and emits them as additional assets so
# that exposed ingress IPs show up in inventory.
#
# Credentials (runZero "Custom Integration Script Secrets"):
#   url           : Kubernetes API server URL, e.g.
#                   https://kubernetes.example.com:6443
#   bearer_token  : ServiceAccount bearer token with at least
#                   `get`/`list` on nodes (and services, if enabled).
#
# To create a token:
#   kubectl create serviceaccount runzero -n kube-system
#   kubectl create clusterrolebinding runzero-readonly \
#     --clusterrole=view \
#     --serviceaccount=kube-system:runzero
#   kubectl -n kube-system create token runzero --duration=8760h
#
# Many on-prem clusters present a self-signed apiserver certificate.
# Use the tls_disable_validation parameter only when you trust the network path.

load("runzero.types", "ImportAsset", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "bearer")
load("kwargs", "get_bool", "get_int", "get_http_options")

# --- Defaults ---
DEFAULT_INCLUDE_LOADBALANCER_SERVICES = True
DEFAULT_REQUEST_TIMEOUT = 300


def _log(msg):
    print("[KUBERNETES] " + msg)


def _api_get(base_url, path, token, timeout_seconds, config_kwargs):
    url = base_url.rstrip("/") + path
    headers = {
        "Authorization": bearer(token),
        "Accept": "application/json",
    }
    return get_json(
        url,
        timeout=timeout_seconds,
        **get_http_options(config_kwargs, headers=headers)
    )


def _node_to_asset(node):
    meta = node.get("metadata") or {}
    status = node.get("status") or {}
    info = status.get("nodeInfo") or {}
    spec = node.get("spec") or {}
    labels = meta.get("labels") or {}

    node_id = meta.get("uid")
    if not node_id:
        return None

    addresses = status.get("addresses") or []
    ips = []
    hostnames = []
    for a in addresses:
        a_type = a.get("type", "")
        a_addr = a.get("address", "")
        if not a_addr:
            continue
        if a_type in ("InternalIP", "ExternalIP"):
            ips.append(a_addr)
        elif a_type in ("Hostname", "InternalDNS", "ExternalDNS"):
            hostnames.append(a_addr)

    name = meta.get("name", "")
    if name and name not in hostnames:
        hostnames.insert(0, name)

    nic = network_interface(ips=ips)
    nics = [nic] if nic else []

    attrs = to_custom_attributes({
        "k8s.node.name":               name,
        "k8s.node.uid":                node_id,
        "k8s.node.creation_timestamp": meta.get("creationTimestamp"),
        "k8s.node.provider_id":        spec.get("providerID"),
        "k8s.node.pod_cidr":           spec.get("podCIDR"),
        "k8s.node.pod_cidrs":          spec.get("podCIDRs"),
        "k8s.node.unschedulable":      spec.get("unschedulable", False),
        "k8s.node.taints":             spec.get("taints"),
        "k8s.node.architecture":       info.get("architecture"),
        "k8s.node.boot_id":            info.get("bootID"),
        "k8s.node.container_runtime":  info.get("containerRuntimeVersion"),
        "k8s.node.kernel_version":     info.get("kernelVersion"),
        "k8s.node.kube_proxy_version": info.get("kubeProxyVersion"),
        "k8s.node.kubelet_version":    info.get("kubeletVersion"),
        "k8s.node.machine_id":         info.get("machineID"),
        "k8s.node.system_uuid":        info.get("systemUUID"),
        "k8s.node.os_image":           info.get("osImage"),
        "k8s.node.capacity":           status.get("capacity"),
        "k8s.node.allocatable":        status.get("allocatable"),
        "k8s.node.labels":             labels,
    }, list_join="json")

    return ImportAsset(
        id="k8s-node-" + node_id,
        hostnames=hostnames,
        networkInterfaces=nics,
        os=info.get("operatingSystem", "linux"),
        osVersion=info.get("osImage", ""),
        manufacturer=labels.get("node.kubernetes.io/instance-type", ""),
        deviceType="Kubernetes Node",
        tags=["kubernetes", "k8s-node"],
        customAttributes=attrs,
    )


def _service_to_asset(svc):
    meta = svc.get("metadata") or {}
    spec = svc.get("spec") or {}
    status = svc.get("status") or {}

    svc_uid = meta.get("uid")
    if not svc_uid:
        return None

    svc_type = spec.get("type", "")
    if svc_type not in ("LoadBalancer", "NodePort"):
        return None

    ips = []
    hostnames = []

    # ClusterIP(s)
    cluster_ips = spec.get("clusterIPs") or []
    for ip in cluster_ips:
        if ip and ip != "None":
            ips.append(ip)
    cluster_ip = spec.get("clusterIP")
    if cluster_ip and cluster_ip != "None" and cluster_ip not in ips:
        ips.append(cluster_ip)

    # LoadBalancer ingress
    lb = status.get("loadBalancer") or {}
    for ing in lb.get("ingress") or []:
        if ing.get("ip"):
            ips.append(ing.get("ip"))
        if ing.get("hostname"):
            hostnames.append(ing.get("hostname"))

    # External IPs
    for ip in spec.get("externalIPs") or []:
        ips.append(ip)

    name = meta.get("name", "")
    namespace = meta.get("namespace", "")
    fqdn = "{}.{}.svc".format(name, namespace) if name and namespace else name
    if fqdn:
        hostnames.insert(0, fqdn)

    nic = network_interface(ips=ips)
    if not nic:
        return None

    attrs = to_custom_attributes({
        "k8s.service.name":              name,
        "k8s.service.namespace":         namespace,
        "k8s.service.uid":               svc_uid,
        "k8s.service.type":              svc_type,
        "k8s.service.creation_timestamp": meta.get("creationTimestamp"),
        "k8s.service.cluster_ip":        cluster_ip,
        "k8s.service.external_name":     spec.get("externalName"),
        "k8s.service.session_affinity":  spec.get("sessionAffinity"),
        "k8s.service.ports":             spec.get("ports"),
        "k8s.service.selector":          spec.get("selector"),
        "k8s.service.labels":            meta.get("labels"),
    }, list_join="json")

    return ImportAsset(
        id="k8s-svc-" + svc_uid,
        hostnames=hostnames,
        networkInterfaces=[nic],
        deviceType="Kubernetes Service",
        tags=["kubernetes", "k8s-service", "k8s-svc-" + svc_type.lower()],
        customAttributes=attrs,
    )


def main(*args, **kwargs):
    base_url = kwargs.get("url", "")
    token = kwargs.get("bearer_token", "")
    include_loadbalancer_services = get_bool(kwargs, "include_loadbalancer_services", DEFAULT_INCLUDE_LOADBALANCER_SERVICES)
    timeout_seconds = get_int(kwargs, "request_timeout", DEFAULT_REQUEST_TIMEOUT)

    if not base_url:
        _log("ERROR: url (Kubernetes API server URL) is required.")
        return []
    if not token:
        _log("ERROR: bearer_token (ServiceAccount bearer token) is required.")
        return []

    assets = []

    nodes_resp, err = _api_get(base_url, "/api/v1/nodes", token, timeout_seconds, kwargs)
    if err:
        _log("ERROR: failed to list nodes: " + err)
        return []
    for node in (nodes_resp or {}).get("items", []):
        a = _node_to_asset(node)
        if a:
            assets.append(a)
    _log("nodes: imported {} asset(s)".format(len(assets)))

    if include_loadbalancer_services:
        svc_count = 0
        svcs_resp, err = _api_get(base_url, "/api/v1/services", token, timeout_seconds, kwargs)
        if err:
            _log("WARN: failed to list services: " + err)
        else:
            for svc in (svcs_resp or {}).get("items", []):
                a = _service_to_asset(svc)
                if a:
                    assets.append(a)
                    svc_count += 1
            _log("services: imported {} asset(s)".format(svc_count))

    # Stream assets to runZero via report_assets instead of returning a list.
    reported = report_assets(assets)
    _log("SUCCESS: reported {} ImportAsset(s)".format(reported))
    return None

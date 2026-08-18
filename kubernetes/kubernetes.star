# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-kubernetes",
    "name": "Kubernetes",
    "type": "inbound",
    "description": "Imports nodes, LoadBalancer/NodePort services, and optionally pods from a Kubernetes cluster.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
            "key": "include_pods",
            "label": "Import pods",
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Import every pod as an asset, with its container images as software. Off by default: a cluster holds far more pods than nodes, and a pod is replaced on every rollout, so each deployment mints new assets.",
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
# that exposed ingress IPs show up in inventory, and Pods with their
# container images as Software.
#
# Credentials (runZero "Custom Integration Script Secrets"):
#   url           : Kubernetes API server URL, e.g.
#                   https://kubernetes.example.com:6443
#   bearer_token  : ServiceAccount bearer token with at least
#                   `get`/`list` on nodes (and services and pods, if
#                   those imports are enabled).
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

load("runzero.types", "ImportAsset", "Software", "to_custom_attributes")
load("net", "network_interface")
load("http", "get_json", "bearer")
load("kwargs", "get_bool", "get_int", "get_http_options")

# --- Defaults ---
DEFAULT_INCLUDE_LOADBALANCER_SERVICES = True
DEFAULT_INCLUDE_PODS = False
DEFAULT_REQUEST_TIMEOUT = 300

# ImportAsset caps software, services and vulnerabilities at 99 per asset.
MAX_SOFTWARE_PER_ASSET = 99


def _log(msg):
    print("kubernetes: " + msg)


def _collect(items, convert, kind, assets):
    """Convert one collection, appending to assets and TALLYING the drops.

    A record with no metadata.uid has no stable identity, so it cannot be
    imported. Logging each one costs a line per record on a large cluster, so
    the count is what gets reported and one name is carried along for
    diagnosis.
    """
    imported = 0
    skipped = 0
    first_skipped = ""
    for item in items:
        meta = item.get("metadata") or {}
        if not meta.get("uid"):
            skipped += 1
            if skipped == 1:
                first_skipped = str(meta.get("name", ""))
            continue
        asset = convert(item)
        # A None from the converter here is a deliberate filter -- a
        # ClusterIP-only Service, say -- not a defect, so it is not tallied as
        # a skip. Only the identity gate above counts.
        if asset:
            assets.append(asset)
            imported += 1
    _log("imported {} {}".format(imported, kind))
    if skipped > 0:
        _log("skipped {} {} with no metadata.uid (first name: {})".format(
            skipped, kind, first_skipped))
    return imported


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

    # ClusterIPs are deliberately NOT placed on the network interface. They are
    # allocated from the cluster's service CIDR, which defaults to the same
    # range on virtually every install, so the same address identifies a
    # different Service in every cluster: importing two clusters would IP-match
    # kube-dns in one onto kube-dns in the other and merge them. They are also
    # not reachable from outside the cluster, so they are of little use as a
    # correlation signal even when unique. Both values are kept as custom
    # attributes below. Only genuinely routable LoadBalancer ingress addresses
    # reach the interface.
    cluster_ip = spec.get("clusterIP")
    cluster_ips = spec.get("clusterIPs") or []

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
        "k8s.service.cluster_ips":       cluster_ips,
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


def _pod_software(spec, status):
    """Return the container images of one pod as Software records.

    The image is the closest thing a cluster has to a software inventory and is
    the join key against any container-image scanner, so it is the part of a Pod
    worth importing. `status.containerStatuses` is preferred over `spec` because
    it reports the image the kubelet actually resolved and pulled, including the
    digest, where the spec may name only a floating tag."""
    resolved = {}
    for cs in (status.get("containerStatuses") or []) + (status.get("initContainerStatuses") or []):
        if type(cs) != "dict":
            continue
        name = str(cs.get("name", "") or "")
        if name:
            resolved[name] = cs

    software = []
    containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
    for container in containers:
        if type(container) != "dict":
            continue
        name = str(container.get("name", "") or "")
        image = str(container.get("image", "") or "")
        cs = resolved.get(name) or {}
        if cs.get("image"):
            image = str(cs.get("image"))
        if not image:
            continue

        # An image reference is <registry>/<repository>:<tag>, and the registry
        # host may itself carry a :port -- so the tag is whatever follows the
        # LAST colon, and only when no "/" appears after it. A digest reference
        # (...@sha256:...) has no tag at all.
        product = image
        version = ""
        at = image.rfind("@")
        if at > 0:
            version = image[at + 1:]
            product = image[:at]
        colon = product.rfind(":")
        if colon > 0 and product.find("/", colon) < 0:
            if not version:
                version = product[colon + 1:]
            product = product[:colon]

        software.append(Software(
            id=image,
            product=product,
            version=version,
            customAttributes=to_custom_attributes({
                "k8s.container.name":          name,
                "k8s.container.image":         image,
                "k8s.container.image_id":      cs.get("imageID"),
                "k8s.container.ready":         cs.get("ready"),
                "k8s.container.restart_count": cs.get("restartCount"),
                "k8s.container.started":       cs.get("started"),
            }),
        ))
        if len(software) >= MAX_SOFTWARE_PER_ASSET:
            break
    return software


def _pod_to_asset(pod):
    """Build one ImportAsset from a Pod object, or None when it must be skipped.

    IDENTITY. `metadata.uid` is the documented stable key -- "a unique in time
    and space value" minted by the API server -- and it is stable for as long as
    the object exists, which is exactly as long as the asset it describes exists.
    A rollout replaces the pod and therefore mints a new asset; that is
    semantically right (it genuinely is a different pod) and is why this import
    is off by default.

    ADDRESSING. A pod IP is deliberately NOT placed on a network interface, for
    the same reason ClusterIPs are excluded from Service assets above, only more
    so: pod addresses come from the cluster pod CIDR, which defaults to the same
    range on virtually every install, AND they are recycled within a single
    cluster within minutes of a pod exiting. Importing them would IP-match a pod
    in one cluster onto an unrelated pod in another, and a dead pod onto its
    replacement. `status.hostIP` is worse still -- it is the NODE's address, so
    it would merge every pod on a node into the node itself. Both are kept as
    custom attributes.

    So a pod correlates on a synthesized `<name>.<namespace>.pod` hostname, the
    same shape the Service path uses. The pod's own `metadata.name` is
    deliberately not imported as a bare hostname: a StatefulSet names its pods
    `web-0`, `db-1`, which would collide with real hosts of those names."""
    meta = pod.get("metadata") or {}
    spec = pod.get("spec") or {}
    status = pod.get("status") or {}

    pod_uid = meta.get("uid")
    if not pod_uid:
        return None

    name = str(meta.get("name", "") or "")
    namespace = str(meta.get("namespace", "") or "")
    fqdn = "{}.{}.pod".format(name, namespace) if name and namespace else name

    owners = []
    for owner in meta.get("ownerReferences") or []:
        if type(owner) != "dict":
            continue
        kind = str(owner.get("kind", "") or "")
        owner_name = str(owner.get("name", "") or "")
        if kind and owner_name:
            owners.append(kind + "/" + owner_name)

    restarts = 0
    for cs in status.get("containerStatuses") or []:
        if type(cs) == "dict" and type(cs.get("restartCount")) == "int":
            restarts += cs.get("restartCount")

    attrs = to_custom_attributes({
        "k8s.pod.name":               name,
        "k8s.pod.namespace":          namespace,
        "k8s.pod.uid":                pod_uid,
        "k8s.pod.creation_timestamp": meta.get("creationTimestamp"),
        "k8s.pod.node_name":          spec.get("nodeName"),
        "k8s.pod.host_network":       spec.get("hostNetwork", False),
        "k8s.pod.service_account":    spec.get("serviceAccountName"),
        "k8s.pod.priority_class":     spec.get("priorityClassName"),
        "k8s.pod.restart_policy":     spec.get("restartPolicy"),
        "k8s.pod.phase":              status.get("phase"),
        "k8s.pod.qos_class":          status.get("qosClass"),
        "k8s.pod.start_time":         status.get("startTime"),
        "k8s.pod.pod_ip":             status.get("podIP"),
        "k8s.pod.pod_ips":            status.get("podIPs"),
        "k8s.pod.host_ip":            status.get("hostIP"),
        "k8s.pod.owners":             owners,
        "k8s.pod.restart_count":      restarts,
        "k8s.pod.labels":             meta.get("labels"),
    }, list_join="json")

    return ImportAsset(
        id="k8s-pod-" + pod_uid,
        hostnames=[fqdn],
        networkInterfaces=[],
        deviceType="Kubernetes Pod",
        tags=["kubernetes", "k8s-pod"],
        software=_pod_software(spec, status),
        customAttributes=attrs,
    )


def main(*args, **kwargs):
    base_url = kwargs.get("url", "")
    token = kwargs.get("bearer_token", "")
    include_loadbalancer_services = get_bool(kwargs, "include_loadbalancer_services", DEFAULT_INCLUDE_LOADBALANCER_SERVICES)
    include_pods = get_bool(kwargs, "include_pods", DEFAULT_INCLUDE_PODS)
    timeout_seconds = get_int(kwargs, "request_timeout", DEFAULT_REQUEST_TIMEOUT)

    if not base_url:
        _log("url (Kubernetes API server URL) is required")
        return []
    if not token:
        _log("bearer_token (ServiceAccount bearer token) is required")
        return []

    assets = []

    nodes_resp, err = _api_get(base_url, "/api/v1/nodes", token, timeout_seconds, kwargs)
    if err:
        _log("failed to list nodes: " + err)
        return []
    _collect((nodes_resp or {}).get("items", []), _node_to_asset, "nodes", assets)

    if include_loadbalancer_services:
        svcs_resp, err = _api_get(base_url, "/api/v1/services", token, timeout_seconds, kwargs)
        if err:
            _log("failed to list services: " + err)
        else:
            _collect((svcs_resp or {}).get("items", []), _service_to_asset, "services", assets)

    if include_pods:
        pods_resp, err = _api_get(base_url, "/api/v1/pods", token, timeout_seconds, kwargs)
        if err:
            _log("failed to list pods: " + err)
        else:
            _collect((pods_resp or {}).get("items", []), _pod_to_asset, "pods", assets)

    # Stream assets to runZero via report_assets instead of returning a list.
    reported = report_assets(assets)
    _log("reported {} assets".format(reported))
    return None

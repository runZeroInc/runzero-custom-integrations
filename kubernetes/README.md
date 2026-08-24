# Custom Integration: Kubernetes

Pulls cluster Nodes (and, optionally, LoadBalancer / NodePort Services and
Pods) from the Kubernetes API server and imports them as runZero assets.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations)
- An Explorer that has network reach to the Kubernetes API server

## Kubernetes requirements

- API server URL (e.g. `https://kubernetes.example.com:6443`)
- A ServiceAccount bearer token with read access to `nodes` (and
  `services`, if you want LoadBalancer ingress IPs, and `pods`, if you enable
  pod import).

### Create a read-only ServiceAccount and token

Do **not** bind the built-in `view` ClusterRole for this. `view` is built from
the namespaced read rules aggregated under
`rbac.authorization.k8s.io/aggregate-to-view`, and `nodes` is a cluster-scoped
resource that is not among them. A ServiceAccount bound to `view` can list
`services` but gets `403 Forbidden` on `GET /api/v1/nodes`, which is the call
this integration depends on — the task then runs to completion and imports
nothing. No upstream built-in ClusterRole grants read on nodes short of
`cluster-admin`, so create a small one:

```sh
kubectl create serviceaccount runzero -n kube-system

kubectl create clusterrole runzero-inventory \
  --verb=get,list,watch \
  --resource=nodes,services,pods

kubectl create clusterrolebinding runzero-inventory \
  --clusterrole=runzero-inventory \
  --serviceaccount=kube-system:runzero

kubectl -n kube-system create token runzero --duration=8760h
```

That is the whole grant: read on `nodes`, `services`, and `pods`, cluster-wide,
and nothing else. `pods` grants the pod *objects*, not `pods/log` or
`pods/exec` — it reaches no Secrets, no pod logs, and no workload contents.
Drop `services` and `pods` from `--resource` if you set
`include_loadbalancer_services` and `include_pods` to false and only want
Nodes; `pods` in particular is only needed when `include_pods` is on, which it
is not by default.

Confirm the binding actually works before you configure anything in runZero —
this answers `yes` or `no` rather than making you infer it from an empty
import:

```sh
kubectl auth can-i list nodes \
  --as=system:serviceaccount:kube-system:runzero
```

**On token lifetime.** `kubectl create token` issues a bound, expiring token,
and the API server will silently issue a *shorter* one than you asked for if
`--service-account-max-token-expiration` is set lower on your cluster; check
the expiry you were actually granted rather than assuming a year. When the
token expires the integration task starts failing authentication, so either
re-issue on a schedule or, if your cluster policy permits it, create a
long-lived `kubernetes.io/service-account-token` Secret for the ServiceAccount
and use the token from that Secret instead.

## Steps

### Kubernetes configuration

1. Get the API server URL: `kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'`
2. Create the ServiceAccount, ClusterRole, ClusterRoleBinding, and token (see above).
3. Decide how the Explorer will trust the API server certificate. Most clusters
   present a certificate from the cluster's own CA, which no public trust store
   contains. Export that CA and set it as the credential's `tls_ca_cert`:

   ```sh
   kubectl config view --raw --minify \
     -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d
   ```

   Disabling validation with `tls_disable_validation` works but should be a last
   resort. Both are TLS options on the credential — this integration has no
   in-script `INSECURE_SKIP_VERIFY` switch.
4. To skip Services and only import Nodes, set the
   `include_loadbalancer_services` parameter to false on the credential. It is a
   credential field, not a script edit. To add Pods, set `include_pods` to true
   — see [Pods](#pods) below for what that costs and what it gets you.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Type: `Custom Integration Script Secrets`
    - **API server URL** (`url`): the Kubernetes API server URL (e.g. `https://kubernetes.example.com:6443`)
    - **Bearer token** (`bearer_token`): the ServiceAccount bearer token
    - **Import LoadBalancer/NodePort services** (`include_loadbalancer_services`): optional; default enabled
    - **Import pods** (`include_pods`): optional; default **disabled**
    - **Request timeout (seconds)** (`request_timeout`): optional; default 300
    - **TLS options** (`tls_*`): set `tls_ca_cert` to the cluster CA exported above
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon
    - Toggle `Enable custom integration script` and paste in the contents of
      `kubernetes.star`
    - Click `Validate`, then `Save`
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created above
    - Pick an Explorer that can reach the apiserver
    - Set the schedule and `Save`

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to see what
an integration would import before scheduling it — and the fastest way to find out that
the ServiceAccount cannot list nodes. `--kwargs` is repeated once per parameter:

```bash
runzero script --filename kubernetes/kubernetes.star \
  --kwargs url=https://kubernetes.example.com:6443 \
  --kwargs bearer_token="$(kubectl -n kube-system create token runzero)" \
  --kwargs include_loadbalancer_services=true \
  --kwargs include_pods=true \
  --kwargs request_timeout=60 \
  --kwargs tls_ca_cert=/etc/runzero/k8s-ca.crt \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./kubernetes-run
```

`--output` writes the assets the run produced. The scanner refuses to write into a
directory that already exists, so add `--overwrite` when re-running into the same path.
Add `--verbose` for the request-by-request log, or omit `--output` to see only the log
lines. An RBAC gap shows up here as `ERROR: failed to list nodes` in the log with zero
node assets in the output directory; a token that is simply expired shows up as a 401 on
the same call.

`--kwargs` takes the value verbatim as long as the whole argument holds a single `=`, so
a comma inside a value is passed through intact. Only a value that *also* contains an `=`
flips the flag into comma-separated parsing, and then the value is cut at the first comma
— the remainder either becomes a fabricated second parameter or aborts the run with
`must be formatted as key=value`. Neither character appears in a ServiceAccount token: a
JWT is dot-separated base64url with no padding.

To check the `CONFIG` block and the HTTP and TLS wiring without a live cluster:

```bash
runzero script --filename kubernetes/kubernetes.star --validate
```

Validation generates placeholder parameter values and answers from a local dummy server,
so it proves the script initializes, declares its parameters correctly, and issues a
request. It does not prove the API server accepts the token, that the ServiceAccount
holds `list` on nodes, or that any Node is parsed. The fixture scenarios are what
exercise the parsing:

```bash
python3 tests/run.py kubernetes
```

The same script also runs under the `scan` command, which is what the platform itself
invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat kubernetes/kubernetes.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'url=https://kubernetes.example.com:6443,bearer_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUifQ.ExampleFakeServiceAccountToken.0123456789abcdef' \
  --output ./kubernetes-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's page.
`--custom-integration-entry-function-name` defaults to `main` and only needs setting for
a script with a different entry point. Note that `--custom-integration-script-kwargs`
takes one comma-separated string; prefer `script --kwargs` for ad-hoc runs.

### What's next?

- The task runs like any other ingestion task. Existing assets are merged
  on hostname / MAC / IP; new ones are created when nothing matches.
- Search for imported assets with `custom_integration:<your-integration-name>`.
- Node assets carry a rich `k8s.node.*` attribute set
  (kubelet/containerd versions, kernel, OS image, capacity, allocatable,
  pod CIDRs, labels, taints).
- Service assets are tagged `k8s-service` plus a type-specific tag
  (`k8s-svc-loadbalancer`, `k8s-svc-nodeport`).
- Pod assets, when enabled, are tagged `k8s-pod`, carry a `k8s.pod.*`
  attribute set, and list their container images as software — so
  `software:"ghcr.io/acme/storefront"` answers "where is this image running".

## Pods

Off by default. Set `include_pods` to true on the credential to add
`GET /api/v1/pods` to the walk and emit one asset per Pod, tagged `k8s-pod`,
with each container's image as a runZero `Software` record.

**Why it is off by default.** A cluster holds one or two orders of magnitude
more pods than nodes, and a pod is *replaced*, not updated, on every rollout —
a new object with a new UID, and therefore a new runZero asset. Turning this on
means node and service assets stop being the bulk of what the integration
produces, and it means asset churn proportional to your deploy rate. That is a
deliberate choice to make rather than a default to inherit.

**What a pod asset carries.** The `k8s.pod.*` attribute set: namespace, node
name, phase, QoS class, service account, priority class, restart policy, owner
references (`ReplicaSet/storefront-7d9f8b6c5`, `DaemonSet/kube-proxy`), summed
container restart count, start and creation timestamps, labels, and the
addresses discussed below. Each container — including init containers —
produces a `Software` record whose product is the image repository and whose
version is the tag or digest, capped at 99 per asset. `status.containerStatuses`
is preferred over `spec.containers` for the image, because it names what the
kubelet actually resolved and pulled rather than a floating tag.

**Pod addresses are deliberately not imported onto an interface, and a pod
asset therefore has no IP or MAC at all.** This is the same decision made for
Service ClusterIPs above, and it is more clear-cut here, for two independent
reasons rather than one:

- A pod address comes from the cluster pod CIDR, which defaults to the same
  range on virtually every install (`10.244.0.0/16` under Flannel,
  `192.168.0.0/16` under Calico). Importing two clusters would IP-match
  unrelated pods in each onto each other.
- Within a *single* cluster the address is recycled, often within minutes of a
  pod exiting. A dead pod's asset and its unrelated replacement would match on
  an address that was never simultaneously theirs.

`status.hostIP` is worse still and is likewise excluded: it is the **node's**
address, so importing it would merge every pod on a node into the node itself.
Both `podIP` and `hostIP` are kept as `k8s.pod.pod_ip` / `k8s.pod.host_ip`
attributes, where they are searchable but cannot drive a match.

**A pod correlates on a synthesized `<name>.<namespace>.pod` hostname**, the
same shape the Service path uses. The pod's own `metadata.name` is deliberately
*not* imported as a bare hostname even though it is genuinely the hostname the
container sees: a StatefulSet names its pods `web-0` and `db-1`, and those
collide with real hosts of those names in any estate that has one. Pods with
`hostNetwork: true` — `kube-proxy`, CNI agents, static control-plane pods —
are the sharp case: they share the node's network namespace, so their in-container
hostname *is* the node's hostname and their `podIP` equals the node's `hostIP`.
Importing either would silently merge the pod into `worker-01`. The pod-scoped
hostname is what makes that impossible, and it is why the rule is applied
uniformly rather than only to hostNetwork pods.

## Asset identity

- Target entities: a **Node** (a cluster machine), optionally a **Service** of type `LoadBalancer` or `NodePort`, and optionally a **Pod**. Three kinds of object, three id prefixes, one id space.
- Source ID field: `metadata.uid` for all three, prefixed — `k8s-node-<uid>`, `k8s-svc-<uid>`, and `k8s-pod-<uid>`.
- Documentation evidence: this is the strongest identity contract of any source in this repository, because Kubernetes states it outright. `metadata.uid` is defined as "a unique in time and space value" — an RFC 4122 UUID generated by the API server for every object, whose explicit purpose is to distinguish between objects that carry the same name but existed at different times. It is not a field that happens to be unique; it is the identity primitive of the API.
- Uniqueness scope: **global, by construction.** UUIDs do not collide across clusters, so importing several clusters through one custom integration is safe without any cluster prefix. The `k8s-node-` and `k8s-svc-` prefixes exist to keep the two object kinds separable, not to disambiguate.
- Cardinality: one asset per Node object; one asset per qualifying Service object; one asset per Pod object when `include_pods` is on.
- Stability: **for the lifetime of the object, and deliberately no longer.** A Node deleted and re-registered under the same name gets a new UID — Kubernetes documents that as the whole reason UIDs exist. The practical consequence in a cloud cluster is that node assets churn: every scale event, every node-pool upgrade, and every spot-instance replacement produces a new UID and therefore a new runZero asset. That is semantically correct (it genuinely is a different machine) but it means node assets accumulate over time and have to be aged out in runZero rather than merged. The same applies to a Service deleted and re-created by a redeploy, and — far more often — to a Pod, which is replaced on every rollout. Pod churn is the reason `include_pods` defaults to false.
- Reuse behavior: never. A UUID is not reassigned.
- Presence: guaranteed by the API server on any object that exists. The script still checks and returns `None` when absent, and **logs the skip** with the object's name.
- Final runZero ID: `k8s-node-<uid>`, `k8s-svc-<uid>`, or `k8s-pod-<uid>`. The bare uid is also preserved as the `k8s.node.uid` / `k8s.service.uid` / `k8s.pod.uid` custom attribute.
- Missing-ID behavior: skip, with a `kubernetes: skipping <kind> with no metadata.uid: name=<name>` log line. Only the name is logged, never the object.
- Match behavior: **not set** — the platform default, all match and break dimensions on. Correct under the governing rule, and unusually well-founded: the id is a genuine persistent identifier for the object's lifetime, so matching on it is what keeps a Node coherent while its addresses and conditions change.
- Verdict: **authoritative for a Kubernetes object.** Not authoritative for the underlying machine across a node replacement, which is a property of Kubernetes rather than of this integration.

**No MAC addresses exist anywhere in the Kubernetes API**, so correlation rests on addresses and hostnames. For Nodes those are `InternalIP` and `ExternalIP` plus the `Hostname`, `InternalDNS`, and `ExternalDNS` entries from `status.addresses`, with `metadata.name` inserted first. For Services they are the LoadBalancer ingress addresses and `spec.externalIPs`, plus a synthesized `<name>.<namespace>.svc` hostname.

**ClusterIPs are deliberately excluded from the network interface, and this is the most important decision in the mapping.** A ClusterIP is allocated from the cluster's service CIDR, which defaults to the same range on virtually every installation — so the same address identifies a *different* Service in every cluster. Importing two clusters would IP-match `kube-dns` in one onto `kube-dns` in the other and merge them into a single asset. They are also unreachable from outside the cluster, so they are of little correlation value even when unique. Both `spec.clusterIP` and `spec.clusterIPs` are kept as custom attributes instead. A Service with no routable ingress or external address therefore produces no asset at all — which is why a NodePort Service that exposes itself only through node addresses is skipped rather than imported with the node's identity.

The Node record also carries `status.nodeInfo.systemUUID` and `machineID`, both imported as custom attributes. Neither is used as identity, but they are the values that would let a Node be reconciled by hand against the same host seen through an agent — `machineID` in particular is the same `/etc/machine-id` value the `linux-ssh/` integration uses as *its* foreign id.

## Future

- **Vulnerabilities for the container images now imported as `Software`.** The Kubernetes API publishes no vulnerability data at all, so **`Vulnerability` records are out of reach from this source alone**. The image reference — repository plus tag or digest — is the join key against a container-image scanner (Trivy, Grype, a registry's own scanning), and that is the route by which CVEs would eventually reach pod assets.
- **Field selectors and phase filtering for pods.** Every pod in the cluster is fetched, including `Succeeded` and `Failed` ones that a completed Job left behind and that will never run again. `?fieldSelector=status.phase!=Succeeded` would drop those at the API server rather than importing them as assets, and a namespace filter would let an operator scope the import to the workloads they actually track.
- **Pods are attributed to their node only by name.** `k8s.pod.node_name` is `spec.nodeName`, a string, and nothing links a pod asset to the node asset it runs on. The Node UID is not carried on the Pod object, so building that link means indexing the node list by name during the run.
- **Ingresses for real external hostnames.** `/apis/networking.k8s.io/v1/ingresses` carries the hostnames and TLS configuration through which cluster workloads are actually published. Those are names runZero can resolve and scan from outside, which makes them far more useful for correlation than the synthesized `<name>.<namespace>.svc` form used today.
- **Incremental sync.** The list calls are now chunked (`limit=500` plus `continue`, with each asset reported as it is built), so memory stays bounded on a large cluster. The `resourceVersion` returned alongside each chunk is the basis for an incremental watch-based sync rather than a full walk, which is the remaining efficiency step.
- **Node conditions as health data.** `status.conditions` reports `Ready`, `MemoryPressure`, `DiskPressure`, and `PIDPressure`. The script imports `capacity` and `allocatable` but not the conditions, so a node that is present but `NotReady` looks identical to a healthy one in runZero.
- **Namespace and workload context.** Namespace labels and the Deployment, DaemonSet, and StatefulSet objects describe what a cluster is *for*, which turns an inventory of nodes into something an operator can navigate. Attached as attributes or tags, "every node running a workload from this namespace" becomes a runZero search.
- **A cluster identifier is missing, and it will matter.** Nothing in the imported attributes says which cluster an asset came from — UUID identity makes that safe for merging, but it makes multi-cluster reporting impossible: two nodes from two clusters are indistinguishable in a search. There is no canonical cluster id in the Kubernetes API, so the practical options are the `kube-system` namespace UID or an operator-supplied name, and either would have to be added as a parameter.
- **Outbound: label or annotate nodes with runZero data.** `PATCH /api/v1/nodes/{name}` would let runZero's classification reach the cluster, where scheduling constraints and policy can select on it. Note the cost honestly: this needs write access on nodes, which is a materially larger grant than the read-only ClusterRole this README recommends, and it would change the security posture of the credential for a benefit that is mostly cosmetic. Reading is where the value is here.
- **Coverage-gap reporting in both directions.** Node addresses that runZero has never scanned are usually on a cluster network no Explorer reaches — worth knowing, because that is where the kubelet and container runtime ports live. In the other direction, LoadBalancer ingress addresses are cluster workloads deliberately published to the network, and feeding them into runZero's own scan scope establishes what those services actually expose rather than what the Service object says they should.

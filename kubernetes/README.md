# Custom Integration: Kubernetes

Pulls cluster Nodes (and, optionally, LoadBalancer / NodePort Services) from
the Kubernetes API server and imports them as runZero assets.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations)
- An Explorer that has network reach to the Kubernetes API server

## Kubernetes requirements

- API server URL (e.g. `https://kubernetes.example.com:6443`)
- A ServiceAccount bearer token with read access to `nodes` (and
  `services`, if you want LoadBalancer ingress IPs).

### Create a read-only ServiceAccount and token

```sh
kubectl create serviceaccount runzero -n kube-system
kubectl create clusterrolebinding runzero-readonly \
  --clusterrole=view \
  --serviceaccount=kube-system:runzero
kubectl -n kube-system create token runzero --duration=8760h
```

The `view` ClusterRole already grants `get`/`list`/`watch` on `nodes` and
`services` and does **not** grant access to Secrets or pod logs.

## Steps

### Kubernetes configuration

1. Get the API server URL: `kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'`
2. Create the ServiceAccount, ClusterRoleBinding, and token (see above).
3. If your apiserver presents a self-signed certificate, set
   `INSECURE_SKIP_VERIFY = True` at the top of
   `kubernetes.star`. Prefer leaving it `False` and
   trusting the apiserver CA whenever possible.
4. To skip Services and only import Nodes, set
   `INCLUDE_LOADBALANCER_SERVICES = False`.

### runZero configuration

1. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Type: `Custom Integration Script Secrets`
    - `url`: the Kubernetes API server URL (e.g. `https://kubernetes.example.com:6443`)
    - `bearer_token`: the ServiceAccount bearer token
2. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon
    - Toggle `Enable custom integration script` and paste in the contents of
      `kubernetes.star`
    - Click `Validate`, then `Save`
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created above
    - Pick an Explorer that can reach the apiserver
    - Set the schedule and `Save`

### What's next?

- The task runs like any other ingestion task. Existing assets are merged
  on hostname / MAC / IP; new ones are created when nothing matches.
- Search for imported assets with `custom_integration:<your-integration-name>`.
- Node assets carry a rich `k8s.node.*` attribute set
  (kubelet/containerd versions, kernel, OS image, capacity, allocatable,
  pod CIDRs, labels, taints).
- Service assets are tagged `k8s-service` plus a type-specific tag
  (`k8s-svc-loadbalancer`, `k8s-svc-nodeport`).

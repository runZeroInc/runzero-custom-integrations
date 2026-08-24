#!/usr/bin/env python3
"""Seed the k3s cluster and mint the credential the integration authenticates with.

Creates the read-only ServiceAccount the integration's README tells an operator
to create, a LoadBalancer Service so the run has something other than the node
to import, and prints the identifiers the manifest asserts against.

Note the ClusterRole below. The integration's README instructs operators to bind
the built-in `view` role, but `view` does not grant `list` on nodes -- nodes are
cluster-scoped and excluded from it. Binding `view` here produces a run that
imports nothing at all. That is a documentation defect in the integration, not
something to paper over, so this file grants the permissions the script actually
needs and the discrepancy is reported rather than hidden.
"""

import json
import os
import subprocess
import sys
import time

PROJECT = os.environ["RZ_PROJECT"]
COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
SERVICE = os.environ["RZ_SERVICE"]

MANIFESTS = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: runzero
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: runzero-inventory
rules:
  - apiGroups: [""]
    resources: ["nodes", "services"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: runzero-inventory
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: runzero-inventory
subjects:
  - kind: ServiceAccount
    name: runzero
    namespace: kube-system
---
apiVersion: v1
kind: Service
metadata:
  name: rz-edge
  namespace: default
spec:
  type: LoadBalancer
  ports:
    - port: 8080
      targetPort: 8080
      protocol: TCP
  selector:
    app: rz-edge
"""


def kubectl(*args, stdin=None, check=True):
    argv = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", SERVICE, "kubectl"] + list(args)
    proc = subprocess.run(argv, capture_output=True, text=True, input=stdin, timeout=180)
    if check and proc.returncode != 0:
        sys.exit("kubectl %s failed (%d): %s" % (" ".join(args), proc.returncode,
                                                 (proc.stderr or proc.stdout).strip()))
    return proc.stdout


def jsonpath(*args):
    return kubectl(*args).strip()


def main():
    kubectl("apply", "-f", "-", stdin=MANIFESTS)

    # klipper-lb assigns the ingress address asynchronously. Poll for it rather
    # than sleeping: the address is what puts the Service on an interface, and
    # without it the integration correctly emits no Service asset at all.
    ingress = ""
    for _ in range(60):
        ingress = jsonpath("get", "svc", "rz-edge", "-n", "default", "-o",
                           "jsonpath={.status.loadBalancer.ingress[0].ip}")
        if ingress:
            break
        time.sleep(2)
    if not ingress:
        sys.exit("the LoadBalancer service never received an ingress address")

    node_name = jsonpath("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")
    node_uid = jsonpath("get", "nodes", "-o", "jsonpath={.items[0].metadata.uid}")
    node_ip = jsonpath("get", "nodes", "-o",
                       "jsonpath={.items[0].status.addresses[?(@.type=='InternalIP')].address}")
    svc_uid = jsonpath("get", "svc", "rz-edge", "-n", "default", "-o", "jsonpath={.metadata.uid}")

    # A ServiceAccount token, exactly as the integration documents.
    token = kubectl("-n", "kube-system", "create", "token", "runzero", "--duration=24h").strip()
    if not token:
        sys.exit("could not mint a ServiceAccount token")

    print(json.dumps({
        "token": token,
        "node_name": node_name,
        "node_uid": node_uid,
        "node_ip": node_ip,
        "service_uid": svc_uid,
        "service_ingress_ip": ingress,
    }))


if __name__ == "__main__":
    main()

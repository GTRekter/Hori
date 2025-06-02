+++
author = "Ivan Porta"
title = "Control Plane"
date = "2025-06-01"
description = "Deep dive into Linkerd’s control-plane architecture—destination, identity, policy, and proxy-injector controllers—and how they coordinate gRPC traffic and leader election in Kubernetes."
tags = [
  "linkerd",
  "control-plane",
  "architecture",
  "kubernetes",
  "deep-dive"
]
+++

# Control Plane

Linkerd Service Mesh has a two layer archtitecture with:
- **Control Plane:** composed by the destination, policy, identity, sp-validatior and proxy-injector controllers
- **Data Plane:** composed by the proxies running alongside the applications in the same pod and taking care of managin all the inbound/outbound communications.

The Control Plane and the proxies communicate via gRPC, while the proxies communivate via HTTP/2.

# Prerequisites

- macOS/Linux/Windows with a Unix‑style shell
- k3d (v5+) for local Kubernetes clusters
- kubectl (v1.25+)
- Helm (v3+)
- Smallstep (step) CLI for certificate generation

# Tutorial

## 1. Create the configuration files

```
cat << 'EOF' > audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["*"]
  - level: RequestResponse
    resources:
      - group: "linkerd.io"
        resources: ["*"]
      - group: "policy.linkerd.io"
        resources: ["*"]
      - group: "gateway.networking.k8s.io"
        resources: ["*"]
  - level: None
EOF
cat << 'EOF' > cluster.yaml
apiVersion: k3d.io/v1alpha5
kind: Simple
metadata:
  name: "cluster"
servers: 1
agents: 0
image: rancher/k3s:v1.33.0-k3s1
network: playground
options:
  k3s:
    extraArgs:
      - arg: --disable=traefik
        nodeFilters: ["server:*"]
      - arg: --cluster-cidr=10.23.0.0/16
        nodeFilters: ["server:*"]
      - arg: --service-cidr=10.247.0.0/16
        nodeFilters: ["server:*"]
      - arg: --debug
        nodeFilters: ["server:*"]
      - arg: --kube-apiserver-arg=audit-policy-file=/etc/rancher/k3s/audit-policy.yaml
        nodeFilters: ["server:*"]
      - arg: --kube-apiserver-arg=audit-log-path=/var/log/kubernetes/audit/audit.log
        nodeFilters: ["server:*"]
ports:
  - port: 8081:80
    nodeFilters: ["loadbalancer"]
volumes:
  - volume: "<LOCAL-FULL-PATH>/audit-policy.yaml:/etc/rancher/k3s/audit-policy.yaml"
    nodeFilters: ["server:*"]
EOF
```

## 2. Create a Local Kubernetes Cluster

Use k3d and your cluster.yaml to spin up a lightweight Kubernetes cluster:

```
k3d cluster create --kubeconfig-update-default \
  -c ./cluster.yaml
```

## 3. Generate Identity Certificates

Linkerd requires a trust anchor (root CA) and an issuer (intermediate CA) for mTLS identity.

```
step certificate create root.linkerd.cluster.local ./certificates/ca.crt ./certificates/ca.key \
    --profile root-ca \
    --no-password \
    --insecure
step certificate create identity.linkerd.cluster.local ./certificates/issuer.crt ./certificates/issuer.key \
    --profile intermediate-ca \
    --not-after 8760h \
    --no-password \
    --insecure \
    --ca ./certificates/ca.crt \
    --ca-key ./certificates/ca.key
```

## 4. Install Linkerd via Helm

```
helm repo add linkerd-edge https://helm.linkerd.io/edge
helm repo update
helm install linkerd-crds linkerd-edge/linkerd-crds \
  -n linkerd --create-namespace --set installGatewayAPI=true
helm upgrade --install linkerd-control-plane \
  -n linkerd \
  --set-file identityTrustAnchorsPEM=./certificates/ca.crt \
  --set-file identity.issuer.tls.crtPEM=./certificates/issuer.crt \
  --set-file identity.issuer.tls.keyPEM=./certificates/issuer.key \
  --set controllerLogLevel=debug \
  --set policyController.logLevel=debug \
  --set policyController.logLevel=debug \
  linkerd-edge/linkerd-control-plane
```

## 5. Linkerd Destination 

Linkerd destination index the data retrieved by the Kuberentes API so that when a proxy is asking for these informations they are available.

```
kubectl logs -n linkerd deploy/linkerd-destination -c destination --follow
...
time="2025-05-19T08:52:47Z" level=debug msg="Adding ES default/kubernetes" addr=":8086" component=service-publisher ns=default svc=kubernetes
...
time="2025-05-19T08:52:47Z" level=debug msg="Adding ES linkerd/linkerd-dst-g7mvf" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-dst
...
time="2025-05-19T08:52:47Z" level=info  msg="caches synced"
...
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/nodes?allowWatchBookmarks=true&resourceVersion=10726&timeout=5m7s&timeoutSeconds=307&watch=true 200 OK in 2 milliseconds"
```

Linkerd’s destination component doesn’t poll the API server with repeated GET calls—instead it opens long-lived watch streams (parameter &watch=0) so it can receive change events as they happen. Destination maintains an in-memory cache of which pods back which services and gets notified instantly of adds/updates/deletes. If you check the logs of the Requests to the Kubernetes API collected via the Audit mode, you will see the enstablish of the connection.

```
docker exec -it k3d-cluster-server-0 sh -c 'grep linkerd /var/log/kubernetes/audit/audit.log'
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"6780ab29-bdb9-4f60-9ac4-906f8901c0ac","stage":"ResponseComplete","requestURI":"/api/v1/services?allowWatchBookmarks=true\u0026resourceVersion=745\u0026timeout=6m45s\u0026timeoutSeconds=405\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"services","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2025-05-19T09:37:51.360338Z","stageTimestamp":"2025-05-19T09:44:36.347050Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"linkerd-linkerd-destination\" of ClusterRole \"linkerd-linkerd-destination\" to ServiceAccount \"linkerd-destination/linkerd\""}}
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"28ab3987-e67b-4cda-8e0d-1e8754bbb125","stage":"RequestReceived","requestURI":"/api/v1/services?allowWatchBookmarks=true\u0026resourceVersion=1115\u0026timeout=7m38s\u0026timeoutSeconds=458\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"services","apiVersion":"v1"},"requestReceivedTimestamp":"2025-05-19T09:44:36.348992Z","stageTimestamp":"2025-05-19T09:44:36.348992Z"}
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"28ab3987-e67b-4cda-8e0d-1e8754bbb125","stage":"ResponseStarted","requestURI":"/api/v1/services?allowWatchBookmarks=true\u0026resourceVersion=1115\u0026timeout=7m38s\u0026timeoutSeconds=458\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"services","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2025-05-19T09:44:36.348992Z","stageTimestamp":"2025-05-19T09:44:36.350388Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"linkerd-linkerd-destination\" of ClusterRole \"linkerd-linkerd-destination\" to ServiceAccount \"linkerd-destination/linkerd\""}}
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"7e656540-35ea-460e-afe1-2ba7eae26912","stage":"ResponseComplete","requestURI":"/api/v1/endpoints?allowWatchBookmarks=true\u0026resourceVersion=747\u0026timeout=6m47s\u0026timeoutSeconds=407\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"endpoints","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2025-05-19T09:37:51.360352Z","stageTimestamp":"2025-05-19T09:44:38.348080Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"linkerd-linkerd-destination\" of ClusterRole \"linkerd-linkerd-destination\" to ServiceAccount \"linkerd-destination/linkerd\"","k8s.io/deprecated":"true"}}
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"617cc8c5-69f6-407f-96e9-478cd2decd6c","stage":"RequestReceived","requestURI":"/api/v1/endpoints?allowWatchBookmarks=true\u0026resourceVersion=1119\u0026timeout=6m49s\u0026timeoutSeconds=409\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"endpoints","apiVersion":"v1"},"requestReceivedTimestamp":"2025-05-19T09:44:38.349086Z","stageTimestamp":"2025-05-19T09:44:38.349086Z"}
...
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"617cc8c5-69f6-407f-96e9-478cd2decd6c","stage":"ResponseStarted","requestURI":"/api/v1/endpoints?allowWatchBookmarks=true\u0026resourceVersion=1119\u0026timeout=6m49s\u0026timeoutSeconds=409\u0026watch=true","verb":"watch","user":{"username":"system:serviceaccount:linkerd:linkerd-destination","uid":"48a11242-4481-40fb-a400-71bab76ceb26","groups":["system:serviceaccounts","system:serviceaccounts:linkerd","system:authenticated"],"extra":{"authentication.kubernetes.io/credential-id":["JTI=17ab4926-813f-4ffe-9173-f288d07c1b31"],"authentication.kubernetes.io/node-name":["k3d-cluster-server-0"],"authentication.kubernetes.io/node-uid":["9aef01ef-f1d5-49ba-97e6-9c38c1101007"],"authentication.kubernetes.io/pod-name":["linkerd-destination-7d6c6c7775-49tpt"],"authentication.kubernetes.io/pod-uid":["150aeb23-56c8-4b3c-aa23-c40779154fd2"]}},"sourceIPs":["10.23.0.6"],"userAgent":"controller/v0.0.0 (linux/arm64) kubernetes/$Format","objectRef":{"resource":"endpoints","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2025-05-19T09:44:38.349086Z","stageTimestamp":"2025-05-19T09:44:38.349832Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"linkerd-linkerd-destination\" of ClusterRole \"linkerd-linkerd-destination\" to ServiceAccount \"linkerd-destination/linkerd\""}}
```

Linkerd’s destination controller uses a leader/follower model. It leverages Kubernetes’s native coordination.k8s.io/v1 leases API to perform leader election. By default it renews its lease every ~2 seconds—each successful PUT …/leases/... 200 OK confirms it remains the active leader. If it fails (e.g. due to a crash or network partition), the lease expires and another instance takes over.

```
time="2025-05-19T08:53:23Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 2 milliseconds"
...
time="2025-05-19T08:53:25Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 6 milliseconds"
```

## 6. Linkerd Proxy-Injector

It's using a mutating webhook to intercept the requests to the kubernetes API when a new pod is created, then check the annotations and if there is `linkerd.io/injected: enabled` then inject a Linkerd proxy and ProxyInit containers.

## References

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
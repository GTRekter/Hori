+++
title = "Destination"
author = "Ivan Porta"
tags = ["index"]
type = "bookcase"
bookcase_cover_src = 'control-plane/destination.png'
bookcase_cover_src_dark = 'control-plane/destination_white.png'
+++

Deep dive into Linkerd’s Destination controller—how it leverages informers, watches EndpointSlices, and performs leader election to serve service discovery in Kubernetes.



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
  linkerd-edge/linkerd-control-plane
```

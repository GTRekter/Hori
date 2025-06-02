+++
author = "Ivan Porta"
title = "Timeouts"
date = "2025-06-01"
description = "Practical guide to configuring request, response, and idle timeouts in Linkerd using Kubernetes service annotations—complete with hands-on examples."
tags = [
  "linkerd",
  "timeouts",
  "service-annotations",
  "kubernetes",
  "tutorial"
]
+++

# Timeouts

Linkerd provides fine‑grained timeout settings to control the lifecycle of HTTP requests and TCP connections between services in your mesh. You can configure three primary timeout policies via Kubernetes service annotations:

- **timeout.linkerd.io/request:** Maximum time from when a request is sent until the first byte of the request body arrives at the server.
- **timeout.linkerd.io/response:** Maximum time from when the first byte of the response header is received until the entire response body is delivered.
- **timeout.linkerd.io/idle:** Maximum time of inactivity between data frames (both request and response) before the connection is closed.

# Prerequisites

- macOS/Linux/Windows with a Unix‑style shell
- k3d (v5+) for local Kubernetes clusters
- kubectl (v1.25+)
- Helm (v3+)
- Smallstep (step) CLI for certificate generation

# Tutorial

## 1. Create the configuration files

```
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
ports:
  - port: 8081:80
    nodeFilters: ["loadbalancer"]
EOF
cat << 'EOF' > application.yaml
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: simple-app
  annotations:
    linkerd.io/inject: enabled
spec:
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["sleep", "infinity"]
---
apiVersion: v1
kind: Namespace
metadata:
  name: simple-app
  annotations:
    linkerd.io/inject: enabled
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: server
  namespace: simple-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: server
      version: v1
  template:
    metadata:
      labels:
        app: server
        version: v1
    spec:
      containers:
        - name: http-app
          image: kong/httpbin:latest
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: server
  namespace: simple-app
spec:
  selector:
    app: server
    version: v1
  ports:
    - port: 80
      targetPort: 80
EOF
```

## 2. Create a Local Kubernetes Cluster

Use k3d and your cluster.yaml to spin up a lightweight Kubernetes cluster:

```
k3d cluster create  --kubeconfig-update-default \
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
helm install linkerd-control-plane \
  -n linkerd \
  --set-file identityTrustAnchorsPEM=./certificates/ca.crt \
  --set-file identity.issuer.tls.crtPEM=./certificates/issuer.crt \
  --set-file identity.issuer.tls.keyPEM=./certificates/issuer.key \
  linkerd-edge/linkerd-control-plane
```

## 5. Deploy the Sample Application

```
kubectl apply -f ./application.yaml
```

You can then validate that the traffic is going from the client's pod to server's deployment

```
kubectl exec -n simple-app client -c curl -- sh -c '\
  curl -sS --no-progress-meter \
    -X POST \
    -H "Content-Type: application/json" \
    -o /dev/null \
    -w "HTTPSTATUS:%{http_code}\n" \
    http://server.simple-app.svc.cluster.local/post \
'
```

# Timeout Scenarios

Below are examples of how to annotate your server service and test each timeout policy.

## 1. Request Timeout (timeout.linkerd.io/request)

Limit the time to upload the entire request body by setting the following annotation to the server's service.

```
kubectl annotate svc server \
  -n simple-app \
  timeout.linkerd.io/request=1s \
  timeout.linkerd.io/response=1h \
  timeout.linkerd.io/idle=1h \
  --overwrite
```

Throttle the upload to take longer than 1s (100 KB at 20 KB/s):

```
kubectl exec -n simple-app client -c curl -- sh -c '\
  yes a | head -c 100000 > /tmp/payload.json && \
  curl -sS --no-progress-meter \
    --limit-rate 20K \
    -X POST \
    -H "Content-Type: application/json" \
    --data-binary @/tmp/payload.json \
    -o /dev/null \
    -w "HTTPSTATUS:%{http_code}\n" \
    http://server.simple-app.svc.cluster.local/post \
'
```

## 2. Response Timeout (timeout.linkerd.io/response)

Limit the time to receive the full response by setting the following annotation to the server's service.

```
kubectl annotate svc server \
  -n simple-app \
  timeout.linkerd.io/request=1h \
  timeout.linkerd.io/response=1s \
  timeout.linkerd.io/idle=1h \
  --overwrite
```

Use HTTPBin’s /delay/5 endpoint to delay the response >5s:

```
kubectl exec -n simple-app client -c curl -- sh -c '\
  curl -sS --no-progress-meter \
    -X POST \
    -H "Content-Type: application/json" \
    -o /dev/null \
    -w "HTTPSTATUS:%{http_code}\n" \
    http://server.simple-app.svc.cluster.local/delay/5 \
'
```

## References

- https://linkerd.io/2.18/reference/timeouts/
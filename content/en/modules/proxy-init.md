+++
author = "Ivan Porta"
title = "Proxy-Init"
date = "2025-06-01"
description = "Lorem Ipsum Dolor Si Amet"
tags = [
    "markdown",
    "text",
]
+++

The `linkerd-init` container is added to each meshed pod as a Kubernetes init container that runs before any other containers start. It configures `iptables` rules that redirect all TCP traffic to and from the pod through the Linkerd proxy.

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
```

## 2. Create a Local Kubernetes Cluster

Use k3d and the `cluster.yaml` to spin up a lightweight Kubernetes cluster:

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

## 5. Inspect the Linkerd destination pod

Inspect the `linkerd-destination` pod to view the `linkerd-init` container and the arguments provided by the default Helm chart installation, which are passed to the init script.

```
kubectl describe pod -n linkerd                  linkerd-destination-8696d67545-4d4hj 
Name:             linkerd-destination-8696d67545-4d4hj
Namespace:        linkerd
...
Init Containers:
  linkerd-init:
    Container ID:    containerd://30f1e3964e09df03c043c38911fa521766cc71b0061ff12a8db53730ea14f4ec
    Image:           cr.l5d.io/linkerd/proxy-init:v2.4.2
    Image ID:        cr.l5d.io/linkerd/proxy-init@sha256:fa4ffce8c934f3a6ec89e97bda12d94b1eb485558681b9614c9085e37a1b4014
    Port:            <none>
    Host Port:       <none>
    SeccompProfile:  RuntimeDefault
    Args:
      --ipv6=false
      --incoming-proxy-port
      4143
      --outgoing-proxy-port
      4140
      --proxy-uid
      2102
      --inbound-ports-to-ignore
      4190,4191,4567,4568
      --outbound-ports-to-ignore
      443,443
    State:          Terminated
      Reason:       Completed
      Exit Code:    0
      Started:      Sun, 18 May 2025 23:42:27 +0900
      Finished:     Sun, 18 May 2025 23:42:27 +0900
    Ready:          True
    Restart Count:  0
    Environment:    <none>
    Mounts:
      /run from linkerd-proxy-init-xtables-lock (rw)
    ...
```

## 6. Deploy a debug container

To inspect iptables rules without restarting the pod, deploy a debug container running Ubuntu with the `netadmin` profile, which grants the necessary `NET_ADMIN` capability:

```
kubectl debug -n linkerd deploy/linkerd-destination \
  -it \
  --image=ubuntu:22.04 \
  --target=destination \
  --profile=netadmin \
  -- bash -il
```

Install `iptables` inside the container:

```
apt-get update && apt-get install -y iptables
```

## 7. Check the iptables

Now that the debug container is running and iptables is installed, you can inspect the chain rules. Let's start with the inbound `PREROUTING` chain

```
iptables-legacy -t nat -L PREROUTING -n -v
Chain PREROUTING (policy ACCEPT 3095 packets, 186K bytes)
 pkts bytes target               prot opt in     out     source               destination         
12412  745K PROXY_INIT_REDIRECT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/install-proxy-init-prerouting */
```

All ingress packets first hit the `PROXY_INIT_REDIRECT` chain:

```
iptables-legacy -t nat -L PROXY_INIT_REDIRECT -n -v
Chain PROXY_INIT_REDIRECT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 3096  186K RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 4190,4191,4567,4568 /* proxy-init/ignore-port-4190,4191,4567,4568 */
 9320  559K REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-incoming-to-proxy-port */ redir ports 4143
```

- The first rule bypasses redirection for traffic to ports `4190`, `4191`, `4567`, and `4568`.
- The second rule sends all other inbound TCP traffic to the Linkerd proxy's inbound listener on port `4143`.

```
iptables-legacy -t nat -L PROXY_INIT_REDIRECT -n -v
Chain PROXY_INIT_REDIRECT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 3096  186K RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 4190,4191,4567,4568 /* proxy-init/ignore-port-4190,4191,4567,4568 */
 9320  559K REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-incoming-to-proxy-port */ redir ports 4143
```

Let's take a look at the outbound with the `OUTPUT` chain.

```
iptables-legacy -t nat -L OUTPUT     -n -v
Chain OUTPUT (policy ACCEPT 9360 packets, 562K bytes)
 pkts bytes target             prot opt in     out     source               destination         
 9364  563K PROXY_INIT_OUTPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/install-proxy-init-output */
```

- Similarly to the inbound, all outbound traffic will hits the `PROXY_INIT_OUTPUT` chain. 

```
iptables-legacy -t nat -L PROXY_INIT_OUTPUT   -n -v
Chain PROXY_INIT_OUTPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 9320  559K RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 2102 /* proxy-init/ignore-proxy-user-id */
    0     0 RETURN     all  --  *      lo      0.0.0.0/0            0.0.0.0/0            /* proxy-init/ignore-loopback */
   26  1560 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 443,6443 /* proxy-init/ignore-port-443,6443 */
    4   240 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-outgoing-to-proxy-port */ redir ports 4140
```

- The first rule skips redirection for traffic originating from the proxy itself (UID 2102).
- The second rule will skip loopback traffic. 
- The third rule will skips traffic destined for ports `443` and `6443` (Kubernetes API and control plane).
- Finally, the last rule will send all other outbound TCP traffic to the proxy’s outbound listener on port `4140`.

## References

- https://linkerd.io/2-edge/reference/architecture/
- https://github.com/linkerd/linkerd2-proxy-init/blob/main/proxy-init/cmd/root.go
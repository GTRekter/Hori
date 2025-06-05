---
title: '프록시 초기화'
author: "Ivan Porta"
date: "2025-06-01"
description: "Linkerd proxy-init 컨테이너 심층 분석—메시 내 파드 트래픽을 우회하기 위해 iptables 규칙을 주입하는 방식과 Kubernetes에서 그 규칙을 확인하는 방법을 다룹니다."
tags: [
  "linkerd",
  "proxy-init",
  "iptables",
  "kubernetes",
  "deep-dive"
]
bookcase_cover_src: 'data-plane/proxy-init.png'
bookcase_cover_src_dark: 'data-plane/proxy-init_white.png'
---

# 프록시 초기화

`linkerd-init` 컨테이너는 메시 네트워크에 주입된 모든 파드에 쿠버네티스 **Init 컨테이너**로 추가되며, 애플리케이션 컨테이너들보다 먼저 실행됩니다. 이 컨테이너는 `iptables` 규칙을 설정해 파드로 들어오고 나가는 모든 TCP 트래픽을 Linkerd 프록시로 우회시킵니다.

# 사전 요구 사항

- Unix-스타일 셸이 가능한 macOS/Linux/Windows
- 로컬 쿠버네티스 클러스터용 k3d(v5+)
- kubectl(v1.25+)
- Helm(v3+)
- 인증서 생성을 위한 Smallstep(step) CLI

# 튜토리얼

## 1. 구성 파일 생성

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

## 2. 로컬 쿠버네티스 클러스터 생성

`cluster.yaml`을 이용해 k3d로 가벼운 쿠버네티스 클러스터를 띄웁니다:

```
k3d cluster create --kubeconfig-update-default \
  -c ./cluster.yaml
```

## 3. ID 인증서 생성

Linkerd는 mTLS ID를 위해 신뢰 앵커(루트 CA)와 발급자(중간 CA)가 필요합니다.

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

## 4. Helm으로 Linkerd 설치

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

## 5. Linkerd destination 파드 확인

`linkerd-destination` 파드를 살펴보면 Helm 기본 값으로 전달된 인수들과 `linkerd-init` 컨테이너를 볼 수 있습니다:

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

## 6. 디버그 컨테이너 배포

파드를 재시작하지 않고 `iptables` 규칙을 확인하려면 `netadmin` 프로필이 적용된 Ubuntu 디버그 컨테이너를 주입합니다:

```
kubectl debug -n linkerd deploy/linkerd-destination \
  -it \
  --image=ubuntu:22.04 \
  --target=destination \
  --profile=netadmin \
  -- bash -il
```

컨테이너 안에서 `iptables`를 설치합니다:

```
apt-get update && apt-get install -y iptables
```

## 7. iptables 확인

이제 디버그 컨테이너에서 체인 규칙을 확인할 수 있습니다. 먼저 인바운드 `PREROUTING` 체인을 살펴봅니다:

```
iptables-legacy -t nat -L PREROUTING -n -v
Chain PREROUTING (policy ACCEPT 3095 packets, 186K bytes)
 pkts bytes target               prot opt in     out     source               destination         
12412  745K PROXY_INIT_REDIRECT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/install-proxy-init-prerouting */
```

모든 인바운드 패킷은 우선 `PROXY_INIT_REDIRECT` 체인으로 전달됩니다:

```
iptables-legacy -t nat -L PROXY_INIT_REDIRECT -n -v
Chain PROXY_INIT_REDIRECT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 3096  186K RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 4190,4191,4567,4568 /* proxy-init/ignore-port-4190,4191,4567,4568 */
 9320  559K REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-incoming-to-proxy-port */ redir ports 4143
```

첫 번째 규칙은 포트 4190, 4191, 4567, 4568로 향하는 트래픽을 우회합니다.
두 번째 규칙은 그 외 모든 인바운드 TCP 트래픽을 프록시의 인바운드 리스너(포트 4143)로 리다이렉트합니다.

```
iptables-legacy -t nat -L PROXY_INIT_REDIRECT -n -v
Chain PROXY_INIT_REDIRECT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 3096  186K RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 4190,4191,4567,4568 /* proxy-init/ignore-port-4190,4191,4567,4568 */
 9320  559K REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-incoming-to-proxy-port */ redir ports 4143
```

다음으로 아웃바운드를 `OUTPUT` 체인에서 확인합니다.

```
iptables-legacy -t nat -L OUTPUT     -n -v
Chain OUTPUT (policy ACCEPT 9360 packets, 562K bytes)
 pkts bytes target             prot opt in     out     source               destination         
 9364  563K PROXY_INIT_OUTPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/install-proxy-init-output */
```

`PROXY_INIT_OUTPUT` 체인 규칙:

```
iptables-legacy -t nat -L PROXY_INIT_OUTPUT   -n -v
Chain PROXY_INIT_OUTPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 9320  559K RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            owner UID match 2102 /* proxy-init/ignore-proxy-user-id */
    0     0 RETURN     all  --  *      lo      0.0.0.0/0            0.0.0.0/0            /* proxy-init/ignore-loopback */
   26  1560 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 443,6443 /* proxy-init/ignore-port-443,6443 */
    4   240 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* proxy-init/redirect-all-outgoing-to-proxy-port */ redir ports 4140
```

- 첫 번째 규칙은 프록시 자체(UID 2102)에서 발생한 트래픽을 제외합니다.
- 두 번째 규칙은 루프백 트래픽을 제외합니다.
- 세 번째 규칙은 포트 443 및 6443(쿠버네티스 API/제어 플레인)을 제외합니다.
- 마지막 규칙은 그 외 모든 아웃바운드 TCP 트래픽을 프록시의 아웃바운드 리스너(포트 4140)로 리다이렉트합니다.

## 참고 자료

- https://linkerd.io/2-edge/reference/architecture/
- https://github.com/linkerd/linkerd2-proxy-init/blob/main/proxy-init/cmd/root.go
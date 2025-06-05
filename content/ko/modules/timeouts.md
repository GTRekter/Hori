---
title: '타임아웃'
author: "Ivan Porta"
date: "2025-06-01"
description: "쿠버네티스 서비스 애너테이션으로 Linkerd의 요청·응답·유휴 타임아웃을 설정하는 실전 가이드—핸즈온 예제까지 제공합니다"
tags: [
  "linkerd",
  "timeouts",
  "service-annotations",
  "kubernetes",
  "tutorial"
]
bookcase_cover_src: 'modules/timeouts.png'
bookcase_cover_src_dark: 'modules/timeouts_white.png'
---

# 타임아웃

Linkerd는 메시 내 서비스 간 HTTP 요청 및 TCP 연결의 수명을 세밀하게 제어할 수 있도록 다양한 타임아웃 설정을 제공합니다. 쿠버네티스 서비스 애너테이션을 통해 다음 세 가지 기본 타임아웃 정책을 설정할 수 있습니다.

- **timeout.linkerd.io/request:** 클라이언트가 요청을 전송한 순간부터 서버가 요청 본문의 첫 바이트를 수신할 때까지의 최대 시간
- **timeout.linkerd.io/response:** 서버 응답 헤더의 첫 바이트를 받은 순간부터 전체 응답 본문이 전달될 때까지의 최대 시간
- **timeout.linkerd.io/idle:** 요청·응답 데이터 프레임 사이에 트래픽이 없을 때 연결을 닫기 전까지 허용되는 최대 유휴 시간

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

## 2. 로컬 쿠버네티스 클러스터 생성

`cluster.yaml`을 이용해 k3d로 가벼운 쿠버네티스 클러스터를 띄웁니다:

```
k3d cluster create  --kubeconfig-update-default \
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
helm install linkerd-control-plane \
  -n linkerd \
  --set-file identityTrustAnchorsPEM=./certificates/ca.crt \
  --set-file identity.issuer.tls.crtPEM=./certificates/issuer.crt \
  --set-file identity.issuer.tls.keyPEM=./certificates/issuer.key \
  linkerd-edge/linkerd-control-plane
```

## 5. 샘플 애플리케이션 배포

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

# 타임아웃 시나리오

아래 예시는 서버 서비스에 애너테이션을 추가한 뒤 각 타임아웃 정책을 테스트하는 방법을 보여 줍니다.

## 1. 요청 타임아웃(timeout.linkerd.io/request)

요청 본문 업로드 시간을 제한하려면 다음과 같이 애너테이션을 설정합니다.

```
kubectl annotate svc server \
  -n simple-app \
  timeout.linkerd.io/request=1s \
  timeout.linkerd.io/response=1h \
  timeout.linkerd.io/idle=1h \
  --overwrite
```

업로드를 1 초 이상 지연시키려면(100 KB를 20 KB/s로 업로드):

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

## 2. 응답 타임아웃(timeout.linkerd.io/response)

전체 응답을 받을 시간을 제한하려면 다음과 같이 애너테이션을 설정합니다.

```
kubectl annotate svc server \
  -n simple-app \
  timeout.linkerd.io/request=1h \
  timeout.linkerd.io/response=1s \
  timeout.linkerd.io/idle=1h \
  --overwrite
```

HTTPBin의 /delay/5 엔드포인트를 사용해 5초 이상 지연된 응답을 테스트합니다.

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

## 참고 자료

- https://linkerd.io/2.18/reference/timeouts/
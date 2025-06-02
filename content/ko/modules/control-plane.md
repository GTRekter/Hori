+++
author = "Ivan Porta"
title = "컨트롤 플레인"
date = "2025-06-01"
description = "Linkerd 컨트롤 플레인 아키텍처 심층 분석—destination, identity·policy, proxy-injector 컨트롤러가 Kubernetes에서 gRPC 트래픽과 리더 선출을 어떻게 조정하는지 살펴봅니다."

tags = [
  "linkerd",
  "control-plane",
  "architecture",
  "kubernetes",
  "deep-dive"
]
+++

# 컨트롤 플레인

Linkerd 서비스 메시의 아키텍처는 두 계층으로 구성됩니다.  
- **제어 플레인(Control Plane):** destination, policy, identity, sp-validator, proxy-injector 컨트롤러로 이루어져 있습니다.  
- **데이터 플레인(Data Plane):** 애플리케이션과 동일한 파드 안에서 함께 실행되는 프록시들이 모든 인바운드/아웃바운드 통신을 처리합니다.  

제어 플레인과 프록시는 gRPC로 통신하며, 프록시 간 통신은 HTTP/2를 사용합니다.

# 사전 요구 사항

- Unix-스타일 셸이 가능한 macOS/Linux/Windows
- 로컬 쿠버네티스 클러스터용 k3d(v5+)
- kubectl(v1.25+)
- Helm(v3+)
- 인증서 생성을 위한 Smallstep(step) CLI

# 튜토리얼

## 1. 구성 파일 생성

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

## 5. Linkerd Destination

Linkerd Destination은 Kubernetes API에서 가져온 데이터를 인덱싱하여, 프록시가 정보를 요청할 때 즉시 반환할 수 있도록 준비합니다.

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

Destination 컴포넌트는 반복적인 GET 호출로 API 서버를 폴링하지 않고, `watch=true` 파라미터로 장기 스트림을 열어 실시간 변경 이벤트를 수신합니다. 이렇게 하여 서비스와 파드 매핑을 메모리에 캐시하고, 추가·업데이트·삭제를 즉시 감지합니다. 감사(Audit) 로그를 확인하면 이러한 연결이 생성되는 것을 볼 수 있습니다.

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

Linkerd Destination 컨트롤러는 리더/팔로어 모델을 사용하며, Kubernetes coordination.k8s.io/v1 Lease API를 통해 리더 선출을 수행합니다. 기본적으로 약 2초마다 리스를 갱신하며(`PUT …/leases/... 200 OK`), 실패 시 다른 인스턴스가 리더를 승계합니다.

```
time="2025-05-19T08:53:23Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 2 milliseconds"
...
time="2025-05-19T08:53:25Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 6 milliseconds"
```

## 6. Linkerd Proxy-Injector

Proxy-Injector는 변형(Mutating) Webhook을 사용해 새 파드 생성 요청을 가로채고, 어노테이션에 `linkerd.io/injected: enabled`가 있으면 Linkerd Proxy 및 ProxyInit 컨테이너를 주입합니다.

## 참고 자료

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
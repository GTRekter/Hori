---
title: '인증서'
author: "Ivan Porta"
date: "2025-06-01"
description: "Linkerd의 인증서 계층 구조 심층 분석: 제어 플레인이 메시 전반에서 mTLS ID를 발급·저장·갱신하는 방법"
tags: [
  "linkerd",
  "certificates",
  "mTLS",
  "identity",
  "deep-dive"
]
bookcase_cover_src: 'modules/certificates.png'
bookcase_cover_src_dark: 'modules/certificates_white.png'
---

# 인증서

Linkerd는 메시 네트워크에 포함된 파드 간의 모든 TCP 트래픽에 대해 자동으로 mTLS를 활성화합니다. 이를 위해 제어 플레인이 정상적으로 동작하려면 여러 인증서가 준비되어 있어야 합니다. 설치 과정에서 직접 제공할 수도 있고, Cert-Manager나 Trust-Manager 같은 서드파티 도구를 사용할 수도 있습니다. 

![Certificate Hierarchy](modules/certificates/hierarchy.jpg)


# 사전 요구 사항

- Unix-스타일 셸이 가능한 macOS/Linux/Windows
- 로컬 쿠버네티스 클러스터용 k3d(v5+)
- kubectl(v1.25+)

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

`cluster.yaml`을 이용해 k3d로 가벼운 쿠버네티스 클러스터를 띄웁니다.

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

## 
## 5. 루트 신뢰 앵커 인증서

Linkerd의 루트 신뢰 앵커는 모든 서비스 메시 인증서에 대한 궁극적인 신뢰 지점을 설정하는 공개 CA 인증서입니다. 이 인증서는 워크로드 인증서를 직접 발급하지 않고, 대신 중간 CA 인증서를 서명해 워크로드 인증서를 발급하도록 합니다. 이렇게 분리함으로써 각 클러스터(또는 다중 클러스터)가 자체 발급자를 실행하면서도 동일한 루트 앵커를 통해 검증할 수 있어, 매일 루트 키를 노출하지 않고도 메시 전체의 신뢰를 유지할 수 있습니다.

루트 신뢰 앵커 인증서(공개 키만 포함)는 `linkerd-identity-trust-roots`라는 ConfigMap에 저장됩니다. 개인 키가 없으므로 평문으로 보관해도 안전하며, 모든 중간 및 엔티티 인증서의 신뢰 부트스트랩에 사용됩니다. 대부분의 엔터프라이즈에서는 자체 PKI를 운영하며, 이를 통해 새 중간 인증서를 생성해 사용하곤 합니다.

새 Linkerd 프록시가 워크로드 파드에 주입되면 환경 변수와 마운트 볼륨을 통해 신뢰 구성을 받습니다.


```
linkerd-proxy:
    Container ID:    containerd://f348b4bebec14d557c44951f309e07fac969de2ea93f20e9d1920b4a8e02180e
    Image:           cr.l5d.io/linkerd/proxy:edge-25.5.3
    ...
    Environment:
     ...
      LINKERD2_PROXY_IDENTITY_DIR:                               /var/run/linkerd/identity/end-entity
      LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS:                     <set to the key 'ca-bundle.crt' of config map 'linkerd-identity-trust-roots'>  Optional: false
      LINKERD2_PROXY_IDENTITY_TOKEN_FILE:                        /var/run/secrets/tokens/linkerd-identity-token
      ...
    Mounts:
      /var/run/linkerd/identity/end-entity from linkerd-identity-end-entity (rw)
      /var/run/secrets/tokens from linkerd-identity-token (rw)
...
Volumes:
  trust-roots:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      linkerd-identity-trust-roots
    Optional:  false
  linkerd-identity-token:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  86400
  linkerd-identity-end-entity:
    Type:        EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:      Memory
    SizeLimit:   <unset>
```

프록시가 시작되면, `LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS`에 정의된 신뢰 앵커를 로드합니다. 이어서 `LINKERD2_PROXY_IDENTITY_DIR` 경로가 존재하는지 확인한 후 공개 키와 ECDSA P-256 개인 키를 생성해 PKCS#8 PEM 형식으로 인코딩한 뒤 `key.p8` 파일로 저장합니다. 

```
func generateAndStoreKey(p string) (key *ecdsa.PrivateKey, err error) {
    key, err = tls.GenerateKey()
    if err != nil {
        return
    }
    pemb := tls.EncodePrivateKeyP8(key)
    err = os.WriteFile(p, pemb, 0600)
    return
}
```

그다음 Common Name과 DNS SAN이 포함된 X.509 CSR을 생성해 `csr.der`로 저장합니다.

```
func generateAndStoreCSR(p, id string, key *ecdsa.PrivateKey) ([]byte, error) {
    csr := x509.CertificateRequest{
        Subject:  pkix.Name{CommonName: id},
        DNSNames: []string{id},
    }
    csrb, err := x509.CreateCertificateRequest(rand.Reader, &csr, key)
    if err != nil {
        return nil, fmt.Errorf("failed to create CSR: %w", err)
    }
    if err := os.WriteFile(p, csrb, 0600); err != nil {
        return nil, fmt.Errorf("failed to write CSR: %w", err)
    }
    return csrb, nil
}
```

그리고 Rust 바이너리가 시작돼 `TokenSource::load()`로 서비스 계정 JWT를 읽고, 앞서 생성된 신뢰 앵커와 두 파일(key.p8, csr.der)을 로드한 뒤 CSR 원본 바이트를 gRPC 요청에 첨부합니다.

```
let req = tonic::Request::new(api::CertifyRequest {
  token: token.load()?,                   
  identity: name.to_string(),               
  certificate_signing_request: docs.csr_der.clone(),
});
let api::CertifyResponse { leaf_certificate, intermediate_certificates, valid_until } =
  IdentityClient::new(client).certify(req).await?.into_inner();
```

여기서 identity는 SPIFFE ID(spiffe://<trust-domain>/ns/<ns>/sa/<sa>)를 담고 있으며, 제어 플레인은 이를 사용해 URI SAN이 SPIFFE ID로 설정된 인증서를 발급합니다. CSR 자체의 SAN은 URI 용도로 무시됩니다.

## 6. ID 중간 발급자 인증서

중간 발급자 인증서는 `linkerd` 네임스페이스의 `linkerd-identity-issuer` 시크릿에 저장됩니다. Identity 서비스가 CSR을 받으면, 먼저 `authentication.k8s.io/v1/tokenreviews` 엔드포인트에 다음 정보를 담아 토큰 검증 요청을 보냅니다.
- CSR에서 추출한 ServiceAccount 토큰
- `identity.l5d.io` 오디언스(토큰이 Linkerd용으로만 발급됐음을 보장)

검증에 실패하거나 토큰이 인증되지 않으면 즉시 실패하며, 성공 시 API 서버는 토큰 서명, 만료, 발급자 및 오디언스를 확인합니다.

Identity 서비스는 이어서 ServiceAccount 참조(system:serviceaccount:<namespace>:<name>)를 파싱하고 DNS-1123 레이블 여부를 확인한 뒤, 구성된 트러스트 도메인 아래 SPIFFE URI를 구성합니다.

그다음 아래 정보를 포함한 x509.Certificate 템플릿을 생성합니다.
- CSR에서 가져온 공개 키
- SPIFFE URI로 설정된 SAN
- 현재 시각부터 24시간 후(기본값)까지의 유효 기간

이를 `x509.CreateCertificate(rand.Reader, &template, issuerCert, csr.PublicKey, issuerKey)`로 서명해 프록시에 반환합니다.

동작을 확인하려면 `identity` 파드의 로깅 레벨을 `debug`로 변경해 보십시오.

```
kubectl logs -n linkerd       linkerd-identity-56d78cdd86-8c64w 
Defaulted container "identity" out of: identity, linkerd-proxy, linkerd-init (init)
time="2025-05-21T12:11:32Z" level=info msg="running version enterprise-2.17.1"
time="2025-05-21T12:11:32Z" level=info msg="starting gRPC license client" component=license-client grpc-address="linkerd-enterprise:8082"
time="2025-05-21T12:11:32Z" level=info msg="starting admin server on :9990"
time="2025-05-21T12:11:32Z" level=info msg="Using k8s client with QPS=100.00 Burst=200"
time="2025-05-21T12:11:32Z" level=info msg="POST https://10.247.0.1:443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews 201 Created in 1 milliseconds"
time="2025-05-21T12:11:32Z" level=debug msg="Loaded issuer cert: -----BEGIN CERTIFICATE-----\nMIIBsjCCAVigAwIBAgIQZelMfABi9RPUkaa1fEXfIjAKBggqhkjOPQQDAjAlMSMw\nIQYDVQQDExpyb290LmxpbmtlcmQuY2x1c3Rlci5sb2NhbDAeFw0yNTA1MjExMjEx\nMDJaFw0yNjA1MjExMjExMDJaMCkxJzAlBgNVBAMTHmlkZW50aXR5LmxpbmtlcmQu\nY2x1c3Rlci5sb2NhbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABO52MoQ7mva8\nYPg7abR7rqO3UhE0csDoPgFKoqM54JAfQY9/8rwgKWn3AUvH9NKNNy46Nq0MmPFd\nZgz/qSX3i0WjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEA\nMB0GA1UdDgQWBBTSq+l58FRN+T4ZSwqPyX9EFJmysTAfBgNVHSMEGDAWgBQpPJRY\nnNGBgGrC7LAnIDcwXkIHVjAKBggqhkjOPQQDAgNIADBFAiA7bw59dCwkhQ9CSyUN\nLR4/U7nt2mFV519zCtvD5cJmjgIhAKhPME9EJVtN28L6ZpaYSWbnSTyih1aL/b7m\neqW0acqg\n-----END CERTIFICATE-----\n"
time="2025-05-21T12:11:32Z" level=debug msg="Issuer has been updated"
time="2025-05-21T12:11:32Z" level=info msg="starting gRPC server on :8080"
time="2025-05-21T12:11:37Z" level=debug msg="Validating token for linkerd-identity.linkerd.serviceaccount.identity.linkerd.cluster.local"
time="2025-05-21T12:11:37Z" level=info msg="POST https://10.247.0.1:443/apis/authentication.k8s.io/v1/tokenreviews 201 Created in 2 milliseconds"
time="2025-05-21T12:11:37Z" level=info msg="issued certificate for linkerd-identity.linkerd.serviceaccount.identity.linkerd.cluster.local until 2025-05-22 12:11:57 +0000 UTC: a7048ff55002e726894ad92eccfd6738fcbc72b496d58ef3071a73c866c8e311"
```

## 7. 프록시 리프 인증서

프록시는 인증서를 수신하면 메모리 스토어에 로드하고 mTLS를 위해 사용합니다. TTL의 약 70% 시점이 되면 인증서를 자동으로 갱신하며, 새 CSR을 요청해 무중단으로 교체합니다.

```
fn refresh_in(config: &Config, expiry: SystemTime) -> Duration {
    match expiry.duration_since(SystemTime::now()).ok().map(|d| d * 7 / 10) // 70% duration
    {
        None => config.min_refresh,
        Some(lifetime) if lifetime < config.min_refresh => config.min_refresh,
        Some(lifetime) if config.max_refresh < lifetime => config.max_refresh,
        Some(lifetime) => lifetime,
    }
}
```

전체 흐름은 다음과 같습니다.

![mTLS Flow](modules/certificates/mtls-flow.jpg)

# 참고 자료

- https://linkerd.io/2-edge/tasks/generate-certificates/
- https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/
- https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/identity-client/src/certify.rs
- https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/spire-client/src/lib.rs
- https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/src/identity.rs
- https://github.com/linkerd/linkerd2/blob/main/controller/identity/validator.go
- https://github.com/linkerd/linkerd2/blob/main/proxy-identity/main.go

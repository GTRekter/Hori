+++
author = "Ivan Porta"
title = "Linkerd CLI"
date = "2025-06-01"
description = "Linkerd CLI 설치 및 사용 실습 튜토리얼—Kubernetes에서 CRD 설치, 제어 플레인 설정, 명령어 탐색까지 다룹니다."

tags = [
  "linkerd",
  "cli",
  "kubernetes",
  "crd",
  "tutorial"
]
+++

# Linkerd CLI

Linkerd 유지관리자들은 명령줄에서 Linkerd CRD, 제어 플레인 컴포넌트, 확장 기능을 손쉽게 설치·관리할 수 있도록 풍부한 CLI를 제공합니다.

# 사전 요구 사항

- Unix-스타일 셸이 가능한 macOS/Linux/Windows
- 로컬 쿠버네티스 클러스터용 k3d(v5+)
- kubectl(v1.25+)

# 튜토리얼

## 1. 로컬 쿠버네티스 클러스터 생성

`cluster.yaml`을 사용해 k3d로 가벼운 쿠버네티스 클러스터를 띄웁니다:

```
k3d cluster create --kubeconfig-update-default \
  -c ./cluster.yaml
```

## 2. Linkerd CLI 설정

Linkerd CLI에는 설치할 버전과 바이너리가 설치될 경로를 지정할 수 있는 두 가지 매개변수가 있습니다:

```
LINKERD2_VERSION=${LINKERD2_VERSION:-edge-25.5.3}
INSTALLROOT=${INSTALLROOT:-"${HOME}/.linkerd2"}
```

CLI를 설치하려면 아래 명령을 실행하여 설치 스크립트를 다운로드하고 로컬에서 실행합니다:

```
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install-edge | sh
```

설치가 완료되면 실행 파일을 `PATH` 환경 변수에 추가하는 것을 잊지 마세요:

```
export PATH=$HOME/.linkerd2/bin:$PATH
```

설치 스크립트를 살펴보면 `uname` 명령으로 OS와 아키텍처를 식별한 뒤, 환경 변수를 활용해 GitHub에서 Linkerd 릴리스를 임시 디렉터리에 다운로드하는 것을 확인할 수 있습니다:

```
OS=$(uname -s)
arch=$(uname -m)
...
tmpdir=$(mktemp -d /tmp/linkerd2.XXXXXX)
srcfile="linkerd2-cli-${LINKERD2_VERSION}-${OS}"
if [ -n "${cli_arch}" ]; then
  srcfile="${srcfile}-${cli_arch}"
fi
dstfile="${INSTALLROOT}/bin/linkerd-${LINKERD2_VERSION}"
url="https://github.com/linkerd/linkerd2/releases/download/${LINKERD2_VERSION}/${srcfile}"
```

## 3. CLI 탐색

CLI는 다양한 기능을 제공하며, 유지관리자들은 지속적으로 개선하고 있습니다. 사용 가능한 모든 명령은 `linkerd help`로 확인할 수 있습니다:

```
linkerd help  
linkerd manages the Linkerd service mesh.

Usage:
  linkerd [command]

Available Commands:
  authz        List authorizations for a resource
  check        Check the Linkerd installation for potential problems
  completion   Output shell completion code for the specified shell (bash, zsh or fish)
  diagnostics  Commands used to diagnose Linkerd components
  help         Help about any command
  identity     Display the certificate(s) of one or more selected pod(s)
  inject       Add the Linkerd proxy to a Kubernetes config
  install      Output Kubernetes configs to install Linkerd
  install-cni  Output Kubernetes configs to install Linkerd CNI
  jaeger       jaeger manages the jaeger extension of Linkerd service mesh
  multicluster Manages the multicluster setup for Linkerd
  profile      Output service profile config for Kubernetes
  prune        Output extraneous Kubernetes resources in the linkerd control plane
  uninject     Remove the Linkerd proxy from a Kubernetes config
  uninstall    Output Kubernetes resources to uninstall Linkerd control plane
  upgrade      Output Kubernetes configs to upgrade an existing Linkerd control plane
  version      Print the client and server version information
  viz          viz manages the linkerd-viz extension of Linkerd service mesh
```

각 명령은 자체 하위 명령을 가지고 있습니다. `linkerd <command> --help`를 실행하면 확인할 수 있습니다. 예를 들어:

```
linkerd authz --help
List authorizations for a resource.

Usage:
  linkerd authz [flags] resource

Flags:
  -h, --help               help for authz
  -n, --namespace string   Namespace of resource

Global Flags:
      --api-addr string            Override kubeconfig and communicate directly with the control plane at host:port (mostly for testing)
      --as string                  Username to impersonate for Kubernetes operations
      --as-group stringArray       Group to impersonate for Kubernetes operations
      --cni-namespace string       Namespace in which the Linkerd CNI plugin is installed (default "linkerd-cni")
      --context string             Name of the kubeconfig context to use
      --kubeconfig string          Path to the kubeconfig file to use for CLI requests
  -L, --linkerd-namespace string   Namespace in which Linkerd is installed ($LINKERD_NAMESPACE) (default "linkerd")
      --verbose                    Turn on debug logging
```

## 4. 클러스터에 Linkerd 설치

Linkerd를 설치하려면 먼저 제어 플레인에 필요한 CRD를 설치해야 합니다. API Gateway CRD, Linkerd CRD를 차례로 설치한 뒤, 제어 플레인을 설치합니다. `linkerd install` 명령은 YAML 매니페스트를 출력만 하므로, `kubectl apply`와 파이프해 적용해야 합니다.

```
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
```

**참고:** 2.18 이전 버전의 Linkerd는 자체 API Gateway 버전을 제공했지만, 0.7 버전에 고정되어 있어 Kong Gateway와 같은 타사 도구가 다른 버전을 요구할 때 문제가 있었습니다. 이를 해결하기 위해 2.18부터 Linkerd는 1.0.0 이상의 Gateway API 버전을 지원하며, 사용자가 별도로 설치해야 합니다. Linkerd 2.18 이전 버전에서 API Gateway 1.2.0을 실행하면 정책 컨트롤러가 특정 gRPCRoute Gateway API 버전을 감시하므로 제어 플레인이 동작하지 않습니다.

API 리소스를 확인하면 API Gateway와 Linkerd 리소스가 모두 표시됩니다.

```
kubectl api-resources 
NAME                                SHORTNAMES                 APIVERSION                          NAMESPACED   KIND
...
gatewayclasses                      gc                         gateway.networking.k8s.io/v1        false        GatewayClass
gateways                            gtw                        gateway.networking.k8s.io/v1        true         Gateway
grpcroutes                                                     gateway.networking.k8s.io/v1        true         GRPCRoute
httproutes                                                     gateway.networking.k8s.io/v1        true         HTTPRoute
referencegrants                     refgrant                   gateway.networking.k8s.io/v1beta1   true         ReferenceGrant
...
serviceprofiles                     sp                         linkerd.io/v1alpha2                 true         ServiceProfile
...
authorizationpolicies               authzpolicy                policy.linkerd.io/v1alpha1          true         AuthorizationPolicy
egressnetworks                                                 policy.linkerd.io/v1alpha1          true         EgressNetwork
httplocalratelimitpolicies                                     policy.linkerd.io/v1alpha1          true         HTTPLocalRateLimitPolicy
httproutes                                                     policy.linkerd.io/v1beta3           true         HTTPRoute
meshtlsauthentications              meshtlsauthn               policy.linkerd.io/v1alpha1          true         MeshTLSAuthentication
networkauthentications              netauthn,networkauthn      policy.linkerd.io/v1alpha1          true         NetworkAuthentication
serverauthorizations                saz,serverauthz,srvauthz   policy.linkerd.io/v1beta1           true         ServerAuthorization
servers                             srv                        policy.linkerd.io/v1beta3           true         Server
...
externalworkloads                                              workload.linkerd.io/v1beta1         true         ExternalWorkload
```

CRD 역시 동일하게 여러 API 버전을 제공할 수 있습니다. 예를 들어 다음과 같습니다.

```
kubectl get crds -A
NAME                                           CREATED AT
addons.k3s.cattle.io                           2025-05-20T04:54:40Z
authorizationpolicies.policy.linkerd.io        2025-05-20T05:18:06Z
egressnetworks.policy.linkerd.io               2025-05-20T05:18:07Z
externalworkloads.workload.linkerd.io          2025-05-20T05:18:07Z
gatewayclasses.gateway.networking.k8s.io       2025-05-20T05:16:36Z
gateways.gateway.networking.k8s.io             2025-05-20T05:16:36Z
grpcroutes.gateway.networking.k8s.io           2025-05-20T05:16:36Z
httplocalratelimitpolicies.policy.linkerd.io   2025-05-20T05:18:07Z
httproutes.gateway.networking.k8s.io           2025-05-20T05:16:36Z
httproutes.policy.linkerd.io                   2025-05-20T05:18:07Z
meshtlsauthentications.policy.linkerd.io       2025-05-20T05:18:07Z
networkauthentications.policy.linkerd.io       2025-05-20T05:18:07Z
referencegrants.gateway.networking.k8s.io      2025-05-20T05:16:36Z
serverauthorizations.policy.linkerd.io         2025-05-20T05:18:07Z
servers.policy.linkerd.io                      2025-05-20T05:18:07Z
serviceprofiles.linkerd.io                     2025-05-20T05:18:07Z
```

중요한 점은 각 CRD가 동일한 API의 여러 버전을 제공할 수 있다는 것입니다. 이러한 버전들은 표에서 바로 보이지 않지만, CRD 리소스를 `describe` 해 보면 모두 확인할 수 있습니다.

```
kubectl describe crd servers.policy.linkerd.io
Name:         servers.policy.linkerd.io
Namespace:    
Labels:       helm.sh/chart=linkerd-crds-0.0.0-undefined
              linkerd.io/control-plane-ns=linkerd
Annotations:  linkerd.io/created-by: linkerd/cli edge-25.5.3
API Version:  apiextensions.k8s.io/v1
Kind:         CustomResourceDefinition
Metadata:
  Creation Timestamp:  2025-05-20T05:18:07Z
  Generation:          1
  Resource Version:    961
  UID:                 7b046714-27b4-4d19-8292-6651025ff071
Spec:
  Conversion:
    Strategy:  None
  Group:       policy.linkerd.io
  Names:
    Kind:       Server
    List Kind:  ServerList
    Plural:     servers
    Short Names:
      srv
    Singular:  server
  Scope:       Namespaced
  Versions:
    Deprecated:           true
    Deprecation Warning:  policy.linkerd.io/v1alpha1 Server is deprecated; use policy.linkerd.io/v1beta1 Server
    Name:                 v1alpha1
    Schema:
      openAPIV3Schema:
      ...
    Served:    true
    Storage:   false
    ...
    Deprecated:           true
    Deprecation Warning:  policy.linkerd.io/v1beta1 Server is deprecated; use policy.linkerd.io/v1beta3 Server
    Name:                 v1beta1
    Schema:
      openAPIV3Schema:
      ...
    Served:    true
    Storage:   false
    ...
    Name:           v1beta2
    Schema:
      openAPIV3Schema:
      ...
    Served:    true
    Storage:   false
    
```

마지막으로 linkerd 네임스페이스에서 동작 중인 배포 및 파드를 확인하면 `linkerd-destination`, `linkerd-identity`, `linkerd-proxy-injector`가 실행 중인 것을 볼 수 있습니다:

```
kubectl get deploy -n linkerd
NAME                     READY   UP-TO-DATE   AVAILABLE   AGE
linkerd-destination      1/1     1            1           28m
linkerd-identity         1/1     1            1           28m
linkerd-proxy-injector   1/1     1            1           28m

kubectl get pods -n linkerd 
NAME                                      READY   STATUS    RESTARTS   AGE
linkerd-destination-75f4bc85cd-fswvp      4/4     Running   0          28m
linkerd-identity-9bf7d8b86-zmkb2          2/2     Running   0          28m
linkerd-proxy-injector-5d5687794c-4kmhs   2/2     Running   0          28m
```

이번 모듈에서는 여기까지 다루고, 이후 과정에서 다양한 명령을 더 자세히 살펴보겠습니다.

## 참고 자료

- https://linkerd.io/2.17/getting-started/
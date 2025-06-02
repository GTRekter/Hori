+++
author = "Ivan Porta"
title = "Linkerd CLI"
date = "2025-06-01"
description = "Hands-on tutorial for installing and using the Linkerd CLI—covering CRD installation, control-plane setup, and command exploration on Kubernetes."
tags = [
  "linkerd",
  "cli",
  "kubernetes",
  "crd",
  "tutorial"
]
+++

# Linkerd CLI

The Linkerd maintainers have developed a rich CLI that allows you to easily install Linkerd CRDs, control plane components, and manage extensions directly from the command line.

# Prerequisites

- macOS/Linux/Windows with a Unix‑style shell
- k3d (v5+) for local Kubernetes clusters
- kubectl (v1.25+)

# Tutorial

## 1. Create a Local Kubernetes Cluster

Use k3d and the `cluster.yaml` to spin up a lightweight Kubernetes cluster:

```
k3d cluster create --kubeconfig-update-default \
  -c ./cluster.yaml
```

## 2. Configure the Linkerd CLI

The Linkerd CLI has two parameters you can define to specify the version to install and the path where the binaries will be installed:

```
LINKERD2_VERSION=${LINKERD2_VERSION:-edge-25.5.3}
INSTALLROOT=${INSTALLROOT:-"${HOME}/.linkerd2"}
```

To install the CLI, execute the following command, which downloads and runs the installer script locally:

```
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install-edge | sh
```

Once installed, don’t forget to add the executable to your PATH environment variable:

```
export PATH=$HOME/.linkerd2/bin:$PATH
```

If you inspect the installer script, you’ll see that it uses the `uname` command to identify the OS and Architecture and then use the environment variables to download the Linkerd release from GitHub into a temporary directory:

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

## 3. Explore the CLI

The CLI has a lot of functionality, and the maintainers are constantly working to enhance it. You can list all available commands by running `linkerd help`:

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

Each of these commands has its own subcommands.  You can view them by running ` linkerd <command> --help`. for example:

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

## 4. Install Linkerd on Your Cluster

To install Linkerd, you must first install the CRDs required by the control plane, starting with the API Gateway CRDs, then the Linkerd CRDs, and finally the control plane itself. The `linkerd install` command output the YAML manifest but do not apply it directly. You will need to pipe the output to `kubectl apply`.

```
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
```

**Note:** Prior to 2.18, Linkerd provided its own version of the API Gateway, but it was limited by dependencies tied to version 0.7, which posed an issue when third-party tools like Kong Gateway required a different version. To solve this, the maintainers decoupled them so that, starting with 2.18, Linkerd supports Gateway API versions from 1.0.0 onward and will require users to install it separatly. Running API Gateway 1.2.0 on a Linkerd version prior to 2.18 will break the control plane, since the policy controller watches for a specific version of the gRPCRoute Gateway API, which is not provided in 1.2.0.

If we check the API Resouces we will see both API Gateway and Linkerd resources.

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

The same applies to the CRDs using these APIs.

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

One important thing to highlight is that each CRD might serve multiple versions of the same API, which are not immeditly visible in the table. However, if we describe the CRD resource, you will see those multiple versions.

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

Finally, if you check the deployments and pods running in the linkerd namespace, you will see the `linkerd-destination`, `linkerd-identity`, and `linkerd-proxy-injector` running:

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

During the course, we will dig more into the various commands. But for this first module, we will stop here.

## References

- https://linkerd.io/2.17/getting-started/
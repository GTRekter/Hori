---
title: 'Proxy-Injector'
author: "Ivan Porta"
date: "2025-06-01"
description: "A deep dive into Linkerd's control plane architecture—examining how the destination, identity·policy, and proxy-injector controllers coordinate gRPC traffic and leader election in Kubernetes."
tags: [
  "linkerd",
  "control-plane",
  "architecture",
  "kubernetes",
  "deep-dive"
]
bookcase_cover_src: 'control-plane/proxy-injector.png'
bookcase_cover_src_dark: 'control-plane/proxy-injector_white.png'
---

## Linkerd Proxy-Injector

The Linkerd Proxy-Injector uses a mutating webhook to intercept requests to the Kubernetes API when a new Pod (or Service) is created. If the namespace or Pod is annotated with `linkerd.io/inject: enabled`, the webhook injects the Linkerd proxy and ProxyInit containers into the Pod spec.

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
cat << 'EOF' > application.yaml
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
  name: simple-app-v1
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

## 5. Deploy the Sample Application

Since the `simple-app` namespace is annotated with `linkerd.io/inject: enabled`, Linkerd’s proxy-injector webhook will automatically inject a sidecar into the `simple-app-v1` Deployment’s Pods.

```
kubectl apply -f ./application.yaml
```

At this point, Kubernetes will send a CREATE request for the Deployment’s ReplicaSet and then for the Pod.

## 6. Interactions with the Kuberentes API

When you apply `application.yaml`, Kubernetes processes it and calls any matching mutating webhooks. In Linkerd’s case, this is the `linkerd-proxy-injector-webhook` (configured under `MutatingWebhookConfiguration`). Here’s a trimmed-down view of that webhook configuration:

```
kubectl get mutatingwebhookconfiguration linkerd-proxy-injector-webhook-config -o yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: linkerd-proxy-injector-webhook-config
webhooks:
- admissionReviewVersions:
  - v1
  - v1beta1
  clientConfig:
    caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVakNDQWpxZ0F3SUJBZ0lRSzVya2tEMHVmQVNyRTRPeEV0Q2JTekFOQmdrcWhraUc5dzBCQVFzRkFEQXQKTVNzd0tRWURWUVFERXlKc2FXNXJaWEprTFhCeWIzaDVMV2x1YW1WamRHOXlMbXhwYm10bGNtUXVjM1pqTUI0WApEVEkxTURZd05ERXhNVGcxTVZvWERUSTJNRFl3TkRFeE1UZzFNVm93TFRFck1Da0dBMVVFQXhNaWJHbHVhMlZ5ClpDMXdjbTk0ZVMxcGJtcGxZM1J2Y2k1c2FXNXJaWEprTG5OMll6Q0NBU0l3RFFZSktvWklodmNOQVFFQkJRQUQKZ2dFUEFEQ0NBUW9DZ2dFQkFNOGM3ZXNMNXhNakxFMzlXYUMwZVpJOThtTVhSK24zTUdvWHJJSXc0S3NCeUw1QwpuWHp3Um9ISTV1WnVMR1ZMY0N6L1h0YWozWWp3T0RhL2pLODVKRHZ4ajF2MTFMV3J2NWN5b1ladTBJRm8ybkVLCnpIY21TdVJZSjJwSHFFOHhZQXRmcnh0SktDdldWK3FZTTFLTTI2V1lVT2kzSU9DVGNoV0d4MS9vSENCclFiUnAKalRpSUEvY2d3QU55dXpqQUV3a1ZCRWl4UE92YnduVHl4YmhDZVFBTGZCV2JiM3Z6MGJwTUVKOUxpNkoxVms2egpWOW9ycFA2UW0yam1iNHJ3SElWVGRTN1dXOXU5YWY5SEFGdlozeFdldHhYRXkzRzNvSEl0REFiQ3YyemhaZDNWCkVlYmZHdGR3RDFTQmNqbnlHbTllc1IzSlMySU4vejRKWC9KWmoyVUNBd0VBQWFOdU1Hd3dEZ1lEVlIwUEFRSC8KQkFRREFnV2dNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZCd01CQmdnckJnRUZCUWNEQWpBTUJnTlZIUk1CQWY4RQpBakFBTUMwR0ExVWRFUVFtTUNTQ0lteHBibXRsY21RdGNISnZlSGt0YVc1cVpXTjBiM0l1YkdsdWEyVnlaQzV6CmRtTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBR1pxRlFFY0g0THBqK0l5K1dwVFY1VTFuOHFqRGNOMFcyS3AKMHg0T25RaHp3NkZNUm8rR2NBdUR0Nk5kNkROVlZHZjNEdFBtcXhBM21wTUxDTDFSbytnUm9FSWg5N3pxdlZjSQpNalBmeXpkNGhRQ09ocmhyblJFazh2OEN6Rm5YREtPYmkyaUx1THVTNlJtc3I0alpPV2FrdWRKTzlqaUREUmJVCnlvcHhpWTgycW81VmNoT1IvaGg4K1o3S1FKL29lT29BMlp0Zk9QbmZ0VGYvenBwekJPQmtXRUxvYlRRVHRUbUoKbVdNaS9URUQ5QlE4U0NMUU5TUk1SRXpuaElFTGhja0lPVzBqMkNkYmJWWXdkZ2wrTSt1aVYweHdlTk9pQ2RxZApyZm9Yamp6TTh6MWk1Y0FzMS9IcGcvaEt2czlpM2hKNHQwd0NrZ0JQVXcyZzQxN29MU2s9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
    service:
      name: linkerd-proxy-injector
      namespace: linkerd
      path: /
      port: 443
  failurePolicy: Ignore
  matchPolicy: Equivalent
  name: linkerd-proxy-injector.linkerd.io
  namespaceSelector:
    matchExpressions:
    - key: config.linkerd.io/admission-webhooks
      operator: NotIn
      values:
      - disabled
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - kube-system
      - cert-manager
  objectSelector:
    matchExpressions:
    - key: linkerd.io/control-plane-component
      operator: DoesNotExist
    - key: linkerd.io/cni-resource
      operator: DoesNotExist
  reinvocationPolicy: Never
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    resources:
    - pods
    - services
    scope: Namespaced
  sideEffects: None
  timeoutSeconds: 10
```

The mutating webhook will:
- Be triggered by any Pod or Service creation in a namespace that does NOT have `config.linkerd.io/admission-webhooks=disabled` will be sent to this webhook. The webhook also ignores any object labeled with `linkerd.io/control-plane-component` or `linkerd.io/cni-resource`, and it skips system namespaces `kube-system` and `cert-manager`.
- Point to the `linkerd-proxy-injector` service in the `linkerd` namespace on port `443`. 

If we take a look a inside the `linkerd-proxy-injector` Pod we will see that:
- It will mount a volume containing the `linkerd-config` ConfigMap that holds the chart‐rendered values.yaml, including defaults for proxy image, opaque ports, resource limits, and so forth.
- It will mount a volume which contains the `linkerd-identity-trust-roots` ConfigMap. This ConfigMap contains the the trust anchor Certificate.

```
kubectl get pods -n linkerd linkerd-proxy-injector-******** -o yaml
apiVersion: v1
kind: Pod
  ...
  name: linkerd-proxy-injector-********
  namespace: linkerd
spec:
  containers:
  ...
  - args:
    - proxy-injector
    - -log-level=debug
    - -log-format=plain
    - -linkerd-namespace=linkerd
    - -enable-pprof=false
    image: ghcr.io/buoyantio/controller:enterprise-2.18.0
    ...
    name: proxy-injector
    ports:
    - containerPort: 8443
      name: proxy-injector
      protocol: TCP
    - containerPort: 9995
      name: admin-http
      protocol: TCP
    volumeMounts:
    - mountPath: /var/run/linkerd/config
      name: config
    - mountPath: /var/run/linkerd/identity/trust-roots
      name: trust-roots
    - mountPath: /var/run/linkerd/tls
      name: tls
      readOnly: true
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access
      readOnly: true
  volumes:
  - configMap:
      defaultMode: 420
      name: linkerd-config
    name: config
  - configMap:
      defaultMode: 420
      name: linkerd-identity-trust-roots
    name: trust-roots
  - name: tls
    secret:
      defaultMode: 420
      secretName: linkerd-proxy-injector-k8s-tls
  - name: kube-api-access
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
  - emptyDir: {}
    name: linkerd-proxy-init-xtables-lock
  - name: linkerd-identity-token
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          audience: identity.l5d.io
          expirationSeconds: 86400
          path: linkerd-identity-token
  - emptyDir:
      medium: Memory
    name: linkerd-identity-end-entity
```

When the webhook binary starts handling a request, the first lines of code read both the mounted volume with the `linkerd-config` ConfigMap and `linkerd-identity-trust-roots` ConfigMap so that the injector will know the configurations and correct trust root to inject in the proxy configuration.

```
valuesConfig, err := config.Values(pkgK8s.MountPathValuesConfig)
if err != nil {
  return nil, err
}
caPEM, err := os.ReadFile(pkgK8s.MountPathTrustRootsPEM)
if err != nil {
  return nil, err
}
valuesConfig.IdentityTrustAnchorsPEM = string(caPEM)
```

Next, the webhook fetches the namespace object to read any namespace-level Linkerd annotations. This is important because these values will be propagated to the proxy itself if no annotations in the deployment override them.

```
ns, err := api.Get(k8s.NS, request.Namespace)
if err != nil {
  return nil, err
}
```

Then it constructs a `ResourceConfig` struct that carries:
- The chart values merged with any overrides from Pod annotations.
- All namespace‐level annotations, so that any Linkerd annotation set at the namespace is automatically inherited by each Pod.
- The resource kind (e.g. “Pod” or “Deployment”) so that the code knows where to look for a Pod template if the resource is a Deployment.
- An “OwnerRetriever” function that can look up the parent resource (e.g. Deployment → ReplicaSet → Pod) so that injected events can be attached to the highest‐level owner.

```
resourceConfig := inject.NewResourceConfig(valuesConfig, inject.OriginWebhook, linkerdNamespace).
  WithOwnerRetriever(ownerRetriever(ctx, api, request.Namespace)).
  WithNsAnnotations(ns.GetAnnotations()).
  WithKind(request.Kind.Kind)
...
func NewResourceConfig(values *l5dcharts.Values, origin Origin, ns string) *ResourceConfig {
	config := &ResourceConfig{
		namespace:     ns,
		nsAnnotations: make(map[string]string),
		values:        values,
		origin:        origin,
	}
	config.workload.Meta = &metav1.ObjectMeta{}
	config.pod.meta = &metav1.ObjectMeta{}
	config.pod.labels = map[string]string{k8s.ControllerNSLabel: ns}
	config.pod.annotations = map[string]string{}
	return config
}
func (conf *ResourceConfig) WithOwnerRetriever(f OwnerRetrieverFunc) *ResourceConfig {
	conf.ownerRetriever = f
	return conf
}
func (conf *ResourceConfig) WithNsAnnotations(m map[string]string) *ResourceConfig {
	conf.nsAnnotations = m
	return conf
}
func (conf *ResourceConfig) WithKind(kind string) *ResourceConfig {
	conf.workload.metaType = metav1.TypeMeta{Kind: kind}
	return conf
}
```

At this point, the webhook deserializes the raw JSON bytes from the admission request into typed Kubernetes objects and fills some additional field in the `ResourceConfig` struct:
- `resourceConfig.workload.metatype` and `resourceConfig.workload.meta` if the object is a Deployment, StatefulSet, Service, and so on.
- `resourceConfig.pod.spec` and `resourceConfig.pod.meta` if the object is a Pod (or if the object has a PodTemplate, such as a Deployment template).
- `resourceConfig.ownerRef` if there is a controller owner reference (for example, a Pod owned by a ReplicaSet, owned by a Deployment).

```
report, err := resourceConfig.ParseMetaAndYAML(request.Object.Raw)
if err != nil {
  return nil, err
}
log.Infof("received %s", report.ResName())
```

You will see log lines like:

```
time="2025-06-04T11:19:18Z" level=info msg="received service/simple-app-v1"
time="2025-06-04T11:19:18Z" level=info msg="received admission review request \"919c6889-a59c-4168-be0d-6d448460af98\""
```

If the resource has a parent (for example, a Pod created by a ReplicaSet which is managed by a Deployment), the code looks it up so that any Kubernetes Event (Injected or Skipped) goes on the parent:


```
var parent *metav1.PartialObjectMetadata
var ownerKind string
if ownerRef := resourceConfig.GetOwnerRef(); ownerRef != nil {
  res, err := k8s.GetAPIResource(ownerRef.Kind)
  if err != nil {
    log.Tracef("skipping event for parent %s: %s", ownerRef.Kind, err)
  } else {
    objs, err := api.GetByNamespaceFiltered(res, request.Namespace, ownerRef.Name, labels.Everything())
    if err != nil {
      log.Warnf("couldn't retrieve parent object %s-%s-%s; error: %s", request.Namespace, ownerRef.Kind, ownerRef.Name, err)
    } else if len(objs) == 0 {
      log.Warnf("couldn't retrieve parent object %s-%s-%s", request.Namespace, ownerRef.Kind, ownerRef.Name)
    } else {
      parent = objs[0]
    }
    ownerKind = strings.ToLower(ownerRef.Kind)
  }
}
```

With those pieces in place, the webhook calls `report.Injectable()` to decide whether injection should proceed. To do so it checks:
- `HostNetwork` mode (iptables won’t work if the Pod is on the host network).
- Existing sidecar detecting that injection would be redundant.
- Unsupported resource kinds.
- An explicit annotation that disables injection.
- Whether the Pod automounts its ServiceAccount token (needed for mTLS).
If any of these checks fail, the function returns `false` along with one or more human-readable reasons. 


```
injectable, reasons := report.Injectable()
...
func (r *Report) Injectable() (bool, []string) {
	var reasons []string
	if r.HostNetwork {
		reasons = append(reasons, hostNetworkEnabled)
	}
	if r.Sidecar {
		reasons = append(reasons, sidecarExists)
	}
	if r.UnsupportedResource {
		reasons = append(reasons, unsupportedResource)
	}
	if r.InjectDisabled {
		reasons = append(reasons, r.InjectDisabledReason)
	}

	if !r.AutomountServiceAccountToken {
		reasons = append(reasons, disabledAutomountServiceAccountToken)
	}

	if len(reasons) > 0 {
		return false, reasons
	}
	return true, nil
}
```

If `Injectable()` returns `true`, the webhook proceeds with injection and:
- Append a `config.linkerd.io/created-by` annotation.
- Copy any namespace‐level Linkerd annotations (for CPU/memory limits, proxy image overrides, etc.) onto the Pod template if they are not explicitly set on the Pod.
- If the Pod does not already have a `config.linkerd.io/opaque-ports` annotation, split the comma-separated default opaque ports from `valuesConfig.Proxy.OpaquePorts`, filter them against the actual container ports in the Pod spec, and then set the annotation to just the matching ports.

Then it will call `resourceConfig.GetPodPatch(true)` to build the JSON patch that:
- Adds the `linkerd-init` init container (which programs iptables rules).
- Adds the `linkerd-proxy` sidecar container with all required environment variables, volume mounts, and command-line flags.
- Attaches the `config.linkerd.io/opaque-ports` and `config.linkerd.io/created-by` annotations.
- Mounts the trust anchors and TLS secrets (so the proxy can talk securely to the control plane).
- If a parent was found, emit a Kubernetes Event on the parent resource with reason Injected and message **Linkerd sidecar proxy injected.**
- Log the generated patch at INFO level and debug-print the full JSON patch.

```
if injectable {
  resourceConfig.AppendPodAnnotation(pkgK8s.CreatedByAnnotation, fmt.Sprintf("linkerd/proxy-injector %s", version.Version))
  inject.AppendNamespaceAnnotations(resourceConfig.GetOverrideAnnotations(), resourceConfig.GetNsAnnotations(), resourceConfig.GetWorkloadAnnotations())
  if !resourceConfig.HasWorkloadAnnotation(pkgK8s.ProxyOpaquePortsAnnotation) {
    defaultPorts := strings.Split(resourceConfig.GetValues().Proxy.OpaquePorts, ",")
    filteredPorts := resourceConfig.FilterPodOpaquePorts(defaultPorts)
    if len(filteredPorts) != 0 {
      ports := strings.Join(filteredPorts, ",")
      resourceConfig.AppendPodAnnotation(pkgK8s.ProxyOpaquePortsAnnotation, ports)
    }
  }
  patchJSON, err := resourceConfig.GetPodPatch(true)
  if err != nil {
    return nil, err
  }
  if parent != nil {
    recorder.Event(parent, v1.EventTypeNormal, eventTypeInjected, "Linkerd sidecar proxy injected")
  }
  log.Infof("injection patch generated for: %s", report.ResName())
  log.Debugf("injection patch: %s", patchJSON)
  proxyInjectionAdmissionResponses.With(admissionResponseLabels(ownerKind, request.Namespace, "false", "", report.InjectAnnotationAt, configLabels)).Inc()
  patchType := admissionv1beta1.PatchTypeJSONPatch
  return &admissionv1beta1.AdmissionResponse{
    UID:       request.UID,
    Allowed:   true,
    PatchType: &patchType,
    Patch:     patchJSON,
  }, nil
}
...
func (conf *ResourceConfig) GetPodPatch(injectProxy bool) ([]byte, error) {
	namedPorts := make(map[string]int32)
	if conf.HasPodTemplate() {
		namedPorts = util.GetNamedPorts(conf.pod.spec.Containers)
	}
	values, err := GetOverriddenValues(conf.values, conf.getAnnotationOverrides(), namedPorts)
	values.Proxy.PodInboundPorts = getPodInboundPorts(conf.pod.spec)
	if err != nil {
		return nil, fmt.Errorf("could not generate Overridden Values: %w", err)
	}
	if values.ClusterNetworks != "" {
		for _, network := range strings.Split(strings.Trim(values.ClusterNetworks, ","), ",") {
			if _, _, err := net.ParseCIDR(network); err != nil {
				return nil, fmt.Errorf("cannot parse destination get networks: %w", err)
			}
		}
	}
	patch := &podPatch{
		Values:      *values,
		Annotations: map[string]string{},
		Labels:      map[string]string{},
	}
	switch strings.ToLower(conf.workload.metaType.Kind) {
	case k8s.Pod:
	case k8s.CronJob:
		patch.PathPrefix = "/spec/jobTemplate/spec/template"
	default:
		patch.PathPrefix = "/spec/template"
	}
	if conf.pod.spec != nil {
		conf.injectPodAnnotations(patch)
		if injectProxy {
			conf.injectObjectMeta(patch)
			conf.injectPodSpec(patch)
		} else {
			patch.Proxy = nil
			patch.ProxyInit = nil
		}
	}
	rawValues, err := yaml.Marshal(patch)
	if err != nil {
		return nil, err
	}
	files := []*loader.BufferedFile{
		{Name: chartutil.ChartfileName},
		{Name: "requirements.yaml"},
		{Name: "templates/patch.json"},
	}
	chart := &charts.Chart{
		Name:      "patch",
		Dir:       "patch",
		Namespace: conf.namespace,
		RawValues: rawValues,
		Files:     files,
		Fs:        static.Templates,
	}
	buf, err := chart.Render()
	if err != nil {
		return nil, err
	}
	res := rTrail.ReplaceAll(buf.Bytes(), []byte("\n"))
	return res, nil
}
```

You can see the related logs in the Deployment's Events.

```
kubectl describe deployment/simple-app-v1 -n simple-app
...
Events:
  Type    Reason             Age                    From                    Message
  ----    ------             ----                   ----                    -------
  Normal  ScalingReplicaSet  2m26s                  deployment-controller   Scaled up replica set simple-app-v1-658b475d7c from 0 to 1
  Normal  Injected           2m25s (x2 over 2m26s)  linkerd-proxy-injector  Linkerd sidecar proxy injected
  Normal  ScalingReplicaSet  2m25s                  deployment-controller   Scaled up replica set simple-app-v1-76fc99b86b from 0 to 1
  Normal  ScalingReplicaSet  2m19s                  deployment-controller   Scaled down replica set simple-app-v1-658b475d7c from 1 to 0
```

Once the Json is generated, it calls the `chart.Render()` that returns the resulting []byte patch that Kubernetes applies. You can see the raw byte array of the incoming admission request, including the trust anchor PEM, Linkerd-related annotations, and Pod spec. For example:

```
time="2025-06-04T11:19:18Z" level=debug msg="admission request: &AdmissionRequest{UID:919c6889-a59c-4168-be0d-6d448460af98,Kind:/v1, Kind=Service,Resource:{ v1 services},SubResource:,Name:simple-app-v2,Namespace:simple-app,Operation:CREATE,UserInfo:{system:admin  [system:masters system:authenticated] map[authentication.kubernetes.io/credential-id:[X509SHA256=4bc6de6278f805fc173745e09f4a564b7c7b4fac138201f729d912cd623fa55b]]},Object:{[123 34 97 112 105 86 101 114 115 105 111 110 34 58 34 118 49 34 44 34 107 105 110 100 34 58 34 83 101 114 118 105 99 101 34 44 34 109 101 116 97 100 97 116 97 34 58 123 34 97 110 110 111 116 97 116 105 111 110 115 34 58 123 34 107 117 98 101 99 116 108 46 107 117 98 101 114 110 101 116 101 115 46 105 111 47 108 97 115 116 45 97 112 112 108 105 101 100 45 99 111 110 102 105 103 117 114 97 116 105 111 110 34 58 34 123 92 34 97 112 105 86 101 114 115 105 111 110 92 34 58 92 34 118 49 92 34 44 92 34 107 105 110 100 92 34 58 92 34 83 101 114 118 105 99 101 92 34 44 92 34 109 101 116 97 100 97 116 97 92 34 58 123 92 34 97 110 110 111 116 97 116 105 111 110 115 92 34 58 123 125 44 92 34 110 97 109 101 92 34 58 92 34 115 105 109 112 108 101 45 97 112 112 45 118 50 92 34 44 92 34 110 97 109 101 115 112 97 99 101 92 34 58 92 34 115 105 109 112 108 101 45 97 112 112 92 34 125 44 92 34 115 112 101 99 92 34 58 123 92 34 112 111 114 116 115 92 34 58 91 123 92 34 112 111 114 116 92 34 58 56 48 44 92 34 116 97 114 103 101 116 80 111 114 116 92 34 58 53 54 55 56 125 93 44 92 34 115 101 108 101 99 116 111 114 92 34 58 123 92 34 97 112 112 92 34 58 92 34 115 105 109 112 108 101 45 97 112 112 45 118 50 92 34 44 92 34 118 101 114 115 105 111 110 92 34 58 92 34 118 50 92 34 125 125 125 92 110 34 125 44 34 99 114 101 97 116 105 111 110 84 105 109 101 115 116 97 109 112 34 58 110 117 108 108 44 34 109 97 110 97 103 101 100 70 105 101 108 100 115 34 58 91 123 34 97 112 105 86 101 114 115 105 111 110 34 58 34 118 49 34 44 34 102 105 101 108 100 115 84 121 112 101 34 58 34 70 105 101 108 100 115 86 49 34 44 34 102 105 101 108 100 115 86 49 34 58 123 34 102 58 109 101 116 97 100 97 116 97 34 58 123 34 102 58 97 110 110 111 116 97 116 105 111 110 115 34 58 123 34 46 34 58 123 125 44 34 102 58 107 117 98 101 99 116 108 46 107 117 98 101 114 110 101 116 101 115 46 105 111 47 108 97 115 116 45 97 112 112 108 105 101 100 45 99 111 110 102 105 103 117 114 97 116 105 111 110 34 58 123 125 125 125 44 34 102 58 115 112 101 99 34 58 123 34 102 58 105 110 116 101 114 110 97 108 84 114 97 102 102 105 99 80 111 108 105 99 121 34 58 123 125 44 34 102 58 112 111 114 116 115 34 58 123 34 46 34 58 123 125 44 34 107 58 123 92 34 112 111 114 116 92 34 58 56 48 44 92 34 112 114 111 116 111 99 111 108 92 34 58 92 34 84 67 80 92 34 125 34 58 123 34 46 34 58 123 125 44 34 102 58 112 111 114 116 34 58 123 125 44 34 102 58 112 114 111 116 111 99 111 108 34 58 123 125 44 34 102 58 116 97 114 103 101 116 80 111 114 116 34 58 123 125 125 125 44 34 102 58 115 101 108 101 99 116 111 114 34 58 123 125 44 34 102 58 115 101 115 115 105 111 110 65 102 102 105 110 105 116 121 34 58 123 125 44 34 102 58 116 121 112 101 34 58 123 125 125 125 44 34 109 97 110 97 103 101 114 34 58 34 107 117 98 101 99 116 108 45 99 108 105 101 110 116 45 115 105 100 101 45 97 112 112 108 121 34 44 34 111 112 101 114 97 116 105 111 110 34 58 34 85 112 100 97 116 101 34 44 34 116 105 109 101 34 58 34 50 48 50 53 45 48 54 45 48 52 84 49 49 58 49 57 58 49 56 90 34 125 93 44 34 110 97 109 101 34 58 34 115 105 109 112 108 101 45 97 112 112 45 118 50 34 44 34 110 97 109 101 115 112 97 99 101 34 58 34 115 105 109 112 108 101 45 97 112 112 34 125 44 34 115 112 101 99 34 58 123 34 105 110 116 101 114 110 97 108 84 114 97 102 102 105 99 80 111 108 105 99 121 34 58 34 67 108 117 115 116 101 114 34 44 34 112 111 114 116 115 34 58 91 123 34 112 111 114 116 34 58 56 48 44 34 112 114 111 116 111 99 111 108 34 58 34 84 67 80 34 44 34 116 97 114 103 101 116 80 111 114 116 34 58 53 54 55 56 125 93 44 34 115 101 108 101 99 116 111 114 34 58 123 34 97 112 112 34 58 34 115 105 109 112 108 101 45 97 112 112 45 118 50 34 44 34 118 101 114 115 105 111 110 34 58 34 118 50 34 125 44 34 115 101 115 115 105 111 110 65 102 102 105 110 105 116 121 34 58 34 78 111 110 101 34 44 34 116 121 112 101 34 58 34 67 108 117 115 116 101 114 73 80 34 125 44 34 115 116 97 116 117 115 34 58 123 34 108 111 97 100 66 97 108 97 110 99 101 114 34 58 123 125 125 125] <nil>},OldObject:{[] <nil>},DryRun:*false,Options:{[123 34 97 112 105 86 101 114 115 105 111 110 34 58 34 109 101 116 97 46 107 56 115 46 105 111 47 118 49 34 44 34 102 105 101 108 100 77 97 110 97 103 101 114 34 58 34 107 117 98 101 99 116 108 45 99 108 105 101 110 116 45 115 105 100 101 45 97 112 112 108 121 34 44 34 102 105 101 108 100 86 97 108 105 100 97 116 105 111 110 34 58 34 83 116 114 105 99 116 34 44 34 107 105 110 100 34 58 34 67 114 101 97 116 101 79 112 116 105 111 110 115 34 125] <nil>},RequestKind:/v1, Kind=Service,RequestResource:/v1, Resource=services,RequestSubResource:,}"
time="2025-06-04T11:19:18Z" level=debug msg="request object bytes: {\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{\"kubectl.kubernetes.io/last-applied-configuration\":\"{\\\"apiVersion\\\":\\\"v1\\\",\\\"kind\\\":\\\"Service\\\",\\\"metadata\\\":{\\\"annotations\\\":{},\\\"name\\\":\\\"simple-app-v2\\\",\\\"namespace\\\":\\\"simple-app\\\"},\\\"spec\\\":{\\\"ports\\\":[{\\\"port\\\":80,\\\"targetPort\\\":5678}],\\\"selector\\\":{\\\"app\\\":\\\"simple-app-v2\\\",\\\"version\\\":\\\"v2\\\"}}}\\n\"},\"creationTimestamp\":null,\"managedFields\":[{\"apiVersion\":\"v1\",\"fieldsType\":\"FieldsV1\",\"fieldsV1\":{\"f:metadata\":{\"f:annotations\":{\".\":{},\"f:kubectl.kubernetes.io/last-applied-configuration\":{}}},\"f:spec\":{\"f:internalTrafficPolicy\":{},\"f:ports\":{\".\":{},\"k:{\\\"port\\\":80,\\\"protocol\\\":\\\"TCP\\\"}\":{\".\":{},\"f:port\":{},\"f:protocol\":{},\"f:targetPort\":{}}},\"f:selector\":{},\"f:sessionAffinity\":{},\"f:type\":{}}},\"manager\":\"kubectl-client-side-apply\",\"operation\":\"Update\",\"time\":\"2025-06-04T11:19:18Z\"}],\"name\":\"simple-app-v2\",\"namespace\":\"simple-app\"},\"spec\":{\"internalTrafficPolicy\":\"Cluster\",\"ports\":[{\"port\":80,\"protocol\":\"TCP\",\"targetPort\":5678}],\"selector\":{\"app\":\"simple-app-v2\",\"version\":\"v2\"},\"sessionAffinity\":\"None\",\"type\":\"ClusterIP\"},\"status\":{\"loadBalancer\":{}}}"
time="2025-06-04T11:19:18Z" level=debug msg="/var/run/linkerd/config/values config YAML: clusterDomain: cluster.local\nclusterNetworks: 10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16,fd00::/8\ncniEnabled: false\ncommonLabels: {}\ncontrolPlaneTracing: false\ncontrolPlaneTracingNamespace: linkerd-jaeger\ncontroller:\n  podDisruptionBudget:\n    maxUnavailable: 1\ncontrollerGID: -1\ncontrollerImage: ghcr.io/buoyantio/controller\ncontrollerImageVersion: \"\"\ncontrollerLogFormat: plain\ncontrollerLogLevel: debug\ncontrollerReplicas: 1\ncontrollerUID: 2103\ndebugContainer:\n  image:\n    name: cr.l5d.io/linkerd/debug\n    pullPolicy: \"\"\n    version: edge-25.4.4\ndeploymentStrategy:\n  rollingUpdate:\n    maxSurge: 25%\n    maxUnavailable: 25%\ndestinationController:\n  additionalArgs:\n  - -ext-endpoint-zone-weights\n  livenessProbe:\n    timeoutSeconds: 1\n  podAnnotations: {}\n  readinessProbe:\n    timeoutSeconds: 1\ndisableHeartBeat: false\ndisableIPv6: true\negress:\n  globalEgressNetworkNamespace: linkerd-egress\nenableEndpointSlices: true\nenableH2Upgrade: true\nenablePSP: false\nenablePodAntiAffinity: false\nenablePodDisruptionBudget: false\nenablePprof: false\nidentity:\n  externalCA: false\n  issuer:\n    clockSkewAllowance: 20s\n    issuanceLifetime: 24h0m0s\n    scheme: linkerd.io/tls\n    tls:\n      crtPEM: |\n        -----BEGIN CERTIFICATE-----\n        MIIBsjCCAVigAwIBAgIQG4RR1EkQLvanRZspKw9R3jAKBggqhkjOPQQDAjAlMSMw\n        IQYDVQQDExpyb290LmxpbmtlcmQuY2x1c3Rlci5sb2NhbDAeFw0yNTA2MDQxMTE4\n        NDJaFw0yNjA2MDQxMTE4NDJaMCkxJzAlBgNVBAMTHmlkZW50aXR5LmxpbmtlcmQu\n        Y2x1c3Rlci5sb2NhbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKyE5Px3kwpI\n        ZEGR9Ky0feN3/X/3DQOSDweb3B1O6JK4fAtYDetnyUul+T0zXKtrLX0lrAdRzyaj\n        MLhci5ZMEd6jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEA\n        MB0GA1UdDgQWBBSkrmSMxXmF/CJz14sL5SNbwNh9qjAfBgNVHSMEGDAWgBSw5rC0\n        vxQuKzp3Qyo9+367k6kzMTAKBggqhkjOPQQDAgNIADBFAiA7L9KiSSJdKD8WxSXM\n        cLcyqPe7Sw9lBko/Wcgcue80iwIhAJjddq/892QBoQspnTBctEfUVovznJCIMSKq\n        P4YtzyEn\n        -----END CERTIFICATE-----\n  kubeAPI:\n    clientBurst: 200\n    clientQPS: 100\n  livenessProbe:\n    timeoutSeconds: 1\n  podAnnotations: {}\n  readinessProbe:\n    timeoutSeconds: 1\n  serviceAccountTokenProjection: true\nidentityTrustAnchorsPEM: |\n  -----BEGIN CERTIFICATE-----\n  MIIBjTCCATSgAwIBAgIRAIMD4XLxwxvmNPAOcIuzz/EwCgYIKoZIzj0EAwIwJTEj\n  MCEGA1UEAxMacm9vdC5saW5rZXJkLmNsdXN0ZXIubG9jYWwwHhcNMjUwNjA0MTEx\n  ODQyWhcNMzUwNjAyMTExODQyWjAlMSMwIQYDVQQDExpyb290LmxpbmtlcmQuY2x1\n  c3Rlci5sb2NhbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLwQ70dJQiN0LHY6\n  q4fvIND1LqcyypW8P+qrhVuIdHThgPx/KXXLa2+KjAbUzzeu8PRagGriwRn6+A69\n  AixeeuKjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0G\n  A1UdDgQWBBSw5rC0vxQuKzp3Qyo9+367k6kzMTAKBggqhkjOPQQDAgNHADBEAiAt\n  ZkhSf0dHy7c6dDorCcfUiwNVjSdV2Z+Sl2EJ0ZxorgIgO9hII30K/26KlicbXygh\n  CxaYQ3t5qyY437Z08s11FEg=\n  -----END CERTIFICATE-----\nidentityTrustDomain: cluster.local\nimagePullPolicy: IfNotPresent\nimagePullSecrets: []\nkubeAPI:\n  clientBurst: 200\n  clientQPS: 100\nlicenseResources:\n  resources:\n    limits:\n      cpu: 500m\n      memory: 256Mi\n    requests:\n      cpu: 250m\n      memory: 128Mi\nlicenseSecret: null\nlinkerdVersion: enterprise-2.18.0\nmanageExternalWorkloads: true\nnetworkValidator:\n  connectAddr: \"\"\n  enableSecurityContext: true\n  listenAddr: \"\"\n  logFormat: plain\n  logLevel: debug\n  timeout: 10s\nnodeSelector:\n  kubernetes.io/os: linux\npodAnnotations: {}\npodLabels: {}\npodMonitor:\n  controller:\n    enabled: true\n    namespaceSelector: |\n      matchNames:\n        - {{ .Release.Namespace }}\n        - linkerd-viz\n        - linkerd-jaeger\n  enabled: false\n  labels: {}\n  proxy:\n    enabled: true\n  scrapeInterval: 10s\n  scrapeTimeout: 10s\n  serviceMirror:\n    enabled: true\npolicyController:\n  image:\n    name: ghcr.io/buoyantio/policy-controller\n    pullPolicy: \"\"\n    version: \"\"\n  livenessProbe:\n    timeoutSeconds: 1\n  logLevel: info\n  probeNetworks:\n  - 0.0.0.0/0\n  - ::/0\n  readinessProbe:\n    timeoutSeconds: 1\n  resources:\n    cpu:\n      limit: \"\"\n      request: \"\"\n    ephemeral-storage:\n      limit: \"\"\n      request: \"\"\n    memory:\n      limit: \"\"\n      request: \"\"\npolicyValidator:\n  caBundle: \"\"\n  crtPEM: \"\"\n  externalSecret: false\n  injectCaFrom: \"\"\n  injectCaFromSecret: \"\"\n  namespaceSelector:\n    matchExpressions:\n    - key: config.linkerd.io/admission-webhooks\n      operator: NotIn\n      values:\n      - disabled\npriorityClassName: \"\"\nprofileValidator:\n  caBundle: \"\"\n  crtPEM: \"\"\n  externalSecret: false\n  injectCaFrom: \"\"\n  injectCaFromSecret: \"\"\n  namespaceSelector:\n    matchExpressions:\n    - key: config.linkerd.io/admission-webhooks\n      operator: NotIn\n      values:\n      - disabled\nprometheusUrl: \"\"\nproxy:\n  additionalEnv:\n  - name: BUOYANT_BALANCER_LOAD_LOW\n    value: \"0.1\"\n  - name: BUOYANT_BALANCER_LOAD_HIGH\n    value: \"3.0\"\n  await: true\n  control:\n    streams:\n      idleTimeout: 5m\n      initialTimeout: 3s\n      lifetime: 1h\n  cores: null\n  defaultInboundPolicy: all-unauthenticated\n  disableInboundProtocolDetectTimeout: false\n  disableOutboundProtocolDetectTimeout: false\n  enableExternalProfiles: false\n  enableShutdownEndpoint: false\n  gid: -1\n  image:\n    name: ghcr.io/buoyantio/proxy\n    pullPolicy: \"\"\n    version: \"\"\n  inbound:\n    server:\n      http2:\n        keepAliveInterval: 100s\n        keepAliveTimeout: 100s\n  inboundConnectTimeout: 100ms\n  inboundDiscoveryCacheUnusedTimeout: 90s\n  livenessProbe:\n    initialDelaySeconds: 10\n    timeoutSeconds: 1\n  logFormat: plain\n  logHTTPHeaders: \"off\"\n  logLevel: warn,linkerd=debug,hickory=error,linkerd_proxy_http::client[{headers}]=on\n  metrics:\n    hostnameLabels: false\n  nativeSidecar: false\n  opaquePorts: 25,587,3306,4444,5432,6379,9300,11211\n  outbound:\n    server:\n      http2:\n        keepAliveInterval: 200s\n        keepAliveTimeout: 200s\n  outboundConnectTimeout: 1000ms\n  outboundDiscoveryCacheUnusedTimeout: 5s\n  outboundTransportMode: transport-header\n  ports:\n    admin: 4191\n    control: 4190\n    inbound: 4143\n    outbound: 4140\n  readinessProbe:\n    initialDelaySeconds: 2\n    timeoutSeconds: 1\n  requireIdentityOnInboundPorts: \"\"\n  resources:\n    cpu:\n      limit: \"\"\n      request: \"\"\n    ephemeral-storage:\n      limit: \"\"\n      request: \"\"\n    memory:\n      limit: \"\"\n      request: \"\"\n  runtime:\n    workers:\n      maximumCPURatio: null\n      minimum: 1\n  shutdownGracePeriod: \"\"\n  startupProbe:\n    failureThreshold: 120\n    initialDelaySeconds: 0\n    periodSeconds: 1\n  uid: 2102\n  waitBeforeExitSeconds: 0\nproxyInit:\n  closeWaitTimeoutSecs: 0\n  ignoreInboundPorts: 4567,4568\n  ignoreOutboundPorts: 4567,4568\n  image:\n    name: ghcr.io/buoyantio/proxy-init\n    pullPolicy: \"\"\n    version: enterprise-2.18.0\n  iptablesMode: legacy\n  kubeAPIServerPorts: 443,6443\n  logFormat: \"\"\n  logLevel: \"\"\n  privileged: false\n  runAsGroup: 65534\n  runAsRoot: false\n  runAsUser: 65534\n  skipSubnets: \"\"\n  xtMountPath:\n    mountPath: /run\n    name: linkerd-proxy-init-xtables-lock\nproxyInjector:\n  caBundle: \"\"\n  crtPEM: \"\"\n  externalSecret: false\n  injectCaFrom: \"\"\n  injectCaFromSecret: \"\"\n  livenessProbe:\n    timeoutSeconds: 1\n  namespaceSelector:\n    matchExpressions:\n    - key: config.linkerd.io/admission-webhooks\n      operator: NotIn\n      values:\n      - disabled\n    - key: kubernetes.io/metadata.name\n      operator: NotIn\n      values:\n      - kube-system\n      - cert-manager\n  objectSelector:\n    matchExpressions:\n    - key: linkerd.io/control-plane-component\n      operator: DoesNotExist\n    - key: linkerd.io/cni-resource\n      operator: DoesNotExist\n  podAnnotations: {}\n  readinessProbe:\n    timeoutSeconds: 1\n  timeoutSeconds: 10\nrevisionHistoryLimit: 10\nruntimeClassName: \"\"\nspValidator:\n  livenessProbe:\n    timeoutSeconds: 1\n  readinessProbe:\n    timeoutSeconds: 1\nwebhookFailurePolicy: Ignore\n"
```

## References

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook
- https://github.com/linkerd/linkerd2/blob/main/pkg/inject/inject.go
- https://github.com/linkerd/linkerd2/blob/main/controller/proxy-injector/webhook.go
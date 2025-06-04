+++
author = "Ivan Porta"
title = "Control Plane"
date = "2025-06-01"
description = "Deep dive into Linkerd’s Destination controller—how it leverages informers, watches EndpointSlices, and performs leader election to serve service discovery in Kubernetes."
tags = [
  "linkerd",
  "control-plane",
  "destination",
  "kubernetes",
  "deep-dive"
]
+++

# Destination

The Destination controller in Linkerd’s control plane is responsible for service discovery and routing. It watches Kubernetes resources (Services, EndpointSlices, Pods, ExternalWorkloads, etc.) via shared informers, builds a local cache of endpoints, and serves gRPC requests from data-plane proxies. 

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

## 5. Linkerd Destination 

### Interactions with the Kuberentes API

When Destination starts, it use the `k8s.io/client-go` GO module to build one shared informer for every resource kinds it cares about (CronJobs, Pods, Services, etc.) and stores the handle in the API struct, as well as check and records a HasSynced check for each, and registers a Prometheus gauge that reports the current key count per cache. 

```
func newAPI(
	k8sClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	l5dCrdClient l5dcrdclient.Interface,
	sharedInformers informers.SharedInformerFactory,
	cluster string,
	resources ...APIResource,
) *API {
	var l5dCrdSharedInformers l5dcrdinformer.SharedInformerFactory
	if l5dCrdClient != nil {
		l5dCrdSharedInformers = l5dcrdinformer.NewSharedInformerFactory(l5dCrdClient, ResyncTime)
	}

	api := &API{
		Client:                k8sClient,
		L5dClient:             l5dCrdClient,
		DynamicClient:         dynamicClient,
		syncChecks:            make([]cache.InformerSynced, 0),
		sharedInformers:       sharedInformers,
		l5dCrdSharedInformers: l5dCrdSharedInformers,
	}

	informerLabels := prometheus.Labels{
		"cluster": cluster,
	}

	for _, resource := range resources {
		switch resource {
		case CJ:
			api.cj = sharedInformers.Batch().V1().CronJobs()
			api.syncChecks = append(api.syncChecks, api.cj.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.CronJob, informerLabels, api.cj.Informer())
		case CM:
			api.cm = sharedInformers.Core().V1().ConfigMaps()
			api.syncChecks = append(api.syncChecks, api.cm.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.ConfigMap, informerLabels, api.cm.Informer())
		case Deploy:
			api.deploy = sharedInformers.Apps().V1().Deployments()
			api.syncChecks = append(api.syncChecks, api.deploy.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Deployment, informerLabels, api.deploy.Informer())
		case DS:
			api.ds = sharedInformers.Apps().V1().DaemonSets()
			api.syncChecks = append(api.syncChecks, api.ds.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.DaemonSet, informerLabels, api.ds.Informer())
		case Endpoint:
			api.endpoint = sharedInformers.Core().V1().Endpoints()
			api.syncChecks = append(api.syncChecks, api.endpoint.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Endpoints, informerLabels, api.endpoint.Informer())
		case ES:
			api.es = sharedInformers.Discovery().V1().EndpointSlices()
			api.syncChecks = append(api.syncChecks, api.es.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.EndpointSlices, informerLabels, api.es.Informer())
		case ExtWorkload:
			if l5dCrdSharedInformers == nil {
				panic("Linkerd CRD shared informer not configured")
			}
			api.ew = l5dCrdSharedInformers.Externalworkload().V1beta1().ExternalWorkloads()
			api.syncChecks = append(api.syncChecks, api.ew.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.ExtWorkload, informerLabels, api.ew.Informer())
		case Job:
			api.job = sharedInformers.Batch().V1().Jobs()
			api.syncChecks = append(api.syncChecks, api.job.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Job, informerLabels, api.job.Informer())
		case Link:
			if l5dCrdSharedInformers == nil {
				panic("Linkerd CRD shared informer not configured")
			}
			api.link = l5dCrdSharedInformers.Link().V1alpha3().Links()
			api.syncChecks = append(api.syncChecks, api.link.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Link, informerLabels, api.link.Informer())
		case MWC:
			api.mwc = sharedInformers.Admissionregistration().V1().MutatingWebhookConfigurations()
			api.syncChecks = append(api.syncChecks, api.mwc.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.MutatingWebhookConfig, informerLabels, api.mwc.Informer())
		case NS:
			api.ns = sharedInformers.Core().V1().Namespaces()
			api.syncChecks = append(api.syncChecks, api.ns.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Namespace, informerLabels, api.ns.Informer())
		case Pod:
			api.pod = sharedInformers.Core().V1().Pods()
			api.syncChecks = append(api.syncChecks, api.pod.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Pod, informerLabels, api.pod.Informer())
		case RC:
			api.rc = sharedInformers.Core().V1().ReplicationControllers()
			api.syncChecks = append(api.syncChecks, api.rc.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.ReplicationController, informerLabels, api.rc.Informer())
		case RS:
			api.rs = sharedInformers.Apps().V1().ReplicaSets()
			api.syncChecks = append(api.syncChecks, api.rs.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.ReplicaSet, informerLabels, api.rs.Informer())
		case SP:
			if l5dCrdSharedInformers == nil {
				panic("Linkerd CRD shared informer not configured")
			}
			api.sp = l5dCrdSharedInformers.Linkerd().V1alpha2().ServiceProfiles()
			api.syncChecks = append(api.syncChecks, api.sp.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.ServiceProfile, informerLabels, api.sp.Informer())
		case Srv:
			if l5dCrdSharedInformers == nil {
				panic("Linkerd CRD shared informer not configured")
			}
			api.srv = l5dCrdSharedInformers.Server().V1beta3().Servers()
			api.syncChecks = append(api.syncChecks, api.srv.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Server, informerLabels, api.srv.Informer())
		case SS:
			api.ss = sharedInformers.Apps().V1().StatefulSets()
			api.syncChecks = append(api.syncChecks, api.ss.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.StatefulSet, informerLabels, api.ss.Informer())
		case Svc:
			api.svc = sharedInformers.Core().V1().Services()
			api.syncChecks = append(api.syncChecks, api.svc.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Service, informerLabels, api.svc.Informer())
		case Node:
			api.node = sharedInformers.Core().V1().Nodes()
			api.syncChecks = append(api.syncChecks, api.node.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Node, informerLabels, api.node.Informer())
		case Secret:
			api.secret = sharedInformers.Core().V1().Secrets()
			api.syncChecks = append(api.syncChecks, api.secret.Informer().HasSynced)
			api.promGauges.addInformerSize(k8s.Secret, informerLabels, api.secret.Informer())
		}
	}
	return api
}
```

When the `Sync` function is called, each informer request to get the initial snapshot, and then opens long-lived watch streams (parameter `watch=0`) so it can receive change events as they happen. If no events arrive withing 10 minutes (defined by the constant `ResyncTime = 10 * time.Minute`), it will requets a new compelte snapshot to the Kubernetes API Server.

```
kubectl logs -n linkerd deploy/linkerd-destination -c destination --follow
...
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/workload.linkerd.io/v1beta1/externalworkloads?allowWatchBookmarks=true&resourceVersion=740&timeout=7m47s&timeoutSeconds=467&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/discovery.k8s.io/v1/endpointslices?allowWatchBookmarks=true&resourceVersion=751&timeout=9m16s&timeoutSeconds=556&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/batch/v1/jobs?allowWatchBookmarks=true&resourceVersion=740&timeout=9m10s&timeoutSeconds=550&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/endpoints?allowWatchBookmarks=true&resourceVersion=740&timeout=9m35s&timeoutSeconds=575&watch=true 200 OK in 1 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/linkerd.io/v1alpha2/serviceprofiles?allowWatchBookmarks=true&resourceVersion=740&timeout=7m19s&timeoutSeconds=439&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/policy.linkerd.io/v1beta3/servers?allowWatchBookmarks=true&resourceVersion=740&timeout=8m16s&timeoutSeconds=496&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/services?allowWatchBookmarks=true&resourceVersion=740&timeout=8m50s&timeoutSeconds=530&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/pods?allowWatchBookmarks=true&resourceVersion=741&timeout=8m55s&timeoutSeconds=535&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/apps/v1/replicasets?allowWatchBookmarks=true&resourceVersion=739&timeout=7m4s&timeoutSeconds=424&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/apis/batch/v1/jobs?allowWatchBookmarks=true&resourceVersion=740&timeout=7m29s&timeoutSeconds=449&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/nodes?allowWatchBookmarks=true&resourceVersion=740&timeout=8m30s&timeoutSeconds=510&watch=true 200 OK in 0 milliseconds"
time="2025-05-19T09:10:15Z" level=info msg="GET https://10.247.0.1:443/api/v1/namespaces/linkerd/secrets?allowWatchBookmarks=true&resourceVersion=740&timeout=9m7s&timeoutSeconds=547&watch=true 200 OK in 0 milliseconds"
```

Each informer owns a thread-safe local cache where it store the data returned by the Kubernetes API Server. 


By itself, an informer does not actually notify your business logic when things change; it only populates a local cache and lets you query it. For this reason the Controller's source code has several watchers on top of the related informers that registers event handlers on those informers, so it actually gets notified when the cache is updated.

```
func NewEndpointsWatcher(k8sAPI *k8s.API, metadataAPI *k8s.MetadataAPI, log *logging.Entry, enableEndpointSlices bool, cluster string) (*EndpointsWatcher, error) {
	ew := &EndpointsWatcher{
		publishers:           make(map[ServiceID]*servicePublisher),
		k8sAPI:               k8sAPI,
		metadataAPI:          metadataAPI,
		enableEndpointSlices: enableEndpointSlices,
		cluster:              cluster,
		log: log.WithFields(logging.Fields{
			"component": "endpoints-watcher",
		}),
	}
	var err error
	ew.svcHandle, err = k8sAPI.Svc().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ew.addService,
		DeleteFunc: ew.deleteService,
		UpdateFunc: ew.updateService,
	})
	if err != nil {
		return nil, err
	}
	ew.srvHandle, err = k8sAPI.Srv().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ew.addServer,
		DeleteFunc: ew.deleteServer,
		UpdateFunc: ew.updateServer,
	})
	if err != nil {
		return nil, err
	}
	if ew.enableEndpointSlices {
		ew.log.Debugf("Watching EndpointSlice resources")
		ew.epHandle, err = k8sAPI.ES().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    ew.addEndpointSlice,
			DeleteFunc: ew.deleteEndpointSlice,
			UpdateFunc: ew.updateEndpointSlice,
		})
		if err != nil {
			return nil, err
		}
	} else {
		ew.log.Debugf("Watching Endpoints resources")
		ew.epHandle, err = k8sAPI.Endpoint().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    ew.addEndpoints,
			DeleteFunc: ew.deleteEndpoints,
			UpdateFunc: ew.updateEndpoints,
		})
		if err != nil {
			return nil, err
		}
	}
	return ew, nil
}
```

Once notified, depending on the action, will create a differential between the new and old version, and then update the listerers  so that see only the incremental change.

```
func (pp *portPublisher) updateEndpoints(endpoints *corev1.Endpoints) {
	newAddressSet := pp.endpointsToAddresses(endpoints)
	if len(newAddressSet.Addresses) == 0 {
		for _, listener := range pp.listeners {
			listener.NoEndpoints(true)
		}
	} else {
		add, remove := diffAddresses(pp.addresses, newAddressSet)
		for _, listener := range pp.listeners {
			if len(remove.Addresses) > 0 {
				listener.Remove(remove)
			}
			if len(add.Addresses) > 0 {
				listener.Add(add)
			}
		}
	}
	pp.addresses = newAddressSet
	pp.exists = true
	pp.metrics.incUpdates()
	pp.metrics.setPods(len(pp.addresses.Addresses))
	pp.metrics.setExists(true)
}
```

You will be able to see the related logs message

```
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for kube-system/kube-dns" addr=":8086" component=service-publisher ns=kube-system svc=kube-dns
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for kube-system/metrics-server" addr=":8086" component=service-publisher ns=kube-system svc=metrics-server
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-dst" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-dst
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-dst-headless" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-dst-headless
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-identity" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-identity
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-identity-headless" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-identity-headless
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-policy" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-policy
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-policy-validator" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-policy-validator
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-proxy-injector" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-proxy-injector
time="2025-06-03T15:39:09Z" level=debug msg="Updating service for linkerd/linkerd-sp-validator" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-sp-validator
```

The same will happen for EndpointSlices and Endpoints. It's important to understant that it won't watch both of them. Depending on `ew.enableEndpointSlices` it will watch one or the other. This value is received as parameter from the container `-enable-endpoint-slices` and by default is set to `true`.

```
func (sp *servicePublisher) addEndpointSlice(newSlice *discovery.EndpointSlice) {
	sp.Lock()
	defer sp.Unlock()

	sp.log.Debugf("Adding ES %s/%s", newSlice.Namespace, newSlice.Name)
	for _, port := range sp.ports {
		port.addEndpointSlice(newSlice)
	}
}
...
func (ew *EndpointsWatcher) addEndpointSlice(obj interface{}) {
	newSlice, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		ew.log.Errorf("error processing EndpointSlice resource, got %#v expected *discovery.EndpointSlice", obj)
		return
	}

	id, err := getEndpointSliceServiceID(newSlice)
	if err != nil {
		ew.log.Errorf("Could not fetch resource service name:%v", err)
		return
	}

	sp := ew.getOrNewServicePublisher(id)
	sp.addEndpointSlice(newSlice)
}
```

With their related logs

```
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES default/kubernetes" addr=":8086" component=service-publisher ns=default svc=kubernetes
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES kube-system/kube-dns-g2kr4" addr=":8086" component=service-publisher ns=kube-system svc=kube-dns
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES kube-system/metrics-server-mfqjs" addr=":8086" component=service-publisher ns=kube-system svc=metrics-server
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-dst-headless-kz5q4" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-dst-headless
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-dst-pmtjw" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-dst
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-identity-dzpzm" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-identity
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-identity-headless-45vjs" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-identity-headless
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-policy-n54jm" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-policy
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-policy-validator-5hqbl" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-policy-validator
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-proxy-injector-kzk6j" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-proxy-injector
time="2025-06-03T15:39:09Z" level=debug msg="Adding ES linkerd/linkerd-sp-validator-g7vgx" addr=":8086" component=service-publisher ns=linkerd svc=linkerd-sp-validator
```

### External Workloads

Linkerd’s destination subsystem manages `ExternalWorkload` resources to represent workloads running outside the cluster. Unlike normal Pods, these workloads are not native Kubernetes objects; their IPs live in the `ExternalWorkload.spec.workloadIPs` field.

```
kubectl get externalworkload -n simple-app   external-simple-app-v1-0e340584 -o yaml
apiVersion: workload.linkerd.io/v1beta1
kind: ExternalWorkload
metadata:
  name: external-simple-app-v1-0e340584
  namespace: simple-app
  ...
spec:
  meshTLS:
    identity: spiffe://root.linkerd.cluster.local/proxy-harness
    serverName: external-simple-app-v1-0e340584.simple-app.external.identity.linkerd.cluster.local
  ports:
  - name: http
    port: 80
    protocol: TCP
  workloadIPs:
  - ip: 172.20.0.8
...
```

When an `ExternalWorkload` is created, updated, or deleted, Linkerd’s controller sets up informers to catch those events and invoke the related function in the handler.

```
func (ec *EndpointsController) addHandlers() error {
	...
	ec.ewHandle, err = ec.k8sAPI.ExtWorkload().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ec.onAddExternalWorkload,
		DeleteFunc: ec.onDeleteExternalWorkload,
		UpdateFunc: ec.onUpdateExternalWorkload,
	})
	if err != nil {
		return err
	}
	return nil
}
```

To decide which Services should include a given `ExternalWorkload`, the controller uses a label‐selector match to create a list of `<namespace>/<service-name>` so that it will know exactly which Services need to be re‐synced.

```
func (ec *EndpointsController) getExternalWorkloadSvcMembership(workload *ewv1beta1.ExternalWorkload) (sets.Set[string], error) {
	keys := sets.Set[string]{}
	services, err := ec.k8sAPI.Svc().Lister().Services(workload.Namespace).List(labels.Everything())
	if err != nil {
		return keys, err
	}
	for _, svc := range services {
		if svc.Spec.Selector == nil {
			continue
		}
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(svc)
		if err != nil {
			return sets.Set[string]{}, err
		}
		if labels.ValidatedSetSelector(svc.Spec.Selector).Matches(labels.Set(workload.Labels)) {
			keys.Insert(key)
		}
	}
	return keys, nil
}
```

When an `ExternalWorkload` is updated, it re‐evaluate both its IPs and its labels. Only if something actually changed do it will re‐enqueue the affected Services.

```
func (ec *EndpointsController) getServicesToUpdateOnExternalWorkloadChange(old, cur interface{}) sets.Set[string] {
	newEw, newEwOk := cur.(*ewv1beta1.ExternalWorkload)
	oldEw, oldEwOk := old.(*ewv1beta1.ExternalWorkload)
	if !oldEwOk {
		ec.log.Errorf("Expected (cur) to be an EndpointSlice in getServicesToUpdateOnExternalWorkloadChange(), got type: %T", cur)
		return sets.Set[string]{}
	}
	if !newEwOk {
		ec.log.Errorf("Expected (old) to be an EndpointSlice in getServicesToUpdateOnExternalWorkloadChange(), got type: %T", old)
		return sets.Set[string]{}
	}
	if newEw.ResourceVersion == oldEw.ResourceVersion {
		return sets.Set[string]{}
	}
	ewChanged, labelsChanged := ewEndpointsChanged(oldEw, newEw)
	if !ewChanged && !labelsChanged {
		ec.log.Errorf("skipping update; nothing has changed between old rv %s and new rv %s", oldEw.ResourceVersion, newEw.ResourceVersion)
		return sets.Set[string]{}
	}
	services, err := ec.getExternalWorkloadSvcMembership(newEw)
	if err != nil {
		ec.log.Errorf("unable to get pod %s/%s's service memberships: %v", newEw.Namespace, newEw.Name, err)
		return sets.Set[string]{}
	}
	if labelsChanged {
		oldServices, err := ec.getExternalWorkloadSvcMembership(oldEw)
		if err != nil {
			ec.log.Errorf("unable to get pod %s/%s's service memberships: %v", oldEw.Namespace, oldEw.Name, err)
		}
		services = determineNeededServiceUpdates(oldServices, services, ewChanged)
	}
	return services
}
```

Once Services are enqueued, a background worker handles them one at a time.

```
func (ec *EndpointsController) processQueue() {
	for {
		key, quit := ec.queue.Get()
		if quit {
			ec.log.Trace("queue received shutdown signal")
			return
		}
		err := ec.syncService(key)
		ec.handleError(err, key)
		ec.queue.Done(key)
	}
}
```

The `syncService` method ensures the set of EndpointSlice objects for a Service matches exactly the IPs from its corresponding ExternalWorkload CRs. It will consider only Services with a Type different than `ExternalName`.

```
func (ec *EndpointsController) syncService(update string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(update)
	if err != nil {
		return err
	}
	svc, err := ec.k8sAPI.Svc().Lister().Services(namespace).Get(name)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}
		ec.reconciler.endpointTracker.DeleteService(namespace, name)
		return nil
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return nil
	}
	if svc.Spec.Selector == nil {
		return nil
	}
	ewSelector := labels.Set(svc.Spec.Selector).AsSelectorPreValidated()
	ews, err := ec.k8sAPI.ExtWorkload().Lister().List(ewSelector)
	if err != nil {
		return err
	}
	esSelector := labels.Set(map[string]string{
		discoveryv1.LabelServiceName: svc.Name,
		discoveryv1.LabelManagedBy:   managedBy,
	}).AsSelectorPreValidated()
	epSlices, err := ec.k8sAPI.ES().Lister().List(esSelector)
	if err != nil {
		return err
	}
	epSlices = dropEndpointSlicesPendingDeletion(epSlices)
	if ec.reconciler.endpointTracker.StaleSlices(svc, epSlices) {
		ec.log.Warnf("detected EndpointSlice informer cache is out of date when processing %s", update)
		return errors.New("EndpointSlice informer cache is out of date")
	}
	err = ec.reconciler.reconcile(svc, ews, epSlices)
	if err != nil {
		return err
	}
	return nil
}
```

Fianlly, it will delegates the heavy lifting to the `reconcile` method. The goal of this method is to produce exactly the right set of `EndpointSlice` objects so that each Service’s external IPs (from `ExternalWorkload`) are reflected. It will immediately deletes any slices that advertise an `AddressType` the Service no longer supports, create three lists with the slices to Create, Update, or Delete.

```
func (r *endpointsReconciler) reconcile(svc *corev1.Service, ews []*ewv1beta1.ExternalWorkload, existingSlices []*discoveryv1.EndpointSlice) error {
	toDelete := []*discoveryv1.EndpointSlice{}
	slicesByAddrType := make(map[discoveryv1.AddressType][]*discoveryv1.EndpointSlice)
	errs := []error{}
	supportedAddrTypes := getSupportedAddressTypes(svc)
	for _, slice := range existingSlices {
		if _, supported := supportedAddrTypes[slice.AddressType]; !supported {
			toDelete = append(toDelete, slice)
			continue
		}
		if _, ok := slicesByAddrType[slice.AddressType]; !ok {
			slicesByAddrType[slice.AddressType] = []*discoveryv1.EndpointSlice{}
		}
		slicesByAddrType[slice.AddressType] = append(slicesByAddrType[slice.AddressType], slice)
	}
	for addrType := range supportedAddrTypes {
		existingSlices := slicesByAddrType[addrType]
		err := r.reconcileByAddressType(svc, ews, existingSlices, addrType)
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, slice := range toDelete {
		err := r.k8sAPI.Client.DiscoveryV1().EndpointSlices(svc.Namespace).Delete(context.TODO(), slice.Name, metav1.DeleteOptions{})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}
```

Once we know exactly which slices need to be created, updated, or deleted, we push those changes to Kubernetes.

```
func (r *endpointsReconciler) finalize(svc *corev1.Service, slicesToCreate, slicesToUpdate, slicesToDelete []*discoveryv1.EndpointSlice) error {
	for i := 0; i < len(slicesToDelete); {
		if len(slicesToCreate) == 0 {
			break
		}
		sliceToDelete := slicesToDelete[i]
		slice := slicesToCreate[len(slicesToCreate)-1]
		if sliceToDelete.AddressType == slice.AddressType && ownedBy(sliceToDelete, svc) {
			slice.Name = sliceToDelete.Name
			slicesToCreate = slicesToCreate[:len(slicesToCreate)-1]
			slicesToUpdate = append(slicesToUpdate, slice)
			slicesToDelete = append(slicesToDelete[:i], slicesToDelete[i+1:]...)
		} else {
			i++
		}
	}
	r.log.Debugf("reconciliation result for %s/%s: %d to add, %d to update, %d to remove", svc.Namespace, svc.Name, len(slicesToCreate), len(slicesToUpdate), len(slicesToDelete))
	if svc.DeletionTimestamp == nil {
		for _, slice := range slicesToCreate {
			r.log.Tracef("starting create: %s/%s", slice.Namespace, slice.Name)
			createdSlice, err := r.k8sAPI.Client.DiscoveryV1().EndpointSlices(svc.Namespace).Create(context.TODO(), slice, metav1.CreateOptions{})
			if err != nil {
				if errors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
					return nil
				}
				return err
			}
			r.endpointTracker.Update(createdSlice)
			r.log.Tracef("finished creating: %s/%s", createdSlice.Namespace, createdSlice.Name)
		}
	}
	for _, slice := range slicesToUpdate {
		r.log.Tracef("starting update: %s/%s", slice.Namespace, slice.Name)
		updatedSlice, err := r.k8sAPI.Client.DiscoveryV1().EndpointSlices(svc.Namespace).Update(context.TODO(), slice, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		r.endpointTracker.Update(updatedSlice)
		r.log.Tracef("finished updating: %s/%s", updatedSlice.Namespace, updatedSlice.Name)
	}
	for _, slice := range slicesToDelete {
		r.log.Tracef("starting delete: %s/%s", slice.Namespace, slice.Name)
		err := r.k8sAPI.Client.DiscoveryV1().EndpointSlices(svc.Namespace).Delete(context.TODO(), slice.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		r.endpointTracker.ExpectDeletion(slice)
		r.log.Tracef("finished deleting: %s/%s", slice.Namespace, slice.Name)
	}
	return nil
}
```

Because multiple `destination` controller replicas may run, Linekrd use a leader election pattern to ensure only one instance writes `EndpointSlice` objects at a time. It uses a Kubernetes `Lease` object to coordinate leadership with the following configuration.

```
ec.lec = leaderelection.LeaderElectionConfig{
    Lock: &resourcelock.LeaseLock{
        LeaseMeta: metav1.ObjectMeta{
            Name:      "linkerd-destination-endpoint-write",
            Namespace: controllerNs,
        },
        Client: k8sAPI.Client.CoordinationV1(),
        LockConfig: resourcelock.ResourceLockConfig{
            Identity: hostname,  // unique ID per instance
        },
    },
    LeaseDuration: 30 * time.Second,
    RenewDeadline: 10 * time.Second,
    RetryPeriod:   2 * time.Second,
    Callbacks: leaderelection.LeaderCallbacks{
        OnStartedLeading: ec.addHandlers,
        OnStoppedLeading: ec.removeHandlers,
    },
}
```

As long as the leader continues to renew, it keeps reconciling ExternalWorkload changes. If it fails, another replica becomes leader and resumes write operations. You will be able to see an output with the periodic renewals.

```
time="2025-05-19T08:53:23Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 2 milliseconds"
...
time="2025-05-19T08:53:25Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 6 milliseconds"
```

## References

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/watcher/workload_watcher.go
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/watcher/k8s.go
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/watcher/endpoints_watcher.go
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/external-workload/endpoints_controller.go
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/external-workload/endpoints_reconciler.go
- https://github.com/linkerd/linkerd2/blob/main/controller/k8s/k8s.go
- https://github.com/linkerd/linkerd2/blob/main/controller/k8s/api.go
- https://pkg.go.dev/k8s.io/client-go
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/
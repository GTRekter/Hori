+++
author = "Ivan Porta"
title = "Control Plane"
date = "2025-06-01"
description = "Deep dive into Linkerd’s control-plane architecture—destination, identity, policy, and proxy-injector controllers—and how they coordinate gRPC traffic and leader election in Kubernetes."
tags = [
  "linkerd",
  "control-plane",
  "architecture",
  "kubernetes",
  "deep-dive"
]
+++

# Control Plane

Linkerd Service Mesh has a two layer archtitecture with:
- **Control Plane:** composed by the destination, policy, identity, sp-validatior and proxy-injector controllers
- **Data Plane:** composed by the proxies running alongside the applications in the same pod and taking care of managin all the inbound/outbound communications.

The Control Plane and the proxies communicate via gRPC, while the proxies communivate via HTTP/2.

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

### External Workloads

Destination is also in charge of handling the `ExternalWorkloads` endpoints. To preventing conflicts with other instances, it will use a leader/follower model. It's configuration is defined as following:

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

When the controller gains leadership, it registers event handlers that are going to be triggered on changes to Kubernetes Service, EndpointSlices and ExternalWorkloads resources.

```
func (ec *EndpointsController) addHandlers() error {
	var err error
	ec.Lock()
	defer ec.Unlock()
	ec.reconciler.endpointTracker = epsliceutil.NewEndpointSliceTracker()
	ec.svcHandle, err = ec.k8sAPI.Svc().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ec.onServiceUpdate,
		DeleteFunc: ec.onServiceUpdate,
		UpdateFunc: func(_, newObj interface{}) {
			ec.onServiceUpdate(newObj)
		},
	})
	...
	ec.esHandle, err = ec.k8sAPI.ES().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ec.onEndpointSliceAdd,
		UpdateFunc: ec.onEndpointSliceUpdate,
		DeleteFunc: ec.onEndpointSliceDelete,
	})
	...
	ec.ewHandle, err = ec.k8sAPI.ExtWorkload().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ec.onAddExternalWorkload,
		DeleteFunc: ec.onDeleteExternalWorkload,
		UpdateFunc: ec.onUpdateExternalWorkload,
	})
	...
	return nil
}
```

It will then create/update or delete EndpointSlice based of the comparison with the existing resources. 

```
func (r *endpointsReconciler) finalize(svc *corev1.Service, slicesToCreate, slicesToUpdate, slicesToDelete []*discoveryv1.EndpointSlice) error {
	...
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

The lease is renewed peridically and visible in the logs as following.

```
time="2025-05-19T08:53:23Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 2 milliseconds"
...
time="2025-05-19T08:53:25Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 6 milliseconds"
```

## 6. Linkerd Proxy-Injector

It's using a mutating webhook to intercept the requests to the kubernetes API when a new pod is created, then check the annotations and if there is `linkerd.io/injected: enabled` then inject a Linkerd proxy and ProxyInit containers.

## References

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
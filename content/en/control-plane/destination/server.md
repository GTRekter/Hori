---
title: 'Destination Controller'
author: "Ivan Porta"
date: "2025-06-01"
description: "Deep dive into Linkerd’s Destination controller—how it leverages informers, watches EndpointSlices, and performs leader election to serve service discovery in Kubernetes."
tags: [
  "linkerd",
  "control-plane",
  "destination",
  "kubernetes",
  "deep-dive"
]
bookcase_cover_src: 'control-plane/destination.png'
bookcase_cover_src_dark: 'control-plane/destination_white.png'
---

# Destination Controller

When we install Linkerd, it will deploy a destination controller in the destination pods. This controller is responsible for service discovery and routing. t watches Kubernetes resources (Services, EndpointSlices, Pods, ExternalWorkloads, etc.) via shared informers, builds a local cache of endpoints, and serves gRPC requests from data-plane proxies. It will server the requests coming from the proxies via gRPC on port 8086, and expose the metrics on port 9996.

```
kubectl get pod -n linkerd       linkerd-destination-86f8d8498b-sbtdl -o yaml
apiVersion: v1
kind: Pod
metadata:
  name: linkerd-destination-86f8d8498b-sbtdl
  namespace: linkerd
spec:
  automountServiceAccountToken: false
  containers:
  - args:
    - destination
    - -addr=:8086
    - -controller-namespace=linkerd
    - -enable-h2-upgrade=true
    - -log-level=debug
    - -log-format=plain
    - -enable-endpoint-slices=true
    - -cluster-domain=cluster.local
    - -identity-trust-domain=cluster.local
    - -default-opaque-ports=25,587,3306,4444,5432,6379,9300,11211
    - -enable-ipv6=false
    - -enable-pprof=false
    - -ext-endpoint-zone-weights
    image: ghcr.io/buoyantio/controller:enterprise-2.17.1
    name: destination
    ports:
    - containerPort: 8086
      name: grpc
      protocol: TCP
    - containerPort: 9996
      name: admin-http
      protocol: TCP
	...
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access
      readOnly: true
```

When the container starts, it will:
- Start a new server to export the metrics via HTTP with `adminServer := admin.NewServer(*metricsAddr, *enablePprof, &ready)`
- Create a K8s API Client `k8Client, err := pkgK8s.NewAPI(*kubeConfigPath, "", "", []string{}, 0)` that is going to be later initialized diferently based on the `enableEndpointSlices` parameter.
- Validate and use the the parameter passed to the container to initialize a new server `destination.NewServer(*addr, config, k8sAPI, metadataAPI, clusterStore, done)`
- Start the cluster store watcher directly via `clusterStore, err := watcher.NewClusterStore(k8Client, *controllerNamespace, *enableEndpointSlices)`

## Interactions with the Kuberentes API

When K8s API Client starts, it use the `k8s.io/client-go` GO module to build one shared informer for every resource kinds it cares about (CronJobs, Pods, Services, etc.) and stores the handle in the API struct, as well as check and records a HasSynced check for each, and registers a Prometheus gauge that reports the current key count per cache. 

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

By itself, an informer does not actually notify your business logic when things change; it only populates a local cache and lets you query it. For this reason the Controller's source code has several watchers on top of the related informers that registers event handlers on those informers, so it actually gets notified when the cache is updated. At the time of this writing, there are currently 5 main watchers:
- Endpoints Watcher
- Profile Watcher
- Workload Watcher
- Opaque Port sWatcher
- Federated Service Watcher

## Destination Server

The server.go file is the “glue” that ties all of the individual watchers and translators together into a single gRPC server that speaks the Destination API to the data‐plane proxies. Its contructor will ensure that all of the informer are set up so that each watcher can do fast lookups.

```
func NewServer(
	addr string,
	config Config,
	k8sAPI *k8s.API,
	metadataAPI *k8s.MetadataAPI,
	clusterStore *watcher.ClusterStore,
	shutdown <-chan struct{},
) (*grpc.Server, error) {
	log := logging.WithFields(logging.Fields{
		"addr":      addr,
		"component": "server",
	})
	err := watcher.InitializeIndexers(k8sAPI)
	if err != nil {
		return nil, err
	}
	workloads, err := watcher.NewWorkloadWatcher(k8sAPI, metadataAPI, log, config.EnableEndpointSlices, config.DefaultOpaquePorts)
	if err != nil {
		return nil, err
	}
	endpoints, err := watcher.NewEndpointsWatcher(k8sAPI, metadataAPI, log, config.EnableEndpointSlices, "local")
	if err != nil {
		return nil, err
	}
	opaquePorts, err := watcher.NewOpaquePortsWatcher(k8sAPI, log, config.DefaultOpaquePorts)
	if err != nil {
		return nil, err
	}
	profiles, err := watcher.NewProfileWatcher(k8sAPI, log)
	if err != nil {
		return nil, err
	}
	federatedServices, err := newFederatedServiceWatcher(k8sAPI, metadataAPI, &config, clusterStore, endpoints, log)
	if err != nil {
		return nil, err
	}
	srv := server{
		pb.UnimplementedDestinationServer{},
		config,
		workloads,
		endpoints,
		opaquePorts,
		profiles,
		clusterStore,
		federatedServices,
		k8sAPI,
		metadataAPI,
		log,
		shutdown,
	}
	s := prometheus.NewGrpcServer(grpc.MaxConcurrentStreams(0))
	pb.RegisterDestinationServer(s, &srv)
	return s, nil
}
```

It will then expose two endpoints: `Get` and `GetProfile`.

### Get Endpoint

This method will process Inbound gRPC requests coming from the proxies. It extracts the remote TCP address of whoever opened this gRPC connection, and splits that string to get the `Host` and `Port`. Next, it takes `Host` (e.g. "svc.ns.svc.cluster.local") and figures out which Kubernetes Service object it corresponds to. To do this, it uses the `parseK8sServiceName` function, which splits the FQDN and—based on the length of the resulting array does one of two things:
- **Service-only:** `<svc-name>.<ns>.svc.<cluster-domain>`. It returns the service obtained from the service watcher.
- **Hostname + service:** `<pod-hostname>.<svc-name>.<ns>.svc.<cluster-domain>`. It returns both the service obtained from the service watcher and an instanceID (the pod’s name), so updates can be scoped to that specific pod if needed.

Next, it uses the informer’s Lister (cached read) to fetch the `*corev1.Service`. If it’s not found, it returns gRPC NotFound. Otherwise, now that it knows the Service, it identifies what kind of service it is:
- Federated service
- Remote-discovery service
- Local service

#### Federated Services

If the Service has either the `multicluster.linkerd.io/local-discovery` or `multicluster.linkerd.io/remote-discovery` annotation, it processes it as a federated service and subscribes to the federatedServicesWatcher. This section is going to be described in details in the realted federated watcher page. However, to give you more context, it will looks up the in‐memory “federatedService” object for the given `<namespace>/<service>`, it will split the service’s `multicluster.linkerd.io/remote-discovery="<svcA>@clusterA,<svcB>@clusterB` annotation and get the remoteWatcher, and remoteConfig from the related clusterStore. It will create and start an endpointTraslator passing the service name, port, and traslator, then Subscribe to the remoteWatcher that 
whenever the remote cluster’s endpoints change for <id.service>, remoteWatcher calls translator.Add/Remove/NoEndpoints, which enqueues a diff. The translator then sends those changes via syncStream.Send(…) down to the proxy. It will optionally do the same for the local cluster.

#### Remote Services

If the Service is labeled with `multicluster.linkerd.io/cluster-name=***`, it treats it as a remote-discovery service and calls `Get` function of the `clusterStore`, which returns:
- The `EndpointsWatcher` that manages Endpoints in the remote cluster. You subscribe to it with (ServiceID, port, hostname, listener), and it pushes endpoint‐added/removed events from that remote cluster into your translator.
- The `ClusterConfig` containing the TrustDomain and ClusterDomain. These fields were read from the Secret’s annotations when that remote cluster was added to the store. TrustDomain is the identity trust domain for mTLS in that remote cluster, and ClusterDomain is the DNS suffix (e.g. cluster.local) that Kubernetes uses in that cluster.
It then builds and starts a new EndpointTranslator using these values, and subscribe to the remote EndpointsWatcher passing the `EndpointTranslator` and the service, port, and InstaceId as references.

#### Local Services

If neither “federated” nor “remote discovery” applies, it treats the Service as a normal local Kubernetes service. It then builds an new `EndpointTranslator` pointing to the local cluster, starts it, and subscribes to it passing the `EndpointTranslator` and the service, port, and InstaceId as references.


After setting up the translator and subscription to ay of these watchers, it waits until one of these three things happens:
- The control plane is shutting down entirely (i.e. the global shutdown channel is closed).
- The proxy’s gRPC connection is canceled (e.g. the pod was killed or the network broke). It logs at DEBUG and exits.
- The translator’s internal queue overflowed (meaning it couldn’t keep up with endpoint churn). The translator then does close(streamEnd). It logs an ERROR (“stream aborted”) to signal that the stream was closed because it fell behind. The proxy is expected to reconnect and resynchronize.
After any of these three cases fires, it returns nil, which causes gRPC to complete the RPC and close the HTTP/2 stream. Because it uses defer translator.Stop() and defer s.endpoints.Unsubscribe(...), everything unhooks in the correct order.

```
func (s *server) Get(dest *pb.GetDestination, stream pb.Destination_GetServer) error {
	log := s.log
	client, _ := peer.FromContext(stream.Context())
	if client != nil {
		log = log.WithField("remote", client.Addr)
	}
	var token contextToken
	if dest.GetContextToken() != "" {
		log.Debugf("Dest token: %q", dest.GetContextToken())
		token = s.parseContextToken(dest.GetContextToken())
		log = log.WithFields(logging.Fields{"context-pod": token.Pod, "context-ns": token.Ns})
	}
	log.Debugf("Get %s", dest.GetPath())
	streamEnd := make(chan struct{})
	host, port, err := getHostAndPort(dest.GetPath())
	if err != nil {
		log.Debugf("Invalid service %s", dest.GetPath())
		return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
	}
	if ip := net.ParseIP(host); ip != nil {
		return status.Errorf(codes.InvalidArgument, "IP queries not supported by Get API: host=%s", host)
	}
	service, instanceID, err := parseK8sServiceName(host, s.config.ClusterDomain)
	if err != nil {
		log.Debugf("Invalid service %s", dest.GetPath())
		return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
	}
	svc, err := s.k8sAPI.Svc().Lister().Services(service.Namespace).Get(service.Name)
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.Debugf("Service not found %s", service)
			return status.Errorf(codes.NotFound, "Service %s.%s not found", service.Name, service.Namespace)
		}
		log.Debugf("Failed to get service %s: %v", service, err)
		return status.Errorf(codes.Internal, "Failed to get service %s", dest.GetPath())
	}
	if isFederatedService(svc) {
		remoteDiscovery := svc.Annotations[labels.RemoteDiscoveryAnnotation]
		localDiscovery := svc.Annotations[labels.LocalDiscoveryAnnotation]
		log.Debugf("Federated service discovery, remote:[%s] local:[%s]", remoteDiscovery, localDiscovery)
		err := s.federatedServices.Subscribe(svc.Name, svc.Namespace, port, token.NodeName, instanceID, stream, streamEnd)
		if err != nil {
			log.Errorf("Failed to subscribe to federated service %q: %s", dest.GetPath(), err)
			return err
		}
		defer s.federatedServices.Unsubscribe(svc.Name, svc.Namespace, stream)
	} else if cluster, found := svc.Labels[labels.RemoteDiscoveryLabel]; found {
		log.Debug("Remote discovery service detected")
		remoteSvc, found := svc.Labels[labels.RemoteServiceLabel]
		if !found {
			log.Debugf("Remote discovery service missing remote service name %s", service)
			return status.Errorf(codes.FailedPrecondition, "Remote discovery service missing remote service name %s", dest.GetPath())
		}
		remoteWatcher, remoteConfig, found := s.clusterStore.Get(cluster)
		if !found {
			log.Errorf("Failed to get remote cluster %s", cluster)
			return status.Errorf(codes.NotFound, "Remote cluster not found: %s", cluster)
		}
		translator := newEndpointTranslator(
			s.config.ControllerNS,
			remoteConfig.TrustDomain,
			s.config.ForceOpaqueTransport,
			s.config.EnableH2Upgrade,
			false, // Disable endpoint filtering for remote discovery.
			s.config.EnableIPv6,
			s.config.ExtEndpointZoneWeights,
			s.config.MeshedHttp2ClientParams,
			fmt.Sprintf("%s.%s.svc.%s:%d", remoteSvc, service.Namespace, remoteConfig.ClusterDomain, port),
			token.NodeName,
			s.config.DefaultOpaquePorts,
			s.metadataAPI,
			stream,
			streamEnd,
			log,
		)
		translator.Start()
		defer translator.Stop()
		err = remoteWatcher.Subscribe(watcher.ServiceID{Namespace: service.Namespace, Name: remoteSvc}, port, instanceID, translator)
		if err != nil {
			var ise watcher.InvalidService
			if errors.As(err, &ise) {
				log.Debugf("Invalid remote discovery service %s", dest.GetPath())
				return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
			}
			log.Errorf("Failed to subscribe to remote discovery service %q in cluster %s: %s", dest.GetPath(), cluster, err)
			return err
		}
		defer remoteWatcher.Unsubscribe(watcher.ServiceID{Namespace: service.Namespace, Name: remoteSvc}, port, instanceID, translator)
	} else {
		log.Debug("Local discovery service detected")
		translator := newEndpointTranslator(
			s.config.ControllerNS,
			s.config.IdentityTrustDomain,
			s.config.ForceOpaqueTransport,
			s.config.EnableH2Upgrade,
			true,
			s.config.EnableIPv6,
			s.config.ExtEndpointZoneWeights,
			s.config.MeshedHttp2ClientParams,
			dest.GetPath(),
			token.NodeName,
			s.config.DefaultOpaquePorts,
			s.metadataAPI,
			stream,
			streamEnd,
			log,
		)
		translator.Start()
		defer translator.Stop()
		err = s.endpoints.Subscribe(service, port, instanceID, translator)
		if err != nil {
			var ise watcher.InvalidService
			if errors.As(err, &ise) {
				log.Debugf("Invalid service %s", dest.GetPath())
				return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
			}
			log.Errorf("Failed to subscribe to %s: %s", dest.GetPath(), err)
			return err
		}
		defer s.endpoints.Unsubscribe(service, port, instanceID, translator)
	}
	select {
	case <-s.shutdown:
	case <-stream.Context().Done():
		log.Debugf("Get %s cancelled", dest.GetPath())
	case <-streamEnd:
		log.Errorf("Get %s stream aborted", dest.GetPath())
	}
	return nil
}
```

If we inspect the logs we will be able to see references to these behaviors. The following is an example of local service.

```
time="2025-06-06T06:11:39Z" level=debug msg="Get simple-app-v1.simple-app.svc.cluster.local:80" addr=":8086" component=server context-ns=simple-app context-pod=traffic-5cf984699d-rvcrz remote="10.23.0.30:45616"
time="2025-06-06T06:11:39Z" level=debug msg="Local discovery service detected" addr=":8086" component=server context-ns=simple-app context-pod=traffic-5cf984699d-rvcrz remote="10.23.0.30:45616"
time="2025-06-06T06:11:39Z" level=debug msg="Hints not available on endpointslice. Zone Filtering disabled. Falling back to routing to all pods" addr=":8086" component=endpoint-translator context-ns=simple-app context-pod=traffic-5cf984699d-rvcrz remote="10.23.0.30:45616" service="simple-app-v1.simple-app.svc.cluster.local:80"
time="2025-06-06T06:11:39Z" level=debug msg="Sending destination add: add:{addrs:{addr:{ip:{ipv4:169279523} port:5678} weight:10000 metric_labels:{key:\"control_plane_ns\" value:\"linkerd\"} metric_labels:{key:\"deployment\" value:\"simple-app-v1\"} metric_labels:{key:\"pod\" value:\"simple-app-v1-57b57f8947-b6bpd\"} metric_labels:{key:\"pod_template_hash\" value:\"57b57f8947\"} metric_labels:{key:\"serviceaccount\" value:\"default\"} metric_labels:{key:\"zone\" value:\"\"} metric_labels:{key:\"zone_locality\" value:\"unknown\"} tls_identity:{dns_like_identity:{name:\"default.simple-app.serviceaccount.identity.linkerd.cluster.local\"} server_name:{name:\"default.simple-app.serviceaccount.identity.linkerd.cluster.local\"}} protocol_hint:{h2:{}}} metric_labels:{key:\"namespace\" value:\"simple-app\"} metric_labels:{key:\"service\" value:\"simple-app-v1\"}}" addr=":8086" component=endpoint-translator context-ns=simple-app context-pod=traffic-5cf984699d-rvcrz remote="10.23.0.30:45616" service="simple-app-v1.simple-app.svc.cluster.local:80"
```

### Get Profile Endpoint

```
func (s *server) GetProfile(dest *pb.GetDestination, stream pb.Destination_GetProfileServer) error {
	log := s.log
	client, _ := peer.FromContext(stream.Context())
	if client != nil {
		log = log.WithField("remote", client.Addr)
	}
	var token contextToken
	if dest.GetContextToken() != "" {
		log.Debugf("Dest token: %q", dest.GetContextToken())
		token = s.parseContextToken(dest.GetContextToken())
		log = log.WithFields(logging.Fields{"context-pod": token.Pod, "context-ns": token.Ns})
	}
	log.Debugf("Getting profile for %s", dest.GetPath())
	host, port, err := getHostAndPort(dest.GetPath())
	if err != nil {
		log.Debugf("Invalid address %q", dest.GetPath())
		return status.Errorf(codes.InvalidArgument, "invalid authority: %q: %q", dest.GetPath(), err)
	}
	if ip := net.ParseIP(host); ip != nil {
		err = s.getProfileByIP(token, ip, port, log, stream)
		if err != nil {
			var ise watcher.InvalidService
			if errors.As(err, &ise) {
				log.Debugf("Invalid service %s", dest.GetPath())
				return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
			}
			log.Errorf("Failed to subscribe to profile by ip %q: %q", dest.GetPath(), err)
		}
		return err
	}
	err = s.getProfileByName(token, host, port, log, stream)
	if err != nil {
		var ise watcher.InvalidService
		if errors.As(err, &ise) {
			log.Debugf("Invalid service %s", dest.GetPath())
			return status.Errorf(codes.InvalidArgument, "Invalid authority: %s", dest.GetPath())
		}
		log.Errorf("Failed to subscribe to profile by name %q: %q", dest.GetPath(), err)
	}
	return err
}
```

## Metrics

The destination controller will exponse an extensive quantity of metrics that can be summarized by sending a GET request to the `/metrics` endpoint of the port `9996`.

```
kubectl -n linkerd port-forward deploy/linkerd-destination 9996
curl -s http://localhost:9996/metrics
```




```
# HELP cluster_store_size The number of linked clusters in the remote discovery cluster store
# TYPE cluster_store_size gauge
cluster_store_size 0



# HELP grpc_server_handled_total Total number of RPCs completed on the server, regardless of success or failure.
# TYPE grpc_server_handled_total counter
grpc_server_handled_total{grpc_code="OK",grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 318
grpc_server_handled_total{grpc_code="OK",grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 318

# HELP grpc_server_handling_seconds Histogram of response latency (seconds) of gRPC that had been application-level handled by the server.
# TYPE grpc_server_handling_seconds histogram
grpc_server_handling_seconds_bucket{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream",le="0.005"} 0
...
grpc_server_handling_seconds_sum{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 8135.809845959998
grpc_server_handling_seconds_count{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 318
grpc_server_handling_seconds_bucket{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream",le="0.005"} 0
... 
grpc_server_handling_seconds_sum{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 9666.61187774301
grpc_server_handling_seconds_count{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 318

# HELP grpc_server_msg_received_total Total number of RPC stream messages received on the server.
# TYPE grpc_server_msg_received_total counter
grpc_server_msg_received_total{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 325
grpc_server_msg_received_total{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 328

# HELP grpc_server_msg_sent_total Total number of gRPC stream messages sent by the server.
# TYPE grpc_server_msg_sent_total counter
grpc_server_msg_sent_total{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 319
grpc_server_msg_sent_total{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 328

# HELP grpc_server_started_total Total number of RPCs started on the server.
# TYPE grpc_server_started_total counter
grpc_server_started_total{grpc_method="Get",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 325
grpc_server_started_total{grpc_method="GetProfile",grpc_service="io.linkerd.proxy.destination.Destination",grpc_type="server_stream"} 328

# HELP http_client_burst Burst used for the client config.
# TYPE http_client_burst gauge
http_client_burst{client="k8s"} 10

# HELP http_client_in_flight_requests A gauge of in-flight requests for the wrapped client.
# TYPE http_client_in_flight_requests gauge
http_client_in_flight_requests{client="k8s"} 0
http_client_in_flight_requests{client="l5dCrd"} 0

# HELP http_client_qps Max QPS used for the client config.
# TYPE http_client_qps gauge
http_client_qps{client="k8s"} 5

# HELP http_client_request_latency_seconds A histogram of request latencies.
# TYPE http_client_request_latency_seconds histogram
http_client_request_latency_seconds_bucket{client="k8s",code="200",method="get",le="0.01"} 53
...
http_client_request_latency_seconds_sum{client="k8s",code="200",method="get"} 0.06556754500000002
http_client_request_latency_seconds_count{client="k8s",code="200",method="get"} 53
http_client_request_latency_seconds_bucket{client="k8s",code="200",method="put",le="0.01"} 855
...
http_client_request_latency_seconds_sum{client="k8s",code="200",method="put"} 4.401309381000001
http_client_request_latency_seconds_count{client="k8s",code="200",method="put"} 868
http_client_request_latency_seconds_bucket{client="k8s",code="201",method="post",le="0.01"} 3
...
http_client_request_latency_seconds_sum{client="k8s",code="201",method="post"} 0.003263582
http_client_request_latency_seconds_count{client="k8s",code="201",method="post"} 3
http_client_request_latency_seconds_bucket{client="k8s",code="404",method="get",le="0.01"} 1
...
http_client_request_latency_seconds_sum{client="k8s",code="404",method="get"} 0.001214416
http_client_request_latency_seconds_count{client="k8s",code="404",method="get"} 1
http_client_request_latency_seconds_bucket{client="l5dCrd",code="200",method="get",le="0.01"} 18
...
http_client_request_latency_seconds_sum{client="l5dCrd",code="200",method="get"} 0.023537168000000004
http_client_request_latency_seconds_count{client="l5dCrd",code="200",method="get"} 18

# HELP http_client_requests_total A counter for requests from the wrapped client.
# TYPE http_client_requests_total counter
http_client_requests_total{client="k8s",code="200",method="get"} 53
http_client_requests_total{client="k8s",code="200",method="put"} 868
http_client_requests_total{client="k8s",code="201",method="post"} 3
http_client_requests_total{client="k8s",code="404",method="get"} 1
http_client_requests_total{client="l5dCrd",code="200",method="get"} 18

# HELP workqueue_adds_total Total number of adds handled by workqueue
# TYPE workqueue_adds_total counter
workqueue_adds_total{name="endpoints_controller_workqueue"} 48

# HELP workqueue_depth Current depth of workqueue
# TYPE workqueue_depth gauge
workqueue_depth{name="endpoints_controller_workqueue"} 0

# HELP workqueue_drops_total Total number of dropped items from the queue due to exceeding retry threshold
# TYPE workqueue_drops_total counter
workqueue_drops_total{name="endpoints_controller_workqueue"} 0

# HELP workqueue_longest_running_processor_seconds How many seconds has the longest running processor for workqueue been running.
# TYPE workqueue_longest_running_processor_seconds gauge
workqueue_longest_running_processor_seconds{name="endpoints_controller_workqueue"} 0

# HELP workqueue_queue_duration_seconds How long in seconds an item stays in workqueue before being requested.
# TYPE workqueue_queue_duration_seconds histogram
workqueue_queue_duration_seconds_bucket{name="endpoints_controller_workqueue",le="1e-08"} 0
...
workqueue_queue_duration_seconds_sum{name="endpoints_controller_workqueue"} 0.011922585000000001
workqueue_queue_duration_seconds_count{name="endpoints_controller_workqueue"} 48

# HELP workqueue_retries_total Total number of retries handled by workqueue
# TYPE workqueue_retries_total counter
workqueue_retries_total{name="endpoints_controller_workqueue"} 0

# HELP workqueue_unfinished_work_seconds How many seconds of work has done that is in progress and hasn't been observed by work_duration. Large values indicate stuck threads. One can deduce the number of stuck threads by observing the rate at which this increases.
# TYPE workqueue_unfinished_work_seconds gauge
workqueue_unfinished_work_seconds{name="endpoints_controller_workqueue"} 0

# HELP workqueue_work_duration_seconds How long in seconds processing an item from workqueue takes.
# TYPE workqueue_work_duration_seconds histogram
workqueue_work_duration_seconds_bucket{name="endpoints_controller_workqueue",le="1e-08"} 0
...
workqueue_work_duration_seconds_sum{name="endpoints_controller_workqueue"} 0.002472292
workqueue_work_duration_seconds_count{name="endpoints_controller_workqueue"} 48
```








The destination controller will emit metrics related to each informer with a gauge named `<kind>_cache_size` that reports the current number of items in that informer’s cache.

```
# HELP endpoints_cache_size Number of items in the client-go endpoints cache
# TYPE endpoints_cache_size gauge
endpoints_cache_size{cluster="local"} 26

# HELP job_cache_size Number of items in the client-go job cache
# TYPE job_cache_size gauge
job_cache_size{cluster="local"} 0

# HELP node_cache_size Number of items in the client-go node cache
# TYPE node_cache_size gauge
node_cache_size{cluster="local"} 4

# HELP pod_cache_size Number of items in the client-go pod cache
# TYPE pod_cache_size gauge
pod_cache_size{cluster="local"} 24

# HELP replicaset_cache_size Number of items in the client-go replicaset cache
# TYPE replicaset_cache_size gauge
replicaset_cache_size{cluster="local"} 24

# HELP server_cache_size Number of items in the client-go server cache
# TYPE server_cache_size gauge
server_cache_size{cluster="local"} 0

# HELP service_cache_size Number of items in the client-go service cache
# TYPE service_cache_size gauge
service_cache_size{cluster="local"} 26

# HELP serviceprofile_cache_size Number of items in the client-go serviceprofile cache
# TYPE serviceprofile_cache_size gauge
serviceprofile_cache_size{cluster="local"} 0
```

![Destination Cache Metrics](/control-plane/destination_cache_metrics.png)


The watchers will also expose metrics related to the lag (in seconds) between the last update to a specific object and its processing by the informer with a gauge named `<kind>_informer_lag_seconds`.

```
# HELP endpoints_informer_lag_seconds The amount of time between when an Endpoints resource is updated and when an informer observes it
# TYPE endpoints_informer_lag_seconds histogram
endpoints_informer_lag_seconds_bucket{le="0.5"} 0
...
endpoints_informer_lag_seconds_sum 0
endpoints_informer_lag_seconds_count 0

# HELP endpointslices_informer_lag_seconds The amount of time between when an EndpointSlice resource is updated and when an informer observes it
# TYPE endpointslices_informer_lag_seconds histogram
endpointslices_informer_lag_seconds_bucket{le="0.5"} 4
...
endpointslices_informer_lag_seconds_sum 30.301216474000004
endpointslices_informer_lag_seconds_count 42

# HELP externalworkload_cache_size Number of items in the client-go externalworkload cache
# TYPE externalworkload_cache_size gauge
externalworkload_cache_size{cluster="local"} 0

# HELP externalworkload_informer_lag_seconds The amount of time between when an ExternalWorkload resource is updated and when an informer observes it
# TYPE externalworkload_informer_lag_seconds histogram
externalworkload_informer_lag_seconds_bucket{le="0.5"} 0
...
externalworkload_informer_lag_seconds_sum 0
externalworkload_informer_lag_seconds_count 0

# HELP pods_informer_lag_seconds The amount of time between when a Pod resource is updated and when an informer observes it
# TYPE pods_informer_lag_seconds histogram
pods_informer_lag_seconds_bucket{le="0.5"} 6
...
pods_informer_lag_seconds_sum 41.22129725400001
pods_informer_lag_seconds_count 56

# HELP servers_informer_lag_seconds The amount of time between when a Server resource is updated and when an informer observes it
# TYPE servers_informer_lag_seconds histogram
servers_informer_lag_seconds_bucket{le="0.5"} 0
...
servers_informer_lag_seconds_sum 0
servers_informer_lag_seconds_count 0
```

![Destination Cache Metrics](/control-plane/destination_lag_metrics.png)


Linkerd Controllers share the usage of the `/prometheus/client_golang/prometheus/promhttp` module that will allow them to expose metrics related to he Go runtime metrics.

```
# HELP go_gc_duration_seconds A summary of the wall-time pause (stop-the-world) duration in garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 3.1001e-05
go_gc_duration_seconds_sum 0.007744916
go_gc_duration_seconds_count 24

# HELP go_gc_gogc_percent Heap size target percentage configured by the user, otherwise 100. This value is set by the GOGC environment variable, and the runtime/debug.SetGCPercent function. Sourced from /gc/gogc:percent
# TYPE go_gc_gogc_percent gauge
go_gc_gogc_percent 100

# HELP go_gc_gomemlimit_bytes Go runtime memory limit configured by the user, otherwise math.MaxInt64. This value is set by the GOMEMLIMIT environment variable, and the runtime/debug.SetMemoryLimit function. Sourced from /gc/gomemlimit:bytes
# TYPE go_gc_gomemlimit_bytes gauge
go_gc_gomemlimit_bytes 9.223372036854776e+18

# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 187

# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.23.5"} 1

# HELP go_memstats_alloc_bytes Number of bytes allocated in heap and currently in use. Equals to /memory/classes/heap/objects:bytes.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 1.6198776e+07

# HELP go_memstats_alloc_bytes_total Total number of bytes allocated in heap until now, even if released already. Equals to /gc/heap/allocs:bytes.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 1.56505128e+08

# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table. Equals to /memory/classes/profiling/buckets:bytes.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.515081e+06

# HELP go_memstats_frees_total Total number of heap objects frees. Equals to /gc/heap/frees:objects + /gc/heap/tiny/allocs:objects.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 1.366899e+06

# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata. Equals to /memory/classes/metadata/other:bytes.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 4.032768e+06

# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and currently in use, same as go_memstats_alloc_bytes. Equals to /memory/classes/heap/objects:bytes.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 1.6198776e+07

# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used. Equals to /memory/classes/heap/released:bytes + /memory/classes/heap/free:bytes.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 9.633792e+06

# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use. Equals to /memory/classes/heap/objects:bytes + /memory/classes/heap/unused:bytes
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 2.1397504e+07

# HELP go_memstats_heap_objects Number of currently allocated objects. Equals to /gc/heap/objects:objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 82595

# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS. Equals to /memory/classes/heap/released:bytes.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 8.372224e+06

# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system. Equals to /memory/classes/heap/objects:bytes + /memory/classes/heap/unused:bytes + /memory/classes/heap/released:bytes + /memory/classes/heap/free:bytes.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 3.1031296e+07

# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.749141896403e+09

# HELP go_memstats_mallocs_total Total number of heap objects allocated, both live and gc-ed. Semantically a counter version for go_memstats_heap_objects gauge. Equals to /gc/heap/allocs:objects + /gc/heap/tiny/allocs:objects.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 1.449494e+06

# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures. Equals to /memory/classes/metadata/mcache/inuse:bytes.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 16800

# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system. Equals to /memory/classes/metadata/mcache/inuse:bytes + /memory/classes/metadata/mcache/free:bytes.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 31200

# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures. Equals to /memory/classes/metadata/mspan/inuse:bytes.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 324640

# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system. Equals to /memory/classes/metadata/mspan/inuse:bytes + /memory/classes/metadata/mspan/free:bytes.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 359040

# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place. Equals to /gc/heap/goal:bytes.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 2.2538656e+07

# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations. Equals to /memory/classes/other:bytes.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 1.325407e+06

# HELP go_memstats_stack_inuse_bytes Number of bytes obtained from system for stack allocator in non-CGO environments. Equals to /memory/classes/heap/stacks:bytes.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 2.424832e+06

# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator. Equals to /memory/classes/heap/stacks:bytes + /memory/classes/os-stacks:bytes.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 2.424832e+06

# HELP go_memstats_sys_bytes Number of bytes obtained from system. Equals to /memory/classes/total:byte.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 4.0719624e+07

# HELP go_sched_gomaxprocs_threads The current runtime.GOMAXPROCS setting, or the number of operating system threads that can execute user-level Go code simultaneously. Sourced from /sched/gomaxprocs:threads
# TYPE go_sched_gomaxprocs_threads gauge
go_sched_gomaxprocs_threads 14

# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 14

# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 4.15

# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 65536

# HELP process_network_receive_bytes_total Number of bytes received by the process over the network.
# TYPE process_network_receive_bytes_total counter
process_network_receive_bytes_total 1.1785203e+07

# HELP process_network_transmit_bytes_total Number of bytes sent by the process over the network.
# TYPE process_network_transmit_bytes_total counter
process_network_transmit_bytes_total 1.2693481e+07

# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 18

# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 7.45472e+07

# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.7491402229e+09

# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 5.612982272e+09

# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19

# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1

# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 170
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
```

![Destination Go Metrics](/control-plane/destination_go_metrics.png)


## References

- Entrypoint: https://github.com/linkerd/linkerd2/blob/main/controller/cmd/destination/main.go

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
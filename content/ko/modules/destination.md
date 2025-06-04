+++
author = "Ivan Porta"
title = "컨트롤 플레인"
date = "2025-06-01"
description = "Linkerd의 Destination 컨트롤러에 대한 심층 분석—인포머를 어떻게 활용하고 EndpointSlice를 감시하며 리더 선출을 수행해 Kubernetes에서 서비스 디스커버리를 제공하는지."
tags = [
  "linkerd",
  "control-plane",
  "destination",
  "kubernetes",
  "deep-dive"
]
+++

# Destination

Linkerd 제어 플레인의 Destination 컨트롤러는 서비스 디스커버리와 라우팅을 담당합니다. 이 컨트롤러는 Kubernetes 리소스(Services, EndpointSlices, Pods, ExternalWorkloads 등)를 공유 인포머(shared informers)를 통해 감시하고, 엔드포인트의 로컬 캐시를 구축하며, 데이터 플레인 프록시로부터의 gRPC 요청을 제공합니다.

# 사전 준비

- macOS/Linux/Windows에서 유닉스 스타일 셸 사용 가능
- 로컬 Kubernetes 클러스터용 k3d (v5+) 설치
- kubectl (v1.25+) 설치
- Helm (v3+) 설치
- 인증서 생성을 위한 Smallstep (step) CLI

# 튜토리얼

## 1. 설정 파일 생성

```bash
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

## 2. 로컬 Kubernetes 클러스터 생성

k3d와 앞서 만든 cluster.yaml을 사용하여 경량 Kubernetes 클러스터를 시작합니다:

```
k3d cluster create --kubeconfig-update-default \
  -c ./cluster.yaml
```

## 3. 인증서 생성

Linkerd는 mTLS 식별을 위해 트러스트 앵커(root CA)와 발급자(intermediate CA)가 필요합니다.

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
  linkerd-edge/linkerd-control-plane
```

## 5. Linkerd Destination

### Kubernetes API와의 상호작용

Destination이 시작되면, `k8s.io/client-go` Go 모듈을 사용하여 관심 있는 모든 리소스 종류(CronJobs, Pods, Services 등)에 대해 하나의 공유 인포머(shared informer)를 생성하고, API 구조체에 해당 핸들을 저장하며, 각 인포머가 동기화되었는지 확인하는 체크(HasSynced)를 기록하고, 현재 캐시의 키 개수를 나타내는 Prometheus 게이지를 등록합니다.

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

`Sync` 함수가 호출되면, 각 인포머는 초기 스냅샷을 가져오기 위해 API 서버에 요청하고, 이후 변경 이벤트를 실시간으로 수신하기 위해 장기 워치 스트림(`watch=0`)을 엽니다. `ResyncTime = 10 * time.Minute`으로 정의된 10분 동안 이벤트가 도착하지 않으면, Kubernetes API 서버에 전체 스냅샷 재요청을 보냅니다.

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

각 인포머는 Kubernetes API 서버에서 반환된 데이터를 저장하는 스레드 안전한 로컬 캐시를 소유합니다.

인포머 자체만으로는 캐시가 업데이트될 때 비즈니스 로직에 알림을 보내지 않으며, 단지 로컬 캐시를 채우고 이를 쿼리할 수 있게 합니다. 그래서 컨트롤러 소스 코드에는 관련 인포머 위에 여러 워처(watcher)가 있으며, 인포머에 이벤트 핸들러(event handlers)를 등록하여 캐시가 업데이트될 때 실제로 알림을 받도록 구현되어 있습니다.

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

알림을 받으면, 동작에 따라 새 버전과 이전 버전 사이의 차분(diff)을 생성하고, 리스너(listener)에게 증분 변경만 전달하여 업데이트를 반영합니다.

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

관련 로그 메시지를 확인할 수 있습니다:

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

EndpointSlice와 Endpoints도 마찬가지로 처리됩니다. 중요한 점은 `ew.enableEndpointSlices` 값을 기준으로 둘 중 하나만 감시한다는 것입니다. 이 값은 컨테이너의 매개변수 `-enable-endpoint-slices`로 전달되며, 기본값은 true입니다.

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

관련 로그:

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

### 외부 워크로드(External Workloads)

Linkerd의 Destination 서브시스템은 클러스터 외부에서 실행되는 워크로드를 나타내는 ExternalWorkload 리소스를 관리합니다. 일반적인 Pod과 달리 내부 IP가 Kubernetes 리소스에 존재하지 않으므로, 워크로드 IP는 ExternalWorkload.spec.workloadIPs 필드에 정의되어 있습니다.

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

`ExternalWorkload`가 생성, 업데이트, 삭제될 때 Linkerd 컨트롤러는 해당 리소스를 감시하기 위해 인포머를 설정하고, 핸들러의 관련 함수(add, update, delete)를 호출합니다.

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

어떤 Service에 특정 `ExternalWorkload`를 포함시켜야 하는지 결정하기 위해, 컨트롤러는 레이블 셀렉터(label-selector) 매칭을 사용하여 `<namespace>/<service-name>` 목록을 생성합니다. 이를 통해 어떤 Service를 다시 동기화해야 하는지 알 수 있습니다.

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

`ExternalWorkload`가 업데이트되면 IP와 레이블 모두를 재평가하며, 실제로 변경이 발생했을 때만 영향을 받는 Service들을 다시 큐(queue)에 넣습니다.

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

Service가 큐에 추가되면, 백그라운드 워커가 하나씩 처리합니다.

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

`s‍yncService` 메서드는 서비스의 타입이 `ExternalName`이 아닌 경우에만 `ExternalWorkload` CR에서 가져온 IP와 일치하도록 EndpointSlice 객체 세트를 보장합니다. Service의 셀렉터가 없으면 아무런 작업도 수행하지 않습니다.

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

마지막으로, 정확히 생성·업데이트·삭제해야 할 EndpointSlice 객체를 계산하고 Kubernetes에 반영합니다.

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

어떤 슬라이스를 생성(Create), 업데이트(Update), 삭제(Delete)해야 할지 알게 되면, 해당 변경 사항을 Kubernetes에 푸시합니다.

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

Destination 컨트롤러 복제본이 여러 개 실행될 수 있으므로, 여러 인스턴스 중 오직 하나만 EndpointSlice 객체를 쓰도록 리더 선출 패턴을 사용합니다. Kubernetes Lease 객체를 사용하여 다음과 같은 설정으로 리더십을 조율합니다.

```
ec.lec = leaderelection.LeaderElectionConfig{
    Lock: &resourcelock.LeaseLock{
        LeaseMeta: metav1.ObjectMeta{
            Name:      "linkerd-destination-endpoint-write",
            Namespace: controllerNs,
        },
        Client: k8sAPI.Client.CoordinationV1(),
        LockConfig: resourcelock.ResourceLockConfig{
            Identity: hostname,  // 인스턴스마다 고유한 ID
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

리더가 주기적으로 갱신을 계속하는 동안 ExternalWorkload 변경 사항을 계속 리컨실(reconcile)하며, 리더가 실패하면 다른 복제본이 리더가 되어 쓰기 작업을 이어받습니다. 다음과 같은 주기적인 갱신 로그를 확인할 수 있습니다:

```
time="2025-05-19T08:53:23Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 2 milliseconds"
...
time="2025-05-19T08:53:25Z" level=info msg="PUT https://10.247.0.1:443/apis/coordination.k8s.io/v1/namespaces/linkerd/leases/linkerd-destination-endpoint-write 200 OK in 6 milliseconds"
```

## 참고 문헌

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
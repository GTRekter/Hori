### Endpoints Watcher

THe Endpoints Watcher is in charge of handling changes to Services, EndpointSlices, and Endpoints. It's important to understant that it won't watch both of Ednpoint and EndpointSlice. Depending on `ew.enableEndpointSlices` it will watch one or the other. This value is received as parameter from the container `-enable-endpoint-slices` and by default is set to `true`.

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

Once notified, depending on the action, will create a differential between the new and old version, and then update the listerers so that see only the incremental change. 

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

The same will happen for EndpointSlices and Endpoints. 

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

The endpoint watcher will also emit metrics about the crud opearations related to the endpoints

```
# HELP endpoint_profile_updates_queue_overflow A counter incremented whenever the endpoint profile updates queue overflows
# TYPE endpoint_profile_updates_queue_overflow counter
endpoint_profile_updates_queue_overflow 0

# HELP endpoint_updates_queue_overflow A counter incremented whenever the endpoint updates queue overflows
# TYPE endpoint_updates_queue_overflow counter
endpoint_updates_queue_overflow{service="linkerd-enterprise.linkerd.svc.cluster.local:8082"} 0
endpoint_updates_queue_overflow{service="prometheus-server.monitoring.svc.cluster.local:80"} 0
endpoint_updates_queue_overflow{service="prometheus-server.monitoring.svc.cluster.local:9090"} 0
endpoint_updates_queue_overflow{service="simple-app-v1.simple-app.svc.cluster.local:80"} 0

# HELP endpoints_exists A gauge which is 1 if the endpoints exists and 0 if it does not.
# TYPE endpoints_exists gauge
endpoints_exists{cluster="local",hostname="",namespace="linkerd",port="8082",service="linkerd-enterprise"} 1
endpoints_exists{cluster="local",hostname="",namespace="monitoring",port="9090",service="prometheus-server"} 1
endpoints_exists{cluster="local",hostname="",namespace="simple-app",port="80",service="simple-app-v1"} 1

# HELP endpoints_pods A gauge for the current number of pods in a endpoints.
# TYPE endpoints_pods gauge
endpoints_pods{cluster="local",hostname="",namespace="linkerd",port="8082",service="linkerd-enterprise"} 1
endpoints_pods{cluster="local",hostname="",namespace="monitoring",port="9090",service="prometheus-server"} 1
endpoints_pods{cluster="local",hostname="",namespace="simple-app",port="80",service="simple-app-v1"} 1

# HELP endpoints_subscribers A gauge for the current number of subscribers to a endpoints.
# TYPE endpoints_subscribers gauge
endpoints_subscribers{cluster="local",hostname="",namespace="linkerd",port="8082",service="linkerd-enterprise"} 5
endpoints_subscribers{cluster="local",hostname="",namespace="monitoring",port="9090",service="prometheus-server"} 1
endpoints_subscribers{cluster="local",hostname="",namespace="simple-app",port="80",service="simple-app-v1"} 1

# HELP endpoints_updates A counter for number of updates to a endpoints.
# TYPE endpoints_updates counter
endpoints_updates{cluster="local",hostname="",namespace="linkerd",port="8082",service="linkerd-enterprise"} 3
endpoints_updates{cluster="local",hostname="",namespace="monitoring",port="9090",service="prometheus-server"} 1
endpoints_updates{cluster="local",hostname="",namespace="simple-app",port="80",service="simple-app-v1"} 1
```

![Destination Endpoint Watcher Metrics](/control-plane/destination_endpoints_metrics.png)
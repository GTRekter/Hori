# Profiles

The Profile Watcher is responsible for monitoring `ServiceProfile` custom resources in the cluster. It triggers updates to subscribed listeners whenever a profile is added, updated, or deleted. This enables dynamic service behavior such as retries, timeouts, and routing logic to be applied to Linkerd proxies without restarting them.

```
func NewProfileWatcher(k8sAPI *k8s.API, log *logging.Entry) (*ProfileWatcher, error) {
	watcher := &ProfileWatcher{
		profileLister: k8sAPI.SP().Lister(),
		profiles:      make(map[ProfileID]*profilePublisher),
		log:           log.WithField("component", "profile-watcher"),
	}
	_, err := k8sAPI.SP().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    watcher.addProfile,
			UpdateFunc: watcher.updateProfile,
			DeleteFunc: watcher.deleteProfile,
		},
	)
	if err != nil {
		return nil, err
	}
	return watcher, nil
}
```

Each time a `ServiceProfile` is modified, the change is forwarded to its associated profilePublisher, which then propagates updates to all its subscribers:

```
func (pp *profilePublisher) subscribe(listener ProfileUpdateListener) {
	pp.Lock()
	defer pp.Unlock()
	pp.listeners = append(pp.listeners, listener)
	listener.Update(pp.profile)
	pp.profileMetrics.setSubscribers(len(pp.listeners))
}
```

The subscriber will immediately receive the latest profile (if available), and will continue to receive updates on future changes via the `Update(profile *sp.ServiceProfile)` method.

```
kubectl logs -n linkerd       linkerd-destination-6468fd7dbb-8st99 -c destination 
...
time="2025-06-05T19:01:52Z" level=debug msg="Establishing watch on profile simple-app/simple-app-v1.simple-app.svc.cluster.local" addr=":8086" component=profile-watcher
time="2025-06-05T19:01:52Z" level=debug msg="Sending profile update: fully_qualified_name:\"simple-app-v1.simple-app.svc.cluster.local\" retry_budget:{retry_ratio:0.2 min_retries_per_second:10 ttl:{seconds:10}} parent_ref:{resource:{group:\"core\" kind:\"Service\" name:\"simple-app-v1\" namespace:\"simple-app\" port:80}} profile_ref:{resource:{group:\"linkerd.io\"}}" addr=":8086" component=profile-translator context-ns=simple-app context-pod=traffic-56cb8b47b8-rtn6v ns=simple-app port=80 remote="10.23.0.9:45792" svc=simple-app-v1
time="2025-06-05T19:01:51Z" level=debug msg="Stopping watch on profile simple-app/simple-app-v1.simple-app.svc.cluster.local" addr=":8086" component=profile-watcher
```

When a new profile is added or updated, the `update(profile *sp.ServiceProfile)` method is called on each listener. 

```
func (pt *profileTranslator) update(profile *sp.ServiceProfile) {
	if profile == nil {
		pt.stream.Send(pt.defaultServiceProfile())
		return
	}
	destinationProfile, err := pt.createDestinationProfile(profile)
	if err != nil {
		pt.log.Error(err)
		return
	}
	pt.stream.Send(destinationProfile)
}
```

The update includes the routes, retry budget, and destination overrides specified in the profile. If no profile is found, it synthesizes a default profile on-the-fly like this:

```
func (pt *profileTranslator) defaultServiceProfile() *pb.DestinationProfile {
	return &pb.DestinationProfile{
		Routes:             []*pb.Route{},
		RetryBudget:        defaultRetryBudget(),
		FullyQualifiedName: pt.fullyQualifiedName,
	}
}
```

## Metrics

The Profile Watcher will also expose metrics used to track the number of subscribers to service profiles.

```
# HELP profile_subscribers A gauge for the current number of subscribers to a profile.
# TYPE profile_subscribers gauge
profile_subscribers{namespace="linkerd",profile="linkerd-dst-headless.linkerd.svc.cluster.local"} 2
profile_subscribers{namespace="linkerd",profile="linkerd-enterprise.linkerd.svc.cluster.local"} 10
profile_subscribers{namespace="linkerd",profile="linkerd-identity-headless.linkerd.svc.cluster.local"} 0
profile_subscribers{namespace="linkerd",profile="linkerd-policy.linkerd.svc.cluster.local"} 2
profile_subscribers{namespace="monitoring",profile="prometheus-server.monitoring.svc.cluster.local"} 2
profile_subscribers{namespace="simple-app",profile="simple-app-v1.simple-app.svc.cluster.local"} 4

# HELP profile_updates A counter for number of updates to a profile.
# TYPE profile_updates counter
profile_updates{namespace="linkerd",profile="linkerd-dst-headless.linkerd.svc.cluster.local"} 0
profile_updates{namespace="linkerd",profile="linkerd-enterprise.linkerd.svc.cluster.local"} 0
profile_updates{namespace="linkerd",profile="linkerd-identity-headless.linkerd.svc.cluster.local"} 0
profile_updates{namespace="linkerd",profile="linkerd-policy.linkerd.svc.cluster.local"} 0
profile_updates{namespace="monitoring",profile="prometheus-server.monitoring.svc.cluster.local"} 0
profile_updates{namespace="simple-app",profile="simple-app-v1.simple-app.svc.cluster.local"} 0

# HELP profile_updates_queue_overflow A counter incremented whenever the profile updates queue overflows
# TYPE profile_updates_queue_overflow counter
profile_updates_queue_overflow{fqn="linkerd-dst-headless.linkerd.svc.cluster.local",port="8086"} 0
profile_updates_queue_overflow{fqn="linkerd-enterprise.linkerd.svc.cluster.local",port="8082"} 0
profile_updates_queue_overflow{fqn="linkerd-identity-headless.linkerd.svc.cluster.local",port="8080"} 0
profile_updates_queue_overflow{fqn="linkerd-policy.linkerd.svc.cluster.local",port="8090"} 0
profile_updates_queue_overflow{fqn="prometheus-server.monitoring.svc.cluster.local",port="80"} 0
profile_updates_queue_overflow{fqn="prometheus-server.monitoring.svc.cluster.local",port="9090"} 0
profile_updates_queue_overflow{fqn="simple-app-v1.simple-app.svc.cluster.local",port="80"} 0

# HELP service_subscribers Number of subscribers to Service changes.
# TYPE service_subscribers gauge
service_subscribers{name="linkerd-dst-headless",namespace="linkerd"} 1
service_subscribers{name="linkerd-enterprise",namespace="linkerd"} 5
service_subscribers{name="linkerd-policy",namespace="linkerd"} 1
service_subscribers{name="prometheus-server",namespace="monitoring"} 1
service_subscribers{name="simple-app-v1",namespace="simple-app"} 2
```

![Destination Profile Watcher Metrics](/control-plane/destination_profile_metrics.png)

## References

- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/watcher/k8s.go
- https://github.com/linkerd/linkerd2/blob/main/controller/api/destination/watcher/profile_watcher.go
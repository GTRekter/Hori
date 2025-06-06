## 6. External Workloads Controller

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

# Hori 

Linkerd is famously *simple* to install and operate, but that apparent simplicity masks a lot of sophisticated engineering:

* **Annotations** configure everything from proxy behavior to control-plane policies.  
* Features such as **mTLS, protocol detection, circuit breaking, rate limiting, and multi-cluster communication** all rely on carefully orchestrated interactions between the proxy and control-plane controllers.  
* Underneath it all, Kubernetes resources—CRDs, webhooks, leases, and more—quietly do the heavy lifting.

Most tutorials stop at the “happy path.”  
**This course is different.** We’ll dissect *every* moving part—down to the source code and Kubernetes API calls—so you can:

1. **Understand** exactly *why* Linkerd behaves the way it does.  
2. **Diagnose** problems in production with confidence.  
3. **Extend** or integrate Linkerd features in your own environment.

Each module is hands-on, self-contained, and designed to run on a local **k3d** cluster.  
Copy, paste, and experiment at your own pace.

[Website](http://ivanporta.net//Hori)
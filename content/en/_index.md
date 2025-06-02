---
type: 'blank'
title: "About"
description: "Who I am, why this course exists, and what you can expect to learn."
---

## 👋 Hi, I’m Ivan Porta  

I’m a **Customer Engineer at Buoyant** living in  **South Korea**.  
Over the years I’ve helped large and small organizations adopt **Linkerd**, tune it for production traffic, and even peek under the hood when things got interesting.

![About](/about/selfie.png)

---

### Why this course?

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

---

### What you’ll learn

| Topic | Key Takeaways |
|-------|---------------|
| Certificate Hierarchy | How trust anchors, issuers, and proxies work together to enable mTLS. |
| Control Plane Deep-Dive | gRPC coordination, leader election, and policy enforcement under the hood. |
| Proxy-Init & iptables | How traffic is transparently steered through the mesh—plus debugging tips. |
| Timeout Policies | Fine-grained request, response, and idle timeouts via service annotations. |
| CLI Mastery | From CRD installation to day-two troubleshooting commands. |

…and more as the curriculum grows.

---

### Get in touch

Feedback, questions, or wild feature ideas?  
Open an issue in the course repository or reach out on **[Slack(@gtrekter)](https://linkerd.slack.com/archives/D07M5GLPVLK)**.  
Let’s make service-mesh internals a little less mysterious—together.

{{< icon vendor="feather" name="github" link="https://github.com/GTRekter/Hori" >}}
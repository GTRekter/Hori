+++
author = "Ivan Porta"
title = "컨트롤 플레인"
date = "2025-06-01"
description = "Linkerd 컨트롤 플레인 아키텍처 심층 분석—destination, identity·policy, proxy-injector 컨트롤러가 Kubernetes에서 gRPC 트래픽과 리더 선출을 어떻게 조정하는지 살펴봅니다."

tags = [
  "linkerd",
  "control-plane",
  "architecture",
  "kubernetes",
  "deep-dive"
]
+++

## Linkerd Proxy-Injector

It's using a mutating webhook to intercept the requests to the kubernetes API when a new pod is created, then check the annotations and if there is `linkerd.io/injected: enabled` then inject a Linkerd proxy and ProxyInit containers.

## 참고 자료

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
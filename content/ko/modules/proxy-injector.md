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

Proxy-Injector는 변형(Mutating) Webhook을 사용해 새 파드 생성 요청을 가로채고, 어노테이션에 `linkerd.io/injected: enabled`가 있으면 Linkerd Proxy 및 ProxyInit 컨테이너를 주입합니다.

## 참고 자료

- https://linkerd.io/2-edge/reference/architecture/
- https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
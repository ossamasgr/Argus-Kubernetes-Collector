# Application metrics

Version 0.3.0 adds `prometheus.metrics` to the existing approved-target lease protocol. The initial `minishop-v1` profile reads request rate, server error percentage, p95 latency, accepted order rate, application CPU cores, memory MiB, available replicas and healthy scrape targets. Every selector is restricted to one enrolled inventory namespace. Both `namespace` and `kubernetes_namespace` scrape labels are supported for application instrumentation.

The platform sends a `metrics_namespace`, never an expression, URL, HTTP options or local credential path. The collector rejects namespaces absent from its operator-owned `ARGUS_NAMESPACES`. It generates a fixed `/api/v1/query_range` request: the last hour, 60-second steps, 10-second query timeout, at most eight aggregate series and 61 samples per series. Existing TLS, DNS pinning, redirect refusal, target revision checks and persistent replay claims apply. The API independently rechecks the owner, binding and namespace when issuing and consuming a lease. The metrics namespace is part of lease/result correlation.

Responses contain only the metric key, timestamps and finite numeric values. Nonfinite Prometheus values become null gaps. Empty results remain unavailable; zero traffic does not imply a zero p95 latency or a measured error percentage. Application traffic excludes `/healthz`, `/readyz` and `/metrics`. Collectors still report their existing inventory every minute.

Rule discovery also retains state, duration, severity and bounded query/summary text. Unrelated labels and annotations are dropped. If the existing 64 KiB payload budget is reached, narrative fields are removed before rule names, state or severity. Metrics use the same size limit.

Install the backend update before upgrading the collector. Older collectors continue using the original rules/alerts contract and do not advertise metrics. Reuse the existing monitoring Secret, replay PVC, CA and service-proxy RBAC; metrics require no extra Kubernetes permissions or network destinations. Published Helm charts pin the runtime image digest.

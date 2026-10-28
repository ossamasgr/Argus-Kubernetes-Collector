# 0.2.0

- Optional, operator-approved private Prometheus rule discovery and signal reads.
- Fixed read operations, verified TLS, address checks, replay claims and minimized results.
- Private monitoring requires explicit target, platform and Kubernetes API egress destinations.

# 0.1.1

- Optional host aliases for private Argus ingress addresses while preserving HTTPS hostname/certificate verification.
- Helm now manages private routing overrides across upgrades.
- Explicit platform CA bundles define trust without silently accepting certificates from unrelated public sites.

# 0.1.0

- Outbound HTTPS inventory and status from selected namespaces, with explicit partial coverage.
- Namespace read-only RBAC, restricted non-root container and egress policy.
- Public Helm chart with external credentials, private CA support and credential rollout revision.
- AMD64 and ARM64 images; published chart releases pin image digests.
- No workload changes, pod logs, Secrets, ConfigMaps or node access.

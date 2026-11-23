## 0.5.0

- Optional read-only security view for Argus security reviews, on by default: workload and pod settings, services,
  ingresses, network policies, service accounts, roles and bindings, disruption budgets, quotas and the cluster version.
- Secrets and ConfigMaps are never read. Environment values become `(set)`, commands and arguments are removed, only
  allowlisted annotations are kept, and the snapshot is capped at 2 MB with per-kind coverage.
- `securityRead.cluster` (default on) adds a read-only ClusterRole for cluster-wide roles and bindings that reach the
  watched namespaces, `get` on the watched namespaces only, and ingress classes. Set `securityRead.enabled=false` to keep 0.4 permissions.

## 0.4.1

- Remove the fixed Kubernetes 1.27 gate; render security settings for the cluster API version.
- Fall back to the legacy CronJob API only for unavailable stable endpoints.
- Report safe failure stages and categories for network, TLS and credential diagnosis.
- Validate representative chart versions from Kubernetes 1.16 through 1.36 and document same-cluster ingress NAT.

# 0.4.0

- Discover namespace-scoped metric names and run bounded application dashboard queries through the approved reader.
- Carry metric identifiers and template kinds in leases; reject arbitrary PromQL, endpoints, namespace escapes and replay.
- Return source sample timestamps alongside range samples for explicit freshness. Credentials remain mounted in the collector.

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
# 0.3.0

- Add fixed, namespace-scoped one-hour application metric queries through the approved Prometheus target.
- Preserve bounded alert-rule details instead of sending names only.
- Keep existing target permissions, TLS verification, response limits and replay protection.

# 0.3.1

- Drain up to ten individually authorized monitoring reads per inventory cycle, with a bounded time budget and one capability advertisement, so alert watches do not starve metric collection.


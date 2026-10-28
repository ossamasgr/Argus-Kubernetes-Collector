# Security

Report vulnerabilities privately through GitHub private vulnerability reporting when enabled, or privately to the repository owner. Do not post credentials or private cluster information in public issues.

Runtime RBAC permits only namespace-local get/list on approved inventory resources. No Secrets, ConfigMaps, pod logs, exec, nodes or mutations are allowed. Kubernetes returns full permitted objects, but only identity and selected status counters are exported. Treat reported names/status as untrusted evidence, not proof of health.

Credentials are mounted from an external Kubernetes Secret, never Helm values or container environment variables. Keep enrollment files private and revoke access in Argus when uninstalling. TLS verification is mandatory; redirects and environment proxies are disabled. An explicit CA bundle defines platform trust without fallback to unrelated public roots. Without a custom bundle, system trust is used. NetworkPolicy enforcement requires a supporting CNI. Inventory-only mode restricts ports; optional private monitoring additionally requires explicit target, platform and API CIDRs.

Published charts pin images by digest. Updates require explicit Helm upgrades. The collector source is MIT licensed.

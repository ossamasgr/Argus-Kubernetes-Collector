# Argus Kubernetes Collector

Read-only, namespace-scoped Kubernetes inventory for Argus SRE. The collector runs inside your cluster and sends snapshots outbound over verified HTTPS every minute. It exposes no inbound service and needs no public Kubernetes API address or uploaded kubeconfig.

## Install

Requirements: Kubernetes 1.27+, Helm 3.10+, kubectl with administrator access to your cluster, and outbound DNS/HTTPS access to Argus and the image registry. Selected namespaces must already exist. NetworkPolicy enforcement depends on your CNI.

In Argus, open your project → **Connections → Kubernetes → Connect a cluster**. Enter a name and choose namespaces, then copy the installation command and run it in your cluster terminal within 30 minutes. No script download is required. The command creates an external credential Secret and optional CA ConfigMap, then installs the public chart. The dialog updates automatically from Connecting to Connected when the collector reports back. Cluster details show inventory and collection coverage.

For a manual Helm install, first create a Secret in the collector namespace with keys `enrollment-key` and `agent-key` from Argus. Use private files or your secret manager; keep credentials out of Helm values and command arguments:

```bash
kubectl create namespace argus-system
kubectl -n argus-system create secret generic argus-credentials \
  --from-file=enrollment-key=/private/path/enrollment-key \
  --from-file=agent-key=/private/path/agent-key

helm repo add argus https://ossamasgr.github.io/Argus-Kubernetes-Collector
helm repo update argus
helm upgrade --install argus-collector argus/argus-collector \
  --namespace argus-system \
  --version 0.1.1 \
  --set-string argus.endpoint='https://YOUR_ARGUS/api/kubernetes-agent/PROJECT_ID/CONNECTION_ID' \
  --set credentials.existingSecret=argus-credentials \
  --set-json 'watchNamespaces=["production","monitoring"]'
```

Replace the placeholder endpoint with the complete URL supplied by Argus. Public charts/images need no GitHub login; each connection still needs project enrollment credentials. For private Argus certificates, create a ConfigMap with the trusted CA under `ca.crt` and add `--set ca.existingConfigMap=argus-platform-ca`. Argus-generated setup includes the configured CA automatically. TLS verification stays enabled; private CA trust supplements system trust.

## Collected data and access

| Resources | Exported fields |
| --- | --- |
| Pods | Name, namespace, UID, phase, ready/desired containers, restarts |
| Deployments, StatefulSets, DaemonSets | Identity and ready/desired replicas |
| Jobs | Identity and succeeded/failed/desired counts |
| Services, CronJobs | Identity |
| PVCs | Identity and phase |
| Events | Identity and Warning/Normal classification, without message text |

The ServiceAccount can only get/list these resources in the 1–20 selected namespaces. It cannot change workloads, read Secrets/ConfigMaps/pod logs, execute commands or access nodes. Kubernetes returns full permitted objects to the collector; pod specs, environment values, labels, annotations and event messages are filtered before export.

Snapshots include at most 500 resources, bounded payloads and explicit coverage for every namespace/resource pair. Permission failures, unavailable APIs and collection limits produce partial coverage. Empty inventory is not proof of health. Argus marks collection offline after three minutes without receipt. Changing Helm namespace values alone does not expand the scope authorized by Argus.

## Configuration

| Value | Purpose |
| --- | --- |
| `argus.endpoint` | Complete HTTPS project/connection endpoint |
| `watchNamespaces` | Explicit namespaces matching the Argus connection |
| `hostAliases` | Optional IP/hostname pairs for private Argus routing; no cluster-wide DNS changes |
| `credentials.existingSecret` | External Secret with both credential keys |
| `credentials.revision` | Non-secret rollout revision after replacing credentials |
| `ca.existingConfigMap` | Optional ConfigMap containing `ca.crt` |
| `image.digest` | Immutable image reference, set in published chart releases |
| `resources` | CPU/memory requests and limits |
| `networkPolicy.apiServerPort` | API port, default 6443; 443 is also allowed |
| `networkPolicy.platformPort` | Argus HTTPS port, default 443 |
| `networkPolicy.enabled` | Denied ingress and port-restricted egress, default true |

The pod runs as UID/GID 10001 with a read-only filesystem, dropped capabilities and RuntimeDefault seccomp. It rereads rotated ServiceAccount tokens for each request. Environment proxies are disabled; proxy-only clusters require an explicit supported adaptation. No insecure TLS mode exists.

If Argus uses private DNS, ensure the collector resolves its hostname to the correct ingress. You can provide `--set-json 'hostAliases=[{"ip":"192.0.2.10","hostnames":["argus.example.com"]}]'` with your administrator-provided address, or use private DNS. A wrong public DNS result can reach a different website. The hostname in the endpoint and its trusted certificate must still match. Always run the complete Argus-generated install command: the final Helm line alone assumes that the referenced credential Secret and optional CA ConfigMap already exist.

## Upgrade and uninstall

Upgrade with an explicit chart version and retain your endpoint, namespace scope and external Secret/CA settings. Credential replacement in Argus immediately invalidates old keys: update the external Secret and change `credentials.revision` or restart the deployment. For existing YAML installations, remove the old installation before migrating; the generated Helm namespace avoids ownership collisions.

```bash
kubectl -n argus-system rollout status deployment/argus-collector-argus
kubectl -n argus-system logs deployment/argus-collector-argus
helm uninstall argus-collector --namespace argus-system
```

Helm uninstall removes the deployment and its namespace Roles/RoleBindings. It leaves the external Secret, CA ConfigMap and namespace. Remove those when appropriate and revoke the connection in Argus. Do not delete a namespace containing other workloads.

## Develop and publish

Run `bash scripts/validate.sh` on a Docker-enabled development host. It checks the chart schema, manifests, read-only RBAC, collector tests and non-root runtime. Runtime Python uses only the standard library.

Pull requests are checked by GitHub Actions. Push a matching `vX.Y.Z` tag after merging a reviewed release to publish AMD64/ARM64 images, package the chart with its image digest, create a GitHub Release and update the GitHub Pages chart index. Set GitHub Pages source to **GitHub Actions**. The first GHCR package must be made public in package settings; verify an anonymous pull before announcing the release. Subsequent releases retain that visibility.

License: [MIT](LICENSE). See [SECURITY.md](SECURITY.md).

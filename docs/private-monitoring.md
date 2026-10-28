# Private Prometheus monitoring

Private monitoring is opt-in. The collector uses fixed, read-only Prometheus
rule and alert endpoints; it does not accept URLs, headers or queries from Argus.
It retains inventory collection independently. A signal watch records observations
for review and does not automatically start an investigation.

Before enabling the feature, a cluster administrator provides:

* A Secret in the collector namespace containing `targets.json` and any public CA
  and bearer-token files. Do not put tokens into Helm values or `targets.json`.
* A writable, persistent claim for replay-protection records, accessible to UID
  and group 10001. Do not share this claim with another collector installation.
* NetworkPolicy egress entries for approved target CIDRs and TCP ports, plus
  explicit Kubernetes API and Argus platform CIDRs. The cluster's CNI must enforce
  NetworkPolicy; choose the actual destinations seen after service routing.

`targets.json` is an array, for example:

```json
[{"connection_id":"monitoring:EXAMPLE", "connection_revision":"<64 lowercase hex digits from the connection>",
  "target_revision":"<64 lowercase hex digits chosen by the administrator>",
  "host":"prometheus.monitoring.svc.cluster.local", "port":8443,
  "ca_file":"/monitoring/ca.crt", "token_file":"/monitoring/token"}]
```

Use the actual connection ID and revision from the same Argus project as the
collector. `ca_file` and `token_file` are optional and, when supplied, must be
files in the mounted Secret. HTTPS certificate verification is always enabled;
the certificate must match the configured host. All DNS answers are checked,
and forbidden addresses, redirects and unsupported operations are rejected.

The collector derives its advertised target revision from the local target
configuration and CA. Change the administrator's `target_revision` nonce when
rotating a bearer token; token contents are never hashed into or sent with the
advertisement. Target or connection changes require the owner to approve the new
revision and discover the rules again before starting a new watch.

Enable the chart with `monitoring.enabled=true`, the names of the pre-created
`monitoring.existingSecret` and `monitoring.stateClaim`, and explicit
`monitoring.egress` CIDR/port pairs and the `monitoring.apiServerCidrs` and
`monitoring.platformCidrs` lists. NetworkPolicy cannot be disabled while this
feature is enabled. An old inventory-only collector does not
advertise this capability. Upgrade it to a release that includes this feature.

For example, after creating the Secret and persistent claim in the collector
namespace, configure the existing release with the destinations for your cluster:

```sh
helm upgrade argus-collector argus/argus-collector --namespace YOUR_COLLECTOR_NAMESPACE \
  --version 0.2.0 --reuse-values --set monitoring.enabled=true \
  --set monitoring.existingSecret=YOUR_TARGET_SECRET --set monitoring.stateClaim=YOUR_STATE_CLAIM \
  --set-json 'monitoring.apiServerCidrs=["YOUR_API_CIDR"]' \
  --set-json 'monitoring.platformCidrs=["YOUR_PLATFORM_CIDR"]' \
  --set-json 'monitoring.egress=[{"cidr":"YOUR_PROMETHEUS_CIDR","port":8443}]'
```

Replace every placeholder with values for your cluster. If the Argus or Kubernetes
API port differs from the chart defaults, also set
`networkPolicy.platformPort` or `networkPolicy.apiServerPort` accordingly.
Then open the Prometheus
connection in Signals, choose the collector, approve its advertised target and
request rule discovery. If a required CIDR, port, CA, target revision or Secret
is wrong, discovery fails and the watch does not report recovery. Older collector
releases and plain inventory manifests do not provide private monitoring.

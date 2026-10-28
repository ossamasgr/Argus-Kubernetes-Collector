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
* NetworkPolicy egress entries for the approved target CIDRs and TCP ports. The
  cluster's CNI must enforce NetworkPolicy. Existing DNS, platform and Kubernetes
  API egress remains available for inventory delivery.

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
`monitoring.egress` CIDR/port pairs. An old inventory-only collector does not
advertise this capability. Upgrade it to a release that includes this feature.

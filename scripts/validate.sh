#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
helm() { docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work alpine/helm:3.19.0 "$@"; }
helm lint --strict charts/argus-collector -f tests/values.yaml
helm template test charts/argus-collector --namespace argus-test -f tests/values.yaml > artifacts/rendered.yaml
docker run --rm -v "$PWD/artifacts:/manifests:ro" ghcr.io/yannh/kubeconform:v0.6.7 -strict -summary -kubernetes-version 1.28.10 /manifests/rendered.yaml
private=(--set monitoring.enabled=true --set monitoring.existingSecret=test-targets --set monitoring.stateClaim=test-state
  --set 'monitoring.egress[0].cidr=10.0.0.0/8' --set 'monitoring.egress[0].port=8443'
  --set 'monitoring.apiServerCidrs[0]=10.1.0.0/16' --set 'monitoring.platformCidrs[0]=10.2.0.0/16')
helm template private charts/argus-collector --namespace argus-test -f tests/values.yaml "${private[@]}" > artifacts/private-monitoring.yaml
docker run --rm -v "$PWD/artifacts:/manifests:ro" ghcr.io/yannh/kubeconform:v0.6.7 -strict -summary -kubernetes-version 1.28.10 /manifests/private-monitoring.yaml
if helm template invalid charts/argus-collector -f tests/values.yaml "${private[@]}" --set networkPolicy.enabled=false >artifacts/invalid.log 2>&1; then
  echo 'FAIL: private monitoring accepted a disabled NetworkPolicy'; exit 1
fi
for invalid in 'argus.endpoint=http://example.com' 'watchNamespaces[0]=Bad_Namespace' 'credentials.existingSecret='; do
  if helm template invalid charts/argus-collector -f tests/values.yaml --set "$invalid" >artifacts/invalid.log 2>&1; then
    echo "FAIL: chart accepted invalid values: $invalid"; exit 1
  fi
done
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONPATH=/work -v "$PWD:/work" -w /work python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 sh -c 'pip install --quiet --user pytest==8.4.2 ruff==0.17.1 PyYAML==6.0.3 && python -m ruff check collector tests && python -m pytest -q'
docker build --provenance=false --sbom=false -t argus-collector:validation .
docker run --rm --entrypoint python argus-collector:validation -c 'import os,ssl; assert os.getuid()==10001; assert ssl.create_default_context().get_ca_certs(); import agent; assert len(agent.RESOURCES)==9; print("Non-root runtime and TLS trust verified")'
echo 'Collector and Helm validation passed'

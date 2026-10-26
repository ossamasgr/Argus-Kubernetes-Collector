#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
trivy() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/source:ro" -v argus-collector-trivy-cache:/root/.cache/trivy aquasec/trivy:0.74.0 "$@"; }
trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress /source
trivy config --severity HIGH,CRITICAL --exit-code 1 /source/artifacts/rendered.yaml
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress argus-collector:validation

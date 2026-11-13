FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG VERSION=0.3.0
LABEL org.opencontainers.image.title="Argus Kubernetes Collector" \
      org.opencontainers.image.description="Outbound, namespace-scoped, read-only Kubernetes inventory for Argus SRE" \
      org.opencontainers.image.source="https://github.com/ossamasgr/Argus-Kubernetes-Collector" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$VERSION
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/argus
RUN groupadd --gid 10001 argus && useradd --uid 10001 --gid 10001 --no-create-home argus
COPY --chown=10001:10001 collector/agent.py ./agent.py
COPY --chown=10001:10001 collector/monitoring.py collector/monitoring_runtime.py ./
COPY --chown=10001:10001 collector/metric_profile.py ./
COPY LICENSE ./LICENSE
USER 10001:10001
ENTRYPOINT ["python", "-B", "/opt/argus/agent.py"]

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
ARG VERSION=0.1.1
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
COPY LICENSE ./LICENSE
USER 10001:10001
ENTRYPOINT ["python", "-B", "/opt/argus/agent.py"]

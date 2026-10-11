# IncidentIQ backend image (API + dashboard + detector loop).
#
#   docker build -f backend.Dockerfile -t incidentiq-backend:local .
#   kind load docker-image incidentiq-backend:local --name incidentiq
#
# ROLLBACK_MODE=python (the default) needs no extra tools. If you set
# ROLLBACK_MODE=kubectl, build with kubectl included:
#   docker build -f backend.Dockerfile --build-arg INSTALL_KUBECTL=true -t incidentiq-backend:local .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/incidentiq

COPY requirements-backend.txt .
RUN pip install -r requirements-backend.txt

# Optional kubectl for ROLLBACK_MODE=kubectl. Pinned version, checksum verified.
ARG INSTALL_KUBECTL=false
ARG KUBECTL_VERSION=v1.31.4
RUN if [ "${INSTALL_KUBECTL}" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
      && ARCH="$(dpkg --print-architecture)" \
      && curl -fsSLO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
      && curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl.sha256" -o kubectl.sha256 \
      && echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check \
      && install -m 0755 kubectl /usr/local/bin/kubectl \
      && rm -f kubectl kubectl.sha256 \
      && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*; \
    fi

# Non-root user; the UID matches runAsUser in k8s/backend.yaml.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin incidentiq \
    && mkdir -p /data && chown 10001:10001 /data

COPY backend/ ./backend/
COPY dashboard/ ./dashboard/

ENV APP_ENV=production \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DATABASE_PATH=/data/incidentiq.db

USER 10001
EXPOSE 8000

# One worker only: the detector loop lives inside this process.
CMD ["python", "-m", "uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]

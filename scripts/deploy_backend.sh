#!/usr/bin/env bash
# Build the IncidentIQ backend image, load it into kind and deploy it.
#
#   1. build backend.Dockerfile            4. create/update the Secret from .env
#   2. load the image into kind            5. apply k8s/backend.yaml and wait for it
#   3. apply k8s/rbac.yaml
#
# Usage:   scripts/deploy_backend.sh
# Env:     BACKEND_IMAGE (default incidentiq-backend:local), INSTALL_KUBECTL=true
#          (only for ROLLBACK_MODE=kubectl), ROLLOUT_TIMEOUT_SECONDS (default 120)
# Needs:   scripts/setup_cluster.sh already run (cluster + .env with a generated API_KEY).
# Secrets: API_KEY and GEMINI_API_KEY are read from .env, written to a private temp file
#          and never appear on a command line or in the output.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BACKEND_IMAGE="${BACKEND_IMAGE:-incidentiq-backend:local}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-incidentiq}"
INSTALL_KUBECTL="${INSTALL_KUBECTL:-false}"
ROLLOUT_TIMEOUT_SECONDS="${ROLLOUT_TIMEOUT_SECONDS:-120}"
SECRET_NAME="incidentiq-secrets"

kb() { kubectl --context "${KUBE_CONTEXT}" --namespace "${BACKEND_NAMESPACE}" "$@"; }

log "Step 1/5: checking prerequisites"
require_cmd docker "Install Docker Desktop: https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1 || die "Docker is installed but the daemon is not running. Start Docker Desktop."
require_cmd kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
require_cmd kind "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
ensure_cluster_context
[[ -f "${REPO_ROOT}/.env" ]] || die ".env not found. Run scripts/setup_cluster.sh first (it creates .env and a stable API_KEY)."

API_KEY_VALUE="$(dotenv_get API_KEY)"
[[ -n "${API_KEY_VALUE}" ]] || die "API_KEY is empty in .env. Run scripts/setup_cluster.sh or set a value (32+ characters)."
if [[ "${#API_KEY_VALUE}" -lt 32 ]]; then
  die "API_KEY in .env is shorter than 32 characters. The in-cluster backend runs with APP_ENV=production, which requires a strong key. Generate one: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
fi
GEMINI_KEY_VALUE="$(dotenv_get GEMINI_API_KEY)"
if [[ -z "${GEMINI_KEY_VALUE}" ]]; then
  warn "GEMINI_API_KEY is empty: diagnoses will use the deterministic fallback (source=fallback)."
fi

log "Step 2/5: building ${BACKEND_IMAGE}"
docker build --quiet -f "${REPO_ROOT}/backend.Dockerfile" \
  --build-arg "INSTALL_KUBECTL=${INSTALL_KUBECTL}" -t "${BACKEND_IMAGE}" "${REPO_ROOT}" >/dev/null
kind load docker-image "${BACKEND_IMAGE}" --name "${CLUSTER_NAME}"
ok "Image ${BACKEND_IMAGE} built and loaded into kind"

log "Step 3/5: applying RBAC (namespace, ServiceAccount, Role, RoleBinding)"
kubectl --context "${KUBE_CONTEXT}" apply -f "${REPO_ROOT}/k8s/rbac.yaml"

log "Step 4/5: creating Secret ${BACKEND_NAMESPACE}/${SECRET_NAME}"
umask 077
SECRET_FILE="$(mktemp)"
trap 'rm -f "${SECRET_FILE}"' EXIT
{
  printf 'API_KEY=%s\n' "${API_KEY_VALUE}"
  printf 'GEMINI_API_KEY=%s\n' "${GEMINI_KEY_VALUE}"
} > "${SECRET_FILE}"
kb create secret generic "${SECRET_NAME}" --from-env-file="${SECRET_FILE}" \
  --dry-run=client -o yaml | kb apply -f - >/dev/null
rm -f "${SECRET_FILE}"
ok "Secret applied (values not displayed)"

log "Step 5/5: deploying the backend"
kubectl --context "${KUBE_CONTEXT}" apply -f "${REPO_ROOT}/k8s/backend.yaml"
# An already-running pod keeps the old image/Secret; restart it so a rebuild is picked up.
kb rollout restart deployment/incidentiq-backend >/dev/null
if ! kb rollout status deployment/incidentiq-backend --timeout="${ROLLOUT_TIMEOUT_SECONDS}s"; then
  warn "Backend did not become ready. Recent pod state and logs:"
  kb get pods -o wide || true
  kb logs deployment/incidentiq-backend --tail=40 || true
  die "incidentiq-backend did not become ready within ${ROLLOUT_TIMEOUT_SECONDS}s."
fi

ok "IncidentIQ backend is running."
cat <<NEXT

  Dashboard:   http://localhost:8080
  Inject:      BACKEND_URL=http://localhost:8080 scripts/deploy_bad.sh v2
  Restore:     scripts/deploy_good.sh
  Backend log: kubectl --context ${KUBE_CONTEXT} -n ${BACKEND_NAMESPACE} logs -f deployment/incidentiq-backend

NEXT

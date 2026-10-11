#!/usr/bin/env bash
# One-time (and safely repeatable) local environment setup.
#
#   1. check prerequisites      4. load images into kind
#   2. create the kind cluster  5. deploy shop-api v1 and wait for readiness
#   3. build shop-api v1..v4    6. prepare the Python backend environment
#
# Usage:   scripts/setup_cluster.sh
# Env:     CLUSTER_NAME (default incidentiq), SKIP_VENV=true to skip step 6
# Windows: run from Git Bash or WSL. Docker Desktop must be running.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SKIP_VENV="${SKIP_VENV:-false}"
VERSIONS=(v1 v2 v3 v4)

log "Step 1/6: checking prerequisites"
require_cmd docker "Install Docker Desktop: https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1 || die "Docker is installed but the daemon is not running. Start Docker Desktop."
require_cmd kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
require_cmd kind "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
PYTHON="$(find_python)" || die "Python 3.10+ is required."
"${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "Python 3.10+ is required (found $("${PYTHON}" --version 2>&1))."
ok "docker, kubectl, kind and $("${PYTHON}" --version 2>&1) are available"

log "Step 2/6: kind cluster '${CLUSTER_NAME}'"
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  ok "Cluster '${CLUSTER_NAME}' already exists; reusing it"
else
  kind create cluster --config "${REPO_ROOT}/k8s/kind-config.yaml" --name "${CLUSTER_NAME}"
  ok "Cluster '${CLUSTER_NAME}' created"
fi
kubectl config use-context "${KUBE_CONTEXT}" >/dev/null
kc wait --for=condition=Ready node --all --timeout=120s >/dev/null
ok "Node is Ready (context ${KUBE_CONTEXT})"

log "Step 3/6: building ${IMAGE_REPO}:{${VERSIONS[*]}}"
for v in "${VERSIONS[@]}"; do
  docker build --quiet -t "${IMAGE_REPO}:${v}" --build-arg "APP_VERSION=${v}" "${REPO_ROOT}/app" >/dev/null
  ok "Built ${IMAGE_REPO}:${v}"
done

log "Step 4/6: loading images into kind"
for v in "${VERSIONS[@]}"; do
  kind load docker-image "${IMAGE_REPO}:${v}" --name "${CLUSTER_NAME}"
done

log "Step 5/6: deploying shop-api v1"
"${SCRIPT_DIR}/deploy_good.sh"

log "Step 6/6: preparing the backend Python environment"
if [[ "${SKIP_VENV}" == "true" ]]; then
  warn "Skipped (SKIP_VENV=true)"
elif [[ ! -f "${REPO_ROOT}/requirements.txt" ]]; then
  warn "No requirements.txt at the repo root yet (backend dependencies arrive in a later stage). Skipping."
else
  if [[ ! -d "${REPO_ROOT}/.venv" ]]; then
    "${PYTHON}" -m venv "${REPO_ROOT}/.venv"
  fi
  VENV_PY="${REPO_ROOT}/.venv/bin/python"
  [[ -x "${VENV_PY}" ]] || VENV_PY="${REPO_ROOT}/.venv/Scripts/python.exe"   # Windows layout
  "${VENV_PY}" -m pip install --quiet --upgrade pip
  "${VENV_PY}" -m pip install --quiet -r "${REPO_ROOT}/requirements.txt"
  ok "Backend dependencies installed in .venv"
fi
if [[ ! -f "${REPO_ROOT}/.env" && -f "${REPO_ROOT}/.env.example" ]]; then
  cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
  ok "Created .env from .env.example"
fi
# A blank API_KEY makes the backend invent a new random key on every start, which
# deploy_bad.sh and the dashboard could never know. Generate one stable key.
if [[ -f "${REPO_ROOT}/.env" && -z "$(dotenv_get API_KEY)" ]]; then
  "${PYTHON}" - "${REPO_ROOT}/.env" <<'PYEOF'
import re, secrets, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
key = secrets.token_urlsafe(32)
if re.search(r"^API_KEY=.*$", text, flags=re.M):
    text = re.sub(r"^API_KEY=.*$", lambda _m: "API_KEY=" + key, text, count=1, flags=re.M)
else:
    text += "\nAPI_KEY=" + key + "\n"
open(path, "w", encoding="utf-8").write(text)
PYEOF
  ok "Generated a stable API_KEY in .env (not displayed). Add GEMINI_API_KEY there to enable Gemini."
fi

cat <<NEXT

Setup complete. Next steps:
  1. Deploy the IncidentIQ backend into the cluster:  scripts/deploy_backend.sh
     (add GEMINI_API_KEY to .env first if you want Gemini; otherwise the fallback diagnosis is used)
  2. Open the dashboard:                              http://localhost:8080
  3. Inject a failure:                                BACKEND_URL=http://localhost:8080 scripts/deploy_bad.sh v2
  4. Restore the healthy version:                     scripts/deploy_good.sh

Prefer to run the backend on your machine instead of in the cluster?
  .venv/bin/python -m uvicorn backend.api:app --port 8000     # dashboard on http://localhost:8000
NEXT

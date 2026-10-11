#!/usr/bin/env bash
# Inject a faulty shop-api version and observe the failure.
#
# Usage:   scripts/deploy_bad.sh v2|v3|v4
#   v2  startup exception "DB_URL missing"  -> CrashLoopBackOff
#   v3  /health returns HTTP 500             -> Running but never Ready
#   v4  memory grows past the limit          -> OOMKilled
#
# Order of operations (important for MTTD):
#   1. POST /api/injection   -> IncidentIQ records the injection timestamp
#   2. kubectl set image     -> the failure actually starts
#   3. observe the symptom   -> proves the fault was really injected
#
# Env:
#   BACKEND_URL            IncidentIQ URL (default http://localhost:8000; use
#                          http://localhost:8080 for the in-cluster backend)
#   INCIDENTIQ_API_KEY     API key; falls back to API_KEY in the repo's .env
#   OBSERVE_TIMEOUT_SECONDS  how long to wait for the symptom (default 120)
#   ALLOW_NO_INJECTION=true  continue even if the injection call fails (MTTD
#                          will then be unavailable for the incident)
#   SKIP_IMAGE_CHECK=true  skip the "image is loaded into kind" check
#
# The API key is never printed and is passed to curl on stdin, so it does not
# appear in the process list.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
OBSERVE_TIMEOUT_SECONDS="${OBSERVE_TIMEOUT_SECONDS:-120}"
ALLOW_NO_INJECTION="${ALLOW_NO_INJECTION:-false}"
SKIP_IMAGE_CHECK="${SKIP_IMAGE_CHECK:-false}"

usage() {
  echo "Usage: $0 v2|v3|v4" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
VERSION="$1"
case "${VERSION}" in
  v2) MODE="crashloop"; EXPECTED_SYMPTOM="CrashLoopBackOff" ;;
  v3) MODE="unready";   EXPECTED_SYMPTOM="Running but not Ready (readiness probe failing)" ;;
  v4) MODE="oomkilled"; EXPECTED_SYMPTOM="OOMKilled" ;;
  *)  echo "Invalid version '${VERSION}'. Allowed: v2, v3, v4." >&2; usage ;;
esac
TARGET_IMAGE="${IMAGE_REPO}:${VERSION}"

require_cmd kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
require_cmd curl "Install curl."
PYTHON="$(find_python)" || die "Python 3 is required."
ensure_cluster_context

kc get deployment "${DEPLOYMENT}" >/dev/null 2>&1 \
  || die "Deployment '${DEPLOYMENT}' not found. Run scripts/deploy_good.sh first."

# v4 allocates memory until it is killed; never run it without a container limit.
mem_limit="$(kc get deployment "${DEPLOYMENT}" -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}')"
if [[ "${VERSION}" == "v4" && -z "${mem_limit}" ]]; then
  die "Refusing to inject v4: the Deployment has no container memory limit."
fi

# The kind node must already have the image, otherwise you would see
# ErrImagePull instead of the intended failure.
if [[ "${SKIP_IMAGE_CHECK}" != "true" ]] && command -v docker >/dev/null 2>&1 \
   && docker inspect "${CLUSTER_NAME}-control-plane" >/dev/null 2>&1; then
  if ! docker exec "${CLUSTER_NAME}-control-plane" crictl images 2>/dev/null \
       | awk -v repo="${IMAGE_REPO}" -v tag="${VERSION}" '$1 ~ (repo "$") && $2 == tag { f = 1 } END { exit !f }'; then
    die "Image ${TARGET_IMAGE} is not loaded in kind. Run scripts/setup_cluster.sh (or: kind load docker-image ${TARGET_IMAGE} --name ${CLUSTER_NAME})."
  fi
fi

record_injection() {
  local key payload url body_file code
  key="${INCIDENTIQ_API_KEY:-$(dotenv_get API_KEY)}"
  if [[ -z "${key}" ]]; then
    warn "No API key found (set INCIDENTIQ_API_KEY or API_KEY in .env)."
    return 1
  fi
  if [[ "${key}" == *\"* || "${key}" == *\\* || "${key}" == *$'\n'* ]]; then
    warn "API key contains unsupported characters (quote, backslash or newline)."
    return 1
  fi
  payload="$(printf '{"service":"%s","namespace":"%s"}' "${DEPLOYMENT}" "${NAMESPACE}")"
  url="${BACKEND_URL%/}/api/injection"
  body_file="$(mktemp)"
  code="$(printf 'header = "X-API-Key: %s"\n' "${key}" \
    | curl -sS -K - -X POST "${url}" \
        -H 'Content-Type: application/json' -d "${payload}" \
        --connect-timeout 5 --max-time 15 \
        -o "${body_file}" -w '%{http_code}' 2>/dev/null)" || code="000"
  if [[ "${code}" =~ ^2[0-9][0-9]$ ]]; then
    rm -f "${body_file}"
    return 0
  fi
  warn "POST ${url} failed (HTTP ${code})."
  if [[ "${code}" != "000" ]]; then
    warn "Response: $(head -c 300 "${body_file}")"
  else
    warn "Could not connect. Is the IncidentIQ backend running at ${BACKEND_URL}?"
  fi
  rm -f "${body_file}"
  return 1
}

log "Step 1/3: recording the injection timestamp with IncidentIQ (${BACKEND_URL})"
if record_injection; then
  ok "IncidentIQ accepted the injection record for ${NAMESPACE}/${DEPLOYMENT} (API call succeeded)."
elif [[ "${ALLOW_NO_INJECTION}" == "true" ]]; then
  warn "Continuing WITHOUT an injection timestamp (ALLOW_NO_INJECTION=true). MTTD will be unavailable."
else
  die "Injection was NOT recorded, so the deployment was left unchanged. Start the backend, or set ALLOW_NO_INJECTION=true to proceed without MTTD."
fi

log "Step 2/3: switching ${NAMESPACE}/${DEPLOYMENT} to ${TARGET_IMAGE}"
kc set image "deployment/${DEPLOYMENT}" "${DEPLOYMENT}=${TARGET_IMAGE}"

log "Step 3/3: waiting up to ${OBSERVE_TIMEOUT_SECONDS}s to observe: ${EXPECTED_SYMPTOM}"
deadline=$((SECONDS + OBSERVE_TIMEOUT_SECONDS))
observed=false
while (( SECONDS < deadline )); do
  if kc get pods -l "${APP_LABEL}" -o json | "${PYTHON}" -c "${POD_SYMPTOM_PY}" "${MODE}" "${TARGET_IMAGE}" 15; then
    observed=true
    break
  fi
  sleep 3
done

kc get pods -l "${APP_LABEL}" -o wide || true
if [[ "${observed}" == "true" ]]; then
  ok "Fault confirmed: ${TARGET_IMAGE} shows ${EXPECTED_SYMPTOM}."
else
  warn "The expected symptom (${EXPECTED_SYMPTOM}) was not observed within ${OBSERVE_TIMEOUT_SECONDS}s."
  warn "If AUTO_REMEDIATE=true, IncidentIQ may already have rolled back. Check the dashboard and 'kubectl describe pod'."
fi

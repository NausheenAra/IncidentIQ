#!/usr/bin/env bash
# Shared helpers for the IncidentIQ scripts. This file is sourced, not executed.
#
# SAFETY: every kubectl call goes through kc(), which pins --context to the kind
# cluster. Scripts therefore cannot touch whatever cluster your kubeconfig
# happens to have selected (a production cluster, for example).

if [[ -n "${_INCIDENTIQ_LIB_LOADED:-}" ]]; then
  return 0
fi
_INCIDENTIQ_LIB_LOADED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-incidentiq}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${CLUSTER_NAME}}"
NAMESPACE="${NAMESPACE:-default}"
DEPLOYMENT="${DEPLOYMENT:-shop-api}"
APP_LABEL="${APP_LABEL:-app=shop-api}"
IMAGE_REPO="${IMAGE_REPO:-shop-api}"
EXPECTED_REPLICAS="${EXPECTED_REPLICAS:-2}"

if [[ -t 1 ]]; then
  _C_RED=$'\033[31m'; _C_GRN=$'\033[32m'; _C_YEL=$'\033[33m'; _C_BLU=$'\033[34m'; _C_OFF=$'\033[0m'
else
  _C_RED=""; _C_GRN=""; _C_YEL=""; _C_BLU=""; _C_OFF=""
fi

log()  { printf '%s[incidentiq]%s %s\n' "${_C_BLU}" "${_C_OFF}" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "${_C_GRN}" "${_C_OFF}" "$*"; }
warn() { printf '%s[warn]%s %s\n' "${_C_YEL}" "${_C_OFF}" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "${_C_RED}" "${_C_OFF}" "$*" >&2; exit 1; }

# Pick a Python 3 interpreter (python3 on Linux/macOS, python on Git Bash).
find_python() {
  local candidate
  for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1 \
       && "${candidate}" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1. $2"
}

# kubectl pinned to the kind context and demo namespace.
kc() {
  kubectl --context "${KUBE_CONTEXT}" --namespace "${NAMESPACE}" "$@"
}

ensure_cluster_context() {
  if ! kubectl config get-contexts -o name 2>/dev/null | grep -qx "${KUBE_CONTEXT}"; then
    die "kubectl context '${KUBE_CONTEXT}' not found. Run scripts/setup_cluster.sh first."
  fi
  if ! kc get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    die "Cannot reach namespace '${NAMESPACE}' using context '${KUBE_CONTEXT}'. Is the kind cluster running?"
  fi
}

# Read NAME from the repo's .env without sourcing it (never executes .env content).
dotenv_get() {
  local name="$1" file="${REPO_ROOT}/.env" line value
  [[ -f "${file}" ]] || return 0
  line="$(grep -E "^${name}=" "${file}" | tail -n 1 || true)"
  value="${line#*=}"
  value="${value%$'\r'}"
  value="${value#\"}"; value="${value%\"}"
  value="${value#\'}"; value="${value%\'}"
  printf '%s' "${value}"
}

ready_replicas() {
  local n
  n="$(kc get deployment "${DEPLOYMENT}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  printf '%s' "${n:-0}"
}

# Python helper: reads `kubectl get pods -o json` on stdin and exits 0 when the
# requested failure symptom is present on a pod running the target image.
#   argv: MODE TARGET_IMAGE [MIN_UNREADY_SECONDS]
#   MODE: crashloop | unready | oomkilled
# shellcheck disable=SC2034  # used by scripts that source this file
read -r -d '' POD_SYMPTOM_PY <<'PYEOF' || true
import json, sys
from datetime import datetime, timezone

mode, image = sys.argv[1], sys.argv[2]
min_unready = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
now = datetime.now(timezone.utc)
found = False
for pod in json.load(sys.stdin).get("items", []):
    containers = pod.get("spec", {}).get("containers", [])
    if not any(c.get("image") == image for c in containers):
        continue
    for cs in pod.get("status", {}).get("containerStatuses", []) or []:
        state = cs.get("state", {})
        last = cs.get("lastState", {})
        if mode == "crashloop":
            found |= state.get("waiting", {}).get("reason") == "CrashLoopBackOff"
        elif mode == "oomkilled":
            found |= state.get("terminated", {}).get("reason") == "OOMKilled"
            found |= last.get("terminated", {}).get("reason") == "OOMKilled"
        elif mode == "unready":
            running = state.get("running")
            if running and not cs.get("ready", False):
                started = datetime.fromisoformat(running["startedAt"].replace("Z", "+00:00"))
                found |= (now - started).total_seconds() >= min_unready
sys.exit(0 if found else 1)
PYEOF

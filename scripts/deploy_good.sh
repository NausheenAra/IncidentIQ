#!/usr/bin/env bash
# Deploy the healthy shop-api v1 and wait until both replicas are Ready.
#
# Usage:   scripts/deploy_good.sh
# Env:     ROLLOUT_TIMEOUT_SECONDS (default 120), KUBE_CONTEXT, NAMESPACE
# Windows: run from Git Bash or WSL (bash is required).
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ROLLOUT_TIMEOUT_SECONDS="${ROLLOUT_TIMEOUT_SECONDS:-120}"

require_cmd kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
ensure_cluster_context

log "Applying ${REPO_ROOT}/k8s/deployment.yaml (image ${IMAGE_REPO}:v1) to context ${KUBE_CONTEXT}"
kubectl --context "${KUBE_CONTEXT}" apply -f "${REPO_ROOT}/k8s/deployment.yaml"

log "Waiting up to ${ROLLOUT_TIMEOUT_SECONDS}s for the rollout to finish"
if ! kc rollout status "deployment/${DEPLOYMENT}" --timeout="${ROLLOUT_TIMEOUT_SECONDS}s"; then
  warn "Rollout did not complete. Current pod state:"
  kc get pods -l "${APP_LABEL}" -o wide || true
  die "${DEPLOYMENT} did not become healthy within ${ROLLOUT_TIMEOUT_SECONDS}s."
fi

ready="$(ready_replicas)"
if [[ "${ready}" != "${EXPECTED_REPLICAS}" ]]; then
  kc get pods -l "${APP_LABEL}" -o wide || true
  die "Expected ${EXPECTED_REPLICAS} ready replicas but found ${ready}."
fi

ok "${DEPLOYMENT} v1 is healthy: ${ready}/${EXPECTED_REPLICAS} replicas ready."
kc get pods -l "${APP_LABEL}" -o wide

#!/usr/bin/env bash
# Delete the local kind cluster (and with it shop-api, the backend and its SQLite data).
# Usage: scripts/teardown.sh [--yes]
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd kind "Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}" || { ok "Cluster '${CLUSTER_NAME}' does not exist. Nothing to do."; exit 0; }

if [[ "${1:-}" != "--yes" ]]; then
  read -r -p "Delete kind cluster '${CLUSTER_NAME}' and all incident data in it? [y/N] " answer
  [[ "${answer}" =~ ^[Yy]$ ]] || { log "Aborted."; exit 1; }
fi
kind delete cluster --name "${CLUSTER_NAME}"
ok "Cluster '${CLUSTER_NAME}' deleted. Re-create it with scripts/setup_cluster.sh"

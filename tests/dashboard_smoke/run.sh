#!/usr/bin/env bash
# Optional browser-level dashboard check. Needs Node 18+ and network access for "npm install".
#
#   tests/dashboard_smoke/run.sh
#
# Seeds a throw-away SQLite file, starts the real backend on a local port (no Kubernetes
# needed), loads both dashboard pages in jsdom, and clicks through the approval flow.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
PORT="${SMOKE_PORT:-8765}"
WORK="$(mktemp -d)"
PYTHON="$(command -v python3 || command -v python)"
SERVER_PID=""
cleanup() { [[ -n "${SERVER_PID}" ]] && kill "${SERVER_PID}" 2>/dev/null || true; rm -rf "${WORK}"; }
trap cleanup EXIT

command -v node >/dev/null 2>&1 || { echo "Node.js is required for this optional check." >&2; exit 2; }
[[ -d "${HERE}/node_modules/jsdom" ]] || (cd "${HERE}" && npm install --silent --no-audit --no-fund)

export DATABASE_PATH="${WORK}/smoke.db" APP_ENV=test API_KEY=smoke-key-123 AUTO_REMEDIATE=false \
       KUBERNETES_NAMESPACE_ALLOWLIST=default DETECTOR_INTERVAL_SECONDS=3600
(cd "${ROOT}" && "${PYTHON}" "${HERE}/seed.py") >/dev/null
(cd "${ROOT}" && "${PYTHON}" -m uvicorn backend.api:app --port "${PORT}" --log-level warning) &
SERVER_PID=$!
for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
cd "${HERE}" && SMOKE_BASE_URL="http://127.0.0.1:${PORT}" node smoke.js

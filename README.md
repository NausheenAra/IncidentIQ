# IncidentIQ

<<<<<<< HEAD
**IncidentIQ** is an AI-assisted Kubernetes incident detection, diagnosis, and guarded-remediation demo. It runs locally on a [kind](https://kind.sigs.k8s.io/) cluster and watches a demo Deployment named `shop-api`.
=======
AI-assisted Kubernetes incident detection, diagnosis and remediation, running as a local demo on
[kind](https://kind.sigs.k8s.io/). It watches a Deployment (`shop-api`), notices when a bad version breaks it,
collects evidence, asks Gemini for a structured root-cause analysis (with a deterministic fallback), applies a
**guarded** remediation after approval, **verifies** recovery, and shows the whole lifecycle with MTTD/MTTR on a live, multi-cluster dashboard.
>>>>>>> b07119a (Update IncidentIQ project)

When a bad application version breaks the service, IncidentIQ detects the unhealthy workload, collects evidence, requests a structured root-cause analysis from Gemini (with a deterministic fallback), recommends a guarded remediation, supports an approval step, verifies recovery, and records the incident lifecycle and MTTD/MTTR on a dashboard.

```text
deploy v1 -> inject faulty version -> detect -> collect evidence -> diagnose
          -> approve -> remediate -> verify -> dashboard
```

> **Scope:** IncidentIQ is a local demonstration, not a production-ready incident-management platform. See [Security and limitations](#security-and-limitations).

## Contents

- [Features](#features)
- [Architecture and workflow](#architecture-and-workflow)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Failure scenarios](#failure-scenarios)
- [Configuration](#configuration)
- [Tests](#tests)
- [Demo script](docs/demo.md)
- [Troubleshooting](#troubleshooting)
- [Security and limitations](#security-and-limitations)
- [Project status](#project-status)
- [Repository layout](#repository-layout)

## Features

- **Kubernetes health detection:** polls Kubernetes and identifies unhealthy application workloads.
- **Evidence collection:** gathers pod states, logs, events, deployment information, and rollout history.
- **AI-assisted root-cause analysis:** requests structured JSON analysis from Gemini when configured.
- **Deterministic fallback:** continues with fallback diagnosis when Gemini is not configured or a model response cannot be used.
- **Guarded remediation:** supports a limited set of actions and requires approval by default.
- **Recovery verification:** an incident is marked `RESOLVED` only after the verifier reports recovery.
- **Incident dashboard:** displays incident details, timeline, evidence, diagnosis, and MTTD/MTTR.
- **Local reproducibility:** provides scripts for cluster setup, healthy and faulty deployments, backend deployment, and teardown.

## Architecture and workflow

1. **Run the demo service.** `shop-api` starts with a healthy version.
2. **Inject a fault.** The bad-deploy script records the injection time with IncidentIQ, then deploys a selected faulty version.
3. **Detect the incident.** The backend polls Kubernetes and detects unhealthy pods or deployments.
4. **Collect evidence.** IncidentIQ gathers relevant Kubernetes state, logs, events, and deployment history.
5. **Diagnose.** Gemini returns a structured root-cause analysis when available; otherwise, the deterministic fallback is used.
6. **Review and approve.** By default, the incident waits for an approval before remediation.
7. **Remediate.** The guarded engine can select only the allowed actions: `rollback`, `restart`, or `scale`.
8. **Verify.** Recovery is checked rather than assumed from a successful remediation API call.
9. **Record and display.** The incident lifecycle and measured timing information appear on the dashboard.

## Live multi-cluster dashboard

`http://localhost:8080` (or `:8000` when running locally) is a live view of every connected cluster:

* **Monitored clusters** row: one card per healthy cluster (pods ready, restarts, log and error rate, workload health, last sample age).
* **Active incident** box: a cluster moves here the moment an incident opens (with a link to review and approve it) and moves back when it is resolved.
* **Live analytics**: pods ready, log volume, error lines, restarts, unhealthy pods and warning events, per cluster or combined, with rising/falling arrows. Hover a chart for exact values.
* **Incident analytics**: status mix, MTTD/MTTR per incident, detector reasons. Plus a workload table and a live activity feed.
* **Connect cluster** button: choose a kubeconfig context and a name; IncidentIQ tests the connection, then starts analysing it and handling its incidents with the same guardrails.
* **Delete** on each cluster card: stops the analysis and removes the live metrics (incident history is kept). It is refused while that cluster has an open incident, and the built-in cluster cannot be deleted.

Things to know about connecting more clusters:

* Only the **context name** is stored. The backend must be able to read that context in a kubeconfig, so extra clusters can be connected when the backend runs **on your machine** (`.venv/bin/python -m uvicorn ...`). The in-cluster backend has no kubeconfig and will say so.
* The context's credentials are used as they are. Apply `k8s/rbac.yaml` in the target cluster and use a context bound to that least-privilege ServiceAccount rather than an admin one. Namespaces are still limited by `KUBERNETES_NAMESPACE_ALLOWLIST`.
* Metrics are sampled every `METRICS_INTERVAL_SECONDS` (default 5). CPU and memory are not shown because they need metrics-server.
* `GET /api/clusters` and the other reads are unauthenticated like the rest of the demo API; connecting and deleting need the API key.

## Prerequisites

| Tool | Check | Notes |
|---|---|---|
| Docker (Docker Desktop on Windows/macOS) | `docker --version` and `docker info` | Docker engine must be running with Linux containers; Windows may use WSL 2. |
| `kubectl` | `kubectl version --client` | Kubernetes command-line client. |
| `kind` | `kind --version` | Runs a local Kubernetes cluster in Docker. |
| Python 3.10+ | `python --version` or `python3 --version` | Needed for tests and some local development tasks. |
| Bash | — | On Windows, use Git Bash or WSL; project scripts are Bash scripts. |
| Gemini API key | Optional | Obtain one from [Google AI Studio](https://aistudio.google.com/). Without a usable key, the deterministic fallback diagnosis is used. |

## Quick start

Run commands from the repository root. On Windows, run the Bash scripts from Git Bash or WSL.

### 1. Create the local cluster and demo application

```bash
scripts/setup_cluster.sh
```

This script sets up the kind cluster, builds and loads the demo images, deploys the healthy `shop-api` version, prepares the Python virtual environment, and creates a local `.env` with a generated `API_KEY`.

### 2. (Optional) Configure Gemini

Put your own Gemini key in your local `.env` file:

```dotenv
GEMINI_API_KEY=your_gemini_api_key_here
```

Use a real key only in your local `.env`; never put it in `.env.example`, source code, screenshots, or Git history. The `.env` file is git-ignored. If the key is blank, IncidentIQ uses the deterministic fallback diagnosis.

### 3. Build and deploy the IncidentIQ backend

```bash
scripts/deploy_backend.sh
```

The script builds and loads the backend image, configures its Kubernetes permissions and configuration, creates the Kubernetes Secret from local `.env` values, and deploys the backend.

### 4. Open the dashboard

By default, the local kind setup publishes the dashboard/backend at:

```text
http://localhost:8080
```

If port `8080` is already occupied or your cluster was created without the required port mapping, consult [Troubleshooting](#troubleshooting).

### 5. Inject a failure

```bash
BACKEND_URL=http://localhost:8080 scripts/deploy_bad.sh v2
```

The script records the injection time first, then deploys the faulty version. This timestamp is used when calculating detection timing.

### 6. Review the incident

Open the dashboard, inspect the evidence and diagnosis, and click **Approve remediation** when the incident is awaiting approval. The incident should be marked `RESOLVED` only after the verifier reports that the workload has recovered.

### 7. Restore the healthy version

```bash
scripts/deploy_good.sh
```

You can remove the local demo resources with:

```bash
scripts/teardown.sh
```

### Run the backend outside the cluster (development)

For local backend development, use one Uvicorn worker because the detector loop runs inside the process:

```bash
.venv/bin/python -m uvicorn backend.api:app --port 8000
```

On Windows PowerShell:

```powershell
.venv\Scripts\python.exe -m uvicorn backend.api:app --port 8000
```

The dashboard is then available at `http://localhost:8000`. In this mode, `scripts/deploy_bad.sh` uses its default `BACKEND_URL` unless you override it.

## Failure scenarios

| Version | Intended behavior | Kubernetes symptom | Detector reason |
|---|---|---|---|
| `v1` | Healthy application | Running and Ready | None |
| `v2` | Startup raises `Exception("DB_URL missing")` | `CrashLoopBackOff` | `CrashLoopBackOff` |
| `v3` | `/health` returns HTTP 500 | Running but never Ready | `NotReady` after the 30-second grace period |
| `v4` | Leaks memory until the 128 MiB limit | `OOMKilled` | `OOMKilled` |

Start with `v2`; it is the most straightforward demonstration. The permitted remediation actions are `rollback`, `restart`, and `scale`. For these example faults, rollback is the action intended to restore the prior healthy version. Restarting a still-broken version should fail verification rather than being reported as a successful recovery.

## Configuration

Settings are validated at startup by `backend/config.py`. Safe defaults and examples are documented in `.env.example`; see also `docs/contracts.md` for configuration details.

| Variable | Default or source | Meaning |
|---|---|---|
<<<<<<< HEAD
| `API_KEY` | Generated by `setup_cluster.sh` | Protects write endpoints such as `POST /api/incidents/{id}/approve` and `POST /api/injection`; production configuration requires 32 or more characters. |
| `GEMINI_API_KEY` | Empty | Empty means use fallback diagnosis. Keep any real key in local `.env` only. |
| `GEMINI_MODEL` | Set in configuration | Gemini model name used for diagnosis. |
| `AUTO_REMEDIATE` | `false` | When false, incidents wait in `AWAITING_APPROVAL`; when true, remediation may run immediately, subject to guardrails. |
| `KUBERNETES_NAMESPACE_ALLOWLIST` | `default` | Namespaces IncidentIQ is allowed to inspect or change; wildcards are rejected. |
| `ROLLBACK_MODE` | `python` | `kubectl` mode also requires an image built with `INSTALL_KUBECTL=true`. |
| `MAX_REMEDIATION_ATTEMPTS` | `2` | Hard cap per incident (1–2). |
| `VERIFICATION_TIMEOUT_SECONDS` | `120` | Maximum time to poll for recovery before the incident is marked `FAILED`. |
| `INCIDENT_COOLDOWN_SECONDS` | `60` | Prevents a new incident for the same service for this period after one closes. |
=======
| `API_KEY` | generated by `setup_cluster.sh` | protects `POST /api/incidents/{id}/approve` and `POST /api/injection`; 32+ chars in production |
| `GEMINI_API_KEY` | empty | empty means fallback diagnosis |
| `AUTO_REMEDIATE` | `false` | `false` waits in `AWAITING_APPROVAL`; `true` remediates immediately (the guardrails still apply) |
| `KUBERNETES_NAMESPACE_ALLOWLIST` | `default` | the only namespaces inspected or changed; wildcards are rejected |
| `ROLLBACK_MODE` | `python` | `kubectl` also needs the image built with `INSTALL_KUBECTL=true` |
| `MAX_REMEDIATION_ATTEMPTS` | `2` | hard cap per incident (1-2) |
| `VERIFICATION_TIMEOUT_SECONDS` | `120` | how long recovery is polled (every 5 s) before the incident is `FAILED` |
| `INCIDENT_COOLDOWN_SECONDS` | `60` | no new incident for the same service (in the same cluster) for this long after one closes |
| `METRICS_INTERVAL_SECONDS` | `5` | how often every connected cluster is sampled for the live charts (2-300) |
>>>>>>> b07119a (Update IncidentIQ project)

In Kubernetes, non-secret settings live in the `incidentiq-config` ConfigMap. Secret values are supplied to the `incidentiq-secrets` Secret by `scripts/deploy_backend.sh` from local `.env`. Do not commit `.env` or real credentials.

After changing `.env` or backend code, rerun:

```bash
scripts/deploy_backend.sh
```

This rebuilds and redeploys the backend.

## Tests

Install dependencies and run the Python test suite:

```bash
python -m pip install -r requirements.txt
<<<<<<< HEAD
python -m pytest
=======
python -m pytest                         # 601 tests; no cluster, network or Gemini key needed
>>>>>>> b07119a (Update IncidentIQ project)
```

The repository's test documentation reports **554 tests**. Re-run the suite against the current checkout and use the actual output when reporting a test result.

| Check | Command | Needs |
|---|---|---|
| Unit and API tests covering database, configuration, detector, collector, RCA, remediation, pipeline, API, dashboard files, manifests, and runner logic | `python -m pytest` | Python dependencies |
| Dashboard smoke test using a real backend, seeded data, approval flow, and hostile log-line check | `tests/dashboard_smoke/run.sh` | Node 18+; installs npm dependencies automatically |
| End-to-end scenarios for `v2`, `v3`, `v4`, approval, recovery verification, MTTD/MTTR, and duplicate-incident behavior | `python scripts/e2e.py` | Local kind cluster and deployed backend |

The end-to-end script uses `http://localhost:8080` by default and reads the API key from `.env`. Use `--backend-url` if your backend is listening on a different port.

Useful flags include `--scenario v2`, `--no-approve`, `--no-restore`, `--detect-timeout`, and `--resolve-timeout`. To test fallback diagnosis, leave `GEMINI_API_KEY` blank and redeploy the backend.

Example output layout (illustrative only; your measurements will differ):

```text
scenario  incident  status    reason            rca  action    MTTD   MTTR   result
v2        #1        RESOLVED  CrashLoopBackOff  llm  rollback  8.2s   41.0s  PASS
```

MTTD is the time from recorded injection to detection. MTTR is the time from detection to resolution. Values are measured; they should not be filled with zero when unavailable.

## Troubleshooting

| Symptom | Possible cause and fix |
|---|---|
| `docker is not recognized` or `docker info` cannot connect | Install/start Docker Desktop, reopen the terminal, check PATH, and use Linux containers. |
| `kind is not recognized` | Install the appropriate kind binary, add it to PATH, and open a new terminal. |
| `ImagePullBackOff` on `shop-api` or `incidentiq-backend` | The image may not be loaded into the kind node. Rerun `scripts/setup_cluster.sh` for `shop-api` or `scripts/deploy_backend.sh` for the backend. |
| Backend pod `CreateContainerConfigError` | The `incidentiq-secrets` Secret may be missing. Run `scripts/deploy_backend.sh` to recreate it from local `.env`. |
| Backend pod `CrashLoopBackOff` | Inspect logs with `kubectl --context kind-incidentiq -n incidentiq logs deployment/incidentiq-backend`. Check required configuration, including a sufficiently long `API_KEY` in production mode. |
| `http://localhost:8080` does not respond | Check whether the cluster was created with the required port mapping and whether another process occupies port 8080. Port mappings are set at cluster creation. |
| Dashboard says `Cluster: forbidden` | Check the namespaced RBAC configuration and apply `k8s/rbac.yaml` if appropriate. |
| Dashboard says `Cluster: not configured` or `unreachable` | For local execution, check kubeconfig and `KUBE_CONTEXT=kind-incidentiq`. In-cluster execution requires the ServiceAccount token to be available. |
| `deploy_bad.sh` cannot connect | It posts to `BACKEND_URL` (default `http://localhost:8000`). Set `BACKEND_URL` to the port where your backend is listening. |
| `deploy_bad.sh` or approval returns 401 | The key in local `.env` may differ from the key in the Kubernetes Secret. Rerun `scripts/deploy_backend.sh` after confirming local configuration. |
| CrashLoopBackOff but no incident appears | An incident may already be open, the cooldown may not have elapsed, or the namespace may not be allow-listed. Check the incident list and status endpoint. |
| MTTD shows a dash | The injection time may not have been recorded, may be too old, or may have been sent to the wrong backend URL. A dash means “not measured,” not zero. |
| MTTR shows a dash | MTTR is counted only for incidents that reach `RESOLVED`; failed incidents are excluded. |
| Evidence says `No previous logs` | Kubernetes may not have retained the earlier container instance. The collector may use current logs instead. |
| Diagnosis says `Fallback heuristic` | Gemini may be unconfigured, unavailable, timed out, or returned an unusable response. Check backend logs and configuration. |
| Incident ends `FAILED` after rollback | The previous revision may not be healthy, or recovery may have exceeded `VERIFICATION_TIMEOUT_SECONDS`. Inspect the last timeline entry for the verifier's reason. |
| Incidents disappear after backend restart | SQLite uses an `emptyDir` volume in this demo, so its data is not durable across relevant pod/cluster recreation. |
| Dashboard is blank or unstyled | Hard-refresh the browser and check the browser console for content-security-policy or resource errors. |

## Security and limitations

- **Least privilege:** the backend is intended to use a namespaced Role in `default` for required pod, log, event, ReplicaSet, and Deployment operations. It should not require cluster-admin access or Secrets read access.
- **Guarded remediation:** only `rollback`, `restart`, and `scale` are permitted. Namespace allow-lists and attempt limits apply; approval is required by default.
- **Verification matters:** a successful Kubernetes API call does not by itself mark an incident `RESOLVED`; the verifier must report recovery.
- **Untrusted evidence:** logs and events may contain untrusted input. The design redacts secrets, constrains model instructions to collected evidence, validates quoted evidence, and renders dashboard text safely.
- **API exposure:** write endpoints require an API key, but read endpoints—including incident details and evidence—are unauthenticated in this demo. Keep the dashboard/API bound to your own machine. Do not expose it to the internet without adding appropriate authentication, authorization, TLS, and network controls.
- **Not production-ready:** the demo uses SQLite on an `emptyDir`, a single backend process, no high availability, and no TLS. Root-cause analysis is best-effort and is not guaranteed to be correct. Keep a human in the loop for remediation.
- **Secrets:** never commit `.env`, real API keys, service-account credentials, or other secrets. `.gitignore` should exclude local `.env` files while allowing the sanitized `.env.example`. Check the contents of example files before pushing to a public repository.

## Project status

IncidentIQ has been exercised locally using a kind Kubernetes cluster. The following items were observed during the local `v2` demonstration, based on the project run and logs:

- The IncidentIQ backend was deployed in the local cluster.
- The intentionally faulty `shop-api:v2` version was deployed.
- Backend logs showed detection of unhealthy pods, including `CrashLoopBackOff` and `HighRestartCount`.
- The Gemini API request returned HTTP 200.
- The dashboard displayed a root-cause diagnosis identifying the missing `DB_URL` configuration.
- The dashboard later displayed the incident as `RESOLVED` and indicated that recovery had been verified.

These observations describe the demonstrated `v2` workflow. They do **not** by themselves establish that every failure scenario, fallback path, security property, or automated end-to-end test has passed. Record the actual output of the test suite and any `v3`/`v4`/fallback runs separately.

### Acceptance checklist

Use this checklist to record repeatable results from your own runs:

- [ ] A clean setup following this README succeeds (`setup_cluster.sh`, then `deploy_backend.sh`).
- [ ] `python -m pytest` passes on the current checkout.
- [ ] The healthy app deploys repeatably (`deploy_good.sh` run twice).
- [ ] `v2` is detected end to end, with exactly one incident.
- [ ] Evidence and root-cause analysis are stored with the incident.
- [ ] Remediation waits for approval by default and obeys the guardrails.
- [ ] The incident is `RESOLVED` only after verification and is `FAILED` with useful detail when recovery fails.
- [ ] The dashboard shows lifecycle, evidence, diagnosis, timeline, and measured MTTD/MTTR.
- [ ] The fallback path works with Gemini unavailable.
- [ ] `v3` and `v4` behave as described in the failure-scenarios table.
- [ ] No real secrets are present in tracked files or Git history.

### Observed local demonstration

| Item | Observation |
|---|---|
<<<<<<< HEAD
| Environment | Local Docker/kind Kubernetes cluster |
| Fault scenario | `shop-api:v2` |
| Detection | `CrashLoopBackOff` and `HighRestartCount` appeared in backend logs |
| AI integration | Gemini request returned HTTP 200 |
| Diagnosis | Dashboard showed missing `DB_URL` as the root cause |
| Final dashboard status | `RESOLVED`; dashboard indicated recovery verification |
=======
| Database, config, detector, collector, RCA, remediation, pipeline, API | Unit/API tested: **601 tests pass** (Python 3.12.3, FastAPI 0.143, kubernetes client 37.0, pytest 9.1) against simulated Kubernetes. |
| Dashboard | Static contract tests plus a jsdom run against the real backend (both pages, cluster row and incident box, charts, connect and delete dialogs with no/wrong/correct key, metrics, timeline, evidence, approval, hostile log line and hostile workload name inert, 404 page). **Not yet looked at in a real browser by a person.** |
| Kubernetes manifests | Parsed and checked by tests (exact RBAC, ConfigMap accepted by the config loader, ports match kind). **Not yet applied to a cluster.** |
| Multi-cluster: connecting a second real cluster, per-cluster detection and rollback, live charts against real pods | Unit-tested with simulated Kubernetes and a jsdom run; **not yet exercised against two real clusters**. |
| Docker images, kind cluster, real RBAC enforcement, in-cluster config, real Gemini calls | **Not yet exercised.** They need your machine. |
| Real end-to-end behaviour (v2/v3/v4 detection times, rollback recovery, MTTD/MTTR numbers) | **Not yet demonstrated.** Run `python scripts/e2e.py` and record the result below. |
>>>>>>> b07119a (Update IncidentIQ project)

Do not add timing measurements or claim additional scenarios passed unless you have the corresponding run output.

## Repository layout

<<<<<<< HEAD
```text
app/                  shop-api demo service (v1-v4) and Dockerfile
backend/              configuration, database, Kubernetes, detector, collector,
                      RCA, remediation, pipeline, and API
dashboard/            index.html, incident.html, style.css, app.js
k8s/                  deployment.yaml, rbac.yaml, backend.yaml, kind-config.yaml
scripts/              setup_cluster.sh, deploy_good.sh, deploy_bad.sh,
                      deploy_backend.sh, teardown.sh, e2e.py
tests/                pytest suite and dashboard_smoke/
docs/                 contracts.md, architecture.md, demo.md
backend.Dockerfile    backend image definition
requirements*.txt     Python dependencies
=======
```
app/                  shop-api demo service (v1-v4) + Dockerfile
backend/              config, db, kube, detector, collector, metrics, rca, remediation, pipeline, api
dashboard/            index.html (live multi-cluster view), incident.html, style.css, app.js (no build step)
k8s/                  deployment.yaml (shop-api), rbac.yaml, backend.yaml, kind-config.yaml
scripts/              setup_cluster.sh, deploy_good.sh, deploy_bad.sh, deploy_backend.sh, teardown.sh, e2e.py
tests/                pytest suite + dashboard_smoke/ (optional jsdom check)
docs/                 contracts.md (interfaces, source of truth), architecture.md, demo.md
backend.Dockerfile    backend image            requirements*.txt   dependencies
>>>>>>> b07119a (Update IncidentIQ project)
```

Further reading: [architecture](docs/architecture.md), [demo script](docs/demo.md), and [module contracts](docs/contracts.md).

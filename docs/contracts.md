# IncidentIQ Module Contracts

This document is the single source of truth for module interfaces and JSON
shapes. **Do not change a contract on your own branch** - propose the change to
the Backend Lead, update this file, and tell the other members.

Legend: **[implemented]** = exists in the repository and is covered by tests.
**[planned]** = agreed contract from the project specification, to be
implemented in the stage shown. Planned contracts are *not yet verified*.

---

## 1. `backend/config.py` [implemented - Stage 1]

```python
get_settings() -> Settings        # cached, process-wide
reload_settings() -> Settings     # discard cache and reload
reset_settings() -> None          # discard cache (used by tests)
setup_logging(settings=None)      # structured logs, secrets redacted
Settings.from_env(env=None)       # build + validate; raises ConfigError
```

`Settings` is a frozen dataclass. Secret fields are excluded from `repr`.

| Environment variable | Attribute | Default | Validation |
|---|---|---|---|
| `APP_NAME` | `app_name` | `IncidentIQ` | - |
| `APP_ENV` | `app_env` | `development` | `development` \| `test` \| `production` |
| `LOG_LEVEL` | `log_level` | `INFO` | standard level names, case-insensitive |
| `API_HOST` | `api_host` | `0.0.0.0` | - |
| `API_PORT` | `api_port` | `8000` | 1-65535 |
| `API_KEY` | `api_key` | random (dev only) | production: required, >= 32 chars, not a known weak value |
| `DATABASE_PATH` | `database_path` | `./data/incidentiq.db` | real file path; `:memory:` and `file:` URIs rejected |
| `GEMINI_API_KEY` | `gemini_api_key` | empty | optional; empty means fallback RCA |
| `GEMINI_MODEL` | `gemini_model` | `gemini-2.5-flash` | - |
| `GEMINI_TIMEOUT_SECONDS`* | `gemini_timeout_seconds` | `30` | 1-300 |
| `KUBERNETES_NAMESPACE_ALLOWLIST` | `namespace_allowlist` | `default` | explicit RFC 1123 names; wildcards rejected |
| `DETECTOR_INTERVAL_SECONDS` | `detector_interval_seconds` | `10` | 1-3600 |
| `METRICS_INTERVAL_SECONDS`* | `metrics_interval_seconds` | `5` | 2-300 |
| `UNHEALTHY_POD_GRACE_SECONDS` | `unhealthy_pod_grace_seconds` | `30` | 0-86400 |
| `AUTO_REMEDIATE` | `auto_remediate` | `false` | boolean |
| `ROLLBACK_MODE` | `rollback_mode` | `python` | `python` \| `kubectl` |
| `MAX_REMEDIATION_ATTEMPTS` | `max_remediation_attempts` | `2` | 1-2 (hard project cap) |
| `SCALE_TARGET_REPLICAS`* | `scale_target_replicas` | `2` | 1-10 |
| `VERIFICATION_TIMEOUT_SECONDS` | `verification_timeout_seconds` | `120` | 1-3600 |
| `VERIFICATION_INTERVAL_SECONDS` | `verification_interval_seconds` | `5` | 1-300, <= timeout |
| `INCIDENT_COOLDOWN_SECONDS` | `incident_cooldown_seconds` | `60` | 0-86400 |
| `INJECTION_MAX_AGE_SECONDS`* | `injection_max_age_seconds` | `600` | 1-86400 |

\* Not in the original variable list. Added because the specification requires a
Gemini call timeout and a "configured target" for the `scale` action, and (Stage 5)
a rule for when a recorded failure injection is too old to attach to an incident.

Helpers: `settings.is_namespace_allowed(ns)`, `settings.gemini_enabled`,
`settings.is_production`, `settings.redacted()`.

---

## 2. `backend/db.py` [implemented - Stage 1]

### Tables

`incidents`: `id, service, namespace, reason, status, detected_at, resolved_at,
injected_at, evidence_json, rca_json, action, remediation_attempts`

`timeline`: `id, incident_id (FK -> incidents.id, ON DELETE CASCADE), step,
message, timestamp`

Two deliberate details:

* `remediation_attempts` is an addition to the specified columns. It stores the
  per-incident attempt counter so the limit survives repeated function calls.
* `action` is the **action actually executed**. The *recommended* action lives
  inside `rca_json.recommended_action`.

### Statuses

`DETECTED`, `ANALYZING`, `AWAITING_APPROVAL`, `REMEDIATING`, `VERIFYING`,
`RESOLVED`, `FAILED`.
Open = every status except `RESOLVED` and `FAILED`.
Enforced both in Python and by a SQL `CHECK` constraint.

### Functions

| Function | Returns | Notes |
|---|---|---|
| `init_db()` | `None` | Idempotent. Creates parent directory, tables, indexes. |
| `create_incident(service, namespace, reason)` | `int` | Status `DETECTED`, `detected_at` = now (UTC). Over-long `reason` is truncated. |
| `update_incident(id, **fields)` | `None` | Allowed: `reason, status, resolved_at, injected_at, evidence_json, rca_json, action`. `ValueError` for unknown field, bad status/action/timestamp/JSON. `IncidentNotFoundError` if missing. Setting `status="RESOLVED"` without `resolved_at` stamps now. |
| `add_timeline(id, step, message)` | `None` | Timestamp added automatically. `IncidentNotFoundError` if missing. |
| `list_incidents()` | `list[dict]` | Newest first. **Summary** shape (below). |
| `get_incident(id)` | `dict \| None` | `None` if missing (API maps this to 404). Full shape (below). |
| `get_metrics()` | `dict` | Shape below. |
| `find_open_incident(service, namespace)` | `dict \| None` | Summary of newest open incident. Used for duplicate prevention. |
| `get_last_closed_at(service, namespace)` | `str \| None` | Latest `RESOLVED`/`FAILED` closure time. Used for cooldown. |
| `increment_remediation_attempts(id)` | `int` | Atomic; returns the new total. |

`evidence_json` / `rca_json` accept Python objects (serialised for you) or an
already-serialised JSON string (validated), or `None`.

### Stage 5 additions to `db.py`

A third table, `injections(id, service, namespace, injected_at, consumed_by_incident,
consumed_at)`, stores failure-injection timestamps until an incident claims them.

| Function | Returns | Notes |
|---|---|---|
| `transition_status(id, expected, new)` | `bool` | Atomic compare-and-set. `True` only for the single caller that performed the change; used so concurrent approvals run once. Moving to `RESOLVED` stamps `resolved_at`. |
| `list_incidents_with_status(statuses)` | `list[dict]` | Summaries, oldest first. Used for startup recovery. |
| `record_injection(service, namespace)` | `str` | Stores "now" (UTC); returns the timestamp. |
| `claim_injection(incident_id, max_age_seconds)` | `str \| None` | Attaches the newest eligible injection to the incident (`incidents.injected_at`). Eligible = unconsumed, same service/namespace, recorded **before** detection, at most `max_age_seconds` old. Every unconsumed injection recorded before detection is consumed, so stale ones can never attach to a later incident. Injections recorded after detection are left for the next incident. |

### Incident summary (`list_incidents`, `find_open_incident`)

```json
{
  "id": 1, "service": "shop-api", "namespace": "default",
  "reason": "CrashLoopBackOff", "status": "RESOLVED",
  "detected_at": "2026-10-09T09:34:01.339876+00:00",
  "resolved_at": "2026-10-09T09:35:10.100000+00:00",
  "injected_at": "2026-10-09T09:33:50.000000+00:00",
  "action": "rollback", "remediation_attempts": 1,
  "mttd_seconds": 11.34, "mttr_seconds": 68.76
}
```

### Incident detail (`get_incident`)

Everything in the summary, plus:

```json
{
  "evidence": { "...": "parsed evidence object, or null" },
  "rca": { "...": "parsed RCA object, or null" },
  "timeline": [
    {"id": 1, "step": "DETECTED", "message": "...", "timestamp": "2026-10-09T09:34:01.341322+00:00"}
  ]
}
```

Timeline is ordered oldest to newest. If stored JSON is corrupt, `evidence` /
`rca` is `null` and a warning is logged; the incident is still returned.

### Metrics (`get_metrics`)

```json
{"total": 5, "resolved": 3, "avg_mttd_seconds": 23.333, "avg_mttr_seconds": 60.0}
```

* **MTTD** = `detected_at - injected_at`; **MTTR** = `resolved_at - detected_at`
  (only for `RESOLVED` incidents).
* Unavailable (missing timestamp) and negative durations are `None` per
  incident and are **excluded** from averages. Averages are `None` when no
  incident qualifies.
* MTTR is only computed for `RESOLVED` incidents, so `FAILED` incidents can never distort it.

### Timestamps

All stored as `YYYY-MM-DDTHH:MM:SS.ffffff+00:00` (UTC). Inputs accepting a
timestamp take a `datetime` or ISO 8601 string (`Z` suffix allowed; naive values
are treated as UTC) and are normalised.

---

## 3. `backend/detector.py` [implemented - Stage 3]

```python
check_cluster() -> list[dict]
# [{"service": "shop-api", "namespace": "default", "reason": "CrashLoopBackOff"}]
```

Exactly three keys per issue, one issue per affected Deployment (never per pod),
sorted by namespace then service. Pods are mapped Pod -> ReplicaSet -> Deployment
through owner references; pods with no Deployment owner are ignored. Only
namespaces in `KUBERNETES_NAMESPACE_ALLOWLIST` are inspected.

`reason` is one of the following, strongest first (the first one found among a
Deployment's pods is reported):

| reason | Trigger |
|---|---|
| `OOMKilled` | container termination reason (current or last) is `OOMKilled` |
| `CrashLoopBackOff` | container waiting reason |
| `ImagePullBackOff` | container waiting reason |
| `ErrImagePull` | container waiting reason |
| `HighRestartCount` | container restart count >= 3 |
| `NotReady` | pod Ready=False for longer than `UNHEALTHY_POD_GRACE_SECONDS` |

Deliberate refinements: terminating pods (`deletionTimestamp`) and `Succeeded`
pods are ignored; `OOMKilled` and `HighRestartCount` are *history* that
Kubernetes keeps until the next restart, so on a container that is currently
**ready** they only count if the last termination was within 10 minutes. This
stops a recovered service being re-detected forever.

Never raises: a missing kubeconfig, API error, timeout or connection failure is
logged and the namespace is retried on the next poll (returns `[]` if nothing
could be determined). The detector *loop* (interval, threads, shutdown) is `pipeline.DetectorLoop` (Stage 5).

## 4. `backend/collector.py` [implemented - Stage 3]

```python
collect_evidence(namespace, service) -> dict
```

Exactly these top-level keys, always present, JSON-serialisable:

| Key | Shape |
|---|---|
| `logs` | `[{"pod","container","source": "previous"\|"current"\|"none","lines": [str, ...<=50],"error": str\|null}]` - crashed containers try `previous` first, then fall back to `current`; at most 6 pods (unhealthy first); lines truncated to 500 chars; configured secrets redacted |
| `events` | `[{"type","reason","message","involved_object": "Kind/name","count","timestamp"}]` - Deployment, its ReplicaSets and pods only; newest 30, oldest first |
| `pods` | `[{"name","phase","ready","created","terminating","containers": [{"name","image","ready","state","waiting_reason","terminated_reason","restart_count","last_termination_reason","last_exit_code"}]}]` |
| `last_deploy_time` | ISO 8601 UTC string or `null`. Time the Deployment was last **changed** (newest `managedFields` write that is not a status update; fallbacks: Progressing condition, current-revision ReplicaSet). Never the observation time. |
| `rollout_history` | `[{"name","revision","is_current","images","created","desired_replicas","replicas","ready_replicas","available_replicas","change_cause","pod_template": {"containers": [{"name","image","env_var_names","resource_requests","resource_limits"}]}}]`, newest revision first. Env var **names only**, never values. |

A failure in one part is logged and leaves that part empty (`[]` / `null`); for
logs the failure is recorded in the entry's `error` field. Nothing raises for
Kubernetes problems.

## 4b. `backend/kube.py` [implemented - Stage 3]

Shared client setup used by the detector, collector and (Stage 4) remediation.
`core_v1()`, `apps_v1()` return cached clients; `ensure_configured()` tries
in-cluster config, then kubeconfig (context from `KUBE_CONTEXT` if set) and raises
`KubeConfigError` on failure (not cached, so it retries on the next call).
`REQUEST_TIMEOUT_SECONDS = 10` applies to every API call. Tests monkeypatch
`kube.core_v1` / `kube.apps_v1`, so always call them as `kube.core_v1()`.

### RBAC needed by Stage 3 (for `k8s/rbac.yaml`, Stage 7)

| Resource | Verbs | Used by |
|---|---|---|
| `pods` | `get, list` | detector, collector |
| `pods/log` | `get` | collector |
| `events` | `get, list` | collector |
| `replicasets` (apps) | `get, list` | detector (ownership), collector |
| `deployments` (apps) | `get, list` | collector |

---

## 5. `backend/rca.py` [implemented - Stage 4]

```python
analyze(evidence: dict) -> dict      # never raises
```

```json
{
  "probable_cause": "string",
  "evidence": ["verbatim line from the collected evidence", "..."],
  "confidence": 0.0,
  "recommended_action": "rollback | restart | scale",
  "source": "llm | fallback"
}
```

* The prompt starts with the exact SRE instruction from the spec, then
  `EVIDENCE (JSON):` and the evidence (shrunk if over 40,000 characters).
* Gemini is called with `response_mime_type="application/json"`, a response
  schema (action restricted to the three allowed values), `temperature=0`, model
  `GEMINI_MODEL` and timeout `GEMINI_TIMEOUT_SECONDS`.
* Markdown fences are stripped, the reply is parsed with `json.loads` and
  validated strictly: `probable_cause` non-empty string, `evidence` list of
  strings, `confidence` a finite number in [0, 1] (booleans rejected),
  `recommended_action` exactly one of the three (no case/whitespace leniency).
  Unknown extra keys are dropped.
* **Evidence grounding:** every quoted line must exist in the collected logs /
  events / pod reasons (case and whitespace tolerant). Invented lines are
  dropped; if ALL quoted lines are invented the reply is rejected.
* **Fallback** (no key, API error, empty/invalid JSON, validation failure):
  `rollback` if `last_deploy_time` is within the last 10 minutes (a timestamp
  more than 5 minutes in the future is not trusted), otherwise `restart`;
  unknown or unparseable deploy time means `restart`. `source` is `"fallback"`,
  confidence is a fixed 0.4 (rollback) or 0.3 (restart), `probable_cause` says
  why AI analysis was unavailable, and `evidence` holds up to 3 verbatim error
  lines from the real logs (never invented). Secrets are redacted from the reason.
* A model answer is only a recommendation. It is never executed directly.

## 6. `backend/remediation.py` [implemented - Stage 4]

```python
execute(action, namespace, service, *, incident_id=None, approved=False)
    -> {"success": bool, "detail": str}                  # never raises
verify(namespace, service, timeout=None) -> bool          # None = VERIFICATION_TIMEOUT_SECONDS
verify_with_detail(namespace, service, timeout=None) -> (bool, str)
```

`incident_id` and `approved` are optional keyword-only extras; the three-argument
contract form still works. Without `incident_id`, the OPEN incident for the
service and namespace is used. `verify_with_detail` returns a human-readable
reason that the pipeline should put in the timeline.

**Guardrails** (checked in this order, before any cluster call; a refusal returns
`success: false`, `detail` starting with `Refused:`, and does NOT use an attempt):
action allow-list (exact match) -> namespace allow-list -> valid Kubernetes
object name -> approval (`approved=True` required unless `AUTO_REMEDIATE=true`) ->
open incident exists, matches service/namespace and is not terminal -> attempt
limit (`incidents.remediation_attempts` in SQLite vs `MAX_REMEDIATION_ATTEMPTS`) ->
a second `rollback` for one incident is refused (a rollback creates a new
revision, so repeating it would redeploy the bad version).
**Stage 5 must set `incidents.action` to the executed action** so the repeat guard
works, and must pass `approved=True` only from the authenticated approve endpoint.

| Action | Behaviour |
|---|---|
| `rollback` | `ROLLBACK_MODE=python`: previous revision = newest ReplicaSet with a revision number BELOW the Deployment's current revision (the failing one is never chosen). JSON-patch `replace /spec/template` with that template minus the controller-managed `pod-template-hash` label, guarded by a `test` op on the current revision annotation. `ROLLBACK_MODE=kubectl`: `kubectl [--context $KUBE_CONTEXT] --namespace NS rollout undo deployment/NAME` as an argument list (no shell), 60 s timeout, exit code checked. |
| `restart` | merge-patch of `spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]` |
| `scale` | merge-patch `spec.replicas` to `SCALE_TARGET_REPLICAS` (1-10); no write if already equal |

**`verify`** polls every `VERIFICATION_INTERVAL_SECONDS` until the timeout and
returns `True` only if ALL hold: spec replicas >= 1; controller has observed the
latest generation; `updatedReplicas == readyReplicas == availableReplicas ==`
desired; no extra old replicas; exactly the desired number of non-terminating pods
owned by the Deployment, each `Running` with Ready=True. It fails immediately (no
waiting) if the Deployment is missing (404), access is denied (401/403) or
Kubernetes is not configured; transient API errors are retried until the timeout.
Never mark an incident RESOLVED merely because `execute` succeeded.

### RBAC needed by Stage 4 (for `k8s/rbac.yaml`, Stage 7)

| Resource | Verbs | Used by |
|---|---|---|
| `deployments` (apps) | `get, list, patch` | rollback, restart, scale (patch); verify (get) |
| `replicasets` (apps) | `get, list` | rollback (find previous revision), verify |
| `pods` | `get, list` | verify |

`kubectl rollout undo` (kubectl mode) needs the same permissions. Scale uses a
Deployment patch, so `deployments/scale` is not required.

---

## 7. `backend/pipeline.py` [implemented - Stage 5]

```python
handle_incident(issue: dict) -> None                  # never raises
approve_incident(incident_id, *, background=True) -> dict
recover_interrupted_incidents() -> int                # call once at startup
join_workers(timeout=10) -> bool                      # shutdown / tests
skip_reason(service, namespace) -> str | None         # why a new incident must not be created
class DetectorLoop: start() / stop() / run_once() / status() / running
class ApprovalError(Exception): .kind in {"not_found", "conflict", "invalid"}
```

**Lifecycle** (every step is a timeline entry; `step` is the status name):
`DETECTED -> ANALYZING -> AWAITING_APPROVAL -> REMEDIATING -> VERIFYING -> RESOLVED | FAILED`
(with `AUTO_REMEDIATE=true` the approval wait is skipped).

1. Create the incident (atomic check: no open incident for the service, cooldown elapsed).
2. Claim a matching failure injection (sets `injected_at`, so MTTD works) and log `DETECTED`.
3. `ANALYZING`: `collector.collect_evidence` (a failure degrades to empty evidence, it never aborts), save `evidence_json`, run `rca.analyze` (garbage or an exception falls back to `rca.fallback_analysis`), save `rca_json`.
4. A recommended action outside `rollback|restart|scale` ends in `FAILED`; nothing is executed.
5. `AUTO_REMEDIATE=false`: status `AWAITING_APPROVAL` and stop. Otherwise continue.
6. `REMEDIATING`: **one** `remediation.execute` call. `incidents.action` is set to the action attempted (when it succeeded or consumed an attempt; pure refusals are not recorded).
7. A refusal or failure ends in `FAILED` (verification is skipped).
8. `VERIFYING`: `remediation.verify_with_detail`. `RESOLVED` (with `resolved_at`) **only** if it returns `True`; otherwise `FAILED` with the verification detail.

**Rules**: at most one open incident per service and namespace; a cooldown
(`INCIDENT_COOLDOWN_SECONDS`) applies after an incident closes, **whether RESOLVED or
FAILED**; namespaces outside the allow-list and malformed issues are ignored;
`approved=True` is passed to `execute` only from `approve_incident`.

**`approve_incident`** validates the incident exists (`not_found`), is
`AWAITING_APPROVAL` (`conflict`), has a valid stored recommendation in an allow-listed
namespace (`invalid`), then performs the compare-and-set to `REMEDIATING` (the loser of a
race gets `conflict`). Only the **stored** recommendation runs; the request cannot choose
the action. With `background=True` (the API) it returns immediately and a tracked worker
runs remediation and verification.

**`DetectorLoop`**: polls `detector.check_cluster()` every `DETECTOR_INTERVAL_SECONDS`.
Per service it starts a worker only if none is in flight, no incident is open and the
cooldown has passed; at most 4 workers overall, so repeated polls of a broken service
never spawn unbounded threads. `stop()` wakes the waiting loop immediately.

**Startup recovery**: incidents left in `DETECTED`, `ANALYZING`, `REMEDIATING` or `VERIFYING`
by a previous process are marked `FAILED` ("interrupted by a backend restart").
`AWAITING_APPROVAL` incidents are kept.

## 8. `backend/api.py` [implemented - Stage 5]

Start: `python -m uvicorn backend.api:app --port 8000` (**single worker**: the detector
loop lives in the process) or `python -m backend.api` (uses `API_HOST`/`API_PORT`).
`create_app(start_detector=True, dashboard_dir=None, configure_logging=True)` is the factory.

| Method and path | Auth | Success | Errors |
|---|---|---|---|
| `GET /api/incidents` | none | 200 list of summaries, newest first | |
| `GET /api/incidents/{id}` | none | 200 incident with `evidence`, `rca`, `timeline` | 404 missing; 422 non-integer, `< 1` or beyond 64-bit |
| `GET /api/metrics` | none | 200 `total, resolved, avg_mttd_seconds, avg_mttr_seconds` | |
| `GET /api/status` | none | 200 (shape below) | |
| `POST /api/incidents/{id}/approve` | API key | **202** `{"id","status":"REMEDIATING","action","approved":true}` | 401; 404 missing; 409 not `AWAITING_APPROVAL` or already approved; 422 no valid recommendation |
| `POST /api/injection` | API key | **201** `{"service","namespace","injected_at"}` | 401; 403 namespace not allow-listed; 422 invalid body |
| `GET /healthz` | none | 200 `{"status":"ok","detector_running":bool}` | |
| `GET /` | none | dashboard `index.html` | 404 JSON if the file is missing |
| `GET /incidents/{id}` | none | dashboard `incident.html` | 404 JSON if the file is missing |
| `GET /static/*` | none | files from `dashboard/` | 404 |

**Authentication**: header `X-API-Key`, constant-time comparison, `401` with
`WWW-Authenticate: ApiKey`. It is checked **before** the incident lookup and body
validation, so callers without the key learn nothing. A key in the query string is not
accepted. The key is never logged or echoed (validation errors report only `loc` and `msg`,
never the submitted values).

**`POST /api/injection`** body is exactly what `scripts/deploy_bad.sh` sends:
`{"service":"shop-api","namespace":"default"}` (Kubernetes-name patterns enforced; unknown
extra fields are ignored). *Verified end to end: the real `scripts/deploy_bad.sh` was run against a live uvicorn process (Kubernetes simulated) and got 401 for a wrong key, 201 for the right one, and parsed a CRLF `.env`.*

**`GET /api/status`** (for the dashboard cluster-status card and mode badges):

```json
{"app":"IncidentIQ","environment":"development","auto_remediate":false,
 "rollback_mode":"python","max_remediation_attempts":2,"namespaces":["default"],
 "gemini_enabled":false,
 "detector":{"running":true,"interval_seconds":10.0,"last_poll_at":"...","last_poll_issue_count":0,"in_flight":[]},
 "kubernetes":{"state":"connected","checked_at":"..."}}
```

`kubernetes.state` is `connected`, `not_configured`, `forbidden` (HTTP 401/403),
`unreachable` or `error`. It is a cached (10 s) `list pods limit=1` in the first
allow-listed namespace, so it needs no RBAC beyond what Stage 3 already requires.

**Dashboard contract for Stage 6**: pages are `dashboard/index.html` and
`dashboard/incident.html`; assets are referenced as `/static/app.js` and
`/static/style.css`. HTML responses carry
`Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; ...`,
so the pages must use **no inline `<script>`, no inline `style=` attributes and no external
hosts or fonts**. Every response has `X-Content-Type-Options: nosniff` and
`X-Frame-Options: DENY`; `/api/*` responses are `Cache-Control: no-store`. Interactive docs
(`/docs`) are disabled when `APP_ENV=production`.

The read endpoints are unauthenticated in this local demo and expose incident evidence
(logs); see the security notes in the README (Stage 8).

---

## 9. Demo application `app/main.py` [implemented - Stage 2]

Image tags `shop-api:v1` ... `shop-api:v4`, built from one Dockerfile with
`--build-arg APP_VERSION=vN` (baked in as the `APP_VERSION` env var). The
Deployment only ever changes the **image tag**, so a rollback restores a previous
ReplicaSet cleanly.

| Version | Behaviour | Expected Kubernetes symptom | Log evidence |
|---|---|---|---|
| v1 | `/` and `/health` return 200 | Running + Ready | startup line |
| v2 | startup raises `Exception("DB_URL missing")` when `DB_URL` is unset | `CrashLoopBackOff`, restart count grows | `CRITICAL ... DB_URL is not set`, traceback ending `Exception: DB_URL missing` |
| v3 | `/` returns 200, `/health` returns 500 | Running, never Ready (not restarted: liveness uses `/`) | `Health check failing on purpose` |
| v4 | allocates `MEM_STEP_MB` (10) every `MEM_INTERVAL_SECONDS` (1) | `OOMKilled` at the 128Mi limit | `Allocated N MB so far` |

v4 refuses to allocate unless a container memory limit is detected (or
`ALLOW_UNBOUNDED_MEMORY=true` is set for a throwaway test) and never exceeds
`MEM_MAX_MB` (512).

Workload identity used by the detector, collector and remediation: Deployment
`shop-api`, label `app=shop-api`, container `shop-api`, namespace `default`,
2 replicas, `revisionHistoryLimit: 5` (rollback needs the previous ReplicaSet).

## 10. Scripts [implemented - Stage 2]

| Script | Contract |
|---|---|
| `scripts/setup_cluster.sh` | Idempotent. Creates kind cluster `incidentiq` (context `kind-incidentiq`), builds and loads v1-v4, deploys v1, creates `.venv`, creates `.env` from `.env.example` and generates a stable `API_KEY` if blank. |
| `scripts/deploy_good.sh` | Applies `k8s/deployment.yaml`; exits non-zero unless 2/2 replicas are ready. |
| `scripts/deploy_bad.sh v2\|v3\|v4` | 1) `POST $BACKEND_URL/api/injection` with header `X-API-Key` and body `{"service":"shop-api","namespace":"default"}`; any non-2xx aborts **before** the image is changed (unless `ALLOW_NO_INJECTION=true`). 2) `kubectl set image`. 3) waits for the expected symptom and says so honestly if it is not seen. |

All scripts pin `kubectl --context kind-incidentiq`. The API key is read from
`INCIDENTIQ_API_KEY` or `API_KEY` in `.env`, never printed, and passed to curl on
stdin. **Stage 5 must accept exactly the header and body above on
`POST /api/injection` and respond 2xx on success.**

---

## 11. Dashboard `dashboard/` [implemented - Stage 6]

Files: `index.html` (incident list + metric cards), `incident.html` (detail), `style.css`, `app.js`.
Served by the API at `/`, `/incidents/{id}` and `/static/*`; it obeys the CSP in section 8 (no inline
script/style, no external hosts, no `innerHTML`: all API text is written with `textContent`).

| Page | Reads (every 3 s, never overlapping; paused while the tab is hidden) | Shows |
|---|---|---|
| `/` | `GET /api/metrics`, `/api/incidents`, `/api/status` | total, resolved, avg MTTD, avg MTTR; table of incidents; status chips (cluster, detector, approval mode, Gemini/fallback, rollback mode) |
| `/incidents/{id}` | `GET /api/incidents/{id}`, `/api/status` | summary, diagnosis (cause, confidence, `llm`/`fallback` badge, quoted evidence, recommended action), executed action and attempts, timeline, collapsible evidence (pods, logs, events, rollout history) |

* **Approval:** the panel is shown only while `status == AWAITING_APPROVAL`. The operator types the API key
  (password field), a confirm dialog names the action, then `POST /api/incidents/{id}/approve` is sent with
  `X-API-Key`. The key is kept in `sessionStorage` (this tab only) after a successful approval, removed on a 401,
  and never placed in a URL. 401/409/422/network errors each have their own message.
* **Missing values** (`mttd_seconds`/`mttr_seconds` = `null`) display an en dash, never `0`.
* **States:** loading, empty ("No incidents yet"), API error (banner, keeps last data and keeps retrying),
  unknown incident (404 message, polling stops). Closed incidents poll every 15 s.
* Tests: `tests/test_dashboard.py` (CSP/structure, ids the script uses, served headers) and the optional
  browser-level check `tests/dashboard_smoke/run.sh` (jsdom, real backend, seeded data, hostile log line, approval flow).

## 12. Kubernetes deployment of the backend [implemented - Stage 7]

| File | Contents |
|---|---|
| `backend.Dockerfile`, `.dockerignore`, `requirements-backend.txt` | Image `incidentiq-backend:local`: non-root UID 10001, single uvicorn worker, runtime dependencies only. `--build-arg INSTALL_KUBECTL=true` adds a checksum-verified kubectl for `ROLLBACK_MODE=kubectl`. `requirements.txt` = runtime + test packages. |
| `k8s/rbac.yaml` | Namespace `incidentiq`, ServiceAccount `incidentiq-backend`, **Role + RoleBinding in the monitored namespace `default`** (no ClusterRole). Rules are exactly the RBAC tables in sections 4b and 6: pods get/list, pods/log get, events get/list, replicasets get/list, deployments get/list/patch. No Secrets, no create/delete. |
| `k8s/backend.yaml` | ConfigMap `incidentiq-config` (all non-secret settings, `APP_ENV=production`, `AUTO_REMEDIATE=false`), Deployment (**1 replica, `Recreate`**, read-only root filesystem, emptyDir `/data` and `/tmp`, `/healthz` probes), NodePort Service 30080. |
| Secret `incidentiq-secrets` | **Not in git.** `scripts/deploy_backend.sh` builds it from `.env` (`API_KEY`, `GEMINI_API_KEY`) through a private temp file. |
| `scripts/deploy_backend.sh` | build, `kind load`, apply RBAC, apply Secret, apply manifest, restart, wait for rollout; refuses an `API_KEY` under 32 characters. |
| `scripts/teardown.sh` | deletes the kind cluster (asks first, `--yes` to skip). |

The dashboard is at `http://localhost:8080` (kind maps host `127.0.0.1:8080` to NodePort 30080). When the backend
runs in the cluster, `deploy_bad.sh` needs `BACKEND_URL=http://localhost:8080`.
Why one replica: each pod owns a detector loop and its own SQLite file; two pods would both handle every incident.
Tests: `tests/test_manifests.py` (RBAC is the exact least-privilege set, no committed secrets, the ConfigMap is
accepted by `Settings.from_env`, NodePort matches kind, Dockerfile matches the pod spec).

## 13. End-to-end runner `scripts/e2e.py` [implemented - Stage 8]

```
python scripts/e2e.py [--scenario v2|v3|v4 ...] [--backend-url URL] [--no-approve] [--no-restore]
                      [--detect-timeout S] [--resolve-timeout S] [--cooldown-wait S]
```

Per scenario: require no open incident, `deploy_good.sh`, `deploy_bad.sh vN` (records the injection first), wait for
exactly one new incident, check the stored evidence keys and RCA fields (`probable_cause`, `confidence` in [0,1],
`recommended_action` in the allow-list, `source` in `llm|fallback`), approve through the API (unless
`AUTO_REMEDIATE=true`), wait for `RESOLVED`, check the timeline has DETECTED/ANALYZING/REMEDIATING/VERIFYING/RESOLVED
and that MTTD and MTTR are real numbers, then restore v1. Prints a table and exits non-zero on any failure.
`--no-approve` runs only the first scenario and leaves the incident at the approval gate (and the bad version
deployed) so it can be approved in the dashboard. A detector reason different from the expected one is a note, not a failure.
Tests: `tests/test_e2e_runner.py` (scripted fake backend; proves the runner fails on bad runs, not that a cluster behaves).

## 14. Multi-cluster live dashboard [implemented]

**Model.** `clusters` table (`id`, `name`, `context`, `is_default`, `state`, `state_detail`, `created_at`,
`last_sample_at`, `snapshot_json`) and `cluster_samples` (one row per cluster per `METRICS_INTERVAL_SECONDS`, newest 360 kept).
`incidents.cluster_id` (default `1`, added to existing databases automatically) says which cluster an incident belongs to.
Cluster `1` is the **built-in** cluster (in-cluster config, or `KUBE_CONTEXT`); it has `context = NULL` and cannot be deleted.
Only a kubeconfig **context name** is stored, never credentials.

**Routing.** `kube.use_cluster(context)` is a context manager (backed by a `ContextVar`) that makes `kube.core_v1()` /
`kube.apps_v1()` return clients for that kubeconfig context in the current thread. The detector loop wraps every
`check_cluster()` in it and tags each issue with `cluster_id`; `pipeline.handle_incident` and `approve_incident` run the whole
lifecycle (evidence, remediation, verification) inside it, so an incident can only ever act on the cluster it was detected in.
Open-incident and cooldown checks are per cluster. All existing guardrails (allow-listed namespaces, two attempts, approval)
apply unchanged to every cluster.

**`backend/metrics.py`.** `MetricsSampler` samples every cluster in its own thread (read-only: list pods, deployments and
events, read pod logs) and stores counts only: pods total/ready/unhealthy, restarts, warning events in the last minute,
log lines and error-looking lines since the previous sample. Log text is never stored. CPU/memory are not sampled
(they need metrics-server). A failing cluster is marked `unreachable`, `forbidden` or `not_configured` and retried.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/clusters` | none | every cluster with `latest`, `series` (last 60 samples; log and error rates are per minute), `workloads`, `open_incidents`, `can_delete`, `delete_blocked_reason` |
| `GET /api/activity?limit=` | none | newest incident timeline entries across all clusters (1-200) |
| `GET /api/kube/contexts` | API key | context names in the backend's kubeconfig, with `active` and `connected` flags |
| `POST /api/clusters` | API key | body `{name, context}`; the context must exist and answer a pod list, otherwise `400`; duplicates `409`; success `201` |
| `DELETE /api/clusters/{id}` | API key | `404` unknown, `403` built-in cluster, `409` while the cluster has an open incident; incident history is kept |

**Dashboard.** Order on `index.html`: monitored-clusters row (clusters without an open incident), the "active incident" box
(clusters with one), KPI cards, live analytics (six charts, cluster selector, rising/falling arrows), incident analytics (status
donut, MTTD/MTTR bars, detector reasons), workloads, activity feed, incident table with a cluster column. Charts are inline SVG built
with `createElementNS`; the CSP and the "no `innerHTML`, no style attributes" rules still hold.

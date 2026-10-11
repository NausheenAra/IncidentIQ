# IncidentIQ demo script

About 10 minutes for v2 alone. Rehearse once on a clean cluster first, and write the numbers you actually observed
into the results table in the README. Do not quote timings you have not measured.

## Before the audience arrives

1. `scripts/setup_cluster.sh` then `scripts/deploy_backend.sh` (do this the day before; it builds four images and the backend).
2. Open `http://localhost:8080` and confirm the chips read **Cluster: connected**, **Detector running**, **Approval required**
   (and **Gemini RCA** if you set a key).
3. `kubectl --context kind-incidentiq get pods` shows two `shop-api` pods `1/1 Running`.
4. Have two terminals ready: one for commands, one running
   `kubectl --context kind-incidentiq get pods -w` so the audience sees Kubernetes react.
5. If a previous run left an incident open or recent, wait out the 60 s cooldown (or start from a fresh cluster).

## The v2 story (crash loop)

| # | You do | They see | Say |
|---|---|---|---|
| 1 | Show the dashboard: empty list, four metric cards with dashes | "No incidents yet" | The dashes are deliberate: nothing measured yet, no fake zeros. |
| 2 | Show the architecture (`docs/architecture.md`) | | Detector, collector, diagnosis, guarded remediation, verifier, SQLite, dashboard. |
| 3 | `BACKEND_URL=http://localhost:8080 scripts/deploy_bad.sh v2` | The script records the injection time, then swaps the image | The injection time is what makes MTTD a real measurement. |
| 4 | Point at the pod watch | new pods go `CrashLoopBackOff` | Kubernetes alone just keeps retrying. |
| 5 | Dashboard: the incident row appears (status `DETECTED` then `ANALYZING`) | one incident, not one per pod | Detection is grouped per Deployment and suppresses duplicates. |
| 6 | Open the incident | Diagnosis, confidence, **AI diagnosis** or **Fallback heuristic** badge, quoted log lines | Every quoted line really exists in the collected logs; invented ones are rejected. |
| 7 | Expand **Collected evidence** | pods, last logs (`DB_URL missing`), events, rollout history | The model only sees this evidence. Logs are treated as untrusted. |
| 8 | Show the status `AWAITING APPROVAL` panel | "Nothing has been changed in the cluster yet." | Auto-remediation is off by default; a human approves. |
| 9 | Paste the API key, click **Approve remediation**, confirm | status moves to `REMEDIATING`, then `VERIFYING` | Only the stored recommendation runs, never one typed into the request. |
| 10 | Wait for `RESOLVED`; `kubectl get pods` shows `shop-api` healthy again | timeline with every step; MTTD and MTTR filled in | Resolved means the verifier saw every pod Running and Ready, not that the API call worked. |
| 11 | Explain the numbers | | MTTD = detection minus injection. MTTR = resolution minus detection. |

`python scripts/e2e.py --scenario v2` automates steps 3-11 and prints a PASS/FAIL table, useful as a dry run before the demo.

## If time permits

* **v3 (readiness failure):** `BACKEND_URL=http://localhost:8080 scripts/deploy_bad.sh v3`. Pods are `Running` but never `1/1`; the
  detector waits out the 30 s grace period before flagging `NotReady`.
* **v4 (OOM):** `... deploy_bad.sh v4`. The container allocates memory until it is `OOMKilled`; the evidence shows the termination reason.
* **Fallback path:** remove `GEMINI_API_KEY` from `.env`, run `scripts/deploy_backend.sh`, repeat v2. The badge reads
  **Fallback heuristic** and the confidence is a fixed 0.4 (rollback) or 0.3 (restart). This is what happens when the model is down.
* **Authentication:** `curl -i -X POST -H "X-API-Key: wrong" http://localhost:8080/api/injection` returns 401; writes need the key, reads do not.

## Reset between runs

```bash
scripts/deploy_good.sh          # healthy v1 again (an incident that is still open stays open until approved or restarted)
scripts/teardown.sh --yes && scripts/setup_cluster.sh && scripts/deploy_backend.sh   # full clean slate
```

Recreating the backend pod empties the database (emptyDir), which is the quickest way to clear the incident list before a demo:
`kubectl --context kind-incidentiq -n incidentiq rollout restart deployment/incidentiq-backend`.

## If something goes wrong on stage

Say what you see. The troubleshooting table in the README covers the likely causes; the most common are a stale open incident
(cooldown or still awaiting approval) and `BACKEND_URL` pointing at port 8000 instead of 8080.

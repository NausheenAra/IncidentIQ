"""Seed a throw-away database for the dashboard browser smoke test (see run.sh)."""
import os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB = os.environ["DATABASE_PATH"]  # run.sh sets this to a temp file
os.environ.update(APP_ENV="test", API_KEY="smoke-key-123", AUTO_REMEDIATE="false",
                  KUBERNETES_NAMESPACE_ALLOWLIST="default", DETECTOR_INTERVAL_SECONDS="3600")
if os.path.exists(DB):
    os.remove(DB)
sys.path.insert(0, str(ROOT))
from backend import db
db.init_db()
ev = {"logs":[{"pod":"shop-api-1","container":"shop-api","source":"previous","lines":["CRITICAL DB_URL is not set","<img src=x onerror=window.__pwned=1>","Exception: DB_URL missing"],"error":None}],
      "events":[{"type":"Warning","reason":"BackOff","message":"Back-off restarting failed container","involved_object":"Pod/shop-api-1","count":4,"timestamp":"2026-10-10T05:00:00+00:00"}],
      "pods":[{"name":"shop-api-1","phase":"Running","ready":False,"created":"x","terminating":False,"containers":[{"name":"shop-api","image":"shop-api:v2","ready":False,"state":"waiting","waiting_reason":"CrashLoopBackOff","terminated_reason":None,"restart_count":4,"last_termination_reason":"Error","last_exit_code":1}]}],
      "last_deploy_time":"2026-10-10T04:59:00+00:00",
      "rollout_history":[{"name":"shop-api-abc","revision":2,"is_current":True,"images":["shop-api:v2"],"created":"2026-10-10T04:59:00+00:00","desired_replicas":2,"replicas":2,"ready_replicas":0}]}
rca = {"probable_cause":"Missing DB_URL <b>bold</b>","evidence":["Exception: DB_URL missing"],"confidence":0.87,"recommended_action":"rollback","source":"llm"}
i1 = db.create_incident("shop-api","default","CrashLoopBackOff")
db.update_incident(i1, evidence_json=ev, rca_json=rca, status="AWAITING_APPROVAL")
db.add_timeline(i1,"DETECTED","Detected CrashLoopBackOff"); db.add_timeline(i1,"ANALYZING","Collected evidence"); db.add_timeline(i1,"AWAITING_APPROVAL","Waiting for approval")
i2 = db.create_incident("shop-api","default","NotReady")
db.update_incident(i2, injected_at="2026-10-10T04:00:00+00:00", status="RESOLVED", action="rollback")
db.add_timeline(i2,"RESOLVED","Recovery verified")

# --- multi-cluster data: the built-in cluster has the open incident above; "staging" is healthy
staging = db.create_cluster("staging", "kind-staging")
for cid, bad in ((db.DEFAULT_CLUSTER_ID, True), (staging, False)):
    for n in range(14):
        db.record_sample(cid, {"pods_total": 2, "pods_ready": 1 if bad and n > 6 else 2, "pods_unhealthy": 1 if bad and n > 6 else 0,
                               "restarts_total": (n // 3) if bad else 0, "warning_events": (n % 4) if bad else 0,
                               "log_lines": 20 + n * 3, "error_lines": (n * 2) if bad else 0, "interval_seconds": 5},
                         {"workloads": [{"name": "<img src=x onerror=window.__pwned=1>" if cid == staging else "shop-api", "namespace": "default",
                                         "desired": 2, "ready": 1 if bad else 2, "image": "shop-api:v1", "restarts": 3 if bad else 0,
                                         "problem": "CrashLoopBackOff" if bad else None, "status": "Degraded" if bad else "Healthy"}],
                          "namespaces": ["default"]})
db.set_cluster_state(db.DEFAULT_CLUSTER_ID, "connected")
db.set_cluster_state(staging, "connected")
print(i1, i2)

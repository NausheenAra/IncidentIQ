"""IncidentIQ backend package.

Modules:
    config       - centralised, validated configuration
    db           - SQLite persistence for incidents and timelines
    kube         - shared Kubernetes client configuration       (Stage 3)
    detector     - Kubernetes unhealthy-workload detection      (Stage 3)
    collector    - diagnostic evidence collection               (Stage 3)
    rca          - AI root-cause analysis with fallback         (Stage 4)
    remediation  - guarded remediation and verification         (Stage 4)
    pipeline     - incident lifecycle orchestration             (Stage 5)
    api          - FastAPI application and dashboard hosting    (Stage 5)
"""

# Audit Report: Routing Incident (2025-10-08)

## Summary
- Observed multiple 404 responses on `/status`, `/api/system-health`, and `/api/agents/*` across ports 5000 and 5001.
- Root cause: route registration mismatch due to multiple Flask instances running concurrently (5000 and 5001), and verification targeting the instance without the new routes.
- Impact: Agent registry remained empty; UI did not reflect agent features; audit temporarily missed early detection.

## Evidence
- See `ORCH/REPORTS/AGENTS_API_AUDIT.md` and `ORCH/REPORTS/agents_api_audit_summary.json` (Total checks: 11 | OK: 2 | Errors: 9).

## Corrective Actions (Implemented)
1. Stopped the 5001 development instance to avoid domain conflict and confusion.
2. Established a dedicated audit script: `scripts/ops/audit_endpoints.py` to perform endpoint checks and produce reports.

## Next Steps (Planned)
1. Unify serving on port 5000 and ensure a single authoritative app instance.
2. Fix routing registration for `/status`, `/api/system-health`, and `/api/agents/*` so they are present on the running instance.
3. Add CI job to run `audit_endpoints.py`; block merges on failures and send notifications.
4. Add Agent Management UI tab to enable in-UI smoke tests for agent APIs.

## Preventive Measures
- Enforce pre-deploy audit in CI.
- Output a routes list on startup (e.g., `/debug/routes`) to verify expected endpoints.
- Create UI snapshot before changes and maintain a rollback plan.

## Status
- Current: In progress.
- Owner: Orchestrator (Trae).
- Next audit: After routing fix and server unification.
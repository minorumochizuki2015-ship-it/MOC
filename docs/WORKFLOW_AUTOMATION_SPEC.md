Workflow Automation Specification (Phase 4)

Version: 0.1 (Draft)
Status: In Progress

Overview
- Purpose: Define a simple, safe, and observable workflow automation model for ORCH Phase 4.
- Scope: Workflow DSL, execution semantics, approval policies, integrations, security, observability, API surface, and acceptance criteria.

Goals
- Reliable execution with idempotency, retries, and timeouts.
- First-class approvals with SLA and escalation.
- Easy integration (Webhook/HTTP, Queue, IDP/ERP).
- Secure by default (JWT, RBAC), auditable, and observable.

Workflow DSL (YAML)
```yaml
workflow:
  id: wf_user_onboarding
  name: "User Onboarding"
  description: "Create ERP account, request approval, assign IDP role."
  triggers:
    - type: event
      name: user.created
    - type: http
      path: /api/workflows/wf_user_onboarding/trigger

  context:
    required:
      - user.id
      - user.email
    optional:
      - user.risk_score

  steps:
    - id: create_account
      action: http.request
      with:
        method: POST
        url: https://erp.example/api/accounts
        headers:
          Content-Type: application/json
        body:
          user_id: "${user.id}"
          email: "${user.email}"
      retry:
        max_attempts: 3
        backoff: exponential
        initial_delay_ms: 500
      timeout_ms: 5000

    - id: approval
      action: approval.request
      with:
        policy: level2
        sla: P2D # ISO-8601 duration: 2 days
        approvers:
          dynamic: "team.leads(${user.id})" # resolver function
      on_decision:
        approve:
          transition: next
        reject:
          transition: end
          result: failed

    - id: provision_access
      action: idp.assign_role
      condition:
        when: "${user.risk_score} < 0.7"
      with:
        role: VIEWER
      retry:
        max_attempts: 2
        backoff: fixed
        delay_ms: 1000

  completion:
    on_success:
      result: success
    on_failure:
      result: failed
```

Execution Semantics
- Deterministic state machine: pending → running → waiting_approval → running → success/failed.
- Idempotency: action keys form idempotency key; external calls include it to avoid duplicates.
- Retries: per-step policy (max_attempts, backoff = fixed|exponential, jitter optional).
- Timeouts: per-step timeout; global workflow timeout optional.
- Concurrency: per-workflow key; queueing with FIFO and optional parallel windows.
- Data binding: "${path}" resolves from context/result; undefined paths fail fast unless optional.

Approval Policies
- Levels: level1 (single approver), level2 (two independent), levelN (policy-driven).
- SLA: ISO-8601 durations; breach triggers escalation (notify, auto-escalate, or auto-approve if policy allows).
- Dynamic approvers: resolver functions (e.g., team.leads(user_id)); fallbacks on empty sets.
- Exceptions: explicit rejections, timeouts, invalid policies → workflow failed with audit trail.

Integrations
- HTTP/Webhook: signed requests with HMAC; include idempotency-key header.
- Queue: publish/subscribe with at-least-once delivery; dedupe by idempotency-key.
- IDP/ERP: provider adapters with typed actions (assign_role, create_account, etc.).
- Secrets: resolved via config/secrets with least privilege.

Security
- JWT verification: RS256/HS256; strict exp; iat skew allowance; role claim mapping per src/security.py.
- RBAC: API endpoints require roles (ADMIN for registration, OPERATOR for execution, VIEWER for read-only).
- Audit log: immutable append-only records for decisions and side-effects.

Observability
- Metrics (Prometheus):
  - orch_workflows_total{status}
  - orch_workflow_duration_seconds{workflow_id}
  - orch_approvals_total{decision}
- Logs: structured with workflow_id, step_id, correlation_id.
- Tracing: optional; span per step; correlation across external systems.

API Surface (initial)
- POST /api/workflows           # register/update workflows
- GET  /api/workflows/{id}      # get workflow definition/status
- POST /api/workflows/{id}/run  # execute workflow (trigger)
- POST /api/approvals/{id}/decision  # approve/reject with reason

Acceptance Criteria
- Unit/integration tests: happy path, retries, approvals (approve/reject), idempotency.
- Load test: p95 execution latency within target; zero unhandled exceptions under concurrency.
- Security: JWT/RBAC enforced; audit trail for all decisions and side-effects.
- Documentation: this spec + operator guide; examples and API reference.

Notes
- This document is a living spec; updates will be tracked under ORCH/STATE/CURRENT_MILESTONE.md.
- Initial implementation will focus on HTTP + approval + IDP role assignment.
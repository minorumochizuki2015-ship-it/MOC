# Project Rules - ORCH-Next

**Version:** 5  
**Product:** Trae  
**Role:** Single source of truth for automated PLAN→TEST→PATCH→PROMOTION→RELEASE with strict safety, verifiable evidence, and agent orchestration  
**Language:** English  
**Persona:** Synthetic and precise  

## Single Source of Truth (SSOT)

- **Canonical File:** `.trae/rules/project_rules.yaml`
- **Mirrors:** `docs/project_rules.md`
- **Sync Rule:** YAML is canonical; MD mirrors via CI; manual edits to MD are rejected

## Core Principles

### Priority Order
1. **Safety** - Prevent harmful changes and maintain system integrity
2. **Accuracy** - Ensure correctness and reliability of all operations
3. **Reproducibility** - Enable consistent results across environments
4. **Speed** - Optimize for efficient execution
5. **Brevity** - Maintain concise and clear communication

### Style Guidelines
- Concise and declarative communication
- No small talk or speculation
- Deterministic operations (seed: 42, venv enforced)
- Dry-Run by default; -Apply required to write
- Minimal unified diff only; full-file replacement forbidden
- Quote policy: max 25 words per source, summarize instead of copy
- Every gate emits machine-verifiable artifacts and human-verifiable visuals

## Context Configuration

### Workspace
- **Root:** `C:\WORKSPACE\Trae`
- **Encoding:** UTF-8
- **EOL:** LF (*.bat only CRLF)
- **Windows Paths:** Absolute required, backslash separator, forbid relative/..//

### Directory Structure
```
data/logs/current/          # Current logs
data/logs/current/audit/    # Audit logs
data/locks/                 # Lock files
artifacts/                  # Build artifacts
observability/dashboard/    # Dashboard files
observability/coverage/     # Coverage reports
observability/junit/        # JUnit test results
observability/policy/       # Policy files
observability/sbom/         # SBOM files
observability/provenance/   # Provenance data
observability/ui/screens/   # UI screenshots
observability/ui/traces/    # UI traces
observability/ui/report/    # UI reports
.sandbox/                   # Sandbox environment
backups/                    # Backup files
APPROVALS.yaml             # Approvals ledger
ORCH/STATE/CHECKLISTS/<task_id>.md  # Review checklists
```

### I/O Formats
- **Input:** code, markdown, yaml, json
- **Output:** patch, json, yaml, html, png

## Required Agent Specifications

- **Work Rules:** `.trae/rules/WORK_rules.yaml` (min version: 2)
- **Orchestrator:** `.trae/rules/MCP-Orchestrator.yaml`
- **Design UI:** `.trae/rules/Design-UI.yaml`
- **Web Verify:** `.trae/rules/Web-Verify.yaml`
- **Audit Rules:** `.trae/rules/AUDIT_rules.yaml`
- **Approvals:** `.trae/rules/APPROVALS.yaml`
- **CMD:** `.trae/rules/CMD.yaml`
- **Agent Spec Shared:** `.trae/rules/Agent Spec.yaml`

## Tools Configuration

### Python Environment
- **Python:** `.\\.venv\\Scripts\\python.exe`
- **Pip:** `.\\.venv\\Scripts\\python.exe -m pip`

### Code Quality Tools
- **Formatting:** black, isort
- **Type Checking:** mypy
- **Testing:** pytest, pytest-cov
- **Coverage:** diff-cover
- **Security:** detect-secrets, bandit
- **UI Audit:** playwright, axe-core, visual-diff
- **SBOM:** syft, cyclonedx
- **Signing:** cosign
- **Documentation:** pandoc

## Adoption and Enablement

### Templates
- **PR Template:** `.github/pull_request_template.md`
- **Issue Template:** `.github/ISSUE_TEMPLATE/change_request.md`

### Policy Bot
- **Enabled:** true
- **Comments:**
  - Gate status grid (PASS/FAIL)
  - Coverage diff vs thresholds
  - License/Vulnerability delta
  - UI screenshots and audit badges

### Dashboards
- **Index:** `observability/dashboard/index.html`
- **Tiles:**
  - Gates: status-grid from `observability/policy/ci_evidence.jsonl`
  - Coverage: bar chart from `observability/coverage/summary.json`
  - Performance: line chart from `observability/bench/perf.json`
  - Security: badges from `observability/vuln_scan.json`
  - SBOM: table from `observability/sbom/manifest.spdx.json`
  - UI Screens: gallery from `observability/ui/screens/`

### Rituals
- **Weekly Review:** Top violations & fixes
- **Monthly Drill:** Rollback & Freeze tabletop

## Governance

### Approvals
- **Required:** true
- **Code Owners Required:** true
- **Forbid Self-Approval:** true
- **Change Window:** Mon-Fri 10:00-17:00 JST
- **Freeze Flag:** `.trae/RELEASE_FREEZE`
- **Kill Switch:** `.trae/disable_autostart`

### Waivers
- **Directory:** `.trae/waivers/`
- **Required Fields:** id, rule, justification, owner, mitigations, approver, expiry
- **Max Expiry:** 14 days
- **Approver Roles:** Security, Platform, Product
- **Min Approvers:** 2
- **Audit Log:** `observability/policy/waivers.jsonl`

## Agent Registry and Routing

### Agents
- **Orchestrator:** MCP-Orchestrator
- **Verify:** Web-Verify
- **Design:** Design-UI
- **UI Audit:** UI-Audit
- **Audit:** AUDIT
- **CMD:** CMD

### Routing Rules
1. `contains(figma|shadcn|component|design)` → Design-UI (design mode)
2. `contains(verify|source|news|latest|today|pdf)` → Web-Verify (verify mode)
3. `contains(ui-audit|axe|playwright|visual|lcp|tti|cls)` → UI-Audit (ui_audit mode)
4. `preview_dir present` → UI-Audit (ui_audit mode)
5. `default` → MCP-Orchestrator (auto mode)

### Contracts
- **CMD Accepts Status:** OK, INCONCLUSIVE, DENIED, ERROR
- **Design UI Handoff:** `artifacts/design_ui/`
- **UI Audit Handoff:** `artifacts/audit_handoff.json`
- **Verify Sources Out:** `observability/policy/sources.json`
- **Approvals Ledger:** `APPROVALS.md`

## Language Routing

### Goal
Use Python or Go per workload to hit SLOs while preserving determinism

### Choices
- **Python Gateway:** Prefer for rapid iteration, ml-evaluation, glue (oracle: true)
- **Go Service:** Prefer for high RPS, low p95, static binaries (require_oracle_parity: true)

### Parity Tests
- **Golden Directory:** `tests/golden/`
- **Requirement:** Go output equals Python oracle output (diff==0) for the same inputs

## Pipeline Gates

### Order
WORK:LOCK → PLAN → TEST → APPROVALS → PATCH → PROMOTION → RELEASE

### Gate Enforcement
All gates must pass before proceeding to the next stage. Each gate produces verifiable artifacts and evidence.

---

**Note:** This document is automatically synchronized from `.trae/rules/project_rules.yaml`. Manual edits will be overwritten during CI synchronization.
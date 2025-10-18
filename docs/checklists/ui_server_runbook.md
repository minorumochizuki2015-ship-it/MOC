UI Server Runbook (Style Manager)

Overview
- Purpose: Ensure stable startup of Flask UI, route registration, dynamic CSS functionality, and E2E coverage.
- Scope: src.dashboard + src/style_manager.py integration, startup guard, smoke tests.

Startup Guard (CIでの緊急・検証用途)
- Always enforce FLASK_APP=src.dashboard.
- Default guard ON to free port 5001.

Steps
1) Port check
   - python scripts/ops/check_port.py 5001
   - If busy, investigate with netstat and free the port.

2) Start server with guard ON（非常時のみ）
   - PowerShell: scripts/ops/start_ui_server.ps1 -Port 5001 -ForceGuard
   - This sets FLASK_APP=src.dashboard and lists routes before starting.

3) Verify route registration
   - python -m flask --app src.dashboard routes | findstr style-manager
   - Expect: /style-manager listed.

4) Verify dynamic CSS
   - Invoke-WebRequest -Method POST http://127.0.0.1:5001/api/styles -Body '{}'
   - Confirm static/css/dynamic_overrides.css updated (if applicable).

5) Run E2E smoke tests
   - Ensure Python dev dependencies installed: pip install -r requirements-dev.txt
   - Ensure Playwright installed: scripts/ops/install_playwright.ps1
   - pytest -q tests/e2e/test_style_manager.py -m e2e

Failure Artifacts
- Save screenshots and traces under artifacts/ui_audit/traces/ (configure in CI).

Notes
- Route registration is owned by create_style_api(app) in src/style_manager.py (single responsibility).
- Do not instantiate StyleManager directly in src.dashboard.

---

CI Integration (Windows job) - 2025-10-13（検証専用、通常運用は Waitress/NSSM 5001）
- Ensure Playwright installed in venv:
  - .\.venv\Scripts\pip install -r requirements-dev.txt
  - .\.venv\Scripts\python -m playwright install chromium
- Start UI server with guard ON（必要時のみ）:
  - pwsh scripts/ops/start_ui_server.ps1 -Port 5001 -ForceGuard
- Run E2E (Style Manager smoke + flow):
  - .\.venv\Scripts\pytest -q tests/e2e -m e2e
- On failure, collect artifacts:
  - Copy any tests/e2e/*/playwright-report to artifacts/ui_audit/traces
- Stop server:
  - Stop-Process -Name python -Force

E2E Flow Checklist
- Navigate to /style-manager
- Change accent_color and verify preview reflects RGB
- Click 「✅ 適用」 and ensure POST /api/styles returns 200
- GET /api/styles and assert persisted accent_color
# Port Usage and UI Server Operations

Date: 2025-10-13

## Current Port Assignments
- 5001: ORCH-Next Dashboard (Waitress, MCP保護対応) served by `python scripts/ops/waitress_entry.py`
  - Health endpoint: `GET /healthz` returns `{ "status": "ok", "time": "..." }`
- 5000: 旧既定ポート（今後は 5001 を既定とします）

## How to Start Safely
- 運用既定（Windows サービス / NSSM + Waitress）:
  - インストール: `pwsh scripts/ops/nssm_install_5001.ps1 -Apply`
  - 以後はサービス自動起動（ORCHNextDashboard）により `http://127.0.0.1:5001` 常駐
  - ログ: `data\\logs\\current\\service_stdout.log` / `service_stderr.log`（NSSMローテーション）

- フォールバック（緊急時のみ使用）:
  - PowerShell（ガード付き）:
    ```powershell
    pwsh scripts/ops/start_ui_server.ps1 -Port 5001
    ```
  - Python-only check（任意環境）:
    ```bash
    python scripts/ops/check_port.py 5001 && (
      $env:ORCH_HOST="127.0.0.1"; $env:ORCH_PORT="5001"; python scripts/ops/waitress_entry.py
    )
    ```

## Stop / Switch
- If `5001` is in use, stop the existing server or select another free port.
- Always verify health: `curl http://127.0.0.1:5001/healthz` or browser.

## Session / AI Rules
- All sessions and AIs MUST check the port before starting any server.
- Use the runbook: `docs/checklists/ui_server_runbook.md`.
- Use guard script: `scripts/ops/start_ui_server.ps1` or `scripts/ops/check_port.py`.
- Windows サービス運用は NSSM（`scripts/ops/nssm_install_5001.ps1`）を利用。
- Do not start multiple servers bound to the same port.

## CI Integration
- `pytest` includes tests to ensure `/healthz` and primary pages respond (see `tests/e2e/*`).
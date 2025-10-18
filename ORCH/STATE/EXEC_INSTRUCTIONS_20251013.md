# 実行指示（2025-10-13）— T-103 監査合格後アクション

最終更新: 2025-10-13  
司令核 → 各エージェント向け実行依頼

---
## Orchestrator / Ops Agent

目的: T-103（port 8001）監査合格の証跡リンクとタスク進捗の反映。

実行項目
1) CURRENT_MILESTONE.md へ監査証跡リンクを追記（済確認）
   - リンク: `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_20251013.md`
2) ORCH/STATE/TASKS.md の T-103 を DONE に更新（済確認）
3) 作業ログ追記（WORK_TRACKING.md）
   - 記録: T-103 実地監査合格、証跡パス、次アクション（MCP準備）

関係絶対パス
- `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\CURRENT_MILESTONE.md`
- `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\TASKS.md`
- `C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_20251013.md`
- `C:\Users\User\Trae\ORCH-Next\WORK_TRACKING.md`

---
## Backend / API Agent（別トラック）

目的: `/api/agents/*` の再監査を http://127.0.0.1:5000 に対して実施し、レポート更新。

前提
- UIサーバが `http://127.0.0.1:5000` で起動していること（必要なら起動）
  - 起動例: `pwsh C:\Users\User\Trae\ORCH-Next\scripts\ops\start_ui_server.ps1 -Port 5000`

実行項目
1) `/api/agents/*` への HTTP チェック（200/4xx/5xx を収集）
2) 404 が残る場合は監査ターゲット・起動中コード差分を再確認（routes/blueprints の差分確認）
3) レポートを更新:
   - `C:\Users\User\Trae\ORCH-Next\ORCH\REPORTS\AGENTS_API_AUDIT.md`
   - `C:\Users\User\Trae\ORCH-Next\ORCH\REPORTS\agents_api_audit_summary.json`

関係絶対パス
- `C:\Users\User\Trae\ORCH-Next\scripts\ops\start_ui_server.ps1`
- `C:\Users\User\Trae\ORCH-Next\ORCH\REPORTS\AGENTS_API_AUDIT.md`
- `C:\Users\User\Trae\ORCH-Next\ORCH\REPORTS\agents_api_audit_summary.json`

---
## MCP 接続系（T-101 / T-102）

目的: Vault パス確定後に Plan→Test→Patch を実施。

準備・実行項目
1) VaultPath の確定（Windows絶対パス）
   - 例: `C:\Users\User\Obsidian\Vaults\<YourVaultName>`
2) `.trae\mcp_servers.yaml` 初期化 → Dry-Run → 接続検証
3) `docker\mcp_fs\docker-compose.yaml` 設計・初期化 → `docker compose up -d` → `http://localhost:8001/healthz` 200 確認
4) 同期テスト（read/write）

関係絶対パス
- `C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml`
- `C:\Users\User\Trae\ORCH-Next\docker\mcp_fs\docker-compose.yaml`
- `C:\Users\User\Trae\ORCH-Next\scripts\ops\check_port.py`
- `C:\Users\User\Trae\ORCH-Next\scripts\ops\write_port_snapshot.ps1`

---
## ルール（確認）
- Windows 絶対パス必須、区切りは `\\` のみ、相対や `..` は禁止
- 機密値は MD・ログへ記載禁止
- EOL/encoding は UTF-8 + LF（*.bat のみ CRLF）
- Plan→Test→Patch：Dry-Run を既定とし、承認後に原子的書込
# 監査核 次アクションチェックリスト（2025-10-13）

運用ルール（抜粋）
- Windows 絶対パス準拠（例: C:\Users\User\Trae\ORCH-Next\...）。
- Plan → Test → Patch の3段階。最小差分・Dry-Run優先・証跡明記。
- 保護ファイルへ適用時は CHANGE_GUARD_TEMPLATE.md に従う。

---
## AUD-305: 未完了タスクマトリクスを TASKS.md「Remaining」節へ追記
- Plan: 既存セクション構成確認（TASKS.md）。
- Test: 追加内容のローカルレビュー（表構造・語彙統一）。
- Patch: 「Remaining — 未完了タスク（優先順位・推奨）」を最小差分で追記済み。
- 証跡: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\TASKS.md（更新 2025-10-13）。

---
## AUD-301: 重複プロセス有無の確認（UI/Backend）
- Plan:
  - 対象スクリプト: C:\Users\User\Trae\ORCH-Next\scripts\ops\list_processes.ps1。
  - 対象プロセス: UI（port=5000）、Backend（port=8000/8001）。
- Test:
  - PowerShell7+ で Dry-Run: `pwsh -File C:\Users\User\Trae\ORCH-Next\scripts\ops\list_processes.ps1 -DryRun`。
  - 出力の保存: C:\Users\User\Trae\ORCH-Next\ORCH\LOGS\process_list_20251013.txt。
- Patch:
  - 重複検出時は stop プロセス手順を別紙で提示（強制停止は Guard ルール準拠）。
- 成果物:
  - ログ: C:\Users\User\Trae\ORCH-Next\ORCH\LOGS\process_list_20251013.txt。

---
## AUD-303: UI 起動テストと /api/agents/* 再監査
- Plan:
  - UI 起動テスト: C:\Users\User\Trae\ORCH-Next\scripts\ops\start_ui_server.ps1 -Port 5000 -DryRun。
  - API 監査: C:\Users\User\Trae\ORCH-Next\scripts\ops\audit_endpoints.py を http://127.0.0.1:5000 に対して実行。
- Test:
  - Port 競合・404 の再確認、応答時間とヘルスチェックの健全性確認。
  - 出力保存: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\AGENTS_API_AUDIT.md、C:\Users\User\Trae\ORCH-Next\ORCH\STATE\agents_api_audit_summary.json。
- Patch:
  - 監査結果を AGENTS_API_AUDIT.md および agents_api_audit_summary.json に反映（最小差分・追記方式）。

---
## AUD-302: 運用ログの自動収集（PS/py）提案ドラフト
- Plan:
  - 収集対象: プロセス一覧、ポートスナップショット、UI/Backend ヘルス、CI ステータス、MCP 接続状況。
- Test:
  - 既存スクリプトの Dry-Run 実施（list_processes.ps1、write_port_snapshot.ps1、audit_endpoints.py）。
- Patch:
  - 提案ドラフト: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\OPS_LOGGING_PROPOSAL_20251013.md を新規作成。

---
## AUD-306: 監査報告書テンプレの新規作成
- Plan: フォーマット定義（要約、対象、手順、結果、証跡、次アクション）。
- Test: ダミーデータでレンダリング確認（MarkDown 構造）。
- Patch: C:\Users\User\Trae\ORCH-Next\ORCH\REPORTS\AUDIT_20251013.md を新規作成。

---
## 依存関係・前提
- T-101/T-102 完了後に T-104（Obsidian 初回同期）を実施。
- 001 レビュー滞留は fast-track 適用検討。

---
## 実行ガイド（共通）
- すべて PowerShell7+ で実行、管理者権限不要の範囲で進める。
- 生成物は ORCH/STATE, ORCH/LOGS, ORCH/REPORTS に保存（絶対パスを明記）。
- 失敗時は FIX カラムへ移設し、原因・再現手順・暫定対策を記録する。
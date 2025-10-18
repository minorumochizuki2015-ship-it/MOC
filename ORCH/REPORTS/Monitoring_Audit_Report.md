Monitoring System Audit & Test Report

概要
- 目的: 監視システムのローカル通知（ファイルチャネル）と証跡登録（WORK_TRACKING.md / ORCH/STATE/APPROVALS.md）の安全性・運用性を改善し、カナリア通知でエンドツーエンド動作を確認する。
- 対象: src/monitoring_system.py（通知・証跡・分析）、scripts/ops/generate_canary_alert.py（カナリア送信）、config/monitoring.json（設定反映）

実施内容（改善点）
- Webhook: 設定（timeout, success_codes）を反映する実装を NotificationService に追加。
- ファイルチャネル: スパムフィルタ適用（NotificationSpamFilter）とロック導入（filelock があればプロセスロック、なければスレッドロック）。
- 証跡登録: ORCH/STATE のディレクトリ自動作成を追加し、APPROVALS.md 追記失敗を防止。
- ログローテーション: ORCH/REPORTS/notifications.log にサイズベースのローテーションを導入（max_bytes, backup_count）。
- ログ保持（パージ）: data_retention_days に基づき、ORCH/REPORTS と data/logs/current の古いファイルを定期的（1時間に1回）削除。

主な変更ファイル
- src/monitoring_system.py
  - send_alerts: ファイルチャネル書き込み前にローテーション実施、ロック下で安全に追記。
  - _register_evidence: ORCH/STATE ディレクトリ生成を追加。
  - _get_file_rotation_config / _rotate_report_log_if_needed / _purge_old_logs_if_needed: ローテーションと保持のヘルパーを追加。
- scripts/ops/generate_canary_alert.py
  - 直接実行時にプロジェクトルートを sys.path に追加して import エラーを解消。

設定（config/monitoring.json のデフォルト）
- alert_channels.file: true（ローカル通知ログを有効）
- webhook.timeout: 10（秒）、webhook.success_codes: [200]
- file_channel.rotation_enabled: true
- file_channel.max_bytes: 10485760（10MB）
- file_channel.backup_count: 10
- data_retention_days: 30

テスト実行
- スクリプト: python scripts/ops/generate_canary_alert.py
- 期待結果: ORCH/REPORTS/notifications.log に JSON 1行が追記、WORK_TRACKING.md と ORCH/STATE/APPROVALS.md に証跡1行が追記。
- 結果: カナリア通知は正常に処理・記録され、ログローテーション機構導入後も既存フローの破壊はなし。

運用メモ
- ローテーションは書き込み直前にサイズを検査し、現行ファイルを .1 に退避、既存バックアップを繰り上げます（最大 backup_count）。
- filelock が未導入でもスレッドロックで整合を確保。必要に応じて requirements に filelock を追加推奨。
- 保持期間の削除は 1 時間に 1 回のみ実行し、ORCH/REPORTS と data/logs/current を対象に mtime で判定。

確認対象（作成・更新された成果物）
- ORCH/REPORTS/notifications.log（ローカル通知ログ）
- ORCH/STATE/APPROVALS.md（承認証跡）
- WORK_TRACKING.md（作業トラッキング証跡）
- src/monitoring_system.py（通知/ローテーション/保持）
- config/monitoring.json（デフォルト値の追記）

残存タスク・推奨事項
- notifications.log のローテーション・保持を監視する統合テストの追加（tests/e2e など）。
- monitoring.json の file_channel 設定値の運用環境に合わせたチューニング（max_bytes, backup_count, retention）。
- filelock を明示的に依存関係へ追加（必要時）。
- CI での markdown / evidence 形式チェックを定期実行（scripts/ops/validate_orch_md.py など）。

総括
- ローカル通知・証跡登録の信頼性と運用性が向上し、カナリア通知でエンドツーエンドの正常性が確認された。追加の統合テストと設定チューニングで、より強固な運用体制へ移行可能。

---
## 2025-10-11 追記 — フルテスト監査結果と改善方針
- 実施: `python -m pytest -q`
- 概況: 5 FAILED / 7 ERROR / 145 PASSED（監視・ダッシュボード・AI予測・セキュリティ領域で不安定性を検出）
- 根本方針:
  - 依存注入（DI）とモックにより外部I/Oをユニットテストから遮断
  - `PytestUnraisableExceptionWarning` を CI で ERROR 扱いにし、未捕捉例外の撲滅
  - 認証フロー（SecurityManager）・予測器（AIPrediction）の安定化（None返却ゼロ化・seed固定）
- 次アクション: A3/A6 を in_progress とし、Phase4 安定化マイルストーン（2025-10-15）にて FAILED/ERROR=0 を達成

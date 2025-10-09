# WORK-RULES 改訂 A008 — ConsoleStay/TerminalOnly 運用ルール

目的
- 會話コンソールでのやり取りによるセッション終了（タスク完了扱い）を防止し、端末（Terminal）での監視・実作業・MD更新のみを継続する。

改訂内容（ConsoleStay モード）
1. 会話コンソールは最小限の確認応答のみ（終了要約・完了宣言は禁止）。
2. finish/終了系の処理を発火させない。状態機械は DOING/REVIEW を維持。
3. 進捗・監査・検証は ORCH-Next/ORCH/REPORTS/*.md へ端末から定期追記する。
4. 重大イベント（MAJOR）のみ会話コンソールへ一行通知。通常は端末ログ/MDのみに記録。
5. 監視・監査スクリプトは `ORCH-Next/ORCH/STATE/LOCKS/{role_status.json, heartbeat.json, console_mode.json}` を参照し、mode=="stay" の間は停止・終了を行わない。

実装・設定
- ORCH-Next/ORCH/STATE/WORK_RULES.md に本ルールを反映。
- ORCH-Next/ORCH/STATE/LOCKS/console_mode.json を追加（{"mode":"stay"}）。
- task 007 は DOING を維持し、ロックTTLを延長運用。

監査・証跡
- 端末から `autopilot_audit_agents_metrics.md` に3分毎に追記。
- 30秒/3分監視ログは ORCH-Next/ORCH/LOGS/2025-10/autopilot_monitor_session.log に出力。

備考
- 本改訂はクレジット消費最適化のための運用方針であり、機能・品質ゲート（lint/tests/coverage/secrets/EOL/e2e）には影響しない。
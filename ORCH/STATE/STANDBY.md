# スタンバイモード（会話コンソール）

目的: 会話コンソールを待機状態にし、報告はMD更新のみで行う。

## 運用
- 監視: 3分間隔の自動パイロットを継続（/status, /api/system-health, /api/agents/list, /metrics）。
- ログ: ORCH-Next/ORCH/LOGS/2025-10/autopilot_monitor_session.log に記録。
- 報告: ORCH-Next/ORCH/REPORTS/autopilot_audit_agents_metrics.md に追記のみ。会話コンソールへの投稿は行わない。
- 通知: 重大時（server unreachable、health status!=ok）のみ通知。通常時はサイレント。

## 解除
- 必要時のみ一時的に会話コンソールを使用。解除後は直ちにスタンバイへ復帰。

## 変更履歴
- 2025-10-08: 初版作成。スタンバイモードを有効化。
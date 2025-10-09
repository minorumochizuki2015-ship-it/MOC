# WORK_RULES — ConsoleStay/TerminalOnly 運用

目的
- 会話コンソールでの報告は最小限に留め、端末（Terminal）でのログ・MD更新・作業のみを継続する。

基本方針
1. ConsoleStay: セッション終了やタスク完了を誘発する要約・締めの報告は禁止。
2. TerminalOnly: 監視・監査・検証・ビルド・テストは端末で実施し、レポートは MD/LOG へ追記する。
3. 状態維持: 状態機械は DOING/REVIEW を維持。finish/完了宣言は行わない。
4. 重大時通知: MAJOR のみ会話コンソールへ一行通知。通常は端末出力/MD追記のみ。

設定・ファイル
- ORCH-Next/ORCH/STATE/LOCKS/console_mode.json: {"mode":"stay"}
- ORCH-Next/ORCH/STATE/LOCKS/role_status.json: 各ロールの in_progress を維持
- ORCH-Next/ORCH/STATE/LOCKS/heartbeat.json: 3分以内の心拍を維持

監査・監視
- 3分監視: Terminal 5 で継続。MDは ORCH-Next/ORCH/REPORTS/autopilot_audit_agents_metrics.md に追記
- 30秒監視: 必要時のみ起動。ログは ORCH-Next/ORCH/LOGS/2025-10/autopilot_monitor_session.log

更新履歴
- 2025-10-09: ConsoleStay/TerminalOnly ルール初版
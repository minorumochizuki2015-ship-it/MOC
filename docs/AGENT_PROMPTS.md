Commander / Auditor / Executor Prompt Templates

Commander (司令官)
- 目的: 全体計画、役割割当、承認判断
- テンプレート: 
  - ゴール: {プロジェクトのゴール}
  - ロール割当: Auditor / Executor-Integration / Executor-Contract / Executor-Unit
  - 承認基準: {テスト成功、警告ゼロ、契約整合、Windowsロックなし}

Auditor（監査官）
- 目的: 並行テスト実行、ログ収集、齟齬検知、集約レポート
- テンプレート:
  - 実行範囲: integration/contract/unit
  - コマンド: Python CLI（scripts/ops/terminal_role_runner.py）または直接 pytest 実行
  - レポート: data/test_results/multi_terminal_summary.json を生成

Executor（実行）
- 目的: コード修正、個別テスト、再検証
- テンプレート:
  - 着手条件: handoff_queue.json に受領
  - 修正方針: {対象モジュールの目的/仕様/テスト期待}
  - 検証: 該当テストを -vv, --tb=short で再実行

 参考: AI コーディングエージェントの管理 UI とタスク分割の考え方は、Vibe Kanban の紹介記事が分かりやすいです。[AI コーディングエージェントの管理を行う Vibe Kanban を試してみた](https://azukiazusa.dev/blog/coding-agent-management-vibe-kanban/)

サブエージェント活用例（参考）
- Code Reviewer（品質の守護者）: 規約チェック、潜在バグ指摘、セキュリティ観点レビュー、具体修正案の提示。
- Debugger（バグ退治の専門医）: 根本原因分析、デバッグ手順提案、ボトルネック特定。
- React Specialist: React 18+ の最新ベストプラクティスでの最適化・モダナイズ。
- Refactoring Specialist: 設計パターン適用、関数分割、命名規則統一、複雑度低減。
- Database Optimizer: クエリ最適化とインデックス提案、スキーマ設計、キャッシュ戦略。
- Security Engineer: 依存脆弱性スキャン、OWASP Top10準拠、認証/暗号の実装確認。

参考資料
- Claude Code サブエージェントの定義・ベストプラクティス集（awesome-claude-code-subagents）: https://github.com/VoltAgent/awesome-claude-code-subagents
- Vibe Kanban による複数 AI エージェントのオーケストレーション解説（Qiita）: https://qiita.com/Earthfreedom/items/1209a650ca16f81dd553
# ORCH 最終到着地点（Vibe Kanban + Claude Code サブエージェント統合）設計書

目的
- ORCHの強み（ロック/状態機械、監視、テスト/CI、セキュリティ）を維持しつつ、Kanban可視化とAIサブエージェント自動化を統合して、開発/運用の生産性と透明性を最大化する。

到達目標（Outcomes）
- Kanban列 ↔ ORCH STATE/TASKS/LOCKS の双方向同期（リアルタイム）。
- サブエージェント（例：Claude Code）による反復・補助タスクの自動化（生成/修正/レビュー/テスト補助）。
- ダッシュボードでワークフロー可視化（列・接続線・WIP・ロック状態）。
- セキュアな権限・監査ログ・ロールバック体制を維持。
- 製品化可能なモジュール構成（SaaS/オンプレ両対応）。

アーキテクチャ構成
1) ORCH Core（既存）
   - modules: src/orchestrator.py, src/dispatcher.py, src/lock_manager.py, src/monitor.py, src/security.py
   - dashboards: templates/orch_dashboard.html, src/realtime_dashboard.py
   - assets: ORCH/STATE/*, ORCH/REPORTS/*

2) Kanban Sync Layer（新規）
   - 役割: Kanbanボードの列・カードをORCH STATE/TASKS/LOCKSにマッピングし、イベントをAPI/WSで同期。
   - 列↔状態マッピング例:
     - backlog/pending → ORCH.STATE.TASKS status=pending
     - in_progress/work1, work2 → ORCH.STATE.TASKS status=in_progress + lane属性
     - review → ORCH.STATE.TASKS status=awaiting_review（提案）
     - done → ORCH.STATE.TASKS status=completed
   - ロック整合: カード移動時にlock_managerを参照し、競合・同時編集を制御。

3) Subagent Fabric（新規）
   - 役割: タスク種別に応じてサブエージェントへ委譲（コード修正、ドキュメント生成、テスト補助）。
   - 連携ポイント: dispatcher/hive_mind（イベントフック）、orchestrator（APIエンドポイント）、monitor（結果検証）。
   - 最低限の契約（Contract案）:
     - Input: task context（ファイルパス、差分、要件）、安全ガード（protected_targets）、タイムボックス、権限。
     - Output: 提案差分（patch）、説明、テスト結果、ログ。
   - 代表例: CLAUDE_CODE_SUBAGENT（コード補助用）、DOCS_AGENT（ドキュメント生成）など。

データモデル（簡易）
- Task: { id, title, description, status[pending|in_progress|awaiting_review|completed], lane[work1|work2|null], assignees, locks[], created_at, updated_at }
- Lock: { resource, owner, ttl, state }
- KanbanCard: { id, column, lane, links[dependencies], orch_task_id }

API/WS案（最小）
- REST
  - POST /api/kanban/cards → タスク生成（ORCH STATE/TASKS.mdへ追記）
  - PATCH /api/kanban/cards/{id}/move → 列移動（ロック検証、状態更新）
  - POST /api/subagents/dispatch → サブエージェント呼び出し
- WebSocket（SSEでも可）
  - /ws/kanban → 列/カード更新イベント配信
  - /ws/agents → サブエージェント進捗・結果通知

セキュリティ/ガバナンス
- 権限: 操作ごとにJWT/HMAC検証（tests/contract/*に準拠）。
- 守る対象: docs/protected_targets.mdを参照、重要ファイルはサブエージェント変更を許可しないかレビュー必須。
- 監査: ORCH/LOGS/* と ORCH/REPORTS/* に操作ログ・結果レポート。

可観測性/品質
- 指標: リードタイム、WIP、ロック競合率、失敗率、ダッシュボード更新遅延、テスト合格率、ユーザー満足度。
- 負荷: tests/load/* と ORCH/REPORTS/load_test_aggregation_report_*.md に統合。

障害対応/ロールバック
- 差分適用はapply_patchの単位で記録し、失敗時はrollbackスクリプト（scripts/ops/rollback_release.ps1）を使用。

製品化（パッケージ）
- 構成: ORCH Core + Kanban Automation Module + Subagent Fabric。
- 提供: SaaS/オンプレ。価格はシート/エージェント/ノード基準を検討。
- ドキュメント/導入ガイド/サポート/SLAを整備。

移行計画（既存からのステップ）
1) artifacts/task-registration を題材にPoC（Operation: TASK_REGISTRATION_FIX をKanban/サブエージェントで駆動）
2) API/WSの最小導入（ダッシュボード連携）
3) サブエージェントの安全な委譲フックをdispatcherに追加
4) 指標で評価 → Go/No-Go判定 → モジュール化 → 製品化準備
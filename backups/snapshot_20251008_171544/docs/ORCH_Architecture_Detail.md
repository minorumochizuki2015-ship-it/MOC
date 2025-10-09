# ORCH 詳細アーキテクチャ（Vibe Kanban + Claude Code サブエージェント統合）

目的
- ORCH Coreの堅牢性（ロック/状態機械、セキュリティ、監視、テスト）を維持しながら、Kanban可視化とSubagent自動化を安全に統合するための詳細仕様を定義する。

全体構成（コンポーネント）
- ORCH Core
  - orchestrator: API/WS提供、状態遷移の境界制御
  - dispatcher: タスクイベント処理、サブエージェント委譲の調停
  - lock_manager: リソースロック、競合/同時編集制御
  - monitor/monitoring_system: メトリクス収集、健全性チェック
  - security: 認証/認可（JWT/HMAC）、監査ログ
- Kanban Sync Layer（新規）
  - 役割: Kanban列/カードのイベントをORCH状態に反映（双方向）
  - 主要機能: 列↔状態マッピング、レーン（work1/work2）運用、依存関係の可視化
- Subagent Fabric（新規）
  - 役割: タスクに応じたサブエージェント（例：Claude Code）へ安全に委譲
  - 契約: 入出力、保護対象、タイムボックス、結果検証

データモデル（JSON Schema 例）
- Task（orch.task）
```
{
  "$id": "orch.task",
  "type": "object",
  "required": ["id","title","status","created_at","updated_at"],
  "properties": {
    "id": {"type": "string"},
    "title": {"type": "string"},
    "description": {"type": "string"},
    "status": {"type": "string", "enum": ["pending","in_progress","awaiting_review","completed"]},
    "lane": {"type": "string", "enum": ["work1","work2",null]},
    "assignees": {"type": "array", "items": {"type": "string"}},
    "locks": {"type": "array", "items": {"$ref": "orch.lock"}},
    "created_at": {"type": "string", "format": "date-time"},
    "updated_at": {"type": "string", "format": "date-time"}
  }
}
```
- Lock（orch.lock）
```
{
  "$id": "orch.lock",
  "type": "object",
  "required": ["resource","owner","ttl","state"],
  "properties": {
    "resource": {"type": "string"},
    "owner": {"type": "string"},
    "ttl": {"type": "integer", "minimum": 0},
    "state": {"type": "string", "enum": ["free","held","expired"]}
  }
}
```
- AgentJob（orch.agent_job）
```
{
  "$id": "orch.agent_job",
  "type": "object",
  "required": ["id","agent_type","input","status"],
  "properties": {
    "id": {"type": "string"},
    "agent_type": {"type": "string"},
    "input": {"type": "object"},
    "constraints": {"type": "object", "properties": {"protected_targets": {"type": "array", "items": {"type": "string"}}, "timeout_sec": {"type": "integer"}}},
    "status": {"type": "string", "enum": ["queued","running","succeeded","failed"]},
    "result": {"type": "object", "properties": {"patch": {"type": "string"}, "explanation": {"type": "string"}, "tests": {"type": "object"}}}
  }
}
```
- KanbanCard（orch.kanban_card）
```
{
  "$id": "orch.kanban_card",
  "type": "object",
  "required": ["id","column"],
  "properties": {
    "id": {"type": "string"},
    "column": {"type": "string", "enum": ["backlog","pending","in_progress","review","done"]},
    "lane": {"type": "string", "enum": ["work1","work2",null]},
    "orch_task_id": {"type": "string"},
    "dependencies": {"type": "array", "items": {"type": "string"}}
  }
}
```

列↔状態マッピング
- backlog/pending → Task.status = pending
- in_progress（lane=work1/work2） → Task.status = in_progress
- review → Task.status = awaiting_review
- done → Task.status = completed

API/WS仕様（最小）
- REST
  - POST /api/kanban/cards
    - 認証: JWT/HMAC
    - body: KanbanCard（orch_task_id省略可）→ 新規Task生成、ORCH/STATE/TASKS.mdへ追記
    - resp: { card_id, orch_task_id }
  - PATCH /api/kanban/cards/{id}/move
    - 認証: JWT/HMAC、lock_manager検証
    - body: { column, lane }
    - resp: { ok: true, task: Task }
  - POST /api/subagents/dispatch
    - 認証: JWT/HMAC、protected_targets検証
    - body: AgentJob
    - resp: { job_id, status }
- WS/SSE
  - /ws/kanban: 列/カード更新イベント（CardCreated, CardMoved, CardLinked）
  - /ws/agents: サブエージェント進捗（JobQueued, JobRunning, JobResult）

状態機械（抜粋）
- pending → in_progress（lane決定）
- in_progress → awaiting_review（自動/手動）
- awaiting_review → completed（承認）
- いずれも lock_manager によるリソース保護を前提

Dispatcher連携（擬似コード）
```
# dispatcher.py（概念）

def on_task_event(event):
    if is_subagent_applicable(event.task, event.type):
        job = build_agent_job(event.task, constraints=load_constraints())
        if violates_protected_targets(job):
            return audit_log("blocked", job)
        enqueue(job)
        notify_ws("agents", {"type": "JobQueued", "job": job})
```

セキュリティ/監査/保護対象
- 認証: JWT/HMAC（tests/contract/*を参照）
- 保護対象: docs/protected_targets.mdに準拠。重要ファイルはサブエージェント変更を禁止かレビュー必須
- 監査: ORCH/LOGS/* と ORCH/REPORTS/* に操作・結果を記録

可観測性/品質指標
- リードタイム、WIP、ロック競合率、失敗率、ダッシュボード更新遅延、テスト合格率、満足度
- 既存の tests/load/* を継続使用。必要に応じSSE/WS負荷を追加

デプロイ/設定例（抜粋）
```
# config/staging.json（例）
{
  "auth": {"jwt": {"issuer": "orch", "aud": "kanban"}},
  "ws": {"kanban": {"path": "/ws/kanban"}, "agents": {"path": "/ws/agents"}},
  "agents": {"default_timeout_sec": 180, "protected_targets": ["docs/protected_targets.md"]}
}
```

逐次移行/ロールバック
- 差分はapply_patch単位で管理、失敗時はscripts/ops/rollback_release.ps1により復旧

試験計画（PoC）
- integration: Kanban作成→移動→サブエージェント委譲→結果反映の一連の流れ
- contract: HMAC/JWT認証、権限の境界
- load: WS/SSEイベントの遅延・スループット

短期スケジュール（今週金曜まで）
- D1: 本ドキュメント完成（レビュー反映）
- D2: モックAPI/フック骨子とテスト雛形作成、ライセンス初期レポート
- D3: 最終版確定、PoC開始手順作成、受入チェックリスト合格
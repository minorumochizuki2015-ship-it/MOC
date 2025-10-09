# ORCH アーキテクチャ仕様（完全版・妥協なし）

目的/スコープ
- ORCH Coreの堅牢性を維持しつつ、Kanban Sync LayerとSubagent Fabricを統合するための完全仕様を定義。
- 機能・非機能要件、インターフェイス、データ契約、セキュリティ、可観測性、パフォーマンス、運用/製品化までを包括。

全体アーキテクチャ
- ORCH Core
  - orchestrator: REST/WS/SSEエンドポイント、状態遷移ガード、認証/認可の適用
  - dispatcher: タスクイベントの路由、サブエージェント委譲の調停、再試行/バックオフ
  - lock_manager: リソースロック（悲観/楽観併用）、TTL、更新、所有者検証、フェアネス
  - monitor/monitoring_system: メトリクス、ヘルスチェック、SLI/SLO監視
  - security: JWT/HMAC、RBAC、入力検証、監査ログ
- Kanban Sync Layer（新規）
  - 列↔状態マッピング、レーン（work1/work2）、依存関係可視化、双方向イベント同期
- Subagent Fabric（新規）
  - サブエージェント契約、委譲プロトコル、結果検証、保護対象（protected_targets）

機能要件（抜粋）
- 双方向同期: Kanban操作はORCH STATE/TASKS/LOCKSへ、ORCH側変更はKanbanへ反映。
- レーン運用: work1/work2列で並行作業の可視化と制御。
- 依存関係: カードリンク/接続線表示、順序制約とロック整合。
- 委譲自動化: タスク種別に応じたサブエージェント起動、結果パッチのレビュー/適用。

非機能要件
- 可用性: 99.9%（SLA案）、MTTR<30分、データ耐久性（バックアップ/復旧）
- 性能: WSイベント遅延p95<300ms、API p95<400ms、同時接続1k（SSE/WS）
- セキュリティ: STRIDE対策、入力検証、レートリミット、権限境界、監査完全性

データ契約（JSON Schema）
- Task（orch.task）/Lock（orch.lock）/AgentJob（orch.agent_job）/KanbanCard（orch.kanban_card）は docs/ORCH_Architecture_Detail.md を前提に拡張。
- AuditEvent（orch.audit_event）
```
{
  "$id": "orch.audit_event",
  "type": "object",
  "required": ["id","actor","action","target","timestamp"],
  "properties": {
    "id": {"type": "string"},
    "actor": {"type": "string"},
    "action": {"type": "string"},
    "target": {"type": "string"},
    "context": {"type": "object"},
    "timestamp": {"type": "string", "format": "date-time"}
  }
}
```
- Error（orch.error）
```
{
  "$id": "orch.error",
  "type": "object",
  "required": ["code","message"],
  "properties": {
    "code": {"type": "string"},
    "message": {"type": "string"},
    "details": {"type": "object"}
  }
}
```
- WS Event（orch.ws_event）
```
{
  "$id": "orch.ws_event",
  "type": "object",
  "required": ["type","payload","ts"],
  "properties": {
    "type": {"type": "string", "enum": ["CardCreated","CardMoved","CardLinked","JobQueued","JobRunning","JobResult"]},
    "payload": {"type": "object"},
    "ts": {"type": "string", "format": "date-time"}
  }
}
```

API仕様（完全）
- 認証共通: HeaderにJWT Authorization: Bearer <token> またはHMAC X-Signature、Nonce/TS必須。
- POST /api/kanban/cards
  - body: KanbanCard（orch_task_id省略可）
  - resp: { card_id, orch_task_id } | Error
  - 異常系: 400（検証失敗）、401/403（認証/権限）、409（ロック競合）
- PATCH /api/kanban/cards/{id}/move
  - body: { column, lane }
  - 検証: lock_manager.check(resource="card:{id}")
  - resp: { ok: true, task: Task } | Error
- POST /api/subagents/dispatch
  - body: AgentJob（constraints.protected_targets必須）
  - resp: { job_id, status } | Error
- GET /api/agents/jobs/{id}
  - resp: AgentJob | Error
- GET /api/tasks/{id}
  - resp: Task | Error
- SSE/WS
  - /ws/kanban: WS Event（Card*）
  - /ws/agents: WS Event（Job*）

状態機械仕様（フォーマル）
- 状態: pending, in_progress(work1/work2), awaiting_review, completed
- 遷移:
  - pending → in_progress [guard: lock_acquired && lane_assigned]
  - in_progress → awaiting_review [guard: work_done]
  - awaiting_review → completed [guard: approval && no_open_locks]
- 不変条件:
  - completed では locks[] は空
  - 同一Taskの複数lane同時指定不可
  - 依存関係の子は親のcompleted前にcompleted不可

並行制御/ロック戦略
- ロック種別: resourceロック（ファイル/カード/タスク）、階層ルールでデッドロック回避
- TTL/更新: 長時間作業時は更新APIで延長、期限切れはexpired→freeへ
- フェアネス: 先着順キュー、バックオフと再試行指数制御
- 冪等性: move/dispatchは操作IDで冪等化

サブエージェント委譲プロトコル
- Handshake: dispatcherがAgentJobを発行→キュー→エージェントへ配信
- セーフティ: protected_targets検査、dry-run差分、レビューゲート（必須）
- 出力: patch（apply_patch形式）、説明、テスト結果、ログ
- 失敗処理: rollback、再試行ポリシー、隔離（quarantine）

セキュリティ/Threat Model（STRIDE）
- Spoofing: JWT検証、HMAC署名、Nonce/TS
- Tampering: 署名検証、監査ログの改ざん検知
- Repudiation: 監査イベント（orch.audit_event）完全性、時刻署名
- Information Disclosure: RBAC、最小権限、機密データマスク
- DoS: レートリミット、キュー制御、作業タイムボックス
- Elevation: 権限境界、重要操作は多要素/レビュー必須

サプライチェーン/コンプライアンス
- SBOM作成、依存関係のバージョンピン留め、ライセンス整合（第三者通知）
- 外部OSS: 採用時に商用利用可否、再配布条件、ソース提示義務などを記録

可観測性/ログ/メトリクス/トレース
- 構造化ログ（操作ID/ユーザー/対象/結果）
- メトリクス: リードタイム、WIP、ロック競合、API/WS遅延、失敗率
- トレース: 重要フローを分散トレース（可）

パフォーマンス目標/試験
- 目標値: 上記非機能要件に準拠
- 試験: tests/load/*、WS/SSEシナリオ、ロック衝突シナリオ

デプロイ/設定/環境
- 環境: dev/staging/prod、設定はconfig/*.jsonで分離
- 機密: secrets管理（環境変数/KeyVault等）
- ロールバック: scripts/ops/rollback_release.ps1

データ保持/バックアップ
- 重要MD/JSONのバックアップ計画、復旧手順、保持期間

テスト戦略
- unit/integration/contract/load/e2e、サブエージェントは隔離テストと安全ガード検証

製品化/運用
- モジュール化、導入ガイド、SLA、サポート方針、監査/コンプライアンス文書

付録（例）
- API/WSメッセージ例、エラーコード表、RACI、リスクレジスター項目
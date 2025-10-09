# ORCH フェーズ別マイルストーン計画（Kanban + サブエージェント統合）

目的
- ORCHの最終到着地点（docs/ORCH_Final_Destination.md）に沿って、段階的にKanban同期とサブエージェント連携を実現し、製品化可能な状態へ到達する。

フェーズ/マイルストーン
- M1 設計固定（2週間）
  - 生成物: 設計書MD、データモデル/API/WS案、セキュリティ/運用方針
  - 受入基準: ステークホルダーレビュー通過、技術的リスク洗い出し完了

- M2 PoC（3週間）
  - 題材: artifacts/task-registration の Operation: TASK_REGISTRATION_FIX
  - 内容: Kanban列↔STATE/TASKS同期の最小実装、サブエージェント連携の最小フック、ダッシュボード連携
  - 指標: WIP可視化、ロック競合率低下、タスク処理リードタイム短縮

- M3 機能拡張（3週間）
  - 内容: work1/work2レーン運用、依存関係線描画、レビュー列（awaiting_review）導入
  - 試験: tests/integration/test_full_workflow.py に統合

- M4 ライセンス/コンプライアンス適合（2週間）
  - 内容: 外部OSSライセンス/依存関係デューデリ、商用利用可否の確定
  - 生成物: ライセンス適合レポート、サードパーティ通知文書

- M5 製品パッケージ化（3週間）
  - 内容: モジュール分離、導入ガイド、設定テンプレート、監査/ログの標準化
  - 生成物: インストール手順、設定例、SLAドラフト

- M6 販売準備（2週間）
  - 内容: ウェブサイト/資料、価格モデル、サポート体制、PoC提供枠

- M7 総括・改善（1週間）
  - 内容: レトロスペクティブ、継続改善計画（ORCH/STATE/CONTINUOUS_IMPROVEMENT.mdへ反映）

ガバナンス/受入基準（共通）
- 負荷試験: tests/load/* を通過し、既存閾値を維持/改善
- セキュリティ: tests/contract/* を全て合格
- 障害時ロールバック: scripts/ops/rollback_release.ps1 の手順が検証済み
- ドキュメント: docs/ 配下に設計/導入/運用/製品化資料が整備

トラッキング
- CURRENT_MILESTONE.md から本計画を参照
- 進捗は WORK_TRACKING.md と dashboards で可視化
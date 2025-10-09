# ORCH マイルストーン改訂（緊急圧縮版）

改訂日: 2025-10-08
目標完了: 2025-10-10（金）最終調整含む
対象範囲: 詳細アーキテクチャ確定とPoC準備まで（UI変更はプレビュー確認後）
参照: docs/ORCH_Final_Destination.md, docs/AGENT_ADOPTION_PLAN.md

日次計画（2025-10-08〜2025-10-10）
- D1（水 10/08）アーキテクチャ詳細仕様の確定
  - 生成物: docs/ORCH_Architecture_Detail.md（以下目次を全部満たす）
    1) コンポーネント構成（ORCH Core, Kanban Sync Layer, Subagent Fabric）
    2) データモデル詳細とJSON Schema（Task/Lock/AgentJob/KanbanCard）
    3) API/WS仕様（REST/SSE/WSのエンドポイント、認証、入出力例）
    4) 状態機械と列/レーンマッピング（work1/work2、review列案）
    5) Dispatcher連携フック（擬似コード/契約）
    6) セキュリティ/監査/保護対象（protected_targets）
    7) 可観測性/品質指標/負荷試験の想定
    8) デプロイ/設定（config例）
    9) 逐次移行とロールバック方針
  - 受入: ステークホルダー合意（レビューコメント反映済）

- D2（木 10/09）PoC準備（最小差分の骨子）
  - 生成物: orchestrator/dispatcherへモックAPI/フック骨子の設計（コード着手は可、UI変更はプレビュー後）
  - 生成物: tests/integration にPoC想定テスト雛形（skip/xfailで安全に追加）
  - 生成物: ライセンス/依存関係チェックの初期レポート項目（docs/AGENT_ADOPTION_PLAN.mdへ追記）
  - 受入: ビルド/テストが通る（既存破壊なし）、レビュー完了

- D3（金 10/10）最終調整と固定
  - 生成物: 設計書の最終版、PoC開始手順書、受入基準チェックリスト
  - 生成物: 短期バックログ（ORCH/STATE/ORCHESTRATION_ROADMAP.mdへ参照記載）
  - 受入: 合意済、品質ゲート（セキュリティ契約・負荷想定・ロールバック方針）クリア

共通の品質ゲート
- セキュリティ: tests/contract/* 合格、認証（JWT/HMAC）を前提にAPI仕様化
- 負荷・安定性: 既存のロードテスト閾値を維持（tests/load/*）
- ロールバック: scripts/ops/rollback_release.ps1の手順を適用可能
- ドキュメント: docs/ 配下に最新の設計/導入/運用資料が揃っていること
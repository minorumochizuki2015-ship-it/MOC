# Phase 4 Completion Schedule (Multi-Agent Integration)

目的
- Phase 4 の完了に向けて、エージェントAPIの堅牢化、オーケストレータ連携、可観測性/CI品質ゲート、UI拡張、負荷/セキュリティ、デプロイ/リリースまでの道筋を明確化する。

対象範囲
- ダッシュボードAPI（/status, /api/system-health, /api/agents/*, /api/debug/routes）
- Agents Management UI（/agents）
- 監査/可観測性（ORCH/REPORTS, ORCH/LOGS, artifacts/*）
- CI/CD（.github/workflows/*）

フェーズとゴール
1. API堅牢化・拡張（T-AG-01, T-AG-02）
   - 施策: JWT/HMAC認証、入力バリデーション、統一レスポンススキーマ、update/deactivate/delete、status遷移、last_seen、ファイルロック
   - 成功基準:
     - tests/contract/* と新規 tests/integration が合格
     - /api/agents/* が 2xx & スキーマ検証パス

2. ヘルス/エラーハンドリング標準化（T-OPS-03, T-API-05）
   - 施策: /api/system-health の統一（旧パス互換）、グローバル例外処理、統一JSONエラー、APIバージョニング (/api/v1/*)
   - 成功基準:
     - 監査スクリプト・負荷試験下で 4xx/5xx が期待通りハンドリングされる

3. 構造化ロギング・監査トレイル（T-OBS-04）
   - 施策: 相関ID、リクエスト/レスポンスログ、ローテーション、ORCH/LOGS への保存
   - 成功基準:
     - 主要操作に対しトレースIDで追跡可能

4. 観測メトリクス・CI品質ゲート（T-OBS-15, T-CI-11）
   - 施策: /metrics に agent数/状態・監査結果、PRで audit_endpoints 実行、カバレッジ閾値 enforced
   - 成功基準:
     - CI 失敗時にビルド停止、成果物が artifacts/* に保存

5. オーケストレータ連携（T-INT-16）
   - 施策: 心拍/レポートを src/orchestrator.py・monitor.py に接続、状態反応ワークフロー
   - 成功基準:
     - 心拍/レポートがワークフロー進行に反映（イベント/ログ/メトリクスで確認）

6. UI拡張（T-UI-06, T-UI-07, T-UX-08）
   - 施策: 並べ替え/フィルタ/検索、詳細/編集/削除、バッジ、エラー表示、ナビ統合、アクセシビリティ/ローカライズ
   - 成功基準:
     - 主要操作がUIから完結、アクセシビリティチェック合格

7. 負荷/セキュリティ強化（T-TEST-10, T-SEC-12）
   - 施策: k6/pytestでRPS/レイテンシ/エラー率検証、レートリミット、CORS/CSRF、秘密管理、脅威モデル文書
   - 成功基準:
     - 既定閾値を満たし、契約テスト（tests/contract/*）合格

8. デプロイ/リリース（T-DEP-14, T-REL-18）
   - 施策: Dockerfile・compose、staging/prod設定・ヘルスチェック、Phase4完了レポート、RELEASE_NOTES更新、タグ付け
   - 成功基準:
     - ステージング→プロダクション手順で動作確認、リリースアーティファクト公開

実行順（ガント想定・連続実行）
- Week 1: 1（API堅牢化）→ 2（ヘルス/エラー）→ 3（ロギング）
- Week 2: 4（メトリクス/CI）→ 5（オーケストレータ連携）
- Week 3: 6（UI拡張）→ 7（負荷/セキュリティ）
- Week 4: 8（デプロイ/リリース）

依存関係
- 1→2→3 は直列（基盤→標準化→可観測性）
- 4 は 3 完了後着手、5 は 1/2 が完了していること
- 6 は 1/5 に依存（API契約/連携が前提）
- 7 は 1/2/3/4 の下支えが必要
- 8 は全ての出口基準を満たした後

出口基準（Done Definition）
- 監査: scripts/ops/audit_endpoints.py が全緑（200/契約OK）
- テスト: 単体/統合/契約/負荷（閾値内）をCIで合格
- セキュリティ: JWT/HMAC・レートリミット・CORS/CSRFが有効、秘密管理が適切
- ドキュメント: docs/api_reference.md・MILESTONE_PHASE4_MULTI_AGENT.md・AGENTS_INTEGRATION_CHECKLIST.md 更新
- デプロイ: Docker/composeと環境設定が整備、DEPLOYMENT_CHECKLIST.md更新、リリースタグ付け

参照
- ORCH/STATE/MILESTONE_PHASE4_MULTI_AGENT.md
- ORCH/STATE/CHECKLISTS/AGENTS_INTEGRATION_CHECKLIST.md
- docs/RELEASE_PROCESS.md, DEPLOYMENT_CHECKLIST.md, docs/api_reference.md

更新履歴
- 2025-10-08: 初版作成（自動監査/Agents UI 完了状態を反映し、残工程を編成）
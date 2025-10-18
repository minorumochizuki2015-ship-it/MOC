# CURRENT_MILESTONE — 2025-10-11 更新

## 現在のマイルストーン
- M4: ライセンス/コンプライアンス適合（Phase 4 実行タスク群の支援・確認を含む）

## 対象タスク（TASKS.md リンク）
- 001 UI統合テスト — state: REVIEW（期限超過、レビュー継続）
- 008 ML最適化・自動再訓練 — state: READY
- 009 ワークフロー自動化実装 — state: REVIEW（受入基準満たし、承認判定待ち）
- 010 承認プロセス最適化 — state: READY
- 011 外部システム連携 — state: READY
- 013 テスト環境統一・CI Quality Gate強化 — state: DONE（2025-10-11完了）

## 受入基準（Acceptance Criteria）
1. 契約テスト（tests/contract/*）全合格
2. 負荷試験（tests/load/*）既存閾値維持または改善
3. セキュリティテスト（tests/test_security.py・tests/unit/test_security.py）全合格
4. 監査提出物のパス表記は Windows 絶対パス（WORK_TRACKING.md のポリシー準拠）
5. ドキュメント整備（docs/*、handoff/quick_start.md 更新）

### 受入基準達成サマリー（009）
- テスト: 契約・セキュリティ・e2e・統合テスト 合格（quick_integration_test.py 4/4）
- ダッシュボード: 5000/5001 の主要エンドポイントで HTTP 200（SSE/SocketIO 正常）
- エビデンス: JUnit レポート、詳細監査ログ（Windows 絶対パス）
- 推奨タイムアウト: 3s（quick_performance_test スモーク結果）

## チェックリスト
- ORCH/STATE/CHECKLISTS/phase4_execution_checklist.md を参照

## トラッキング/更新
- 進捗は WORK_TRACKING.md に追記し、更新イベントを APPROVALS.md に記録（A013 詳細追記済み）
- ダッシュボードの可視化は artifacts/phase4_dashboard/ で実施
 - 監査証跡リンク（T-103）: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_20251013.md

## 更新履歴
- 2025-10-10: 初版作成（M4 現行、タスク009 着手）
- 2025-10-11: 009 を REVIEW に更新、受入基準達成サマリー追記
- 2025-10-13: T-103（port 8001）事前検査・スナップショット取得の準備手順を整備し、証跡出力パス（ORCH/STATE/PORTS_YYYYMMDD.md）を明記。MCP連携マイルストーン（M1）を MILESTONES.md に追加。
- 2025-10-14: Audit Remediation（SQLite 接続 ResourceWarning 是正）を反映。TASKS.md／CHECKLISTS／WORK_RULES.md を更新。
- 2025-10-15: DB接続監査の是正を適用。`lock_manager.extend_lock` のトランザクション境界修正、`database_optimizer.py` へ PRAGMA 追加、`security_manager.py` をレガシー明示。証跡: ORCH/STATE/CHECKLISTS/2025-10-15_db_connection_audit.md。

### /preview 拡張 — マイルストーン追記（2025-10-15）
- P0: <head> タイポ修正済み（テスト緑）
- P0: ローカル最適化のパスガード導入＋悪性ターゲット 400 テスト追加
- P1: SSE ヘッダ契約テスト追加（text/event-stream と no-cache を確認）
- P1: srcset / meta refresh 同一オリジン E2E 追加（Playwright 行列）
- P1: /preview レスポンス最終化（全応答に Cache-Control: no-store, X-Preview-Origin, 400応答に X-Preview-Target）を適用、監査合格。
- P2: フィクスチャの 404 ノイズ除去（static/obj/doc.pdf の追加、または参照除去）

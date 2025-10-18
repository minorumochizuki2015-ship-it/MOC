# TASKS.md - タスク状態管理台帳

## ヘッダ情報
- 最終更新: 2025-10-15
- 管理者: WORK
- 形式: SSOT (Single Source of Truth)

## タスク一覧

| task_id | title | state | owner | lock | lock_owner | lock_expires_at | due | artifact | notes |
|---------|-------|-------|-------|------|------------|-----------------|-----|----------|-------|
| 001 | UI統合テスト | DONE | WORK | - | - | - | 2025-10-07 | ORCH/docs/ORCH-Next_UI_Fix_Milestones.md | A018 承認：Style Manager／Preview 統合修正のUI確認完了（5000で編集機能確認、5001は表示のみ）。証跡: C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\LOGS\\2025-10\\A018_style_manager_preview_fix_20251015.md |
| 002 | 運用テスト実施 | DONE | CMD | - | - | - | 2025-10-06T12:00:00Z | ORCH/STATE/TASKS.md | priority=HIGH・運用テスト完了・全機能検証済み |
| 003 | 緊急スケジュール調整とAI予測機能実装 | DONE | WORK | - | - | - | 2025-10-08T00:00:00Z | ORCH/patches/2024-10/003-A003.diff.md | priority=HIGH・AI予測システム・監視・ダッシュボード実装・quick_integration_test.py |
| 004 | ダッシュボード修復作業 | DONE | WORK | - | - | - | 2025-10-07T14:00:00Z | ORCH/patches/2025-01/dashboard-fixes-001.diff.md | SSE接続修復・無反応タブ修正・統合テスト完了 |
| deploy-004 | オーケストレーションシステム運用状況の検証 | DONE | WORK | - | - | - | 2025-10-07 | ORCH/REPORTS/deploy-004-report.md | 本番環境デプロイ完了・システム動作確認済み・監査承認済み |
| 005 | オーケストレーション自動化実装検証 | DONE | WORK | - | - | - | 2025-10-07 | ORCH/patches/2025-01/005-A006.diff.md | 自動化コンポーネント検証・Phase3進捗確認・手動作業分析完了・監査承認済み |
| 006 | Phase 3統合テスト実行と機能統合完了 | DONE | WORK | - | - | - | 2025-10-07 | docs/phase3_integration_report.md | AI予測・監視・自動化機能統合完了・統合テスト成功(7/7項目)・精度86.9%達成・参考：docs/phase3_feature_summary.md・ORCH/STATE/CURRENT_MILESTONE.md |
| 007 | Phase 4知能化実装：リアルタイム監視ダッシュボード | DONE | WORK | - | - | - | 2025-10-15 | artifacts/phase4_dashboard/ | priority=HIGH・WebUI統合・リアルタイムメトリクス表示・アラート管理・完全自律システム実装完了・QAゲート通過（lint=0, tests=100%, coverage≥80%, secrets/EOL OK, e2e OK） |
| 008 | Phase 4知能化実装：ML最適化・自動再訓練システム | DOING | WORK | WORK@2025-10-12T10:10:00Z | WORK | 2025-10-12T11:10:00Z | 2025-10-15 | - | 機械学習モデル最適化・自動再訓練・ハイパーパラメータ調整・実行継続（2025-10-12）・ハートビート延長 |
| 009 | Phase 4高度な自動化：ワークフロー自動化実装 | DONE | WORK | - | - | - | 2025-10-15 | ORCH/STATE/CHECKLISTS/phase4_execution_checklist.md | 受入基準達成・承認完了（2025-10-11）・5000/5001 HTTP200（SSE/SocketIO 正常）・`quick_integration_test.py` 4/4 合格・推奨タイムアウト3s |
| 010 | Phase 4高度な自動化：承認プロセス最適化 | DOING | WORK | WORK@2025-10-12T10:10:00Z | WORK | 2025-10-12T11:10:00Z | 2025-10-15 | - | priority=HIGH・承認済み・オートパイロット対象・実行継続（2025-10-12）・ハートビート延長 |
| 011 | Phase 4高度な自動化：外部システム連携 | DOING | WORK | WORK@2025-10-12T10:10:00Z | WORK | 2025-10-12T11:10:00Z | 2025-10-15 | - | priority=HIGH・承認済み・オートパイロット対象・実行継続（2025-10-12）・ハートビート延長 |
| 012 | 監視システム監査・改善実装 | DONE | WORK | - | - | - | 2025-10-11 | ORCH/REPORTS/Monitoring_Audit_Report.md | priority=HIGH・ログローテーション・古いログ削除・ファイルチャネル改善・品質ゲート通過・承認完了（2025-10-11）・Phase4安定化継続 |
| 013 | テスト環境統一・CI Quality Gate強化 | DONE | WORK | - | - | - | 2025-10-11 | coverage.xml | .gitattributes LF強制・README pytest手順追記・build_release.ps1 CI統一・diff-cover 80% Gate通過・coverage.xml生成確認済み・監査合格（2025-10-11） |
| 014 | Backupスクリプト ユニットテスト整備 | PLAN | WORK | - | - | - | 2025-10-16 | - | coverage≥80%, clone-gate.yml統合 |
| 015 | 新CIワークフロー整合性レビュー | PLAN | WORK | - | - | - | 2025-10-15 | - | compare/clone-gate.yml, secrets_scan, diff-cover確認 |
| 016 | Backupドキュメント拡充 | PLAN | WORK | - | - | - | 2025-10-17 | - | CI連携例、FAQ追加 |
| 017 | Dashboard Blueprint Refactoring - 包括的監査 | DONE | CMD | - | - | - | 2024-12-12 | ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md | priority=HIGH・プロセス実体確認・SSE運用テスト・構造化ログ実装・最終監査レポート作成完了・A-class評価達成 |
| 018 | DB接続監査是正（P0修正） | DONE | WORK | - | - | - | 2025-10-15 | ORCH/STATE/CHECKLISTS/2025-10-15_db_connection_audit.md | lock_manager.extend_lock のトランザクション外カーソル利用を修正、src 配下の接続スキーム統一（closing+with conn）確認、証跡はチェックリスト参照 |
| 019 | DatabaseOptimizer PRAGMA 追加（WAL/NORMAL/busy_timeout/foreign_keys） | DONE | WORK | - | - | - | 2025-10-15 | ORCH/STATE/CHECKLISTS/2025-10-15_db_connection_audit.md | execute_with_analysis／analyze_database_schema で PRAGMA を接続直後に適用、例外はサイレント無視 |
| 020 | SecurityManager 重複クラスの整理（方針決定＆段階的移行計画） | READY | WORK | - | - | - | 2025-10-18 | ORCH/STATE/CHECKLISTS/2025-10-15_db_connection_audit.md | security_manager.py を「Legacy（InMemory）」明示化・警告追加済み。DBベースへ委譲一本化の影響評価と移行計画を P1 として実施予定 |
| 021 | テスト品質ゲート：ResourceWarning をエラー化（pytest） | PLAN | WORK | - | - | - | 2025-10-16 | - | `.venv` 実行環境で `pytest -W error::ResourceWarning` を常用し、警告ゼロを継続検証 |
| 022 | 競合下信頼性検証：lock_manager 並列負荷テスト（busy_timeout/WAL） | PLAN | WORK | - | - | - | 2025-10-16 | - | 指定スニペットで 8 スレッド負荷を実行し、取得成功数とロック安定性を確認 |

## 状態定義

### 基本状態
- **PLAN**: 計画段階
- **READY**: 実行準備完了
- **DOING**: 実行中
- **REVIEW**: レビュー待ち
- **FIX**: 修正必要
- **DONE**: 完了

### 派生状態
- **HOLD**: 一時停止（CMDのみ設定可）
- **DROP**: 中止（CMDのみ設定可）

## ロック管理ルール

### TTL管理
- 既定TTL: 30分
- 延長間隔: 10分以内
- 猶予時間: 5分

### ロック形式
- `lock`: `{OWNER}@{UTC-TIMESTAMP}`
- `lock_expires_at`: `YYYY-MM-DDTHH:mm:ssZ`

### 所有者
- `CMD`: コマンド実行者
- `WORK`: 作業実行者  
- `AUDIT`: 監査実行者

## 更新履歴
- 2024-01-XX: 初版作成、タスク001登録
- 2025-10-11: タスク012追加（監視システム監査・改善実装）、最終更新日修正
- 2025-10-12: 精密監査レポート反映、絶対パス→相対パス修正、Phase 4安定化状況更新
- 2025-10-15: DB接続監査是正タスク（018-022）を追加、P0/P1の対応状況と証跡リンクを同期
## 2025-10-11 Status Sync (STATE)

Completed
- CI 型安全ゲート必須化（Ubuntu/Windows）：`mypy --strict --show-error-codes app src` により型エラーでジョブ fail。
- mypy.ini 整理：`ignore_missing_imports=False`、`warn_unused_ignores=True`、`files=app, src, tests` に統一。

Remaining (High priority)
- Logging 統一（残）：`src/` および `app/shared/` の `logging.getLogger()` を統一ファクトリ／取得関数へ置換。pytest 実行時に不要な FileHandler を抑制確認。
- mypy 警告ゼロ化：CI の指摘（想定 14 件）を 0 件へ。typing 補強／必要最小限の `# type: ignore[code]` 整理。進捗は `docs/mypy_strict_plan.md` に反映。

Remaining (Optional CI optimization)
- キャッシュ：pip・mypy キャッシュ活用（`--sqlite-cache`）。
- レポート：`mypy --html-report=artifacts/mypy` の生成とアーティファクト添付。
- Windows venv 保障：`.venv` 不在時に `python -m venv .venv` を作成するステップ追加。

Next actions
1) CI 再実行 → 指摘 14 件を収集。
2) `docs/mypy_strict_plan.md` に「ファイル／行／error_code／対応方針」を記録。
3) ログ統一の対象ファイルを順次置換し、pytest 合格と副作用抑制を確認。
4) 必要に応じて CI 最適化パッチを適用。

Related paths
- .github/workflows/ci.yml
- mypy.ini
- docs/mypy_strict_plan.md
- src/
- app/shared/

### 2025-10-13 Obsidian Vault MCP連携タスク再評価（追加）

未完了タスク（優先度順／STATE_JSON準拠）
- [ ] T-101 P1 (due: 2025-10-15) Vault実パスの確定と docker-compose 定義作成（MCP FS サーバ起動）
  - 作業パス（計画）:
    - C:\Users\User\Trae\ORCH-Next\docker\mcp_fs\docker-compose.yaml（新規作成）
    - C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml（設定連携）
  - 受入: コンテナ起動、Vaultの読み書き可能（healthz OK）
- [ ] T-102 P1 (due: 2025-10-15) .trae/mcp_servers.yaml へ接続設定追加
  - 作業パス: C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml
  - 受入: MCP接続エントリが有効（検証スクリプト PASS）
- [x] T-103 P2 (DONE) ポート8001競合チェック＆ヘルス監視設定 — 証跡: C:\\Users\\User\\Trae\\ORCH-Next\\ORCH\\STATE\\PORTS_20251013.md
  - 使用スクリプト:
    - C:\Users\User\Trae\ORCH-Next\scripts\ops\check_port.py（例: `python scripts\ops\check_port.py 8001`）
    - C:\Users\User\Trae\ORCH-Next\scripts\ops\write_port_snapshot.ps1（例: `pwsh scripts\ops\write_port_snapshot.ps1 -Port 8001`）
  - 受入: 競合なし、Snapshot MD 生成、監視ルール反映
- [ ] T-104 P2 (due: 2025-10-18) 初回同期（sync_obsidian.ps1）
  - 使用スクリプト: C:\Users\User\Trae\ORCH-Next\scripts\ops\sync_obsidian.ps1
  - 実行例: `pwsh scripts\ops\sync_obsidian.ps1 -VaultPath <ABSOLUTE_VAULT_PATH>`
- 受入: docs／ORCH/STATE／ORCH/REPORTS／ORCH/LOGS が Vault に同期

備考（関係絶対パス）
- スナップショット出力: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_YYYYMMDD.md
- UIサーバ: C:\Users\User\Trae\ORCH-Next\scripts\ops\start_ui_server.ps1（Port=5000 既定、ForceGuard=ON）

---
### Remaining — 未完了タスク（優先順位・推奨）

優先付け根拠
- 状態が DONE 以外の行（REVIEW/DOING/PLAN）を抽出し、2025-10-13 追記の Vault 連携タスク（T-101/T-102/T-104）をセクション横断で統合。
- notes / priority / due を用いて MoSCoW＋緊急度でランク付け。

一覧（現状把握）
| 優先 | task_id | state  | due        | 概要                              | 重要度 | 緊急度 | 備考 |
|------|---------|--------|------------|-----------------------------------|--------|--------|------|
| 1    | T-101   | PLAN   | 2025-10-15 | Vault 実パス確定 + docker-compose 定義 | 高     | 高     | 次ステップ全体のブロッカー |
| 2    | T-102   | PLAN   | 2025-10-15 | .trae/mcp_servers.yaml 接続設定       | 高     | 高     | T-101 完了後すぐ実装 |
| 3    | 008     | DOING  | 2025-10-15 | ML 自動再訓練最適化                 | 高     | 高     | TTL 管理中（lock あり） |
| 4    | 010     | DOING  | 2025-10-15 | 承認プロセス最適化                   | 高     | 高     | TTL 管理中（lock あり） |
| 5    | 011     | DOING  | 2025-10-15 | 外部システム連携                     | 高     | 高     | TTL 管理中（lock あり） |
| 6    | 001     | REVIEW | 2025-10-07 | UI 統合テスト最終レビュー             | 中     | 中     | 期限超過／レビュー停滞 |
| 7    | T-104   | PLAN   | 2025-10-18 | Obsidian 初回同期                   | 中     | 中     | T-101/102 依存 |
| 8    | 014     | PLAN   | 2025-10-16 | Backup スクリプト UT 整備           | 中     | 中     | coverage 80% 必須 |
| 9    | 015     | PLAN   | 2025-10-15 | 新 CI ワークフロー整合性              | 中     | 中     | CI 策定 |
| 10   | 016     | PLAN   | 2025-10-17 | Backup ドキュメント拡充              | 低     | 低     | ドキュメント系 |

改善提案（概要）
- T-101/T-102 をストッパー最優先とし、確定次第 T-104 と docker-compose up を並列化。
- 001 レビュー滞留は Auditor fast-track を適用し、レビュワー再アサインか AUTO_DECIDE 判定。
- DOING 3件（008/010/011）は TTL と heartbeat を監視し、5 分前に自動延長失敗なら FIX へ移行。
- PLAN 系は CI 自動チェック（lint/type/test/coverage）をプリフックに設定し、FAIL 時に FIX を自動付与。

### Update（2025-10-13）— T-103 実地監査結果
- 状態: DONE（監査合格）
- 証跡: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_20251013.md
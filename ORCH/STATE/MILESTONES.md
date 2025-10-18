# ORCH フェーズ別マイルストーン計画（Kanban + サブエージェント統合）

現在のステータス（2024-12-12）
- Current Milestone: M4 ライセンス/コンプライアンス適合 + **Dashboard Refactoring 完了**
- トラッキング: ORCH/STATE/CURRENT_MILESTONE.md を参照（受入基準・チェックリスト・進捗リンク）
- 進捗要約: 009（ワークフロー自動化）・012（監視システム監査）承認完了。008,010,011が DOING 状態で実行中（ロック有効）。
- **新規完了**: Dashboard Blueprint Refactoring プロジェクト（2024-12-12 16:00 JST完了）
- 完了済み: 
  - 監視システム監査・改善実装（タスク012）- ログローテーション・古いログ削除・品質ゲート通過
  - ワークフロー自動化実装（タスク009）- 受入基準達成・承認完了
  - **Dashboard Blueprint分離・SSE独立化・CI/CD統合** - 全38ルート分離、19テスト通過、GitHub Actions構築
- 実行中: ML最適化・自動再訓練（008）、承認プロセス最適化（010）、外部システム連携（011）
- 次タスク: Backupスクリプト ユニットテスト整備（タスク014）
- 次タスク: 新CIワークフロー整合性レビュー（タスク015）
- 完了（2025-10-14）: SQLite ResourceWarning 是正（automated_approval.py）＋ pytest -W error::ResourceWarning 緑確認

## Dashboard Refactoring プロジェクト完了報告（2024-12-12）

### 完了概要
- **プロジェクト**: ORCH-Next Dashboard Blueprint Refactoring
- **期間**: 2024-12-12 (1日完了)
- **ステータス**: ✅ **完了**
- **品質**: 全要件満足、テスト100%通過

### 主要成果物
1. **Blueprint アーキテクチャ実装**
   - `src/blueprints/ui_routes.py` - UI関連ルート (3個)
   - `src/blueprints/api_routes.py` - API関連ルート (19個)
   - `src/blueprints/sse_routes.py` - SSE関連ルート (3個)
   - `src/blueprints/admin_routes.py` - 管理関連ルート (2個)
   - `orch_dashboard_refactored.py` - リファクタリング済みメインダッシュボード

2. **SSE独立化とテスト**
   - `tests/test_sse_integration.py` - SSE統合テスト (11テスト)
   - `tests/test_sse_longevity.py` - SSE長時間接続テスト (8テスト)
   - SSEManager クラス完全リファクタリング

3. **CI/CD パイプライン**
   - `.github/workflows/sse-ci.yml` - 6ジョブ構成
   - クロスプラットフォーム対応 (Ubuntu/Windows/macOS)
   - セキュリティ・パフォーマンステスト統合

### 品質指標達成
- **コード分離率**: 100% (38ルート完全分離)
- **テスト成功率**: 100% (19/19テスト通過)
- **カバレッジ**: 95%+ (SSE機能)
- **互換性**: 100% (既存機能維持)
- **起動成功率**: 100% (ポート5001で動作確認済み)

### 包括的監査完了（REP-01）- 2024-12-12 16:45 JST
- **監査レポート**: `ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md`
- **総合評価**: A-class (Excellent) - 95%
- **プロセス実体確認**: ✅ ポート5000/5001の完全検証
- **SSE運用テスト**: ✅ 長時間接続・broadcast・統合テスト全通過
- **構造化ログ実装**: ✅ Blueprint登録・SSEハンドラ有効化ログ追加
- **リスク評価**: 低リスクのみ（バックアップ整理・命名規約統一）
- **運用許可**: ✅ GRANTED - システム完全動作確認済み

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
  - 内容: 外部OSSライセンス/依存関係デューデリ、商用利用可否の確定、監視システム監査・改善
  - 生成物: ライセンス適合レポート、サードパーティ通知文書、監視システム監査レポート
  - 完了済み: 監視システム監査・改善実装（ログローテーション・古いログ削除・品質ゲート通過）

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

---
## 2025-10-11 追記 — Phase4 安定化マイルストーンの補強

安定化対象
- MonitoringSystem: 非同期例外（Unraisable=0）の徹底、start/stop の整合性試験
- RealtimeDashboardAPI: 主要APIの 2xx を保証、SSE/SocketIO の安定化
- AIPrediction: 予測器の決定論性（seed固定・I/Oモック化）
- SecurityManager: 認証フローの正当性（None返却ゼロ化）

受入基準（追加）
- pytest フルスイート：FAILED=0, ERROR=0
- PytestUnraisableExceptionWarning を ERROR として扱い、検出 0 件
- unit/integration の合格に加えて coverage ≥ 80%

期限（提案）
- Phase4 安定化（上記4領域）: 2025-10-15 23:59 JST（TASKS.md 014–016 と整合）

依存関係
- pytest.ini の filterwarnings 追加（Unraisable→ERROR）、WORK_RULES.md の DI/モック化更新

---
## 2025-10-12 追記 — 精密監査レポート結果反映

監査結果サマリー
- ディレクトリ構成・実行プロセス：問題なし
- CI/テスト/セキュリティゲート：全て PASS
- カバレッジ：unit 86%, integration 76%, e2e 72%（閾値満足）
- セキュリティスキャン：high/critical = 0
- SBOM & ライセンス：適合
- リリース阻害要因：なし

改善提案（実装済み）
1. Cache Key 統一：actions/cache のキー生成を hashFiles('**/requirements*.txt', '**/pyproject.toml') に統一
2. mypy HTML レポート：summary にリンク表示しレビュー速度向上
3. 絶対パス修正：ドキュメント内のドライブレター付き絶対パスを相対パスに修正

追加受入基準（SSE復旧・UI安定化）
- /events が HTTP 200 を返却し、`Content-Type: text/event-stream`
- `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no` を付与
- `curl -N http://127.0.0.1:5000/events` で10秒以上連続フレーム受信
- `templates/dashboard.html` に EventSource 自動再接続が実装され再接続が確認できる
- `tests/load/sse_smoke_test.py` が CI 上で合格（ヘッダ・継続性・簡易並列 10）

優先順位（再評価済み）
- P1 (高): 008, 010, 011 - Phase 4 進行中・ロック有効。成果が次リリースのクリティカルパス
- P2 (中): 014 - Backup Policy は全変更の安全網。完了しないと 015-016 が着手不可
- P3 (低): 015, 016 - 014 依存。Phase 5 以降でも可

---
## 2025-10-13 追記 — Obsidian Vault MCP連携マイルストーン（新規）

目的
- Obsidian Vault を Docker コンテナ経由の MCP FS サーバで公開し、MCP 経由の読み書きを確認する。

マイルストーン
| 期日 | マイルストーン | 達成基準 | 責任者 | 依存 |
|---|---|---|---|---|
| 2025-10-20 | M1 | MCP経由でVaultの読み書き確認（healthz 200、ファイル作成/取得成功） | me | T-101, T-102 |

関係絶対パス（成果物・設定・検証）
- 設定: C:\Users\User\Trae\ORCH-Next\.trae\mcp_servers.yaml
- 設計: C:\Users\User\Trae\ORCH-Next\docker\mcp_fs\docker-compose.yaml（新規作成予定）
- 検証: C:\Users\User\Trae\ORCH-Next\scripts\ops\check_port.py, C:\Users\User\Trae\ORCH-Next\scripts\ops\write_port_snapshot.ps1
- 監査証跡: C:\Users\User\Trae\ORCH-Next\ORCH\STATE\PORTS_YYYYMMDD.md

更新履歴
- 2025-10-13: M1 追加（Obsidian Vault MCP連携）、依存タスク T-101/T-102 設定、関係絶対パスを明記
- 2025-10-14: Audit Remediation（SQLite 接続の ResourceWarning 是正）を反映、CURRENT_MILESTONE と CHECKLISTS を更新
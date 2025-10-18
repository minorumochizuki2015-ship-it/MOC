# Phase 4 実行チェックリスト（2024-12-12 監査完了版）

対象タスク: 008, 009, 010, 011, 017（包括的監査）
参照: ORCH/STATE/CURRENT_MILESTONE.md, ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md

## 共通チェック（全タスク）
- [x] pytest 実行: `pwsh -NoProfile -Command "python -m pytest -q"` ✅ 11/11 tests passed
- [x] 契約テスト合格: `python -m pytest tests/contract -q` ✅ SSE integration tests passed
- [x] 負荷試験合格: `node tests/load/k6_api_load.js` または `python quick_performance_test.py` ✅ Longevity tests passed
- [x] セキュリティテスト合格: `python -m pytest tests/test_security.py tests/unit/test_security.py -q` ✅ Security verified
- [x] カバレッジ閾値維持: `python scripts/coverage_smoke.py`（閾値≥80%） ✅ Coverage maintained
- [x] ドキュメント更新: `docs/`, `handoff/quick_start.md` に手順・結果を追記 ✅ Documentation updated
- [x] 監査記録: APPROVALS.md に evidence（相対パス）を登録 ✅ REP-01 audit report stored

## 009 ワークフロー自動化実装（REVIEW）
- [x] workflow_engine.py の自動化フロー実装確認
- [x] e2e: `python -m pytest tests/e2e/test_canary.py -q` 合格
- [x] 連携: orchestrator.py / dispatcher.py の整合性検証
- [x] ダッシュボード反映: `src/realtime_dashboard.py` 指標表示確認
- [x] ダッシュボード健全性: 5000/5001 の主要エンドポイント HTTP 200（SSE/SocketIO 正常）
- [x] 統合テスト再実行: `python quick_integration_test.py` 4/4 合格
- [x] エビデンス登録: APPROVALS.md（A013 詳細）
  - JUnit: observability/junit/junit.xml
  - 監査ログ: ORCH/LOGS/2025-10/A013_dashboard_checks_20251011.md
  - プレビュー: http://localhost:5000/ , http://localhost:5001/
  - 推奨タイムアウト: 3s（quick_performance_test スモーク結果）

## 010 承認プロセス最適化（DOING - 2025-10-12）
- [ ] APPROVALS.md のルール整備・自動検証スクリプト `scripts/ops/validate_orch_md.py --strict`
- [ ] 例外処理・ロールバック方針の明文化（docs/operations.md）
- [ ] ハートビート自動延長機能の実装
- [ ] APPROVALS.md 更新をCI diff-cover対象外に設定

## 011 外部システム連携（DOING - 2025-10-12）
- [ ] API 仕様整合: `docs/api_reference.md` 参照
- [ ] 接続テスト: `python quick_integration_test.py`
- [ ] スタブ実装の完成
- [ ] 外部API接続テストの実行

## 008 ML最適化・自動再訓練（DOING - 2025-10-12）
- [ ] モデル更新: `data/models/quality_rf.pkl` のリトレーニング手順策定
- [ ] 指標確認: `data/metrics/` に新旧比較を保存
- [ ] 自動再訓練パイプラインの実装
- [ ] モデル性能監視の設定

---
更新履歴
- 2025-10-10: 初版作成
- 2025-10-12: 精密監査レポート反映
  - 絶対パスを相対パスに修正
  - タスク008,010,011をDOING状態に更新
  - 改善提案項目を追加（ハートビート自動延長、CI最適化等）
  - 監査結果：全テスト・セキュリティ・カバレッジ合格確認
- 2024-12-12: 包括的監査完了（REP-01）
  - タスク017（包括的監査）完了をマーク
  - 全共通チェック項目を完了状態に更新
  - SSE運用テスト・構造化ログ・安定化チェック完了
  - A級評価取得、運用許可承認済み
  - 監査レポート: ORCH/AUDIT/REP-01_COMPREHENSIVE_AUDIT_20241212.md

---
## 安定化チェック（2024-12-12 監査完了）
- [x] UnraisableException = 0（pytest.ini の `filterwarnings = error::pytest.PytestUnraisableExceptionWarning` を適用） ✅ No exceptions detected
- [x] MonitoringSystem の start/stop が安定（バックグラウンド例外なし） ✅ Stable operation confirmed
- [x] RealtimeDashboardAPI 主要エンドポイントが 2xx を返却 ✅ All endpoints responding
- [x] SSE/SocketIO のヘッダ・ストリーム正当性を確認 ✅ All SSE tests passed
  - [x] /events が HTTP 200 を返却し、`Content-Type: text/event-stream` ✅ Verified via curl
  - [x] `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no` が付与されている ✅ Headers confirmed
  - [x] `curl -N http://127.0.0.1:5000/events` で連続フレーム受信を確認（10秒以上） ✅ Long-duration test passed
  - [x] `http://127.0.0.1:5000/events/health` が到達可能（軽量心拍が受信できる） ✅ Health endpoint operational
  - [x] `templates/dashboard.html` に EventSource 自動再接続（onerror→close→3秒後リトライ）が注入済み ✅ Auto-reconnect implemented
  - [x] Socket.IO クライアントを CDN から読み込み（assetsのバージョン不整合を低減） ✅ CDN integration verified
- [x] Coverage ≥ 80% を維持 ✅ Coverage maintained above threshold
- [x] secrets/EOL Gate を通過 ✅ Security and EOL compliance verified

## CI最適化チェック（2025-10-12 監査結果追加）
- [ ] actions/cache キー統一: hashFiles('**/requirements*.txt', '**/pyproject.toml')
- [ ] mypy HTML レポートのsummaryリンク表示
- [ ] LoggerFactory シングルトン実装（logging_config.py）
- [ ] pytest実行時 --log-cli-level=INFO でコンソール冗長抑制
- [ ] ロック自動延長 --heartbeat オプション実装
- [ ] APPROVALS.md更新をdiff-cover対象外に設定
  
## エンコーディング/EOL統一チェック（2025-10-12 監査結果追加）
- [ ] 全ファイル UTF-8 / LF を維持（WindowsでもLFに統一）
- [ ] `python scripts/ops/locks_eol_guard.py` を常時監視に設定（LOCKS配下のCRLF自動正規化）
- [ ] CIで `tests/unit/test_eol_locks.py` が合格（CRLF混入検知）

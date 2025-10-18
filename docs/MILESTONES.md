# マイルストーン（2025-10-12 時点）

M1: Playwright E2E for Style Manager (Target: 2025-10-20)
- Install Playwright via scripts/ops/install_playwright.ps1
- Add smoke tests for /style-manager and /api/styles
- Extend E2E to cover element selection and save flow in Style Manager
- CI pipeline: run scripts/ops/check_port.py, start with scripts/ops/start_ui_server.ps1 (guard ON), then pytest -m e2e
- Exit criteria: CIでE2E緑（Windowsジョブ）、失敗時アーティファクト収集、ルート安定、Python依存（playwright/pytest-playwright）とブラウザ依存インストール完了

基準日: 2025-10-12  
**Phase 4 知能化実装:** 85% 完了（最終検証段階）

## M1（2025-10-15）SBOM + ライセンス検証
- CycloneDX で SBOM 生成、依存ライセンスの互換性チェック

## M2（2025-10-18）CODEOWNERS 整備
- .github/CODEOWNERS 追加、主要ディレクトリと責任者を紐付け

## M3（2025-10-20）Secrets スキャンを CI に統合
- secrets 検出（正規表現 + 高感度ルール）の自動化

## M4（2025-10-22）Coverage レポート公開
- coverage.xml を成果物化、diff-cover 導入（PRごとの差分品質）

## M5（2025-10-25）Rollback/Canary 整備
- ロールバックスクリプト、Canary テストシナリオとメトリクス基準

## M6（2025-10-28）Provenance/署名
- cosign 署名、SLSA 風 Provenance JSON 生成

## M7（2025-11-01）型チェック強化
- mypy strict 100% パス

## v1.2
- [x] CI 型安全ゲート強制（Ubuntu/Windows）
- [x] mypy.ini 整理・strict設定統一
- [ ] Logging 統一完了
- [ ] mypy --strict 0 errors
- [ ] pytest 100% / diff-cover ≥ 80

### Progress note (2025-10-12 - Phase 4 最終検証完了)
- **完了**: Phase 4 リアルタイム監視ダッシュボード実装、ワークフロー自動化、監視システム監査、CI Quality Gate強化
- **品質ゲート**: PyTest 96.33%カバレッジ、UI監査PASS（アクセシビリティ100%、パフォーマンス85%）
- **進行中**: ML最適化・自動再訓練システム、承認プロセス最適化、外部システム連携（オートパイロット承認済み）
- **残タスク（高優先度）**: Task 008, 010, 011の完了確認、最終統合テスト
- **残タスク（中優先度）**: PyTest警告解決（pytest.mark.performance、Pydantic V2移行）
- **見込み**: Phase 4完了条件を満たし、Phase 5計画策定準備完了

### Next milestone targets (v1.3)
- [ ] CI最適化完了（キャッシュ活用・レポート生成・環境保障）
- [ ] SBOM生成・ライセンス検証自動化（M1対応）
- [ ] CODEOWNERS整備（M2対応）
- [ ] Secrets スキャンCI統合（M3対応）
## P0 (Immediate Adoption)

- Add multi-layer UI guards (Lighthouse + Linkinator) to CI Windows test job
- Generate accountability card from CI and store under ORCH/patches/<YYYY-MM>/
- Verify UI-Audit (axe/visual/LCP) remains unaffected

## P1 (MVP in current phase)

- Introduce semantic anchors (data-sem-role / data-sem-intent) on Style Manager controls
- Migrate E2E locators to semantic anchors for stability
- Prepare minimal diff pipeline (diff --numstat check) for CI integration
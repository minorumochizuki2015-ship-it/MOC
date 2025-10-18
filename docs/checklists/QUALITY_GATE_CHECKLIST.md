# 品質ゲート チェックリスト（CI）

## 監査完了項目（2025-10-11）
- [x] 型安全ゲート強制: CI Ubuntu/Windows両ジョブで `mypy --strict` 実行・型エラー時fail
- [x] mypy.ini設定統一: `ignore_missing_imports = False`, `files = app, src, tests`
- [x] CI設定整合性: 重複YAML削除、型安全ゲート統一実装
- [x] ドキュメント同期: WORK_TRACKING.md, TASKS.md, MILESTONES.md整合性確認

## 実行中品質ゲート
- [ ] 型安全ゲート: mypy --strict 0 errors AND pytest 100% Pass AND 差分カバレッジ ≥ 80
- [ ] カバレッジ >= 80%、coverage.xml 生成、差分カバレッジ合格
- [ ] Kernel healthcheck（`status=="ok"`）を CI プリフライトで確認
- [ ] Windows ジョブで diff-cover `--fail-under=80` を適用し閾値未達なら fail
- [ ] flake8, isort, black --check 合格
- [ ] secrets スキャン合格（検知ゼロ）
- [ ] 依存性監査（pip-audit/safety）重大問題ゼロ
- [ ] SBOM 生成（CycloneDX）
- [ ] ライセンス互換性検証合格
- [ ] 成果物署名/Provenance（段階導入）

## 次ステップ（高優先度）
- [ ] mypy 14件エラー詳細収集 → docs/mypy_strict_plan.md埋め込み
- [ ] Logging統一（src/・app/shared/のloggerファクトリ化）
- [ ] CI最適化（pip/mypyキャッシュ、HTMLレポート、Windows venv保障）

備考（2025-10-11 - 監査完了）
- 型安全ゲートは CI の Ubuntu/Windows 両ジョブで `mypy --strict --show-error-codes app src` を実行し、型エラー発生時にジョブが必ず fail する構成に移行済み。
- SSOT/WORK規則適合、形式要件（UTF-8+LF、Secrets未検出、最小unified diff）確認済み。
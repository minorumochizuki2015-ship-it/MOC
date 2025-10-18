# 品質ゲート チェックリスト（CI）

- [ ] pytest（単体/統合）成功
- [ ] カバレッジ >= 80%、coverage.xml 生成、差分カバレッジ合格
- [ ] flake8, isort, black --check 合格
- [ ] mypy（strict）合格（暫定は許容例外管理）
- [ ] secrets スキャン合格（検知ゼロ）
- [ ] 依存性監査（pip-audit/safety）重大問題ゼロ
- [ ] SBOM 生成（CycloneDX）
- [ ] ライセンス互換性検証合格
- [ ] 成果物署名/Provenance（段階導入）
# リリース チェックリスト

前提: CI の品質ゲートに全合格、運用ドキュメント更新済み。

## 機能・品質
- [ ] 変更点と影響範囲のレビュー完了（2名以上）
- [ ] テスト結果とカバレッジのエビデンス保存
- [ ] 重大脆弱性なし（監査結果添付）
- [ ] 型安全ゲート（mypy --strict 0 errors / pytest 100% / diff-cover ≥ 80）

## セキュリティ/コンプライアンス
- [ ] SBOM を成果物と共に保存
- [ ] ライセンス整合性チェック合格
- [ ] Secrets スキャン結果ゼロ
- [ ] 署名/Provenance（可能範囲で）

## デプロイ/運用
- [ ] Canary 設計と段階的リリース計画
- [ ] 監視ダッシュボードの更新（メトリクス/アラート基準）
- [ ] ロールバック手順の検証（演習記録）
- [ ] リリースノートとバージョニング（SemVer）
 - [ ] CI プリフライトで kernel healthcheck OK を確認
 - [ ] 必要なディレクトリ（`data/baseline/...`）の事前作成を確認（Windows ジョブ）

## v1.2リリース準備状況（2025-10-11 - 監査完了）

### 完了項目
- [x] CI型安全ゲート強制（Ubuntu/Windows両ジョブ）
- [x] mypy.ini設定統一・重複削除
- [x] CI設定整合性確認・YAML重複解消
- [x] ドキュメント同期（WORK_TRACKING.md, TASKS.md, MILESTONES.md）

### 残タスク（v1.2達成条件）
- [ ] mypy --strict 0 errors（現在14件エラー → docs/mypy_strict_plan.md詳細化）
- [ ] Logging統一完了（src/・app/shared/のloggerファクトリ化）
- [ ] pytest 100% / diff-cover ≥ 80（現在の品質ゲート維持）

### 次期v1.3準備項目
- [ ] CI最適化（pip/mypyキャッシュ、HTMLレポート、Windows venv保障）
- [ ] SBOM生成・ライセンス検証自動化
- [ ] CODEOWNERS整備・Secretsスキャン統合

備考（2025-10-11 - 監査完了）
- 型安全ゲートは CI の Ubuntu/Windows 両ジョブで `mypy --strict --show-error-codes app src` を実行し、型エラー発生時にジョブが必ず fail する構成に移行済み。
- SSOT/WORK規則適合、形式要件（UTF-8+LF、Secrets未検出、最小unified diff）確認済み。